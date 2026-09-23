// SPDX-License-Identifier: Apache-2.0

//! Signed occurrence-retention control records (plan Section 7.10).
//!
//! Retention is deliberately an offline control-plane concern.  A tenant
//! authority signs immutable, epoch-addressed records for one occurrence;
//! ingestion never reads them and has no deletion route.  The record history
//! is folded by an offline reader: tombstones are permanent, a legal hold
//! overrides a tombstone in either epoch order, and an occurrence with no
//! records is retained indefinitely.

use std::collections::BTreeMap;
use std::fmt;

use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{
    Ed25519PublicKey, Ed25519Signature, KeyId, OccurrenceId, TenantId, Timestamp,
};

use crate::authority::{
    AuthorityChainError, PinnedAuthorityRoot, utc_instant, verify_control_record,
};
use crate::ed25519;

/// The control trust namespace every retention record carries.
const CONTROL_NAMESPACE: &str = "archivist.control/v1";

/// The largest epoch permitted by the control schema and its object-key
/// grammar: eighteen decimal digits, with no leading zero.
const EPOCH_MAX: u64 = 999_999_999_999_999_999;

/// The schema-pinned deletion grace period (`wait 30 days`).
pub const DELETION_GRACE_DAYS: u64 = 30;

/// The deletion grace period in seconds, used by the offline eligibility
/// predicate.  The two-pass scan and its 24-hour spacing belong to the
/// deletion workflow, not to this record.
pub const DELETION_GRACE_SECONDS: i64 = 30 * 24 * 60 * 60;

const EPOCH_MAX_I64: i64 = 999_999_999_999_999_999;

const RETENTION_MEMBERS: [&str; 12] = [
    "schema",
    "record_type",
    "record_kind",
    "tenant_id",
    "occurrence_id",
    "authorization_epoch",
    "retention_action",
    "reason_class",
    "audit_identity",
    "signed_at",
    "authority_key_id",
    "authority_signature",
];

/// One immutable retention event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetentionAction {
    /// Permanently marks the occurrence for deletion after the workflow's
    /// grace and reference-safety checks.
    Tombstone,
    /// Prevents deletion until a later release event.
    LegalHold,
    /// Releases an active legal hold; it never clears a tombstone.
    Release,
}

impl RetentionAction {
    /// Every action in schema order.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Tombstone, Self::LegalHold, Self::Release]
    }

    /// The closed wire token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Tombstone => "tombstone",
            Self::LegalHold => "legal-hold",
            Self::Release => "release",
        }
    }

    /// Parse the closed action vocabulary.
    ///
    /// # Errors
    /// Returns [`RetentionError::MalformedRecord`] for an unknown token.
    pub fn parse(text: &str) -> Result<Self, RetentionError> {
        match text {
            "tombstone" => Ok(Self::Tombstone),
            "legal-hold" => Ok(Self::LegalHold),
            "release" => Ok(Self::Release),
            _ => Err(RetentionError::MalformedRecord),
        }
    }
}

impl fmt::Display for RetentionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Why a retention event was directed.  This is audit provenance, not an
/// authorization decision: enforcement depends on [`RetentionAction`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetentionReasonClass {
    /// A litigation or regulatory preservation demand.
    LegalHold,
    /// A tenant-defined retention-policy decision.
    TenantPolicy,
    /// A direct offline administrator instruction.
    OperatorRequest,
    /// Material ingested in error, superseded, or withdrawn.
    PrivacyRequest,
}

impl RetentionReasonClass {
    /// Every reason class in schema order.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::LegalHold,
            Self::TenantPolicy,
            Self::OperatorRequest,
            Self::PrivacyRequest,
        ]
    }

    /// The closed wire token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::LegalHold => "legal-hold",
            Self::TenantPolicy => "tenant-policy",
            Self::OperatorRequest => "operator-request",
            Self::PrivacyRequest => "privacy-request",
        }
    }

    /// Parse the closed reason vocabulary.
    ///
    /// # Errors
    /// Returns [`RetentionError::MalformedRecord`] for an unknown token.
    pub fn parse(text: &str) -> Result<Self, RetentionError> {
        match text {
            "legal-hold" => Ok(Self::LegalHold),
            "tenant-policy" => Ok(Self::TenantPolicy),
            "operator-request" => Ok(Self::OperatorRequest),
            "privacy-request" => Ok(Self::PrivacyRequest),
            _ => Err(RetentionError::MalformedRecord),
        }
    }
}

impl fmt::Display for RetentionReasonClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Why a retention record could not be accepted or folded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetentionError {
    /// The bytes or a member do not satisfy the closed retention schema.
    MalformedRecord,
    /// The record disagrees with its tenant, occurrence, epoch-addressed key,
    /// or control-record identity.
    RecordDisagreement,
    /// The tenant-authority signature is not trusted by the pinned root.
    UntrustedAuthority,
    /// The verified history cannot be folded without rewriting an epoch or
    /// violating its occurrence sequence.
    InconsistentView,
}

impl RetentionError {
    /// Content-free error text suitable for diagnostics.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::MalformedRecord => "malformed-record",
            Self::RecordDisagreement => "record-disagreement",
            Self::UntrustedAuthority => "untrusted-authority",
            Self::InconsistentView => "inconsistent-view",
        }
    }
}

impl fmt::Display for RetentionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for RetentionError {}

impl From<AuthorityChainError> for RetentionError {
    fn from(error: AuthorityChainError) -> Self {
        match error {
            AuthorityChainError::RecordDisagreement => Self::RecordDisagreement,
            _ => Self::UntrustedAuthority,
        }
    }
}

/// One verified, tenant-authority-signed retention event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionRecord {
    tenant_id: TenantId,
    occurrence_id: OccurrenceId,
    epoch: u64,
    action: RetentionAction,
    reason_class: RetentionReasonClass,
    audit_identity: String,
    signed_at: Timestamp,
}

impl RetentionRecord {
    /// Verify one record at its derived
    /// `retention/<occurrence>/<epoch>.json` address.
    ///
    /// # Errors
    /// Returns a content-free [`RetentionError`] when the envelope is
    /// malformed, disagrees with its addressed identity, or fails authority
    /// verification.
    pub fn verify(
        root: &PinnedAuthorityRoot,
        envelope: &[u8],
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
        addressed_occurrence: &OccurrenceId,
        addressed_epoch: u64,
    ) -> Result<Self, RetentionError> {
        const MALFORMED: RetentionError = RetentionError::MalformedRecord;
        let Value::Object(object) = json::parse(envelope).map_err(|_| MALFORMED)? else {
            return Err(MALFORMED);
        };
        verify_member_set(&object)?;
        if text_member(&object, "schema") != Some(CONTROL_NAMESPACE)
            || text_member(&object, "record_type") != Some("retention")
            || text_member(&object, "record_kind") != Some("immutable")
        {
            return Err(RetentionError::RecordDisagreement);
        }

        let tenant = TenantId::parse(text_member(&object, "tenant_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if tenant != *root.tenant_id() {
            return Err(RetentionError::RecordDisagreement);
        }
        let occurrence =
            OccurrenceId::parse(text_member(&object, "occurrence_id").ok_or(MALFORMED)?)
                .map_err(|_| MALFORMED)?;
        if occurrence != *addressed_occurrence {
            return Err(RetentionError::RecordDisagreement);
        }
        let epoch = epoch_member(&object)?;
        if epoch != addressed_epoch {
            return Err(RetentionError::RecordDisagreement);
        }
        let action =
            RetentionAction::parse(text_member(&object, "retention_action").ok_or(MALFORMED)?)?;
        let reason_class =
            RetentionReasonClass::parse(text_member(&object, "reason_class").ok_or(MALFORMED)?)?;
        let audit_identity = text_member(&object, "audit_identity").ok_or(MALFORMED)?;
        if !valid_audit_identity(audit_identity) {
            return Err(MALFORMED);
        }
        let signed_at = Timestamp::parse(text_member(&object, "signed_at").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if !signed_at.calendar_valid() {
            return Err(MALFORMED);
        }

        verify_control_record(root, envelope, fetch)?;
        Ok(Self {
            tenant_id: tenant,
            occurrence_id: occurrence,
            epoch,
            action,
            reason_class,
            audit_identity: audit_identity.to_owned(),
            signed_at,
        })
    }

    /// The tenant whose authority signed the event.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The occurrence the event addresses.
    #[must_use]
    pub const fn occurrence_id(&self) -> &OccurrenceId {
        &self.occurrence_id
    }

    /// The occurrence retention-history epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The event's enforcement action.
    #[must_use]
    pub const fn action(&self) -> RetentionAction {
        self.action
    }

    /// Alias for callers that use the wire member name.
    #[must_use]
    pub const fn retention_action(&self) -> RetentionAction {
        self.action
    }

    /// The audit-only reason class.
    #[must_use]
    pub const fn reason_class(&self) -> RetentionReasonClass {
        self.reason_class
    }

    /// The bounded account or role label supplied by the administrator.
    #[must_use]
    pub fn audit_identity(&self) -> &str {
        &self.audit_identity
    }

    /// The immutable authority-signing instant.
    #[must_use]
    pub const fn signed_at(&self) -> &Timestamp {
        &self.signed_at
    }
}

/// The folded retention state for one occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionState {
    occurrence_id: OccurrenceId,
    records: BTreeMap<u64, RetentionRecord>,
    tombstone_at: Option<Timestamp>,
    hold_active: bool,
}

impl RetentionState {
    /// Start with no control records.  This is the indefinite-retention
    /// default: absence creates neither deletion nor a finite expiry.
    #[must_use]
    pub fn new(occurrence_id: OccurrenceId) -> Self {
        Self {
            occurrence_id,
            records: BTreeMap::new(),
            tombstone_at: None,
            hold_active: false,
        }
    }

    /// Fold any order of verified records into one state.
    ///
    /// # Errors
    /// Returns [`RetentionError::RecordDisagreement`] for another occurrence
    /// and [`RetentionError::InconsistentView`] for conflicting events at
    /// one immutable epoch.
    pub fn fold<I>(occurrence_id: OccurrenceId, records: I) -> Result<Self, RetentionError>
    where
        I: IntoIterator<Item = RetentionRecord>,
    {
        let mut state = Self::new(occurrence_id);
        let mut records: Vec<_> = records.into_iter().collect();
        records.sort_by_key(RetentionRecord::epoch);
        for record in records {
            state.apply(record)?;
        }
        Ok(state)
    }

    /// Fold a record into this state.  Re-delivery of the same event is an
    /// idempotent repair; a different event at the same immutable epoch is
    /// an integrity conflict.
    ///
    /// # Errors
    /// Returns [`RetentionError::RecordDisagreement`] for another occurrence
    /// and [`RetentionError::InconsistentView`] for a conflicting event at
    /// an occupied epoch.
    pub fn apply(&mut self, record: RetentionRecord) -> Result<(), RetentionError> {
        if record.occurrence_id != self.occurrence_id {
            return Err(RetentionError::RecordDisagreement);
        }
        if let Some(existing) = self.records.get(&record.epoch) {
            return if existing == &record {
                Ok(())
            } else {
                Err(RetentionError::InconsistentView)
            };
        }

        match record.action {
            RetentionAction::Tombstone => {
                if self.tombstone_at.is_none() {
                    self.tombstone_at = Some(record.signed_at.clone());
                }
            }
            RetentionAction::LegalHold => self.hold_active = true,
            RetentionAction::Release => self.hold_active = false,
        }
        self.records.insert(record.epoch, record);
        Ok(())
    }

    /// The addressed occurrence.
    #[must_use]
    pub const fn occurrence_id(&self) -> &OccurrenceId {
        &self.occurrence_id
    }

    /// The last epoch folded, or zero when the history is empty.
    #[must_use]
    pub fn last_epoch(&self) -> u64 {
        self.records.keys().next_back().copied().unwrap_or(0)
    }

    /// Every event in ascending epoch order.
    pub fn records(&self) -> impl Iterator<Item = &RetentionRecord> {
        self.records.values()
    }

    /// Whether a legal hold currently blocks deletion.
    #[must_use]
    pub const fn has_active_legal_hold(&self) -> bool {
        self.hold_active
    }

    /// Alias for the workflow vocabulary.
    #[must_use]
    pub const fn is_held(&self) -> bool {
        self.hold_active
    }

    /// Whether a tombstone has ever been published.
    #[must_use]
    pub const fn is_tombstoned(&self) -> bool {
        self.tombstone_at.is_some()
    }

    /// The first tombstone's immutable grace anchor, if any.
    #[must_use]
    pub const fn tombstone_at(&self) -> Option<&Timestamp> {
        self.tombstone_at.as_ref()
    }

    /// Whether this occurrence has the no-record indefinite default.
    #[must_use]
    pub fn is_indefinite(&self) -> bool {
        self.records.is_empty()
    }

    /// Whether the 30-day grace has elapsed and no hold blocks collection.
    /// An occurrence with no tombstone is never eligible.
    #[must_use]
    pub fn eligible_for_deletion_at(&self, at: &Timestamp) -> bool {
        let Some(tombstone_at) = self.tombstone_at() else {
            return false;
        };
        if self.hold_active || !at.calendar_valid() {
            return false;
        }
        grace_elapsed(tombstone_at, at)
    }

    /// Alias used by deletion workflows.
    #[must_use]
    pub fn may_delete_at(&self, at: &Timestamp) -> bool {
        self.eligible_for_deletion_at(at)
    }
}

/// The signed record and its server-derived control key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPublication {
    envelope: Vec<u8>,
    object_key: String,
}

impl RetentionPublication {
    /// Canonical signed envelope bytes.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// `tenants/<tenant>/v1/control/retention/<occurrence>/<epoch>.json`.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }
}

/// Errors raised before a retention event is signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetentionPublicationError {
    /// An epoch, timestamp, audit identity, or other supplied member is
    /// outside the closed record contract.
    MalformedInput,
}

/// Short module-local name matching the other authority publication APIs.
pub type PublicationError = RetentionPublicationError;

impl RetentionPublicationError {
    /// Content-free error text.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        "malformed-input"
    }
}

impl fmt::Display for RetentionPublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for RetentionPublicationError {}

/// Sign one immutable retention event.
///
/// # Errors
/// Returns [`RetentionPublicationError::MalformedInput`] when the epoch,
/// timestamp, or audit identity is outside the closed record contract.
#[allow(clippy::too_many_arguments)]
pub fn publish_retention(
    authority_seed: &[u8; 32],
    tenant: &TenantId,
    occurrence_id: &OccurrenceId,
    epoch: u64,
    action: RetentionAction,
    reason_class: RetentionReasonClass,
    audit_identity: &str,
    signed_at: &Timestamp,
) -> Result<RetentionPublication, RetentionPublicationError> {
    if !valid_epoch(epoch) || !signed_at.calendar_valid() || !valid_audit_identity(audit_identity) {
        return Err(RetentionPublicationError::MalformedInput);
    }
    let authority_public = ed25519::public_key_from_seed(authority_seed);
    let authority_key_id = KeyId::from_public_key(&Ed25519PublicKey::from_raw(authority_public));

    let mut members = Object::new();
    members.set("schema", text(CONTROL_NAMESPACE));
    members.set("record_type", text("retention"));
    members.set("record_kind", text("immutable"));
    members.set("tenant_id", text(tenant.as_str()));
    members.set("occurrence_id", text(&occurrence_id.to_hex()));
    members.set(
        "authorization_epoch",
        Value::Int(i64::try_from(epoch).map_err(|_| RetentionPublicationError::MalformedInput)?),
    );
    members.set("retention_action", text(action.token()));
    members.set("reason_class", text(reason_class.token()));
    members.set("audit_identity", text(audit_identity));
    members.set("signed_at", text(signed_at.as_str()));
    members.set("authority_key_id", text(&authority_key_id.to_hex()));

    let signature = ed25519::sign(
        authority_seed,
        &Value::Object(members.clone()).canonical_bytes(),
    );
    members.set(
        "authority_signature",
        text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
    );
    Ok(RetentionPublication {
        envelope: Value::Object(members).canonical_bytes(),
        object_key: retention_object_key(tenant, occurrence_id, epoch),
    })
}

/// Sign a tombstone event.
///
/// # Errors
/// Returns [`RetentionPublicationError::MalformedInput`] when the supplied
/// epoch, timestamp, or audit identity is malformed.
pub fn publish_tombstone(
    authority_seed: &[u8; 32],
    tenant: &TenantId,
    occurrence_id: &OccurrenceId,
    epoch: u64,
    reason_class: RetentionReasonClass,
    audit_identity: &str,
    signed_at: &Timestamp,
) -> Result<RetentionPublication, RetentionPublicationError> {
    publish_retention(
        authority_seed,
        tenant,
        occurrence_id,
        epoch,
        RetentionAction::Tombstone,
        reason_class,
        audit_identity,
        signed_at,
    )
}

/// Sign a legal-hold event.
///
/// # Errors
/// Returns [`RetentionPublicationError::MalformedInput`] when the supplied
/// epoch, timestamp, or audit identity is malformed.
pub fn publish_legal_hold(
    authority_seed: &[u8; 32],
    tenant: &TenantId,
    occurrence_id: &OccurrenceId,
    epoch: u64,
    reason_class: RetentionReasonClass,
    audit_identity: &str,
    signed_at: &Timestamp,
) -> Result<RetentionPublication, RetentionPublicationError> {
    publish_retention(
        authority_seed,
        tenant,
        occurrence_id,
        epoch,
        RetentionAction::LegalHold,
        reason_class,
        audit_identity,
        signed_at,
    )
}

/// Sign a legal-hold release event.
///
/// # Errors
/// Returns [`RetentionPublicationError::MalformedInput`] when the supplied
/// epoch, timestamp, or audit identity is malformed.
pub fn publish_release(
    authority_seed: &[u8; 32],
    tenant: &TenantId,
    occurrence_id: &OccurrenceId,
    epoch: u64,
    reason_class: RetentionReasonClass,
    audit_identity: &str,
    signed_at: &Timestamp,
) -> Result<RetentionPublication, RetentionPublicationError> {
    publish_retention(
        authority_seed,
        tenant,
        occurrence_id,
        epoch,
        RetentionAction::Release,
        reason_class,
        audit_identity,
        signed_at,
    )
}

/// Derive the immutable retention record key.
#[must_use]
pub fn retention_object_key(tenant: &TenantId, occurrence_id: &OccurrenceId, epoch: u64) -> String {
    format!(
        "tenants/{}/v1/control/retention/{}/{}.json",
        tenant.as_str(),
        occurrence_id.to_hex(),
        epoch
    )
}

fn verify_member_set(object: &Object) -> Result<(), RetentionError> {
    if object.len() != RETENTION_MEMBERS.len()
        || RETENTION_MEMBERS
            .iter()
            .any(|member| !object.contains(member))
    {
        return Err(RetentionError::MalformedRecord);
    }
    Ok(())
}

fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(value)) => Some(value.as_str()),
        _ => None,
    }
}

fn epoch_member(object: &Object) -> Result<u64, RetentionError> {
    match object.get("authorization_epoch") {
        Some(Value::Int(value)) if (1..=EPOCH_MAX_I64).contains(value) => {
            u64::try_from(*value).map_err(|_| RetentionError::MalformedRecord)
        }
        _ => Err(RetentionError::MalformedRecord),
    }
}

fn valid_epoch(epoch: u64) -> bool {
    (1..=EPOCH_MAX).contains(&epoch)
}

fn valid_audit_identity(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b".@_:/-".contains(byte))
}

fn grace_elapsed(anchor: &Timestamp, at: &Timestamp) -> bool {
    let (anchor_seconds, anchor_nanos) = utc_instant(anchor);
    let Some(close_seconds) = anchor_seconds.checked_add(DELETION_GRACE_SECONDS) else {
        return false;
    };
    let at_instant = utc_instant(at);
    at_instant >= (close_seconds, anchor_nanos)
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use archivist_protocol::json::Value;

    const ROOT_SEED: [u8; 32] = [0x11; 32];
    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const OCCURRENCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).unwrap()
    }

    fn occurrence() -> OccurrenceId {
        OccurrenceId::parse(OCCURRENCE).unwrap()
    }

    fn stamp(value: &str) -> Timestamp {
        Timestamp::parse(value).unwrap()
    }

    fn root() -> PinnedAuthorityRoot {
        PinnedAuthorityRoot::new(
            tenant(),
            Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&ROOT_SEED)),
        )
    }

    fn signed(action: RetentionAction, epoch: u64, at: &str) -> RetentionPublication {
        publish_retention(
            &ROOT_SEED,
            &tenant(),
            &occurrence(),
            epoch,
            action,
            RetentionReasonClass::OperatorRequest,
            "retention-admin",
            &stamp(at),
        )
        .unwrap()
    }

    #[test]
    fn signed_records_verify_and_keep_their_immutable_audit_members() {
        let publication = signed(RetentionAction::Tombstone, 1, "2026-09-01T00:00:00Z");
        let record =
            RetentionRecord::verify(&root(), publication.envelope(), |_| None, &occurrence(), 1)
                .unwrap();
        assert_eq!(record.action(), RetentionAction::Tombstone);
        assert_eq!(record.reason_class(), RetentionReasonClass::OperatorRequest);
        assert_eq!(record.audit_identity(), "retention-admin");
        assert_eq!(record.signed_at().as_str(), "2026-09-01T00:00:00Z");
        assert_eq!(
            publication.object_key(),
            retention_object_key(&tenant(), &occurrence(), 1)
        );
    }

    #[test]
    fn holds_override_tombstones_in_both_epoch_orders() {
        let tombstone = RetentionRecord::verify(
            &root(),
            signed(RetentionAction::Tombstone, 1, "2026-09-01T00:00:00Z").envelope(),
            |_| None,
            &occurrence(),
            1,
        )
        .unwrap();
        let hold = RetentionRecord::verify(
            &root(),
            signed(RetentionAction::LegalHold, 2, "2026-09-02T00:00:00Z").envelope(),
            |_| None,
            &occurrence(),
            2,
        )
        .unwrap();
        let state = RetentionState::fold(occurrence(), [tombstone, hold]).unwrap();
        assert!(state.is_tombstoned());
        assert!(state.is_held());
        assert!(!state.eligible_for_deletion_at(&stamp("2026-10-05T00:00:00Z")));

        let hold = RetentionRecord::verify(
            &root(),
            signed(RetentionAction::LegalHold, 1, "2026-09-01T00:00:00Z").envelope(),
            |_| None,
            &occurrence(),
            1,
        )
        .unwrap();
        let tombstone = RetentionRecord::verify(
            &root(),
            signed(RetentionAction::Tombstone, 2, "2026-09-02T00:00:00Z").envelope(),
            |_| None,
            &occurrence(),
            2,
        )
        .unwrap();
        let state = RetentionState::fold(occurrence(), [tombstone, hold]).unwrap();
        assert!(state.is_held());
        assert!(!state.eligible_for_deletion_at(&stamp("2026-10-06T00:00:00Z")));
    }

    #[test]
    fn release_clears_only_the_hold_and_tombstone_never_lapses() {
        let records = [
            RetentionRecord::verify(
                &root(),
                signed(RetentionAction::LegalHold, 1, "2026-09-01T00:00:00Z").envelope(),
                |_| None,
                &occurrence(),
                1,
            )
            .unwrap(),
            RetentionRecord::verify(
                &root(),
                signed(RetentionAction::Tombstone, 2, "2026-09-02T00:00:00Z").envelope(),
                |_| None,
                &occurrence(),
                2,
            )
            .unwrap(),
            RetentionRecord::verify(
                &root(),
                signed(RetentionAction::Release, 3, "2026-09-03T00:00:00Z").envelope(),
                |_| None,
                &occurrence(),
                3,
            )
            .unwrap(),
        ];
        let state = RetentionState::fold(occurrence(), records).unwrap();
        assert!(!state.is_held());
        assert!(state.is_tombstoned());
        assert!(!state.eligible_for_deletion_at(&stamp("2026-10-01T00:00:00Z")));
        assert!(state.eligible_for_deletion_at(&stamp("2026-10-03T00:00:00Z")));
    }

    #[test]
    fn no_records_are_indefinite_and_invalid_audit_or_action_fails_closed() {
        let state = RetentionState::new(occurrence());
        assert!(state.is_indefinite());
        assert!(!state.is_tombstoned());
        assert!(!state.eligible_for_deletion_at(&stamp("2099-01-01T00:00:00Z")));

        assert!(
            publish_retention(
                &ROOT_SEED,
                &tenant(),
                &occurrence(),
                1,
                RetentionAction::Tombstone,
                RetentionReasonClass::OperatorRequest,
                "bad identity!",
                &stamp("2026-09-01T00:00:00Z"),
            )
            .is_err()
        );

        let mut bytes = signed(RetentionAction::Tombstone, 1, "2026-09-01T00:00:00Z")
            .envelope()
            .to_vec();
        let Value::Object(mut object) = json::parse(&bytes).unwrap() else {
            panic!("object")
        };
        object.set("retention_action", text("erase"));
        bytes = Value::Object(object).canonical_bytes();
        assert_eq!(
            RetentionRecord::verify(&root(), &bytes, |_| None, &occurrence(), 1),
            Err(RetentionError::MalformedRecord)
        );
    }
}
