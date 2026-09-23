// SPDX-License-Identifier: Apache-2.0

//! Runtime enforcement of the client's revocation and rotation
//! workflows: the ingestion replica's half of both, from signed
//! control-record publication through trust evaluation (plan Section 5;
//! ID-006 — credentials must be revocable; EC-09 — propagation is
//! bounded by the reader's trust cache).
//!
//! A revocation is two records, never one: the tenant-authority-signed
//! [`RevocationRecord`] at the epoch-addressed key
//! `tenants/<tenant>/v1/control/revocations/<client>/<epoch>.json`, and
//! the strictly higher-epoch [`LinkedClientPointer`] that completes it.
//! The record preserves what the current-pointer shape cannot — a
//! current-pointer object retains no history of the epoch it left — and
//! the pointer is what makes stale-epoch attempts fail closed. Neither
//! record is ever removed or edited (EC-12): relinking after revocation
//! is a new, higher epoch with a new key.
//!
//! A client key rotation is the same shape with the overlap where the
//! permanence sits: the tenant-authority-signed [`RotationRecord`] at
//! `tenants/<tenant>/v1/control/rotations/<client>/<epoch>.json` —
//! both public halves, at the epoch the rotation establishes — is
//! published together with the strictly higher-epoch pointer naming the
//! new half, and that pointer bump is what keeps the authorization
//! epochs monotonic. For [`ROTATION_OVERLAP_SECONDS`] from the record's
//! `signed_at` (24 hours, plan Section 5), an attempt at the *current*
//! epoch may sign with either half of that rotation — the window
//! widens which key may sign, never which epoch is current — so a
//! retry of an already-frozen spool envelope re-authorizes with fresh
//! per-attempt state under either half instead of stranding there
//! (plan Section 5; EC-12). Past the window only the new half verifies;
//! the old half survives in the record precisely so a stateless replica
//! can verify an old-key attempt inside the window without any
//! server-local key history.
//!
//! Four surfaces cover the replica's side of that workflow:
//!
//! - [`RevocationRecord::verify`], [`LinkedClientPointer::verify`], and
//!   [`RotationRecord::verify`] are the evidence gate. All three run the
//!   family's closed member set and every VAL-002 cross-field check —
//!   the record must agree with the address it was served at, the tenant
//!   with the pinned root, the pointer's key ID with the pinned
//!   derivation of its own public half, a rotation's two key IDs with
//!   the derivations of their own halves and with each other's epoch —
//!   and then the signature, through
//!   [`crate::authority::verify_control_record`]'s fetch-verify-adopt
//!   chain walk from the pinned root. Unverified bytes never become a
//!   value of either type, so every downstream decision is over
//!   authenticated evidence by construction.
//! - [`ClientTrustView`] is the fold: one client's current pointer plus
//!   its verified revocations and rotations, with the append-only epoch
//!   rules. A revocation or rotation at an epoch the pointer has not
//!   reached is an inconsistent view, two different records at one epoch
//!   are an integrity conflict, and a re-delivered identical record is
//!   an idempotent repair — mirroring the write classes the control
//!   store already enforces, because a replica's view can be assembled
//!   from a retrying reader just as a store's history can be assembled
//!   from a retrying writer.
//! - [`ClientTrustView::evaluate`] is the runtime decision an attempt
//!   authorization calls: the attempt's client, authorization epoch, and
//!   key ID against the view, rejected
//!   [`Revoked`](AttemptRejection::Revoked),
//!   [`StaleEpoch`](AttemptRejection::StaleEpoch),
//!   [`EpochBeyondPointer`](AttemptRejection::EpochBeyondPointer), or
//!   [`KeyEpochMismatch`](AttemptRejection::KeyEpochMismatch) — every
//!   failure closed, none retried at a weaker class.
//!
//! Propagation is bounded by the reader's 60-second trust-record cache
//! (plan Section 5; EC-09) and by nothing in the records themselves —
//! a revocation carries no expiry, because nothing may un-revoke. The
//! bound is pinned here as [`REVOCATION_PROPAGATION_BOUND_SECONDS`] and
//! proven equal to the schema's `revocationPropagationBoundSeconds` by a
//! test; the cache that enforces the bound over live reads is the
//! bounded-trust-cache deliverable, which composes in front of the
//! [`verify`](RevocationRecord::verify) calls exactly as the authority
//! chain's cache seam does.
//!
//! # The decision order, and why
//!
//! [`ClientTrustView::evaluate`] checks, in order: a different client
//! than the view's ([`AttemptRejection::ClientMismatch`]); an epoch above
//! the pointer's ([`AttemptRejection::EpochBeyondPointer`] — one-based
//! epochs, so epoch zero is beyond every pointer); then revocations at or
//! below the attempt's epoch. That last ordering is deliberate: an
//! attempt presenting a revoked epoch is stale *and* revoked, and the
//! revocation is the sharper evidence — the pointer says the epoch is
//! old, the record says the key is dead, and the schema's own words are
//! "dead twice over". Only then does staleness against the pointer
//! ([`AttemptRejection::StaleEpoch`]) and the pointer's own half check
//! ([`AttemptRejection::KeyEpochMismatch`]) apply. Every rejection path
//! ends the attempt; nothing downgrades a rejection to a weaker class.
//!
//! [`ClientTrustView::evaluate_at`] is that same decision at an
//! explicit instant, and the instant is where the rotation overlap
//! lives: when the attempt's key is not the pointer's standing half,
//! a folded rotation whose 24-hour window covers the instant admits
//! either of its own halves at the pointer's epoch — and nothing else
//! changes. Staleness is decided before the window is ever consulted,
//! so an old epoch stays dead inside every window; a revocation still
//! outranks the window (a dead key never reschedules itself); and
//! [`ClientTrustView::evaluate`], which reads no clock, is exactly this
//! decision with every window closed — the conservative rule a caller
//! falls back to when it cannot name the instant it is deciding at.

use std::collections::BTreeMap;
use std::fmt;

use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{
    ClientId, Ed25519PublicKey, Ed25519Signature, KeyId, TenantId, Timestamp,
};

use crate::authority::{
    utc_instant, verify_control_record, AuthorityChainError, PinnedAuthorityRoot,
};
use crate::ed25519;

/// The control trust namespace every record here is written in.
const CONTROL_NAMESPACE: &str = "archivist.control/v1";

/// The maximum seconds a verified trust view may serve decisions after
/// the evidence behind it last changed: the envelope's
/// `trustRecordCacheTtlSeconds`, pinned on the revocation schema as
/// `revocationPropagationBoundSeconds` and proven equal by the schema
/// gate and by the module's propagation test (plan Section 5; EC-09).
///
/// Within the window a replica may accept an attempt whose revocation has
/// already published — that is the propagation delay the plan accepts.
/// Past it, every healthy replica's refreshed view rejects the revoked
/// key; the tests prove both halves.
pub const REVOCATION_PROPAGATION_BOUND_SECONDS: u64 = 60;

/// The overlap window one rotation record opens, in seconds: 24 hours
/// from the record's `signed_at` (plan Section 5), the same dual-key
/// window the authority chain pins as
/// [`crate::authority::ROTATION_VERIFICATION_OVERLAP_HOURS`] and the
/// rotation schema names `rotationVerificationOverlapHours`; the
/// module's schema-gate test proves the three agree.
///
/// The window widens which key may sign at the *current* epoch — never
/// which epoch is current — so a retry of an already-frozen spool
/// envelope re-authorizes under either half instead of stranding there.
/// Past it only the rotation's new half verifies, which is what
/// [`ClientTrustView::evaluate_at`] decides and
/// [`ClientTrustView::evaluate`] never admits.
pub const ROTATION_OVERLAP_SECONDS: u64 = 24 * 60 * 60;

/// The closed member set of a revocation record
/// (`schemas/v1/control-revocation.json`; `additionalProperties: false`).
const REVOCATION_MEMBERS: [&str; 10] = [
    "schema",
    "record_type",
    "record_kind",
    "tenant_id",
    "client_id",
    "revoked_key_id",
    "authorization_epoch",
    "signed_at",
    "authority_key_id",
    "authority_signature",
];

/// The closed member set of a linked-client record
/// (`schemas/v1/control-client.json`; `additionalProperties: false`).
const LINKED_CLIENT_MEMBERS: [&str; 13] = [
    "schema",
    "record_type",
    "record_kind",
    "tenant_id",
    "client_id",
    "key_id",
    "key_algorithm",
    "public_key",
    "scopes",
    "authorization_epoch",
    "signed_at",
    "authority_key_id",
    "authority_signature",
];

/// The closed member set of a key-rotation record
/// (`schemas/v1/control-rotation.json`; `additionalProperties: false`):
/// the seven wrapper members every immutable control record carries plus
/// the rotation payload — both public halves with their derivable
/// identifiers and the two adjacent epochs.
const ROTATION_MEMBERS: [&str; 15] = [
    "schema",
    "record_type",
    "record_kind",
    "tenant_id",
    "client_id",
    "previous_epoch",
    "previous_public_key",
    "previous_key_id",
    "key_algorithm",
    "public_key",
    "key_id",
    "authorization_epoch",
    "signed_at",
    "authority_key_id",
    "authority_signature",
];

/// Why revocation evidence or a revocation-governed decision failed:
/// a closed class of failure carrying no echoed material (CFG-027).
///
/// The classes mirror the rejection vocabulary the control corpus pins
/// for the family: a malformed record never parsed as its own shape, a
/// disagreement between the record and the address, tenant, or pointer it
/// claims, an authority that does not verify, and a view that cannot be
/// internally consistent. Callers match exhaustively; a new failure class
/// has to be added here first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevocationError {
    /// The envelope is not a revocation (or linked-client) record: not
    /// JSON, not an object, a member outside the closed shape, a missing
    /// or non-canonical member, a value failing its grammar, or an
    /// instant that is not a real calendar moment. Nothing about the
    /// offending input is echoed.
    MalformedRecord,
    /// The record parsed but disagrees with its context: a foreign
    /// namespace, record type, or write class, a tenant other than the
    /// pinned root's, a record served at an address its own members do
    /// not name, or a pointer whose key ID is not the pinned derivation
    /// of its public half.
    RecordDisagreement,
    /// The authority signature does not verify: the signer does not
    /// resolve through the pinned root's chain, was not established at
    /// the record's instant, or the signature is not the signer's. The
    /// record is not a revocation (or a pointer) whoever else signed it.
    UntrustedAuthority,
    /// A verified record cannot be folded into a consistent view: a
    /// revocation at an epoch the client's pointer has not reached
    /// (the corpus's `epoch-unreached`), a revocation at the current
    /// epoch naming a half the pointer does not hold
    /// (`key-id-mismatch`), or two different revocations at one epoch
    /// (`integrity-conflict`). A view carrying any of these is torn or
    /// forged, and the only safe decision about it is none.
    InconsistentView,
}

impl RevocationError {
    /// The class's content-free display text.
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

impl fmt::Display for RevocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for RevocationError {}

impl From<AuthorityChainError> for RevocationError {
    fn from(error: AuthorityChainError) -> Self {
        match error {
            AuthorityChainError::RecordDisagreement => Self::RecordDisagreement,
            // Every other chain failure — a signer that does not resolve,
            // a broken link, a signature that is not the signer's, an
            // instant outside the acceptance window — is, to the
            // revocation decision, the same fact: the authority named is
            // not one the pinned root vouches for.
            _ => Self::UntrustedAuthority,
        }
    }
}

/// One verified revocation record: the tenant authority's statement that
/// `client_id`'s authorization at `epoch` — the half named by
/// `revoked_key_id` — is dead, permanently.
///
/// Construction is [`RevocationRecord::verify`] and nothing else; the
/// type cannot hold unverified bytes. Every member is an identifier, a
/// timestamp, or a signature — public material only (SEC-006).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationRecord {
    tenant_id: TenantId,
    client_id: ClientId,
    revoked_key_id: KeyId,
    epoch: u64,
    signed_at: Timestamp,
}

impl RevocationRecord {
    /// Verify one revocation record served at the epoch-addressed key
    /// `tenants/<tenant>/v1/control/revocations/<addressed_client>/
    /// <addressed_epoch>.json`.
    ///
    /// The family checks run before the signature: the closed member
    /// set, the namespace and the `revocation`/`immutable` identity
    /// pair, every member grammar, a calendar-valid `signed_at`, and the
    /// VAL-002 cross-field checks — the record's client and revoked
    /// epoch must equal the address it was served at, so a record served
    /// under another client's prefix or another epoch's key is a
    /// disagreement, not a naming oddity. Only then does the authority
    /// signature verify, through the pinned root's chain walk.
    ///
    /// # Errors
    /// [`RevocationError::MalformedRecord`] for any shape or grammar
    /// failure, [`RevocationError::RecordDisagreement`] for a record
    /// that disagrees with its namespace, class, tenant, or address, and
    /// [`RevocationError::UntrustedAuthority`] when the signature does
    /// not verify against the pinned root.
    pub fn verify(
        root: &PinnedAuthorityRoot,
        envelope: &[u8],
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
        addressed_client: &ClientId,
        addressed_epoch: u64,
    ) -> Result<Self, RevocationError> {
        const MALFORMED: RevocationError = RevocationError::MalformedRecord;
        let Value::Object(object) = json::parse(envelope).map_err(|_| MALFORMED)? else {
            return Err(MALFORMED);
        };
        verify_member_set(&object, &REVOCATION_MEMBERS)?;
        if text_member(&object, "record_type") != Some("revocation")
            || text_member(&object, "record_kind") != Some("immutable")
            || text_member(&object, "schema") != Some(CONTROL_NAMESPACE)
        {
            return Err(RevocationError::RecordDisagreement);
        }
        let tenant = TenantId::parse(text_member(&object, "tenant_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if tenant != *root.tenant_id() {
            return Err(RevocationError::RecordDisagreement);
        }
        let client = ClientId::parse(text_member(&object, "client_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if client != *addressed_client {
            return Err(RevocationError::RecordDisagreement);
        }
        let revoked_key_id = KeyId::parse(text_member(&object, "revoked_key_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        let epoch = epoch_member(&object)?;
        if epoch != addressed_epoch {
            // The epoch is signed: a record cannot be re-dated to the
            // address it was found at, and a record found at one
            // epoch's key naming another epoch is a torn store, not a
            // revocation of the attempt epoch.
            return Err(RevocationError::RecordDisagreement);
        }
        let signed_at = Timestamp::parse(text_member(&object, "signed_at").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if !signed_at.calendar_valid() {
            return Err(MALFORMED);
        }
        verify_control_record(root, envelope, fetch)?;
        Ok(Self {
            tenant_id: tenant,
            client_id: client,
            revoked_key_id,
            epoch,
            signed_at,
        })
    }

    /// The tenant whose authority signed the record.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The client whose authorization the record revokes.
    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// The key ID that died at `epoch` — the half the client's pointer
    /// held there, under the pinned derivation.
    #[must_use]
    pub const fn revoked_key_id(&self) -> &KeyId {
        &self.revoked_key_id
    }

    /// The revoked authorization epoch, equal to the object key's epoch
    /// segment.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The wall-clock instant the authority signed the revocation —
    /// audit context only; the record never expires.
    #[must_use]
    pub const fn signed_at(&self) -> &Timestamp {
        &self.signed_at
    }
}

/// One verified linked-client record, narrowed to the identity triple
/// runtime enforcement consumes: the client, its current signed
/// authorization epoch, and the key ID that holds there.
///
/// The pointer is a current-pointer record: its epoch only ever advances,
/// so the triple is both "who is linked" and "how fresh any authorization
/// claim may be". The full linked-client family contract — the scope
/// tokens and their administration — is the signed-client-records
/// deliverable's; this type carries exactly what a revocation decision
/// reads, verified through the same authority chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedClientPointer {
    client_id: ClientId,
    epoch: u64,
    key_id: KeyId,
}

impl LinkedClientPointer {
    /// Verify one linked-client record served at
    /// `tenants/<tenant>/v1/control/clients/<addressed_client>.json`.
    ///
    /// The family checks mirror [`RevocationRecord::verify`]'s, plus the
    /// pointer's own VAL-002 checks: the `key_id` member must be the
    /// pinned derivation of the record's own `public_key` half, and the
    /// `scopes` member must be the record schema's two-allowlist object
    /// (`schemas/v1/control-client.json`: exactly `harnesses` and
    /// `operations`, each a non-empty bounded array) — the tokens inside
    /// it are the linked-client family's contract, not the revocation
    /// decision's.
    ///
    /// # Errors
    /// As [`RevocationRecord::verify`].
    pub fn verify(
        root: &PinnedAuthorityRoot,
        envelope: &[u8],
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
        addressed_client: &ClientId,
    ) -> Result<Self, RevocationError> {
        const MALFORMED: RevocationError = RevocationError::MalformedRecord;
        let Value::Object(object) = json::parse(envelope).map_err(|_| MALFORMED)? else {
            return Err(MALFORMED);
        };
        verify_member_set(&object, &LINKED_CLIENT_MEMBERS)?;
        if text_member(&object, "record_type") != Some("linked-client")
            || text_member(&object, "record_kind") != Some("current-pointer")
            || text_member(&object, "schema") != Some(CONTROL_NAMESPACE)
        {
            return Err(RevocationError::RecordDisagreement);
        }
        let tenant = TenantId::parse(text_member(&object, "tenant_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if tenant != *root.tenant_id() {
            return Err(RevocationError::RecordDisagreement);
        }
        let client = ClientId::parse(text_member(&object, "client_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if client != *addressed_client {
            return Err(RevocationError::RecordDisagreement);
        }
        let public = Ed25519PublicKey::parse(text_member(&object, "public_key").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        let key_id = KeyId::parse(text_member(&object, "key_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if key_id != KeyId::from_public_key(&public) {
            // The key ID is a derivation, not a label: a record whose
            // half and ID disagree is a forged or corrupt pointer even
            // before the signature is read.
            return Err(RevocationError::RecordDisagreement);
        }
        if text_member(&object, "key_algorithm") != Some("ed25519") {
            return Err(RevocationError::RecordDisagreement);
        }
        if !scopes_allowlist_object(object.get("scopes")) {
            return Err(MALFORMED);
        }
        let epoch = epoch_member(&object)?;
        let signed_at = Timestamp::parse(text_member(&object, "signed_at").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if !signed_at.calendar_valid() {
            return Err(MALFORMED);
        }
        verify_control_record(root, envelope, fetch)?;
        Ok(Self {
            client_id: client,
            epoch,
            key_id,
        })
    }

    /// The linked client.
    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// The pointer's signed authorization epoch — the freshest epoch any
    /// attempt from this client may present.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The key ID that holds at `epoch`, under the pinned derivation.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }
}

/// One verified key-rotation record: the tenant authority's statement
/// that `client_id`'s authorization moved from the half named by
/// `previous_key_id` at `previous_epoch` to the half named by `key_id`
/// at `epoch` — the epoch the rotation establishes, equal to the object
/// key's epoch segment.
///
/// The record is where the previous public half survives: the
/// current-pointer linked-client record retains no history once it
/// moves, and a stateless replica verifying an old-key attempt inside
/// the overlap window reads the half here, never from server-local
/// state. Construction is [`RotationRecord::verify`] and nothing else;
/// the type cannot hold unverified bytes. Every member is an identifier,
/// a public half, a timestamp, or a signature — public material only,
/// doubly so (SEC-006): both halves here are public by definition, and
/// no private half exists in any record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationRecord {
    tenant_id: TenantId,
    client_id: ClientId,
    previous_epoch: u64,
    previous_public_key: Ed25519PublicKey,
    previous_key_id: KeyId,
    epoch: u64,
    public_key: Ed25519PublicKey,
    key_id: KeyId,
    signed_at: Timestamp,
}

impl RotationRecord {
    /// Verify one key-rotation record served at the epoch-addressed key
    /// `tenants/<tenant>/v1/control/rotations/<addressed_client>/
    /// <addressed_epoch>.json`, where the epoch segment is the epoch the
    /// rotation establishes.
    ///
    /// The family checks run before the signature: the closed member
    /// set, the namespace and the `rotation`/`immutable` identity pair,
    /// every member grammar, a calendar-valid `signed_at`, and the
    /// VAL-002 cross-field checks — the record's client and established
    /// epoch must equal the address it was served at, `previous_epoch`
    /// must be exactly `authorization_epoch` − 1 (every pointer move
    /// publishes the next epoch, so a rotation never skips one), and
    /// both key IDs must be the pinned derivations of their own public
    /// halves. Only then does the authority signature verify, through
    /// the pinned root's chain walk.
    ///
    /// # Errors
    /// [`RevocationError::MalformedRecord`] for any shape or grammar
    /// failure, [`RevocationError::RecordDisagreement`] for a record
    /// that disagrees with its namespace, class, tenant, address, epoch
    /// adjacency, or key derivations, and
    /// [`RevocationError::UntrustedAuthority`] when the signature does
    /// not verify against the pinned root.
    pub fn verify(
        root: &PinnedAuthorityRoot,
        envelope: &[u8],
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
        addressed_client: &ClientId,
        addressed_epoch: u64,
    ) -> Result<Self, RevocationError> {
        const MALFORMED: RevocationError = RevocationError::MalformedRecord;
        let Value::Object(object) = json::parse(envelope).map_err(|_| MALFORMED)? else {
            return Err(MALFORMED);
        };
        verify_member_set(&object, &ROTATION_MEMBERS)?;
        if text_member(&object, "record_type") != Some("rotation")
            || text_member(&object, "record_kind") != Some("immutable")
            || text_member(&object, "schema") != Some(CONTROL_NAMESPACE)
        {
            return Err(RevocationError::RecordDisagreement);
        }
        let tenant = TenantId::parse(text_member(&object, "tenant_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if tenant != *root.tenant_id() {
            return Err(RevocationError::RecordDisagreement);
        }
        let client = ClientId::parse(text_member(&object, "client_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if client != *addressed_client {
            return Err(RevocationError::RecordDisagreement);
        }
        if text_member(&object, "key_algorithm") != Some("ed25519") {
            return Err(RevocationError::RecordDisagreement);
        }
        let public_key =
            Ed25519PublicKey::parse(text_member(&object, "public_key").ok_or(MALFORMED)?)
                .map_err(|_| MALFORMED)?;
        let key_id = KeyId::parse(text_member(&object, "key_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if key_id != KeyId::from_public_key(&public_key) {
            // As with the pointer: a key ID is a derivation, not a
            // label, on both halves.
            return Err(RevocationError::RecordDisagreement);
        }
        let previous_public_key =
            Ed25519PublicKey::parse(text_member(&object, "previous_public_key").ok_or(MALFORMED)?)
                .map_err(|_| MALFORMED)?;
        let previous_key_id =
            KeyId::parse(text_member(&object, "previous_key_id").ok_or(MALFORMED)?)
                .map_err(|_| MALFORMED)?;
        if previous_key_id != KeyId::from_public_key(&previous_public_key) {
            return Err(RevocationError::RecordDisagreement);
        }
        if previous_key_id == key_id {
            // A same-key record is not a rotation: accepting it would
            // create a second epoch without changing the authorization
            // key and would make the overlap evidence ambiguous.
            return Err(RevocationError::RecordDisagreement);
        }
        let epoch = epoch_member(&object)?;
        if epoch != addressed_epoch {
            // The established epoch is signed: a record cannot be
            // re-dated to the address it was found at, and the overlap
            // evidence for epoch E's key lives at exactly
            // `rotations/<client>/E.json`.
            return Err(RevocationError::RecordDisagreement);
        }
        let previous_epoch = epoch_member_named(&object, "previous_epoch")?;
        if previous_epoch + 1 != epoch {
            // Every pointer move publishes exactly the next epoch, so a
            // rotation establishes exactly the adjacent one — a record
            // that skips or re-dates the boundary is a torn or forged
            // history, not a naming oddity.
            return Err(RevocationError::RecordDisagreement);
        }
        let signed_at = Timestamp::parse(text_member(&object, "signed_at").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if !signed_at.calendar_valid() {
            return Err(MALFORMED);
        }
        verify_control_record(root, envelope, fetch)?;
        Ok(Self {
            tenant_id: tenant,
            client_id: client,
            previous_epoch,
            previous_public_key,
            previous_key_id,
            epoch,
            public_key,
            key_id,
            signed_at,
        })
    }

    /// The tenant whose authority signed the record.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The rotating client.
    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// The epoch the rotation leaves — exactly `epoch` − 1, verified.
    #[must_use]
    pub const fn previous_epoch(&self) -> u64 {
        self.previous_epoch
    }

    /// The public half that held at `previous_epoch` — the old half of
    /// the overlap, which survives here precisely so a stateless replica
    /// can verify an old-key attempt inside the window.
    #[must_use]
    pub const fn previous_public_key(&self) -> &Ed25519PublicKey {
        &self.previous_public_key
    }

    /// The key ID that held at `previous_epoch`, under the pinned
    /// derivation.
    #[must_use]
    pub const fn previous_key_id(&self) -> &KeyId {
        &self.previous_key_id
    }

    /// The established authorization epoch, equal to the object key's
    /// epoch segment.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The new public half — the key of the epoch this rotation
    /// establishes, the half the established epoch's linked-client
    /// record carries.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// The key ID that holds at `epoch`, under the pinned derivation.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The wall-clock instant the authority signed the rotation — the
    /// anchor of the overlap window.
    #[must_use]
    pub const fn signed_at(&self) -> &Timestamp {
        &self.signed_at
    }

    /// Whether the overlap window opened at `signed_at` covers `at`:
    /// from the anchor instant through `signed_at` +
    /// [`ROTATION_OVERLAP_SECONDS`], both ends inclusive — the same
    /// boundary the authority chain's dual-key window draws, and never
    /// on either side of it. Before the anchor the rotation has not
    /// happened yet; past the close only the new half verifies.
    ///
    /// A calendar-invalid instant is covered by nothing: the question
    /// fails closed.
    #[must_use]
    pub fn window_covers(&self, at: &Timestamp) -> bool {
        if !at.calendar_valid() {
            return false;
        }
        let (anchor_seconds, anchor_nanoseconds) = utc_instant(&self.signed_at);
        // The constant is 86 400, far inside `i64`; the bound it is
        // added to is a real calendar instant's seconds.
        let close = (
            anchor_seconds + i64::try_from(ROTATION_OVERLAP_SECONDS).unwrap_or(i64::MAX),
            anchor_nanoseconds,
        );
        let at_instant = utc_instant(at);
        (anchor_seconds, anchor_nanoseconds) <= at_instant && at_instant <= close
    }
}

/// One client's revocation-governed trust view: the verified current
/// pointer plus every verified revocation and rotation folded in
/// ascending epoch order.
///
/// The fold is append-only by construction. [`ClientTrustView::
/// record_revocation`] accepts a re-delivered identical revocation as an
/// idempotent repair and refuses everything else that would rewrite
/// history: an epoch the pointer has not reached, a half the pointer does
/// not hold at the current epoch, a second, different revocation at an
/// occupied epoch. [`ClientTrustView::record_rotation`] folds a rotation
/// under the same rules, with the rotation's new half standing in for
/// the revoked one — the two records are the same workflow's two shapes.
/// There is no method that removes a record, because neither workflow
/// has one (EC-12).
///
/// The view is a pure function of the verified records handed to it, so
/// the 60-second trust cache composes in front of construction exactly as
/// it composes in front of [`RevocationRecord::verify`]: a decision this
/// view renders is a decision its evidence supports, and the cache TTL is
/// what bounds how long the evidence may lag the control plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientTrustView {
    pointer: LinkedClientPointer,
    /// Revoked epoch → the key ID that died there, ascending.
    revocations: BTreeMap<u64, KeyId>,
    /// Established epoch → the verified rotation that established it,
    /// ascending. At most one rotation per epoch: a second, different
    /// one is an integrity conflict at the fold.
    rotations: BTreeMap<u64, RotationRecord>,
}

impl ClientTrustView {
    /// Begin a client's view at its verified current pointer.
    #[must_use]
    pub fn new(pointer: LinkedClientPointer) -> Self {
        Self {
            pointer,
            revocations: BTreeMap::new(),
            rotations: BTreeMap::new(),
        }
    }

    /// Fold one verified revocation into the view, append-only.
    ///
    /// # Errors
    /// [`RevocationError::RecordDisagreement`] for a record naming
    /// another client than the view's,
    /// [`RevocationError::InconsistentView`] for an epoch the pointer
    /// has not reached, a current-epoch revocation naming a half the
    /// pointer does not hold, or different revocation bytes already
    /// folded at the same epoch. A re-delivered identical revocation is
    /// idempotent success.
    pub fn record_revocation(&mut self, record: &RevocationRecord) -> Result<(), RevocationError> {
        if record.client_id() != self.pointer.client_id() {
            return Err(RevocationError::RecordDisagreement);
        }
        if record.epoch() > self.pointer.epoch() {
            // One cannot pre-revoke an epoch the client has not reached:
            // a revocation ahead of the pointer would arm itself against
            // a legitimate later rotation (the corpus's `epoch-unreached`).
            return Err(RevocationError::InconsistentView);
        }
        if record.epoch() == self.pointer.epoch()
            && record.revoked_key_id() != self.pointer.key_id()
        {
            // At the current epoch the pointer's half is checkable, and
            // the record must name it (`key-id-mismatch`). Below the
            // current epoch the historical halves are not in the view;
            // the signature is the only witness, and the decision rules
            // below need none.
            return Err(RevocationError::InconsistentView);
        }
        match self.revocations.get(&record.epoch()) {
            Some(existing) if existing == record.revoked_key_id() => {
                // The same revocation delivered twice — a retrying
                // reader's idempotent repair, never an overwrite.
                Ok(())
            }
            Some(_) => Err(RevocationError::InconsistentView),
            None => {
                self.revocations
                    .insert(record.epoch(), *record.revoked_key_id());
                Ok(())
            }
        }
    }

    /// The view's current pointer.
    #[must_use]
    pub const fn pointer(&self) -> &LinkedClientPointer {
        &self.pointer
    }

    /// Every folded revocation as `(epoch, revoked key ID)`, ascending.
    pub fn revocations(&self) -> impl Iterator<Item = (u64, &KeyId)> {
        self.revocations.iter().map(|(epoch, key)| (*epoch, key))
    }

    /// Fold one verified key rotation into the view, append-only — the
    /// same fold [`Self::record_revocation`] runs, with the rotation's
    /// new half where the revocation's named half stands.
    ///
    /// # Errors
    /// [`RevocationError::RecordDisagreement`] for a record naming
    /// another client than the view's,
    /// [`RevocationError::InconsistentView`] for an established epoch
    /// the pointer has not reached, a rotation at the pointer's epoch
    /// whose new half the pointer does not carry, or different rotation
    /// bytes already folded at the same epoch. A re-delivered identical
    /// rotation is idempotent success.
    pub fn record_rotation(&mut self, record: &RotationRecord) -> Result<(), RevocationError> {
        if record.client_id() != self.pointer.client_id() {
            return Err(RevocationError::RecordDisagreement);
        }
        if record.epoch() > self.pointer.epoch() {
            // One cannot pre-date a rotation for an epoch the client has
            // not reached: a forward-dated rotation would arm its
            // overlap window early (the schema's epoch rule).
            return Err(RevocationError::InconsistentView);
        }
        if record.epoch() == self.pointer.epoch() && record.key_id() != self.pointer.key_id() {
            // The rotation and the pointer bump that activates it are
            // one administrative act, so at the current epoch the
            // pointer must carry the rotation's new half.
            return Err(RevocationError::InconsistentView);
        }
        match self.rotations.get(&record.epoch()) {
            Some(existing) if existing == record => {
                // The same rotation delivered twice — a retrying
                // reader's idempotent repair, never an overwrite.
                Ok(())
            }
            Some(_) => Err(RevocationError::InconsistentView),
            None => {
                self.rotations.insert(record.epoch(), record.clone());
                Ok(())
            }
        }
    }

    /// Every folded rotation as `(established epoch, record)`, ascending.
    pub fn rotations(&self) -> impl Iterator<Item = (u64, &RotationRecord)> {
        self.rotations
            .iter()
            .map(|(epoch, record)| (*epoch, record))
    }

    /// Evaluate one client attempt: may `attempt`'s key authorize at
    /// `attempt`'s epoch, given this view?
    ///
    /// The decision order is the module's contract (see the module docs):
    /// client, epoch reachability, revocation, staleness, pointer half.
    /// A revoked epoch reports [`AttemptRejection::Revoked`] even though
    /// it is also stale — the record is the sharper evidence — and an
    /// epoch below the pointer with no revocation naming it reports
    /// [`AttemptRejection::StaleEpoch`]: a rotation without a revocation
    /// strands the old epoch, and a revocation without the completing
    /// pointer would leave it accepted until the pointer propagates,
    /// which is exactly the bounded window the plan accepts.
    ///
    /// This is [`Self::evaluate_at`] with every rotation window closed —
    /// the conservative rule a caller falls back to when it cannot name
    /// the instant it is deciding at.
    ///
    /// # Errors
    /// The matching [`AttemptRejection`] class; `Ok(())` only when the
    /// attempt presents the pointer's own half at the pointer's own
    /// epoch and no revocation names that key at or below it.
    pub fn evaluate(&self, attempt: &AuthorizationAttempt) -> Result<(), AttemptRejection> {
        self.standing(attempt)?;
        if attempt.key_id == *self.pointer.key_id() {
            return Ok(());
        }
        Err(AttemptRejection::KeyEpochMismatch)
    }

    /// Evaluate one client attempt at an explicit instant — the decision
    /// [`Self::evaluate`] renders with the rotation overlap open, and
    /// the instant is where the overlap lives.
    ///
    /// The shared prefix is the module's contract: client, epoch
    /// reachability, revocation, staleness — staleness decided before
    /// the window is ever consulted, so an old epoch stays dead inside
    /// every window, and a revocation outranking the window, because a
    /// dead key never reschedules itself. Past them, an attempt at the
    /// pointer's epoch presenting a half the pointer does not hold is
    /// admitted exactly when a rotation that established the current
    /// epoch is folded, its 24-hour window
    /// ([`RotationRecord::window_covers`]) covers `at`, and the half is
    /// that rotation's previous one — the retry path of an
    /// already-frozen spool envelope, which re-authorizes with fresh
    /// per-attempt state under either half instead of stranding there
    /// (plan Section 5; EC-12).
    ///
    /// # Errors
    /// The matching [`AttemptRejection`] class, as [`Self::evaluate`];
    /// `Ok(())` additionally admits the establishing rotation's previous
    /// half inside its window.
    pub fn evaluate_at(
        &self,
        attempt: &AuthorizationAttempt,
        at: &Timestamp,
    ) -> Result<(), AttemptRejection> {
        self.standing(attempt)?;
        if attempt.key_id == *self.pointer.key_id() {
            return Ok(());
        }
        if let Some(rotation) = self.rotations.get(&self.pointer.epoch())
            && rotation.window_covers(at)
            && attempt.key_id == *rotation.previous_key_id()
        {
            return Ok(());
        }
        Err(AttemptRejection::KeyEpochMismatch)
    }

    /// The decision prefix both evaluations share: the client, the
    /// epoch's reachability, revocation, staleness. `Ok(())` means the
    /// attempt stands at the pointer's epoch, un-revoked — both
    /// decisions then narrow on the half the attempt presents.
    fn standing(&self, attempt: &AuthorizationAttempt) -> Result<(), AttemptRejection> {
        if attempt.client_id != *self.pointer.client_id() {
            return Err(AttemptRejection::ClientMismatch);
        }
        if attempt.epoch == 0 || attempt.epoch > self.pointer.epoch() {
            // Epochs are one-based: zero was never established, and an
            // epoch above the pointer is not established yet — no
            // attempt may present either.
            return Err(AttemptRejection::EpochBeyondPointer);
        }
        for (epoch, revoked) in self.revocations.range(..=attempt.epoch).rev() {
            if *revoked == attempt.key_id {
                // The key died at `epoch` and the attempt presents it
                // now: dead at its own epoch and dead at every later
                // one, because no record can slide the boundary back.
                return Err(AttemptRejection::Revoked);
            }
            if *epoch == attempt.epoch {
                // The attempt names a revoked epoch with a key that
                // epoch's revocation does not name — a forged epoch/key
                // pairing, rejected on the record alone.
                return Err(AttemptRejection::KeyEpochMismatch);
            }
        }
        if attempt.epoch < self.pointer.epoch() {
            // Staleness is decided before any rotation window is
            // consulted: the window widens which key may sign at the
            // current epoch, never which epoch is current.
            return Err(AttemptRejection::StaleEpoch);
        }
        Ok(())
    }
}

/// One client attempt as the runtime decision sees it: the linked client,
/// the authorization epoch the attempt presents, and the key ID the
/// attempt signs with.
///
/// The members are already-validated vocabulary types; the one rule the
/// constructor adds is the one-based epoch floor, so an attempt that
/// cannot be evaluated cannot be constructed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationAttempt {
    /// The linked client presenting the attempt.
    pub client_id: ClientId,
    /// The authorization epoch the attempt presents — the epoch of the
    /// linked-client record whose key the attempt signs with.
    pub epoch: u64,
    /// The key ID the attempt signs with, under the pinned derivation.
    pub key_id: KeyId,
}

impl AuthorizationAttempt {
    /// Build an attempt. `None` for a zero epoch: authorization epochs
    /// are one-based, and no attempt can present an epoch that no
    /// linked-client record ever established.
    #[must_use]
    pub fn new(client_id: ClientId, epoch: u64, key_id: KeyId) -> Option<Self> {
        (epoch >= 1).then_some(Self {
            client_id,
            epoch,
            key_id,
        })
    }
}

/// Why an attempt is rejected: the closed decision classes a replica
/// reports. Every variant is fail-closed — none is retryable against the
/// same evidence, and none carries the offending identifiers (CFG-027).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptRejection {
    /// The attempt names a client other than the view's.
    ClientMismatch,
    /// The attempt presents an epoch the client's pointer has not
    /// reached — including epoch zero, which no pointer ever
    /// established.
    EpochBeyondPointer,
    /// The attempt presents an epoch below the pointer's current one:
    /// dead against the completing pointer, revocation or not.
    StaleEpoch,
    /// A verified revocation names the attempt's key at or below the
    /// attempt's epoch: the key is dead, permanently.
    Revoked,
    /// The attempt's key does not match its epoch's authority — the
    /// pointer's half at the current epoch (or, inside its 24-hour
    /// window, the establishing rotation's previous half), or the
    /// revocation's named half at a revoked one.
    KeyEpochMismatch,
}

impl AttemptRejection {
    /// The class's content-free display text.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::ClientMismatch => "client-mismatch",
            Self::EpochBeyondPointer => "epoch-beyond-pointer",
            Self::StaleEpoch => "stale-epoch",
            Self::Revoked => "revoked",
            Self::KeyEpochMismatch => "key-epoch-mismatch",
        }
    }
}

impl fmt::Display for AttemptRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for AttemptRejection {}

/// Why the offline authority refused to publish a revocation: the closed
/// set of write-time rejections the family pins, mirroring the corpus's
/// classes. A refused publication produced no bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PublicationError {
    /// A member the authority supplies is outside its grammar: a zero
    /// epoch or a `signed_at` that is not a real calendar instant.
    MalformedInput,
    /// The revocation names an epoch above the client's pointer: no
    /// forward-dated revocation (the corpus's `epoch-unreached`).
    EpochUnreached,
    /// The revocation names the pointer's current epoch with a half the
    /// pointer does not hold (the corpus's `key-id-mismatch`).
    KeyIdMismatch,
}

impl PublicationError {
    /// The class's content-free display text.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::MalformedInput => "malformed-input",
            Self::EpochUnreached => "epoch-unreached",
            Self::KeyIdMismatch => "key-id-mismatch",
        }
    }
}

impl fmt::Display for PublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for PublicationError {}

/// A published revocation: the byte-exact canonical envelope and the
/// object key the offline store writes it to, in one value so the two can
/// never drift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationPublication {
    envelope: Vec<u8>,
    object_key: String,
}

impl RevocationPublication {
    /// The canonical record bytes. A lost-response retry re-derives
    /// these byte-identically, which is what makes the store's
    /// identical-bytes rule an idempotent repair.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// The object key
    /// `tenants/<tenant>/v1/control/revocations/<client>/<epoch>.json`
    /// the envelope is written to (plan Section 7.5).
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }
}

/// A published client-key rotation: the byte-exact canonical envelope and
/// the epoch-addressed object key the offline store writes it to, in one
/// value so the two cannot drift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationPublication {
    envelope: Vec<u8>,
    object_key: String,
}

impl RotationPublication {
    /// The canonical, authority-signed rotation record bytes.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// The object key
    /// `tenants/<tenant>/v1/control/rotations/<client>/<epoch>.json`.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }
}

/// Publish one revocation: build the record from validated members,
/// enforce the family's append-only epoch rules against the client's
/// current pointer, sign it with the tenant authority's key, and return
/// the envelope with the object key it is written to.
///
/// The epoch rules mirror the corpus's pinned classes: an epoch above the
/// pointer's is [`PublicationError::EpochUnreached`] — one cannot
/// pre-revoke an epoch the client has not reached — and naming the
/// pointer's current epoch with a half the pointer does not hold is
/// [`PublicationError::KeyIdMismatch`]. Below the current epoch the
/// historical half is the administrator's own record; the signature, not
/// the pointer view, is what makes it authoritative. Completing the
/// revocation — the strictly higher-epoch pointer with the replacement
/// key — is the linked-client family's publication, composed by the same
/// administrator act.
///
/// The signing seed is the tenant authority's private half and enters
/// only as a borrowed slice, the same discipline every signing surface
/// here holds (SEC-004, SEC-006); the record carries its public
/// derivation only.
///
/// # Errors
/// [`PublicationError::MalformedInput`] for a zero epoch or a
/// calendar-invalid instant, [`PublicationError::EpochUnreached`] and
/// [`PublicationError::KeyIdMismatch`] for the two epoch rules.
pub fn publish_revocation(
    authority_seed: &[u8; 32],
    tenant: &TenantId,
    client: &ClientId,
    revoke_epoch: u64,
    revoked_key_id: &KeyId,
    pointer: &LinkedClientPointer,
    signed_at: &Timestamp,
) -> Result<RevocationPublication, PublicationError> {
    if revoke_epoch == 0 || !signed_at.calendar_valid() {
        return Err(PublicationError::MalformedInput);
    }
    if revoke_epoch > pointer.epoch() {
        return Err(PublicationError::EpochUnreached);
    }
    if revoke_epoch == pointer.epoch() && revoked_key_id != pointer.key_id() {
        return Err(PublicationError::KeyIdMismatch);
    }
    let authority_public = ed25519::public_key_from_seed(authority_seed);
    let authority_key_id = KeyId::from_public_key(&Ed25519PublicKey::from_raw(authority_public));
    let mut members = Object::new();
    members.set("schema", text(CONTROL_NAMESPACE));
    members.set("record_type", text("revocation"));
    members.set("record_kind", text("immutable"));
    members.set("tenant_id", text(tenant.as_str()));
    members.set("client_id", text(client.as_str()));
    members.set("revoked_key_id", text(&revoked_key_id.to_hex()));
    members.set(
        "authorization_epoch",
        Value::Int(i64::try_from(revoke_epoch).map_err(|_| PublicationError::MalformedInput)?),
    );
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
    let envelope = Value::Object(members).canonical_bytes();
    Ok(RevocationPublication {
        object_key: revocation_object_key(tenant, client, revoke_epoch),
        envelope,
    })
}

/// The object key of one revocation record (plan Section 7.5), the layout
/// `schemas/v1/control-revocation.json`'s `objectKey` pattern pins.
#[must_use]
pub fn revocation_object_key(tenant: &TenantId, client: &ClientId, epoch: u64) -> String {
    format!(
        "tenants/{}/v1/control/revocations/{}/{}.json",
        tenant.as_str(),
        client.as_str(),
        epoch
    )
}

/// Publish one client-key rotation from the verified current pointer.
///
/// The pointer is the new epoch's already-signed current record: its epoch
/// must be at least two, and its key ID must be the derivation of
/// `public_key`. The rotation record then names the adjacent predecessor
/// epoch and derives `previous_key_id` from `previous_public_key`. This
/// keeps the publication's immutable evidence and the pointer it activates
/// aligned while leaving the store's strictly-increasing pointer write as
/// the final monotonicity gate.
///
/// The private halves never enter this function. The caller supplies only
/// the two public halves; the tenant authority signs the resulting record.
///
/// # Errors
/// [`PublicationError::MalformedInput`] for a first-epoch pointer or a
/// calendar-invalid instant, and [`PublicationError::KeyIdMismatch`] when
/// the new half does not match the pointer or the two halves are identical.
pub fn publish_rotation(
    authority_seed: &[u8; 32],
    tenant: &TenantId,
    client: &ClientId,
    previous_public_key: &Ed25519PublicKey,
    public_key: &Ed25519PublicKey,
    pointer: &LinkedClientPointer,
    signed_at: &Timestamp,
) -> Result<RotationPublication, PublicationError> {
    if pointer.epoch() < 2 || !signed_at.calendar_valid() {
        return Err(PublicationError::MalformedInput);
    }
    if pointer.client_id() != client
        || previous_public_key == public_key
        || pointer.key_id() != &KeyId::from_public_key(public_key)
    {
        return Err(PublicationError::KeyIdMismatch);
    }
    let epoch = pointer.epoch();
    let previous_epoch = epoch - 1;
    let epoch_value = i64::try_from(epoch).map_err(|_| PublicationError::MalformedInput)?;
    let previous_epoch_value =
        i64::try_from(previous_epoch).map_err(|_| PublicationError::MalformedInput)?;
    let authority_public = ed25519::public_key_from_seed(authority_seed);
    let authority_key_id = KeyId::from_public_key(&Ed25519PublicKey::from_raw(authority_public));
    let previous_key_id = KeyId::from_public_key(previous_public_key);
    let key_id = KeyId::from_public_key(public_key);
    let mut members = Object::new();
    members.set("schema", text(CONTROL_NAMESPACE));
    members.set("record_type", text("rotation"));
    members.set("record_kind", text("immutable"));
    members.set("tenant_id", text(tenant.as_str()));
    members.set("client_id", text(client.as_str()));
    members.set("previous_epoch", Value::Int(previous_epoch_value));
    members.set("previous_public_key", text(&previous_public_key.to_hex()));
    members.set("previous_key_id", text(&previous_key_id.to_hex()));
    members.set("key_algorithm", text("ed25519"));
    members.set("public_key", text(&public_key.to_hex()));
    members.set("key_id", text(&key_id.to_hex()));
    members.set("authorization_epoch", Value::Int(epoch_value));
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
    Ok(RotationPublication {
        object_key: rotation_object_key(tenant, client, epoch),
        envelope: Value::Object(members).canonical_bytes(),
    })
}

/// The object key of one client-key rotation, addressed by the epoch it
/// establishes.
#[must_use]
pub fn rotation_object_key(tenant: &TenantId, client: &ClientId, epoch: u64) -> String {
    format!(
        "tenants/{}/v1/control/rotations/{}/{}.json",
        tenant.as_str(),
        client.as_str(),
        epoch
    )
}

/// The object key of one client's linked-client pointer (plan Section
/// 7.5): the current-pointer key no revocation ever occupies.
#[must_use]
pub fn client_pointer_object_key(tenant: &TenantId, client: &ClientId) -> String {
    format!(
        "tenants/{}/v1/control/clients/{}.json",
        tenant.as_str(),
        client.as_str()
    )
}

/// Reject any member set other than exactly `expected` — the closed
/// shape's `additionalProperties: false`, checked as one step so an
/// extra member is a malformed record and not a smuggled payload.
fn verify_member_set(object: &Object, expected: &[&str]) -> Result<(), RevocationError> {
    if object.len() != expected.len() {
        return Err(RevocationError::MalformedRecord);
    }
    for name in expected {
        if !object.contains(name) {
            return Err(RevocationError::MalformedRecord);
        }
    }
    Ok(())
}

/// Read one text member, failing closed when it is absent or not text.
fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Read the signed `authorization_epoch`: a positive integer inside the
/// u64 range the 18-digit ceiling bounds.
fn epoch_member(object: &Object) -> Result<u64, RevocationError> {
    epoch_member_named(object, "authorization_epoch")
}

/// Read one named epoch member — `authorization_epoch` or a rotation's
/// `previous_epoch` — under the same one-based grammar: a positive
/// integer inside the u64 range the 18-digit ceiling bounds. Every
/// epoch a control record names was established by a linked-client
/// record, and those epochs are one-based, so zero is outside every
/// epoch member's grammar.
fn epoch_member_named(object: &Object, name: &str) -> Result<u64, RevocationError> {
    match object.get(name) {
        Some(Value::Int(value)) if *value >= 1 => {
            u64::try_from(*value).map_err(|_| RevocationError::MalformedRecord)
        }
        _ => Err(RevocationError::MalformedRecord),
    }
}

/// Whether `value` is the linked-client record schema's `scopes` member
/// (`schemas/v1/control-client.json`, `additionalProperties: false`):
/// an object carrying exactly the `harnesses` and `operations`
/// allowlists, each a non-empty array of at most 64 non-empty text
/// tokens. Which tokens those are is the family's grammar, not the
/// revocation decision's.
fn scopes_allowlist_object(value: Option<&Value>) -> bool {
    const SCOPE_BOUND: usize = 64;
    let Some(Value::Object(scopes)) = value else {
        return false;
    };
    if scopes.len() != 2 || !scopes.contains("harnesses") || !scopes.contains("operations") {
        return false;
    }
    let allowlist = |name: &str| match scopes.get(name) {
        Some(Value::Array(items)) => {
            !items.is_empty()
                && items.len() <= SCOPE_BOUND
                && items
                    .iter()
                    .all(|item| matches!(item, Value::Text(token) if !token.is_empty()))
        }
        _ => false,
    };
    allowlist("harnesses") && allowlist("operations")
}

/// A canonical text value, for the record builders.
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tenant and client identifiers the committed corpus pins —
    /// synthetic fixture UUIDs, stable across the family's vectors.
    const TENANT: &str = "3e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30";
    const CLIENT: &str = "c7d8e9f0-1a2b-4c3d-9e4f-5a6b7c8d9e0f";
    /// Instants inside the authority chain's acceptance windows: the
    /// records' own `signed_at` values, never the read time.
    const LINK_INSTANT: &str = "2026-09-13T00:00:00Z";
    const REVOKE_INSTANT: &str = "2026-09-13T02:00:00Z";
    const RELINK_INSTANT: &str = "2026-09-13T03:00:00Z";
    const ROTATE_INSTANT: &str = "2026-09-14T01:00:00Z";

    /// The authority's seed and the three client keys, fixed by test
    /// vector so every record in this module's tests is reproducible.
    const AUTHORITY_SEED: [u8; 32] = [7; 32];
    const KEY1_SEED: [u8; 32] = [11; 32];
    const KEY2_SEED: [u8; 32] = [12; 32];
    const KEY3_SEED: [u8; 32] = [13; 32];

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).expect("pinned tenant uuid")
    }

    fn client() -> ClientId {
        ClientId::parse(CLIENT).expect("pinned client uuid")
    }

    fn root() -> PinnedAuthorityRoot {
        PinnedAuthorityRoot::new(tenant(), public_half(&AUTHORITY_SEED))
    }

    fn public_half(seed: &[u8; 32]) -> Ed25519PublicKey {
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(seed))
    }

    fn key_id(seed: &[u8; 32]) -> KeyId {
        KeyId::from_public_key(&public_half(seed))
    }

    fn instant(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("pinned test instant")
    }

    /// Sign `members` with `seed` under the control-record-v1
    /// construction: canonical bytes without the signature, then the
    /// signature appended.
    fn signed(seed: &[u8; 32], mut members: Object) -> Vec<u8> {
        let signature = ed25519::sign(seed, &Value::Object(members.clone()).canonical_bytes());
        members.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        Value::Object(members).canonical_bytes()
    }

    /// The linked-client record linking `client` at `epoch` with the
    /// half `key_seed` derives, signed by the authority.
    fn linked_client(epoch: u64, key_seed: &[u8; 32], signed_at: &str) -> Vec<u8> {
        let half = public_half(key_seed);
        let mut members = Object::new();
        members.set("schema", text(CONTROL_NAMESPACE));
        members.set("record_type", text("linked-client"));
        members.set("record_kind", text("current-pointer"));
        members.set("tenant_id", text(TENANT));
        members.set("client_id", text(CLIENT));
        members.set("key_id", text(&KeyId::from_public_key(&half).to_hex()));
        members.set("key_algorithm", text("ed25519"));
        members.set("public_key", text(&half.to_hex()));
        let mut scopes = Object::new();
        scopes.set("harnesses", Value::Array(vec![text("claude-code")]));
        scopes.set("operations", Value::Array(vec![text("ingest")]));
        members.set("scopes", Value::Object(scopes));
        members.set("authorization_epoch", Value::Int(epoch.cast_signed()));
        members.set("signed_at", text(signed_at));
        members.set("authority_key_id", text(&key_id(&AUTHORITY_SEED).to_hex()));
        signed(&AUTHORITY_SEED, members)
    }

    /// The revocation record revoking `client` at `epoch` — the half
    /// `revoked_seed` derives — signed by the authority.
    fn revocation(epoch: u64, revoked_seed: &[u8; 32], signed_at: &str) -> Vec<u8> {
        publish_revocation(
            &AUTHORITY_SEED,
            &tenant(),
            &client(),
            epoch,
            &key_id(revoked_seed),
            &pointer_at(epoch, revoked_seed),
            &instant(signed_at),
        )
        .expect("the fixture revocation names the pointer's own half")
        .envelope()
        .to_vec()
    }

    /// A pointer at `epoch` holding the half `key_seed` derives — the
    /// verifier never sees the bytes, only the verified triple, so the
    /// fixtures build the triple directly for publication targets.
    fn pointer_at(epoch: u64, key_seed: &[u8; 32]) -> LinkedClientPointer {
        LinkedClientPointer {
            client_id: client(),
            epoch,
            key_id: key_id(key_seed),
        }
    }

    /// Verify a fixture pointer from its bytes.
    fn verified_pointer(bytes: &[u8]) -> LinkedClientPointer {
        LinkedClientPointer::verify(&root(), bytes, |_| None, &client())
            .expect("the fixture pointer verifies")
    }

    /// The pointer and revocation of the corpus's canonical history:
    /// link at epoch 1, revoke epoch 1, relink at epoch 2.
    fn linked_view() -> (LinkedClientPointer, RevocationRecord) {
        let pointer = verified_pointer(&linked_client(1, &KEY1_SEED, LINK_INSTANT));
        let record = RevocationRecord::verify(
            &root(),
            &revocation(1, &KEY1_SEED, REVOKE_INSTANT),
            |_| None,
            &client(),
            1,
        )
        .expect("the fixture revocation verifies");
        (pointer, record)
    }

    /// The signed rotation from the epoch-1 half to the epoch-2 half. The
    /// epoch-2 pointer is the activation record the offline administrator
    /// publishes alongside this immutable evidence.
    fn rotation() -> Vec<u8> {
        publish_rotation(
            &AUTHORITY_SEED,
            &tenant(),
            &client(),
            &public_half(&KEY1_SEED),
            &public_half(&KEY2_SEED),
            &pointer_at(2, &KEY2_SEED),
            &instant(ROTATE_INSTANT),
        )
        .expect("the fixture rotation matches the epoch-2 pointer")
        .envelope()
        .to_vec()
    }

    #[test]
    fn published_record_round_trips_through_verification() {
        let pointer = verified_pointer(&linked_client(1, &KEY1_SEED, LINK_INSTANT));
        let publication = publish_revocation(
            &AUTHORITY_SEED,
            &tenant(),
            &client(),
            1,
            &key_id(&KEY1_SEED),
            &pointer,
            &instant(REVOKE_INSTANT),
        )
        .expect("the current half at the current epoch publishes");
        assert_eq!(
            publication.object_key(),
            revocation_object_key(&tenant(), &client(), 1),
            "the publication names the epoch-addressed key"
        );
        assert_eq!(
            publication.object_key(),
            format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/1.json"),
            "the key follows the plan Section 7.5 layout"
        );
        let record =
            RevocationRecord::verify(&root(), publication.envelope(), |_| None, &client(), 1)
                .expect("the published bytes verify");
        assert_eq!(record.epoch(), 1);
        assert_eq!(record.revoked_key_id(), &key_id(&KEY1_SEED));
        assert_eq!(record.tenant_id(), &tenant());
        assert_eq!(record.client_id(), &client());
        assert_eq!(record.signed_at().as_str(), REVOKE_INSTANT);
        // Canonical in, canonical out: a retry re-derives byte-identical
        // evidence, which is what makes the store's identical-bytes rule
        // an idempotent repair.
        assert_eq!(
            Value::Object(match json::parse(publication.envelope()).expect("json") {
                Value::Object(object) => object,
                _ => panic!("object"),
            })
            .canonical_bytes(),
            publication.envelope(),
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn revocation_verification_fails_closed_on_every_contract_rule() {
        let good = revocation(1, &KEY1_SEED, REVOKE_INSTANT);
        let rewritten = |edit: &dyn Fn(&mut Object)| {
            let Value::Object(mut object) = json::parse(&good).expect("json") else {
                panic!("object");
            };
            edit(&mut object);
            Value::Object(object).canonical_bytes()
        };

        // Shape: not JSON, not an object, an extra member, a missing
        // member, a non-text member.
        assert_eq!(
            RevocationRecord::verify(&root(), b"not json", |_| None, &client(), 1).unwrap_err(),
            RevocationError::MalformedRecord
        );
        assert_eq!(
            RevocationRecord::verify(&root(), b"[1]", |_| None, &client(), 1).unwrap_err(),
            RevocationError::MalformedRecord
        );
        assert_eq!(
            RevocationRecord::verify(
                &root(),
                &rewritten(&|o| o.set("extra", Value::Int(1))),
                |_| None,
                &client(),
                1
            )
            .unwrap_err(),
            RevocationError::MalformedRecord
        );
        assert_eq!(
            RevocationRecord::verify(
                &root(),
                &rewritten(&|o| {
                    let _ = o.remove("revoked_key_id");
                }),
                |_| None,
                &client(),
                1
            )
            .unwrap_err(),
            RevocationError::MalformedRecord
        );

        // Identity: foreign namespace, wrong record type, wrong write
        // class.
        for (name, value) in [
            ("schema", "archivist.control/v2"),
            ("record_type", "rotation"),
            ("record_kind", "current-pointer"),
        ] {
            assert_eq!(
                RevocationRecord::verify(
                    &root(),
                    &rewritten(&|o| o.set(name, text(value))),
                    |_| None,
                    &client(),
                    1
                )
                .unwrap_err(),
                RevocationError::RecordDisagreement,
                "{name} disagreement must be its own class"
            );
        }

        // Grammars and calendar: tenant, client, key ID, epoch, instant.
        for (name, value) in [
            ("tenant_id", "not-a-uuid"),
            ("client_id", "not-a-uuid"),
            ("revoked_key_id", "zz"),
            ("signed_at", "2026-02-30T00:00:00Z"),
        ] {
            assert_eq!(
                RevocationRecord::verify(
                    &root(),
                    &rewritten(&|o| o.set(name, text(value))),
                    |_| None,
                    &client(),
                    1
                )
                .unwrap_err(),
                RevocationError::MalformedRecord,
                "{name} grammar failure must be malformed"
            );
        }
        assert_eq!(
            RevocationRecord::verify(
                &root(),
                &rewritten(&|o| o.set("authorization_epoch", Value::Int(0))),
                |_| None,
                &client(),
                1
            )
            .unwrap_err(),
            RevocationError::MalformedRecord,
            "epoch zero is outside the one-based grammar"
        );

        // Address disagreement: the record must name the client and the
        // epoch it was served at.
        let other_client =
            ClientId::parse("d8e9f0a1-2b3c-4d4e-9f50-6b7c8d9e0f11").expect("second fixture uuid");
        assert_eq!(
            RevocationRecord::verify(&root(), &good, |_| None, &other_client, 1).unwrap_err(),
            RevocationError::RecordDisagreement,
            "a record under another client's address is a disagreement"
        );
        assert_eq!(
            RevocationRecord::verify(&root(), &good, |_| None, &client(), 2).unwrap_err(),
            RevocationError::RecordDisagreement,
            "a record at another epoch's key is a disagreement"
        );

        // Cross-tenant: a record of another tenant under this root is a
        // forgery, not a naming oddity.
        let other_tenant =
            TenantId::parse("4a5b6c7d-8e9f-4a0b-8c3d-4e5f6a7b8c9d").expect("other fixture tenant");
        assert_eq!(
            RevocationRecord::verify(
                &PinnedAuthorityRoot::new(other_tenant, public_half(&AUTHORITY_SEED)),
                &good,
                |_| None,
                &client(),
                1
            )
            .unwrap_err(),
            RevocationError::RecordDisagreement
        );

        // Untrusted authority: a signature that is not the signer's, a
        // signer the pinned root does not vouch for.
        assert_eq!(
            RevocationRecord::verify(
                &root(),
                &rewritten(&|o| {
                    let signature = ed25519::sign(&KEY1_SEED, b"some other message");
                    o.set(
                        "authority_signature",
                        text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
                    );
                }),
                |_| None,
                &client(),
                1
            )
            .unwrap_err(),
            RevocationError::UntrustedAuthority
        );
        let impostor = PinnedAuthorityRoot::new(tenant(), public_half(&KEY2_SEED));
        assert_eq!(
            RevocationRecord::verify(&impostor, &good, |_| None, &client(), 1).unwrap_err(),
            RevocationError::UntrustedAuthority,
            "a root the record was not signed under rejects it"
        );
    }

    #[test]
    fn pointer_verification_carries_the_identity_triple_and_fails_closed() {
        let bytes = linked_client(2, &KEY2_SEED, RELINK_INSTANT);
        let pointer = verified_pointer(&bytes);
        assert_eq!(pointer.epoch(), 2);
        assert_eq!(pointer.key_id(), &key_id(&KEY2_SEED));
        assert_eq!(pointer.client_id(), &client());

        // The key ID is the derivation of the record's own half: an
        // edited pair is a disagreement before the signature is read.
        let Value::Object(mut object) = json::parse(&bytes).expect("json") else {
            panic!("object");
        };
        object.set("key_id", text(&key_id(&KEY3_SEED).to_hex()));
        let signature = ed25519::sign(
            &AUTHORITY_SEED,
            &Value::Object(object.clone()).canonical_bytes(),
        );
        object.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        let re_signed = Value::Object(object).canonical_bytes();
        assert_eq!(
            LinkedClientPointer::verify(&root(), &re_signed, |_| None, &client()).unwrap_err(),
            RevocationError::RecordDisagreement,
            "a key ID that is not its half's derivation is a disagreement"
        );
    }

    #[test]
    fn view_fold_is_append_only() {
        let (pointer, record) = linked_view();
        let mut view = ClientTrustView::new(pointer);
        view.record_revocation(&record)
            .expect("the epoch-1 revocation folds");
        // Identical re-delivery is an idempotent repair.
        view.record_revocation(&record)
            .expect("the same revocation re-delivered is idempotent");

        // No un-revoke: a different revocation at the occupied epoch is
        // an integrity conflict, and the original stays folded.
        let conflicting = RevocationRecord {
            tenant_id: tenant(),
            client_id: client(),
            revoked_key_id: key_id(&KEY2_SEED),
            epoch: 1,
            signed_at: instant(REVOKE_INSTANT),
        };
        assert_eq!(
            view.record_revocation(&conflicting).unwrap_err(),
            RevocationError::InconsistentView,
            "a second, different revocation at one epoch is an integrity conflict"
        );
        assert_eq!(view.revocations().count(), 1, "the fold did not rewrite");

        // No forward-dated revocation: above the pointer's epoch the
        // record does not fold.
        let ahead = RevocationRecord {
            tenant_id: tenant(),
            client_id: client(),
            revoked_key_id: key_id(&KEY1_SEED),
            epoch: 5,
            signed_at: instant(REVOKE_INSTANT),
        };
        assert_eq!(
            view.record_revocation(&ahead).unwrap_err(),
            RevocationError::InconsistentView,
            "an epoch the pointer has not reached cannot be revoked"
        );

        // At the current epoch the record must name the pointer's half.
        let wrong_half = RevocationRecord {
            tenant_id: tenant(),
            client_id: client(),
            revoked_key_id: key_id(&KEY3_SEED),
            epoch: 1,
            signed_at: instant(REVOKE_INSTANT),
        };
        assert_eq!(
            view.record_revocation(&wrong_half).unwrap_err(),
            RevocationError::InconsistentView,
            "a current-epoch revocation naming a foreign half is inconsistent"
        );

        // A revocation of another client never folds into this view.
        let other_client =
            ClientId::parse("d8e9f0a1-2b3c-4d4e-9f50-6b7c8d9e0f11").expect("second fixture uuid");
        let foreign = RevocationRecord {
            tenant_id: tenant(),
            client_id: other_client,
            revoked_key_id: key_id(&KEY1_SEED),
            epoch: 1,
            signed_at: instant(REVOKE_INSTANT),
        };
        assert_eq!(
            view.record_revocation(&foreign).unwrap_err(),
            RevocationError::RecordDisagreement
        );
    }

    #[test]
    fn evaluate_rejects_stale_epochs_after_the_pointer_advances() {
        // Rotation without revocation: the client rotates from epoch 1
        // to epoch 2. The old epoch is stale the moment the pointer
        // advances, revocation or not.
        let pointer = verified_pointer(&linked_client(2, &KEY2_SEED, RELINK_INSTANT));
        let view = ClientTrustView::new(pointer);
        let stale =
            AuthorizationAttempt::new(client(), 1, key_id(&KEY1_SEED)).expect("one-based epoch");
        assert_eq!(view.evaluate(&stale), Err(AttemptRejection::StaleEpoch));
        // The current half at the current epoch is the one acceptance.
        assert_eq!(
            view.evaluate(
                &AuthorizationAttempt::new(client(), 2, key_id(&KEY2_SEED))
                    .expect("one-based epoch")
            ),
            Ok(())
        );
        // Beyond the pointer: not established yet, and epoch zero never.
        assert_eq!(
            view.evaluate(
                &AuthorizationAttempt::new(client(), 3, key_id(&KEY2_SEED)).expect("one-based")
            ),
            Err(AttemptRejection::EpochBeyondPointer)
        );
        assert_eq!(
            view.evaluate(
                &AuthorizationAttempt::new(client(), 2, key_id(&KEY3_SEED)).expect("one-based")
            ),
            Err(AttemptRejection::KeyEpochMismatch),
            "the current epoch authorizes only the pointer's own half"
        );
        // Another client's attempt never evaluates against this view.
        let other_client =
            ClientId::parse("d8e9f0a1-2b3c-4d4e-9f50-6b7c8d9e0f11").expect("second fixture uuid");
        assert_eq!(
            view.evaluate(
                &AuthorizationAttempt::new(other_client, 2, key_id(&KEY2_SEED)).expect("one-based")
            ),
            Err(AttemptRejection::ClientMismatch)
        );
    }

    #[test]
    fn rotation_publication_round_trips_and_is_epoch_addressed() {
        let pointer = verified_pointer(&linked_client(2, &KEY2_SEED, RELINK_INSTANT));
        let publication = publish_rotation(
            &AUTHORITY_SEED,
            &tenant(),
            &client(),
            &public_half(&KEY1_SEED),
            &public_half(&KEY2_SEED),
            &pointer,
            &instant(ROTATE_INSTANT),
        )
        .expect("the new public half matches the pointer");
        assert_eq!(
            publication.object_key(),
            rotation_object_key(&tenant(), &client(), 2)
        );
        assert_eq!(
            publication.object_key(),
            format!("tenants/{TENANT}/v1/control/rotations/{CLIENT}/2.json")
        );
        let record =
            RotationRecord::verify(&root(), publication.envelope(), |_| None, &client(), 2)
                .expect("the published rotation verifies");
        assert_eq!(record.previous_epoch(), 1);
        assert_eq!(record.previous_key_id(), &key_id(&KEY1_SEED));
        assert_eq!(record.epoch(), 2);
        assert_eq!(record.key_id(), &key_id(&KEY2_SEED));
        assert_eq!(record.signed_at().as_str(), ROTATE_INSTANT);
        assert_eq!(
            Value::Object(match json::parse(publication.envelope()).expect("json") {
                Value::Object(object) => object,
                _ => panic!("object"),
            })
            .canonical_bytes(),
            publication.envelope()
        );
    }

    #[test]
    fn rotation_overlap_keeps_current_epoch_retries_live_but_rejects_stale_epochs() {
        let pointer = verified_pointer(&linked_client(2, &KEY2_SEED, RELINK_INSTANT));
        let record = RotationRecord::verify(&root(), &rotation(), |_| None, &client(), 2)
            .expect("the fixture rotation verifies");
        let mut view = ClientTrustView::new(pointer);
        view.record_rotation(&record)
            .expect("the rotation matches the current pointer");

        let old_key = AuthorizationAttempt::new(client(), 2, key_id(&KEY1_SEED))
            .expect("current epoch with the old key");
        let new_key = AuthorizationAttempt::new(client(), 2, key_id(&KEY2_SEED))
            .expect("current epoch with the new key");
        assert_eq!(
            view.evaluate(&old_key),
            Err(AttemptRejection::KeyEpochMismatch),
            "clock-free evaluation never guesses that a rotation window is open"
        );
        assert_eq!(
            view.evaluate_at(&old_key, &instant("2026-09-14T00:59:59Z")),
            Err(AttemptRejection::KeyEpochMismatch),
            "the old half is not valid before the signed rotation"
        );
        assert_eq!(
            view.evaluate_at(&old_key, &instant("2026-09-14T13:00:00Z")),
            Ok(()),
            "a frozen envelope can receive fresh authorization under the old half"
        );
        assert_eq!(
            view.evaluate_at(&old_key, &instant("2026-09-15T01:00:00Z")),
            Ok(()),
            "the documented 24-hour boundary is inclusive"
        );
        assert_eq!(
            view.evaluate_at(&old_key, &instant("2026-09-15T01:00:01Z")),
            Err(AttemptRejection::KeyEpochMismatch),
            "the old half is rejected after the overlap"
        );
        assert_eq!(
            view.evaluate_at(&new_key, &instant("2026-09-20T00:00:00Z")),
            Ok(()),
            "the new half remains valid after the overlap"
        );

        let stale_old = AuthorizationAttempt::new(client(), 1, key_id(&KEY1_SEED))
            .expect("stale epoch with the old key");
        let stale_new = AuthorizationAttempt::new(client(), 1, key_id(&KEY2_SEED))
            .expect("stale epoch with the new key");
        assert_eq!(
            view.evaluate_at(&stale_old, &instant("2026-09-14T13:00:00Z")),
            Err(AttemptRejection::StaleEpoch)
        );
        assert_eq!(
            view.evaluate_at(&stale_new, &instant("2026-09-14T13:00:00Z")),
            Err(AttemptRejection::StaleEpoch)
        );
    }

    #[test]
    fn rotation_record_rejects_non_adjacent_or_same_key_history() {
        let good = rotation();
        let rewritten = |edit: &dyn Fn(&mut Object)| {
            let Value::Object(mut object) = json::parse(&good).expect("json") else {
                panic!("object");
            };
            edit(&mut object);
            signed(&AUTHORITY_SEED, object)
        };

        assert_eq!(
            RotationRecord::verify(
                &root(),
                &rewritten(&|object| object.set("previous_epoch", Value::Int(3))),
                |_| None,
                &client(),
                2,
            )
            .unwrap_err(),
            RevocationError::RecordDisagreement
        );
        assert_eq!(
            RotationRecord::verify(
                &root(),
                &rewritten(&|object| {
                    object.set("previous_key_id", text(&key_id(&KEY2_SEED).to_hex()));
                }),
                |_| None,
                &client(),
                2,
            )
            .unwrap_err(),
            RevocationError::RecordDisagreement
        );
        assert_eq!(
            publish_rotation(
                &AUTHORITY_SEED,
                &tenant(),
                &client(),
                &public_half(&KEY2_SEED),
                &public_half(&KEY2_SEED),
                &pointer_at(2, &KEY2_SEED),
                &instant(ROTATE_INSTANT),
            )
            .unwrap_err(),
            PublicationError::KeyIdMismatch
        );
    }

    #[test]
    fn evaluate_rejects_revoked_keys_fail_closed() {
        // The corpus's canonical history: link 1, revoke (1, K1),
        // relink at 2 with K2.
        let (_, record) = linked_view();
        // The replica's view at the completing pointer's tip, with the
        // still-standing revocation folded (the records are
        // append-only, the replica re-reads them whole).
        let mut view = ClientTrustView::new(verified_pointer(&linked_client(
            2,
            &KEY2_SEED,
            RELINK_INSTANT,
        )));
        view.record_revocation(&record)
            .expect("the revocation folds at the new tip");

        // The revoked epoch is dead twice over — stale against the
        // completing pointer and named dead by the record — and the
        // record is the class reported.
        assert_eq!(
            view.evaluate(
                &AuthorizationAttempt::new(client(), 1, key_id(&KEY1_SEED)).expect("one-based")
            ),
            Err(AttemptRejection::Revoked)
        );
        // Key reuse: presenting the dead key at a later epoch is still
        // dead — no record slides the boundary back.
        assert_eq!(
            view.evaluate(
                &AuthorizationAttempt::new(client(), 2, key_id(&KEY1_SEED)).expect("one-based")
            ),
            Err(AttemptRejection::Revoked),
            "the revoked key is dead at every later epoch too"
        );
        // A forged epoch/key pairing at the revoked epoch.
        assert_eq!(
            view.evaluate(
                &AuthorizationAttempt::new(client(), 1, key_id(&KEY3_SEED)).expect("one-based")
            ),
            Err(AttemptRejection::KeyEpochMismatch)
        );
        // The relinked half at the new epoch is the one acceptance.
        assert_eq!(
            view.evaluate(
                &AuthorizationAttempt::new(client(), 2, key_id(&KEY2_SEED)).expect("one-based")
            ),
            Ok(())
        );
    }

    #[test]
    fn propagation_is_bounded_by_the_trust_record_cache() {
        // t0: the replica's view is the epoch-1 pointer, no revocation
        // folded yet. The attempt is accepted — this is the bounded
        // window the plan accepts.
        let (pointer, record) = linked_view();
        let fresh_view = ClientTrustView::new(pointer.clone());
        assert_eq!(
            fresh_view.evaluate(
                &AuthorizationAttempt::new(client(), 1, key_id(&KEY1_SEED)).expect("one-based")
            ),
            Ok(()),
            "inside the propagation window the pre-revocation view accepts"
        );

        // t0 + 60s: the cache expired, the replica re-read, and the view
        // now carries the revocation and the completing pointer. The
        // same attempt fails closed.
        let mut refreshed = ClientTrustView::new(verified_pointer(&linked_client(
            2,
            &KEY2_SEED,
            RELINK_INSTANT,
        )));
        refreshed
            .record_revocation(&record)
            .expect("the revocation folds");
        assert_eq!(
            refreshed.evaluate(
                &AuthorizationAttempt::new(client(), 1, key_id(&KEY1_SEED)).expect("one-based")
            ),
            Err(AttemptRejection::Revoked),
            "after the bounded window the refreshed view rejects the revoked key"
        );
        assert_eq!(
            refreshed.evaluate(
                &AuthorizationAttempt::new(client(), 2, key_id(&KEY2_SEED)).expect("one-based")
            ),
            Ok(()),
            "the relinked half authorizes after the window"
        );

        // The bound is the schema's own pinned constant, byte-proven
        // from the committed schema file.
        let schema =
            json::parse(include_str!("../../../schemas/v1/control-revocation.json").as_bytes())
                .expect("the committed revocation schema parses");
        let Value::Object(schema) = schema else {
            panic!("object");
        };
        let Some(Value::Object(archivist)) = schema.get("x-archivist") else {
            panic!("x-archivist");
        };
        assert_eq!(
            archivist.get("revocationPropagationBoundSeconds"),
            Some(&Value::Int(
                REVOCATION_PROPAGATION_BOUND_SECONDS.cast_signed(),
            )),
            "the module's bound is the schema's revocationPropagationBoundSeconds"
        );
    }

    #[test]
    fn publication_enforces_the_append_only_epoch_rules() {
        let pointer = verified_pointer(&linked_client(2, &KEY2_SEED, LINK_INSTANT));

        // No forward-dated revocation.
        assert_eq!(
            publish_revocation(
                &AUTHORITY_SEED,
                &tenant(),
                &client(),
                3,
                &key_id(&KEY2_SEED),
                &pointer,
                &instant(REVOKE_INSTANT),
            )
            .unwrap_err(),
            PublicationError::EpochUnreached
        );

        // The current epoch names the pointer's half or nothing.
        assert_eq!(
            publish_revocation(
                &AUTHORITY_SEED,
                &tenant(),
                &client(),
                2,
                &key_id(&KEY3_SEED),
                &pointer,
                &instant(REVOKE_INSTANT),
            )
            .unwrap_err(),
            PublicationError::KeyIdMismatch
        );

        // Malformed inputs: a zero epoch and a calendar-invalid instant.
        assert_eq!(
            publish_revocation(
                &AUTHORITY_SEED,
                &tenant(),
                &client(),
                0,
                &key_id(&KEY2_SEED),
                &pointer,
                &instant(REVOKE_INSTANT),
            )
            .unwrap_err(),
            PublicationError::MalformedInput
        );
        assert_eq!(
            publish_revocation(
                &AUTHORITY_SEED,
                &tenant(),
                &client(),
                2,
                &key_id(&KEY2_SEED),
                &pointer,
                &instant("2026-02-30T00:00:00Z"),
            )
            .unwrap_err(),
            PublicationError::MalformedInput
        );

        // The accepted shape: the current half at the current epoch —
        // and a historical epoch below the pointer, whose half is the
        // administrator's own record.
        assert!(publish_revocation(
            &AUTHORITY_SEED,
            &tenant(),
            &client(),
            2,
            &key_id(&KEY2_SEED),
            &pointer,
            &instant(REVOKE_INSTANT),
        )
        .is_ok());
        assert!(publish_revocation(
            &AUTHORITY_SEED,
            &tenant(),
            &client(),
            1,
            &key_id(&KEY1_SEED),
            &pointer,
            &instant(REVOKE_INSTANT),
        )
        .is_ok());
    }
}
