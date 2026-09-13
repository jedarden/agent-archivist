// SPDX-License-Identifier: Apache-2.0

//! The offline control-administration authority of the S3 adapter (plan
//! Section 5): [`S3ControlAdminStore`], the portable implementation of
//! [`ControlAdminStore`] over a dedicated administration credential.
//!
//! This is the write half of the control-plane boundary. The ingestion
//! replica reads the five signed record families through a read-only
//! credential and never receives this store's credential at all; the
//! administrator CLI is the single writer that does. Everything here is
//! shaped around that split:
//!
//! - **Dedicated protected credential.** The store is configured from a
//!   [`ControlAdminConfig`] — a separate
//!   configuration surface with its own credential reference, never a field
//!   of the ingest [`S3StorageConfig`](crate::config::S3StorageConfig).
//!   [`reject_administration_credential`](crate::config::S3StorageConfig::reject_administration_credential)
//!   refuses the one
//!   composition mistake the type system cannot prevent on its own: mapping
//!   an ingest role onto the administration credential reference.
//! - **Server-derived tenant control keys.** The store accepts complete
//!   signed record envelopes and nothing else — no method takes a key. It
//!   parses the envelope's own validated members and derives the object key
//!   from them ([`ControlObjectKey`]), exactly the layout the control
//!   record registry (`tools/control-records.toml`) and the envelope's
//!   object-key patterns pin (plan Section 7.5, ID-008). A record whose
//!   members do not carry their record family's grammar fails closed before
//!   any request is issued.
//! - **Two write classes.** An immutable family (`revocation`, `rotation`,
//!   `receipt-key`) is written once at its derived key: a byte-identical
//!   re-put is an idempotent success, an incompatible object at the key is
//!   an integrity conflict (`EC-06`). A current-pointer family
//!   (`linked-client`, `delegation`) is replaced only when the presented
//!   record's signed `authorization_epoch` strictly increases over the
//!   stored pointer — equal or lower is a stale write.
//! - **One tenant, one prefix.** The configuration pins the tenant whose
//!   control prefix the administration credential provisions, and
//!   [`permits_key`](crate::config::ControlAdminConfig::permits_key) is the
//!   raw-key model of that scope: the five control
//!   layouts under `tenants/<tenant>/v1/control/`, and nothing else. Every
//!   non-control prefix — raw, catalog, derived, tombstone, legal-hold,
//!   another tenant's control prefix — is denied. The deployment's backend
//!   policy for the administration credential mirrors that predicate
//!   (read-write below the tenant control prefix, deny everything else),
//!   and the compatibility-suite profiles prove it on live backends.
//!
//! # What validation here is and is not
//!
//! The store validates envelopes *structurally*: canonical JSON, the
//! control namespace, the record-type and record-kind agreement the
//! envelope registry pins, every key member's grammar, the epoch rules, and
//! the presence and shape of the wrapper's signature members. It does not
//! verify the tenant-authority signature — cryptographic verification is
//! `archivist-auth`'s Phase 3 contract — and it does not decide trust;
//! readers do. A record that passes here is *addressable* (its members
//! derive one key), not yet *trusted*.
//!
//! # Concurrency
//!
//! The write rules are checked read-then-write against the backend. The
//! control plane is a single-writer surface — the administrator CLI through
//! this store (the control schemas note's single-writer model) — so the
//! sequential check implements the rule the write classes pin; a backend
//! binding may tighten it further with a conditional create where the
//! capability probe reports one, and a versioned backend retains any
//! redundant noncurrent version without changing the logical rule.

use std::fmt;
use std::future::Future;
use std::str::FromStr;

use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{
    ClientId, Ed25519Signature, GrammarError, KeyId, TenantId, Timestamp,
};
use archivist_storage::control::{
    AdminControlRecord, AuthorizationEpoch, ControlAdminStore, ControlRecordKind, ControlWriteClass,
};
use archivist_storage::error::{StorageError, StorageErrorKind};

use crate::config::ControlAdminConfig;

/// Why a candidate object key is not a valid derived control key.
pub type ControlKeyError = GrammarError;

/// The control trust namespace (`archivist.control/v1`, the envelope's
/// `schema` member; decision 1 of the control schemas note).
const CONTROL_NAMESPACE: &str = "archivist.control/v1";

/// The authorization-epoch ceiling the epoch-addressed key grammars and the
/// envelope's `authorization-epoch` bound pin in lockstep: the 18-digit
/// canonical decimal (`schemas/v1/control-envelope.json`).
const EPOCH_MAX: u64 = 999_999_999_999_999_999;

/// The same ceiling as the integer-domain bound the epoch member check
/// compares against (`Value::Int` is `i64`; the ceiling is far inside it).
const EPOCH_MAX_I64: i64 = EPOCH_MAX.cast_signed();

/// The object-key length bound the envelope's key patterns pin.
const KEY_MAX: usize = 512;

// Content-safe detail literals, one static sentence per failure site. A
// unit test pins every one of them against the protocol's safe-message
// grammar, the same discipline `archivist-storage`'s error type keeps.
const DETAIL_NOT_A_RECORD: &str = "envelope does not parse as a control record";
const DETAIL_NAMESPACE: &str = "envelope namespace is not the control namespace";
const DETAIL_INCOMPLETE: &str = "envelope is not a complete signed record of its family";
const DETAIL_TYPE_DISAGREES: &str = "envelope record type disagrees with the presented kind";
const DETAIL_WRITE_METHOD: &str = "record family does not use this write method";
const DETAIL_EPOCH: &str = "authorization epoch is missing or outside its bounds";
const DETAIL_SELF_DELEGATION: &str = "relay and origin name the same client";
const DETAIL_RECEIPT_EPOCH: &str = "receipt-key record carries no authorization epoch";
const DETAIL_IMMUTABLE_CONFLICT: &str = "stored record differs from the presented immutable record";
const DETAIL_POINTER_CONFLICT: &str = "stored pointer is not a valid record of its family";
const DETAIL_SCOPE: &str = "record tenant is outside this administration identity";

/// A server-derived control object key: one of the five canonical layouts
/// below `tenants/<tenant>/v1/control/` (plan Section 7.5; the control
/// record registry's `object_key` entries).
///
/// Construction is the derivation: every constructor takes the validated
/// members the record family's key is derived from — never a caller-chosen
/// string — so a value of this type is a key the envelope's object-key
/// pattern accepts by construction (ID-008). [`ControlObjectKey::parse`]
/// re-makes the same check from the wire side, which is how any reader
/// re-verifies a store's derivation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ControlObjectKey {
    text: String,
    kind: ControlRecordKind,
    tenant: TenantId,
}

impl ControlObjectKey {
    /// Derive the linked-client pointer key:
    /// `tenants/<tenant>/v1/control/clients/<client>.json`.
    #[must_use]
    pub fn linked_client(tenant: &TenantId, client: &ClientId) -> Self {
        Self {
            text: format!("tenants/{tenant}/v1/control/clients/{client}.json"),
            kind: ControlRecordKind::LinkedClient,
            tenant: tenant.clone(),
        }
    }

    /// Derive the delegation pointer key:
    /// `tenants/<tenant>/v1/control/delegations/<relay>/<origin>.json`.
    ///
    /// One object per (relay, origin) pair — the relation a relay grant is
    /// the conjunction over; `relay == origin` is a self-delegation the
    /// store rejects before it ever derives a key, so this constructor
    /// still expects two distinct clients by the time it runs.
    #[must_use]
    pub fn delegation(tenant: &TenantId, relay: &ClientId, origin: &ClientId) -> Self {
        Self {
            text: format!("tenants/{tenant}/v1/control/delegations/{relay}/{origin}.json"),
            kind: ControlRecordKind::Delegation,
            tenant: tenant.clone(),
        }
    }

    /// Derive the revocation key:
    /// `tenants/<tenant>/v1/control/revocations/<client>/<epoch>.json`,
    /// the epoch addressed in canonical decimal.
    #[must_use]
    pub fn revocation(tenant: &TenantId, client: &ClientId, epoch: AuthorizationEpoch) -> Self {
        Self {
            text: format!("tenants/{tenant}/v1/control/revocations/{client}/{epoch}.json"),
            kind: ControlRecordKind::Revocation,
            tenant: tenant.clone(),
        }
    }

    /// Derive the key-rotation key:
    /// `tenants/<tenant>/v1/control/rotations/<client>/<epoch>.json`, the
    /// established epoch addressed in canonical decimal.
    #[must_use]
    pub fn rotation(tenant: &TenantId, client: &ClientId, epoch: AuthorizationEpoch) -> Self {
        Self {
            text: format!("tenants/{tenant}/v1/control/rotations/{client}/{epoch}.json"),
            kind: ControlRecordKind::Rotation,
            tenant: tenant.clone(),
        }
    }

    /// Derive the receipt-key record key:
    /// `tenants/<tenant>/v1/control/receipt-keys/<key>.json`, the certified
    /// key ID under the pinned SHA-256 derivation.
    #[must_use]
    pub fn receipt_key(tenant: &TenantId, key: &KeyId) -> Self {
        Self {
            text: format!("tenants/{tenant}/v1/control/receipt-keys/{key}.json"),
            kind: ControlRecordKind::ReceiptKey,
            tenant: tenant.clone(),
        }
    }

    /// Parse one object key against the five canonical layouts, failing
    /// closed on anything else — every non-control prefix, a malformed
    /// identifier segment, a non-canonical epoch, and a wrong family shape
    /// all refuse rather than normalize.
    ///
    /// # Errors
    /// [`ControlKeyError::NotCanonical`] for any text outside the five
    /// layouts.
    pub fn parse(text: &str) -> Result<Self, ControlKeyError> {
        let invalid = || ControlKeyError::NotCanonical;
        if text.is_empty() || text.len() > KEY_MAX {
            return Err(invalid());
        }
        let mut segments = text.split('/');
        if segments.next() != Some("tenants") {
            return Err(invalid());
        }
        let Some(tenant_text) = segments.next() else {
            return Err(invalid());
        };
        let tenant = TenantId::parse(tenant_text).map_err(|_| invalid())?;
        if segments.next() != Some("v1") || segments.next() != Some("control") {
            return Err(invalid());
        }
        let Some(family) = segments.next() else {
            return Err(invalid());
        };
        match family {
            "clients" => {
                let client = ident_segment(segments.next())?;
                ends_here(segments.next())?;
                Ok(Self::linked_client(&tenant, &client))
            }
            "delegations" => {
                // The layout puts `.json` on the origin segment alone;
                // the relay segment is a bare identifier.
                let relay = bare_client_segment(segments.next())?;
                let origin = ident_segment(segments.next())?;
                ends_here(segments.next())?;
                Ok(Self::delegation(&tenant, &relay, &origin))
            }
            "revocations" => {
                // `.json` rides the epoch segment alone; the client
                // segment is a bare identifier.
                let client = bare_client_segment(segments.next())?;
                let epoch = epoch_segment(segments.next())?;
                ends_here(segments.next())?;
                Ok(Self::revocation(&tenant, &client, epoch))
            }
            "rotations" => {
                let client = bare_client_segment(segments.next())?;
                let epoch = epoch_segment(segments.next())?;
                ends_here(segments.next())?;
                Ok(Self::rotation(&tenant, &client, epoch))
            }
            "receipt-keys" => {
                let key = key_segment(segments.next())?;
                ends_here(segments.next())?;
                Ok(Self::receipt_key(&tenant, &key))
            }
            _ => Err(invalid()),
        }
    }

    /// The key exactly as derived.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The record family whose layout produced this key.
    #[must_use]
    pub const fn kind(&self) -> ControlRecordKind {
        self.kind
    }

    /// The tenant whose control prefix the key lives under.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}

impl fmt::Display for ControlObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl FromStr for ControlObjectKey {
    type Err = ControlKeyError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Parse one `<ident>.json` segment as a client identifier.
fn ident_segment(segment: Option<&str>) -> Result<ClientId, ControlKeyError> {
    let raw = json_named_segment(segment)?;
    ClientId::parse(raw).map_err(|_| ControlKeyError::NotCanonical)
}

/// Parse one bare (suffix-less) segment as a client identifier — the
/// delegation layout's relay position, which carries no `.json`.
fn bare_client_segment(segment: Option<&str>) -> Result<ClientId, ControlKeyError> {
    let raw = segment
        .filter(|body| !body.is_empty())
        .ok_or(ControlKeyError::NotCanonical)?;
    ClientId::parse(raw).map_err(|_| ControlKeyError::NotCanonical)
}

/// Parse one `<key>.json` segment as a key ID.
fn key_segment(segment: Option<&str>) -> Result<KeyId, ControlKeyError> {
    let raw = json_named_segment(segment)?;
    KeyId::parse(raw).map_err(|_| ControlKeyError::NotCanonical)
}

/// Strip the required `.json` suffix from one key segment.
fn json_named_segment(segment: Option<&str>) -> Result<&str, ControlKeyError> {
    segment
        .and_then(|raw| raw.strip_suffix(".json"))
        .filter(|body| !body.is_empty())
        .ok_or(ControlKeyError::NotCanonical)
}

/// Parse one `<epoch>.json` segment as a one-based epoch in canonical
/// decimal — no leading zeros, at most the 18 digits the epoch key grammar
/// and the envelope's epoch bound pin together.
fn epoch_segment(segment: Option<&str>) -> Result<AuthorizationEpoch, ControlKeyError> {
    let raw = json_named_segment(segment)?;
    let bytes = raw.as_bytes();
    let canonical_decimal = !bytes.is_empty()
        && bytes.len() <= 18
        && bytes[0].is_ascii_digit()
        && bytes[0] != b'0'
        && bytes[1..].iter().all(u8::is_ascii_digit);
    if !canonical_decimal {
        return Err(ControlKeyError::NotCanonical);
    }
    AuthorizationEpoch::from_str(raw).map_err(|_| ControlKeyError::NotCanonical)
}

/// Refuse trailing segments after a complete layout.
fn ends_here(next: Option<&str>) -> Result<(), ControlKeyError> {
    if next.is_none() {
        Ok(())
    } else {
        Err(ControlKeyError::NotCanonical)
    }
}

/// The validated view of one control envelope: the family that claims it,
/// the tenant it belongs to, the key its own members derive, and — for the
/// four families whose identity or pointer the epoch is — the signed epoch.
///
/// This is the store's addressing decision and nothing more: it says where
/// a record lives and how a replacement compares, never that the record is
/// trustworthy (verification is `archivist-auth`'s contract).
#[derive(Debug)]
struct ValidatedEnvelope {
    kind: ControlRecordKind,
    tenant: TenantId,
    key: ControlObjectKey,
    epoch: Option<AuthorizationEpoch>,
}

/// Validate one envelope structurally and derive its key, failing closed on
/// every member the derivation and the write rules lean on.
///
/// Checked: canonical JSON and an object at the top level; the control
/// namespace; `record_type` and `record_kind` present, canonical, and in
/// the registry's agreement (the kind the envelope declares is the class
/// its family pins); `tenant_id`; the family's key members; the epoch rules
/// (required and bounded for the four epoch-bearing families, absent for
/// the receipt-key record); and the wrapper's `signed_at`,
/// `authority_key_id`, and `authority_signature` shapes. Payload members
/// beyond the wrapper are the record schema's business — the schema gate
/// (`tools/check-control-schemas.py`) and Phase 3 verification own them.
///
/// # Errors
/// [`StorageErrorKind::MalformedInput`] for the first violated rule; the
/// detail is a static literal and never echoes envelope content.
fn validate_envelope(bytes: &[u8]) -> Result<ValidatedEnvelope, StorageError> {
    let malformed = StorageError::of_kind(StorageErrorKind::MalformedInput);
    let Value::Object(object) = json::parse(bytes).map_err(|_| malformed)? else {
        return Err(StorageError::new(
            StorageErrorKind::MalformedInput,
            DETAIL_NOT_A_RECORD,
        ));
    };

    if text_member(&object, "schema") != Some(CONTROL_NAMESPACE) {
        return Err(StorageError::new(
            StorageErrorKind::MalformedInput,
            DETAIL_NAMESPACE,
        ));
    }

    let type_token = text_member(&object, "record_type").ok_or(malformed)?;
    let kind = ControlRecordKind::parse(type_token)
        .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_INCOMPLETE))?;
    let kind_token = text_member(&object, "record_kind").ok_or(malformed)?;
    if kind_token != write_class_token(kind.write_class()) {
        return Err(StorageError::new(
            StorageErrorKind::MalformedInput,
            DETAIL_INCOMPLETE,
        ));
    }

    let tenant_text = text_member(&object, "tenant_id").ok_or(malformed)?;
    let tenant = TenantId::parse(tenant_text)
        .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_INCOMPLETE))?;
    let signed_at = text_member(&object, "signed_at").ok_or(malformed)?;
    Timestamp::parse(signed_at)
        .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_INCOMPLETE))?;
    let authority_key = text_member(&object, "authority_key_id").ok_or(malformed)?;
    KeyId::parse(authority_key)
        .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_INCOMPLETE))?;
    let signature = text_member(&object, "authority_signature").ok_or(malformed)?;
    Ed25519Signature::parse(signature)
        .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_INCOMPLETE))?;

    let (key, epoch) = match kind {
        ControlRecordKind::LinkedClient => {
            let client = client_member(&object, "client_id")?;
            let epoch = epoch_member(&object)?;
            (
                ControlObjectKey::linked_client(&tenant, &client),
                Some(epoch),
            )
        }
        ControlRecordKind::Delegation => {
            let relay = client_member(&object, "relay_client_id")?;
            let origin = client_member(&object, "origin_client_id")?;
            if relay == origin {
                return Err(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    DETAIL_SELF_DELEGATION,
                ));
            }
            let epoch = epoch_member(&object)?;
            (
                ControlObjectKey::delegation(&tenant, &relay, &origin),
                Some(epoch),
            )
        }
        ControlRecordKind::Revocation => {
            let client = client_member(&object, "client_id")?;
            let epoch = epoch_member(&object)?;
            (
                ControlObjectKey::revocation(&tenant, &client, epoch),
                Some(epoch),
            )
        }
        ControlRecordKind::Rotation => {
            let client = client_member(&object, "client_id")?;
            let epoch = epoch_member(&object)?;
            (
                ControlObjectKey::rotation(&tenant, &client, epoch),
                Some(epoch),
            )
        }
        ControlRecordKind::ReceiptKey => {
            if object.contains("authorization_epoch") {
                return Err(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    DETAIL_RECEIPT_EPOCH,
                ));
            }
            let key_id = key_member(&object, "key_id")?;
            (ControlObjectKey::receipt_key(&tenant, &key_id), None)
        }
    };

    Ok(ValidatedEnvelope {
        kind,
        tenant,
        key,
        epoch,
    })
}

/// The write-class token the envelope's `record_kind` member carries.
const fn write_class_token(class: ControlWriteClass) -> &'static str {
    match class {
        ControlWriteClass::Immutable => "immutable",
        ControlWriteClass::CurrentPointer => "current-pointer",
    }
}

/// One text member, or [`None`] for anything but a JSON string.
fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(text)) => Some(text.as_str()),
        _ => None,
    }
}

/// One required client-identifier member.
fn client_member(object: &Object, name: &str) -> Result<ClientId, StorageError> {
    text_member(object, name)
        .and_then(|text| ClientId::parse(text).ok())
        .ok_or_else(|| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_INCOMPLETE))
}

/// One required key-ID member.
fn key_member(object: &Object, name: &str) -> Result<KeyId, StorageError> {
    text_member(object, name)
        .and_then(|text| KeyId::parse(text).ok())
        .ok_or_else(|| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_INCOMPLETE))
}

/// The signed authorization epoch: required, integral, and inside the
/// 18-digit ceiling the key grammars and the envelope bound pin together.
fn epoch_member(object: &Object) -> Result<AuthorizationEpoch, StorageError> {
    match object.get("authorization_epoch") {
        Some(Value::Int(value)) if (1..=EPOCH_MAX_I64).contains(value) => {
            let number = u64::try_from(*value)
                .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_EPOCH))?;
            AuthorizationEpoch::new(number)
                .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_EPOCH))
        }
        _ => Err(StorageError::new(
            StorageErrorKind::MalformedInput,
            DETAIL_EPOCH,
        )),
    }
}

/// The S3 request seam of the administration identity: the two object
/// primitives the offline control-administration credential needs, keyed by
/// the derived [`ControlObjectKey`] only.
///
/// The trait is deliberately narrower than an S3 client: there is no
/// delete, no list, no arbitrary-key method, and no bucket-level call —
/// the administration credential "can put only validated,
/// tenant-authority-signed objects below the tenant control prefix" (plan
/// Section 5), so this is the entire surface that authority has. A concrete
/// binding (the reference profile's HTTP client, the compatibility suite's
/// fault-injecting backend) implements these two operations over
/// `GetObject`/`PutObject` and enforces the same prefix scope the
/// deployment's backend policy states: read-write below
/// `tenants/<tenant>/v1/control/`, deny every other prefix. The mock in
/// this module's tests mirrors that denial so the store's requests are
/// proven to stay inside it.
pub trait ControlAdminBackend {
    /// Read the stored bytes at one derived control key.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the key is outside
    /// this credential's provisioned prefix.
    fn get_control_object(
        &self,
        key: &ControlObjectKey,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, StorageError>> + Send;

    /// Write `envelope` at one derived control key.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the key is outside
    /// this credential's provisioned prefix.
    fn put_control_object(
        &self,
        key: &ControlObjectKey,
        envelope: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// The portable S3 [`ControlAdminStore`]: one administration configuration,
/// one backend seam, and the two write rules of the control plane.
///
/// Constructed by the offline administrator CLI (the composition root),
/// never by an ingest replica: the ingest surface cannot name this type's
/// configuration, and
/// [`reject_administration_credential`](crate::config::S3StorageConfig::reject_administration_credential)
/// refuses a deployment that tries to reuse the credential across the
/// split.
pub struct S3ControlAdminStore<B> {
    config: ControlAdminConfig,
    backend: B,
}

impl<B> S3ControlAdminStore<B> {
    /// Compose the administration authority: the validated configuration
    /// (its credential reference and pinned tenant) over one backend seam.
    #[must_use]
    pub const fn new(config: ControlAdminConfig, backend: B) -> Self {
        Self { config, backend }
    }

    /// The administration configuration this store was composed with.
    #[must_use]
    pub const fn config(&self) -> &ControlAdminConfig {
        &self.config
    }
}

impl<B: ControlAdminBackend> S3ControlAdminStore<B> {
    /// Validate one presented record for a write of `method_class`:
    /// structurally complete, of the family the caller's construction site
    /// claims, routed through the method its family's write class pins, and
    /// inside this identity's one provisioned tenant.
    fn validate(
        &self,
        record: &AdminControlRecord,
        method_class: ControlWriteClass,
    ) -> Result<ValidatedEnvelope, StorageError> {
        let validated = validate_envelope(record.envelope())?;
        if validated.kind != record.kind() {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_TYPE_DISAGREES,
            ));
        }
        if record.kind().write_class() != method_class {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_WRITE_METHOD,
            ));
        }
        if validated.tenant != *self.config.tenant() {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        Ok(validated)
    }
}

// `Sync` on the backend is what lets `&self` ride across the awaits of the
// trait's `Send` futures; every real backend (an HTTP client handle over
// the administration credential) is sync in exactly this sense.
impl<B: ControlAdminBackend + Sync> ControlAdminStore for S3ControlAdminStore<B> {
    async fn put_immutable_record(&self, record: &AdminControlRecord) -> Result<(), StorageError> {
        let validated = self.validate(record, ControlWriteClass::Immutable)?;
        match self.backend.get_control_object(&validated.key).await? {
            None => {
                self.backend
                    .put_control_object(&validated.key, record.envelope())
                    .await
            }
            // The byte-identical retry of one administrative write: the
            // record is already the object at its derived key, so the
            // write succeeded and repeating it changes nothing.
            Some(stored) if stored.as_slice() == record.envelope() => Ok(()),
            // Anything else at an immutable family's key is an integrity
            // conflict: retrying the same bytes is an overwrite loop, and
            // no write this store offers can displace it (EC-06).
            Some(_) => Err(StorageError::new(
                StorageErrorKind::IntegrityConflict,
                DETAIL_IMMUTABLE_CONFLICT,
            )),
        }
    }

    async fn put_current_pointer(&self, record: &AdminControlRecord) -> Result<(), StorageError> {
        let validated = self.validate(record, ControlWriteClass::CurrentPointer)?;
        // A current-pointer family always carries its epoch (validation
        // required it); the let-else keeps that invariant explicit without
        // guessing a number.
        let Some(new_epoch) = validated.epoch else {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_EPOCH,
            ));
        };
        match self.backend.get_control_object(&validated.key).await? {
            None => {
                self.backend
                    .put_control_object(&validated.key, record.envelope())
                    .await
            }
            Some(stored) => {
                // The stored pointer must re-validate as this family's
                // record and re-derive to this very key; a pointer that
                // does not is corruption at a derived key, which no
                // replacement this store offers may paper over.
                let stored_validated = validate_envelope(&stored)
                    .ok()
                    .filter(|candidate| {
                        candidate.kind == validated.kind && candidate.key == validated.key
                    })
                    .ok_or_else(|| {
                        StorageError::new(
                            StorageErrorKind::IntegrityConflict,
                            DETAIL_POINTER_CONFLICT,
                        )
                    })?;
                let stored_epoch = stored_validated.epoch.ok_or_else(|| {
                    StorageError::new(StorageErrorKind::IntegrityConflict, DETAIL_POINTER_CONFLICT)
                })?;
                if new_epoch.get() > stored_epoch.get() {
                    self.backend
                        .put_control_object(&validated.key, record.envelope())
                        .await
                } else {
                    // Equal or lower — including a byte-identical replay,
                    // whose epoch is the stored one by definition. The
                    // epoch is signed precisely so this is the one rule a
                    // replacement cannot talk its way past.
                    Err(StorageError::of_kind(StorageErrorKind::StaleEpoch))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use archivist_protocol::json::{Object, Value};
    use archivist_protocol::vocabulary::Ed25519PublicKey;
    use archivist_storage::control::ControlRecordKind;

    use super::{
        AdminControlRecord, AuthorizationEpoch, ControlAdminBackend, ControlAdminStore,
        ControlObjectKey, S3ControlAdminStore, StorageError, StorageErrorKind,
    };
    use crate::config::ControlAdminConfig;

    // The golden identifiers the control schema gate pins
    // (tools/check-control-schemas.py): the same tenant, client, relay,
    // authority root, and receipt key, so this module's derived keys and
    // the registry's layouts are proven in agreement on one story rather
    // than on unrelated values.
    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";
    const RELAY: &str = "2b1a0f9e-8d7c-4e6b-9a5f-1e2d3c4b5a69";
    const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
    const SIGNED_AT: &str = "2026-09-11T00:00:00Z";
    const ADMIN_REF: &str = "file:/etc/archivist/storage/control-admin-credentials";
    const CONTROL_BUCKET: &str = "archivist-control-example";

    fn tenant() -> archivist_protocol::vocabulary::TenantId {
        TENANT.parse().unwrap()
    }

    fn client() -> archivist_protocol::vocabulary::ClientId {
        CLIENT.parse().unwrap()
    }

    fn relay() -> archivist_protocol::vocabulary::ClientId {
        RELAY.parse().unwrap()
    }

    fn signature_hex() -> String {
        "00".repeat(64)
    }

    fn authority_key_id() -> String {
        key_id_of(&[0xab; 32])
    }

    fn key_id_of(raw: &[u8; 32]) -> String {
        let public = Ed25519PublicKey::from_raw(*raw);
        archivist_protocol::vocabulary::KeyId::from_public_key(&public).to_hex()
    }

    fn admin_config() -> ControlAdminConfig {
        ControlAdminConfig::builder()
            .endpoint_url("https://s3.example.invalid")
            .region("us-east-1")
            .control_bucket(CONTROL_BUCKET)
            .tenant(TENANT)
            .control_admin_credentials(ADMIN_REF)
            .build()
            .expect("golden administration configuration validates")
    }

    /// A no-dependency executor for futures that complete without pending
    /// (the same helper the storage crate's ingest tests use).
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            match future.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    /// Canonical envelope bytes from ordered members (the builder upserts,
    /// and canonical output sorts, so call sites read in any order).
    fn envelope(members: &[(&str, Value)]) -> Vec<u8> {
        let mut object = Object::new();
        for (name, value) in members {
            object.set(name, value.clone());
        }
        Value::Object(object).canonical_bytes()
    }

    fn text(value: &str) -> Value {
        Value::Text(value.to_owned())
    }

    /// The wrapper members every control record carries, with the family's
    /// own type and kind tokens.
    fn wrapper(record_type: &str, record_kind: &str) -> Vec<(&'static str, Value)> {
        vec![
            ("schema", text("archivist.control/v1")),
            ("record_type", text(record_type)),
            ("record_kind", text(record_kind)),
            ("tenant_id", text(TENANT)),
            ("signed_at", text(SIGNED_AT)),
            ("authority_key_id", text(&authority_key_id())),
            ("authority_signature", text(&signature_hex())),
        ]
    }

    fn linked_client_envelope(epoch: i64) -> Vec<u8> {
        let mut members = wrapper("linked-client", "current-pointer");
        members.extend([
            ("client_id", text(CLIENT)),
            ("key_id", text(&key_id_of(&[0xcd; 32]))),
            ("key_algorithm", text("ed25519")),
            ("public_key", text(&"cd".repeat(32))),
            ("authorization_epoch", Value::Int(epoch)),
        ]);
        envelope(&members)
    }

    fn delegation_envelope(epoch: i64) -> Vec<u8> {
        let mut members = wrapper("delegation", "current-pointer");
        members.extend([
            ("relay_client_id", text(RELAY)),
            ("origin_client_id", text(CLIENT)),
            ("delegation_state", text("active")),
            ("authorization_epoch", Value::Int(epoch)),
        ]);
        envelope(&members)
    }

    fn revocation_envelope(epoch: i64) -> Vec<u8> {
        let mut members = wrapper("revocation", "immutable");
        members.extend([
            ("client_id", text(CLIENT)),
            ("revoked_key_id", text(&key_id_of(&[0xcd; 32]))),
            ("authorization_epoch", Value::Int(epoch)),
        ]);
        envelope(&members)
    }

    fn rotation_envelope(epoch: i64) -> Vec<u8> {
        let mut members = wrapper("rotation", "immutable");
        members.extend([
            ("client_id", text(CLIENT)),
            ("previous_epoch", Value::Int(epoch - 1)),
            ("previous_public_key", text(&"ef".repeat(32))),
            ("previous_key_id", text(&key_id_of(&[0xef; 32]))),
            ("key_algorithm", text("ed25519")),
            ("public_key", text(&"cd".repeat(32))),
            ("key_id", text(&key_id_of(&[0xcd; 32]))),
            ("authorization_epoch", Value::Int(epoch)),
        ]);
        envelope(&members)
    }

    fn receipt_key_envelope() -> Vec<u8> {
        let mut members = wrapper("receipt-key", "immutable");
        members.extend([
            ("key_id", text(&key_id_of(&[0x3c; 32]))),
            ("key_algorithm", text("ed25519")),
            ("public_key", text(&"3c".repeat(32))),
            ("valid_from", text("2026-09-04T00:00:00Z")),
            ("valid_until", text("2026-10-11T00:00:00Z")),
        ]);
        envelope(&members)
    }

    /// The in-memory backend: an object map plus the prefix denial the
    /// deployment's administration-credential policy states. Keys outside
    /// the provisioned tenant's control prefix — the only request the store
    /// can issue is a derived control key, but the backend refuses one from
    /// any other scope all the same, mirroring what the live policy does.
    #[derive(Clone, Debug)]
    struct MapBackend {
        tenant: archivist_protocol::vocabulary::TenantId,
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        writes: Arc<Mutex<HashMap<String, u32>>>,
    }

    impl MapBackend {
        fn new(tenant: archivist_protocol::vocabulary::TenantId) -> Self {
            Self {
                tenant,
                objects: Arc::new(Mutex::new(HashMap::new())),
                writes: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn stored(&self, key: &str) -> Option<Vec<u8>> {
            self.objects
                .lock()
                .expect("test backend lock")
                .get(key)
                .cloned()
        }

        /// How many puts this backend actually issued at one key — the
        /// counter an idempotent replay or a refused write must not move.
        /// Preloads do not count; only `put_control_object` does.
        fn puts_at(&self, key: &str) -> u32 {
            self.writes
                .lock()
                .expect("test backend lock")
                .get(key)
                .copied()
                .unwrap_or(0)
        }

        fn preload(&self, key: &str, bytes: &[u8]) {
            self.objects
                .lock()
                .expect("test backend lock")
                .insert(key.to_owned(), bytes.to_vec());
        }
    }

    impl ControlAdminBackend for MapBackend {
        async fn get_control_object(
            &self,
            key: &super::ControlObjectKey,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            if key.tenant() != &self.tenant {
                return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
            }
            Ok(self
                .objects
                .lock()
                .expect("test backend lock")
                .get(key.as_str())
                .cloned())
        }

        async fn put_control_object(
            &self,
            key: &super::ControlObjectKey,
            bytes: &[u8],
        ) -> Result<(), StorageError> {
            if key.tenant() != &self.tenant {
                return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
            }
            *self
                .writes
                .lock()
                .expect("test backend lock")
                .entry(key.as_str().to_owned())
                .or_insert(0) += 1;
            self.objects
                .lock()
                .expect("test backend lock")
                .insert(key.as_str().to_owned(), bytes.to_vec());
            Ok(())
        }
    }

    fn store() -> S3ControlAdminStore<MapBackend> {
        S3ControlAdminStore::new(admin_config(), MapBackend::new(tenant()))
    }

    fn record(kind: ControlRecordKind, bytes: Vec<u8>) -> AdminControlRecord {
        AdminControlRecord::new(kind, bytes)
    }

    fn error_kind(result: Result<(), StorageError>) -> StorageErrorKind {
        result.expect_err("this write must fail").kind()
    }

    #[test]
    fn derived_keys_agree_with_the_registry_layouts() {
        // The layouts of tools/control-records.toml with the schema gate's
        // golden identifiers substituted — layout, pattern, and key members
        // are one contract, and this pins the Rust side into it.
        let tenant = tenant();
        let client = client();
        let relay = relay();
        let epoch = AuthorizationEpoch::new(3).unwrap();
        let receipt_key =
            archivist_protocol::vocabulary::KeyId::parse(&key_id_of(&[0x3c; 32])).unwrap();

        let cases = [
            (
                ControlObjectKey::linked_client(&tenant, &client),
                format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json"),
                ControlRecordKind::LinkedClient,
            ),
            (
                ControlObjectKey::delegation(&tenant, &relay, &client),
                format!("tenants/{TENANT}/v1/control/delegations/{RELAY}/{CLIENT}.json"),
                ControlRecordKind::Delegation,
            ),
            (
                ControlObjectKey::revocation(&tenant, &client, epoch),
                format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/3.json"),
                ControlRecordKind::Revocation,
            ),
            (
                ControlObjectKey::rotation(&tenant, &client, epoch),
                format!("tenants/{TENANT}/v1/control/rotations/{CLIENT}/3.json"),
                ControlRecordKind::Rotation,
            ),
            (
                ControlObjectKey::receipt_key(&tenant, &receipt_key),
                format!("tenants/{TENANT}/v1/control/receipt-keys/{receipt_key}.json"),
                ControlRecordKind::ReceiptKey,
            ),
        ];
        for (key, expected, kind) in cases {
            assert_eq!(key.as_str(), expected);
            assert_eq!(key.to_string(), expected);
            assert_eq!(key.kind(), kind);
            assert_eq!(key.tenant(), &tenant);
            assert_eq!(ControlObjectKey::parse(&expected).unwrap(), key);
        }
    }

    #[test]
    fn key_parsing_fails_closed_outside_the_five_layouts() {
        let digest = "0f".repeat(32);
        let epoch_ceiling = "999999999999999999"; // the 18-digit bound
        for accepted in [
            format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json"),
            format!("tenants/{TENANT}/v1/control/delegations/{RELAY}/{CLIENT}.json"),
            format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/{epoch_ceiling}.json"),
            format!("tenants/{TENANT}/v1/control/rotations/{CLIENT}/1.json"),
            format!("tenants/{TENANT}/v1/control/receipt-keys/{digest}.json"),
        ] {
            assert!(
                ControlObjectKey::parse(&accepted).is_ok(),
                "{accepted} must parse"
            );
        }
        for rejected in [
            String::new(),
            String::from("clients/x.json"),
            format!("tenants/{TENANT}/v2/control/clients/{CLIENT}.json"),
            format!("tenants/{TENANT}/v1/control/client/{CLIENT}.json"),
            format!("tenants/{TENANT}/v1/control/clients/{CLIENT}"),
            format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.jsonx"),
            format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json/extra"),
            format!("tenants/{TENANT}/v1/control/delegations/{RELAY}.json"),
            format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/0.json"),
            format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/01.json"),
            format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/9999999999999999999.json"),
            format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/x.json"),
            format!("tenants/{TENANT}/v1/control/receipt-keys/{digest}.json.bak"),
            // An uppercase rendering is not canonical.
            format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json").to_uppercase(),
        ] {
            assert!(
                ControlObjectKey::parse(&rejected).is_err(),
                "{rejected} must be rejected"
            );
        }
        // A short (non-digest) key-ID segment is refused.
        assert!(
            ControlObjectKey::parse(&format!(
                "tenants/{TENANT}/v1/control/receipt-keys/abcd.json"
            ))
            .is_err()
        );
    }

    #[test]
    fn every_derived_key_stays_inside_the_permission_scope() {
        // "Backend permissions deny every non-control prefix": the store's
        // requests can only ever be derived keys, so proving each derived
        // layout is inside the configured scope — and that the scope model
        // denies every other namespace — is the whole boundary.
        let config = admin_config();
        let tenant = tenant();
        let client = client();
        let relay = relay();
        let digest = archivist_protocol::vocabulary::KeyId::parse(&key_id_of(&[0x3c; 32])).unwrap();
        let derived = [
            ControlObjectKey::linked_client(&tenant, &client),
            ControlObjectKey::delegation(&tenant, &relay, &client),
            ControlObjectKey::revocation(&tenant, &client, AuthorizationEpoch::new(1).unwrap()),
            ControlObjectKey::rotation(&tenant, &client, AuthorizationEpoch::new(2).unwrap()),
            ControlObjectKey::receipt_key(&tenant, &digest),
        ];
        for key in derived {
            assert!(config.permits_key(key.as_str()), "{}", key.as_str());
        }

        let blob = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let denied = [
            // Raw, catalog, derived, tombstone, and legal-hold namespaces
            // (plan Sections 5 and 7.5): none of them is control data.
            format!("tenants/{TENANT}/v1/raw/blobs/zstd-v1/sha256/0123/{blob}.zst"),
            format!(
                "tenants/{TENANT}/v1/raw/occurrences/{CLIENT}/claude-code/sh/{blob}/{blob}.json"
            ),
            format!("tenants/{TENANT}/v1/raw/attestations/{blob}/{blob}/{blob}.json"),
            format!("tenants/{TENANT}/v1/catalog/checkpoints/{blob}.json"),
            format!("tenants/{TENANT}/v1/derived/inference/v1/day/2026-09-13/{blob}.json"),
            format!("tenants/{TENANT}/v1/tombstones/{CLIENT}/{blob}.json"),
            format!("tenants/{TENANT}/v1/legal-hold/{CLIENT}.json"),
            // Another tenant's control prefix is not this credential's.
            format!("tenants/{OTHER_TENANT}/v1/control/clients/{CLIENT}.json"),
            // The control prefix itself with a non-canonical shape.
            format!("tenants/{TENANT}/v1/control/clients/not-a-uuid.json"),
            format!("tenants/{TENANT}/v1/control/anything-else"),
            "tenants//v1/control/clients/x.json".to_owned(),
            String::new(),
        ];
        for key in denied {
            assert!(!config.permits_key(&key), "{key} must be denied");
        }
    }

    #[test]
    fn golden_shaped_envelopes_validate_and_derive_their_keys() {
        let tenant = tenant();
        for (bytes, kind, expected_key) in [
            (
                linked_client_envelope(3),
                ControlRecordKind::LinkedClient,
                ControlObjectKey::linked_client(&tenant, &client()),
            ),
            (
                delegation_envelope(2),
                ControlRecordKind::Delegation,
                ControlObjectKey::delegation(&tenant, &relay(), &client()),
            ),
            (
                revocation_envelope(3),
                ControlRecordKind::Revocation,
                ControlObjectKey::revocation(
                    &tenant,
                    &client(),
                    AuthorizationEpoch::new(3).unwrap(),
                ),
            ),
            (
                rotation_envelope(3),
                ControlRecordKind::Rotation,
                ControlObjectKey::rotation(&tenant, &client(), AuthorizationEpoch::new(3).unwrap()),
            ),
            (
                receipt_key_envelope(),
                ControlRecordKind::ReceiptKey,
                ControlObjectKey::receipt_key(
                    &tenant,
                    &archivist_protocol::vocabulary::KeyId::parse(&key_id_of(&[0x3c; 32])).unwrap(),
                ),
            ),
        ] {
            let validated = super::validate_envelope(&bytes)
                .unwrap_or_else(|e| panic!("golden envelope must validate: {e}"));
            assert_eq!(validated.kind, kind);
            assert_eq!(validated.tenant, tenant);
            assert_eq!(validated.key, expected_key);
        }
    }

    #[test]
    fn envelope_validation_fails_closed() {
        fn assert_rejected(bytes: &[u8]) {
            let error =
                super::validate_envelope(bytes).expect_err("this envelope must fail validation");
            assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        }

        // Not JSON at all, not an object, wrong namespace.
        assert_rejected(b"not json");
        assert_rejected(b"[1,2,3]");
        let mut wrong_namespace = linked_client_envelope(1);
        wrong_namespace = replace_member(&wrong_namespace, "schema", text("archivist.control/v2"));
        assert_rejected(&wrong_namespace);

        // Unknown record type; a kind token the registry disagrees with.
        assert_rejected(&replace_member(
            &linked_client_envelope(1),
            "record_type",
            text("authority-rotation"),
        ));
        assert_rejected(&replace_member(
            &linked_client_envelope(1),
            "record_kind",
            text("immutable"),
        ));
        assert_rejected(&replace_member(
            &revocation_envelope(3),
            "record_kind",
            text("current-pointer"),
        ));

        // Missing or malformed key members.
        assert_rejected(&without_member(&linked_client_envelope(1), "client_id"));
        assert_rejected(&replace_member(
            &linked_client_envelope(1),
            "client_id",
            text("not-a-uuid"),
        ));
        assert_rejected(&replace_member(
            &delegation_envelope(1),
            "relay_client_id",
            text(CLIENT),
        ));
        assert_rejected(&without_member(&delegation_envelope(1), "origin_client_id"));

        // Epoch rules: missing, zero, above the 18-digit ceiling, or a
        // receipt-key record carrying one at all.
        assert_rejected(&without_member(
            &linked_client_envelope(1),
            "authorization_epoch",
        ));
        assert_rejected(&replace_member(
            &linked_client_envelope(1),
            "authorization_epoch",
            Value::Int(0),
        ));
        assert_rejected(&replace_member(
            &linked_client_envelope(1),
            "authorization_epoch",
            Value::Int(1_000_000_000_000_000_000),
        ));
        assert_rejected(&replace_member(
            &linked_client_envelope(1),
            "authorization_epoch",
            text("1"),
        ));
        assert_rejected(&{
            let mut members = wrapper("receipt-key", "immutable");
            members.extend([("key_id", text(&key_id_of(&[0x3c; 32])))]);
            members.push(("authorization_epoch", Value::Int(1)));
            envelope(&members)
        });

        // Wrapper signature members: missing, wrong shape.
        assert_rejected(&without_member(
            &linked_client_envelope(1),
            "authority_signature",
        ));
        assert_rejected(&replace_member(
            &linked_client_envelope(1),
            "authority_signature",
            text("00"),
        ));
        assert_rejected(&without_member(
            &linked_client_envelope(1),
            "authority_key_id",
        ));
        assert_rejected(&without_member(&linked_client_envelope(1), "signed_at"));
        assert_rejected(&replace_member(
            &linked_client_envelope(1),
            "signed_at",
            text("2026-09-11 00:00:00"),
        ));
    }

    /// Replace one top-level text/int member of an envelope (test helper:
    /// re-parse, set, re-serialize canonically).
    fn replace_member(bytes: &[u8], name: &str, value: Value) -> Vec<u8> {
        let Value::Object(mut object) = archivist_protocol::json::parse(bytes).unwrap() else {
            panic!("test envelopes are objects");
        };
        object.set(name, value);
        Value::Object(object).canonical_bytes()
    }

    /// Drop one top-level member of an envelope.
    fn without_member(bytes: &[u8], name: &str) -> Vec<u8> {
        let Value::Object(mut object) = archivist_protocol::json::parse(bytes).unwrap() else {
            panic!("test envelopes are objects");
        };
        let _ = object.remove(name);
        Value::Object(object).canonical_bytes()
    }

    #[test]
    fn immutable_families_write_once_replay_idempotently_and_reject_incompatible_bytes() {
        // The immutable write class is one rule over its three families
        // (plan Section 5; the trait's EC-06 contract): a fresh record
        // creates the object at its derived key, the byte-identical retry
        // of that same administrative write is already the object there —
        // success without a second write — and any other bytes at the key
        // are the containment case: refuse, and leave exactly what was
        // stored where it was.
        let cases = [
            (
                ControlRecordKind::Revocation,
                format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/3.json"),
                revocation_envelope(3),
                replace_member(
                    &revocation_envelope(3),
                    "revoked_key_id",
                    text(&key_id_of(&[0xef; 32])),
                ),
            ),
            (
                ControlRecordKind::Rotation,
                format!("tenants/{TENANT}/v1/control/rotations/{CLIENT}/3.json"),
                rotation_envelope(3),
                replace_member(&rotation_envelope(3), "public_key", text(&"ef".repeat(32))),
            ),
            (
                ControlRecordKind::ReceiptKey,
                format!(
                    "tenants/{TENANT}/v1/control/receipt-keys/{}.json",
                    key_id_of(&[0x3c; 32])
                ),
                receipt_key_envelope(),
                replace_member(
                    &receipt_key_envelope(),
                    "valid_until",
                    text("2026-10-12T00:00:00Z"),
                ),
            ),
        ];
        for (kind, key, record_bytes, conflicting) in cases {
            let store = store();

            // A fresh write at an unoccupied derived key creates the object.
            block_on(store.put_immutable_record(&record(kind, record_bytes.clone()))).unwrap();
            assert_eq!(
                store.backend.stored(&key).as_deref(),
                Some(record_bytes.as_slice())
            );
            assert_eq!(store.backend.puts_at(&key), 1);

            // The byte-identical re-put is an idempotent success that
            // issues no second write.
            block_on(store.put_immutable_record(&record(kind, record_bytes.clone()))).unwrap();
            assert_eq!(store.backend.puts_at(&key), 1, "replay must not write");
            assert_eq!(
                store.backend.stored(&key).as_deref(),
                Some(record_bytes.as_slice())
            );

            // Incompatible bytes at the same derived key are the EC-06
            // integrity conflict — refused, and nothing of the
            // conflicting record is written over what is stored.
            assert_ne!(conflicting, record_bytes);
            assert_eq!(
                error_kind(block_on(
                    store.put_immutable_record(&record(kind, conflicting.clone()))
                )),
                StorageErrorKind::IntegrityConflict
            );
            assert_eq!(store.backend.puts_at(&key), 1, "refusal must not write");
            assert_eq!(
                store.backend.stored(&key).as_deref(),
                Some(record_bytes.as_slice())
            );
        }
    }

    #[test]
    fn a_different_epoch_addresses_a_different_immutable_key() {
        // The epoch-addressed families never conflict across epochs: the
        // next epoch is a new object at a new derived key, which is why an
        // immutable record is corrected by publishing the next epoch
        // rather than rewriting this one.
        let store = store();
        block_on(store.put_immutable_record(&record(
            ControlRecordKind::Revocation,
            revocation_envelope(3),
        )))
        .unwrap();
        block_on(
            store.put_immutable_record(&record(ControlRecordKind::Rotation, rotation_envelope(3))),
        )
        .unwrap();
        block_on(store.put_immutable_record(&record(
            ControlRecordKind::Revocation,
            revocation_envelope(4),
        )))
        .unwrap();
        assert!(
            store
                .backend
                .stored(&format!(
                    "tenants/{TENANT}/v1/control/revocations/{CLIENT}/4.json"
                ))
                .is_some()
        );
        assert!(
            store
                .backend
                .stored(&format!(
                    "tenants/{TENANT}/v1/control/rotations/{CLIENT}/3.json"
                ))
                .is_some()
        );
        assert_eq!(
            store
                .backend
                .stored(&format!(
                    "tenants/{TENANT}/v1/control/revocations/{CLIENT}/3.json"
                ))
                .as_deref(),
            Some(revocation_envelope(3).as_slice())
        );
    }

    #[test]
    fn current_pointer_replacement_requires_a_strictly_higher_signed_epoch() {
        let store = store();
        let key = format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json");

        // The absent pointer accepts the link (epoch 1 or any first epoch).
        block_on(store.put_current_pointer(&record(
            ControlRecordKind::LinkedClient,
            linked_client_envelope(2),
        )))
        .unwrap();

        // A strictly higher signed epoch replaces the pointer.
        block_on(store.put_current_pointer(&record(
            ControlRecordKind::LinkedClient,
            linked_client_envelope(3),
        )))
        .unwrap();
        assert_eq!(
            store.backend.stored(&key).as_deref(),
            Some(linked_client_envelope(3).as_slice())
        );

        // Equal epoch — including a byte-identical replay — is stale.
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::LinkedClient,
                linked_client_envelope(3),
            )))),
            StorageErrorKind::StaleEpoch
        );
        // Lower epoch is stale.
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::LinkedClient,
                linked_client_envelope(1),
            )))),
            StorageErrorKind::StaleEpoch
        );
        // The refused writes left the stored pointer where it was.
        assert_eq!(
            store.backend.stored(&key).as_deref(),
            Some(linked_client_envelope(3).as_slice())
        );

        // Any strictly higher epoch is accepted — the rule is monotonic,
        // not step-by-step.
        block_on(store.put_current_pointer(&record(
            ControlRecordKind::LinkedClient,
            linked_client_envelope(7),
        )))
        .unwrap();

        // The delegation pointer is the same rule over the (relay, origin)
        // relation's own epoch sequence.
        let delegation_key =
            format!("tenants/{TENANT}/v1/control/delegations/{RELAY}/{CLIENT}.json");
        block_on(store.put_current_pointer(&record(
            ControlRecordKind::Delegation,
            delegation_envelope(1),
        )))
        .unwrap();
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::Delegation,
                delegation_envelope(1),
            )))),
            StorageErrorKind::StaleEpoch
        );
        block_on(store.put_current_pointer(&record(
            ControlRecordKind::Delegation,
            delegation_envelope(2),
        )))
        .unwrap();
        // Lower epoch is stale on this family's own sequence too — the
        // relation's epochs advance independently of the linked-client
        // pointer's, and the same strict-increase rule gates them.
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::Delegation,
                delegation_envelope(1),
            )))),
            StorageErrorKind::StaleEpoch
        );
        assert_eq!(
            store.backend.stored(&delegation_key).as_deref(),
            Some(delegation_envelope(2).as_slice())
        );
    }

    #[test]
    fn an_invalid_epoch_fails_closed_before_any_write() {
        // The epoch gate runs on the presented record before the store
        // touches the backend: an epoch that is missing, not an integer,
        // zero, negative, or past the 18-digit ceiling is a malformed
        // record, refused with the epoch detail — and the pointer already
        // stored stays byte-for-byte what it was, because no put is ever
        // issued on a refused path.
        let cases = [
            (
                ControlRecordKind::LinkedClient,
                format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json"),
                linked_client_envelope(1),
                linked_client_envelope(2),
            ),
            (
                ControlRecordKind::Delegation,
                format!("tenants/{TENANT}/v1/control/delegations/{RELAY}/{CLIENT}.json"),
                delegation_envelope(1),
                delegation_envelope(2),
            ),
        ];
        for (kind, key, stored_pointer, candidate) in cases {
            let store = store();
            block_on(store.put_current_pointer(&record(kind, stored_pointer.clone()))).unwrap();
            assert_eq!(store.backend.puts_at(&key), 1);

            let broken_epochs = [
                // Unsigned: the epoch member is absent altogether.
                without_member(&candidate, "authorization_epoch"),
                // Present but not an epoch: text, zero, negative, and one
                // past the ceiling the envelope's epoch bound pins.
                replace_member(&candidate, "authorization_epoch", text("2")),
                replace_member(&candidate, "authorization_epoch", Value::Int(0)),
                replace_member(&candidate, "authorization_epoch", Value::Int(-1)),
                replace_member(
                    &candidate,
                    "authorization_epoch",
                    Value::Int(1_000_000_000_000_000_000),
                ),
            ];
            for broken in &broken_epochs {
                let error = block_on(store.put_current_pointer(&record(kind, broken.clone())))
                    .expect_err("an invalid epoch must fail the write");
                assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
                assert_eq!(error.detail(), super::DETAIL_EPOCH);
            }

            // Every refusal happened before any request that could write:
            // the initial pointer is still the only put, and the object at
            // the key is still the pointer that was stored first.
            assert_eq!(store.backend.puts_at(&key), 1, "refusals must not write");
            assert_eq!(
                store.backend.stored(&key).as_deref(),
                Some(stored_pointer.as_slice())
            );
        }
    }

    #[test]
    fn a_corrupt_stored_pointer_is_an_integrity_conflict() {
        let store = store();
        let key = format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json");

        // Garbage at the pointer's key: not a record of any family.
        store.backend.preload(&key, b"not-a-record");
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::LinkedClient,
                linked_client_envelope(2),
            )))),
            StorageErrorKind::IntegrityConflict
        );

        // A valid record of the wrong family at this key: still a pointer
        // this family cannot interpret or replace.
        store.backend.preload(&key, &delegation_envelope(5));
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::LinkedClient,
                linked_client_envelope(2),
            )))),
            StorageErrorKind::IntegrityConflict
        );
        // And a corrupt object at an immutable family's key is refused by
        // the immutable rule's compatibility arm.
        let revocation_key = format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/9.json");
        store.backend.preload(&revocation_key, b"not-a-record");
        assert_eq!(
            error_kind(block_on(store.put_immutable_record(&record(
                ControlRecordKind::Revocation,
                revocation_envelope(9),
            )))),
            StorageErrorKind::IntegrityConflict
        );
        // The refusal issued no write: the corrupt object stays byte-for-
        // byte what it was.
        assert_eq!(store.backend.puts_at(&revocation_key), 0);
        assert_eq!(
            store.backend.stored(&revocation_key).as_deref(),
            Some(b"not-a-record".as_slice())
        );
    }

    #[test]
    fn write_methods_are_per_family() {
        let store = store();
        // A current-pointer family record through the immutable method.
        assert_eq!(
            error_kind(block_on(store.put_immutable_record(&record(
                ControlRecordKind::LinkedClient,
                linked_client_envelope(1),
            )))),
            StorageErrorKind::MalformedInput
        );
        // An immutable family record through the pointer method.
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::Rotation,
                rotation_envelope(3),
            )))),
            StorageErrorKind::MalformedInput
        );
        // An envelope whose own record_type disagrees with the kind the
        // record was constructed with.
        let mut masquerading = revocation_envelope(3);
        masquerading = replace_member(&masquerading, "record_type", text("rotation"));
        masquerading = replace_member(&masquerading, "record_kind", text("immutable"));
        // The rotation layout addresses epochs the same way, so the key
        // would still derive — but the presented kind disagrees with the
        // envelope, which is refused before any request is issued.
        assert_eq!(
            error_kind(block_on(store.put_immutable_record(&record(
                ControlRecordKind::Revocation,
                masquerading,
            )))),
            StorageErrorKind::MalformedInput
        );
        // Nothing was written by any refused path.
        assert!(
            store
                .backend
                .stored(&format!(
                    "tenants/{TENANT}/v1/control/rotations/{CLIENT}/3.json"
                ))
                .is_none()
        );
    }

    #[test]
    fn administration_is_scoped_to_one_tenant() {
        let store = store();
        let mut foreign = linked_client_envelope(2);
        foreign = replace_member(&foreign, "tenant_id", text(OTHER_TENANT));
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::LinkedClient,
                foreign,
            )))),
            StorageErrorKind::ScopeViolation
        );
        // And the backend seam denies a foreign-tenant control key even if
        // one were somehow derived — the permission profile's denial.
        let foreign_key = ControlObjectKey::parse(&format!(
            "tenants/{OTHER_TENANT}/v1/control/clients/{CLIENT}.json"
        ))
        .unwrap();
        assert_eq!(
            block_on(store.backend.get_control_object(&foreign_key))
                .expect_err("foreign tenant must be denied")
                .kind(),
            StorageErrorKind::ScopeViolation
        );
        assert!(
            store
                .backend
                .stored(&format!(
                    "tenants/{TENANT}/v1/control/clients/{CLIENT}.json"
                ))
                .is_none()
        );
    }

    #[test]
    fn every_error_detail_is_a_safe_message() {
        for detail in [
            super::DETAIL_NOT_A_RECORD,
            super::DETAIL_NAMESPACE,
            super::DETAIL_INCOMPLETE,
            super::DETAIL_TYPE_DISAGREES,
            super::DETAIL_WRITE_METHOD,
            super::DETAIL_EPOCH,
            super::DETAIL_SELF_DELEGATION,
            super::DETAIL_RECEIPT_EPOCH,
            super::DETAIL_IMMUTABLE_CONFLICT,
            super::DETAIL_POINTER_CONFLICT,
            super::DETAIL_SCOPE,
        ] {
            let parsed = archivist_protocol::vocabulary::SafeMessage::parse(detail)
                .unwrap_or_else(|_| panic!("detail is not a safe message: {detail}"));
            assert_eq!(parsed.as_str(), detail);
        }
    }
}
