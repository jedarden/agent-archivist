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
//!   any request is issued. The six derivable layouts include the
//!   authority-rotation link's predecessor-addressed key — the chain
//!   history appends precisely because the retiring half's own ID is the
//!   address an immutable write can never repeat at.
//! - **Two write classes.** An immutable family (`revocation`, `rotation`,
//!   `receipt-key`, `authority-rotation`) is written once at its derived
//!   key: a byte-identical re-put is an idempotent success, an incompatible
//!   object at the key is an integrity conflict (`EC-06`). A
//!   current-pointer family (`linked-client`, `delegation`) is replaced
//!   only when the presented record's signed `authorization_epoch`
//!   strictly increases over the stored pointer — equal or lower is a
//!   stale write.
//! - **One tenant, one prefix.** The configuration pins the tenant whose
//!   control prefix the administration credential provisions, and
//!   [`permits_key`](crate::config::ControlAdminConfig::permits_key) is the
//!   raw-key model of that scope: the six control
//!   layouts under `tenants/<tenant>/v1/control/`, and nothing else. Every
//!   non-control prefix — raw, catalog, derived, tombstone, legal-hold,
//!   another tenant's control prefix — is denied. The deployment's backend
//!   policy for the administration credential mirrors that predicate
//!   (read-write below the tenant control prefix, deny everything else),
//!   and the compatibility-suite profiles prove it on live backends.
//! - **The authority's signed publications route here.** The Phase 3
//!   administrator act composes with the store at exactly two typed
//!   entries: [`S3ControlAdminStore::put_link_approval`] carries an
//!   approved link request's signed envelope onto the current-pointer
//!   class, and [`S3ControlAdminStore::put_revocation`] carries a signed
//!   revocation onto the immutable class. The signing surface
//!   (`archivist-auth`) and this store meet in those two methods and
//!   nowhere else — the publication value already binds the envelope to
//!   the object key the authority derived, the routing re-makes that key
//!   through [`ControlObjectKey::parse`] as a pre-flight (family and
//!   provisioned tenant, refused before any request), and the store's own
//!   write rules derive the landed key from the envelope's signed members.
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

use archivist_auth::link::ClientLinkPublication;
use archivist_auth::revocation::RevocationPublication;
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
const DETAIL_AUTHORITY_EPOCH: &str = "authority-rotation record carries no authorization epoch";
const DETAIL_IMMUTABLE_CONFLICT: &str = "stored record differs from the presented immutable record";
const DETAIL_POINTER_CONFLICT: &str = "stored pointer is not a valid record of its family";
const DETAIL_SCOPE: &str = "record tenant is outside this administration identity";
const DETAIL_PUBLICATION_KEY: &str =
    "publication names an object key outside the derived control layouts";
const DETAIL_PUBLICATION_FAMILY: &str = "publication family does not match this write method";

/// A server-derived control object key: one of the six canonical layouts
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

    /// Derive the authority-rotation link key:
    /// `tenants/<tenant>/v1/control/authority-rotations/<key>.json`, the
    /// retiring authority half's key ID under the pinned SHA-256
    /// derivation — predecessor addressing, so the verifier holding a
    /// trusted half fetches the link that retires it at that half's own
    /// address and successive rotations append as one immutable object per
    /// retired key.
    #[must_use]
    pub fn authority_rotation(tenant: &TenantId, previous_key: &KeyId) -> Self {
        Self {
            text: format!("tenants/{tenant}/v1/control/authority-rotations/{previous_key}.json"),
            kind: ControlRecordKind::AuthorityRotation,
            tenant: tenant.clone(),
        }
    }

    /// Parse one object key against the six canonical layouts, failing
    /// closed on anything else — every non-control prefix, a malformed
    /// identifier segment, a non-canonical epoch, and a wrong family shape
    /// all refuse rather than normalize.
    ///
    /// # Errors
    /// [`ControlKeyError::NotCanonical`] for any text outside the six
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
            "authority-rotations" => {
                let previous_key = key_segment(segments.next())?;
                ends_here(segments.next())?;
                Ok(Self::authority_rotation(&tenant, &previous_key))
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
/// the two key-addressed families, receipt-key and authority-rotation); and
/// the wrapper's `signed_at`, `authority_key_id`, and `authority_signature`
/// shapes. Payload members
/// beyond the wrapper are the record schema's business — the schema gate
/// (`tools/check-control-schemas.py`) and Phase 3 verification own them.
///
/// # Errors
/// [`StorageErrorKind::MalformedInput`] for the first violated rule; the
/// detail is a static literal and never echoes envelope content.
// One closed function per family arm: the derivation rules read as one
// table, and splitting the table would hide the per-family symmetry.
#[allow(clippy::too_many_lines)]
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
        ControlRecordKind::AuthorityRotation => {
            // The chain has no epoch sequence — the links themselves are
            // the order, each retiring exactly the key the previous link
            // established (the envelope's write-class rule: the identity
            // this record's key names is the retired authority key ID).
            if object.contains("authorization_epoch") {
                return Err(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    DETAIL_AUTHORITY_EPOCH,
                ));
            }
            let previous_key_id = key_member(&object, "previous_key_id")?;
            (
                ControlObjectKey::authority_rotation(&tenant, &previous_key_id),
                None,
            )
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
        // The backend permission model, enforced store-side as well: the
        // derived key must sit inside the one provisioned prefix this
        // configuration pins. Unreachable while the key derivation and the
        // scope model agree — which is exactly the agreement a drift
        // between the two must fail closed on, before any request is
        // issued against the administration credential.
        if !self.config.permits_key(validated.key.as_str()) {
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

// -----------------------------------------------------------------------
// The Phase 3 administrator act: the offline authority signs, this store
// publishes. Two typed routes carry `archivist-auth`'s signed
// publications onto the two write classes — an approved link request is a
// current-pointer record, a signed revocation is an immutable one — so
// the signing surface and the storage surface meet exactly here, and the
// administrator CLI only wires the two together.
// -----------------------------------------------------------------------
impl<B: ControlAdminBackend + Sync> S3ControlAdminStore<B> {
    /// Pre-flight one publication's declared object key against the
    /// family the calling method routes: the key must be one of the six
    /// derived control layouts, of exactly that family, and inside the
    /// one provisioned tenant. The store's own write rules govern the put
    /// that follows — this check refuses a misaddressed publication
    /// before any request is issued, the same fail-closed order every
    /// other refusal here keeps.
    fn route_publication(
        &self,
        declared_key: &str,
        family: ControlRecordKind,
    ) -> Result<(), StorageError> {
        let declared = ControlObjectKey::parse(declared_key).map_err(|_| {
            StorageError::new(StorageErrorKind::MalformedInput, DETAIL_PUBLICATION_KEY)
        })?;
        if declared.kind() != family {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_PUBLICATION_FAMILY,
            ));
        }
        if declared.tenant() != self.config.tenant() || !self.config.permits_key(declared.as_str()) {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        Ok(())
    }

    /// Route one approved link request onto the control plane: the
    /// authority's signed current-pointer record, published at
    /// [`ControlObjectKey::linked_client`] through
    /// [`ControlAdminStore::put_current_pointer`].
    ///
    /// The publication is the byte-exact envelope
    /// `approve_link_request` signed; the store derives the landed key
    /// from the envelope's own signed members, so the record sits exactly
    /// where every reader re-derives it. The pointer family's monotonic
    /// rule applies unchanged: a write whose signed epoch is not strictly
    /// greater than the stored pointer's — the byte-identical retry of an
    /// approval already published included — is refused, and the stored
    /// pointer stays what it was.
    ///
    /// # Errors
    /// [`StorageErrorKind::StaleEpoch`] and the other
    /// [`ControlAdminStore::put_current_pointer`] rejections, plus
    /// [`StorageErrorKind::MalformedInput`] when the publication's own
    /// object key is not a derived linked-client key and
    /// [`StorageErrorKind::ScopeViolation`] when its tenant is outside
    /// this administration identity.
    pub async fn put_link_approval(
        &self,
        approval: &ClientLinkPublication,
    ) -> Result<(), StorageError> {
        self.route_publication(approval.object_key(), ControlRecordKind::LinkedClient)?;
        self.put_current_pointer(&AdminControlRecord::new(
            ControlRecordKind::LinkedClient,
            approval.envelope().to_vec(),
        ))
        .await
    }

    /// Route one signed revocation onto the control plane: the
    /// authority's immutable record, published at
    /// [`ControlObjectKey::revocation`] through
    /// [`ControlAdminStore::put_immutable_record`].
    ///
    /// Re-routing the same publication — the lost-response retry of one
    /// administrative write — is the idempotent replay the immutable
    /// class promises: the byte-identical record is already the object at
    /// its derived key, and nothing is written again.
    ///
    /// # Errors
    /// The [`ControlAdminStore::put_immutable_record`] rejections, plus
    /// [`StorageErrorKind::MalformedInput`] when the publication's own
    /// object key is not a derived revocation key and
    /// [`StorageErrorKind::ScopeViolation`] when its tenant is outside
    /// this administration identity.
    pub async fn put_revocation(
        &self,
        publication: &RevocationPublication,
    ) -> Result<(), StorageError> {
        self.route_publication(publication.object_key(), ControlRecordKind::Revocation)?;
        self.put_immutable_record(&AdminControlRecord::new(
            ControlRecordKind::Revocation,
            publication.envelope().to_vec(),
        ))
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};

    use archivist_protocol::json::{Object, Value};
    use archivist_protocol::vocabulary::Ed25519PublicKey;
    use archivist_storage::control::{ControlRecordKind, ControlWriteClass};

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

    /// The golden chain link: the pinned authority root (the `ab` half
    /// every golden envelope's `authority_key_id` names) retires itself
    /// and establishes the `9e` successor half — the same one-root trust
    /// story the schema gate's golden authority-rotation record tells, so
    /// the store's derivation and the registry's layout are proven in
    /// agreement on the same identifiers the gate pins.
    fn authority_rotation_envelope() -> Vec<u8> {
        let mut members = wrapper("authority-rotation", "immutable");
        members.extend([
            ("previous_public_key", text(&"ab".repeat(32))),
            ("previous_key_id", text(&key_id_of(&[0xab; 32]))),
            ("key_algorithm", text("ed25519")),
            ("public_key", text(&"9e".repeat(32))),
            ("key_id", text(&key_id_of(&[0x9e; 32]))),
        ]);
        envelope(&members)
    }

    /// The in-memory backend: an object map plus the prefix denial the
    /// deployment's administration-credential policy states. The check is
    /// the policy's own shape — a literal string-prefix rule over the key,
    /// read-write below `tenants/<tenant>/v1/control/` and deny everything
    /// else — not a structural tenant compare, so the store's requests are
    /// proven to stay inside the prefix exactly as a live backend would
    /// grant or refuse them. Every request that reaches either verb is
    /// counted, so a test can prove a refused record never issued one.
    #[derive(Clone, Debug)]
    struct MapBackend {
        control_prefix: String,
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        writes: Arc<Mutex<HashMap<String, u32>>>,
        requests: Arc<Mutex<u32>>,
    }

    impl MapBackend {
        fn new(tenant: &archivist_protocol::vocabulary::TenantId) -> Self {
            Self {
                control_prefix: format!("tenants/{tenant}/v1/control/"),
                objects: Arc::new(Mutex::new(HashMap::new())),
                writes: Arc::new(Mutex::new(HashMap::new())),
                requests: Arc::new(Mutex::new(0)),
            }
        }

        /// How many requests reached this backend at all, granted or
        /// refused — the counter a refused-before-any-request proof holds
        /// at zero.
        fn requests(&self) -> u32 {
            *self.requests.lock().expect("test backend lock")
        }

        /// The deployment policy for the administration credential, as a
        /// grant predicate over one object key.
        fn policy_permits(&self, key: &str) -> bool {
            key.starts_with(&self.control_prefix)
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
            *self.requests.lock().expect("test backend lock") += 1;
            if !self.policy_permits(key.as_str()) {
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
            *self.requests.lock().expect("test backend lock") += 1;
            if !self.policy_permits(key.as_str()) {
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
        S3ControlAdminStore::new(admin_config(), MapBackend::new(&tenant()))
    }

    fn record(kind: ControlRecordKind, bytes: Vec<u8>) -> AdminControlRecord {
        AdminControlRecord::new(kind, bytes)
    }

    fn error_kind(result: Result<(), StorageError>) -> StorageErrorKind {
        result.expect_err("this write must fail").kind()
    }

    /// Registry families whose Rust derivation has not landed — each sits
    /// here only while its implementing slice is open work, and landing the
    /// derivation removes the name. Anything the registry ships that is in
    /// neither this list nor the derivation fails the proof below, so a new
    /// registry family cannot drift past the Rust side silently.
    const PENDING_DERIVATIONS: &[&str] = &["retention"];

    #[test]
    #[allow(clippy::too_many_lines)]
    fn derived_keys_agree_with_the_registry_layouts() {
        // The agreement is mechanical, not transcribed: the registry's own
        // `object_key` layouts, read from tools/control-records.toml and
        // substituted with the schema gate's golden identifiers per each
        // family's `key_members`, must equal the typed derivations, the
        // wire-side parse, and the keys the store derives from each
        // family's signed envelope — and the registry's write class must
        // route each family to the write method the store pins for it.
        let registry_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/control-records.toml");
        let registry_text = std::fs::read_to_string(&registry_path)
            .unwrap_or_else(|e| panic!("the control record registry must be readable: {e}"));
        let registry = parse_registry(&registry_text)
            .unwrap_or_else(|e| panic!("the control record registry must parse: {e}"));

        // The derivation implements exactly the registry's record set —
        // no family without a Rust layout, no layout without a family —
        // minus the families whose derivation is still pending its own
        // implementing slice.
        // (The registry's append-only rule lands a new family's schema,
        // envelope entry, enum token, object-key pattern, and this
        // derivation in one change; this assertion is the Rust side of
        // that rule.)
        let families: Vec<&str> = registry
            .keys()
            .map(String::as_str)
            .filter(|family| !PENDING_DERIVATIONS.contains(family))
            .collect();
        assert_eq!(
            families,
            [
                "authority-rotation",
                "delegation",
                "linked-client",
                "receipt-key",
                "revocation",
                "rotation"
            ],
            "the registry and the derivation must name the same families"
        );

        let tenant = tenant();
        let client = client();
        let relay = relay();
        let epoch = AuthorizationEpoch::new(3).unwrap();
        let receipt_key =
            archivist_protocol::vocabulary::KeyId::parse(&key_id_of(&[0x3c; 32])).unwrap();
        let authority_root =
            archivist_protocol::vocabulary::KeyId::parse(&key_id_of(&[0xab; 32])).unwrap();
        let golden: HashMap<&str, String> = HashMap::from([
            ("tenant_id", TENANT.to_owned()),
            ("client_id", CLIENT.to_owned()),
            ("relay_client_id", RELAY.to_owned()),
            ("origin_client_id", CLIENT.to_owned()),
            ("authorization_epoch", epoch.get().to_string()),
            ("key_id", key_id_of(&[0x3c; 32])),
            ("previous_key_id", key_id_of(&[0xab; 32])),
        ]);

        for (family, entry) in &registry {
            if PENDING_DERIVATIONS.contains(&family.as_str()) {
                continue;
            }
            let expected = entry
                .substitute(family, &golden)
                .unwrap_or_else(|e| panic!("{family}: {e}"));

            let (kind, derived) = match family.as_str() {
                "authority-rotation" => (
                    ControlRecordKind::AuthorityRotation,
                    ControlObjectKey::authority_rotation(&tenant, &authority_root),
                ),
                "delegation" => (
                    ControlRecordKind::Delegation,
                    ControlObjectKey::delegation(&tenant, &relay, &client),
                ),
                "linked-client" => (
                    ControlRecordKind::LinkedClient,
                    ControlObjectKey::linked_client(&tenant, &client),
                ),
                "receipt-key" => (
                    ControlRecordKind::ReceiptKey,
                    ControlObjectKey::receipt_key(&tenant, &receipt_key),
                ),
                "revocation" => (
                    ControlRecordKind::Revocation,
                    ControlObjectKey::revocation(&tenant, &client, epoch),
                ),
                "rotation" => (
                    ControlRecordKind::Rotation,
                    ControlObjectKey::rotation(&tenant, &client, epoch),
                ),
                _ => unreachable!("the family set was proven equal above"),
            };
            assert_eq!(
                derived.as_str(),
                expected,
                "{family}: the typed derivation must equal the registry layout"
            );
            assert_eq!(derived.to_string(), expected);
            assert_eq!(derived.kind(), kind);
            assert_eq!(derived.tenant(), &tenant);
            assert_eq!(
                ControlObjectKey::parse(&expected).unwrap(),
                derived,
                "{family}: the wire side must re-make the same key"
            );

            // The registry's write class is the routing the store pins.
            let expected_class = match entry.write_class.as_str() {
                "current-pointer" => ControlWriteClass::CurrentPointer,
                "immutable" => ControlWriteClass::Immutable,
                other => panic!("{family}: unknown registry write class {other:?}"),
            };
            assert_eq!(
                kind.write_class(),
                expected_class,
                "{family}: the registry's write class must route the family"
            );

            // And the family's signed envelope derives that same key from
            // its own validated members.
            let bytes = match family.as_str() {
                "authority-rotation" => authority_rotation_envelope(),
                "delegation" => delegation_envelope(3),
                "linked-client" => linked_client_envelope(3),
                "receipt-key" => receipt_key_envelope(),
                "revocation" => revocation_envelope(3),
                "rotation" => rotation_envelope(3),
                _ => unreachable!(),
            };
            let validated = super::validate_envelope(&bytes)
                .unwrap_or_else(|e| panic!("{family}: the golden envelope must validate: {e}"));
            assert_eq!(
                validated.key, derived,
                "{family}: the envelope's own members must derive the registry layout"
            );
        }
    }

    // -------------------------------------------------------------------
    // The control record registry, read at test time.
    //
    // The scanner is strict over the registry's own flat shape — a
    // `[records.<family>]` header opens an entry; the `write_class`,
    // `object_key`, and `key_members` lines fill it; comments, blanks, and
    // every other key (summary, schema, status) pass — and anything it
    // cannot understand fails the scan instead of passing silently.
    // -------------------------------------------------------------------

    /// One `[records.<family>]` entry, pared to the keys this proof reads.
    struct RegistryRecord {
        write_class: String,
        object_key: String,
        key_members: Vec<String>,
    }

    /// The registry's record table, family name to entry.
    type Registry = BTreeMap<String, RegistryRecord>;

    impl RegistryRecord {
        /// Substitute the golden identifiers into the layout, in the
        /// family's own `key_members` order: every declared member must
        /// fill a placeholder of the layout and every placeholder must
        /// carry a golden value, or the proof fails rather than guessing.
        fn substitute(
            &self,
            family: &str,
            golden: &HashMap<&str, String>,
        ) -> Result<String, String> {
            let mut key = self.object_key.clone();
            for member in &self.key_members {
                let placeholder = format!("<{member}>");
                let value = golden.get(member.as_str()).ok_or_else(|| {
                    format!("[records.{family}]: no golden identifier for key member {member}")
                })?;
                if !key.contains(&placeholder) {
                    return Err(format!(
                        "[records.{family}]: key member {member} fills no placeholder of {}",
                        self.object_key
                    ));
                }
                key = key.replacen(&placeholder, value, 1);
            }
            if key.contains('<') {
                return Err(format!(
                    "[records.{family}]: layout carries an unsubstituted placeholder: {key}"
                ));
            }
            Ok(key)
        }
    }

    /// Read the `[records.*]` table out of tools/control-records.toml.
    fn parse_registry(text: &str) -> Result<Registry, String> {
        // One entry under assembly: (family, write_class, object_key,
        // key_members), opened by its header and flushed by the next.
        type Assembling = (String, Option<String>, Option<String>, Option<Vec<String>>);
        let at = |line: usize, message: String| {
            format!("tools/control-records.toml:{}: {message}", line + 1)
        };
        let flush = |entry: Option<Assembling>,
                     registry: &mut Registry,
                     line: usize|
         -> Result<(), String> {
            let Some((family, write_class, object_key, key_members)) = entry else {
                return Ok(());
            };
            let missing = |what: &str| at(line, format!("[records.{family}] declares no {what}"));
            let record = RegistryRecord {
                write_class: write_class.ok_or_else(|| missing("write_class"))?,
                object_key: object_key.ok_or_else(|| missing("object_key"))?,
                key_members: key_members.ok_or_else(|| missing("key_members"))?,
            };
            if record.key_members.is_empty() {
                return Err(at(
                    line,
                    format!("[records.{family}] declares no key members"),
                ));
            }
            if registry.insert(family.clone(), record).is_some() {
                return Err(at(line, format!("[records.{family}] is declared twice")));
            }
            Ok(())
        };

        let mut registry = Registry::new();
        let mut current: Option<Assembling> = None;
        for (number, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(header) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                flush(current.take(), &mut registry, number)?;
                if let Some(family) = header.strip_prefix("records.") {
                    if family.is_empty() {
                        return Err(at(number, "a record header names no family".to_owned()));
                    }
                    current = Some((family.to_owned(), None, None, None));
                }
                continue;
            }
            let Some((name, value)) = line.split_once('=') else {
                return Err(at(number, format!("unrecognized line: {line}")));
            };
            if let Some((_, write_class, object_key, key_members)) = current.as_mut() {
                match name.trim() {
                    "write_class" => {
                        *write_class = Some(unquote(value).map_err(|e| at(number, e))?);
                    }
                    "object_key" => {
                        *object_key = Some(unquote(value).map_err(|e| at(number, e))?);
                    }
                    "key_members" => {
                        *key_members = Some(parse_members(value).map_err(|e| at(number, e))?);
                    }
                    _ => {}
                }
            }
        }
        flush(current.take(), &mut registry, text.lines().count())?;
        Ok(registry)
    }

    /// Read one double-quoted string (the registry's only scalar shape).
    /// Leading and trailing whitespace around the value — the space after
    /// `=`, and any before a trailing comment-free newline — is not part
    /// of it.
    fn unquote(value: &str) -> Result<String, String> {
        value
            .trim()
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .map(str::to_owned)
            .ok_or_else(|| format!("expected a double-quoted string, found {value:?}"))
    }

    /// Read one TOML string array: `["a", "b"]`. The whitespace the
    /// `=` leaves on the value side belongs to the separator, not the
    /// array — trimmed before the brackets are read.
    fn parse_members(value: &str) -> Result<Vec<String>, String> {
        let body = value
            .trim()
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .ok_or_else(|| format!("expected a string array, found {value:?}"))?;
        let body = body.trim();
        if body.is_empty() {
            return Ok(Vec::new());
        }
        body.split(',')
            .map(|member| unquote(member.trim()))
            .collect()
    }

    #[test]
    fn key_parsing_fails_closed_outside_the_six_layouts() {
        let digest = "0f".repeat(32);
        let epoch_ceiling = "999999999999999999"; // the 18-digit bound
        for accepted in [
            format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json"),
            format!("tenants/{TENANT}/v1/control/delegations/{RELAY}/{CLIENT}.json"),
            format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/{epoch_ceiling}.json"),
            format!("tenants/{TENANT}/v1/control/rotations/{CLIENT}/1.json"),
            format!("tenants/{TENANT}/v1/control/receipt-keys/{digest}.json"),
            format!("tenants/{TENANT}/v1/control/authority-rotations/{digest}.json"),
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
            // The authority-rotation layout is key-addressed like the
            // receipt-key one: an epoch segment where the retiring key's
            // ID belongs is a wrong family shape, and a bare segment
            // without the `.json` suffix never parses.
            format!("tenants/{TENANT}/v1/control/authority-rotations/1.json"),
            format!("tenants/{TENANT}/v1/control/authority-rotations/{digest}"),
            // An uppercase rendering is not canonical.
            format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json").to_uppercase(),
            // Over the key-length bound the envelope's key patterns pin:
            // refused on size before the shape is read at all.
            "x".repeat(super::KEY_MAX + 1),
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
        let authority_root =
            archivist_protocol::vocabulary::KeyId::parse(&key_id_of(&[0xab; 32])).unwrap();
        let derived = [
            ControlObjectKey::linked_client(&tenant, &client),
            ControlObjectKey::delegation(&tenant, &relay, &client),
            ControlObjectKey::revocation(&tenant, &client, AuthorizationEpoch::new(1).unwrap()),
            ControlObjectKey::rotation(&tenant, &client, AuthorizationEpoch::new(2).unwrap()),
            ControlObjectKey::receipt_key(&tenant, &digest),
            ControlObjectKey::authority_rotation(&tenant, &authority_root),
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
            (
                authority_rotation_envelope(),
                ControlRecordKind::AuthorityRotation,
                ControlObjectKey::authority_rotation(
                    &tenant,
                    &archivist_protocol::vocabulary::KeyId::parse(&key_id_of(&[0xab; 32])).unwrap(),
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
    fn authority_rotation_links_publish_at_the_predecessor_address() {
        // The write path the chain walk depends on: the offline store
        // accepts a structurally validated link and publishes it at the
        // retiring half's own key ID — the address a verifier holding the
        // pinned root fetches — with no epoch anywhere in its identity
        // (the links themselves are the order) and the family routed
        // through the immutable method alone.
        let store = store();
        let key = format!(
            "tenants/{TENANT}/v1/control/authority-rotations/{}.json",
            key_id_of(&[0xab; 32])
        );
        block_on(store.put_immutable_record(&record(
            ControlRecordKind::AuthorityRotation,
            authority_rotation_envelope(),
        )))
        .unwrap();
        assert_eq!(
            store.backend.stored(&key).as_deref(),
            Some(authority_rotation_envelope().as_slice())
        );

        // The validated view carries the whole addressing decision: the
        // family, the provisioned tenant, the predecessor-addressed key,
        // and no epoch for the chain to disagree about.
        let validated = super::validate_envelope(&authority_rotation_envelope()).unwrap();
        assert_eq!(validated.kind, ControlRecordKind::AuthorityRotation);
        assert_eq!(validated.tenant, tenant());
        assert_eq!(
            validated.key,
            ControlObjectKey::parse(&key).expect("the stored-at key is canonical")
        );
        assert_eq!(validated.epoch, None);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
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
        // key-addressed record (receipt-key, authority-rotation) carrying
        // one at all.
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

        // The authority-rotation link is key-addressed like the receipt-key
        // record: the chain has no epoch sequence, so carrying one is not
        // the record this family writes, and its deriving member
        // (`previous_key_id`) is required and must carry the key grammar.
        assert_rejected(&{
            let mut members = wrapper("authority-rotation", "immutable");
            members.extend([
                ("previous_public_key", text(&"ab".repeat(32))),
                ("key_algorithm", text("ed25519")),
                ("public_key", text(&"9e".repeat(32))),
                ("key_id", text(&key_id_of(&[0x9e; 32]))),
            ]);
            members.push(("authorization_epoch", Value::Int(1)));
            envelope(&members)
        });
        assert_rejected(&without_member(
            &authority_rotation_envelope(),
            "previous_key_id",
        ));
        assert_rejected(&replace_member(
            &authority_rotation_envelope(),
            "previous_key_id",
            text("not-a-key-id"),
        ));

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
    #[allow(clippy::too_many_lines)]
    fn immutable_families_write_once_replay_idempotently_and_reject_incompatible_bytes() {
        // The immutable write class is one rule over its four families
        // (plan Section 5; the trait's EC-06 contract): a fresh record
        // creates the object at its derived key, the byte-identical retry
        // of that same administrative write is already the object there —
        // success without a second write — and any other bytes at the key
        // are the containment case: refuse, and leave exactly what was
        // stored where it was. "Incompatible" is a statement about the
        // whole byte-exact envelope, so each family proves it twice: a
        // payload member mutated, and a wrapper member mutated — a
        // re-signed or re-timestamped variant of the same record is still
        // different bytes at an occupied key, not the same record.
        let cases = vec![
            (
                ControlRecordKind::Revocation,
                format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/3.json"),
                revocation_envelope(3),
                vec![
                    replace_member(
                        &revocation_envelope(3),
                        "revoked_key_id",
                        text(&key_id_of(&[0xef; 32])),
                    ),
                    replace_member(
                        &revocation_envelope(3),
                        "authority_signature",
                        text(&"11".repeat(64)),
                    ),
                ],
            ),
            (
                ControlRecordKind::Rotation,
                format!("tenants/{TENANT}/v1/control/rotations/{CLIENT}/3.json"),
                rotation_envelope(3),
                vec![
                    replace_member(&rotation_envelope(3), "public_key", text(&"ef".repeat(32))),
                    replace_member(
                        &rotation_envelope(3),
                        "signed_at",
                        text("2026-09-12T00:00:00Z"),
                    ),
                ],
            ),
            (
                ControlRecordKind::ReceiptKey,
                format!(
                    "tenants/{TENANT}/v1/control/receipt-keys/{}.json",
                    key_id_of(&[0x3c; 32])
                ),
                receipt_key_envelope(),
                vec![
                    replace_member(
                        &receipt_key_envelope(),
                        "valid_until",
                        text("2026-10-12T00:00:00Z"),
                    ),
                    replace_member(
                        &receipt_key_envelope(),
                        "authority_signature",
                        text(&"22".repeat(64)),
                    ),
                ],
            ),
            (
                ControlRecordKind::AuthorityRotation,
                format!(
                    "tenants/{TENANT}/v1/control/authority-rotations/{}.json",
                    key_id_of(&[0xab; 32])
                ),
                authority_rotation_envelope(),
                vec![
                    replace_member(
                        &authority_rotation_envelope(),
                        "public_key",
                        text(&"ef".repeat(32)),
                    ),
                    replace_member(
                        &authority_rotation_envelope(),
                        "authority_signature",
                        text(&"33".repeat(64)),
                    ),
                ],
            ),
        ];
        for (kind, key, record_bytes, conflictings) in cases {
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

            // Every incompatible variant at the same derived key is the
            // EC-06 integrity conflict — refused, and nothing of the
            // conflicting record is written over what is stored.
            for conflicting in &conflictings {
                assert_ne!(conflicting, &record_bytes);
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
    fn successive_authority_rotations_append_one_object_per_retired_key() {
        // The authority-rotation family's append-only history, at the
        // store level: each link is addressed at the key it retires, so
        // successive rotations land as distinct objects that coexist —
        // the second write never touches the first, and re-publishing
        // either link byte-identically stays the idempotent replay its
        // immutable class promises. The chain order itself (in-order
        // append, one link per retired key) is the verifier's gate in
        // `archivist-auth`; the store contributes exactly the addressing
        // and the write class, which is what this proof pins.
        let first = authority_rotation_envelope();
        let first_key = format!(
            "tenants/{TENANT}/v1/control/authority-rotations/{}.json",
            key_id_of(&[0xab; 32])
        );
        // The next link: the `9e` successor half retires itself and
        // establishes a fresh half, at the successor's own address.
        let second = {
            let mut members = wrapper("authority-rotation", "immutable");
            members.extend([
                ("previous_public_key", text(&"9e".repeat(32))),
                ("previous_key_id", text(&key_id_of(&[0x9e; 32]))),
                ("key_algorithm", text("ed25519")),
                ("public_key", text(&"7c".repeat(32))),
                ("key_id", text(&key_id_of(&[0x7c; 32]))),
            ]);
            envelope(&members)
        };
        let second_key = format!(
            "tenants/{TENANT}/v1/control/authority-rotations/{}.json",
            key_id_of(&[0x9e; 32])
        );

        let store = store();
        block_on(
            store
                .put_immutable_record(&record(ControlRecordKind::AuthorityRotation, first.clone())),
        )
        .unwrap();
        block_on(store.put_immutable_record(&record(
            ControlRecordKind::AuthorityRotation,
            second.clone(),
        )))
        .unwrap();
        assert_eq!(
            store.backend.stored(&first_key).as_deref(),
            Some(first.as_slice()),
            "the second link must not touch the first"
        );
        assert_eq!(
            store.backend.stored(&second_key).as_deref(),
            Some(second.as_slice())
        );

        // Both replays stay idempotent, each issuing no second write.
        block_on(
            store
                .put_immutable_record(&record(ControlRecordKind::AuthorityRotation, first.clone())),
        )
        .unwrap();
        block_on(store.put_immutable_record(&record(
            ControlRecordKind::AuthorityRotation,
            second.clone(),
        )))
        .unwrap();
        assert_eq!(store.backend.puts_at(&first_key), 1);
        assert_eq!(store.backend.puts_at(&second_key), 1);
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
        // The refused writes left the stored pointer where it was — and
        // issued no write of their own: the two puts so far are the two
        // accepted pointers, epochs 2 and 3.
        assert_eq!(store.backend.puts_at(&key), 2);
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

        // And the epoch, not the bytes, is the gate: different payload
        // carrying the *stored* epoch is still stale — a pointer cannot
        // be rewritten at epoch 7 with bytes the epoch-7 signature never
        // covered, any more than a replay of the exact bytes can.
        let rewrite = replace_member(
            &linked_client_envelope(7),
            "public_key",
            text(&"ef".repeat(32)),
        );
        assert_ne!(rewrite, linked_client_envelope(7));
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::LinkedClient,
                rewrite,
            )))),
            StorageErrorKind::StaleEpoch
        );
        assert_eq!(
            store.backend.puts_at(&key),
            3,
            "a same-epoch rewrite must not write"
        );
        assert_eq!(
            store.backend.stored(&key).as_deref(),
            Some(linked_client_envelope(7).as_slice())
        );

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
        // Two accepted puts on this relation's sequence — epochs 1 and 2 —
        // and neither stale refusal added a third.
        assert_eq!(store.backend.puts_at(&delegation_key), 2);
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
            // Stronger still: the epoch gate ran before the backend saw
            // *any* request at all — the only requests ever issued are the
            // initial pointer write's own read and put.
            assert_eq!(
                store.backend.requests(),
                2,
                "invalid epochs must be refused before any request is issued"
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
        // And subtler: a *well-formed* record of the right family whose
        // own members derive a *different* key. The stored pointer must
        // re-derive to the very key it sits at; one that does not is
        // bytes moved to the wrong address, and no replacement this store
        // offers may interpret or displace it.
        store.backend.preload(
            &key,
            &replace_member(&linked_client_envelope(5), "client_id", text(RELAY)),
        );
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::LinkedClient,
                linked_client_envelope(2),
            )))),
            StorageErrorKind::IntegrityConflict
        );
        // Every corrupt-pointer refusal issued no write either: the key
        // still holds exactly the corrupt bytes last preloaded, unchanged.
        assert_eq!(
            store.backend.puts_at(&key),
            0,
            "a corrupt pointer must not be written over"
        );
        assert_eq!(
            store.backend.stored(&key).as_deref(),
            Some(replace_member(&linked_client_envelope(5), "client_id", text(RELAY)).as_slice())
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
        // The authority-rotation link is immutable like the rest of the
        // key-addressed families — the chain history appends, never moves
        // a pointer.
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::AuthorityRotation,
                authority_rotation_envelope(),
            )))),
            StorageErrorKind::MalformedInput
        );
        // Nothing was written by the refused pointer writes.
        assert!(
            store
                .backend
                .stored(&format!(
                    "tenants/{TENANT}/v1/control/authority-rotations/{}.json",
                    key_id_of(&[0xab; 32])
                ))
                .is_none()
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
        // The refusal happened in the store's validation, before the
        // backend saw anything: no read, no write, no request at all.
        assert_eq!(
            store.backend.requests(),
            0,
            "a foreign-tenant record must be refused before any request is issued"
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
            super::DETAIL_AUTHORITY_EPOCH,
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

/// The Phase 3 routing proofs: the authority's signed publications
/// (`archivist-auth`) carried through [`S3ControlAdminStore`]'s two typed
/// entries, over a mock of the [`ControlAdminBackend`] seam whose policy
/// is the deployment's own prefix rule. Real signed envelopes throughout —
/// a deterministic authority half signs, a deterministic installation
/// identity asks, and every record that lands re-verifies through the
/// auth crate the way a reader would.
#[cfg(test)]
mod publication_tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use archivist_auth::authority::PinnedAuthorityRoot;
    use archivist_auth::ed25519;
    use archivist_auth::identity::InstallationIdentity;
    use archivist_auth::link::{
        ClientLinkPublication, LinkRequest, RequestedScopes, ScopeOperation, approve_link_request,
    };
    use archivist_auth::revocation::{
        LinkedClientPointer, RevocationPublication, RevocationRecord, publish_revocation,
    };
    use archivist_protocol::vocabulary::{
        ClientId, Ed25519PublicKey, HarnessId, KeyId, TenantId, Timestamp,
    };
    use archivist_storage::control::{AuthorizationEpoch, ControlRecordKind};

    use super::{
        ControlAdminBackend, ControlObjectKey, S3ControlAdminStore, StorageError, StorageErrorKind,
    };
    use crate::config::ControlAdminConfig;

    // The deterministic story: the same fixture identifiers the auth
    // crate's own approval tests pin, so every signature below is
    // reproducible byte for byte and every re-approval re-derives the
    // same envelope.
    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";
    const AUTHORITY_SEED: [u8; 32] = [0x17; 32];
    const CLIENT_SEED: [u8; 32] = [0x2a; 32];
    const APPROVAL_INSTANT: &str = "2026-09-19T00:00:00Z";
    const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
    const ADMIN_REF: &str = "file:/etc/archivist/storage/control-admin-credentials";
    const CONTROL_BUCKET: &str = "archivist-control-example";

    fn tenant() -> TenantId {
        TENANT.parse().expect("grammar")
    }

    fn client_id() -> ClientId {
        CLIENT.parse().expect("grammar")
    }

    fn instant() -> Timestamp {
        Timestamp::parse(APPROVAL_INSTANT).expect("pinned test instant")
    }

    fn root() -> PinnedAuthorityRoot {
        PinnedAuthorityRoot::new(
            tenant(),
            Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&AUTHORITY_SEED)),
        )
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

    /// The deterministic installation identity: the client half its seed
    /// derives, no entropy in the story.
    fn installation() -> InstallationIdentity {
        let public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&CLIENT_SEED));
        InstallationIdentity::from_seed(client_id(), CLIENT_SEED, public)
            .expect("the seed derives the identity")
    }

    /// The link request the installation emits: public identity, this
    /// tenant, one harness and the one v1 operation.
    fn link_draft(request_tenant: &TenantId) -> Vec<u8> {
        let scopes = RequestedScopes::new(
            vec![HarnessId::parse("claude-code").expect("grammar")],
            vec![ScopeOperation::Ingest],
        )
        .expect("an in-bounds scope");
        LinkRequest::new(
            installation().public_identity(),
            request_tenant.clone(),
            scopes,
        )
        .canonical_bytes()
    }

    /// A chain fetch that finds nothing: the authority half here is the
    /// pinned root itself, and a root needs no links.
    fn no_links(_: &KeyId) -> Option<Vec<u8>> {
        None
    }

    /// The approval the administrator act produces: the signed
    /// linked-client current-pointer publication at epoch 1.
    fn approval() -> ClientLinkPublication {
        approve_link_request(
            &AUTHORITY_SEED,
            &root(),
            &link_draft(&tenant()),
            &instant(),
            no_links,
        )
        .expect("the golden draft approves")
    }

    /// The verified pointer of one approval envelope, exactly as a reader
    /// re-derives it from the pinned root.
    fn pointer_of(envelope: &[u8]) -> LinkedClientPointer {
        LinkedClientPointer::verify(&root(), envelope, no_links, &client_id())
            .expect("the approval envelope verifies from the pinned root")
    }

    /// The revocation publication at the pointer's own epoch — the
    /// administrator act that completes the link termination.
    fn revocation_of(pointer: &LinkedClientPointer) -> RevocationPublication {
        publish_revocation(
            &AUTHORITY_SEED,
            &tenant(),
            &client_id(),
            pointer.epoch(),
            pointer.key_id(),
            pointer,
            &instant(),
        )
        .expect("the pointer's own epoch revokes")
    }

    /// The derived keys the two publications are addressed at, from the
    /// store side's own constructors.
    fn pointer_key() -> String {
        ControlObjectKey::linked_client(&tenant(), &client_id())
            .as_str()
            .to_owned()
    }

    fn revocation_key() -> String {
        ControlObjectKey::revocation(&tenant(), &client_id(), AuthorizationEpoch::new(1).unwrap())
            .as_str()
            .to_owned()
    }

    /// A no-dependency executor for futures that complete without pending
    /// (the same helper this module's store tests use).
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

    /// Which deployment policy a mock backend enforces, as a literal
    /// string-prefix rule over object keys — the same shape the real
    /// backend binding grants and refuses with.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Policy {
        /// The administration credential: read-write below
        /// `tenants/<tenant>/v1/control/`, every other prefix denied.
        Administration,
        /// The widest grant an ingest credential could carry: every
        /// prefix an ingest replica may touch, everything except the
        /// control plane. Under this policy any out-of-prefix write the
        /// store attempted would be *granted* — bytes would land and be
        /// seen — so an empty bucket after refused control writes is the
        /// tripwire proof that the store aims only at the control prefix.
        Ingest,
    }

    /// The mock [`ControlAdminBackend`]: one policy, one object map, and
    /// the two counters a prefix proof reads — every requested key, and
    /// every put that was actually issued.
    #[derive(Clone, Debug)]
    struct PolicyBackend {
        policy: Policy,
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        requested: Arc<Mutex<Vec<String>>>,
        puts: Arc<Mutex<u32>>,
    }

    impl PolicyBackend {
        fn new(policy: Policy) -> Self {
            Self {
                policy,
                objects: Arc::new(Mutex::new(HashMap::new())),
                requested: Arc::new(Mutex::new(Vec::new())),
                puts: Arc::new(Mutex::new(0)),
            }
        }

        /// The reconnected backend a replica replacement builds: a fresh
        /// client — none of the first store's in-process counters — over
        /// the same bucket state.
        fn reconnected(&self) -> Self {
            Self {
                policy: self.policy,
                objects: Arc::clone(&self.objects),
                requested: Arc::new(Mutex::new(Vec::new())),
                puts: Arc::new(Mutex::new(0)),
            }
        }

        fn grants(&self, key: &str) -> bool {
            let control_prefix = format!("tenants/{TENANT}/v1/control/");
            match self.policy {
                Policy::Administration => key.starts_with(&control_prefix),
                Policy::Ingest => !key.starts_with(&control_prefix),
            }
        }

        fn requested(&self) -> Vec<String> {
            self.requested.lock().expect("test backend lock").clone()
        }

        fn puts(&self) -> u32 {
            *self.puts.lock().expect("test backend lock")
        }

        fn stored(&self, key: &str) -> Option<Vec<u8>> {
            self.objects
                .lock()
                .expect("test backend lock")
                .get(key)
                .cloned()
        }

        fn landing_sites(&self) -> Vec<String> {
            self.objects
                .lock()
                .expect("test backend lock")
                .keys()
                .cloned()
                .collect()
        }
    }

    impl ControlAdminBackend for PolicyBackend {
        async fn get_control_object(
            &self,
            key: &ControlObjectKey,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            self.requested
                .lock()
                .expect("test backend lock")
                .push(key.as_str().to_owned());
            if !self.grants(key.as_str()) {
                return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
            }
            Ok(self.stored(key.as_str()))
        }

        async fn put_control_object(
            &self,
            key: &ControlObjectKey,
            bytes: &[u8],
        ) -> Result<(), StorageError> {
            self.requested
                .lock()
                .expect("test backend lock")
                .push(key.as_str().to_owned());
            if !self.grants(key.as_str()) {
                return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
            }
            *self.puts.lock().expect("test backend lock") += 1;
            self.objects
                .lock()
                .expect("test backend lock")
                .insert(key.as_str().to_owned(), bytes.to_vec());
            Ok(())
        }
    }

    #[test]
    fn approval_and_revocation_route_through_the_store() {
        let backend = PolicyBackend::new(Policy::Administration);
        let store = S3ControlAdminStore::new(admin_config(), backend.clone());
        let approved = approval();

        // The approval routes onto the current-pointer class and lands,
        // byte-exact, at the derived key the authority declared.
        block_on(store.put_link_approval(&approved)).expect("the approval routes");
        assert_eq!(approved.object_key(), pointer_key());
        assert_eq!(
            backend.stored(approved.object_key()).as_deref(),
            Some(approved.envelope())
        );
        assert_eq!(backend.puts(), 1);

        // A second approval of the same request re-derives the same
        // signed bytes — the same epoch — and the pointer family refuses
        // any write whose epoch is not strictly greater than the stored
        // one. The refusal changes nothing on the bucket.
        let replay = approval();
        assert_eq!(replay, approved, "re-approval is byte-identical");
        assert_eq!(
            block_on(store.put_link_approval(&replay))
                .expect_err("an equal-epoch pointer is stale")
                .kind(),
            StorageErrorKind::StaleEpoch
        );
        assert_eq!(backend.puts(), 1, "a stale pointer must not write");
        assert_eq!(
            backend.stored(approved.object_key()).as_deref(),
            Some(approved.envelope())
        );

        // The stored pointer re-verifies through the auth crate and
        // carries the epoch the revocation is published at.
        let stored_pointer = backend.stored(approved.object_key()).expect("stored");
        let pointer = pointer_of(&stored_pointer);
        assert_eq!(pointer.epoch(), 1);
        assert_eq!(pointer.client_id(), &client_id());

        // The revocation routes onto the immutable class at the pointer's
        // own epoch and lands byte-exact at its derived key.
        let revoked = revocation_of(&pointer);
        assert_eq!(revoked.object_key(), revocation_key());
        block_on(store.put_revocation(&revoked)).expect("the revocation routes");
        assert_eq!(
            backend.stored(revoked.object_key()).as_deref(),
            Some(revoked.envelope())
        );
        assert_eq!(backend.puts(), 2);

        // The lost-response retry is the idempotent replay the immutable
        // class promises: the record is already the object at its key.
        block_on(store.put_revocation(&revoked)).expect("the replay is idempotent");
        assert_eq!(backend.puts(), 2, "a replay must not write");

        // The stored revocation re-verifies through the auth crate too,
        // against the address it was stored at.
        let stored_revocation = backend.stored(revoked.object_key()).expect("stored");
        RevocationRecord::verify(
            &root(),
            &stored_revocation,
            no_links,
            &client_id(),
            pointer.epoch(),
        )
        .expect("the stored revocation re-verifies from the pinned root");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_replica_replacement_reads_back_byte_identical_records() {
        // The persistence clause the plan pins: the control plane's state
        // lives in the bucket, not in the store. A fresh store instance
        // over a reconnected backend — a new client over the same bucket —
        // reads every record back byte-identical, every record re-verifies
        // through the auth crate from exactly those fresh bytes, and the
        // replacement enforces the same monotonic epochs the first store
        // did: the replaced state keeps the rule.
        let backend = PolicyBackend::new(Policy::Administration);
        let store = S3ControlAdminStore::new(admin_config(), backend.clone());
        let approved = approval();
        let pointer = pointer_of(approved.envelope());
        let revoked = revocation_of(&pointer);
        block_on(store.put_link_approval(&approved)).expect("the approval routes");
        block_on(store.put_revocation(&revoked)).expect("the revocation routes");

        let replacement = backend.reconnected();
        let fresh = S3ControlAdminStore::new(admin_config(), replacement.clone());

        // Every record reads back byte-identical at the key the authority
        // declared — which is the derived key the store wrote: the two
        // addressings agree across the crate boundary.
        let read_pointer = replacement
            .stored(approved.object_key())
            .expect("the pointer survives the replacement");
        let read_revocation = replacement
            .stored(revoked.object_key())
            .expect("the revocation survives the replacement");
        assert_eq!(read_pointer, approved.envelope());
        assert_eq!(read_revocation, revoked.envelope());
        assert_eq!(
            ControlObjectKey::parse(approved.object_key())
                .expect("the declared key is a derived layout")
                .kind(),
            ControlRecordKind::LinkedClient
        );

        // Both re-verify through the auth crate from the fresh reads.
        let replacement_pointer = pointer_of(&read_pointer);
        assert_eq!(replacement_pointer.epoch(), 1);
        RevocationRecord::verify(
            &root(),
            &read_revocation,
            no_links,
            &client_id(),
            replacement_pointer.epoch(),
        )
        .expect("the replaced revocation re-verifies from the pinned root");

        // And the replacement acts on the same state under the same
        // rules: the revocation replay is still idempotent, and the
        // approval's epoch is still the ceiling — the monotonic rule
        // survived the replacement.
        block_on(fresh.put_revocation(&revoked)).expect("the replacement sees the same state");
        assert_eq!(replacement.puts(), 0, "the replay wrote nothing new");
        assert_eq!(
            block_on(fresh.put_link_approval(&approved))
                .expect_err("the replaced state keeps the epoch rule")
                .kind(),
            StorageErrorKind::StaleEpoch
        );
        assert_eq!(replacement.puts(), 0);
    }

    #[test]
    fn every_routed_request_stays_below_the_control_prefix() {
        // The administration backend grants only the tenant control
        // prefix, so a store that ever aimed a request outside it would
        // be refused mid-flow and fail it. The flow completing, plus the
        // requested-key log, is the proof: every request — granted or
        // refused — named a key below `tenants/<tenant>/v1/control/`.
        let backend = PolicyBackend::new(Policy::Administration);
        let store = S3ControlAdminStore::new(admin_config(), backend.clone());
        let approved = approval();
        let revoked = revocation_of(&pointer_of(approved.envelope()));
        block_on(store.put_link_approval(&approved)).expect("the approval routes");
        block_on(store.put_revocation(&revoked)).expect("the revocation routes");

        let control_prefix = format!("tenants/{TENANT}/v1/control/");
        let requested = backend.requested();
        assert!(
            !requested.is_empty(),
            "the flow must have reached the backend"
        );
        for key in requested {
            assert!(
                key.starts_with(&control_prefix),
                "{key} aimed outside the control prefix"
            );
        }
        // The writes landed at exactly the two derived keys — the
        // pointer and the epoch-addressed revocation, nothing else.
        assert_eq!(backend.puts(), 2);
        let mut sites = backend.landing_sites();
        sites.sort();
        assert_eq!(sites, vec![pointer_key(), revocation_key()]);
    }

    #[test]
    fn an_ingest_scoped_backend_never_lands_a_control_record() {
        // The ingest credential's policy denies everything below the
        // tenant control prefix — and this mock grants *everything else*,
        // so any out-of-prefix write the store attempted would land bytes
        // and be seen. Both routes are refused, nothing lands anywhere,
        // and no put is ever issued: every request the store made aimed
        // below the control prefix, exactly where the policy denied it.
        let backend = PolicyBackend::new(Policy::Ingest);
        let store = S3ControlAdminStore::new(admin_config(), backend.clone());
        let approved = approval();
        let revoked = revocation_of(&pointer_of(approved.envelope()));

        assert_eq!(
            block_on(store.put_link_approval(&approved))
                .expect_err("control records are not an ingest credential's to write")
                .kind(),
            StorageErrorKind::ScopeViolation
        );
        assert_eq!(
            block_on(store.put_revocation(&revoked))
                .expect_err("control records are not an ingest credential's to write")
                .kind(),
            StorageErrorKind::ScopeViolation
        );

        assert!(
            backend.landing_sites().is_empty(),
            "no byte may land under an ingest-scoped credential"
        );
        assert_eq!(backend.puts(), 0, "no put may be issued");
        let control_prefix = format!("tenants/{TENANT}/v1/control/");
        let requested = backend.requested();
        assert!(
            !requested.is_empty(),
            "the refusals happened at the backend"
        );
        for key in requested {
            assert!(
                key.starts_with(&control_prefix),
                "{key} aimed outside the control prefix"
            );
        }
    }

    #[test]
    fn a_foreign_tenant_publication_is_refused_before_any_request() {
        // The other tenant's authority signs under its own root, for its
        // own tenant; this store's administration identity is provisioned
        // for one tenant and refuses the publication on its declared
        // address before the backend sees anything at all.
        let other_tenant: TenantId = OTHER_TENANT.parse().expect("grammar");
        let other_root = PinnedAuthorityRoot::new(
            other_tenant.clone(),
            Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&AUTHORITY_SEED)),
        );
        let foreign = approve_link_request(
            &AUTHORITY_SEED,
            &other_root,
            &link_draft(&other_tenant),
            &instant(),
            no_links,
        )
        .expect("the foreign authority signs its own tenant's request");

        let backend = PolicyBackend::new(Policy::Administration);
        let store = S3ControlAdminStore::new(admin_config(), backend.clone());
        assert_eq!(
            block_on(store.put_link_approval(&foreign))
                .expect_err("a foreign-tenant publication is outside this identity")
                .kind(),
            StorageErrorKind::ScopeViolation
        );
        assert_eq!(
            backend.requested(),
            Vec::<String>::new(),
            "the refusal happened before any request was issued"
        );
        assert_eq!(backend.puts(), 0);
        assert!(backend.landing_sites().is_empty());
    }
}
