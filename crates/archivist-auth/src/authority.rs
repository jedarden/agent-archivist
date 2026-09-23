// SPDX-License-Identifier: Apache-2.0

//! The tenant-authority key rotation chain (control-trust story item 7;
//! `schemas/v1/control-authority-rotation.json`, plan Section 5's
//! control-plane boundary and the envelope's authority-chain rule).
//!
//! One immutable link per retired key: the authority-rotation record
//! carries both public halves and both pinned-derivation key IDs, is
//! addressed at the retiring half's own ID
//! (`tenants/<tenant>/v1/control/authority-rotations/<previous_key_id>.json`,
//! written by the offline `ControlAdminStore`), and is signed by the key
//! it retires — the predecessor's signed witness to its own retirement,
//! because the successor cannot witness its own establishment. Verification
//! always starts at the pinned root and walks forward:
//! fetch-verify-adopt-repeat, never trusting a key because a record
//! asserts it.
//!
//! This module is the verifier core, storage-agnostic on purpose: the
//! walk reads links through a caller-supplied fetch (the bytes a
//! `ControlReadStore` serves at the predecessor's address), so the same
//! code resolves signers on a client, on an ingestion replica, and in
//! tests, with every storage decision left to the caller (plan Section
//! 5) — and with the caller-side 60-second trust cache itself left to
//! its own deliverable, which composes with this rule at the resolution
//! seam this module ships by the construction the next paragraph pins
//! (EC-09).
//!
//! Three surfaces cover the story end to end: [`resolve_authority`] walks
//! the chain and [`ResolvedAuthority`] carries the acceptance decision;
//! [`verify_control_record`] verifies any tenant-authority-signed control
//! record — the either-half rule inside the window, fail-closed past it,
//! and retained records verifiable forever; and
//! [`prepare_rotation_publication`] gates the offline store's publication
//! of a new link against the chain state, so succession stays in order
//! and one retired key keeps exactly one link. Two more serve the
//! consumers of those three: [`resolve_active_authority`] walks to the
//! chain's current tip — the active trust anchor a fresh publication or
//! a readiness check wants — and
//! [`verify_control_record_resolved`] is the resolution seam a bounded
//! trust cache's cached verifier composes at.
//!
//! The acceptance rule this module pins, at the record's own `signed_at`
//! and never at read time:
//!
//! - the pinned root may sign from linking until the link that retires it
//!   says otherwise; a successor may sign from its establishing link's
//!   `signed_at` (inclusive) — a record whose instant precedes that fails
//!   closed;
//! - for `ROTATION_VERIFICATION_OVERLAP_HOURS` (24) after a link's
//!   `signed_at` (inclusive at the boundary), the retired predecessor's
//!   half still verifies — the dual-key window the offline store's cutover
//!   races — and past it a predecessor-signed record fails closed, while
//!   everything either half signed inside its validity verifies for as
//!   long as the records are retained;
//! - a chain that cannot be walked from the pinned root to the signer —
//!   a missing, mis-signed, mis-addressed, cross-tenant, non-advancing,
//!   or cyclical link — fails closed as a broken chain.
//!
//! The 60-second trust cache (plan Section 5; EC-09) composes with this
//! rule by construction: a resolution is a pure function of the link
//! bytes the walk fetched, so a replica serving a resolution from a view
//! up to 60 seconds stale accepts exactly the records that view's chain
//! state accepts — and because acceptance is evaluated at each record's
//! own `signed_at`, no record the stale view accepted is invalidated
//! when the fresher view (the retirement link) arrives. Propagation lag
//! can only widen acceptance temporarily, never retroactively revoke.

use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{
    Ed25519PublicKey, Ed25519Signature, KeyId, SignatureAlgorithm, TenantId, Timestamp,
};

use crate::ed25519;

/// The control trust namespace every control record carries
/// (`archivist.control/v1`, the envelope's `schema` member): an unknown
/// namespace fails closed before anything else is read.
const CONTROL_NAMESPACE: &str = "archivist.control/v1";

/// This record type's token in the envelope's closed record-type enum.
const RECORD_TYPE: &str = "authority-rotation";

/// The write class this immutable record type carries.
const RECORD_KIND: &str = "immutable";

/// The complete, closed member set of the authority-rotation record
/// (`schemas/v1/control-authority-rotation.json`: seven wrapper members
/// plus the five chain members, `additionalProperties: false`). A record
/// that parses carries exactly these members and no others.
const MEMBERS: [&str; 12] = [
    "authority_key_id",
    "authority_signature",
    "key_algorithm",
    "key_id",
    "previous_key_id",
    "previous_public_key",
    "public_key",
    "record_kind",
    "record_type",
    "schema",
    "signed_at",
    "tenant_id",
];

/// `rotationVerificationOverlapHours` — 24 (plan Section 5: "Key rotation
/// accepts old and new keys for 24 hours"; the envelope's named constant,
/// pinned by the schema gate over the registry, the envelope, and every
/// consuming schema). For this many hours after an authority-rotation
/// link's `signed_at`, inclusive at the boundary, either authority half
/// may sign control records and receipt-key certifications and both
/// verify; past the window a predecessor-signed record fails closed. The
/// window bounds signing acceptance, never the validity of what was
/// already signed inside it.
pub const ROTATION_VERIFICATION_OVERLAP_HOURS: i64 = 24;

/// The overlap expressed in whole seconds, the form the acceptance
/// arithmetic compares instants in.
const OVERLAP_SECONDS: i64 = ROTATION_VERIFICATION_OVERLAP_HOURS * 60 * 60;

/// Why an authority-chain verification failed.
///
/// Every variant is a unit: diagnostics name the failure class and never
/// carry a key value, a signature, or any other record content (SEC-004),
/// exactly like [`crate::error::IdentityError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityChainError {
    /// A record (or a presented signing instant) is not well-formed: not
    /// canonical JSON, not the closed twelve-member shape, a member
    /// failing its grammar, an unknown key algorithm, or a timestamp that
    /// is not a real calendar instant (VAL-002).
    MalformedRecord,
    /// A record disagrees about what it is: the namespace, record type,
    /// or write class is not this record type's, the tenant is not the
    /// pinned root's tenant, or the bytes sit at an address whose key
    /// segment is not the record's own `previous_key_id`.
    RecordDisagreement,
    /// A key ID member is not the pinned SHA-256 derivation of its public
    /// half — the identities are asserted, not computable from the
    /// record's own public material (VAL-002).
    KeyDerivation,
    /// The chain rule fails: `authority_key_id` is not the
    /// `previous_key_id` (someone other than the retired key signed the
    /// retirement), or the succession does not strictly advance (a link
    /// that re-establishes a key the walk already holds).
    ChainRule,
    /// A predecessor signature does not verify under the control-record-v1
    /// construction against the half the walk already trusts.
    Signature,
    /// The walk from the pinned root cannot reach the signer: the store
    /// holds no link at some predecessor address between them. A signer
    /// no chain names is untrusted, not best-effort accepted.
    Unreachable,
    /// The record's own `signed_at` precedes its signer's establishing
    /// link — a successor cannot sign before it exists.
    NotEstablished,
    /// The signer's half was retired and the record's own `signed_at`
    /// falls past the 24-hour dual-key window.
    Retired,
    /// A verified link already retires this key: immutable,
    /// predecessor-addressed storage admits no second link for one
    /// retired key, so the offered publication is refused before any
    /// write is attempted.
    AlreadyRetired,
}

impl std::fmt::Display for AuthorityChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::MalformedRecord => {
                "authority record is not a well-formed authority-rotation link"
            }
            Self::RecordDisagreement => {
                "authority record disagrees with its claimed type, tenant, or address"
            }
            Self::KeyDerivation => {
                "authority key identifier is not the pinned derivation of its public half"
            }
            Self::ChainRule => {
                "authority rotation violates the chain rule: the predecessor must sign a strictly advancing succession"
            }
            Self::Signature => "authority rotation signature failed predecessor verification",
            Self::Unreachable => "signing key is not reachable from the pinned authority root",
            Self::NotEstablished => {
                "record predates the authority link that established its signer"
            }
            Self::Retired => {
                "record was signed by a retired authority half past the verification overlap"
            }
            Self::AlreadyRetired => {
                "a verified authority link already retires this key; a key retires once"
            }
        };
        f.write_str(text)
    }
}

impl std::error::Error for AuthorityChainError {}

/// The tenant authority root a client or ingestion replica pinned during
/// linking (ID-009): the public half the whole chain is anchored at. The
/// pin never moves — linking pins the root for the client's lifetime and
/// the chain extends it forward, so an authority rotation never requires
/// a re-link.
///
/// The key ID is derived, never asserted: construction takes the public
/// half alone and computes the pinned SHA-256 identifier, so a root cannot
/// carry an identity its half does not hash to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PinnedAuthorityRoot {
    tenant_id: TenantId,
    public_key: Ed25519PublicKey,
    key_id: KeyId,
}

impl PinnedAuthorityRoot {
    /// Adopt the public half a tenant's clients pinned, for that tenant.
    ///
    /// The chain a root establishes has no force outside its tenant: a
    /// link carrying any other tenant is a cross-tenant forgery and the
    /// walk rejects it.
    #[must_use]
    pub fn new(tenant_id: TenantId, public_key: Ed25519PublicKey) -> Self {
        Self {
            key_id: KeyId::from_public_key(&public_key),
            tenant_id,
            public_key,
        }
    }

    /// The pinned half's identifier under the pinned derivation.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The pinned public half.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// The tenant whose authority this root is.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// One validated authority-rotation record — the immutable chain link
/// that retires one tenant-authority half and establishes its successor.
///
/// Construction ([`AuthorityRotationLink::parse`]) validates the complete
/// closed shape, every member grammar, both pinned key-ID derivations, and
/// the chain rule; it does not verify the signature, because a signature
/// means something only against the half a walk already trusts
/// ([`AuthorityRotationLink::verify_predecessor_signature`] does that,
/// and the walk calls it). No private material exists anywhere in this
/// type: both halves here are public, and the successor's private half is
/// generated by the tenant operator out of band (SEC-006).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityRotationLink {
    tenant_id: TenantId,
    previous_public_key: Ed25519PublicKey,
    previous_key_id: KeyId,
    key_algorithm: SignatureAlgorithm,
    public_key: Ed25519PublicKey,
    key_id: KeyId,
    signed_at: Timestamp,
    authority_key_id: KeyId,
    authority_signature: Ed25519Signature,
}

impl AuthorityRotationLink {
    /// Parse and validate the stored record bytes, failing closed on the
    /// first violated rule of the record's own contract.
    ///
    /// The bytes need not already be canonical: the signing construction
    /// hashes the RFC 8785 canonicalization of the object, so the same
    /// record verifies whatever byte order it was stored under.
    ///
    /// # Errors
    /// [`AuthorityChainError::MalformedRecord`] for a shape, grammar,
    /// algorithm, or calendar failure; [`AuthorityChainError::
    /// RecordDisagreement`] when the namespace, record type, or write
    /// class is not this record type's;
    /// [`AuthorityChainError::KeyDerivation`] when either key ID is not
    /// the pinned SHA-256 of its public half;
    /// [`AuthorityChainError::ChainRule`] when `authority_key_id` is not
    /// the `previous_key_id`, or the link does not strictly advance.
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthorityChainError> {
        let malformed = AuthorityChainError::MalformedRecord;
        let Value::Object(object) = json::parse(bytes).map_err(|_| malformed)? else {
            return Err(malformed);
        };
        // The closed shape: exactly the twelve members the schema pins,
        // each a JSON string. Length first, so an extra member never
        // parses as a near-miss of the type.
        if object.len() != MEMBERS.len() {
            return Err(malformed);
        }
        for name in MEMBERS {
            if text_member(&object, name).is_none() {
                return Err(malformed);
            }
        }

        if text_member(&object, "schema") != Some(CONTROL_NAMESPACE) {
            return Err(AuthorityChainError::RecordDisagreement);
        }
        if text_member(&object, "record_type") != Some(RECORD_TYPE) {
            return Err(AuthorityChainError::RecordDisagreement);
        }
        if text_member(&object, "record_kind") != Some(RECORD_KIND) {
            return Err(AuthorityChainError::RecordDisagreement);
        }

        let tenant_text = text_member(&object, "tenant_id").ok_or(malformed)?;
        let tenant_id =
            TenantId::parse(tenant_text).map_err(|_| AuthorityChainError::MalformedRecord)?;
        let previous_public_text = text_member(&object, "previous_public_key").ok_or(malformed)?;
        let previous_public_key = Ed25519PublicKey::parse(previous_public_text)
            .map_err(|_| AuthorityChainError::MalformedRecord)?;
        let public_text = text_member(&object, "public_key").ok_or(malformed)?;
        let public_key = Ed25519PublicKey::parse(public_text)
            .map_err(|_| AuthorityChainError::MalformedRecord)?;
        let key_algorithm_text = text_member(&object, "key_algorithm").ok_or(malformed)?;
        // Unknown algorithm fails closed before either key is used, the
        // closed enum's own rule.
        let key_algorithm = SignatureAlgorithm::parse(key_algorithm_text)
            .map_err(|_| AuthorityChainError::MalformedRecord)?;
        let signed_at_text = text_member(&object, "signed_at").ok_or(malformed)?;
        let signed_at =
            Timestamp::parse(signed_at_text).map_err(|_| AuthorityChainError::MalformedRecord)?;
        // The grammar alone accepts impossible instants; VAL-002's
        // semantic check is part of the record's contract.
        if !signed_at.calendar_valid() {
            return Err(AuthorityChainError::MalformedRecord);
        }

        // Both key IDs are computable from this record's own public
        // material, never asserted (VAL-002).
        let previous_key_id_text = text_member(&object, "previous_key_id").ok_or(malformed)?;
        let previous_key_id =
            KeyId::parse(previous_key_id_text).map_err(|_| AuthorityChainError::MalformedRecord)?;
        if previous_key_id != KeyId::from_public_key(&previous_public_key) {
            return Err(AuthorityChainError::KeyDerivation);
        }
        let key_id_text = text_member(&object, "key_id").ok_or(malformed)?;
        let key_id = KeyId::parse(key_id_text).map_err(|_| AuthorityChainError::MalformedRecord)?;
        if key_id != KeyId::from_public_key(&public_key) {
            return Err(AuthorityChainError::KeyDerivation);
        }

        let authority_key_id_text = text_member(&object, "authority_key_id").ok_or(malformed)?;
        let authority_key_id = KeyId::parse(authority_key_id_text)
            .map_err(|_| AuthorityChainError::MalformedRecord)?;
        // The chain rule: the predecessor signs its own retirement, and
        // the succession strictly advances — a link that established its
        // own predecessor would be circular, and one that re-establishes
        // a key already in the chain is not a chain.
        if authority_key_id != previous_key_id || key_id == previous_key_id {
            return Err(AuthorityChainError::ChainRule);
        }

        let signature_text = text_member(&object, "authority_signature").ok_or(malformed)?;
        let authority_signature = Ed25519Signature::parse(signature_text)
            .map_err(|_| AuthorityChainError::MalformedRecord)?;

        Ok(Self {
            tenant_id,
            previous_public_key,
            previous_key_id,
            key_algorithm,
            public_key,
            key_id,
            signed_at,
            authority_key_id,
            authority_signature,
        })
    }

    /// The tenant whose authority rotated; the chain has no force outside
    /// it.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The retiring half — the key this link retires, and the half its
    /// own signature verifies against.
    #[must_use]
    pub const fn previous_public_key(&self) -> &Ed25519PublicKey {
        &self.previous_public_key
    }

    /// The retiring half's identifier, the object key's own segment: the
    /// address a verifier holding the half fetches this link at.
    #[must_use]
    pub const fn previous_key_id(&self) -> &KeyId {
        &self.previous_key_id
    }

    /// The successor half — the key this link establishes, which records
    /// signed after the cutover name in their `authority_key_id`.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// The successor half's identifier.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The algorithm of both halves; Ed25519 only in v1.
    #[must_use]
    pub const fn key_algorithm(&self) -> SignatureAlgorithm {
        self.key_algorithm
    }

    /// When the predecessor signed the rotation — the anchor of the
    /// dual-key window and the successor's establishment.
    #[must_use]
    pub const fn signed_at(&self) -> &Timestamp {
        &self.signed_at
    }

    /// The RFC 8785 canonicalization of this record with the
    /// `authority_signature` member removed — exactly the bytes the
    /// control-record-v1 construction signs and verifies.
    #[must_use]
    pub fn unsigned_canonical_bytes(&self) -> Vec<u8> {
        let mut members = Object::new();
        members.set("schema", text(CONTROL_NAMESPACE));
        members.set("record_type", text(RECORD_TYPE));
        members.set("record_kind", text(RECORD_KIND));
        members.set("tenant_id", text(self.tenant_id.as_str()));
        members.set(
            "previous_public_key",
            text(&self.previous_public_key.to_hex()),
        );
        members.set("previous_key_id", text(&self.previous_key_id.to_hex()));
        members.set("key_algorithm", text(self.key_algorithm.token()));
        members.set("public_key", text(&self.public_key.to_hex()));
        members.set("key_id", text(&self.key_id.to_hex()));
        members.set("signed_at", text(self.signed_at.as_str()));
        members.set("authority_key_id", text(&self.authority_key_id.to_hex()));
        Value::Object(members).canonical_bytes()
    }

    /// The RFC 8785 canonical bytes of the complete signed record — the
    /// byte-exact form the offline store publishes and a re-parsed link
    /// renders back identically.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut members = Object::new();
        members.set("schema", text(CONTROL_NAMESPACE));
        members.set("record_type", text(RECORD_TYPE));
        members.set("record_kind", text(RECORD_KIND));
        members.set("tenant_id", text(self.tenant_id.as_str()));
        members.set(
            "previous_public_key",
            text(&self.previous_public_key.to_hex()),
        );
        members.set("previous_key_id", text(&self.previous_key_id.to_hex()));
        members.set("key_algorithm", text(self.key_algorithm.token()));
        members.set("public_key", text(&self.public_key.to_hex()));
        members.set("key_id", text(&self.key_id.to_hex()));
        members.set("signed_at", text(self.signed_at.as_str()));
        members.set("authority_key_id", text(&self.authority_key_id.to_hex()));
        members.set(
            "authority_signature",
            text(&self.authority_signature.to_hex()),
        );
        Value::Object(members).canonical_bytes()
    }

    /// Verify the predecessor signature under the control-record-v1
    /// construction: Ed25519 by the retiring half over the RFC 8785
    /// canonicalization of this object with the signature member removed.
    ///
    /// Callers walking a chain should first check the link retires the
    /// key they hold (its `previous_key_id` equals the trusted key's ID);
    /// the pinned derivation then ties this record's
    /// `previous_public_key` to that trusted half, which is what makes
    /// this check a check against something already trusted rather than
    /// against the record's own assertion.
    #[must_use]
    pub fn verify_predecessor_signature(&self) -> bool {
        let signature = ed25519::Signature::from_bytes(*self.authority_signature.as_raw());
        ed25519::verify(
            self.previous_public_key.as_raw(),
            &self.unsigned_canonical_bytes(),
            &signature,
        )
    }
}

/// The signer a chain walk reached: the public half, when it was
/// established, and — if the walk also found the link that retires it —
/// when it was retired.
///
/// This is everything acceptance at a signing instant needs, computed
/// from the store's public material alone: the half established by link L
/// verifies from L's `signed_at`, and until the `signed_at` of the link
/// whose `previous_key_id` names it — or indefinitely, if no such link
/// exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAuthority {
    key_id: KeyId,
    public_key: Ed25519PublicKey,
    established_at: Option<Timestamp>,
    retired_at: Option<Timestamp>,
}

impl ResolvedAuthority {
    /// The resolved signer's identifier.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The resolved signer's public half — the key a record's own
    /// signature verifies against once acceptance is granted.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// When this half was established: the establishing link's
    /// `signed_at`, or [`None`] for the pinned root itself, which was
    /// never established by a record — it was pinned.
    #[must_use]
    pub const fn established_at(&self) -> Option<&Timestamp> {
        self.established_at.as_ref()
    }

    /// When this half was retired: the retiring link's `signed_at`, or
    /// [`None`] when no verified link retires it (yet).
    #[must_use]
    pub const fn retired_at(&self) -> Option<&Timestamp> {
        self.retired_at.as_ref()
    }

    /// Whether this half may have signed a record whose own `signed_at`
    /// is `at` — the acceptance decision, evaluated at the record's own
    /// instant and never at read time.
    ///
    /// Fails closed (returns `false`) for an instant that is not a real
    /// calendar moment, and for every boundary violation: before
    /// establishment, or past the 24-hour dual-key window after
    /// retirement. Both boundaries are inclusive — the successor may sign
    /// from the establishing link's instant, and the predecessor through
    /// the overlap's last instant.
    #[must_use]
    pub fn accepts_signing_at(&self, at: &Timestamp) -> bool {
        matches!(self.acceptance(at), Acceptance::Accepted)
    }

    /// The acceptance decision at `at` as its error class — the granular
    /// form of [`ResolvedAuthority::accepts_signing_at`] a cached
    /// resolution applies at the record's own instant, identical to the
    /// classes [`verify_signing_authority`] reports.
    ///
    /// # Errors
    /// [`AuthorityChainError::MalformedRecord`] for an instant that is
    /// not a real calendar moment,
    /// [`AuthorityChainError::NotEstablished`] before this half's
    /// establishing link, and [`AuthorityChainError::Retired`] past the
    /// 24-hour dual-key window after its retirement.
    pub fn verify_signing_at(&self, at: &Timestamp) -> Result<(), AuthorityChainError> {
        match self.acceptance(at) {
            Acceptance::Accepted => Ok(()),
            Acceptance::InvalidInstant => Err(AuthorityChainError::MalformedRecord),
            Acceptance::BeforeEstablishment => Err(AuthorityChainError::NotEstablished),
            Acceptance::AfterRetirement => Err(AuthorityChainError::Retired),
        }
    }

    /// The granular acceptance decision the boolean narrows.
    fn acceptance(&self, at: &Timestamp) -> Acceptance {
        if !at.calendar_valid() {
            return Acceptance::InvalidInstant;
        }
        if self
            .established_at
            .as_ref()
            .is_some_and(|established| utc_instant(at) < utc_instant(established))
        {
            return Acceptance::BeforeEstablishment;
        }
        if let Some(retired) = &self.retired_at {
            let (retired_seconds, retired_nanoseconds) = utc_instant(retired);
            if utc_instant(at) > (retired_seconds + OVERLAP_SECONDS, retired_nanoseconds) {
                return Acceptance::AfterRetirement;
            }
        }
        Acceptance::Accepted
    }
}

/// The acceptance decision's granular outcomes.
enum Acceptance {
    /// The half may have signed at this instant.
    Accepted,
    /// The instant is not a real calendar moment; nothing may hinge on it.
    InvalidInstant,
    /// The instant precedes this half's establishing link.
    BeforeEstablishment,
    /// The instant falls past the dual-key window after this half's
    /// retirement.
    AfterRetirement,
}

/// Resolve one signer through the chain anchored at `root`, reading each
/// link through `fetch` — the bytes stored at
/// `tenants/<tenant>/v1/control/authority-rotations/<key-id>.json` for
/// the key the walk currently holds.
///
/// The walk is fetch-verify-adopt-repeat: it starts at the pinned root,
/// requires each link to be addressed at the key it holds, to belong to
/// the root's tenant, to carry the pinned key-ID derivations and the
/// chain rule, and to verify against the half already trusted — and only
/// then adopts the successor the link establishes. The succession must
/// strictly advance: a link re-establishing any key the walk has already
/// held (its own predecessor included) is a broken chain, which is what
/// keeps a corrupted store from looping the walk. Termination needs no
/// step bound for the same reason: each adopted link must carry a
/// predecessor signature only that predecessor could have made, so a
/// store can extend the walk only with links the operator actually
/// signed.
///
/// The returned [`ResolvedAuthority`] also probes one link past the
/// signer — the link that retires it, when one exists and verifies — so
/// the dual-key window's anchor is established material, not an absence.
///
/// # Errors
/// [`AuthorityChainError::Unreachable`] when the store holds no link at
/// some predecessor address between the root and the signer (a signer no
/// chain names is untrusted); the parse, disagreement, derivation,
/// chain-rule, and signature failures of each link on the path as
/// [`AuthorityRotationLink::parse`] and signature verification report
/// them.
pub fn resolve_authority(
    root: &PinnedAuthorityRoot,
    signer: &KeyId,
    mut fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<ResolvedAuthority, AuthorityChainError> {
    let mut current_id = *root.key_id();
    let mut current_public = *root.public_key();
    let mut established_at = None;
    // Every key the walk has held, the pinned root first: the set a
    // strictly advancing succession never revisits.
    let mut visited = vec![*root.key_id()];
    loop {
        let link_bytes = fetch(&current_id);
        if current_id == *signer {
            // The retirement probe is held to the same strictly advancing
            // rule as an adopted link: a link at the signer's address that
            // re-establishes a key the walk already held is a loop, not a
            // history, and anchors no retirement.
            let retired_at = match link_bytes {
                None => None,
                Some(bytes) => {
                    let link = verified_link_at(&current_id, root, &bytes)?;
                    if visited.contains(&link.key_id) {
                        return Err(AuthorityChainError::ChainRule);
                    }
                    Some(link.signed_at)
                }
            };
            return Ok(ResolvedAuthority {
                key_id: current_id,
                public_key: current_public,
                established_at,
                retired_at,
            });
        }
        let Some(bytes) = link_bytes else {
            return Err(AuthorityChainError::Unreachable);
        };
        let link = verified_link_at(&current_id, root, &bytes)?;
        let successor = link.key_id;
        if visited.contains(&successor) {
            return Err(AuthorityChainError::ChainRule);
        }
        visited.push(successor);
        established_at = Some(link.signed_at);
        current_id = successor;
        current_public = link.public_key;
    }
}

/// Resolve the chain's **active trust anchor**: the newest half the walk
/// from `root` can adopt — established by the last verified link, retired
/// by nothing, the half the next publication extends and a readiness
/// check names as the tenant's current authority.
///
/// The walk is [`resolve_authority`]'s without a destination: it adopts
/// each link that retires the half it holds until the store serves no
/// link at the current half's address — that absence is what "active"
/// means, so the returned [`ResolvedAuthority`] always carries
/// `retired_at == None` (and `established_at == None` only for a pinned
/// root no link has ever retired). Every link the walk does read is held
/// to the full admission rule — addressed at the half it retires, the
/// root's tenant, the pinned derivations, the strictly advancing
/// succession, and a predecessor signature against the half already
/// trusted — so a broken chain fails closed exactly as a named-signer
/// walk does, and termination needs no step bound for the same reason:
/// the store can extend the walk only with links the operator actually
/// signed ([`resolve_authority`] documents the argument).
///
/// # Errors
/// The link-level failures of [`AuthorityRotationLink::parse`] and
/// [`resolve_authority`] — a missing link mid-chain never happens here
/// (an absent link is the walk's terminus), but a present link that
/// mis-addresses, cross-tenants, mis-derives, loops, or fails its
/// predecessor signature fails closed as usual.
pub fn resolve_active_authority(
    root: &PinnedAuthorityRoot,
    mut fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<ResolvedAuthority, AuthorityChainError> {
    let mut current_id = *root.key_id();
    let mut current_public = *root.public_key();
    let mut established_at = None;
    let mut visited = vec![*root.key_id()];
    while let Some(bytes) = fetch(&current_id) {
        let link = verified_link_at(&current_id, root, &bytes)?;
        let successor = link.key_id;
        if visited.contains(&successor) {
            return Err(AuthorityChainError::ChainRule);
        }
        visited.push(successor);
        established_at = Some(link.signed_at);
        current_id = successor;
        current_public = link.public_key;
    }
    Ok(ResolvedAuthority {
        key_id: current_id,
        public_key: current_public,
        established_at,
        retired_at: None,
    })
}

/// Verify that `signer` may have signed a record whose own `signed_at` is
/// `signed_at`: resolve the signer through the chain from `root`, then
/// apply the dual-key acceptance rule at the record's own instant.
///
/// On acceptance the resolved signer is returned — its public half is the
/// key the record's own signature verifies against, the caller's next
/// step. On rejection the error names the class: an unresolvable signer
/// or a broken link is [`AuthorityChainError::Unreachable`] /
/// link-level failure, a record predating its signer's establishment is
/// [`AuthorityChainError::NotEstablished`], and one past the 24-hour
/// dual-key window after the signer's retirement is
/// [`AuthorityChainError::Retired`].
///
/// # Errors
/// As [`resolve_authority`], plus
/// [`AuthorityChainError::MalformedRecord`] for a presented instant that
/// is not a real calendar moment,
/// [`AuthorityChainError::NotEstablished`] and
/// [`AuthorityChainError::Retired`] for the acceptance boundaries.
pub fn verify_signing_authority(
    root: &PinnedAuthorityRoot,
    signer: &KeyId,
    signed_at: &Timestamp,
    fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<ResolvedAuthority, AuthorityChainError> {
    if !signed_at.calendar_valid() {
        return Err(AuthorityChainError::MalformedRecord);
    }
    let resolved = resolve_authority(root, signer, fetch)?;
    resolved.verify_signing_at(signed_at)?;
    Ok(resolved)
}

/// Verify one tenant-authority-signed control record of any record type —
/// a linked-client, delegation, revocation, rotation, receipt-key, or
/// retention record, or any later member of the family — against the
/// authority chain anchored at `root`.
///
/// This is the verifier every consumer of a signed control record runs
/// before trusting it. The record needs only the seven envelope wrapper
/// members this decision leans on (`schema`, `record_type`, `record_kind`,
/// `tenant_id`, `signed_at`, `authority_key_id`, `authority_signature`);
/// the family's payload members are opaque here, owned by the record's own
/// schema and parser. The signature is checked under the control-record-v1
/// construction — Ed25519 by the signer named in `authority_key_id` over
/// the RFC 8785 canonicalization of the object with the signature member
/// removed — against the half the chain resolves, never against the
/// record's own assertion of it.
///
/// The dual-key window is the acceptance rule, evaluated at the record's
/// own `signed_at` and never at read time: inside the 24-hour overlap
/// after the signer's retirement either half verifies, past it a
/// predecessor-signed record fails closed ([`AuthorityChainError::
/// Retired`]), and a record whose signer was valid at its own instant
/// keeps verifying for as long as the record is retained — which is what
/// makes verification of retained receipts survive every later authority
/// rotation.
///
/// # Errors
/// [`AuthorityChainError::RecordDisagreement`] for a foreign namespace,
/// tenant, or a member failing its grammar's identity;
/// [`AuthorityChainError::MalformedRecord`] for bytes that are not a JSON
/// object, a missing or non-string wrapper member, or an impossible
/// instant; the chain errors of [`verify_signing_authority`] for an
/// unreachable signer or an acceptance boundary; [`AuthorityChainError::
/// Signature`] when the signature does not verify against the resolved
/// half.
pub fn verify_control_record(
    root: &PinnedAuthorityRoot,
    envelope: &[u8],
    mut fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<ResolvedAuthority, AuthorityChainError> {
    verify_control_record_resolved(envelope, |record_tenant, signer, signed_at| {
        // The chain has no force outside the root's tenant: a record
        // claiming another tenant fails closed before the walk, whatever
        // half signed it.
        if *record_tenant != root.tenant_id {
            return Err(AuthorityChainError::RecordDisagreement);
        }
        verify_signing_authority(root, signer, signed_at, &mut fetch)
    })
}

/// Verify one tenant-authority-signed control record through a
/// caller-supplied signer resolution — the seam a trust cache composes
/// at (a bounded trust cache's cached verifier is this function with
/// the 60-second cache in front of the walk, and a readiness probe is
/// this function over a signed control read).
///
/// Everything but the resolution is [`verify_control_record`]'s own
/// contract: the wrapper members are read and grammar-checked, the
/// namespace fails closed first, and `resolve` names the acceptance
/// policy — it is handed the record's parsed `tenant_id`,
/// `authority_key_id`, and `signed_at`, decides which tenant's chain the
/// record verifies against (and rejects a tenant it holds no root for),
/// and returns the resolved authority that accepted the signer at that
/// instant. The signature then verifies against the half `resolve`
/// returned — never against the record's own assertion of it.
///
/// # Errors
/// As [`verify_control_record`], plus whatever `resolve` reports for
/// its own policy's rejections.
pub fn verify_control_record_resolved(
    envelope: &[u8],
    resolve: impl FnOnce(
        &TenantId,
        &KeyId,
        &Timestamp,
    ) -> Result<ResolvedAuthority, AuthorityChainError>,
) -> Result<ResolvedAuthority, AuthorityChainError> {
    let malformed = AuthorityChainError::MalformedRecord;
    let Value::Object(mut object) = json::parse(envelope).map_err(|_| malformed)? else {
        return Err(malformed);
    };
    // The namespace fails closed before anything else is read.
    if text_member(&object, "schema") != Some(CONTROL_NAMESPACE) {
        return Err(AuthorityChainError::RecordDisagreement);
    }
    // The wrapper members every control record carries; the payload is
    // the family's own business.
    for name in ["record_type", "record_kind"] {
        if text_member(&object, name).is_none() {
            return Err(malformed);
        }
    }
    let tenant_text = text_member(&object, "tenant_id").ok_or(malformed)?;
    let tenant_id = TenantId::parse(tenant_text).map_err(|_| malformed)?;
    let signer_id_text = text_member(&object, "authority_key_id").ok_or(malformed)?;
    let signer_id = KeyId::parse(signer_id_text).map_err(|_| malformed)?;
    let signature_text = text_member(&object, "authority_signature").ok_or(malformed)?;
    let signature = Ed25519Signature::parse(signature_text).map_err(|_| malformed)?;
    let signed_at_text = text_member(&object, "signed_at").ok_or(malformed)?;
    let signed_at = Timestamp::parse(signed_at_text).map_err(|_| malformed)?;

    // Acceptance first, against the resolution policy: the record's
    // tenant must be one the policy holds a root for, the signer must
    // resolve against that tenant's chain, and it may have signed at
    // this record's own instant. On success the resolved authority
    // carries the public half the signature checks against.
    let resolved = resolve(&tenant_id, &signer_id, &signed_at)?;

    // The control-record-v1 construction: canonicalize without the
    // signature member, then verify against the resolved half.
    let _ = object.remove("authority_signature");
    let canonical = Value::Object(object).canonical_bytes();
    let signature = ed25519::Signature::from_bytes(*signature.as_raw());
    if !ed25519::verify(resolved.public_key().as_raw(), &canonical, &signature) {
        return Err(AuthorityChainError::Signature);
    }
    Ok(resolved)
}

/// The offline publication gate's decision for a candidate authority
/// rotation link.
///
/// The gate runs before any store write: the offline
/// `ControlAdminStore` reuses its immutable write class downstream
/// (byte-identical re-put idempotent, incompatible object at the occupied
/// key an integrity conflict), and everything the chain knows that the
/// byte-level rule cannot see is decided here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPublication {
    /// No verified link retires the candidate's predecessor yet: the
    /// candidate is the in-order next link, publish it.
    Publish,
    /// The byte-identical link is already published: a lost-response
    /// retry, succeed idempotently without a second write.
    AlreadyPublished,
}

/// Gate one candidate authority-rotation link for publication through the
/// offline store, against the chain state `fetch` serves.
///
/// The rules, each failing closed:
///
/// - the candidate must belong to the pinned root's tenant — a link for
///   another tenant is a cross-tenant forgery, not a naming oddity
///   ([`AuthorityChainError::RecordDisagreement`]);
/// - the candidate's own predecessor signature must verify — the store is
///   never handed a link whose signature fails, whatever the walk would
///   later say ([`AuthorityChainError::Signature`]);
/// - the predecessor must be reachable from the pinned root with no gap
///   in the chain — publishing a link whose predecessor address cannot be
///   walked to is an out-of-order link ([`AuthorityChainError::
///   Unreachable`]);
/// - the predecessor must not already be retired by a different link —
///   one immutable link per retired key, addressed at the key it retires,
///   so a second link for an already-retired key is refused, never
///   rewritten ([`AuthorityChainError::AlreadyRetired`]).
///
/// The successor the candidate establishes needs no separate rule: it is
/// signed for only by the predecessor's verified signature, so an
/// already-established key cannot be re-established through the gate
/// without forging that signature.
///
/// # Errors
/// As the rules above; never a store error — nothing has been written
/// when the gate returns.
pub fn prepare_rotation_publication(
    root: &PinnedAuthorityRoot,
    candidate: &AuthorityRotationLink,
    mut fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<RotationPublication, AuthorityChainError> {
    if candidate.tenant_id != *root.tenant_id() {
        return Err(AuthorityChainError::RecordDisagreement);
    }
    if !candidate.verify_predecessor_signature() {
        return Err(AuthorityChainError::Signature);
    }
    // The predecessor must be the chain's current end: reachable from the
    // pinned root, and not already retired. Resolving it probes the link
    // at its own address, which is exactly the retirement question.
    let resolved = resolve_authority(root, candidate.previous_key_id(), &mut fetch)?;
    if resolved.retired_at().is_none() {
        Ok(RotationPublication::Publish)
    } else {
        let stored = fetch(candidate.previous_key_id()).ok_or(AuthorityChainError::Signature)?;
        if stored == candidate.canonical_bytes() {
            Ok(RotationPublication::AlreadyPublished)
        } else {
            Err(AuthorityChainError::AlreadyRetired)
        }
    }
}

/// Parse and verify the link addressed at `addressed_key` for `root`'s
/// tenant, returning it only when it retires exactly the key the walk
/// holds and its predecessor signature verifies — the one admission a
/// chain walk grants a record.
fn verified_link_at(
    addressed_key: &KeyId,
    root: &PinnedAuthorityRoot,
    bytes: &[u8],
) -> Result<AuthorityRotationLink, AuthorityChainError> {
    let link = AuthorityRotationLink::parse(bytes)?;
    if link.tenant_id != root.tenant_id {
        return Err(AuthorityChainError::RecordDisagreement);
    }
    // The link must retire exactly the key whose address it sits at: the
    // pinned derivation ties `previous_public_key` to this ID, so the
    // signature below verifies against the half the walk already trusts.
    if link.previous_key_id != *addressed_key {
        return Err(AuthorityChainError::RecordDisagreement);
    }
    if !link.verify_predecessor_signature() {
        return Err(AuthorityChainError::Signature);
    }
    Ok(link)
}

/// One text member, or [`None`] for anything but a JSON string.
fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(text)) => Some(text.as_str()),
        _ => None,
    }
}

/// Insert a text member.
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

/// An RFC 3339 UTC timestamp as seconds since the Unix epoch plus
/// nanoseconds into that second, the pair instants compare as.
///
/// The caller guarantees the calendar is valid
/// ([`Timestamp::calendar_valid`]); the leap second `:60` folds into the
/// next minute's first second, which is exactly where the wire calendar
/// places it.
///
/// The client-rotation trust view reuses the same instant ordering for its
/// 24-hour overlap boundary.
pub(crate) fn utc_instant(stamp: &Timestamp) -> (i64, u32) {
    let bytes = stamp.as_str().as_bytes();
    let number = |slice: &[u8]| {
        slice
            .iter()
            .fold(0i64, |acc, c| acc * 10 + i64::from(c - b'0'))
    };
    let year = number(&bytes[0..4]);
    let month = number(&bytes[5..7]);
    let day = number(&bytes[8..10]);
    let hour = number(&bytes[11..13]);
    let minute = number(&bytes[14..16]);
    let second = number(&bytes[17..19]);
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    let nanoseconds = if bytes.len() > 20 {
        // ".fffffffff" before the terminal 'Z': 1..=9 digits, scaled to
        // the nanosecond grid.
        let digits = &bytes[20..bytes.len() - 1];
        let mut nanoseconds = 0u32;
        for digit in digits {
            nanoseconds = nanoseconds * 10 + u32::from(digit - b'0');
        }
        for _ in digits.len()..9 {
            nanoseconds *= 10;
        }
        nanoseconds
    } else {
        0
    };
    (seconds, nanoseconds)
}

/// Days since 1970-01-01 of a proleptic-Gregorian civil date (Howard
/// Hinnant's `days_from_civil`), the standard dependency-free calendar
/// the protocol's own no-dependency policy asks for.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_offset = if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * (month + month_offset) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A deterministic predecessor/successor pair: seeds fixed by test
    /// vectors, so every signature below is reproducible byte for byte.
    const ROOT_SEED: [u8; 32] = [0x01; 32];
    const SUCCESSOR_SEED: [u8; 32] = [0x02; 32];
    const THIRD_SEED: [u8; 32] = [0x03; 32];
    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
    const LINK_INSTANT: &str = "2026-09-10T00:00:00Z";
    const SECOND_LINK_INSTANT: &str = "2026-09-12T00:00:00Z";

    fn tenant() -> TenantId {
        TENANT.parse().expect("tenant grammar")
    }

    fn root() -> PinnedAuthorityRoot {
        PinnedAuthorityRoot::new(tenant(), public_half(&ROOT_SEED))
    }

    fn public_half(seed: &[u8; 32]) -> Ed25519PublicKey {
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(seed))
    }

    /// Build the signed link that retires `predecessor_seed` and
    /// establishes `successor_seed` at `signed_at`.
    fn signed_link(
        predecessor_seed: &[u8; 32],
        successor_seed: &[u8; 32],
        signed_at: &str,
        tenant: &TenantId,
    ) -> Vec<u8> {
        let previous_public = public_half(predecessor_seed);
        let public = public_half(successor_seed);
        let previous_key_id = KeyId::from_public_key(&previous_public);
        let mut members = Object::new();
        members.set("schema", text(CONTROL_NAMESPACE));
        members.set("record_type", text(RECORD_TYPE));
        members.set("record_kind", text(RECORD_KIND));
        members.set("tenant_id", text(tenant.as_str()));
        members.set("previous_public_key", text(&previous_public.to_hex()));
        members.set("previous_key_id", text(&previous_key_id.to_hex()));
        members.set("key_algorithm", text("ed25519"));
        members.set("public_key", text(&public.to_hex()));
        members.set("key_id", text(&KeyId::from_public_key(&public).to_hex()));
        members.set("signed_at", text(signed_at));
        members.set("authority_key_id", text(&previous_key_id.to_hex()));
        let signature = ed25519::sign(
            predecessor_seed,
            &Value::Object(members.clone()).canonical_bytes(),
        );
        members.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        Value::Object(members).canonical_bytes()
    }

    /// A chain store: the bytes at each predecessor address, exactly as a
    /// `ControlReadStore` would serve them.
    fn chain_store(links: Vec<Vec<u8>>) -> HashMap<KeyId, Vec<u8>> {
        let mut store = HashMap::new();
        for bytes in links {
            let link = AuthorityRotationLink::parse(&bytes).expect("test links are well-formed");
            store.insert(link.previous_key_id, bytes);
        }
        store
    }

    fn fetch_from(store: &HashMap<KeyId, Vec<u8>>) -> impl FnMut(&KeyId) -> Option<Vec<u8>> + '_ {
        move |key| store.get(key).cloned()
    }

    fn instant(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("test instants are grammatical")
    }

    #[test]
    fn a_valid_rotation_link_parses_and_verifies() {
        let bytes = signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant());
        let link = AuthorityRotationLink::parse(&bytes).expect("the golden link is well-formed");
        assert_eq!(*link.tenant_id(), tenant());
        assert_eq!(
            *link.previous_public_key(),
            public_half(&ROOT_SEED),
            "the retiring half is the pinned root's own half"
        );
        assert_eq!(
            *link.previous_key_id(),
            KeyId::from_public_key(&public_half(&ROOT_SEED))
        );
        assert_eq!(*link.public_key(), public_half(&SUCCESSOR_SEED));
        assert_eq!(
            *link.key_id(),
            KeyId::from_public_key(&public_half(&SUCCESSOR_SEED))
        );
        assert_eq!(link.key_algorithm(), SignatureAlgorithm::Ed25519);
        assert_eq!(link.signed_at().as_str(), LINK_INSTANT);
        assert!(
            link.verify_predecessor_signature(),
            "the predecessor's own signature must verify"
        );
        // And the record renders back to exactly the bytes it parses
        // from: canonical in, canonical out.
        assert_eq!(link.canonical_bytes(), bytes);
    }

    // The full negative matrix in one test on purpose: every rejection
    // class of the record's contract, asserted against its own error.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn parse_fails_closed_on_every_contract_rule() {
        let good = signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant());
        let rewritten = |edit: &dyn Fn(&mut Object)| {
            let Value::Object(mut object) = json::parse(&good).expect("json") else {
                panic!("object");
            };
            edit(&mut object);
            Value::Object(object).canonical_bytes()
        };

        // Shape: not JSON, not an object, an extra member, a missing
        // member, a non-string member.
        assert_eq!(
            AuthorityRotationLink::parse(b"not json").unwrap_err(),
            AuthorityChainError::MalformedRecord
        );
        assert_eq!(
            AuthorityRotationLink::parse(b"[1]").unwrap_err(),
            AuthorityChainError::MalformedRecord
        );
        assert_eq!(
            AuthorityRotationLink::parse(&rewritten(&|o| {
                o.set("extra", Value::Int(1));
            }))
            .unwrap_err(),
            AuthorityChainError::MalformedRecord
        );
        assert_eq!(
            AuthorityRotationLink::parse(&rewritten(&|o| {
                let _ = o.remove("key_algorithm");
            }))
            .unwrap_err(),
            AuthorityChainError::MalformedRecord
        );
        assert_eq!(
            AuthorityRotationLink::parse(&rewritten(&|o| {
                o.set("signed_at", Value::Int(1));
            }))
            .unwrap_err(),
            AuthorityChainError::MalformedRecord
        );

        // Identity disagreement: namespace, record type, write class.
        for (name, value) in [
            ("schema", "archivist.control/v2"),
            ("record_type", "rotation"),
            ("record_kind", "current-pointer"),
        ] {
            assert_eq!(
                AuthorityRotationLink::parse(&rewritten(&|o| {
                    o.set(name, text(value));
                }))
                .unwrap_err(),
                AuthorityChainError::RecordDisagreement,
                "{name} disagreement must be its own class"
            );
        }

        // Grammars: tenant, public halves, key IDs, algorithm, calendar.
        for (name, value) in [
            ("tenant_id", "not-a-uuid"),
            ("previous_public_key", "AB"),
            ("public_key", "0"),
            ("previous_key_id", "abcd"),
            ("key_id", "zz"),
            ("key_algorithm", "rsa"),
            ("authority_key_id", "short"),
            ("authority_signature", "00"),
        ] {
            assert_eq!(
                AuthorityRotationLink::parse(&rewritten(&|o| {
                    o.set(name, text(value));
                }))
                .unwrap_err(),
                AuthorityChainError::MalformedRecord,
                "{name} grammar failure must be malformed"
            );
        }
        assert_eq!(
            AuthorityRotationLink::parse(&rewritten(&|o| {
                o.set("signed_at", text("2026-02-30T00:00:00Z"));
            }))
            .unwrap_err(),
            AuthorityChainError::MalformedRecord,
            "an impossible calendar instant is not a record"
        );

        // Derivations: both key IDs are recomputed, never trusted.
        for name in ["previous_key_id", "key_id"] {
            let other = KeyId::from_public_key(&public_half(&THIRD_SEED));
            assert_eq!(
                AuthorityRotationLink::parse(&rewritten(&|o| {
                    o.set(name, text(&other.to_hex()));
                }))
                .unwrap_err(),
                AuthorityChainError::KeyDerivation,
                "{name} must be the pinned derivation of its half"
            );
        }

        // The chain rule: the successor signs its own establishment, or
        // the link retires and establishes the same key.
        assert_eq!(
            AuthorityRotationLink::parse(&rewritten(&|o| {
                let successor = KeyId::from_public_key(&public_half(&SUCCESSOR_SEED));
                o.set("authority_key_id", text(&successor.to_hex()));
            }))
            .unwrap_err(),
            AuthorityChainError::ChainRule,
            "the successor cannot witness its own establishment"
        );
        let self_link = {
            let previous = public_half(&ROOT_SEED);
            let mut members = Object::new();
            members.set("schema", text(CONTROL_NAMESPACE));
            members.set("record_type", text(RECORD_TYPE));
            members.set("record_kind", text(RECORD_KIND));
            members.set("tenant_id", text(TENANT));
            members.set("previous_public_key", text(&previous.to_hex()));
            members.set(
                "previous_key_id",
                text(&KeyId::from_public_key(&previous).to_hex()),
            );
            members.set("key_algorithm", text("ed25519"));
            members.set("public_key", text(&previous.to_hex()));
            members.set("key_id", text(&KeyId::from_public_key(&previous).to_hex()));
            members.set("signed_at", text(LINK_INSTANT));
            members.set(
                "authority_key_id",
                text(&KeyId::from_public_key(&previous).to_hex()),
            );
            let signature = ed25519::sign(
                &ROOT_SEED,
                &Value::Object(members.clone()).canonical_bytes(),
            );
            members.set(
                "authority_signature",
                text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
            );
            Value::Object(members).canonical_bytes()
        };
        assert_eq!(
            AuthorityRotationLink::parse(&self_link).unwrap_err(),
            AuthorityChainError::ChainRule,
            "a link that establishes its own predecessor does not advance"
        );
    }

    #[test]
    fn a_tampered_link_fails_the_signature_check() {
        let bytes = signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant());
        let Value::Object(mut object) = json::parse(&bytes).expect("json") else {
            panic!("object");
        };
        // Swap the signature for one the predecessor never made over these
        // bytes: a valid Ed25519 signature over a different message.
        let signature = ed25519::sign(&ROOT_SEED, b"some other message");
        object.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        let forged = AuthorityRotationLink::parse(&Value::Object(object).canonical_bytes())
            .expect("shape and derivations are intact");
        assert!(!forged.verify_predecessor_signature());
    }

    #[test]
    fn the_predecessor_not_retired_verifies_indefinitely() {
        // The empty store: no link retires the pinned root, so the root
        // signs forever — the default is trust in the pinned half, not a
        // lease on it.
        let store = chain_store(vec![]);
        let resolved = resolve_authority(&root(), root().key_id(), fetch_from(&store))
            .expect("the pinned root resolves with no links at all");
        assert_eq!(*resolved.key_id(), *root().key_id());
        assert_eq!(*resolved.public_key(), *root().public_key());
        assert!(
            resolved.established_at().is_none(),
            "the root was pinned, never established by a link"
        );
        assert!(resolved.retired_at().is_none());
        // Any instant — long before and long after the golden link's
        // calendar — accepts the root's signature.
        for at in [
            "2020-01-01T00:00:00Z",
            LINK_INSTANT,
            "2040-06-01T12:00:00.500Z",
        ] {
            assert!(
                resolved.accepts_signing_at(&instant(at)),
                "an unretired root accepts at {at}"
            );
        }
    }

    #[test]
    fn the_walk_resolves_successors_and_the_dual_key_window() {
        // One link: the root retires at LINK_INSTANT, the successor is
        // established then, and for 24 hours either half verifies.
        let store = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);
        let successor_id = KeyId::from_public_key(&public_half(&SUCCESSOR_SEED));

        // The successor resolves through the chain with its boundaries.
        let resolved = resolve_authority(&root(), &successor_id, fetch_from(&store))
            .expect("the successor resolves through its establishing link");
        assert_eq!(*resolved.key_id(), successor_id);
        assert_eq!(
            resolved.established_at().map(Timestamp::as_str),
            Some(LINK_INSTANT)
        );
        assert!(
            resolved.retired_at().is_none(),
            "no link retires the successor"
        );

        // The root resolves with its retirement window anchored at the
        // link that retires it.
        let root_resolved = resolve_authority(&root(), root().key_id(), fetch_from(&store))
            .expect("the root still resolves");
        assert_eq!(
            root_resolved.retired_at().map(Timestamp::as_str),
            Some(LINK_INSTANT)
        );

        // Mid-overlap: 12 hours in, either half signs.
        let mid_overlap = "2026-09-10T12:00:00Z";
        assert!(root_resolved.accepts_signing_at(&instant(mid_overlap)));
        assert!(resolved.accepts_signing_at(&instant(mid_overlap)));

        // The exact boundary instants, both inclusive.
        let boundary = "2026-09-11T00:00:00Z"; // LINK_INSTANT + 24h
        assert!(
            root_resolved.accepts_signing_at(&instant(boundary)),
            "the overlap includes its last instant"
        );
        assert!(
            !root_resolved.accepts_signing_at(&instant("2026-09-11T00:00:00.000000001Z")),
            "one nanosecond past the overlap fails closed"
        );
        assert!(
            !root_resolved.accepts_signing_at(&instant("2026-09-11T00:00:01Z")),
            "one second past the overlap fails closed"
        );

        // The successor may sign from the establishing instant itself...
        assert!(resolved.accepts_signing_at(&instant(LINK_INSTANT)));
        // ...and not one nanosecond before it.
        assert!(
            !resolved.accepts_signing_at(&instant("2026-09-09T23:59:59.999999999Z")),
            "a successor cannot sign before it exists"
        );
    }

    #[test]
    fn a_multi_hop_chain_resolves_through_every_intermediate_link() {
        // Root -> successor -> third: the walk adopts each link in turn,
        // and the middle half's window is bounded by the second link.
        let store = chain_store(vec![
            signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant()),
            signed_link(&SUCCESSOR_SEED, &THIRD_SEED, SECOND_LINK_INSTANT, &tenant()),
        ]);
        let successor_id = KeyId::from_public_key(&public_half(&SUCCESSOR_SEED));
        let third_id = KeyId::from_public_key(&public_half(&THIRD_SEED));

        let third = resolve_authority(&root(), &third_id, fetch_from(&store))
            .expect("the third half resolves through both links");
        assert_eq!(*third.key_id(), third_id);
        assert_eq!(
            third.established_at().map(Timestamp::as_str),
            Some(SECOND_LINK_INSTANT)
        );
        assert!(third.retired_at().is_none());

        let middle = resolve_authority(&root(), &successor_id, fetch_from(&store))
            .expect("the middle half resolves");
        assert_eq!(
            middle.retired_at().map(Timestamp::as_str),
            Some(SECOND_LINK_INSTANT),
            "the second link retires the middle half"
        );
        // The middle half signs through the second link's overlap, which
        // the first link's window never extended.
        assert!(middle.accepts_signing_at(&instant("2026-09-13T00:00:00Z")));
        assert!(!middle.accepts_signing_at(&instant("2026-09-13T00:00:00.000000001Z")));

        // The root's own window is still the first link's, unaffected by
        // later links.
        let root_resolved = resolve_authority(&root(), root().key_id(), fetch_from(&store))
            .expect("the root resolves");
        assert!(!root_resolved.accepts_signing_at(&instant(SECOND_LINK_INSTANT)));
    }

    // One broken-chain store per failure class, asserted in sequence.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_broken_chain_fails_closed_in_every_named_way() {
        let successor_id = KeyId::from_public_key(&public_half(&SUCCESSOR_SEED));
        let third_id = KeyId::from_public_key(&public_half(&THIRD_SEED));

        // A missing intermediate link: the successor's link exists but
        // the walk never reaches it because nothing retires the root.
        let orphan_store = chain_store(vec![signed_link(
            &SUCCESSOR_SEED,
            &THIRD_SEED,
            SECOND_LINK_INSTANT,
            &tenant(),
        )]);
        assert_eq!(
            resolve_authority(&root(), &third_id, fetch_from(&orphan_store)).unwrap_err(),
            AuthorityChainError::Unreachable,
            "a signer no reachable chain names is untrusted"
        );

        // A mis-signed link: the retirement is signed by the successor it
        // establishes — circular, and it fails the predecessor check even
        // though the signature itself is a real Ed25519 signature.
        let mis_signed = {
            let previous = public_half(&ROOT_SEED);
            let public = public_half(&SUCCESSOR_SEED);
            let mut members = Object::new();
            members.set("schema", text(CONTROL_NAMESPACE));
            members.set("record_type", text(RECORD_TYPE));
            members.set("record_kind", text(RECORD_KIND));
            members.set("tenant_id", text(TENANT));
            members.set("previous_public_key", text(&previous.to_hex()));
            members.set(
                "previous_key_id",
                text(&KeyId::from_public_key(&previous).to_hex()),
            );
            members.set("key_algorithm", text("ed25519"));
            members.set("public_key", text(&public.to_hex()));
            members.set("key_id", text(&KeyId::from_public_key(&public).to_hex()));
            members.set("signed_at", text(LINK_INSTANT));
            members.set(
                "authority_key_id",
                text(&KeyId::from_public_key(&previous).to_hex()),
            );
            let signature = ed25519::sign(
                &SUCCESSOR_SEED,
                &Value::Object(members.clone()).canonical_bytes(),
            );
            members.set(
                "authority_signature",
                text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
            );
            Value::Object(members).canonical_bytes()
        };
        let successor_signed_store = chain_store(vec![mis_signed]);
        assert_eq!(
            resolve_authority(&root(), &successor_id, fetch_from(&successor_signed_store))
                .unwrap_err(),
            AuthorityChainError::Signature,
            "a successor-signed link verifies against nothing the walk trusts"
        );

        // A tampered link: valid shape, valid derivations, bytes the
        // predecessor never signed.
        let tampered = {
            let bytes = signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant());
            let Value::Object(mut object) = json::parse(&bytes).expect("json") else {
                panic!("object");
            };
            object.set("signed_at", text("2026-09-10T00:00:01Z"));
            Value::Object(object).canonical_bytes()
        };
        let tampered_store = chain_store(vec![tampered]);
        assert_eq!(
            resolve_authority(&root(), &successor_id, fetch_from(&tampered_store)).unwrap_err(),
            AuthorityChainError::Signature,
            "tampered signed bytes fail the signature check"
        );

        // A cross-tenant link: signed by the real predecessor, but for
        // another tenant — no force outside its tenant.
        let foreign = signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &OTHER_TENANT.parse().expect("grammar"),
        );
        let foreign_store = chain_store(vec![foreign]);
        assert_eq!(
            resolve_authority(&root(), &successor_id, fetch_from(&foreign_store)).unwrap_err(),
            AuthorityChainError::RecordDisagreement
        );

        // A cyclical succession: the successor's link retires the
        // successor and re-establishes the root — individually signed,
        // jointly a loop. Resolving the successor fails: its retiring
        // probe reads the looping link, and a link that re-establishes a
        // key the walk already held anchors no retirement.
        let loop_link = signed_link(&SUCCESSOR_SEED, &ROOT_SEED, SECOND_LINK_INSTANT, &tenant());
        let loop_store = chain_store(vec![
            signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant()),
            loop_link,
        ]);
        assert_eq!(
            resolve_authority(&root(), &successor_id, fetch_from(&loop_store)).unwrap_err(),
            AuthorityChainError::ChainRule,
            "the retiring probe must refuse a link that loops the chain"
        );
        // The root's own resolution is untouched by the loop behind it:
        // the link that retires the root is verified and advances, so the
        // root's retirement fact stands — and the acceptance rule, not
        // the store's shape, is what bounds the root's signing window.
        let root_resolved = resolve_authority(&root(), root().key_id(), fetch_from(&loop_store))
            .expect("the root's own retirement link advances");
        assert_eq!(
            root_resolved.retired_at().map(Timestamp::as_str),
            Some(LINK_INSTANT)
        );

        // A link addressed at the wrong key: bytes of the second link
        // served at the root's address retire a key the walk does not
        // hold there.
        let displaced_store = {
            let mut store = HashMap::new();
            let bytes = signed_link(&SUCCESSOR_SEED, &THIRD_SEED, SECOND_LINK_INSTANT, &tenant());
            store.insert(*root().key_id(), bytes);
            store
        };
        assert_eq!(
            resolve_authority(&root(), &third_id, fetch_from(&displaced_store)).unwrap_err(),
            AuthorityChainError::RecordDisagreement
        );
    }

    #[test]
    fn verify_signing_authority_reports_each_boundary_by_class() {
        let store = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);
        let successor_id = KeyId::from_public_key(&public_half(&SUCCESSOR_SEED));

        // Accepted: the predecessor mid-overlap, the successor from its
        // establishing instant.
        assert!(
            verify_signing_authority(
                &root(),
                root().key_id(),
                &instant("2026-09-10T09:30:00Z"),
                fetch_from(&store)
            )
            .is_ok()
        );
        assert!(
            verify_signing_authority(
                &root(),
                &successor_id,
                &instant(LINK_INSTANT),
                fetch_from(&store)
            )
            .is_ok()
        );

        // The retired predecessor past the window.
        assert_eq!(
            verify_signing_authority(
                &root(),
                root().key_id(),
                &instant("2026-09-12T00:00:00Z"),
                fetch_from(&store)
            )
            .unwrap_err(),
            AuthorityChainError::Retired
        );
        // The successor before its establishment.
        assert_eq!(
            verify_signing_authority(
                &root(),
                &successor_id,
                &instant("2026-09-09T23:59:59Z"),
                fetch_from(&store)
            )
            .unwrap_err(),
            AuthorityChainError::NotEstablished
        );
        // A presented instant that is not a real moment.
        assert_eq!(
            verify_signing_authority(
                &root(),
                &successor_id,
                &instant("2026-02-30T00:00:00Z"),
                fetch_from(&store)
            )
            .unwrap_err(),
            AuthorityChainError::MalformedRecord
        );
        // A signer no chain reaches.
        assert_eq!(
            verify_signing_authority(
                &root(),
                &KeyId::from_raw([0x99; 32]),
                &instant(LINK_INSTANT),
                fetch_from(&store)
            )
            .unwrap_err(),
            AuthorityChainError::Unreachable
        );
    }

    #[test]
    fn civil_time_matches_pinned_reference_values() {
        // Pin the calendar arithmetic against independently computed day
        // counts (Python: datetime.utcfromtimestamp / toordinal).
        let cases = [
            ("1970-01-01T00:00:00Z", (0, 0)),
            ("1970-01-01T00:00:00.000000001Z", (0, 1)),
            ("2026-09-14T00:00:00Z", (20_710 * 86_400, 0)),
            ("2026-09-10T00:00:00Z", (20_706 * 86_400, 0)),
            // 2026-09-11 is root link + 24h: the boundary instant.
            ("2026-09-11T00:00:00Z", (20_707 * 86_400, 0)),
            (
                "2000-02-29T12:34:56.789Z",
                (11_016 * 86_400 + 45_296, 789_000_000),
            ),
            ("1969-12-31T23:59:59Z", (-1, 0)),
        ];
        for (text, expected) in cases {
            let stamp = Timestamp::parse(text).expect("grammar");
            assert!(stamp.calendar_valid(), "the pinned cases are real instants");
            assert_eq!(utc_instant(&stamp), expected, "{text}");
        }
        // The overlap boundary arithmetic end to end: LINK_INSTANT + 24h
        // compares equal, one nanosecond later compares greater.
        let retired = utc_instant(&instant("2026-09-10T00:00:00Z"));
        let boundary = utc_instant(&instant("2026-09-11T00:00:00Z"));
        assert_eq!(
            (retired.0 + OVERLAP_SECONDS, retired.1),
            boundary,
            "24 hours lands exactly on the boundary instant"
        );
        assert!(
            utc_instant(&instant("2026-09-11T00:00:00.000000001Z"))
                > (retired.0 + OVERLAP_SECONDS, retired.1)
        );
    }

    #[test]
    fn the_overlap_constant_is_the_pinned_window() {
        assert_eq!(ROTATION_VERIFICATION_OVERLAP_HOURS, 24);
        assert_eq!(OVERLAP_SECONDS, 86_400);
    }

    #[test]
    fn a_stale_cached_resolution_never_invalidates_what_it_accepted() {
        // EC-09 propagation (plan Section 5): a replica's 60-second trust
        // cache serves a resolution computed from the link bytes its view
        // held at walk time. This test is the composition property the
        // cache relies on, pinned at the rule's own home: the stale view
        // (the retirement link not yet propagated) and the fresh view
        // (the link present) agree on every record signed inside the
        // predecessor's validity, so propagation lag can only widen
        // acceptance temporarily — no record the stale view accepted is
        // retroactively revoked by the fresher view, and the fresher
        // view is the only one that fails the post-window signature.
        let link = signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant());
        let successor_id = KeyId::from_public_key(&public_half(&SUCCESSOR_SEED));

        // The stale view: the walk runs before the link is visible, so
        // the predecessor resolves unretired and signs at any instant.
        let stale_store = chain_store(vec![]);
        let stale = resolve_authority(&root(), root().key_id(), fetch_from(&stale_store))
            .expect("the root resolves on the stale view");
        assert!(stale.retired_at().is_none());
        let record_signed_mid_window = "2026-09-10T12:00:00Z";
        assert!(
            stale.accepts_signing_at(&instant(record_signed_mid_window)),
            "the stale view accepts the predecessor mid-window"
        );

        // The fresh view: the link has propagated. The same resolution
        // request now carries the retirement anchor...
        let fresh_store = chain_store(vec![link]);
        let fresh = resolve_authority(&root(), root().key_id(), fetch_from(&fresh_store))
            .expect("the root resolves on the fresh view");
        assert_eq!(
            fresh.retired_at().map(Timestamp::as_str),
            Some(LINK_INSTANT)
        );
        // ...and every instant the stale view accepted, the fresh view
        // accepts too: acceptance is the record's own instant, not the
        // view's freshness.
        assert!(fresh.accepts_signing_at(&instant(record_signed_mid_window)));
        assert!(fresh.accepts_signing_at(&instant("2026-09-11T00:00:00Z")));

        // The one divergence is exactly the window's own rule, and only
        // in the closing direction: a signature the predecessor made
        // after the window is refused by the fresh view, while the stale
        // view — which cannot know the key retired — still accepts it
        // for at most the cache's 60-second TTL (EC-09's bound), never
        // longer.
        let after_window = "2026-09-12T00:00:00Z";
        assert!(stale.accepts_signing_at(&instant(after_window)));
        assert_eq!(
            verify_signing_authority(
                &root(),
                root().key_id(),
                &instant(after_window),
                fetch_from(&fresh_store)
            )
            .unwrap_err(),
            AuthorityChainError::Retired
        );
        // The successor's acceptance is view-independent in both
        // directions: established material on the stale view is no
        // chain at all (the walk cannot reach it), and on the fresh view
        // it verifies from its establishing instant — a lagging view
        // fails closed, never wrongly open.
        assert_eq!(
            resolve_authority(&root(), &successor_id, fetch_from(&stale_store)).unwrap_err(),
            AuthorityChainError::Unreachable
        );
        assert!(
            resolve_authority(&root(), &successor_id, fetch_from(&fresh_store))
                .expect("the fresh view resolves the successor")
                .accepts_signing_at(&instant(LINK_INSTANT))
        );
    }

    /// A synthetic tenant-authority-signed control record of a family the
    /// chain protects — modeled on the receipt-key record, one key member
    /// of payload. Signed by `signer_seed` at `signed_at` under the
    /// control-record-v1 construction, exactly as the offline store signs
    /// every record.
    fn signed_control_record(
        signer_seed: &[u8; 32],
        signed_at: &str,
        tenant: &TenantId,
    ) -> Vec<u8> {
        let signer_public = public_half(signer_seed);
        let signer_key_id = KeyId::from_public_key(&signer_public);
        let payload_key = KeyId::from_public_key(&public_half(&[0x5c; 32]));
        let mut members = Object::new();
        members.set("schema", text(CONTROL_NAMESPACE));
        members.set("record_type", text("receipt-key"));
        members.set("record_kind", text("immutable"));
        members.set("tenant_id", text(tenant.as_str()));
        members.set("key_algorithm", text("ed25519"));
        members.set("key_id", text(&payload_key.to_hex()));
        members.set("signed_at", text(signed_at));
        members.set("authority_key_id", text(&signer_key_id.to_hex()));
        let signature = ed25519::sign(
            signer_seed,
            &Value::Object(members.clone()).canonical_bytes(),
        );
        members.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        Value::Object(members).canonical_bytes()
    }

    #[test]
    fn control_records_verify_under_either_half_inside_the_window() {
        // One link: the root retires at LINK_INSTANT, the successor is
        // established then, and for 24 hours either half signs.
        let store = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);

        // Mid-overlap, a control record signed by either half verifies,
        // each against the half the chain resolves.
        let mid_overlap = "2026-09-10T12:00:00Z";
        assert!(
            verify_control_record(
                &root(),
                &signed_control_record(&ROOT_SEED, mid_overlap, &tenant()),
                fetch_from(&store)
            )
            .is_ok()
        );
        assert!(
            verify_control_record(
                &root(),
                &signed_control_record(&SUCCESSOR_SEED, mid_overlap, &tenant()),
                fetch_from(&store)
            )
            .is_ok()
        );

        // The boundaries: the overlap's last instant admits the
        // predecessor and refuses it one nanosecond past, while the
        // successor signs from its establishing instant onward.
        let boundary = "2026-09-11T00:00:00Z";
        assert!(
            verify_control_record(
                &root(),
                &signed_control_record(&ROOT_SEED, boundary, &tenant()),
                fetch_from(&store)
            )
            .is_ok()
        );
        assert_eq!(
            verify_control_record(
                &root(),
                &signed_control_record(&ROOT_SEED, "2026-09-11T00:00:00.000000001Z", &tenant()),
                fetch_from(&store)
            )
            .unwrap_err(),
            AuthorityChainError::Retired,
            "a predecessor-signed record past the overlap fails closed"
        );
        assert!(
            verify_control_record(
                &root(),
                &signed_control_record(&SUCCESSOR_SEED, boundary, &tenant()),
                fetch_from(&store)
            )
            .is_ok()
        );
    }

    #[test]
    fn verification_of_retained_records_survives_later_rotations() {
        // Two rotations: root -> successor -> third. Records the earlier
        // halves validly signed inside their own validity keep verifying
        // against the fully rotated chain — acceptance lives at the
        // record's own signed_at, and no read-time clock can expire it.
        // This is the property that makes verification of retained
        // receipts survive an authority rotation.
        let store = chain_store(vec![
            signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant()),
            signed_link(&SUCCESSOR_SEED, &THIRD_SEED, SECOND_LINK_INSTANT, &tenant()),
        ]);

        // The root signed before its one and only rotation; the chain as
        // it stands now is two links past it, its window long closed, and
        // the record still verifies.
        let retained = signed_control_record(&ROOT_SEED, "2026-09-09T23:00:00Z", &tenant());
        assert!(verify_control_record(&root(), &retained, fetch_from(&store)).is_ok());

        // The middle half at its own overlap's exact last instant, with
        // both links in the store.
        let middle = signed_control_record(&SUCCESSOR_SEED, "2026-09-13T00:00:00Z", &tenant());
        assert!(verify_control_record(&root(), &middle, fetch_from(&store)).is_ok());

        // The same half one second past its window is refused — the
        // window bounded signing acceptance, and this signing fell
        // outside it.
        let late = signed_control_record(&SUCCESSOR_SEED, "2026-09-13T00:00:01Z", &tenant());
        assert_eq!(
            verify_control_record(&root(), &late, fetch_from(&store)).unwrap_err(),
            AuthorityChainError::Retired
        );
    }

    #[test]
    fn control_record_verification_fails_closed_on_every_forgery_class() {
        let store = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);
        let good = signed_control_record(&ROOT_SEED, LINK_INSTANT, &tenant());
        let rewritten = |edit: &dyn Fn(&mut Object)| {
            let Value::Object(mut object) = json::parse(&good).expect("json") else {
                panic!("object");
            };
            edit(&mut object);
            Value::Object(object).canonical_bytes()
        };

        // A tampered payload: the signature no longer covers the bytes.
        assert_eq!(
            verify_control_record(
                &root(),
                &rewritten(&|o| {
                    o.set(
                        "key_id",
                        text(&KeyId::from_public_key(&public_half(&THIRD_SEED)).to_hex()),
                    );
                }),
                fetch_from(&store)
            )
            .unwrap_err(),
            AuthorityChainError::Signature,
            "a payload the signature does not cover is a forgery"
        );

        // A foreign namespace fails closed before anything else is read.
        assert_eq!(
            verify_control_record(
                &root(),
                &rewritten(&|o| {
                    o.set("schema", text("archivist.control/v2"));
                }),
                fetch_from(&store)
            )
            .unwrap_err(),
            AuthorityChainError::RecordDisagreement
        );

        // A cross-tenant record: signed by the real predecessor, but its
        // chain has no force outside the root's tenant.
        assert_eq!(
            verify_control_record(
                &root(),
                &signed_control_record(
                    &ROOT_SEED,
                    LINK_INSTANT,
                    &OTHER_TENANT.parse().expect("grammar")
                ),
                fetch_from(&store)
            )
            .unwrap_err(),
            AuthorityChainError::RecordDisagreement
        );

        // A missing wrapper member is not a record of the family.
        assert_eq!(
            verify_control_record(
                &root(),
                &rewritten(&|o| {
                    let _ = o.remove("signed_at");
                }),
                fetch_from(&store)
            )
            .unwrap_err(),
            AuthorityChainError::MalformedRecord
        );

        // A signer no chain names is untrusted.
        assert_eq!(
            verify_control_record(
                &root(),
                &signed_control_record(&THIRD_SEED, LINK_INSTANT, &tenant()),
                fetch_from(&store)
            )
            .unwrap_err(),
            AuthorityChainError::Unreachable
        );

        // Bytes that are not a JSON object at all.
        assert_eq!(
            verify_control_record(&root(), b"[", fetch_from(&store)).unwrap_err(),
            AuthorityChainError::MalformedRecord
        );
    }

    #[test]
    fn the_publication_gate_admits_only_in_order_appends() {
        let first_bytes = signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant());
        let first = AuthorityRotationLink::parse(&first_bytes).expect("well-formed");
        let second_bytes =
            signed_link(&SUCCESSOR_SEED, &THIRD_SEED, SECOND_LINK_INSTANT, &tenant());
        let second = AuthorityRotationLink::parse(&second_bytes).expect("well-formed");

        // The first link publishes against the empty store.
        let empty = chain_store(vec![]);
        assert_eq!(
            prepare_rotation_publication(&root(), &first, fetch_from(&empty)).unwrap(),
            RotationPublication::Publish
        );

        // The byte-identical link already published: a lost-response
        // retry succeeds idempotently.
        let published = chain_store(vec![first_bytes.clone()]);
        assert_eq!(
            prepare_rotation_publication(&root(), &first, fetch_from(&published)).unwrap(),
            RotationPublication::AlreadyPublished
        );

        // A different link at the same predecessor address: the key
        // already retired once, and one retired key keeps exactly one
        // link.
        let relink = AuthorityRotationLink::parse(&signed_link(
            &ROOT_SEED,
            &THIRD_SEED,
            LINK_INSTANT,
            &tenant(),
        ))
        .expect("well-formed");
        assert_eq!(
            prepare_rotation_publication(&root(), &relink, fetch_from(&published)).unwrap_err(),
            AuthorityChainError::AlreadyRetired,
            "no second link for an already-retired key"
        );

        // The in-order append: once the first link exists, the second
        // publishes.
        assert_eq!(
            prepare_rotation_publication(&root(), &second, fetch_from(&published)).unwrap(),
            RotationPublication::Publish
        );

        // Out of order: the second link offered before the first exists —
        // the walk from the pinned root cannot reach its predecessor
        // without a gap, and a gap fails closed.
        assert_eq!(
            prepare_rotation_publication(&root(), &second, fetch_from(&empty)).unwrap_err(),
            AuthorityChainError::Unreachable,
            "an out-of-order link fails closed"
        );

        // After both links exist, a new link that also retires the root
        // is the re-used-retired-key case, refused.
        let both = chain_store(vec![first_bytes, second_bytes]);
        let reused = AuthorityRotationLink::parse(&signed_link(
            &ROOT_SEED,
            &THIRD_SEED,
            SECOND_LINK_INSTANT,
            &tenant(),
        ))
        .expect("well-formed");
        assert_eq!(
            prepare_rotation_publication(&root(), &reused, fetch_from(&both)).unwrap_err(),
            AuthorityChainError::AlreadyRetired
        );

        // A candidate whose own signature fails never reaches the store,
        // even against an empty chain.
        let tampered_bytes = {
            let bytes = signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant());
            let Value::Object(mut object) = json::parse(&bytes).expect("json") else {
                panic!("object");
            };
            object.set("signed_at", text("2026-09-10T00:00:01Z"));
            Value::Object(object).canonical_bytes()
        };
        let tampered = AuthorityRotationLink::parse(&tampered_bytes).expect("shape is intact");
        assert_eq!(
            prepare_rotation_publication(&root(), &tampered, fetch_from(&empty)).unwrap_err(),
            AuthorityChainError::Signature
        );

        // A cross-tenant candidate is refused before anything else.
        let foreign = AuthorityRotationLink::parse(&signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &OTHER_TENANT.parse().expect("grammar"),
        ))
        .expect("well-formed");
        assert_eq!(
            prepare_rotation_publication(&root(), &foreign, fetch_from(&empty)).unwrap_err(),
            AuthorityChainError::RecordDisagreement
        );
    }

    #[test]
    fn the_active_walk_lands_on_the_chain_tip() {
        // Two links: the walk adopts both and anchors at the third half,
        // established by the second link and retired by nothing.
        let store = chain_store(vec![
            signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant()),
            signed_link(&SUCCESSOR_SEED, &THIRD_SEED, SECOND_LINK_INSTANT, &tenant()),
        ]);
        let third_id = KeyId::from_public_key(&public_half(&THIRD_SEED));

        let anchor = resolve_active_authority(&root(), fetch_from(&store))
            .expect("the walk lands on the newest half the store admits");
        assert_eq!(*anchor.key_id(), third_id);
        assert_eq!(*anchor.public_key(), public_half(&THIRD_SEED));
        assert_eq!(
            anchor.established_at().map(Timestamp::as_str),
            Some(SECOND_LINK_INSTANT)
        );
        assert!(
            anchor.retired_at().is_none(),
            "the active anchor is retired by nothing — that absence is what active means"
        );
        // The granular acceptance form on the anchor itself: it signs
        // from its establishing instant, and not one nanosecond before.
        assert!(
            anchor
                .verify_signing_at(&instant(SECOND_LINK_INSTANT))
                .is_ok()
        );
        assert!(
            anchor
                .verify_signing_at(&instant("2030-01-01T00:00:00Z"))
                .is_ok()
        );
        assert_eq!(
            anchor
                .verify_signing_at(&instant("2026-09-11T23:59:59.999999999Z"))
                .unwrap_err(),
            AuthorityChainError::NotEstablished
        );

        // One link: the tip is the successor, anchored at its own link.
        let one_link = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);
        let successor = resolve_active_authority(&root(), fetch_from(&one_link))
            .expect("one link, one adoption");
        assert_eq!(
            *successor.key_id(),
            KeyId::from_public_key(&public_half(&SUCCESSOR_SEED))
        );
        assert_eq!(
            successor.established_at().map(Timestamp::as_str),
            Some(LINK_INSTANT)
        );
        assert!(successor.retired_at().is_none());
    }

    #[test]
    fn the_pinned_root_alone_is_the_active_anchor() {
        // The empty store: no link has ever retired the root, so the root
        // is the active anchor — pinned, never established, retired by
        // nothing.
        let store = chain_store(vec![]);
        let anchor = resolve_active_authority(&root(), fetch_from(&store))
            .expect("a chain of no links anchors at the pinned root");
        assert_eq!(*anchor.key_id(), *root().key_id());
        assert_eq!(*anchor.public_key(), *root().public_key());
        assert!(
            anchor.established_at().is_none(),
            "the root was pinned, never established by a link"
        );
        assert!(anchor.retired_at().is_none());
        // And the root-anchor signs at every instant, the granular form
        // agreeing with the boolean.
        for at in ["2020-01-01T00:00:00Z", LINK_INSTANT, "2040-06-01T12:00:00Z"] {
            assert!(anchor.accepts_signing_at(&instant(at)), "{at}");
            assert!(anchor.verify_signing_at(&instant(at)).is_ok(), "{at}");
        }
    }

    #[test]
    fn an_active_walk_fails_closed_on_a_broken_mid_chain_link() {
        // The first link admits the walk; the link at the successor's
        // address is tampered, and the walk refuses the chain instead of
        // quietly anchoring at the last good half.
        let tampered_second = {
            let bytes = signed_link(&SUCCESSOR_SEED, &THIRD_SEED, SECOND_LINK_INSTANT, &tenant());
            let Value::Object(mut object) = json::parse(&bytes).expect("json") else {
                panic!("object");
            };
            object.set("signed_at", text("2026-09-12T00:00:01Z"));
            Value::Object(object).canonical_bytes()
        };
        let tampered = chain_store(vec![
            signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant()),
            tampered_second,
        ]);
        assert_eq!(
            resolve_active_authority(&root(), fetch_from(&tampered)).unwrap_err(),
            AuthorityChainError::Signature,
            "a mid-chain link the predecessor never signed breaks the whole walk"
        );

        // A mid-chain link addressed at the wrong half: the bytes at the
        // successor's address retire the root, a key the walk no longer
        // holds there.
        let displaced = {
            let mut store = HashMap::new();
            store.insert(
                *root().key_id(),
                signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant()),
            );
            store.insert(
                KeyId::from_public_key(&public_half(&SUCCESSOR_SEED)),
                signed_link(&ROOT_SEED, &THIRD_SEED, SECOND_LINK_INSTANT, &tenant()),
            );
            store
        };
        assert_eq!(
            resolve_active_authority(&root(), fetch_from(&displaced)).unwrap_err(),
            AuthorityChainError::RecordDisagreement
        );
    }

    #[test]
    fn an_active_walk_refuses_a_link_that_loops_the_chain() {
        // The successor's link retires the successor and re-establishes
        // the root: individually signed, jointly a loop, and the walk
        // refuses it instead of walking forever.
        let loop_store = chain_store(vec![
            signed_link(&ROOT_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant()),
            signed_link(&SUCCESSOR_SEED, &ROOT_SEED, SECOND_LINK_INSTANT, &tenant()),
        ]);
        assert_eq!(
            resolve_active_authority(&root(), fetch_from(&loop_store)).unwrap_err(),
            AuthorityChainError::ChainRule,
            "a succession that revisits the pinned root is a loop, not a history"
        );
    }

    /// The tenant-pinned resolver [`verify_control_record`] itself closes
    /// over, named so the seam tests compose exactly what production
    /// composes: the chain has no force outside the root's tenant, and
    /// the walk plus acceptance rule decide the rest.
    fn pinned_resolver(
        store: &HashMap<KeyId, Vec<u8>>,
    ) -> impl Fn(&TenantId, &KeyId, &Timestamp) -> Result<ResolvedAuthority, AuthorityChainError> + '_
    {
        move |tenant, signer, at| {
            if *tenant != root().tenant_id {
                return Err(AuthorityChainError::RecordDisagreement);
            }
            verify_signing_authority(&root(), signer, at, fetch_from(store))
        }
    }

    #[test]
    fn the_resolution_seam_applies_the_resolvers_acceptance_classes() {
        let store = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);

        // Accepted: the predecessor mid-overlap, and the seam hands back
        // the half the signature checks against.
        let mid_overlap = "2026-09-10T12:00:00Z";
        let accepted = verify_control_record_resolved(
            &signed_control_record(&ROOT_SEED, mid_overlap, &tenant()),
            pinned_resolver(&store),
        )
        .expect("the resolver accepts the predecessor mid-overlap");
        assert_eq!(*accepted.key_id(), *root().key_id());
        assert_eq!(*accepted.public_key(), *root().public_key());

        // The successor's record one nanosecond before its establishment:
        // the resolver's NotEstablished class is the seam's answer.
        assert_eq!(
            verify_control_record_resolved(
                &signed_control_record(
                    &SUCCESSOR_SEED,
                    "2026-09-09T23:59:59.999999999Z",
                    &tenant()
                ),
                pinned_resolver(&store),
            )
            .unwrap_err(),
            AuthorityChainError::NotEstablished
        );

        // The predecessor past its 24-hour window: Retired.
        assert_eq!(
            verify_control_record_resolved(
                &signed_control_record(&ROOT_SEED, "2026-09-12T00:00:00Z", &tenant()),
                pinned_resolver(&store),
            )
            .unwrap_err(),
            AuthorityChainError::Retired
        );

        // A presented instant that is not a real moment: the grammar
        // parses it, the resolver's calendar check refuses it.
        assert_eq!(
            verify_control_record_resolved(
                &signed_control_record(&SUCCESSOR_SEED, "2026-02-30T00:00:00Z", &tenant()),
                pinned_resolver(&store),
            )
            .unwrap_err(),
            AuthorityChainError::MalformedRecord
        );

        // A signer no chain names: Unreachable, through the seam unchanged.
        assert_eq!(
            verify_control_record_resolved(
                &signed_control_record(&THIRD_SEED, mid_overlap, &tenant()),
                pinned_resolver(&store),
            )
            .unwrap_err(),
            AuthorityChainError::Unreachable
        );
    }

    #[test]
    fn the_resolution_seam_fails_closed_before_verifying_a_foreign_tenant() {
        let store = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);
        // The record claims another tenant AND carries a signature that
        // verifies against nothing: RecordDisagreement is the answer only
        // if the resolver's rejection runs first — the ordering this seam
        // pins.
        let foreign = {
            let bytes = signed_control_record(
                &ROOT_SEED,
                LINK_INSTANT,
                &OTHER_TENANT.parse().expect("grammar"),
            );
            let Value::Object(mut object) = json::parse(&bytes).expect("json") else {
                panic!("object");
            };
            object.set(
                "authority_signature",
                text(&Ed25519Signature::from_raw([0x42; 64]).to_hex()),
            );
            Value::Object(object).canonical_bytes()
        };
        assert_eq!(
            verify_control_record_resolved(&foreign, pinned_resolver(&store)).unwrap_err(),
            AuthorityChainError::RecordDisagreement,
            "a tenant the resolver holds no root for fails closed before the walk and the signature"
        );
    }
}
