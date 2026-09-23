// SPDX-License-Identifier: Apache-2.0

//! Tenant-authority administration for `export-approval-v1`.
//!
//! Raw export is deliberately a different authority from derived-content
//! use.  This module therefore has no connection to the consumption-policy
//! or agent-use approval types: an export approval names one `UUIDv7` export
//! request, one frozen `inventory-v1` digest, one selected-occurrence-set
//! digest, one purpose, one destination class, one requester, one policy
//! version, and one short expiry.  It contains no storage credential, object
//! path, prompt permission, or reusable capability.
//!
//! The tenant export authority signs the immutable record with the same
//! authority-chain rule used by the control plane.  Publication is a typed,
//! digest-addressed operation through [`ExportApprovalRepository`].  A
//! revocation is another signed immutable record addressed by the approval
//! digest; it is never an edit or a delete.  The in-memory repository is a
//! small reference implementation for offline administration and tests.  A
//! production adapter can implement the same approval-only boundary without
//! receiving a raw-write or agent-use credential.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use archivist_protocol::json::{Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{
    BlobDigest, Ed25519PublicKey, Ed25519Signature, KeyId, RequestId, TenantId, Timestamp,
};

use crate::authority::{PinnedAuthorityRoot, verify_signing_authority};
use crate::ed25519;
use crate::error::IdentityError;
use crate::identity::SigningKey;
use crate::reference::ProtectedReference;

/// Namespace of the raw-export administration records.
pub const EXPORT_APPROVAL_SCHEMA: &str = "archivist.export/v1";
/// Immutable raw-export authorization record type.
pub const EXPORT_APPROVAL_RECORD_TYPE: &str = "export-approval-v1";
/// Immutable record type that permanently revokes an export approval.
pub const EXPORT_APPROVAL_REVOCATION_RECORD_TYPE: &str = "export-approval-revocation-v1";
/// The maximum export approval lifetime, inclusive of the 24-hour boundary.
pub const MAX_EXPORT_APPROVAL_LIFETIME: Duration = Duration::from_hours(24);

const APPROVAL_MEMBERS: [&str; 15] = [
    "authority_key_id",
    "authority_signature",
    "destination_class",
    "expires_at",
    "export_request_id",
    "inventory_digest",
    "issued_at",
    "policy_version",
    "purpose",
    "record_kind",
    "record_type",
    "requester",
    "schema",
    "selected_occurrence_set_digest",
    "tenant_id",
];

// The revocation has nine members.  This explicit list makes the closed
// shape auditable beside the approval shape.
const REVOCATION_MEMBER_NAMES: [&str; 9] = [
    "approval_digest",
    "authority_key_id",
    "authority_signature",
    "export_request_id",
    "record_kind",
    "record_type",
    "revoked_at",
    "schema",
    "tenant_id",
];

/// A candidate approval supplied by an offline export operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportApprovalSpec {
    /// Tenant whose raw archive may be exported.
    pub tenant_id: TenantId,
    /// `UUIDv7` handle for exactly one frozen export request.
    pub export_request_id: RequestId,
    /// Digest of the frozen `inventory-v1` evidence.
    pub inventory_digest: BlobDigest,
    /// Digest of the canonical selected-occurrence set.
    pub selected_occurrence_set_digest: BlobDigest,
    /// Human-approved export purpose.
    pub purpose: String,
    /// Closed destination class, not a bucket, URL, or credential.
    pub destination_class: String,
    /// Requesting operator identity.
    pub requester: String,
    /// Policy version under which the operator made this decision.
    pub policy_version: u64,
    /// Authority issue instant and the start of the approval's validity.
    pub issued_at: Timestamp,
    /// Approval expiry, no more than 24 hours after [`Self::issued_at`].
    pub expires_at: Timestamp,
}

/// A tenant's private export-authority signing identity.
pub struct TenantExportAuthority {
    tenant_id: TenantId,
    signing_key: SigningKey,
}

/// Short alias for callers that use the phrase “export authority”.
pub type ExportAuthority = TenantExportAuthority;

impl fmt::Debug for TenantExportAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TenantExportAuthority(<redacted>)")
    }
}

impl TenantExportAuthority {
    /// Adopt an authority seed for one tenant.
    ///
    /// The seed is retained only inside [`SigningKey`], whose `Debug`
    /// implementation is redacted.  Operational callers should prefer
    /// [`Self::from_protected_reference`] so the seed never enters ordinary
    /// configuration or command arguments.
    #[must_use]
    pub fn from_seed(tenant_id: TenantId, seed: [u8; 32]) -> Self {
        Self {
            tenant_id,
            signing_key: SigningKey::from_seed(seed),
        }
    }

    /// Load the authority seed through the protected `file:`/`env:`
    /// reference mechanism.
    ///
    /// # Errors
    /// [`IdentityError`] when the protected reference is missing, unsafe, or
    /// does not contain exactly one Ed25519 seed.
    pub fn from_protected_reference(
        tenant_id: TenantId,
        reference: &ProtectedReference,
    ) -> Result<Self, IdentityError> {
        let bytes = reference.resolve()?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::IdentityCorrupt)?;
        Ok(Self::from_seed(tenant_id, seed))
    }

    /// Tenant governed by this signing identity.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Public key identifier that appears in an approval record.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        let public = Ed25519PublicKey::from_raw(self.signing_key.public_key());
        KeyId::from_public_key(&public)
    }

    /// Issue one signed approval after checking the authority chain.
    ///
    /// The `fetch` callback is used only for public authority-rotation links.
    /// It cannot be used to read raw objects, and the resulting publication
    /// contains only the bounded approval fields and a signature.
    ///
    /// # Errors
    /// [`ExportApprovalError::InvalidBounds`] for malformed fields or a
    /// lifetime over 24 hours, [`ExportApprovalError::ScopeViolation`] for a
    /// foreign tenant, and [`ExportApprovalError::UntrustedAuthority`] when
    /// this key is not an accepted half of the tenant authority chain.
    pub fn issue(
        &self,
        root: &PinnedAuthorityRoot,
        spec: &ExportApprovalSpec,
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
    ) -> Result<ExportApprovalPublication, ExportApprovalError> {
        if self.tenant_id != *root.tenant_id() || spec.tenant_id != self.tenant_id {
            return Err(ExportApprovalError::ScopeViolation);
        }
        validate_spec(spec)?;
        let authority_key_id = self.key_id();
        let public = Ed25519PublicKey::from_raw(self.signing_key.public_key());
        let resolved = verify_signing_authority(root, &authority_key_id, &spec.issued_at, fetch)
            .map_err(|_| ExportApprovalError::UntrustedAuthority)?;
        if *resolved.public_key() != public {
            return Err(ExportApprovalError::UntrustedAuthority);
        }

        let mut object = approval_object(spec, &authority_key_id);
        let signature = self
            .signing_key
            .sign(&Value::Object(object.clone()).canonical_bytes());
        object.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        let envelope = Value::Object(object).canonical_bytes();
        let digest = BlobDigest::from_raw(sha256::digest(&envelope));
        Ok(ExportApprovalPublication {
            object_key: export_approval_object_key(&spec.tenant_id, &digest),
            envelope,
            digest,
            tenant_id: spec.tenant_id.clone(),
        })
    }

    /// Sign an append-only revocation for a verified approval.
    ///
    /// The revocation contains the approval digest and request UUID, but no
    /// storage capability.  Once published, its presence permanently ends
    /// the approval.
    ///
    /// # Errors
    /// [`ExportApprovalError::ScopeViolation`] for a foreign approval and
    /// [`ExportApprovalError::InvalidBounds`] for an invalid revocation
    /// instant.
    pub fn revoke(
        &self,
        root: &PinnedAuthorityRoot,
        approval: &ExportApproval,
        revoked_at: &Timestamp,
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
    ) -> Result<ExportApprovalRevocationPublication, ExportApprovalError> {
        if self.tenant_id != *root.tenant_id() || approval.tenant_id() != &self.tenant_id {
            return Err(ExportApprovalError::ScopeViolation);
        }
        if !revoked_at.calendar_valid()
            || timestamp_cmp(revoked_at, approval.issued_at())? == std::cmp::Ordering::Less
        {
            return Err(ExportApprovalError::InvalidBounds);
        }
        let authority_key_id = self.key_id();
        let public = Ed25519PublicKey::from_raw(self.signing_key.public_key());
        let resolved = verify_signing_authority(root, &authority_key_id, revoked_at, fetch)
            .map_err(|_| ExportApprovalError::UntrustedAuthority)?;
        if *resolved.public_key() != public {
            return Err(ExportApprovalError::UntrustedAuthority);
        }

        let mut object = revocation_object(approval, revoked_at, &authority_key_id);
        let signature = self
            .signing_key
            .sign(&Value::Object(object.clone()).canonical_bytes());
        object.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        let envelope = Value::Object(object).canonical_bytes();
        let digest = BlobDigest::from_raw(sha256::digest(&envelope));
        Ok(ExportApprovalRevocationPublication {
            object_key: export_approval_revocation_object_key(
                approval.tenant_id(),
                approval.digest(),
            ),
            envelope,
            digest,
            approval_digest: *approval.digest(),
            tenant_id: approval.tenant_id().clone(),
        })
    }
}

/// Issue an approval through a tenant export authority.
///
/// # Errors
/// Returns [`ExportApprovalError`] when the scope, bounds, authority chain,
/// or signing identity is not accepted.
pub fn issue_export_approval(
    authority: &TenantExportAuthority,
    root: &PinnedAuthorityRoot,
    spec: &ExportApprovalSpec,
    fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<ExportApprovalPublication, ExportApprovalError> {
    authority.issue(root, spec, fetch)
}

/// A signed immutable approval ready for an approval-only repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportApprovalPublication {
    object_key: String,
    envelope: Vec<u8>,
    digest: BlobDigest,
    tenant_id: TenantId,
}

impl ExportApprovalPublication {
    /// Digest-addressed approval object key.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    /// Complete canonical signed record.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// Digest of the complete signed record.
    #[must_use]
    pub const fn digest(&self) -> &BlobDigest {
        &self.digest
    }

    /// Tenant named by the signed record.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// A signed immutable revocation ready for an approval-only repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportApprovalRevocationPublication {
    object_key: String,
    envelope: Vec<u8>,
    digest: BlobDigest,
    approval_digest: BlobDigest,
    tenant_id: TenantId,
}

impl ExportApprovalRevocationPublication {
    /// Approval-digest-addressed revocation object key.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    /// Complete canonical signed revocation record.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// Digest of the complete revocation record.
    #[must_use]
    pub const fn digest(&self) -> &BlobDigest {
        &self.digest
    }

    /// Approval permanently ended by this record.
    #[must_use]
    pub const fn approval_digest(&self) -> &BlobDigest {
        &self.approval_digest
    }

    /// Tenant named by the signed record.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// A verified export approval.  The type has no read capability; it is only
/// an authenticated statement of the narrow selection and validity window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportApproval {
    tenant_id: TenantId,
    export_request_id: RequestId,
    inventory_digest: BlobDigest,
    selected_occurrence_set_digest: BlobDigest,
    purpose: String,
    destination_class: String,
    requester: String,
    policy_version: u64,
    issued_at: Timestamp,
    expires_at: Timestamp,
    digest: BlobDigest,
}

impl ExportApproval {
    /// Verify one approval against the pinned tenant authority chain.
    ///
    /// The record is accepted only in its exact canonical closed shape and
    /// only when its authority signature verifies at the record's own issue
    /// instant.  A `use-approval` or governance signature cannot parse as
    /// this record type.
    ///
    /// # Errors
    /// Returns [`ExportApprovalError`] when the closed shape, scope, bounds,
    /// authority chain, or signature is invalid.
    pub fn verify(
        root: &PinnedAuthorityRoot,
        envelope: &[u8],
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
    ) -> Result<Self, ExportApprovalError> {
        let object = parse_closed_object(envelope, &APPROVAL_MEMBERS)?;
        if text_member(&object, "schema") != Some(EXPORT_APPROVAL_SCHEMA)
            || text_member(&object, "record_type") != Some(EXPORT_APPROVAL_RECORD_TYPE)
            || text_member(&object, "record_kind") != Some("immutable")
        {
            return Err(ExportApprovalError::MalformedRecord);
        }
        if Value::Object(object.clone()).canonical_bytes() != envelope {
            return Err(ExportApprovalError::MalformedRecord);
        }
        let tenant_id = parse_tenant(&object, "tenant_id")?;
        if tenant_id != *root.tenant_id() {
            return Err(ExportApprovalError::ScopeViolation);
        }
        let export_request_id = RequestId::parse(required_text(&object, "export_request_id")?)
            .map_err(|_| ExportApprovalError::MalformedRecord)?;
        let inventory_digest = parse_digest(&object, "inventory_digest")?;
        let selected_occurrence_set_digest =
            parse_digest(&object, "selected_occurrence_set_digest")?;
        let purpose = parse_token(&object, "purpose")?;
        let destination_class = parse_token(&object, "destination_class")?;
        let requester = parse_token(&object, "requester")?;
        let policy_version = positive_number(&object, "policy_version")?;
        let issued_at = parse_timestamp(&object, "issued_at")?;
        let expires_at = parse_timestamp(&object, "expires_at")?;
        validate_lifetime(&issued_at, &expires_at)?;
        let authority_key_id = KeyId::parse(required_text(&object, "authority_key_id")?)
            .map_err(|_| ExportApprovalError::MalformedRecord)?;
        let signature = Ed25519Signature::parse(required_text(&object, "authority_signature")?)
            .map_err(|_| ExportApprovalError::MalformedRecord)?;
        let resolved = verify_signing_authority(root, &authority_key_id, &issued_at, fetch)
            .map_err(|_| ExportApprovalError::UntrustedAuthority)?;
        let mut unsigned = object;
        let _ = unsigned.remove("authority_signature");
        if !ed25519::verify(
            resolved.public_key().as_raw(),
            &Value::Object(unsigned).canonical_bytes(),
            &ed25519::Signature::from_bytes(*signature.as_raw()),
        ) {
            return Err(ExportApprovalError::InvalidSignature);
        }
        Ok(Self {
            tenant_id,
            export_request_id,
            inventory_digest,
            selected_occurrence_set_digest,
            purpose,
            destination_class,
            requester,
            policy_version,
            issued_at,
            expires_at,
            digest: BlobDigest::from_raw(sha256::digest(envelope)),
        })
    }

    /// Tenant named by the approval.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// UUIDv7 request handle bound by the approval.
    #[must_use]
    pub const fn export_request_id(&self) -> &RequestId {
        &self.export_request_id
    }

    /// Frozen inventory digest bound by the approval.
    #[must_use]
    pub const fn inventory_digest(&self) -> &BlobDigest {
        &self.inventory_digest
    }

    /// Selected-occurrence-set digest bound by the approval.
    #[must_use]
    pub const fn selected_occurrence_set_digest(&self) -> &BlobDigest {
        &self.selected_occurrence_set_digest
    }

    /// Approved purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        self.purpose.as_str()
    }

    /// Approved destination class.
    #[must_use]
    pub fn destination_class(&self) -> &str {
        self.destination_class.as_str()
    }

    /// Requesting operator.
    #[must_use]
    pub fn requester(&self) -> &str {
        self.requester.as_str()
    }

    /// Policy version bound by the decision.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// Issue instant.
    #[must_use]
    pub const fn issued_at(&self) -> &Timestamp {
        &self.issued_at
    }

    /// Expiry instant.
    #[must_use]
    pub const fn expires_at(&self) -> &Timestamp {
        &self.expires_at
    }

    /// Digest of the complete signed approval.
    #[must_use]
    pub const fn digest(&self) -> &BlobDigest {
        &self.digest
    }

    /// Whether the approval is valid at `now`, before considering revocation.
    #[must_use]
    pub fn valid_at(&self, now: &Timestamp) -> bool {
        timestamp_cmp(now, &self.issued_at)
            .is_ok_and(|ordering| ordering != std::cmp::Ordering::Less)
            && timestamp_cmp(now, &self.expires_at)
                .is_ok_and(|ordering| ordering == std::cmp::Ordering::Less)
    }
}

/// A verified append-only revocation record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportApprovalRevocation {
    tenant_id: TenantId,
    approval_digest: BlobDigest,
    export_request_id: RequestId,
    revoked_at: Timestamp,
    digest: BlobDigest,
}

impl ExportApprovalRevocation {
    /// Verify a revocation against the pinned tenant authority chain.
    ///
    /// # Errors
    /// Returns [`ExportApprovalError`] when the closed shape, scope,
    /// authority chain, or signature is invalid.
    pub fn verify(
        root: &PinnedAuthorityRoot,
        envelope: &[u8],
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
    ) -> Result<Self, ExportApprovalError> {
        let object = parse_closed_object(envelope, &REVOCATION_MEMBER_NAMES)?;
        if text_member(&object, "schema") != Some(EXPORT_APPROVAL_SCHEMA)
            || text_member(&object, "record_type") != Some(EXPORT_APPROVAL_REVOCATION_RECORD_TYPE)
            || text_member(&object, "record_kind") != Some("immutable")
        {
            return Err(ExportApprovalError::MalformedRecord);
        }
        if Value::Object(object.clone()).canonical_bytes() != envelope {
            return Err(ExportApprovalError::MalformedRecord);
        }
        let tenant_id = parse_tenant(&object, "tenant_id")?;
        if tenant_id != *root.tenant_id() {
            return Err(ExportApprovalError::ScopeViolation);
        }
        let approval_digest = parse_digest(&object, "approval_digest")?;
        let export_request_id = RequestId::parse(required_text(&object, "export_request_id")?)
            .map_err(|_| ExportApprovalError::MalformedRecord)?;
        let revoked_at = parse_timestamp(&object, "revoked_at")?;
        let authority_key_id = KeyId::parse(required_text(&object, "authority_key_id")?)
            .map_err(|_| ExportApprovalError::MalformedRecord)?;
        let signature = Ed25519Signature::parse(required_text(&object, "authority_signature")?)
            .map_err(|_| ExportApprovalError::MalformedRecord)?;
        let resolved = verify_signing_authority(root, &authority_key_id, &revoked_at, fetch)
            .map_err(|_| ExportApprovalError::UntrustedAuthority)?;
        let mut unsigned = object;
        let _ = unsigned.remove("authority_signature");
        if !ed25519::verify(
            resolved.public_key().as_raw(),
            &Value::Object(unsigned).canonical_bytes(),
            &ed25519::Signature::from_bytes(*signature.as_raw()),
        ) {
            return Err(ExportApprovalError::InvalidSignature);
        }
        Ok(Self {
            tenant_id,
            approval_digest,
            export_request_id,
            revoked_at,
            digest: BlobDigest::from_raw(sha256::digest(envelope)),
        })
    }

    /// Tenant named by the revocation.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Approval permanently ended by the revocation.
    #[must_use]
    pub const fn approval_digest(&self) -> &BlobDigest {
        &self.approval_digest
    }

    /// Request UUID copied from the approval for cross-record checking.
    #[must_use]
    pub const fn export_request_id(&self) -> &RequestId {
        &self.export_request_id
    }

    /// Authority issue instant of the revocation.
    #[must_use]
    pub const fn revoked_at(&self) -> &Timestamp {
        &self.revoked_at
    }

    /// Digest of the complete signed revocation.
    #[must_use]
    pub const fn digest(&self) -> &BlobDigest {
        &self.digest
    }
}

/// State of an inspected approval at a supplied instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExportApprovalStatus {
    /// Issue time has not yet arrived.
    NotYetValid,
    /// The approval is currently valid and has no stored revocation.
    Active,
    /// The signed expiry has passed.
    Expired,
    /// An append-only revocation is present.
    Revoked,
}

/// A fully verified approval plus its append-only status evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectedExportApproval {
    approval: ExportApproval,
    revocation: Option<ExportApprovalRevocation>,
    status: ExportApprovalStatus,
}

impl InspectedExportApproval {
    /// Verified approval.
    #[must_use]
    pub const fn approval(&self) -> &ExportApproval {
        &self.approval
    }

    /// Verified revocation, if one has been appended.
    #[must_use]
    pub const fn revocation(&self) -> Option<&ExportApprovalRevocation> {
        self.revocation.as_ref()
    }

    /// Status at the instant supplied to [`inspect_export_approval`].
    #[must_use]
    pub const fn status(&self) -> ExportApprovalStatus {
        self.status
    }

    /// Whether an exporter may proceed with this inspected selection.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, ExportApprovalStatus::Active)
    }
}

/// Approval-only storage boundary.  There is intentionally no raw-object
/// read, list, delete, credential, or agent-use method here.
pub trait ExportApprovalRepository {
    /// Read a digest-addressed approval.
    fn read_approval(
        &self,
        digest: &BlobDigest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, ExportApprovalError>> + Send;

    /// Read the immutable revocation addressed by an approval digest.
    fn read_revocation(
        &self,
        approval_digest: &BlobDigest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, ExportApprovalError>> + Send;

    /// Put an approval once; equal bytes are an idempotent retry.
    fn put_approval(
        &mut self,
        publication: &ExportApprovalPublication,
    ) -> impl Future<Output = Result<(), ExportApprovalError>> + Send;

    /// Append one revocation once; equal bytes are an idempotent retry and a
    /// different record at the same approval key is an integrity conflict.
    fn put_revocation(
        &mut self,
        publication: &ExportApprovalRevocationPublication,
    ) -> impl Future<Output = Result<(), ExportApprovalError>> + Send;
}

/// In-memory approval-only repository for offline tooling and tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryExportApprovalRepository {
    approvals: std::collections::BTreeMap<BlobDigest, Vec<u8>>,
    revocations: std::collections::BTreeMap<BlobDigest, Vec<u8>>,
}

impl MemoryExportApprovalRepository {
    /// Create an empty repository.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            approvals: std::collections::BTreeMap::new(),
            revocations: std::collections::BTreeMap::new(),
        }
    }
}

impl ExportApprovalRepository for MemoryExportApprovalRepository {
    async fn read_approval(
        &self,
        digest: &BlobDigest,
    ) -> Result<Option<Vec<u8>>, ExportApprovalError> {
        Ok(self.approvals.get(digest).cloned())
    }

    async fn read_revocation(
        &self,
        approval_digest: &BlobDigest,
    ) -> Result<Option<Vec<u8>>, ExportApprovalError> {
        Ok(self.revocations.get(approval_digest).cloned())
    }

    async fn put_approval(
        &mut self,
        publication: &ExportApprovalPublication,
    ) -> Result<(), ExportApprovalError> {
        match self.approvals.get(publication.digest()) {
            None => {
                self.approvals
                    .insert(*publication.digest(), publication.envelope.clone());
                Ok(())
            }
            Some(existing) if existing == publication.envelope() => Ok(()),
            Some(_) => Err(ExportApprovalError::IntegrityConflict),
        }
    }

    async fn put_revocation(
        &mut self,
        publication: &ExportApprovalRevocationPublication,
    ) -> Result<(), ExportApprovalError> {
        match self.revocations.get(publication.approval_digest()) {
            None => {
                self.revocations
                    .insert(*publication.approval_digest(), publication.envelope.clone());
                Ok(())
            }
            Some(existing) if existing == publication.envelope() => Ok(()),
            Some(_) => Err(ExportApprovalError::IntegrityConflict),
        }
    }
}

/// Verify and store a signed approval through the approval-only repository.
///
/// # Errors
/// Returns [`ExportApprovalError`] when the record or publication disagrees,
/// the authority signature fails, or the repository rejects the immutable
/// write.
pub async fn publish_export_approval<R: ExportApprovalRepository>(
    repository: &mut R,
    root: &PinnedAuthorityRoot,
    publication: &ExportApprovalPublication,
    fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<(), ExportApprovalError> {
    let approval = ExportApproval::verify(root, publication.envelope(), fetch)?;
    if approval.digest() != publication.digest()
        || approval.tenant_id() != publication.tenant_id()
        || publication.object_key()
            != export_approval_object_key(approval.tenant_id(), approval.digest())
    {
        return Err(ExportApprovalError::MalformedRecord);
    }
    repository.put_approval(publication).await
}

/// Verify and append a signed revocation, requiring its target approval to
/// exist and its copied `UUIDv7` request to match.
///
/// # Errors
/// Returns [`ExportApprovalError`] when the target is missing, either signed
/// record is invalid, the records disagree, or the append is a conflict.
pub async fn publish_export_approval_revocation<R: ExportApprovalRepository>(
    repository: &mut R,
    root: &PinnedAuthorityRoot,
    publication: &ExportApprovalRevocationPublication,
    mut fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<(), ExportApprovalError> {
    let approval_bytes = repository
        .read_approval(publication.approval_digest())
        .await?
        .ok_or(ExportApprovalError::MissingApproval)?;
    let approval = ExportApproval::verify(root, &approval_bytes, &mut fetch)?;
    let revocation = ExportApprovalRevocation::verify(root, publication.envelope(), &mut fetch)?;
    if revocation.approval_digest() != approval.digest()
        || revocation.export_request_id() != approval.export_request_id()
        || revocation.tenant_id() != approval.tenant_id()
        || revocation.digest() != publication.digest()
        || publication.object_key()
            != export_approval_revocation_object_key(approval.tenant_id(), approval.digest())
    {
        return Err(ExportApprovalError::RecordDisagreement);
    }
    if timestamp_cmp(revocation.revoked_at(), approval.issued_at())? == std::cmp::Ordering::Less {
        return Err(ExportApprovalError::InvalidBounds);
    }
    repository.put_revocation(publication).await
}

/// Read, verify, and classify one approval and its optional revocation.
///
/// # Errors
/// Returns [`ExportApprovalError`] when the approval is missing or either
/// stored record fails verification or cross-record consistency checks.
pub async fn inspect_export_approval<R: ExportApprovalRepository>(
    repository: &R,
    root: &PinnedAuthorityRoot,
    digest: &BlobDigest,
    now: &Timestamp,
    mut fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<InspectedExportApproval, ExportApprovalError> {
    let bytes = repository
        .read_approval(digest)
        .await?
        .ok_or(ExportApprovalError::MissingApproval)?;
    let approval = ExportApproval::verify(root, &bytes, &mut fetch)?;
    if approval.digest() != digest {
        return Err(ExportApprovalError::RecordDisagreement);
    }
    let revocation = match repository.read_revocation(digest).await? {
        Some(bytes) => {
            let revocation = ExportApprovalRevocation::verify(root, &bytes, &mut fetch)?;
            if revocation.approval_digest() != approval.digest()
                || revocation.export_request_id() != approval.export_request_id()
            {
                return Err(ExportApprovalError::RecordDisagreement);
            }
            Some(revocation)
        }
        None => None,
    };
    let status = if revocation.is_some() {
        ExportApprovalStatus::Revoked
    } else if timestamp_cmp(now, approval.issued_at())? == std::cmp::Ordering::Less {
        ExportApprovalStatus::NotYetValid
    } else if timestamp_cmp(now, approval.expires_at())? != std::cmp::Ordering::Less {
        ExportApprovalStatus::Expired
    } else {
        ExportApprovalStatus::Active
    };
    Ok(InspectedExportApproval {
        approval,
        revocation,
        status,
    })
}

/// Issue and append a revocation for an approval already stored in the
/// repository.
///
/// # Errors
/// Returns [`ExportApprovalError`] when the approval is missing or invalid,
/// the authority cannot sign at the requested instant, or the append fails.
pub async fn revoke_export_approval<R: ExportApprovalRepository>(
    repository: &mut R,
    authority: &TenantExportAuthority,
    root: &PinnedAuthorityRoot,
    approval_digest: &BlobDigest,
    revoked_at: &Timestamp,
    mut fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<ExportApprovalRevocationPublication, ExportApprovalError> {
    let bytes = repository
        .read_approval(approval_digest)
        .await?
        .ok_or(ExportApprovalError::MissingApproval)?;
    let approval = ExportApproval::verify(root, &bytes, &mut fetch)?;
    if approval.digest() != approval_digest {
        return Err(ExportApprovalError::RecordDisagreement);
    }
    let publication = authority.revoke(root, &approval, revoked_at, &mut fetch)?;
    publish_export_approval_revocation(repository, root, &publication, &mut fetch).await?;
    Ok(publication)
}

/// Stable, content-free failure classes for export administration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExportApprovalError {
    /// The record was not the exact closed shape or contained an invalid
    /// identifier, digest, token, timestamp, or policy version.
    MalformedRecord,
    /// The candidate's numeric or timestamp relationship is invalid,
    /// including an expiry beyond 24 hours.
    InvalidBounds,
    /// The record names another tenant.
    ScopeViolation,
    /// The authority key is not accepted by the pinned chain.
    UntrustedAuthority,
    /// The authority signature does not verify.
    InvalidSignature,
    /// The publication and its signed record disagree.
    RecordDisagreement,
    /// The requested immutable target does not exist.
    MissingApproval,
    /// An immutable object at the derived address differs from the retry.
    IntegrityConflict,
    /// The approval has passed its signed expiry.
    Expired,
    /// The approval has an append-only revocation.
    Revoked,
    /// The repository could not complete an operation.
    RepositoryUnavailable,
}

impl ExportApprovalError {
    /// Content-free diagnostic class.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::MalformedRecord => "malformed-record",
            Self::InvalidBounds => "invalid-bounds",
            Self::ScopeViolation => "scope-violation",
            Self::UntrustedAuthority => "untrusted-authority",
            Self::InvalidSignature => "invalid-signature",
            Self::RecordDisagreement => "record-disagreement",
            Self::MissingApproval => "missing-approval",
            Self::IntegrityConflict => "integrity-conflict",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::RepositoryUnavailable => "repository-unavailable",
        }
    }
}

impl fmt::Display for ExportApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.class_text())
    }
}

impl std::error::Error for ExportApprovalError {}

/// Digest-addressed approval object key.
#[must_use]
pub fn export_approval_object_key(tenant: &TenantId, digest: &BlobDigest) -> String {
    format!(
        "tenants/{}/v1/control/export-approvals/{}.json",
        tenant.as_str(),
        digest.to_hex()
    )
}

/// Approval-addressed immutable revocation object key.
#[must_use]
pub fn export_approval_revocation_object_key(
    tenant: &TenantId,
    approval_digest: &BlobDigest,
) -> String {
    format!(
        "tenants/{}/v1/control/export-approval-revocations/{}.json",
        tenant.as_str(),
        approval_digest.to_hex()
    )
}

fn approval_object(spec: &ExportApprovalSpec, authority_key_id: &KeyId) -> Object {
    let mut object = Object::new();
    object.set("schema", text(EXPORT_APPROVAL_SCHEMA));
    object.set("record_type", text(EXPORT_APPROVAL_RECORD_TYPE));
    object.set("record_kind", text("immutable"));
    object.set("tenant_id", text(spec.tenant_id.as_str()));
    object.set("export_request_id", text(spec.export_request_id.as_str()));
    object.set("inventory_digest", text(&spec.inventory_digest.to_hex()));
    object.set(
        "selected_occurrence_set_digest",
        text(&spec.selected_occurrence_set_digest.to_hex()),
    );
    object.set("purpose", text(&spec.purpose));
    object.set("destination_class", text(&spec.destination_class));
    object.set("requester", text(&spec.requester));
    object.set(
        "policy_version",
        Value::Int(spec.policy_version.cast_signed()),
    );
    object.set("issued_at", text(spec.issued_at.as_str()));
    object.set("expires_at", text(spec.expires_at.as_str()));
    object.set("authority_key_id", text(&authority_key_id.to_hex()));
    object
}

fn revocation_object(
    approval: &ExportApproval,
    revoked_at: &Timestamp,
    authority_key_id: &KeyId,
) -> Object {
    let mut object = Object::new();
    object.set("schema", text(EXPORT_APPROVAL_SCHEMA));
    object.set("record_type", text(EXPORT_APPROVAL_REVOCATION_RECORD_TYPE));
    object.set("record_kind", text("immutable"));
    object.set("tenant_id", text(approval.tenant_id.as_str()));
    object.set("approval_digest", text(&approval.digest.to_hex()));
    object.set(
        "export_request_id",
        text(approval.export_request_id.as_str()),
    );
    object.set("revoked_at", text(revoked_at.as_str()));
    object.set("authority_key_id", text(&authority_key_id.to_hex()));
    object
}

fn validate_spec(spec: &ExportApprovalSpec) -> Result<(), ExportApprovalError> {
    if spec.policy_version == 0
        || !spec.issued_at.calendar_valid()
        || !spec.expires_at.calendar_valid()
        || !valid_token(&spec.purpose)
        || !valid_token(&spec.destination_class)
        || !valid_token(&spec.requester)
    {
        return Err(ExportApprovalError::InvalidBounds);
    }
    validate_lifetime(&spec.issued_at, &spec.expires_at)
}

fn validate_lifetime(
    issued_at: &Timestamp,
    expires_at: &Timestamp,
) -> Result<(), ExportApprovalError> {
    let issued = timestamp_value(issued_at)?;
    let expires = timestamp_value(expires_at)?;
    let lifetime = expires
        .checked_sub(issued)
        .ok_or(ExportApprovalError::InvalidBounds)?;
    if lifetime <= 0
        || lifetime > i128::from(MAX_EXPORT_APPROVAL_LIFETIME.as_secs()) * 1_000_000_000
    {
        return Err(ExportApprovalError::InvalidBounds);
    }
    Ok(())
}

fn valid_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte))
}

fn parse_closed_object(envelope: &[u8], members: &[&str]) -> Result<Object, ExportApprovalError> {
    let Value::Object(object) = archivist_protocol::json::parse(envelope)
        .map_err(|_| ExportApprovalError::MalformedRecord)?
    else {
        return Err(ExportApprovalError::MalformedRecord);
    };
    if object.len() != members.len() || members.iter().any(|name| object.get(name).is_none()) {
        return Err(ExportApprovalError::MalformedRecord);
    }
    Ok(object)
}

fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(text)) => Some(text),
        _ => None,
    }
}

fn required_text<'a>(object: &'a Object, name: &str) -> Result<&'a str, ExportApprovalError> {
    text_member(object, name).ok_or(ExportApprovalError::MalformedRecord)
}

fn parse_tenant(object: &Object, name: &str) -> Result<TenantId, ExportApprovalError> {
    TenantId::parse(required_text(object, name)?).map_err(|_| ExportApprovalError::MalformedRecord)
}

fn parse_digest(object: &Object, name: &str) -> Result<BlobDigest, ExportApprovalError> {
    BlobDigest::parse(required_text(object, name)?)
        .map_err(|_| ExportApprovalError::MalformedRecord)
}

fn parse_timestamp(object: &Object, name: &str) -> Result<Timestamp, ExportApprovalError> {
    let timestamp = Timestamp::parse(required_text(object, name)?)
        .map_err(|_| ExportApprovalError::MalformedRecord)?;
    if !timestamp.calendar_valid() {
        return Err(ExportApprovalError::MalformedRecord);
    }
    Ok(timestamp)
}

fn parse_token(object: &Object, name: &str) -> Result<String, ExportApprovalError> {
    let text = required_text(object, name)?;
    if !valid_token(text) {
        return Err(ExportApprovalError::MalformedRecord);
    }
    Ok(text.to_owned())
}

fn positive_number(object: &Object, name: &str) -> Result<u64, ExportApprovalError> {
    match object.get(name) {
        Some(Value::Int(value)) if *value > 0 => {
            u64::try_from(*value).map_err(|_| ExportApprovalError::MalformedRecord)
        }
        _ => Err(ExportApprovalError::MalformedRecord),
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn timestamp_cmp(
    left: &Timestamp,
    right: &Timestamp,
) -> Result<std::cmp::Ordering, ExportApprovalError> {
    Ok(timestamp_value(left)?.cmp(&timestamp_value(right)?))
}

/// Convert the protocol's UTC timestamp to nanoseconds on a proleptic
/// Gregorian timeline.  This avoids lexical comparison bugs when one
/// timestamp has a one-digit fraction and the other has nine digits.
fn timestamp_value(timestamp: &Timestamp) -> Result<i128, ExportApprovalError> {
    if !timestamp.calendar_valid() {
        return Err(ExportApprovalError::InvalidBounds);
    }
    let bytes = timestamp.as_str().as_bytes();
    let number = |start: usize, end: usize| -> i128 {
        bytes[start..end]
            .iter()
            .fold(0_i128, |value, byte| value * 10 + i128::from(byte - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let hour = number(11, 13);
    let minute = number(14, 16);
    let second = number(17, 19);
    let adjusted_year = year - i128::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let fraction = if bytes[19] == b'.' {
        let end = bytes.len() - 1;
        let raw = &bytes[20..end];
        let value = raw
            .iter()
            .fold(0_i128, |value, byte| value * 10 + i128::from(byte - b'0'));
        let exponent =
            u32::try_from(9 - raw.len()).map_err(|_| ExportApprovalError::InvalidBounds)?;
        value * 10_i128.pow(exponent)
    } else {
        0
    };
    Ok((((days * 24 + hour) * 60 + minute) * 60 + second) * 1_000_000_000 + fraction)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const REQUEST: &str = "018f2d2a-7b3c-7abc-8def-0123456789ab";
    const ISSUED: &str = "2026-09-20T00:00:00Z";
    const EXPIRES: &str = "2026-09-21T00:00:00Z";
    const REVOKED: &str = "2026-09-20T01:00:00Z";
    const AUTHORITY_SEED: [u8; 32] = [0x17; 32];

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).expect("tenant grammar")
    }

    fn root() -> PinnedAuthorityRoot {
        PinnedAuthorityRoot::new(
            tenant(),
            Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&AUTHORITY_SEED)),
        )
    }

    fn authority() -> TenantExportAuthority {
        TenantExportAuthority::from_seed(tenant(), AUTHORITY_SEED)
    }

    fn spec() -> ExportApprovalSpec {
        ExportApprovalSpec {
            tenant_id: tenant(),
            export_request_id: RequestId::parse(REQUEST).expect("uuidv7 grammar"),
            inventory_digest: BlobDigest::from_raw([1; 32]),
            selected_occurrence_set_digest: BlobDigest::from_raw([2; 32]),
            purpose: "customer-restore".to_owned(),
            destination_class: "offline-vault".to_owned(),
            requester: "operator-7".to_owned(),
            policy_version: 4,
            issued_at: Timestamp::parse(ISSUED).expect("timestamp grammar"),
            expires_at: Timestamp::parse(EXPIRES).expect("timestamp grammar"),
        }
    }

    fn issue() -> ExportApprovalPublication {
        authority()
            .issue(&root(), &spec(), |_| None)
            .expect("root authority issues")
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(value) => return value,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn approval_binds_every_export_scope_and_verifies() {
        let publication = issue();
        let approval = ExportApproval::verify(&root(), publication.envelope(), |_| None)
            .expect("signed approval verifies");
        assert_eq!(approval.export_request_id().as_str(), REQUEST);
        assert_eq!(approval.inventory_digest(), &BlobDigest::from_raw([1; 32]));
        assert_eq!(
            approval.selected_occurrence_set_digest(),
            &BlobDigest::from_raw([2; 32])
        );
        assert_eq!(approval.purpose(), "customer-restore");
        assert_eq!(approval.destination_class(), "offline-vault");
        assert_eq!(approval.requester(), "operator-7");
        assert_eq!(approval.policy_version(), 4);
        assert!(approval.valid_at(&Timestamp::parse("2026-09-20T12:00:00Z").unwrap()));
        assert!(!approval.valid_at(&Timestamp::parse(EXPIRES).unwrap()));
        assert!(
            !publication
                .envelope()
                .windows(3)
                .any(|window| window == b"s3")
        );
    }

    #[test]
    fn lifetime_is_at_most_24_hours_and_request_is_uuidv7() {
        let mut candidate = spec();
        candidate.expires_at = Timestamp::parse("2026-09-21T00:00:00.001Z").unwrap();
        assert_eq!(
            authority().issue(&root(), &candidate, |_| None),
            Err(ExportApprovalError::InvalidBounds)
        );
        candidate.export_request_id =
            RequestId::parse("018f2d2a-7b3c-47bc-8def-0123456789ab").unwrap();
        assert_eq!(
            authority().issue(&root(), &candidate, |_| None),
            Err(ExportApprovalError::InvalidBounds)
        );
    }

    #[test]
    fn storage_is_immutable_and_revocation_is_append_only() {
        let publication = issue();
        let mut repository = MemoryExportApprovalRepository::new();
        assert_eq!(
            block_on(publish_export_approval(
                &mut repository,
                &root(),
                &publication,
                |_| None
            )),
            Ok(())
        );
        assert_eq!(
            block_on(publish_export_approval(
                &mut repository,
                &root(),
                &publication,
                |_| None
            )),
            Ok(())
        );
        let revoked = block_on(revoke_export_approval(
            &mut repository,
            &authority(),
            &root(),
            publication.digest(),
            &Timestamp::parse(REVOKED).unwrap(),
            |_| None,
        ))
        .expect("revocation appends");
        let inspected = block_on(inspect_export_approval(
            &repository,
            &root(),
            publication.digest(),
            &Timestamp::parse("2026-09-20T02:00:00Z").unwrap(),
            |_| None,
        ))
        .expect("inspection verifies both records");
        assert_eq!(inspected.status(), ExportApprovalStatus::Revoked);
        assert_eq!(inspected.revocation().unwrap().digest(), revoked.digest());
        assert!(!inspected.is_active());
    }

    #[test]
    fn foreign_signature_and_use_approval_do_not_verify_as_export() {
        let publication = issue();
        let mut bytes = publication.envelope().to_vec();
        let marker = b"export-approval-v1";
        let position = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("record type is present");
        bytes[position] = b'u';
        assert_eq!(
            ExportApproval::verify(&root(), &bytes, |_| None),
            Err(ExportApprovalError::MalformedRecord)
        );
    }
}
