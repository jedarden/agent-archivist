// SPDX-License-Identifier: Apache-2.0

//! Offline administration and verification of `use-approval-v1`.
//!
//! A use approval is the human authorization half of derived-use
//! governance (implementation plan, Phase 10): after a classifier has
//! produced evidence, a person decides.  The offline tenant governance
//! identity signs one immutable record that binds the tenant, the episode
//! digest, the assessment digest, the purpose, the allowed consumer class,
//! the policy version the decision was made under, the approver identity,
//! the issue and expiry instants, and the assessment-freshness policy
//! snapshot copied from the current [`ConsumptionPolicy`] at the instant
//! of authorization — so an independent verifier re-derives the same
//! freshness decision from the record alone.  Approval for one purpose or
//! episode cannot authorize another: the record carries exactly one of
//! each, and evaluation re-checks the purpose-to-consumer-class mapping
//! against the current policy before any derived byte moves.
//!
//! Revocation is a second signed record, never an edit.  It is appended at
//! a key derived from the approval digest it kills and, like every
//! immutable record in this crate, is written once: a byte-identical retry
//! is an idempotent repair and an incompatible object at the same key is
//! an integrity conflict.  No operation removes or supersedes a
//! revocation, and a revocation carries no expiry, because nothing may
//! un-revoke.
//!
//! The module deliberately owns an approval-only repository boundary: the
//! offline administrator can publish, inspect, and revoke approval records
//! through it, but has no operation for raw, catalog, derived, or
//! arbitrary object data, and the governance identity that signs here
//! cannot reach raw bytes by construction.  A production adapter can
//! implement [`UseApprovalRepository`] over the dedicated governance
//! credential without widening that authority.
//!
//! # Private material discipline
//!
//! The governance identity's seed never appears as a literal: the
//! offline administrator adopts it through
//! [`OfflineGovernanceIdentity::from_protected_reference`], which resolves
//! a [`ProtectedReference`] (`file:`/`env:`) to exactly 32 seed bytes and
//! fails closed otherwise.  The identity renders redacted in `Debug`, and
//! every error names its failure class without echoing record contents.

use std::fmt;
use std::future::Future;

use archivist_protocol::json::{Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{BlobDigest, Ed25519Signature, KeyId, TenantId, Timestamp};

use crate::consumption_policy::{
    self, CLOCK_SKEW_ALLOWANCE_SECONDS, ConsumptionPolicy, GovernanceTrustAnchor,
    MAX_APPROVAL_LIFETIME_SECONDS, MAX_ASSESSMENT_AGE_SECONDS, OfflineGovernanceIdentity,
};
use crate::ed25519;
use crate::error::IdentityError;
use crate::reference::ProtectedReference;

/// The governance namespace of use-approval-v1 records.
pub const USE_APPROVAL_SCHEMA: &str = "archivist.governance/v1";
/// The immutable use-approval record type.
pub const USE_APPROVAL_RECORD_TYPE: &str = "use-approval-v1";
/// The immutable revocation record type that ends a use approval.
pub const USE_APPROVAL_REVOCATION_RECORD_TYPE: &str = "use-approval-revocation-v1";

/// A use-approval definition supplied by the offline approver before
/// signing.
///
/// The freshness snapshot is *not* supplied:
/// [`OfflineGovernanceIdentity::sign_use_approval`] copies
/// it from the current policy at signing time, which is the instant of
/// authorization, and stamps the policy version with it.  The constructor
/// is intentionally small; signing performs the complete cross-field
/// validation against the policy the approval binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UseApprovalSpec {
    /// The tenant whose derived content is approved for use.
    pub tenant_id: TenantId,
    /// Digest of the `redaction-v1` episode the approval covers.
    pub episode_digest: BlobDigest,
    /// Digest of the `risk-assessment-v1` result the decision relied on.
    pub assessment_digest: BlobDigest,
    /// The one purpose this approval grants.
    pub purpose: String,
    /// The one consumer class this approval grants the purpose to.
    pub consumer_class: String,
    /// The human approver identity taking responsibility for the decision.
    pub approver: String,
    /// When the governance identity issued the approval.
    pub issued_at: Timestamp,
    /// When the approval stops authorizing use.
    pub expires_at: Timestamp,
}

/// The assessment-freshness policy an approval was authorized under.
///
/// Copied from the current [`ConsumptionPolicy`] at the instant of
/// authorization: the freshness bounds the decision used, and the
/// evaluation timestamp that lets independent verifiers reproduce the
/// decision.  Evaluation requires both bounds to still equal the current
/// policy's — a policy change denies every outstanding approval until it
/// is re-issued under the new policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssessmentFreshness {
    /// When freshness was evaluated: the instant of authorization.
    pub evaluated_at: Timestamp,
    /// The policy's `assessment_not_before` at evaluation time.
    pub not_before: Timestamp,
    /// The policy's `max_assessment_age_seconds` at evaluation time.
    pub max_age_seconds: u64,
}

/// A signed immutable use approval ready for storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UseApprovalPublication {
    object_key: String,
    envelope: Vec<u8>,
    digest: BlobDigest,
    tenant_id: TenantId,
}

impl UseApprovalPublication {
    /// The digest-addressed immutable object key.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    /// The complete canonical signed record.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// The digest of the complete signed record, and the revocation key's
    /// subject.
    #[must_use]
    pub const fn digest(&self) -> &BlobDigest {
        &self.digest
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// A signed immutable revocation ready for storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UseApprovalRevocationPublication {
    object_key: String,
    envelope: Vec<u8>,
    approval_digest: BlobDigest,
    tenant_id: TenantId,
}

impl UseApprovalRevocationPublication {
    /// The append-only revocation object key.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    /// The complete canonical signed record.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// The approval the revocation ends.
    #[must_use]
    pub const fn approval_digest(&self) -> &BlobDigest {
        &self.approval_digest
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// A verified immutable use-approval record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UseApproval {
    tenant_id: TenantId,
    episode_digest: BlobDigest,
    assessment_digest: BlobDigest,
    purpose: String,
    consumer_class: String,
    policy_version: u64,
    approver: String,
    issued_at: Timestamp,
    expires_at: Timestamp,
    freshness: AssessmentFreshness,
    digest: BlobDigest,
}

impl UseApproval {
    /// Verify one signed use approval against the offline-published
    /// governance anchor.
    ///
    /// # Errors
    ///
    /// Returns an approval error for malformed, out-of-scope, or
    /// incorrectly signed bytes.
    pub fn verify(
        anchor: &GovernanceTrustAnchor,
        envelope: &[u8],
    ) -> Result<Self, UseApprovalError> {
        let object = consumption_policy::parse_closed_object(envelope, &APPROVAL_MEMBERS)?;
        if consumption_policy::text_member(&object, "schema") != Some(USE_APPROVAL_SCHEMA)
            || consumption_policy::text_member(&object, "record_type")
                != Some(USE_APPROVAL_RECORD_TYPE)
            || consumption_policy::text_member(&object, "record_kind") != Some("immutable")
        {
            return Err(UseApprovalError::MalformedRecord);
        }
        if Value::Object(object.clone()).canonical_bytes() != envelope {
            return Err(UseApprovalError::MalformedRecord);
        }
        let tenant_id = consumption_policy::parse_tenant(&object, "tenant_id")?;
        if tenant_id != *anchor.tenant_id() {
            return Err(UseApprovalError::ScopeViolation);
        }
        let episode_digest = consumption_policy::parse_digest(&object, "episode_digest")?;
        let assessment_digest = consumption_policy::parse_digest(&object, "assessment_digest")?;
        let purpose = required_token(&object, "purpose")?;
        let consumer_class = required_token(&object, "consumer_class")?;
        let approver = required_token(&object, "approver")?;
        let policy_version = consumption_policy::positive_number(&object, "policy_version")?;
        let issued_at = consumption_policy::parse_timestamp(&object, "issued_at")?;
        let expires_at = consumption_policy::parse_timestamp(&object, "expires_at")?;
        let freshness = parse_freshness(&object)?;
        if consumption_policy::timestamp_cmp(&issued_at, &expires_at)? != std::cmp::Ordering::Less
            || freshness.evaluated_at != issued_at
            || freshness.max_age_seconds == 0
            || freshness.max_age_seconds > MAX_ASSESSMENT_AGE_SECONDS
            || approval_lifetime_nanos(&issued_at, &expires_at)?
                > i128::from(MAX_APPROVAL_LIFETIME_SECONDS) * 1_000_000_000
        {
            return Err(UseApprovalError::InvalidBounds);
        }
        let signer = KeyId::parse(consumption_policy::required_text(
            &object,
            "governance_key_id",
        )?)
        .map_err(|_| UseApprovalError::MalformedRecord)?;
        if signer != *anchor.key_id() {
            return Err(UseApprovalError::UntrustedGovernance);
        }
        let signature = Ed25519Signature::parse(consumption_policy::required_text(
            &object,
            "governance_signature",
        )?)
        .map_err(|_| UseApprovalError::MalformedRecord)?;
        let mut unsigned = object.clone();
        let _ = unsigned.remove("governance_signature");
        if !ed25519::verify(
            anchor.public_key().as_raw(),
            &Value::Object(unsigned).canonical_bytes(),
            &ed25519::Signature::from_bytes(*signature.as_raw()),
        ) {
            return Err(UseApprovalError::InvalidSignature);
        }
        Ok(Self {
            tenant_id,
            episode_digest,
            assessment_digest,
            purpose,
            consumer_class,
            policy_version,
            approver,
            issued_at,
            expires_at,
            freshness,
            digest: BlobDigest::from_raw(sha256::digest(envelope)),
        })
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The approved episode digest.
    #[must_use]
    pub const fn episode_digest(&self) -> &BlobDigest {
        &self.episode_digest
    }

    /// The assessed-episode digest the decision relied on.
    #[must_use]
    pub const fn assessment_digest(&self) -> &BlobDigest {
        &self.assessment_digest
    }

    /// The granted purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// The granted consumer class.
    #[must_use]
    pub fn consumer_class(&self) -> &str {
        &self.consumer_class
    }

    /// The policy version the decision was made under.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// The approver identity.
    #[must_use]
    pub fn approver(&self) -> &str {
        &self.approver
    }

    /// The issue instant.
    #[must_use]
    pub const fn issued_at(&self) -> &Timestamp {
        &self.issued_at
    }

    /// The expiry instant.
    #[must_use]
    pub const fn expires_at(&self) -> &Timestamp {
        &self.expires_at
    }

    /// The freshness policy the decision was authorized under.
    #[must_use]
    pub const fn freshness(&self) -> &AssessmentFreshness {
        &self.freshness
    }

    /// The digest of the complete signed record.
    #[must_use]
    pub const fn digest(&self) -> &BlobDigest {
        &self.digest
    }
}

/// A verified immutable revocation record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UseApprovalRevocation {
    tenant_id: TenantId,
    approval_digest: BlobDigest,
    episode_digest: BlobDigest,
    revoked_at: Timestamp,
}

impl UseApprovalRevocation {
    /// Verify one signed revocation against the governance anchor.
    ///
    /// # Errors
    ///
    /// Returns an approval error for malformed, out-of-scope, or
    /// incorrectly signed bytes.
    pub fn verify(
        anchor: &GovernanceTrustAnchor,
        envelope: &[u8],
    ) -> Result<Self, UseApprovalError> {
        let object = consumption_policy::parse_closed_object(envelope, &REVOCATION_MEMBERS)?;
        if consumption_policy::text_member(&object, "schema") != Some(USE_APPROVAL_SCHEMA)
            || consumption_policy::text_member(&object, "record_type")
                != Some(USE_APPROVAL_REVOCATION_RECORD_TYPE)
            || consumption_policy::text_member(&object, "record_kind") != Some("immutable")
        {
            return Err(UseApprovalError::MalformedRecord);
        }
        if Value::Object(object.clone()).canonical_bytes() != envelope {
            return Err(UseApprovalError::MalformedRecord);
        }
        let tenant_id = consumption_policy::parse_tenant(&object, "tenant_id")?;
        if tenant_id != *anchor.tenant_id() {
            return Err(UseApprovalError::ScopeViolation);
        }
        let approval_digest = consumption_policy::parse_digest(&object, "approval_digest")?;
        let episode_digest = consumption_policy::parse_digest(&object, "episode_digest")?;
        let revoked_at = consumption_policy::parse_timestamp(&object, "revoked_at")?;
        let signer = KeyId::parse(consumption_policy::required_text(
            &object,
            "governance_key_id",
        )?)
        .map_err(|_| UseApprovalError::MalformedRecord)?;
        if signer != *anchor.key_id() {
            return Err(UseApprovalError::UntrustedGovernance);
        }
        let signature = Ed25519Signature::parse(consumption_policy::required_text(
            &object,
            "governance_signature",
        )?)
        .map_err(|_| UseApprovalError::MalformedRecord)?;
        let mut unsigned = object.clone();
        let _ = unsigned.remove("governance_signature");
        if !ed25519::verify(
            anchor.public_key().as_raw(),
            &Value::Object(unsigned).canonical_bytes(),
            &ed25519::Signature::from_bytes(*signature.as_raw()),
        ) {
            return Err(UseApprovalError::InvalidSignature);
        }
        Ok(Self {
            tenant_id,
            approval_digest,
            episode_digest,
            revoked_at,
        })
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The approval the revocation ends.
    #[must_use]
    pub const fn approval_digest(&self) -> &BlobDigest {
        &self.approval_digest
    }

    /// The approved episode, copied from the approval and cross-checked at
    /// append time.
    #[must_use]
    pub const fn episode_digest(&self) -> &BlobDigest {
        &self.episode_digest
    }

    /// When the revocation was signed.
    #[must_use]
    pub const fn revoked_at(&self) -> &Timestamp {
        &self.revoked_at
    }
}

impl OfflineGovernanceIdentity {
    /// Adopt a governance seed the offline administrator holds behind a
    /// protected reference (CFG-029/CFG-030).
    ///
    /// The reference resolves to exactly 32 raw seed bytes — a
    /// mode-restricted `file:` target with the seed, or an `env:` variable
    /// holding it.  The reference, not the value, is what configuration
    /// and diagnostics carry.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when the reference fails to resolve or
    /// does not hold exactly 32 bytes; no error echoes the target or the
    /// value.
    pub fn from_protected_reference(reference: &ProtectedReference) -> Result<Self, IdentityError> {
        let bytes = reference.resolve()?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::IdentityCorrupt)?;
        Ok(Self::from_seed(seed))
    }

    /// Validate, canonicalize, sign, and address one use approval under the
    /// current policy.
    ///
    /// This is the instant of authorization: the record stamps the
    /// policy version, copies the policy's freshness bounds as the
    /// `AssessmentFreshness` snapshot, and cross-checks the purpose and
    /// consumer class against the policy's mapping.  The signing identity
    /// must be the same governance key that signed the policy.
    ///
    /// # Errors
    ///
    /// Returns [`UseApprovalError::PurposeDenied`] when the policy does not
    /// map the purpose to the consumer class,
    /// [`UseApprovalError::InvalidBounds`] when timestamps, tokens, or the
    /// approval lifetime are out of bounds,
    /// [`UseApprovalError::ScopeViolation`] when the spec names another
    /// tenant, and [`UseApprovalError::UntrustedGovernance`] when the
    /// identity did not sign the policy.
    pub fn sign_use_approval(
        &self,
        spec: &UseApprovalSpec,
        policy: &ConsumptionPolicy,
    ) -> Result<UseApprovalPublication, UseApprovalError> {
        if spec.tenant_id != *policy.tenant_id() {
            return Err(UseApprovalError::ScopeViolation);
        }
        if policy.governance_key_id() != &self.key_id() {
            return Err(UseApprovalError::UntrustedGovernance);
        }
        for candidate in [&spec.purpose, &spec.consumer_class, &spec.approver] {
            if !consumption_policy::token(candidate) {
                return Err(UseApprovalError::InvalidBounds);
            }
        }
        consumption_policy::validate_timestamp(&spec.issued_at)
            .map_err(|_| UseApprovalError::InvalidBounds)?;
        consumption_policy::validate_timestamp(&spec.expires_at)
            .map_err(|_| UseApprovalError::InvalidBounds)?;
        if consumption_policy::timestamp_cmp(&spec.issued_at, &spec.expires_at)?
            != std::cmp::Ordering::Less
        {
            return Err(UseApprovalError::InvalidBounds);
        }
        if approval_lifetime_nanos(&spec.issued_at, &spec.expires_at)?
            > i128::from(policy.max_approval_lifetime_seconds()) * 1_000_000_000
        {
            return Err(UseApprovalError::InvalidBounds);
        }
        let granted = policy
            .purpose_to_consumer_classes()
            .get(&spec.purpose)
            .is_some_and(|classes| classes.contains(&spec.consumer_class));
        if !granted {
            return Err(UseApprovalError::PurposeDenied);
        }
        let freshness = AssessmentFreshness {
            evaluated_at: spec.issued_at.clone(),
            not_before: policy.assessment_not_before().clone(),
            max_age_seconds: policy.max_assessment_age_seconds(),
        };
        let mut object = approval_object(spec, &freshness, policy.policy_version(), &self.key_id());
        let signature = self
            .signing_key()
            .sign(&Value::Object(object.clone()).canonical_bytes());
        object.set(
            "governance_signature",
            consumption_policy::text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        let envelope = Value::Object(object).canonical_bytes();
        let digest = BlobDigest::from_raw(sha256::digest(&envelope));
        Ok(UseApprovalPublication {
            object_key: use_approval_object_key(&spec.tenant_id, &digest),
            envelope,
            digest,
            tenant_id: spec.tenant_id.clone(),
        })
    }

    /// Sign the append-only revocation that ends a verified approval.
    ///
    /// The record names the approval by digest and copies its episode
    /// digest so the act is self-describing; the append path cross-checks
    /// the copy against the stored approval.  A revocation may be signed
    /// after its approval's expiry — the record stands as evidence even
    /// where the approval no longer authorizes — but never before the
    /// approval existed.
    ///
    /// # Errors
    ///
    /// Returns [`UseApprovalError::InvalidBounds`] when `revoked_at` is
    /// malformed or precedes the approval's issuance.
    pub fn sign_use_approval_revocation(
        &self,
        anchor: &GovernanceTrustAnchor,
        approval: &UseApproval,
        revoked_at: &Timestamp,
    ) -> Result<UseApprovalRevocationPublication, UseApprovalError> {
        if *approval.tenant_id() != *anchor.tenant_id() {
            return Err(UseApprovalError::ScopeViolation);
        }
        if self.key_id() != *anchor.key_id() {
            return Err(UseApprovalError::UntrustedGovernance);
        }
        consumption_policy::validate_timestamp(revoked_at)
            .map_err(|_| UseApprovalError::InvalidBounds)?;
        if consumption_policy::timestamp_cmp(&approval.issued_at, revoked_at)?
            == std::cmp::Ordering::Greater
        {
            return Err(UseApprovalError::InvalidBounds);
        }
        let mut object = Object::new();
        object.set("schema", consumption_policy::text(USE_APPROVAL_SCHEMA));
        object.set(
            "record_type",
            consumption_policy::text(USE_APPROVAL_REVOCATION_RECORD_TYPE),
        );
        object.set("record_kind", consumption_policy::text("immutable"));
        object.set(
            "tenant_id",
            consumption_policy::text(approval.tenant_id().as_str()),
        );
        object.set(
            "approval_digest",
            consumption_policy::text(&approval.digest().to_hex()),
        );
        object.set(
            "episode_digest",
            consumption_policy::text(&approval.episode_digest().to_hex()),
        );
        object.set("revoked_at", consumption_policy::text(revoked_at.as_str()));
        object.set(
            "governance_key_id",
            consumption_policy::text(&self.key_id().to_hex()),
        );
        let signature = self
            .signing_key()
            .sign(&Value::Object(object.clone()).canonical_bytes());
        object.set(
            "governance_signature",
            consumption_policy::text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        let envelope = Value::Object(object).canonical_bytes();
        Ok(UseApprovalRevocationPublication {
            object_key: use_approval_revocation_object_key(approval.tenant_id(), approval.digest()),
            envelope,
            approval_digest: *approval.digest(),
            tenant_id: approval.tenant_id().clone(),
        })
    }
}

/// Why use-approval administration or evaluation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UseApprovalError {
    /// Bytes were not the exact closed, canonical record shape.
    MalformedRecord,
    /// A record belongs to another tenant, or a revocation names an
    /// approval of another tenant.
    ScopeViolation,
    /// The governance signature failed.
    InvalidSignature,
    /// The signer is not the configured offline governance identity —
    /// including a key rotated out of the anchor, and an approval signed
    /// under a policy this identity did not sign.
    UntrustedGovernance,
    /// The record's bounded numeric, token, or timestamp relationships are
    /// invalid.
    InvalidBounds,
    /// The approval binds a policy version or freshness snapshot other
    /// than the current policy's.
    PolicyMismatch,
    /// The current policy does not map the approval's purpose to its
    /// consumer class.
    PurposeDenied,
    /// A signed clock instant lies beyond the operational uncertainty
    /// bound.
    ClockUncertain,
    /// The approval's expiry has passed.
    Expired,
    /// A verified revocation stands at the approval's revocation key.
    Revoked,
    /// The named approval is absent from the repository.
    MissingApproval,
    /// The repository could not complete an operation.
    RepositoryUnavailable,
    /// A different immutable object already occupies the derived key.
    IntegrityConflict,
}

impl UseApprovalError {
    /// A stable, content-free failure class.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::MalformedRecord => "malformed-record",
            Self::ScopeViolation => "scope-violation",
            Self::InvalidSignature => "invalid-signature",
            Self::UntrustedGovernance => "untrusted-governance",
            Self::InvalidBounds => "invalid-bounds",
            Self::PolicyMismatch => "policy-mismatch",
            Self::PurposeDenied => "purpose-denied",
            Self::ClockUncertain => "clock-uncertain",
            Self::Expired => "approval-expired",
            Self::Revoked => "approval-revoked",
            Self::MissingApproval => "missing-approval",
            Self::RepositoryUnavailable => "repository-unavailable",
            Self::IntegrityConflict => "integrity-conflict",
        }
    }
}

impl fmt::Display for UseApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for UseApprovalError {}

impl From<consumption_policy::ConsumptionPolicyError> for UseApprovalError {
    fn from(error: consumption_policy::ConsumptionPolicyError) -> Self {
        match error {
            consumption_policy::ConsumptionPolicyError::MalformedRecord
            | consumption_policy::ConsumptionPolicyError::UnsupportedPolicy
            | consumption_policy::ConsumptionPolicyError::Discontinuous
            | consumption_policy::ConsumptionPolicyError::Rollback
            | consumption_policy::ConsumptionPolicyError::MissingPolicy
            | consumption_policy::ConsumptionPolicyError::NotEffective => Self::MalformedRecord,
            consumption_policy::ConsumptionPolicyError::ScopeViolation => Self::ScopeViolation,
            consumption_policy::ConsumptionPolicyError::InvalidSignature => Self::InvalidSignature,
            consumption_policy::ConsumptionPolicyError::UntrustedGovernance => {
                Self::UntrustedGovernance
            }
            consumption_policy::ConsumptionPolicyError::InvalidBounds => Self::InvalidBounds,
            consumption_policy::ConsumptionPolicyError::ClockUncertain => Self::ClockUncertain,
            consumption_policy::ConsumptionPolicyError::RepositoryUnavailable => {
                Self::RepositoryUnavailable
            }
            consumption_policy::ConsumptionPolicyError::IntegrityConflict => {
                Self::IntegrityConflict
            }
        }
    }
}

/// An approval-only storage boundary for the offline governance identity.
pub trait UseApprovalRepository {
    /// Read a signed approval by its digest.
    fn read_approval(
        &self,
        digest: &BlobDigest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, UseApprovalError>> + Send;

    /// Read the revocation standing at an approval's digest, if any.
    fn read_revocation(
        &self,
        approval_digest: &BlobDigest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, UseApprovalError>> + Send;

    /// Put a digest-addressed approval, idempotently for equal bytes.
    fn put_approval(
        &mut self,
        publication: &UseApprovalPublication,
    ) -> impl Future<Output = Result<(), UseApprovalError>> + Send;

    /// Append a revocation at its approval's derived key, idempotently for
    /// equal bytes.
    fn put_revocation(
        &mut self,
        publication: &UseApprovalRevocationPublication,
    ) -> impl Future<Output = Result<(), UseApprovalError>> + Send;
}

/// An in-memory repository useful for offline tooling and deterministic
/// tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryUseApprovalRepository {
    approvals: std::collections::BTreeMap<BlobDigest, Vec<u8>>,
    revocations: std::collections::BTreeMap<BlobDigest, Vec<u8>>,
}

impl MemoryUseApprovalRepository {
    /// Create an empty approval repository.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            approvals: std::collections::BTreeMap::new(),
            revocations: std::collections::BTreeMap::new(),
        }
    }
}

impl UseApprovalRepository for MemoryUseApprovalRepository {
    async fn read_approval(
        &self,
        digest: &BlobDigest,
    ) -> Result<Option<Vec<u8>>, UseApprovalError> {
        Ok(self.approvals.get(digest).cloned())
    }

    async fn read_revocation(
        &self,
        approval_digest: &BlobDigest,
    ) -> Result<Option<Vec<u8>>, UseApprovalError> {
        Ok(self.revocations.get(approval_digest).cloned())
    }

    async fn put_approval(
        &mut self,
        publication: &UseApprovalPublication,
    ) -> Result<(), UseApprovalError> {
        match self.approvals.get(publication.digest()) {
            None => {
                self.approvals
                    .insert(*publication.digest(), publication.envelope.clone());
                Ok(())
            }
            Some(existing) if existing == publication.envelope() => Ok(()),
            Some(_) => Err(UseApprovalError::IntegrityConflict),
        }
    }

    async fn put_revocation(
        &mut self,
        publication: &UseApprovalRevocationPublication,
    ) -> Result<(), UseApprovalError> {
        match self.revocations.get(publication.approval_digest()) {
            None => {
                self.revocations
                    .insert(*publication.approval_digest(), publication.envelope.clone());
                Ok(())
            }
            Some(existing) if existing == publication.envelope() => Ok(()),
            Some(_) => Err(UseApprovalError::IntegrityConflict),
        }
    }
}

/// Store a signed approval at its digest address.
///
/// Issuance is the administrative act of signing; this is the store half,
/// and it re-verifies the bytes against the anchor so unverified material
/// never lands.
///
/// # Errors
///
/// Returns an approval error when verification fails or the derived key
/// is occupied by different bytes.
pub async fn issue_use_approval<R: UseApprovalRepository>(
    repository: &mut R,
    anchor: &GovernanceTrustAnchor,
    publication: &UseApprovalPublication,
) -> Result<(), UseApprovalError> {
    let approval = UseApproval::verify(anchor, publication.envelope())?;
    if approval.digest() != publication.digest()
        || approval.tenant_id() != publication.tenant_id()
        || publication.object_key()
            != use_approval_object_key(approval.tenant_id(), approval.digest())
    {
        return Err(UseApprovalError::MalformedRecord);
    }
    repository.put_approval(publication).await
}

/// Alias for [`issue_use_approval`] using the publication terminology shared
/// by the other immutable governance record families.
///
/// # Errors
/// Returns the same verification or immutable-write error as
/// [`issue_use_approval`].
pub async fn publish_use_approval<R: UseApprovalRepository>(
    repository: &mut R,
    anchor: &GovernanceTrustAnchor,
    publication: &UseApprovalPublication,
) -> Result<(), UseApprovalError> {
    issue_use_approval(repository, anchor, publication).await
}

/// Read and verify one stored approval.
///
/// # Errors
///
/// Returns [`UseApprovalError::MissingApproval`] when the digest is
/// absent, and a verification error for malformed or incorrectly signed
/// bytes.
pub async fn inspect_use_approval<R: UseApprovalRepository>(
    repository: &R,
    anchor: &GovernanceTrustAnchor,
    digest: &BlobDigest,
) -> Result<UseApproval, UseApprovalError> {
    let bytes = repository
        .read_approval(digest)
        .await?
        .ok_or(UseApprovalError::MissingApproval)?;
    let approval = UseApproval::verify(anchor, &bytes)?;
    if approval.digest() != digest {
        return Err(UseApprovalError::MalformedRecord);
    }
    Ok(approval)
}

/// Sign, cross-check, and append the revocation that ends an approval.
///
/// The approval must already be stored: revoking an approval the
/// repository never saw would let a revocation outlive its subject's
/// evidence.  `now` bounds the signed instant the same five-minute
/// operational allowance every governance record uses.
///
/// # Errors
///
/// Returns [`UseApprovalError::MissingApproval`] when the approval is not
/// stored, [`UseApprovalError::Revoked`] when a revocation already
/// stands, and a verification or storage error otherwise.
pub async fn revoke_use_approval<R: UseApprovalRepository>(
    repository: &mut R,
    anchor: &GovernanceTrustAnchor,
    identity: &OfflineGovernanceIdentity,
    approval_digest: &BlobDigest,
    now: &Timestamp,
) -> Result<UseApprovalRevocationPublication, UseApprovalError> {
    let approval = inspect_use_approval(repository, anchor, approval_digest).await?;
    if let Some(bytes) = repository.read_revocation(approval_digest).await? {
        let existing = UseApprovalRevocation::verify(anchor, &bytes)?;
        if existing.approval_digest() != approval.digest()
            || existing.episode_digest() != approval.episode_digest()
        {
            return Err(UseApprovalError::MalformedRecord);
        }
        return Err(UseApprovalError::Revoked);
    }
    consumption_policy::validate_timestamp(now).map_err(|_| UseApprovalError::InvalidBounds)?;
    if timestamp_is_beyond_clock_allowance(now, approval.issued_at())? {
        return Err(UseApprovalError::ClockUncertain);
    }
    let publication = identity.sign_use_approval_revocation(anchor, &approval, now)?;
    if publication.approval_digest() != approval.digest()
        || publication.tenant_id() != approval.tenant_id()
        || publication.object_key()
            != use_approval_revocation_object_key(approval.tenant_id(), approval.digest())
    {
        return Err(UseApprovalError::MalformedRecord);
    }
    repository.put_revocation(&publication).await?;
    Ok(publication)
}

/// An approval that passed every evaluation check at the current policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedUseApproval {
    approval: UseApproval,
}

impl EvaluatedUseApproval {
    /// The verified approval.
    #[must_use]
    pub const fn approval(&self) -> &UseApproval {
        &self.approval
    }
}

/// The fail-closed authorization read a derived-content consumer performs
/// before returning derived bytes.
///
/// The checks run in a fixed order, and the order is the semantics: the
/// evidence gate (signature and closed shape) first, then the scope and
/// current-policy bindings, then the purpose mapping, then the clock,
/// then the revocation — the durable evidence, which outranks every
/// derived condition — and only then expiry.  A revoked approval reads as
/// [`UseApprovalError::Revoked`] even when it is also expired, and no
/// path downgrades a denial to a weaker class.
///
/// # Errors
///
/// Returns the denial class for the first failed check; see
/// [`UseApprovalError`].
pub async fn evaluate_use_approval<R: UseApprovalRepository>(
    repository: &R,
    anchor: &GovernanceTrustAnchor,
    policy: &ConsumptionPolicy,
    approval_digest: &BlobDigest,
    now: &Timestamp,
) -> Result<EvaluatedUseApproval, UseApprovalError> {
    if policy.tenant_id() != anchor.tenant_id() {
        return Err(UseApprovalError::ScopeViolation);
    }
    let approval = inspect_use_approval(repository, anchor, approval_digest).await?;
    if approval.policy_version() != policy.policy_version()
        || approval.freshness().not_before != *policy.assessment_not_before()
        || approval.freshness().max_age_seconds != policy.max_assessment_age_seconds()
    {
        return Err(UseApprovalError::PolicyMismatch);
    }
    let granted = policy
        .purpose_to_consumer_classes()
        .get(approval.purpose())
        .is_some_and(|classes| classes.contains(approval.consumer_class()));
    if !granted {
        return Err(UseApprovalError::PurposeDenied);
    }
    consumption_policy::validate_timestamp(now).map_err(|_| UseApprovalError::MalformedRecord)?;
    for instant in [
        approval.issued_at(),
        &approval.freshness().evaluated_at,
        &approval.freshness().not_before,
    ] {
        if timestamp_is_beyond_clock_allowance(now, instant)? {
            return Err(UseApprovalError::ClockUncertain);
        }
    }
    if let Some(bytes) = repository.read_revocation(approval_digest).await? {
        let revocation = UseApprovalRevocation::verify(anchor, &bytes)?;
        if revocation.approval_digest() != approval.digest()
            || revocation.episode_digest() != approval.episode_digest()
        {
            return Err(UseApprovalError::MalformedRecord);
        }
        return Err(UseApprovalError::Revoked);
    }
    if timestamp_nanos(&approval.expires_at)? <= timestamp_nanos(now)? {
        return Err(UseApprovalError::Expired);
    }
    Ok(EvaluatedUseApproval { approval })
}

/// Derive the immutable approval object key.
#[must_use]
pub fn use_approval_object_key(tenant: &TenantId, digest: &BlobDigest) -> String {
    format!(
        "tenants/{}/v1/control/use-approvals/{}.json",
        tenant.as_str(),
        digest.to_hex()
    )
}

/// Derive the append-only revocation object key.
#[must_use]
pub fn use_approval_revocation_object_key(tenant: &TenantId, digest: &BlobDigest) -> String {
    format!(
        "tenants/{}/v1/control/use-approval-revocations/{}.json",
        tenant.as_str(),
        digest.to_hex()
    )
}

const APPROVAL_MEMBERS: [&str; 15] = [
    "approver",
    "assessment_digest",
    "assessment_freshness",
    "consumer_class",
    "episode_digest",
    "expires_at",
    "governance_key_id",
    "governance_signature",
    "issued_at",
    "policy_version",
    "purpose",
    "record_kind",
    "record_type",
    "schema",
    "tenant_id",
];

const REVOCATION_MEMBERS: [&str; 9] = [
    "approval_digest",
    "episode_digest",
    "governance_key_id",
    "governance_signature",
    "record_kind",
    "record_type",
    "revoked_at",
    "schema",
    "tenant_id",
];

const FRESHNESS_MEMBERS: [&str; 3] = ["evaluated_at", "max_age_seconds", "not_before"];

fn approval_object(
    spec: &UseApprovalSpec,
    freshness: &AssessmentFreshness,
    policy_version: u64,
    key_id: &KeyId,
) -> Object {
    let mut object = Object::new();
    object.set("schema", consumption_policy::text(USE_APPROVAL_SCHEMA));
    object.set(
        "record_type",
        consumption_policy::text(USE_APPROVAL_RECORD_TYPE),
    );
    object.set("record_kind", consumption_policy::text("immutable"));
    object.set(
        "tenant_id",
        consumption_policy::text(spec.tenant_id.as_str()),
    );
    object.set(
        "episode_digest",
        consumption_policy::text(&spec.episode_digest.to_hex()),
    );
    object.set(
        "assessment_digest",
        consumption_policy::text(&spec.assessment_digest.to_hex()),
    );
    object.set("purpose", consumption_policy::text(&spec.purpose));
    object.set(
        "consumer_class",
        consumption_policy::text(&spec.consumer_class),
    );
    object.set(
        "policy_version",
        consumption_policy::signed_integer(policy_version),
    );
    object.set("approver", consumption_policy::text(&spec.approver));
    object.set(
        "issued_at",
        consumption_policy::text(spec.issued_at.as_str()),
    );
    object.set(
        "expires_at",
        consumption_policy::text(spec.expires_at.as_str()),
    );
    let mut freshness_object = Object::new();
    freshness_object.set(
        "evaluated_at",
        consumption_policy::text(freshness.evaluated_at.as_str()),
    );
    freshness_object.set(
        "not_before",
        consumption_policy::text(freshness.not_before.as_str()),
    );
    freshness_object.set(
        "max_age_seconds",
        consumption_policy::signed_integer(freshness.max_age_seconds),
    );
    object.set("assessment_freshness", Value::Object(freshness_object));
    object.set(
        "governance_key_id",
        consumption_policy::text(&key_id.to_hex()),
    );
    object
}

fn parse_freshness(object: &Object) -> Result<AssessmentFreshness, UseApprovalError> {
    let Some(Value::Object(freshness)) = object.get("assessment_freshness") else {
        return Err(UseApprovalError::MalformedRecord);
    };
    if freshness.len() != FRESHNESS_MEMBERS.len()
        || FRESHNESS_MEMBERS
            .iter()
            .any(|member| !freshness.contains(member))
    {
        return Err(UseApprovalError::MalformedRecord);
    }
    let evaluated_at = consumption_policy::parse_timestamp(freshness, "evaluated_at")?;
    let not_before = consumption_policy::parse_timestamp(freshness, "not_before")?;
    let max_age_seconds = consumption_policy::positive_number(freshness, "max_age_seconds")?;
    Ok(AssessmentFreshness {
        evaluated_at,
        not_before,
        max_age_seconds,
    })
}

fn required_token(object: &Object, name: &str) -> Result<String, UseApprovalError> {
    let value = consumption_policy::required_text(object, name)?;
    if consumption_policy::token(value) {
        Ok(value.to_owned())
    } else {
        Err(UseApprovalError::MalformedRecord)
    }
}

fn approval_lifetime_nanos(
    issued_at: &Timestamp,
    expires_at: &Timestamp,
) -> Result<i128, UseApprovalError> {
    Ok(timestamp_nanos(expires_at)? - timestamp_nanos(issued_at)?)
}

fn timestamp_nanos(timestamp: &Timestamp) -> Result<i128, UseApprovalError> {
    let (seconds, nanos) = consumption_policy::timestamp_value(timestamp)?;
    Ok(i128::from(seconds) * 1_000_000_000 + i128::from(nanos))
}

fn timestamp_is_beyond_clock_allowance(
    now: &Timestamp,
    instant: &Timestamp,
) -> Result<bool, UseApprovalError> {
    Ok(timestamp_nanos(instant)?
        > timestamp_nanos(now)? + i128::from(CLOCK_SKEW_ALLOWANCE_SECONDS) * 1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consumption_policy::{
        ConsumptionPolicyError, ConsumptionPolicySpec, DEFAULT_MAX_ASSESSMENT_AGE_SECONDS,
        MemoryPolicyRepository, PolicyRepository, SUPPORTED_CLASSIFIER_KIND, advance_policy,
        publish_policy,
    };
    use std::task::Poll;

    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const OTHER_TENANT: &str = "2a3b4c5d-6e7f-4a1b-9c2d-3e4f5a6b7c8d";
    const ISSUE: &str = "2026-09-20T00:00:00Z";
    const EXPIRY: &str = "2026-09-20T01:00:00Z";
    const AFTER_EXPIRY: &str = "2026-09-20T01:00:01Z";
    const RULE_SET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const EPISODE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const ASSESSMENT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn tenant() -> TenantId {
        TENANT.parse().unwrap()
    }

    fn other_tenant() -> TenantId {
        OTHER_TENANT.parse().unwrap()
    }

    fn digest(hex: &str) -> BlobDigest {
        hex.parse().unwrap()
    }

    fn policy_spec(version: u64, predecessor: Option<BlobDigest>) -> ConsumptionPolicySpec {
        ConsumptionPolicySpec {
            tenant_id: tenant(),
            policy_version: version,
            issued_at: ISSUE.parse().unwrap(),
            effective_at: ISSUE.parse().unwrap(),
            allowed_classifier_kinds: vec![SUPPORTED_CLASSIFIER_KIND.to_owned()],
            allowed_rule_set_digests: vec![digest(RULE_SET)],
            assessment_not_before: ISSUE.parse().unwrap(),
            max_assessment_age_seconds: DEFAULT_MAX_ASSESSMENT_AGE_SECONDS,
            purpose_to_consumer_classes: std::collections::BTreeMap::from([(
                "agent-use".to_owned(),
                vec!["agent".to_owned()],
            )]),
            max_approval_lifetime_seconds: 3600,
            predecessor_digest: predecessor,
        }
    }

    fn approval_spec() -> UseApprovalSpec {
        UseApprovalSpec {
            tenant_id: tenant(),
            episode_digest: digest(EPISODE),
            assessment_digest: digest(ASSESSMENT),
            purpose: "agent-use".to_owned(),
            consumer_class: "agent".to_owned(),
            approver: "operator.primary".to_owned(),
            issued_at: ISSUE.parse().unwrap(),
            expires_at: EXPIRY.parse().unwrap(),
        }
    }

    fn governance_identity() -> OfflineGovernanceIdentity {
        OfflineGovernanceIdentity::from_seed([7; 32])
    }

    /// Publish and make current the genesis policy for `identity`, and
    /// return the verified policy.
    fn current_policy(
        identity: &OfflineGovernanceIdentity,
        repository: &mut MemoryPolicyRepository,
    ) -> ConsumptionPolicy {
        let publication = identity.sign_policy(&policy_spec(1, None)).unwrap();
        block_on(publish_policy(
            repository,
            &identity.trust_anchor(tenant()),
            &publication,
        ))
        .unwrap();
        block_on(advance_policy(
            repository,
            identity,
            &publication,
            &ISSUE.parse().unwrap(),
        ))
        .unwrap();
        ConsumptionPolicy::verify(&identity.trust_anchor(tenant()), publication.envelope()).unwrap()
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
        }
    }

    #[test]
    fn approval_binds_every_acceptance_field() {
        let identity = governance_identity();
        let mut policies = MemoryPolicyRepository::new();
        let policy = current_policy(&identity, &mut policies);
        let publication = identity
            .sign_use_approval(&approval_spec(), &policy)
            .unwrap();
        let mut approvals = MemoryUseApprovalRepository::new();
        block_on(issue_use_approval(
            &mut approvals,
            &identity.trust_anchor(tenant()),
            &publication,
        ))
        .unwrap();
        let approval = block_on(inspect_use_approval(
            &approvals,
            &identity.trust_anchor(tenant()),
            publication.digest(),
        ))
        .unwrap();
        assert_eq!(approval.tenant_id(), &tenant());
        assert_eq!(approval.episode_digest(), &digest(EPISODE));
        assert_eq!(approval.assessment_digest(), &digest(ASSESSMENT));
        assert_eq!(approval.purpose(), "agent-use");
        assert_eq!(approval.consumer_class(), "agent");
        assert_eq!(approval.policy_version(), policy.policy_version());
        assert_eq!(approval.approver(), "operator.primary");
        assert_eq!(approval.issued_at(), policy.issued_at());
        assert_eq!(approval.expires_at(), &EXPIRY.parse::<Timestamp>().unwrap());
        assert_eq!(
            approval.freshness().not_before,
            *policy.assessment_not_before()
        );
        assert_eq!(
            approval.freshness().max_age_seconds,
            policy.max_assessment_age_seconds()
        );
        assert_eq!(approval.freshness().evaluated_at, *approval.issued_at());
        assert_eq!(
            publication.object_key(),
            use_approval_object_key(&tenant(), publication.digest())
        );
    }

    #[test]
    fn issuance_under_the_current_policy_evaluates() {
        let identity = governance_identity();
        let mut policies = MemoryPolicyRepository::new();
        let policy = current_policy(&identity, &mut policies);
        let publication = identity
            .sign_use_approval(&approval_spec(), &policy)
            .unwrap();
        let mut approvals = MemoryUseApprovalRepository::new();
        block_on(issue_use_approval(
            &mut approvals,
            &identity.trust_anchor(tenant()),
            &publication,
        ))
        .unwrap();
        let evaluated = block_on(evaluate_use_approval(
            &approvals,
            &identity.trust_anchor(tenant()),
            &policy,
            publication.digest(),
            &ISSUE.parse().unwrap(),
        ))
        .unwrap();
        assert_eq!(evaluated.approval().digest(), publication.digest());
    }

    #[test]
    fn purpose_outside_the_policy_mapping_is_denied() {
        let identity = governance_identity();
        let mut policies = MemoryPolicyRepository::new();
        let policy = current_policy(&identity, &mut policies);
        let mut unmapped = approval_spec();
        unmapped.purpose = "raw-export".to_owned();
        assert_eq!(
            identity.sign_use_approval(&unmapped, &policy),
            Err(UseApprovalError::PurposeDenied)
        );
        let mut unlisted_class = approval_spec();
        unlisted_class.consumer_class = "operator".to_owned();
        assert_eq!(
            identity.sign_use_approval(&unlisted_class, &policy),
            Err(UseApprovalError::PurposeDenied)
        );
    }

    #[test]
    fn a_policy_without_consumers_denies_every_purpose() {
        let identity = governance_identity();
        let mut default_spec = policy_spec(1, None);
        default_spec.purpose_to_consumer_classes = std::collections::BTreeMap::new();
        let publication = identity.sign_policy(&default_spec).unwrap();
        let policy =
            ConsumptionPolicy::verify(&identity.trust_anchor(tenant()), publication.envelope())
                .unwrap();
        assert_eq!(
            identity.sign_use_approval(&approval_spec(), &policy),
            Err(UseApprovalError::PurposeDenied)
        );
    }

    #[test]
    fn lifetime_beyond_the_policy_maximum_is_rejected() {
        let identity = governance_identity();
        let mut policies = MemoryPolicyRepository::new();
        let policy = current_policy(&identity, &mut policies);
        let mut long = approval_spec();
        long.expires_at = "2026-09-20T01:00:01Z".parse().unwrap();
        assert_eq!(
            identity.sign_use_approval(&long, &policy),
            Err(UseApprovalError::InvalidBounds)
        );
        let mut backwards = approval_spec();
        backwards.expires_at = ISSUE.parse().unwrap();
        assert_eq!(
            identity.sign_use_approval(&backwards, &policy),
            Err(UseApprovalError::InvalidBounds)
        );
    }

    #[test]
    fn expired_approval_fails_closed() {
        let identity = governance_identity();
        let mut policies = MemoryPolicyRepository::new();
        let policy = current_policy(&identity, &mut policies);
        let publication = identity
            .sign_use_approval(&approval_spec(), &policy)
            .unwrap();
        let approvals = MemoryUseApprovalRepository::new();
        assert_eq!(
            block_on(evaluate_use_approval(
                &approvals,
                &identity.trust_anchor(tenant()),
                &policy,
                publication.digest(),
                &AFTER_EXPIRY.parse().unwrap(),
            )),
            Err(UseApprovalError::MissingApproval)
        );
        let mut approvals = MemoryUseApprovalRepository::new();
        block_on(issue_use_approval(
            &mut approvals,
            &identity.trust_anchor(tenant()),
            &publication,
        ))
        .unwrap();
        assert_eq!(
            block_on(evaluate_use_approval(
                &approvals,
                &identity.trust_anchor(tenant()),
                &policy,
                publication.digest(),
                &AFTER_EXPIRY.parse().unwrap(),
            )),
            Err(UseApprovalError::Expired)
        );
    }

    #[test]
    fn a_policy_change_denies_approvals_issued_under_the_old_one() {
        let identity = governance_identity();
        let mut policies = MemoryPolicyRepository::new();
        let first = current_policy(&identity, &mut policies);
        let publication = identity
            .sign_use_approval(&approval_spec(), &first)
            .unwrap();
        let mut approvals = MemoryUseApprovalRepository::new();
        block_on(issue_use_approval(
            &mut approvals,
            &identity.trust_anchor(tenant()),
            &publication,
        ))
        .unwrap();
        // A second policy with tightened freshness bounds, chained to the
        // first.
        let mut second_spec = policy_spec(2, Some(*first.digest()));
        second_spec.max_assessment_age_seconds = 3600;
        let second_publication = identity.sign_policy(&second_spec).unwrap();
        block_on(publish_policy(
            &mut policies,
            &identity.trust_anchor(tenant()),
            &second_publication,
        ))
        .unwrap();
        let second = block_on(advance_policy(
            &mut policies,
            &identity,
            &second_publication,
            &ISSUE.parse().unwrap(),
        ))
        .unwrap();
        let current = ConsumptionPolicy::verify(
            &identity.trust_anchor(tenant()),
            &block_on(policies.read_policy(second.policy_digest()))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            block_on(evaluate_use_approval(
                &approvals,
                &identity.trust_anchor(tenant()),
                &current,
                publication.digest(),
                &ISSUE.parse().unwrap(),
            )),
            Err(UseApprovalError::PolicyMismatch)
        );
        // Re-issued under the new policy, the same grant evaluates again.
        let reissued = identity
            .sign_use_approval(&approval_spec(), &current)
            .unwrap();
        block_on(issue_use_approval(
            &mut approvals,
            &identity.trust_anchor(tenant()),
            &reissued,
        ))
        .unwrap();
        block_on(evaluate_use_approval(
            &approvals,
            &identity.trust_anchor(tenant()),
            &current,
            reissued.digest(),
            &ISSUE.parse().unwrap(),
        ))
        .unwrap();
    }

    #[test]
    fn governance_key_rotation_requires_reissue() {
        let old_identity = governance_identity();
        let mut policies = MemoryPolicyRepository::new();
        let first = current_policy(&old_identity, &mut policies);
        let old_approval = old_identity
            .sign_use_approval(&approval_spec(), &first)
            .unwrap();
        let mut approvals = MemoryUseApprovalRepository::new();
        block_on(issue_use_approval(
            &mut approvals,
            &old_identity.trust_anchor(tenant()),
            &old_approval,
        ))
        .unwrap();
        // The rotated governance key publishes the next policy; readers
        // pin the new anchor from then on.  The current pointer the old
        // key advanced will not follow: a pointer chain is
        // key-contiguous, so the new identity cannot advance it and must
        // publish a fresh repository lineage.
        let new_identity = OfflineGovernanceIdentity::from_seed([11; 32]);
        let mut second_spec = policy_spec(2, Some(*first.digest()));
        second_spec.max_assessment_age_seconds = 3600;
        let second_publication = new_identity.sign_policy(&second_spec).unwrap();
        block_on(publish_policy(
            &mut policies,
            &new_identity.trust_anchor(tenant()),
            &second_publication,
        ))
        .unwrap();
        assert_eq!(
            block_on(advance_policy(
                &mut policies,
                &new_identity,
                &second_publication,
                &ISSUE.parse().unwrap(),
            ))
            .map(|_| ()),
            Err(ConsumptionPolicyError::UntrustedGovernance)
        );
        let current = ConsumptionPolicy::verify(
            &new_identity.trust_anchor(tenant()),
            second_publication.envelope(),
        )
        .unwrap();
        // The old key may not issue under a policy it did not sign, and
        // its outstanding approval fails closed against the new anchor.
        assert_eq!(
            old_identity.sign_use_approval(&approval_spec(), &current),
            Err(UseApprovalError::UntrustedGovernance)
        );
        assert_eq!(
            block_on(evaluate_use_approval(
                &approvals,
                &new_identity.trust_anchor(tenant()),
                &current,
                old_approval.digest(),
                &ISSUE.parse().unwrap(),
            )),
            Err(UseApprovalError::UntrustedGovernance)
        );
        // Re-issued under the rotated key, the grant evaluates.
        let reissued = new_identity
            .sign_use_approval(&approval_spec(), &current)
            .unwrap();
        block_on(issue_use_approval(
            &mut approvals,
            &new_identity.trust_anchor(tenant()),
            &reissued,
        ))
        .unwrap();
        block_on(evaluate_use_approval(
            &approvals,
            &new_identity.trust_anchor(tenant()),
            &current,
            reissued.digest(),
            &ISSUE.parse().unwrap(),
        ))
        .unwrap();
    }

    #[test]
    fn revocation_is_append_only_and_ends_use() {
        let identity = governance_identity();
        let mut policies = MemoryPolicyRepository::new();
        let policy = current_policy(&identity, &mut policies);
        let publication = identity
            .sign_use_approval(&approval_spec(), &policy)
            .unwrap();
        let mut approvals = MemoryUseApprovalRepository::new();
        block_on(issue_use_approval(
            &mut approvals,
            &identity.trust_anchor(tenant()),
            &publication,
        ))
        .unwrap();
        // Revoking an approval the repository never saw is refused.
        assert_eq!(
            block_on(revoke_use_approval(
                &mut approvals,
                &identity.trust_anchor(tenant()),
                &identity,
                &digest(ASSESSMENT),
                &ISSUE.parse().unwrap(),
            )),
            Err(UseApprovalError::MissingApproval)
        );
        let revocation = block_on(revoke_use_approval(
            &mut approvals,
            &identity.trust_anchor(tenant()),
            &identity,
            publication.digest(),
            &ISSUE.parse().unwrap(),
        ))
        .unwrap();
        assert_eq!(
            revocation.object_key(),
            use_approval_revocation_object_key(&tenant(), publication.digest())
        );
        assert_eq!(
            block_on(evaluate_use_approval(
                &approvals,
                &identity.trust_anchor(tenant()),
                &policy,
                publication.digest(),
                &ISSUE.parse().unwrap(),
            )),
            Err(UseApprovalError::Revoked)
        );
        // The byte-identical retry is an idempotent repair; different
        // bytes at the derived key are an integrity conflict. Nothing
        // removes or supersedes the standing revocation.
        assert_eq!(
            block_on(revoke_use_approval(
                &mut approvals,
                &identity.trust_anchor(tenant()),
                &identity,
                publication.digest(),
                &ISSUE.parse().unwrap(),
            )),
            Err(UseApprovalError::Revoked)
        );
        let standing = block_on(approvals.read_revocation(publication.digest()))
            .unwrap()
            .unwrap();
        // Signing the same revocation again deterministically reproduces
        // the standing bytes, so a retrying administrator repairs instead
        // of forked-revoking.
        let stored = block_on(inspect_use_approval(
            &approvals,
            &identity.trust_anchor(tenant()),
            publication.digest(),
        ))
        .unwrap();
        let replayed = identity
            .sign_use_approval_revocation(
                &identity.trust_anchor(tenant()),
                &stored,
                &ISSUE.parse().unwrap(),
            )
            .unwrap();
        assert_eq!(replayed.envelope(), standing.as_slice());
        block_on(approvals.put_revocation(&replayed)).unwrap();
        // A revocation signed at a different instant is different bytes at
        // the same derived key, and the append-only boundary refuses them
        // outright.
        let conflicting = identity
            .sign_use_approval_revocation(
                &identity.trust_anchor(tenant()),
                &stored,
                &EXPIRY.parse().unwrap(),
            )
            .unwrap();
        assert_eq!(conflicting.object_key(), revocation.object_key());
        assert_ne!(conflicting.envelope(), standing.as_slice());
        assert_eq!(
            block_on(approvals.put_revocation(&conflicting)),
            Err(UseApprovalError::IntegrityConflict)
        );
        assert_eq!(
            block_on(approvals.read_revocation(publication.digest()))
                .unwrap()
                .unwrap(),
            standing
        );
    }

    #[test]
    fn tampered_or_foreign_records_fail_closed() {
        let identity = governance_identity();
        let other = OfflineGovernanceIdentity::from_seed([13; 32]);
        let mut policies = MemoryPolicyRepository::new();
        let policy = current_policy(&identity, &mut policies);
        let publication = identity
            .sign_use_approval(&approval_spec(), &policy)
            .unwrap();
        // A different tenant's anchor refuses the record outright.
        assert_eq!(
            UseApproval::verify(&other.trust_anchor(other_tenant()), publication.envelope()),
            Err(UseApprovalError::ScopeViolation)
        );
        // A value flip breaks the signature; a shape change breaks the
        // closed parse.
        let mut flipped = publication.envelope().to_vec();
        let marker = b"\"governance_signature\":\"";
        let signature_start = flipped
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap()
            + marker.len();
        flipped[signature_start] = if flipped[signature_start] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert_eq!(
            UseApproval::verify(&identity.trust_anchor(tenant()), &flipped),
            Err(UseApprovalError::InvalidSignature)
        );
        let mut truncated = publication.envelope().to_vec();
        truncated.pop();
        assert_eq!(
            UseApproval::verify(&identity.trust_anchor(tenant()), &truncated),
            Err(UseApprovalError::MalformedRecord)
        );
    }

    #[test]
    fn the_governance_seed_enters_only_through_a_protected_reference() {
        let dir = tempfile_under_target();
        let reference_path = dir.join("governance-seed");
        std::fs::write(&reference_path, [42u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&reference_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let reference =
            ProtectedReference::parse(&format!("file:{}", reference_path.display())).unwrap();
        let discovered = OfflineGovernanceIdentity::from_protected_reference(&reference).unwrap();
        assert_eq!(
            discovered.key_id(),
            OfflineGovernanceIdentity::from_seed([42; 32]).key_id()
        );
        // The identity renders redacted and never carries the seed.
        assert!(!format!("{discovered:?}").contains("2a"));
        // A short target is refused, and a missing one too.
        std::fs::write(&reference_path, [42u8; 31]).unwrap();
        assert!(matches!(
            OfflineGovernanceIdentity::from_protected_reference(&reference),
            Err(IdentityError::IdentityCorrupt)
        ));
        let absent = ProtectedReference::parse("env:GOVERNANCE_SEED_ABSENT").unwrap();
        assert!(matches!(
            OfflineGovernanceIdentity::from_protected_reference(&absent),
            Err(IdentityError::ReferenceMissing)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A unique scratch directory for reference fixtures.
    fn tempfile_under_target() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "archivist-use-approval-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
