// SPDX-License-Identifier: Apache-2.0

//! Offline administration and verification of `consumption-policy-v1`.
//!
//! A policy is governance evidence, not an authorization decision.  The
//! governance identity signs an immutable policy object and then signs a
//! separate current pointer.  Policy objects are addressed by the digest of
//! their complete signed bytes; the pointer is the only mutable object and
//! can advance one policy version at a time.  This separation means a
//! rollback is another signed policy, never a rewrite of history.
//!
//! The module deliberately owns a policy-only repository boundary.  The
//! offline administrator can publish and inspect policy objects through this
//! boundary, but it has no operation for raw, catalog, derived, or arbitrary
//! object data.  A production adapter can implement [`PolicyRepository`] over
//! the dedicated governance credential without widening that authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;

use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{
    BlobDigest, Ed25519PublicKey, Ed25519Signature, KeyId, TenantId, Timestamp,
};

use crate::ed25519;
use crate::error::IdentityError;
use crate::identity::SigningKey;

/// The namespace of the governance policy family.
pub const POLICY_SCHEMA: &str = "archivist.governance/v1";
/// The immutable policy record type.
pub const POLICY_RECORD_TYPE: &str = "consumption-policy";
/// The signed current-pointer record type.
pub const POLICY_POINTER_RECORD_TYPE: &str = "consumption-policy-pointer";
/// The only policy schema version understood by this module.
pub const POLICY_FORMAT_VERSION: u64 = 1;
/// Default maximum age of a risk assessment: 24 hours.
pub const DEFAULT_MAX_ASSESSMENT_AGE_SECONDS: u64 = 24 * 60 * 60;
/// The absolute freshness ceiling: policy may not permit older assessments.
pub const MAX_ASSESSMENT_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;
/// The maximum lifetime an approval policy may grant: 24 hours.
pub const MAX_APPROVAL_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
/// The operational clock uncertainty allowance from the governance plan.
pub const CLOCK_SKEW_ALLOWANCE_SECONDS: i64 = 5 * 60;
/// The initial supported deterministic classifier kind.
pub const SUPPORTED_CLASSIFIER_KIND: &str = "rules-v1";

const POLICY_MAX_VERSION: u64 = 999_999_999_999_999_999;
const POLICY_MAX_VERSION_I64: i64 = 999_999_999_999_999_999;
const MAX_ALLOWLIST_ITEMS: usize = 64;

/// A policy definition supplied by the offline administrator before signing.
///
/// All fields are copied into the signed record.  The constructor is kept
/// intentionally small; [`OfflineGovernanceIdentity::sign_policy`] performs
/// the complete cross-field validation and canonicalizes array ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumptionPolicySpec {
    /// The tenant governed by this policy.
    pub tenant_id: TenantId,
    /// The strictly increasing policy sequence number.
    pub policy_version: u64,
    /// When the governance identity issued the policy.
    pub issued_at: Timestamp,
    /// When the policy becomes effective.
    pub effective_at: Timestamp,
    /// Classifier kinds permitted to produce usable assessments.
    pub allowed_classifier_kinds: Vec<String>,
    /// Rule-set artifact digests permitted to produce usable assessments.
    pub allowed_rule_set_digests: Vec<BlobDigest>,
    /// Assessments before this instant are not usable under this policy.
    pub assessment_not_before: Timestamp,
    /// Maximum permitted assessment age at authorization time.
    pub max_assessment_age_seconds: u64,
    /// Purpose to allowed consumer-class mappings.
    pub purpose_to_consumer_classes: BTreeMap<String, Vec<String>>,
    /// Maximum lifetime of a use approval under this policy.
    pub max_approval_lifetime_seconds: u64,
    /// Digest of the immediately preceding signed policy, or `None` for v1.
    pub predecessor_digest: Option<BlobDigest>,
}

/// A public governance trust anchor used by readers to verify policy bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceTrustAnchor {
    tenant_id: TenantId,
    public_key: Ed25519PublicKey,
    key_id: KeyId,
}

impl GovernanceTrustAnchor {
    /// Construct an anchor from a tenant and its governance public key.
    #[must_use]
    pub fn new(tenant_id: TenantId, public_key: Ed25519PublicKey) -> Self {
        Self {
            tenant_id,
            key_id: KeyId::from_public_key(&public_key),
            public_key,
        }
    }

    /// The governed tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The public governance key.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// The derived governance key ID.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }
}

/// The offline tenant governance identity.
pub struct OfflineGovernanceIdentity {
    signing_key: SigningKey,
}

/// Short name for [`OfflineGovernanceIdentity`].
pub type GovernanceIdentity = OfflineGovernanceIdentity;

/// Short name for the unsigned policy definition.
pub type ConsumptionPolicyDefinition = ConsumptionPolicySpec;

/// Short name for an immutable policy publication.
pub type ConsumptionPolicyPublication = PolicyPublication;

/// Short name for the verified current pointer.
pub type ConsumptionPolicyPointer = CurrentPolicyPointer;

impl fmt::Debug for OfflineGovernanceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OfflineGovernanceIdentity(<redacted>)")
    }
}

impl OfflineGovernanceIdentity {
    /// Generate a governance identity from the operating system entropy
    /// source.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] when the operating system entropy source is
    /// unavailable.
    pub fn generate() -> Result<Self, IdentityError> {
        Ok(Self {
            signing_key: SigningKey::generate()?,
        })
    }

    /// Adopt a seed already held by the offline administrator.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_seed(seed),
        }
    }

    /// Borrow the signing key for an explicit offline signing operation.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Derive the public governance anchor for `tenant`.
    #[must_use]
    pub fn trust_anchor(&self, tenant: TenantId) -> GovernanceTrustAnchor {
        GovernanceTrustAnchor::new(
            tenant,
            Ed25519PublicKey::from_raw(self.signing_key.public_key()),
        )
    }

    /// The governance key ID that signed publications carry.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        KeyId::from_public_key(&Ed25519PublicKey::from_raw(self.signing_key.public_key()))
    }

    /// Validate, canonicalize, sign, and address one immutable policy.
    ///
    /// # Errors
    ///
    /// Returns a policy error when the definition has invalid bounds or
    /// timestamps.
    pub fn sign_policy(
        &self,
        spec: &ConsumptionPolicySpec,
    ) -> Result<PolicyPublication, ConsumptionPolicyError> {
        validate_spec(spec)?;
        let mut object = policy_object(spec, &self.key_id());
        let signature = self
            .signing_key
            .sign(&Value::Object(object.clone()).canonical_bytes());
        object.set(
            "governance_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        let envelope = Value::Object(object).canonical_bytes();
        let digest = BlobDigest::from_raw(sha256::digest(&envelope));
        Ok(PolicyPublication {
            object_key: policy_object_key(&spec.tenant_id, &digest),
            envelope,
            digest,
            tenant_id: spec.tenant_id.clone(),
            policy_version: spec.policy_version,
            effective_at: spec.effective_at.clone(),
        })
    }

    /// Define and sign a policy in one explicit offline operation.
    ///
    /// # Errors
    ///
    /// Returns a policy error when the definition has invalid bounds or
    /// timestamps.
    pub fn define_policy(
        &self,
        spec: &ConsumptionPolicySpec,
    ) -> Result<PolicyPublication, ConsumptionPolicyError> {
        self.sign_policy(spec)
    }

    /// Sign a current pointer for an already signed policy.
    ///
    /// # Errors
    ///
    /// Returns a policy error when the publication is malformed or is not
    /// signed by this identity.
    pub fn sign_pointer(
        &self,
        publication: &PolicyPublication,
    ) -> Result<PointerPublication, ConsumptionPolicyError> {
        let policy = ConsumptionPolicy::verify(
            &self.trust_anchor(publication.tenant_id.clone()),
            publication.envelope(),
        )?;
        if policy.digest() != publication.digest()
            || policy.policy_version() != publication.policy_version()
        {
            return Err(ConsumptionPolicyError::MalformedRecord);
        }
        let mut object = pointer_object(
            &publication.tenant_id,
            publication.policy_version,
            &publication.digest,
            policy.effective_at(),
            &self.key_id(),
        );
        let signature = self
            .signing_key
            .sign(&Value::Object(object.clone()).canonical_bytes());
        object.set(
            "governance_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        Ok(PointerPublication {
            object_key: current_pointer_object_key(&publication.tenant_id),
            envelope: Value::Object(object).canonical_bytes(),
            tenant_id: publication.tenant_id.clone(),
            policy_version: publication.policy_version,
            policy_digest: publication.digest,
        })
    }
}

/// A signed immutable policy ready for storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyPublication {
    object_key: String,
    envelope: Vec<u8>,
    digest: BlobDigest,
    tenant_id: TenantId,
    policy_version: u64,
    effective_at: Timestamp,
}

impl PolicyPublication {
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

    /// The digest used by the pointer and object key.
    #[must_use]
    pub const fn digest(&self) -> &BlobDigest {
        &self.digest
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The policy sequence number.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// The policy effective instant.
    #[must_use]
    pub const fn effective_at(&self) -> &Timestamp {
        &self.effective_at
    }
}

/// A signed current-pointer publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PointerPublication {
    object_key: String,
    envelope: Vec<u8>,
    tenant_id: TenantId,
    policy_version: u64,
    policy_digest: BlobDigest,
}

impl PointerPublication {
    /// The fixed `current.json` object key.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    /// The complete canonical signed pointer.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The pointer's monotonic policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// The policy digest the pointer names.
    #[must_use]
    pub const fn policy_digest(&self) -> &BlobDigest {
        &self.policy_digest
    }
}

/// A verified immutable policy record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumptionPolicy {
    tenant_id: TenantId,
    policy_version: u64,
    issued_at: Timestamp,
    effective_at: Timestamp,
    allowed_classifier_kinds: BTreeSet<String>,
    allowed_rule_set_digests: BTreeSet<BlobDigest>,
    assessment_not_before: Timestamp,
    max_assessment_age_seconds: u64,
    purpose_to_consumer_classes: BTreeMap<String, BTreeSet<String>>,
    max_approval_lifetime_seconds: u64,
    predecessor_digest: Option<BlobDigest>,
    governance_key_id: KeyId,
    digest: BlobDigest,
}

impl ConsumptionPolicy {
    /// Verify one signed immutable policy against the offline-published
    /// governance anchor.
    ///
    /// # Errors
    ///
    /// Returns a policy error for malformed, unsupported, out-of-scope, or
    /// incorrectly signed bytes.
    pub fn verify(
        anchor: &GovernanceTrustAnchor,
        envelope: &[u8],
    ) -> Result<Self, ConsumptionPolicyError> {
        let object = parse_closed_object(envelope, &POLICY_MEMBERS)?;
        if text_member(&object, "schema") != Some(POLICY_SCHEMA)
            || text_member(&object, "record_type") != Some(POLICY_RECORD_TYPE)
            || text_member(&object, "record_kind") != Some("immutable")
        {
            return Err(ConsumptionPolicyError::UnsupportedPolicy);
        }
        if Value::Object(object.clone()).canonical_bytes() != envelope {
            return Err(ConsumptionPolicyError::MalformedRecord);
        }
        let tenant_id = parse_tenant(&object, "tenant_id")?;
        if tenant_id != *anchor.tenant_id() {
            return Err(ConsumptionPolicyError::ScopeViolation);
        }
        let policy_version = positive_number(&object, "policy_version")?;
        let issued_at = parse_timestamp(&object, "issued_at")?;
        let effective_at = parse_timestamp(&object, "effective_at")?;
        let assessment_not_before = parse_timestamp(&object, "assessment_not_before")?;
        let allowed_classifier_kinds = string_set(&object, "allowed_classifier_kinds")?;
        let allowed_rule_set_digests = digest_set(&object, "allowed_rule_set_digests")?;
        let purpose_to_consumer_classes = purpose_map(&object)?;
        let max_assessment_age_seconds = bounded_seconds(
            &object,
            "max_assessment_age_seconds",
            MAX_ASSESSMENT_AGE_SECONDS,
        )?;
        let max_approval_lifetime_seconds = bounded_seconds(
            &object,
            "max_approval_lifetime_seconds",
            MAX_APPROVAL_LIFETIME_SECONDS,
        )?;
        let predecessor_digest = optional_digest(&object, "predecessor_digest")?;
        validate_timestamps(&issued_at, &effective_at, &assessment_not_before)?;
        let governance_key_id = KeyId::parse(required_text(&object, "governance_key_id")?)
            .map_err(|_| ConsumptionPolicyError::MalformedRecord)?;
        if governance_key_id != *anchor.key_id() {
            return Err(ConsumptionPolicyError::UntrustedGovernance);
        }
        let signature = Ed25519Signature::parse(required_text(&object, "governance_signature")?)
            .map_err(|_| ConsumptionPolicyError::MalformedRecord)?;
        let mut unsigned = object.clone();
        let _ = unsigned.remove("governance_signature");
        if !ed25519::verify(
            anchor.public_key().as_raw(),
            &Value::Object(unsigned).canonical_bytes(),
            &ed25519::Signature::from_bytes(*signature.as_raw()),
        ) {
            return Err(ConsumptionPolicyError::InvalidSignature);
        }
        Ok(Self {
            tenant_id,
            policy_version,
            issued_at,
            effective_at,
            allowed_classifier_kinds,
            allowed_rule_set_digests,
            assessment_not_before,
            max_assessment_age_seconds,
            purpose_to_consumer_classes,
            max_approval_lifetime_seconds,
            predecessor_digest,
            governance_key_id,
            digest: BlobDigest::from_raw(sha256::digest(envelope)),
        })
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The monotonic policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// The issue instant.
    #[must_use]
    pub const fn issued_at(&self) -> &Timestamp {
        &self.issued_at
    }

    /// The effective instant.
    #[must_use]
    pub const fn effective_at(&self) -> &Timestamp {
        &self.effective_at
    }

    /// The allowed classifier kinds.
    pub fn allowed_classifier_kinds(&self) -> impl Iterator<Item = &str> {
        self.allowed_classifier_kinds.iter().map(String::as_str)
    }

    /// The allowed rule-set digests.
    pub fn allowed_rule_set_digests(&self) -> impl Iterator<Item = &BlobDigest> {
        self.allowed_rule_set_digests.iter()
    }

    /// The assessment freshness lower bound.
    #[must_use]
    pub const fn assessment_not_before(&self) -> &Timestamp {
        &self.assessment_not_before
    }

    /// The maximum assessment age.
    #[must_use]
    pub const fn max_assessment_age_seconds(&self) -> u64 {
        self.max_assessment_age_seconds
    }

    /// The purpose-to-consumer-class allowlist.
    #[must_use]
    pub fn purpose_to_consumer_classes(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.purpose_to_consumer_classes
    }

    /// The maximum approval lifetime.
    #[must_use]
    pub const fn max_approval_lifetime_seconds(&self) -> u64 {
        self.max_approval_lifetime_seconds
    }

    /// The predecessor policy digest, or `None` for the genesis policy.
    #[must_use]
    pub const fn predecessor_digest(&self) -> Option<&BlobDigest> {
        self.predecessor_digest.as_ref()
    }

    /// The governance key ID that signed this policy and must issue any
    /// approval binding this policy version.
    ///
    /// A use approval binds the policy version, so the identity issuing one
    /// must be the same governance key this policy was signed with; the
    /// approval-issuing surface cross-checks the pair before signing.
    #[must_use]
    pub const fn governance_key_id(&self) -> &KeyId {
        &self.governance_key_id
    }

    /// The digest of the complete signed policy bytes.
    #[must_use]
    pub const fn digest(&self) -> &BlobDigest {
        &self.digest
    }
}

/// The verified current pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentPolicyPointer {
    tenant_id: TenantId,
    policy_version: u64,
    policy_digest: BlobDigest,
    effective_at: Timestamp,
}

impl CurrentPolicyPointer {
    /// Verify a signed pointer against the governance anchor.
    ///
    /// # Errors
    ///
    /// Returns a policy error for malformed, unsupported, out-of-scope, or
    /// incorrectly signed bytes.
    pub fn verify(
        anchor: &GovernanceTrustAnchor,
        envelope: &[u8],
    ) -> Result<Self, ConsumptionPolicyError> {
        let object = parse_closed_object(envelope, &POINTER_MEMBERS)?;
        if text_member(&object, "schema") != Some(POLICY_SCHEMA)
            || text_member(&object, "record_type") != Some(POLICY_POINTER_RECORD_TYPE)
            || text_member(&object, "record_kind") != Some("current-pointer")
        {
            return Err(ConsumptionPolicyError::UnsupportedPolicy);
        }
        if Value::Object(object.clone()).canonical_bytes() != envelope {
            return Err(ConsumptionPolicyError::MalformedRecord);
        }
        let tenant_id = parse_tenant(&object, "tenant_id")?;
        if tenant_id != *anchor.tenant_id() {
            return Err(ConsumptionPolicyError::ScopeViolation);
        }
        let policy_version = positive_number(&object, "policy_version")?;
        let policy_digest = parse_digest(&object, "policy_digest")?;
        let effective_at = parse_timestamp(&object, "effective_at")?;
        let signer = KeyId::parse(required_text(&object, "governance_key_id")?)
            .map_err(|_| ConsumptionPolicyError::MalformedRecord)?;
        if signer != *anchor.key_id() {
            return Err(ConsumptionPolicyError::UntrustedGovernance);
        }
        let signature = Ed25519Signature::parse(required_text(&object, "governance_signature")?)
            .map_err(|_| ConsumptionPolicyError::MalformedRecord)?;
        let mut unsigned = object.clone();
        let _ = unsigned.remove("governance_signature");
        if !ed25519::verify(
            anchor.public_key().as_raw(),
            &Value::Object(unsigned).canonical_bytes(),
            &ed25519::Signature::from_bytes(*signature.as_raw()),
        ) {
            return Err(ConsumptionPolicyError::InvalidSignature);
        }
        Ok(Self {
            tenant_id,
            policy_version,
            policy_digest,
            effective_at,
        })
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The current policy version.
    #[must_use]
    pub const fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// The current policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> &BlobDigest {
        &self.policy_digest
    }

    /// The effective instant copied into the pointer.
    #[must_use]
    pub const fn effective_at(&self) -> &Timestamp {
        &self.effective_at
    }
}

/// Supported policy vocabulary used by a reader before it authorizes use.
///
/// A policy can be structurally valid and signed yet still be unsupported by
/// the installed evaluator.  Such a policy is rejected rather than treated
/// as an empty or partially understood allowlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySupport {
    classifier_kinds: BTreeSet<String>,
    rule_set_digests: Option<BTreeSet<BlobDigest>>,
}

impl Default for PolicySupport {
    fn default() -> Self {
        Self {
            classifier_kinds: BTreeSet::from([SUPPORTED_CLASSIFIER_KIND.to_owned()]),
            rule_set_digests: None,
        }
    }
}

impl PolicySupport {
    /// Create a support declaration with explicit classifier and rule-set
    /// allowlists.  An empty rule-set set means the evaluator accepts any
    /// syntactically valid digest because its artifact registry is external.
    #[must_use]
    pub fn new(
        classifier_kinds: impl IntoIterator<Item = String>,
        rule_set_digests: Option<impl IntoIterator<Item = BlobDigest>>,
    ) -> Self {
        Self {
            classifier_kinds: classifier_kinds.into_iter().collect(),
            rule_set_digests: rule_set_digests.map(|values| values.into_iter().collect()),
        }
    }

    fn accepts(&self, policy: &ConsumptionPolicy) -> bool {
        policy
            .allowed_classifier_kinds
            .iter()
            .all(|kind| self.classifier_kinds.contains(kind))
            && self.rule_set_digests.as_ref().is_none_or(|known| {
                policy
                    .allowed_rule_set_digests
                    .iter()
                    .all(|digest| known.contains(digest))
            })
    }
}

/// A verified, internally continuous current policy view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectedPolicy {
    pointer: CurrentPolicyPointer,
    policy: ConsumptionPolicy,
}

impl InspectedPolicy {
    /// The verified pointer.
    #[must_use]
    pub const fn pointer(&self) -> &CurrentPolicyPointer {
        &self.pointer
    }

    /// The verified policy named by the pointer.
    #[must_use]
    pub const fn policy(&self) -> &ConsumptionPolicy {
        &self.policy
    }
}

/// Why policy administration or inspection failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConsumptionPolicyError {
    /// Bytes were not the exact closed, canonical record shape.
    MalformedRecord,
    /// A record belongs to another tenant or a pointer disagrees with its
    /// policy.
    ScopeViolation,
    /// The governance signature or key binding failed.
    InvalidSignature,
    /// The signer is not the configured offline governance identity.
    UntrustedGovernance,
    /// The record names a policy kind or rule set this evaluator cannot
    /// understand.
    UnsupportedPolicy,
    /// A signed predecessor is absent, mismatched, or not the immediately
    /// previous policy version.
    Discontinuous,
    /// A candidate pointer would move to an equal or lower policy version.
    Rollback,
    /// The current pointer names a digest-addressed object that is absent.
    MissingPolicy,
    /// The policy is signed for a future effective instant.
    NotEffective,
    /// A signed clock instant lies beyond the operational uncertainty bound.
    ClockUncertain,
    /// The policy's bounded numeric or timestamp relationships are invalid.
    InvalidBounds,
    /// The repository could not complete an operation.
    RepositoryUnavailable,
    /// A different immutable object already occupies the derived key.
    IntegrityConflict,
}

impl ConsumptionPolicyError {
    /// A stable, content-free failure class.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::MalformedRecord => "malformed-record",
            Self::ScopeViolation => "scope-violation",
            Self::InvalidSignature => "invalid-signature",
            Self::UntrustedGovernance => "untrusted-governance",
            Self::UnsupportedPolicy => "unsupported-policy",
            Self::Discontinuous => "discontinuous-policy",
            Self::Rollback => "policy-rollback",
            Self::MissingPolicy => "missing-policy",
            Self::NotEffective => "policy-not-effective",
            Self::ClockUncertain => "clock-uncertain",
            Self::InvalidBounds => "invalid-bounds",
            Self::RepositoryUnavailable => "repository-unavailable",
            Self::IntegrityConflict => "integrity-conflict",
        }
    }
}

impl fmt::Display for ConsumptionPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for ConsumptionPolicyError {}

/// A policy-only storage boundary for the offline governance identity.
pub trait PolicyRepository {
    /// Read the signed current pointer.
    fn read_current(
        &self,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, ConsumptionPolicyError>> + Send;

    /// Read an immutable policy by its digest.
    fn read_policy(
        &self,
        digest: &BlobDigest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, ConsumptionPolicyError>> + Send;

    /// Put an immutable digest-addressed policy, idempotently for equal bytes.
    fn put_policy(
        &mut self,
        publication: &PolicyPublication,
    ) -> impl Future<Output = Result<(), ConsumptionPolicyError>> + Send;

    /// Advance `current.json` only when the signed version increases.
    fn put_current(
        &mut self,
        publication: &PointerPublication,
    ) -> impl Future<Output = Result<(), ConsumptionPolicyError>> + Send;
}

/// An in-memory repository useful for offline tooling and deterministic tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryPolicyRepository {
    policies: BTreeMap<BlobDigest, Vec<u8>>,
    current: Option<Vec<u8>>,
}

impl MemoryPolicyRepository {
    /// Create an empty policy repository.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
            current: None,
        }
    }
}

impl PolicyRepository for MemoryPolicyRepository {
    async fn read_current(&self) -> Result<Option<Vec<u8>>, ConsumptionPolicyError> {
        Ok(self.current.clone())
    }

    async fn read_policy(
        &self,
        digest: &BlobDigest,
    ) -> Result<Option<Vec<u8>>, ConsumptionPolicyError> {
        Ok(self.policies.get(digest).cloned())
    }

    async fn put_policy(
        &mut self,
        publication: &PolicyPublication,
    ) -> Result<(), ConsumptionPolicyError> {
        match self.policies.get(publication.digest()) {
            None => {
                self.policies
                    .insert(*publication.digest(), publication.envelope.clone());
                Ok(())
            }
            Some(existing) if existing == publication.envelope() => Ok(()),
            Some(_) => Err(ConsumptionPolicyError::IntegrityConflict),
        }
    }

    async fn put_current(
        &mut self,
        publication: &PointerPublication,
    ) -> Result<(), ConsumptionPolicyError> {
        if let Some(existing) = &self.current {
            // The repository does not own a trust anchor; compare only the
            // signed version after a caller has verified the existing bytes.
            // This fallback never accepts an equal or lower pointer.
            let old_version = pointer_version(existing)?;
            if publication.policy_version <= old_version {
                return Err(ConsumptionPolicyError::Rollback);
            }
        }
        self.current = Some(publication.envelope.clone());
        Ok(())
    }
}

/// Publish an immutable policy record through the policy-only repository.
///
/// # Errors
///
/// Returns a policy error when verification, support, or immutable storage
/// fails.
pub async fn publish_policy<R: PolicyRepository>(
    repository: &mut R,
    anchor: &GovernanceTrustAnchor,
    publication: &PolicyPublication,
) -> Result<(), ConsumptionPolicyError> {
    let policy = ConsumptionPolicy::verify(anchor, publication.envelope())?;
    if policy.digest() != publication.digest()
        || policy.policy_version() != publication.policy_version()
    {
        return Err(ConsumptionPolicyError::MalformedRecord);
    }
    if !PolicySupport::default().accepts(&policy) {
        return Err(ConsumptionPolicyError::UnsupportedPolicy);
    }
    repository.put_policy(publication).await
}

/// Verify and advance the signed current pointer after its immutable policy
/// has been published.  The pointer is written last, so a failed policy put
/// can never make an unreadable policy current.
///
/// # Errors
///
/// Returns a policy error when the candidate, clock, predecessor chain, or
/// current pointer is invalid.
pub async fn advance_policy<R: PolicyRepository>(
    repository: &mut R,
    identity: &OfflineGovernanceIdentity,
    publication: &PolicyPublication,
    now: &Timestamp,
) -> Result<PointerPublication, ConsumptionPolicyError> {
    let anchor = identity.trust_anchor(publication.tenant_id.clone());
    let candidate = ConsumptionPolicy::verify(&anchor, publication.envelope())?;
    if candidate.digest() != publication.digest()
        || candidate.policy_version() != publication.policy_version()
    {
        return Err(ConsumptionPolicyError::MalformedRecord);
    }
    if !PolicySupport::default().accepts(&candidate) {
        return Err(ConsumptionPolicyError::UnsupportedPolicy);
    }
    check_clock(now, &candidate)?;
    if let Some(current_bytes) = repository.read_current().await? {
        let current = CurrentPolicyPointer::verify(&anchor, &current_bytes)?;
        let current_policy_bytes = repository
            .read_policy(current.policy_digest())
            .await?
            .ok_or(ConsumptionPolicyError::MissingPolicy)?;
        let current_policy = ConsumptionPolicy::verify(&anchor, &current_policy_bytes)?;
        if current.policy_digest() != current_policy.digest()
            || current.policy_version() != current_policy.policy_version()
        {
            return Err(ConsumptionPolicyError::Discontinuous);
        }
        if candidate.policy_version() <= current.policy_version() {
            return Err(ConsumptionPolicyError::Rollback);
        }
        if candidate.predecessor_digest() != Some(current_policy.digest()) {
            return Err(ConsumptionPolicyError::Discontinuous);
        }
    } else if candidate.policy_version() != 1 || candidate.predecessor_digest().is_some() {
        return Err(ConsumptionPolicyError::Discontinuous);
    }
    repository.put_policy(publication).await?;
    let pointer = identity.sign_pointer(publication)?;
    repository.put_current(&pointer).await?;
    Ok(pointer)
}

/// Inspect a pointer, its named policy, and the complete predecessor chain.
///
/// The function does not return a partially understood policy.  Every link
/// must verify, every digest must match, versions must strictly increase, the
/// policy must be supported, and the effective clock must be known.
///
/// # Errors
///
/// Returns a policy error when any pointer, policy, predecessor, support, or
/// clock check fails.
pub async fn inspect_policy<R: PolicyRepository>(
    repository: &R,
    anchor: &GovernanceTrustAnchor,
    now: &Timestamp,
) -> Result<InspectedPolicy, ConsumptionPolicyError> {
    inspect_policy_with_support(repository, anchor, now, &PolicySupport::default()).await
}

/// Inspect a policy using an explicit evaluator support declaration.
///
/// # Errors
///
/// Returns a policy error when any pointer, policy, predecessor, support, or
/// clock check fails.
pub async fn inspect_policy_with_support<R: PolicyRepository>(
    repository: &R,
    anchor: &GovernanceTrustAnchor,
    now: &Timestamp,
    support: &PolicySupport,
) -> Result<InspectedPolicy, ConsumptionPolicyError> {
    let pointer_bytes = repository
        .read_current()
        .await?
        .ok_or(ConsumptionPolicyError::MissingPolicy)?;
    let pointer = CurrentPolicyPointer::verify(anchor, &pointer_bytes)?;
    let policy_bytes = repository
        .read_policy(pointer.policy_digest())
        .await?
        .ok_or(ConsumptionPolicyError::MissingPolicy)?;
    let policy = ConsumptionPolicy::verify(anchor, &policy_bytes)?;
    if pointer.policy_digest() != policy.digest()
        || pointer.policy_version() != policy.policy_version()
        || pointer.effective_at() != policy.effective_at()
    {
        return Err(ConsumptionPolicyError::Discontinuous);
    }
    if !support.accepts(&policy) {
        return Err(ConsumptionPolicyError::UnsupportedPolicy);
    }
    check_clock(now, &policy)?;
    if timestamp_cmp(policy.effective_at(), now)? == std::cmp::Ordering::Greater {
        return Err(ConsumptionPolicyError::NotEffective);
    }
    let mut current = policy.clone();
    while let Some(predecessor_digest) = current.predecessor_digest() {
        let predecessor_bytes = repository
            .read_policy(predecessor_digest)
            .await?
            .ok_or(ConsumptionPolicyError::Discontinuous)?;
        let predecessor = ConsumptionPolicy::verify(anchor, &predecessor_bytes)?;
        if predecessor.digest() != predecessor_digest
            || predecessor.policy_version() >= current.policy_version()
        {
            return Err(ConsumptionPolicyError::Discontinuous);
        }
        current = predecessor;
    }
    if current.policy_version() != 1 {
        return Err(ConsumptionPolicyError::Discontinuous);
    }
    Ok(InspectedPolicy { pointer, policy })
}

/// Derive the immutable policy object key.
#[must_use]
pub fn policy_object_key(tenant: &TenantId, digest: &BlobDigest) -> String {
    format!(
        "tenants/{}/v1/control/consumption-policies/{}.json",
        tenant.as_str(),
        digest.to_hex()
    )
}

/// Derive the signed current-pointer key.
#[must_use]
pub fn current_pointer_object_key(tenant: &TenantId) -> String {
    format!(
        "tenants/{}/v1/control/consumption-policies/current.json",
        tenant.as_str()
    )
}

const POLICY_MEMBERS: [&str; 16] = [
    "allowed_classifier_kinds",
    "allowed_rule_set_digests",
    "assessment_not_before",
    "effective_at",
    "governance_key_id",
    "governance_signature",
    "issued_at",
    "max_approval_lifetime_seconds",
    "max_assessment_age_seconds",
    "policy_version",
    "predecessor_digest",
    "purpose_to_consumer_classes",
    "record_kind",
    "record_type",
    "schema",
    "tenant_id",
];

const POINTER_MEMBERS: [&str; 9] = [
    "effective_at",
    "governance_key_id",
    "governance_signature",
    "policy_digest",
    "policy_version",
    "record_kind",
    "record_type",
    "schema",
    "tenant_id",
];

fn policy_object(spec: &ConsumptionPolicySpec, key_id: &KeyId) -> Object {
    let mut object = Object::new();
    object.set("schema", text(POLICY_SCHEMA));
    object.set("record_type", text(POLICY_RECORD_TYPE));
    object.set("record_kind", text("immutable"));
    object.set("tenant_id", text(spec.tenant_id.as_str()));
    object.set("policy_version", signed_integer(spec.policy_version));
    object.set("issued_at", text(spec.issued_at.as_str()));
    object.set("effective_at", text(spec.effective_at.as_str()));
    let mut classifier_kinds = spec.allowed_classifier_kinds.clone();
    classifier_kinds.sort();
    object.set(
        "allowed_classifier_kinds",
        Value::Array(classifier_kinds.iter().cloned().map(Value::Text).collect()),
    );
    let mut rule_set_digests = spec.allowed_rule_set_digests.clone();
    rule_set_digests.sort();
    object.set(
        "allowed_rule_set_digests",
        Value::Array(
            rule_set_digests
                .iter()
                .map(|digest| text(&digest.to_hex()))
                .collect(),
        ),
    );
    object.set(
        "assessment_not_before",
        text(spec.assessment_not_before.as_str()),
    );
    object.set(
        "max_assessment_age_seconds",
        signed_integer(spec.max_assessment_age_seconds),
    );
    let mut purposes = Object::new();
    for (purpose, classes) in &spec.purpose_to_consumer_classes {
        let mut classes = classes.clone();
        classes.sort();
        purposes.set(
            purpose,
            Value::Array(classes.into_iter().map(Value::Text).collect()),
        );
    }
    object.set("purpose_to_consumer_classes", Value::Object(purposes));
    object.set(
        "max_approval_lifetime_seconds",
        signed_integer(spec.max_approval_lifetime_seconds),
    );
    object.set(
        "predecessor_digest",
        spec.predecessor_digest
            .as_ref()
            .map_or(Value::Null, |digest| text(&digest.to_hex())),
    );
    object.set("governance_key_id", text(&key_id.to_hex()));
    object
}

fn pointer_object(
    tenant: &TenantId,
    policy_version: u64,
    digest: &BlobDigest,
    effective_at: &Timestamp,
    key_id: &KeyId,
) -> Object {
    let mut object = Object::new();
    object.set("schema", text(POLICY_SCHEMA));
    object.set("record_type", text(POLICY_POINTER_RECORD_TYPE));
    object.set("record_kind", text("current-pointer"));
    object.set("tenant_id", text(tenant.as_str()));
    object.set("policy_version", signed_integer(policy_version));
    object.set("policy_digest", text(&digest.to_hex()));
    object.set("effective_at", text(effective_at.as_str()));
    object.set("governance_key_id", text(&key_id.to_hex()));
    object
}

fn validate_spec(spec: &ConsumptionPolicySpec) -> Result<(), ConsumptionPolicyError> {
    if spec.policy_version == 0 || spec.policy_version > POLICY_MAX_VERSION {
        return Err(ConsumptionPolicyError::InvalidBounds);
    }
    validate_timestamp(&spec.issued_at)?;
    validate_timestamp(&spec.effective_at)?;
    validate_timestamp(&spec.assessment_not_before)?;
    validate_timestamps(
        &spec.issued_at,
        &spec.effective_at,
        &spec.assessment_not_before,
    )?;
    if spec.allowed_classifier_kinds.is_empty()
        || spec.allowed_classifier_kinds.len() > MAX_ALLOWLIST_ITEMS
        || spec.allowed_rule_set_digests.is_empty()
        || spec.allowed_rule_set_digests.len() > MAX_ALLOWLIST_ITEMS
    {
        return Err(ConsumptionPolicyError::InvalidBounds);
    }
    if spec.max_assessment_age_seconds == 0
        || spec.max_assessment_age_seconds > MAX_ASSESSMENT_AGE_SECONDS
        || spec.max_approval_lifetime_seconds == 0
        || spec.max_approval_lifetime_seconds > MAX_APPROVAL_LIFETIME_SECONDS
    {
        return Err(ConsumptionPolicyError::InvalidBounds);
    }
    let mut classifiers = BTreeSet::new();
    for kind in &spec.allowed_classifier_kinds {
        if !token(kind) || !classifiers.insert(kind) {
            return Err(ConsumptionPolicyError::InvalidBounds);
        }
    }
    let mut digests = BTreeSet::new();
    for digest in &spec.allowed_rule_set_digests {
        if !digests.insert(*digest) {
            return Err(ConsumptionPolicyError::InvalidBounds);
        }
    }
    for (purpose, classes) in &spec.purpose_to_consumer_classes {
        if !token(purpose) || classes.is_empty() {
            return Err(ConsumptionPolicyError::InvalidBounds);
        }
        let mut seen = BTreeSet::new();
        for class in classes {
            if !token(class) || !seen.insert(class) {
                return Err(ConsumptionPolicyError::InvalidBounds);
            }
        }
    }
    Ok(())
}

fn validate_timestamps(
    issued_at: &Timestamp,
    effective_at: &Timestamp,
    assessment_not_before: &Timestamp,
) -> Result<(), ConsumptionPolicyError> {
    if timestamp_cmp(issued_at, effective_at)? == std::cmp::Ordering::Greater
        || timestamp_cmp(effective_at, assessment_not_before)? == std::cmp::Ordering::Greater
    {
        return Err(ConsumptionPolicyError::InvalidBounds);
    }
    Ok(())
}

fn check_clock(now: &Timestamp, policy: &ConsumptionPolicy) -> Result<(), ConsumptionPolicyError> {
    validate_timestamp(now)?;
    let now_value = timestamp_value(now)?;
    for instant in [
        policy.issued_at(),
        policy.effective_at(),
        policy.assessment_not_before(),
    ] {
        let value = timestamp_value(instant)?;
        if value.0 > now_value.0.saturating_add(CLOCK_SKEW_ALLOWANCE_SECONDS) {
            return Err(ConsumptionPolicyError::ClockUncertain);
        }
    }
    Ok(())
}

pub(crate) fn validate_timestamp(timestamp: &Timestamp) -> Result<(), ConsumptionPolicyError> {
    if timestamp.calendar_valid() {
        Ok(())
    } else {
        Err(ConsumptionPolicyError::MalformedRecord)
    }
}

pub(crate) fn parse_closed_object(
    bytes: &[u8],
    members: &[&str],
) -> Result<Object, ConsumptionPolicyError> {
    let Value::Object(object) =
        json::parse(bytes).map_err(|_| ConsumptionPolicyError::MalformedRecord)?
    else {
        return Err(ConsumptionPolicyError::MalformedRecord);
    };
    if object.len() != members.len() || members.iter().any(|member| !object.contains(member)) {
        return Err(ConsumptionPolicyError::MalformedRecord);
    }
    Ok(object)
}

pub(crate) fn required_text<'a>(
    object: &'a Object,
    name: &str,
) -> Result<&'a str, ConsumptionPolicyError> {
    text_member(object, name).ok_or(ConsumptionPolicyError::MalformedRecord)
}

pub(crate) fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(value)) => Some(value.as_str()),
        _ => None,
    }
}

pub(crate) fn parse_tenant(
    object: &Object,
    name: &str,
) -> Result<TenantId, ConsumptionPolicyError> {
    TenantId::parse(required_text(object, name)?)
        .map_err(|_| ConsumptionPolicyError::MalformedRecord)
}

pub(crate) fn parse_timestamp(
    object: &Object,
    name: &str,
) -> Result<Timestamp, ConsumptionPolicyError> {
    let timestamp = Timestamp::parse(required_text(object, name)?)
        .map_err(|_| ConsumptionPolicyError::MalformedRecord)?;
    validate_timestamp(&timestamp)?;
    Ok(timestamp)
}

pub(crate) fn parse_digest(
    object: &Object,
    name: &str,
) -> Result<BlobDigest, ConsumptionPolicyError> {
    BlobDigest::parse(required_text(object, name)?)
        .map_err(|_| ConsumptionPolicyError::MalformedRecord)
}

fn optional_digest(
    object: &Object,
    name: &str,
) -> Result<Option<BlobDigest>, ConsumptionPolicyError> {
    match object.get(name) {
        Some(Value::Null) => Ok(None),
        Some(Value::Text(value)) => BlobDigest::parse(value)
            .map(Some)
            .map_err(|_| ConsumptionPolicyError::MalformedRecord),
        _ => Err(ConsumptionPolicyError::MalformedRecord),
    }
}

pub(crate) fn positive_number(object: &Object, name: &str) -> Result<u64, ConsumptionPolicyError> {
    match object.get(name) {
        Some(Value::Int(value)) if (1..=POLICY_MAX_VERSION_I64).contains(value) => {
            u64::try_from(*value).map_err(|_| ConsumptionPolicyError::InvalidBounds)
        }
        _ => Err(ConsumptionPolicyError::InvalidBounds),
    }
}

fn bounded_seconds(
    object: &Object,
    name: &str,
    maximum: u64,
) -> Result<u64, ConsumptionPolicyError> {
    let maximum = i64::try_from(maximum).map_err(|_| ConsumptionPolicyError::InvalidBounds)?;
    match object.get(name) {
        Some(Value::Int(value)) if (1..=maximum).contains(value) => {
            u64::try_from(*value).map_err(|_| ConsumptionPolicyError::InvalidBounds)
        }
        _ => Err(ConsumptionPolicyError::InvalidBounds),
    }
}

fn string_set(object: &Object, name: &str) -> Result<BTreeSet<String>, ConsumptionPolicyError> {
    let Some(Value::Array(values)) = object.get(name) else {
        return Err(ConsumptionPolicyError::MalformedRecord);
    };
    if values.is_empty() || values.len() > MAX_ALLOWLIST_ITEMS {
        return Err(ConsumptionPolicyError::InvalidBounds);
    }
    let mut set = BTreeSet::new();
    for value in values {
        let Value::Text(value) = value else {
            return Err(ConsumptionPolicyError::MalformedRecord);
        };
        if !token(value) || !set.insert(value.clone()) {
            return Err(ConsumptionPolicyError::InvalidBounds);
        }
    }
    Ok(set)
}

fn digest_set(object: &Object, name: &str) -> Result<BTreeSet<BlobDigest>, ConsumptionPolicyError> {
    let Some(Value::Array(values)) = object.get(name) else {
        return Err(ConsumptionPolicyError::MalformedRecord);
    };
    if values.is_empty() || values.len() > MAX_ALLOWLIST_ITEMS {
        return Err(ConsumptionPolicyError::InvalidBounds);
    }
    let mut set = BTreeSet::new();
    for value in values {
        let Value::Text(value) = value else {
            return Err(ConsumptionPolicyError::MalformedRecord);
        };
        let digest =
            BlobDigest::parse(value).map_err(|_| ConsumptionPolicyError::MalformedRecord)?;
        if !set.insert(digest) {
            return Err(ConsumptionPolicyError::InvalidBounds);
        }
    }
    Ok(set)
}

fn purpose_map(
    object: &Object,
) -> Result<BTreeMap<String, BTreeSet<String>>, ConsumptionPolicyError> {
    let Some(Value::Object(purposes)) = object.get("purpose_to_consumer_classes") else {
        return Err(ConsumptionPolicyError::MalformedRecord);
    };
    let mut map = BTreeMap::new();
    for (purpose, value) in purposes.iter() {
        if !token(purpose) {
            return Err(ConsumptionPolicyError::InvalidBounds);
        }
        let Value::Array(classes) = value else {
            return Err(ConsumptionPolicyError::MalformedRecord);
        };
        if classes.is_empty() || classes.len() > MAX_ALLOWLIST_ITEMS {
            return Err(ConsumptionPolicyError::InvalidBounds);
        }
        let mut set = BTreeSet::new();
        for class in classes {
            let Value::Text(class) = class else {
                return Err(ConsumptionPolicyError::MalformedRecord);
            };
            if !token(class) || !set.insert(class.clone()) {
                return Err(ConsumptionPolicyError::InvalidBounds);
            }
        }
        map.insert(purpose.to_owned(), set);
    }
    Ok(map)
}

/// The shared governance-token grammar: lowercase lead, 64 bytes, and the
/// punctuation set every closed record family in this crate validates with.
pub(crate) fn token(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte))
}

fn pointer_version(bytes: &[u8]) -> Result<u64, ConsumptionPolicyError> {
    let Value::Object(object) =
        json::parse(bytes).map_err(|_| ConsumptionPolicyError::MalformedRecord)?
    else {
        return Err(ConsumptionPolicyError::MalformedRecord);
    };
    positive_number(&object, "policy_version")
}

pub(crate) fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

pub(crate) fn signed_integer(value: u64) -> Value {
    Value::Int(
        i64::try_from(value)
            .unwrap_or_else(|_| unreachable!("policy numeric bounds fit in a signed integer")),
    )
}

pub(crate) fn timestamp_cmp(
    left: &Timestamp,
    right: &Timestamp,
) -> Result<std::cmp::Ordering, ConsumptionPolicyError> {
    Ok(timestamp_value(left)?.cmp(&timestamp_value(right)?))
}

pub(crate) fn timestamp_value(timestamp: &Timestamp) -> Result<(i64, u32), ConsumptionPolicyError> {
    validate_timestamp(timestamp)?;
    let bytes = timestamp.as_str().as_bytes();
    let number = |slice: &[u8]| {
        slice
            .iter()
            .fold(0i64, |acc, byte| acc * 10 + i64::from(byte - b'0'))
    };
    let year = number(&bytes[0..4]);
    let month = number(&bytes[5..7]);
    let day = number(&bytes[8..10]);
    let hour = number(&bytes[11..13]);
    let minute = number(&bytes[14..16]);
    let second = number(&bytes[17..19]);
    let nanoseconds = if bytes.len() > 20 {
        let digits = &bytes[20..bytes.len() - 1];
        let mut value = 0u32;
        for digit in digits {
            value = value * 10 + u32::from(digit - b'0');
        }
        let digit_count =
            u32::try_from(digits.len()).map_err(|_| ConsumptionPolicyError::MalformedRecord)?;
        value * 10u32.pow(9u32.saturating_sub(digit_count))
    } else {
        0
    };
    Ok((
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second,
        nanoseconds,
    ))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = (if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    }) / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_from_march = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const ISSUE: &str = "2026-09-20T00:00:00Z";
    const EFFECTIVE: &str = "2026-09-20T00:00:00Z";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn tenant() -> TenantId {
        TENANT.parse().unwrap()
    }

    fn digest() -> BlobDigest {
        DIGEST.parse().unwrap()
    }

    fn spec(version: u64, predecessor_digest: Option<BlobDigest>) -> ConsumptionPolicySpec {
        ConsumptionPolicySpec {
            tenant_id: tenant(),
            policy_version: version,
            issued_at: ISSUE.parse().unwrap(),
            effective_at: EFFECTIVE.parse().unwrap(),
            allowed_classifier_kinds: vec![SUPPORTED_CLASSIFIER_KIND.to_owned()],
            allowed_rule_set_digests: vec![digest()],
            assessment_not_before: ISSUE.parse().unwrap(),
            max_assessment_age_seconds: DEFAULT_MAX_ASSESSMENT_AGE_SECONDS,
            purpose_to_consumer_classes: BTreeMap::from([(
                "agent-use".to_owned(),
                vec!["agent".to_owned()],
            )]),
            max_approval_lifetime_seconds: 3600,
            predecessor_digest,
        }
    }

    fn identity() -> OfflineGovernanceIdentity {
        OfflineGovernanceIdentity::from_seed([7; 32])
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
        }
    }

    #[test]
    fn policy_and_pointer_are_signed_and_inspectable() {
        let identity = identity();
        let first = identity.sign_policy(&spec(1, None)).unwrap();
        let mut repository = MemoryPolicyRepository::new();
        block_on(publish_policy(
            &mut repository,
            &identity.trust_anchor(tenant()),
            &first,
        ))
        .unwrap();
        // The policy is effective at ISSUE; use a time inside the signed
        // policy's clock window.
        let pointer = block_on(advance_policy(
            &mut repository,
            &identity,
            &first,
            &ISSUE.parse().unwrap(),
        ))
        .unwrap();
        CurrentPolicyPointer::verify(&identity.trust_anchor(tenant()), pointer.envelope()).unwrap();
        let inspected = block_on(inspect_policy(
            &repository,
            &identity.trust_anchor(tenant()),
            &ISSUE.parse().unwrap(),
        ))
        .unwrap();
        assert_eq!(inspected.policy().digest(), first.digest());
    }

    #[test]
    fn malformed_pointer_shape_is_rejected_closed() {
        let identity = identity();
        let first = identity.sign_policy(&spec(1, None)).unwrap();
        let mut pointer = identity.sign_pointer(&first).unwrap().envelope().to_vec();
        pointer.pop();
        assert_eq!(
            CurrentPolicyPointer::verify(&identity.trust_anchor(tenant()), &pointer),
            Err(ConsumptionPolicyError::MalformedRecord)
        );
    }

    #[test]
    fn unsupported_classifier_fails_closed() {
        let identity = identity();
        let mut unsupported = spec(1, None);
        unsupported.allowed_classifier_kinds = vec!["model-v9".to_owned()];
        let publication = identity.sign_policy(&unsupported).unwrap();
        let policy =
            ConsumptionPolicy::verify(&identity.trust_anchor(tenant()), publication.envelope())
                .unwrap();
        assert!(!PolicySupport::default().accepts(&policy));
    }

    #[test]
    fn continuity_requires_predecessor_digest_and_monotonic_version() {
        let identity = identity();
        let first = identity.sign_policy(&spec(1, None)).unwrap();
        let second = identity.sign_policy(&spec(3, Some(digest()))).unwrap();
        let mut repository = MemoryPolicyRepository::new();
        block_on(publish_policy(
            &mut repository,
            &identity.trust_anchor(tenant()),
            &first,
        ))
        .unwrap();
        let pointer = identity.sign_pointer(&first).unwrap();
        repository.current = Some(pointer.envelope().to_vec());
        assert_eq!(
            block_on(advance_policy(
                &mut repository,
                &identity,
                &second,
                &ISSUE.parse().unwrap(),
            )),
            Err(ConsumptionPolicyError::Discontinuous)
        );
    }

    #[test]
    fn pointer_advancement_rejects_rollback() {
        let identity = identity();
        let first = identity.sign_policy(&spec(1, None)).unwrap();
        let second = identity
            .sign_policy(&spec(2, Some(*first.digest())))
            .unwrap();
        let mut repository = MemoryPolicyRepository::new();
        block_on(advance_policy(
            &mut repository,
            &identity,
            &first,
            &ISSUE.parse().unwrap(),
        ))
        .unwrap();
        block_on(advance_policy(
            &mut repository,
            &identity,
            &second,
            &ISSUE.parse().unwrap(),
        ))
        .unwrap();
        assert_eq!(
            block_on(advance_policy(
                &mut repository,
                &identity,
                &first,
                &ISSUE.parse().unwrap(),
            )),
            Err(ConsumptionPolicyError::Rollback)
        );
    }

    #[test]
    fn future_beyond_clock_allowance_fails_closed() {
        let identity = identity();
        let future: Timestamp = "2099-01-01T00:00:00Z".parse().unwrap();
        let mut future_spec = spec(1, None);
        future_spec.issued_at = future.clone();
        future_spec.effective_at = future.clone();
        future_spec.assessment_not_before = future.clone();
        let publication = identity.sign_policy(&future_spec).unwrap();
        let policy =
            ConsumptionPolicy::verify(&identity.trust_anchor(tenant()), publication.envelope())
                .unwrap();
        assert_eq!(
            check_clock(&ISSUE.parse().unwrap(), &policy),
            Err(ConsumptionPolicyError::ClockUncertain)
        );
    }

    #[test]
    fn digest_address_is_stable_and_does_not_expose_seed() {
        let identity = identity();
        let publication = identity.sign_policy(&spec(1, None)).unwrap();
        assert_eq!(
            publication.object_key(),
            policy_object_key(&tenant(), publication.digest())
        );
        assert!(!format!("{identity:?}").contains("07"));
        assert_ne!(
            publication.digest().to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
