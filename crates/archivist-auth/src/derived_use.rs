// SPDX-License-Identifier: Apache-2.0

//! The read-time authorization gate for derived episodes.
//!
//! Derived bytes are not a capability.  A consumer must perform a fresh,
//! fail-closed read of the governance state immediately before it receives
//! them.  This module composes the policy pointer and its predecessor chain,
//! the self-verifying episode and assessment, and the scoped approval and
//! revocation records.  There is deliberately no convenience path that
//! returns an episode without this gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;

use archivist_protocol::derivation::FrameBuilder;
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{BlobDigest, TenantId, Timestamp};

use crate::consumption_policy::{
    self, ConsumptionPolicyError, GovernanceTrustAnchor, PolicyRepository,
};
use crate::use_approval::{self, EvaluatedUseApproval, UseApprovalError, UseApprovalRepository};

const EPISODE_DIGEST_LABEL: &str = "episode-v1";
const ASSESSMENT_DIGEST_LABEL: &str = "risk-assessment-v1";
const ASSESSMENT_CLASSIFIER_KIND: &str = "rules";
const ASSESSMENT_CLASSIFIER_VERSION: &str = "1";
const ASSESSMENT_RULE_SET_DIGEST: &str =
    "9b7100cf73896b3c92a5ac299991ffd328f4b1f202ea7b201848691660448150";

const EPISODE_MEMBERS: [&str; 11] = [
    "detector_corpus_digest",
    "episode_digest",
    "episode_version",
    "marker_counts",
    "occurrence_ids",
    "pipeline_id",
    "pipeline_version",
    "pseudonym_counts",
    "pseudonym_key_id",
    "records",
    "tenant_id",
];

const ASSESSMENT_REQUIRED_MEMBERS: [&str; 14] = [
    "assessment_digest",
    "assessment_version",
    "assessed_at",
    "classifier_kind",
    "classifier_version",
    "episode_digest",
    "episode_version",
    "labels",
    "matches",
    "occurrence_ids",
    "outcome",
    "rule_set_digest",
    "severity",
    "tenant_id",
];

const ASSESSMENT_OPTIONAL_MEMBERS: [&str; 1] = ["failure_reason"];

/// The request a derived-content consumer presents to the authorization gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedUseRequest {
    /// The tenant whose episode is being requested.
    pub tenant_id: TenantId,
    /// The self-digest of the episode whose bytes will be returned.
    pub episode_digest: BlobDigest,
    /// The assessment the approval relied on.
    pub assessment_digest: BlobDigest,
    /// The approval granting this particular use.
    pub approval_digest: BlobDigest,
    /// The purpose being exercised.
    pub purpose: String,
    /// The consumer class receiving the bytes.
    pub consumer_class: String,
}

/// The only successful result of [`authorize_derived_use`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedDerivedContent {
    bytes: Vec<u8>,
    episode_digest: BlobDigest,
    assessment_digest: BlobDigest,
    approval_digest: BlobDigest,
}

impl AuthorizedDerivedContent {
    /// The exact canonical episode bytes that passed the complete gate.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the authorization result and return the episode bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The episode digest bound by the successful authorization.
    #[must_use]
    pub const fn episode_digest(&self) -> &BlobDigest {
        &self.episode_digest
    }

    /// The assessment digest bound by the successful authorization.
    #[must_use]
    pub const fn assessment_digest(&self) -> &BlobDigest {
        &self.assessment_digest
    }

    /// The approval digest that authorized the returned bytes.
    #[must_use]
    pub const fn approval_digest(&self) -> &BlobDigest {
        &self.approval_digest
    }
}

/// Read-only storage needed by the use-time gate.
///
/// The policy and approval supertraits retain their existing immutable-write
/// operations for the administrative workflows.  A consumer receives only a
/// shared reference to this trait, so authorization cannot publish, replace,
/// or revoke governance state while it reads.
pub trait DerivedUseRepository: PolicyRepository + UseApprovalRepository {
    /// Read the episode bytes at their requested digest address.
    fn read_episode(
        &self,
        digest: &BlobDigest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, DerivedUseError>> + Send;

    /// Read every assessment indexed for one episode.
    ///
    /// The index is evidence, not authority: every returned record is
    /// independently verified before it can supersede the requested one.
    fn read_assessments_for_episode(
        &self,
        episode_digest: &BlobDigest,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>, DerivedUseError>> + Send;

    /// Read one assessment by its digest-addressed object key.
    fn read_assessment(
        &self,
        digest: &BlobDigest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, DerivedUseError>> + Send;
}

/// Why a derived-use request was denied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerivedUseError {
    /// The current policy pointer or its verified chain denied use.
    Policy(ConsumptionPolicyError),
    /// The signed use approval or revocation denied use.
    Approval(UseApprovalError),
    /// The requested episode was not present.
    MissingEpisode,
    /// The episode was not a canonical, self-verifying v1 episode.
    InvalidEpisode,
    /// The episode's tenant or self-digest did not match the request.
    EpisodeMismatch,
    /// The requested assessment was not present.
    MissingAssessment,
    /// The assessment was not canonical, self-verifying, or supported.
    InvalidAssessment,
    /// The assessment was an explicit unknown or resource-failure result.
    AssessmentFailed,
    /// The assessment did not meet the current policy's freshness bounds.
    AssessmentStale,
    /// A newer valid assessment for this episode superseded the requested one.
    AssessmentSuperseded,
    /// The assessment and requested episode or approval were not the same.
    AssessmentMismatch,
    /// A repository returned an invalid item from the episode assessment index.
    AssessmentIndexCorrupt,
    /// A repository failed without yielding trustworthy evidence.
    RepositoryUnavailable,
}

impl DerivedUseError {
    /// A stable, content-free denial class.
    #[must_use]
    pub const fn class_text(&self) -> &'static str {
        match self {
            Self::Policy(error) => error.class_text(),
            Self::Approval(error) => error.class_text(),
            Self::MissingEpisode => "missing-episode",
            Self::InvalidEpisode => "invalid-episode",
            Self::EpisodeMismatch => "episode-mismatch",
            Self::MissingAssessment => "missing-assessment",
            Self::InvalidAssessment => "invalid-assessment",
            Self::AssessmentFailed => "assessment-failed",
            Self::AssessmentStale => "assessment-stale",
            Self::AssessmentSuperseded => "assessment-superseded",
            Self::AssessmentMismatch => "assessment-mismatch",
            Self::AssessmentIndexCorrupt => "assessment-index-corrupt",
            Self::RepositoryUnavailable => "repository-unavailable",
        }
    }
}

impl fmt::Display for DerivedUseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for DerivedUseError {}

impl From<ConsumptionPolicyError> for DerivedUseError {
    fn from(error: ConsumptionPolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<UseApprovalError> for DerivedUseError {
    fn from(error: UseApprovalError) -> Self {
        Self::Approval(error)
    }
}

/// Read, verify, and authorize one derived episode before returning its bytes.
///
/// The policy pointer and complete predecessor chain are read first on every
/// call.  No policy, assessment, approval, or revocation result is cached by
/// this function.  A successful return proves the exact bytes in the result
/// are the self-verifying episode named by the request and that all current
/// governance checks passed immediately before the return.
///
/// # Errors
///
/// Any missing, malformed, unknown, failed, stale, discontinuous, mismatched,
/// revoked, expired, or clock-uncertain state returns an error and no bytes.
pub async fn authorize_derived_use<R: DerivedUseRepository>(
    repository: &R,
    anchor: &GovernanceTrustAnchor,
    request: &DerivedUseRequest,
    now: &Timestamp,
) -> Result<AuthorizedDerivedContent, DerivedUseError> {
    let inspected = consumption_policy::inspect_policy(repository, anchor, now)
        .await
        .map_err(DerivedUseError::Policy)?;
    if request.tenant_id != *anchor.tenant_id()
        || request.tenant_id != *inspected.policy().tenant_id()
    {
        return Err(DerivedUseError::EpisodeMismatch);
    }

    let episode_bytes = repository
        .read_episode(&request.episode_digest)
        .await?
        .ok_or(DerivedUseError::MissingEpisode)?;
    let episode = parse_episode(&episode_bytes)?;
    if episode.tenant_id != request.tenant_id || episode.digest != request.episode_digest {
        return Err(DerivedUseError::EpisodeMismatch);
    }

    let assessment_bytes = repository
        .read_assessment(&request.assessment_digest)
        .await?
        .ok_or(DerivedUseError::MissingAssessment)?;
    let assessment = parse_assessment(&assessment_bytes)?;
    validate_assessment(&assessment, &episode, inspected.policy(), now)?;

    for candidate_bytes in repository
        .read_assessments_for_episode(&request.episode_digest)
        .await?
    {
        let candidate = parse_assessment(&candidate_bytes)
            .map_err(|_| DerivedUseError::AssessmentIndexCorrupt)?;
        if candidate.tenant_id != request.tenant_id || candidate.episode_digest != episode.digest {
            return Err(DerivedUseError::AssessmentIndexCorrupt);
        }
        if candidate.digest != assessment.digest
            && timestamp_cmp(&candidate.assessed_at, &assessment.assessed_at)?
                == std::cmp::Ordering::Greater
            && assessment_is_usable(&candidate, &episode, inspected.policy(), now).is_ok()
        {
            return Err(DerivedUseError::AssessmentSuperseded);
        }
    }

    let evaluated = use_approval::evaluate_use_approval(
        repository,
        anchor,
        inspected.policy(),
        &request.approval_digest,
        now,
    )
    .await
    .map_err(DerivedUseError::Approval)?;
    validate_approval_scope(&evaluated, request, &assessment)?;

    Ok(AuthorizedDerivedContent {
        bytes: episode_bytes,
        episode_digest: request.episode_digest,
        assessment_digest: request.assessment_digest,
        approval_digest: request.approval_digest,
    })
}

/// Alias named after the returned value for callers that use “bytes” as the
/// storage-layer term.
///
/// # Errors
/// Returns the same fail-closed denial classes as [`authorize_derived_use`].
pub async fn authorize_derived_bytes<R: DerivedUseRepository>(
    repository: &R,
    anchor: &GovernanceTrustAnchor,
    request: &DerivedUseRequest,
    now: &Timestamp,
) -> Result<AuthorizedDerivedContent, DerivedUseError> {
    authorize_derived_use(repository, anchor, request, now).await
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedEpisode {
    tenant_id: TenantId,
    digest: BlobDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedAssessment {
    tenant_id: TenantId,
    episode_digest: BlobDigest,
    digest: BlobDigest,
    assessed_at: Timestamp,
    classifier: String,
    rule_set_digest: BlobDigest,
    outcome: String,
}

fn parse_episode(bytes: &[u8]) -> Result<ParsedEpisode, DerivedUseError> {
    let object = parse_canonical_record(bytes, &EPISODE_MEMBERS, false)
        .map_err(|()| DerivedUseError::InvalidEpisode)?;
    if !has_exact_members(&object, &EPISODE_MEMBERS) {
        return Err(DerivedUseError::InvalidEpisode);
    }
    if object.get("episode_version") != Some(&Value::Int(1))
        || text(&object, "pipeline_id") != Some("redaction")
        || text(&object, "pipeline_version") != Some("1")
    {
        return Err(DerivedUseError::InvalidEpisode);
    }
    let tenant_id = TenantId::parse(text_required(&object, "tenant_id")?)
        .map_err(|_| DerivedUseError::InvalidEpisode)?;
    let digest = BlobDigest::parse(text_required(&object, "episode_digest")?)
        .map_err(|_| DerivedUseError::InvalidEpisode)?;
    let mut unsigned = object.clone();
    let _ = unsigned.remove("episode_digest");
    let mut frame = FrameBuilder::new(EPISODE_DIGEST_LABEL);
    frame.push_bytes(&Value::Object(unsigned).canonical_bytes());
    if sha256::encode_hex(&frame.finish()) != digest.to_hex() {
        return Err(DerivedUseError::InvalidEpisode);
    }
    validate_episode_shape(&object)?;
    Ok(ParsedEpisode { tenant_id, digest })
}

fn validate_episode_shape(object: &Object) -> Result<(), DerivedUseError> {
    validate_episode_identity(object)?;
    validate_episode_records(object)
}

fn validate_episode_identity(object: &Object) -> Result<(), DerivedUseError> {
    for name in ["detector_corpus_digest", "pseudonym_key_id"] {
        BlobDigest::parse(text_required(object, name)?)
            .map_err(|_| DerivedUseError::InvalidEpisode)?;
    }
    let Some(Value::Array(occurrences)) = object.get("occurrence_ids") else {
        return Err(DerivedUseError::InvalidEpisode);
    };
    if occurrences.is_empty() || occurrences.len() > 65_536 {
        return Err(DerivedUseError::InvalidEpisode);
    }
    let mut occurrence_set = BTreeSet::new();
    for occurrence in occurrences {
        let Value::Text(value) = occurrence else {
            return Err(DerivedUseError::InvalidEpisode);
        };
        let digest = BlobDigest::parse(value).map_err(|_| DerivedUseError::InvalidEpisode)?;
        if !occurrence_set.insert(digest) {
            return Err(DerivedUseError::InvalidEpisode);
        }
    }
    validate_counts(
        object.get("marker_counts"),
        &[
            "authorization_header",
            "environment_secret",
            "high_entropy_token",
            "pinned_credential",
            "private_key_block",
        ],
    )?;
    validate_counts(
        object.get("pseudonym_counts"),
        &[
            "absolute_path",
            "email_address",
            "hostname",
            "ip_address",
            "username",
        ],
    )?;
    Ok(())
}

fn validate_episode_records(object: &Object) -> Result<(), DerivedUseError> {
    let Some(Value::Array(records)) = object.get("records") else {
        return Err(DerivedUseError::InvalidEpisode);
    };
    if records.is_empty() || records.len() > 65_536 {
        return Err(DerivedUseError::InvalidEpisode);
    }
    let mut ordinals = BTreeSet::new();
    for record in records {
        let Value::Object(record) = record else {
            return Err(DerivedUseError::InvalidEpisode);
        };
        if record.iter().any(|(key, _)| {
            ![
                "content",
                "ordinal",
                "parent_ordinals",
                "role",
                "source_time",
            ]
            .contains(&key)
        }) || !record.contains("content")
            || !record.contains("ordinal")
            || !record.contains("role")
        {
            return Err(DerivedUseError::InvalidEpisode);
        }
        if !matches!(record.get("content"), Some(Value::Text(content)) if content.len() <= 1_048_576)
            || !matches!(record.get("role"), Some(Value::Text(role)) if matches!(role.as_str(), "assistant" | "system" | "tool" | "user"))
        {
            return Err(DerivedUseError::InvalidEpisode);
        }
        let Some(Value::Int(ordinal)) = record.get("ordinal") else {
            return Err(DerivedUseError::InvalidEpisode);
        };
        if *ordinal < 0 || !ordinals.insert(*ordinal) {
            return Err(DerivedUseError::InvalidEpisode);
        }
        if let Some(source_time) = record.get("source_time")
            && !matches!(source_time, Value::Text(value) if Timestamp::parse(value).is_ok())
        {
            return Err(DerivedUseError::InvalidEpisode);
        }
        if let Some(Value::Array(parents)) = record.get("parent_ordinals") {
            if parents.is_empty() || parents.len() > 64 {
                return Err(DerivedUseError::InvalidEpisode);
            }
            for parent in parents {
                let Value::Int(parent) = parent else {
                    return Err(DerivedUseError::InvalidEpisode);
                };
                if *parent < 0 || *parent >= *ordinal {
                    return Err(DerivedUseError::InvalidEpisode);
                }
            }
        } else if record.contains("parent_ordinals") {
            return Err(DerivedUseError::InvalidEpisode);
        }
    }
    if ordinals
        .iter()
        .copied()
        .enumerate()
        .any(|(expected, actual)| i64::try_from(expected).ok() != Some(actual))
    {
        return Err(DerivedUseError::InvalidEpisode);
    }
    Ok(())
}

fn parse_assessment(bytes: &[u8]) -> Result<ParsedAssessment, DerivedUseError> {
    let object = parse_canonical_record(bytes, &ASSESSMENT_REQUIRED_MEMBERS, true)
        .map_err(|()| DerivedUseError::InvalidAssessment)?;
    if object.len() < ASSESSMENT_REQUIRED_MEMBERS.len()
        || object.len() > ASSESSMENT_REQUIRED_MEMBERS.len() + ASSESSMENT_OPTIONAL_MEMBERS.len()
        || object.iter().any(|(key, _)| {
            !ASSESSMENT_REQUIRED_MEMBERS.contains(&key)
                && !ASSESSMENT_OPTIONAL_MEMBERS.contains(&key)
        })
    {
        return Err(DerivedUseError::InvalidAssessment);
    }
    if object.get("assessment_version") != Some(&Value::Int(1))
        || object.get("episode_version") != Some(&Value::Int(1))
        || text(&object, "classifier_kind") != Some(ASSESSMENT_CLASSIFIER_KIND)
        || text(&object, "classifier_version") != Some(ASSESSMENT_CLASSIFIER_VERSION)
    {
        return Err(DerivedUseError::InvalidAssessment);
    }
    let tenant_id = TenantId::parse(assessment_text_required(&object, "tenant_id")?)
        .map_err(|_| DerivedUseError::InvalidAssessment)?;
    let episode_digest = BlobDigest::parse(assessment_text_required(&object, "episode_digest")?)
        .map_err(|_| DerivedUseError::InvalidAssessment)?;
    let digest = BlobDigest::parse(assessment_text_required(&object, "assessment_digest")?)
        .map_err(|_| DerivedUseError::InvalidAssessment)?;
    let assessed_at = Timestamp::parse(assessment_text_required(&object, "assessed_at")?)
        .map_err(|_| DerivedUseError::InvalidAssessment)?;
    consumption_policy::validate_timestamp(&assessed_at)
        .map_err(|_| DerivedUseError::InvalidAssessment)?;
    let rule_set_digest = BlobDigest::parse(assessment_text_required(&object, "rule_set_digest")?)
        .map_err(|_| DerivedUseError::InvalidAssessment)?;
    let outcome = assessment_text_required(&object, "outcome")?.to_owned();
    if !matches!(
        outcome.as_str(),
        "positive" | "none_detected" | "unknown" | "resource_failure"
    ) {
        return Err(DerivedUseError::InvalidAssessment);
    }
    if object.get("failure_reason").is_some()
        && !matches!(outcome.as_str(), "unknown" | "resource_failure")
    {
        return Err(DerivedUseError::InvalidAssessment);
    }
    let mut unsigned = object.clone();
    let _ = unsigned.remove("assessment_digest");
    let mut frame = FrameBuilder::new(ASSESSMENT_DIGEST_LABEL);
    frame.push_bytes(&Value::Object(unsigned).canonical_bytes());
    if sha256::encode_hex(&frame.finish()) != digest.to_hex() {
        return Err(DerivedUseError::InvalidAssessment);
    }
    Ok(ParsedAssessment {
        tenant_id,
        episode_digest,
        digest,
        assessed_at,
        classifier: format!("{ASSESSMENT_CLASSIFIER_KIND}-v{ASSESSMENT_CLASSIFIER_VERSION}"),
        rule_set_digest,
        outcome,
    })
}

fn validate_assessment(
    assessment: &ParsedAssessment,
    episode: &ParsedEpisode,
    policy: &crate::consumption_policy::ConsumptionPolicy,
    now: &Timestamp,
) -> Result<(), DerivedUseError> {
    assessment_is_usable(assessment, episode, policy, now)
}

fn assessment_is_usable(
    assessment: &ParsedAssessment,
    episode: &ParsedEpisode,
    policy: &crate::consumption_policy::ConsumptionPolicy,
    now: &Timestamp,
) -> Result<(), DerivedUseError> {
    if assessment.tenant_id != *policy.tenant_id() || assessment.episode_digest != episode.digest {
        return Err(DerivedUseError::AssessmentMismatch);
    }
    if !policy
        .allowed_classifier_kinds()
        .any(|kind| kind == assessment.classifier)
        || !policy
            .allowed_rule_set_digests()
            .any(|digest| *digest == assessment.rule_set_digest)
    {
        return Err(DerivedUseError::InvalidAssessment);
    }
    if assessment.rule_set_digest.to_hex() != ASSESSMENT_RULE_SET_DIGEST {
        return Err(DerivedUseError::InvalidAssessment);
    }
    if matches!(assessment.outcome.as_str(), "unknown" | "resource_failure") {
        return Err(DerivedUseError::AssessmentFailed);
    }
    let now_nanos = timestamp_nanos(now)?;
    let assessed_nanos = timestamp_nanos(&assessment.assessed_at)?;
    if assessed_nanos > now_nanos + clock_allowance_nanos() {
        return Err(DerivedUseError::Policy(
            ConsumptionPolicyError::ClockUncertain,
        ));
    }
    if timestamp_cmp(&assessment.assessed_at, policy.assessment_not_before())?
        == std::cmp::Ordering::Less
    {
        return Err(DerivedUseError::AssessmentStale);
    }
    if now_nanos >= assessed_nanos
        && now_nanos - assessed_nanos
            > i128::from(policy.max_assessment_age_seconds()) * 1_000_000_000
    {
        return Err(DerivedUseError::AssessmentStale);
    }
    Ok(())
}

fn validate_approval_scope(
    evaluated: &EvaluatedUseApproval,
    request: &DerivedUseRequest,
    assessment: &ParsedAssessment,
) -> Result<(), DerivedUseError> {
    let approval = evaluated.approval();
    if approval.tenant_id() != &request.tenant_id
        || approval.episode_digest() != &request.episode_digest
        || approval.assessment_digest() != &request.assessment_digest
        || approval.purpose() != request.purpose
        || approval.consumer_class() != request.consumer_class
        || timestamp_cmp(&assessment.assessed_at, approval.issued_at())?
            == std::cmp::Ordering::Greater
    {
        return Err(DerivedUseError::AssessmentMismatch);
    }
    Ok(())
}

fn parse_canonical_record(bytes: &[u8], required: &[&str], optional: bool) -> Result<Object, ()> {
    if !bytes.ends_with(b"\n") || bytes.len() < 2 {
        return Err(());
    }
    let body = &bytes[..bytes.len() - 1];
    let Value::Object(object) = json::parse(body).map_err(|_| ())? else {
        return Err(());
    };
    if Value::Object(object.clone()).canonical_bytes() != body
        || required.iter().any(|member| !object.contains(member))
        || (!optional && object.len() != required.len())
    {
        return Err(());
    }
    Ok(object)
}

fn has_exact_members(object: &Object, members: &[&str]) -> bool {
    object.len() == members.len() && members.iter().all(|member| object.contains(member))
}

fn text<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(value)) => Some(value),
        _ => None,
    }
}

fn text_required<'a>(object: &'a Object, name: &str) -> Result<&'a str, DerivedUseError> {
    text(object, name).ok_or(DerivedUseError::InvalidEpisode)
}

fn assessment_text_required<'a>(
    object: &'a Object,
    name: &str,
) -> Result<&'a str, DerivedUseError> {
    text(object, name).ok_or(DerivedUseError::InvalidAssessment)
}

fn validate_counts(value: Option<&Value>, names: &[&str]) -> Result<(), DerivedUseError> {
    let Some(Value::Object(counts)) = value else {
        return Err(DerivedUseError::InvalidEpisode);
    };
    if !has_exact_members(counts, names) {
        return Err(DerivedUseError::InvalidEpisode);
    }
    if counts
        .iter()
        .any(|(_, value)| !matches!(value, Value::Int(number) if *number >= 0))
    {
        return Err(DerivedUseError::InvalidEpisode);
    }
    Ok(())
}

fn timestamp_nanos(timestamp: &Timestamp) -> Result<i128, DerivedUseError> {
    let (seconds, nanos) =
        consumption_policy::timestamp_value(timestamp).map_err(DerivedUseError::Policy)?;
    Ok(i128::from(seconds) * 1_000_000_000 + i128::from(nanos))
}

fn timestamp_cmp(
    left: &Timestamp,
    right: &Timestamp,
) -> Result<std::cmp::Ordering, DerivedUseError> {
    Ok(timestamp_nanos(left)?.cmp(&timestamp_nanos(right)?))
}

fn clock_allowance_nanos() -> i128 {
    i128::from(consumption_policy::CLOCK_SKEW_ALLOWANCE_SECONDS) * 1_000_000_000
}

/// Empty by default: no policy, episode, assessment, or approval is silently
/// considered authorized by a fresh installation.
#[derive(Clone, Debug, Default)]
pub struct MemoryDerivedUseRepository {
    policies: BTreeMap<BlobDigest, Vec<u8>>,
    current: Option<Vec<u8>>,
    approvals: BTreeMap<BlobDigest, Vec<u8>>,
    revocations: BTreeMap<BlobDigest, Vec<u8>>,
    episodes: BTreeMap<BlobDigest, Vec<u8>>,
    assessments: BTreeMap<BlobDigest, Vec<u8>>,
}

impl MemoryDerivedUseRepository {
    /// Create an empty fail-closed repository.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
            current: None,
            approvals: BTreeMap::new(),
            revocations: BTreeMap::new(),
            episodes: BTreeMap::new(),
            assessments: BTreeMap::new(),
        }
    }

    /// Insert episode bytes for deterministic tests and offline tooling.
    pub fn insert_episode(&mut self, digest: BlobDigest, bytes: Vec<u8>) {
        self.episodes.insert(digest, bytes);
    }

    /// Insert assessment bytes for deterministic tests and offline tooling.
    pub fn insert_assessment(&mut self, digest: BlobDigest, bytes: Vec<u8>) {
        self.assessments.insert(digest, bytes);
    }
}

impl PolicyRepository for MemoryDerivedUseRepository {
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
        publication: &consumption_policy::PolicyPublication,
    ) -> Result<(), ConsumptionPolicyError> {
        match self.policies.get(publication.digest()) {
            None => {
                self.policies
                    .insert(*publication.digest(), publication.envelope().to_vec());
                Ok(())
            }
            Some(existing) if existing == publication.envelope() => Ok(()),
            Some(_) => Err(ConsumptionPolicyError::IntegrityConflict),
        }
    }

    async fn put_current(
        &mut self,
        publication: &consumption_policy::PointerPublication,
    ) -> Result<(), ConsumptionPolicyError> {
        if let Some(existing) = &self.current {
            let Value::Object(object) =
                json::parse(existing).map_err(|_| ConsumptionPolicyError::MalformedRecord)?
            else {
                return Err(ConsumptionPolicyError::MalformedRecord);
            };
            let old = match object.get("policy_version") {
                Some(Value::Int(version)) if *version > 0 => *version,
                _ => return Err(ConsumptionPolicyError::MalformedRecord),
            };
            if i64::try_from(publication.policy_version())
                .ok()
                .is_none_or(|version| version <= old)
            {
                return Err(ConsumptionPolicyError::Rollback);
            }
        }
        self.current = Some(publication.envelope().to_vec());
        Ok(())
    }
}

impl UseApprovalRepository for MemoryDerivedUseRepository {
    async fn read_approval(
        &self,
        digest: &BlobDigest,
    ) -> Result<Option<Vec<u8>>, UseApprovalError> {
        Ok(self.approvals.get(digest).cloned())
    }

    async fn read_revocation(
        &self,
        digest: &BlobDigest,
    ) -> Result<Option<Vec<u8>>, UseApprovalError> {
        Ok(self.revocations.get(digest).cloned())
    }

    async fn put_approval(
        &mut self,
        publication: &crate::use_approval::UseApprovalPublication,
    ) -> Result<(), UseApprovalError> {
        match self.approvals.get(publication.digest()) {
            None => {
                self.approvals
                    .insert(*publication.digest(), publication.envelope().to_vec());
                Ok(())
            }
            Some(existing) if existing == publication.envelope() => Ok(()),
            Some(_) => Err(UseApprovalError::IntegrityConflict),
        }
    }

    async fn put_revocation(
        &mut self,
        publication: &crate::use_approval::UseApprovalRevocationPublication,
    ) -> Result<(), UseApprovalError> {
        match self.revocations.get(publication.approval_digest()) {
            None => {
                self.revocations.insert(
                    *publication.approval_digest(),
                    publication.envelope().to_vec(),
                );
                Ok(())
            }
            Some(existing) if existing == publication.envelope() => Ok(()),
            Some(_) => Err(UseApprovalError::IntegrityConflict),
        }
    }
}

impl DerivedUseRepository for MemoryDerivedUseRepository {
    async fn read_episode(&self, digest: &BlobDigest) -> Result<Option<Vec<u8>>, DerivedUseError> {
        Ok(self.episodes.get(digest).cloned())
    }

    async fn read_assessments_for_episode(
        &self,
        episode_digest: &BlobDigest,
    ) -> Result<Vec<Vec<u8>>, DerivedUseError> {
        let mut result = Vec::new();
        for bytes in self.assessments.values() {
            let Ok(assessment) = parse_assessment(bytes) else {
                result.push(bytes.clone());
                continue;
            };
            if assessment.episode_digest == *episode_digest {
                result.push(bytes.clone());
            }
        }
        Ok(result)
    }

    async fn read_assessment(
        &self,
        digest: &BlobDigest,
    ) -> Result<Option<Vec<u8>>, DerivedUseError> {
        Ok(self.assessments.get(digest).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consumption_policy::{
        ConsumptionPolicy, ConsumptionPolicySpec, DEFAULT_MAX_ASSESSMENT_AGE_SECONDS,
        OfflineGovernanceIdentity, SUPPORTED_CLASSIFIER_KIND, advance_policy, publish_policy,
    };
    use crate::use_approval::revoke_use_approval;
    use crate::use_approval::{UseApprovalSpec, issue_use_approval};
    use archivist_protocol::episode_derivation::{DerivedEpisode, OccurrenceInput, PseudonymKey};
    use archivist_protocol::occurrence_redaction::SourceRecord;
    use archivist_protocol::risk_assessment::RiskAssessment;
    use std::collections::BTreeMap;

    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const NOW: &str = "2026-09-20T01:00:00Z";

    fn tenant() -> TenantId {
        TENANT.parse().unwrap()
    }

    fn identity() -> OfflineGovernanceIdentity {
        OfflineGovernanceIdentity::from_seed([17; 32])
    }

    fn episode() -> DerivedEpisode {
        let records = [SourceRecord {
            role: "user",
            ordinal: 0,
            source_time: None,
            parent_ordinals: &[],
            content: "safe status",
        }];
        let input = [OccurrenceInput {
            occurrence_id: archivist_protocol::vocabulary::OccurrenceId::from_raw([3; 32]),
            records: &records,
        }];
        DerivedEpisode::derive(&tenant(), &PseudonymKey::new(&[9; 32]), &input).unwrap()
    }

    fn policy_spec() -> ConsumptionPolicySpec {
        ConsumptionPolicySpec {
            tenant_id: tenant(),
            policy_version: 1,
            issued_at: "2026-09-20T00:00:00Z".parse().unwrap(),
            effective_at: "2026-09-20T00:00:00Z".parse().unwrap(),
            allowed_classifier_kinds: vec![SUPPORTED_CLASSIFIER_KIND.to_owned()],
            allowed_rule_set_digests: vec![ASSESSMENT_RULE_SET_DIGEST.parse().unwrap()],
            assessment_not_before: "2026-09-20T00:00:00Z".parse().unwrap(),
            max_assessment_age_seconds: DEFAULT_MAX_ASSESSMENT_AGE_SECONDS,
            purpose_to_consumer_classes: BTreeMap::from([(
                "agent-use".to_owned(),
                vec!["agent".to_owned()],
            )]),
            max_approval_lifetime_seconds: 3600,
            predecessor_digest: None,
        }
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

    fn prepared() -> (
        MemoryDerivedUseRepository,
        GovernanceTrustAnchor,
        DerivedUseRequest,
    ) {
        let identity = identity();
        let anchor = identity.trust_anchor(tenant());
        let policy = identity.sign_policy(&policy_spec()).unwrap();
        let now: Timestamp = NOW.parse().unwrap();
        let mut repository = MemoryDerivedUseRepository::new();
        block_on(publish_policy(&mut repository, &anchor, &policy)).unwrap();
        block_on(advance_policy(&mut repository, &identity, &policy, &now)).unwrap();

        let episode = episode();
        let assessment = RiskAssessment::assess(&episode, &"2026-09-20T00:30:00Z".parse().unwrap());
        repository.insert_episode(episode.digest().parse().unwrap(), episode.serialized());
        repository.insert_assessment(
            assessment.digest().parse().unwrap(),
            assessment.serialized(),
        );
        let approval = identity
            .sign_use_approval(
                &UseApprovalSpec {
                    tenant_id: tenant(),
                    episode_digest: episode.digest().parse().unwrap(),
                    assessment_digest: assessment.digest().parse().unwrap(),
                    purpose: "agent-use".to_owned(),
                    consumer_class: "agent".to_owned(),
                    approver: "operator".to_owned(),
                    issued_at: "2026-09-20T00:40:00Z".parse().unwrap(),
                    expires_at: "2026-09-20T01:30:00Z".parse().unwrap(),
                },
                &ConsumptionPolicy::verify(&anchor, policy.envelope()).unwrap(),
            )
            .unwrap();
        block_on(issue_use_approval(&mut repository, &anchor, &approval)).unwrap();
        let request = DerivedUseRequest {
            tenant_id: tenant(),
            episode_digest: episode.digest().parse().unwrap(),
            assessment_digest: assessment.digest().parse().unwrap(),
            approval_digest: approval.digest().to_owned(),
            purpose: "agent-use".to_owned(),
            consumer_class: "agent".to_owned(),
        };
        (repository, anchor, request)
    }

    #[test]
    fn empty_installation_denies_before_returning_bytes() {
        let repository = MemoryDerivedUseRepository::new();
        let identity = identity();
        let request = DerivedUseRequest {
            tenant_id: tenant(),
            episode_digest: "00".repeat(32).parse().unwrap(),
            assessment_digest: "11".repeat(32).parse().unwrap(),
            approval_digest: "22".repeat(32).parse().unwrap(),
            purpose: "agent-use".to_owned(),
            consumer_class: "agent".to_owned(),
        };
        let result = block_on(authorize_derived_use(
            &repository,
            &identity.trust_anchor(tenant()),
            &request,
            &NOW.parse().unwrap(),
        ));
        assert!(matches!(
            result,
            Err(DerivedUseError::Policy(
                ConsumptionPolicyError::MissingPolicy
            ))
        ));
    }

    #[test]
    fn complete_gate_returns_only_the_bound_episode() {
        let (repository, anchor, request) = prepared();
        let authorized = block_on(authorize_derived_use(
            &repository,
            &anchor,
            &request,
            &NOW.parse().unwrap(),
        ))
        .unwrap();
        assert!(!authorized.bytes().is_empty());
        assert_eq!(authorized.episode_digest(), &request.episode_digest);
    }

    #[test]
    fn a_newer_valid_assessment_supersedes_the_approved_one() {
        let (mut repository, anchor, request) = prepared();
        let newer = {
            let episode = episode();
            RiskAssessment::assess(&episode, &"2026-09-20T00:50:00Z".parse().unwrap())
        };
        repository.insert_assessment(newer.digest().parse().unwrap(), newer.serialized());
        let result = block_on(authorize_derived_use(
            &repository,
            &anchor,
            &request,
            &NOW.parse().unwrap(),
        ));
        assert!(matches!(result, Err(DerivedUseError::AssessmentSuperseded)));
    }

    #[test]
    fn tampered_episode_bytes_never_cross_the_return_boundary() {
        let (mut repository, anchor, request) = prepared();
        repository
            .episodes
            .insert(request.episode_digest, b"{}\n".to_vec());
        let result = block_on(authorize_derived_use(
            &repository,
            &anchor,
            &request,
            &NOW.parse().unwrap(),
        ));
        assert!(matches!(result, Err(DerivedUseError::InvalidEpisode)));
    }

    #[test]
    fn expired_and_revoked_approvals_deny_at_the_last_gate() {
        let (repository, anchor, request) = prepared();
        let expired = block_on(authorize_derived_use(
            &repository,
            &anchor,
            &request,
            &"2026-09-20T02:00:00Z".parse().unwrap(),
        ));
        assert!(matches!(
            expired,
            Err(DerivedUseError::Approval(UseApprovalError::Expired))
        ));

        let identity = identity();
        let mut revoked_repository = repository;
        block_on(revoke_use_approval(
            &mut revoked_repository,
            &anchor,
            &identity,
            &request.approval_digest,
            &"2026-09-20T00:50:00Z".parse().unwrap(),
        ))
        .unwrap();
        let revoked = block_on(authorize_derived_use(
            &revoked_repository,
            &anchor,
            &request,
            &NOW.parse().unwrap(),
        ));
        assert!(matches!(
            revoked,
            Err(DerivedUseError::Approval(UseApprovalError::Revoked))
        ));
    }
}
