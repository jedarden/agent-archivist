// SPDX-License-Identifier: Apache-2.0

//! The storage capability probe: it observes what a backend actually
//! supports — conditional create, multipart commit/abort, the stored
//! checksum form, versioning, server-side encryption — and reduces those
//! observations fail-closed onto the [`crate::capability`] model, caching
//! only advisory results (plan Section 8, Phase 2).
//!
//! # Nothing here grants authority
//!
//! Every output of this module is an observation about a backend at a
//! moment in time, never a grant: no method anywhere takes authority from
//! a report, and the failure class for acting on a missing capability
//! remains [`StorageErrorKind::CapabilityUnavailable`](crate::error::StorageErrorKind::CapabilityUnavailable).
//! A store's [`crate::raw_write::RawWriteStore::capabilities`] may serve a
//! cached report from [`CapabilityCache`]; the cache bounds how stale that
//! advice may be and discards it entirely on expiry — it never promotes
//! advice into a guarantee.
//!
//! # Without mutating arbitrary keys
//!
//! Probing is a deployment-time activity under its own identity: the
//! ingestion replica never probes (its `capabilities()` call "never
//! performs I/O against tenant data", plan Section 7.7). A
//! [`CapabilitySource`] that needs a write-shaped instrument may aim it
//! only at a [`ProbeKey`] — a key derived into the reserved
//! `tenants/<tenant>/v1/probe/` namespace, outside the audited raw prefix
//! the `inventory-v1` freeze enumerates — and never at arbitrary or
//! caller-supplied text. The bucket-shaped facts (versioning, encryption
//! configuration) come from read-only configuration surfaces, and
//! multipart support is established by beginning and aborting the probe's
//! own session, which stores nothing visible at any key. Probe objects a
//! write-shaped instrument did leave behind are named by [`ProbeKey`]s
//! under the probe namespace, so a deployment can expire them with one
//! lifecycle rule without touching tenant content.
//!
//! # Unknown is never stronger
//!
//! [`ProbeFindings::capabilities`] reduces each fact independently: an
//! established fact reports its observed value, and *any* unestablished
//! fact — never attempted, unreachable backend, refused instrument —
//! reduces to the weakest value the model has for it:
//!
//! ```text
//! fact                     established            unestablished
//! conditional_create       supported              unavailable
//! stored_checksum          observed form          unavailable
//! versioning               enabled | disabled     unknown
//! server_side_encryption   verified               unavailable
//! ```
//!
//! The weaker value is always the safe one: `unavailable` conditional
//! create routes the writer to deterministic overwrite (STO-006),
//! versioning `unknown` fails the backup-and-restore precondition closed
//! instead of assuming either state, and a checksum or encryption report
//! never claims more than the probe saw. There is no input shape that
//! turns an unestablished fact into a stronger claim — the reduction is
//! total and reads only the established arm.
//!
//! Multipart commit/abort is the one primitive that cannot degrade, so it
//! is absent from the reported model (see [`crate::capability`]): the
//! probe reports it as the profile-support question instead —
//! [`ProbeFindings::profile_supported`] is false when the probe could not
//! establish a full begin/write/commit/abort session, and such a backend
//! is not a supported profile (plan Section 7.7).
//!
//! # Verification-manifest evidence
//!
//! [`CapabilityReport::canonical_bytes`] renders one probe run as RFC 8785
//! canonical JSON under the pinned `archivist.capability-report/v1`
//! schema, and [`CapabilityReport::report_digest`] binds those bytes as
//! `sha256:<hex>` — the form the verification manifest's
//! `capability_reports` evidence entry records, with the probed backend
//! named in the entry's `profiles` list. The report carries the model
//! tokens, the method each fact was probed with, and the reason every
//! unestablished fact is unproven, so two runs that differ in any of those
//! produce different digests: honesty is captured in evidence, not
//! asserted in prose.

use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use archivist_protocol::json::{Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{TenantId, Timestamp};

use crate::capability::{
    ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
};

/// The schema token pinned in every capability report's canonical bytes.
pub const REPORT_SCHEMA: &str = "archivist.capability-report/v1";

/// Why a probe input is not a value of its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeInputError {
    /// The text does not match the type's grammar (length, charset, shape).
    NotCanonical,
}

impl std::fmt::Display for ProbeInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCanonical => write!(f, "value does not match the canonical grammar"),
        }
    }
}

impl std::error::Error for ProbeInputError {}

/// A key in the reserved probe namespace: `tenants/<tenant>/v1/probe/<label>`.
///
/// This is the only key shape a write-shaped probe instrument may target.
/// The namespace sits under the tenant's provisioning but *outside* the
/// `v1/raw/` prefix, so a probe write can never collide with a content
/// key, never enter an `inventory-v1` freeze, and never depend on
/// caller-supplied text: the label is validated into a closed grammar and
/// the rest of the key is derived from the typed [`TenantId`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeKey(String);

impl ProbeKey {
    /// Derive a probe key from a tenant and a validated probe label.
    ///
    /// The label is 1–64 ASCII characters of `[a-z0-9-]`, starting with a
    /// letter or digit — content-free by grammar, so a probe key can never
    /// carry or resemble tenant data.
    ///
    /// # Errors
    /// [`ProbeInputError::NotCanonical`] for a label outside that grammar.
    pub fn new(tenant: &TenantId, label: &str) -> Result<Self, ProbeInputError> {
        let bytes = label.as_bytes();
        let head_ok = bytes
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let tail_ok = bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
        if !head_ok || !tail_ok || bytes.len() > 64 {
            return Err(ProbeInputError::NotCanonical);
        }
        Ok(Self(format!(
            "tenants/{}/v1/probe/{label}",
            tenant.as_str()
        )))
    }

    /// The full derived key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProbeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of the backend profile a probe run observed (for example
/// `minio-reference`, `b2`, `armor-s3`).
///
/// Bounded and content-free (1–64 characters, starting alphanumeric, then
/// `[A-Za-z0-9 ._()/-]`) so the name can travel through verification
/// manifests and logs without carrying prose or injection payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendProfile(String);

impl BackendProfile {
    /// Adopt `text` as a profile name.
    ///
    /// # Errors
    /// [`ProbeInputError::NotCanonical`] for anything outside the grammar.
    pub fn parse(text: &str) -> Result<Self, ProbeInputError> {
        let valid = |b: &u8| {
            b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'(' | b')' | b'/' | b'-')
        };
        if text.is_empty()
            || text.len() > 64
            || !text.as_bytes()[0].is_ascii_alphanumeric()
            || !text.bytes().all(|b| valid(&b))
        {
            return Err(ProbeInputError::NotCanonical);
        }
        Ok(Self(text.to_owned()))
    }

    /// The name exactly as adopted.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BackendProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The instrument a probe used for one fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProbeMethod {
    /// A read-only bucket-configuration surface (versioning, encryption).
    BucketConfiguration,
    /// A write-shaped instrument aimed at a [`ProbeKey`] only.
    ProbeKeyWrite,
    /// A begin/write/commit/abort session the probe owns end to end.
    MultipartSession,
    /// The probe never attempted this fact.
    NotProbed,
}

impl ProbeMethod {
    /// Every token, in declaration order.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        &[
            "bucket_configuration",
            "probe_key_write",
            "multipart_session",
            "not_probed",
        ]
    }

    /// The report token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::BucketConfiguration => "bucket_configuration",
            Self::ProbeKeyWrite => "probe_key_write",
            Self::MultipartSession => "multipart_session",
            Self::NotProbed => "not_probed",
        }
    }
}

/// Why a probe could not establish a fact.
///
/// Every reason reduces the fact to the same weaker model value; the
/// reason exists for the evidence record, so an operator can tell "the
/// probe never ran" from "the backend refused the instrument".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnprovenReason {
    /// The probe never attempted this fact.
    NotProbed,
    /// The probe could not reach the backend, or its identity lacks the
    /// permission the instrument needs.
    ProbeUnavailable,
    /// The instrument ran and the backend refused or failed it.
    BackendRefused,
    /// The backend does not expose the surface the instrument reads.
    MethodUnsupported,
}

impl UnprovenReason {
    /// Every token, in declaration order.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        &[
            "not_probed",
            "probe_unavailable",
            "backend_refused",
            "method_unsupported",
        ]
    }

    /// The report token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::NotProbed => "not_probed",
            Self::ProbeUnavailable => "probe_unavailable",
            Self::BackendRefused => "backend_refused",
            Self::MethodUnsupported => "method_unsupported",
        }
    }
}

/// What one instrument established about one fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactResult<T> {
    /// The probe positively established the fact with this value.
    Established(T),
    /// The probe could not establish the fact, for this reason.
    Unproven(UnprovenReason),
}

/// One probed fact: the instrument used and what it established.
///
/// `T` is the observed value — `()` for the facts whose established form
/// is a single known answer (conditional create, multipart, encryption),
/// [`ChecksumForm`] and [`VersioningObservation`] for the facts with a
/// choice of observed values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fact<T> {
    /// The instrument the probe used (or would have used).
    pub method: ProbeMethod,
    /// What the instrument established.
    pub result: FactResult<T>,
}

impl<T> Fact<T> {
    /// The instrument positively established `value`.
    #[must_use]
    pub fn established(method: ProbeMethod, value: T) -> Self {
        Self {
            method,
            result: FactResult::Established(value),
        }
    }

    /// The instrument ran but could not establish the fact.
    #[must_use]
    pub fn unproven(method: ProbeMethod, reason: UnprovenReason) -> Self {
        Self {
            method,
            result: FactResult::Unproven(reason),
        }
    }

    /// The probe never attempted this fact.
    #[must_use]
    pub fn not_probed() -> Self {
        Self {
            method: ProbeMethod::NotProbed,
            result: FactResult::Unproven(UnprovenReason::NotProbed),
        }
    }

    /// The established value, when there is one.
    #[must_use]
    pub fn established_value(&self) -> Option<&T> {
        match &self.result {
            FactResult::Established(value) => Some(value),
            FactResult::Unproven(_) => None,
        }
    }

    /// Whether the fact is established.
    #[must_use]
    pub fn is_established(&self) -> bool {
        matches!(self.result, FactResult::Established(_))
    }
}

/// The stored-checksum form a probe observed, before reduction onto
/// [`StoredChecksum`]. The model's `unavailable` is the *unproven* arm,
/// never an observed value, so a backend that reports no checksum is
/// indistinguishable here from one nobody could observe — both reduce to
/// `unavailable`, which is the honest claim in both cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChecksumForm {
    /// The backend verifies SHA-256 over stored bytes.
    Sha256,
    /// The backend verifies MD5 over stored bytes.
    Md5,
    /// The backend maintains some other provider-specific checksum.
    ProviderSpecific,
}

impl ChecksumForm {
    /// The report token (the model's own token for the observed form).
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Md5 => "md5",
            Self::ProviderSpecific => "provider_specific",
        }
    }
}

/// The versioning state a probe observed, before reduction onto
/// [`VersioningState`]. The model's `unknown` is the *unproven* arm: only
/// a positive observation of the bucket's versioning configuration
/// reports `enabled` or `disabled`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VersioningObservation {
    /// Versioning is enabled on the bucket.
    Enabled,
    /// Versioning is disabled (never enabled, or explicitly suspended).
    Disabled,
}

impl VersioningObservation {
    /// The report token (the model's own token for the observed state).
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

/// The raw findings of one probe run against one backend profile.
///
/// A plain value by design: a [`CapabilitySource`] produces it, nothing
/// else can, and [`ProbeFindings::capabilities`] reduces it onto the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeFindings {
    /// Atomic create-if-absent verified on a probe key.
    pub conditional_create: Fact<()>,
    /// A full begin/write/commit/abort session verified end to end.
    pub multipart_commit_abort: Fact<()>,
    /// The stored-checksum form the backend maintains.
    pub stored_checksum: Fact<ChecksumForm>,
    /// The bucket's versioning state.
    pub versioning: Fact<VersioningObservation>,
    /// At-rest encryption verified on a probe write.
    pub server_side_encryption: Fact<()>,
}

impl ProbeFindings {
    /// The findings of a run that established nothing — every fact
    /// [`UnprovenReason::NotProbed`].
    #[must_use]
    pub fn unprobed() -> Self {
        Self {
            conditional_create: Fact::not_probed(),
            multipart_commit_abort: Fact::not_probed(),
            stored_checksum: Fact::not_probed(),
            versioning: Fact::not_probed(),
            server_side_encryption: Fact::not_probed(),
        }
    }

    /// Whether the backend is a supported profile: the probe established a
    /// full multipart commit/abort session, the one primitive
    /// [`crate::raw_write::RawWriteStore`] cannot degrade on.
    #[must_use]
    pub fn profile_supported(&self) -> bool {
        self.multipart_commit_abort.is_established()
    }

    /// Reduce the findings fail-closed onto the capability model: every
    /// unestablished fact reports the weaker value, never a stronger one.
    #[must_use]
    pub fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            conditional_create: if self.conditional_create.is_established() {
                ConditionalCreate::Supported
            } else {
                ConditionalCreate::Unavailable
            },
            stored_checksum: match self.stored_checksum.established_value() {
                Some(ChecksumForm::Sha256) => StoredChecksum::Sha256,
                Some(ChecksumForm::Md5) => StoredChecksum::Md5,
                Some(ChecksumForm::ProviderSpecific) => StoredChecksum::ProviderSpecific,
                None => StoredChecksum::Unavailable,
            },
            versioning: match self.versioning.established_value() {
                Some(VersioningObservation::Enabled) => VersioningState::Enabled,
                Some(VersioningObservation::Disabled) => VersioningState::Disabled,
                None => VersioningState::Unknown,
            },
            server_side_encryption: if self.server_side_encryption.is_established() {
                EncryptionState::Verified
            } else {
                EncryptionState::Unavailable
            },
        }
    }

    /// The facts object of the report JSON: one member per fact with its
    /// method, status, observed value (or `null`), and reason (or `null`).
    fn to_value(self) -> Object {
        let mut facts = Object::new();
        let _ = facts.insert(
            "conditional_create",
            fact_value(
                &self.conditional_create,
                self.conditional_create
                    .is_established()
                    .then_some("supported"),
            ),
        );
        let _ = facts.insert(
            "multipart_commit_abort",
            fact_value(
                &self.multipart_commit_abort,
                self.multipart_commit_abort
                    .is_established()
                    .then_some("verified"),
            ),
        );
        let _ = facts.insert(
            "stored_checksum",
            fact_value(
                &self.stored_checksum,
                self.stored_checksum
                    .established_value()
                    .map(|form| form.token()),
            ),
        );
        let _ = facts.insert(
            "versioning",
            fact_value(
                &self.versioning,
                self.versioning
                    .established_value()
                    .map(|state| state.token()),
            ),
        );
        let _ = facts.insert(
            "server_side_encryption",
            fact_value(
                &self.server_side_encryption,
                self.server_side_encryption
                    .is_established()
                    .then_some("verified"),
            ),
        );
        facts
    }
}

/// One fact's report object: `method`, `reason`, `status`, `value` — the
/// same four members for every fact and every outcome, so a consumer can
/// navigate any report uniformly.
fn fact_value<T>(fact: &Fact<T>, value: Option<&'static str>) -> Value {
    let (status, reason) = match fact.result {
        FactResult::Established(_) => ("established", None),
        FactResult::Unproven(reason) => ("unproven", Some(reason.token())),
    };
    let mut object = Object::new();
    let _ = object.insert("method", Value::Text(fact.method.token().to_owned()));
    let _ = object.insert(
        "reason",
        reason.map_or(Value::Null, |token| Value::Text(token.to_owned())),
    );
    let _ = object.insert("status", Value::Text(status.to_owned()));
    let _ = object.insert(
        "value",
        value.map_or(Value::Null, |token| Value::Text(token.to_owned())),
    );
    Value::Object(object)
}

/// The backend seam the probe runs against: one method, total by contract.
///
/// A concrete adapter (the portable S3 adapter is the first) implements
/// this over its backend's configuration surfaces and its own probe keys.
/// The contract's teeth:
///
/// - **Total.** `probe` never fails; a run that could not establish a
///   fact returns it [`Unproven`] with the reason, so the probe always
///   yields an honest report instead of an error a caller might swallow.
/// - **Own identity.** The implementation runs under a deployment
///   identity granted for probing — never the ingestion writer, whose
///   provisioning covers the raw prefix only.
/// - **Own keys.** Any write-shaped instrument targets a [`ProbeKey`] and
///   nothing else; bucket facts come from read-only configuration
///   surfaces; multipart probing begins and aborts one session the probe
///   owns.
///
/// [`Unproven`]: FactResult::Unproven
pub trait CapabilitySource {
    /// Gather one run's findings for this backend.
    fn probe(&self) -> impl Future<Output = ProbeFindings> + Send;
}

/// Probe a [`CapabilitySource`] once and bind the findings to a report.
///
/// The one entry point a deployment's probe job needs: run the source,
/// stamp the findings with the profile name and the observation time, and
/// produce the report the advisory cache and the verification manifest
/// consume. Total — the report is honest however little the source could
/// establish.
pub async fn observe<S: CapabilitySource + ?Sized>(
    source: &S,
    profile: BackendProfile,
    observed_at: Timestamp,
) -> CapabilityReport {
    let findings = source.probe().await;
    CapabilityReport::new(profile, observed_at, findings)
}

/// The evidence record of one probe run: what was observed, with which
/// instruments, at what time, on which backend profile.
///
/// `canonical_bytes` and `report_digest` make the record embeddable in a
/// verification manifest: the manifest stores the digest and the profile
/// name, and the bytes travel as the run's evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityReport {
    profile: BackendProfile,
    observed_at: Timestamp,
    findings: ProbeFindings,
}

impl CapabilityReport {
    /// Bind findings to a profile and an observation time.
    #[must_use]
    pub fn new(profile: BackendProfile, observed_at: Timestamp, findings: ProbeFindings) -> Self {
        Self {
            profile,
            observed_at,
            findings,
        }
    }

    /// The probed backend profile.
    #[must_use]
    pub fn profile(&self) -> &BackendProfile {
        &self.profile
    }

    /// When the run observed the backend.
    #[must_use]
    pub fn observed_at(&self) -> &Timestamp {
        &self.observed_at
    }

    /// The run's raw findings.
    #[must_use]
    pub fn findings(&self) -> &ProbeFindings {
        &self.findings
    }

    /// The fail-closed reduction of the findings onto the model.
    #[must_use]
    pub fn capabilities(&self) -> StoreCapabilities {
        self.findings.capabilities()
    }

    /// Whether the probed backend is a supported profile.
    #[must_use]
    pub fn profile_supported(&self) -> bool {
        self.findings.profile_supported()
    }

    /// The report as a protocol JSON value (members end up in canonical
    /// order in the bytes regardless of insertion order).
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut root = Object::new();
        let _ = root.insert("schema", Value::Text(REPORT_SCHEMA.to_owned()));
        let _ = root.insert("profile", Value::Text(self.profile.as_str().to_owned()));
        let _ = root.insert(
            "observed_at",
            Value::Text(self.observed_at.as_str().to_owned()),
        );
        let _ = root.insert(
            "capabilities",
            capabilities_value(self.findings.capabilities()),
        );
        let _ = root.insert("facts", Value::Object(self.findings.to_value()));
        let _ = root.insert(
            "profile_supported",
            Value::Bool(self.findings.profile_supported()),
        );
        Value::Object(root)
    }

    /// The RFC 8785 canonical bytes of the report — the bytes the digest
    /// binds.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.to_value().canonical_bytes()
    }

    /// The report digest in the verification manifest's evidence form:
    /// `sha256:<64 lowercase hex characters>` over [`Self::canonical_bytes`].
    #[must_use]
    pub fn report_digest(&self) -> String {
        format!(
            "sha256:{}",
            sha256::encode_hex(&sha256::digest(&self.canonical_bytes()))
        )
    }
}

/// The `capabilities` object of the report JSON: the reduced model, in its
/// own tokens.
fn capabilities_value(capabilities: StoreCapabilities) -> Value {
    let mut object = Object::new();
    let _ = object.insert(
        "conditional_create",
        Value::Text(capabilities.conditional_create.token().to_owned()),
    );
    let _ = object.insert(
        "server_side_encryption",
        Value::Text(capabilities.server_side_encryption.token().to_owned()),
    );
    let _ = object.insert(
        "stored_checksum",
        Value::Text(capabilities.stored_checksum.token().to_owned()),
    );
    let _ = object.insert(
        "versioning",
        Value::Text(capabilities.versioning.token().to_owned()),
    );
    Value::Object(object)
}

/// One advisory cache entry: the reduced report plus the traceability a
/// consumer needs to tie an advisory read back to its evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedReport {
    capabilities: StoreCapabilities,
    profile_supported: bool,
    observed_at: Timestamp,
    report_digest: String,
}

impl CachedReport {
    /// The advisory capability report.
    #[must_use]
    pub fn capabilities(&self) -> StoreCapabilities {
        self.capabilities
    }

    /// Whether the cached run established the profile as supported.
    #[must_use]
    pub fn profile_supported(&self) -> bool {
        self.profile_supported
    }

    /// When the underlying run observed the backend (wall-clock evidence
    /// time — freshness against the TTL is tracked separately, on the
    /// monotonic clock of the cache).
    #[must_use]
    pub fn observed_at(&self) -> &Timestamp {
        &self.observed_at
    }

    /// The digest binding the run's canonical report bytes.
    #[must_use]
    pub fn report_digest(&self) -> &str {
        &self.report_digest
    }
}

/// What a cache read can honestly say.
///
/// There is no arm that serves an aged-out report: once the TTL passes,
/// the strong values are unreadable from the cache, and every accessor
/// degrades to [`StoreCapabilities::unprobed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CurrentCapabilities {
    /// A probe report inside its freshness window.
    Current(CachedReport),
    /// Nothing may be assumed: no probe has ever run, or the last report
    /// aged out.
    Unprobed {
        /// Whether an aged-out report *exists* — a re-probe signal for
        /// operators; nothing from that report is readable here.
        expired: bool,
    },
}

impl CurrentCapabilities {
    /// The advisory capabilities: the cached reduction, or the unprobed
    /// report — the weakest value of every fact — when nothing is current.
    #[must_use]
    pub fn capabilities(&self) -> StoreCapabilities {
        match self {
            Self::Current(cached) => cached.capabilities,
            Self::Unprobed { .. } => StoreCapabilities::unprobed(),
        }
    }

    /// Whether a current report establishes the profile as supported; a
    /// cache with nothing current never claims support, and — because
    /// profile support is the one non-degradable fact — also never claims
    /// the opposite: an unsupported verdict belongs to a report, not to
    /// the absence of one.
    #[must_use]
    pub fn profile_supported(&self) -> bool {
        match self {
            Self::Current(cached) => cached.profile_supported,
            Self::Unprobed { .. } => false,
        }
    }
}

/// The advisory cache a store serves [`crate::raw_write::RawWriteStore::
/// capabilities`] from.
///
/// Only a [`CapabilityReport`] can enter — there is no way to cache
/// capabilities nobody observed — and every entry is stamped with the
/// monotonic time it was remembered. Reads inside the TTL serve the
/// cached report; reads outside it (and reads of an empty cache) report
/// [`CurrentCapabilities::Unprobed`], whose capabilities are the unprobed
/// report. A cache can therefore hold advice that grows stale, but can
/// never serve a strong claim that outlived its observation — the
/// "unknown never becomes a stronger guarantee" rule applied to time.
///
/// The entry is replaced wholesale on every `remember`, so a refresh that
/// established less than the last run simply becomes the cached truth:
/// downgrading is data, never a special case.
pub struct CapabilityCache {
    ttl: Duration,
    entry: Mutex<Option<(CachedReport, Instant)>>,
}

impl CapabilityCache {
    /// A cache whose entries stay advisory for `ttl` of monotonic time.
    ///
    /// A zero TTL is accepted and means every read is
    /// [`CurrentCapabilities::Unprobed`] — the cache becomes an honest
    /// "nothing is current" stub.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entry: Mutex::new(None),
        }
    }

    /// Replace whatever the cache held with this report, stamped at
    /// `now`.
    ///
    /// # Panics
    /// Panics only if the entry mutex is poisoned — a concurrent panic
    /// while holding it, which is itself a bug.
    pub fn remember(&self, report: &CapabilityReport, now: Instant) {
        let cached = CachedReport {
            capabilities: report.capabilities(),
            profile_supported: report.profile_supported(),
            observed_at: report.observed_at().clone(),
            report_digest: report.report_digest(),
        };
        *self.entry.lock().expect("capability cache mutex") = Some((cached, now));
    }

    /// The current advisory state at `now`.
    ///
    /// Freshness is strict: a report remembered exactly `ttl` ago is
    /// already expired, so a caller never serves advice on its last
    /// breath.
    ///
    /// # Panics
    /// Panics only if the entry mutex is poisoned — a concurrent panic
    /// while holding it, which is itself a bug.
    #[must_use]
    pub fn current(&self, now: Instant) -> CurrentCapabilities {
        let guard = self.entry.lock().expect("capability cache mutex");
        match guard.as_ref() {
            None => CurrentCapabilities::Unprobed { expired: false },
            Some((cached, stamped)) => {
                if now.saturating_duration_since(*stamped) < self.ttl {
                    CurrentCapabilities::Current(cached.clone())
                } else {
                    CurrentCapabilities::Unprobed { expired: true }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use archivist_protocol::vocabulary::GrammarError;

    use super::{
        BackendProfile, CapabilityCache, CapabilityReport, CapabilitySource, ChecksumForm,
        CurrentCapabilities, Fact, FactResult, ProbeFindings, ProbeInputError, ProbeKey,
        ProbeMethod, UnprovenReason, VersioningObservation, observe,
    };
    use crate::capability::{
        ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
    };

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";

    fn tenant() -> archivist_protocol::vocabulary::TenantId {
        archivist_protocol::vocabulary::TenantId::parse(TENANT).unwrap()
    }

    fn observed_at() -> archivist_protocol::vocabulary::Timestamp {
        archivist_protocol::vocabulary::Timestamp::parse("2026-09-13T12:00:00Z").unwrap()
    }

    fn profile() -> BackendProfile {
        BackendProfile::parse("minio-reference").unwrap()
    }

    /// Findings where every fact is established, the fully-supported
    /// profile.
    fn fully_established() -> ProbeFindings {
        ProbeFindings {
            conditional_create: Fact::established(ProbeMethod::ProbeKeyWrite, ()),
            multipart_commit_abort: Fact::established(ProbeMethod::MultipartSession, ()),
            stored_checksum: Fact::established(ProbeMethod::ProbeKeyWrite, ChecksumForm::Sha256),
            versioning: Fact::established(
                ProbeMethod::BucketConfiguration,
                VersioningObservation::Enabled,
            ),
            server_side_encryption: Fact::established(ProbeMethod::ProbeKeyWrite, ()),
        }
    }

    /// A no-dependency executor for the mock futures, following the
    /// multipart-module pattern: every mock future completes without
    /// pending, so first-poll-until-ready terminates.
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

    /// A source that always reports the same findings.
    struct StaticSource(ProbeFindings);

    impl CapabilitySource for StaticSource {
        async fn probe(&self) -> ProbeFindings {
            self.0
        }
    }

    fn all_unproven_reasons() -> [UnprovenReason; 4] {
        [
            UnprovenReason::NotProbed,
            UnprovenReason::ProbeUnavailable,
            UnprovenReason::BackendRefused,
            UnprovenReason::MethodUnsupported,
        ]
    }

    fn all_methods() -> [ProbeMethod; 4] {
        [
            ProbeMethod::BucketConfiguration,
            ProbeMethod::ProbeKeyWrite,
            ProbeMethod::MultipartSession,
            ProbeMethod::NotProbed,
        ]
    }

    #[test]
    fn probe_key_grammar_and_namespace() {
        let key = ProbeKey::new(&tenant(), "capability-probe").unwrap();
        assert_eq!(
            key.as_str(),
            "tenants/0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b/v1/probe/capability-probe"
        );
        // Outside the audited raw prefix, inside the tenant's namespace.
        assert!(key.as_str().contains("/v1/probe/"));
        assert!(!key.as_str().contains("/v1/raw/"));

        assert!(ProbeKey::new(&tenant(), "a").is_ok());
        assert!(ProbeKey::new(&tenant(), "0first-digit").is_ok());
        assert!(ProbeKey::new(&tenant(), &"a".repeat(64)).is_ok());
        assert!(ProbeKey::new(&tenant(), "").is_err());
        assert!(ProbeKey::new(&tenant(), &"a".repeat(65)).is_err());
        assert!(ProbeKey::new(&tenant(), "-leads-with-dash").is_err());
        assert!(ProbeKey::new(&tenant(), "has space").is_err());
        assert!(ProbeKey::new(&tenant(), "UpperCase").is_err());
        assert!(ProbeKey::new(&tenant(), "slash/name").is_err());
    }

    #[test]
    fn backend_profile_grammar() {
        assert_eq!(
            BackendProfile::parse("minio-reference").unwrap().as_str(),
            "minio-reference"
        );
        assert!(BackendProfile::parse("B2 (prod)").is_ok());
        assert!(BackendProfile::parse("armor_s3.v2").is_ok());
        assert!(BackendProfile::parse("").is_err());
        assert!(BackendProfile::parse(".hidden").is_err());
        assert!(BackendProfile::parse(&"x".repeat(65)).is_err());
        assert!(BackendProfile::parse(&"x".repeat(64)).is_ok());
        assert!(BackendProfile::parse("has\ttab").is_err());
        assert!(BackendProfile::parse("éclair").is_err());
    }

    #[test]
    fn unprobed_findings_reduce_to_the_unprobed_report() {
        let findings = ProbeFindings::unprobed();
        assert_eq!(findings.capabilities(), StoreCapabilities::unprobed());
        assert_eq!(
            findings.capabilities().conditional_create,
            ConditionalCreate::Unavailable
        );
        assert_eq!(
            findings.capabilities().stored_checksum,
            StoredChecksum::Unavailable
        );
        assert_eq!(findings.capabilities().versioning, VersioningState::Unknown);
        assert_eq!(
            findings.capabilities().server_side_encryption,
            EncryptionState::Unavailable
        );
        assert!(!findings.profile_supported());
    }

    #[test]
    fn no_unproven_shape_becomes_a_stronger_guarantee() {
        // For every method and every unproven reason, each fact reduces to
        // its weakest model value. This is the acceptance rule stated as
        // an exhaustive check: no instrument, no failure reason, and no
        // combination of unestablished facts can produce a stronger
        // report than unprobed().
        for method in all_methods() {
            for reason in all_unproven_reasons() {
                let findings = ProbeFindings {
                    conditional_create: Fact::unproven(method, reason),
                    multipart_commit_abort: Fact::unproven(method, reason),
                    stored_checksum: Fact::unproven(method, reason),
                    versioning: Fact::unproven(method, reason),
                    server_side_encryption: Fact::unproven(method, reason),
                };
                assert_eq!(
                    findings.capabilities(),
                    StoreCapabilities::unprobed(),
                    "method {method:?} + reason {reason:?} produced a stronger report"
                );
                assert!(!findings.profile_supported());
            }
        }
    }

    #[test]
    fn established_facts_reduce_to_their_observed_values() {
        let findings = fully_established();
        let capabilities = findings.capabilities();
        assert_eq!(
            capabilities.conditional_create,
            ConditionalCreate::Supported
        );
        assert_eq!(capabilities.stored_checksum, StoredChecksum::Sha256);
        assert_eq!(capabilities.versioning, VersioningState::Enabled);
        assert_eq!(
            capabilities.server_side_encryption,
            EncryptionState::Verified
        );
        assert!(findings.profile_supported());

        // Each checksum form keeps its own model value; a disabled bucket
        // reports disabled, not unknown — both are positive observations.
        for (form, expected) in [
            (ChecksumForm::Sha256, StoredChecksum::Sha256),
            (ChecksumForm::Md5, StoredChecksum::Md5),
            (
                ChecksumForm::ProviderSpecific,
                StoredChecksum::ProviderSpecific,
            ),
        ] {
            let mut findings = fully_established();
            findings.stored_checksum = Fact::established(ProbeMethod::ProbeKeyWrite, form);
            assert_eq!(findings.capabilities().stored_checksum, expected);
        }
        let mut disabled = fully_established();
        disabled.versioning = Fact::established(
            ProbeMethod::BucketConfiguration,
            VersioningObservation::Disabled,
        );
        assert_eq!(
            disabled.capabilities().versioning,
            VersioningState::Disabled
        );
    }

    #[test]
    fn profile_support_requires_established_multipart() {
        for method in all_methods() {
            for reason in all_unproven_reasons() {
                let mut findings = fully_established();
                findings.multipart_commit_abort = Fact::unproven(method, reason);
                assert!(
                    !findings.profile_supported(),
                    "unproven multipart ({method:?} / {reason:?}) cannot be a supported profile"
                );
                // The other facts stay honest even when the profile is
                // unsupported: reduction is per fact.
                assert_eq!(
                    findings.capabilities().conditional_create,
                    ConditionalCreate::Supported
                );
            }
        }
    }

    #[test]
    fn fact_constructors_report_method_status_and_value() {
        let established = Fact::established(ProbeMethod::BucketConfiguration, ());
        assert!(established.is_established());
        assert_eq!(established.method, ProbeMethod::BucketConfiguration);
        assert!(matches!(established.result, FactResult::Established(())));

        let unproven =
            Fact::<()>::unproven(ProbeMethod::ProbeKeyWrite, UnprovenReason::BackendRefused);
        assert!(!unproven.is_established());
        assert!(unproven.established_value().is_none());

        let not_probed = Fact::<()>::not_probed();
        assert_eq!(not_probed.method, ProbeMethod::NotProbed);
        assert!(matches!(
            not_probed.result,
            FactResult::Unproven(UnprovenReason::NotProbed)
        ));
    }

    #[test]
    fn report_is_canonical_digestible_and_evidence_shaped() {
        let report = CapabilityReport::new(profile(), observed_at(), fully_established());
        let bytes = report.canonical_bytes();

        // Canonical form is stable across construction and matches the
        // pinned schema.
        let again = CapabilityReport::new(profile(), observed_at(), fully_established());
        assert_eq!(again.canonical_bytes(), bytes);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains(r#""schema":"archivist.capability-report/v1""#));
        // RFC 8785 sorts members: the top-level member tokens must appear in
        // the canonical bytes in ascending byte order — checked on the bytes
        // themselves, position by position, not on a reparsed value (whose
        // Object keeps sorted order by construction and would hide a defect).
        let top_level = [
            "capabilities",
            "facts",
            "observed_at",
            "profile",
            "profile_supported",
            "schema",
        ];
        let positions: Vec<usize> = top_level
            .iter()
            .map(|member| {
                text.find(&format!("\"{member}\":"))
                    .unwrap_or_else(|| panic!("member {member} missing from canonical bytes"))
            })
            .collect();
        let mut sorted_positions = positions.clone();
        sorted_positions.sort_unstable();
        assert_eq!(
            positions, sorted_positions,
            "top-level members must be canonically ordered"
        );

        // The bytes parse as protocol JSON and survive a canonical
        // round-trip unchanged — the digest binds exactly these bytes.
        let parsed = archivist_protocol::json::parse(&bytes).unwrap();
        assert_eq!(parsed.canonical_bytes(), bytes);

        // The digest is the manifest's evidence form: sha256:<64 hex>.
        let digest = report.report_digest();
        assert!(digest.starts_with("sha256:"));
        let hex = &digest["sha256:".len()..];
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );

        // Content: the reduced model, the profile-support verdict, the
        // observation time.
        assert!(text.contains(r#""profile":"minio-reference""#));
        assert!(text.contains(r#""observed_at":"2026-09-13T12:00:00Z""#));
        assert!(text.contains(r#""profile_supported":true"#));
        assert!(text.contains(r#""conditional_create":"supported""#));
        assert!(text.contains(r#""versioning":"enabled""#));
    }

    #[test]
    fn report_digest_distinguishes_honesty_states() {
        let established = CapabilityReport::new(profile(), observed_at(), fully_established());
        // Same run shape, one fact unproven for a *recorded reason*: a
        // different report, a different digest — the reason travels in
        // evidence.
        let mut refused = fully_established();
        refused.versioning = Fact::unproven(
            ProbeMethod::BucketConfiguration,
            UnprovenReason::BackendRefused,
        );
        let refused = CapabilityReport::new(profile(), observed_at(), refused);
        let mut unsupported = fully_established();
        unsupported.multipart_commit_abort = Fact::unproven(
            ProbeMethod::MultipartSession,
            UnprovenReason::ProbeUnavailable,
        );
        let unsupported = CapabilityReport::new(profile(), observed_at(), unsupported);

        assert_ne!(established.report_digest(), refused.report_digest());
        assert_ne!(established.report_digest(), unsupported.report_digest());
        assert_ne!(refused.report_digest(), unsupported.report_digest());
        assert!(!unsupported.profile_supported());
        // The unproven fact weakens only itself.
        assert_eq!(refused.capabilities().versioning, VersioningState::Unknown);
        assert_eq!(
            refused.capabilities().conditional_create,
            ConditionalCreate::Supported
        );
    }

    #[test]
    fn observe_binds_source_findings_into_a_report() {
        let source = StaticSource(fully_established());
        let report = block_on(observe(&source, profile(), observed_at()));
        assert_eq!(report.profile(), &profile());
        assert_eq!(report.findings(), &fully_established());
        assert_eq!(report.capabilities(), fully_established().capabilities());
        assert!(report.profile_supported());
    }

    #[test]
    fn cache_serves_fresh_advice_and_discards_expired_strength() {
        let cache = CapabilityCache::new(Duration::from_mins(1));
        let start = std::time::Instant::now();

        // Nothing probed yet: no support claim, weakest capabilities.
        let CurrentCapabilities::Unprobed { expired } = cache.current(start) else {
            panic!("empty cache must read unprobed");
        };
        assert!(!expired);
        assert_eq!(
            cache.current(start).capabilities(),
            StoreCapabilities::unprobed()
        );
        assert!(!cache.current(start).profile_supported());

        // A supported profile enters; reads inside the TTL serve it.
        let report = CapabilityReport::new(profile(), observed_at(), fully_established());
        cache.remember(&report, start);
        let fresh = cache.current(start + Duration::from_secs(59));
        let CurrentCapabilities::Current(cached) = &fresh else {
            panic!("fresh read must be current");
        };
        assert_eq!(cached.capabilities(), fully_established().capabilities());
        assert!(cached.profile_supported());
        assert_eq!(cached.observed_at().as_str(), "2026-09-13T12:00:00Z");
        assert_eq!(cached.report_digest(), report.report_digest());
        assert_eq!(fresh.capabilities(), fully_established().capabilities());

        // At exactly the TTL the advice is already gone — and with it the
        // strong values: an expired cache cannot serve Supported/Enabled.
        let stale = cache.current(start + Duration::from_mins(1));
        let CurrentCapabilities::Unprobed { expired } = stale else {
            panic!("expired read must be unprobed");
        };
        assert!(expired);
        assert_eq!(stale.capabilities(), StoreCapabilities::unprobed());
        assert!(!stale.profile_supported());
    }

    #[test]
    fn cache_refresh_replaces_wholesale_and_can_only_downgrade_by_data() {
        let cache = CapabilityCache::new(Duration::from_mins(1));
        let start = std::time::Instant::now();

        cache.remember(
            &CapabilityReport::new(profile(), observed_at(), fully_established()),
            start,
        );
        // A later run that established less simply becomes the truth; the
        // downgrade needs no special case because it travels in the
        // findings.
        let mut weaker = fully_established();
        weaker.conditional_create =
            Fact::unproven(ProbeMethod::ProbeKeyWrite, UnprovenReason::BackendRefused);
        let weaker_report = CapabilityReport::new(profile(), observed_at(), weaker);
        cache.remember(&weaker_report, start + Duration::from_secs(10));

        let read = cache.current(start + Duration::from_secs(20));
        let CurrentCapabilities::Current(cached) = &read else {
            panic!("refresh must be current");
        };
        assert_eq!(
            cached.capabilities().conditional_create,
            ConditionalCreate::Unavailable
        );
        assert_eq!(cached.capabilities().versioning, VersioningState::Enabled);
        assert!(cached.profile_supported());
        assert_eq!(cached.report_digest(), weaker_report.report_digest());
    }

    #[test]
    fn zero_ttl_cache_is_an_honest_nothing_current_stub() {
        let cache = CapabilityCache::new(Duration::ZERO);
        let start = std::time::Instant::now();
        cache.remember(
            &CapabilityReport::new(profile(), observed_at(), fully_established()),
            start,
        );
        let read = cache.current(start);
        let CurrentCapabilities::Unprobed { expired } = read else {
            panic!("zero-TTL entry must expire immediately");
        };
        assert!(expired);
        assert_eq!(read.capabilities(), StoreCapabilities::unprobed());
    }

    #[test]
    fn method_and_reason_tokens_are_closed_sets() {
        assert_eq!(ProbeMethod::tokens().len(), 4);
        assert_eq!(UnprovenReason::tokens().len(), 4);
        for (method, value) in ProbeMethod::tokens().iter().zip([
            ProbeMethod::BucketConfiguration,
            ProbeMethod::ProbeKeyWrite,
            ProbeMethod::MultipartSession,
            ProbeMethod::NotProbed,
        ]) {
            assert_eq!(*method, value.token());
        }
        for (reason, value) in UnprovenReason::tokens().iter().zip([
            UnprovenReason::NotProbed,
            UnprovenReason::ProbeUnavailable,
            UnprovenReason::BackendRefused,
            UnprovenReason::MethodUnsupported,
        ]) {
            assert_eq!(*reason, value.token());
        }
    }

    #[test]
    fn probe_inputs_fail_closed_with_the_shared_error() {
        let err = ProbeKey::new(&tenant(), "BAD").unwrap_err();
        assert_eq!(err, ProbeInputError::NotCanonical);
        assert_eq!(
            err.to_string(),
            "value does not match the canonical grammar"
        );
        assert!(matches!(
            BackendProfile::parse("").unwrap_err(),
            ProbeInputError::NotCanonical
        ));
    }

    #[test]
    fn unprobed_report_is_the_constant_every_failure_lands_on() {
        // The unprobed constructor and the probe reduction agree exactly,
        // so "cache expired", "never probed", and "probe ran and saw
        // nothing" are the same safe answer for a caller.
        let reference = StoreCapabilities {
            conditional_create: ConditionalCreate::Unavailable,
            stored_checksum: StoredChecksum::Unavailable,
            versioning: VersioningState::Unknown,
            server_side_encryption: EncryptionState::Unavailable,
        };
        assert_eq!(StoreCapabilities::unprobed(), reference);
        assert_eq!(ProbeFindings::unprobed().capabilities(), reference);
    }

    /// The vocabulary parse helpers this module's tests rely on fail
    /// closed — a guard so a grammar loosening upstream is noticed here.
    #[test]
    fn test_fixtures_still_parse() {
        assert!(matches!(
            archivist_protocol::vocabulary::TenantId::parse("not-a-tenant"),
            Err(GrammarError::NotCanonical)
        ));
    }
}
