// SPDX-License-Identifier: Apache-2.0

//! The community qualification runner: the operator-side engine that
//! executes the community qualification kit's three legs in order over
//! the workspace's public seams and files the honest outcome
//! ([`QualificationReport`]).
//!
//! The kit (`docs/notes/community-qualification-kit.md`) defines what a
//! run executes; this module is the engine that executes it. The
//! credential-free synthetic suite
//! (`crates/archivist-storage-s3/tests/storage_compatibility.rs`) proves
//! the portable contract against an S3-shaped test double, and project
//! automation never runs a community profile — the live binding and the
//! physical observation are exactly the two things the operator supplies.
//! The runner sits between those poles: generic over the three public
//! seams ([`ProbeWriteBackend`], [`RawWriteBackend`],
//! [`VersionAuditBackend`]), it drives them in the kit's Section 5 order
//! and records what actually happened.
//!
//! # The three legs, no subset waived
//!
//! SP-003 requires the complete per-profile suite. The runner walks the
//! legs in order — the capability probe first, the seven write-path
//! scenarios second, the enumeration leg third — and every leg and every
//! scenario lands in the report as one closed outcome: executed and
//! matching, executed and contradicting the declared capabilities,
//! errored (the backend could not answer — the honest unknown), or not
//! reached (an earlier leg already failed the run).
//! [`ScenarioOutcome::NotReached`] is a recorded outcome, never a silent
//! skip: the report structurally carries all three legs and all eight
//! scenario observations, and any contradiction, any error, or any
//! unreached scenario renders a [`RunVerdict::Unqualified`]. A partial
//! run qualifies nothing.
//!
//! # The physical half
//!
//! The write-shaped store cannot read, so the physical facts the report
//! line cites — object counts, version identities, stored checksum tags —
//! come through the one authority with list grants, the audit/restore
//! identity's versions listing, frozen over the run's tenant raw scope.
//! Those counts and the STO-009 [`NoncurrentVersionReport`] are two
//! renderings of one listing, so the report line and the audit can never
//! disagree. A frozen history the declared axes cannot explain (a version
//! count under a declared axis, a checksum form the report does not
//! declare) fails the run. Where the versioning axis is not established
//! the audit is refused (`noncurrent_audit=refused`) and no version-id
//! claim is rendered — unknown never strengthens.
//!
//! # The record's redaction (SP-006)
//!
//! The transcript a contribution attaches carries the capability report's
//! canonical bytes and digest, the `profile_supported` answer, the report
//! line, every leg's exit status, and the suite revision — and it renders
//! only after [`redaction_violations`] finds no forbidden field: no
//! scheme prefix, no address shape, no address-shaped string, no tailnet
//! hostname, and none of the run's own configured endpoint, bucket, or
//! reference values. [`RunTranscript::render`] fails closed on any
//! violation; the transcript itself is attached to the contribution,
//! never committed.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::vocabulary::{
    AttestationId, BlobDigest, ClientId, HarnessId, OccurrenceId, SessionHash, StorageOutcome,
    StorageProfile, TenantId, Timestamp,
};
use archivist_storage::audit_restore::{InventoryKey, InventoryScope};
use archivist_storage::capability::{
    ConditionalCreate, StoreCapabilities, StoredChecksum, VersioningState,
};
use archivist_storage::commit::commit_manifest;
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::lifecycle_audit::{
    FrozenVersionListing, KeyVersions, NoncurrentVersionReport, VersionedEntry, VersionedPage,
    freeze_version_listing,
};
use archivist_storage::metadata::{Observation, StorageVersionId};
use archivist_storage::probe::{BackendProfile, ChecksumForm, ProbeFindings};
use archivist_storage::raw_write::{ManifestKey, PartNumber, RawWriteStore};

use crate::lifecycle_audit::{S3LifecycleAuditStore, VersionAuditBackend};
use crate::probe::{ProbeWriteBackend, S3ProbeSource, classify_checksum};
use crate::raw_write::{RawWriteBackend, S3RawWriteStore};

// Content-safe reason literals, one static sentence per failure site —
// the same discipline the sibling stores keep. No failure reason ever
// carries runtime text, so no endpoint, hostname, or credential can
// reach a report or a transcript through this module.
const REASON_ABORT: &str =
    "multipart-abort repeated an error instead of reporting idempotent cleanup";
const REASON_ATTESTATION: &str =
    "an attestation observed a branch the declared capabilities do not predict";
const REASON_CHECKSUM: &str =
    "a stored checksum tag contradicts the stored-checksum form the report declares";
const REASON_CONCURRENT: &str =
    "concurrent-writers observed a branch the declared capabilities do not predict";
const REASON_CONFLICT: &str =
    "read-capable-conflict observed a branch the declared capabilities do not predict";
const REASON_COUNT: &str =
    "the frozen physical history contradicts the versioning axis the report declares";
const REASON_DUPLICATE: &str =
    "duplicate-request observed a branch the declared capabilities do not predict";
const REASON_ENUM_FAULTS: &str = "the enumeration contract accepted an injected fault";
const REASON_ENUM_LIVE: &str = "the live control-prefix enumeration violated the freeze contract";
const REASON_ERRORED: &str = "the backend could not answer a write-path scenario";
const REASON_MULTIPART: &str =
    "multipart-commit observed a branch the declared capabilities do not predict";
const REASON_OVERWRITE: &str =
    "equivalent-overwrite observed a branch the declared capabilities do not predict";
const REASON_PHYSICAL: &str =
    "the run's own physical history could not be frozen through the audit identity";
const REASON_PROFILE: &str =
    "the backend is not a supported profile: multipart commit/abort was not established";
const REASON_PROBE_UNKNOWN: &str = "the capability probe could not establish any fact";
const REASON_UNREACHED: &str = "an earlier scenario already stopped the leg";

/// The kit's Section 4 fixture tenant, fixed for every run so a
/// transcript is reproducible and purgeable by the identity set alone.
/// The identity set is never substituted with production values.
pub const FIXTURE_TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
/// The fixture client identity.
pub const FIXTURE_CLIENT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f";
/// The fixture harness identity.
pub const FIXTURE_HARNESS: &str = "synthetic";
/// The fixture session hash.
pub const FIXTURE_SESSION: &str =
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
/// The attestation scenario's source occurrence.
pub const FIXTURE_OCCURRENCE_SOURCE: &str =
    "0011223344556677001122334455667700112233445566770011223344556677";
/// The duplicate-request scenario's occurrence.
pub const FIXTURE_OCCURRENCE_DUPLICATE: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
/// The equivalent-overwrite scenario's occurrence.
pub const FIXTURE_OCCURRENCE_OVERWRITE: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
/// The concurrent-writers scenario's occurrence.
pub const FIXTURE_OCCURRENCE_CONCURRENT: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
/// The read-capable-conflict scenario's occurrence.
pub const FIXTURE_OCCURRENCE_CONFLICT: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
/// The origin uploader's attestation identity.
pub const FIXTURE_ATTESTATION_ORIGIN: &str =
    "9988776655443322110088776655443322110088776655443322110088776655";
/// The relay uploader's attestation identity.
pub const FIXTURE_ATTESTATION_RELAY: &str =
    "8877665544332211008877665544332211008877665544332211008877665544";
/// The fixture blob digest (`zstd-v1`).
pub const FIXTURE_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The scenario labels, in execution order. Seven scenarios, eight
/// observations: the attestation scenario drives two independent keys,
/// and the report line renders each.
const SCENARIO_LABELS: [&str; 8] = [
    "duplicate-request",
    "equivalent-overwrite",
    "concurrent-writers",
    "read-capable-conflict",
    "multipart-abort",
    "multipart-commit",
    "origin-attestation",
    "relay-attestation",
];

/// The sentinel an unversioned backend's listing hands back for a
/// version it never named — a parseable identity by grammar, but not one
/// a run may claim, so the physical histories filter it out.
const NULL_VERSION: &str = "null";

/// The three legs, in the kit's execution order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LegId {
    /// The capability probe: the five-axis reduction the report binds.
    Probe,
    /// The seven write-path scenarios through the store's public commit
    /// paths, plus the physical observations the report line cites.
    WritePath,
    /// The enumeration fault-injection set and the live control-prefix
    /// enumeration.
    Enumeration,
}

impl LegId {
    /// Every leg, in execution order.
    #[must_use]
    pub fn all() -> [Self; 3] {
        [Self::Probe, Self::WritePath, Self::Enumeration]
    }

    /// The closed token the transcript renders.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::WritePath => "write-path",
            Self::Enumeration => "enumeration",
        }
    }
}

/// A leg's exit status: the transcript records one per leg, and no leg
/// is ever absent from a report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegExit {
    /// The leg executed end to end and every check matched.
    Complete,
    /// The leg executed and observed behavior its declared capabilities
    /// do not predict — the run files the honest negative (SP-005).
    Failed,
    /// The leg could not complete: the backend could not answer. The
    /// honest unknown, and an `unqualified` record with the reason.
    Unknown,
    /// The leg never executed because an earlier leg already stopped the
    /// run. Recorded, never silent — a partial run qualifies nothing.
    NotReached,
}

impl LegExit {
    /// The closed token the transcript renders.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::NotReached => "not_reached",
        }
    }
}

/// One leg's recorded outcome: its exit and, when the exit is not
/// [`LegExit::Complete`], the fixed reason sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegObservation {
    /// Which leg this observation records.
    pub leg: LegId,
    /// How the leg exited.
    pub exit: LegExit,
    /// The fixed reason sentence for anything but a complete leg.
    pub reason: Option<&'static str>,
}

impl LegObservation {
    /// Record a leg that completed.
    #[must_use]
    pub const fn complete(leg: LegId) -> Self {
        Self {
            leg,
            exit: LegExit::Complete,
            reason: None,
        }
    }

    /// Record a leg's non-complete exit with its fixed reason.
    #[must_use]
    pub const fn stopped(leg: LegId, exit: LegExit, reason: &'static str) -> Self {
        Self {
            leg,
            exit,
            reason: Some(reason),
        }
    }
}

/// What one scenario observed, as a closed outcome — there is no
/// "skipped": a scenario the leg never reached records
/// [`ScenarioOutcome::NotReached`], and the run cannot qualify with one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScenarioOutcome {
    /// Executed; the observed branch and the physical history match what
    /// the declared capabilities predict.
    Matched,
    /// Executed; the observed branch or physical history contradicts the
    /// declared capabilities — the run files the honest negative.
    Contradicted,
    /// Executed as far as the backend answering; the backend could not,
    /// so the honest outcome is the unknown one.
    Errored,
    /// Never executed: an earlier scenario already stopped the leg.
    NotReached,
}

impl ScenarioOutcome {
    /// The closed token the transcript renders.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Contradicted => "contradicted",
            Self::Errored => "errored",
            Self::NotReached => "not_reached",
        }
    }
}

/// One scenario's observation: the closed outcome and the logical
/// branch the store reported, when it reported one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScenarioObservation {
    /// The scenario label, as the report line renders it.
    pub label: &'static str,
    /// The closed outcome.
    pub outcome: ScenarioOutcome,
    /// The logical branch the store reported, when the scenario's
    /// decisive call returned one.
    pub branch: Option<StorageOutcome>,
    /// The fixed reason sentence for anything but a matched scenario.
    pub reason: Option<&'static str>,
}

/// The physical history one scenario left behind, as the frozen
/// versions listing observed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalHistory {
    /// How many physical versions the key carries.
    pub count: usize,
    /// The backend's version identities, when the run may claim them —
    /// empty where the versioning axis is not established or the
    /// listing named no identity.
    pub version_ids: Vec<String>,
}

/// How the run resolved: the SP-005 fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunVerdict {
    /// Every leg completed, the profile is supported, and every scenario
    /// matched its declared branch — the run may file a qualified record,
    /// subject to the maintainer's acceptance.
    Qualified,
    /// Something contradicted, errored, or went unreached; the reason
    /// sentence says which. The honest negative SP-005 accepts.
    Unqualified(&'static str),
}

/// The report one run produces: the capability matrix the probe bound,
/// every leg's exit, every scenario's observation, the physical
/// histories, and the STO-009 audit — the evidence a record cites.
#[derive(Clone, Debug)]
pub struct QualificationReport {
    profile_key: String,
    findings: ProbeFindings,
    profile_supported: bool,
    capabilities: StoreCapabilities,
    capability_report_bytes: Vec<u8>,
    capability_report_digest: String,
    legs: BTreeMap<LegId, LegObservation>,
    scenarios: Vec<ScenarioObservation>,
    physical_versions: BTreeMap<&'static str, PhysicalHistory>,
    noncurrent: Option<NoncurrentVersionReport>,
    verdict: RunVerdict,
}

impl QualificationReport {
    /// The registry key the run files under.
    #[must_use]
    pub fn profile_key(&self) -> &str {
        &self.profile_key
    }

    /// The probe's findings, as observed — the record's `capability`
    /// table must be their reduction (SP-007).
    #[must_use]
    pub const fn findings(&self) -> &ProbeFindings {
        &self.findings
    }

    /// Whether the probe established a full multipart session — the
    /// profile-support fact (SP-004).
    #[must_use]
    pub const fn profile_supported(&self) -> bool {
        self.profile_supported
    }

    /// The declared capabilities the write path ran under: the probe's
    /// five-axis reduction.
    #[must_use]
    pub const fn capabilities(&self) -> &StoreCapabilities {
        &self.capabilities
    }

    /// The capability report's canonical RFC 8785 JSON bytes — the
    /// transcript evidence.
    #[must_use]
    pub fn capability_report_bytes(&self) -> &[u8] {
        &self.capability_report_bytes
    }

    /// The capability report's `sha256:<hex>` digest over the canonical
    /// bytes.
    #[must_use]
    pub fn capability_report_digest(&self) -> &str {
        &self.capability_report_digest
    }

    /// Every leg's observation, in execution order.
    #[must_use]
    pub fn legs(&self) -> [&LegObservation; 3] {
        let all = LegId::all();
        all.map(|leg| &self.legs[&leg])
    }

    /// One leg's observation.
    #[must_use]
    pub fn leg(&self, leg: LegId) -> &LegObservation {
        &self.legs[&leg]
    }

    /// Every scenario's observation, in execution order — always all
    /// eight slots, whatever happened.
    #[must_use]
    pub fn scenarios(&self) -> &[ScenarioObservation] {
        &self.scenarios
    }

    /// The physical history per scenario label, as the frozen listing
    /// observed it.
    #[must_use]
    pub fn physical_versions(&self) -> &BTreeMap<&'static str, PhysicalHistory> {
        &self.physical_versions
    }

    /// The STO-009 audit, when the versioning axis was established;
    /// `None` renders as `noncurrent_audit=refused`.
    #[must_use]
    pub const fn noncurrent(&self) -> Option<&NoncurrentVersionReport> {
        self.noncurrent.as_ref()
    }

    /// How the run resolved.
    #[must_use]
    pub const fn verdict(&self) -> &RunVerdict {
        &self.verdict
    }

    /// The report line: the exact grammar the in-repo suite renders,
    /// with every scenario observation present and the noncurrent audit
    /// (or its refusal) trailing.
    #[must_use]
    pub fn render_line(&self) -> String {
        let rendered = self
            .scenarios
            .iter()
            .filter_map(|observation| {
                let history = self.physical_versions.get(observation.label)?;
                Some(format!(
                    "{}:{}:{:?}",
                    observation.label, history.count, history.version_ids
                ))
            })
            .collect::<Vec<_>>()
            .join(",");
        let noncurrent = match &self.noncurrent {
            Some(audit) => format!("noncurrent_audit=[{}]", render_safe_audit(audit)),
            None => "noncurrent_audit=refused".to_owned(),
        };
        format!(
            "storage-compatibility profile={} conditional_create={} stored_checksum={} versioning={} server_side_encryption={} physical_versions=[{}] {}",
            self.profile_key,
            self.capabilities.conditional_create.token(),
            self.capabilities.stored_checksum.token(),
            self.capabilities.versioning.token(),
            self.capabilities.server_side_encryption.token(),
            rendered,
            noncurrent,
        )
    }
}

/// Render the audit counters without putting a tenant prefix or a raw object
/// key into the qualification report. The underlying audit retains those
/// values for the operator's private physical evidence; the report and its
/// transcript are the printable record and must stay free of account, tenant,
/// client, session, and occurrence identifiers.
fn render_safe_audit(audit: &NoncurrentVersionReport) -> String {
    let scope = match audit.scope() {
        InventoryScope::TenantRaw(_) => "tenant-raw",
        InventoryScope::TenantControl(_) => "tenant-control",
        InventoryScope::TenantCatalog(_) => "tenant-catalog",
        InventoryScope::TenantDerived(_) => "tenant-derived",
    };
    let mut line = format!(
        "noncurrent-version-audit scope={scope} keys={} versions={} noncurrent={} retained_bytes={} guidance={}",
        audit.distinct_keys(),
        audit.total_versions(),
        audit.noncurrent_versions(),
        audit.noncurrent_bytes(),
        archivist_storage::lifecycle_audit::NONCURRENT_VERSION_GUIDANCE,
    );
    if audit.fullest_key().is_some() {
        use std::fmt::Write as _;
        let _ = write!(
            line,
            " fullest_key=redacted fullest_noncurrent={}",
            audit.fullest_noncurrent()
        );
    }
    line
}

/// The run's fixed inputs: what the operator's driver supplies besides
/// the live seams.
#[derive(Clone, Debug)]
pub struct RunPlan<'a> {
    /// The registry key the run files under (`tools/storage-profiles.toml`).
    pub profile_key: &'a str,
    /// The repository revision the executed driver was built from — the
    /// record's `suite_revision`. The runner cannot know this; the
    /// driver states it and the transcript pins it.
    pub suite_revision: &'a str,
    /// Whether the write identity's grant can read back existing-object
    /// evidence. The kit's branch table keys on this; it is the driver's
    /// own provisioning, declared — never guessed.
    pub read_capable: bool,
    /// The instant the run stamps its observations with.
    pub observed_at: Timestamp,
}

/// Execute one qualification run: the three legs, in order, no subset
/// waived, over the live seams the driver composed.
///
/// The composition is the one the deployment's serve path performs — the
/// probe source over the probe authority's instrument, the raw-write
/// store with the probe's declared capabilities, and the lifecycle-audit
/// store over the offline-restore identity — and this engine adds only
/// the ordering, the branch table, and the honest recording.
///
/// # Panics
/// Never at runtime by contract: the fixture identity set is fixed
/// compile-time text the kit publishes, so the typed key constructors'
/// parses cannot fail. If kit text and grammar ever diverge, the parse
/// failure is the alarm.
pub async fn run<P, B, A>(
    plan: &RunPlan<'_>,
    tenant: &TenantId,
    probe: &S3ProbeSource<P>,
    store: &Arc<S3RawWriteStore<B>>,
    audit: &S3LifecycleAuditStore<A>,
) -> QualificationReport
where
    P: ProbeWriteBackend + Sync,
    B: RawWriteBackend + Clone + Sync,
    A: VersionAuditBackend + Clone + Sync,
{
    // ---------- Leg 1: the capability probe ----------
    let profile = BackendProfile::parse(plan.profile_key)
        .unwrap_or_else(|_| BackendProfile::parse("unnamed").expect("static grammar"));
    let report = archivist_storage::probe::observe(probe, profile, plan.observed_at.clone()).await;
    let findings = *report.findings();
    let capabilities = report.capabilities();
    let profile_supported = report.profile_supported();
    let capability_report_bytes = report.canonical_bytes();
    let capability_report_digest = report.report_digest();

    let probe_exit = if profile_supported || probe_established_something(&findings) {
        LegObservation::complete(LegId::Probe)
    } else {
        LegObservation::stopped(LegId::Probe, LegExit::Unknown, REASON_PROBE_UNKNOWN)
    };

    let mut legs = BTreeMap::new();
    legs.insert(LegId::Probe, probe_exit);
    for leg in [LegId::WritePath, LegId::Enumeration] {
        legs.insert(
            leg,
            LegObservation::stopped(leg, LegExit::NotReached, REASON_PROFILE),
        );
    }
    let mut assembled = QualificationReport {
        profile_key: plan.profile_key.to_owned(),
        findings,
        profile_supported,
        capabilities,
        capability_report_bytes,
        capability_report_digest,
        legs,
        scenarios: unwalked_scenarios(REASON_PROFILE),
        physical_versions: BTreeMap::new(),
        noncurrent: None,
        verdict: RunVerdict::Unqualified(REASON_PROFILE),
    };

    // SP-004: multipart is the profile question, not an axis to
    // negotiate — a backend that cannot begin/write/commit/abort is not
    // a supported profile at all, and the run ends here with the honest
    // negative. The same early stop applies when the probe could
    // establish nothing: there is no honest write path to declare.
    if !profile_supported || assembled.legs[&LegId::Probe].exit == LegExit::Unknown {
        assembled.verdict = RunVerdict::Unqualified(match assembled.legs[&LegId::Probe].reason {
            Some(reason) => reason,
            None => REASON_PROFILE,
        });
        return assembled;
    }

    // ---------- Leg 2: the write-path exercises ----------
    // The kit's Section 5 step 2: the store the deployment would build —
    // the same composition the driver handed in, now carrying exactly the
    // capabilities this run's own probe observed. The probe instrument is
    // not idempotent against its namespace, so the binding happens here,
    // from this run's single observe — a caller that pre-bound a report
    // from an earlier probe would grade against stale facts. The audit
    // half carries the same report, so the STO-009 measurement the run
    // files is gated by the same single versioning fact.
    let declared = Arc::new(store.rebased(capabilities));
    let audit = &audit.rebased(capabilities);
    let walked = walk_write_path(plan, tenant, &declared, audit).await;
    assembled.physical_versions = walked.physical;
    assembled.noncurrent = walked.noncurrent;
    assembled.scenarios = walked.scenarios;
    let write_exit = match walked.failure {
        Some((exit, reason)) => LegObservation::stopped(LegId::WritePath, exit, reason),
        None => LegObservation::complete(LegId::WritePath),
    };
    assembled.legs.insert(LegId::WritePath, write_exit);

    // ---------- Leg 3: the enumeration set ----------
    // The kit runs the legs in order and a failed leg stops the run, but
    // the enumeration leg's portable fault half is evidence either way:
    // it exercises the freeze contract, not the backend. It runs unless
    // the write path could not complete at all.
    let enumeration = if walked
        .failure
        .is_some_and(|(exit, _)| exit == LegExit::Unknown)
    {
        LegObservation::stopped(LegId::Enumeration, LegExit::NotReached, REASON_ERRORED)
    } else {
        walk_enumeration(tenant, audit).await
    };
    assembled.legs.insert(LegId::Enumeration, enumeration);

    assembled.verdict = resolve_verdict(&assembled);
    assembled
}

/// Whether the probe established at least one fact — the difference
/// between an honest report over an unhelpful backend and a probe that
/// never really ran.
fn probe_established_something(findings: &ProbeFindings) -> bool {
    [
        findings.conditional_create.is_established(),
        findings.multipart_commit_abort.is_established(),
        findings.stored_checksum.is_established(),
        findings.versioning.is_established(),
        findings.server_side_encryption.is_established(),
    ]
    .into_iter()
    .any(std::convert::identity)
}

/// The eight scenario slots, in execution order, recorded as unreached —
/// the shape a run that stopped before the write path files.
fn unwalked_scenarios(reason: &'static str) -> Vec<ScenarioObservation> {
    SCENARIO_LABELS
        .iter()
        .map(|label| ScenarioObservation {
            label,
            outcome: ScenarioOutcome::NotReached,
            branch: None,
            reason: Some(reason),
        })
        .collect()
}

/// The scenario slot the label names, as an index into the observation
/// vector.
fn slot(label: &str) -> usize {
    SCENARIO_LABELS
        .iter()
        .position(|candidate| *candidate == label)
        .unwrap_or(0)
}

/// What the write-path leg produced.
struct WalkedWritePath {
    scenarios: Vec<ScenarioObservation>,
    physical: BTreeMap<&'static str, PhysicalHistory>,
    noncurrent: Option<NoncurrentVersionReport>,
    failure: Option<(LegExit, &'static str)>,
}

/// Drive two futures to completion together — the two independent
/// concurrent-writers drives, in flight at the same time so the backend's
/// own atomic primitive is the race's arbiter.
///
/// The workspace's tokio pin carries no `macros` feature, so this is the
/// dependency-free join: both futures are polled on every wake, each at
/// most once past its completion, and the pair resolves when both have.
async fn join_two<A, B>(left: A, right: B) -> (A::Output, B::Output)
where
    A: Future,
    B: Future,
{
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut left_output: Option<A::Output> = None;
    let mut right_output: Option<B::Output> = None;
    std::future::poll_fn(move |context| {
        if left_output.is_none()
            && let std::task::Poll::Ready(output) = left.as_mut().poll(context)
        {
            left_output = Some(output);
        }
        if right_output.is_none()
            && let std::task::Poll::Ready(output) = right.as_mut().poll(context)
        {
            right_output = Some(output);
        }
        match (left_output.take(), right_output.take()) {
            (Some(left), Some(right)) => std::task::Poll::Ready((left, right)),
            (left, right) => {
                left_output = left;
                right_output = right;
                std::task::Poll::Pending
            }
        }
    })
    .await
}

/// The shared honesty table for a two-write replay — the shape the
/// duplicate-request and equivalent-overwrite scenarios both grade
/// against. Read-capable + supported: `Created` then `AlreadyPresent`.
/// Writer-only + supported: `Created` then the unknown-physical branch.
/// Unsupported: the unknown-physical branch for both — the deterministic
/// overwrite cannot say what it landed on.
fn replay_honest(
    conditional_supported: bool,
    read_capable: bool,
    observed_first: StorageOutcome,
    observed_second: StorageOutcome,
) -> bool {
    let first_honest = if conditional_supported {
        observed_first == StorageOutcome::Created
    } else {
        observed_first == StorageOutcome::LogicallyCommittedUnknownPhysicalResult
    };
    let second_honest = match (conditional_supported, read_capable) {
        (true, true) => observed_second == StorageOutcome::AlreadyPresent,
        (true, false) | (false, _) => {
            observed_second == StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        }
    };
    first_honest && second_honest
}

/// Grade the concurrent-writers scenario from its two in-flight
/// outcomes. The backend's atomic primitive is the race's arbiter:
/// supported means exactly one `Created` and the rest converged;
/// unsupported means every outcome is the honest unknown.
fn concurrent_honest(
    conditional_supported: bool,
    read_capable: bool,
    outcomes: [StorageOutcome; 2],
) -> bool {
    match (conditional_supported, read_capable) {
        (true, true) => {
            outcomes.contains(&StorageOutcome::Created)
                && outcomes.contains(&StorageOutcome::AlreadyPresent)
        }
        (true, false) => {
            outcomes.contains(&StorageOutcome::Created)
                && outcomes.contains(&StorageOutcome::LogicallyCommittedUnknownPhysicalResult)
        }
        (false, _) => outcomes
            .iter()
            .all(|outcome| *outcome == StorageOutcome::LogicallyCommittedUnknownPhysicalResult),
    }
}

/// Grade one attestation write: `Created` where the conditional
/// primitive is supported, the honest unknown otherwise — each uploader
/// key independent, the keys never colliding.
fn attestation_graded(
    conditional_supported: bool,
    committed: Result<StorageOutcome, StorageError>,
) -> Graded {
    match committed {
        Ok(outcome) => {
            let honest = if conditional_supported {
                outcome == StorageOutcome::Created
            } else {
                outcome == StorageOutcome::LogicallyCommittedUnknownPhysicalResult
            };
            grade(ScenarioOutcome::from_honest(honest), Some(outcome))
        }
        Err(_) => grade(ScenarioOutcome::Errored, None),
    }
}

/// Drive the seven write-path scenarios in order through the store's
/// public commit paths, then freeze the run's physical history through
/// the audit identity and corroborate it against the declared axes.
#[allow(clippy::too_many_lines)] // the kit's scenarios in execution order, read top to bottom
async fn walk_write_path<B, A>(
    plan: &RunPlan<'_>,
    tenant: &TenantId,
    store: &Arc<S3RawWriteStore<B>>,
    audit: &S3LifecycleAuditStore<A>,
) -> WalkedWritePath
where
    B: RawWriteBackend + Sync,
    A: VersionAuditBackend + Sync,
{
    let fixtures = Fixtures::new(tenant);
    let conditional_supported =
        store.capabilities().conditional_create == ConditionalCreate::Supported;
    // Seeded with the closed not-reached outcome per slot: a scenario the
    // leg never reaches records NotReached — there is no absent slot.
    let mut observations: Vec<ScenarioObservation> = unwalked_scenarios(REASON_UNREACHED);
    let mut failure: Option<(LegExit, &'static str)> = None;

    // duplicate-request: two identical commits on one occurrence key.
    {
        let graded = grade_pair(
            commit_manifest(store.as_ref(), &fixtures.duplicate, b"duplicate-request").await,
            commit_manifest(store.as_ref(), &fixtures.duplicate, b"duplicate-request").await,
            |first, second| replay_honest(conditional_supported, plan.read_capable, first, second),
        );
        record(
            &mut observations,
            &mut failure,
            slot(SCENARIO_LABELS[0]),
            graded,
            REASON_DUPLICATE,
        );
    }

    // equivalent-overwrite: the same deterministic key and bytes twice —
    // a successful replay, never an integrity conflict.
    {
        let graded = grade_pair(
            store
                .write_manifest(&fixtures.overwrite, b"equivalent-overwrite")
                .await,
            store
                .write_manifest(&fixtures.overwrite, b"equivalent-overwrite")
                .await,
            |first, second| replay_honest(conditional_supported, plan.read_capable, first, second),
        );
        record(
            &mut observations,
            &mut failure,
            slot(SCENARIO_LABELS[1]),
            graded,
            REASON_OVERWRITE,
        );
    }

    // concurrent-writers: the same key committed from two independent
    // drives, in flight together.
    {
        let (left, right) = join_two(
            commit_manifest(store.as_ref(), &fixtures.concurrent, b"concurrent-writers"),
            commit_manifest(store.as_ref(), &fixtures.concurrent, b"concurrent-writers"),
        )
        .await;
        let graded = match (left, right) {
            (Ok(left), Ok(right)) => grade(
                ScenarioOutcome::from_honest(concurrent_honest(
                    conditional_supported,
                    plan.read_capable,
                    [left, right],
                )),
                Some(left),
            ),
            _ => grade(ScenarioOutcome::Errored, None),
        };
        record(
            &mut observations,
            &mut failure,
            slot(SCENARIO_LABELS[2]),
            graded,
            REASON_CONCURRENT,
        );
    }

    // read-capable-conflict: preloaded bytes, then a commit of different
    // bytes at the same key. Read-capable + supported must refuse with
    // an integrity conflict and leave the existing bytes alone;
    // writer-only + supported takes the honest unknown; unsupported
    // overwrites and reports the unknown-physical branch.
    {
        let preload = store
            .write_manifest(&fixtures.conflict, b"old-incompatible")
            .await;
        let conflict = match preload {
            Ok(_) => Some(
                commit_manifest(store.as_ref(), &fixtures.conflict, b"new-compatible-length").await,
            ),
            Err(_) => None,
        };
        let graded = match (preload, conflict) {
            (Ok(_), Some(Ok(conflict))) => {
                let honest = !(conditional_supported && plan.read_capable)
                    && conflict == StorageOutcome::LogicallyCommittedUnknownPhysicalResult;
                grade(ScenarioOutcome::from_honest(honest), Some(conflict))
            }
            (Ok(_), Some(Err(conflict))) => {
                let honest = conditional_supported
                    && plan.read_capable
                    && conflict.kind() == StorageErrorKind::IntegrityConflict;
                grade(ScenarioOutcome::from_honest(honest), None)
            }
            _ => grade(ScenarioOutcome::Errored, None),
        };
        record(
            &mut observations,
            &mut failure,
            slot(SCENARIO_LABELS[3]),
            graded,
            REASON_CONFLICT,
        );
    }

    // multipart-abort: begin, one part, abort, abort again. The repeat
    // abort must not error — cleanup is idempotent — and the aborted
    // session must store nothing visible, which the physical half
    // corroborates: the blob key's final history is the committed
    // session's one version and nothing else.
    {
        let graded = multipart_abort(store, &fixtures.blob).await;
        record(
            &mut observations,
            &mut failure,
            slot(SCENARIO_LABELS[4]),
            graded,
            REASON_ABORT,
        );
    }

    // multipart-commit: begin, one part, commit. The commit is
    // unconditional, so the honest logical outcome is the
    // unknown-physical one; the bytes are stored with the declared
    // checksum and version behavior, which the physical half verifies.
    {
        let graded = multipart_commit(store, &fixtures.blob).await;
        record(
            &mut observations,
            &mut failure,
            slot(SCENARIO_LABELS[5]),
            graded,
            REASON_MULTIPART,
        );
    }

    // origin/relay-attestation: one source occurrence, two uploader
    // attestation keys — each graded independently.
    for (label, graded) in [
        (
            SCENARIO_LABELS[6],
            attestation_graded(
                conditional_supported,
                commit_manifest(
                    store.as_ref(),
                    &fixtures.origin,
                    b"uploader=origin;request=request-origin",
                )
                .await,
            ),
        ),
        (
            SCENARIO_LABELS[7],
            attestation_graded(
                conditional_supported,
                commit_manifest(
                    store.as_ref(),
                    &fixtures.relay,
                    b"uploader=relay;request=request-relay",
                )
                .await,
            ),
        ),
    ] {
        record(
            &mut observations,
            &mut failure,
            slot(label),
            graded,
            REASON_ATTESTATION,
        );
    }

    // A scenario that errored or was contradicted stops the walk: the
    // remaining slots record NotReached, and the run cannot qualify.
    if failure.is_some() {
        mark_unreached(&mut observations);
        return WalkedWritePath {
            scenarios: observations,
            physical: BTreeMap::new(),
            noncurrent: None,
            failure,
        };
    }

    // The physical half: freeze the run's own raw prefix through the one
    // authority with list grants, and reduce the STO-009 audit from the
    // same listing.
    let raw_scope = InventoryScope::TenantRaw(tenant.clone());
    let listing = match freeze_version_listing(audit, &raw_scope).await {
        Ok(listing) => listing,
        Err(error) => {
            let exit = match error.kind() {
                StorageErrorKind::Unavailable => LegExit::Unknown,
                _ => LegExit::Failed,
            };
            failure.get_or_insert((exit, REASON_PHYSICAL));
            mark_unreached(&mut observations);
            return WalkedWritePath {
                scenarios: observations,
                physical: BTreeMap::new(),
                noncurrent: None,
                failure,
            };
        }
    };

    let declared = store.capabilities();
    let claim_versions = declared.versioning == VersioningState::Enabled;
    let mut physical = BTreeMap::new();
    let mut count_failure = false;
    for (label, key) in fixtures.observed_keys() {
        let group = listing
            .keys()
            .iter()
            .find(|group| group.key().as_str() == key.as_str());
        let count = group.map_or(0, KeyVersions::len);
        let version_ids = match (claim_versions, group) {
            (true, Some(group)) => group
                .versions()
                .iter()
                .map(|entry| entry.version().as_str().to_owned())
                .filter(|version| version != NULL_VERSION)
                .collect(),
            _ => Vec::new(),
        };
        if count != expected_versions(declared, label) {
            count_failure = true;
        }
        physical.insert(label, PhysicalHistory { count, version_ids });
    }
    let noncurrent = audit.audit_noncurrent(&raw_scope).await.ok();
    if count_failure {
        failure.get_or_insert((LegExit::Failed, REASON_COUNT));
    } else if checksum_contradicts(&listing, declared.stored_checksum) {
        failure.get_or_insert((LegExit::Failed, REASON_CHECKSUM));
    }
    mark_unreached(&mut observations);
    WalkedWritePath {
        scenarios: observations,
        physical,
        noncurrent,
        failure,
    }
}

/// The expected physical-version count for one observed scenario, derived
/// from the declared capabilities exactly as the in-repo suite's table
/// predicts: one object per key on a disabled axis regardless of writes,
/// one version per write otherwise. The conflict scenario's preload is a
/// write too, and the multipart-commit key always lands exactly one
/// committed object (the aborted session stores nothing visible).
fn expected_versions(capabilities: StoreCapabilities, label: &str) -> usize {
    let writes = match label {
        "duplicate-request" | "equivalent-overwrite" | "concurrent-writers" => {
            match capabilities.conditional_create {
                ConditionalCreate::Supported => 1,
                ConditionalCreate::Unavailable => 2,
            }
        }
        "read-capable-conflict" => match capabilities.conditional_create {
            ConditionalCreate::Supported => 1,
            ConditionalCreate::Unavailable => 2,
        },
        "multipart-commit" | "origin-attestation" | "relay-attestation" => 1,
        _ => 0,
    };
    match capabilities.versioning {
        VersioningState::Disabled => usize::from(writes > 0),
        VersioningState::Enabled | VersioningState::Unknown => writes,
    }
}

/// Whether any stored tag contradicts the declared checksum form. A
/// declared-unavailable form corroborates nothing; a missing tag on an
/// object that must exist, or a tag that classifies to a different form
/// than declared, is the contradiction. Both enums carry the same model
/// token for the same form, so the comparison rides the tokens.
fn checksum_contradicts(listing: &FrozenVersionListing, declared: StoredChecksum) -> bool {
    listing
        .keys()
        .iter()
        .flat_map(|group| group.versions().iter())
        .any(|entry| match (declared, entry.observation().etag()) {
            (StoredChecksum::Unavailable, _) => false,
            (_, None) => true,
            (_, Some(tag)) => {
                classify_checksum(Some(tag.as_str())).map(ChecksumForm::token)
                    != Some(declared.token())
            }
        })
}

/// Grade the multipart-abort scenario: begin, one part, abort, abort
/// again. The repeat abort must succeed — cleanup is idempotent.
async fn multipart_abort<B>(store: &Arc<S3RawWriteStore<B>>, blob: &BlobObjectKey) -> Graded
where
    B: RawWriteBackend + Sync,
{
    let part = PartNumber::new(1).expect("part number 1 is inside the trait's bounds");
    match store.begin_multipart(blob).await {
        Ok(upload) => {
            let written = store.write_part(&upload, part, b"abandoned-part").await;
            let first = store.abort_multipart(&upload).await;
            let repeat = store.abort_multipart(&upload).await;
            match (written, first, repeat) {
                (Ok(_), Ok(()), Ok(())) => Graded {
                    outcome: ScenarioOutcome::Matched,
                    branch: None,
                },
                (Err(_), _, _) | (_, Err(_), _) | (_, _, Err(_)) => Graded {
                    outcome: ScenarioOutcome::Errored,
                    branch: None,
                },
            }
        }
        Err(_) => Graded {
            outcome: ScenarioOutcome::Errored,
            branch: None,
        },
    }
}

/// Grade the multipart-commit scenario: begin, one part, commit. The
/// commit is unconditional, so the honest logical outcome is the
/// unknown-physical one.
async fn multipart_commit<B>(store: &Arc<S3RawWriteStore<B>>, blob: &BlobObjectKey) -> Graded
where
    B: RawWriteBackend + Sync,
{
    let part = PartNumber::new(1).expect("part number 1 is inside the trait's bounds");
    match store.begin_multipart(blob).await {
        Ok(upload) => {
            let written = store.write_part(&upload, part, b"committed-part").await;
            match written {
                Ok(commitment) => match store.commit_multipart(&upload, &[commitment]).await {
                    Ok(outcome) => Graded {
                        outcome: ScenarioOutcome::from_honest(
                            outcome == StorageOutcome::LogicallyCommittedUnknownPhysicalResult,
                        ),
                        branch: Some(outcome),
                    },
                    Err(_) => Graded {
                        outcome: ScenarioOutcome::Errored,
                        branch: None,
                    },
                },
                Err(_) => Graded {
                    outcome: ScenarioOutcome::Errored,
                    branch: None,
                },
            }
        }
        Err(_) => Graded {
            outcome: ScenarioOutcome::Errored,
            branch: None,
        },
    }
}

/// One scenario's graded result before it is recorded.
#[derive(Clone, Copy)]
struct Graded {
    outcome: ScenarioOutcome,
    branch: Option<StorageOutcome>,
}

/// Grade one scenario from its honesty.
fn grade(outcome: ScenarioOutcome, branch: Option<StorageOutcome>) -> Graded {
    Graded { outcome, branch }
}

impl ScenarioOutcome {
    /// The honest mapping: a check that held matched; one that did not
    /// is a contradiction of the declared capabilities.
    fn from_honest(honest: bool) -> Self {
        if honest {
            Self::Matched
        } else {
            Self::Contradicted
        }
    }
}

/// Grade one two-write scenario from both outcomes.
fn grade_pair<F>(
    first: Result<StorageOutcome, StorageError>,
    second: Result<StorageOutcome, StorageError>,
    honest: F,
) -> Graded
where
    F: FnOnce(StorageOutcome, StorageOutcome) -> bool,
{
    match (first, second) {
        (Ok(first), Ok(second)) => Graded {
            outcome: ScenarioOutcome::from_honest(honest(first, second)),
            branch: Some(first),
        },
        _ => Graded {
            outcome: ScenarioOutcome::Errored,
            branch: None,
        },
    }
}

/// Record one graded scenario, and note the leg's first stopping failure.
fn record(
    observations: &mut [ScenarioObservation],
    failure: &mut Option<(LegExit, &'static str)>,
    index: usize,
    graded: Graded,
    reason: &'static str,
) {
    let exit = match graded.outcome {
        ScenarioOutcome::Contradicted => Some((LegExit::Failed, reason)),
        ScenarioOutcome::Errored => Some((LegExit::Unknown, REASON_ERRORED)),
        ScenarioOutcome::Matched | ScenarioOutcome::NotReached => None,
    };
    observations[index] = ScenarioObservation {
        label: observations[index].label,
        outcome: graded.outcome,
        branch: graded.branch,
        reason: match graded.outcome {
            ScenarioOutcome::Matched | ScenarioOutcome::NotReached => None,
            _ => Some(reason),
        },
    };
    if let Some(exit) = exit {
        failure.get_or_insert(exit);
    }
}

/// Mark every slot after the first stopping observation as unreached.
fn mark_unreached(observations: &mut [ScenarioObservation]) {
    let mut stopped = false;
    for observation in &mut *observations {
        if stopped {
            observation.outcome = ScenarioOutcome::NotReached;
            observation.branch = None;
            observation.reason = Some(REASON_UNREACHED);
            continue;
        }
        if matches!(
            observation.outcome,
            ScenarioOutcome::Errored | ScenarioOutcome::Contradicted
        ) {
            stopped = true;
        }
    }
}

/// The enumeration leg: the fault-injection set the freeze contract must
/// refuse, then the live control-prefix enumeration.
///
/// The fault half is identical for every profile — the faults live in
/// the enumeration source, not the backend — and each injected fault
/// must surface as a freeze refusal, never be silently consumed. The
/// live half is the run's real paginated enumeration of its control
/// prefix through the audit identity: duplicate keys across pages,
/// truncated pages, and looping continuations surface as freeze
/// failures, not as a consumed listing. The concurrent-writes fault is
/// the write-path leg's concurrent-writers observation against real
/// storage, already recorded there.
async fn walk_enumeration<A>(tenant: &TenantId, audit: &S3LifecycleAuditStore<A>) -> LegObservation
where
    A: VersionAuditBackend + Sync,
{
    for fault in faulted_sequences(tenant) {
        if fault().is_ok() {
            return LegObservation::stopped(
                LegId::Enumeration,
                LegExit::Failed,
                REASON_ENUM_FAULTS,
            );
        }
    }
    let control_scope = InventoryScope::TenantControl(tenant.clone());
    match freeze_version_listing(audit, &control_scope).await {
        Ok(_) => LegObservation::complete(LegId::Enumeration),
        Err(error) => {
            let exit = match error.kind() {
                StorageErrorKind::Unavailable => LegExit::Unknown,
                _ => LegExit::Failed,
            };
            LegObservation::stopped(LegId::Enumeration, exit, REASON_ENUM_LIVE)
        }
    }
}

/// The enumeration fault-injection set: one boxed closure per Plan
/// Section 7.7 fault the versions freeze can observe, each building the
/// faulting page sequence and freezing it. Every closure must return
/// `Err` — a fault the freeze accepted is exactly the failure the leg
/// exists to catch.
///
/// - duplicate pages: the same *(key, version)* pair on two pages;
/// - token loop: a continuation token that repeats — a loop is a fault
///   even when the pages happen to agree;
/// - page mutation: a key whose observed currency conflicts
///   mid-sequence, because the overwrite landed while the listing was
///   being taken;
/// - page error: a page that errors mid-sequence fails the whole freeze
///   closed.
fn faulted_sequences(tenant: &TenantId) -> Vec<Box<dyn FnOnce() -> Result<(), StorageError> + '_>> {
    let raw_prefix = format!("tenants/{tenant}/v1/raw/");
    let key = |tail: &str| {
        InventoryKey::parse(&format!("{raw_prefix}{tail}"))
            .expect("fault keys are inside the inventory grammar")
    };
    let entry = |tail: &str, version: &str, latest: bool| {
        VersionedEntry::new(
            key(tail),
            16,
            StorageVersionId::parse(version).expect("fault versions parse"),
            latest,
            Observation::new(None, None, kit_timestamp()),
        )
    };
    let page = |entries: Vec<VersionedEntry>, next: Option<&str>| {
        VersionedPage::new(
            entries,
            next.map(|token| {
                archivist_storage::audit_restore::ContinuationToken::parse(token)
                    .expect("fault tokens parse")
            }),
        )
    };
    let scope = InventoryScope::TenantRaw(tenant.clone());
    let ok = |page| Ok::<_, StorageError>(page);

    vec![
        // Duplicate pages: `a` v1 appears on both pages.
        {
            let scope = scope.clone();
            let first = page(vec![entry("a", "v1", true)], Some("t2"));
            let second = page(vec![entry("a", "v1", true)], None);
            Box::new(move || freeze_fault_pages(&scope, vec![ok(first), ok(second)]))
        },
        // Token loop: both pages continue the same token.
        {
            let scope = scope.clone();
            let first = page(vec![entry("b", "v1", true)], Some("loop"));
            let second = page(vec![entry("b", "v2", false)], Some("loop"));
            Box::new(move || freeze_fault_pages(&scope, vec![ok(first), ok(second)]))
        },
        // Page mutation: `c` reports two current versions — the
        // overwrite landed mid-sequence and both reads surfaced.
        {
            let scope = scope.clone();
            let first = page(vec![entry("c", "v1", true)], Some("t2"));
            let second = page(vec![entry("c", "v2", true)], None);
            Box::new(move || freeze_fault_pages(&scope, vec![ok(first), ok(second)]))
        },
        // Page error: the second page fails, and the freeze refuses.
        {
            let scope = scope.clone();
            let first = page(vec![entry("d", "v1", true)], Some("t2"));
            Box::new(move || {
                freeze_fault_pages(
                    &scope,
                    vec![
                        ok(first),
                        Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
                    ],
                )
            })
        },
    ]
}

/// The kit's reference instant, for the fault fixtures' observation
/// stamps — the fault set is portable and identical for every profile,
/// so its evidence carries a fixed instant, not a wall clock.
fn kit_timestamp() -> Timestamp {
    Timestamp::parse("2026-09-27T00:00:00Z").expect("the kit's reference instant parses")
}

/// Freeze one fault sequence's page list: the fault half's driver. A
/// plain function, not a capturing closure, so every boxed fault owns
/// its own clone of the scope and none moves the freeze out from under
/// the others.
fn freeze_fault_pages(
    scope: &InventoryScope,
    pages: Vec<Result<VersionedPage, StorageError>>,
) -> Result<(), StorageError> {
    FrozenVersionListing::from_pages(scope, pages).map(|_| ())
}

/// Resolve the run's verdict from the assembled report: qualified only
/// when the profile is supported, every leg completed, and every
/// scenario matched its declared branch.
fn resolve_verdict(report: &QualificationReport) -> RunVerdict {
    if !report.profile_supported {
        return RunVerdict::Unqualified(REASON_PROFILE);
    }
    for leg in report.legs() {
        match leg.exit {
            LegExit::Complete => {}
            LegExit::Failed | LegExit::NotReached => {
                return RunVerdict::Unqualified(leg.reason.unwrap_or(REASON_PROFILE));
            }
            LegExit::Unknown => {
                return RunVerdict::Unqualified(leg.reason.unwrap_or(REASON_ERRORED));
            }
        }
    }
    for observation in &report.scenarios {
        match observation.outcome {
            ScenarioOutcome::Matched => {}
            ScenarioOutcome::Contradicted => {
                return RunVerdict::Unqualified(observation.reason.unwrap_or(REASON_DUPLICATE));
            }
            ScenarioOutcome::Errored => {
                return RunVerdict::Unqualified(observation.reason.unwrap_or(REASON_ERRORED));
            }
            ScenarioOutcome::NotReached => {
                return RunVerdict::Unqualified(REASON_UNREACHED);
            }
        }
    }
    RunVerdict::Qualified
}

/// The kit's Section 4 fixture identity set, rendered into the typed key
/// constructors the run drives. A driver never hand-builds key strings.
struct Fixtures {
    duplicate: ManifestKey,
    overwrite: ManifestKey,
    concurrent: ManifestKey,
    conflict: ManifestKey,
    origin: ManifestKey,
    relay: ManifestKey,
    blob: BlobObjectKey,
}

impl Fixtures {
    /// Derive every scenario key from the fixed identity set.
    ///
    /// # Panics
    /// The kit publishes these exact values as grammar-valid; a parse
    /// failure means the kit text and the grammar diverged, and the run
    /// must not proceed on a substituted identity set.
    fn new(tenant: &TenantId) -> Self {
        let client = ClientId::parse(FIXTURE_CLIENT).expect("fixture client parses");
        let harness = HarnessId::parse(FIXTURE_HARNESS).expect("fixture harness parses");
        let session = SessionHash::parse(FIXTURE_SESSION).expect("fixture session parses");
        let occurrence_key = |occurrence: &str| {
            ManifestKey::Occurrence(OccurrenceObjectKey::new(
                tenant,
                &client,
                &harness,
                &session,
                &OccurrenceId::parse(occurrence).expect("fixture occurrence parses"),
            ))
        };
        let attestation_key = |attestation: &str| {
            ManifestKey::Attestation(AttestationObjectKey::new(
                tenant,
                &OccurrenceId::parse(FIXTURE_OCCURRENCE_SOURCE).expect("fixture occurrence parses"),
                &AttestationId::parse(attestation).expect("fixture attestation parses"),
            ))
        };
        Self {
            duplicate: occurrence_key(FIXTURE_OCCURRENCE_DUPLICATE),
            overwrite: occurrence_key(FIXTURE_OCCURRENCE_OVERWRITE),
            concurrent: occurrence_key(FIXTURE_OCCURRENCE_CONCURRENT),
            conflict: occurrence_key(FIXTURE_OCCURRENCE_CONFLICT),
            origin: attestation_key(FIXTURE_ATTESTATION_ORIGIN),
            relay: attestation_key(FIXTURE_ATTESTATION_RELAY),
            blob: BlobObjectKey::new(
                tenant,
                StorageProfile::ZstdV1,
                &BlobDigest::parse(FIXTURE_DIGEST).expect("fixture digest parses"),
            ),
        }
    }

    /// Every scenario's observed key, paired with its report-line label.
    /// The aborted multipart session stores nothing visible, so the
    /// multipart-abort scenario observes no key; the multipart-commit
    /// key's final history is exactly the committed session's one
    /// version.
    fn observed_keys(&self) -> Vec<(&'static str, String)> {
        vec![
            ("duplicate-request", self.duplicate.as_str().to_owned()),
            ("equivalent-overwrite", self.overwrite.as_str().to_owned()),
            ("concurrent-writers", self.concurrent.as_str().to_owned()),
            ("read-capable-conflict", self.conflict.as_str().to_owned()),
            ("multipart-commit", self.blob.as_str().to_owned()),
            ("origin-attestation", self.origin.as_str().to_owned()),
            ("relay-attestation", self.relay.as_str().to_owned()),
        ]
    }
}

/// A forbidden field the redaction pass found: the shape class that
/// matched, and where in the text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionViolation {
    /// The shape class the record gate forbids (SP-006).
    pub what: &'static str,
    /// The byte offset the shape starts at.
    pub at: usize,
}

/// Scan text for the forbidden field shapes SP-006 keeps out of any
/// committed record field, plus every configured value the driver names
/// (its endpoint, its bucket names, its credential reference targets).
///
/// The shape classes mirror the record gate's own identifier patterns:
/// a URL or scheme prefix, an IPv4 address, a UUID-shaped identity, an
/// address-shaped `user@host` string, and a tailnet hostname. A nonempty
/// violation list means the text must not be rendered into a transcript.
#[must_use]
pub fn redaction_violations(text: &str, configured: &[String]) -> Vec<RedactionViolation> {
    let mut violations = Vec::new();
    if let Some(at) = text.find("://") {
        violations.push(RedactionViolation {
            what: "a URL or scheme prefix",
            at,
        });
    }
    for (at, ()) in address_shapes(text) {
        violations.push(RedactionViolation {
            what: "an IPv4 address",
            at,
        });
    }
    for (at, ()) in uuid_shapes(text) {
        violations.push(RedactionViolation {
            what: "an identifier-shaped UUID",
            at,
        });
    }
    for token in text.split_ascii_whitespace() {
        let Some(at) = token.find('@') else {
            continue;
        };
        if at > 0 && at + 1 < token.len() {
            violations.push(RedactionViolation {
                what: "an address-shaped string",
                at: text.find(token).unwrap_or(0) + at,
            });
        }
        if let Some(position) = token.rfind(".ts.net") {
            violations.push(RedactionViolation {
                what: "a tailnet hostname",
                at: text.find(token).unwrap_or(0) + position,
            });
        }
    }
    for value in configured {
        // Empty values are not useful scan terms and would match every
        // transcript. Every non-empty configured value is sensitive,
        // including short bucket names, so never let a length heuristic
        // turn one into printable output.
        if !value.is_empty()
            && let Some(at) = text.find(value.as_str())
        {
            violations.push(RedactionViolation {
                what: "a configured endpoint, bucket, or reference value",
                at,
            });
        }
    }
    violations
}

/// The IPv4-shaped runs in `text`: four dot-separated groups of one to
/// three ASCII digits, each bounded by non-digit characters. Shape only,
/// not routability — the record gate's pattern is the same width match.
fn address_shapes(text: &str) -> Vec<(usize, ())> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        let mut groups = 0;
        let mut digits = 0;
        let mut cursor = start;
        while cursor < bytes.len() && groups < 4 {
            digits = 0;
            while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                cursor += 1;
                digits += 1;
            }
            if digits == 0 || digits > 3 {
                break;
            }
            groups += 1;
            if groups < 4 {
                if cursor < bytes.len() && bytes[cursor] == b'.' {
                    cursor += 1;
                } else {
                    break;
                }
            }
        }
        let bounded_before = start == 0 || !bytes[start - 1].is_ascii_digit();
        let bounded_after = cursor >= bytes.len() || !bytes[cursor].is_ascii_alphanumeric();
        if groups == 4 && digits <= 3 && bounded_before && bounded_after {
            found.push((start, ()));
            index = cursor;
        } else {
            index = start + digits.max(1);
        }
    }
    found
}

/// The canonical UUID shape used by tenant, client, session, occurrence, and
/// attestation identities. It is deliberately shape-only: the renderer does
/// not need to know which identity family a leaked value belongs to before it
/// refuses the transcript.
fn uuid_shapes(text: &str) -> Vec<(usize, ())> {
    const UUID_BYTES: usize = 36;
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    if bytes.len() < UUID_BYTES {
        return found;
    }
    for start in 0..=bytes.len() - UUID_BYTES {
        let candidate = &bytes[start..start + UUID_BYTES];
        let hyphen = [8, 13, 18, 23];
        if hyphen.iter().any(|&position| candidate[position] != b'-')
            || candidate
                .iter()
                .enumerate()
                .any(|(position, byte)| !hyphen.contains(&position) && !byte.is_ascii_hexdigit())
        {
            continue;
        }
        let bounded_before = start == 0 || !bytes[start - 1].is_ascii_hexdigit();
        let end = start + UUID_BYTES;
        let bounded_after = end == bytes.len() || !bytes[end].is_ascii_hexdigit();
        if bounded_before && bounded_after {
            found.push((start, ()));
        }
    }
    found
}

/// The transcript a contribution attaches: the capability report's
/// canonical bytes and digest, the `profile_supported` answer, the
/// report line, every leg's exit, and the suite revision the record
/// cites. Rendered only when the redaction pass finds no forbidden
/// field — the transcript is attached to the contribution, never
/// committed (SP-006).
#[derive(Clone, Debug)]
pub struct RunTranscript {
    profile_key: String,
    suite_revision: String,
    capability_report_bytes: String,
    capability_report_digest: String,
    profile_supported: bool,
    report_line: String,
    legs: Vec<(LegId, LegExit)>,
    scenarios: Vec<(String, ScenarioOutcome)>,
    verdict: RunVerdict,
}

/// Why a transcript refused to render: the redaction pass found the
/// forbidden shapes it names, and the transcript fails closed instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionError {
    /// Every forbidden field the pass found.
    pub violations: Vec<RedactionViolation>,
}

impl RunTranscript {
    /// Assemble the transcript from a finished run.
    #[must_use]
    pub fn from_report(report: &QualificationReport, suite_revision: &str) -> Self {
        Self {
            profile_key: report.profile_key.clone(),
            suite_revision: suite_revision.to_owned(),
            capability_report_bytes: String::from_utf8_lossy(report.capability_report_bytes())
                .into_owned(),
            capability_report_digest: report.capability_report_digest().to_owned(),
            profile_supported: report.profile_supported(),
            report_line: report.render_line(),
            legs: LegId::all()
                .into_iter()
                .map(|leg| (leg, report.leg(leg).exit))
                .collect(),
            scenarios: report
                .scenarios()
                .iter()
                .map(|observation| (observation.label.to_owned(), observation.outcome))
                .collect(),
            verdict: report.verdict().clone(),
        }
    }

    /// Render the transcript, or refuse: the text is scanned for the
    /// forbidden field shapes and for every configured value the driver
    /// names (its endpoint, buckets, and reference targets), and any
    /// hit fails the render closed.
    ///
    /// # Errors
    /// [`RedactionError`] when the pass finds any forbidden field.
    pub fn render(&self, configured: &[String]) -> Result<String, RedactionError> {
        let verdict = match &self.verdict {
            RunVerdict::Qualified => "qualified".to_owned(),
            RunVerdict::Unqualified(reason) => format!("unqualified reason={reason}"),
        };
        let legs = self
            .legs
            .iter()
            .map(|(leg, exit)| format!("leg={} exit={}", leg.token(), exit.token()))
            .collect::<Vec<_>>()
            .join("\n");
        let scenarios = self
            .scenarios
            .iter()
            .map(|(label, outcome)| format!("scenario={label} outcome={}", outcome.token()))
            .collect::<Vec<_>>()
            .join("\n");
        let text = format!(
            "storage-qualification profile={} suite_revision={}\ncapability-report-digest={} profile_supported={}\n{}\n{}\n{}\n",
            self.profile_key,
            self.suite_revision,
            self.capability_report_digest,
            self.profile_supported,
            self.report_line,
            legs,
            scenarios,
        );
        let text = format!(
            "{text}capability-report={}\nverdict={verdict}\n",
            self.capability_report_bytes
        );
        let violations = redaction_violations(&text, configured);
        if violations.is_empty() {
            Ok(text)
        } else {
            Err(RedactionError { violations })
        }
    }
}

#[cfg(test)]
mod tests {
    //! The outcome model over synthetic seams: one honest backend proves
    //! the complete run qualifies, fault toggles prove the failed and
    //! unknown outcomes file the honest negative, and the redaction guard
    //! proves the transcript refuses forbidden fields.

    use super::*;
    use crate::config::{EncryptionPolicy, S3StorageConfig};
    use crate::probe::{ProbeObjectObservation, ProbeReceipt};
    use crate::raw_write::RawObjectKey;
    use archivist_storage::audit_restore::ContinuationToken;
    use archivist_storage::commit::{CreateIfAbsent, ExistingObject};
    use archivist_storage::metadata::ObjectTag;
    use archivist_storage::probe::{ProbeKey, VersioningObservation};
    use archivist_storage::raw_write::PartCommitment;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const OBSERVED_AT: &str = "2026-09-27T12:00:00Z";

    /// One listing record: key, size, version id, currency, stored tag.
    type AuditRecord = (String, u64, String, bool, Option<String>);

    /// One open multipart session: its key and the uploaded parts.
    type UploadSession = (String, Vec<(PartNumber, Vec<u8>, String)>);

    /// What the bucket-versioning read answers: the real surface, or
    /// the honest no-surface answer.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    enum VersioningAnswer {
        #[default]
        Enabled,
        NoSurface,
    }

    #[derive(Clone, Debug)]
    struct Physical {
        bytes: Vec<u8>,
        checksum: Option<String>,
        version: Option<String>,
    }

    #[derive(Debug, Default)]
    struct State {
        objects: HashMap<String, Vec<Physical>>,
        uploads: HashMap<String, UploadSession>,
        probe_objects: HashMap<String, Vec<Physical>>,
        probe_uploads: HashMap<String, UploadSession>,
        next_id: u64,
        versioning_answer: VersioningAnswer,
        fail_raw_writes: bool,
        fail_probe_multipart: bool,
    }

    #[derive(Clone, Debug, Default)]
    struct Fake {
        state: Arc<Mutex<State>>,
        versioned: bool,
    }

    impl Fake {
        fn honest() -> Self {
            Self {
                state: Arc::new(Mutex::new(State::default())),
                versioned: true,
            }
        }

        fn version(&self, state: &mut State) -> String {
            state.next_id += 1;
            if self.versioned {
                format!("v{}", state.next_id)
            } else {
                // The real listing hands a pre-versioning object the
                // "null" sentinel: parseable, but never a claimable
                // identity.
                String::from(NULL_VERSION)
            }
        }

        fn store(map: &mut HashMap<String, Vec<Physical>>, key: &str, object: Physical) {
            map.entry(key.to_owned()).or_default().push(object);
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use archivist_protocol::sha256;
        sha256::encode_hex(&sha256::digest(bytes))
    }

    /// The stored tag an honest sha256-checksumming backend attaches.
    fn checksum(bytes: &[u8]) -> String {
        sha256_hex(bytes)
    }

    fn tenant() -> TenantId {
        TenantId::parse(FIXTURE_TENANT).expect("fixture tenant")
    }

    fn observed_at() -> Timestamp {
        Timestamp::parse(OBSERVED_AT).expect("static timestamp")
    }

    fn config() -> S3StorageConfig {
        S3StorageConfig::builder()
            .endpoint_url("https://synthetic.example.test")
            .region("synthetic")
            .encryption(EncryptionPolicy::S3Sse)
            .raw_bucket("archivist-raw-synthetic")
            .control_bucket("archivist-control-synthetic")
            .raw_write_credentials("file:/synthetic/raw-writer")
            .control_read_credentials("file:/synthetic/control-reader")
            .offline_restore_credentials("file:/synthetic/offline-restore")
            .build()
            .expect("synthetic configuration")
    }

    impl ProbeWriteBackend for Fake {
        async fn write_probe_if_absent(
            &self,
            key: &ProbeKey,
            bytes: &[u8],
        ) -> Result<ProbeReceipt, StorageError> {
            let mut state = self.state.lock().expect("fake lock");
            if let Some(existing) = state
                .probe_objects
                .get(key.as_str())
                .and_then(|objects| objects.last())
            {
                return Ok(ProbeReceipt::new(
                    false,
                    existing.version.clone(),
                    existing.checksum.clone(),
                    true,
                ));
            }
            let version = self.version(&mut state);
            let object = Physical {
                bytes: bytes.to_vec(),
                checksum: Some(checksum(bytes)),
                version: Some(version),
            };
            Self::store(&mut state.probe_objects, key.as_str(), object);
            let stored = state.probe_objects[key.as_str()]
                .last()
                .expect("just stored");
            Ok(ProbeReceipt::new(
                true,
                stored.version.clone(),
                stored.checksum.clone(),
                true,
            ))
        }

        async fn read_probe_object(
            &self,
            key: &ProbeKey,
        ) -> Result<Option<ProbeObjectObservation>, StorageError> {
            let state = self.state.lock().expect("fake lock");
            Ok(state
                .probe_objects
                .get(key.as_str())
                .and_then(|objects| objects.last())
                .map(|object| {
                    ProbeObjectObservation::new(
                        object.bytes.len() as u64,
                        object.version.clone(),
                        object.checksum.clone(),
                        true,
                    )
                }))
        }

        async fn bucket_versioning(&self) -> Result<Option<VersioningObservation>, StorageError> {
            match self.state.lock().expect("fake lock").versioning_answer {
                VersioningAnswer::Enabled => Ok(Some(VersioningObservation::Enabled)),
                VersioningAnswer::NoSurface => Ok(None),
            }
        }

        async fn bucket_encryption(&self) -> Result<bool, StorageError> {
            Ok(true)
        }

        async fn create_probe_multipart(&self, key: &ProbeKey) -> Result<String, StorageError> {
            let mut state = self.state.lock().expect("fake lock");
            if state.fail_probe_multipart {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            state.next_id += 1;
            let id = format!("probe-upload-{}", state.next_id);
            state
                .probe_uploads
                .insert(id.clone(), (key.as_str().to_owned(), Vec::new()));
            Ok(id)
        }

        async fn upload_probe_part(
            &self,
            _key: &ProbeKey,
            session: &str,
            part: PartNumber,
            bytes: &[u8],
        ) -> Result<String, StorageError> {
            let mut state = self.state.lock().expect("fake lock");
            let upload = state
                .probe_uploads
                .get_mut(session)
                .expect("adapter validates the probe session");
            let tag = checksum(bytes);
            upload.1.push((part, bytes.to_vec(), tag.clone()));
            Ok(tag)
        }

        async fn complete_probe_multipart(
            &self,
            _key: &ProbeKey,
            session: &str,
            _parts: &[PartCommitment],
        ) -> Result<(), StorageError> {
            let mut state = self.state.lock().expect("fake lock");
            let (key, parts) = state
                .probe_uploads
                .remove(session)
                .expect("open probe session");
            let mut bytes = Vec::new();
            for (_, part, _) in parts {
                bytes.extend(part);
            }
            let version = self.version(&mut state);
            let object = Physical {
                checksum: Some(checksum(&bytes)),
                version: Some(version),
                bytes,
            };
            Self::store(&mut state.probe_objects, &key, object);
            Ok(())
        }

        async fn abort_probe_multipart(
            &self,
            _key: &ProbeKey,
            session: &str,
        ) -> Result<(), StorageError> {
            self.state
                .lock()
                .expect("fake lock")
                .probe_uploads
                .remove(session);
            Ok(())
        }
    }

    impl RawWriteBackend for Fake {
        async fn put_raw_object(
            &self,
            key: &RawObjectKey,
            bytes: &[u8],
        ) -> Result<(), StorageError> {
            let mut state = self.state.lock().expect("fake lock");
            if state.fail_raw_writes {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            let version = self.version(&mut state);
            let object = Physical {
                bytes: bytes.to_vec(),
                checksum: Some(checksum(bytes)),
                version: Some(version),
            };
            Self::store(&mut state.objects, key.as_str(), object);
            Ok(())
        }

        async fn create_raw_object_if_absent(
            &self,
            key: &RawObjectKey,
            bytes: &[u8],
        ) -> Result<CreateIfAbsent, StorageError> {
            let mut state = self.state.lock().expect("fake lock");
            if state.fail_raw_writes {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            if let Some(existing) = state
                .objects
                .get(key.as_str())
                .and_then(|objects| objects.last())
            {
                let mut evidence = ExistingObject::new().with_size(existing.bytes.len() as u64);
                if existing.checksum.is_some() {
                    evidence = evidence
                        .with_stored_sha256(archivist_protocol::sha256::digest(&existing.bytes));
                }
                return Ok(CreateIfAbsent::AlreadyExists(evidence));
            }
            let version = self.version(&mut state);
            let object = Physical {
                bytes: bytes.to_vec(),
                checksum: Some(checksum(bytes)),
                version: Some(version),
            };
            Self::store(&mut state.objects, key.as_str(), object);
            Ok(CreateIfAbsent::Created)
        }

        async fn create_multipart(&self, key: &RawObjectKey) -> Result<String, StorageError> {
            let mut state = self.state.lock().expect("fake lock");
            state.next_id += 1;
            let id = format!("upload-{}", state.next_id);
            state
                .uploads
                .insert(id.clone(), (key.as_str().to_owned(), Vec::new()));
            Ok(id)
        }

        async fn upload_part(
            &self,
            _key: &RawObjectKey,
            session: &str,
            part: PartNumber,
            bytes: &[u8],
        ) -> Result<String, StorageError> {
            let mut state = self.state.lock().expect("fake lock");
            let upload = state.uploads.get_mut(session).expect("open session");
            let tag = checksum(bytes);
            upload.1.push((part, bytes.to_vec(), tag.clone()));
            Ok(tag)
        }

        async fn complete_multipart(
            &self,
            _key: &RawObjectKey,
            session: &str,
            _parts: &[PartCommitment],
        ) -> Result<(), StorageError> {
            let mut state = self.state.lock().expect("fake lock");
            let (key, parts) = state.uploads.remove(session).expect("open session");
            let mut bytes = Vec::new();
            for (_, part, _) in parts {
                bytes.extend(part);
            }
            let version = self.version(&mut state);
            let object = Physical {
                checksum: Some(checksum(&bytes)),
                version: Some(version),
                bytes,
            };
            Self::store(&mut state.objects, &key, object);
            Ok(())
        }

        async fn abort_multipart(
            &self,
            _key: &RawObjectKey,
            session: &str,
        ) -> Result<(), StorageError> {
            self.state
                .lock()
                .expect("fake lock")
                .uploads
                .remove(session);
            Ok(())
        }
    }

    impl VersionAuditBackend for Fake {
        async fn list_object_versions(
            &self,
            scope: &InventoryScope,
            after: Option<&ContinuationToken>,
        ) -> Result<VersionedPage, StorageError> {
            let state = self.state.lock().expect("fake lock");
            // A real prefix listing answers with the scope's keys only —
            // the control-prefix freeze over an honest run is empty.
            let scope_prefix = scope.prefix();
            let mut records: Vec<AuditRecord> = state
                .objects
                .iter()
                .filter(|(key, _)| key.starts_with(&scope_prefix))
                .flat_map(|(key, objects)| {
                    let tail = objects.len().saturating_sub(1);
                    objects
                        .iter()
                        .enumerate()
                        .filter_map(move |(index, object)| {
                            let version = object.version.as_ref()?;
                            Some((
                                key.clone(),
                                object.bytes.len() as u64,
                                version.clone(),
                                index == tail,
                                object.checksum.clone(),
                            ))
                        })
                })
                .collect();
            records.sort_by(|a, b| {
                a.0.as_bytes()
                    .cmp(b.0.as_bytes())
                    .then(a.2.as_bytes().cmp(b.2.as_bytes()))
            });
            let entries = records
                .into_iter()
                .map(|(key, size, version, is_latest, checksum)| {
                    VersionedEntry::new(
                        InventoryKey::parse(&key).expect("synthetic inventory key"),
                        size,
                        StorageVersionId::parse(&version).expect("synthetic version"),
                        is_latest,
                        Observation::new(
                            checksum
                                .as_deref()
                                .map(ObjectTag::parse)
                                .transpose()
                                .expect("synthetic tag"),
                            None,
                            observed_at(),
                        ),
                    )
                })
                .collect::<Vec<_>>();
            let page = 2usize;
            let index = match after {
                None => 0,
                Some(token) => token
                    .as_str()
                    .strip_prefix('p')
                    .and_then(|number| number.parse::<usize>().ok())
                    .ok_or_else(|| StorageError::of_kind(StorageErrorKind::Unavailable))?,
            };
            let start = index * page;
            if start > entries.len() {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            let end = (start + page).min(entries.len());
            let next = if end < entries.len() {
                Some(
                    ContinuationToken::parse(&format!("p{}", end / page)).expect("synthetic token"),
                )
            } else {
                None
            };
            Ok(VersionedPage::new(entries[start..end].to_vec(), next))
        }
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    /// One full run over the given fake, driven exactly as the operator
    /// driver drives it: probe first, then the rebased store and audit.
    fn run_over(fake: &Fake, profile: &'static str) -> QualificationReport {
        let probe = S3ProbeSource::new(fake.clone(), tenant());
        let store = Arc::new(S3RawWriteStore::new(config(), tenant(), fake.clone()));
        let audit = S3LifecycleAuditStore::new(config(), tenant(), fake.clone())
            .expect("the synthetic profile grants the offline-restore identity");
        let plan = RunPlan {
            profile_key: profile,
            suite_revision: "test-revision",
            read_capable: true,
            observed_at: observed_at(),
        };
        block_on(run(&plan, &tenant(), &probe, &store, &audit))
    }

    #[test]
    fn complete_run_qualifies_over_an_honest_backend() {
        let fake = Fake::honest();
        let report = run_over(&fake, "minio");
        assert_eq!(report.verdict(), &RunVerdict::Qualified);
        for leg in report.legs() {
            assert_eq!(leg.exit, LegExit::Complete, "leg {:?}", leg.leg);
        }
        let scenarios = report.scenarios();
        assert_eq!(scenarios.len(), SCENARIO_LABELS.len());
        for observation in scenarios {
            assert_eq!(observation.outcome, ScenarioOutcome::Matched);
        }
        assert!(report.profile_supported());
        assert!(report.noncurrent().is_some(), "the STO-009 audit measured");
        for (label, history) in report.physical_versions() {
            assert!(history.count > 0, "{label} stored nothing");
            assert!(
                !history.version_ids.is_empty(),
                "{label} claimed no versions"
            );
        }
    }

    #[test]
    fn unknown_versioning_refuses_the_audit_and_claims_no_versions() {
        let fake = Fake {
            state: Arc::new(Mutex::new(State {
                versioning_answer: VersioningAnswer::NoSurface,
                ..State::default()
            })),
            versioned: false,
        };
        let report = run_over(&fake, "minio");
        assert_eq!(report.verdict(), &RunVerdict::Qualified);
        assert!(report.noncurrent().is_none(), "unknown never strengthens");
        for (label, history) in report.physical_versions() {
            assert!(
                history.version_ids.is_empty(),
                "{label} claimed versions without an established axis"
            );
        }
        assert!(
            report.render_line().contains("noncurrent_audit=refused"),
            "the report line files the refusal: {}",
            report.render_line()
        );
    }

    #[test]
    fn failed_backend_files_the_honest_negative_and_skips_nothing() {
        let fake = Fake::honest();
        fake.state.lock().expect("fake lock").fail_raw_writes = true;
        let report = run_over(&fake, "minio");
        assert!(matches!(report.verdict(), RunVerdict::Unqualified(_)));
        let write_leg = report.leg(LegId::WritePath);
        assert_ne!(write_leg.exit, LegExit::Complete);
        assert_eq!(report.leg(LegId::Enumeration).exit, LegExit::NotReached);
        assert!(
            report
                .scenarios()
                .iter()
                .any(|observation| observation.outcome == ScenarioOutcome::Errored),
            "the backend failure surfaced as an errored scenario"
        );
        for observation in report.scenarios() {
            assert_ne!(observation.outcome, ScenarioOutcome::Matched);
        }
    }

    #[test]
    fn unsupported_profile_ends_the_run_at_the_probe_leg() {
        let fake = Fake::honest();
        fake.state.lock().expect("fake lock").fail_probe_multipart = true;
        let report = run_over(&fake, "minio");
        assert_eq!(
            report.verdict(),
            &RunVerdict::Unqualified(REASON_PROFILE),
            "SP-004: multipart is the profile question"
        );
        assert!(!report.profile_supported());
        assert_eq!(report.leg(LegId::Probe).exit, LegExit::Complete);
        for leg in [LegId::WritePath, LegId::Enumeration] {
            assert_eq!(report.leg(leg).exit, LegExit::NotReached);
        }
        for observation in report.scenarios() {
            assert_eq!(observation.outcome, ScenarioOutcome::NotReached);
        }
    }

    #[test]
    fn transcript_renders_clean_and_refuses_forbidden_fields() {
        let report = run_over(&Fake::honest(), "minio");
        let transcript = RunTranscript::from_report(&report, "test-revision");
        let clean = transcript
            .render(&[String::from("a-value-not-in-the-run")])
            .expect("clean render");
        assert!(clean.contains("minio"));
        let violation = transcript
            .render(&[String::from("minio")])
            .expect_err("a configured value the record carries is a violation");
        let message = format!("{violation:?}");
        assert!(!message.contains("minio"), "refusals never echo the value");
        assert!(
            redaction_violations("plain content only", &[]).is_empty(),
            "content-free text is clean"
        );
        assert!(
            !redaction_violations("endpoint https://s3.example.invalid/bucket", &[]).is_empty(),
            "address shapes are violations on their own"
        );
        assert!(
            !redaction_violations("tenant=0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b", &[]).is_empty(),
            "identity-shaped UUIDs are violations on their own"
        );
        assert!(
            !redaction_violations("bucket=raw", &[String::from("raw")]).is_empty(),
            "short configured values are still sensitive"
        );
    }

    #[test]
    fn safe_audit_render_keeps_counts_without_identity_keys() {
        let tenant = tenant();
        let scope = InventoryScope::TenantRaw(tenant.clone());
        let key = InventoryKey::parse(&format!("tenants/{tenant}/v1/raw/objects/synthetic-object"))
            .expect("synthetic audit key");
        let entries = vec![
            VersionedEntry::new(
                key.clone(),
                4,
                StorageVersionId::parse("v1").expect("version"),
                false,
                Observation::new(None, None, observed_at()),
            ),
            VersionedEntry::new(
                key,
                4,
                StorageVersionId::parse("v2").expect("version"),
                true,
                Observation::new(None, None, observed_at()),
            ),
        ];
        let listing =
            FrozenVersionListing::from_pages(&scope, vec![Ok(VersionedPage::new(entries, None))])
                .expect("synthetic version listing");
        let audit = NoncurrentVersionReport::from_listing(&listing);
        let rendered = render_safe_audit(&audit);

        assert!(rendered.contains("scope=tenant-raw"));
        assert!(rendered.contains("versions=2"));
        assert!(rendered.contains("noncurrent=1"));
        assert!(rendered.contains("fullest_key=redacted fullest_noncurrent=1"));
        assert!(!rendered.contains(FIXTURE_TENANT));
    }
}
