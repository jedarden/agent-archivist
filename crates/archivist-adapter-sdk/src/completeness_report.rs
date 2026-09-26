// SPDX-License-Identifier: Apache-2.0

//! The archive-level completeness report (plan Phase 10 deliverable:
//! "Produce versioned Parquet inventories and completeness reports"; plan
//! Section 12's operational objective: "separate semantic and exact-inference
//! coverage counts with no unclassified state").
//!
//! One document joins the five evidence families the archive already
//! classifies, and it is the only place they are published together:
//!
//! - the **raw occurrence** dimension — how many occurrences of a source
//!   committed with a verified receipt, sit pending in the spool, hit an
//!   integrity conflict (plan `EC-06`), or were quarantined before commit
//!   (plan `EC-07`), classified by [`OccurrenceState`];
//! - the **attestation** dimension — whether every committed occurrence's
//!   upload attestation is durable, so an `EC-10` delivery failure stays
//!   visible instead of reading as an accepted upload, classified by
//!   [`AttestationState`];
//! - the **adapter** dimension — how each source's last inventory pass
//!   ended ([`ScanClassification`], the pass-outcome vocabulary of
//!   requirement CAP-010);
//! - the **semantic** dimension — each source's harness-coverage state
//!   ([`CoverageState`], plan Section 12's `missing` … `backfilled`
//!   vocabulary); and
//! - the **exact-inference** dimension — every instrumented route's
//!   ledger partition ([`RouteCoverage`], plan Phase 9), carried verbatim
//!   from the [`InferenceCoverageManifest`] this report links by digest.
//!
//! # The classification contract
//!
//! Every source row classifies all four non-exact dimensions, and no
//! dimension can be left unnamed: the two ingest states are total functions
//! of their counters ([`OccurrenceEvidence::state`],
//! [`AttestationEvidence::state`]), and the adapter and semantic states are
//! constructor parameters of closed enums.  A row without a classified
//! state is unrepresentable, which is the mechanical form of "every source
//! has a classified state".
//!
//! The ingest states are derived worst-condition-first: a refusal,
//! quarantine, or missing attestation names the state even when committed
//! volume exists alongside it, and a source with no evidence at all names
//! [`OccurrenceState::Absent`] explicitly — absence is a state, never an
//! implicit claim of completeness.
//!
//! # What the report refuses to do
//!
//! Like the manifest it links, the type exposes **no** completeness
//! predicate.  A source can be semantically current while a route is
//! exactly unobserved, and both stay visible in their own subtrees; no
//! field, method, or aggregate merges the semantic and exact dimensions or
//! folds either into a completeness claim (threat `EC-13`: unobserved
//! exact traffic is never inferred complete).  A route with no traffic
//! reports the manifest's explicit zeroes — absence of expectations is
//! visible, never promoted to coverage.
//!
//! # Boundedness and provenance
//!
//! The document is content-free like every report in this crate: a fixed
//! key set of closed-vocabulary tokens, version integers, hex digests, and
//! saturating counters — no session, host, path, prompt, provider, or
//! credential text can appear, because no member accepts it.  Per-source
//! rows make the per-source classification readable; the per-dimension
//! count objects are the bounded projection an operator surface can show
//! when row detail does not belong.  Provenance stays traceable without
//! content: each row carries the SHA-256 hex digest of the ingest evidence
//! fold its counters were measured from, the exact section is the linked
//! manifest's own route partition, and the whole document digests
//! canonically so a verification run can name it by digest.

use std::fmt;

use archivist_protocol::json::{Object, Value};
use archivist_protocol::sha256::{digest, encode_hex};
use archivist_protocol::vocabulary::AdapterId;

use crate::coverage_manifest::InferenceCoverageManifest;
use crate::expected_inference::{EXPECTATION_VERSION, RouteCoverage};
use crate::status::{
    AccountLabel, ClassificationCounts, CoverageCounts, CoverageState, ScanClassification, SourceId,
};

/// The schema token of the published completeness report. Growth is a new
/// token — a fixed key set never grows in place.
pub const COMPLETENESS_REPORT_SCHEMA: &str = "archivist.completeness-report/v1";

/// The integer version axis of the report schema, pinned by the token
/// above. A consumer branches on the integer; the token is the human
/// spelling of the same fact.
pub const COMPLETENESS_REPORT_SCHEMA_VERSION: i64 = 1;

/// Why a completeness report was refused. All variants are closed and
/// carry no identifiers or content, keeping errors safe for status/metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportError {
    /// Two rows classify the same `(source, adapter, account)` scope, so a
    /// denominator would count it twice.
    DuplicateSource,
    /// A row's evidence reference is not a lowercase SHA-256 hex digest,
    /// so its classification could not be traced.
    EvidenceDigest,
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::DuplicateSource => "duplicate_source",
            Self::EvidenceDigest => "evidence_digest",
        };
        f.write_str(token)
    }
}

impl std::error::Error for ReportError {}

/// The classified state of a source's raw-occurrence dimension.
///
/// The state names the worst observable condition of the source's
/// occurrence evidence — never an average and never a best case — so a
/// refusal or quarantine stays named no matter how much committed volume
/// stands beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OccurrenceState {
    /// Occurrences committed and receipt-verified; nothing is pending,
    /// conflicted, or quarantined.
    Committed,
    /// At least one occurrence is a retained upload promise without a
    /// verified receipt yet — no receipt, no completeness.
    Pending,
    /// At least one occurrence hit an integrity conflict and was refused
    /// before receipt (plan `EC-06`).
    Conflict,
    /// At least one occurrence was quarantined locally before commit with
    /// a bounded reason (plan `EC-07`).
    Quarantined,
    /// No occurrence evidence exists for this source at all. Absence is
    /// explicit, never an implicit zero or a coverage claim.
    Absent,
}

impl OccurrenceState {
    /// Every state, worst-first within the evidence-bearing states, with
    /// [`OccurrenceState::Absent`] last.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::Committed,
            Self::Pending,
            Self::Conflict,
            Self::Quarantined,
            Self::Absent,
        ]
    }

    /// The bounded report token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Pending => "pending",
            Self::Conflict => "conflict",
            Self::Quarantined => "quarantined",
            Self::Absent => "absent",
        }
    }
}

impl fmt::Display for OccurrenceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// The content-free occurrence counters of one source, as measured from
/// its ingest evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OccurrenceEvidence {
    /// Occurrences committed with a verified receipt.
    pub committed: u64,
    /// Retained upload promises without a verified receipt yet.
    pub pending: u64,
    /// Occurrences refused before receipt on an integrity conflict
    /// (plan `EC-06`).
    pub conflict: u64,
    /// Occurrences quarantined locally before commit (plan `EC-07`).
    pub quarantined: u64,
}

impl OccurrenceEvidence {
    /// The zeroed evidence of a source with no occurrence history.
    pub const ABSENT: Self = Self {
        committed: 0,
        pending: 0,
        conflict: 0,
        quarantined: 0,
    };

    /// The classified state of this evidence, worst-condition-first: a
    /// conflict or quarantine names the state before a pending count
    /// does, a pending count before bare committed volume, and zero
    /// evidence names [`OccurrenceState::Absent`] explicitly.
    #[must_use]
    pub const fn state(self) -> OccurrenceState {
        if self.conflict > 0 {
            OccurrenceState::Conflict
        } else if self.quarantined > 0 {
            OccurrenceState::Quarantined
        } else if self.pending > 0 {
            OccurrenceState::Pending
        } else if self.committed > 0 {
            OccurrenceState::Committed
        } else {
            OccurrenceState::Absent
        }
    }

    /// The bounded report representation: the counters beside the state
    /// they classify, one fixed key set.
    #[must_use]
    pub fn to_json(self) -> Value {
        let mut object = Object::new();
        object.set("committed", Value::Int(saturating_i64(self.committed)));
        object.set("conflict", Value::Int(saturating_i64(self.conflict)));
        object.set("pending", Value::Int(saturating_i64(self.pending)));
        object.set("quarantined", Value::Int(saturating_i64(self.quarantined)));
        object.set("state", Value::Text(self.state().token().to_owned()));
        Value::Object(object)
    }
}

/// The classified state of a source's upload-attestation dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttestationState {
    /// Every committed occurrence's upload attestation is durable.
    Attested,
    /// At least one committed occurrence lacks its durable attestation —
    /// the `EC-10` shape, visible here instead of reading as an accepted
    /// upload.
    Unattested,
    /// No committed occurrence exists to attest. Explicit absence.
    Absent,
}

impl AttestationState {
    /// Every state, worst-first within the evidence-bearing states, with
    /// [`AttestationState::Absent`] last.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Attested, Self::Unattested, Self::Absent]
    }

    /// The bounded report token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Attested => "attested",
            Self::Unattested => "unattested",
            Self::Absent => "absent",
        }
    }
}

impl fmt::Display for AttestationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// The content-free attestation counters of one source, as measured from
/// its ingest evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttestationEvidence {
    /// Committed occurrences whose upload attestation is durable.
    pub attested: u64,
    /// Committed occurrences whose upload attestation is not durable —
    /// the `EC-10` delivery-failure shape.
    pub unattested: u64,
}

impl AttestationEvidence {
    /// The zeroed evidence of a source with nothing committed to attest.
    pub const ABSENT: Self = Self {
        attested: 0,
        unattested: 0,
    };

    /// The classified state of this evidence, worst-condition-first: a
    /// single missing attestation names the state, durable attestations
    /// name theirs, and nothing committed names
    /// [`AttestationState::Absent`] explicitly.
    #[must_use]
    pub const fn state(self) -> AttestationState {
        if self.unattested > 0 {
            AttestationState::Unattested
        } else if self.attested > 0 {
            AttestationState::Attested
        } else {
            AttestationState::Absent
        }
    }

    /// The bounded report representation: the counters beside the state
    /// they classify, one fixed key set.
    #[must_use]
    pub fn to_json(self) -> Value {
        let mut object = Object::new();
        object.set("attested", Value::Int(saturating_i64(self.attested)));
        object.set("state", Value::Text(self.state().token().to_owned()));
        object.set("unattested", Value::Int(saturating_i64(self.unattested)));
        Value::Object(object)
    }
}

/// One source's classified row across the four non-exact dimensions: raw
/// occurrence, attestation, adapter pass, and semantic coverage.
///
/// Every field is a classified state or a bounded counter — the type has
/// no hole a dimension could hide in. Construction is the only way to
/// produce a row, and it derives the two ingest states from their
/// evidence rather than accepting a claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceCompleteness {
    source: SourceId,
    adapter: AdapterId,
    account: AccountLabel,
    occurrence: OccurrenceEvidence,
    attestation: AttestationEvidence,
    adapter_classification: ScanClassification,
    semantic: CoverageState,
    evidence: String,
}

impl SourceCompleteness {
    /// Classify one source from its measured evidence.
    ///
    /// `evidence` is the SHA-256 hex digest of the canonical ingest
    /// evidence fold the two counter families were measured from — the
    /// provenance reference that keeps the classification traceable
    /// without carrying content. It must be 64 lowercase hex characters.
    ///
    /// # Errors
    /// [`ReportError::EvidenceDigest`] when `evidence` is not a
    /// lowercase SHA-256 hex digest.
    #[allow(clippy::too_many_arguments)] // the arguments are the classified row's own members
    pub fn new(
        source: SourceId,
        adapter: AdapterId,
        account: AccountLabel,
        occurrence: OccurrenceEvidence,
        attestation: AttestationEvidence,
        adapter_classification: ScanClassification,
        semantic: CoverageState,
        evidence: String,
    ) -> Result<Self, ReportError> {
        if !is_sha256_hex(&evidence) {
            return Err(ReportError::EvidenceDigest);
        }
        Ok(Self {
            source,
            adapter,
            account,
            occurrence,
            attestation,
            adapter_classification,
            semantic,
            evidence,
        })
    }

    /// The source this row classifies.
    #[must_use]
    pub const fn source(&self) -> &SourceId {
        &self.source
    }

    /// The adapter that captured the source.
    #[must_use]
    pub const fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    /// The configured account label the source was captured under.
    #[must_use]
    pub const fn account(&self) -> &AccountLabel {
        &self.account
    }

    /// The raw-occurrence evidence and its classified state.
    #[must_use]
    pub const fn occurrence(&self) -> OccurrenceEvidence {
        self.occurrence
    }

    /// The attestation evidence and its classified state.
    #[must_use]
    pub const fn attestation(&self) -> AttestationEvidence {
        self.attestation
    }

    /// How the source's last inventory pass ended.
    #[must_use]
    pub const fn adapter_classification(&self) -> ScanClassification {
        self.adapter_classification
    }

    /// The source's semantic harness-coverage state.
    #[must_use]
    pub const fn semantic(&self) -> CoverageState {
        self.semantic
    }

    /// The SHA-256 hex digest of the ingest evidence fold this row's
    /// counters were measured from.
    #[must_use]
    pub fn evidence(&self) -> &str {
        &self.evidence
    }

    /// The scope this row classifies, as the `(source, adapter, account)`
    /// triple compose keys rows on.
    #[must_use]
    pub fn scope(&self) -> (&str, &str, &str) {
        (
            self.source.as_str(),
            self.adapter.as_str(),
            self.account.as_str(),
        )
    }

    /// The bounded report representation: one flat, fixed key set — the
    /// four classified states beside their counters and the evidence
    /// digest. No free text, no content, no exact-inference member: the
    /// exact dimension is per route, never per source.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set("account", Value::Text(self.account.as_str().to_owned()));
        object.set("adapter", Value::Text(self.adapter.as_str().to_owned()));
        object.set(
            "adapter_classification",
            Value::Text(self.adapter_classification.token().to_owned()),
        );
        object.set("attestation", self.attestation.to_json());
        object.set("evidence", Value::Text(self.evidence.clone()));
        object.set("occurrence", self.occurrence.to_json());
        object.set("semantic", Value::Text(self.semantic.token().to_owned()));
        object.set("source", Value::Text(self.source.as_str().to_owned()));
        Value::Object(object)
    }
}

/// Per-state source counts for the occurrence dimension: the bounded
/// replacement for reading the per-source rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OccurrenceCounts {
    /// Sources currently in the committed state.
    pub committed: u64,
    /// Sources currently in the pending state.
    pub pending: u64,
    /// Sources currently in the conflict state.
    pub conflict: u64,
    /// Sources currently in the quarantined state.
    pub quarantined: u64,
    /// Sources currently in the absent state.
    pub absent: u64,
}

impl OccurrenceCounts {
    /// Add one source in `state`.
    pub fn record(&mut self, state: OccurrenceState) {
        match state {
            OccurrenceState::Committed => self.committed += 1,
            OccurrenceState::Pending => self.pending += 1,
            OccurrenceState::Conflict => self.conflict += 1,
            OccurrenceState::Quarantined => self.quarantined += 1,
            OccurrenceState::Absent => self.absent += 1,
        }
    }

    /// The count for one state.
    #[must_use]
    pub const fn get(&self, state: OccurrenceState) -> u64 {
        match state {
            OccurrenceState::Committed => self.committed,
            OccurrenceState::Pending => self.pending,
            OccurrenceState::Conflict => self.conflict,
            OccurrenceState::Quarantined => self.quarantined,
            OccurrenceState::Absent => self.absent,
        }
    }

    /// The number of sources counted, across every state.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.committed + self.pending + self.conflict + self.quarantined + self.absent
    }

    /// The report-JSON object for these counts, keyed by state token.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        for state in OccurrenceState::all() {
            object.set(state.token(), Value::Int(saturating_i64(self.get(state))));
        }
        Value::Object(object)
    }
}

/// Per-state source counts for the attestation dimension.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationCounts {
    /// Sources currently in the attested state.
    pub attested: u64,
    /// Sources currently in the unattested state.
    pub unattested: u64,
    /// Sources currently in the absent state.
    pub absent: u64,
}

impl AttestationCounts {
    /// Add one source in `state`.
    pub fn record(&mut self, state: AttestationState) {
        match state {
            AttestationState::Attested => self.attested += 1,
            AttestationState::Unattested => self.unattested += 1,
            AttestationState::Absent => self.absent += 1,
        }
    }

    /// The count for one state.
    #[must_use]
    pub const fn get(&self, state: AttestationState) -> u64 {
        match state {
            AttestationState::Attested => self.attested,
            AttestationState::Unattested => self.unattested,
            AttestationState::Absent => self.absent,
        }
    }

    /// The number of sources counted, across every state.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.attested + self.unattested + self.absent
    }

    /// The report-JSON object for these counts, keyed by state token.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        for state in AttestationState::all() {
            object.set(state.token(), Value::Int(saturating_i64(self.get(state))));
        }
        Value::Object(object)
    }
}

/// The archive-level completeness report: every source's four classified
/// dimensions beside every instrumented route's exact-coverage partition,
/// in one versioned, content-free document.
///
/// Construct it through [`CompletenessReport::compose`]; the fields are
/// otherwise readable only, so a composed report cannot be edited after
/// the fact. The type deliberately exposes **no** completeness predicate:
/// semantic and exact coverage stay in disjoint subtrees, an unobserved
/// route stays unobserved beside whatever the semantic dimension says,
/// and nothing folds the five dimensions into a claim (threat `EC-13`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletenessReport {
    /// Every source's classified row, ordered by
    /// `(source, adapter, account)` so the canonical bytes are a pure
    /// function of the classified evidence, never of input order.
    sources: Vec<SourceCompleteness>,
    /// Every instrumented route's exact partition, copied verbatim from
    /// the linked manifest in [`crate::expected_inference::RoutePolicy`]
    /// order — including routes with no traffic, whose explicit zeroes
    /// stay visible.
    routes: [RouteCoverage; 2],
    /// The SHA-256 hex digest of the linked [`InferenceCoverageManifest`]'s
    /// canonical bytes: the provenance link between this report's exact
    /// section and the published manifest it was copied from.
    coverage_evidence: String,
    /// Per-state source counts for the occurrence dimension.
    occurrence_states: OccurrenceCounts,
    /// Per-state source counts for the attestation dimension.
    attestation_states: AttestationCounts,
    /// Per-classification source counts for the adapter dimension.
    adapter_classifications: ClassificationCounts,
    /// Per-state source counts for the semantic dimension.
    semantic_states: CoverageCounts,
}

impl CompletenessReport {
    /// Compose the report from one classified row per source and the
    /// published exact-coverage manifest.
    ///
    /// Rows are ordered canonically before composition, so two composes
    /// over the same evidence produce byte-identical documents regardless
    /// of the order rows arrived in. The exact section is the manifest's
    /// own route partition — never recomputed, never merged with anything
    /// semantic — and the manifest's evidence digest is carried as the
    /// report's provenance link.
    ///
    /// # Errors
    /// [`ReportError::DuplicateSource`] when two rows classify the same
    /// `(source, adapter, account)` scope, which would count one
    /// denominator twice.
    pub fn compose(
        mut sources: Vec<SourceCompleteness>,
        manifest: &InferenceCoverageManifest,
    ) -> Result<Self, ReportError> {
        sources.sort_by(|a, b| a.scope().cmp(&b.scope()));
        let mut occurrence_states = OccurrenceCounts::default();
        let mut attestation_states = AttestationCounts::default();
        let mut adapter_classifications = ClassificationCounts::default();
        let mut semantic_states = CoverageCounts::default();
        for index in 1..sources.len() {
            let earlier = &sources[index - 1];
            let later = &sources[index];
            if earlier.source == later.source
                && earlier.adapter == later.adapter
                && earlier.account == later.account
            {
                return Err(ReportError::DuplicateSource);
            }
        }
        for source in &sources {
            occurrence_states.record(source.occurrence.state());
            attestation_states.record(source.attestation.state());
            adapter_classifications.record(source.adapter_classification);
            semantic_states.record(source.semantic);
        }
        Ok(Self {
            sources,
            routes: *manifest.routes(),
            coverage_evidence: manifest.evidence_digest(),
            occurrence_states,
            attestation_states,
            adapter_classifications,
            semantic_states,
        })
    }

    /// Every source's classified row, in canonical
    /// `(source, adapter, account)` order.
    #[must_use]
    pub fn sources(&self) -> &[SourceCompleteness] {
        &self.sources
    }

    /// Every instrumented route's exact partition, in
    /// [`crate::expected_inference::RoutePolicy`] order.
    #[must_use]
    pub const fn routes(&self) -> &[RouteCoverage; 2] {
        &self.routes
    }

    /// The SHA-256 hex digest of the linked coverage manifest's canonical
    /// bytes: where this report's exact section was copied from.
    #[must_use]
    pub fn coverage_evidence(&self) -> &str {
        &self.coverage_evidence
    }

    /// Per-state source counts for the occurrence dimension.
    #[must_use]
    pub const fn occurrence_states(&self) -> &OccurrenceCounts {
        &self.occurrence_states
    }

    /// Per-state source counts for the attestation dimension.
    #[must_use]
    pub const fn attestation_states(&self) -> &AttestationCounts {
        &self.attestation_states
    }

    /// Per-classification source counts for the adapter dimension.
    #[must_use]
    pub const fn adapter_classifications(&self) -> &ClassificationCounts {
        &self.adapter_classifications
    }

    /// Per-state source counts for the semantic dimension.
    #[must_use]
    pub const fn semantic_states(&self) -> &CoverageCounts {
        &self.semantic_states
    }

    /// The bounded report representation: one fixed top-level key set.
    /// The four per-source dimensions live under `sources` and their
    /// aggregate count objects; the exact dimension lives under `routes`
    /// alone. No key mixes the dimensions.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set(
            "adapter_classifications",
            self.adapter_classifications.to_json(),
        );
        object.set("attestation_states", self.attestation_states.to_json());
        object.set(
            "coverage_evidence",
            Value::Text(self.coverage_evidence.clone()),
        );
        object.set("expectation_version", Value::Int(EXPECTATION_VERSION));
        object.set("occurrence_states", self.occurrence_states.to_json());
        object.set(
            "routes",
            Value::Array(self.routes.iter().map(RouteCoverage::to_json).collect()),
        );
        object.set("schema", Value::Text(COMPLETENESS_REPORT_SCHEMA.to_owned()));
        object.set(
            "schema_version",
            Value::Int(COMPLETENESS_REPORT_SCHEMA_VERSION),
        );
        object.set("semantic_states", self.semantic_states.to_json());
        object.set(
            "sources",
            Value::Array(
                self.sources
                    .iter()
                    .map(SourceCompleteness::to_json)
                    .collect(),
            ),
        );
        Value::Object(object)
    }

    /// The canonical RFC 8785 bytes of the report.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.to_json().canonical_bytes()
    }

    /// The SHA-256 hex digest of the canonical bytes: the completeness
    /// evidence a verification run records, content-addressed so the
    /// report can be named without being carried.
    #[must_use]
    pub fn evidence_digest(&self) -> String {
        encode_hex(&digest(&self.canonical_bytes()))
    }
}

impl fmt::Display for CompletenessReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "completeness: sources={} occurrence={} attestation={} adapter={} semantic={} routes={}",
            self.sources.len(),
            self.occurrence_states.total(),
            self.attestation_states.total(),
            self.adapter_classifications.total(),
            self.semantic_states.total(),
            self.routes.len(),
        )
    }
}

/// A SHA-256 hex digest: exactly 64 lowercase hexadecimal characters.
fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Clip a counter into the protocol's signed wire range: counters grow
/// without wrapping into negative wire integers.
fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compatibility::CompatibilityMatrix;
    use crate::ephemeral_flush::{EphemeralCapturePolicy, FlushAbandonment};
    use crate::expected_inference::{
        ExactOutcome, ExpectedInferenceLedger, ExpectedInferenceRecord, InferenceArtifactKind,
        InferenceIdentity, ObservedArtifact, RoutePolicy,
    };
    use crate::status::CoverageState;
    use archivist_protocol::vocabulary::{
        InferenceRequestId, OpaqueId, ProviderAttemptId, Timestamp, TraceId,
    };

    const EVIDENCE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn source(seed: u8) -> SourceId {
        SourceId::parse(&format!("{seed:08x}-1111-5111-8111-000000000001")).expect("source")
    }

    fn account() -> AccountLabel {
        AccountLabel::parse("default").expect("account")
    }

    fn adapter() -> AdapterId {
        AdapterId::parse("claude-code").expect("adapter")
    }

    fn committed_row(seed: u8) -> SourceCompleteness {
        SourceCompleteness::new(
            source(seed),
            adapter(),
            account(),
            OccurrenceEvidence {
                committed: 3,
                ..OccurrenceEvidence::ABSENT
            },
            AttestationEvidence {
                attested: 3,
                unattested: 0,
            },
            ScanClassification::Ok,
            CoverageState::Current,
            EVIDENCE.to_owned(),
        )
        .expect("row")
    }

    fn identity(seed: u8) -> InferenceIdentity {
        InferenceIdentity::new(
            TraceId::parse(&format!("0000000{seed}-1111-7111-8111-000000000001")).expect("trace"),
            InferenceRequestId::parse(&format!("0000000{seed}-2222-7222-8222-000000000002"))
                .expect("inference"),
        )
    }

    fn session(seed: u8) -> OpaqueId {
        OpaqueId::parse(&format!("session-{seed}")).expect("session")
    }

    fn timestamp() -> Timestamp {
        Timestamp::parse("2026-09-20T12:00:00Z").expect("timestamp")
    }

    /// One retained exact artifact on an attempt.
    fn artifact(seed: u8, ordinal: u64, kind: InferenceArtifactKind) -> ObservedArtifact {
        ObservedArtifact::new(
            identity(seed),
            session(seed),
            ProviderAttemptId::parse(&format!("0000000{seed}-3333-7333-8333-{ordinal:012x}"))
                .expect("attempt"),
            ordinal,
            kind,
        )
    }

    /// An explicit incomplete flush: the bounded report an abandoned
    /// wait produces, with no observer traffic needed.
    fn abandoned_flush() -> crate::ephemeral_flush::EphemeralFlushReport {
        crate::ephemeral_flush::EphemeralFlushGate::new(EphemeralCapturePolicy::BestEffort)
            .abandon(FlushAbandonment::StorageOutage)
    }

    /// Walk a report value and refuse any completeness vocabulary outside
    /// the schema token itself: no member name and no other text may name
    /// a completeness claim, so no merged predicate can hide in the
    /// document.
    fn assert_no_completeness_claim(value: &Value, schema: &str) {
        match value {
            Value::Object(object) => {
                for (name, member) in object.iter() {
                    assert!(
                        !name.contains("complete"),
                        "member name {name} names a completeness claim"
                    );
                    assert_no_completeness_claim(member, schema);
                }
            }
            Value::Array(items) => {
                for item in items {
                    assert_no_completeness_claim(item, schema);
                }
            }
            Value::Text(text) if text != schema => assert!(
                !text.contains("complete"),
                "text {text:?} carries a completeness claim"
            ),
            _ => {}
        }
    }

    /// A manifest over a ledger carrying one observed proxy expectation
    /// and one closed-but-unobserved hook expectation: both routes hold
    /// evidence, and neither is complete.
    fn manifest_with_unobserved_route() -> InferenceCoverageManifest {
        let mut ledger = ExpectedInferenceLedger::new();
        ledger
            .persist(ExpectedInferenceRecord::new(
                identity(1),
                session(1),
                RoutePolicy::Proxy,
                timestamp(),
            ))
            .expect("persist proxy");
        ledger
            .record_artifact(artifact(1, 0, InferenceArtifactKind::ProviderRequest))
            .expect("request");
        ledger
            .record_artifact(artifact(1, 0, InferenceArtifactKind::ProviderResponse))
            .expect("response");
        assert_eq!(
            ledger.close_completed(&identity(1)),
            Ok(ExactOutcome::Observed)
        );
        ledger
            .persist(ExpectedInferenceRecord::new(
                identity(2),
                session(2),
                RoutePolicy::SdkHook,
                timestamp(),
            ))
            .expect("persist hook");
        assert_eq!(
            ledger.close_completed(&identity(2)),
            Ok(ExactOutcome::Unobserved)
        );
        let matrix = CompatibilityMatrix::new();
        InferenceCoverageManifest::publish(
            &matrix,
            &ledger,
            CoverageCounts::default(),
            &abandoned_flush(),
        )
    }

    #[test]
    fn occurrence_state_names_the_worst_condition() {
        assert_eq!(OccurrenceEvidence::ABSENT.state(), OccurrenceState::Absent);
        let committed = OccurrenceEvidence {
            committed: 7,
            ..OccurrenceEvidence::ABSENT
        };
        assert_eq!(committed.state(), OccurrenceState::Committed);
        // Pending volume means no receipt yet: never reads as committed.
        let pending = OccurrenceEvidence {
            committed: 7,
            pending: 1,
            ..OccurrenceEvidence::ABSENT
        };
        assert_eq!(pending.state(), OccurrenceState::Pending);
        let quarantined = OccurrenceEvidence {
            committed: 7,
            pending: 1,
            quarantined: 2,
            ..OccurrenceEvidence::ABSENT
        };
        assert_eq!(quarantined.state(), OccurrenceState::Quarantined);
        // A conflict names the state even beside committed volume.
        let conflicted = OccurrenceEvidence {
            committed: 7,
            pending: 1,
            quarantined: 2,
            conflict: 1,
        };
        assert_eq!(conflicted.state(), OccurrenceState::Conflict);
    }

    #[test]
    fn attestation_state_names_the_worst_condition() {
        assert_eq!(
            AttestationEvidence::ABSENT.state(),
            AttestationState::Absent
        );
        let attested = AttestationEvidence {
            attested: 4,
            unattested: 0,
        };
        assert_eq!(attested.state(), AttestationState::Attested);
        // One missing attestation is the EC-10 shape: never reads attested.
        let unattested = AttestationEvidence {
            attested: 4,
            unattested: 1,
        };
        assert_eq!(unattested.state(), AttestationState::Unattested);
    }

    #[test]
    fn row_classifies_every_dimension() {
        let row = committed_row(1);
        assert_eq!(row.occurrence().state(), OccurrenceState::Committed);
        assert_eq!(row.attestation().state(), AttestationState::Attested);
        assert_eq!(row.adapter_classification(), ScanClassification::Ok);
        assert_eq!(row.semantic(), CoverageState::Current);
        assert_eq!(row.evidence(), EVIDENCE);
    }

    #[test]
    fn evidence_reference_must_be_a_sha256_hex_digest() {
        let error = SourceCompleteness::new(
            source(1),
            adapter(),
            account(),
            OccurrenceEvidence::ABSENT,
            AttestationEvidence::ABSENT,
            ScanClassification::Ok,
            CoverageState::Absent,
            "not-a-digest".to_owned(),
        )
        .expect_err("uppercase and short digests are refused");
        assert_eq!(error, ReportError::EvidenceDigest);
        let uppercase = EVIDENCE.to_uppercase();
        let error = SourceCompleteness::new(
            source(1),
            adapter(),
            account(),
            OccurrenceEvidence::ABSENT,
            AttestationEvidence::ABSENT,
            ScanClassification::Ok,
            CoverageState::Absent,
            uppercase,
        )
        .expect_err("uppercase digests are refused");
        assert_eq!(error, ReportError::EvidenceDigest);
    }

    #[test]
    fn compose_folds_every_dimension_and_carries_the_routes() {
        let unattested = SourceCompleteness::new(
            source(2),
            adapter(),
            account(),
            OccurrenceEvidence {
                committed: 2,
                ..OccurrenceEvidence::ABSENT
            },
            AttestationEvidence {
                attested: 1,
                unattested: 1,
            },
            ScanClassification::ReadError,
            CoverageState::Partial,
            EVIDENCE.to_owned(),
        )
        .expect("row");
        let report = CompletenessReport::compose(
            vec![committed_row(1), unattested],
            &manifest_with_unobserved_route(),
        )
        .expect("compose");
        assert_eq!(report.sources().len(), 2);
        assert_eq!(report.occurrence_states().total(), 2);
        // Both rows committed their occurrences: an attestation failure is
        // its own dimension and never demotes the occurrence state.
        assert_eq!(
            report.occurrence_states().get(OccurrenceState::Committed),
            2
        );
        assert_eq!(
            report
                .attestation_states()
                .get(AttestationState::Unattested),
            1
        );
        assert_eq!(
            report
                .adapter_classifications()
                .get(ScanClassification::ReadError),
            1
        );
        assert_eq!(report.semantic_states().get(CoverageState::Current), 1);
        assert_eq!(report.semantic_states().get(CoverageState::Partial), 1);
        // Every instrumented route is present, including the unobserved one.
        let routes = report.routes();
        assert_eq!(routes[0].route, RoutePolicy::Proxy);
        assert_eq!(routes[0].observed, 1);
        assert_eq!(routes[1].route, RoutePolicy::SdkHook);
        assert_eq!(routes[1].unobserved, 1);
    }

    #[test]
    fn compose_refuses_two_rows_for_one_scope() {
        let duplicate = committed_row(1);
        let error = CompletenessReport::compose(
            vec![committed_row(1), duplicate],
            &manifest_with_unobserved_route(),
        )
        .expect_err("one scope twice would count its denominator twice");
        assert_eq!(error, ReportError::DuplicateSource);
    }

    #[test]
    fn compose_is_canonical_regardless_of_input_order() {
        let extra = SourceCompleteness::new(
            source(3),
            adapter(),
            account(),
            OccurrenceEvidence::ABSENT,
            AttestationEvidence::ABSENT,
            ScanClassification::NotObserved,
            CoverageState::Absent,
            EVIDENCE.to_owned(),
        )
        .expect("row");
        let forward = CompletenessReport::compose(
            vec![committed_row(1), extra.clone()],
            &manifest_with_unobserved_route(),
        )
        .expect("compose");
        let reversed = CompletenessReport::compose(
            vec![extra, committed_row(1)],
            &manifest_with_unobserved_route(),
        )
        .expect("compose");
        assert_eq!(forward.canonical_bytes(), reversed.canonical_bytes());
        assert_eq!(forward.evidence_digest(), reversed.evidence_digest());
    }

    #[test]
    fn unobserved_exact_traffic_is_never_inferred_complete() {
        // The source is semantically current; the hook route closed
        // unobserved. Both facts must survive into the same document.
        let report =
            CompletenessReport::compose(vec![committed_row(1)], &manifest_with_unobserved_route())
                .expect("compose");
        let text = String::from_utf8(report.canonical_bytes()).expect("utf8");
        assert!(text.contains("\"semantic\":\"current\""));
        assert!(text.contains("\"unobserved\":1"));
        assert!(text.contains("\"route\":\"sdk_hook\""));
        let json = report.to_json();
        // No completeness claim exists anywhere in the document: no
        // merged predicate, no complete token, no summed dimension. The
        // schema token names the document kind rather than any claim, so
        // it is the one allowed mention.
        assert_no_completeness_claim(&json, COMPLETENESS_REPORT_SCHEMA);
        // The dimensions stay in disjoint subtrees: the semantic count
        // object never names a route, and the route rows never name a
        // semantic state.
        assert!(!text.contains("\"semantic_states\":{\"absent"));
        let Value::Object(object) = &json else {
            panic!("report is an object");
        };
        let Value::Object(semantic) = object
            .iter()
            .find(|(name, _)| *name == "semantic_states")
            .map_or(&Value::Null, |(_, value)| value)
        else {
            panic!("semantic_states is an object");
        };
        for name in semantic.iter().map(|(name, _)| name) {
            assert!(
                RoutePolicy::parse(name).is_err(),
                "semantic subtree carried the route token {name}"
            );
        }
    }

    #[test]
    fn provenance_stays_traceable_through_the_digest_chain() {
        let manifest = manifest_with_unobserved_route();
        let report =
            CompletenessReport::compose(vec![committed_row(1)], &manifest).expect("compose");
        // The report links the exact section to the manifest it copied.
        assert_eq!(report.coverage_evidence(), manifest.evidence_digest());
        // Each row carries its own ingest-evidence reference.
        assert!(
            report
                .sources()
                .iter()
                .all(|row| is_sha256_hex(row.evidence()))
        );
        // The document itself is content-addressed, and different
        // evidence digests differently.
        let digest = report.evidence_digest();
        assert!(is_sha256_hex(&digest));
        let drifted = SourceCompleteness::new(
            source(1),
            adapter(),
            account(),
            OccurrenceEvidence {
                committed: 4,
                ..OccurrenceEvidence::ABSENT
            },
            AttestationEvidence {
                attested: 3,
                unattested: 0,
            },
            ScanClassification::Ok,
            CoverageState::Current,
            EVIDENCE.to_owned(),
        )
        .expect("row");
        let drifted = CompletenessReport::compose(vec![drifted], &manifest).expect("compose");
        assert_ne!(drifted.evidence_digest(), digest);
    }

    #[test]
    fn the_report_is_versioned_and_content_free() {
        let report =
            CompletenessReport::compose(vec![committed_row(1)], &manifest_with_unobserved_route())
                .expect("compose");
        let json = report.to_json();
        let Value::Object(object) = &json else {
            panic!("report is an object");
        };
        let names: Vec<_> = object.iter().map(|(name, _)| name).collect();
        assert_eq!(
            names,
            vec![
                "adapter_classifications",
                "attestation_states",
                "coverage_evidence",
                "expectation_version",
                "occurrence_states",
                "routes",
                "schema",
                "schema_version",
                "semantic_states",
                "sources",
            ]
        );
        let Some(Value::Text(schema)) = object
            .iter()
            .find(|(name, _)| *name == "schema")
            .map(|(_, value)| value)
        else {
            panic!("schema member is text");
        };
        assert_eq!(schema, COMPLETENESS_REPORT_SCHEMA);
        assert_eq!(schema, "archivist.completeness-report/v1");
        assert_eq!(report.to_json(), json);
    }
}
