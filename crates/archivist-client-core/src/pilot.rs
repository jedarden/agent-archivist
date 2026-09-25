// SPDX-License-Identifier: Apache-2.0

//! The archive inventory comparator (plan Phase 8; the `pilot compare`
//! command's engine): one read-only pass that joins a content-free legacy
//! collector inventory against everything the local Archivist state has
//! acknowledged, and classifies every difference into the closed gap
//! vocabulary the metrics registry pins (`gap_class`: `matched`,
//! `missing_new`, `missing_legacy`, `digest_mismatch`, `unexplained`).
//!
//! The two evidence sources never meet as content:
//!
//! - **The legacy inventory document** ([`LegacyInventory`]): the operand
//!   the deployment-specific legacy collector exports out of band, its
//!   closed shape pinned by the parser under the namespace
//!   [`LEGACY_INVENTORY_NAMESPACE`]. Every member is a
//!   derived identity hash, a closed-vocabulary token, or an integer —
//!   the same content-free rule the fleet inventory's sanitization
//!   contract set. No path, host, account value, or transcript byte can
//!   appear, because the grammar has no field that could carry one.
//! - **The Archivist state** (the `sources`, `generations`, `ranges`, and
//!   `upload_attestations` tables of [`crate::state`], read through a
//!   read-only snapshot): what the new collector has actually
//!   acknowledged, occurrence by occurrence, with the provenance of who
//!   uploaded each one.
//!
//! Sources join on the derived pair (`session_hash`, `artifact_hash`) —
//! never on a path or an upstream identifier — and occurrences join on
//! the position tuple (range kind, start, end) within a source,
//! comparing blob digests. The join deliberately folds the new side's
//! generations: two generations of one artifact can legitimately hold
//! the same position with different payloads (plan `EC-02` preserves
//! both histories), so a position maps to a *set* of payloads on the new
//! side. The legacy side cannot express generations, so a legacy
//! position naming two different payloads is evidence contradicting
//! itself and classifies [`GapClass::Unexplained`] — the difference
//! stays explicit instead of being silently resolved.
//!
//! # Provenance is never erased by overlap
//!
//! An occurrence both collectors hold is *matched*, and matching never
//! collapses the two collections into one: the report counts
//! `sources_both` and per-relation upload attestations separately from
//! occurrence classes, so a relay re-uploading an occurrence the origin
//! already committed (the STO-002/STO-004 convergence) adds provenance
//! rather than
//! replacing it. Identical duplicate entries within one side's evidence
//! collapse — identity is the deduplication — but they are counted
//! (`legacy_duplicates`, `new_duplicates`), so an export merging two
//! overlapping legacy collectors stays visible as overlap, not silence.
//!
//! # Every unexplained difference stays explicit
//!
//! The comparator explains what its evidence can explain and refuses to
//! guess the rest. A difference is `unexplained` exactly when the legacy
//! evidence contradicts itself (one position, two payloads); the verdict
//! and the per-class counters keep that count in front of the operator,
//! because the plan blocks the source-of-record change on reconciling
//! unexplained differences — never on hiding them.
//!
//! # Signed pilot evidence
//!
//! The report is a pure function of its two inputs: sources render in
//! canonical (`session_hash`, `artifact_hash`) order, and `digest` is the
//! SHA-256 of the `pilot-comparison-v1` framed preimage over *every*
//! union source — matched sources included — so a signed cutover
//! checklist that names the digest binds the whole comparison, while the
//! document itself lists only the differing sources an operator must
//! reconcile. The digest excludes the report's own `generated_at`, so
//! re-running the comparison over the same evidence reproduces it.

use std::collections::{BTreeSet, HashMap, HashSet};

use archivist_adapter_sdk::status::{CoverageState, FreshnessLane};
use archivist_protocol::derivation::FrameBuilder;
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{
    AdapterId, ArtifactHash, BlobDigest, RangeKind, SessionHash, Timestamp,
};
use rusqlite::Connection;

use crate::inventory::bounded_i64;
use crate::state::{StateError, StateErrorKind};

/// The operand document's namespace member: the value a consumer checks
/// before treating a document as legacy inventory evidence. The closed
/// shape behind the member is pinned by [`LegacyInventory::parse`] — the
/// parser is the shape's only validation authority.
pub const LEGACY_INVENTORY_NAMESPACE: &str = "archivist.pilot-legacy-inventory/v1";

/// The operand document's input bound: 64 MiB. At the document's
/// per-occurrence shape a six-figure occurrence inventory stays an order
/// of magnitude below the bound, so this caps parse work against
/// unbounded input rather than describing a measured export.
pub const LEGACY_INVENTORY_MAX_BYTES: usize = 64 * 1024 * 1024;

/// The report digest's domain label (`pilot-comparison-v1`): SHA-256
/// over the framed per-source comparison table documented on
/// [`ComparisonReport::digest`], built with the protocol's labeled
/// framing so a standalone verifier reproduces it without this crate.
pub const COMPARISON_DIGEST_LABEL: &str = "pilot-comparison-v1";

/// Why a legacy inventory document could not become evidence. Every
/// refusal is content-free: the detail names the structural defect,
/// never the bytes that exhibited it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyInventoryErrorKind {
    /// The bytes are not JSON, or not the no-float value domain.
    MalformedJson,
    /// A member was missing, of the wrong kind, or outside the closed
    /// shape the schema pins.
    MalformedShape,
    /// An identity hash, token, timestamp, or range coordinate was
    /// outside its grammar.
    MalformedGrammar,
    /// Two source entries claimed one (`session_hash`, `artifact_hash`)
    /// pair, making the join ambiguous.
    DuplicateSource,
}

impl LegacyInventoryErrorKind {
    /// The closed, content-free detail for this kind.
    #[must_use]
    pub fn detail(self) -> &'static str {
        match self {
            Self::MalformedJson => "the legacy inventory document is not valid JSON",
            Self::MalformedShape => {
                "the legacy inventory document violates its pinned closed shape"
            }
            Self::MalformedGrammar => {
                "the legacy inventory document carries a value outside its grammar"
            }
            Self::DuplicateSource => "the legacy inventory document declares one source pair twice",
        }
    }
}

/// A rejected legacy inventory document: the kind of defect, carried
/// without any of the bytes that exhibited it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyInventoryError {
    kind: LegacyInventoryErrorKind,
}

impl LegacyInventoryError {
    /// The kind of defect the document carried.
    #[must_use]
    pub fn kind(&self) -> LegacyInventoryErrorKind {
        self.kind
    }

    /// The closed, content-free detail for the defect.
    #[must_use]
    pub fn detail(&self) -> &'static str {
        self.kind.detail()
    }
}

impl std::fmt::Display for LegacyInventoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind.detail())
    }
}

impl std::error::Error for LegacyInventoryError {}

/// One occurrence position inside a source: the range kind with its
/// coordinates. Generations are deliberately absent — the new side folds
/// them (a position maps to a set of payloads), and the legacy side
/// cannot express them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Position {
    kind: RangeKind,
    start: u64,
    end: u64,
}

/// One side's evidence for a source: the payload digests observed at
/// each position, the raw entry counts, and the derived byte/event
/// sums. Shared by both sides so the comparison is symmetric arithmetic
/// over one shape.
#[derive(Clone, Debug, Default)]
struct SourceEvidence {
    positions: HashMap<Position, BTreeSet<[u8; 32]>>,
    entries: u64,
    bytes: u64,
    events: u64,
    duplicates: u64,
}

impl SourceEvidence {
    /// Fold one occurrence entry into the evidence. The first payload at
    /// a position extends the set; an identical repeat is duplication
    /// converging on one identity (counted, never silently dropped).
    fn record(&mut self, kind: RangeKind, start: u64, end: u64, digest: [u8; 32]) {
        let position = Position { kind, start, end };
        let span = end.saturating_sub(start);
        match kind {
            RangeKind::Byte => self.bytes = self.bytes.saturating_add(span),
            RangeKind::Event => self.events = self.events.saturating_add(span),
        }
        self.entries = self.entries.saturating_add(1);
        if self
            .positions
            .get(&position)
            .is_some_and(|payloads| payloads.contains(&digest))
        {
            self.duplicates = self.duplicates.saturating_add(1);
        }
        self.positions.entry(position).or_default().insert(digest);
    }

    /// The total number of distinct payloads the evidence holds, at
    /// every position — the denominator class counts come from.
    fn total_payloads(&self) -> u64 {
        self.positions
            .values()
            .map(|payloads| u64::try_from(payloads.len()).unwrap_or(u64::MAX))
            .fold(0u64, u64::saturating_add)
    }
}

/// One legacy source entry: the join keys, the legacy collector's own
/// coverage classification of the source, its adapter token, and the
/// occurrence evidence it holds.
#[derive(Clone, Debug)]
pub struct LegacySource {
    session: SessionHash,
    artifact: ArtifactHash,
    adapter: AdapterId,
    coverage: CoverageState,
    evidence: SourceEvidence,
}

impl LegacySource {
    /// The session-namespace hash the source joins on.
    #[must_use]
    pub fn session(&self) -> &SessionHash {
        &self.session
    }

    /// The artifact hash the source joins on.
    #[must_use]
    pub fn artifact(&self) -> &ArtifactHash {
        &self.artifact
    }

    /// The legacy collector's own coverage classification of the source.
    #[must_use]
    pub fn coverage(&self) -> CoverageState {
        self.coverage
    }
}

/// The parsed legacy inventory document: the export instant and the
/// per-source evidence, with every join key unique.
#[derive(Clone, Debug)]
pub struct LegacyInventory {
    generated_at: Timestamp,
    sources: Vec<LegacySource>,
}

impl LegacyInventory {
    /// Parse and validate a legacy inventory document against the closed
    /// shape this parser pins. Validation is the parser: an unknown
    /// namespace, an unknown member, a token outside a closed
    /// vocabulary, an identity hash outside its grammar, or a duplicate
    /// join key refuses the whole document — the comparator never
    /// compares partial evidence.
    ///
    /// # Errors
    /// [`LegacyInventoryError`], content-free, for the first structural
    /// defect: [`LegacyInventoryErrorKind::MalformedJson`] for bytes
    /// outside the value domain, `MalformedShape` for a member outside
    /// the closed shape, `MalformedGrammar` for a value outside its
    /// grammar, `DuplicateSource` for an ambiguous join.
    pub fn parse(bytes: &[u8]) -> Result<Self, LegacyInventoryError> {
        let document =
            json::parse_with_limits(bytes, LEGACY_INVENTORY_MAX_BYTES, json::DEFAULT_MAX_DEPTH)
                .map_err(|_| LegacyInventoryError {
                    kind: LegacyInventoryErrorKind::MalformedJson,
                })?;
        let Value::Object(members) = document else {
            return Err(LegacyInventoryError {
                kind: LegacyInventoryErrorKind::MalformedShape,
            });
        };
        if !closed_shape(&members, DOCUMENT_MEMBERS) {
            return Err(LegacyInventoryError {
                kind: LegacyInventoryErrorKind::MalformedShape,
            });
        }
        match members.get("schema") {
            Some(Value::Text(namespace)) if namespace.as_str() == LEGACY_INVENTORY_NAMESPACE => {}
            _ => {
                return Err(LegacyInventoryError {
                    kind: LegacyInventoryErrorKind::MalformedShape,
                });
            }
        }
        let generated_at = match members.get("generated_at") {
            Some(Value::Text(text)) => {
                Timestamp::parse(text).map_err(|_| LegacyInventoryError {
                    kind: LegacyInventoryErrorKind::MalformedGrammar,
                })?
            }
            _ => {
                return Err(LegacyInventoryError {
                    kind: LegacyInventoryErrorKind::MalformedShape,
                });
            }
        };
        let entries = match members.get("sources") {
            Some(Value::Array(entries)) => entries.as_slice(),
            _ => {
                return Err(LegacyInventoryError {
                    kind: LegacyInventoryErrorKind::MalformedShape,
                });
            }
        };
        let mut sources = Vec::new();
        let mut seen: HashSet<(SessionHash, ArtifactHash)> = HashSet::new();
        for entry in entries {
            let Value::Object(source) = entry else {
                return Err(LegacyInventoryError {
                    kind: LegacyInventoryErrorKind::MalformedShape,
                });
            };
            let legacy = parse_legacy_source(source)?;
            if !seen.insert((legacy.session, legacy.artifact)) {
                return Err(LegacyInventoryError {
                    kind: LegacyInventoryErrorKind::DuplicateSource,
                });
            }
            sources.push(legacy);
        }
        Ok(Self {
            generated_at,
            sources,
        })
    }

    /// The export instant the legacy document carries.
    #[must_use]
    pub fn generated_at(&self) -> &Timestamp {
        &self.generated_at
    }

    /// The per-source evidence, in document order.
    #[must_use]
    pub fn sources(&self) -> &[LegacySource] {
        &self.sources
    }
}

/// Parse one `sources` array member: join keys, adapter, coverage, and
/// the occurrence list, each against its grammar.
fn parse_legacy_source(source: &Object) -> Result<LegacySource, LegacyInventoryError> {
    let malformed_shape = || LegacyInventoryError {
        kind: LegacyInventoryErrorKind::MalformedShape,
    };
    if !closed_shape(source, SOURCE_MEMBERS) {
        return Err(malformed_shape());
    }
    let malformed_grammar = || LegacyInventoryError {
        kind: LegacyInventoryErrorKind::MalformedGrammar,
    };
    let session =
        SessionHash::parse(text_of(source, "session_hash")?).map_err(|_| malformed_grammar())?;
    let artifact =
        ArtifactHash::parse(text_of(source, "artifact_hash")?).map_err(|_| malformed_grammar())?;
    let adapter = AdapterId::parse(text_of(source, "adapter")?).map_err(|_| malformed_grammar())?;
    let coverage =
        CoverageState::parse(text_of(source, "coverage")?).map_err(|_| malformed_grammar())?;
    let occurrences = match source.get("occurrences") {
        Some(Value::Array(entries)) => entries.as_slice(),
        _ => return Err(malformed_shape()),
    };
    let mut evidence = SourceEvidence::default();
    for entry in occurrences {
        let Value::Object(occurrence) = entry else {
            return Err(malformed_shape());
        };
        if !closed_shape(occurrence, OCCURRENCE_MEMBERS) {
            return Err(malformed_shape());
        }
        let kind = RangeKind::parse(text_of(occurrence, "range_kind")?)
            .map_err(|_| malformed_grammar())?;
        let start = u63_of(occurrence, "range_start")?;
        let end = u63_of(occurrence, "range_end")?;
        if end < start {
            return Err(malformed_grammar());
        }
        let digest = BlobDigest::parse(text_of(occurrence, "blob_digest")?)
            .map_err(|_| malformed_grammar())?;
        evidence.record(kind, start, end, digest.as_raw().to_owned());
    }
    Ok(LegacySource {
        session,
        artifact,
        adapter,
        coverage,
        evidence,
    })
}

/// A required text member: the borrowed value, or the shape refusal.
fn text_of<'a>(members: &'a Object, name: &str) -> Result<&'a str, LegacyInventoryError> {
    match members.get(name) {
        Some(Value::Text(text)) => Ok(text.as_str()),
        _ => Err(LegacyInventoryError {
            kind: LegacyInventoryErrorKind::MalformedShape,
        }),
    }
}

/// A required `u63` member: non-negative, integral by the value domain's
/// construction.
fn u63_of(members: &Object, name: &str) -> Result<u64, LegacyInventoryError> {
    match members.get(name) {
        Some(Value::Int(value)) if *value >= 0 => Ok(u64::try_from(*value).unwrap_or(u64::MAX)),
        _ => Err(LegacyInventoryError {
            kind: LegacyInventoryErrorKind::MalformedShape,
        }),
    }
}

/// The member names each level of the operand document may carry. The
/// JSON layer already rejects duplicate names, so an unknown member is
/// the only way to widen the document past its grammar — refused, so no
/// byte can enter the evidence under a name no comparison ever reads.
const DOCUMENT_MEMBERS: &[&str] = &["schema", "generated_at", "sources"];
const SOURCE_MEMBERS: &[&str] = &[
    "session_hash",
    "artifact_hash",
    "adapter",
    "coverage",
    "occurrences",
];
const OCCURRENCE_MEMBERS: &[&str] = &["range_kind", "range_start", "range_end", "blob_digest"];

/// Reject any member outside the closed shape: `true` when every member
/// name is one the grammar defines.
fn closed_shape(members: &Object, known: &[&str]) -> bool {
    members.iter().all(|(name, _)| known.contains(&name))
}

/// One new-side source: the state's lane and adapter for it, its
/// occurrence evidence, and the provenance the acknowledgement path
/// recorded.
#[derive(Clone, Debug)]
struct NewSource {
    lane: FreshnessLane,
    adapter: AdapterId,
    evidence: SourceEvidence,
    attestations_direct: u64,
    attestations_relay: u64,
}

/// The new side of the comparison: every state-known source with its
/// acknowledged occurrences and upload attestations.
#[derive(Clone, Debug, Default)]
struct NewInventory {
    sources: HashMap<(SessionHash, ArtifactHash), NewSource>,
}

/// The closed gap vocabulary the comparator's reports pin: the
/// classification of a coverage difference between collectors, spelled
/// the way an operator dashboard's `gap_class` breakdown renders it.
/// The tokens are wire-stable — renaming one rewrites every report that
/// ever carried it — so a signed cutover checklist can join on them
/// directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GapClass {
    /// Both sides hold the occurrence with the same canonical digest.
    Matched,
    /// The legacy inventory holds it and the new archive does not — the
    /// new collector must catch up before cutover.
    MissingNew,
    /// The new archive holds it and the legacy inventory does not —
    /// coverage the legacy path never established.
    MissingLegacy,
    /// Both sides hold the same position with disjoint canonical
    /// digests: a payload disagreement an operator must adjudicate.
    DigestMismatch,
    /// The evidence contradicts itself and no explanation closes the
    /// difference; reconciliation is blocked on a human decision.
    Unexplained,
}

impl GapClass {
    /// Every class, in severity order: integrity, then the new
    /// archive's gaps, then the legacy archive's gaps, then agreement.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Unexplained,
            Self::DigestMismatch,
            Self::MissingNew,
            Self::MissingLegacy,
            Self::Matched,
        ]
    }

    /// The canonical token (the `gap_class` label value).
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::MissingNew => "missing_new",
            Self::MissingLegacy => "missing_legacy",
            Self::DigestMismatch => "digest_mismatch",
            Self::Unexplained => "unexplained",
        }
    }

    /// Parse one token, failing closed on anything unknown: `None` is
    /// evidence outside the vocabulary, never a guess.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "matched" => Some(Self::Matched),
            "missing_new" => Some(Self::MissingNew),
            "missing_legacy" => Some(Self::MissingLegacy),
            "digest_mismatch" => Some(Self::DigestMismatch),
            "unexplained" => Some(Self::Unexplained),
            _ => None,
        }
    }
}

/// The report's overall verdict: what stands between the two
/// inventories and the cutover checklist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every union source matched: the two archives hold the same
    /// evidence.
    Equivalent,
    /// Differences exist and every one of them is explained by its gap
    /// class; none is unexplained.
    Differences,
    /// At least one difference is unexplained; the plan's
    /// reconcile-before-cutover rule blocks the source-of-record change
    /// until a human closes it.
    Unexplained,
}

impl Verdict {
    /// The canonical token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::Differences => "differences",
            Self::Unexplained => "unexplained",
        }
    }
}

/// The occurrence-level outcome of one source's comparison: per-class
/// payload counts over the union of the two sides' positions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OccurrenceClasses {
    /// Payloads both sides hold identically at one position.
    pub matched: u64,
    /// Legacy-only payloads.
    pub missing_new: u64,
    /// New-only payloads.
    pub missing_legacy: u64,
    /// Payloads party to a position the sides hold with disjoint
    /// digests.
    pub digest_mismatch: u64,
    /// Payloads at legacy positions that name two different payloads:
    /// evidence contradicting itself.
    pub unexplained: u64,
}

impl OccurrenceClasses {
    /// Total classified payloads.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.matched
            .saturating_add(self.missing_new)
            .saturating_add(self.missing_legacy)
            .saturating_add(self.digest_mismatch)
            .saturating_add(self.unexplained)
    }

    /// The dominant source-level class these occurrence outcomes imply,
    /// by severity: a self-contradiction outranks a digest conflict,
    /// which outranks a new-archive gap, which outranks a legacy-archive
    /// gap.
    #[must_use]
    pub fn dominant_gap_class(&self) -> GapClass {
        if self.unexplained > 0 {
            GapClass::Unexplained
        } else if self.digest_mismatch > 0 {
            GapClass::DigestMismatch
        } else if self.missing_new > 0 {
            GapClass::MissingNew
        } else if self.missing_legacy > 0 {
            GapClass::MissingLegacy
        } else {
            GapClass::Matched
        }
    }
}

/// One union source's comparison result: the full content-free evidence
/// row. Matched sources are counted in the report's totals and enter the
/// digest, but are not listed in its `differences` array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceComparison {
    session: SessionHash,
    artifact: ArtifactHash,
    gap_class: GapClass,
    legacy_present: bool,
    new_present: bool,
    legacy_coverage: Option<CoverageState>,
    new_coverage: CoverageState,
    legacy_adapter: Option<AdapterId>,
    new_adapter: Option<AdapterId>,
    bytes_legacy: u64,
    bytes_new: u64,
    events_legacy: u64,
    events_new: u64,
    occurrences: OccurrenceClasses,
    legacy_duplicates: u64,
    new_duplicates: u64,
    attestations_direct: u64,
    attestations_relay: u64,
}

impl SourceComparison {
    /// The session-namespace hash the source joined on.
    #[must_use]
    pub fn session(&self) -> &SessionHash {
        &self.session
    }

    /// The artifact hash the source joined on.
    #[must_use]
    pub fn artifact(&self) -> &ArtifactHash {
        &self.artifact
    }

    /// The source's gap class.
    #[must_use]
    pub fn gap_class(&self) -> GapClass {
        self.gap_class
    }
}

/// Source-grain counts per gap class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceClassCounts {
    /// Sources classified `matched`.
    pub matched: u64,
    /// Sources classified `missing_new`.
    pub missing_new: u64,
    /// Sources classified `missing_legacy`.
    pub missing_legacy: u64,
    /// Sources classified `digest_mismatch`.
    pub digest_mismatch: u64,
    /// Sources classified `unexplained`.
    pub unexplained: u64,
}

impl SourceClassCounts {
    /// Total classified sources.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.matched
            .saturating_add(self.missing_new)
            .saturating_add(self.missing_legacy)
            .saturating_add(self.digest_mismatch)
            .saturating_add(self.unexplained)
    }
}

/// Fleet occurrence-grain counts, per gap class plus the within-side
/// duplication the comparison collapsed — provenance overlap made
/// visible rather than dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OccurrenceClassCounts {
    /// Per-class payload counts across every union source.
    pub classes: OccurrenceClasses,
    /// Identical duplicate entries the legacy export carried: two
    /// legacy collectors converging on one identity.
    pub legacy_duplicates: u64,
    /// Identical duplicate rows the new state carries across
    /// generations of one artifact (plan `EC-02`).
    pub new_duplicates: u64,
}

/// The cross-collector provenance figures: overlap retained, never
/// erased by matching.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProvenanceCounts {
    /// Sources present in both inventories.
    pub sources_both: u64,
    /// Direct upload attestations the new state recorded.
    pub attestations_direct: u64,
    /// Relay upload attestations the new state recorded: re-uploads
    /// that added provenance beside the origin's, never replaced it.
    pub attestations_relay: u64,
}

/// The complete comparison result: the verdict, the digest that binds
/// the whole table, the per-class totals, and the differing sources an
/// operator must reconcile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComparisonReport {
    generated_at: Timestamp,
    legacy_generated_at: Timestamp,
    verdict: Verdict,
    digest: String,
    sources: SourceClassCounts,
    occurrences: OccurrenceClassCounts,
    provenance: ProvenanceCounts,
    differences: Vec<SourceComparison>,
}

impl ComparisonReport {
    /// The instant the comparison ran. Deliberately outside the digest
    /// preimage: the digest binds the evidence, not the run.
    #[must_use]
    pub fn generated_at(&self) -> &Timestamp {
        &self.generated_at
    }

    /// The legacy export instant the comparison joined against.
    #[must_use]
    pub fn legacy_generated_at(&self) -> &Timestamp {
        &self.legacy_generated_at
    }

    /// The overall verdict.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// The lowercase-hex SHA-256 of the `pilot-comparison-v1` framed
    /// preimage over every union source in canonical order — matched
    /// sources included — so a signature over this digest binds the
    /// complete comparison, not only the listed differences.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Source-grain per-class counts.
    #[must_use]
    pub fn sources(&self) -> &SourceClassCounts {
        &self.sources
    }

    /// Occurrence-grain per-class counts and duplication figures.
    #[must_use]
    pub fn occurrences(&self) -> &OccurrenceClassCounts {
        &self.occurrences
    }

    /// The cross-collector provenance figures.
    #[must_use]
    pub fn provenance(&self) -> &ProvenanceCounts {
        &self.provenance
    }

    /// The differing sources, in canonical order. Matched sources are
    /// counted and digested, never listed.
    #[must_use]
    pub fn differences(&self) -> &[SourceComparison] {
        &self.differences
    }

    /// The report-JSON value: every member a counter, a closed-vocabulary
    /// token, a derived identity hash, or a timestamp — nothing a path or
    /// a transcript byte could ride in on.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set(
            "generated_at",
            Value::Text(self.generated_at.as_str().to_owned()),
        );
        object.set("verdict", Value::Text(self.verdict.token().to_owned()));
        object.set("digest", Value::Text(self.digest.clone()));
        object.set(
            "legacy_generated_at",
            Value::Text(self.legacy_generated_at.as_str().to_owned()),
        );
        let mut sources = Object::new();
        sources.set("total", Value::Int(bounded_i64(self.sources.total())));
        sources.set("matched", Value::Int(bounded_i64(self.sources.matched)));
        sources.set(
            "missing_new",
            Value::Int(bounded_i64(self.sources.missing_new)),
        );
        sources.set(
            "missing_legacy",
            Value::Int(bounded_i64(self.sources.missing_legacy)),
        );
        sources.set(
            "digest_mismatch",
            Value::Int(bounded_i64(self.sources.digest_mismatch)),
        );
        sources.set(
            "unexplained",
            Value::Int(bounded_i64(self.sources.unexplained)),
        );
        object.set("sources", Value::Object(sources));
        let mut occurrences = Object::new();
        occurrences.set(
            "total",
            Value::Int(bounded_i64(self.occurrences.classes.total())),
        );
        occurrences.set(
            "matched",
            Value::Int(bounded_i64(self.occurrences.classes.matched)),
        );
        occurrences.set(
            "missing_new",
            Value::Int(bounded_i64(self.occurrences.classes.missing_new)),
        );
        occurrences.set(
            "missing_legacy",
            Value::Int(bounded_i64(self.occurrences.classes.missing_legacy)),
        );
        occurrences.set(
            "digest_mismatch",
            Value::Int(bounded_i64(self.occurrences.classes.digest_mismatch)),
        );
        occurrences.set(
            "unexplained",
            Value::Int(bounded_i64(self.occurrences.classes.unexplained)),
        );
        occurrences.set(
            "legacy_duplicates",
            Value::Int(bounded_i64(self.occurrences.legacy_duplicates)),
        );
        occurrences.set(
            "new_duplicates",
            Value::Int(bounded_i64(self.occurrences.new_duplicates)),
        );
        object.set("occurrences", Value::Object(occurrences));
        let mut provenance = Object::new();
        provenance.set(
            "sources_both",
            Value::Int(bounded_i64(self.provenance.sources_both)),
        );
        provenance.set(
            "attestations_direct",
            Value::Int(bounded_i64(self.provenance.attestations_direct)),
        );
        provenance.set(
            "attestations_relay",
            Value::Int(bounded_i64(self.provenance.attestations_relay)),
        );
        object.set("provenance", Value::Object(provenance));
        object.set(
            "differences",
            Value::Array(
                self.differences
                    .iter()
                    .map(source_comparison_json)
                    .collect(),
            ),
        );
        Value::Object(object)
    }
}

/// One difference row's JSON: the bounded, content-free evidence an
/// operator reconciles from.
fn source_comparison_json(comparison: &SourceComparison) -> Value {
    let mut object = Object::new();
    object.set("session_hash", Value::Text(comparison.session.to_hex()));
    object.set("artifact_hash", Value::Text(comparison.artifact.to_hex()));
    object.set(
        "gap_class",
        Value::Text(comparison.gap_class.token().to_owned()),
    );
    object.set(
        "legacy_coverage",
        comparison.legacy_coverage.map_or(Value::Null, |coverage| {
            Value::Text(coverage.token().to_owned())
        }),
    );
    object.set(
        "new_coverage",
        Value::Text(comparison.new_coverage.token().to_owned()),
    );
    object.set(
        "adapter_legacy",
        comparison
            .legacy_adapter
            .as_ref()
            .map_or(Value::Null, |adapter| {
                Value::Text(adapter.as_str().to_owned())
            }),
    );
    object.set(
        "adapter_new",
        comparison
            .new_adapter
            .as_ref()
            .map_or(Value::Null, |adapter| {
                Value::Text(adapter.as_str().to_owned())
            }),
    );
    object.set(
        "bytes_legacy",
        Value::Int(bounded_i64(comparison.bytes_legacy)),
    );
    object.set("bytes_new", Value::Int(bounded_i64(comparison.bytes_new)));
    object.set(
        "events_legacy",
        Value::Int(bounded_i64(comparison.events_legacy)),
    );
    object.set("events_new", Value::Int(bounded_i64(comparison.events_new)));
    let mut occurrences = Object::new();
    occurrences.set(
        "matched",
        Value::Int(bounded_i64(comparison.occurrences.matched)),
    );
    occurrences.set(
        "missing_new",
        Value::Int(bounded_i64(comparison.occurrences.missing_new)),
    );
    occurrences.set(
        "missing_legacy",
        Value::Int(bounded_i64(comparison.occurrences.missing_legacy)),
    );
    occurrences.set(
        "digest_mismatch",
        Value::Int(bounded_i64(comparison.occurrences.digest_mismatch)),
    );
    occurrences.set(
        "unexplained",
        Value::Int(bounded_i64(comparison.occurrences.unexplained)),
    );
    object.set("occurrences", Value::Object(occurrences));
    object.set(
        "legacy_duplicates",
        Value::Int(bounded_i64(comparison.legacy_duplicates)),
    );
    object.set(
        "new_duplicates",
        Value::Int(bounded_i64(comparison.new_duplicates)),
    );
    object.set(
        "attestations_direct",
        Value::Int(bounded_i64(comparison.attestations_direct)),
    );
    object.set(
        "attestations_relay",
        Value::Int(bounded_i64(comparison.attestations_relay)),
    );
    Value::Object(object)
}

/// Compose the `pilot compare` result document: the CLI result namespace
/// member first, then the comparison report's closed member set — the
/// `Ok` value a `pilot compare` handler hands to the CLI output envelope
/// (CLI-013, CLI-015), composed exactly as [`crate::report`] composes
/// its result documents.
#[must_use]
pub fn comparison_document(report: &ComparisonReport) -> Value {
    let mut document = Object::new();
    document.set(
        "schema",
        Value::Text(crate::report::RESULT_NAMESPACE.to_owned()),
    );
    if let Value::Object(members) = report.to_json() {
        for (name, value) in members.iter() {
            document.set(name, value.clone());
        }
    }
    Value::Object(document)
}

/// Compare a legacy inventory document against everything the local
/// state has acknowledged, read-only.
///
/// # Errors
/// [`StateError`] with [`StateErrorKind::Unavailable`] when the state
/// database cannot be read, or [`StateErrorKind::SchemaCorruption`]
/// when a stored value is outside the vocabulary the schema pins — the
/// same read-side backstop [`crate::inventory`] keeps. Errors carry no
/// runtime text.
pub fn compare(
    conn: &Connection,
    legacy: &LegacyInventory,
    now: &Timestamp,
) -> Result<ComparisonReport, StateError> {
    let new_side = load_new_inventory(conn)?;
    Ok(build_report(legacy, &new_side, now))
}

/// Load the new side: sources, acknowledged occurrences, and upload
/// attestations, each read once.
fn load_new_inventory(conn: &Connection) -> Result<NewInventory, StateError> {
    let mut inventory = NewInventory::default();
    load_state_sources(conn, &mut inventory.sources)?;
    load_state_occurrences(conn, &mut inventory.sources)?;
    load_state_attestations(conn, &mut inventory.sources)?;
    Ok(inventory)
}

/// The `(session_hash, artifact_hash)` join key parsed from one row's
/// stored spellings, or the read-side corruption refusal.
fn join_key_of(session: &str, artifact: &str) -> Result<(SessionHash, ArtifactHash), StateError> {
    let session = SessionHash::parse(session).map_err(|_| corrupted("sources.session_hash"))?;
    let artifact = ArtifactHash::parse(artifact).map_err(|_| corrupted("sources.artifact_hash"))?;
    Ok((session, artifact))
}

/// Read every state-known source's lane and adapter. The schema's
/// UNIQUE constraint makes the join key one row per pair.
fn load_state_sources(
    conn: &Connection,
    sources: &mut HashMap<(SessionHash, ArtifactHash), NewSource>,
) -> Result<(), StateError> {
    let mut statement = conn
        .prepare("SELECT session_hash, artifact_hash, adapter_id, freshness_lane FROM sources")
        .map_err(|_| query_failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| query_failed())?;
    for row in rows {
        let (session, artifact, adapter, lane) = row.map_err(|_| query_failed())?;
        let adapter = AdapterId::parse(&adapter).map_err(|_| corrupted("sources.adapter_id"))?;
        let lane = FreshnessLane::parse(&lane).map_err(|_| corrupted("sources.freshness_lane"))?;
        sources.insert(
            join_key_of(&session, &artifact)?,
            NewSource {
                lane,
                adapter,
                evidence: SourceEvidence::default(),
                attestations_direct: 0,
                attestations_relay: 0,
            },
        );
    }
    Ok(())
}

/// Read every acknowledged occurrence into its source's evidence, the
/// generations folded so a position maps to a set of payloads.
fn load_state_occurrences(
    conn: &Connection,
    sources: &mut HashMap<(SessionHash, ArtifactHash), NewSource>,
) -> Result<(), StateError> {
    let mut statement = conn
        .prepare(
            "SELECT s.session_hash, s.artifact_hash, r.range_kind,
                    r.range_start, r.range_end, r.blob_digest
             FROM ranges r
             JOIN generations g ON g.generation_id = r.generation_id
             JOIN sources s ON s.source_id = g.source_id",
        )
        .map_err(|_| query_failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|_| query_failed())?;
    for row in rows {
        let (session, artifact, kind, start, end, digest) = row.map_err(|_| query_failed())?;
        let key = join_key_of(&session, &artifact)?;
        let source = sources
            .get_mut(&key)
            .ok_or_else(|| corrupted("ranges.generation_id"))?;
        let kind = match kind.as_str() {
            "bytes" => RangeKind::Byte,
            "events" => RangeKind::Event,
            _ => return Err(corrupted("ranges.range_kind")),
        };
        let start = u64::try_from(start.max(0)).unwrap_or(0);
        let end = u64::try_from(end.max(0)).unwrap_or(0);
        let digest = BlobDigest::parse(&digest).map_err(|_| corrupted("ranges.blob_digest"))?;
        source
            .evidence
            .record(kind, start, end, digest.as_raw().to_owned());
    }
    Ok(())
}

/// Read every upload attestation's relation into its source's
/// provenance counts, grouped per relation by the query.
fn load_state_attestations(
    conn: &Connection,
    sources: &mut HashMap<(SessionHash, ArtifactHash), NewSource>,
) -> Result<(), StateError> {
    let mut statement = conn
        .prepare(
            "SELECT s.session_hash, s.artifact_hash, a.relation, COUNT(*)
             FROM upload_attestations a
             JOIN ranges r ON r.occurrence_id = a.occurrence_id
             JOIN generations g ON g.generation_id = r.generation_id
             JOIN sources s ON s.source_id = g.source_id
             GROUP BY s.session_hash, s.artifact_hash, a.relation",
        )
        .map_err(|_| query_failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|_| query_failed())?;
    for row in rows {
        let (session, artifact, relation, count) = row.map_err(|_| query_failed())?;
        let key = join_key_of(&session, &artifact)?;
        let source = sources
            .get_mut(&key)
            .ok_or_else(|| corrupted("upload_attestations.occurrence_id"))?;
        let count = u64::try_from(count.max(0)).unwrap_or(0);
        match relation.as_str() {
            "direct" => source.attestations_direct = count,
            "relay" => source.attestations_relay = count,
            _ => return Err(corrupted("upload_attestations.relation")),
        }
    }
    Ok(())
}

/// Run the comparison over both sides' evidence and compose the report.
fn build_report(
    legacy: &LegacyInventory,
    new_side: &NewInventory,
    now: &Timestamp,
) -> ComparisonReport {
    // The union of join keys, in canonical order: the digest newtypes are
    // ordered values, so `BTreeSet` *is* the canonical (session, artifact)
    // order the report and its digest render sources in, no matter which
    // side or which document order supplied them.
    let mut keys: BTreeSet<(SessionHash, ArtifactHash)> = legacy
        .sources
        .iter()
        .map(|source| (source.session, source.artifact))
        .collect();
    keys.extend(new_side.sources.keys().copied());
    let legacy_by_key: HashMap<(SessionHash, ArtifactHash), &LegacySource> = legacy
        .sources
        .iter()
        .map(|source| ((source.session, source.artifact), source))
        .collect();

    let mut sources = SourceClassCounts::default();
    let mut occurrences = OccurrenceClassCounts::default();
    let mut provenance = ProvenanceCounts::default();
    let mut differences = Vec::new();
    let mut digest_frame = FrameBuilder::new(COMPARISON_DIGEST_LABEL);
    digest_frame.push_u63(u64::try_from(keys.len()).unwrap_or(u64::MAX));
    digest_frame.push_text(legacy.generated_at.as_str());

    for (session, artifact) in keys {
        let legacy_source = legacy_by_key.get(&(session, artifact)).copied();
        let new_source = new_side.sources.get(&(session, artifact));
        let comparison = compare_source(&session, &artifact, legacy_source, new_source);
        record_class(&mut sources, comparison.gap_class);
        occurrences.classes.matched = occurrences
            .classes
            .matched
            .saturating_add(comparison.occurrences.matched);
        occurrences.classes.missing_new = occurrences
            .classes
            .missing_new
            .saturating_add(comparison.occurrences.missing_new);
        occurrences.classes.missing_legacy = occurrences
            .classes
            .missing_legacy
            .saturating_add(comparison.occurrences.missing_legacy);
        occurrences.classes.digest_mismatch = occurrences
            .classes
            .digest_mismatch
            .saturating_add(comparison.occurrences.digest_mismatch);
        occurrences.classes.unexplained = occurrences
            .classes
            .unexplained
            .saturating_add(comparison.occurrences.unexplained);
        occurrences.legacy_duplicates = occurrences
            .legacy_duplicates
            .saturating_add(comparison.legacy_duplicates);
        occurrences.new_duplicates = occurrences
            .new_duplicates
            .saturating_add(comparison.new_duplicates);
        if comparison.legacy_present && comparison.new_present {
            provenance.sources_both = provenance.sources_both.saturating_add(1);
        }
        provenance.attestations_direct = provenance
            .attestations_direct
            .saturating_add(comparison.attestations_direct);
        provenance.attestations_relay = provenance
            .attestations_relay
            .saturating_add(comparison.attestations_relay);
        // The digest frame covers every union source — matched included.
        digest_frame.push_text(&session.to_hex());
        digest_frame.push_text(&artifact.to_hex());
        digest_frame.push_text(comparison.gap_class.token());
        digest_frame.push_text(comparison.new_coverage.token());
        digest_frame.push_text(comparison.legacy_coverage.map_or("", CoverageState::token));
        digest_frame.push_u63(comparison.bytes_legacy);
        digest_frame.push_u63(comparison.bytes_new);
        digest_frame.push_u63(comparison.events_legacy);
        digest_frame.push_u63(comparison.events_new);
        digest_frame.push_u63(comparison.occurrences.matched);
        digest_frame.push_u63(comparison.occurrences.missing_new);
        digest_frame.push_u63(comparison.occurrences.missing_legacy);
        digest_frame.push_u63(comparison.occurrences.digest_mismatch);
        digest_frame.push_u63(comparison.occurrences.unexplained);
        if comparison.gap_class != GapClass::Matched {
            differences.push(comparison);
        }
    }

    let verdict = if sources.unexplained > 0 {
        Verdict::Unexplained
    } else if sources.matched == sources.total() {
        Verdict::Equivalent
    } else {
        Verdict::Differences
    };
    ComparisonReport {
        generated_at: now.clone(),
        legacy_generated_at: legacy.generated_at.clone(),
        verdict,
        digest: encode_hex(&digest_frame.finish()),
        sources,
        occurrences,
        provenance,
        differences,
    }
}

/// Compare one union source. A self-contradiction dominates the source
/// class; presence dominates everything else, and the occurrence
/// arithmetic explains the rest — including a one-sided source, whose
/// every payload is the gap its absence names.
fn compare_source(
    session: &SessionHash,
    artifact: &ArtifactHash,
    legacy_source: Option<&LegacySource>,
    new_source: Option<&NewSource>,
) -> SourceComparison {
    let legacy_present = legacy_source.is_some();
    let new_present = new_source.is_some();
    let mut classes = OccurrenceClasses::default();
    if legacy_present || new_present {
        // Union of positions; each side's payload set at a position is
        // the comparison's atom. A set always holds at least one payload
        // — evidence only exists where a digest was recorded — so the
        // three-way set arithmetic below covers every case, one-sided
        // sources included: a side that holds nothing contributes an
        // empty set at every position, so each of the other side's
        // payloads classifies as the gap the absence names.
        let legacy_positions = legacy_source.map(|source| &source.evidence.positions);
        let new_positions = new_source.map(|source| &source.evidence.positions);
        let mut positions: HashSet<Position> = legacy_positions
            .map(|positions| positions.keys().copied().collect())
            .unwrap_or_default();
        if let Some(new_positions) = new_positions {
            positions.extend(new_positions.keys().copied());
        }
        for position in positions {
            let legacy_payloads = legacy_positions.and_then(|positions| positions.get(&position));
            let new_payloads = new_positions.and_then(|positions| positions.get(&position));
            if legacy_payloads.is_some_and(|payloads| payloads.len() > 1) {
                // The legacy evidence names two payloads at one position:
                // unexplainable at this grain, explicit in the counts.
                classes.unexplained = classes.unexplained.saturating_add(
                    u64::try_from(legacy_payloads.map_or(0, BTreeSet::len)).unwrap_or(u64::MAX),
                );
                continue;
            }
            match (legacy_payloads, new_payloads) {
                (Some(legacy_set), Some(new_set)) => {
                    let both = legacy_set.intersection(new_set).count();
                    let legacy_only = legacy_set.difference(new_set).count();
                    let new_only = new_set.difference(legacy_set).count();
                    if both == 0 {
                        // One position, disjoint payloads: every payload
                        // names the conflict.
                        classes.digest_mismatch = classes.digest_mismatch.saturating_add(
                            u64::try_from(legacy_only + new_only).unwrap_or(u64::MAX),
                        );
                    } else {
                        classes.matched = classes
                            .matched
                            .saturating_add(u64::try_from(both).unwrap_or(u64::MAX));
                        classes.missing_new = classes
                            .missing_new
                            .saturating_add(u64::try_from(legacy_only).unwrap_or(u64::MAX));
                        classes.missing_legacy = classes
                            .missing_legacy
                            .saturating_add(u64::try_from(new_only).unwrap_or(u64::MAX));
                    }
                }
                (Some(legacy_set), None) => {
                    classes.missing_new = classes
                        .missing_new
                        .saturating_add(u64::try_from(legacy_set.len()).unwrap_or(u64::MAX));
                }
                (None, Some(new_set)) => {
                    classes.missing_legacy = classes
                        .missing_legacy
                        .saturating_add(u64::try_from(new_set.len()).unwrap_or(u64::MAX));
                }
                (None, None) => {}
            }
        }
    }
    // A self-contradicting legacy source is unexplained no matter what
    // the new archive holds — the difference needs a human either way.
    let gap_class = if classes.unexplained > 0 {
        GapClass::Unexplained
    } else if !new_present {
        GapClass::MissingNew
    } else if !legacy_present {
        GapClass::MissingLegacy
    } else {
        classes.dominant_gap_class()
    };
    let new_coverage = derive_new_coverage(new_source, legacy_source, &classes);
    SourceComparison {
        session: *session,
        artifact: *artifact,
        gap_class,
        legacy_present,
        new_present,
        legacy_coverage: legacy_source.map(LegacySource::coverage),
        new_coverage,
        legacy_adapter: legacy_source.map(|source| source.adapter.clone()),
        new_adapter: new_source.map(|source| source.adapter.clone()),
        bytes_legacy: legacy_source.map_or(0, |source| source.evidence.bytes),
        bytes_new: new_source.map_or(0, |source| source.evidence.bytes),
        events_legacy: legacy_source.map_or(0, |source| source.evidence.events),
        events_new: new_source.map_or(0, |source| source.evidence.events),
        occurrences: classes,
        legacy_duplicates: legacy_source.map_or(0, |source| source.evidence.duplicates),
        new_duplicates: new_source.map_or(0, |source| source.evidence.duplicates),
        attestations_direct: new_source.map_or(0, |source| source.attestations_direct),
        attestations_relay: new_source.map_or(0, |source| source.attestations_relay),
    }
}

/// The new archive's coverage classification of the source, relative to
/// the legacy evidence, in the status layer's closed vocabulary: absent
/// when the new archive holds nothing, partial while any legacy payload
/// is missing from the new side, and otherwise the lane's caught-up
/// state (`current` for freshness, `backfilled` for backfill).
#[must_use]
fn derive_new_coverage(
    new_source: Option<&NewSource>,
    legacy_source: Option<&LegacySource>,
    classes: &OccurrenceClasses,
) -> CoverageState {
    let Some(new) = new_source else {
        return CoverageState::Absent;
    };
    if new.evidence.positions.is_empty() {
        return CoverageState::Absent;
    }
    let legacy_payloads = legacy_source.map_or(0, |source| source.evidence.total_payloads());
    if classes.missing_new > 0 && legacy_payloads > 0 {
        return CoverageState::Partial;
    }
    match new.lane {
        FreshnessLane::Freshness => CoverageState::Current,
        FreshnessLane::Backfill => CoverageState::FullyBackfilled,
    }
}

/// Fold one source's class into the fleet counts.
fn record_class(counts: &mut SourceClassCounts, gap_class: GapClass) {
    match gap_class {
        GapClass::Matched => counts.matched = counts.matched.saturating_add(1),
        GapClass::MissingNew => counts.missing_new = counts.missing_new.saturating_add(1),
        GapClass::MissingLegacy => {
            counts.missing_legacy = counts.missing_legacy.saturating_add(1);
        }
        GapClass::DigestMismatch => {
            counts.digest_mismatch = counts.digest_mismatch.saturating_add(1);
        }
        GapClass::Unexplained => counts.unexplained = counts.unexplained.saturating_add(1),
    }
}

/// The private state the comparator reads is the same database
/// [`crate::state`] owns; every read failure is classified, content-free,
/// and dropped of driver text that could embed a path.
fn query_failed() -> StateError {
    StateError::with_detail(
        StateErrorKind::Unavailable,
        "the comparator could not read the state database",
    )
}

/// A stored value outside the pinned vocabulary: schema corruption seen
/// from the read side.
fn corrupted(subject: &'static str) -> StateError {
    StateError::of_kind(StateErrorKind::SchemaCorruption).about(subject)
}

/// Lowercase hexadecimal, the wire spelling of every digest the report
/// carries.
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

#[cfg(test)]
mod tests;
