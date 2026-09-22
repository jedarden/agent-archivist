// SPDX-License-Identifier: Apache-2.0

//! The append-only conformance suite (plan Phase 6D): the public,
//! harness-agnostic runner that holds any adapter built on this SDK to
//! the time-dimension capture contracts — complete records, a partial
//! tail, and growth.
//!
//! A community adapter implements [`ConformanceAdapter`] — mount over a
//! store root, run one capture pass, report what the pass captured — and
//! [`ConformanceSuite`] drives it through the synthetic corpus's
//! time-dimension scenes (`fixtures/synthetic/append-only/`, the Phase 6D
//! fixture work). The suite materializes each scene into a scratch
//! directory under [`std::env::temp_dir`] so the adapter always runs over
//! a disposable copy and the checked-in corpus is never written to; the
//! materialized store is removed when the scenario ends, whichever way it
//! ends.
//!
//! # The exit-gate properties
//!
//! Each scenario asserts the Phase 6D exit-gate sentence the plan holds
//! file fixtures to — *file fixtures reconstruct byte-for-byte through
//! the last complete record* — plus the two capture corollaries that
//! follow from CAP-003 and `EC-01`:
//!
//! - **Reconstruction** — the ordered captures of every pass concatenate
//!   byte-for-byte to the source snapshot's complete-record prefix
//!   ([`RecordBoundary::complete_prefix`]). A record lost, reordered,
//!   duplicated, or rewritten breaks the equality.
//! - **The torn tail is excluded** — no captured byte lies past the last
//!   complete-record boundary, in any pass. The tail is measured — the
//!   boundary's [`RecordBoundary::incomplete_tail_bytes`] — and captured
//!   on no pass, and an unchanged source's later passes capture nothing
//!   at all.
//! - **Growth is captured without recapture** — after the source grows,
//!   the appended records are captured exactly once, the unchanged prefix
//!   is not captured again, and the generation *continues*: an append is
//!   continuity, never a rotation (`AC-03`). An adapter that misses the
//!   appended records or rotates on them fails here.
//!
//! The suite's ground truth is [`RecordBoundary`]'s own selection over
//! the exact bytes it materialized — the same selection the capture core
//! is held to by the crate's reconstruction parity oracle — so the
//! comparison is over the adapter's reported behavior, not its internals.
//! A violating adapter is named by [`Violation`]s: content-free, closed
//! figures that say *what* the contract breach was and never quote source
//! bytes.
//!
//! # Running it
//!
//! ```no_run
//! use archivist_adapter_sdk::conformance::ConformanceSuite;
//!
//! let suite = ConformanceSuite::from_workspace_corpus()
//!     .expect("the workspace ships the synthetic corpus");
//! let report = suite.run_time_dimension::<MyAdapter>();
//! assert!(report.passed(), "violations: {report:?}");
//! // use your own adapter type in place of MyAdapter above
//! # struct MyAdapter;
//! # impl archivist_adapter_sdk::conformance::ConformanceAdapter for MyAdapter {
//! #     fn mount(_root: &std::path::Path)
//! #         -> Result<Self, archivist_adapter_sdk::conformance::MountError>
//! #     { Ok(Self) }
//! #     fn capture_pass(&mut self)
//! #         -> Result<archivist_adapter_sdk::conformance::PassReport,
//! #                   archivist_adapter_sdk::conformance::PassError>
//! #     { unreachable!("illustrative only") }
//! # }
//! ```
//!
//! The synthetic adapter wiring this suite's first customer together is
//! the crate's integration test
//! (`tests/conformance_synthetic.rs`), built on the same capture core as
//! the `synthetic_append_only` example.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::file_capture::RecordBoundary;

/// The source file every materialized scene root carries: the corpus
/// contract (`fixtures/synthetic/append-only/README.md`). An adapter
/// mounted over a [`ConformanceAdapter::mount`] root reads its store from
/// `root.join(SOURCE_FILE_NAME)`.
pub const SOURCE_FILE_NAME: &str = "source.jsonl";

/// The synthetic append-only corpus, relative to the workspace root: the
/// scenes [`ConformanceSuite::from_workspace_corpus`] resolves.
pub const CORPUS_RELATIVE: &str = "fixtures/synthetic/append-only";

/// Why the corpus a suite was to run against could not be read. The
/// corpus is committed workspace material, so both variants name a
/// repository defect, not an adapter fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorpusError {
    /// The corpus directory does not exist at the resolved location.
    NotFound,
    /// The corpus directory exists but a scene file could not be read.
    Unreadable,
}

impl fmt::Display for CorpusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::NotFound => "corpus_not_found",
            Self::Unreadable => "corpus_unreadable",
        };
        formatter.write_str(token)
    }
}

impl std::error::Error for CorpusError {}

/// Why mounting over a materialized store root failed. The suite only
/// mounts over roots it just created, so [`MountError::RootAbsent`] names
/// an adapter-side defect: the store the suite materialized is there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountError {
    /// The configured store root does not exist.
    RootAbsent,
}

impl fmt::Display for MountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::RootAbsent => "mount_root_absent",
        };
        formatter.write_str(token)
    }
}

impl std::error::Error for MountError {}

/// Why one capture pass could not be observed. The closed, content-free
/// reason vocabulary a pass reports instead of guessing: every variant is
/// a pass that observed nothing, never a pass that captured something it
/// cannot describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassError {
    /// The store's source file exists but could not be read.
    Unreadable,
    /// The source's layout is not one the adapter detects; nothing was
    /// captured (plan `EC-08`'s fail-closed posture).
    UnsupportedFingerprint,
    /// The source is shorter than a previous pass's boundary: bytes a
    /// cursor counted as complete are gone.
    SourceShrank,
}

impl fmt::Display for PassError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::Unreadable => "pass_source_unreadable",
            Self::UnsupportedFingerprint => "pass_fingerprint_unsupported",
            Self::SourceShrank => "capture_source_shrank",
        };
        formatter.write_str(token)
    }
}

impl std::error::Error for PassError {}

/// What one pass did to the source's generation. The first pass opens
/// the source's first generation; every later pass continues it or
/// rotates it. An append continues — [`GenerationContinuity::Rotated`] on
/// an unchanged file identity and an appended prefix is the growth
/// contract's breach (`AC-03`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationContinuity {
    /// This pass opened the source's first generation.
    Opened,
    /// This pass continued the generation the previous pass left open.
    Continued,
    /// This pass closed the previous generation and opened a new one.
    Rotated,
}

impl GenerationContinuity {
    /// The closed-vocabulary token for this continuity, for diagnostics.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Continued => "continued",
            Self::Rotated => "rotated",
        }
    }
}

impl fmt::Display for GenerationContinuity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// What one capture pass captured, in the shape the suite compares: the
/// newly captured bytes, the whole-source boundary after the pass, and
/// the pass's generation decision.
///
/// `captured` carries only bytes that completed since the previous pass —
/// each record whole with its terminating newline, the torn tail
/// excluded — empty when nothing completed since the last pass. `boundary`
/// is the same split [`crate::file_capture::CaptureCursor`] reports: the
/// figures cover the whole source, not just this pass's suffix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassReport {
    /// The complete records newly captured this pass, in source order.
    pub captured: Vec<u8>,
    /// The whole-source boundary after this pass: complete bytes, complete
    /// records, and the measured-but-uncaptured tail.
    pub boundary: RecordBoundary,
    /// What this pass did to the source's generation.
    pub generation: GenerationContinuity,
}

/// One adapter's conformance obligations, reduced to what the suite
/// observes: mount over a materialized store, and report one capture pass
/// over the store's current bytes.
///
/// The suite drives time from outside the store — it materializes a
/// scene, lets the adapter observe it, may grow the source file in place,
/// and asks for another pass — so an implementation re-reads its store on
/// every [`ConformanceAdapter::capture_pass`] and holds its own cursor,
/// generation, and acknowledgement state between passes, exactly as a
/// live adapter does over a harness store that grows under it.
///
/// Nothing here is harness-specific: a real adapter maps its own `stat`
/// identity, fingerprint detection, and capture core onto these two
/// methods. The synthetic wiring in `tests/conformance_synthetic.rs` is
/// the worked example.
pub trait ConformanceAdapter: Sized {
    /// Mount the adapter over one materialized store root: the directory
    /// that contains (or will contain) [`SOURCE_FILE_NAME`].
    ///
    /// # Errors
    /// [`MountError::RootAbsent`] when the root does not exist: the
    /// adapter mounts over stores that are there, and an absent root is
    /// the coverage-gap shape the suite's sibling scenarios (replacement,
    /// permissions, missing roots) own.
    fn mount(root: &Path) -> Result<Self, MountError>;

    /// Run one capture pass over the store's current bytes and report
    /// what it captured.
    ///
    /// # Errors
    /// [`PassError`] when the pass could not be observed at all. A pass
    /// that observed the source but captured nothing new is *not* an
    /// error — it reports an empty `captured` and the unchanged boundary.
    fn capture_pass(&mut self) -> Result<PassReport, PassError>;
}

/// The time-dimension scenarios the suite drives, in suite order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scenario {
    /// `complete-records`: a fully newline-terminated store — the golden
    /// path. Every record is captured on the first pass with zero tail,
    /// and a second pass over the unchanged store captures nothing.
    CompleteRecords,
    /// `partial-tail`: a complete prefix plus a torn final line. The
    /// prefix is captured; the tail is measured and excluded from every
    /// pass's captures (`EC-01`).
    PartialTail,
    /// `growth`: one store observed before and after an append. The
    /// appended records are captured whole on the second pass, the
    /// unchanged prefix is not recaptured, and the generation continues.
    Growth,
}

impl Scenario {
    /// The three scenarios in suite order.
    #[must_use]
    pub fn all() -> [Self; 3] {
        [Self::CompleteRecords, Self::PartialTail, Self::Growth]
    }

    /// The corpus scene name this scenario materializes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::CompleteRecords => "complete-records",
            Self::PartialTail => "partial-tail",
            Self::Growth => "growth",
        }
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// One contract breach the suite observed. Variants are closed,
/// content-free, and carry figures rather than bytes: a violation says
/// *what* the adapter did that no conforming adapter does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// The adapter refused to mount over the materialized store root.
    MountFailed,
    /// A capture pass could not be observed at all.
    PassFailed,
    /// The ordered captures do not concatenate to the source snapshot's
    /// complete-record prefix: a record was lost, reordered, duplicated,
    /// or rewritten.
    ReconstructionMismatch,
    /// Captured bytes extend past the last complete-record boundary: the
    /// torn tail entered some pass's captures (`EC-01`).
    TailCaptured,
    /// The reported boundary figures disagree with the source's own
    /// complete-record split.
    BoundaryMismatch {
        /// The figures the adapter reported.
        reported: RecordBoundary,
        /// The figures the source's split yields.
        expected: RecordBoundary,
    },
    /// The pass's generation decision disagrees with the observation: a
    /// first pass that did not open, or an append (or an unchanged
    /// source) that did not continue (`AC-03`).
    GenerationContinuityBroken {
        /// The continuity the observation demanded.
        expected: GenerationContinuity,
        /// The continuity the adapter reported.
        reported: GenerationContinuity,
    },
    /// An unchanged source produced new captured bytes on a later pass.
    RecapturedOnUnchangedSource,
    /// An append completed records that capture never took: the growth
    /// went unobserved.
    GrowthMissed,
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MountFailed => {
                formatter.write_str("the adapter refused the materialized store root")
            }
            Self::PassFailed => formatter.write_str("a capture pass could not be observed"),
            Self::ReconstructionMismatch => formatter.write_str(
                "ordered captures do not reconstruct the complete-record prefix byte-for-byte",
            ),
            Self::TailCaptured => {
                formatter.write_str("captured bytes extend past the last complete-record boundary")
            }
            Self::BoundaryMismatch { reported, expected } => write!(
                formatter,
                "boundary figures disagree: reported complete_bytes={} \
                 complete_records={} incomplete_tail_bytes={}, expected \
                 complete_bytes={} complete_records={} incomplete_tail_bytes={}",
                reported.complete_bytes,
                reported.complete_records,
                reported.incomplete_tail_bytes,
                expected.complete_bytes,
                expected.complete_records,
                expected.incomplete_tail_bytes,
            ),
            Self::GenerationContinuityBroken { expected, reported } => write!(
                formatter,
                "generation continuity broken: expected {expected}, reported {reported}"
            ),
            Self::RecapturedOnUnchangedSource => {
                formatter.write_str("an unchanged source produced new captured bytes")
            }
            Self::GrowthMissed => {
                formatter.write_str("an append completed records that capture never took")
            }
        }
    }
}

/// The result of driving one adapter through one scenario: the scenario
/// and every violation observed, empty when the adapter conformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioOutcome {
    /// The scenario that ran.
    pub scenario: Scenario,
    /// Every contract breach observed, in check order.
    pub violations: Vec<Violation>,
}

impl ScenarioOutcome {
    /// Whether the scenario passed: no violation was observed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// The result of the whole time-dimension suite: one outcome per
/// [`Scenario::all`], in suite order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeDimensionReport {
    /// One outcome per scenario, in suite order.
    pub scenarios: Vec<ScenarioOutcome>,
}

impl TimeDimensionReport {
    /// Whether every scenario passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.scenarios.iter().all(ScenarioOutcome::passed)
    }

    /// The outcomes that observed violations.
    pub fn failures(&self) -> impl Iterator<Item = &ScenarioOutcome> {
        self.scenarios.iter().filter(|outcome| !outcome.passed())
    }
}

impl fmt::Display for TimeDimensionReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.passed() {
            return formatter
                .write_str("all time-dimension scenarios passed the conformance suite");
        }
        for outcome in self.failures() {
            writeln!(
                formatter,
                "{}: {} violation(s)",
                outcome.scenario,
                outcome.violations.len()
            )?;
            for violation in &outcome.violations {
                writeln!(formatter, "  - {violation}")?;
            }
        }
        Ok(())
    }
}

/// The conformance suite over one synthetic append-only corpus: the
/// runner that materializes scenes and drives any
/// [`ConformanceAdapter`] through them.
#[derive(Clone, Debug)]
pub struct ConformanceSuite {
    corpus: PathBuf,
}

impl ConformanceSuite {
    /// Open the suite over an explicit corpus directory: the layout is
    /// the committed corpus's (`complete-records/root/source.jsonl` and
    /// siblings), wherever a harness keeps it.
    ///
    /// # Errors
    /// [`CorpusError::NotFound`] when the directory does not exist.
    pub fn open(corpus: &Path) -> Result<Self, CorpusError> {
        if !corpus.is_dir() {
            return Err(CorpusError::NotFound);
        }
        Ok(Self {
            corpus: corpus.to_path_buf(),
        })
    }

    /// Open the suite over the workspace's committed corpus, resolved
    /// from this crate's manifest directory, so the suite runs from any
    /// working directory of a workspace checkout.
    ///
    /// # Errors
    /// [`CorpusError::NotFound`] when the resolved corpus is missing —
    /// the crate has been moved out of the workspace layout.
    pub fn from_workspace_corpus() -> Result<Self, CorpusError> {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .map_or_else(
                || PathBuf::from(CORPUS_RELATIVE),
                |root| root.join(CORPUS_RELATIVE),
            );
        Self::open(&corpus)
    }

    /// The corpus this suite materializes scenes from.
    #[must_use]
    pub fn corpus(&self) -> &Path {
        &self.corpus
    }

    /// Drive one adapter through all three time-dimension scenarios:
    /// complete records, partial tail, growth. Each scenario materializes
    /// its own scratch store and mounts a fresh adapter over it.
    #[must_use]
    pub fn run_time_dimension<S: ConformanceAdapter>(&self) -> TimeDimensionReport {
        TimeDimensionReport {
            scenarios: Scenario::all()
                .into_iter()
                .map(|scenario| self.run_scenario::<S>(scenario))
                .collect(),
        }
    }

    /// The complete-records scenario: a fully newline-terminated store is
    /// captured whole on the first pass with zero tail, and a second pass
    /// over the unchanged store captures nothing.
    #[must_use]
    pub fn run_complete_records<S: ConformanceAdapter>(&self) -> ScenarioOutcome {
        self.run_scenario::<S>(Scenario::CompleteRecords)
    }

    /// The partial-tail scenario: a complete prefix is captured, the torn
    /// final line is measured and excluded from every pass's captures,
    /// and the unchanged store's second pass captures nothing.
    #[must_use]
    pub fn run_partial_tail<S: ConformanceAdapter>(&self) -> ScenarioOutcome {
        self.run_scenario::<S>(Scenario::PartialTail)
    }

    /// The growth scenario: one store observed before and after an
    /// append. The appended records are captured whole on the second
    /// pass, the unchanged prefix is not recaptured, and the generation
    /// continues.
    #[must_use]
    pub fn run_growth<S: ConformanceAdapter>(&self) -> ScenarioOutcome {
        self.run_scenario::<S>(Scenario::Growth)
    }

    /// Drive one scenario end to end: materialize, mount, pass, and
    /// check. The scratch store is removed before returning, whichever
    /// way the scenario ended.
    fn run_scenario<S: ConformanceAdapter>(&self, scenario: Scenario) -> ScenarioOutcome {
        let scratch = match scenario {
            Scenario::CompleteRecords | Scenario::PartialTail => {
                let source = self.scene_bytes(&format!("{scenario}/root/{SOURCE_FILE_NAME}"));
                let scratch = materialize(scenario.name(), &source);
                let violations =
                    Self::run_fixed_store::<S>(&scratch.join("root"), &source, scenario);
                (scratch, violations)
            }
            Scenario::Growth => {
                let before = self.scene_bytes(&format!("growth/before/{SOURCE_FILE_NAME}"));
                let after = self.scene_bytes(&format!("growth/after/{SOURCE_FILE_NAME}"));
                let scratch = materialize(scenario.name(), &before);
                let violations =
                    Self::run_growing_store::<S>(&scratch.join("root"), &before, &after);
                (scratch, violations)
            }
        };
        remove_scratch(&scratch.0);
        ScenarioOutcome {
            scenario,
            violations: scratch.1,
        }
    }

    /// One store, observed twice, that never changes between passes: the
    /// complete-records and partial-tail shape.
    fn run_fixed_store<S: ConformanceAdapter>(
        root: &Path,
        source: &[u8],
        scenario: Scenario,
    ) -> Vec<Violation> {
        let expected = RecordBoundary::select(source);
        let expected_prefix = RecordBoundary::complete_prefix(source);
        // Corpus invariants: the complete-records scene is fully
        // newline-terminated and the partial-tail scene ends torn.
        if scenario == Scenario::CompleteRecords {
            assert!(
                expected.incomplete_tail_bytes == 0,
                "corpus invariant: complete-records has no tail"
            );
        } else {
            assert!(
                expected.incomplete_tail_bytes > 0,
                "corpus invariant: partial-tail ends torn"
            );
        }

        let mut violations = Vec::new();
        let Ok(mut adapter) = S::mount(root) else {
            violations.push(Violation::MountFailed);
            return violations;
        };
        let Ok(first) = adapter.capture_pass() else {
            violations.push(Violation::PassFailed);
            return violations;
        };
        violations.extend(check_opening_pass(&first, expected, expected_prefix));
        let Ok(second) = adapter.capture_pass() else {
            violations.push(Violation::PassFailed);
            return violations;
        };
        violations.extend(check_quiet_pass(&second, expected));
        if !violations.is_empty() {
            return violations;
        }
        // The reconstruction sentence, over both passes' ordered
        // captures: every byte through the last complete record,
        // byte-for-byte, and not one byte past it.
        let mut reconstructed = first.captured;
        reconstructed.extend_from_slice(&second.captured);
        if reconstructed != expected_prefix {
            violations.push(Violation::ReconstructionMismatch);
        }
        violations
    }

    /// One store observed across an append: the before snapshot is
    /// materialized and observed, the file then grows to the after
    /// snapshot's bytes in place, and the second pass runs over the
    /// grown store.
    fn run_growing_store<S: ConformanceAdapter>(
        root: &Path,
        before: &[u8],
        after: &[u8],
    ) -> Vec<Violation> {
        // Corpus invariants: the after snapshot is the before snapshot
        // plus appends — a strictly longer, prefix-identical file whose
        // complete prefix strictly extends the before prefix.
        let before_boundary = RecordBoundary::select(before);
        let after_boundary = RecordBoundary::select(after);
        let before_prefix = RecordBoundary::complete_prefix(before);
        let after_prefix = RecordBoundary::complete_prefix(after);
        assert!(
            after.starts_with(before),
            "corpus invariant: growth/after extends growth/before"
        );
        assert!(
            after_prefix.len() > before_prefix.len(),
            "corpus invariant: growth completes appended records"
        );
        let appended = &after_prefix[before_prefix.len()..];

        let mut violations = Vec::new();
        let Ok(mut adapter) = S::mount(root) else {
            violations.push(Violation::MountFailed);
            return violations;
        };
        let Ok(first) = adapter.capture_pass() else {
            violations.push(Violation::PassFailed);
            return violations;
        };
        violations.extend(check_opening_pass(&first, before_boundary, before_prefix));
        // Time advances: the source file grows in place to the after
        // snapshot's exact bytes, the way a live harness store does.
        let grown = root.join(SOURCE_FILE_NAME);
        fs::write(&grown, after).unwrap_or_else(|error| {
            panic!(
                "the conformance store {} is rewritable: {error}",
                grown.display()
            )
        });
        let Ok(second) = adapter.capture_pass() else {
            violations.push(Violation::PassFailed);
            return violations;
        };
        if second.generation != GenerationContinuity::Continued {
            violations.push(Violation::GenerationContinuityBroken {
                expected: GenerationContinuity::Continued,
                reported: second.generation,
            });
        }
        if second.boundary != after_boundary {
            violations.push(Violation::BoundaryMismatch {
                reported: second.boundary,
                expected: after_boundary,
            });
        }
        if second.captured.is_empty() {
            violations.push(Violation::GrowthMissed);
        } else {
            let complete_cap = bounded(second.boundary.complete_bytes);
            if second.captured.len() > complete_cap {
                violations.push(Violation::TailCaptured);
            }
            if second.captured != appended {
                violations.push(Violation::ReconstructionMismatch);
            }
        }
        if !violations.is_empty() {
            return violations;
        }
        // The reconstruction sentence across the growth: both passes'
        // ordered captures are the after snapshot's complete prefix, and
        // the second pass contributed exactly the appended records — the
        // unchanged prefix was never recaptured.
        let mut reconstructed = first.captured;
        reconstructed.extend_from_slice(&second.captured);
        if reconstructed != after_prefix {
            violations.push(Violation::ReconstructionMismatch);
        }
        violations
    }

    /// One scene file's exact committed bytes.
    ///
    /// # Panics
    /// When a scene file cannot be read: [`ConformanceSuite::open`]
    /// validated the corpus directory, so a missing scene is committed
    /// corpus drift, a repository defect the fixture generator's gate
    /// owns.
    fn scene_bytes(&self, relative: &str) -> Vec<u8> {
        fs::read(self.corpus.join(relative))
            .unwrap_or_else(|error| panic!("the committed scene {relative} is readable: {error}"))
    }
}

/// The checks every store's first pass is held to: it opens the source's
/// first generation, its figures match the source's own split, and its
/// captures are the complete-record prefix — never a byte past the
/// boundary.
fn check_opening_pass(
    report: &PassReport,
    expected: RecordBoundary,
    expected_prefix: &[u8],
) -> Vec<Violation> {
    let mut violations = Vec::new();
    if report.generation != GenerationContinuity::Opened {
        violations.push(Violation::GenerationContinuityBroken {
            expected: GenerationContinuity::Opened,
            reported: report.generation,
        });
    }
    if report.boundary != expected {
        violations.push(Violation::BoundaryMismatch {
            reported: report.boundary,
            expected,
        });
    }
    if report.captured.len() > bounded(expected.complete_bytes) {
        violations.push(Violation::TailCaptured);
    }
    if report.captured != expected_prefix {
        violations.push(Violation::ReconstructionMismatch);
    }
    violations
}

/// The checks an unchanged store's later pass is held to: nothing new is
/// captured, the boundary is unchanged (the torn tail stays measured),
/// and the generation continues.
fn check_quiet_pass(report: &PassReport, expected: RecordBoundary) -> Vec<Violation> {
    let mut violations = Vec::new();
    if report.generation != GenerationContinuity::Continued {
        violations.push(Violation::GenerationContinuityBroken {
            expected: GenerationContinuity::Continued,
            reported: report.generation,
        });
    }
    if !report.captured.is_empty() {
        violations.push(Violation::RecapturedOnUnchangedSource);
    }
    if report.boundary != expected {
        violations.push(Violation::BoundaryMismatch {
            reported: report.boundary,
            expected,
        });
    }
    violations
}

/// A boundary byte figure narrowed into the index domain: a figure the
/// capture core measured from a slice always fits, and the saturating
/// fallback keeps the comparison total.
fn bounded(bytes: u64) -> usize {
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

/// A unique scratch directory for one scenario run, under
/// [`std::env::temp_dir`]: process id, a nanosecond stamp, and a monotonic
/// counter together keep concurrent suites and scenarios apart.
fn materialize(scenario: &str, source: &[u8]) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_nanos()).unwrap_or(0));
    let scratch = std::env::temp_dir().join(format!(
        "archivist-conformance-{}-{}-{}-{}",
        scenario,
        std::process::id(),
        stamp,
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    let root = scratch.join("root");
    fs::create_dir_all(&root).unwrap_or_else(|error| {
        panic!(
            "the conformance scratch {} is creatable: {error}",
            root.display()
        )
    });
    let store = root.join(SOURCE_FILE_NAME);
    fs::write(&store, source).unwrap_or_else(|error| {
        panic!(
            "the conformance store {} is writable: {error}",
            store.display()
        )
    });
    scratch
}

/// Remove one scenario's scratch tree: best-effort, on both outcomes —
/// the stores are synthetic corpus bytes, so a failed removal costs a
/// stray temp directory and nothing else.
fn remove_scratch(scratch: &Path) {
    let _ = fs::remove_dir_all(scratch);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_capture::{CaptureCursor, CaptureCursorError};

    /// The store file of a test subject's mounted root.
    fn store_of(root: &Path) -> Result<PathBuf, MountError> {
        if !root.is_dir() {
            return Err(MountError::RootAbsent);
        }
        Ok(root.join(SOURCE_FILE_NAME))
    }

    /// A conforming subject built straight on the capture core: the
    /// reference behavior the suite's happy path is written against.
    struct ReferenceSubject {
        store: PathBuf,
        cursor: CaptureCursor,
        passes: u64,
    }

    impl ConformanceAdapter for ReferenceSubject {
        fn mount(root: &Path) -> Result<Self, MountError> {
            Ok(Self {
                store: store_of(root)?,
                cursor: CaptureCursor::new(),
                passes: 0,
            })
        }

        fn capture_pass(&mut self) -> Result<PassReport, PassError> {
            let source = fs::read(&self.store).map_err(|_| PassError::Unreadable)?;
            let generation = if self.passes == 0 {
                GenerationContinuity::Opened
            } else {
                GenerationContinuity::Continued
            };
            self.passes += 1;
            let outcome = self
                .cursor
                .observe(&source)
                .map_err(|CaptureCursorError::SourceShrank| PassError::SourceShrank)?;
            Ok(PassReport {
                captured: outcome.captured.to_vec(),
                boundary: outcome.boundary,
                generation,
            })
        }
    }

    /// A subject with the tail-seeding fault: every pass captures the
    /// whole snapshot, torn tail included, and reports a boundary that
    /// pretends there is none.
    struct TailCapturer {
        store: PathBuf,
        passes: u64,
    }

    impl ConformanceAdapter for TailCapturer {
        fn mount(root: &Path) -> Result<Self, MountError> {
            Ok(Self {
                store: store_of(root)?,
                passes: 0,
            })
        }

        fn capture_pass(&mut self) -> Result<PassReport, PassError> {
            let source = fs::read(&self.store).map_err(|_| PassError::Unreadable)?;
            let generation = if self.passes == 0 {
                GenerationContinuity::Opened
            } else {
                GenerationContinuity::Continued
            };
            self.passes += 1;
            let length = u64::try_from(source.len()).unwrap_or(u64::MAX);
            Ok(PassReport {
                captured: source,
                boundary: RecordBoundary {
                    complete_bytes: length,
                    complete_records: u64::MAX,
                    incomplete_tail_bytes: 0,
                },
                generation,
            })
        }
    }

    /// A subject with the growth-seeding fault: the first pass is
    /// conforming, but every later pass re-reports the first pass's
    /// boundary and captures nothing, so an append goes unobserved.
    struct GrowthIgnorer {
        store: PathBuf,
        first_boundary: Option<RecordBoundary>,
    }

    impl ConformanceAdapter for GrowthIgnorer {
        fn mount(root: &Path) -> Result<Self, MountError> {
            Ok(Self {
                store: store_of(root)?,
                first_boundary: None,
            })
        }

        fn capture_pass(&mut self) -> Result<PassReport, PassError> {
            let source = fs::read(&self.store).map_err(|_| PassError::Unreadable)?;
            if let Some(stale) = self.first_boundary {
                return Ok(PassReport {
                    captured: Vec::new(),
                    boundary: stale,
                    generation: GenerationContinuity::Continued,
                });
            }
            let selected = RecordBoundary::select(&source);
            let captured = RecordBoundary::complete_prefix(&source).to_vec();
            self.first_boundary = Some(selected);
            Ok(PassReport {
                captured,
                boundary: selected,
                generation: GenerationContinuity::Opened,
            })
        }
    }

    /// A subject that captures correctly but rotates the generation on
    /// the second pass: an append is continuity, so the rotation is the
    /// breach (`AC-03`), even with every byte in the right place.
    struct AppendRotator {
        store: PathBuf,
        cursor: CaptureCursor,
        passes: u64,
    }

    impl ConformanceAdapter for AppendRotator {
        fn mount(root: &Path) -> Result<Self, MountError> {
            Ok(Self {
                store: store_of(root)?,
                cursor: CaptureCursor::new(),
                passes: 0,
            })
        }

        fn capture_pass(&mut self) -> Result<PassReport, PassError> {
            let source = fs::read(&self.store).map_err(|_| PassError::Unreadable)?;
            self.passes += 1;
            let generation = if self.passes == 1 {
                GenerationContinuity::Opened
            } else {
                GenerationContinuity::Rotated
            };
            let outcome = self
                .cursor
                .observe(&source)
                .map_err(|CaptureCursorError::SourceShrank| PassError::SourceShrank)?;
            Ok(PassReport {
                captured: outcome.captured.to_vec(),
                boundary: outcome.boundary,
                generation,
            })
        }
    }

    fn violations_of(outcome: &ScenarioOutcome) -> &[Violation] {
        &outcome.violations
    }

    #[test]
    fn the_reference_subject_passes_every_time_dimension_scenario() {
        let suite = ConformanceSuite::from_workspace_corpus().expect("the workspace corpus");
        let report = suite.run_time_dimension::<ReferenceSubject>();
        assert!(report.passed(), "{report}");
    }

    #[test]
    fn a_subject_that_captures_the_torn_tail_fails_partial_tail() {
        let suite = ConformanceSuite::from_workspace_corpus().expect("the workspace corpus");
        let outcome = suite.run_partial_tail::<TailCapturer>();
        assert!(!outcome.passed(), "a tail-capturing subject must fail");
        assert!(
            violations_of(&outcome)
                .iter()
                .any(|violation| matches!(violation, Violation::TailCaptured)),
            "the tail violation is named: {outcome:?}"
        );
    }

    #[test]
    fn a_subject_that_misses_a_growth_generation_fails_growth() {
        let suite = ConformanceSuite::from_workspace_corpus().expect("the workspace corpus");
        let outcome = suite.run_growth::<GrowthIgnorer>();
        assert!(!outcome.passed(), "a growth-ignoring subject must fail");
        assert!(
            violations_of(&outcome)
                .iter()
                .any(|violation| matches!(violation, Violation::GrowthMissed)),
            "the growth violation is named: {outcome:?}"
        );
    }

    #[test]
    fn a_subject_that_rotates_on_an_append_fails_growth() {
        let suite = ConformanceSuite::from_workspace_corpus().expect("the workspace corpus");
        let outcome = suite.run_growth::<AppendRotator>();
        assert!(!outcome.passed(), "an append-rotating subject must fail");
        assert!(
            violations_of(&outcome)
                .iter()
                .any(|violation| matches!(violation, Violation::GenerationContinuityBroken { .. })),
            "the continuity violation is named: {outcome:?}"
        );
    }
}
