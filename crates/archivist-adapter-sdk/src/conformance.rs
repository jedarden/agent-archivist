// SPDX-License-Identifier: Apache-2.0

//! The append-only conformance suite (plan Phase 6D): the public,
//! harness-agnostic runner that holds any adapter built on this SDK to
//! the six capture contracts of the synthetic corpus — the three
//! time-dimension scenarios (complete records, a partial tail, growth)
//! and the three environment-dimension scenarios (replacement,
//! permissions, missing roots).
//!
//! A community adapter implements [`ConformanceAdapter`] — mount over a
//! store root, run one capture pass, report what the pass captured — and
//! [`ConformanceSuite`] drives it through the synthetic corpus's scenes
//! (`fixtures/synthetic/append-only/`, the Phase 6D fixture work). The
//! suite materializes each scene into a scratch directory under
//! [`std::env::temp_dir`] so the adapter always runs over a disposable
//! copy and the checked-in corpus is never written to; the materialized
//! store is removed when the scenario ends, whichever way it ends.
//!
//! # The exit-gate properties
//!
//! Each time-dimension scenario asserts the Phase 6D exit-gate sentence
//! the plan holds file fixtures to — *file fixtures reconstruct
//! byte-for-byte through the last complete record* — plus the two capture
//! corollaries that follow from CAP-003 and `EC-01`:
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
//! The environment-dimension scenarios assert what the same contracts
//! owe a source whose *surroundings* change under the adapter (plan
//! Phase 6A's detection list, Phase 6D's exit gate on replacement,
//! permission-error, and missing-root tests):
//!
//! - **Replacement** — a source root swapped for a different fingerprint
//!   closes the old generation and opens a new one named by the
//!   file-identity change (`SID-003`), and capture restarts at the new
//!   generation's first complete record: nothing the old generation
//!   acknowledged — no cursor offset, no record — is silently merged
//!   into the new generation's captures (`EC-02`).
//! - **Permissions** — an unreadable store fails closed: the pass
//!   reports the bounded, content-free unreadable token and nothing
//!   else, on every denied pass. No panic, and no captured bytes or
//!   complete figures are reported over a source the pass could not
//!   read (plan `EC-08`'s fail-closed posture).
//! - **Missing roots** — an absent configured root is reported as the
//!   bounded absent-root token, which the status contract renders as the
//!   `missing` coverage gap (CAP-010): a gap the inventory reports, not
//!   an error storm. An adapter that fabricates a store over the absent
//!   root fails here.
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
//! let report = suite.run_full_suite::<MyAdapter>();
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
//! the `synthetic_append_only` example, which demonstrates the full
//! six-scenario run.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifact::GenerationCause;
use crate::file_capture::RecordBoundary;
use crate::status::{CoverageState, ScanClassification};

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
    /// The detection cause a rotating pass carried: `Some` exactly when
    /// [`PassReport::generation`] is [`GenerationContinuity::Rotated`],
    /// and always a detection cause — a pass that opens or continues a
    /// generation carries `None`. The replacement scenario holds the
    /// cause's *value* to the observation: a swapped root is a
    /// file-identity change, and a rotation named by any other token
    /// misdescribes what the pass saw.
    pub rotation_cause: Option<GenerationCause>,
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
    /// the coverage-gap shape the suite's [`Scenario::MissingRoot`]
    /// scenario owns.
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

/// The scenarios the suite drives, in suite order: three time-dimension
/// scenes over one unchanged-or-grown store, then three
/// environment-dimension scenes over a store whose surroundings change.
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
    /// `replacement`: one store observed before and after its source
    /// root is swapped for a different one — a different file under the
    /// same name. The swap closes the old generation and opens a new one
    /// named by the file-identity change, and capture restarts at the
    /// new generation's first complete record: no cursor offset and no
    /// record of the old generation enters the new generation's captures
    /// (`EC-02`).
    Replacement,
    /// `permissions`: one healthy store whose read access is then
    /// withdrawn. Every denied pass fails closed with the bounded,
    /// content-free unreadable token — no panic, and no captured bytes
    /// or complete figures over a source the pass could not read.
    Permissions,
    /// `missing-root`: the configured root is absent. Mounting reports
    /// the bounded absent-root token — which the status contract renders
    /// as the `missing` coverage gap (CAP-010) — on every attempt, never
    /// a fabricated store.
    MissingRoot,
}

impl Scenario {
    /// The six scenarios in suite order: the time dimension, then the
    /// environment dimension.
    #[must_use]
    pub fn all() -> [Self; 6] {
        [
            Self::CompleteRecords,
            Self::PartialTail,
            Self::Growth,
            Self::Replacement,
            Self::Permissions,
            Self::MissingRoot,
        ]
    }

    /// The three time-dimension scenarios in suite order.
    #[must_use]
    pub fn time_dimension() -> [Self; 3] {
        [Self::CompleteRecords, Self::PartialTail, Self::Growth]
    }

    /// The three environment-dimension scenarios in suite order.
    #[must_use]
    pub fn environment_dimension() -> [Self; 3] {
        [Self::Replacement, Self::Permissions, Self::MissingRoot]
    }

    /// The corpus scene name this scenario materializes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::CompleteRecords => "complete-records",
            Self::PartialTail => "partial-tail",
            Self::Growth => "growth",
            Self::Replacement => "replacement",
            Self::Permissions => "permissions",
            Self::MissingRoot => "missing-root",
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
    /// The rotation's cause disagrees with the observation: a rotation
    /// carried the wrong detection token (or none, where the observation
    /// demanded one), or a non-rotating pass claimed one.
    RotationCauseMismatch {
        /// The cause the observation demanded, when it demanded one.
        expected: Option<GenerationCause>,
        /// The cause the pass carried, when it carried one.
        reported: Option<GenerationCause>,
    },
    /// A replaced root's new generation went unobserved: the pass after
    /// the swap captured nothing.
    ReplacementMissed,
    /// The new generation's captures carried the replaced generation's
    /// state: an old cursor offset, or an old record, entered the new
    /// generation's captures instead of capture restarting at the new
    /// generation's first complete record (`EC-02`).
    ReplacementMerged,
    /// A pass over an unreadable store came back reporting captured bytes
    /// or complete figures — a completion claimed over bytes the pass
    /// could not read.
    UnreadableSourceReportedComplete,
    /// A pass failed closed under the wrong reason token: the observation
    /// demanded one closed vocabulary entry and the pass reported
    /// another.
    PassErrorMismatch {
        /// The reason the observation demanded.
        expected: PassError,
        /// The reason the pass reported.
        reported: PassError,
    },
    /// The adapter mounted over a configured root that does not exist,
    /// fabricating a store where the coverage-gap report was owed.
    AbsentRootMounted,
    /// The status contract no longer renders an absent root as the
    /// `missing` coverage gap: the suite's absent-root token lost its
    /// CAP-010 classification, an SDK vocabulary defect.
    AbsentRootNotACoverageGap,
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
            Self::RotationCauseMismatch { expected, reported } => write!(
                formatter,
                "rotation cause disagrees: expected {}, reported {}",
                CauseToken(*expected),
                CauseToken(*reported),
            ),
            Self::ReplacementMissed => {
                formatter.write_str("a replaced root's new generation captured nothing")
            }
            Self::ReplacementMerged => formatter
                .write_str("the new generation's captures carried the replaced generation's state"),
            Self::UnreadableSourceReportedComplete => formatter.write_str(
                "a pass over an unreadable store reported captured bytes or complete figures",
            ),
            Self::PassErrorMismatch { expected, reported } => write!(
                formatter,
                "pass failed closed under the wrong reason: expected {expected}, reported \
                 {reported}"
            ),
            Self::AbsentRootMounted => {
                formatter.write_str("the adapter mounted over a root that does not exist")
            }
            Self::AbsentRootNotACoverageGap => formatter.write_str(
                "the status contract no longer renders an absent root as the missing coverage \
                 gap",
            ),
        }
    }
}

/// A rotation cause rendered for diagnostics: the cause's token, or the
/// absent token where no cause was carried or demanded.
struct CauseToken(Option<GenerationCause>);

impl fmt::Display for CauseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(cause) => formatter.write_str(cause.token()),
            None => formatter.write_str("no-cause"),
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

/// The result of one suite run — a dimension, or the full six-scenario
/// suite: one outcome per scenario driven, in suite order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuiteReport {
    /// One outcome per scenario, in suite order.
    pub scenarios: Vec<ScenarioOutcome>,
}

impl SuiteReport {
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

impl fmt::Display for SuiteReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.passed() {
            return formatter.write_str("every scenario passed the conformance suite");
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

    /// Drive one adapter through the three time-dimension scenarios:
    /// complete records, partial tail, growth. Each scenario materializes
    /// its own scratch store and mounts a fresh adapter over it.
    #[must_use]
    pub fn run_time_dimension<S: ConformanceAdapter>(&self) -> SuiteReport {
        SuiteReport {
            scenarios: Scenario::time_dimension()
                .into_iter()
                .map(|scenario| self.run_scenario::<S>(scenario))
                .collect(),
        }
    }

    /// Drive one adapter through the three environment-dimension
    /// scenarios: replacement, permissions, missing roots.
    #[must_use]
    pub fn run_environment_dimension<S: ConformanceAdapter>(&self) -> SuiteReport {
        SuiteReport {
            scenarios: Scenario::environment_dimension()
                .into_iter()
                .map(|scenario| self.run_scenario::<S>(scenario))
                .collect(),
        }
    }

    /// Drive one adapter through all six scenarios — the time dimension
    /// then the environment dimension, in [`Scenario::all`] order. This
    /// is the full Phase 6D run the `synthetic_append_only` example
    /// demonstrates.
    #[must_use]
    pub fn run_full_suite<S: ConformanceAdapter>(&self) -> SuiteReport {
        SuiteReport {
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

    /// The replacement scenario: one store observed before and after its
    /// source root is swapped for a different one. The swap rotates the
    /// generation under the file-identity-change cause, capture restarts
    /// at the new generation's first complete record, and a later pass
    /// over the unchanged swapped store captures nothing.
    #[must_use]
    pub fn run_replacement<S: ConformanceAdapter>(&self) -> ScenarioOutcome {
        self.run_scenario::<S>(Scenario::Replacement)
    }

    /// The permissions scenario: one healthy store whose read access is
    /// then withdrawn. Every denied pass fails closed with the bounded
    /// unreadable token — no captured bytes, no complete figures, no
    /// panic.
    #[must_use]
    pub fn run_permissions<S: ConformanceAdapter>(&self) -> ScenarioOutcome {
        self.run_scenario::<S>(Scenario::Permissions)
    }

    /// The missing-root scenario: the configured root is absent, and
    /// mounting reports the bounded absent-root token — the coverage gap
    /// the status contract renders as `missing` — on every attempt.
    #[must_use]
    pub fn run_missing_root<S: ConformanceAdapter>(&self) -> ScenarioOutcome {
        self.run_scenario::<S>(Scenario::MissingRoot)
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
            Scenario::Replacement => {
                let old = self.scene_bytes(&format!("replacement/old/{SOURCE_FILE_NAME}"));
                let new = self.scene_bytes(&format!("replacement/new/{SOURCE_FILE_NAME}"));
                let scratch = materialize(scenario.name(), &old);
                let violations = Self::run_replaced_store::<S>(&scratch.join("root"), &old, &new);
                (scratch, violations)
            }
            Scenario::Permissions => {
                let source = self.scene_bytes(&format!("permissions/root/{SOURCE_FILE_NAME}"));
                let scratch = materialize(scenario.name(), &source);
                let violations = Self::run_denied_store::<S>(&scratch.join("root"), &source);
                (scratch, violations)
            }
            Scenario::MissingRoot => {
                let scratch = materialize_absent_root(scenario.name());
                let violations = Self::run_absent_root::<S>(&scratch.join("root"));
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
        violations.extend(check_cause_presence(&second));
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

    /// The replacement scenario: one store observed before and after its
    /// source root is swapped for a different one — the configured
    /// root's file replaced wholesale under the same name, the way a
    /// replaced export lands on a live host. The pass after the swap
    /// must close the old generation and open a new one named by the
    /// file-identity change (`SID-003`), and capture must restart at the
    /// new generation's first complete record: no cursor offset and no
    /// record of the old generation enters the new generation's captures
    /// (`EC-02`). A quiet pass over the unchanged swapped store then
    /// captures nothing more.
    fn run_replaced_store<S: ConformanceAdapter>(
        root: &Path,
        old: &[u8],
        new: &[u8],
    ) -> Vec<Violation> {
        // Corpus invariants: two complete stores whose complete prefixes
        // share nothing — the swap is a different fingerprint, not a
        // growth of the old store, and a stale cursor's captures can
        // never alias the new generation's prefix.
        let old_boundary = RecordBoundary::select(old);
        let new_boundary = RecordBoundary::select(new);
        let old_prefix = RecordBoundary::complete_prefix(old);
        let new_prefix = RecordBoundary::complete_prefix(new);
        assert!(
            old_boundary.incomplete_tail_bytes == 0,
            "corpus invariant: replacement/old is complete"
        );
        assert!(
            new_boundary.incomplete_tail_bytes == 0,
            "corpus invariant: replacement/new is complete"
        );
        assert!(
            !new_prefix.starts_with(old_prefix),
            "corpus invariant: replacement/new shares no complete prefix with the old store"
        );

        let mut violations = Vec::new();
        let Ok(mut adapter) = S::mount(root) else {
            violations.push(Violation::MountFailed);
            return violations;
        };
        let Ok(first) = adapter.capture_pass() else {
            violations.push(Violation::PassFailed);
            return violations;
        };
        violations.extend(check_opening_pass(&first, old_boundary, old_prefix));
        // The swap: a sibling file written beside the store and renamed
        // over it, so the configured name lands on a genuinely different
        // file — the identity change a live replacement presents.
        swap_store(root, new);
        let Ok(second) = adapter.capture_pass() else {
            violations.push(Violation::PassFailed);
            return violations;
        };
        if second.generation != GenerationContinuity::Rotated {
            violations.push(Violation::GenerationContinuityBroken {
                expected: GenerationContinuity::Rotated,
                reported: second.generation,
            });
        }
        if second.rotation_cause != Some(GenerationCause::FileIdentityChange) {
            violations.push(Violation::RotationCauseMismatch {
                expected: Some(GenerationCause::FileIdentityChange),
                reported: second.rotation_cause,
            });
        }
        if second.boundary != new_boundary {
            violations.push(Violation::BoundaryMismatch {
                reported: second.boundary,
                expected: new_boundary,
            });
        }
        if second.captured.is_empty() {
            violations.push(Violation::ReplacementMissed);
        } else if second.captured != new_prefix {
            violations.push(Violation::ReplacementMerged);
        }
        if !violations.is_empty() {
            return violations;
        }
        // The new generation stands on its own: a quiet pass over the
        // unchanged swapped store continues it and captures nothing.
        let Ok(third) = adapter.capture_pass() else {
            violations.push(Violation::PassFailed);
            return violations;
        };
        violations.extend(check_quiet_pass(&third, new_boundary));
        violations
    }

    /// The permissions scenario: one healthy store whose read access is
    /// then withdrawn (the corpus README's permissions shape: copy the
    /// scene, remove read access). Every denied pass must fail closed
    /// with the bounded, content-free unreadable token — the closed
    /// reason vocabulary's entry for a source that exists but cannot be
    /// read. No panic, no captured bytes, no complete figures: nothing
    /// is reported complete over a source the pass could not read, on
    /// any denied pass.
    fn run_denied_store<S: ConformanceAdapter>(root: &Path, source: &[u8]) -> Vec<Violation> {
        // Corpus invariant: the scene is a normal complete store — the
        // denial is the only thing that changes.
        let expected = RecordBoundary::select(source);
        assert!(
            expected.incomplete_tail_bytes == 0,
            "corpus invariant: permissions/root is complete"
        );
        let expected_prefix = RecordBoundary::complete_prefix(source);

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
        // Withdraw read access, then ask twice: the failure must be the
        // same bounded token on every denied pass, never an escalation
        // and never a fabricated recovery.
        make_unreadable(&root.join(SOURCE_FILE_NAME));
        for _ in 0..2 {
            match adapter.capture_pass() {
                Ok(_) => violations.push(Violation::UnreadableSourceReportedComplete),
                Err(PassError::Unreadable) => {}
                Err(reported) => violations.push(Violation::PassErrorMismatch {
                    expected: PassError::Unreadable,
                    reported,
                }),
            }
        }
        violations
    }

    /// The missing-root scenario: the configured root is absent — the
    /// corpus's `missing-root` shape, where the scene directory exists
    /// and the root does not. Mounting over the absent root must report
    /// exactly the bounded, content-free absent-root token on every
    /// attempt: that token is the coverage-gap shape, which the status
    /// contract classifies `root-absent` and renders as the `missing`
    /// coverage state (CAP-010) — a gap the inventory reports, not an
    /// error storm. An adapter that mounts anyway has fabricated a store
    /// over nothing.
    fn run_absent_root<S: ConformanceAdapter>(root: &Path) -> Vec<Violation> {
        let mut violations = Vec::new();
        // A bounded number of attempts: a steady gap reports the same
        // bounded token every time — never a store fabricated to make
        // the error go away.
        for _ in 0..3 {
            match S::mount(root) {
                Err(MountError::RootAbsent) => {}
                Ok(_) => violations.push(Violation::AbsentRootMounted),
            }
        }
        // Pin the rendering the scenario's sentence depends on: the
        // absent-root token the adapter reported classifies `root-absent`
        // and forces the `missing` coverage state in the status contract.
        if ScanClassification::RootAbsent.forced_coverage() != Some(CoverageState::Absent) {
            violations.push(Violation::AbsentRootNotACoverageGap);
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
    violations.extend(check_cause_presence(report));
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
    violations.extend(check_cause_presence(report));
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

/// The report-vocabulary check every pass is held to: a rotation cause
/// belongs to a rotating pass. A pass that opens or continues a
/// generation while claiming a detection cause misdescribes what it did;
/// a rotation that carries no cause is named where the scenario demands
/// one (the replacement scenario's exact-value check).
fn check_cause_presence(report: &PassReport) -> Vec<Violation> {
    if report.generation == GenerationContinuity::Rotated || report.rotation_cause.is_none() {
        return Vec::new();
    }
    vec![Violation::RotationCauseMismatch {
        expected: None,
        reported: report.rotation_cause,
    }]
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

/// Swap the materialized store's file for different bytes, wholesale: a
/// sibling file is written beside the store and renamed over it, so the
/// configured name lands on a genuinely different file — the shape a
/// replaced root presents, a new file identity under the same name.
///
/// # Panics
/// When the scratch store cannot be written or renamed: the suite just
/// materialized it, so a failure here is a host defect, not an adapter
/// observation.
fn swap_store(root: &Path, bytes: &[u8]) {
    let store = root.join(SOURCE_FILE_NAME);
    let sibling = root.join(format!(".{SOURCE_FILE_NAME}.swapped"));
    fs::write(&sibling, bytes).unwrap_or_else(|error| {
        panic!(
            "the conformance sibling {} is writable: {error}",
            sibling.display()
        )
    });
    fs::rename(&sibling, &store).unwrap_or_else(|error| {
        panic!(
            "the conformance store {} is swappable: {error}",
            store.display()
        )
    });
}

/// Withdraw this process's read access to the materialized store — the
/// corpus README's permissions shape: copy the scene, then remove read
/// access. On unix that is the permission denial itself, every read bit
/// stripped from the file; elsewhere the store's name is re-pointed at a
/// directory, a path that exists but can never be read as a file. Either
/// way the suite verifies the withdrawal took hold before driving the
/// adapter.
///
/// # Panics
/// When the store cannot be made unreadable — a host where the denial
/// does not hold (a root run) cannot exercise the scenario, exactly as a
/// missing scene file cannot.
#[cfg(unix)]
fn make_unreadable(store: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(store, fs::Permissions::from_mode(0o0)).unwrap_or_else(|error| {
        panic!(
            "the conformance store {} takes a permission change: {error}",
            store.display()
        )
    });
    assert_unreadable(store);
}

/// The non-unix withdrawal: the store's name now addresses a directory —
/// a source that exists but cannot be read as a file, the same closed
/// failure class the scenario holds adapters to.
///
/// # Panics
/// When the store cannot be replaced, or the replacement can still be
/// read as a file.
#[cfg(not(unix))]
fn make_unreadable(store: &Path) {
    fs::remove_file(store).unwrap_or_else(|error| {
        panic!(
            "the conformance store {} is removable: {error}",
            store.display()
        )
    });
    fs::create_dir(store).unwrap_or_else(|error| {
        panic!(
            "the conformance store {} is creatable: {error}",
            store.display()
        )
    });
    assert_unreadable(store);
}

/// Fail unless the store is unreadable to this process: the scenario's
/// fault must actually be in place before the adapter is asked to
/// observe it.
///
/// # Panics
/// When the store still opens — the host cannot deny reads to its own
/// scratch store (a root run), so the scenario cannot be exercised.
fn assert_unreadable(store: &Path) {
    if let Ok(handle) = fs::File::open(store) {
        drop(handle);
        panic!(
            "the conformance host denies reads to its scratch store {} (not running as root?)",
            store.display()
        );
    }
}

/// A unique scratch directory for the missing-root scenario: the scene
/// directory is created and the store root deliberately is not — the
/// corpus's `missing-root` shape, an absent configured root under a
/// scene that exists.
///
/// # Panics
/// When the scratch directory cannot be created.
fn materialize_absent_root(scenario: &str) -> PathBuf {
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
    fs::create_dir_all(&scratch).unwrap_or_else(|error| {
        panic!(
            "the conformance scratch {} is creatable: {error}",
            scratch.display()
        )
    });
    assert!(
        !scratch.join("root").exists(),
        "a fresh scratch directory carries no store root"
    );
    scratch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_capture::{CaptureCursor, CaptureCursorError};
    use crate::file_generation::{FileGenerationTracker, GenerationDecision};

    /// The store file of a test subject's mounted root.
    fn store_of(root: &Path) -> Result<PathBuf, MountError> {
        if !root.is_dir() {
            return Err(MountError::RootAbsent);
        }
        Ok(root.join(SOURCE_FILE_NAME))
    }

    /// The store's live file identity: the device/inode tuple a `stat`
    /// reports, read fresh on every pass — the way a live adapter stats
    /// its configured root, so a store file replaced by a rename (the
    /// replacement scenario's swap) genuinely changes the identity the
    /// tracker holds.
    fn stat_identity(store: &Path) -> Result<crate::file_generation::FileIdentity, PassError> {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(store).map_err(|_| PassError::Unreadable)?;
        Ok(crate::file_generation::FileIdentity::new(
            metadata.dev(),
            metadata.ino(),
        ))
    }

    /// The generation decision of one pass over the tracker, in the
    /// suite's report vocabulary: the continuity and the rotation cause
    /// a decision-carrying subject reports. `None` before the first
    /// observation.
    fn tracked_pass(
        tracker: &mut Option<FileGenerationTracker>,
        identity: crate::file_generation::FileIdentity,
        source: &[u8],
    ) -> (GenerationContinuity, Option<GenerationCause>) {
        match tracker {
            None => {
                *tracker = Some(FileGenerationTracker::begin(identity, source));
                (GenerationContinuity::Opened, None)
            }
            Some(state) => match state.observe(identity, source) {
                GenerationDecision::Continue => (GenerationContinuity::Continued, None),
                GenerationDecision::Rotated(opened) => {
                    (GenerationContinuity::Rotated, Some(opened.cause))
                }
            },
        }
    }

    /// A conforming subject built straight on the capture core: the
    /// reference behavior the suite's happy path is written against. It
    /// stats the store for its identity, so a swapped file rotates under
    /// the file-identity-change cause, and its cursor restarts at the
    /// new generation's first complete record.
    struct ReferenceSubject {
        store: PathBuf,
        cursor: CaptureCursor,
        tracker: Option<FileGenerationTracker>,
    }

    impl ConformanceAdapter for ReferenceSubject {
        fn mount(root: &Path) -> Result<Self, MountError> {
            Ok(Self {
                store: store_of(root)?,
                cursor: CaptureCursor::new(),
                tracker: None,
            })
        }

        fn capture_pass(&mut self) -> Result<PassReport, PassError> {
            let source = fs::read(&self.store).map_err(|_| PassError::Unreadable)?;
            let identity = stat_identity(&self.store)?;
            let (generation, rotation_cause) = tracked_pass(&mut self.tracker, identity, &source);
            if rotation_cause.is_some() {
                // Capture restarts at the new generation's first complete
                // record (AC-03's mitigation): nothing the replaced
                // generation acknowledged enters the new captures.
                self.cursor = CaptureCursor::new();
            }
            let outcome = self
                .cursor
                .observe(&source)
                .map_err(|CaptureCursorError::SourceShrank| PassError::SourceShrank)?;
            Ok(PassReport {
                captured: outcome.captured.to_vec(),
                boundary: outcome.boundary,
                generation,
                rotation_cause,
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
                rotation_cause: None,
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
                    rotation_cause: None,
                });
            }
            let selected = RecordBoundary::select(&source);
            let captured = RecordBoundary::complete_prefix(&source).to_vec();
            self.first_boundary = Some(selected);
            Ok(PassReport {
                captured,
                boundary: selected,
                generation: GenerationContinuity::Opened,
                rotation_cause: None,
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
                rotation_cause: None,
            })
        }
    }

    /// A subject with the stale-cursor fault: it stats the store and so
    /// detects the swap and rotates under the right cause, but its
    /// cursor keeps the replaced generation's offset. The corpus's new
    /// store is longer than the old one, so the surviving offset lands
    /// inside the new store's records: the pass returns a mid-record
    /// fragment under a record count the replaced generation accrued —
    /// replaced-generation cursor state contaminating the new
    /// generation's captures (`EC-02`'s breach).
    struct StaleCursorSwapper {
        store: PathBuf,
        cursor: CaptureCursor,
        tracker: Option<FileGenerationTracker>,
    }

    impl ConformanceAdapter for StaleCursorSwapper {
        fn mount(root: &Path) -> Result<Self, MountError> {
            Ok(Self {
                store: store_of(root)?,
                cursor: CaptureCursor::new(),
                tracker: None,
            })
        }

        fn capture_pass(&mut self) -> Result<PassReport, PassError> {
            let source = fs::read(&self.store).map_err(|_| PassError::Unreadable)?;
            let identity = stat_identity(&self.store)?;
            let (generation, rotation_cause) = tracked_pass(&mut self.tracker, identity, &source);
            // The fault: the cursor is never restarted, whatever the
            // generation decision said.
            let outcome = self
                .cursor
                .observe(&source)
                .map_err(|CaptureCursorError::SourceShrank| PassError::SourceShrank)?;
            Ok(PassReport {
                captured: outcome.captured.to_vec(),
                boundary: outcome.boundary,
                generation,
                rotation_cause,
            })
        }
    }

    /// A subject with the silent-drop fault: it detects the swap, rotates
    /// under the right cause, and reports the new store's own boundary
    /// figures — but captures none of the new generation's records, so
    /// the replacement is observed and then left unarchived.
    struct SilentDropSwapper {
        store: PathBuf,
        tracker: Option<FileGenerationTracker>,
    }

    impl ConformanceAdapter for SilentDropSwapper {
        fn mount(root: &Path) -> Result<Self, MountError> {
            Ok(Self {
                store: store_of(root)?,
                tracker: None,
            })
        }

        fn capture_pass(&mut self) -> Result<PassReport, PassError> {
            let source = fs::read(&self.store).map_err(|_| PassError::Unreadable)?;
            let identity = stat_identity(&self.store)?;
            let (generation, rotation_cause) = tracked_pass(&mut self.tracker, identity, &source);
            if rotation_cause.is_some() {
                // The fault: the rotation is reported with the new
                // store's figures, and the capture is dropped.
                return Ok(PassReport {
                    captured: Vec::new(),
                    boundary: RecordBoundary::select(&source),
                    generation,
                    rotation_cause,
                });
            }
            Ok(PassReport {
                captured: RecordBoundary::complete_prefix(&source).to_vec(),
                boundary: RecordBoundary::select(&source),
                generation,
                rotation_cause,
            })
        }
    }

    /// A subject with the history-merging fault: it detects the swap,
    /// rotates under the right cause, and restarts its cursor — but it
    /// prepends the replaced generation's captures to the new
    /// generation's, silently merging the old records into the new
    /// generation (`EC-02`'s breach).
    struct HistoryMergingSwapper {
        store: PathBuf,
        cursor: CaptureCursor,
        tracker: Option<FileGenerationTracker>,
        replaced_captures: Option<Vec<u8>>,
    }

    impl ConformanceAdapter for HistoryMergingSwapper {
        fn mount(root: &Path) -> Result<Self, MountError> {
            Ok(Self {
                store: store_of(root)?,
                cursor: CaptureCursor::new(),
                tracker: None,
                replaced_captures: None,
            })
        }

        fn capture_pass(&mut self) -> Result<PassReport, PassError> {
            let source = fs::read(&self.store).map_err(|_| PassError::Unreadable)?;
            let identity = stat_identity(&self.store)?;
            let (generation, rotation_cause) = tracked_pass(&mut self.tracker, identity, &source);
            if generation == GenerationContinuity::Opened {
                self.replaced_captures = Some(RecordBoundary::complete_prefix(&source).to_vec());
            }
            if rotation_cause.is_some() {
                self.cursor = CaptureCursor::new();
            }
            let outcome = self
                .cursor
                .observe(&source)
                .map_err(|CaptureCursorError::SourceShrank| PassError::SourceShrank)?;
            let mut captured = outcome.captured.to_vec();
            if rotation_cause.is_some() {
                // The fault: the replaced generation's records enter the
                // new generation's captures.
                let mut merged = self.replaced_captures.clone().unwrap_or_default();
                merged.append(&mut captured);
                captured = merged;
            }
            Ok(PassReport {
                captured,
                boundary: outcome.boundary,
                generation,
                rotation_cause,
            })
        }
    }

    /// A subject with the fabricating fault: when the store cannot be
    /// read it does not fail closed — it re-reports the last healthy
    /// pass's complete figures as a fresh pass, a completion claimed
    /// over bytes it could not read.
    struct FabricatingReader {
        store: PathBuf,
        cursor: CaptureCursor,
        last_boundary: Option<RecordBoundary>,
    }

    impl ConformanceAdapter for FabricatingReader {
        fn mount(root: &Path) -> Result<Self, MountError> {
            Ok(Self {
                store: store_of(root)?,
                cursor: CaptureCursor::new(),
                last_boundary: None,
            })
        }

        fn capture_pass(&mut self) -> Result<PassReport, PassError> {
            match fs::read(&self.store) {
                Ok(source) => {
                    let outcome = self
                        .cursor
                        .observe(&source)
                        .map_err(|CaptureCursorError::SourceShrank| PassError::SourceShrank)?;
                    self.last_boundary = Some(outcome.boundary);
                    Ok(PassReport {
                        captured: outcome.captured.to_vec(),
                        boundary: outcome.boundary,
                        generation: GenerationContinuity::Opened,
                        rotation_cause: None,
                    })
                }
                // The fault: an unreadable store still reports the stale
                // complete figures as if a pass had measured them.
                Err(_) => Ok(PassReport {
                    captured: Vec::new(),
                    boundary: self.last_boundary.unwrap_or(RecordBoundary {
                        complete_bytes: 0,
                        complete_records: 0,
                        incomplete_tail_bytes: 0,
                    }),
                    generation: GenerationContinuity::Continued,
                    rotation_cause: None,
                }),
            }
        }
    }

    /// A subject that mounts over any configured root, absent or not: a
    /// store fabricated where the coverage-gap report was owed.
    struct FabricatingMounter;

    impl ConformanceAdapter for FabricatingMounter {
        fn mount(_root: &Path) -> Result<Self, MountError> {
            Ok(Self)
        }

        fn capture_pass(&mut self) -> Result<PassReport, PassError> {
            // The fabricated store never yields bytes; the scenario
            // flags the mount before any pass runs.
            Err(PassError::Unreadable)
        }
    }

    fn violations_of(outcome: &ScenarioOutcome) -> &[Violation] {
        &outcome.violations
    }

    #[test]
    fn the_reference_subject_passes_every_scenario_of_the_full_suite() {
        let suite = ConformanceSuite::from_workspace_corpus().expect("the workspace corpus");
        let report = suite.run_full_suite::<ReferenceSubject>();
        assert_eq!(
            report.scenarios.len(),
            Scenario::all().len(),
            "one outcome per scenario, in suite order"
        );
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

    #[test]
    fn a_subject_whose_cursor_survives_a_replacement_contaminates_the_new_generation() {
        let suite = ConformanceSuite::from_workspace_corpus().expect("the workspace corpus");
        let outcome = suite.run_replacement::<StaleCursorSwapper>();
        assert!(
            !outcome.passed(),
            "a stale-cursor subject must fail the replacement"
        );
        assert!(
            violations_of(&outcome)
                .iter()
                .any(|violation| matches!(violation, Violation::ReplacementMerged)),
            "the replaced-generation state contaminating the new capture is named: {outcome:?}"
        );
    }

    #[test]
    fn a_subject_that_drops_the_new_generation_capture_fails_replacement() {
        let suite = ConformanceSuite::from_workspace_corpus().expect("the workspace corpus");
        let outcome = suite.run_replacement::<SilentDropSwapper>();
        assert!(
            !outcome.passed(),
            "a silent-drop subject must fail the replacement"
        );
        assert!(
            violations_of(&outcome)
                .iter()
                .any(|violation| matches!(violation, Violation::ReplacementMissed)),
            "the replacement-missed violation is named: {outcome:?}"
        );
    }

    #[test]
    fn a_subject_that_merges_the_replaced_history_fails_replacement() {
        let suite = ConformanceSuite::from_workspace_corpus().expect("the workspace corpus");
        let outcome = suite.run_replacement::<HistoryMergingSwapper>();
        assert!(
            !outcome.passed(),
            "a history-merging subject must fail the replacement"
        );
        assert!(
            violations_of(&outcome)
                .iter()
                .any(|violation| matches!(violation, Violation::ReplacementMerged)),
            "the replacement-merged violation is named: {outcome:?}"
        );
    }

    #[test]
    fn a_subject_that_fabricates_completion_over_a_denied_store_fails_permissions() {
        let suite = ConformanceSuite::from_workspace_corpus().expect("the workspace corpus");
        let outcome = suite.run_permissions::<FabricatingReader>();
        assert!(
            !outcome.passed(),
            "a fabricating subject must fail the permissions scenario"
        );
        assert!(
            violations_of(&outcome)
                .iter()
                .any(|violation| matches!(violation, Violation::UnreadableSourceReportedComplete)),
            "the fabricated-completion violation is named: {outcome:?}"
        );
    }

    #[test]
    fn a_subject_that_mounts_over_an_absent_root_fails_missing_root() {
        let suite = ConformanceSuite::from_workspace_corpus().expect("the workspace corpus");
        let outcome = suite.run_missing_root::<FabricatingMounter>();
        assert!(
            !outcome.passed(),
            "a fabricating mounter must fail the missing-root scenario"
        );
        assert!(
            violations_of(&outcome)
                .iter()
                .any(|violation| matches!(violation, Violation::AbsentRootMounted)),
            "the absent-root-mounted violation is named: {outcome:?}"
        );
    }
}
