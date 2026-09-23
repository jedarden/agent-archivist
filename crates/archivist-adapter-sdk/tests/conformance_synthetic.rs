// SPDX-License-Identifier: Apache-2.0

//! The conformance suite's first customer: the synthetic append-only
//! adapter, wired through [`ConformanceAdapter`] and driven across the
//! suite's six scenarios — the three time-dimension scenes (complete
//! records, partial tail, growth) and the three environment-dimension
//! scenes (replacement, permissions, missing roots) of plan Phase 6D.
//!
//! The adapter models the same source the `synthetic_append_only`
//! example walks — one JSONL store at
//! `fixtures/synthetic/append-only/.../source.jsonl`, admitted on its
//! `schema: 1` fingerprint, captured through
//! [`crate::file_capture::CaptureCursor`] under the file identity a
//! `stat` of the store reports, with generation detection — reduced to
//! the two methods the suite observes. Everything it reports is derived
//! from the SDK's own capture core, so a suite pass here is a pass over
//! the published interfaces and nothing private.

use std::fs;
use std::path::{Path, PathBuf};

use archivist_adapter_sdk::conformance::{
    ConformanceAdapter, ConformanceSuite, GenerationContinuity, MountError, PassError, PassReport,
    SOURCE_FILE_NAME, Scenario,
};
use archivist_adapter_sdk::file_capture::{CaptureCursor, CaptureCursorError, RecordBoundary};
use archivist_adapter_sdk::file_generation::{
    FileGenerationTracker, FileIdentity, GenerationDecision,
};
use archivist_protocol::json::{self, Value};

/// The fingerprint token the corpus's `schema: 1` stores detect: the
/// same closed token the example publishes.
const FINGERPRINT_TOKEN: &str = "synthetic-append-only-jsonl-v1";

/// The store's live file identity: the device/inode tuple a `stat`
/// reports, read fresh on every pass — the way a live adapter stats its
/// configured root. An append keeps the identity (the suite grows the
/// store in place); the replacement scenario's rename-swap genuinely
/// changes it, which is what the `file-identity-change` rotation names.
fn stat_identity(store: &Path) -> Result<FileIdentity, PassError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(store).map_err(|_| PassError::Unreadable)?;
    Ok(FileIdentity::new(metadata.dev(), metadata.ino()))
}

/// The synthetic append-only adapter, reduced to the conformance
/// surface: one mounted store root, a capture cursor, and a generation
/// tracker held across passes.
struct SyntheticConformanceAdapter {
    /// The store file the passes re-read: `root/source.jsonl`.
    store: PathBuf,
    /// The complete-record cursor held across passes.
    cursor: CaptureCursor,
    /// The generation tracker held across passes: its first observation
    /// opens the source's initial generation, an append continues it,
    /// and a replaced store file rotates it under the identity change.
    tracker: Option<FileGenerationTracker>,
}

impl ConformanceAdapter for SyntheticConformanceAdapter {
    fn mount(root: &Path) -> Result<Self, MountError> {
        if !root.is_dir() {
            return Err(MountError::RootAbsent);
        }
        Ok(Self {
            store: root.join(SOURCE_FILE_NAME),
            cursor: CaptureCursor::new(),
            tracker: None,
        })
    }

    fn capture_pass(&mut self) -> Result<PassReport, PassError> {
        let source = fs::read(&self.store).map_err(|_| PassError::Unreadable)?;
        if detect_fingerprint(&source).is_none() {
            return Err(PassError::UnsupportedFingerprint);
        }
        let identity = stat_identity(&self.store)?;
        // The first pass opens the source's first generation; every
        // later pass decides continue-or-rotate over the acknowledged
        // state, exactly as detection does for a live file source.
        let mut rotation_cause = None;
        let generation = match &mut self.tracker {
            None => {
                self.tracker = Some(FileGenerationTracker::begin(identity, &source));
                GenerationContinuity::Opened
            }
            Some(tracker) => match tracker.observe(identity, &source) {
                GenerationDecision::Continue => GenerationContinuity::Continued,
                GenerationDecision::Rotated(opened) => {
                    rotation_cause = Some(opened.cause);
                    GenerationContinuity::Rotated
                }
            },
        };
        if rotation_cause.is_some() {
            // Capture restarts at the new generation's first complete
            // record (AC-03's mitigation): nothing the replaced
            // generation acknowledged enters the new generation's
            // captures.
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

/// Detect the corpus store's fingerprint from its first complete record:
/// a JSON object carrying `schema: 1` plus text `id`, `type`, and `ts`
/// members — the same closed rule the example applies. Anything else
/// fails closed as undetectable (plan `EC-08`). The detected token is the
/// one the store was admitted on.
fn detect_fingerprint(bytes: &[u8]) -> Option<&'static str> {
    let first = RecordBoundary::records(bytes).next()?;
    let value = json::parse(first).ok()?;
    let Value::Object(object) = value else {
        return None;
    };
    if object.get("schema") != Some(&Value::Int(1)) {
        return None;
    }
    let member = |key: &str| matches!(object.get(key), Some(Value::Text(_)));
    if !member("id") || !member("type") || !member("ts") {
        return None;
    }
    Some(FINGERPRINT_TOKEN)
}

/// The suite runs from the workspace's committed corpus.
fn workspace_suite() -> ConformanceSuite {
    ConformanceSuite::from_workspace_corpus().expect("the workspace ships the synthetic corpus")
}

#[test]
fn the_synthetic_adapter_passes_complete_records() {
    let outcome = workspace_suite().run_complete_records::<SyntheticConformanceAdapter>();
    assert!(
        outcome.passed(),
        "complete-records: {:?}",
        outcome.violations
    );
}

#[test]
fn the_synthetic_adapter_passes_partial_tail() {
    let outcome = workspace_suite().run_partial_tail::<SyntheticConformanceAdapter>();
    assert!(outcome.passed(), "partial-tail: {:?}", outcome.violations);
}

#[test]
fn the_synthetic_adapter_passes_growth() {
    let outcome = workspace_suite().run_growth::<SyntheticConformanceAdapter>();
    assert!(outcome.passed(), "growth: {:?}", outcome.violations);
}

#[test]
fn the_synthetic_adapter_passes_replacement() {
    let outcome = workspace_suite().run_replacement::<SyntheticConformanceAdapter>();
    assert!(outcome.passed(), "replacement: {:?}", outcome.violations);
}

#[test]
fn the_synthetic_adapter_passes_permissions() {
    let outcome = workspace_suite().run_permissions::<SyntheticConformanceAdapter>();
    assert!(outcome.passed(), "permissions: {:?}", outcome.violations);
}

#[test]
fn the_synthetic_adapter_passes_missing_root() {
    let outcome = workspace_suite().run_missing_root::<SyntheticConformanceAdapter>();
    assert!(outcome.passed(), "missing-root: {:?}", outcome.violations);
}

#[test]
fn the_synthetic_adapter_passes_the_whole_time_dimension() {
    let report = workspace_suite().run_time_dimension::<SyntheticConformanceAdapter>();
    assert!(
        report.passed(),
        "the time-dimension suite: violations {report}"
    );
    assert_eq!(
        report.scenarios.len(),
        Scenario::time_dimension().len(),
        "one outcome per time-dimension scenario"
    );
    // The boundary figures the suite's own selection yields for the
    // partial-tail scene are the exit-gate sentence in numbers: the torn
    // tail is measured, and capture's reconstruction stops at the last
    // complete record.
    let suite = workspace_suite();
    let torn = fs::read(
        suite
            .corpus()
            .join("partial-tail")
            .join("root")
            .join(SOURCE_FILE_NAME),
    )
    .expect("the committed partial-tail scene is readable");
    let selected = RecordBoundary::select(&torn);
    assert!(
        selected.incomplete_tail_bytes > 0,
        "the corpus scene ends torn"
    );
    assert_eq!(
        selected.complete_bytes + selected.incomplete_tail_bytes,
        u64::try_from(torn.len()).expect("scene sizes are small"),
        "the split partitions the snapshot exactly"
    );
}

#[test]
fn the_synthetic_adapter_passes_the_full_six_scenario_suite() {
    let report = workspace_suite().run_full_suite::<SyntheticConformanceAdapter>();
    assert!(
        report.passed(),
        "the full conformance suite: violations {report}"
    );
    assert_eq!(
        report.scenarios.len(),
        Scenario::all().len(),
        "one outcome per scenario, the complete corpus run"
    );
    assert_eq!(
        report
            .scenarios
            .iter()
            .map(|outcome| outcome.scenario.name())
            .collect::<Vec<_>>(),
        vec![
            "complete-records",
            "partial-tail",
            "growth",
            "replacement",
            "permissions",
            "missing-root",
        ],
        "the full suite drives the six scenarios in corpus order"
    );
}
