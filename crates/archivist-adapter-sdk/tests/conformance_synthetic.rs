// SPDX-License-Identifier: Apache-2.0

//! The conformance suite's first customer: the synthetic append-only
//! adapter, wired through [`ConformanceAdapter`] and driven across the
//! three time-dimension scenarios (plan Phase 6D).
//!
//! The adapter models the same source the `synthetic_append_only`
//! example walks — one JSONL store at
//! `fixtures/synthetic/append-only/.../source.jsonl`, admitted on its
//! `schema: 1` fingerprint, captured through
//! [`crate::file_capture::CaptureCursor`] under one stable file identity
//! with generation detection — reduced to the two methods the suite
//! observes. Everything it reports is derived from the SDK's own
//! capture core, so a suite pass here is a pass over the published
//! interfaces and nothing private.

use std::fs;
use std::path::{Path, PathBuf};

use archivist_adapter_sdk::conformance::{
    ConformanceAdapter, ConformanceSuite, GenerationContinuity, MountError, PassError, PassReport,
    SOURCE_FILE_NAME,
};
use archivist_adapter_sdk::file_capture::{CaptureCursor, CaptureCursorError, RecordBoundary};
use archivist_adapter_sdk::file_generation::{
    FileGenerationTracker, FileIdentity, GenerationDecision,
};
use archivist_protocol::json::{self, Value};

/// The modeled file identity of the materialized store: the corpus
/// models time by rewriting one file in place, so the identity is held
/// across passes — an append never changes what `stat` would report.
const STORE_IDENTITY: FileIdentity = FileIdentity {
    device: 0,
    inode: 0x6d_5f_1d_5e,
};

/// The fingerprint token the corpus's `schema: 1` stores detect: the
/// same closed token the example publishes.
const FINGERPRINT_TOKEN: &str = "synthetic-append-only-jsonl-v1";

/// The synthetic append-only adapter, reduced to the conformance
/// surface: one mounted store root, a capture cursor, and a generation
/// tracker held across passes.
struct SyntheticConformanceAdapter {
    /// The store file the passes re-read: `root/source.jsonl`.
    store: PathBuf,
    /// The complete-record cursor held across passes.
    cursor: CaptureCursor,
    /// The generation tracker held across passes: its first observation
    /// opens the source's initial generation, and an append continues it.
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
        // The first pass opens the source's first generation; every
        // later pass decides continue-or-rotate over the acknowledged
        // state, exactly as detection does for a live file source.
        let decision = match &mut self.tracker {
            None => {
                self.tracker = Some(FileGenerationTracker::begin(STORE_IDENTITY, &source));
                GenerationContinuity::Opened
            }
            Some(tracker) => match tracker.observe(STORE_IDENTITY, &source) {
                GenerationDecision::Continue => GenerationContinuity::Continued,
                GenerationDecision::Rotated(_) => GenerationContinuity::Rotated,
            },
        };
        let outcome = self
            .cursor
            .observe(&source)
            .map_err(|CaptureCursorError::SourceShrank| PassError::SourceShrank)?;
        Ok(PassReport {
            captured: outcome.captured.to_vec(),
            boundary: outcome.boundary,
            generation: decision,
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
fn the_synthetic_adapter_passes_the_whole_time_dimension() {
    let report = workspace_suite().run_time_dimension::<SyntheticConformanceAdapter>();
    assert!(
        report.passed(),
        "the time-dimension suite: violations {report}"
    );
    assert_eq!(
        report.scenarios.len(),
        archivist_adapter_sdk::conformance::Scenario::all().len(),
        "one outcome per scenario"
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
