// SPDX-License-Identifier: Apache-2.0

//! Tests for the spool-pressure policy state: the high-water boundaries
//! land exactly where the thresholds name them (at-or-above the cap,
//! at-or-below the floor), the pause latches until usage recovers
//! strictly below the resume threshold with the floor recovered, the
//! reason set is closed and ordered, and no rendering can carry a
//! filesystem path.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::{Spool, live_usage_bytes};
use super::{PressureGate, PressureLimits};
use crate::state::StateStore;

// --- the three policy boundaries ------------------------------------------

#[test]
fn spool_cap_pauses_at_or_above_the_cap() {
    let limits = PressureLimits::new(1_000, 0, 80);
    // Below the cap an open gate admits, whatever the margin.
    assert!(
        PressureGate::new(limits)
            .evaluate(999, 1)
            .admits_materialization()
    );
    // At the cap the condition is live: "at or above", not "above".
    let at_cap = PressureGate::new(limits).evaluate(1_000, 1);
    assert!(!at_cap.admits_materialization());
    assert!(at_cap.degraded_reasons().spool_cap_reached());
    assert!(!at_cap.degraded_reasons().free_floor_breached());
    assert!(!at_cap.degraded_reasons().draining());
    // Above it the same condition holds.
    assert!(
        !PressureGate::new(limits)
            .evaluate(1_001, 1)
            .admits_materialization()
    );
}

#[test]
fn free_floor_pauses_at_or_below_the_floor() {
    let limits = PressureLimits::new(u64::MAX, 1_000, 80);
    // One byte above the floor: no condition is live.
    let above = PressureGate::new(limits).evaluate(0, 1_001);
    assert!(above.admits_materialization());
    assert!(!above.is_degraded());
    // At the floor the condition is live: "at or below", not "below".
    let at_floor = PressureGate::new(limits).evaluate(0, 1_000);
    assert!(!at_floor.admits_materialization());
    assert!(at_floor.degraded_reasons().free_floor_breached());
    assert!(!at_floor.degraded_reasons().spool_cap_reached());
    // Below it the same condition holds.
    assert!(
        PressureGate::new(limits)
            .evaluate(0, 999)
            .degraded_reasons()
            .free_floor_breached()
    );
}

#[test]
fn pause_latches_until_usage_recovers_below_the_resume_threshold() {
    let limits = PressureLimits::new(1_000, 0, 80);
    let threshold = limits.resume_threshold_bytes();
    assert_eq!(threshold, 800);
    let mut gate = PressureGate::new(limits);

    // The pause latches at the cap...
    assert!(!gate.evaluate(1_000, 1).admits_materialization());
    // ...and holds between the resume point and the cap, naming the
    // resume rule rather than a live high-water condition.
    let draining = gate.evaluate(850, 1);
    assert!(!draining.admits_materialization());
    assert!(draining.degraded_reasons().draining());
    assert!(!draining.degraded_reasons().spool_cap_reached());
    assert!(!draining.degraded_reasons().free_floor_breached());
    // At the threshold — not strictly below it — the hold remains.
    let at_threshold = gate.evaluate(800, 1);
    assert!(!at_threshold.admits_materialization());
    assert!(at_threshold.degraded_reasons().draining());
    // Strictly below it, the gate opens.
    let resumed = gate.evaluate(799, 1);
    assert!(resumed.admits_materialization());
    assert!(!resumed.is_degraded());
}

#[test]
fn fresh_gate_is_open_between_the_resume_point_and_the_cap() {
    // A gate that never observed a pause is open below the cap exactly
    // as a fresh daemon is: the hysteresis only holds a pause that
    // happened.
    let limits = PressureLimits::new(1_000, 0, 80);
    let fresh = PressureGate::new(limits).evaluate(850, 1);
    assert!(fresh.admits_materialization());
    assert!(!fresh.is_degraded());
    assert!(!fresh.degraded_reasons().draining());
}

#[test]
fn resume_requires_recovered_free_space() {
    let limits = PressureLimits::new(1_000, 500, 80);
    let mut gate = PressureGate::new(limits);

    // Paused with both conditions live.
    let both = gate.evaluate(1_000, 400);
    assert!(!both.admits_materialization());
    assert!(both.degraded_reasons().spool_cap_reached());
    assert!(both.degraded_reasons().free_floor_breached());

    // Usage recovers, but free space sits exactly at the floor: the
    // floor condition is still live, so the pause holds on it.
    let at_floor = gate.evaluate(100, 500);
    assert!(!at_floor.admits_materialization());
    assert!(at_floor.degraded_reasons().free_floor_breached());
    assert!(!at_floor.degraded_reasons().spool_cap_reached());

    // One byte of headroom above the floor and the gate opens.
    let recovered = gate.evaluate(100, 501);
    assert!(recovered.admits_materialization());
    assert!(!recovered.is_degraded());
}

// --- threshold arithmetic ---------------------------------------------------

#[test]
fn resume_threshold_scales_the_cap_by_the_resume_percent() {
    // The registry defaults: 2 GiB cap at 80 percent.
    let limits = PressureLimits::new(2_147_483_648, 5_368_709_120, 80);
    assert_eq!(limits.resume_threshold_bytes(), 1_717_986_918);
    assert_eq!(limits.spool_cap_bytes(), 2_147_483_648);
    assert_eq!(limits.free_floor_bytes(), 5_368_709_120);
    assert_eq!(limits.resume_percent(), 80);
}

#[test]
fn resume_threshold_arithmetic_stays_defined_at_the_extremes() {
    // A 100 percent resume point is the cap itself: a paused gate opens
    // exactly when the cap condition clears.
    assert_eq!(
        PressureLimits::new(1_000, 0, 100).resume_threshold_bytes(),
        1_000
    );
    // The scaling saturates instead of overflowing.
    assert_eq!(
        PressureLimits::new(u64::MAX, 0, 100).resume_threshold_bytes(),
        u64::MAX / 100
    );
    // A zero resume percent never resumes.
    assert_eq!(PressureLimits::new(1_000, 0, 0).resume_threshold_bytes(), 0);
}

// --- the closed reason vocabulary ------------------------------------------

#[test]
fn reason_tokens_are_the_closed_set_in_canonical_order() {
    let limits = PressureLimits::new(1_000, 500, 80);
    // Admitted: no tokens.
    let open = PressureGate::new(limits).evaluate(0, 1_000);
    assert!(open.degraded_reasons().tokens().is_empty());
    // Both high-water conditions live: cap names first.
    let both = PressureGate::new(limits).evaluate(1_000, 500);
    assert_eq!(
        both.degraded_reasons().tokens(),
        vec!["spool_cap", "free_floor"]
    );
    // The latched hold alone: the resume-rule token.
    let mut gate = PressureGate::new(limits);
    let _ = gate.evaluate(1_000, 400);
    let draining = gate.evaluate(900, 1_000);
    assert_eq!(draining.degraded_reasons().tokens(), vec!["draining"]);
}

// --- content-free renderings ------------------------------------------------

/// The canonical JSON text of a status value.
fn canonical(status: &super::PressureStatus) -> String {
    let mut out = Vec::new();
    status.to_json().write_canonical(&mut out);
    String::from_utf8(out).expect("canonical JSON is UTF-8")
}

#[test]
fn renderings_never_carry_a_path() {
    let limits = PressureLimits::new(1_000, 500, 80);
    let paused = PressureGate::new(limits).evaluate(1_000, 400);
    let text = paused.to_string();
    assert!(text.starts_with("materialization paused: "));
    assert!(!text.contains('/'), "display must not carry a path: {text}");
    let json = canonical(&paused);
    assert!(!json.contains('/'), "json must not carry a path: {json}");

    let admitted = PressureGate::new(limits).evaluate(0, 1_000);
    assert_eq!(admitted.to_string(), "materialization admitted");
    assert!(!canonical(&admitted).contains('/'));
}

#[test]
fn status_json_reports_admission_reasons_measurements_and_limits() {
    let limits = PressureLimits::new(1_000, 500, 80);
    let paused = PressureGate::new(limits).evaluate(1_000, 400);
    let json = canonical(&paused);
    assert!(json.contains(r#""admits_materialization":false"#), "{json}");
    assert!(json.contains(r#""degraded":true"#), "{json}");
    assert!(
        json.contains(r#""reasons":["spool_cap","free_floor"]"#),
        "{json}"
    );
    assert!(json.contains(r#""spool_bytes":1000"#), "{json}");
    assert!(json.contains(r#""free_bytes":400"#), "{json}");
    assert!(json.contains(r#""spool_cap_bytes":1000"#), "{json}");
    assert!(json.contains(r#""free_floor_bytes":500"#), "{json}");
    assert!(json.contains(r#""resume_threshold_bytes":800"#), "{json}");

    let admitted = PressureGate::new(limits).evaluate(1, 1_000);
    let json = canonical(&admitted);
    assert!(json.contains(r#""admits_materialization":true"#), "{json}");
    assert!(json.contains(r#""degraded":false"#), "{json}");
    assert!(json.contains(r#""reasons":[]"#), "{json}");
    assert_eq!(admitted.spool_bytes(), 1);
    assert_eq!(admitted.free_bytes(), 1_000);
}

// --- the live measurements --------------------------------------------------

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

/// A private directory removed on drop, so file-backed tests never share
/// state and never leave debris behind.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "archivist-pressure-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A migrated file-backed state store under `dir`, the way the daemon
/// holds one.
fn file_store(dir: &TempDir) -> StateStore {
    let mut store = StateStore::open(&dir.path().join("state.db")).expect("open state store");
    store.migrate().expect("migrate state store");
    store
}

/// A payload of a deterministic length.
fn payload(seed: u8) -> Vec<u8> {
    vec![seed; usize::from(seed) * 64 + 16]
}

#[test]
fn live_usage_sums_the_unacknowledged_entries() {
    let dir = TempDir::new("live-usage");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");

    // An empty spool measures zero.
    assert_eq!(live_usage_bytes(&store).expect("measure"), 0);

    let first = spool.materialize(&store, &payload(1)).expect("materialize");
    let second = spool.materialize(&store, &payload(2)).expect("materialize");
    let expected = first
        .size_bytes()
        .checked_add(second.size_bytes())
        .expect("test payload sizes are small");
    assert_eq!(live_usage_bytes(&store).expect("measure"), expected);
}

#[test]
fn gate_evaluation_takes_both_live_measurements() {
    let dir = TempDir::new("evaluate-spool");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");

    // A cap of zero makes the cap condition live whatever the usage
    // measures; a maximal floor makes the floor condition live whatever
    // the filesystem reports. The decision is host-independent, while
    // the measurements it carried are still asserted to be real.
    let mut gate = PressureGate::new(PressureLimits::new(0, u64::MAX, 80));
    let status = gate.evaluate_spool(&spool, &store).expect("evaluate");
    assert!(!status.admits_materialization());
    assert!(status.degraded_reasons().spool_cap_reached());
    assert!(status.degraded_reasons().free_floor_breached());
    assert_eq!(status.spool_bytes(), 0);
    assert!(
        status.free_bytes() > 0,
        "the filesystem probe measured real free space"
    );

    // The limits are carried onto the status for the reporting surfaces.
    assert_eq!(status.limits().spool_cap_bytes(), 0);
    assert_eq!(status.limits().free_floor_bytes(), u64::MAX);
}
