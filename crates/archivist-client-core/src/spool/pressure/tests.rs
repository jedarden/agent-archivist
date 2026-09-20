// SPDX-License-Identifier: Apache-2.0

//! Tests for the spool-pressure policy state: the high-water boundaries
//! land exactly where the thresholds name them (at-or-above the cap,
//! at-or-below the floor), the pause latches until usage recovers
//! strictly below the resume threshold with the floor recovered, the
//! reason set is closed and ordered, no rendering can carry a
//! filesystem path, and the pause stops new materialization only —
//! pending retries and the receipts they work toward keep flowing
//! while a gate holds.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::{SPOOL_DIR_NAME, Spool, SpoolErrorKind, live_usage_bytes};
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

// --- the configured recovery condition --------------------------------------

/// A loaded configuration of a fully-declared host with the three spool
/// policy keys supplied through the environment tier.
fn configured(resume_percent: &str) -> crate::config::ResolvedConfig {
    use crate::config::ConfigSources;
    ConfigSources::non_interactive()
        .env("HOME", "/home/operator")
        .env("TEST_RAW_CREDENTIAL", "fixture-raw-credential")
        .env(
            "ARCHIVIST_INGEST_ENDPOINT_URL",
            "https://ingest.example.invalid",
        )
        .env(
            "ARCHIVIST_STORAGE_ENDPOINT_URL",
            "https://s3.example.invalid",
        )
        .env("ARCHIVIST_STORAGE_REGION", "us-east-1")
        .env("ARCHIVIST_STORAGE_ENCRYPTION", "s3_sse")
        .env("ARCHIVIST_STORAGE_RAW_BUCKET", "archivist-raw-example")
        .env(
            "ARCHIVIST_STORAGE_CONTROL_BUCKET",
            "archivist-control-example",
        )
        .env(
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            "env:TEST_RAW_CREDENTIAL",
        )
        .env(
            "ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF",
            "env:TEST_CONTROL_CREDENTIAL",
        )
        .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "127.0.0.1:8087")
        .env("ARCHIVIST_ADMIN_ENDPOINT_URL", "https://s3.example.invalid")
        .env("ARCHIVIST_ADMIN_REGION", "us-east-1")
        .env(
            "ARCHIVIST_ADMIN_CONTROL_BUCKET",
            "archivist-control-example",
        )
        .env(
            "ARCHIVIST_ADMIN_TENANT",
            "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b",
        )
        .env(
            "ARCHIVIST_ADMIN_CREDENTIALS_REF",
            "env:TEST_ADMIN_CREDENTIAL",
        )
        .env(
            "ARCHIVIST_ADMIN_AUTHORITY_SEED_REF",
            "env:TEST_AUTHORITY_SEED",
        )
        .env("ARCHIVIST_SPOOL_MAX_BYTES", "1000")
        .env("ARCHIVIST_SPOOL_FREE_FLOOR_BYTES", "400")
        .env("ARCHIVIST_SPOOL_RESUME_PERCENT", resume_percent)
        .load()
        .expect("fully declared host loads")
}

#[test]
fn the_configured_resume_percent_governs_the_recovery_condition() {
    // A non-default resume percent arrives through the configuration
    // tier, and that resolved value — not the registry default — is the
    // recovery condition the held gate resumes under.
    let limits = PressureLimits::from_config(&configured("50"));
    assert_eq!(limits.spool_cap_bytes(), 1_000);
    assert_eq!(limits.free_floor_bytes(), 400);
    assert_eq!(limits.resume_percent(), 50);
    assert_eq!(limits.resume_threshold_bytes(), 500);

    let mut gate = PressureGate::new(limits);
    // The pause latches at the cap...
    assert!(!gate.evaluate(1_000, 401).admits_materialization());
    // ...holds at the configured point itself — "strictly below" — ...
    let at_point = gate.evaluate(500, 401);
    assert!(!at_point.admits_materialization());
    assert!(at_point.degraded_reasons().draining());
    // ...and opens one byte under it, the floor having recovered — the
    // latch itself cleared, not merely this one evaluation.
    let resumed = gate.evaluate(499, 401);
    assert!(resumed.admits_materialization());
    assert!(!gate.is_paused());
    assert!(resumed.degraded_reasons().tokens().is_empty());

    // A different configured percent moves the same boundary: the
    // recovery condition is the configured one, not a constant.
    let limits = PressureLimits::from_config(&configured("100"));
    assert_eq!(limits.resume_percent(), 100);
    assert_eq!(limits.resume_threshold_bytes(), 1_000);
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

// --- the hold stops new materialization only ---------------------------------

#[test]
fn the_hold_leaves_pending_retries_flowing() {
    let dir = TempDir::new("pending-retries");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");
    let spool_dir = dir.path().join(SPOOL_DIR_NAME);

    // Two live bundles under an open gate; their combined size becomes
    // the cap, so the ratio below is exact whatever the recorded sizes.
    let small = spool
        .materialize(
            &store,
            &mut PressureGate::new(PressureLimits::new(u64::MAX, 0, 80)),
            &payload(1),
        )
        .expect("materialize");
    let large = spool
        .materialize(
            &store,
            &mut PressureGate::new(PressureLimits::new(u64::MAX, 0, 80)),
            &[b'x'; 400],
        )
        .expect("materialize");
    let cap = small
        .size_bytes()
        .checked_add(large.size_bytes())
        .expect("test payload sizes are small");
    assert!(
        large.size_bytes() * 5 >= cap * 4,
        "the large bundle must sit at or above the resume point on its own"
    );

    // The hold latches at the cap: new materialization is refused, and
    // the refusal wrote nothing — the spool holds exactly the bytes it
    // held, files included.
    let mut gate = PressureGate::new(PressureLimits::new(cap, 0, 80));
    let refused = spool
        .materialize(&store, &mut gate, b"new capture")
        .expect_err("the at-cap spool must pause new materialization");
    assert_eq!(refused.kind(), SpoolErrorKind::MaterializationPaused);
    assert_eq!(live_usage_bytes(&store).expect("measure"), cap);
    assert!(spool_dir.join(small.bundle_name()).is_file());
    assert!(spool_dir.join(large.bundle_name()).is_file());

    // The pause stops new materialization only. Both pending entries
    // keep moving through their retry schedule — each attempt's
    // bookkeeping advances independently, and the row states run their
    // lifecycle while the gate holds, because draining pending work is
    // the only way the spool shrinks and nothing may block it.
    for (name, attempts) in [(small.bundle_name(), 1), (large.bundle_name(), 3)] {
        let moved = store
            .connection()
            .execute(
                "UPDATE spool_entries SET state = 'uploading', attempt_count = ?1,
                 next_attempt_at = '2026-09-20T23:59:00.000Z'
                 WHERE bundle_name = ?2 AND state = 'materialized'",
                rusqlite::params![attempts, name],
            )
            .expect("a pending retry advances while the gate holds");
        assert_eq!(moved, 1, "the pending entry moved to its next attempt");
    }
    let retried: i64 = store
        .connection()
        .query_row(
            "SELECT attempt_count FROM spool_entries WHERE bundle_name = ?1",
            [large.bundle_name()],
            |row| row.get(0),
        )
        .expect("the retried row is present");
    assert_eq!(retried, 3, "the retry schedule advanced its own entry");

    // A retried entry is still live — a retry is not a receipt — so the
    // cap still counts it and the hold stands on the same numbers.
    assert_eq!(live_usage_bytes(&store).expect("measure"), cap);
    let live = gate.evaluate_spool(&spool, &store).expect("evaluate");
    assert!(!live.admits_materialization());
    assert_eq!(live.degraded_reasons().tokens(), vec!["spool_cap"]);

    // The receipt the retries work toward is also outside the policy.
    // The small entry acknowledges under the hold and the
    // acknowledgement's cleanup removes its bundle; the hold stays
    // latched — the large entry's bytes are still live at or above the
    // resume point — now naming the resume rule.
    store
        .connection()
        .execute(
            "UPDATE spool_entries SET state = 'acknowledged' WHERE bundle_name = ?1",
            [small.bundle_name()],
        )
        .expect("acknowledge under the hold");
    spool
        .remove(small.bundle_name())
        .expect("the acknowledgement's cleanup runs under the hold");
    assert!(!spool_dir.join(small.bundle_name()).exists());

    let draining = gate.evaluate_spool(&spool, &store).expect("evaluate");
    assert!(!draining.admits_materialization());
    assert!(draining.degraded_reasons().draining());
    assert!(spool_dir.join(large.bundle_name()).is_file());

    // The last pending entry receipts and cleans the same way, the
    // drain completes, and the same held gate — not a fresh one —
    // admits again: the next materialization really writes.
    store
        .connection()
        .execute(
            "UPDATE spool_entries SET state = 'acknowledged' WHERE bundle_name = ?1",
            [large.bundle_name()],
        )
        .expect("acknowledge under the hold");
    spool
        .remove(large.bundle_name())
        .expect("the acknowledgement's cleanup runs under the hold");
    assert!(!spool_dir.join(large.bundle_name()).exists());

    let resumed = gate.evaluate_spool(&spool, &store).expect("evaluate");
    assert!(resumed.admits_materialization());
    assert!(!resumed.is_degraded());
    let admitted = spool
        .materialize(&store, &mut gate, b"capture resumes")
        .expect("the drained spool admits the held gate again");
    assert!(spool_dir.join(admitted.bundle_name()).is_file());
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

    let first = spool
        .materialize(
            &store,
            &mut PressureGate::new(PressureLimits::new(u64::MAX, 0, 80)),
            &payload(1),
        )
        .expect("materialize");
    let second = spool
        .materialize(
            &store,
            &mut PressureGate::new(PressureLimits::new(u64::MAX, 0, 80)),
            &payload(2),
        )
        .expect("materialize");
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
