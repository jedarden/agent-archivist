// SPDX-License-Identifier: Apache-2.0

//! Tests for the source backlog inventory: the outstanding-bytes-and-events
//! arithmetic against seeded client state, the active/historical lane
//! split, freshness lag, retained classifications and coverage states, the
//! cursor-retention rule, and the bounded content-free status surface
//! (requirements SCH-002 and CAP-010).

use std::sync::atomic::{AtomicU64, Ordering};

use archivist_adapter_sdk::status::{
    AccountLabel, CoverageCounts, CoverageState, FreshnessLane, ScanClassification, SourceId,
    SourceScan,
};
use archivist_protocol::vocabulary::{AdapterId, Timestamp};
use rusqlite::params;

use crate::inventory::{CursorDecision, InventoryOptions, cursor_retention, inventory};
use crate::state::StateErrorKind;

const NOW: &str = "2026-09-13T12:00:00Z";
/// Ten minutes before `NOW`, as a literal: the lag fixtures stay readable
/// and independent of the conversion code under test.
const TEN_MINUTES_AGO: &str = "2026-09-13T11:50:00Z";
/// One minute before `NOW`.
const ONE_MINUTE_AGO: &str = "2026-09-13T11:59:00Z";

/// Distinct occurrence ids across the ranges one test inserts.
static NEXT_OCCURRENCE: AtomicU64 = AtomicU64::new(1);

/// A distinct 36-character lowercase UUID-shape source identifier.
fn sid(seed: u8) -> SourceId {
    SourceId::parse(&format!("{seed:08x}-1111-4222-8333-{seed:012x}")).expect("source id")
}

/// A distinct generation identifier (shape only has to satisfy the schema's
/// length rule, but keep it UUID-like for readability).
fn gid(seed: u8) -> String {
    format!("{seed:08x}-aaaa-7bbb-8ccc-{seed:012x}")
}

/// A distinct adapter identifier.
fn adapter(seed: u8) -> AdapterId {
    AdapterId::parse(&format!("adapter-{seed}")).expect("adapter id")
}

/// A distinct account label.
fn account(seed: u8) -> AccountLabel {
    AccountLabel::parse(&format!("account-{seed}")).expect("account label")
}

fn now() -> Timestamp {
    Timestamp::parse(NOW).expect("timestamp")
}

/// An `ok` scan for one source under one scope.
fn scan_ok(source: &SourceId, adapter_id: &AdapterId, label: &AccountLabel) -> SourceScan {
    SourceScan {
        source: source.clone(),
        adapter: adapter_id.clone(),
        account: label.clone(),
        complete_bytes: 0,
        complete_events: 0,
        incomplete_tail_bytes: 0,
        last_activity: None,
        active_in_window: false,
        classification: ScanClassification::Ok,
    }
}

fn migrated() -> crate::state::StateStore {
    let mut store = crate::state::StateStore::open_in_memory().expect("open in-memory");
    store.migrate().expect("migrate");
    store
}

/// Enroll one source with every CHECK-constrained column populated.
fn enroll(store: &crate::state::StateStore, source: &SourceId, lane: FreshnessLane) {
    // The unique (session_hash, artifact_hash) pair is derived from the
    // source id so several sources can share one store.
    let digest: String = source
        .as_str()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect();
    let mirrored: String = digest.chars().rev().collect();
    store
        .connection()
        .execute(
            "INSERT INTO sources (source_id, harness, upstream_session_id, id_source,
                session_hash, artifact_kind, adapter_id, adapter_projection_version,
                adapter_artifact_id, artifact_hash, freshness_lane, last_cursor,
                created_at, updated_at)
             VALUES (?1, 'claude', 'upstream-session', 'natural', ?2, 'transcript',
                'adapter-1', 'v1', 'artifact', ?3, ?4, NULL, ?5, ?5)",
            params![
                source.as_str(),
                format!("{digest}{digest}"),
                format!("{mirrored}{mirrored}"),
                lane.token(),
                NOW,
            ],
        )
        .expect("insert source");
}

fn generation(store: &crate::state::StateStore, source: &SourceId, seed: u8, state: &str) {
    store
        .connection()
        .execute(
            "INSERT INTO generations (generation_id, source_id, ordinal, state,
                detected_reason, tail_checksum, file_identity, detected_at)
             VALUES (?1, ?2, 1, ?3, 'first-observed', NULL, NULL, ?4)",
            params![gid(seed), source.as_str(), state, NOW],
        )
        .expect("insert generation");
}

fn captured_range(
    store: &crate::state::StateStore,
    generation_id: &str,
    kind: &str,
    end: u64,
    captured_at: &str,
) {
    let occurrence = NEXT_OCCURRENCE.fetch_add(1, Ordering::Relaxed);
    store
        .connection()
        .execute(
            "INSERT INTO ranges (occurrence_id, generation_id, range_kind, range_start,
                range_end, sequence, blob_digest, spool_entry_id, captured_at)
             VALUES (?1, ?2, ?3, 0, ?4, 0, ?5, NULL, ?6)",
            params![
                format!("{occurrence:064x}"),
                generation_id,
                kind,
                i64::try_from(end).expect("range end fits i64"),
                format!("{:064x}", 3),
                captured_at,
            ],
        )
        .expect("insert range");
}

/// Run the engine over `scans` with healthy capture.
fn run_pass(
    store: &crate::state::StateStore,
    scans: &[SourceScan],
) -> crate::inventory::InventoryReport {
    inventory(
        store.connection(),
        scans,
        &now(),
        &InventoryOptions::default(),
    )
    .expect("inventory pass")
}

#[test]
fn outstanding_is_the_complete_extent_minus_the_acknowledged_prefix() {
    let store = migrated();
    let source = sid(1);
    enroll(&store, &source, FreshnessLane::Freshness);
    generation(&store, &source, 1, "open");
    captured_range(&store, &gid(1), "bytes", 100, NOW);
    captured_range(&store, &gid(1), "events", 3, NOW);

    let mut observed = scan_ok(&source, &adapter(1), &account(1));
    observed.complete_bytes = 250;
    observed.complete_events = 5;
    observed.incomplete_tail_bytes = 17;

    let report = run_pass(&store, &[observed]);
    assert_eq!(report.statuses.len(), 1);
    let status = &report.statuses[0];
    // Active lane: the source is enrolled as freshness.
    assert_eq!(status.active_backlog_bytes, 150);
    assert_eq!(status.active_backlog_events, 2);
    assert_eq!(status.historical_backlog_bytes, 0);
    assert_eq!(status.coverage, CoverageState::Partial);
    // The pending tail is measured but never backlog.
    assert_eq!(report.totals.active_backlog_bytes, 150);
}

#[test]
fn acknowledged_extents_come_from_the_current_generation_only() {
    let store = migrated();
    let source = sid(2);
    enroll(&store, &source, FreshnessLane::Backfill);
    // Generation 1 captured 1_000 bytes, then the artifact was replaced.
    generation(&store, &source, 1, "closed");
    captured_range(&store, &gid(1), "bytes", 1_000, NOW);
    // Generation 2 restarted from zero and has captured 50 bytes.
    store
        .connection()
        .execute(
            "INSERT INTO generations (generation_id, source_id, ordinal, state,
                detected_reason, tail_checksum, file_identity, detected_at)
             VALUES (?1, ?2, 2, 'open', 'replaced', NULL, NULL, ?3)",
            params![gid(2), source.as_str(), NOW],
        )
        .expect("insert generation");
    captured_range(&store, &gid(2), "bytes", 50, NOW);

    let mut observed = scan_ok(&source, &adapter(1), &account(1));
    observed.complete_bytes = 200;
    let report = run_pass(&store, &[observed]);
    // The closed generation's 1_000 bytes must not offset the new one.
    assert_eq!(report.totals.historical_backlog_bytes, 150);
}

#[test]
fn backlog_splits_active_and_historical_by_lane() {
    let store = migrated();
    let fresh = sid(3);
    let historical = sid(4);
    enroll(&store, &fresh, FreshnessLane::Freshness);
    enroll(&store, &historical, FreshnessLane::Backfill);

    let mut fresh_scan = scan_ok(&fresh, &adapter(1), &account(1));
    fresh_scan.complete_bytes = 100;
    fresh_scan.complete_events = 2;
    // A backfill-lane source with a fresh-looking mtime keeps its lane:
    // the state designation wins for enrolled sources.
    let mut historical_scan = scan_ok(&historical, &adapter(1), &account(1));
    historical_scan.complete_bytes = 1_000;
    historical_scan.complete_events = 10;
    historical_scan.active_in_window = true;

    let report = run_pass(&store, &[fresh_scan, historical_scan]);
    assert_eq!(report.totals.active_backlog_bytes, 100);
    assert_eq!(report.totals.active_backlog_events, 2);
    assert_eq!(report.totals.historical_backlog_bytes, 1_000);
    assert_eq!(report.totals.historical_backlog_events, 10);
}

#[test]
fn unenrolled_sources_lane_by_observed_activity() {
    let store = migrated();
    let active = sid(5);
    let idle = sid(6);

    let mut active_scan = scan_ok(&active, &adapter(1), &account(1));
    active_scan.complete_bytes = 10;
    active_scan.active_in_window = true;
    let mut idle_scan = scan_ok(&idle, &adapter(1), &account(1));
    idle_scan.complete_bytes = 500;

    let report = run_pass(&store, &[active_scan, idle_scan]);
    assert_eq!(report.totals.active_backlog_bytes, 10);
    assert_eq!(report.totals.historical_backlog_bytes, 500);
}

#[test]
fn every_coverage_state_is_distinguishable_in_status() {
    let store = migrated();
    // One scope holding exactly one source in each CAP-010 state.
    let absent = sid(7);
    let unsupported = sid(8);
    let failed = sid(9);
    let partial = sid(10);
    let current = sid(11);
    let backfilled = sid(12);
    enroll(&store, &current, FreshnessLane::Freshness);
    enroll(&store, &backfilled, FreshnessLane::Backfill);

    let mut absent_scan = scan_ok(&absent, &adapter(1), &account(1));
    absent_scan.classification = ScanClassification::RootAbsent;
    let mut unsupported_scan = scan_ok(&unsupported, &adapter(1), &account(1));
    unsupported_scan.classification = ScanClassification::FingerprintUnsupported;
    let mut failed_scan = scan_ok(&failed, &adapter(1), &account(1));
    failed_scan.classification = ScanClassification::TransportUnreachable;
    let mut partial_scan = scan_ok(&partial, &adapter(1), &account(1));
    partial_scan.complete_bytes = 10;
    let current_scan = scan_ok(&current, &adapter(1), &account(1));
    let backfilled_scan = scan_ok(&backfilled, &adapter(1), &account(1));

    let report = run_pass(
        &store,
        &[
            absent_scan,
            unsupported_scan,
            failed_scan,
            partial_scan,
            current_scan,
            backfilled_scan,
        ],
    );
    assert_eq!(report.statuses.len(), 1);
    let status = &report.statuses[0];
    // A failure is the condition an operator must attend to first.
    assert_eq!(status.coverage, CoverageState::Failed);
    assert_eq!(status.sources.total(), 6);
    assert_eq!(status.sources.get(CoverageState::Absent), 1);
    assert_eq!(status.sources.get(CoverageState::Unsupported), 1);
    assert_eq!(status.sources.get(CoverageState::Failed), 1);
    assert_eq!(status.sources.get(CoverageState::Partial), 1);
    assert_eq!(status.sources.get(CoverageState::Current), 1);
    assert_eq!(status.sources.get(CoverageState::FullyBackfilled), 1);
    // The last classifications are retained per source, by class.
    assert_eq!(status.classifications.get(ScanClassification::Ok), 3);
    assert_eq!(
        status.classifications.get(ScanClassification::RootAbsent),
        1
    );
    assert_eq!(
        status
            .classifications
            .get(ScanClassification::FingerprintUnsupported),
        1
    );
    assert_eq!(
        status
            .classifications
            .get(ScanClassification::TransportUnreachable),
        1
    );

    // Each state is reachable as a whole scope, too.
    let single = |scan: SourceScan| {
        let report = run_pass(&store, &[scan]);
        report.statuses[0].coverage
    };
    let mut absent_only = scan_ok(&sid(20), &adapter(2), &account(2));
    absent_only.classification = ScanClassification::NoDatabase;
    assert_eq!(single(absent_only), CoverageState::Absent);
    let mut read_error = scan_ok(&sid(21), &adapter(2), &account(2));
    read_error.classification = ScanClassification::ReadError;
    assert_eq!(single(read_error), CoverageState::Failed);
}

#[test]
fn freshness_lag_ages_the_last_acknowledged_progress() {
    let store = migrated();
    let behind = sid(13);
    let caught_up = sid(14);
    enroll(&store, &behind, FreshnessLane::Backfill);
    enroll(&store, &caught_up, FreshnessLane::Backfill);
    generation(&store, &behind, 1, "open");
    generation(&store, &caught_up, 2, "open");
    // Last acknowledged progress ten minutes ago.
    captured_range(&store, &gid(1), "bytes", 10, TEN_MINUTES_AGO);

    let mut behind_scan = scan_ok(&behind, &adapter(1), &account(1));
    behind_scan.complete_bytes = 500;
    let caught_up_scan = scan_ok(&caught_up, &adapter(1), &account(1));

    let report = run_pass(&store, &[behind_scan, caught_up_scan]);
    assert_eq!(report.statuses.len(), 1);
    // The behind source's lag is the age of its last progress; the caught-up
    // one reports zero regardless of when it was last touched.
    assert_eq!(report.statuses[0].max_freshness_lag_seconds, 600);
    // Historical lane: 500 complete bytes minus the 10 already acknowledged.
    assert_eq!(report.totals.historical_backlog_bytes, 490);
}

#[test]
fn freshness_lag_uses_scan_activity_for_unenrolled_sources() {
    let store = migrated();
    let active = sid(15);
    let mut active_scan = scan_ok(&active, &adapter(1), &account(1));
    active_scan.complete_bytes = 10;
    active_scan.active_in_window = true;
    active_scan.last_activity = Some(Timestamp::parse(ONE_MINUTE_AGO).expect("timestamp"));

    let report = run_pass(&store, &[active_scan]);
    assert_eq!(report.statuses[0].max_freshness_lag_seconds, 60);
}

#[test]
fn degraded_capture_holds_the_cursor_and_keeps_the_backlog_visible() {
    // The decision itself: degraded capture never moves a cursor.
    assert_eq!(cursor_retention(100, 3, 250, 5, true), CursorDecision::Hold);
    // Healthy capture advances to the last complete boundary...
    assert_eq!(
        cursor_retention(100, 3, 250, 5, false),
        CursorDecision::Advance {
            bytes: 250,
            events: 5
        }
    );
    // ...never without new complete data...
    assert_eq!(
        cursor_retention(250, 5, 250, 5, false),
        CursorDecision::Hold
    );
    // ...and never backwards on either axis.
    assert_eq!(
        cursor_retention(300, 2, 250, 5, false),
        CursorDecision::Advance {
            bytes: 300,
            events: 5
        }
    );

    // The measurement itself is unaffected by degradation: the backlog and
    // its coverage state stay fully visible while capture holds.
    let store = migrated();
    let source = sid(16);
    enroll(&store, &source, FreshnessLane::Freshness);
    generation(&store, &source, 1, "open");
    captured_range(&store, &gid(1), "bytes", 100, NOW);
    let mut observed = scan_ok(&source, &adapter(1), &account(1));
    observed.complete_bytes = 250;
    observed.complete_events = 5;
    observed.incomplete_tail_bytes = 17;

    let degraded = inventory(
        store.connection(),
        &[observed],
        &now(),
        &InventoryOptions { degraded: true },
    )
    .expect("degraded pass");
    assert_eq!(degraded.totals.active_backlog_bytes, 150);
    assert_eq!(degraded.statuses[0].coverage, CoverageState::Partial);
    assert_eq!(degraded.statuses[0].active_backlog_bytes, 150);
}

#[test]
fn acknowledged_beyond_complete_is_a_reported_anomaly() {
    let store = migrated();
    let source = sid(17);
    enroll(&store, &source, FreshnessLane::Backfill);
    generation(&store, &source, 1, "open");
    captured_range(&store, &gid(1), "bytes", 500, NOW);

    let mut shrunken = scan_ok(&source, &adapter(1), &account(1));
    shrunken.complete_bytes = 250;

    let report = run_pass(&store, &[shrunken]);
    assert_eq!(report.statuses[0].coverage, CoverageState::Failed);
    // No invented backlog and no negative figures: saturating at zero.
    assert_eq!(report.totals.historical_backlog_bytes, 0);
}

#[test]
fn sources_without_a_scan_are_counted_not_guessed() {
    let store = migrated();
    let scanned = sid(18);
    let unscanned = sid(19);
    enroll(&store, &scanned, FreshnessLane::Freshness);
    enroll(&store, &unscanned, FreshnessLane::Freshness);
    generation(&store, &scanned, 1, "open");
    generation(&store, &unscanned, 2, "open");
    captured_range(&store, &gid(2), "bytes", 40, NOW);

    let report = run_pass(&store, &[scan_ok(&scanned, &adapter(1), &account(1))]);
    assert_eq!(report.sources_without_scan, 1);
    // The unmeasured source contributes no invented backlog...
    assert_eq!(report.totals.active_backlog_bytes, 0);
    // ...but its visibility gap keeps the overall state from reading
    // "current".
    assert_eq!(report.overall, CoverageState::Partial);
}

#[test]
fn report_json_is_bounded_and_content_free() {
    let store = migrated();
    let mut scans = Vec::new();
    // Fifty sources, real backlog, an unparseable-looking upstream
    // identifier shape nowhere projectable: status stays aggregate.
    for seed in 30..80u8 {
        let source = sid(seed);
        enroll(&store, &source, FreshnessLane::Backfill);
        let mut scan = scan_ok(&source, &adapter(1), &account(1));
        scan.complete_bytes = u64::from(seed) * 1_000_000;
        scan.complete_events = u64::from(seed);
        scans.push(scan);
    }

    let report = run_pass(&store, &scans);
    let rendered = String::from_utf8(report.to_json().canonical_bytes()).expect("utf-8");

    // Bounded: fifty sources with megabytes of backlog each still render a
    // document of fixed shape — the per-source detail never enters status.
    assert!(rendered.len() < 4_096, "report grew to {}", rendered.len());
    // Content-free: no source identifier, no path syntax, no per-source
    // figures.
    assert!(!rendered.contains(sid(30).as_str()));
    assert!(!rendered.contains('/'));
    // One status per scope, with every acceptance field present.
    assert_eq!(report.statuses.len(), 1);
    for key in [
        "account",
        "active_backlog_bytes",
        "active_backlog_events",
        "adapter",
        "classifications",
        "coverage",
        "coverage_sources",
        "historical_backlog_bytes",
        "historical_backlog_events",
        "max_freshness_lag_seconds",
    ] {
        assert!(rendered.contains(key), "missing status key {key}");
    }
}

#[test]
fn timestamp_arithmetic_matches_known_instants() {
    let epoch = Timestamp::parse("1970-01-01T00:00:00Z").expect("epoch");
    assert_eq!(super::epoch_seconds(&epoch), Some(0));
    let leap_day = Timestamp::parse("2024-02-29T12:00:00Z").expect("leap day");
    // 1970-01-01 → 2024-01-01 is 19723 days; February 29 is 59 days later
    // (54 years with 13 leap days, plus one leap day into the year itself).
    assert_eq!(
        super::epoch_seconds(&leap_day),
        Some(19_782 * 86_400 + 12 * 3_600)
    );
    let fractional = Timestamp::parse("1970-01-01T00:00:01.500Z").expect("fractional");
    assert_eq!(super::epoch_seconds(&fractional), Some(1));
    let leap_second = Timestamp::parse("1970-01-01T00:00:60Z").expect("leap second");
    assert_eq!(super::epoch_seconds(&leap_second), Some(60));
    let pre_epoch = Timestamp::parse("1969-12-31T23:59:59Z").expect("pre-epoch");
    assert_eq!(super::epoch_seconds(&pre_epoch), None);
    // Calendar-invalid text parses grammatically but has no instant.
    let impossible = Timestamp::parse("2026-02-30T00:00:00Z").expect("grammar-valid");
    assert_eq!(super::epoch_seconds(&impossible), None);
}

#[test]
fn unreadable_state_fails_content_free() {
    // A database without its migrations has no state schema: the pass must
    // refuse with the classified, content-free error surface.
    let store = crate::state::StateStore::open_in_memory().expect("open in-memory");
    let error = inventory(
        store.connection(),
        &[scan_ok(&sid(40), &adapter(1), &account(1))],
        &now(),
        &InventoryOptions::default(),
    )
    .expect_err("unreadable state");
    assert_eq!(error.kind(), StateErrorKind::Unavailable);
    // The rendered error names the failure class, never a path or value.
    let rendered = error.to_string();
    assert!(
        !rendered.contains('/'),
        "path material in error: {rendered}"
    );
}

#[test]
fn anomalies_are_part_of_the_per_source_record() {
    let store = migrated();
    let source = sid(41);
    enroll(&store, &source, FreshnessLane::Freshness);
    generation(&store, &source, 1, "open");
    captured_range(&store, &gid(1), "events", 9, NOW);

    let mut observed = scan_ok(&source, &adapter(1), &account(1));
    observed.complete_events = 4;

    let report = run_pass(&store, &[observed]);
    assert_eq!(report.statuses[0].coverage, CoverageState::Failed);
    // No invented backlog: the contradictory range is not counted.
    assert_eq!(report.totals.active_backlog_bytes, 0);
    // A fresh scan of a healthy source reports no anomaly and counts
    // acknowledged events.
    let healthy_source = sid(42);
    enroll(&store, &healthy_source, FreshnessLane::Freshness);
    generation(&store, &healthy_source, 2, "open");
    captured_range(&store, &gid(2), "events", 9, NOW);
    let mut healthy = scan_ok(&healthy_source, &adapter(1), &account(1));
    healthy.complete_events = 9;
    let report = run_pass(&store, &[healthy]);
    assert_eq!(report.statuses[0].coverage, CoverageState::Current);
    assert_eq!(report.totals.active_backlog_events, 0);
}

#[test]
fn coverage_counts_aggregate_across_scopes() {
    let store = migrated();
    let mut scans = Vec::new();
    let mut partial = scan_ok(&sid(50), &adapter(1), &account(1));
    partial.complete_bytes = 5;
    scans.push(partial);
    let mut caught_up = scan_ok(&sid(51), &adapter(1), &account(2));
    caught_up.active_in_window = true;
    scans.push(caught_up);

    let report = run_pass(&store, &scans);
    assert_eq!(report.statuses.len(), 2);
    assert_eq!(report.totals.sources.get(CoverageState::Partial), 1);
    assert_eq!(report.totals.sources.get(CoverageState::Current), 1);
    assert_eq!(report.overall, CoverageState::Partial);
    assert_eq!(report.statuses[1].coverage, CoverageState::Current);
    assert_eq!(CoverageCounts::default().total(), 0);
}
