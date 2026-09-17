// SPDX-License-Identifier: Apache-2.0

//! End-to-end acceptance for the bounded status exposure (requirements
//! CAP-010 and SCH-002; plan Section 6 client data flow step 2): the
//! client-core inventory measurements — complete outstanding bytes and
//! events per source, measured through the last complete record boundary
//! against the acknowledged client state — flowing into the adapter-sdk
//! bounded status types, proven over fixture state through the crate's
//! public API alone.
//!
//! Three properties:
//!
//! - **The mapping is real and exact.** One pass over seeded state
//!   (sources, generations, captured ranges) and adapter scans lands every
//!   measured figure in the right bounded slot of
//!   [`archivist_adapter_sdk::status::AdapterAccountStatus`]: active vs.
//!   historical backlog by lane, freshness lag from the last acknowledged
//!   progress, the retained classifications, and the aggregated coverage.
//! - **The exposure is bounded.** The rendered status grows with the number
//!   of adapter/account scopes, never with the number of sources or the
//!   length of their capture histories: a hundredfold more sources and
//!   fifteenfold more history rows leave each scope's document at the same
//!   key set and near-identical size.
//! - **The exposure is content-free.** Free-text identity material the
//!   state schema permits (path-shaped upstream identifiers, opaque
//!   cursors) never reaches the report JSON, its `Debug` rendering, or the
//!   classified error surface. The crate is log-free by construction (no
//!   logging dependency; see the dependency boundary in `lib.rs`), so these
//!   rendered surfaces are the whole diagnostic output one pass can
//!   produce.

use std::sync::atomic::{AtomicU64, Ordering};

use archivist_adapter_sdk::status::{
    AccountLabel, CoverageState, FreshnessLane, ScanClassification, SourceId, SourceScan,
};
use archivist_client_core::inventory::{
    CursorDecision, CursorPosition, InventoryOptions, InventoryReport, cursor_retention, inventory,
};
use archivist_client_core::state::{StateErrorKind, StateStore};
use archivist_protocol::json::Value;
use archivist_protocol::vocabulary::{AdapterId, Timestamp};
use rusqlite::params;

const NOW: &str = "2026-09-13T12:00:00Z";
/// Ten minutes before `NOW`, as a literal: the lag fixtures stay readable
/// and independent of the conversion code under test.
const TEN_MINUTES_AGO: &str = "2026-09-13T11:50:00Z";

/// The path-shaped upstream session identifier the state schema permits
/// (free text to 1,024 characters) and the exposure must never surface.
const HOSTILE_UPSTREAM: &str = "/home/operator/private/2026/transcripts/session-7f3a.jsonl";
/// The path-shaped adapter artifact identifier, likewise permitted by the
/// schema and forbidden to the status surface.
const HOSTILE_ARTIFACT: &str = "/var/lib/archivist/artifacts/9f2e/import.jsonl";
/// An opaque adapter cursor carrying path syntax.
const HOSTILE_CURSOR: &str = "opaque-cursor:/tmp/spool/cursor-abc?pos=42";

/// Distinct occurrence ids across the ranges one test inserts.
static NEXT_OCCURRENCE: AtomicU64 = AtomicU64::new(1);

/// A distinct 36-character lowercase UUID-shape source identifier.
fn sid(seed: u64) -> SourceId {
    SourceId::parse(&format!("{seed:08x}-1111-4222-8333-{seed:012x}")).expect("source id")
}

/// A distinct generation identifier (shape only has to satisfy the schema's
/// length rule, but keep it UUID-like for readability).
fn gid(seed: u64) -> String {
    format!("{seed:08x}-aaaa-7bbb-8ccc-{seed:012x}")
}

/// A distinct adapter identifier.
fn adapter(seed: u64) -> AdapterId {
    AdapterId::parse(&format!("adapter-{seed}")).expect("adapter id")
}

/// A distinct account label.
fn account(seed: u64) -> AccountLabel {
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

fn migrated() -> StateStore {
    let mut store = StateStore::open_in_memory().expect("open in-memory");
    store.migrate().expect("migrate");
    store
}

/// Enroll one source with every CHECK-constrained column populated. The
/// unique (`session_hash`, `artifact_hash`) pair is derived from the source
/// id so several sources can share one store; the free-text identity columns
/// carry the hostile path-shaped material the schema permits, which no
/// exposed surface may ever repeat.
fn enroll(store: &StateStore, source: &SourceId, lane: FreshnessLane) {
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
             VALUES (?1, 'claude', ?2, 'natural', ?3, 'transcript',
                'adapter-1', 'v1', ?4, ?5, ?6, ?7, ?8, ?8)",
            params![
                source.as_str(),
                HOSTILE_UPSTREAM,
                format!("{digest}{digest}"),
                HOSTILE_ARTIFACT,
                format!("{mirrored}{mirrored}"),
                lane.token(),
                HOSTILE_CURSOR,
                NOW,
            ],
        )
        .expect("insert source");
}

fn generation(store: &StateStore, source: &SourceId, seed: u64, state: &str) {
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
    store: &StateStore,
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

/// `count` zero-length history rows on one generation: the capture trail a
/// long history leaves behind, without changing the acknowledged extent.
fn history_rows(store: &StateStore, generation_id: &str, count: u64) {
    for _ in 0..count {
        captured_range(store, generation_id, "bytes", 0, NOW);
    }
}

/// Run the engine over `scans` with healthy capture.
fn run_pass(store: &StateStore, scans: &[SourceScan]) -> InventoryReport {
    inventory(
        store.connection(),
        scans,
        &now(),
        &InventoryOptions::default(),
    )
    .expect("inventory pass")
}

/// The canonical JSON of one value, as text.
fn rendered(value: &Value) -> String {
    String::from_utf8(value.canonical_bytes()).expect("utf-8")
}

/// The rendered key set of each status object in a report, in scope order.
fn status_key_sets(report: &InventoryReport) -> Vec<Vec<String>> {
    let Value::Object(object) = report.to_json() else {
        panic!("report renders an object");
    };
    let Value::Array(statuses) = object.get("statuses").expect("statuses member") else {
        panic!("statuses renders an array");
    };
    statuses
        .iter()
        .map(|status| match status {
            Value::Object(object) => object.iter().map(|(key, _)| key.to_owned()).collect(),
            _ => panic!("each status renders an object"),
        })
        .collect()
}

#[test]
fn measurements_flow_into_bounded_status_end_to_end() {
    let store = migrated();

    // Scope (adapter-1, account-1): a freshness-lane source with backlog and
    // a pending tail, a backfill-lane source whose last acknowledged
    // progress is ten minutes old, and a source the pass could not read.
    let fresh = sid(1);
    enroll(&store, &fresh, FreshnessLane::Freshness);
    generation(&store, &fresh, 1, "open");
    captured_range(&store, &gid(1), "bytes", 100, NOW);
    captured_range(&store, &gid(1), "events", 3, NOW);

    let historical = sid(2);
    enroll(&store, &historical, FreshnessLane::Backfill);
    generation(&store, &historical, 2, "open");
    captured_range(&store, &gid(2), "bytes", 10, TEN_MINUTES_AGO);

    let unreadable = sid(3);

    // Scope (adapter-2, account-2): one caught-up active source.
    let caught_up = sid(4);

    let mut fresh_scan = scan_ok(&fresh, &adapter(1), &account(1));
    fresh_scan.complete_bytes = 250;
    fresh_scan.complete_events = 5;
    fresh_scan.incomplete_tail_bytes = 17;
    let mut historical_scan = scan_ok(&historical, &adapter(1), &account(1));
    historical_scan.complete_bytes = 1_000;
    historical_scan.complete_events = 10;
    let mut failed_scan = scan_ok(&unreadable, &adapter(1), &account(1));
    failed_scan.classification = ScanClassification::TransportUnreachable;
    let mut caught_up_scan = scan_ok(&caught_up, &adapter(2), &account(2));
    caught_up_scan.active_in_window = true;

    let report = run_pass(
        &store,
        &[fresh_scan, historical_scan, failed_scan, caught_up_scan],
    );

    // One status per scope, not per source.
    assert_eq!(report.statuses.len(), 2);

    let busy = &report.statuses[0];
    assert_eq!(busy.adapter, adapter(1));
    assert_eq!(busy.account, account(1));
    // Active backlog: complete extent minus the acknowledged prefix, with
    // the pending tail excluded (plan EC-01).
    assert_eq!(busy.active_backlog_bytes, 150);
    assert_eq!(busy.active_backlog_events, 2);
    // Historical backlog: the backfill source's unacknowledged extent.
    assert_eq!(busy.historical_backlog_bytes, 990);
    assert_eq!(busy.historical_backlog_events, 10);
    // Freshness lag: the age of the historical source's last acknowledged
    // progress; the freshness source's basis is its own last capture, so
    // it reports no lag.
    assert_eq!(busy.max_freshness_lag_seconds, 600);
    // Coverage aggregates per source, and a failure outranks everything:
    // one partial freshness source, one partial backfill source, one
    // transport failure.
    assert_eq!(busy.coverage, CoverageState::Failed);
    assert_eq!(busy.sources.total(), 3);
    assert_eq!(busy.sources.get(CoverageState::Partial), 2);
    assert_eq!(busy.sources.get(CoverageState::Failed), 1);
    // The last classifications are retained, by class.
    assert_eq!(busy.classifications.get(ScanClassification::Ok), 2);
    assert_eq!(
        busy.classifications
            .get(ScanClassification::TransportUnreachable),
        1
    );

    let quiet = &report.statuses[1];
    assert_eq!(quiet.coverage, CoverageState::Current);
    assert_eq!(quiet.active_backlog_bytes, 0);
    assert_eq!(quiet.historical_backlog_bytes, 0);
    assert_eq!(quiet.max_freshness_lag_seconds, 0);

    // Fleet totals fold the scopes, and the failure holds the overall
    // state.
    assert_eq!(report.totals.active_backlog_bytes, 150);
    assert_eq!(report.totals.historical_backlog_bytes, 990);
    assert_eq!(report.overall, CoverageState::Failed);
    // The same figures render for a consumer of the report JSON.
    let text = rendered(&report.to_json());
    assert!(text.contains("\"active_backlog_bytes\":150"), "{text}");
    assert!(text.contains("\"historical_backlog_bytes\":990"), "{text}");
}

#[test]
fn cursors_are_retained_in_front_of_uncaptured_ranges() {
    // The decision rule, through the public surface: healthy capture
    // advances to the last complete boundary...
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
    // ...never backwards on either axis...
    assert_eq!(
        cursor_retention(300, 2, 250, 5, false),
        CursorDecision::Advance {
            bytes: 300,
            events: 5
        }
    );
    // ...and never at all while capture is degraded (plan EC-11): the
    // cursor stays retained in front of the uncaptured range.
    assert_eq!(cursor_retention(100, 3, 250, 5, true), CursorDecision::Hold);

    // The retained position and the uncaptured extent partition the
    // complete boundary: nothing is skipped, nothing is counted twice.
    let cursor = CursorPosition {
        retained_bytes: 100,
        retained_events: 3,
        uncaptured_bytes: 150,
        uncaptured_events: 2,
    };
    assert!(cursor.has_uncaptured());
    assert_eq!(cursor.retained_bytes + cursor.uncaptured_bytes, 250);
    assert_eq!(cursor.retained_events + cursor.uncaptured_events, 5);

    // Degraded capture changes the cursor decision, never the visibility of
    // the backlog: the cursor is retained at the acknowledged byte prefix,
    // and the whole unacknowledged extent stays visible as backlog.
    let store = migrated();
    let fresh = sid(10);
    enroll(&store, &fresh, FreshnessLane::Freshness);
    generation(&store, &fresh, 10, "open");
    captured_range(&store, &gid(10), "bytes", 100, NOW);
    let mut scan = scan_ok(&fresh, &adapter(1), &account(1));
    scan.complete_bytes = 250;
    scan.complete_events = 5;

    let degraded = inventory(
        store.connection(),
        &[scan],
        &now(),
        &InventoryOptions { degraded: true },
    )
    .expect("degraded pass");
    assert_eq!(degraded.statuses[0].active_backlog_bytes, 150);
    assert_eq!(degraded.statuses[0].active_backlog_events, 5);
    assert_eq!(degraded.statuses[0].coverage, CoverageState::Partial);
}

#[test]
fn status_stays_bounded_across_many_sources_and_long_histories() {
    // Three scopes; the large fixture holds sixty sources each — every one
    // enrolled, with thirty captured-range history rows behind it — where
    // the small fixture holds one source each with two rows. The per-scope
    // status document must not be able to tell the difference beyond count
    // digits.
    fn build(sources_per_scope: u64, rows_per_source: u64) -> InventoryReport {
        let store = migrated();
        let mut scans = Vec::new();
        for scope in 1..=3u64 {
            for index in 0..sources_per_scope {
                let seed = scope * 1_000 + index;
                let source = sid(seed);
                enroll(&store, &source, FreshnessLane::Backfill);
                generation(&store, &source, seed, "open");
                history_rows(&store, &gid(seed), rows_per_source);
                let mut scan = scan_ok(&source, &adapter(scope), &account(scope));
                scan.complete_bytes = 1_000_000;
                scan.complete_events = 100;
                scans.push(scan);
            }
        }
        run_pass(&store, &scans)
    }
    let large = build(60, 30);
    let small = build(1, 2);

    // The document grows with scopes, never with sources: three statuses in
    // both, whatever the source count behind them.
    assert_eq!(large.statuses.len(), 3);
    assert_eq!(small.statuses.len(), 3);

    // Identical key sets at every scope: no per-source detail can enter.
    assert_eq!(status_key_sets(&large), status_key_sets(&small));

    // Each scope document is small, and the hundredfold source and
    // fifteenfold history growth moved it by digit noise only.
    for scope in 0..3 {
        let large_text = rendered(&large.statuses[scope].to_json());
        let small_text = rendered(&small.statuses[scope].to_json());
        assert!(
            large_text.len() < 2_048,
            "scope grew to {}",
            large_text.len()
        );
        assert!(
            large_text.len() < small_text.len() + 64,
            "scope document grew with its sources: {large_text} vs {small_text}"
        );
    }

    // The whole report — every scope, the totals, the coverage state —
    // stays small too.
    let report_text = rendered(&large.to_json());
    assert!(
        report_text.len() < 8_192,
        "report grew to {}",
        report_text.len()
    );
    // No per-source figure survives aggregation: the backlog sums, not the
    // per-source extents.
    assert!(
        !report_text.contains("1000000"),
        "per-source extent leaked into the report: {report_text}"
    );
}

#[test]
fn no_path_or_content_reaches_the_exposed_surfaces() {
    let store = migrated();
    // Both scopes' sources carry the hostile free text the schema permits
    // (see [`enroll`]); one source also fails the pass with a coverage
    // classification of its own.
    let first = sid(20);
    enroll(&store, &first, FreshnessLane::Freshness);
    generation(&store, &first, 20, "open");
    captured_range(&store, &gid(20), "bytes", 100, NOW);
    let second = sid(21);
    enroll(&store, &second, FreshnessLane::Backfill);

    let mut with_backlog = scan_ok(&first, &adapter(1), &account(1));
    with_backlog.complete_bytes = 250;
    let mut root_absent = scan_ok(&second, &adapter(2), &account(2));
    root_absent.classification = ScanClassification::RootAbsent;

    let report = run_pass(&store, &[with_backlog, root_absent]);
    assert_eq!(report.statuses.len(), 2);

    // Every rendered surface — the report JSON, its Debug form, and the
    // totals form — is free of path syntax, of the planted identity
    // material, and of the source identifiers themselves.
    let planted = [
        HOSTILE_UPSTREAM,
        HOSTILE_ARTIFACT,
        HOSTILE_CURSOR,
        "session-7f3a",
        "9f2e",
        "cursor-abc",
        "operator",
        "transcripts",
        first.as_str(),
        second.as_str(),
    ];
    let surfaces = [
        rendered(&report.to_json()),
        format!("{report:?}"),
        rendered(&report.totals.to_json()),
    ];
    for surface in &surfaces {
        assert!(!surface.contains('/'), "path syntax in surface: {surface}");
        for fragment in &planted {
            assert!(
                !surface.contains(fragment),
                "planted material {fragment:?} in surface: {surface}"
            );
        }
    }

    // The error surface is classified and content-free too: a pass against
    // a database without its state schema refuses without naming anything.
    let unmigrated = StateStore::open_in_memory().expect("open in-memory");
    let error = inventory(
        unmigrated.connection(),
        &[scan_ok(&sid(22), &adapter(1), &account(1))],
        &now(),
        &InventoryOptions::default(),
    )
    .expect_err("unreadable state");
    assert_eq!(error.kind(), StateErrorKind::Unavailable);
    let rendered_error = error.to_string();
    assert!(
        !rendered_error.contains('/'),
        "path material in error: {rendered_error}"
    );
    for fragment in &planted {
        assert!(
            !rendered_error.contains(fragment),
            "planted material {fragment:?} in error: {rendered_error}"
        );
    }
}
