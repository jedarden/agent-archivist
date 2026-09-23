// SPDX-License-Identifier: Apache-2.0

//! Tests for the operator report documents: the read-only queries against
//! seeded state, the receipt-chain and bundle-correspondence checks, and
//! the composed documents' closed member sets.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use archivist_adapter_sdk::status::CoverageState;
use archivist_protocol::json::Value;
use archivist_protocol::vocabulary::Timestamp;
use rusqlite::params;

use super::{status_report, verification_report};
use crate::state::{LATEST_SCHEMA_VERSION, StateSnapshot, StateStore};

/// Render a composed document to canonical text for member assertions.
fn rendered(document: &Value) -> String {
    String::from_utf8(document.canonical_bytes()).expect("canonical bytes are utf-8")
}

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);
static NEXT_SEED: AtomicUsize = AtomicUsize::new(0);

const NOW: &str = "2026-09-13T12:00:00Z";
const EARLIER: &str = "2026-09-13T11:00:00Z";

/// A private directory removed on drop, so file-backed tests never share
/// state and never leave debris behind.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("archivist-report-{tag}-{}-{n}", std::process::id()));
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

/// A migrated file-backed state store plus its read-only snapshot: the
/// pair the `read_only` command class holds.
fn snapshot(dir: &TempDir) -> StateSnapshot {
    let mut store =
        StateStore::open(&dir.path().join(crate::state::STATE_DB_NAME)).expect("open state store");
    store.migrate().expect("migrate state store");
    StateSnapshot::open(&dir.path().join(crate::state::STATE_DB_NAME)).expect("open snapshot")
}

fn now() -> Timestamp {
    Timestamp::parse(NOW).expect("timestamp")
}

/// A distinct 36-character UUID-shape identifier for whichever table
/// needs one.
fn uid(tag: &str) -> String {
    let n = NEXT_SEED.fetch_add(1, Ordering::Relaxed);
    format!("{tag:0>8}-1111-4222-8333-{n:012x}")
}

/// A 128-character signature-shape filler (the receipts table's pin).
fn signature(seed: u64) -> String {
    format!("{seed:0128x}")
}

/// A 64-character digest-shape filler.
fn digest(seed: u64) -> String {
    format!("{seed:064x}")
}

/// A distinct 64-bit seed derived from arbitrary text, so fixture rows
/// never collide on the schema's unique (session, artifact) pairs.
fn seed_of(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Enroll one source with every CHECK-constrained column populated.
fn enroll(store: &StateStore, source_id: &str, lane: &str) {
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
                source_id,
                digest(seed_of(source_id)),
                digest(!seed_of(source_id)),
                lane,
                NOW,
            ],
        )
        .expect("insert source");
}

/// Insert one spool entry row with the given state and size.
fn spool_entry(store: &StateStore, entry_id: &str, state: &str, size_bytes: i64) {
    store
        .connection()
        .execute(
            "INSERT INTO spool_entries (spool_entry_id, bundle_name, state, envelope_digest,
                size_bytes, attempt_count, next_attempt_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?6)",
            params![
                entry_id,
                format!("{entry_id}.bundle"),
                state,
                digest(7),
                size_bytes,
                NOW
            ],
        )
        .expect("insert spool entry");
}

/// Insert the frozen request and receipt that acknowledge `entry_id`,
/// captured at `captured_at`.
fn acknowledge(store: &StateStore, entry_id: &str, captured_at: &str) {
    let request_id = uid("req");
    let conn = store.connection();
    conn.execute(
        "INSERT INTO frozen_requests (request_id, spool_entry_id, tenant_id, origin_client_id,
            uploader_client_id, occurrence_id, envelope_version, storage_profile,
            transport_encoding, canonical_digest, incoming_checksum, canonical_size,
            transport_size, source_at, captured_at, envelope_created_at, frozen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'v1', 'profile', NULL, ?7, 'sha256', 1, 1, NULL,
            ?8, ?9, ?9)",
        params![
            request_id,
            entry_id,
            uid("tenant"),
            uid("orig"),
            uid("upld"),
            digest(11),
            digest(13),
            captured_at,
            NOW,
        ],
    )
    .expect("insert frozen request");
    conn.execute(
        "INSERT INTO receipts (request_id, receipt_key_id, signature, receipt_digest,
            commit_ordinal, commit_time, signature_verified, received_at)
         VALUES (?1, 'receipt-key', ?2, ?3, 0, ?4, 1, ?4)",
        params![request_id, signature(17), digest(19), NOW],
    )
    .expect("insert receipt");
}

#[test]
fn status_on_an_empty_store_reports_zeroes_and_null() {
    let dir = TempDir::new("status-empty");
    let snapshot = snapshot(&dir);
    let report = status_report(&snapshot, &now()).expect("status report");
    assert_eq!(report.schema_version, LATEST_SCHEMA_VERSION);
    assert!(report.integrity_ok);
    assert_eq!(report.enrolled_sources, 0);
    assert_eq!(report.freshness_sources, 0);
    assert_eq!(report.backfill_sources, 0);
    assert_eq!(report.live_spool_bytes, 0);
    assert_eq!(report.last_capture_at, None);

    let document = report.to_document();
    let Value::Object(members) = &document else {
        panic!("document is an object");
    };
    let names: Vec<&str> = members.iter().map(|(name, _)| name).collect();
    // Objects serialize in canonical member order.
    assert_eq!(
        names,
        vec![
            "generated_at",
            "last_capture_at",
            "schema",
            "sources",
            "spool",
            "state",
        ]
    );
}

#[test]
fn status_counts_lanes_spool_and_freshest_acknowledged_capture() {
    let dir = TempDir::new("status-counts");
    let mut store =
        StateStore::open(&dir.path().join(crate::state::STATE_DB_NAME)).expect("open state store");
    store.migrate().expect("migrate state store");

    enroll(&store, &uid("src"), "freshness");
    enroll(&store, &uid("src"), "backfill");
    enroll(&store, &uid("src"), "backfill");

    let live_entry = uid("ent");
    spool_entry(&store, &live_entry, "materialized", 100);
    spool_entry(&store, &uid("ent"), "uploading", 20);
    // Acknowledged bytes leave the live sum.
    let done_entry = uid("ent");
    spool_entry(&store, &done_entry, "acknowledged", 5_000);
    acknowledge(&store, &done_entry, EARLIER);

    // A fresher acknowledged capture a later receipt carries.
    let fresher_entry = uid("ent");
    spool_entry(&store, &fresher_entry, "acknowledged", 30);
    acknowledge(&store, &fresher_entry, NOW);

    let snapshot =
        StateSnapshot::open(&dir.path().join(crate::state::STATE_DB_NAME)).expect("open snapshot");
    let report = status_report(&snapshot, &now()).expect("status report");
    assert_eq!(report.enrolled_sources, 3);
    assert_eq!(report.freshness_sources, 1);
    assert_eq!(report.backfill_sources, 2);
    assert_eq!(report.live_spool_bytes, 120);
    assert_eq!(report.last_capture_at.as_deref(), Some(NOW));

    let document = report.to_document();
    let text = rendered(&document);
    assert!(text.contains("\"schema\":\"archivist.cli-result/v1\""));
    assert!(text.contains("\"last_capture_at\":\"2026-09-13T12:00:00Z\""));
}

#[test]
fn verification_on_a_consistent_directory_reports_ok() {
    let dir = TempDir::new("verify-ok");
    let mut store =
        StateStore::open(&dir.path().join(crate::state::STATE_DB_NAME)).expect("open state store");
    store.migrate().expect("migrate state store");

    let live_entry = uid("ent");
    spool_entry(&store, &live_entry, "materialized", 64);
    let done_entry = uid("ent");
    spool_entry(&store, &done_entry, "acknowledged", 16);
    acknowledge(&store, &done_entry, EARLIER);

    let spool_dir = dir.path().join(crate::spool::SPOOL_DIR_NAME);
    std::fs::create_dir_all(&spool_dir).expect("create spool dir");
    std::fs::write(spool_dir.join(format!("{live_entry}.bundle")), b"payload").expect("bundle");

    let snapshot =
        StateSnapshot::open(&dir.path().join(crate::state::STATE_DB_NAME)).expect("open snapshot");
    let report = verification_report(&snapshot, dir.path(), &now()).expect("verification");
    assert!(report.verdict_ok(), "consistent state verifies ok");
    assert!(report.integrity.healthy());
    assert_eq!(report.live_rows_missing_bundles, 0);
    // The acknowledged bundle was already removed by cleanup: its absence
    // is the documented end state, not a finding.
    assert_eq!(report.acknowledged_entries_without_receipts, 0);
    assert_eq!(report.orphan_bundle_files, 0);
}

#[test]
fn verification_counts_missing_and_orphan_bundles_and_broken_receipts() {
    let dir = TempDir::new("verify-degraded");
    let mut store =
        StateStore::open(&dir.path().join(crate::state::STATE_DB_NAME)).expect("open state store");
    store.migrate().expect("migrate state store");

    // A live row whose bundle is gone: corruption.
    let missing_entry = uid("ent");
    spool_entry(&store, &missing_entry, "materialized", 64);
    // An acknowledged entry left with no receipt: a broken invariant.
    let unreceipted_entry = uid("ent");
    spool_entry(&store, &unreceipted_entry, "acknowledged", 16);

    let spool_dir = dir.path().join(crate::spool::SPOOL_DIR_NAME);
    std::fs::create_dir_all(&spool_dir).expect("create spool dir");
    // Crash debris: a complete bundle file no row names, plus a staging
    // file reconciliation removes, which is not a bundle.
    std::fs::write(spool_dir.join(format!("{}.bundle", uid("orph"))), b"debris")
        .expect("orphan bundle");
    std::fs::write(spool_dir.join("interrupted.staging"), b"partial").expect("staging file");

    let snapshot =
        StateSnapshot::open(&dir.path().join(crate::state::STATE_DB_NAME)).expect("open snapshot");
    let report = verification_report(&snapshot, dir.path(), &now()).expect("verification");
    assert!(!report.verdict_ok());
    assert!(!report.live_bundles_present);
    assert!(!report.acknowledged_receipted);
    assert_eq!(report.live_rows_missing_bundles, 1);
    assert_eq!(report.orphan_bundle_files, 1);
    assert_eq!(report.acknowledged_entries_without_receipts, 1);
    // Integrity itself is clean: the degradations are the two checks.
    assert!(report.integrity.healthy());

    let document = report.to_document();
    let text = rendered(&document);
    assert!(text.contains("\"verdict\":\"degraded\""));
    assert!(text.contains("\"live_rows_missing_bundles\":1"));
}

#[test]
fn verification_without_a_spool_directory_fails_live_bundles_closed() {
    let dir = TempDir::new("verify-no-spool");
    let mut store =
        StateStore::open(&dir.path().join(crate::state::STATE_DB_NAME)).expect("open state store");
    store.migrate().expect("migrate state store");
    spool_entry(&store, &uid("ent"), "materialized", 64);

    let snapshot =
        StateSnapshot::open(&dir.path().join(crate::state::STATE_DB_NAME)).expect("open snapshot");
    let report = verification_report(&snapshot, dir.path(), &now()).expect("verification");
    assert!(!report.verdict_ok());
    assert_eq!(report.live_rows_missing_bundles, 1);
    // Nothing on disk is no orphan: there is no debris to count.
    assert_eq!(report.orphan_bundle_files, 0);
}

#[test]
fn cycle_document_carries_the_namespace_and_the_round_figures() {
    let reconcile = crate::spool::ReconcileReport {
        orphan_bundles_indexed: 2,
        acknowledged_bundles_removed: 1,
        staging_files_removed: 3,
        unclassified_entries: 0,
        spool_rows_missing_bundles: 0,
    };
    let mut gate = crate::spool::pressure::PressureGate::new(
        crate::spool::pressure::PressureLimits::new(2_000, 500, 50),
    );
    let pressure = gate.evaluate(10, 1_000);
    let totals = crate::scheduler::CycleTotals {
        capacity_bytes: 1_024,
        drain_entries: 1,
        drain_bytes: 128,
        eligible_sources: 2,
        reserved_sources: 2,
        reserved_bytes: 512,
        reserved_chunks: 2,
        backfilled_sources: 1,
        backfill_bytes: 256,
        backfill_chunks: 1,
        planned_bytes: 768,
        short_reservations: 0,
        deferred_sources: 0,
    };
    let document = super::cycle_document(&reconcile, &pressure, &totals, &now());
    let text = rendered(&document);
    assert!(text.contains("\"schema\":\"archivist.cli-result/v1\""));
    assert!(text.contains("\"orphan_bundles_indexed\":2"));
    assert!(text.contains("\"admits_materialization\":true"));
    assert!(text.contains("\"spool_cap_bytes\":2000"));
    assert!(text.contains("\"planned_bytes\":768"));
    assert!(text.contains("\"short_reservations\":0"));
}

#[test]
fn inventory_document_prepends_the_namespace_member() {
    let report = crate::inventory::InventoryReport {
        generated_at: now(),
        overall: CoverageState::Absent,
        totals: crate::inventory::InventoryTotals::default(),
        statuses: Vec::new(),
        sources_without_scan: 0,
    };
    let document = super::inventory_document(&report);
    let text = rendered(&document);
    assert!(text.contains("\"schema\":\"archivist.cli-result/v1\""));
    assert!(text.contains("\"overall\":\"missing\""));
    assert!(text.contains("\"sources_without_scan\":0"));
}
