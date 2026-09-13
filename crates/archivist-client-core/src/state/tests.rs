// SPDX-License-Identifier: Apache-2.0

//! Tests for the client state schema: migration application and reversal,
//! the automated integrity checks, constraint enforcement, and the rule
//! that diagnostics stay content-free.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use archivist_protocol::vocabulary::SafeMessage;
use rusqlite::Connection;

use super::migrations::{EXPECTED_INDEXES, EXPECTED_TABLES, MIGRATIONS, Migration};
use super::{IntegrityReport, LATEST_SCHEMA_VERSION, StateError, StateErrorKind, StateStore};

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

/// A private directory removed on drop, so file-backed tests never share
/// state and never leave debris behind.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("archivist-state-{tag}-{}-{n}", std::process::id()));
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

/// A 36-character lowercase UUID-shaped identifier, distinct per seed.
fn uuid_like(seed: u8) -> String {
    format!("{seed:08x}-1111-4222-8333-{seed:012x}")
}

/// A 64-character lowercase hex digest, distinct per seed.
fn hex64(seed: u8) -> String {
    format!("{seed:064x}")
}

const TS: &str = "2026-09-13T00:00:00Z";

fn migrated_in_memory() -> StateStore {
    let mut store = StateStore::open_in_memory().expect("open in-memory");
    store.migrate().expect("migrate");
    store
}

fn object_count(store: &StateStore, kind: &str, name: &str) -> i64 {
    store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
            rusqlite::params![kind, name],
            |row| row.get(0),
        )
        .expect("sqlite_master query")
}

// --- Migration list sanity -------------------------------------------------

#[test]
fn migration_list_is_contiguous_unique_and_reversible() {
    assert_eq!(LATEST_SCHEMA_VERSION, 8);
    assert_eq!(MIGRATIONS.len(), 8);
    for (expected, step) in MIGRATIONS.iter().enumerate() {
        let expected_version = i64::try_from(expected).expect("index fits i64") + 1;
        assert_eq!(step.version, expected_version, "gap at index {expected}");
        assert!(!step.name.is_empty());
        assert!(
            step.down.is_some(),
            "migration {} must record reverse SQL or consciously flip this test",
            step.name
        );
    }
    let names: Vec<_> = MIGRATIONS.iter().map(|step| step.name).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(names.len(), sorted.len(), "migration names collide");
}

#[test]
fn expected_object_lists_cover_every_migration() {
    // The expected-object scan must be able to prove the full schema: every
    // index any migration creates is listed by name.
    for index in EXPECTED_INDEXES {
        assert!(
            MIGRATIONS.iter().any(|step| step.up.contains(index)),
            "expected index {index} is created by no migration"
        );
    }
    for table in EXPECTED_TABLES {
        assert!(
            *table == "schema_migrations" || MIGRATIONS.iter().any(|step| step.up.contains(table)),
            "expected table {table} is created by no migration"
        );
    }
}

// --- Applying ---------------------------------------------------------------

#[test]
fn migrate_fresh_reaches_latest_with_expected_objects() {
    let mut store = migrated_in_memory();
    assert_eq!(
        store.schema_version().expect("version"),
        LATEST_SCHEMA_VERSION
    );

    for table in EXPECTED_TABLES {
        assert_eq!(object_count(&store, "table", table), 1, "table {table}");
    }
    for index in EXPECTED_INDEXES {
        assert_eq!(object_count(&store, "index", index), 1, "index {index}");
    }

    let history: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("history count");
    assert_eq!(history, LATEST_SCHEMA_VERSION);
}

#[test]
fn migrate_is_idempotent() {
    let mut store = migrated_in_memory();
    store.migrate().expect("second migrate");
    assert_eq!(
        store.schema_version().expect("version"),
        LATEST_SCHEMA_VERSION
    );
    let history: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("history count");
    assert_eq!(history, LATEST_SCHEMA_VERSION, "no duplicate history rows");
}

#[test]
fn migrate_records_each_step_name() {
    let store = migrated_in_memory();
    for step in MIGRATIONS {
        let name: String = store
            .connection()
            .query_row(
                "SELECT name FROM schema_migrations WHERE version = ?1",
                rusqlite::params![step.version],
                |row| row.get(0),
            )
            .expect("history row");
        assert_eq!(name, step.name);
    }
}

#[test]
fn file_database_runs_in_wal_mode() {
    let dir = TempDir::new("wal");
    let mut store = StateStore::open(&dir.path().join("state.db")).expect("open file db");
    store.migrate().expect("migrate");
    let mode: String = store
        .connection()
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    assert_eq!(mode, "wal");
}

#[test]
fn foreign_keys_are_configured_on_open() {
    let store = migrated_in_memory();
    let enabled: i64 = store
        .connection()
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .expect("foreign_keys pragma");
    assert_eq!(enabled, 1);
}

#[test]
fn migrate_rejects_out_of_range_and_downgrade_targets() {
    let mut store = migrated_in_memory();
    for target in [-1, LATEST_SCHEMA_VERSION + 1, i64::MAX] {
        let error = store
            .migrate_to(target)
            .expect_err("migrate_to must refuse the target");
        assert_eq!(error.kind(), StateErrorKind::VersionOutOfBounds);
    }
    let below = store
        .migrate_to(3)
        .expect_err("migrate_to never moves down");
    assert_eq!(below.kind(), StateErrorKind::VersionOutOfBounds);
    assert_eq!(
        store.schema_version().expect("version"),
        LATEST_SCHEMA_VERSION
    );
}

// --- Reversing --------------------------------------------------------------

#[test]
fn revert_one_steps_down_a_single_migration() {
    let mut store = migrated_in_memory();
    let at = store.revert_one().expect("revert one");
    assert_eq!(at, LATEST_SCHEMA_VERSION - 1);
    assert_eq!(object_count(&store, "table", "adapter_health"), 0);
    assert_eq!(object_count(&store, "table", "receipts"), 1);
    assert_eq!(
        store.schema_version().expect("version"),
        LATEST_SCHEMA_VERSION - 1
    );
}

#[test]
fn full_revert_round_trip_restores_the_schema() {
    let mut store = migrated_in_memory();
    store.revert_to(0).expect("revert to empty");
    assert_eq!(store.schema_version().expect("version"), 0);
    for table in EXPECTED_TABLES {
        if *table == "schema_migrations" {
            continue;
        }
        assert_eq!(object_count(&store, "table", table), 0, "table {table}");
    }
    // The history table survives empty: the record of the machinery is not
    // itself a numbered migration.
    let history: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("history count");
    assert_eq!(history, 0);

    store.migrate().expect("migrate again");
    let report = store.integrity().expect("integrity");
    assert!(report.healthy(), "{report:?}");
}

#[test]
fn revert_to_requires_a_reachable_target() {
    let mut store = migrated_in_memory();
    for target in [-1, LATEST_SCHEMA_VERSION + 1] {
        let error = store
            .revert_to(target)
            .expect_err("revert_to must refuse the target");
        assert_eq!(error.kind(), StateErrorKind::VersionOutOfBounds);
    }
    store.revert_to(3).expect("revert to 3");
    let above = store.revert_to(5).expect_err("revert_to never migrates up");
    assert_eq!(above.kind(), StateErrorKind::VersionOutOfBounds);
    assert_eq!(store.schema_version().expect("version"), 3);
}

#[test]
fn irreversible_step_is_refused_without_touching_the_schema() {
    let mut store = migrated_in_memory();
    store.revert_to(1).expect("revert to first migration");
    let fabricated = Migration {
        version: 2,
        name: "test-irreversible",
        up: "CREATE TABLE test_irreversible (x INTEGER);",
        down: None,
    };
    let mut bare = Connection::open_in_memory().expect("connection");
    // The runner records history; the bare fixture needs the same table for
    // the fabricated step to be recorded like any other.
    bare.execute_batch(
        "CREATE TABLE schema_migrations (
             version INTEGER PRIMARY KEY NOT NULL,
             name TEXT NOT NULL CHECK (name <> ''),
             applied_at TEXT NOT NULL DEFAULT
                 (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
         );",
    )
    .expect("history fixture");
    super::apply_migration(&mut bare, &fabricated).expect("apply fabricated");
    let error = super::revert_migration(&mut bare, &fabricated)
        .expect_err("reverting an irreversible step must fail");
    assert_eq!(error.kind(), StateErrorKind::IrreversibleMigration);
    assert_eq!(error.migration(), Some(("test-irreversible", 2)));
    let still_there: i64 = bare
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'test_irreversible'",
            [],
            |row| row.get(0),
        )
        .expect("table survives refused revert");
    assert_eq!(still_there, 1);
    // The store itself still reports every current step as reversible.
    while store.schema_version().expect("version") > 0 {
        store.revert_one().expect("revert remains possible");
    }
}

// --- Constraints ------------------------------------------------------------

#[test]
fn foreign_keys_are_enforced() {
    let store = migrated_in_memory();
    let error = store
        .connection()
        .execute(
            "INSERT INTO generations (
                 generation_id, source_id, ordinal, state, detected_reason,
                 tail_checksum, detected_at
             ) VALUES (?1, ?2, 1, 'open', 'first-observed', NULL, ?3)",
            rusqlite::params![uuid_like(1), uuid_like(2), TS],
        )
        .expect_err("orphan generation must be refused");
    assert!(
        matches!(error, rusqlite::Error::SqliteFailure(..)),
        "expected an integrity failure, got {error:?}"
    );
}

#[test]
fn closed_check_constraints_reject_invalid_values() {
    let store = migrated_in_memory();
    let conn = store.connection();
    let source = format!(
        "INSERT INTO sources (source_id, harness, upstream_session_id,
             id_source, session_hash, artifact_kind, adapter_id,
             adapter_projection_version, adapter_artifact_id, artifact_hash,
             freshness_lane, last_cursor, created_at, updated_at)
         VALUES ('{id}', 'claude-code', 'session-a', 'natural', '{h}',
                 'jsonl', 'claude', 'v1', 'artifact-a', '{a}',
                 'freshness', NULL, '{TS}', '{TS}')",
        id = uuid_like(1),
        h = hex64(1),
        a = hex64(2)
    );
    conn.execute(&source, []).expect("valid source insert");

    let bad_lane = source.replace("'freshness'", "'urgent'");
    assert!(conn.execute(&bad_lane, []).is_err(), "lane is closed enum");
    let bad_hash = source.replace(&hex64(1), "not-a-digest");
    assert!(conn.execute(&bad_hash, []).is_err(), "hash shape is pinned");
    let long_session = source.replace("'session-a'", &"x".repeat(1_025));
    assert!(
        conn.execute(&long_session, []).is_err(),
        "upstream id is bounded at 1024"
    );
}

#[test]
fn bundle_name_cannot_become_a_path() {
    let store = migrated_in_memory();
    let conn = store.connection();
    let insert = |name: &str| {
        conn.execute(
            "INSERT INTO spool_entries (
                 spool_entry_id, bundle_name, state, envelope_digest,
                 size_bytes, created_at, updated_at)
             VALUES (?1, ?2, 'materialized', ?3, 10, ?4, ?4)",
            rusqlite::params![uuid_like(9), name, hex64(9), TS],
        )
    };
    assert!(
        insert("bundle-0001.bundle").is_ok(),
        "plain file name is valid"
    );
    assert!(insert("nested/bundle.bundle").is_err(), "slash refused");
    assert!(
        insert("escape\\bundle.bundle").is_err(),
        "backslash refused"
    );
    assert!(insert("").is_err(), "empty refused");
}

// --- The full data path ------------------------------------------------------

/// Insert one valid row into every table, chained through the foreign keys,
/// then read values back. Proves the schema accepts the real shape of the
/// data the engine will write.
fn populate_full_chain(store: &StateStore) {
    let conn = store.connection();
    conn.execute(
        "INSERT INTO sources (
             source_id, harness, upstream_session_id, id_source, session_hash,
             artifact_kind, adapter_id, adapter_projection_version,
             adapter_artifact_id, artifact_hash, freshness_lane, last_cursor,
             created_at, updated_at)
         VALUES (?1, 'claude-code', 'session-a', 'natural', ?2, 'jsonl',
                 'claude', 'v1', 'artifact-a', ?3, 'freshness', 'cursor-0',
                 ?4, ?4)",
        rusqlite::params![uuid_like(1), hex64(1), hex64(2), TS],
    )
    .expect("source");
    conn.execute(
        "INSERT INTO generations (
             generation_id, source_id, ordinal, state, detected_reason,
             tail_checksum, detected_at)
         VALUES (?1, ?2, 1, 'open', 'first-observed', ?3, ?4)",
        rusqlite::params![uuid_like(2), uuid_like(1), hex64(3), TS],
    )
    .expect("generation");
    conn.execute(
        "INSERT INTO spool_entries (
             spool_entry_id, bundle_name, state, envelope_digest, size_bytes,
             created_at, updated_at)
         VALUES (?1, 'bundle-0001.bundle', 'materialized', ?2, 4096, ?3, ?3)",
        rusqlite::params![uuid_like(3), hex64(4), TS],
    )
    .expect("spool entry");
    conn.execute(
        "INSERT INTO frozen_requests (
             request_id, spool_entry_id, tenant_id, origin_client_id,
             uploader_client_id, occurrence_id, envelope_version,
             storage_profile, transport_encoding, canonical_digest,
             incoming_checksum, canonical_size, transport_size, source_at,
             captured_at, envelope_created_at, frozen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'envelope-v1', 'zstd-v1', 'identity',
                 ?7, 'sha256-raw', 1000, 800, ?8, ?8, ?8, ?8)",
        rusqlite::params![
            uuid_like(4),
            uuid_like(3),
            uuid_like(5),
            uuid_like(6),
            uuid_like(7),
            hex64(5),
            hex64(6),
            TS
        ],
    )
    .expect("frozen request");
    conn.execute(
        "INSERT INTO ranges (
             occurrence_id, generation_id, range_kind, range_start, range_end,
             sequence, blob_digest, spool_entry_id, captured_at)
         VALUES (?1, ?2, 'bytes', 0, 999, 0, ?3, ?4, ?5)",
        rusqlite::params![hex64(5), uuid_like(2), hex64(7), uuid_like(3), TS],
    )
    .expect("range");
    conn.execute(
        "INSERT INTO upload_attestations (
             attestation_id, tenant_id, occurrence_id, origin_client_id,
             uploader_client_id, request_id, relation, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'direct', ?7)",
        rusqlite::params![
            hex64(8),
            uuid_like(5),
            hex64(5),
            uuid_like(6),
            uuid_like(7),
            uuid_like(4),
            TS
        ],
    )
    .expect("attestation");
    conn.execute(
        "INSERT INTO receipts (
             request_id, receipt_key_id, signature, receipt_digest,
             commit_ordinal, commit_time, signature_verified, received_at)
         VALUES (?1, 'rk-2026-36', ?2, ?3, 1, ?4, 1, ?4)",
        rusqlite::params![uuid_like(4), "ab".repeat(64), hex64(9), TS],
    )
    .expect("receipt");
    conn.execute(
        "INSERT INTO adapter_health (adapter_id) VALUES ('claude')",
        [],
    )
    .expect("adapter health");
}

#[test]
fn schema_accepts_the_full_engine_data_path() {
    let store = migrated_in_memory();
    populate_full_chain(&store);
    let conn = store.connection();

    let state: String = conn
        .query_row(
            "SELECT state FROM spool_entries WHERE spool_entry_id = ?1",
            rusqlite::params![uuid_like(3)],
            |row| row.get(0),
        )
        .expect("spool read");
    assert_eq!(state, "materialized");

    let defaults: (String, i64) = conn
        .query_row(
            "SELECT health_state, consecutive_failures FROM adapter_health
             WHERE adapter_id = 'claude'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("adapter defaults read");
    assert_eq!(defaults, ("healthy".into(), 0));

    let attempt_default: i64 = conn
        .query_row(
            "SELECT attempt_count FROM spool_entries WHERE spool_entry_id = ?1",
            rusqlite::params![uuid_like(3)],
            |row| row.get(0),
        )
        .expect("attempt default read");
    assert_eq!(attempt_default, 0);

    let receipt_count: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
        .expect("receipt count");
    assert_eq!(receipt_count, 1);
}

#[test]
fn cleanup_nulls_bundle_links_but_never_destroys_provenance() {
    let mut store = migrated_in_memory();
    populate_full_chain(&store);
    let conn = store.connection();

    conn.execute(
        "DELETE FROM spool_entries WHERE spool_entry_id = ?1",
        rusqlite::params![uuid_like(3)],
    )
    .expect("spool cleanup");

    let orphan_links: i64 = conn
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM frozen_requests
                  WHERE spool_entry_id IS NOT NULL) +
                 (SELECT COUNT(*) FROM ranges
                  WHERE spool_entry_id IS NOT NULL)",
            [],
            |row| row.get(0),
        )
        .expect("link counts");
    assert_eq!(orphan_links, 0, "cleanup nulls the bundle links");

    let request_survives: i64 = conn
        .query_row("SELECT COUNT(*) FROM frozen_requests", [], |row| row.get(0))
        .expect("request count");
    assert_eq!(
        request_survives, 1,
        "the frozen request outlives its bundle"
    );

    let refused = conn
        .execute(
            "DELETE FROM frozen_requests WHERE request_id = ?1",
            rusqlite::params![uuid_like(4)],
        )
        .expect_err("a receipt blocks deleting its request");
    assert!(
        matches!(refused, rusqlite::Error::SqliteFailure(..)),
        "expected the RESTRICT failure, got {refused:?}"
    );
    assert!(
        store.integrity().expect("integrity").healthy(),
        "the post-cleanup database is consistent"
    );
}

#[test]
fn deleting_a_generation_removes_its_ranges() {
    let store = migrated_in_memory();
    populate_full_chain(&store);
    store
        .connection()
        .execute(
            "DELETE FROM generations WHERE generation_id = ?1",
            rusqlite::params![uuid_like(2)],
        )
        .expect("generation delete");
    let ranges: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM ranges", [], |row| row.get(0))
        .expect("range count");
    assert_eq!(ranges, 0, "ranges cascade with their generation");
}

// --- Integrity checks ---------------------------------------------------------

#[test]
fn integrity_is_clean_after_migration() {
    let mut store = migrated_in_memory();
    let report = store.integrity().expect("integrity");
    assert_eq!(
        report,
        IntegrityReport {
            integrity_ok: true,
            foreign_keys_ok: true,
            schema_objects_ok: true,
        }
    );
    assert_eq!(report.summary(), "ok");
    assert!(report.healthy());
}

#[test]
fn integrity_detects_orphan_rows_without_exposing_them() {
    let mut store = migrated_in_memory();
    // Simulate externally corrupted referential state (the engine can never
    // produce this with foreign keys on): switch enforcement off, insert an
    // orphan, switch it back on, then confirm the automated check finds the
    // inconsistency.
    store
        .connection()
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .expect("disable enforcement");
    store
        .connection()
        .execute(
            "INSERT INTO ranges (
                 occurrence_id, generation_id, range_kind, range_start,
                 range_end, sequence, blob_digest, captured_at)
             VALUES (?1, ?2, 'bytes', 0, 0, 0, ?3, ?4)",
            rusqlite::params![hex64(10), uuid_like(30), hex64(11), TS],
        )
        .expect("orphan insert with enforcement off");
    store
        .connection()
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("re-enable enforcement");

    let report = store.integrity().expect("integrity");
    assert!(!report.foreign_keys_ok, "the orphan is detected");
    assert!(report.integrity_ok, "page-level integrity is independent");
    assert!(report.schema_objects_ok);
    assert_eq!(report.summary(), "degraded");
}

#[test]
fn integrity_detects_a_missing_schema_object() {
    let mut store = migrated_in_memory();
    store
        .connection()
        .execute_batch("DROP TABLE adapter_health;")
        .expect("drop a table to simulate damage");
    let report = store.integrity().expect("integrity");
    assert!(!report.schema_objects_ok);
    assert_eq!(report.summary(), "degraded");

    // The migration runner refuses to declare victory over the same damage.
    let error = store.migrate().expect_err("migrate must verify objects");
    assert_eq!(error.kind(), StateErrorKind::SchemaCorruption);
    assert_eq!(error.subject(), Some("adapter_health"));
}

// --- Content-free diagnostics -------------------------------------------------

#[test]
fn every_error_detail_is_a_safe_message() {
    for kind in StateErrorKind::all() {
        let parsed = SafeMessage::parse(kind.default_detail())
            .unwrap_or_else(|_| panic!("detail of {kind} is not a safe message"));
        assert_eq!(parsed.as_str(), kind.default_detail());
        let rendered = StateError::of_kind(*kind).to_string();
        assert!(
            SafeMessage::parse(&rendered).is_ok(),
            "display of {kind} is not a safe message: {rendered}"
        );
    }
}

#[test]
fn contextual_error_rendering_stays_content_free() {
    let error = StateError::of_kind(StateErrorKind::MigrationFailed)
        .at_migration("create-ranges", 5)
        .about("idx_ranges_generation");
    let rendered = error.to_string();
    assert_eq!(
        rendered,
        "state migration-failed: migration step failed and was rolled back \
         (migration 5 create-ranges) [idx_ranges_generation]"
    );
    assert!(SafeMessage::parse(&rendered).is_ok());
    assert_eq!(error.migration(), Some(("create-ranges", 5)));
    assert_eq!(error.subject(), Some("idx_ranges_generation"));
    assert_eq!(error.detail(), "migration step failed and was rolled back");
}

#[test]
fn open_failures_never_name_the_path() {
    let dir = TempDir::new("unavailable");
    // A file where a directory is needed: opening a database underneath it
    // must fail, and the failure must not echo the attempted path.
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").expect("write blocker");
    let attempted = blocker.join("state.db");

    let error = StateStore::open(&attempted).expect_err("open must fail");
    assert_eq!(error.kind(), StateErrorKind::Unavailable);
    let rendered = error.to_string();
    let path_text = attempted.to_string_lossy();
    assert!(
        !rendered.contains(path_text.as_ref()),
        "error leaked the path: {rendered}"
    );
    assert!(rendered.starts_with("state unavailable: "), "{rendered}");
}

#[test]
fn kinds_are_distinct_and_complete() {
    let all = StateErrorKind::all();
    assert_eq!(all.len(), 6);
    let displays: Vec<_> = all.iter().map(std::string::ToString::to_string).collect();
    let mut sorted = displays.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(displays.len(), sorted.len(), "display strings collide");
}

#[test]
fn in_memory_store_round_trips_through_connection_handle() {
    let store = migrated_in_memory();
    store
        .connection()
        .execute(
            "INSERT INTO adapter_health (adapter_id, health_state,
                 consecutive_failures, last_error_code)
             VALUES ('claude', 'degraded', 2, 'capture-record-invalid')",
            [],
        )
        .expect("adapter health insert");
    let (state, failures, code): (String, i64, String) = store
        .connection()
        .query_row(
            "SELECT health_state, consecutive_failures, last_error_code
             FROM adapter_health WHERE adapter_id = 'claude'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("adapter read");
    assert_eq!(state, "degraded");
    assert_eq!(failures, 2);
    assert_eq!(code, "capture-record-invalid");
}
