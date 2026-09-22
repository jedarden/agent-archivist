// SPDX-License-Identifier: Apache-2.0

//! The snapshot acceptance evidence (plan Phase 6B; the parity decision's
//! reader half; the database half of the "projection-allowlist-negatives"
//! gate row in docs/security/threats/adapter-capture.md): the five
//! allowlisted tables arrive in deterministic order with per-cell
//! presence bits and raw field bytes preserved; two snapshots of an
//! unchanged store are identical; a hostile extra table or view is never
//! read; a store the schema gate rejected is snapshotted as unsupported
//! having read nothing; a store locked past the busy window classifies
//! `read-error`; and no source-derived text reaches an error message.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use archivist_adapter_opencode::{
    ALLOWED_TABLES, Cell, SchemaDivergence, Snapshot, SnapshotError, StoreConnection, TableSnapshot,
};
use archivist_adapter_sdk::ScanClassification;
use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

/// A unique scratch directory, removed when the test ends either way.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let unique = format!(
            "archivist-opencode-snapshot-{}-{}-{}",
            name,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("the clock is after the epoch")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).expect("the scratch directory is creatable");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One seeded session row so the version discriminator has a value to
/// admit: synthetic identifiers, no transcript content.
const SESSION_ROW: &str = "INSERT INTO session (id, project_id, slug, title, version) \
                           VALUES ('session-a', 'project-a', 'a', 'a', '1.18.29')";

const ALLOWLISTED_TABLE_NAMES: [&str; 5] = ["session", "message", "part", "session_input", "todo"];

/// Create the five allowlisted tables with exactly the embedded
/// allowlist's columns, plus the account and credential tables the real
/// store legitimately holds and the projection must never read. `extra`
/// runs last so a test can add hostile schema and seed rows on top of the
/// supported shape. The store is at `<dir>/opencode.db`.
fn seed_store(dir: &Path, extra: &str) -> PathBuf {
    let path = dir.join("opencode.db");
    let writer = Connection::open(&path).expect("the seed store is creatable");
    writer
        .execute_batch(&format!(
            r"
            CREATE TABLE session (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                workspace_id TEXT,
                parent_id TEXT,
                slug TEXT,
                directory TEXT,
                path TEXT,
                title TEXT,
                version TEXT,
                share_url TEXT,
                summary_additions INTEGER,
                summary_deletions INTEGER,
                summary_files INTEGER,
                summary_diffs INTEGER,
                metadata TEXT,
                cost REAL,
                tokens_input INTEGER,
                tokens_output INTEGER,
                tokens_reasoning INTEGER,
                tokens_cache_read INTEGER,
                tokens_cache_write INTEGER,
                revert TEXT,
                permission TEXT,
                agent TEXT,
                model TEXT,
                time_created INTEGER,
                time_updated INTEGER,
                time_compacting INTEGER,
                time_archived INTEGER
            );
            CREATE TABLE message (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                time_created INTEGER,
                time_updated INTEGER,
                data TEXT
            );
            CREATE TABLE part (
                id TEXT PRIMARY KEY,
                message_id TEXT,
                session_id TEXT,
                time_created INTEGER,
                time_updated INTEGER,
                data TEXT
            );
            CREATE TABLE session_input (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                prompt TEXT,
                delivery TEXT,
                admitted_seq INTEGER,
                promoted_seq INTEGER,
                time_created INTEGER
            );
            CREATE TABLE todo (
                session_id TEXT,
                content TEXT,
                status TEXT,
                priority TEXT,
                position INTEGER,
                time_created INTEGER,
                time_updated INTEGER
            );
            CREATE TABLE account (
                id TEXT PRIMARY KEY,
                email TEXT,
                url TEXT,
                access_token TEXT,
                refresh_token TEXT,
                token_expiry INTEGER,
                time_created INTEGER,
                time_updated INTEGER
            );
            CREATE TABLE credential (
                id TEXT PRIMARY KEY,
                integration_id TEXT,
                label TEXT,
                value TEXT,
                connector_id TEXT,
                method_id TEXT,
                active INTEGER,
                time_created INTEGER,
                time_updated INTEGER
            );
            {SESSION_ROW};
            {extra}
            "
        ))
        .expect("the seed schema applies");
    drop(writer);
    path
}

/// The observation of `name` inside `snapshot`, as a test failure if the
/// allowlisted table is missing.
fn table<'a>(snapshot: &'a Snapshot, name: &str) -> &'a TableSnapshot {
    snapshot
        .tables()
        .iter()
        .find(|observed| observed.name() == name)
        .unwrap_or_else(|| panic!("{name} is an allowlisted table"))
}

/// The first column's text of every row of `name` — the ordered key list
/// for the tables whose allowlisted first column is their primary key.
fn ordered_ids(snapshot: &Snapshot, name: &str) -> Vec<Vec<u8>> {
    table(snapshot, name)
        .rows()
        .iter()
        .map(|row| match row.cells()[0] {
            Cell::Text(ref bytes) => bytes.clone(),
            ref cell => panic!("{name} keys are text, not {cell:?}"),
        })
        .collect()
}

#[test]
fn the_snapshot_carries_the_five_allowlisted_tables_in_allowlist_order() {
    let scratch = Scratch::new("shape");
    let path = seed_store(scratch.path(), "");

    let snapshot = Snapshot::take(&StoreConnection::open(&path).expect("the seeded store opens"))
        .expect("the supported store snapshots");

    assert_eq!(snapshot.tables().len(), 5, "exactly the allowlisted tables");
    for (observed, (name, columns)) in snapshot.tables().iter().zip(ALLOWED_TABLES) {
        assert_eq!(observed.name(), *name);
        assert_eq!(observed.columns(), *columns);
    }
}

#[test]
fn rows_are_ordered_by_the_allowlisted_columns_whatever_the_store_serves() {
    // Inserted deliberately out of key order: the observation's order is
    // a function of the values, not of the store's physical row order.
    let scratch = Scratch::new("ordering");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO session (id, project_id, slug, title, version)
             VALUES ('session-c', 'p', 'c', 'c', '1.18.29'),
                    ('session-b', 'p', 'b', 'b', '1.18.29');
         INSERT INTO message (id, session_id) VALUES ('m2', 'session-a'), ('m1', 'session-a');
         INSERT INTO todo (session_id, content, position)
             VALUES ('session-a', 't', 3), ('session-a', 't', 1), ('session-a', 't', 2);",
    );

    let snapshot = Snapshot::take(&StoreConnection::open(&path).expect("the seeded store opens"))
        .expect("the supported store snapshots");

    assert_eq!(
        ordered_ids(&snapshot, "session"),
        [
            b"session-a".to_vec(),
            b"session-b".to_vec(),
            b"session-c".to_vec()
        ],
        "sessions ordered by the allowlisted primary key"
    );
    assert_eq!(
        ordered_ids(&snapshot, "message"),
        [b"m1".to_vec(), b"m2".to_vec()],
    );
    // todo has no primary key in the allowlist: the full allowlisted
    // column set orders it, so the seeded positions come out sorted.
    let positions: Vec<i64> = table(&snapshot, "todo")
        .rows()
        .iter()
        .map(|row| match row.cells()[4] {
            Cell::Integer(position) => position,
            ref cell => panic!("todo position is an integer, not {cell:?}"),
        })
        .collect();
    assert_eq!(
        positions,
        [1, 2, 3],
        "todo ordered by its allowlisted columns"
    );
}

#[test]
fn two_snapshots_of_an_unchanged_store_are_identical() {
    let scratch = Scratch::new("determinism");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data) VALUES ('m1', 'session-a', x'00ff80');
         INSERT INTO todo (session_id, content, status, position)
             VALUES ('session-a', 'same', 'open', 1), ('session-a', 'same', 'open', 1);
         UPDATE session SET cost = 2.5 WHERE id = 'session-a';",
    );

    let first =
        Snapshot::take(&StoreConnection::open(&path).expect("the store opens")).expect("snaps");
    let second =
        Snapshot::take(&StoreConnection::open(&path).expect("the store opens")).expect("snaps");

    // Ordering, presence bits, and bytes all compare equal across two
    // independent observations — including the value-identical todo pair,
    // whose relative physical order the store is free to vary.
    assert_eq!(first, second);
}

#[test]
fn presence_bits_and_raw_field_bytes_are_preserved() {
    let scratch = Scratch::new("cells");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, time_created, data)
             VALUES ('m1', 'session-a', 9223372036854775807, x'00ff80');
         INSERT INTO message (id, session_id, time_updated)
             VALUES ('m2', 'session-a', -9223372036854775808);
         INSERT INTO part (id, message_id, session_id, data)
             VALUES ('p1', 'm1', 'session-a', CAST(x'ff' AS TEXT));
         UPDATE session SET cost = 2.5, share_url = 'https://s' WHERE id = 'session-a';",
    );

    let snapshot = Snapshot::take(&StoreConnection::open(&path).expect("the seeded store opens"))
        .expect("the supported store snapshots");

    let messages = table(&snapshot, "message");
    assert_eq!(messages.rows().len(), 2);
    let m1 = &messages.rows()[0];
    let m2 = &messages.rows()[1];
    assert_eq!(
        m1.cells(),
        [
            Cell::Text(b"m1".to_vec()),
            Cell::Text(b"session-a".to_vec()),
            Cell::Integer(i64::MAX),
            Cell::Null,
            Cell::Blob(vec![0x00, 0xff, 0x80]),
        ],
    );
    assert_eq!(m1.presence_bits(), [true, true, true, false, true]);
    assert_eq!(m2.presence_bits(), [true, true, false, true, false]);
    assert_eq!(m1.cells()[4].raw_bytes(), [0x00, 0xff, 0x80]);
    assert_eq!(m1.cells()[2].raw_bytes(), i64::MAX.to_be_bytes());

    // A blob stored in a text-declared column stays a blob, and text is
    // preserved byte-exactly even when it is not valid UTF-8: the
    // snapshot is an observation, not a decoder.
    let parts = table(&snapshot, "part");
    assert_eq!(parts.rows()[0].cells()[5], Cell::Text(vec![0xff]));
    assert_eq!(parts.rows()[0].cells()[5].raw_bytes(), [0xff]);
    assert_eq!(
        parts.rows()[0].presence_bits(),
        [true, true, true, false, false, true]
    );

    // The session's REAL cell round-trips as the big-endian binary64 the
    // per-field digest is taken over.
    let session = table(&snapshot, "session");
    assert_eq!(session.rows()[0].cells()[15], Cell::Real(2.5));
    assert_eq!(
        session.rows()[0].cells()[15].raw_bytes(),
        2.5f64.to_be_bytes()
    );
    assert!(session.rows()[0].presence_bits()[15]);
}

#[test]
fn a_hostile_extra_table_or_view_is_never_read() {
    // The database half of "projection-allowlist-negatives": a hostile
    // extra table and a hostile view carry planted content, and an
    // authorizer denies every read outside the allowlisted tables and the
    // schema index. The snapshot succeeds only if it never touched them.
    let scratch = Scratch::new("allowlist");
    let path = seed_store(
        scratch.path(),
        "CREATE TABLE password_cache (id TEXT PRIMARY KEY, secret TEXT);
         INSERT INTO password_cache (id, secret) VALUES ('planted', 'planted-secret');
         CREATE VIEW credential_view AS SELECT id, value FROM credential;
         INSERT INTO credential (id, label, value) VALUES ('cred-1', 'l', 'cred-secret');
         INSERT INTO message (id, session_id) VALUES ('m1', 'session-a');",
    );

    let store = StoreConnection::open(&path).expect("the seeded store opens");
    store
        .connection()
        .authorizer(Some(move |context: AuthContext<'_>| match context.action {
            AuthAction::Read { table_name, .. } => {
                if table_name == "sqlite_master" || ALLOWLISTED_TABLE_NAMES.contains(&table_name) {
                    Authorization::Allow
                } else {
                    Authorization::Deny
                }
            }
            _ => Authorization::Allow,
        }))
        .expect("the authorizer installs");

    // The harness is live: the same authorizer denies a direct read of
    // the planted table, so the snapshot's success is evidence, not a
    // vacuous pass.
    let planted = store
        .connection()
        .prepare("SELECT secret FROM password_cache");
    assert!(
        planted.is_err(),
        "the authorizer must deny planted tables for this proof to bind"
    );

    let snapshot = Snapshot::take(&store).expect("the snapshot touches allowlisted tables only");

    assert_eq!(
        snapshot.tables().len(),
        5,
        "nothing outside the allowlist is observed"
    );
    assert_eq!(ordered_ids(&snapshot, "message"), [b"m1".to_vec()]);
}

#[test]
fn a_gate_rejected_store_reads_nothing() {
    // The schema gate runs first: on a store it rejects, the snapshot
    // reports the gate's divergence and no projected column is read —
    // recorded here by an authorizer that logs every table read.
    let scratch = Scratch::new("gate-first");
    let path = seed_store(
        scratch.path(),
        "ALTER TABLE message ADD COLUMN overshare TEXT;",
    );

    let store = StoreConnection::open(&path).expect("the divergent store opens");
    let reads: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let logged = Arc::clone(&reads);
    store
        .connection()
        .authorizer(Some(move |context: AuthContext<'_>| {
            if let AuthAction::Read {
                table_name,
                column_name,
            } = context.action
            {
                logged
                    .lock()
                    .expect("the read log locks")
                    .push((table_name.to_owned(), column_name.to_owned()));
            }
            Authorization::Allow
        }))
        .expect("the authorizer installs");

    let error = Snapshot::take(&store).expect_err("the divergent store must not snapshot");

    assert_eq!(
        error,
        SnapshotError::Unsupported(SchemaDivergence::ColumnDivergence),
    );
    assert_eq!(
        error.classification(),
        ScanClassification::FingerprintUnsupported
    );

    let recorded = reads.lock().expect("the read log locks").clone();
    let projected: Vec<&(String, String)> = recorded
        .iter()
        .filter(|(seen, _)| ["message", "part", "session_input", "todo"].contains(&seen.as_str()))
        .collect();
    assert!(
        projected.is_empty(),
        "no projected table was read: {projected:?}"
    );
    // Everything the attempt did read is the gate's own metadata probe:
    // the schema index, plus at most the version discriminator — the
    // column divergence above fires before that probe, so a rejected
    // store reads nothing of its row content.
    let metadata_only = recorded.iter().all(|(seen, column)| {
        seen == "sqlite_master" || (seen == "session" && column == "version")
    });
    assert!(metadata_only, "only gate metadata was read: {recorded:?}");
    assert!(
        recorded.iter().any(|(seen, _)| seen == "sqlite_master"),
        "the gate really probed the schema"
    );

    // The harness is live: the same recorder logs a deliberate projected
    // read, so its absence above is evidence, not a vacuous pass.
    let before = reads.lock().expect("the read log locks").len();
    assert!(
        store
            .connection()
            .prepare("SELECT data FROM message")
            .is_ok(),
        "the recording authorizer allows projected reads"
    );
    let after = reads.lock().expect("the read log locks").len();
    assert!(after > before, "the recorder must fire on projected reads");
}

#[test]
fn a_store_locked_past_the_busy_window_classifies_read_error() {
    // Reads stay bounded: with a zero busy window, a writer holding the
    // store exclusively ends the snapshot as a bounded read-error instead
    // of waiting, and the classification is all the error says.
    let scratch = Scratch::new("locked");
    let path = seed_store(scratch.path(), "");

    let store = StoreConnection::open_with_busy_timeout(&path, Duration::ZERO)
        .expect("the store opens before the writer locks it");
    let writer = Connection::open(&path).expect("the writer opens");
    writer
        .execute_batch("BEGIN EXCLUSIVE;")
        .expect("the writer takes the exclusive lock");

    let error = Snapshot::take(&store).expect_err("a locked store cannot snapshot");

    writer
        .execute_batch("ROLLBACK;")
        .expect("the writer releases the store");

    assert_eq!(error, SnapshotError::Read);
    assert_eq!(error.classification(), ScanClassification::ReadError);
    assert_eq!(error.classification().token(), "read-error");
    assert_eq!(format!("{error}"), error.token());
}

#[test]
fn error_paths_carry_no_source_text() {
    // Hostile schema and a hostile discriminator: whatever the gate
    // rejects on, the snapshot error's whole rendering is the closed
    // token, never the text that caused it.
    let hostile_column = "<script>alert('schema')</script>";
    let hostile_version = "9.9.9--</script>&/etc/passwd";
    let scratch = Scratch::new("content-freedom");
    let path = seed_store(
        scratch.path(),
        &format!(
            r#"ALTER TABLE session ADD COLUMN "{hostile_column}" TEXT;
               INSERT INTO session (id, project_id, slug, title, version)
               VALUES ('session-h', 'p', 'h', 'h', '{hostile_version}');"#
        ),
    );

    let error = Snapshot::take(&StoreConnection::open(&path).expect("the store opens"))
        .expect_err("the hostile store must not snapshot");

    let rendered = format!("{error}");
    let debugged = format!("{error:?}");
    assert_eq!(rendered, error.token(), "Display is the closed token");
    assert!(!rendered.contains(hostile_column), "Display: {rendered}");
    assert!(!rendered.contains(hostile_version), "Display: {rendered}");
    assert!(!debugged.contains(hostile_column), "Debug: {debugged}");
    assert!(!debugged.contains(hostile_version), "Debug: {debugged}");
    assert_eq!(
        error.classification(),
        ScanClassification::FingerprintUnsupported
    );
}

#[test]
fn snapshot_debug_is_shape_only() {
    let scratch = Scratch::new("debug");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data)
             VALUES ('message-secret-id', 'session-a', 'message-secret-body');",
    );

    let snapshot = Snapshot::take(&StoreConnection::open(&path).expect("the store opens"))
        .expect("the supported store snapshots");
    let rendered = format!("{snapshot:?}");

    assert!(!rendered.contains("message-secret-id"), "Debug: {rendered}");
    assert!(
        !rendered.contains("message-secret-body"),
        "Debug: {rendered}"
    );
    assert!(
        rendered.contains("table_count"),
        "Debug keeps bounded shape: {rendered}"
    );
}
