// SPDX-License-Identifier: Apache-2.0

//! The assembled-reader fault suite (plan Phase 6B; the "database-contention-faults"
//! pre-claim gate row in docs/security/threats/adapter-capture.md): the full
//! reader pipeline — [`StoreConnection::open`] through [`Snapshot::take`] —
//! fails closed on every store fault the parent acceptance names, and no
//! fault ever fabricates projected content:
//!
//! - **Unknown schemas** classify `fingerprint-unsupported` and read no
//!   projected column (plan `EC-08`).
//! - **Locked stores** classify `read-error` inside the injected busy
//!   window while the harness's own writer keeps committing — the store is
//!   never blocked and never corrupted (AC-04).
//! - **Disappearing files** — a store whose bytes vanish or turn hostile
//!   between open and snapshot read — classify `read-error` (or, when the
//!   driver adopts the emptied file as a fresh store, land on the schema
//!   gate as `fingerprint-unsupported`); either way nothing projected is
//!   served from a store that is no longer the one that was opened.
//! - **Permission errors** classify `permission-denied` at the open, the
//!   only stage where the filesystem can still deny this process (AC-08).
//! - **Hostile and oversized cells** cannot crash the reader and never
//!   reach a rendering surface: status, errors, and debug output stay
//!   bounded and content-free (the database half of AC-10's
//!   hostile-source-negatives).

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use archivist_adapter_opencode::{
    BUSY_TIMEOUT, SchemaDivergence, Snapshot, SnapshotError, StoreConnection, StoreOpenError,
};
use archivist_adapter_sdk::ScanClassification;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::{Connection, params};

/// A unique scratch directory, removed when the test ends either way.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let unique = format!(
            "archivist-opencode-faults-{}-{}-{}",
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

/// Create the five allowlisted tables with exactly the embedded allowlist's
/// columns, plus the account and credential tables the real store
/// legitimately holds and the reader must never touch. `extra` runs last so
/// a test can add hostile schema or rows on top of the supported shape. The
/// store is at `<dir>/opencode.db`.
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

/// The `(table, column)` pairs a read touched, as recorded by an
/// authorizer installed on `store`. Only `SQLite`'s schema index and the
/// allowlisted tables can appear, so any projected read is visible here.
fn record_reads(store: &StoreConnection) -> Arc<Mutex<Vec<(String, String)>>> {
    let reads = Arc::new(Mutex::new(Vec::new()));
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
    reads
}

#[test]
fn an_unknown_schema_classifies_fingerprint_unsupported_and_reads_no_content() {
    let scratch = Scratch::new("unknown-schema");
    let path = seed_store(
        scratch.path(),
        "ALTER TABLE message ADD COLUMN overshare TEXT;",
    );

    // The open itself admits the file: opening probes the schema index
    // only. The assembled reader's gate is what must refuse the store.
    let store = StoreConnection::open(&path).expect("the divergent store opens read-only");
    let reads = record_reads(&store);

    let error = Snapshot::take(&store).expect_err("an unknown schema must not snapshot");

    assert_eq!(
        error,
        SnapshotError::Unsupported(SchemaDivergence::ColumnDivergence),
    );
    assert_eq!(
        error.classification(),
        ScanClassification::FingerprintUnsupported,
    );
    assert_eq!(error.classification().token(), "fingerprint-unsupported");
    assert_eq!(
        format!("{error}"),
        error.token(),
        "the token is the message"
    );

    // Fail closed: the whole attempt read gate metadata and at most the
    // version discriminator — never a projected column of any table.
    let recorded = reads.lock().expect("the read log locks").clone();
    assert!(
        recorded.iter().any(|(table, _)| table == "sqlite_master"),
        "the gate really probed the schema: {recorded:?}"
    );
    let metadata_only = recorded.iter().all(|(table, column)| {
        table == "sqlite_master" || (table == "session" && column == "version")
    });
    assert!(metadata_only, "only gate metadata was read: {recorded:?}");

    // The harness is live: the same reader happily serves a projected read
    // when asked directly, so the absence above is evidence, not a vacuous
    // pass.
    let before = reads.lock().expect("the read log locks").len();
    assert!(
        store
            .connection()
            .prepare("SELECT data FROM message")
            .is_ok(),
        "the recording authorizer must allow projected reads"
    );
    let after = reads.lock().expect("the read log locks").len();
    assert!(after > before, "the recorder must fire on projected reads");
}

#[test]
fn a_store_locked_at_open_classifies_read_error_while_the_writer_keeps_writing() {
    let scratch = Scratch::new("locked-at-open");
    let path = seed_store(
        scratch.path(),
        "CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (1);",
    );

    // Hold the store the way a live harness writer does (AC-04): an
    // exclusive transaction with a write applied, kept open across the
    // reader's whole attempt.
    let writer = Connection::open(&path).expect("the writer opens");
    writer
        .execute_batch("BEGIN EXCLUSIVE; INSERT INTO t VALUES (2);")
        .expect("the exclusive write transaction opens");

    let reader = thread::spawn({
        let path = path.clone();
        move || {
            let started = Instant::now();
            let opened = StoreConnection::open_with_busy_timeout(&path, Duration::from_millis(600));
            (opened, started.elapsed())
        }
    });

    // While the reader sits in its busy window, the harness keeps writing
    // its own transaction — the writer is never blocked by the reader's
    // contention, however long the reader waits.
    thread::sleep(Duration::from_millis(100));
    for step in 0..20 {
        let started = Instant::now();
        writer
            .execute("INSERT INTO t VALUES (?1)", [step])
            .expect("the harness writer keeps writing through the contention");
        let write = started.elapsed();
        assert!(
            write < Duration::from_millis(100),
            "write {step} took {write:?}: the reader blocked the harness's own writer"
        );
    }

    let (opened, waited) = reader.join().expect("the reader thread joins");
    let Err(error) = opened else {
        panic!("a store locked for the whole window cannot open");
    };
    writer
        .execute_batch("COMMIT;")
        .expect("the harness writer commits its transaction");

    assert_eq!(error, StoreOpenError::ReadError);
    assert_eq!(error.classification(), ScanClassification::ReadError);
    assert_eq!(error.classification().token(), "read-error");
    assert!(
        waited < BUSY_TIMEOUT,
        "the reader waited {waited:?} — past the production window; the \
         injected window, not the constant, must bound the wait"
    );

    // The contended store is uncorrupted and holds exactly what the
    // harness wrote: the failed reader left nothing behind.
    let rows: i64 = writer
        .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
        .expect("the harness writer reads its own rows");
    assert_eq!(rows, 22, "the seed row, the transaction row, twenty writes");
    let integrity: String = writer
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("the integrity check runs");
    assert_eq!(integrity, "ok", "contention corrupts nothing");
}

#[test]
fn a_snapshot_of_a_store_locked_mid_scan_classifies_read_error_without_reading_rows() {
    let scratch = Scratch::new("locked-mid-scan");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data) VALUES ('m1', 'session-a', 'row content');",
    );

    // The store opens cleanly; the fault arrives between open and read.
    let store = StoreConnection::open_with_busy_timeout(&path, Duration::from_millis(250))
        .expect("the store opens before the writer locks it");
    let reads = record_reads(&store);

    let writer = Connection::open(&path).expect("the writer opens");
    writer
        .execute_batch("BEGIN EXCLUSIVE;")
        .expect("the writer takes the exclusive lock");

    let started = Instant::now();
    let error = Snapshot::take(&store).expect_err("a locked store cannot snapshot");
    let waited = started.elapsed();

    // The reader gave up inside its window, so releasing the store is the
    // writer's own decision, not a wait it was forced into.
    writer
        .execute_batch(
            "INSERT INTO message (id, session_id, data) VALUES ('m2', 'session-a', 'x'); COMMIT;",
        )
        .expect("the harness writer commits as soon as the reader has gone");

    assert_eq!(error, SnapshotError::Read);
    assert_eq!(error.classification(), ScanClassification::ReadError);
    assert_eq!(error.classification().token(), "read-error");
    assert_eq!(format!("{error}"), error.token());
    assert!(
        waited < BUSY_TIMEOUT,
        "the reader waited {waited:?} — the injected window must bound it"
    );
    // Fail closed: no projected row was read after the fault. The gate's
    // schema probe is the only thing the attempt could touch, and even it
    // could not complete under the exclusive lock.
    let recorded = reads.lock().expect("the read log locks").clone();
    assert!(
        recorded.iter().all(|record| record.0 == "sqlite_master"),
        "no projected table was read: {recorded:?}"
    );

    let integrity: String = writer
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("the integrity check runs");
    assert_eq!(integrity, "ok", "contention corrupts nothing");
}

#[test]
fn a_store_whose_bytes_are_replaced_mid_scan_classifies_read_error() {
    // The vanish face the filesystem lets a reader observe: POSIX keeps an
    // unlinked-but-open store readable to the end of its inode, so a
    // disappearing store reaches the reader as bytes that are no longer a
    // database — a rotation that overwrites in place, or a hostile writer.
    // The pre-fault snapshot proves the reader worked; the classification
    // proves the fault was the cause of the failure.
    let scratch = Scratch::new("replaced-bytes");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data) VALUES ('m1', 'session-a', 'row content');",
    );

    let store = StoreConnection::open(&path).expect("the store opens");
    let before = Snapshot::take(&store).expect("the store snapshots before its bytes are replaced");
    assert_eq!(before.tables().len(), 5);

    let original = fs::read(&path).expect("the store bytes are readable");
    let mut replaced = original;
    for byte in replaced.iter_mut().take(200) {
        *byte = 0xde;
    }
    fs::write(&path, replaced).expect("the store bytes are writable from outside the reader");

    let error = Snapshot::take(&store).expect_err("a store that is no longer a database");
    assert_eq!(error, SnapshotError::Read);
    assert_eq!(error.classification(), ScanClassification::ReadError);
    assert_eq!(error.classification().token(), "read-error");
    assert_eq!(format!("{error}"), error.token());
}

#[test]
fn a_store_truncated_mid_scan_fails_closed_on_the_schema_gate() {
    // The emptied-file face of a disappearing store: SQLite serves a
    // zero-length image as a fresh, empty store. The assembled reader must
    // still fail closed — the gate rejects the empty layout as a missing
    // table before any row content is read, and nothing is fabricated from
    // the bytes that are gone.
    let scratch = Scratch::new("truncated-mid-scan");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data) VALUES ('m1', 'session-a', 'row content');",
    );

    let store = StoreConnection::open(&path).expect("the store opens");
    let reads = record_reads(&store);
    let before = Snapshot::take(&store).expect("the store snapshots before it is truncated");
    assert_eq!(before.tables().len(), 5);
    let reads_before = reads.lock().expect("the read log locks").len();

    let handle = fs::File::options()
        .write(true)
        .open(&path)
        .expect("the store file is writable from outside the reader");
    handle.set_len(0).expect("the store is truncated");
    drop(handle);

    let error = Snapshot::take(&store).expect_err("an emptied store cannot snapshot");
    assert_eq!(
        error,
        SnapshotError::Unsupported(SchemaDivergence::MissingTable),
        "the emptied file presents an empty schema, which the gate refuses"
    );
    assert_eq!(
        error.classification(),
        ScanClassification::FingerprintUnsupported,
    );
    assert_eq!(error.classification().token(), "fingerprint-unsupported");

    // Fail closed after the fault: the attempt probed the schema index and
    // stopped there — no projected row served content from the emptied
    // store.
    let recorded: Vec<(String, String)> = reads
        .lock()
        .expect("the read log locks")
        .iter()
        .skip(reads_before)
        .cloned()
        .collect();
    assert!(
        recorded.iter().all(|record| record.0 == "sqlite_master"),
        "after the fault only schema metadata was probed: {recorded:?}"
    );
}

#[test]
fn a_denied_store_classifies_permission_denied_and_never_reads_its_rows() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new("denied");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data) VALUES ('m-sentinel', 'session-a', 'sentinel');",
    );

    fs::set_permissions(&path, fs::Permissions::from_mode(0o000))
        .expect("the store's mode is settable");

    // Be honest about a process the permission boundary does not bind
    // (root, capabilities): skip rather than assert a denial the kernel
    // would not enforce here (adapter-capture.md, the permissions row).
    if fs::File::open(&path).is_ok() {
        eprintln!(
            "skipping: this process reads mode-000 files, so the \
             permission boundary is not enforced in this environment"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("the seed store's mode is restorable");
        return;
    }

    let Err(error) = StoreConnection::open(&path) else {
        panic!("a mode-000 store cannot open");
    };
    assert_eq!(error, StoreOpenError::PermissionDenied);
    assert_eq!(error.classification(), ScanClassification::PermissionDenied,);
    assert_eq!(error.classification().token(), "permission-denied");
    assert_eq!(format!("{error}"), error.classification().token());

    // The positive control: behind the denial sat a real projected row.
    // Restoring the mode lets the assembled reader observe it, so the
    // denial above is what kept the sentinel unread — the fault class is
    // evidence of content withheld, not of an empty store.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .expect("the seed store's mode is restorable");
    let snapshot = Snapshot::take(&StoreConnection::open(&path).expect("the store opens"))
        .expect("the restored store snapshots");
    let messages = snapshot
        .tables()
        .iter()
        .find(|table| table.name() == "message")
        .expect("message is an allowlisted table");
    assert_eq!(messages.rows().len(), 1, "the sentinel row is observed");
}

#[test]
fn a_store_behind_a_closed_directory_classifies_permission_denied() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new("closed-directory");
    let dir = scratch.path().join("session-store");
    fs::create_dir_all(&dir).expect("the store directory is creatable");
    let path = dir.join("opencode.db");
    fs::write(&path, b"not consulted: the directory denies the walk").expect("the file seeds");

    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000))
        .expect("the directory's mode is settable");

    if fs::metadata(&path).is_ok() {
        eprintln!(
            "skipping: this process walks mode-000 directories, so the \
             permission boundary is not enforced in this environment"
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))
            .expect("the directory's mode is restorable");
        return;
    }

    // A denial on a path component is the permission class, not a missing
    // store: something is configured there, and the reader says exactly
    // that (AC-08).
    let Err(error) = StoreConnection::open(&path) else {
        panic!("a store behind a closed directory cannot open");
    };
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))
        .expect("the directory's mode is restorable");

    assert_eq!(error, StoreOpenError::PermissionDenied);
    assert_eq!(error.classification(), ScanClassification::PermissionDenied,);
    assert_eq!(error.classification().token(), "permission-denied");
}

/// The hostile identifier planted in an allowlisted cell: markup, path
/// syntax, and quoting chosen to be distinctive if any surface leaks it.
const HOSTILE_ID: &str = "<script>alert('hostile')</script>-../../etc/passwd";

/// The oversized blob's length: large enough that a content-bearing
/// rendering of the observation would dwarf its shape-only form.
const BLOB_LEN: usize = 4 * 1024 * 1024;

/// Plant fuzz-shaped and oversized values in allowlisted cells: the
/// hostile identifier, a half-mebibyte title, a format-shaped prompt, a
/// control-character todo, a pseudo-random four-mebibyte blob, and text
/// bytes that are not valid UTF-8.
fn plant_hostile_cells(path: &Path) {
    let mut title = format!("{HOSTILE_ID}{{:?}}%s\0");
    title.push_str(&"A".repeat(512 * 1024));
    let mut prompt = String::new();
    prompt.push_str("${hostile}");
    prompt.push_str(&"{:?} ".repeat(64 * 1024));
    let mut blob = vec![0u8; BLOB_LEN];
    let mut seed = 0x243F_6A88_85A3_08D3u64;
    for chunk in blob.chunks_mut(8) {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let bytes = seed.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }

    let writer = Connection::open(path).expect("the planter opens the store");
    writer
        .execute(
            "INSERT INTO message (id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
            params![HOSTILE_ID, "session-a", i64::MAX, blob],
        )
        .expect("the hostile blob plants");
    writer
        .execute(
            "INSERT INTO message (id, session_id, data) VALUES ('m2', 'session-a', CAST(?1 AS TEXT))",
            params![vec![0xffu8, 0xfeu8]],
        )
        .expect("the invalid-utf-8 text plants");
    writer
        .execute(
            "UPDATE session SET title = ?1 WHERE id = 'session-a'",
            params![title],
        )
        .expect("the oversized title plants");
    writer
        .execute(
            "INSERT INTO session_input (id, session_id, prompt) VALUES ('i1', 'session-a', ?1)",
            params![prompt],
        )
        .expect("the format-shaped prompt plants");
    writer
        .execute(
            "INSERT INTO todo (session_id, content, status, priority, position) \
             VALUES ('session-a', ?1, 'open', 'p2', 1)",
            params!["LEAKMARKER\0\x01\x02todo"],
        )
        .expect("the control-character todo plants");
}

#[test]
fn hostile_and_oversized_cells_cannot_crash_the_reader_or_reach_any_surface() {
    // The database half of the hostile-source-negatives row: fuzz-shaped
    // and oversized values planted in allowlisted cells are observed
    // without crashing, and no rendering surface — debug output, status,
    // or the error path a later fault forces — ever carries them.
    let scratch = Scratch::new("hostile-cells");
    let path = seed_store(scratch.path(), "");
    plant_hostile_cells(&path);

    // A zero busy window keeps the later fault instant; with no contention
    // the reads never wait at all.
    let store = StoreConnection::open_with_busy_timeout(&path, Duration::ZERO)
        .expect("the hostile store opens read-only");

    let snapshot = Snapshot::take(&store).expect("hostile cells are observed, never fatal");
    assert_eq!(snapshot.tables().len(), 5);
    let messages = snapshot
        .tables()
        .iter()
        .find(|table| table.name() == "message")
        .expect("message is an allowlisted table");
    assert_eq!(messages.rows().len(), 2);
    // The oversized blob is preserved byte-exactly for the per-field
    // digests: an observation, not a decoder, and not a crash.
    assert_eq!(messages.rows()[0].cells()[4].raw_bytes().len(), BLOB_LEN);

    // No rendering surface carries the hostile bytes: every debug
    // rendering of every observation node is shape only — and provably
    // bounded next to five megabytes of planted content.
    let mut rendered = format!("{snapshot:?}");
    for table in snapshot.tables() {
        let _ = write!(rendered, "{table:?}");
        for row in table.rows() {
            let _ = write!(rendered, "{row:?}");
            for cell in row.cells() {
                let _ = write!(rendered, "{cell:?}");
            }
        }
    }
    for marker in [
        HOSTILE_ID,
        "<script>",
        "../../etc/passwd",
        "LEAKMARKER",
        "{:?}",
        "${hostile}",
    ] {
        assert!(!rendered.contains(marker), "debug leaked {marker:?}");
    }
    assert!(
        rendered.len() < 8192,
        "debug rendered {} bytes for five megabytes of content",
        rendered.len()
    );

    // The status and error faces stay content-free too: a fault injected
    // beside the hostile rows classifies with the closed token, and the
    // planted bytes appear in neither the message nor the debug rendering.
    let fault = Connection::open(&path).expect("the fault writer opens");
    fault
        .execute_batch("BEGIN EXCLUSIVE;")
        .expect("the fault writer locks the store");
    let error = Snapshot::take(&store).expect_err("the locked store cannot snapshot");
    fault
        .execute_batch("ROLLBACK;")
        .expect("the fault writer releases the store");
    assert_eq!(error, SnapshotError::Read);
    assert_eq!(error.classification(), ScanClassification::ReadError);
    let message = format!("{error}");
    let debugged = format!("{error:?}");
    assert_eq!(message, "opencode-snapshot-unreadable");
    assert!(!message.contains(HOSTILE_ID), "Display: {message}");
    assert!(!debugged.contains(HOSTILE_ID), "Debug: {debugged}");
    assert!(!debugged.contains("LEAKMARKER"), "Debug: {debugged}");
}
