// SPDX-License-Identifier: Apache-2.0

//! The store-connection acceptance evidence (plan Phase 6B; requirement
//! CAP-004; the adapter-capture gate row "Database sources — OpenCode"):
//! a missing store classifies `no-database` and creates no file, an
//! unreadable store classifies `permission-denied`, a lock held past the
//! busy window classifies `read-error` without blocking the harness's own
//! writer, the opened connection cannot write, and no source-derived text
//! reaches an error message.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use archivist_adapter_opencode::{BUSY_TIMEOUT, StoreConnection, StoreOpenError};
use archivist_adapter_sdk::ScanClassification;
use rusqlite::Connection;

/// A unique scratch directory, removed when the test ends either way.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let unique = format!(
            "archivist-opencode-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
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

/// Seed a real database file at `scratch/session-store.db` and return
/// once the writer connection is closed (locks released).
fn seed_store(scratch: &Scratch) -> PathBuf {
    let path = scratch.path().join("session-store.db");
    let writer = Connection::open(&path).expect("the seed store is creatable");
    writer
        .execute_batch("CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (1);")
        .expect("the seed schema applies");
    drop(writer);
    path
}

/// The `Ok` half of an open that must fail, as a test failure.
fn open_failure(open: &Result<StoreConnection, StoreOpenError>, why: &str) -> StoreOpenError {
    match open {
        Ok(_) => panic!("{why}"),
        Err(error) => *error,
    }
}

#[test]
fn the_production_busy_window_is_five_seconds() {
    assert_eq!(BUSY_TIMEOUT, Duration::from_secs(5));
}

#[test]
fn a_missing_store_classifies_no_database_and_creates_no_file() {
    let scratch = Scratch::new("missing");
    let path = scratch.path().join("session-store.db");

    let error = open_failure(&StoreConnection::open(&path), "a missing store cannot open");

    assert_eq!(error, StoreOpenError::NoDatabase);
    assert_eq!(error.classification(), ScanClassification::NoDatabase);
    assert_eq!(error.classification().token(), "no-database");
    assert!(!path.exists(), "the open never materializes the store");
    let created: Vec<_> = fs::read_dir(scratch.path())
        .expect("the scratch directory is readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        created.is_empty(),
        "opening a missing store must create no file: {created:?}"
    );
}

#[test]
#[cfg(unix)]
fn an_unreadable_store_classifies_permission_denied() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new("unreadable");
    let path = seed_store(&scratch);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000))
        .expect("the seed store's mode is settable");

    // Be honest about a process the permission boundary does not bind
    // (root, capabilities): skip rather than assert a denial the kernel
    // would not enforce here (adapter-capture.md, the permissions row).
    if fs::File::open(&path).is_ok() {
        eprintln!(
            "skipping: this process reads mode-000 files, so the \
             permission boundary is not enforced in this environment"
        );
        return;
    }

    let error = open_failure(
        &StoreConnection::open(&path),
        "a mode-000 store cannot open",
    );

    assert_eq!(error, StoreOpenError::PermissionDenied);
    assert_eq!(error.classification(), ScanClassification::PermissionDenied);
    assert_eq!(error.classification().token(), "permission-denied");

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .expect("the seed store's mode is restorable");
}

#[test]
fn a_lock_held_past_the_window_classifies_read_error_and_never_blocks_the_writer() {
    let scratch = Scratch::new("contention");
    let path = scratch.path().join("session-store.db");
    let writer = Connection::open(&path).expect("the store is creatable");
    writer
        .execute_batch("CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (1);")
        .expect("the seed schema applies");

    // Hold the store the way a live harness writer does (AC-04): an
    // exclusive transaction with a write applied, kept open across the
    // reader's whole attempt.
    writer
        .execute_batch("BEGIN EXCLUSIVE; INSERT INTO t VALUES (2);")
        .expect("the exclusive write transaction opens");

    let started = Instant::now();
    let error = open_failure(
        &StoreConnection::open_with_busy_timeout(&path, Duration::from_millis(150)),
        "a store locked past the busy window cannot open",
    );
    let waited = started.elapsed();

    assert_eq!(error, StoreOpenError::ReadError);
    assert_eq!(error.classification(), ScanClassification::ReadError);
    assert_eq!(error.classification().token(), "read-error");
    assert!(
        waited < BUSY_TIMEOUT,
        "the reader waited {waited:?} — past the production window; the \
         injected window, not the constant, must bound the wait"
    );

    // The harness's own writer was never blocked past the window: it
    // keeps writing and commits cleanly while the reader has long given
    // up.
    writer
        .execute_batch("INSERT INTO t VALUES (3); COMMIT;")
        .expect("the harness writer keeps the store");
    let rows: i64 = writer
        .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
        .expect("the harness writer reads its own rows");
    assert_eq!(rows, 3);
}

#[test]
fn the_opened_connection_cannot_write() {
    let scratch = Scratch::new("read-only");
    let path = seed_store(&scratch);

    let store = StoreConnection::open(&path).expect("the seeded store opens read-only");

    let inserted = store.connection().execute("INSERT INTO t VALUES (8)", []);
    assert!(
        inserted.is_err(),
        "a read-only store connection cannot write rows"
    );
    let altered = store
        .connection()
        .execute_batch("CREATE TABLE injected (v INTEGER);");
    assert!(
        altered.is_err(),
        "a read-only store connection cannot change the schema"
    );
    let rows: i64 = store
        .connection()
        .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
        .expect("the reader counts the rows it may read");
    assert_eq!(rows, 1, "nothing was written through the reader");
}

#[test]
fn open_errors_carry_no_source_text() {
    let scratch = Scratch::new("content-freedom");
    let hostile = format!("session-{}-store.db", std::process::id());
    let path = scratch.path().join(&hostile);

    let error = open_failure(&StoreConnection::open(&path), "a missing store cannot open");

    let rendered = format!("{error}");
    let debugged = format!("{error:?}");
    assert_eq!(rendered, "no-database", "the token is the whole message");
    assert!(!rendered.contains(&hostile), "Display: {rendered}");
    assert!(!debugged.contains(&hostile), "Debug: {debugged}");
    assert!(!rendered.contains('/'), "no path syntax: {rendered}");
    assert!(!debugged.contains('/'), "no path syntax: {debugged}");
}
