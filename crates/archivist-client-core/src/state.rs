// SPDX-License-Identifier: Apache-2.0

//! The client state database: explicit `SQLite` (WAL) migrations and the
//! automated integrity checks around them (plan Section 7.9).
//!
//! One mutating process owns the state database. Opening it configures the
//! connection before anything else runs: WAL journaling with `synchronous =
//! FULL` so a committed transaction is durable, `foreign_keys = ON` so the
//! schema's referential contract is enforced rather than decorative, and a
//! busy timeout so a `status` reader's snapshot never fails an upload.
//!
//! Migrations are hand-written steps in [`migrations`], applied in order in
//! one transaction each, recorded in a `schema_migrations` history table,
//! and reversible wherever the step is safe to undo. After applying, the
//! runner verifies the resulting object set against the schema's expected
//! tables and indexes, so a partially applied or externally damaged
//! database is detected at startup instead of at first use.
//!
//! # Content-free diagnostics
//!
//! [`StateError`] cannot carry runtime text: its detail, migration name,
//! and subject are all `&'static str`. Driver error strings — which can
//! embed the database path, SQL text, or bound values — are classified at
//! the boundary and dropped. This is the client-side expression of the
//! project's redaction rule: diagnostics name the failure class, never a
//! path or transcript content.

use std::fmt;
use std::path::Path;

use rusqlite::Connection;

pub mod migrations;

#[cfg(test)]
mod tests;

use migrations::{EXPECTED_INDEXES, EXPECTED_TABLES, MIGRATIONS};

/// The schema version a fresh database reaches once every migration is
/// applied.
// The slice length is pinned to eight steps by the migration-list test, so
// the cast cannot lose information.
#[allow(clippy::cast_possible_wrap)]
pub const LATEST_SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

/// The closed set of failure classes a client state operation can report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StateErrorKind {
    /// The state database could not be opened or configured. The path is
    /// deliberately absent from the error; the caller already knows which
    /// directory it asked for.
    Unavailable,
    /// Another process held the write lock beyond the busy timeout. One
    /// mutating process owns the state directory (plan Section 7.9); this
    /// is the signal to exit, not to wait harder.
    Busy,
    /// A migration step failed inside its transaction; the database is
    /// left at the previous version.
    MigrationFailed,
    /// A revert was requested on a migration that records no reverse SQL —
    /// the step destroys information and is deliberately irreversible.
    IrreversibleMigration,
    /// A requested schema version is outside `0..=LATEST`, or would move
    /// the database in the direction the operation never moves.
    VersionOutOfBounds,
    /// The database does not match its recorded schema: an expected object
    /// is missing or the migration history has a gap.
    SchemaCorruption,
}

impl StateErrorKind {
    /// Every kind, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Unavailable,
            Self::Busy,
            Self::MigrationFailed,
            Self::IrreversibleMigration,
            Self::VersionOutOfBounds,
            Self::SchemaCorruption,
        ]
    }

    /// The content-free default detail shipped with this kind. Pinned to
    /// the protocol's safe-message grammar by a unit test.
    #[must_use]
    pub const fn default_detail(self) -> &'static str {
        match self {
            Self::Unavailable => "state database could not be opened",
            Self::Busy => "state database is locked by another process",
            Self::MigrationFailed => "migration step failed and was rolled back",
            Self::IrreversibleMigration => "migration step has no reverse sql",
            Self::VersionOutOfBounds => "schema version target is outside the migration range",
            Self::SchemaCorruption => "state database does not match its recorded schema",
        }
    }
}

impl fmt::Display for StateErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Unavailable => "unavailable",
            Self::Busy => "busy",
            Self::MigrationFailed => "migration-failed",
            Self::IrreversibleMigration => "irreversible-migration",
            Self::VersionOutOfBounds => "version-out-of-bounds",
            Self::SchemaCorruption => "schema-corruption",
        };
        f.write_str(text)
    }
}

/// Why a client state operation failed: a closed class plus content-free
/// context.
///
/// The type is incapable of carrying a path or transcript data by
/// construction — every string field is a static literal, and the only
/// contextual values name a migration or a schema object. Underlying driver
/// errors are classified and dropped, never wrapped, because their text can
/// embed the database path or SQL values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StateError {
    kind: StateErrorKind,
    detail: &'static str,
    migration: Option<(&'static str, i64)>,
    subject: Option<&'static str>,
}

impl StateError {
    /// Build an error carrying the kind's default detail.
    #[must_use]
    pub const fn of_kind(kind: StateErrorKind) -> Self {
        Self {
            kind,
            detail: kind.default_detail(),
            migration: None,
            subject: None,
        }
    }

    /// Build an error with a static, content-free detail other than the
    /// kind's default.
    #[must_use]
    pub const fn with_detail(kind: StateErrorKind, detail: &'static str) -> Self {
        Self {
            kind,
            detail,
            migration: None,
            subject: None,
        }
    }

    /// Attach the migration the failure concerns (static name, version).
    #[must_use]
    pub const fn at_migration(mut self, name: &'static str, version: i64) -> Self {
        self.migration = Some((name, version));
        self
    }

    /// Attach the static schema object name the failure concerns.
    #[must_use]
    pub const fn about(mut self, subject: &'static str) -> Self {
        self.subject = Some(subject);
        self
    }

    /// The failure class.
    #[must_use]
    pub const fn kind(&self) -> StateErrorKind {
        self.kind
    }

    /// The content-free detail text.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }

    /// The migration this error concerns, as its static name and version.
    #[must_use]
    pub const fn migration(&self) -> Option<(&'static str, i64)> {
        self.migration
    }

    /// The schema object this error concerns, by static name.
    #[must_use]
    pub const fn subject(&self) -> Option<&'static str> {
        self.subject
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "state {}: {}", self.kind, self.detail)?;
        if let Some((name, version)) = self.migration {
            write!(f, " (migration {version} {name})")?;
        }
        if let Some(subject) = self.subject {
            write!(f, " [{subject}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for StateError {}

// Deliberately field-free: the driver's own `Debug` renders the database
// path, which must never reach a diagnostic.
impl fmt::Debug for StateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StateStore")
    }
}

/// Whether a driver error is a lock contention signal (the one distinction
/// worth keeping); everything else about the error text is discarded.
fn is_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(ffi, _)
            if matches!(
                ffi.code,
                rusqlite::ErrorCode::DatabaseBusy
                    | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

/// Classify a driver error without keeping any of its text. Driver messages
/// can embed the database path, SQL, or bound values; none of that may reach
/// a diagnostic, so only the busy/non-busy distinction survives.
fn driver_error(err: &rusqlite::Error) -> StateError {
    if is_busy(err) {
        StateError::of_kind(StateErrorKind::Busy)
    } else {
        StateError::of_kind(StateErrorKind::Unavailable)
    }
}

/// The content-free result of the automated integrity checks: one verdict
/// per check, never the offending rows or values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntegrityReport {
    /// `PRAGMA integrity_check` returned a clean verdict.
    pub integrity_ok: bool,
    /// `PRAGMA foreign_key_check` found no orphan rows.
    pub foreign_keys_ok: bool,
    /// Every table and index the schema expects is present.
    pub schema_objects_ok: bool,
}

impl IntegrityReport {
    /// All checks passed.
    #[must_use]
    pub const fn healthy(&self) -> bool {
        self.integrity_ok && self.foreign_keys_ok && self.schema_objects_ok
    }

    /// A stable content-free summary for diagnostics: `ok` or `degraded`.
    #[must_use]
    pub const fn summary(&self) -> &'static str {
        if self.healthy() { "ok" } else { "degraded" }
    }
}

/// The client state database: a configured connection plus the migration
/// runner.
///
/// Open with [`StateStore::open`], then apply the schema explicitly with
/// [`StateStore::migrate`]. Nothing mutates the database at open time, so a
/// reader can open the same file for a snapshot without running the runner.
pub struct StateStore {
    conn: Connection,
}

impl StateStore {
    /// Open (creating if absent) the state database at `path` and configure
    /// it: WAL journaling, `synchronous = FULL`, foreign keys on, busy
    /// timeout. The schema is not touched until [`StateStore::migrate`].
    ///
    /// # Errors
    ///
    /// [`StateErrorKind::Unavailable`] when the file cannot be opened or
    /// WAL mode cannot be established; the path never appears in the error.
    /// [`StateErrorKind::Busy`] when another process holds the write lock.
    pub fn open(path: &Path) -> Result<Self, StateError> {
        let conn = Connection::open(path).map_err(|ref err| driver_error(err))?;
        configure(&conn, true)?;
        Ok(Self { conn })
    }

    /// Open an unnamed in-memory database with the same connection rules
    /// except WAL, which in-memory databases do not journal. For tests and
    /// tools; the daemon always opens a file.
    ///
    /// # Errors
    ///
    /// [`StateErrorKind::Unavailable`] when the driver cannot create the
    /// connection.
    pub fn open_in_memory() -> Result<Self, StateError> {
        let conn = Connection::open_in_memory().map_err(|ref err| driver_error(err))?;
        configure(&conn, false)?;
        Ok(Self { conn })
    }

    /// The underlying connection, for the engine's own prepared statements
    /// against the migrated schema.
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The applied schema version: the highest recorded migration, or 0
    /// before any migration.
    ///
    /// # Errors
    ///
    /// [`StateErrorKind::Unavailable`] when the history table cannot be
    /// created or read.
    pub fn schema_version(&mut self) -> Result<i64, StateError> {
        self.ensure_history()?;
        version_of(&self.conn)
    }

    /// Apply every migration up to [`LATEST_SCHEMA_VERSION`], then verify
    /// the expected schema objects. Already-applied steps are skipped, so
    /// this is idempotent.
    ///
    /// # Errors
    ///
    /// [`StateErrorKind::MigrationFailed`] when a step fails; its
    /// transaction is rolled back and the database stays at the previous
    /// version. [`StateErrorKind::SchemaCorruption`] when the resulting
    /// object set does not match the expected schema or the migration list
    /// has a gap.
    pub fn migrate(&mut self) -> Result<(), StateError> {
        self.migrate_to(LATEST_SCHEMA_VERSION)
    }

    /// Apply migrations up to `target` exactly; never moves down. Use
    /// [`StateStore::revert_to`] for that.
    ///
    /// # Errors
    ///
    /// [`StateErrorKind::VersionOutOfBounds`] when `target` is outside
    /// `0..=[LATEST_SCHEMA_VERSION]` or below the current version.
    /// [`StateErrorKind::MigrationFailed`] when a step fails inside its
    /// transaction. [`StateErrorKind::SchemaCorruption`] when the migration
    /// list has a gap or the resulting object set is wrong.
    pub fn migrate_to(&mut self, target: i64) -> Result<(), StateError> {
        self.ensure_history()?;
        let mut current = version_of(&self.conn)?;
        if !(0..=LATEST_SCHEMA_VERSION).contains(&target) || target < current {
            return Err(StateError::of_kind(StateErrorKind::VersionOutOfBounds));
        }
        while current < target {
            let next = current + 1;
            let migration = MIGRATIONS
                .iter()
                .find(|step| step.version == next)
                .ok_or_else(|| {
                    StateError::of_kind(StateErrorKind::SchemaCorruption)
                        .at_migration("missing", next)
                })?;
            apply_migration(&mut self.conn, migration)?;
            current = version_of(&self.conn)?;
        }
        if let Some(missing) = first_missing_object(&self.conn) {
            return Err(StateError::of_kind(StateErrorKind::SchemaCorruption).about(missing));
        }
        Ok(())
    }

    /// Revert the highest applied migration — where it is reversible — and
    /// return the version the database now sits at. Returns 0 when already
    /// empty.
    ///
    /// # Errors
    ///
    /// [`StateErrorKind::IrreversibleMigration`] when the step records no
    /// reverse SQL. [`StateErrorKind::MigrationFailed`] when the reverse
    /// step fails inside its transaction.
    pub fn revert_one(&mut self) -> Result<i64, StateError> {
        self.ensure_history()?;
        let current = version_of(&self.conn)?;
        if current == 0 {
            return Ok(0);
        }
        let migration = MIGRATIONS
            .iter()
            .find(|step| step.version == current)
            .ok_or_else(|| {
                StateError::of_kind(StateErrorKind::SchemaCorruption)
                    .at_migration("missing", current)
            })?;
        revert_migration(&mut self.conn, migration)?;
        Ok(current - 1)
    }

    /// Revert applied migrations until the database sits at exactly
    /// `target` (0 empties every schema object). Never migrates up.
    ///
    /// # Errors
    ///
    /// [`StateErrorKind::VersionOutOfBounds`] when `target` is outside
    /// `0..=[LATEST_SCHEMA_VERSION]` or above the current version.
    /// [`StateErrorKind::IrreversibleMigration`] and
    /// [`StateErrorKind::MigrationFailed`] as for
    /// [`StateStore::revert_one`].
    pub fn revert_to(&mut self, target: i64) -> Result<(), StateError> {
        self.ensure_history()?;
        let current = version_of(&self.conn)?;
        if !(0..=LATEST_SCHEMA_VERSION).contains(&target) || target > current {
            return Err(StateError::of_kind(StateErrorKind::VersionOutOfBounds));
        }
        let mut current = current;
        while current > target {
            let migration = MIGRATIONS
                .iter()
                .find(|step| step.version == current)
                .ok_or_else(|| {
                    StateError::of_kind(StateErrorKind::SchemaCorruption)
                        .at_migration("missing", current)
                })?;
            revert_migration(&mut self.conn, migration)?;
            current = version_of(&self.conn)?;
        }
        Ok(())
    }

    /// Run the automated integrity checks: `PRAGMA integrity_check`,
    /// `PRAGMA foreign_key_check`, and the expected-object scan. Returns
    /// per-check verdicts only — a failing check reports itself, never the
    /// rows that failed it.
    ///
    /// # Errors
    ///
    /// [`StateErrorKind::Unavailable`] when a check cannot be executed.
    pub fn integrity(&mut self) -> Result<IntegrityReport, StateError> {
        self.ensure_history()?;
        let integrity_ok = {
            let mut statement = self
                .conn
                .prepare("PRAGMA integrity_check")
                .map_err(|ref err| driver_error(err))?;
            let mut rows = statement.query([]).map_err(|ref err| driver_error(err))?;
            match rows.next().map_err(|ref err| driver_error(err))? {
                Some(row) => {
                    let verdict: String = row.get(0).map_err(|ref err| driver_error(err))?;
                    verdict == "ok"
                }
                None => false,
            }
        };
        let foreign_keys_ok = {
            let mut statement = self
                .conn
                .prepare("PRAGMA foreign_key_check")
                .map_err(|ref err| driver_error(err))?;
            let mut rows = statement.query([]).map_err(|ref err| driver_error(err))?;
            rows.next().map_err(|ref err| driver_error(err))?.is_none()
        };
        let schema_objects_ok = first_missing_object(&self.conn).is_none();
        Ok(IntegrityReport {
            integrity_ok,
            foreign_keys_ok,
            schema_objects_ok,
        })
    }

    /// Create the migration history table when absent. Kept out of the
    /// numbered migrations: the history records them, it is not one of
    /// them, and reverting the schema must not erase the record of what
    /// was applied.
    fn ensure_history(&mut self) -> Result<(), StateError> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
                     version INTEGER PRIMARY KEY NOT NULL,
                     name TEXT NOT NULL CHECK (name <> ''),
                     applied_at TEXT NOT NULL DEFAULT
                         (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                 );",
            )
            .map_err(|ref err| driver_error(err))
    }
}

/// The current applied version, after the history table exists.
fn version_of(conn: &Connection) -> Result<i64, StateError> {
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )
    .map_err(|ref err| driver_error(err))
}

/// Configure a fresh connection. `wal` requests WAL journaling and is only
/// used for file-backed databases; the pragma result is checked so a
/// database that silently stayed in rollback-journal mode fails here
/// rather than losing the durability contract at commit time.
fn configure(conn: &Connection, wal: bool) -> Result<(), StateError> {
    conn.execute_batch(
        "PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;
         PRAGMA synchronous = FULL;",
    )
    .map_err(|ref err| driver_error(err))?;
    if wal {
        let mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(|ref err| driver_error(err))?;
        if mode != "wal" {
            return Err(StateError::of_kind(StateErrorKind::Unavailable));
        }
    }
    Ok(())
}

/// The migration step that fails a driver call: the busy class passes
/// through; everything else becomes a migration failure naming the step.
fn step_failure(migration: &migrations::Migration) -> impl Fn(&rusqlite::Error) -> StateError + '_ {
    move |err| {
        if is_busy(err) {
            StateError::of_kind(StateErrorKind::Busy)
        } else {
            StateError::of_kind(StateErrorKind::MigrationFailed)
        }
        .at_migration(migration.name, migration.version)
    }
}

/// Apply one migration inside a single transaction: the step's SQL plus the
/// history insert commit together or not at all.
fn apply_migration(
    conn: &mut Connection,
    migration: &migrations::Migration,
) -> Result<(), StateError> {
    let failed = step_failure(migration);
    let tx = conn.transaction().map_err(|ref err| failed(err))?;
    tx.execute_batch(migration.up)
        .map_err(|ref err| failed(err))?;
    tx.execute(
        "INSERT INTO schema_migrations (version, name) VALUES (?1, ?2)",
        rusqlite::params![migration.version, migration.name],
    )
    .map_err(|ref err| failed(err))?;
    tx.commit().map_err(|ref err| failed(err))
}

/// Reverse one migration inside a single transaction: the step's reverse
/// SQL plus the history delete commit together or not at all.
fn revert_migration(
    conn: &mut Connection,
    migration: &migrations::Migration,
) -> Result<(), StateError> {
    let Some(down) = migration.down else {
        return Err(StateError::of_kind(StateErrorKind::IrreversibleMigration)
            .at_migration(migration.name, migration.version));
    };
    let failed = step_failure(migration);
    let tx = conn.transaction().map_err(|ref err| failed(err))?;
    tx.execute_batch(down).map_err(|ref err| failed(err))?;
    tx.execute(
        "DELETE FROM schema_migrations WHERE version = ?1",
        rusqlite::params![migration.version],
    )
    .map_err(|ref err| failed(err))?;
    tx.commit().map_err(|ref err| failed(err))
}

/// The first expected table or index missing from the database, if any.
/// Static names only — never counts, rows, or values.
fn first_missing_object(conn: &Connection) -> Option<&'static str> {
    let present = |kind: &str, name: &str| {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = ?1 AND name = ?2",
            rusqlite::params![kind, name],
            |row| row.get::<_, i64>(0),
        )
        .is_ok_and(|count| count == 1)
    };
    EXPECTED_TABLES
        .iter()
        .chain(EXPECTED_INDEXES.iter())
        .copied()
        .find(|name| !(present("table", name) || present("index", name)))
}
