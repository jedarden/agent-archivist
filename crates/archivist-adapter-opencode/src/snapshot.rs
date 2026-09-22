// SPDX-License-Identifier: Apache-2.0

//! The transactionally consistent read-only snapshot (plan Phase 6B; the
//! parity decision's "a transactionally consistent read-only snapshot"
//! reader half).
//!
//! [`Snapshot::take`] produces the reader-side observation the Phase 6
//! parity tuple is built from: the five allowlisted tables
//! ([`ALLOWED_TABLES`]) read in one deferred read transaction, rows
//! ordered deterministically by their allowlisted columns, every cell
//! carrying a presence bit and the value's raw bytes so the per-field
//! digests can be taken without re-reading the store. This is the
//! observation only — projecting it into archivist records and deciding
//! parity is the remaining Phase 6B projection work.
//!
//! # One transactional view
//!
//! The five queries run inside one read transaction. In a rollback-journal
//! store the transaction holds the shared lock to commit, so a concurrent
//! write cannot commit into the middle of the read; in a WAL store the
//! reader pins the log's end mark at its first read, so a concurrent
//! commit is invisible to every later table read. Either way a writer
//! committing between the table reads cannot produce a torn snapshot: the
//! whole observation reflects one point in the store's history, which is
//! what makes the snapshot a usable parity basis.
//!
//! # Deterministic ordering
//!
//! Every table is ordered by its allowlisted columns, each under `BINARY`
//! collation, in allowlist order — the allowlisted primary key column
//! (`id`) leads every table that has one. A tie across all columns is a
//! value-identical row, so no remaining order is left to vary: two
//! snapshots of an unchanged store are identical in ordering and presence
//! bits, whatever physical row order the store happens to serve.
//!
//! # Allowlist discipline
//!
//! The queries touch only the allowlisted tables and only their
//! allowlisted columns: every identifier in the SQL comes from this
//! crate's compiled-in constants, never from the store, so a hostile
//! extra table, a view, or a rename cannot widen what is read — there is
//! no source-derived name to interpolate. Credential, account,
//! provider-auth, and unrelated cache tables are not read at all (the
//! database half of the adapter-capture gate row
//! "projection-allowlist-negatives").
//!
//! # Gate first
//!
//! [`detect`] — the schema-version gate — runs before the read
//! transaction opens, and a rejected store reads nothing: the observation
//! is never taken of a layout the adapter does not admit.
//!
//! # Content-freedom and bounds
//!
//! Snapshot content never enters logs, errors, or status. The error type
//! is a closed set of unit variants (plus the gate's own content-free
//! divergence vocabulary), [`fmt::Display`] renders only closed tokens,
//! and the observation types' [`fmt::Debug`] implementations report only
//! shape, storage class, and bounded counts — never field bytes or values.
//! Reads stay bounded: one prepared statement per allowlisted table per
//! snapshot, no per-row follow-up queries, and every lock wait is bounded
//! by the store connection's busy window.

use std::fmt;

use archivist_adapter_sdk::ScanClassification;
use rusqlite::Connection;
use rusqlite::types::ValueRef;

use crate::schema::{ALLOWED_TABLES, DetectError, SchemaDivergence, detect};
use crate::store_connection::StoreConnection;

/// The reader-side observation of one store: the five allowlisted tables,
/// in allowlist order, as of one transactional view.
///
/// The type is a plain data carrier — ordered rows, presence bits, raw
/// field bytes. Its [`fmt::Debug`] implementation is deliberately
/// content-free: rendering a snapshot is the projection's business, never
/// a log line's.
#[derive(Clone, PartialEq)]
pub struct Snapshot {
    tables: Vec<TableSnapshot>,
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Snapshot")
            .field("table_count", &self.tables.len())
            .finish()
    }
}

impl Snapshot {
    /// Take the snapshot of `store`: run the schema gate, then read the
    /// five allowlisted tables inside one read transaction.
    ///
    /// # Errors
    ///
    /// [`SnapshotError::Unsupported`] when the schema gate rejects the
    /// store — nothing was read; [`SnapshotError::Read`] when the gate's
    /// metadata probe or the transactional read could not complete,
    /// including a lock held past the store connection's busy window.
    /// Neither error carries schema, version, or content text.
    pub fn take(store: &StoreConnection) -> Result<Snapshot, SnapshotError> {
        let conn = store.connection();
        detect(conn).map_err(gate_error)?;
        read_tables(conn, &mut |_| {})
    }

    /// The five allowlisted table observations, in allowlist order.
    #[must_use]
    pub fn tables(&self) -> &[TableSnapshot] {
        &self.tables
    }
}

/// Why a snapshot could not be taken. A closed set of unit variants: the
/// type cannot carry a table name, a column name, a path, or any other
/// source-derived text, so no formatting — [`fmt::Display`] included —
/// can leak snapshot or store content into status, an error body, or a
/// log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SnapshotError {
    /// The schema gate rejected the store: no row content was read (plan
    /// `EC-08`).
    Unsupported(SchemaDivergence),
    /// The store could not be read this pass: a lock held past the busy
    /// window, a corrupt page, a driver failure.
    Read,
}

impl SnapshotError {
    /// The closed classification this snapshot outcome reports to the
    /// inventory: the value status retains as the source's last
    /// classification.
    #[must_use]
    pub fn classification(self) -> ScanClassification {
        match self {
            Self::Unsupported(_) => ScanClassification::FingerprintUnsupported,
            Self::Read => ScanClassification::ReadError,
        }
    }

    /// The content-free token naming this outcome: the whole message
    /// [`fmt::Display`] renders.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Unsupported(divergence) => divergence.token(),
            Self::Read => "opencode-snapshot-unreadable",
        }
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

impl std::error::Error for SnapshotError {}

/// One allowlisted table's observation: the allowlisted columns, the rows
/// in deterministic order, one cell per allowlisted column per row.
#[derive(Clone, PartialEq)]
pub struct TableSnapshot {
    name: &'static str,
    columns: &'static [&'static str],
    rows: Vec<Row>,
}

impl fmt::Debug for TableSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TableSnapshot")
            .field("name", &self.name)
            .field("column_count", &self.columns.len())
            .field("row_count", &self.rows.len())
            .finish()
    }
}

impl TableSnapshot {
    /// The allowlisted table name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The allowlisted column names, in allowlist order — the order every
    /// row's cells follow.
    #[must_use]
    pub fn columns(&self) -> &'static [&'static str] {
        self.columns
    }

    /// The rows in the snapshot's deterministic order.
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }
}

/// One row's observation: one cell per allowlisted column, in allowlist
/// order.
#[derive(Clone, PartialEq)]
pub struct Row {
    cells: Vec<Cell>,
}

impl fmt::Debug for Row {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Row")
            .field("cell_count", &self.cells.len())
            .finish()
    }
}

impl Row {
    /// The row's cells, one per allowlisted column, in allowlist order.
    #[must_use]
    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    /// The per-cell presence bits — `true` where the cell holds a value,
    /// `false` where it is NULL — in allowlist order. This is the
    /// null/presence half of the Phase 6 parity tuple.
    #[must_use]
    pub fn presence_bits(&self) -> Vec<bool> {
        self.cells.iter().map(Cell::is_present).collect()
    }
}

/// One cell's observed value: the storage class `SQLite` served plus the
/// raw bytes behind it.
///
/// The storage class is the value's own — a blob stored in a
/// text-declared column is a [`Cell::Blob`] — so the per-field digests
/// distinguish an integer `1` from the text `"1"` and a text value from a
/// byte-equal blob. Text bytes are preserved exactly as stored, valid
/// UTF-8 or not: the snapshot is an observation, not a decoder.
#[derive(Clone, PartialEq)]
pub enum Cell {
    /// The cell is NULL: the absent half of the presence bit.
    Null,
    /// A signed 64-bit integer.
    Integer(i64),
    /// A 64-bit IEEE-754 float. `SQLite` has no NaN representation — it
    /// stores NaN as NULL — so equality on this variant is well defined.
    Real(f64),
    /// A text value's exact stored bytes.
    Text(Vec<u8>),
    /// A blob's exact stored bytes.
    Blob(Vec<u8>),
}

impl fmt::Debug for Cell {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, byte_len) = match self {
            Self::Null => ("null", 0),
            Self::Integer(value) => ("integer", std::mem::size_of_val(value)),
            Self::Real(value) => ("real", std::mem::size_of_val(value)),
            Self::Text(bytes) => ("text", bytes.len()),
            Self::Blob(bytes) => ("blob", bytes.len()),
        };
        formatter
            .debug_struct("Cell")
            .field("kind", &kind)
            .field("byte_len", &byte_len)
            .finish()
    }
}

impl Cell {
    /// The presence bit: `false` only for [`Cell::Null`].
    #[must_use]
    pub fn is_present(&self) -> bool {
        !matches!(self, Self::Null)
    }

    /// The cell's raw bytes, the input the projection's per-field digests
    /// are taken over: integers as eight bytes big-endian, floats as
    /// IEEE-754 binary64 big-endian, text and blobs as the exact stored
    /// bytes, NULL as no bytes. The storage class lives in the variant,
    /// so digesting these bytes cannot confuse value classes a naive
    /// rendering would merge.
    #[must_use]
    pub fn raw_bytes(&self) -> Vec<u8> {
        match self {
            Self::Null => Vec::new(),
            Self::Integer(value) => value.to_be_bytes().to_vec(),
            Self::Real(value) => value.to_be_bytes().to_vec(),
            Self::Text(bytes) | Self::Blob(bytes) => bytes.clone(),
        }
    }

    /// Observe a driver value: the storage class as served, the bytes
    /// exactly as stored.
    fn observe(value: ValueRef<'_>) -> Self {
        match value {
            ValueRef::Null => Self::Null,
            ValueRef::Integer(value) => Self::Integer(value),
            ValueRef::Real(value) => Self::Real(value),
            ValueRef::Text(bytes) => Self::Text(bytes.to_vec()),
            ValueRef::Blob(bytes) => Self::Blob(bytes.to_vec()),
        }
    }
}

/// Why a gate rejection became a snapshot failure: both gate outcomes
/// land in the snapshot's closed vocabulary, so the caller classifies one
/// way regardless of which stage refused.
fn gate_error(error: DetectError) -> SnapshotError {
    match error {
        DetectError::Unsupported(divergence) => SnapshotError::Unsupported(divergence),
        DetectError::Read => SnapshotError::Read,
    }
}

/// Read the five allowlisted tables inside one read transaction on
/// `conn`, calling `after_table` with each table's allowlist index as its
/// observation completes — the seam the concurrency evidence drives a
/// concurrent writer through; production passes a no-op.
fn read_tables(
    conn: &Connection,
    after_table: &mut dyn FnMut(usize),
) -> Result<Snapshot, SnapshotError> {
    // A deferred transaction on this read-only connection: the first
    // table read acquires the read view, the commit releases it. Both
    // journal modes pin every read in the loop to that one view (see the
    // module docs).
    let txn = conn
        .unchecked_transaction()
        .map_err(|_| SnapshotError::Read)?;
    let mut tables = Vec::with_capacity(ALLOWED_TABLES.len());
    for (index, (table, columns)) in ALLOWED_TABLES.iter().enumerate() {
        tables.push(read_table(&txn, table, columns)?);
        after_table(index);
    }
    txn.commit().map_err(|_| SnapshotError::Read)?;
    Ok(Snapshot { tables })
}

/// Read one allowlisted table: exactly its allowlisted columns, ordered
/// deterministically. Every identifier comes from the compiled-in
/// allowlist, never from the store.
fn read_table(
    conn: &Connection,
    table: &'static str,
    columns: &'static [&'static str],
) -> Result<TableSnapshot, SnapshotError> {
    let query = allowlisted_query(table, columns);
    let mut statement = conn.prepare(&query).map_err(|_| SnapshotError::Read)?;
    let mut rows = statement.query([]).map_err(|_| SnapshotError::Read)?;
    let mut observed = Vec::new();
    while let Some(row) = rows.next().map_err(|_| SnapshotError::Read)? {
        let mut cells = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            let value = row.get_ref(index).map_err(|_| SnapshotError::Read)?;
            cells.push(Cell::observe(value));
        }
        observed.push(Row { cells });
    }
    Ok(TableSnapshot {
        name: table,
        columns,
        rows: observed,
    })
}

/// Build the one table read: the allowlisted columns in allowlist order,
/// ordered by all of them under `BINARY` collation so the observation's
/// row order is a function of the values alone.
///
/// The identifiers are this module's compiled-in constants — the driver
/// receives no store-derived text to interpolate. The quote-free property
/// the string building relies on is asserted next to the constants.
fn allowlisted_query(table: &str, columns: &[&str]) -> String {
    let mut sql = String::from("SELECT ");
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        sql.push('"');
        sql.push_str(column);
        sql.push('"');
    }
    sql.push_str(" FROM \"");
    sql.push_str(table);
    sql.push_str("\" ORDER BY ");
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        sql.push('"');
        sql.push_str(column);
        sql.push_str("\" COLLATE BINARY");
    }
    sql
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::{Connection, OpenFlags};

    use super::*;

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

    #[test]
    fn the_allowlisted_identifiers_are_interpolation_safe() {
        for (table, columns) in ALLOWED_TABLES {
            for hostile in ['"', '\'', ';'] {
                assert!(
                    !table.contains(hostile),
                    "a {hostile} in table {table} would break the quoted interpolation"
                );
                for column in *columns {
                    assert!(
                        !column.contains(hostile),
                        "a {hostile} in {table}.{column} would break the quoted interpolation"
                    );
                }
            }
        }
    }

    #[test]
    fn raw_bytes_are_canonical_and_presence_bits_track_null() {
        let cells = [
            Cell::Null,
            Cell::Integer(-2),
            Cell::Real(2.5),
            Cell::Text(b"m1".to_vec()),
            Cell::Blob(vec![0x00, 0xff, 0x80]),
        ];
        let present: Vec<bool> = cells.iter().map(Cell::is_present).collect();
        assert_eq!(present, [false, true, true, true, true]);

        let raw: Vec<Vec<u8>> = cells.iter().map(Cell::raw_bytes).collect();
        assert!(raw[0].is_empty(), "NULL digests no bytes");
        assert_eq!(raw[1], (-2i64).to_be_bytes());
        assert_eq!(raw[2], 2.5f64.to_be_bytes());
        assert_eq!(raw[3], b"m1");
        assert_eq!(raw[4], [0x00, 0xff, 0x80]);

        // The storage class survives: byte-equal text and blob cells stay
        // distinct observations, and an integer 1 is not the text "1".
        assert_ne!(Cell::Text(vec![1]), Cell::Blob(vec![1]));
        assert_ne!(
            Cell::Integer(1).raw_bytes(),
            Cell::Text(b"1".to_vec()).raw_bytes()
        );
    }

    #[test]
    fn a_writer_committing_between_table_reads_cannot_tear_the_snapshot() {
        // The strongest tearing window is a WAL store: the writer's
        // commits land while the reader holds its view, so each orphan
        // row below really is committed between two table reads. In a
        // rollback-journal store the same single transaction instead
        // makes the concurrent commit wait or fail busy — the
        // store-connection contention evidence — and tearing is
        // impossible by locking alone.
        let scratch = Scratch::new("concurrent-writer");
        let path = scratch.path().join("opencode.db");
        let writer = RefCell::new(seed_wal_store(&path));
        let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("the seeded WAL store opens read-only beside its writer");

        // After each table read, commit one orphan row that references a
        // session the snapshot's session view can never contain. If any
        // later table read saw its orphan, the snapshot would be torn:
        // the message read would carry m-orphan while the session read
        // had already missed s-never, and likewise down the chain.
        let snapshot = read_tables(&reader, &mut |index| {
            let orphan = match index {
                0 => Some(
                    "INSERT INTO message (id, session_id, data) \
                     VALUES ('m-orphan', 's-never', 'x');",
                ),
                1 => Some(
                    "INSERT INTO part (id, message_id, session_id, data) \
                     VALUES ('p-orphan', 'm-orphan', 's-never', 'x');",
                ),
                2 => Some(
                    "INSERT INTO session_input (id, session_id, prompt) \
                     VALUES ('i-orphan', 's-never', 'x');",
                ),
                3 => Some(
                    "INSERT INTO todo (session_id, content, status, priority, position) \
                     VALUES ('s-never', 'x', 'open', 'p2', 1);",
                ),
                _ => None,
            };
            if let Some(orphan) = orphan {
                writer
                    .borrow_mut()
                    .execute_batch(orphan)
                    .expect("the orphan commits mid-snapshot");
            }
        })
        .expect("the snapshot reads one transactional view");

        // The orphans really committed mid-snapshot, so their absence
        // from the observation is evidence, not a vacuous pass.
        let writer = writer.into_inner();
        let committed: i64 = writer
            .query_row(
                "SELECT count(*) FROM message WHERE id = 'm-orphan'",
                [],
                |row| row.get(0),
            )
            .expect("the orphan is countable after the snapshot");
        assert_eq!(committed, 1, "the orphan must be in the store");

        let ids = |snapshot: &Snapshot, table: &str| -> Vec<String> {
            let observed = snapshot
                .tables()
                .iter()
                .find(|observed| observed.name() == table)
                .expect("the allowlisted table is in the snapshot");
            observed
                .rows()
                .iter()
                .map(|row| match row.cells()[0] {
                    Cell::Text(ref bytes) => {
                        String::from_utf8(bytes.clone()).expect("the seeded id is utf-8")
                    }
                    ref cell => panic!("{table} ids are text, not {cell:?}"),
                })
                .collect()
        };
        assert_eq!(ids(&snapshot, "session"), ["s1"]);
        assert_eq!(
            ids(&snapshot, "message"),
            ["m1"],
            "m-orphan committed after the session read must be invisible"
        );
        assert_eq!(ids(&snapshot, "part"), ["p1"]);
        assert_eq!(ids(&snapshot, "session_input"), ["i1"]);
        // todo's first allowlisted column is session_id, not a unique id.
        let todos = snapshot
            .tables()
            .iter()
            .find(|observed| observed.name() == "todo")
            .expect("todo is in the snapshot");
        let todo_sessions: Vec<String> = todos
            .rows()
            .iter()
            .map(|row| match row.cells()[0] {
                Cell::Text(ref bytes) => {
                    String::from_utf8(bytes.clone()).expect("the seeded session is utf-8")
                }
                ref cell => panic!("todo sessions are text, not {cell:?}"),
            })
            .collect();
        assert_eq!(
            todo_sessions,
            ["s1"],
            "t-orphan committed mid-snapshot must be invisible"
        );
    }

    /// Open a WAL store holding the five allowlisted tables (plus two of
    /// the tables the real store legitimately holds) and seed one
    /// consistent chain: session s1, message m1, part p1, input i1, todo
    /// t1 — every row referencing only s1. The writer connection stays
    /// open: a read-only reader joins the WAL store through the live
    /// shared-memory index.
    fn seed_wal_store(path: &Path) -> Connection {
        let writer = Connection::open(path).expect("the seed store is creatable");
        let mode: String = writer
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .expect("the journal mode is readable");
        assert_eq!(mode, "wal", "the tearing window needs a WAL store");
        writer
            .execute_batch(
                r"
                CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT, title TEXT, version TEXT);
                CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT);
                CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT, data TEXT);
                CREATE TABLE session_input (id TEXT PRIMARY KEY, session_id TEXT, prompt TEXT);
                CREATE TABLE todo (session_id TEXT, content TEXT, status TEXT, priority TEXT, position INTEGER);
                CREATE TABLE account (id TEXT PRIMARY KEY, access_token TEXT);
                INSERT INTO session (id, project_id, title, version)
                    VALUES ('s1', 'project-a', 'a', '1.18.29');
                INSERT INTO message (id, session_id, data) VALUES ('m1', 's1', 'x');
                INSERT INTO part (id, message_id, session_id, data) VALUES ('p1', 'm1', 's1', 'x');
                INSERT INTO session_input (id, session_id, prompt) VALUES ('i1', 's1', 'x');
                INSERT INTO todo (session_id, content, status, priority, position)
                    VALUES ('s1', 'x', 'open', 'p2', 1);
                ",
            )
            .expect("the seed schema applies");
        writer
    }
}
