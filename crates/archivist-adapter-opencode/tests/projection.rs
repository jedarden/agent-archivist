// SPDX-License-Identifier: Apache-2.0

//! The projection acceptance evidence (plan Phase 6B; the "database
//! key/count/presence/per-field-digest parity" and "verify large fields
//! against direct database reads" adapter tests): every allowlisted row
//! projects to exactly one canonical JSONL record; the Phase 6 parity
//! tuple — keys, order, row counts, null/presence bits, and per-field
//! digests — reconciles against direct database reads; large fields match
//! direct reads byte-exactly so export truncation is caught; the excluded
//! account, token, credential, provider-auth, and cache tables — and a
//! new unexpected column — never reach a record; and a cell with no
//! faithful canonical form fails the projection closed instead of
//! exporting a partial record.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use archivist_adapter_opencode::{
    Cell, FieldValue, Json, ProjectedRow, Projection, ProjectionError, SchemaDivergence, Snapshot,
    SnapshotError, StoreConnection, ALLOWED_TABLES,
};
use archivist_adapter_sdk::ScanClassification;
use rusqlite::types::ValueRef;
use rusqlite::Connection;

/// A unique scratch directory, removed when the test ends either way.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let unique = format!(
            "archivist-opencode-projection-{}-{}-{}",
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

/// The excluded tables the real store legitimately holds among its other
/// tables — the account and provider-auth rows carry planted credentials
/// the projection must never render.
const EXCLUDED_SCHEMA: &str = r"
    CREATE TABLE account (
        id TEXT PRIMARY KEY, email TEXT, url TEXT, access_token TEXT,
        refresh_token TEXT, token_expiry INTEGER, time_created INTEGER, time_updated INTEGER
    );
    CREATE TABLE credential (
        id TEXT PRIMARY KEY, integration_id TEXT, label TEXT, value TEXT,
        connector_id TEXT, method_id TEXT, active INTEGER,
        time_created INTEGER, time_updated INTEGER
    );
    CREATE TABLE provider_auth (
        id TEXT PRIMARY KEY, provider_id TEXT, user_id TEXT, api_key TEXT,
        time_created INTEGER, time_updated INTEGER
    );
    CREATE TABLE cache (
        key TEXT PRIMARY KEY, payload TEXT, time_created INTEGER
    );
";

/// Create the five allowlisted tables with exactly the embedded
/// allowlist's columns, the excluded tables above, and one minimal
/// session row. `extra` runs last so a test can seed rows — hostile or
/// otherwise — on top of the supported shape. The store is at
/// `<dir>/opencode.db`.
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
            {EXCLUDED_SCHEMA}
            {SESSION_ROW};
            {extra}
            "
        ))
        .expect("the seed schema applies");
    drop(writer);
    path
}

/// Project the store at `path` after taking its snapshot.
fn project(path: &Path) -> Projection {
    let snapshot = Snapshot::take(&StoreConnection::open(path).expect("the seeded store opens"))
        .expect("the supported store snapshots");
    Projection::project(&snapshot).expect("the seeded store projects")
}

/// A read-only direct connection to the seeded store — the side the
/// parity tuple is reconciled against.
fn direct(path: &Path) -> Connection {
    Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("the seeded store opens read-only")
}

/// The test's per-field digest: FNV-1a over the raw bytes paired with the
/// byte length. The digest is the parity comparison's own input pairing,
/// not an artifact identity, so it stays dependency-free — the adapter's
/// one external dependency is the driver.
fn digest(bytes: &[u8]) -> (u64, usize) {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash, bytes.len())
}

/// The direct observation of one stored value, the same storage-class
/// mapping the snapshot applies to the driver's `ValueRef`.
fn direct_cell(value: ValueRef<'_>) -> Cell {
    match value {
        ValueRef::Null => Cell::Null,
        ValueRef::Integer(value) => Cell::Integer(value),
        ValueRef::Real(value) => Cell::Real(value),
        ValueRef::Text(bytes) => Cell::Text(bytes.to_vec()),
        ValueRef::Blob(bytes) => Cell::Blob(bytes.to_vec()),
    }
}

/// The projected rows of one table, in projection order.
fn rows_of<'a>(projection: &'a Projection, name: &str) -> Vec<&'a ProjectedRow> {
    projection
        .rows()
        .iter()
        .filter(|row| row.table() == name)
        .collect()
}

/// The test-side key parameter of one projected key value: the key
/// columns are TEXT or INTEGER across the allowlist, so nothing else is
/// reachable.
fn key_param(value: &Json) -> rusqlite::types::Value {
    match value {
        Json::Null => rusqlite::types::Value::Null,
        Json::Text(text) => rusqlite::types::Value::Text(text.clone()),
        Json::Integer(value) => rusqlite::types::Value::Integer(*value),
        other => panic!("a projected key is text or integer, not {other:?}"),
    }
}

/// The `Json` a direct key cell must project back to.
fn key_json(cell: &Cell) -> Json {
    match cell {
        Cell::Null => Json::Null,
        Cell::Text(bytes) => {
            Json::Text(String::from_utf8(bytes.clone()).expect("the seeded key is utf-8"))
        }
        Cell::Integer(value) => Json::Integer(*value),
        other => panic!("a seeded key cell is text or integer, not {other:?}"),
    }
}

/// The allowlist positions of a table's key columns: the `id` column when
/// the table has one, every column otherwise (`todo`, which has no id —
/// its full tuple is its identity, the same tuple the snapshot's row
/// order sorts on).
fn key_positions(columns: &[&str]) -> Vec<usize> {
    match columns.iter().position(|name| *name == "id") {
        Some(at) => vec![at],
        None => (0..columns.len()).collect(),
    }
}

#[test]
fn every_allowlisted_row_projects_to_one_canonical_record() {
    let scratch = Scratch::new("shape");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data) VALUES ('m1', 'session-a', 'x');
         INSERT INTO todo (session_id, content, status, priority, position)
             VALUES ('session-a', 't1', 'open', 'p2', 1);",
    );

    let projection = project(&path);

    // One record per allowlisted row: the seeded session, message, and
    // todo, and nothing outside the allowlist.
    assert_eq!(projection.rows().len(), 3);

    // The record shape is fixed and fully canonical: members sorted, no
    // whitespace, `null` where the cell is NULL.
    let message = rows_of(&projection, "message")[0];
    assert_eq!(
        String::from_utf8(message.record().canonical_bytes()).expect("utf8"),
        "{\"fields\":{\"data\":\"x\",\"id\":\"m1\",\"session_id\":\"session-a\",\
          \"time_created\":null,\"time_updated\":null},\"key\":[\"m1\"],\"table\":\"message\"}"
    );

    // todo has no id column: its key is its full allowlisted tuple, NULLs
    // included — the same tuple the snapshot's row order is built on.
    let todo = rows_of(&projection, "todo")[0];
    assert_eq!(
        String::from_utf8(todo.record().canonical_bytes()).expect("utf8"),
        "{\"fields\":{\"content\":\"t1\",\"position\":1,\"priority\":\"p2\",\
          \"session_id\":\"session-a\",\"status\":\"open\",\"time_created\":null,\
          \"time_updated\":null},\
          \"key\":[\"session-a\",\"t1\",\"open\",\"p2\",1,null,null],\"table\":\"todo\"}"
    );

    // The JSONL stream is exactly the records — newline-terminated, in
    // projection order — and canonical escaping keeps every record on one
    // line, so the stream splits back into the records one for one.
    let jsonl = projection.jsonl();
    let mut expected = Vec::new();
    for row in projection.rows() {
        expected.extend_from_slice(&row.record().canonical_bytes());
        expected.push(b'\n');
    }
    assert_eq!(
        jsonl, expected,
        "the stream is the records in projection order"
    );
    let lines: Vec<&[u8]> = jsonl.split(|byte| *byte == b'\n').collect();
    assert_eq!(
        lines.len(),
        projection.rows().len() + 1,
        "one line per record"
    );
    assert!(
        lines
            .last()
            .expect("the split ends with the trailing newline")
            .is_empty(),
        "the stream ends with a newline"
    );

    // Two projections of the same store are byte-identical.
    assert_eq!(
        project(&path).jsonl(),
        jsonl,
        "the projection is deterministic"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_parity_tuple_reconciles_against_direct_database_reads() {
    // Seeded out of key order, with NULLs, boundary integers, a float,
    // and non-ASCII text: every storage class the allowlist declares. No
    // two todo rows are value-identical — todo's key is its full tuple,
    // so a value-identical pair would re-fetch ambiguously (the
    // determinism of that case is the snapshot suite's evidence).
    let scratch = Scratch::new("parity");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO session (id, project_id, slug, title, version, cost,
                               summary_additions, tokens_input, model, share_url)
             VALUES ('session-c', 'p', 'c', 'third', '1.18.29', 2.5,
                     -12, 0, 'model-x', 'https://é.example/s-c'),
                    ('session-b', 'p', 'b', 'second', '1.18.29', -0.5,
                     NULL, NULL, NULL, NULL);
         INSERT INTO message (id, session_id, time_created, time_updated, data)
             VALUES ('m2', 'session-a', -9223372036854775808, NULL, 'second message'),
                    ('m1', 'session-a', NULL, 9223372036854775807, 'first message');
         INSERT INTO part (id, message_id, session_id, data)
             VALUES ('p1', 'm1', 'session-a', 'part of m1');
         INSERT INTO session_input (id, session_id, prompt, delivery, admitted_seq, promoted_seq)
             VALUES ('i1', 'session-a', 'the prompt', 'tty', 3, 3);
         INSERT INTO todo (session_id, content, status, priority, position, time_created)
             VALUES ('session-a', 'todo-b', 'open', 'p1', 2, 700),
                    ('session-a', 'todo-a', 'done', 'p2', 1, NULL);",
    );

    let projection = project(&path);
    let reader = direct(&path);

    for (table, columns) in ALLOWED_TABLES {
        let projected = rows_of(&projection, table);

        // Row counts: the projection carries exactly the store's rows.
        let stored: i64 = reader
            .query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |row| {
                row.get(0)
            })
            .expect("the table is countable");
        assert_eq!(
            projected.len(),
            usize::try_from(stored).expect("the seeded row count fits usize"),
            "{table}: the projected row count matches the store"
        );

        // One direct ordered observation of every allowlisted column, in
        // the snapshot's own deterministic order.
        let mut select = String::from("SELECT ");
        for (index, column) in columns.iter().enumerate() {
            if index > 0 {
                select.push_str(", ");
            }
            let _ = write!(select, "\"{column}\"");
        }
        let mut order = String::new();
        for column in *columns {
            if !order.is_empty() {
                order.push_str(", ");
            }
            let _ = write!(order, "\"{column}\" COLLATE BINARY");
        }
        let _ = write!(select, " FROM \"{table}\" ORDER BY {order}");
        let mut statement = reader.prepare(&select).expect("the scan prepares");
        let mut scanned = statement.query([]).expect("the scan runs");
        let mut direct_rows: Vec<Vec<Cell>> = Vec::new();
        while let Some(row) = scanned.next().expect("the scan row reads") {
            let mut cells = Vec::with_capacity(columns.len());
            for index in 0..columns.len() {
                cells.push(direct_cell(
                    row.get_ref(index).expect("the column is served"),
                ));
            }
            direct_rows.push(cells);
        }
        assert_eq!(
            direct_rows.len(),
            projected.len(),
            "{table}: the direct scan and the projection agree on how many rows exist"
        );

        let positions = key_positions(columns);
        for (row, cells) in projected.iter().zip(&direct_rows) {
            // Order and keys: the projected key tuple is the direct row's
            // key columns, in the scan's order — projection order and row
            // order are one property.
            let expected_key: Vec<Json> = positions
                .iter()
                .map(|index| key_json(&cells[*index]))
                .collect();
            assert_eq!(
                row.key(),
                &expected_key[..],
                "{table}: the projected key tuple matches the direct row"
            );

            // Null bits and per-field digests, cell by cell: the
            // projected field digests exactly as the direct read of the
            // same stored value, and carries its presence bit.
            for ((name, field), cell) in row.fields().iter().zip(cells) {
                assert_eq!(
                    matches!(field, FieldValue::Null),
                    matches!(cell, Cell::Null),
                    "{table}.{name}: the projected null bit matches the direct read"
                );
                assert_eq!(
                    digest(&field.raw_bytes()),
                    digest(&cell.raw_bytes()),
                    "{table}.{name}: the projected per-field digest matches the direct read"
                );
            }

            // The key tuple identifies the row: re-fetching by it — with
            // null-safe predicates, since todo's tuple can carry NULLs —
            // serves exactly that row back, fields and all.
            let mut fetched = String::from("SELECT ");
            for (index, column) in columns.iter().enumerate() {
                if index > 0 {
                    fetched.push_str(", ");
                }
                let _ = write!(fetched, "\"{column}\"");
            }
            let _ = write!(fetched, " FROM \"{table}\" WHERE ");
            let mut parameters = Vec::new();
            for (position, index) in positions.iter().enumerate() {
                if position > 0 {
                    fetched.push_str(" AND ");
                }
                let _ = write!(fetched, "\"{}\" IS ?", columns[*index]);
                parameters.push(key_param(&row.key()[position]));
            }
            let mut fetch_statement = reader.prepare(&fetched).expect("the re-fetch prepares");
            let mut matched = fetch_statement
                .query(rusqlite::params_from_iter(parameters.iter()))
                .expect("the re-fetch runs");
            let mut refetched: Vec<Vec<Cell>> = Vec::new();
            while let Some(row) = matched.next().expect("the re-fetch row reads") {
                let mut cells = Vec::with_capacity(columns.len());
                for index in 0..columns.len() {
                    cells.push(direct_cell(row.get_ref(index).expect("served")));
                }
                refetched.push(cells);
            }
            assert_eq!(
                refetched.len(),
                1,
                "{table}: the key tuple re-fetches one row"
            );
            for ((name, field), cell) in row.fields().iter().zip(&refetched[0]) {
                assert_eq!(
                    digest(&field.raw_bytes()),
                    digest(&cell.raw_bytes()),
                    "{table}.{name}: the re-fetched row's digest matches the projection"
                );
            }
        }
    }

    // The seed genuinely carries every storage class the loop reconciled
    // — two REAL cells, boundary integers, and NULLs — so the pass is not
    // vacuous.
    let floats: i64 = reader
        .query_row(
            "SELECT count(*) FROM session WHERE cost IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .expect("the float probe counts");
    assert_eq!(floats, 2, "both seeded REAL cells were digested");
    let nulls: i64 = reader
        .query_row(
            "SELECT count(*) FROM message WHERE time_created IS NULL",
            [],
            |row| row.get(0),
        )
        .expect("the null probe counts");
    assert_eq!(nulls, 1, "a seeded NULL cell was digested");
}

#[test]
fn large_fields_match_direct_reads() {
    // Multi-megabyte payloads with a distinctive tail: a truncating
    // export loses the tail or the pattern's interior, and the byte
    // comparison against the direct read fails. The payloads also carry
    // quotes, backslashes, control characters, and non-BMP text, so the
    // canonical escaping is exercised at scale, not only in unit tests.
    let megabyte = "m§σ𝄞\\\"x\n".repeat(96 * 1024);
    let large_message = format!("{megabyte}TAIL-message");
    let large_part = format!("{megabyte}TAIL-part");
    let large_prompt = format!("{megabyte}TAIL-prompt");

    let scratch = Scratch::new("large");
    let sql_text = |value: &str| value.replace('\'', "''");
    let path = seed_store(
        scratch.path(),
        &format!(
            "INSERT INTO message (id, session_id, data)
                 VALUES ('m-large', 'session-a', '{}');
             INSERT INTO part (id, message_id, session_id, data)
                 VALUES ('p-large', 'm-large', 'session-a', '{}');
             INSERT INTO session_input (id, session_id, prompt)
                 VALUES ('i-large', 'session-a', '{}');",
            sql_text(&large_message),
            sql_text(&large_part),
            sql_text(&large_prompt),
        ),
    );

    let projection = project(&path);
    let reader = direct(&path);

    // The projected payload of each large row is byte-identical to the
    // direct read of the same stored value — the whole value, tail
    // included.
    for (table, column, id, expected) in [
        ("message", "data", "m-large", &large_message),
        ("part", "data", "p-large", &large_part),
        ("session_input", "prompt", "i-large", &large_prompt),
    ] {
        let row = rows_of(&projection, table)
            .into_iter()
            .find(|row| row.key() == &[Json::Text(id.to_owned())][..])
            .unwrap_or_else(|| panic!("{table}: the large row projects"));
        let fields: Vec<&(&str, FieldValue)> = row
            .fields()
            .iter()
            .filter(|(name, _)| *name == column)
            .collect();
        assert_eq!(fields.len(), 1, "{table}: one payload column");
        let FieldValue::Text(projected) = &fields[0].1 else {
            panic!("{table}: the large payload projects as text");
        };
        assert_eq!(
            projected, expected,
            "{table}: the projected large field matches the direct read, tail included"
        );

        // The same comparison in the parity tuple's form: the projected
        // per-field digest equals a digest over the direct cell.
        let direct_bytes: Vec<u8> = reader
            .query_row(
                &format!("SELECT \"{column}\" FROM \"{table}\" WHERE id = ?1"),
                [id],
                |row| Ok(row.get_ref(0)?.as_bytes()?.to_vec()),
            )
            .expect("the large cell is directly readable");
        assert_eq!(
            digest(projected.as_bytes()),
            digest(&direct_bytes),
            "{table}: the per-field digest matches the direct read"
        );

        // The canonical stream carries the whole record: the payload's
        // tail survives into the JSONL bytes.
        let tail = match table {
            "message" => "TAIL-message",
            "part" => "TAIL-part",
            "session_input" => "TAIL-prompt",
            _ => unreachable!("only large text fields are checked"),
        };
        assert!(
            projection
                .jsonl()
                .windows(tail.len())
                .any(|window| window == tail.as_bytes()),
            "{table}: the canonical JSONL carries the untruncated tail"
        );
    }
}

#[test]
fn excluded_tables_never_reach_a_record() {
    // Planted credentials in every excluded table, plus a hostile extra
    // table and view on top: none of it has a projection path.
    let scratch = Scratch::new("allowlist-negatives");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO account (id, email, access_token, refresh_token)
             VALUES ('acct-1', 'a@example.com', 'planted-access-token', 'planted-refresh');
         INSERT INTO credential (id, label, value)
             VALUES ('cred-1', 'l', 'planted-credential-value');
         INSERT INTO provider_auth (id, provider_id, api_key)
             VALUES ('pa-1', 'provider', 'planted-api-key');
         INSERT INTO cache (key, payload) VALUES ('k', 'planted-cache-payload');
         CREATE TABLE password_cache (id TEXT PRIMARY KEY, secret TEXT);
         INSERT INTO password_cache (id, secret) VALUES ('planted', 'planted-secret');
         CREATE VIEW credential_view AS SELECT id, value FROM credential;
         INSERT INTO message (id, session_id) VALUES ('m1', 'session-a');",
    );

    let projection = project(&path);
    let rendered = String::from_utf8(projection.jsonl()).expect("the canonical stream is utf-8");

    // No planted value renders anywhere in the stream.
    for planted in [
        "planted-access-token",
        "planted-refresh",
        "planted-credential-value",
        "planted-api-key",
        "planted-cache-payload",
        "planted-secret",
        "a@example.com",
    ] {
        assert!(
            !rendered.contains(planted),
            "a planted value leaked: {planted}"
        );
    }

    // No record names an excluded table, and every record names an
    // allowlisted one.
    for excluded in [
        "account",
        "credential",
        "provider_auth",
        "cache",
        "password_cache",
    ] {
        assert!(
            !rendered.contains(&format!("\"table\":\"{excluded}\"")),
            "an excluded table produced records: {excluded}"
        );
    }
    for table in projection.rows().iter().map(ProjectedRow::table) {
        assert!(
            ALLOWED_TABLES.iter().any(|(name, _)| *name == table),
            "only allowlisted tables project: {table}"
        );
    }

    // The record count is the allowlisted rows alone: the seed holds one
    // session and one message, and the excluded tables' rows — however
    // many — add nothing.
    let reader = direct(&path);
    let mut allowlisted_rows = 0;
    for (table, _) in ALLOWED_TABLES {
        let stored: i64 = reader
            .query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |row| {
                row.get(0)
            })
            .expect("the table is countable");
        allowlisted_rows += usize::try_from(stored).expect("the seeded row count fits usize");
    }
    assert_eq!(
        projection.rows().len(),
        allowlisted_rows,
        "every projected record is an allowlisted row"
    );
    assert_eq!(rows_of(&projection, "message").len(), 1);
}

#[test]
fn a_new_unexpected_column_excludes_the_store_before_any_projection() {
    // The allowlist cannot "skip" a column the source grew: the schema
    // gate refuses the store first, so the new column's planted content
    // is never read, never rendered — exclusion happens before any
    // projected content exists, not by filtering records afterwards.
    let scratch = Scratch::new("new-column");
    let path = seed_store(
        scratch.path(),
        "ALTER TABLE message ADD COLUMN overshare TEXT;
         INSERT INTO message (id, session_id, overshare)
             VALUES ('m1', 'session-a', 'planted-new-column');",
    );

    let store = StoreConnection::open(&path).expect("the divergent store opens");
    let error = Snapshot::take(&store).expect_err("the divergent store must not snapshot");

    assert_eq!(
        error,
        SnapshotError::Unsupported(SchemaDivergence::ColumnDivergence),
    );
    assert_eq!(
        error.classification(),
        ScanClassification::FingerprintUnsupported
    );
    assert!(
        !format!("{error}").contains("planted-new-column"),
        "the rejection names no content"
    );

    // The refusal is not a fluke of one attempt: the store never has a
    // snapshot to project.
    assert!(
        Snapshot::take(&store).is_err(),
        "the gate rejects the store every time"
    );
}

#[test]
fn an_unrepresentable_cell_fails_the_projection_closed() {
    // A blob in an allowlisted column has no faithful canonical form: the
    // projection returns no records at all, rather than an export with
    // the row silently dropped or mangled.
    let scratch = Scratch::new("blob");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data) VALUES ('m1', 'session-a', x'00ff80');",
    );
    let snapshot = Snapshot::take(&StoreConnection::open(&path).expect("the seeded store opens"))
        .expect("the supported store snapshots");
    let error = Projection::project(&snapshot).expect_err("a blob cannot project");

    assert_eq!(error, ProjectionError::Unrepresentable);
    assert_eq!(error.classification(), ScanClassification::ReadError);
    assert_eq!(format!("{error}"), error.token());
    assert_eq!(error.token(), "opencode-projection-unrepresentable");
    assert!(
        !format!("{error:?}").contains("00ff"),
        "Debug names no content"
    );

    // Text that is not valid UTF-8 is equally unrepresentable.
    let scratch = Scratch::new("non-utf8");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO part (id, message_id, session_id, data)
             VALUES ('p1', 'm', 'session-a', CAST(x'ff' AS TEXT));",
    );
    let snapshot = Snapshot::take(&StoreConnection::open(&path).expect("the seeded store opens"))
        .expect("the supported store snapshots");
    let error = Projection::project(&snapshot).expect_err("invalid utf-8 cannot project");
    assert_eq!(error, ProjectionError::Unrepresentable);

    // A non-finite float has no RFC 8785 form — and SQLite stores
    // infinities, so the branch is reachable from a real store.
    let scratch = Scratch::new("infinite");
    let path = seed_store(scratch.path(), "UPDATE session SET cost = 9e999;");
    let snapshot = Snapshot::take(&StoreConnection::open(&path).expect("the seeded store opens"))
        .expect("the supported store snapshots");
    let error = Projection::project(&snapshot).expect_err("an infinite real cannot project");
    assert_eq!(error, ProjectionError::Unrepresentable);
}
