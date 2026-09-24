// SPDX-License-Identifier: Apache-2.0

//! The database parity oracle's end-to-end evidence (plan Phase 6's
//! Database-adapter parity decision; the `parity-mismatch-faults` gate row
//! and AC-07 in docs/security/threats/adapter-capture.md): the adapter's
//! projection and a completely independent direct read of the same store
//! produce the same observation — ordered allowlisted keys, row counts,
//! presence bits, class- and length-bound per-field digests — through the
//! SDK oracle, and every fault the acceptance names is detected and named:
//!
//! - **truncation** — the projection loses a trailing run of rows:
//!   `parity-truncated-rows`.
//! - **omission** — an interior row is lost: `parity-omitted-row`.
//! - **reordering** — rows served out of canonical key order:
//!   `parity-reordered`.
//! - **corruption** — an altered field, a value NULL-ed, a NULL filled
//!   in: `parity-corrupted-field`.
//! - **export truncation** — a multi-megabyte field exported as a strict
//!   byte prefix: `parity-corrupted-field` at the field's ordinal,
//!   because the digest binds the byte length — AC-07's silent-truncation
//!   attack, caught as an ordinary field divergence instead of an
//!   anything-goes fuzzy match.
//! - **accidental non-allowlisted reads** — a column-level authorizer on
//!   the adapter's own connection denies them at the driver while the
//!   honest read passes through untouched, and a stray column folded
//!   into an observation is named by its ordinal alone.
//!
//! The independence is the point (AC-07: the attacker is *a parity
//! implementation keyed to what the adapter already read*). The
//! source-side observation is built by this suite's own queries on its
//! own read-only connection — never from the adapter's snapshot,
//! projection, or types — so an oracle that re-derived one side from the
//! other could not pass here. And parity is the tuple, never a
//! database-file hash: churn committed in the excluded tables *between
//! the two reads* leaves the verdict `Equal` while the store file's own
//! digest changes — exactly the false divergence whole-database hashing
//! would have raised, and the reason the plan rejected it.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use archivist_adapter_opencode::{
    ALLOWED_TABLES, FieldValue, Json, Projection, Snapshot, StoreConnection,
};
use archivist_adapter_sdk::parity::{
    DatabaseObservation, Divergence, FieldDigest, FieldObservation, ObservedValue, RowObservation,
    StorageClass, TableObservation, Verdict, compare,
};
use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::types::ValueRef;

/// A unique scratch directory, removed when the test ends either way.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let unique = format!(
            "archivist-opencode-parity-oracle-{}-{}-{}",
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
/// the parity path must never observe.
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
/// session row. `extra` runs last so a test can seed rows on top of the
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
            {EXCLUDED_SCHEMA}
            {SESSION_ROW};
            {extra}
            "
        ))
        .expect("the seed schema applies");
    drop(writer);
    path
}

/// The allowlist ordinal of a table — the comparison-sequence position
/// the oracle's verdicts name it by.
fn table_index(table: &str) -> usize {
    ALLOWED_TABLES
        .iter()
        .position(|(name, _)| *name == table)
        .unwrap_or_else(|| panic!("{table} is an allowlisted table"))
}

/// The allowlist ordinal of one column of one table — the field position
/// a `parity-corrupted-field` verdict names it by.
fn column_index(table: &str, column: &str) -> usize {
    let (_, columns) = ALLOWED_TABLES
        .iter()
        .find(|(name, _)| *name == table)
        .unwrap_or_else(|| panic!("{table} is an allowlisted table"));
    columns
        .iter()
        .position(|name| *name == column)
        .unwrap_or_else(|| panic!("{column} is an allowlisted column of {table}"))
}

/// The allowlist positions of a table's key columns: the `id` column when
/// the table has one, every column otherwise (`todo`, which declares no
/// primary key — its full tuple is its identity, the same tuple the
/// store's row order sorts on).
fn key_positions(table: &str) -> Vec<usize> {
    let (_, columns) = ALLOWED_TABLES
        .iter()
        .find(|(name, _)| *name == table)
        .unwrap_or_else(|| panic!("{table} is an allowlisted table"));
    match columns.iter().position(|name| *name == "id") {
        Some(at) => vec![at],
        None => (0..columns.len()).collect(),
    }
}

/// The source-side observation: this suite's own queries on its own
/// read-only connection, one per allowlisted table, rows ordered by the
/// same deterministic collation the snapshot's own ordering uses — but
/// read and mapped here, independently of the adapter's snapshot,
/// projection, and types (AC-07).
fn source_observation(path: &Path) -> DatabaseObservation {
    let reader = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("the seeded store opens read-only");
    let mut tables = Vec::with_capacity(ALLOWED_TABLES.len());
    for (table, columns) in ALLOWED_TABLES {
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
        let mut statement = reader.prepare(&select).expect("the direct scan prepares");
        let mut scanned = statement.query([]).expect("the direct scan runs");
        let mut rows = Vec::new();
        while let Some(row) = scanned.next().expect("the direct scan row reads") {
            let values: Vec<ObservedValue> = (0..columns.len())
                .map(|index| {
                    observed_value(row.get_ref(index).expect("the direct column is served"))
                })
                .collect();
            let positions = key_positions(table);
            let key: Vec<ObservedValue> = positions.iter().map(|at| values[*at].clone()).collect();
            rows.push(RowObservation::observe(key, values));
        }
        tables.push(TableObservation::new(rows));
    }
    DatabaseObservation::new(tables)
}

/// The direct observation of one stored value — the same storage-class
/// mapping the snapshot applies to the driver's `ValueRef`, reached here
/// without a single adapter type.
fn observed_value(value: ValueRef<'_>) -> ObservedValue {
    match value {
        ValueRef::Null => ObservedValue::Null,
        ValueRef::Integer(value) => ObservedValue::Integer(value),
        ValueRef::Real(value) => ObservedValue::Real(value),
        ValueRef::Text(bytes) => ObservedValue::Text(bytes.to_vec()),
        ValueRef::Blob(bytes) => ObservedValue::Blob(bytes.to_vec()),
    }
}

/// The projection-side observation from the adapter's projected rows,
/// honestly: key and every allowlisted field in allowlist order.
fn projection_observation(projection: &Projection) -> DatabaseObservation {
    projection_observation_mutated(projection, &mut |_, _, _| {})
}

/// The projection-side observation with a fault injected: `mutate` sees
/// every row's field values before they are observed — the seam each
/// field-level fault (corruption, export truncation, a stray column) is
/// injected through, addressed by allowlist ordinals alone.
fn projection_observation_mutated(
    projection: &Projection,
    mutate: &mut dyn FnMut(usize, usize, &mut Vec<ObservedValue>),
) -> DatabaseObservation {
    let mut tables = Vec::with_capacity(ALLOWED_TABLES.len());
    for (table, columns) in ALLOWED_TABLES {
        let table_at = table_index(table);
        let mut rows = Vec::new();
        for projected in projection.rows().iter().filter(|row| row.table() == *table) {
            let mut fields: Vec<ObservedValue> = projected
                .fields()
                .iter()
                .map(|(_, value)| match value {
                    FieldValue::Null => ObservedValue::Null,
                    FieldValue::Integer(value) => ObservedValue::Integer(*value),
                    FieldValue::Real(value) => ObservedValue::Real(*value),
                    FieldValue::Text(text) => ObservedValue::Text(text.as_bytes().to_vec()),
                })
                .collect();
            debug_assert_eq!(
                fields.len(),
                columns.len(),
                "a projected row carries one field per allowlisted column"
            );
            let row_at = rows.len();
            mutate(table_at, row_at, &mut fields);
            let key: Vec<ObservedValue> = projected
                .key()
                .iter()
                .map(|value| match value {
                    Json::Null => ObservedValue::Null,
                    Json::Integer(value) => ObservedValue::Integer(*value),
                    Json::Real(value) => ObservedValue::Real(*value),
                    Json::Text(text) => ObservedValue::Text(text.as_bytes().to_vec()),
                    other => panic!("a projected key is scalar, not {other:?}"),
                })
                .collect();
            rows.push(RowObservation::observe(key, fields));
        }
        tables.push(TableObservation::new(rows));
    }
    DatabaseObservation::new(tables)
}

/// Rebuild `observation` with one table's rows replaced — the seam the
/// structural faults (truncation, omission, reordering) are injected
/// through.
fn with_rows(
    observation: &DatabaseObservation,
    table: usize,
    rows: Vec<RowObservation>,
) -> DatabaseObservation {
    let mut tables: Vec<TableObservation> = observation.tables().to_vec();
    tables[table] = TableObservation::new(rows);
    DatabaseObservation::new(tables)
}

/// Snapshot and project the store at `path` — the adapter side, exactly
/// as production takes it.
fn project(path: &Path) -> Projection {
    let store = StoreConnection::open(path).expect("the seeded store opens");
    let snapshot = Snapshot::take(&store).expect("the supported store snapshots");
    Projection::project(&snapshot).expect("the seeded store projects")
}

#[test]
fn the_projection_parities_with_an_independent_direct_read() {
    // Rows inserted out of key order, with NULLs, boundary integers,
    // reals, and non-ASCII text — every storage class the allowlist
    // declares that has a faithful canonical form — across all five
    // tables. No two todo rows are value-identical: todo's key is its
    // full tuple, so a value-identical pair would order ambiguously.
    let scratch = Scratch::new("honest");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO session (id, project_id, slug, title, version, cost,
                               summary_additions, tokens_input, model, share_url)
             VALUES ('session-c', 'p', 'c', 'third', '1.18.29', 2.5,
                     -12, 0, 'model-x', 'https://é.example/s-c'),
                    ('session-b', 'p', 'b', 'second', '1.18.29', -0.5,
                     NULL, NULL, NULL, NULL);
         INSERT INTO message (id, session_id, time_created, time_updated, data)
             VALUES ('m3', 'session-a', NULL, 3, 'third σ'),
                    ('m1', 'session-a', -9223372036854775808, NULL, 'first'),
                    ('m2', 'session-a', 9223372036854775807, 2, 'second');
         INSERT INTO part (id, message_id, session_id, data)
             VALUES ('p2', 'm2', 'session-a', 'part of m2'),
                    ('p1', 'm1', 'session-a', 'part of m1');
         INSERT INTO session_input (id, session_id, prompt, delivery, admitted_seq)
             VALUES ('i2', 'session-a', NULL, NULL, 7),
                    ('i1', 'session-a', 'the prompt', 'tty', 3);
         INSERT INTO todo (session_id, content, status, priority, position, time_created)
             VALUES ('session-a', 'todo-b', 'open', 'p1', 2, 700),
                    ('session-a', 'todo-a', 'done', 'p2', 1, NULL);",
    );

    let projection_side = projection_observation(&project(&path));
    let source_side = source_observation(&path);

    // Not vacuous: every allowlisted table is populated.
    for (index, (table, _)) in ALLOWED_TABLES.iter().enumerate() {
        assert!(
            !source_side.tables()[index].rows().is_empty(),
            "{table} is populated, so its parity is evidence"
        );
    }

    // The parity decision holds: identical ordered keys, row counts,
    // presence bits, and per-field digests against a read the adapter
    // never participated in.
    assert_eq!(
        compare(&source_side, &projection_side),
        Verdict::Equal,
        "the projection parities with the independent direct read"
    );

    // Determinism: a second pass over both sides decides identically.
    assert_eq!(
        compare(
            &source_observation(&path),
            &projection_observation(&project(&path))
        ),
        Verdict::Equal
    );
}

#[test]
fn a_lost_trailing_run_of_rows_is_named_truncation() {
    // The reader-stopped-early shape: the projection carries a strict
    // prefix of one table's rows. The verdict names the class and the
    // count — table and row ordinals only, never a key value.
    let scratch = Scratch::new("truncation");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data)
             VALUES ('m1', 'session-a', 'first'),
                    ('m2', 'session-a', 'second'),
                    ('m3', 'session-a', 'third'),
                    ('m4', 'session-a', 'fourth');",
    );

    let source = source_observation(&path);
    let projection_side = projection_observation(&project(&path));
    assert_eq!(
        compare(&source, &projection_side),
        Verdict::Equal,
        "the honest projection parities before the fault is injected"
    );

    let message = table_index("message");
    let mut rows = projection_side.tables()[message].rows().to_vec();
    rows.truncate(rows.len() - 2);
    let truncated = with_rows(&projection_side, message, rows);

    assert_eq!(
        compare(&source, &truncated),
        Verdict::Diverges(vec![Divergence::TruncatedRows {
            table: message,
            rows: 2,
        }]),
        "a lost trailing run is truncation, not two omissions"
    );
}

#[test]
fn an_interior_lost_row_is_named_omission() {
    // A hole before the tail: the reader dropped one row but kept
    // reading after it. Losing the tail too would keep the interior hole
    // named — it is not a trailing run.
    let scratch = Scratch::new("omission");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data)
             VALUES ('m1', 'session-a', 'first'),
                    ('m2', 'session-a', 'second'),
                    ('m3', 'session-a', 'third'),
                    ('m4', 'session-a', 'fourth');",
    );

    let source = source_observation(&path);
    let projection_side = projection_observation(&project(&path));

    let message = table_index("message");
    let mut rows = projection_side.tables()[message].rows().to_vec();
    rows.remove(1);
    let omitted = with_rows(&projection_side, message, rows);

    assert_eq!(
        compare(&source, &omitted),
        Verdict::Diverges(vec![Divergence::OmittedRow {
            table: message,
            source_row: 1,
        }]),
        "an interior hole is omission at its source ordinal"
    );

    // An interior hole plus the lost tail: every lost row is named, so
    // the tail loss cannot disguise the interior omission.
    let mut rows = projection_side.tables()[message].rows().to_vec();
    rows.remove(1);
    rows.truncate(rows.len() - 1);
    let mixed = with_rows(&projection_side, message, rows);
    assert_eq!(
        compare(&source, &mixed),
        Verdict::Diverges(vec![
            Divergence::OmittedRow {
                table: message,
                source_row: 1,
            },
            Divergence::OmittedRow {
                table: message,
                source_row: 3,
            },
        ]),
        "an interior omission and a tail loss each keep their name"
    );
}

#[test]
fn an_out_of_order_projection_is_named_reordering() {
    // Every row present, but served out of canonical key order — the
    // shape of a projection path that lost the store's deterministic
    // ordering. The verdict names the class, not the cascade of spurious
    // omissions and inventions an unsorted walk would manufacture.
    let scratch = Scratch::new("reordering");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO message (id, session_id, data)
             VALUES ('m1', 'session-a', 'first'),
                    ('m2', 'session-a', 'second'),
                    ('m3', 'session-a', 'third'),
                    ('m4', 'session-a', 'fourth');",
    );

    let source = source_observation(&path);
    let projection_side = projection_observation(&project(&path));

    let message = table_index("message");
    let mut rows = projection_side.tables()[message].rows().to_vec();
    rows.swap(1, 2);
    let swapped = with_rows(&projection_side, message, rows);

    assert_eq!(
        compare(&source, &swapped),
        Verdict::Diverges(vec![Divergence::Reordered {
            table: message,
            row: 2,
        }]),
        "out-of-order rows are reordering, at the first fall"
    );
}

#[test]
fn altered_null_ed_and_filled_fields_are_named_corruption() {
    // Three field-level faults in one comparison: altered bytes on one
    // row, a NULL filled in on the same row, and a value NULL-ed on a
    // later row. The verdict names each at its table, row, and field
    // ordinal — the presence-bit flips land as corruption exactly like
    // byte drift.
    let scratch = Scratch::new("corruption");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO session (id, project_id, slug, title, version, cost, share_url)
             VALUES ('session-c', 'p', 'c', 'third', '1.18.29', 2.5, NULL),
                    ('session-b', 'p', 'b', 'second', '1.18.29', -0.5, NULL);",
    );

    let source = source_observation(&path);
    let projection_side = projection_observation(&project(&path));
    assert_eq!(
        compare(&source, &projection_side),
        Verdict::Equal,
        "the honest projection parities before the faults are injected"
    );

    let session = table_index("session");
    let title = column_index("session", "title");
    let share_url = column_index("session", "share_url");
    let cost = column_index("session", "cost");
    // Rows in canonical order: session-a (the seed row), session-b,
    // session-c.
    let session_b = 1;
    let session_c = 2;

    let corrupted = projection_observation_mutated(&project(&path), &mut |table, row, fields| {
        if table != session {
            return;
        }
        if row == session_b {
            // Altered bytes on a present field, and a NULL filled in.
            let ObservedValue::Text(bytes) = &mut fields[title] else {
                panic!("session-b's title is text");
            };
            bytes.push(b'!');
            fields[share_url] = ObservedValue::Text(b"https://invented.example/".to_vec());
        } else if row == session_c {
            // A present value NULL-ed: the presence bit flips the other
            // way.
            fields[cost] = ObservedValue::Null;
        }
    });

    assert_eq!(
        compare(&source, &corrupted),
        Verdict::Diverges(vec![
            Divergence::CorruptedField {
                table: session,
                source_row: session_b,
                field: title,
            },
            Divergence::CorruptedField {
                table: session,
                source_row: session_b,
                field: share_url,
            },
            Divergence::CorruptedField {
                table: session,
                source_row: session_c,
                field: cost,
            },
        ]),
        "each field fault is named at its ordinal, in comparison order"
    );
}

#[test]
fn an_export_truncated_large_field_is_named_corruption() {
    // AC-07's silent-truncation attack: a multi-megabyte field exported
    // as a strict byte prefix of itself. The honest projection parities
    // first — the whole value, tail included — so the divergence below
    // is the truncation, not a seeding artifact. The digest's
    // length-binding is what makes a prefix detectable: no fuzzy match,
    // an ordinary field divergence at the field's ordinal.
    let payload = "m§σ𝄞\\\"x\n".repeat(160 * 1024);
    let large = format!("{payload}TAIL-prompt");

    let scratch = Scratch::new("export-truncation");
    let sql_text = large.replace('\'', "''");
    let path = seed_store(
        scratch.path(),
        &format!(
            "INSERT INTO session_input (id, session_id, prompt)
                 VALUES ('i-large', 'session-a', '{sql_text}');"
        ),
    );

    let source = source_observation(&path);
    let input = table_index("session_input");
    let prompt = column_index("session_input", "prompt");

    // The positive control: the whole field flows through the real
    // projection into the observation and parities.
    let projection_side = projection_observation(&project(&path));
    assert_eq!(
        compare(&source, &projection_side),
        Verdict::Equal,
        "the whole multi-megabyte field parities before the fault"
    );
    // The whole value's class- and length-bound digest — the observation
    // is content-free, so the digest equality is the proof the entire
    // payload, tail included, flowed through the projection.
    assert_eq!(
        projection_side.tables()[input].rows()[0].fields()[prompt],
        FieldObservation::Present(FieldDigest::of(StorageClass::Text, large.as_bytes())),
        "the observed field is the whole value's digest"
    );

    // Half the bytes: an export cut mid-value.
    let halved = projection_observation_mutated(&project(&path), &mut |table, _, fields| {
        if table == input {
            let ObservedValue::Text(bytes) = &mut fields[prompt] else {
                panic!("the large prompt observes as text");
            };
            bytes.truncate(bytes.len() / 2);
        }
    });
    assert_eq!(
        compare(&source, &halved),
        Verdict::Diverges(vec![Divergence::CorruptedField {
            table: input,
            source_row: 0,
            field: prompt,
        }]),
        "half the bytes is corruption at the field ordinal"
    );

    // One byte short: the sharpest silent truncation, equally named.
    let short = projection_observation_mutated(&project(&path), &mut |table, _, fields| {
        if table == input {
            let ObservedValue::Text(bytes) = &mut fields[prompt] else {
                panic!("the large prompt observes as text");
            };
            bytes.truncate(bytes.len() - 1);
        }
    });
    assert_eq!(
        compare(&source, &short),
        Verdict::Diverges(vec![Divergence::CorruptedField {
            table: input,
            source_row: 0,
            field: prompt,
        }]),
        "a one-byte-short export is corruption too"
    );
}

#[test]
fn churn_in_excluded_tables_between_the_reads_leaves_parity_intact() {
    // The no-whole-database-hashing proof, both halves: credential and
    // cache rows commit *between* the adapter's read and this suite's
    // independent read, the store file's own digest changes — so a
    // whole-database hash would have raised a false divergence — and the
    // oracle's verdict stays `Equal`, because the parity tuple is
    // confined to the allowlist and never hashed the churn at all.
    let scratch = Scratch::new("excluded-churn");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO account (id, email, access_token, refresh_token)
             VALUES ('acct-1', 'a@example.com', 'planted-access-token', 'planted-refresh');
         INSERT INTO credential (id, label, value)
             VALUES ('cred-1', 'l', 'planted-credential-value');
         INSERT INTO cache (key, payload) VALUES ('k', 'planted-cache-payload');
         INSERT INTO message (id, session_id, data) VALUES ('m1', 'session-a', 'first');",
    );

    // The adapter's observation, taken before the churn exists.
    let projection_side = projection_observation(&project(&path));
    let bytes_before = fs::read(&path).expect("the store bytes are readable");
    let digest_before = FieldDigest::of(StorageClass::Blob, &bytes_before);

    // The churn: a second writer connection commits new credential,
    // provider-auth, and cache rows — an account token rotated, a
    // credential deleted, a cache entry replaced. Every write lands in
    // an excluded table.
    let writer = Connection::open(&path).expect("the churn writer opens");
    writer
        .execute_batch(
            r"
            UPDATE account SET access_token = 'rotated-second-token' WHERE id = 'acct-1';
            DELETE FROM credential WHERE id = 'cred-1';
            INSERT INTO provider_auth (id, provider_id, api_key)
                VALUES ('pa-1', 'provider', 'planted-api-key');
            INSERT INTO cache (key, payload) VALUES ('k2', 'second-cache-payload');
            UPDATE cache SET payload = 'replaced-cache-payload' WHERE key = 'k';
            ",
        )
        .expect("the excluded-table churn commits");
    let accounts: i64 = writer
        .query_row("SELECT count(*) FROM account", [], |row| row.get(0))
        .expect("the churn is countable");
    drop(writer);
    assert_eq!(accounts, 1, "the churn updated the one excluded row");

    // The store bytes really changed — a whole-file digest sees it.
    let bytes_after = fs::read(&path).expect("the churned store bytes are readable");
    let digest_after = FieldDigest::of(StorageClass::Blob, &bytes_after);
    assert_ne!(
        digest_before, digest_after,
        "the churn must change the store bytes, or the comparison proves nothing"
    );

    // The independent read happens after the churn and still parities
    // with the pre-churn projection: neither side ever observed the
    // excluded tables, so the changed bytes cannot reach the verdict.
    let source = source_observation(&path);
    assert_eq!(
        compare(&source, &projection_side),
        Verdict::Equal,
        "excluded-table churn between the reads cannot diverge parity"
    );
}

#[test]
fn the_read_path_cannot_touch_a_non_allowlisted_column() {
    // The column-level authorizer binding: reads of exactly the
    // allowlisted (table, column) pairs — plus the schema metadata the
    // gate probes — pass; every other read is denied at the driver. The
    // honest adapter read completes untouched under it (and still
    // parities), while an accidental read of a credential column on the
    // very same connection fails: detection at the driver, not
    // after-the-fact filtering.
    let scratch = Scratch::new("authorizer");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO account (id, email, access_token, refresh_token)
             VALUES ('acct-1', 'a@example.com', 'planted-access-token', 'planted-refresh');
         INSERT INTO message (id, session_id, data) VALUES ('m1', 'session-a', 'first');",
    );

    let store = StoreConnection::open(&path).expect("the seeded store opens");
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
                let allowlisted = table_name == "sqlite_master"
                    || ALLOWED_TABLES.iter().any(|(table, columns)| {
                        *table == table_name && columns.contains(&column_name)
                    });
                if !allowlisted {
                    // An accidental non-allowlisted read: denied here,
                    // before any row is served.
                    return Authorization::Deny;
                }
                logged
                    .lock()
                    .expect("the read log locks")
                    .push((table_name.to_owned(), column_name.to_owned()));
            }
            Authorization::Allow
        }))
        .expect("the authorizer installs");

    // The honest read passes through untouched: the full snapshot,
    // projection, and parity decision all complete under the binding.
    let snapshot = Snapshot::take(&store).expect("an allowlisted read needs no denied column");
    let projection = Projection::project(&snapshot).expect("the allowlisted store projects");
    assert_eq!(
        compare(
            &source_observation(&path),
            &projection_observation(&projection)
        ),
        Verdict::Equal,
        "parity holds under the column-level binding"
    );

    // Every read the adapter made — gate metadata included — is an
    // allowlisted pair; the log is the full record, since a denied read
    // never reaches it.
    let recorded = reads.lock().expect("the read log locks").clone();
    assert!(!recorded.is_empty(), "the adapter read something");
    for (table, column) in &recorded {
        let pair_allowlisted = table == "sqlite_master"
            || ALLOWED_TABLES
                .iter()
                .any(|(name, columns)| name == table && columns.contains(&column.as_str()));
        assert!(
            pair_allowlisted,
            "the adapter read {table}.{column}, which the allowlist never declared"
        );
    }

    // The binding detects an accidental non-allowlisted read: a
    // credential column, on the same connection, behind the same
    // authorizer, fails at the driver.
    assert!(
        store
            .connection()
            .prepare("SELECT access_token FROM account")
            .is_err(),
        "the credential-column read must be denied"
    );
    // And the denial is the column, not the connection: an allowlisted
    // read beside it still serves.
    assert!(
        store
            .connection()
            .prepare("SELECT data FROM message")
            .is_ok(),
        "an allowlisted read still passes"
    );
}

#[test]
fn a_stray_non_allowlisted_column_in_the_observation_is_named_by_ordinal() {
    // The oracle's own face of the same fault: an accidental read that
    // did make it into the observation — a column the allowlist never
    // declared, folded into a projected row — diverges the comparison at
    // the first field ordinal the two sides stop sharing, and the
    // verdict names no part of the planted content.
    let scratch = Scratch::new("stray-column");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO account (id, access_token) VALUES ('acct-1', 'planted-access-token');",
    );

    let source = source_observation(&path);
    let session = table_index("session");
    let session_columns = ALLOWED_TABLES
        .iter()
        .find(|(name, _)| *name == "session")
        .expect("session is an allowlisted table")
        .1
        .len();

    let projection_side =
        projection_observation_mutated(&project(&path), &mut |table, row, fields| {
            if table == session && row == 0 {
                // The stray column, carrying planted credential content.
                fields.push(ObservedValue::Text(b"planted-access-token".to_vec()));
            }
        });

    let verdict = compare(&source, &projection_side);
    assert_eq!(
        verdict,
        Verdict::Diverges(vec![Divergence::CorruptedField {
            table: session,
            source_row: 0,
            field: session_columns,
        }]),
        "a stray column diverges at the first unshared field ordinal"
    );

    // Content-freedom: no rendering of the verdict carries the planted
    // value the stray column held.
    let Verdict::Diverges(divergences) = verdict else {
        panic!("the stray column must diverge");
    };
    for divergence in &divergences {
        let rendered = format!("{divergence}");
        let debugged = format!("{divergence:?}");
        assert!(
            !rendered.contains("planted-access-token"),
            "leak: {rendered}"
        );
        assert!(
            !debugged.contains("planted-access-token"),
            "leak: {debugged}"
        );
    }
}
