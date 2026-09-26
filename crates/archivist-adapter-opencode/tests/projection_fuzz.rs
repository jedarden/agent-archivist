// SPDX-License-Identifier: Apache-2.0

//! The adapter-projection fuzz suite (plan Phase 11 "Fuzz ... adapter
//! projections"): deterministic pseudo-random hostile inputs against the
//! assembled reader — [`StoreConnection::open`] through [`Snapshot::take`]
//! to [`Projection::project`] — asserting the fail-closed acceptance
//! properties the Phase 6B contracts promise, over input spaces the
//! deterministic fault suite cannot enumerate:
//!
//! - **Hostile source bytes** — truncations, single-byte flips, and
//!   spliced garbage at randomized offsets can never crash the reader or
//!   invent a classification outside the closed vocabulary, and a damaged
//!   store the reader does admit is still observed deterministically
//!   (the same damaged bytes observe identically twice).
//! - **Corruption and truncation are detected** — destroying the file
//!   header's magic or truncating it below the header never yields a
//!   projected snapshot.
//! - **Unknown schemas remain unread** — randomized divergences (extra,
//!   renamed, dropped columns; dropped tables; view substitution; hostile
//!   version strings shaped like injection attempts) always land on the
//!   schema gate, and an authorizer proves no projected column was read
//!   on the way to the rejection.
//! - **Forbidden columns are never accessed** — extra hostile tables
//!   planted with credential-shaped columns stay unread even when the
//!   schema is otherwise admitted, and every read a successful scan makes
//!   lands on an allowlisted `(table, column)` pair.
//! - **Content never enters crash output** — oversized and hostile cells
//!   (markers, format strings, control bytes) planted at randomized
//!   positions never reach a rendering surface.
//! - **Ordering is a function of content** — two stores holding the same
//!   logical rows inserted in different physical orders observe and
//!   project identically.
//! - **Disappearing sources** — a store whose bytes vanish or turn to
//!   garbage before a fresh read classifies closed; nothing projected is
//!   served from a store that is no longer the one that was seeded.
//!
//! Every loop is driven by a fixed-seed linear-congruential generator, so
//! a failure reproduces from the seed named in the assertion message.

use std::fmt::Write as _;
use std::fs;
use std::io::{Seek, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use archivist_adapter_opencode::{
    ALLOWED_TABLES, Cell, Projection, ProjectionError, SchemaDivergence, Snapshot, SnapshotError,
    StoreConnection, StoreOpenError,
};
use archivist_adapter_sdk::ScanClassification;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, OpenFlags, params_from_iter};

/// The seed-content marker planted in the template store's excluded
/// tables: no rendering surface may ever carry it.
const SECRET_MARKER: &str = "do-not-read";
/// The markers the randomized cell loops plant into allowlisted columns:
/// no rendering surface may carry these either.
const CELL_MARKERS: [&str; 3] = ["FUZZLEAK", "nul\0byte-", "{:?}%s"];

/// A unique scratch directory, removed when the test ends either way.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let unique = format!(
            "archivist-opencode-fuzz-{name}-{}-{}",
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

/// A deterministic linear-congruential generator: the property tests must
/// be reproducible, so no external RNG and no time seeding.
struct Deterministic(u64);

impl Deterministic {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.next() & 0xff).expect("masked to eight bits")
    }

    fn offset_within(&mut self, len: usize) -> usize {
        usize::try_from(self.below(u64::try_from(len).expect("length fits u64"))).expect("fits")
    }
}

/// The one seeded content store every byte-mutation loop copies: the
/// allowlisted schema (plus two of the tables the real store legitimately
/// holds) with a small consistent session chain, and excluded tables
/// carrying [`SECRET_MARKER`] values. Journal mode stays at the rollback
/// default so the single file is self-contained once the writer drops.
fn seed_template_store(path: &Path) {
    let writer = Connection::open(path).expect("the seed store is creatable");
    writer
        .execute_batch(
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
            CREATE TABLE account (id TEXT PRIMARY KEY, access_token TEXT);
            CREATE TABLE credential (id TEXT PRIMARY KEY, value TEXT);
            INSERT INTO session (id, project_id, slug, title, version)
                VALUES ('session-a', 'project-a', 'a', 't', '1.18.29');
            INSERT INTO message (id, session_id, data) VALUES ('m1', 'session-a', 'x');
            INSERT INTO part (id, message_id, session_id, data)
                VALUES ('p1', 'm1', 'session-a', 'x');
            INSERT INTO session_input (id, session_id, prompt) VALUES ('i1', 'session-a', 'x');
            INSERT INTO todo (session_id, content, status, priority, position)
                VALUES ('session-a', 'x', 'open', 'p2', 1);
            INSERT INTO account (id, access_token) VALUES ('acc1', 'do-not-read');
            INSERT INTO credential (id, value) VALUES ('cred1', 'do-not-read');
            ",
        )
        .expect("the seed schema applies");
    drop(writer);
}

/// Create the allowlisted schema with no rows at all: an empty store the
/// gate must still admit (the version probe finds no divergent row).
fn seed_schema_only(path: &Path) {
    seed_template_store(path);
    let writer = Connection::open(path).expect("the store reopens");
    writer
        .execute_batch(
            "DELETE FROM todo; DELETE FROM session_input; DELETE FROM part;
             DELETE FROM message; DELETE FROM session;
             DELETE FROM account; DELETE FROM credential;",
        )
        .expect("the seed rows clear");
    drop(writer);
}

/// The `(table, column)` pairs a read touched, as recorded by an
/// authorizer installed on `store` — the tripwire that turns "the
/// allowlist is compiled in" into observed evidence.
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

/// Whether a rejected read log touched gate metadata only: the schema
/// index, plus at most the version discriminator column.
fn reads_are_metadata_only(recorded: &[(String, String)]) -> bool {
    recorded.iter().all(|(table, column)| {
        table == "sqlite_master" || (table == "session" && column == "version")
    })
}

/// Whether a successful read log touched only allowlisted pairs (plus the
/// schema index).
fn reads_are_allowlisted(recorded: &[(String, String)]) -> bool {
    recorded.iter().all(|(table, column)| {
        table == "sqlite_master"
            || ALLOWED_TABLES
                .iter()
                .any(|(allowed, columns)| allowed == table && columns.contains(&column.as_str()))
    })
}

/// The closed error vocabularies render content-free: the token is the
/// whole message, and the token leaves the lowercase-and-dash alphabet for
/// nothing.
fn assert_open_rendering_is_closed(error: StoreOpenError) {
    let rendered = format!("{error}");
    assert!(
        rendered.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
        "the rendered open error {rendered} leaves the closed token vocabulary"
    );
    assert_eq!(rendered, error.classification().token());
}

fn assert_take_rendering_is_closed(error: SnapshotError) {
    let rendered = format!("{error}");
    assert!(
        rendered.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
        "the rendered snapshot error {rendered} leaves the closed token vocabulary"
    );
    assert_eq!(rendered, error.token());
}

/// The outcome of one full reader pass over a possibly hostile store.
enum Outcome {
    OpenFailed(StoreOpenError),
    SnapshotFailed(SnapshotError),
    Snapshot(Snapshot),
}

fn read_pipeline(path: &Path) -> Outcome {
    let store = match StoreConnection::open_with_busy_timeout(path, Duration::ZERO) {
        Ok(store) => store,
        Err(error) => return Outcome::OpenFailed(error),
    };
    match Snapshot::take(&store) {
        Err(error) => Outcome::SnapshotFailed(error),
        Ok(snapshot) => Outcome::Snapshot(snapshot),
    }
}

/// Assert the two failure shapes stay inside their closed vocabularies.
fn assert_failure_is_closed(outcome: &Outcome) {
    match outcome {
        Outcome::OpenFailed(error) => assert_open_rendering_is_closed(*error),
        Outcome::SnapshotFailed(error) => assert_take_rendering_is_closed(*error),
        Outcome::Snapshot(_) => unreachable!("only failure shapes are asserted here"),
    }
}

/// Debug renderings of every observation node stay shape-only and bounded:
/// no seed content and no planted cell marker can reach one.
fn assert_snapshot_rendering_is_content_free(snapshot: &Snapshot) {
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
    for marker in CELL_MARKERS {
        assert!(
            !rendered.contains(marker),
            "a rendering carried a planted marker"
        );
    }
    assert!(
        !rendered.contains(SECRET_MARKER),
        "a rendering carried seed content"
    );
}

/// The allowlisted row count of a snapshot, table by table.
fn snapshot_rows(snapshot: &Snapshot) -> usize {
    snapshot
        .tables()
        .iter()
        .map(|table| table.rows().len())
        .sum()
}

#[test]
fn fuzz_hostile_source_bytes_fail_closed_and_stay_content_free() {
    let scratch = Scratch::new("byte-corruption");
    let template_path = scratch.path().join("template.db");
    seed_template_store(&template_path);
    let pristine = fs::read(&template_path).expect("the template is readable");
    assert!(pristine.len() > 512, "the template spans past its header");
    let mutant_a = scratch.path().join("mutant-a.db");
    let mutant_b = scratch.path().join("mutant-b.db");

    for iteration in 0..96_u64 {
        let mut deterministic = Deterministic::new(0xa11c_e550_1e55_0000 ^ iteration);
        let mut damaged = pristine.clone();
        apply_random_damage(&mut damaged, &mut deterministic);

        fs::write(&mutant_a, &damaged).expect("the mutant is writable");
        let outcome = read_pipeline(&mutant_a);
        match &outcome {
            Outcome::Snapshot(snapshot) => {
                // A damaged store the reader admitted is still observed
                // deterministically: the same damaged bytes, read fresh,
                // observe identically — no nondeterministic tail of a torn
                // page can leak into the observation.
                fs::write(&mutant_b, &damaged).expect("the twin mutant is writable");
                match read_pipeline(&mutant_b) {
                    Outcome::Snapshot(again) => assert_eq!(
                        snapshot, &again,
                        "iteration {iteration}: the same damaged bytes must observe identically"
                    ),
                    Outcome::OpenFailed(_) | Outcome::SnapshotFailed(_) => {
                        panic!("iteration {iteration}: a readable mutant stopped being readable")
                    }
                }
                // The projection agrees with whatever the observation
                // carried, or fails closed — never a partial export.
                if let Ok(projected) = Projection::project(snapshot) {
                    assert_eq!(
                        projected.rows().len(),
                        snapshot_rows(snapshot),
                        "iteration {iteration}: one record per observed row"
                    );
                }
                assert_snapshot_rendering_is_content_free(snapshot);
            }
            // A failure must stay inside its closed vocabulary; an
            // admitted observation is legitimate damage too — SQLite
            // checksums nothing, so a flip outside the read paths is
            // unobservable and a flip inside them is served as content —
            // and the twin above pins its determinism either way.
            Outcome::OpenFailed(_) | Outcome::SnapshotFailed(_) => {
                assert_failure_is_closed(&outcome);
            }
        }
    }
}

/// Apply one or two randomized damages: a truncation, a single-byte flip,
/// a spliced garbage window, or a zeroed window.
fn apply_random_damage(bytes: &mut Vec<u8>, deterministic: &mut Deterministic) {
    let damages = 1 + deterministic.below(2);
    for _ in 0..damages {
        match deterministic.below(4) {
            0 => {
                let at = deterministic.offset_within(bytes.len());
                bytes.truncate(at);
            }
            1 => {
                let at = deterministic.offset_within(bytes.len());
                bytes[at] ^= 0xff;
            }
            2 => {
                let window =
                    usize::try_from(1 + deterministic.below(64)).expect("window fits usize");
                let fresh: Vec<u8> = (0..window).map(|_| deterministic.byte()).collect();
                let at = deterministic.offset_within(bytes.len().saturating_sub(window));
                bytes[at..at + window].copy_from_slice(&fresh);
            }
            _ => {
                let window =
                    usize::try_from(1 + deterministic.below(64)).expect("window fits usize");
                let at = deterministic.offset_within(bytes.len().saturating_sub(window));
                bytes[at..at + window].fill(0);
            }
        }
    }
}

#[test]
fn fuzz_header_and_truncation_damage_is_always_detected() {
    let scratch = Scratch::new("header-damage");
    let template_path = scratch.path().join("template.db");
    seed_template_store(&template_path);
    let pristine = fs::read(&template_path).expect("the template is readable");
    let mutant = scratch.path().join("mutant.db");

    // Corrupting any byte of the 16-byte file magic must prevent a
    // projected snapshot: the file is no longer a database, and the
    // pipeline has no path that projects it anyway.
    for (offset, byte) in pristine.iter().take(16).enumerate() {
        let mut damaged = pristine.clone();
        damaged[offset] = byte ^ 0xff;
        fs::write(&mutant, &damaged).expect("the mutant is writable");
        let outcome = read_pipeline(&mutant);
        assert!(
            !matches!(outcome, Outcome::Snapshot(_)),
            "offset {offset}: a corrupted file header projected a snapshot"
        );
        assert_failure_is_closed(&outcome);
    }

    // Truncating the file into its header — the first hundred bytes carry
    // the magic, the page sizes, and the schema format — must prevent a
    // projected snapshot too: truncation at these scales is always
    // detected, never silently projected.
    for length in 0..100_usize {
        let mut damaged = pristine.clone();
        damaged.truncate(length);
        fs::write(&mutant, &damaged).expect("the mutant is writable");
        let outcome = read_pipeline(&mutant);
        assert!(
            !matches!(outcome, Outcome::Snapshot(_)),
            "length {length}: a header-truncated store projected a snapshot"
        );
        assert_failure_is_closed(&outcome);
    }
}

/// What the schema gate must produce for one hostile-schema mutation, and
/// what the read log may contain on the way there.
enum Expectation {
    /// The gate must reject with exactly this divergence; the read log
    /// stays gate-metadata-only.
    Reject(SchemaDivergence),
    /// The gate must admit; the scan reads only allowlisted pairs, and the
    /// observation matches the unmated baseline.
    Admit,
}

/// What a mutation plants in the version discriminator: nothing at all,
/// a NULL version, or a hostile text version.
enum VersionPlant {
    /// The mutation does not target the discriminator.
    None,
    /// One extra `session` row carrying a NULL version.
    Null,
    /// One extra `session` row carrying this hostile text version.
    Text(String),
}

/// One hostile-schema mutation applied to a freshly seeded store.
struct Mutation {
    name: &'static str,
    sql: Vec<String>,
    version_row: VersionPlant,
    expected: Expectation,
}

/// The hostile-schema mutation space: divergences shaped like real
/// renames, hidden widenings, substitutions, and injection attempts.
fn mutation_plan() -> Vec<Mutation> {
    let hostile_columns = [
        "overshare",
        "extra\"col",
        "col; DROP TABLE session",
        "col'--",
        "hidden_token",
    ];
    let hostile_versions: [Option<String>; 9] = [
        Some("9.9.9".to_owned()),
        Some("1.18.29 ".to_owned()),
        Some(" 1.18.29".to_owned()),
        Some("1.18.29' OR '1'='1".to_owned()),
        Some("1.18.29\"; DELETE FROM message; --".to_owned()),
        Some(String::new()),
        Some("\u{ff11}.\u{ff11}\u{ff18}.\u{ff12}\u{ff19}".to_owned()),
        Some("1.18.290".to_owned()),
        None,
    ];
    let hostile_tables = ["token_cache", "x\"; DROP TABLE session--", "auth_secret"];

    let mut plan = Vec::new();

    // Extra columns on every allowlisted table, with injection-shaped
    // names: set comparison must reject a widening whatever its bytes.
    for (index, name) in hostile_columns.iter().enumerate() {
        let (table, _) = ALLOWED_TABLES[index];
        let quoted = name.replace('"', "\"\"");
        plan.push(Mutation {
            name: "extra-column",
            sql: vec![format!(
                r#"ALTER TABLE "{table}" ADD COLUMN "{quoted}" TEXT"#
            )],
            version_row: VersionPlant::None,
            expected: Expectation::Reject(SchemaDivergence::ColumnDivergence),
        });
    }

    // Rename and drop a trailing column of the first two tables.
    for (table, columns) in ALLOWED_TABLES.iter().take(2) {
        let renamed = columns[columns.len() - 1];
        plan.push(Mutation {
            name: "renamed-column",
            sql: vec![format!(
                r#"ALTER TABLE "{table}" RENAME COLUMN "{renamed}" TO "renamed_away""#
            )],
            version_row: VersionPlant::None,
            expected: Expectation::Reject(SchemaDivergence::ColumnDivergence),
        });
        plan.push(Mutation {
            name: "dropped-column",
            sql: vec![format!(r#"ALTER TABLE "{table}" DROP COLUMN "{renamed}""#)],
            version_row: VersionPlant::None,
            expected: Expectation::Reject(SchemaDivergence::ColumnDivergence),
        });
    }

    // A dropped table, and a view standing in for one: both are the same
    // absence to the gate — the allowlisted name is not a table.
    for dropped in ["message", "todo"] {
        plan.push(Mutation {
            name: "dropped-table",
            sql: vec![format!(r#"DROP TABLE "{dropped}""#)],
            version_row: VersionPlant::None,
            expected: Expectation::Reject(SchemaDivergence::MissingTable),
        });
    }
    plan.push(Mutation {
        name: "view-substitution",
        sql: vec![
            "DROP TABLE part".to_owned(),
            "CREATE VIEW part AS SELECT * FROM message".to_owned(),
        ],
        version_row: VersionPlant::None,
        expected: Expectation::Reject(SchemaDivergence::MissingTable),
    });

    // Hostile version strings, including the SQL-injection shapes a
    // fingerprint-allowlist bypass attempt would try — plus NULL.
    for version in hostile_versions {
        plan.push(Mutation {
            name: "hostile-version",
            sql: Vec::new(),
            version_row: match version {
                Some(text) => VersionPlant::Text(text),
                None => VersionPlant::Null,
            },
            expected: Expectation::Reject(SchemaDivergence::UnknownVersion),
        });
    }

    // Extra hostile tables with credential-shaped columns must not widen
    // what is read: the gate admits, the scan never touches them.
    for table in hostile_tables {
        let quoted = table.replace('"', "\"\"");
        plan.push(Mutation {
            name: "hostile-extra-table",
            sql: vec![format!(
                r#"CREATE TABLE "{quoted}" (id TEXT PRIMARY KEY, api_key TEXT)"#
            )],
            version_row: VersionPlant::None,
            expected: Expectation::Admit,
        });
    }
    plan
}

#[test]
fn fuzz_hostile_schema_mutations_stay_unread_and_allowlist_confined() {
    let scratch = Scratch::new("schema-mutations");
    let baseline_path = scratch.path().join("baseline.db");
    seed_template_store(&baseline_path);
    let baseline = StoreConnection::open(&baseline_path).expect("the baseline opens");
    let expected_baseline = Snapshot::take(&baseline).expect("the baseline snapshots");
    drop(baseline);

    for (round, mutation) in mutation_plan().into_iter().enumerate() {
        let path = scratch.path().join(format!("mutant-{round}.db"));
        seed_template_store(&path);
        apply_mutation(&path, &mutation);

        let store = StoreConnection::open(&path)
            .unwrap_or_else(|error| panic!("round {round} ({}) opens: {error}", mutation.name));
        let reads = record_reads(&store);
        let taken = Snapshot::take(&store);
        match (&mutation.expected, taken) {
            (Expectation::Reject(divergence), Err(SnapshotError::Unsupported(observed))) => {
                assert_eq!(
                    observed, *divergence,
                    "round {round} ({}) diverged wrong",
                    mutation.name
                );
                assert_eq!(
                    SnapshotError::Unsupported(observed).classification(),
                    ScanClassification::FingerprintUnsupported,
                    "round {round}: every divergence classifies unsupported"
                );
                // Fail closed: the attempt read gate metadata and at most
                // the version discriminator — never a projected column.
                let recorded = reads.lock().expect("the read log locks").clone();
                assert!(
                    reads_are_metadata_only(&recorded),
                    "round {round} ({}) read past the gate: {recorded:?}",
                    mutation.name
                );
            }
            (Expectation::Admit, Ok(snapshot)) => {
                assert_eq!(
                    snapshot, expected_baseline,
                    "round {round} ({}) let the mutation change the observation",
                    mutation.name
                );
                let recorded = reads.lock().expect("the read log locks").clone();
                assert!(
                    reads_are_allowlisted(&recorded),
                    "round {round} ({}) read a forbidden column: {recorded:?}",
                    mutation.name
                );
            }
            // A mutation can also break the reader's own allowlisted
            // query (a renamed discriminator column): the attempt still
            // fails closed as a read error, and nothing past the gate
            // was read.
            (Expectation::Reject(_), Err(SnapshotError::Read)) => {
                let recorded = reads.lock().expect("the read log locks").clone();
                assert!(
                    reads_are_metadata_only(&recorded),
                    "round {round} ({}) read past the gate: {recorded:?}",
                    mutation.name
                );
            }
            (Expectation::Reject(_), Ok(_)) => {
                panic!(
                    "round {round} ({}) admitted a divergent schema",
                    mutation.name
                )
            }
            (Expectation::Admit, Err(error)) => panic!(
                "round {round} ({}) rejected an admissible schema: {error:?}",
                mutation.name
            ),
        }
    }
}

/// Apply one mutation to the seeded store at `path`.
fn apply_mutation(path: &Path, mutation: &Mutation) {
    let writer = Connection::open(path).expect("the mutant reopens for mutation");
    for statement in &mutation.sql {
        writer
            .execute_batch(statement)
            .unwrap_or_else(|error| panic!("mutation {} applies sql: {error}", mutation.name));
    }
    match &mutation.version_row {
        VersionPlant::None => {}
        VersionPlant::Null => {
            writer
                .execute(
                    "INSERT INTO session (id, version) VALUES ('s-hostile', NULL)",
                    [],
                )
                .expect("the NULL version row plants");
        }
        VersionPlant::Text(text) => {
            writer
                .execute(
                    "INSERT INTO session (id, version) VALUES ('s-hostile', ?1)",
                    [text],
                )
                .expect("the hostile version row plants");
        }
    }
    drop(writer);
}

/// One planted cell value, carrying whether the projection can represent
/// it faithfully.
#[derive(Clone)]
enum Planted {
    Null,
    Integer(i64),
    Real(f64),
    /// Valid UTF-8 text, possibly carrying markers and format strings.
    Text(String),
    /// Bytes planted through `CAST(? AS TEXT)` so the storage class is
    /// text while the bytes are not valid UTF-8 — always unrepresentable.
    HostileText(Vec<u8>),
    Blob(Vec<u8>),
}

impl Planted {
    fn unrepresentable(&self) -> bool {
        match self {
            Self::Real(value) => !value.is_finite(),
            Self::HostileText(_) | Self::Blob(_) => true,
            Self::Null | Self::Integer(_) | Self::Text(_) => false,
        }
    }

    /// The parameter value and the SQL fragment that binds it: a plain
    /// slot, or a cast that plants bytes into the text class.
    fn binding(&self) -> (Value, &'static str) {
        match self {
            Self::Null => (Value::Null, "?"),
            Self::Integer(value) => (Value::Integer(*value), "?"),
            Self::Real(value) => (Value::Real(*value), "?"),
            Self::Text(text) => (Value::Text(text.clone()), "?"),
            Self::HostileText(bytes) => (Value::Blob(bytes.clone()), "CAST(? AS TEXT)"),
            Self::Blob(bytes) => (Value::Blob(bytes.clone()), "?"),
        }
    }
}

/// Draw one hostile text shape: markers, format strings, control bytes,
/// astral characters.
fn draw_hostile_text(deterministic: &mut Deterministic) -> String {
    match deterministic.below(4) {
        0 => "FUZZLEAK{:?}%s".to_owned(),
        1 => format!("nul\0byte-\u{1}-{}", deterministic.below(1 << 20)),
        2 => "\u{1f600}\u{10ffff}".repeat(3),
        _ => format!("plain-{}", deterministic.below(1 << 32)),
    }
}

/// Draw one cell value, weighted over the whole observable domain:
/// extremes, markers, format strings, control bytes, oversized payloads,
/// and every storage class.
fn draw_cell(deterministic: &mut Deterministic, large_budget: &mut u32) -> Planted {
    match deterministic.below(20) {
        0..=3 => Planted::Null,
        4..=6 => match deterministic.below(4) {
            0 => Planted::Integer(i64::MIN),
            1 => Planted::Integer(i64::MAX),
            2 => Planted::Integer(0),
            _ => Planted::Integer(i64::from_le_bytes(deterministic.next().to_le_bytes())),
        },
        7..=8 => match deterministic.below(5) {
            0 => Planted::Real(f64::INFINITY),
            1 => Planted::Real(f64::NEG_INFINITY),
            2 => Planted::Real(0.0),
            3 => Planted::Real(-0.0),
            // A NaN drawn from random bits stores as NULL — SQLite has no
            // NaN — so it is re-drawn as the infinity it fails closed on.
            _ => {
                let drawn = f64::from_bits(deterministic.next());
                if drawn.is_nan() {
                    Planted::Real(f64::INFINITY)
                } else {
                    Planted::Real(drawn)
                }
            }
        },
        9..=12 => Planted::Text(draw_hostile_text(deterministic)),
        13..=14 => {
            // A large value, budgeted so the whole suite stays fast: the
            // oversized tail of the value space still gets covered.
            if *large_budget > 0 {
                *large_budget -= 1;
                let fill = draw_hostile_text(deterministic);
                let mut value = String::new();
                while value.len() < 32_768 {
                    value.push_str(&fill);
                }
                Planted::Text(value)
            } else {
                Planted::Text(draw_hostile_text(deterministic))
            }
        }
        16..=17 => {
            let size = usize::try_from(deterministic.below(256)).expect("fits usize");
            Planted::Blob((0..size).map(|_| deterministic.byte()).collect())
        }
        _ => {
            // Bytes with an invalid-UTF-8 lead, planted as text.
            let size = usize::try_from(1 + deterministic.below(64)).expect("fits usize");
            let mut bytes = vec![0x80u8 | u8::try_from(deterministic.below(0x20)).expect("fits")];
            bytes.extend((1..size).map(|_| deterministic.byte()));
            Planted::HostileText(bytes)
        }
    }
}

/// The direct-read fingerprint of one cell: the storage-class tag and the
/// exact bytes. Both the snapshot side and the direct side fingerprint
/// with this recipe, so the comparison depends on neither's ordering.
fn fingerprint(class: u8, bytes: &[u8]) -> (u8, Vec<u8>) {
    (class, bytes.to_vec())
}

fn cell_fingerprint(cell: &Cell) -> (u8, Vec<u8>) {
    match cell {
        Cell::Null => fingerprint(0, &[]),
        Cell::Integer(value) => fingerprint(1, &value.to_be_bytes()),
        Cell::Real(value) => fingerprint(2, &value.to_be_bytes()),
        Cell::Text(bytes) => fingerprint(3, bytes),
        Cell::Blob(bytes) => fingerprint(4, bytes),
    }
}

fn direct_cell(value: ValueRef<'_>) -> (u8, Vec<u8>) {
    match value {
        ValueRef::Null => fingerprint(0, &[]),
        ValueRef::Integer(value) => fingerprint(1, &value.to_be_bytes()),
        ValueRef::Real(value) => fingerprint(2, &value.to_be_bytes()),
        ValueRef::Text(bytes) => fingerprint(3, bytes),
        ValueRef::Blob(bytes) => fingerprint(4, bytes),
    }
}

/// Build one INSERT for `table` binding `values` in the table's allowlist
/// column order, with the per-value SQL fragments from `bindings`.
fn insert_row(writer: &Connection, table: &str, columns: &[&str], row: &[Planted]) {
    let mut slots = String::new();
    let mut values: Vec<Value> = Vec::new();
    for cell in row {
        if !slots.is_empty() {
            slots.push_str(", ");
        }
        let (value, fragment) = cell.binding();
        let _ = write!(slots, "{fragment}");
        values.push(value);
    }
    let names: Vec<String> = columns
        .iter()
        .map(|column| format!("\"{column}\""))
        .collect();
    let sql = format!(
        "INSERT INTO \"{table}\" ({}) VALUES ({slots})",
        names.join(", ")
    );
    writer
        .execute(&sql, params_from_iter(values.iter()))
        .unwrap_or_else(|error| panic!("{table} row plants: {error}"));
}

#[test]
fn fuzz_random_cells_project_whole_or_fail_closed() {
    let scratch = Scratch::new("random-cells");
    for round in 0..12_u64 {
        let mut deterministic = Deterministic::new(0xce11_5eed_00c0_ffee ^ round);
        let mut large_budget = 2_u32;
        let path = scratch.path().join(format!("store-{round}.db"));
        seed_schema_only(&path);

        let mut unrepresentable_planted = false;
        let writer = Connection::open(&path).expect("the round store opens");
        // One version-carrying session row keeps the gate admitted; every
        // other cell of every row is drawn from the hostile space.
        writer
            .execute(
                "INSERT INTO session (id, version) VALUES ('session-a', '1.18.29')",
                [],
            )
            .expect("the version row plants");
        for &(table, columns) in ALLOWED_TABLES.iter().skip(1) {
            let rows = 1 + deterministic.below(4);
            for row in 0..rows {
                let mut cells: Vec<Planted> = Vec::new();
                for (position, column) in columns.iter().enumerate() {
                    if column == &"id" {
                        // The primary key stays unique and well-formed so
                        // the constraint never masks the value fuzz.
                        cells.push(Planted::Text(format!("{table}-r{row}-{position}")));
                        continue;
                    }
                    let planted = draw_cell(&mut deterministic, &mut large_budget);
                    unrepresentable_planted |= planted.unrepresentable();
                    cells.push(planted);
                }
                insert_row(&writer, table, columns, &cells);
            }
        }
        drop(writer);

        let store = StoreConnection::open(&path).expect("the fuzzed store opens read-only");
        let snapshot = Snapshot::take(&store).expect("hostile cells are observed, never fatal");
        assert_eq!(snapshot.tables().len(), 5);
        assert_snapshot_rendering_is_content_free(&snapshot);

        // Two independent opens observe identically: the observation is a
        // function of the store's content, not of the read's history.
        let store_again = StoreConnection::open(&path).expect("the fuzzed store reopens");
        let snapshot_again = Snapshot::take(&store_again).expect("the second observation");
        assert_eq!(
            snapshot, snapshot_again,
            "round {round}: the observation is a function of content"
        );

        let projected = match Projection::project(&snapshot) {
            Ok(projected) => projected,
            Err(observed) => {
                assert_eq!(
                    observed,
                    ProjectionError::Unrepresentable,
                    "round {round}: only unrepresentability fails a projection"
                );
                assert!(
                    unrepresentable_planted,
                    "round {round}: the projection failed without a planted cause"
                );
                continue;
            }
        };
        assert!(
            !unrepresentable_planted,
            "round {round}: a planted unrepresentable projected anyway"
        );
        assert_eq!(
            projected.rows().len(),
            snapshot_rows(&snapshot),
            "round {round}: one record per row"
        );
        assert_projection_matches_direct_reads(&path, &snapshot, round);

        // The JSONL body: one newline-terminated canonical record per
        // projected row, each naming its table.
        let jsonl = projected.jsonl();
        assert_eq!(jsonl.last().copied(), Some(b'\n'), "round {round}");
        let text = std::str::from_utf8(&jsonl).expect("canonical output is utf-8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), projected.rows().len(), "round {round}");
        for (index, line) in lines.iter().enumerate() {
            assert!(
                line.starts_with(r#"{"fields":"#),
                "round {round} line {index}"
            );
            assert!(line.contains(r#","table":""#), "round {round} line {index}");
        }
    }
}

/// Fidelity: the observation is fully accounted for by an independent
/// direct read of the store — same cells, same storage classes, same
/// bytes — compared as sorted multisets so neither side's ordering
/// influences the check.
fn assert_projection_matches_direct_reads(path: &Path, snapshot: &Snapshot, round: u64) {
    let reader = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("the direct read opens");
    for &(table, columns) in ALLOWED_TABLES {
        let names: Vec<String> = columns
            .iter()
            .map(|column| format!("\"{column}\""))
            .collect();
        let sql = format!("SELECT {} FROM \"{table}\"", names.join(", "));
        let mut statement = reader.prepare(&sql).expect("the direct read prepares");
        let mut direct_side: Vec<Vec<(u8, Vec<u8>)>> = statement
            .query_map([], |row| {
                Ok((0..columns.len())
                    .map(|index| {
                        let value = row.get_ref(index).expect("the cell reads");
                        direct_cell(value)
                    })
                    .collect::<Vec<_>>())
            })
            .expect("the direct read queries")
            .collect::<Result<Vec<_>, _>>()
            .expect("the direct read completes");

        let snapshot_table = snapshot
            .tables()
            .iter()
            .find(|candidate| candidate.name() == table)
            .expect("the allowlisted table is in the snapshot");
        let mut snapshot_side: Vec<Vec<(u8, Vec<u8>)>> = snapshot_table
            .rows()
            .iter()
            .map(|row| row.cells().iter().map(cell_fingerprint).collect())
            .collect();
        snapshot_side.sort();
        direct_side.sort();
        assert_eq!(
            snapshot_side, direct_side,
            "round {round}: table {table} diverges from the direct read"
        );
    }
}

/// One shared logical row: the allowlist table it belongs to, a stable
/// unique id (its identity in both stores), and its cells.
type LogicalRow = (usize, String, Vec<Planted>);

#[test]
fn fuzz_snapshot_order_is_a_function_of_content() {
    let scratch = Scratch::new("ordering");
    for round in 0..8_u64 {
        let mut deterministic = Deterministic::new(0x0b57_eed0_fa11_e550 ^ round);
        let mut draw = Deterministic::new(0x1d0a_fa11_e500_0000 ^ round);
        let mut large_budget = 1_u32;
        let mut unrepresentable = false;

        // The same logical rows for both stores: distinct stable ids,
        // randomized payload cells drawn once.
        let mut rows: Vec<LogicalRow> = Vec::new();
        for (table_index, &(table, columns)) in ALLOWED_TABLES.iter().enumerate().skip(1) {
            let count = 1 + deterministic.below(5);
            for row in 0..count {
                let mut cells: Vec<Planted> = Vec::new();
                for column in columns {
                    if column == &"id" {
                        cells.push(Planted::Text(format!("{table}-r{row}")));
                        continue;
                    }
                    let planted = draw_cell(&mut draw, &mut large_budget);
                    unrepresentable |= planted.unrepresentable();
                    cells.push(planted);
                }
                rows.push((table_index, format!("{table}-r{row}"), cells));
            }
        }

        let path_a = scratch.path().join(format!("order-a-{round}.db"));
        let path_b = scratch.path().join(format!("order-b-{round}.db"));
        seed_schema_only(&path_a);
        seed_schema_only(&path_b);
        insert_logical_rows(&path_a, &rows);

        // Store B takes the same logical rows in a rotated, shuffled
        // order — the physical order the store serves must not matter.
        let mut order: Vec<usize> = (0..rows.len()).collect();
        for index in (1..order.len()).rev() {
            let bound = u64::try_from(index + 1).expect("small");
            let swap = usize::try_from(deterministic.below(bound)).expect("fits");
            order.swap(index, swap);
        }
        let reordered: Vec<LogicalRow> = order.iter().map(|&at| rows[at].clone()).collect();
        insert_logical_rows(&path_b, &reordered);

        let snapshot_a =
            Snapshot::take(&StoreConnection::open(&path_a).expect("a opens")).expect("a snapshots");
        let snapshot_b =
            Snapshot::take(&StoreConnection::open(&path_b).expect("b opens")).expect("b snapshots");
        assert_eq!(
            snapshot_a, snapshot_b,
            "round {round}: insertion order must not move the observation"
        );
        let projection_a = Projection::project(&snapshot_a);
        let projection_b = Projection::project(&snapshot_b);
        match (projection_a, projection_b) {
            (Ok(a), Ok(b)) if !unrepresentable => {
                assert_eq!(a, b, "round {round}: projections agree");
                assert_eq!(a.jsonl(), b.jsonl(), "round {round}: bodies agree");
            }
            (Err(_), Err(_)) => {}
            (a, b) => panic!("round {round}: projection outcomes diverge: {a:?} vs {b:?}"),
        }
    }
}

/// Insert the shared logical rows into the store at `path`, in the order
/// they appear, each under its own stable id.
fn insert_logical_rows(path: &Path, rows: &[LogicalRow]) {
    let writer = Connection::open(path).expect("the store opens for insertion");
    for (table_index, id, cells) in rows {
        let (table, columns) = ALLOWED_TABLES[*table_index];
        let mut bound: Vec<Planted> = Vec::new();
        for (position, column) in columns.iter().enumerate() {
            if column == &"id" {
                bound.push(Planted::Text(id.clone()));
            } else {
                bound.push(cells[position].clone());
            }
        }
        insert_row(&writer, table, columns, &bound);
    }
    drop(writer);
}

#[test]
fn fuzz_source_disappearance_before_a_fresh_read_fails_closed() {
    let scratch = Scratch::new("disappearance");
    let path = scratch.path().join("opencode.db");
    seed_template_store(&path);

    // Sanity: the seeded store reads whole before every damage below.
    let baseline = StoreConnection::open(&path).expect("the seeded store opens");
    let _ = Snapshot::take(&baseline).expect("the seeded store snapshots");
    drop(baseline);

    let damage = |name: &str, apply: &mut dyn FnMut(&Path)| {
        let damaged = scratch.path().join(format!("damaged-{name}.db"));
        fs::copy(&path, &damaged).expect("the store copies");
        apply(&damaged);
        let outcome = read_pipeline(&damaged);
        assert!(
            !matches!(outcome, Outcome::Snapshot(_)),
            "damage {name}: a vanished or hostile store projected a snapshot"
        );
        assert_failure_is_closed(&outcome);
    };

    // Emptied in place: the driver may adopt a zero-length file as a fresh
    // empty store, which lands on the schema gate as a missing table — or
    // fail the probe outright. Either way nothing is projected.
    damage("emptied", &mut |path| {
        let handle = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("the store reopens for damage");
        handle.set_len(0).expect("the store empties");
    });

    // Truncated into the header, and overwritten with garbage from the
    // first byte: both destroy the file identity the driver checks first.
    damage("header-truncated", &mut |path| {
        let handle = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("the store reopens for damage");
        handle.set_len(37).expect("the store truncates");
    });
    for round in 0..8_u64 {
        let mut deterministic = Deterministic::new(0xd15a_00ea_0000_0000 ^ round);
        let name = format!("garbage-{round}");
        damage(&name, &mut |path| {
            let mut handle = fs::OpenOptions::new()
                .write(true)
                .open(path)
                .expect("the store reopens for damage");
            let window = 512 + deterministic.offset_within(4096);
            let bytes: Vec<u8> = (0..window).map(|_| deterministic.byte()).collect();
            handle
                .seek(std::io::SeekFrom::Start(0))
                .expect("the write seeks");
            handle.write_all(&bytes).expect("the garbage writes");
        });
    }
}
