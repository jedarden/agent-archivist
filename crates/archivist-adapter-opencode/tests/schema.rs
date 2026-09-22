// SPDX-License-Identifier: Apache-2.0

//! The schema-gate acceptance evidence (plan Phase 6B; plan `EC-08`; AC-05
//! and the "Fingerprint gate" row in docs/security/threats/
//! adapter-capture.md): a supported store is admitted and its fingerprint
//! reconciles to supported in the adapter descriptor; a missing table, an
//! extra or renamed column, an unknown or NULL application version, a
//! view or hidden-column virtual table standing in for an allowlisted
//! table all fail closed as `fingerprint-unsupported` before any row
//! content is read; detection reads schema metadata and the version
//! discriminator only; and no source-derived text reaches an error
//! message.

use std::fs;
use std::path::{Path, PathBuf};

use archivist_adapter_opencode::{
    DetectError, SUPPORTED_FINGERPRINT, SchemaDivergence, adapter_descriptor, detect,
};
use archivist_adapter_sdk::ScanClassification;
use archivist_adapter_sdk::SourceFingerprint;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::{Connection, OpenFlags};

/// A unique scratch directory, removed when the test ends either way.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let unique = format!(
            "archivist-opencode-schema-{}-{}-{}",
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

/// Seed one row of session bookkeeping so the version discriminator has a
/// value to admit: synthetic identifiers, no transcript content.
const SESSION_ROW: &str = "INSERT INTO session (id, project_id, slug, title, version) \
                           VALUES ('session-a', 'project-a', 'a', 'a', '1.18.29')";

/// Create the five allowlisted tables with exactly the embedded
/// allowlist's columns, plus two of the tables the real store legitimately
/// holds and the projection must never read. `extra` runs last so a test
/// can add hostile schema on top of the supported shape. The store is
/// seeded at `<dir>/opencode.db`.
fn seed_store(dir: &Path, extra: &str) -> PathBuf {
    let path = dir.join("opencode.db");
    let writer = Connection::open(&path).expect("the seed store is creatable");
    writer
        .execute_batch(&format!(
            r#"
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
            "#
        ))
        .expect("the seed schema applies");
    drop(writer);
    path
}

/// A read-only connection to the seeded store, the way detection receives
/// one.
fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("the seeded store opens read-only")
}

/// The `Unsupported` half of a detection that must fail, as a test
/// failure.
fn divergence(result: Result<SourceFingerprint, DetectError>, why: &str) -> SchemaDivergence {
    match result {
        Ok(fingerprint) => panic!("{why}: admitted {fingerprint}"),
        Err(DetectError::Unsupported(divergence)) => divergence,
        Err(DetectError::Read) => panic!("{why}: the probe could not read"),
    }
}

#[test]
fn a_supported_store_is_admitted_and_reconciles_to_the_descriptor() {
    let scratch = Scratch::new("supported");
    let path = seed_store(scratch.path(), "");

    let fingerprint = detect(&read_only(&path)).expect("the supported schema is admitted");

    assert_eq!(
        fingerprint,
        SourceFingerprint::parse(SUPPORTED_FINGERPRINT).unwrap()
    );
    assert_eq!(fingerprint.as_str(), "opencode-sqlite-v1");

    // The fingerprint reconciles to supported in the adapter descriptor:
    // the descriptor admits exactly what detection reported.
    let descriptor = adapter_descriptor();
    assert!(descriptor.supports_fingerprint(&fingerprint));
    assert!(descriptor.fingerprints.admit(&fingerprint).is_ok());
}

#[test]
fn an_empty_but_conformant_store_is_admitted() {
    // Schema validity and session presence are different axes: a store
    // with the supported layout and zero sessions has nothing to project,
    // which is coverage's business, not the gate's.
    let scratch = Scratch::new("empty");
    let path = seed_store(scratch.path(), "DELETE FROM session;");

    let fingerprint = detect(&read_only(&path)).expect("the empty store is admitted");
    assert_eq!(fingerprint.as_str(), SUPPORTED_FINGERPRINT);
}

#[test]
fn a_missing_table_fails_closed() {
    let scratch = Scratch::new("missing-table");
    let path = seed_store(scratch.path(), "DROP TABLE todo;");

    let result = detect(&read_only(&path));

    assert_eq!(
        divergence(result, "a dropped table must fail"),
        SchemaDivergence::MissingTable
    );
    assert_eq!(
        DetectError::Unsupported(SchemaDivergence::MissingTable).classification(),
        ScanClassification::FingerprintUnsupported
    );
}

#[test]
fn an_extra_column_fails_closed() {
    let scratch = Scratch::new("extra-column");
    let path = seed_store(
        scratch.path(),
        r#"ALTER TABLE message ADD COLUMN overshare TEXT;"#,
    );

    let result = detect(&read_only(&path));

    assert_eq!(
        divergence(result, "an extra column must fail"),
        SchemaDivergence::ColumnDivergence
    );
}

#[test]
fn a_renamed_column_fails_closed() {
    let scratch = Scratch::new("renamed-column");
    let path = seed_store(
        scratch.path(),
        "DROP TABLE part;
         CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_ref TEXT, \
         time_created INTEGER, time_updated INTEGER, data TEXT);",
    );

    let result = detect(&read_only(&path));

    assert_eq!(
        divergence(result, "a renamed column must fail"),
        SchemaDivergence::ColumnDivergence
    );
}

#[test]
fn an_unknown_application_version_fails_closed() {
    let scratch = Scratch::new("unknown-version");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO session (id, project_id, slug, title, version) \
         VALUES ('session-b', 'project-a', 'b', 'b', '9.9.9');",
    );

    let result = detect(&read_only(&path));

    assert_eq!(
        divergence(result, "an unknown version must fail"),
        SchemaDivergence::UnknownVersion
    );
}

#[test]
fn a_null_application_version_fails_closed() {
    let scratch = Scratch::new("null-version");
    let path = seed_store(
        scratch.path(),
        "INSERT INTO session (id, project_id, slug, title, version) \
         VALUES ('session-b', 'project-a', 'b', 'b', NULL);",
    );

    let result = detect(&read_only(&path));

    assert_eq!(
        divergence(result, "a NULL version must fail"),
        SchemaDivergence::UnknownVersion
    );
}

#[test]
fn a_view_standing_in_for_a_table_fails_closed() {
    // A hostile store drops `todo` and substitutes a view of the same
    // name that presents exactly todo's column shape, projected from a
    // real table. The presence probe filters `sqlite_master` on
    // `type='table'`, so the substitution is a missing table, not a face
    // that passes.
    let scratch = Scratch::new("view-standin");
    let path = seed_store(
        scratch.path(),
        "DROP TABLE todo;
         CREATE VIEW todo AS SELECT id, session_id, prompt AS content, delivery AS status, \
         admitted_seq AS priority, promoted_seq AS position, time_created \
         FROM session_input;",
    );

    let result = detect(&read_only(&path));

    assert_eq!(
        divergence(result, "a view stand-in must fail"),
        SchemaDivergence::MissingTable
    );
}

#[test]
fn a_virtual_table_with_hidden_columns_fails_closed() {
    // An `fts5` virtual table named `message` declares exactly the
    // allowlisted columns, and `PRAGMA table_info` shows exactly those —
    // while the module serves them through machinery that hides two
    // internal columns only `table_xinfo` reveals. The gate reads
    // `table_xinfo`, so the hidden machinery is a divergence.
    let scratch = Scratch::new("virtual-hidden");
    let path = seed_store(
        scratch.path(),
        "DROP TABLE message;
         CREATE VIRTUAL TABLE message USING fts5(id, session_id, time_created, \
         time_updated, data);",
    );

    let result = detect(&read_only(&path));

    assert_eq!(
        divergence(result, "a hidden-column virtual table must fail"),
        SchemaDivergence::ColumnDivergence
    );
}

#[test]
fn detection_errors_carry_no_source_text() {
    // Hostile schema and hostile discriminator values: extra columns and
    // version strings chosen to look like markup, a path, and SQL. The
    // error type is a closed set of unit variants, so nothing rendered
    // from it can carry them — asserted here against the actual hostile
    // strings.
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

    let result = detect(&read_only(&path));

    // The extra column alone is a divergence; whichever divergence is
    // reported first, no rendering carries the hostile text.
    let error = match result {
        Ok(fingerprint) => panic!("hostile schema must not be admitted: {fingerprint}"),
        Err(error) => error,
    };
    let rendered = format!("{error}");
    let debugged = format!("{error:?}");
    let classification = error.classification().token();
    assert!(!rendered.contains(hostile_column), "Display: {rendered}");
    assert!(!rendered.contains(hostile_version), "Display: {rendered}");
    assert!(!debugged.contains(hostile_column), "Debug: {debugged}");
    assert!(!debugged.contains(hostile_version), "Debug: {debugged}");
    assert!(!rendered.contains("DROP TABLE"), "Display: {rendered}");
    assert_eq!(
        classification, "fingerprint-unsupported",
        "the classification is the closed token, not the divergence detail"
    );
}

#[test]
fn detection_reads_schema_metadata_and_the_discriminator_only() {
    // The mechanical proof of the metadata-only contract (AC-05): an
    // authorizer denies every column read on the five allowlisted tables
    // except `session.version` — the discriminator. Detection succeeds
    // only if it never reads a projected column, and the authorizer is
    // proven live below by watching it deny a deliberate projected read.
    let scratch = Scratch::new("metadata-only");
    let path = seed_store(scratch.path(), "");

    let conn = read_only(&path);
    let allowlisted = ["session", "message", "part", "session_input", "todo"];
    conn.authorizer(Some(move |context: AuthContext<'_>| match context.action {
        AuthAction::Read {
            table_name,
            column_name,
        } => {
            let discriminator = table_name == "session" && column_name == "version";
            let schema_index = table_name == "sqlite_master";
            if discriminator || schema_index || !allowlisted.contains(&table_name) {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }
        _ => Authorization::Allow,
    }))
    .expect("the authorizer installs");

    let fingerprint = detect(&conn).expect("detection reads no projected column and is admitted");
    assert_eq!(fingerprint.as_str(), SUPPORTED_FINGERPRINT);

    // The harness is live: the same authorizer denies a projected read,
    // so detection's success is evidence, not a vacuous pass.
    let projected = conn.prepare("SELECT data FROM message");
    assert!(
        projected.is_err(),
        "the authorizer must deny projected reads for this proof to bind"
    );
}
