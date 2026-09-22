// SPDX-License-Identifier: Apache-2.0

//! The schema-version gate (plan Phase 6B "Detect schema version before
//! querying"; plan `EC-08`; AC-05 and the "Fingerprint gate" row in
//! docs/security/threats/adapter-capture.md).
//!
//! Before any projected content is read, [`detect`] inspects the store's
//! schema metadata alone and decides whether the layout is one this
//! adapter supports:
//!
//! 1. **Table presence** — each of the five allowlisted tables
//!    ([`ALLOWED_TABLES`]) exists as a table. A view or a virtual table
//!    standing in for one fails the presence probe: the probe filters
//!    `sqlite_master` on `type = 'table'` and a hostile same-named view is
//!    not a table, so a substitution cannot slip through to the
//!    projection.
//! 2. **Exact column sets** — each allowlisted table exposes exactly the
//!    allowlisted columns: a missing column, a renamed column, or an
//!    extra column all diverge. The probe reads
//!    `PRAGMA table_xinfo`, whose listing *includes hidden columns*, so a
//!    virtual table that hides its real machinery (an `fts5` shadow shows
//!    its declared columns through `PRAGMA table_info` and its internal
//!    columns only through `table_xinfo`) cannot present the allowlisted
//!    face while widening what its module actually serves.
//! 3. **Version discriminator** — the application version recorded in
//!    `session.version` (the fleet inventory's observed discriminator) is
//!    checked against the closed [`ALLOWED_VERSIONS`] vocabulary. A NULL
//!    or unknown version diverges; the probe reads the discriminator
//!    column and no other row value, and it never materializes a version
//!    string into this process: the SQL asks for one row that *diverges*
//!    and the answer is the row's existence, not its content.
//!
//! Every non-allowlisted table the store legitimately holds (the
//! inventory lists nineteen, among them the account, credential, and
//! provider-auth tables) is invisible to the gate: presence is probed per
//! allowlisted name, and nothing else is read at all.
//!
//! # Fail closed
//!
//! Any divergence classifies
//! [`ScanClassification::FingerprintUnsupported`] (plan `EC-08`: read no
//! projected content, report `unsupported`) and a metadata probe that
//! cannot complete — a lock held past the busy window, a corrupt schema
//! page — classifies [`ScanClassification::ReadError`]; neither reading
//! degrades into a best-effort projection.
//!
//! # Content-freedom
//!
//! Detection is content-free twice over. It *reads* only schema metadata
//! and the version discriminator (requirement AC-05's metadata set), and
//! it *reports* nothing but closed-vocabulary tokens: the error type is a
//! closed set of unit variants, so a hostile extra column, a renamed
//! column, or an unknown version string cannot reach status, an error
//! body, or a log — not even to name which table diverged.
//!
//! [`detect`]: detect

use std::fmt;

use archivist_adapter_sdk::AdapterDescriptor;
use archivist_adapter_sdk::AdapterId;
use archivist_adapter_sdk::CapabilitySet;
use archivist_adapter_sdk::FingerprintAllowlist;
use archivist_adapter_sdk::ScanClassification;
use archivist_adapter_sdk::SourceFingerprint;
use archivist_adapter_sdk::VersionToken;
use rusqlite::Connection;
use rusqlite::OptionalExtension;

/// The fingerprint token this adapter reports for the one store layout it
/// supports: the five allowlisted tables with their exact column sets and
/// the allowlisted application version. The token is content-free by the
/// fingerprint grammar and stable across adapter versions — it names the
/// observed layout, not a release.
pub const SUPPORTED_FINGERPRINT: &str = "opencode-sqlite-v1";

/// The projection version the adapter publishes in its descriptor. The
/// projection itself lands with the Phase 6B projection work; the version
/// is the token that stamps every projected record and enters the
/// artifact identity, so it starts at its own `0.1` and bumps only when
/// the projection's field set or record shape changes.
pub const PROJECTION_VERSION: &str = "0.1.0";

/// The five allowlisted tables with their exact column sets, as observed
/// by the fleet inventory (docs/notes/fleet-source-inventory.md: exactly
/// the prototype's projection allowlist; the inventory prose's per-table
/// counts round `session` down by one, and the observed store — version
/// `1.18.29`, the version the inventory names — carries these twenty-nine
/// columns). Order is documentary: [`detect`] compares column *sets*, so
/// a store whose declared column order differs still passes, while a
/// missing, renamed, or extra column cannot.
pub const ALLOWED_TABLES: &[(&str, &[&str])] = &[
    (
        "session",
        &[
            "id",
            "project_id",
            "workspace_id",
            "parent_id",
            "slug",
            "directory",
            "path",
            "title",
            "version",
            "share_url",
            "summary_additions",
            "summary_deletions",
            "summary_files",
            "summary_diffs",
            "metadata",
            "cost",
            "tokens_input",
            "tokens_output",
            "tokens_reasoning",
            "tokens_cache_read",
            "tokens_cache_write",
            "revert",
            "permission",
            "agent",
            "model",
            "time_created",
            "time_updated",
            "time_compacting",
            "time_archived",
        ],
    ),
    (
        "message",
        &["id", "session_id", "time_created", "time_updated", "data"],
    ),
    (
        "part",
        &[
            "id",
            "message_id",
            "session_id",
            "time_created",
            "time_updated",
            "data",
        ],
    ),
    (
        "session_input",
        &[
            "id",
            "session_id",
            "prompt",
            "delivery",
            "admitted_seq",
            "promoted_seq",
            "time_created",
        ],
    ),
    (
        "todo",
        &[
            "session_id",
            "content",
            "status",
            "priority",
            "position",
            "time_created",
            "time_updated",
        ],
    ),
];

/// The closed application-version vocabulary the version discriminator
/// admits: the values observed in `session.version` across the fleet
/// inventory. An application version outside this set diverges and fails
/// closed — a store written by an unobserved release may project
/// differently in ways schema presence alone cannot see.
pub const ALLOWED_VERSIONS: &[&str] = &["1.18.29"];

/// Why a store's schema diverged from the allowlist. A closed set of unit
/// variants: the type cannot carry a table name, a column name, or a
/// version string, so no formatting — [`fmt::Display`] included — can
/// leak schema or version text into status, an error body, or a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchemaDivergence {
    /// One of the five allowlisted tables is absent, or is present only
    /// as a view or other non-table object: the projection would have
    /// nothing allowlisted to read.
    MissingTable,
    /// An allowlisted table's columns diverge: one is missing, renamed,
    /// or an unknown column (hidden ones included) was added.
    ColumnDivergence,
    /// `session.version` carried NULL or a value outside
    /// [`ALLOWED_VERSIONS`]: the store was written by an unobserved
    /// release.
    UnknownVersion,
}

impl SchemaDivergence {
    /// The content-free token naming this divergence: the whole message
    /// [`fmt::Display`] renders.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::MissingTable => "opencode-schema-table-missing",
            Self::ColumnDivergence => "opencode-schema-column-divergence",
            Self::UnknownVersion => "opencode-schema-version-unknown",
        }
    }
}

impl fmt::Display for SchemaDivergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Why schema detection did not admit the store. The two outcomes map to
/// the closed scan classifications: a divergence is
/// [`ScanClassification::FingerprintUnsupported`] (the store exists and
/// was understood enough to reject) and an unreadable probe is
/// [`ScanClassification::ReadError`] (nothing was understood).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DetectError {
    /// The schema diverged from the allowlist; no projected content was
    /// read (plan `EC-08`).
    Unsupported(SchemaDivergence),
    /// The schema metadata itself could not be read: a lock held past
    /// the busy window, a corrupt schema page, a driver failure.
    Read,
}

impl DetectError {
    /// The closed classification this detection outcome reports.
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
            Self::Read => "opencode-schema-unreadable",
        }
    }
}

impl fmt::Display for DetectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

impl std::error::Error for DetectError {}

/// Detect the store's schema and admit it against the embedded allowlist
/// **before any projected content is read** (plan Phase 6B; plan `EC-08`).
///
/// The probe reads schema metadata only — table presence, column
/// listings, and the `session.version` discriminator (AC-05's metadata
/// set) — and reports the store's fingerprint when, and only when, the
/// layout matches the supported one exactly. Every query is bound-bounded
/// by construction: presence is one indexed `sqlite_master` lookup per
/// allowlisted table, the column listing is one pragma per table, and the
/// version probe asks for a single divergent row and stops.
///
/// # Errors
///
/// [`DetectError::Unsupported`] with the divergence reason when the
/// schema fails the allowlist, and [`DetectError::Read`] when the
/// metadata probe cannot complete. Neither error carries schema,
/// version, or content text.
pub fn detect(conn: &Connection) -> Result<SourceFingerprint, DetectError> {
    for (table, _) in ALLOWED_TABLES {
        let present: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| DetectError::Read)?;
        if present.is_none() {
            // A view or a virtual-table shadow with the allowlisted name
            // is not the table either: `type = 'table'` excludes views,
            // and the column probe below runs only after a table was
            // seen, so a substitution fails here first.
            return Err(DetectError::Unsupported(SchemaDivergence::MissingTable));
        }
    }

    for (table, allowed) in ALLOWED_TABLES {
        // `table` comes from this module's constant list, never from the
        // store, so the pragma's name interpolation is not source-derived.
        let mut statement = conn
            .prepare(&format!(r#"PRAGMA table_xinfo("{table}")"#))
            .map_err(|_| DetectError::Read)?;
        let observed: Vec<String> = statement
            .query_map([], |row| row.get(1))
            .map_err(|_| DetectError::Read)?
            .collect::<Result<_, _>>()
            .map_err(|_| DetectError::Read)?;
        // Set equality: hidden columns count, so a virtual table cannot
        // present the allowlisted face while hiding its machinery, and a
        // rename is a divergence, not a near match.
        let allowed: std::collections::BTreeSet<&str> = allowed.iter().copied().collect();
        let observed: std::collections::BTreeSet<&str> =
            observed.iter().map(String::as_str).collect();
        if observed != allowed {
            return Err(DetectError::Unsupported(SchemaDivergence::ColumnDivergence));
        }
    }

    if has_divergent_version(conn)? {
        return Err(DetectError::Unsupported(SchemaDivergence::UnknownVersion));
    }

    SourceFingerprint::parse(SUPPORTED_FINGERPRINT).map_err(|_| DetectError::Read)
}

/// Whether any `session` row carries a version outside the closed
/// vocabulary (or NULL). The probe never materializes a version value:
/// it selects a constant for rows that *diverge* and stops at the first.
fn has_divergent_version(conn: &Connection) -> Result<bool, DetectError> {
    // The literals come from this module's constant list, whose tokens
    // are closed-vocabulary version strings (no quotes are possible in
    // the grammar), so the interpolation cannot smuggle SQL.
    let mut sql =
        String::from("SELECT 1 FROM \"session\" WHERE \"version\" IS NULL OR \"version\" NOT IN (");
    for (index, version) in ALLOWED_VERSIONS.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        sql.push('\'');
        sql.push_str(version);
        sql.push('\'');
    }
    sql.push_str(") LIMIT 1");
    let divergent: Option<i64> = conn
        .query_row(&sql, [], |row| row.get(0))
        .optional()
        .map_err(|_| DetectError::Read)?;
    Ok(divergent.is_some())
}

/// The adapter's published descriptor (CAP-002): identity, projection
/// version, declared capabilities, and the exact fingerprint allowlist
/// the schema gate admits against. Every part is a compile-time constant
/// validated by its own module, so publication cannot fail.
///
/// # Panics
///
/// Never in practice: every [`expect`] guards a literal against a
/// grammar its own module defines — the fingerprint token and adapter id
/// are valid by the token grammars, the capability token is in the
/// closed set, and a one-element allowlist satisfies the set rules.
#[must_use]
pub fn adapter_descriptor() -> AdapterDescriptor {
    let fingerprints = FingerprintAllowlist::new([SourceFingerprint::parse(SUPPORTED_FINGERPRINT)
        .expect("the supported fingerprint is grammar-valid")])
    .expect("the allowlist is non-empty");
    AdapterDescriptor::publish(
        AdapterId::parse("opencode").expect("the adapter id is a valid short token"),
        VersionToken::parse(PROJECTION_VERSION).expect("the projection version is a valid token"),
        CapabilitySet::parse(["database-projection"]).expect("the token is in the closed set"),
        fingerprints,
    )
    .expect("the declared capability set is non-empty")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_allowlist_covers_the_observed_inventory_shape() {
        let tables: Vec<_> = ALLOWED_TABLES.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            tables,
            ["session", "message", "part", "session_input", "todo"],
            "the five allowlisted tables, in inventory order"
        );
        // The exact column sets observed on the 1.18.29 store (the
        // inventory's "exactly the prototype's projection allowlist").
        let sizes: Vec<_> = ALLOWED_TABLES.iter().map(|(_, c)| c.len()).collect();
        assert_eq!(sizes, [29, 5, 6, 7, 7]);
        // Every allowlisted table names its columns at least once and no
        // column repeats: set comparison is only exact if the constants
        // are duplicate-free.
        for (table, columns) in ALLOWED_TABLES {
            let mut unique = columns.to_vec();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(
                unique.len(),
                columns.len(),
                "{table} repeats a column in the embedded allowlist"
            );
        }
    }

    #[test]
    fn the_embedded_version_vocabulary_is_quote_free() {
        // The version probe interpolates these as SQL literals; the
        // grammar this constant is written against admits only version
        // tokens, but the property is what keeps the interpolation safe,
        // so it is asserted next to the code that relies on it.
        assert!(!ALLOWED_VERSIONS.is_empty());
        for version in ALLOWED_VERSIONS {
            assert!(
                !version.contains('\'') && !version.contains('"') && !version.contains(';'),
                "a quote or separator in {version} would break the literal"
            );
        }
        assert_eq!(
            ALLOWED_VERSIONS,
            ["1.18.29"],
            "the observed inventory value"
        );
    }

    #[test]
    fn detection_errors_are_closed_content_free_tokens() {
        let divergences = [
            SchemaDivergence::MissingTable,
            SchemaDivergence::ColumnDivergence,
            SchemaDivergence::UnknownVersion,
        ];
        for divergence in divergences {
            let rendered = format!("{divergence}");
            assert_eq!(rendered, divergence.token());
            assert!(!rendered.contains('\''), "no quoting: {rendered}");
        }

        // Every unsupported divergence forces the same classification —
        // the plan EC-08 one — and the unit vocabulary stays distinct
        // from it so status carries exactly the closed token.
        let error = DetectError::Unsupported(SchemaDivergence::ColumnDivergence);
        assert_eq!(
            error.classification(),
            ScanClassification::FingerprintUnsupported
        );
        assert_eq!(error.classification().token(), "fingerprint-unsupported");
        let unreadable = DetectError::Read;
        assert_eq!(unreadable.classification(), ScanClassification::ReadError);
        assert_eq!(unreadable.classification().token(), "read-error");
        for token in [
            DetectError::Unsupported(SchemaDivergence::MissingTable).token(),
            DetectError::Unsupported(SchemaDivergence::ColumnDivergence).token(),
            DetectError::Unsupported(SchemaDivergence::UnknownVersion).token(),
            DetectError::Read.token(),
        ] {
            assert!(
                token.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "the token {token} leaves the closed lowercase-token vocabulary"
            );
        }
    }

    #[test]
    fn the_descriptor_publishes_the_supported_fingerprint() {
        let descriptor = adapter_descriptor();
        let supported =
            SourceFingerprint::parse(SUPPORTED_FINGERPRINT).expect("the token is grammar-valid");
        assert!(descriptor.supports_fingerprint(&supported));
        assert!(descriptor.fingerprints.admit(&supported).is_ok());
        // Anything else fails closed through the SDK's own decision.
        let unknown = SourceFingerprint::parse("opencode-sqlite-v9").expect("parses");
        assert!(!descriptor.supports_fingerprint(&unknown));
        assert_eq!(
            descriptor
                .fingerprints
                .admit(&unknown)
                .expect_err("fails closed")
                .classification(),
            ScanClassification::FingerprintUnsupported
        );
        let text = String::from_utf8(descriptor.to_json().canonical_bytes()).expect("utf8");
        assert!(text.contains(r#""adapter":"opencode""#));
        assert!(text.contains(r#""opencode-sqlite-v1""#));
        assert!(text.contains(r#""projection":"0.1.0""#));
    }
}
