// SPDX-License-Identifier: Apache-2.0

//! The explicit client state schema: one hand-written migration per table
//! group, applied in order, each with the SQL that reverses it.
//!
//! Every table stores identifiers, digests, and timestamps only. Source file
//! paths and transcript content have no column anywhere in this schema: a
//! source is named by its derived session and artifact hashes (plan Section
//! 7.4), a spool bundle by its file name inside the spool directory, and
//! adapter failures by a content-free error code. The `CHECK` constraints
//! pin those shapes at the database level so a future column cannot quietly
//! start carrying content.
//!
//! Identifier shapes pinned here: UUID text is 36 lowercase characters, a
//! SHA-256 digest is 64 lowercase hex characters, and every timestamp column
//! holds RFC 3339 UTC text (plan Section 7.3). The engine layer validates
//! the full grammars before insert; the constraints here are the backstop,
//! not the validator.

/// One schema step: the version it moves the database to, the SQL that
/// applies it, and — wherever the step is safe to undo — the SQL that
/// reverses it.
pub struct Migration {
    /// The schema version this migration moves the database to. Versions
    /// start at 1 and are contiguous; version 0 means "no migrations
    /// applied".
    pub version: i64,
    /// Stable content-free identifier, recorded with the version in the
    /// history table and reused in error text.
    pub name: &'static str,
    /// Forward SQL, executed inside one transaction together with the
    /// history insert.
    pub up: &'static str,
    /// Reverse SQL, executed inside one transaction together with the
    /// history delete, or `None` when the step destroys information and is
    /// deliberately irreversible. Reversibility is per step: a migration
    /// that only creates objects is safe to reverse; one that rewrites or
    /// drops data is not, and must say so here by being `None`.
    pub down: Option<&'static str>,
}

/// Migration 1: capture sources under management.
///
/// A source is one adapter-defined artifact stream of a logical session,
/// named by its derived session and artifact hashes rather than by any
/// filesystem path. `last_cursor` is the opaque adapter cursor marking where
/// capture stopped; it is adapter data, bounded at 1,024 characters like the
/// upstream identifiers, never a local path.
const SOURCES: Migration = Migration {
    version: 1,
    name: "create-sources",
    up: r"
        CREATE TABLE sources (
            source_id TEXT PRIMARY KEY NOT NULL
                CHECK (length(source_id) = 36),
            harness TEXT NOT NULL
                CHECK (length(harness) BETWEEN 1 AND 64),
            upstream_session_id TEXT NOT NULL
                CHECK (length(upstream_session_id) BETWEEN 1 AND 1024),
            id_source TEXT NOT NULL
                CHECK (id_source IN ('natural', 'synthetic')),
            session_hash TEXT NOT NULL
                CHECK (length(session_hash) = 64),
            artifact_kind TEXT NOT NULL
                CHECK (length(artifact_kind) BETWEEN 1 AND 64),
            adapter_id TEXT NOT NULL
                CHECK (length(adapter_id) BETWEEN 1 AND 64),
            adapter_projection_version TEXT NOT NULL
                CHECK (length(adapter_projection_version) BETWEEN 1 AND 64),
            adapter_artifact_id TEXT NOT NULL
                CHECK (length(adapter_artifact_id) BETWEEN 1 AND 1024),
            artifact_hash TEXT NOT NULL
                CHECK (length(artifact_hash) = 64),
            freshness_lane TEXT NOT NULL
                CHECK (freshness_lane IN ('freshness', 'backfill')),
            last_cursor TEXT
                CHECK (last_cursor IS NULL OR length(last_cursor) <= 1024),
            created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 20 AND 35),
            updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 20 AND 35),
            UNIQUE (session_hash, artifact_hash)
        );
    ",
    down: Some(
        r"
        DROP TABLE sources;
    ",
    ),
};

/// Migration 2: artifact generations.
///
/// A generation is a `UUIDv7` epoch created when a source artifact is first
/// observed or detected as truncated, replaced, or incompatibly rewritten
/// (plan Section 7.2, `EC-02`). `tail_checksum` and `file_identity` hold
/// digests and adapter identity values used for detection — never a path.
const GENERATIONS: Migration = Migration {
    version: 2,
    name: "create-generations",
    up: r"
        CREATE TABLE generations (
            generation_id TEXT PRIMARY KEY NOT NULL
                CHECK (length(generation_id) = 36),
            source_id TEXT NOT NULL
                REFERENCES sources (source_id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL CHECK (ordinal >= 1),
            state TEXT NOT NULL CHECK (state IN ('open', 'closed')),
            detected_reason TEXT NOT NULL CHECK (
                detected_reason IN
                ('first-observed', 'truncated', 'replaced', 'rewritten')
            ),
            tail_checksum TEXT
                CHECK (tail_checksum IS NULL OR length(tail_checksum) = 64),
            file_identity TEXT
                CHECK (file_identity IS NULL OR length(file_identity) <= 1024),
            detected_at TEXT NOT NULL
                CHECK (length(detected_at) BETWEEN 20 AND 35)
        );
        CREATE INDEX idx_generations_source
            ON generations (source_id, state);
    ",
    down: Some(
        r"
        DROP INDEX idx_generations_source;
        DROP TABLE generations;
    ",
    ),
};

/// Migration 3: spool entries.
///
/// One row per durable spool bundle, committed only after the bundle file
/// itself is written, synchronized, and atomically renamed (plan Section
/// 7.9). `bundle_name` is the bundle's file name inside the spool
/// directory; the check constraint forbids path separators so the column
/// cannot drift into storing a location.
const SPOOL_ENTRIES: Migration = Migration {
    version: 3,
    name: "create-spool-entries",
    up: r"
        CREATE TABLE spool_entries (
            spool_entry_id TEXT PRIMARY KEY NOT NULL
                CHECK (length(spool_entry_id) = 36),
            bundle_name TEXT NOT NULL CHECK (
                length(bundle_name) BETWEEN 1 AND 255 AND
                instr(bundle_name, '/') = 0 AND
                instr(bundle_name, '\') = 0
            ),
            state TEXT NOT NULL CHECK (
                state IN ('materialized', 'uploading', 'uploaded', 'acknowledged')
            ),
            envelope_digest TEXT NOT NULL
                CHECK (length(envelope_digest) = 64),
            size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
            attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
            next_attempt_at TEXT
                CHECK (next_attempt_at IS NULL
                       OR length(next_attempt_at) BETWEEN 20 AND 35),
            created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 20 AND 35),
            updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 20 AND 35)
        );
        CREATE INDEX idx_spool_entries_state
            ON spool_entries (state, next_attempt_at);
    ",
    down: Some(
        r"
        DROP INDEX idx_spool_entries_state;
        DROP TABLE spool_entries;
    ",
    ),
};

/// Migration 4: frozen upload requests.
///
/// The request identity and immutable envelope fields frozen when the spool
/// entry is created (plan Section 7.4); per-attempt authorization is
/// refreshed on every retry and never stored here. The row outlives its
/// bundle: cleanup sets `spool_entry_id` to null rather than deleting the
/// request a receipt may point at.
const FROZEN_REQUESTS: Migration = Migration {
    version: 4,
    name: "create-frozen-requests",
    up: r"
        CREATE TABLE frozen_requests (
            request_id TEXT PRIMARY KEY NOT NULL
                CHECK (length(request_id) = 36),
            spool_entry_id TEXT
                REFERENCES spool_entries (spool_entry_id) ON DELETE SET NULL,
            tenant_id TEXT NOT NULL CHECK (length(tenant_id) = 36),
            origin_client_id TEXT NOT NULL
                CHECK (length(origin_client_id) = 36),
            uploader_client_id TEXT NOT NULL
                CHECK (length(uploader_client_id) = 36),
            occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) = 64),
            envelope_version TEXT NOT NULL
                CHECK (length(envelope_version) BETWEEN 1 AND 64),
            storage_profile TEXT NOT NULL
                CHECK (length(storage_profile) BETWEEN 1 AND 64),
            transport_encoding TEXT
                CHECK (transport_encoding IS NULL
                       OR length(transport_encoding) BETWEEN 1 AND 64),
            canonical_digest TEXT NOT NULL
                CHECK (length(canonical_digest) = 64),
            incoming_checksum TEXT NOT NULL
                CHECK (length(incoming_checksum) BETWEEN 1 AND 128),
            canonical_size INTEGER NOT NULL CHECK (canonical_size >= 0),
            transport_size INTEGER NOT NULL CHECK (transport_size >= 0),
            source_at TEXT CHECK (source_at IS NULL
                                  OR length(source_at) BETWEEN 20 AND 35),
            captured_at TEXT NOT NULL
                CHECK (length(captured_at) BETWEEN 20 AND 35),
            envelope_created_at TEXT NOT NULL
                CHECK (length(envelope_created_at) BETWEEN 20 AND 35),
            frozen_at TEXT NOT NULL CHECK (length(frozen_at) BETWEEN 20 AND 35),
            UNIQUE (spool_entry_id)
        );
        CREATE INDEX idx_frozen_requests_occurrence
            ON frozen_requests (occurrence_id);
    ",
    down: Some(
        r"
        DROP INDEX idx_frozen_requests_occurrence;
        DROP TABLE frozen_requests;
    ",
    ),
};

/// Migration 5: captured ranges.
///
/// One row per captured byte or event range of a generation — half of an
/// occurrence identity (plan Section 7.2). `spool_entry_id` links the range
/// to the bundle carrying it while that bundle exists; cleanup nulls the
/// link but keeps the coverage row, because a range must never be recorded
/// as acknowledged without its committed receipt.
const RANGES: Migration = Migration {
    version: 5,
    name: "create-ranges",
    up: r"
        CREATE TABLE ranges (
            occurrence_id TEXT PRIMARY KEY NOT NULL
                CHECK (length(occurrence_id) = 64),
            generation_id TEXT NOT NULL
                REFERENCES generations (generation_id) ON DELETE CASCADE,
            range_kind TEXT NOT NULL CHECK (range_kind IN ('bytes', 'events')),
            range_start INTEGER NOT NULL CHECK (range_start >= 0),
            range_end INTEGER NOT NULL CHECK (range_end >= range_start),
            sequence INTEGER NOT NULL CHECK (sequence >= 0),
            blob_digest TEXT NOT NULL CHECK (length(blob_digest) = 64),
            spool_entry_id TEXT
                REFERENCES spool_entries (spool_entry_id) ON DELETE SET NULL,
            captured_at TEXT NOT NULL
                CHECK (length(captured_at) BETWEEN 20 AND 35)
        );
        CREATE INDEX idx_ranges_generation
            ON ranges (generation_id, range_kind, range_start);
        CREATE INDEX idx_ranges_spool ON ranges (spool_entry_id);
    ",
    down: Some(
        r"
        DROP INDEX idx_ranges_spool;
        DROP INDEX idx_ranges_generation;
        DROP TABLE ranges;
    ",
    ),
};

/// Migration 6: upload attestations.
///
/// Immutable provenance binding one occurrence and frozen request to its
/// linked uploader (plan Section 7.2). Nothing cascades into this table:
/// provenance survives every cleanup, and `ON DELETE RESTRICT`-style
/// protection is provided at the receipt end. `relation` distinguishes a
/// direct upload from a relayed one.
const UPLOAD_ATTESTATIONS: Migration = Migration {
    version: 6,
    name: "create-upload-attestations",
    up: r"
        CREATE TABLE upload_attestations (
            attestation_id TEXT PRIMARY KEY NOT NULL
                CHECK (length(attestation_id) = 64),
            tenant_id TEXT NOT NULL CHECK (length(tenant_id) = 36),
            occurrence_id TEXT NOT NULL CHECK (length(occurrence_id) = 64),
            origin_client_id TEXT NOT NULL
                CHECK (length(origin_client_id) = 36),
            uploader_client_id TEXT NOT NULL
                CHECK (length(uploader_client_id) = 36),
            request_id TEXT NOT NULL CHECK (length(request_id) = 36),
            relation TEXT NOT NULL CHECK (relation IN ('direct', 'relay')),
            discovered_at TEXT
                CHECK (discovered_at IS NULL
                       OR length(discovered_at) BETWEEN 20 AND 35),
            captured_at TEXT
                CHECK (captured_at IS NULL
                       OR length(captured_at) BETWEEN 20 AND 35),
            envelope_created_at TEXT
                CHECK (envelope_created_at IS NULL
                       OR length(envelope_created_at) BETWEEN 20 AND 35),
            recorded_at TEXT NOT NULL
                CHECK (length(recorded_at) BETWEEN 20 AND 35)
        );
        CREATE UNIQUE INDEX idx_upload_attestations_request
            ON upload_attestations (request_id);
        CREATE INDEX idx_upload_attestations_occurrence
            ON upload_attestations (occurrence_id);
    ",
    down: Some(
        r"
        DROP INDEX idx_upload_attestations_occurrence;
        DROP INDEX idx_upload_attestations_request;
        DROP TABLE upload_attestations;
    ",
    ),
};

/// Migration 7: signed receipts.
///
/// One row per committed upload, keyed by the frozen request it
/// acknowledges. A receipt is evidence: `ON DELETE RESTRICT` back into
/// `frozen_requests` means the request a receipt attests can never be
/// deleted out from under it. `signature_verified` records whether the
/// receipt signature has been checked under the named receipt key; the
/// acknowledgement transaction may only advance state on a verified row.
const RECEIPTS: Migration = Migration {
    version: 7,
    name: "create-receipts",
    up: r"
        CREATE TABLE receipts (
            request_id TEXT PRIMARY KEY NOT NULL
                REFERENCES frozen_requests (request_id) ON DELETE RESTRICT,
            receipt_key_id TEXT NOT NULL
                CHECK (length(receipt_key_id) BETWEEN 1 AND 64),
            signature TEXT NOT NULL CHECK (length(signature) = 128),
            receipt_digest TEXT NOT NULL CHECK (length(receipt_digest) = 64),
            commit_ordinal INTEGER NOT NULL CHECK (commit_ordinal >= 0),
            commit_time TEXT NOT NULL
                CHECK (length(commit_time) BETWEEN 20 AND 35),
            signature_verified INTEGER NOT NULL
                CHECK (signature_verified IN (0, 1)),
            received_at TEXT NOT NULL
                CHECK (length(received_at) BETWEEN 20 AND 35)
        );
        CREATE INDEX idx_receipts_commit ON receipts (commit_ordinal);
    ",
    down: Some(
        r"
        DROP INDEX idx_receipts_commit;
        DROP TABLE receipts;
    ",
    ),
};

/// Migration 8: adapter health.
///
/// Per-adapter scheduling health for the two-lane scheduler. `last_error_code`
/// holds a stable content-free error code; the check constraint's non-empty
/// rule plus the 128-character bound keep it a token, never a message that
/// could carry transcript or path content.
const ADAPTER_HEALTH: Migration = Migration {
    version: 8,
    name: "create-adapter-health",
    up: r"
        CREATE TABLE adapter_health (
            adapter_id TEXT PRIMARY KEY NOT NULL
                CHECK (length(adapter_id) BETWEEN 1 AND 64),
            health_state TEXT NOT NULL DEFAULT 'healthy' CHECK (
                health_state IN ('healthy', 'degraded', 'disabled')
            ),
            consecutive_failures INTEGER NOT NULL DEFAULT 0
                CHECK (consecutive_failures >= 0),
            last_success_at TEXT
                CHECK (last_success_at IS NULL
                       OR length(last_success_at) BETWEEN 20 AND 35),
            last_failure_at TEXT
                CHECK (last_failure_at IS NULL
                       OR length(last_failure_at) BETWEEN 20 AND 35),
            last_error_code TEXT
                CHECK (last_error_code IS NULL
                       OR length(last_error_code) BETWEEN 1 AND 128)
        );
    ",
    down: Some(
        r"
        DROP TABLE adapter_health;
    ",
    ),
};

/// Every schema migration, oldest first. The runner refuses gaps, so this
/// slice must stay contiguous from version 1.
pub(crate) const MIGRATIONS: &[Migration] = &[
    SOURCES,
    GENERATIONS,
    SPOOL_ENTRIES,
    FROZEN_REQUESTS,
    RANGES,
    UPLOAD_ATTESTATIONS,
    RECEIPTS,
    ADAPTER_HEALTH,
];

/// Tables the schema is expected to contain once every migration is applied,
/// including the migration history table the runner itself maintains.
pub(crate) const EXPECTED_TABLES: &[&str] = &[
    "schema_migrations",
    "sources",
    "generations",
    "spool_entries",
    "frozen_requests",
    "ranges",
    "upload_attestations",
    "receipts",
    "adapter_health",
];

/// Named indexes the schema is expected to contain once every migration is
/// applied. Unique constraints create anonymous automatic indexes; only the
/// explicitly named ones are listed here.
pub(crate) const EXPECTED_INDEXES: &[&str] = &[
    "idx_generations_source",
    "idx_spool_entries_state",
    "idx_frozen_requests_occurrence",
    "idx_ranges_generation",
    "idx_ranges_spool",
    "idx_upload_attestations_request",
    "idx_upload_attestations_occurrence",
    "idx_receipts_commit",
];
