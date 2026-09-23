// SPDX-License-Identifier: Apache-2.0

//! `OpenCode` source adapter.
//!
//! Opens the supported `OpenCode` database read-only with a five-second busy
//! timeout, detects the schema version before querying, and projects only the
//! allowlisted session, message, part, input, and task fields as RFC 8785 JSONL
//! records. Account, token, credential, provider-auth, and unrelated cache
//! tables are never read or projected, and large fields are verified against
//! direct database reads so export truncation cannot pass silently
//! (implementation plan, Phase 6B).
//!
//! # Status
//!
//! Phase 6B in progress. The read-only store connection is implemented:
//! [`StoreConnection`] opens the configured database under the driver's
//! read-only flag with the five-second busy window, and open-time outcomes
//! classify into the SDK's closed
//! [`ScanClassification`](archivist_adapter_sdk::ScanClassification)
//! vocabulary. The schema-version gate is implemented: [`detect`]
//! validates the store's schema metadata against the embedded allowlist
//! before any projected content is read, and [`adapter_descriptor`]
//! publishes the adapter's fail-closed fingerprint allowlist. The
//! transactionally consistent snapshot is implemented: [`Snapshot::take`]
//! gates on the schema allowlist and reads the five allowlisted tables
//! inside one read transaction, with deterministic ordering, per-cell
//! presence bits, raw field bytes, and shape-only debug output. The
//! allowlisted projection is implemented: [`Projection::project`] renders
//! the snapshot as one RFC 8785 canonical JSON record per allowlisted row
//! — the table, its ordered key tuple, and every allowlisted field with
//! `null` where the cell is NULL — and a cell with no faithful canonical
//! form (a blob, invalid UTF-8, a non-finite float) fails the projection
//! closed, so no partial export exists to mistake for complete. The
//! parity evidence (`tests/projection.rs`) reconciles the Phase 6 parity
//! tuple — keys, order, row counts, null/presence bits, and per-field
//! digests — against direct database reads and verifies large fields
//! byte-exactly, so export truncation cannot pass silently. The
//! assembled-reader fault suite (`tests/
//! database_faults.rs`) lands the "database-contention-faults" gate-row
//! evidence: unknown schemas, locks held past the busy window, store bytes
//! that vanish mid-scan, and permission denials all classify into the
//! closed vocabulary without reading projected content, the harness's own
//! writer commits through the reader's whole contention window, and
//! hostile or oversized cells never reach a rendering surface
//! (docs/security/threats/adapter-capture.md).
//!
//! # Dependency boundary
//!
//! Depends on `archivist-adapter-sdk` only. Must not depend on the other
//! adapters, the client engine, storage, or the server. The pinned,
//! bundled `rusqlite` driver is the crate's one external dependency, kept
//! inside the adapter per docs/notes/crate-ownership.md rule 3.

mod canonical;
mod projection;
mod schema;
mod snapshot;
mod store_connection;

pub use canonical::{Json, Object};
pub use projection::{FieldValue, ProjectedRow, Projection, ProjectionError};

pub use schema::{
    adapter_descriptor, detect, DetectError, SchemaDivergence, ALLOWED_TABLES, ALLOWED_VERSIONS,
    PROJECTION_VERSION, SUPPORTED_FINGERPRINT,
};
pub use snapshot::{Cell, Row, Snapshot, SnapshotError, TableSnapshot};
pub use store_connection::{StoreConnection, StoreOpenError, BUSY_TIMEOUT};
