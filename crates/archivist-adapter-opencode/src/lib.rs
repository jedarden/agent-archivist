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
//! allowlisted projection and the parity oracle
//! — a transactionally consistent read-only snapshot and the adapter
//! producing identical allowlisted keys, row counts, null/presence bits,
//! and per-field digests — arrive with the remaining Phase 6B work.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-adapter-sdk` only. Must not depend on the other
//! adapters, the client engine, storage, or the server. The pinned,
//! bundled `rusqlite` driver is the crate's one external dependency, kept
//! inside the adapter per docs/notes/crate-ownership.md rule 3.

mod schema;
mod store_connection;

pub use schema::{
    ALLOWED_TABLES, ALLOWED_VERSIONS, DetectError, PROJECTION_VERSION, SUPPORTED_FINGERPRINT,
    SchemaDivergence, adapter_descriptor, detect,
};
pub use store_connection::{BUSY_TIMEOUT, StoreConnection, StoreOpenError};
