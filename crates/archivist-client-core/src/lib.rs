// SPDX-License-Identifier: Apache-2.0

//! Archivist client engine: discovery cursors, the crash-safe mode-restricted
//! spool, immutable canonical upload envelopes with per-attempt
//! re-authorization, the freshness/backfill scheduler, receipt verification
//! and acknowledgement, `SQLite` (WAL) state with explicit migrations, retry
//! policy, and spool/free-disk high-water behavior.
//!
//! Clients own discovery cursors, pending spools, retry schedules, and
//! acknowledgements; the server holds no durable per-client state
//! (implementation plan, Section 3). A spool bundle is durable on disk before
//! its state row commits, and payload cleanup happens only after the
//! receipt/acknowledgement transaction commits (Section 7.9).
//!
//! # Status
//!
//! Skeleton scaffold (Phase 0). Behavior arrives with Phase 5 (durable client
//! engine). It deliberately contains no placeholder production code.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` and `archivist-adapter-sdk` only. Must
//! not depend on the server, a concrete storage backend, or any specific
//! harness adapter.
