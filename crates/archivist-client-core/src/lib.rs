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
//! The client state schema — explicit `SQLite` (WAL) migrations for sources,
//! generations, spool entries, frozen requests, ranges, upload attestations,
//! receipts, and adapter health, with automated integrity checks — arrived
//! with Phase 5; see [`state`]. The configuration loader — XDG-native TOML
//! discovery, flag/environment/file/default precedence, protected secret
//! references, and the stable exit-64 error surface — arrived with Phase 5
//! as well; see [`config`]. The crash-safe spool — mode-`0600` bundle
//! materialization, atomic rename, commit-after-rename ordering, and the
//! startup reconciliation pass — arrived with Phase 5 too; see [`spool`].
//! The source backlog inventory — complete outstanding bytes and events per
//! source, cursors retained in front of uncaptured ranges, and bounded
//! adapter/account status — arrived with Phase 5 alongside them; see
//! [`inventory`]. The registry-driven command parser, output envelope, error
//! diagnostics, and handler router live in [`cli`]; command behavior remains
//! in the implementing library crates and is attached by the composition
//! root. The remaining surfaces are still the Phase 0 skeleton and
//! deliberately contain no placeholder production code.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` and `archivist-adapter-sdk` only. Must
//! not depend on the server, a concrete storage backend, or any specific
//! harness adapter.

pub mod cli;
pub mod config;
pub mod inventory;
pub mod spool;
pub mod state;
