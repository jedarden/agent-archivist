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
//! [`inventory`]. The two-lane freshness/backfill scheduler — one
//! deterministic pass that drains the pending spool, reserves one chunk
//! for every active source, then spends the remaining capacity
//! largest-backlog-first under a 256 MiB per-source quantum, with
//! deterministic simulations proving largest histories progress first
//! while small and low-volume sources stay starvation-bounded — plans the
//! cycle from that inventory; see [`scheduler`]. The immutable upload
//! retry state — [`upload::freeze_upload`] freezes the identity at spool
//! creation (request, occurrence, and upload-attestation), while each claim
//! receives fresh per-attempt authorization, the full-jitter schedule runs
//! from one second to a 15-minute cap with no attempt limit, and the locked
//! Section 7.8 error matrix's quarantine survives a restart — turns a
//! materialized bundle into a retried, re-authorized upload promise; see
//! [`upload`]. The nonoverlapping daemon loop — [`daemon::run`] starts the
//! first cycle immediately and each later cycle one uniformly jittered delay
//! (fifteen minutes, up to ten percent) after the previous cycle *returned*,
//! times every wait on the monotonic clock a wall-clock step cannot bend,
//! and stops only on cancellation or a dead jitter source while holding two
//! words of state — is the shell the collection engine attaches to at the
//! composition root; see [`daemon`]. The operator report documents —
//! [`report`] reads the same engine through a read-only snapshot to compose
//! the `status` and `verify-state` reports and the one-cycle `run`
//! document, every figure a content-free counter pinned to its
//! `schemas/v1/` wire shape — are what the composition root's command
//! handlers emit. The registry-driven
//! command parser, output envelope, error diagnostics, and handler router
//! live in [`cli`]; command behavior remains in the implementing library
//! crates and is attached by the composition root. The remaining surfaces
//! are still the Phase 0 skeleton and deliberately contain no placeholder
//! production code.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` and `archivist-adapter-sdk` only. Must
//! not depend on the server, a concrete storage backend, or any specific
//! harness adapter.

pub mod acknowledgement;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod doctor;
pub mod inventory;
pub mod report;
pub mod scheduler;
pub mod spool;
pub mod state;
pub mod upload;
