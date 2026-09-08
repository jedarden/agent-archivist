// SPDX-License-Identifier: Apache-2.0

//! Claude Code source adapter.
//!
//! Discovers default and explicitly configured Claude Code account and source
//! roots, captures JSONL session files and related sidecars as separate
//! artifact kinds with explicit relationships, parses only on complete record
//! boundaries, and detects inode/file identity changes, truncation, tail
//! mismatch, and rewrites as new source generations. Harness and upstream
//! session IDs are preserved without treating either as global
//! (implementation plan, Phase 6A).
//!
//! Ships in the first adapter wave: file-based capture exercises marathon
//! chunking and these histories are expected to be the largest. An embedded
//! fingerprint allowlist fails closed on unknown schema versions rather than
//! attempting a best-effort parse.
//!
//! # Status
//!
//! Skeleton scaffold (Phase 0). Implementation arrives with Phase 6A and its
//! golden projection, active-growth, replacement, permission, and missing-root
//! tests. It deliberately contains no placeholder production code.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-adapter-sdk` only. Must not depend on the other
//! adapters, the client engine, storage, or the server.
