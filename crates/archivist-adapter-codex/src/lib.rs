// SPDX-License-Identifier: Apache-2.0

//! Codex source adapter.
//!
//! Discovers configured Codex account and source roots, captures JSONL session
//! files and related sidecars as separate artifact kinds with explicit
//! relationships, parses only on complete record boundaries, and detects
//! inode/file identity changes, truncation, tail mismatch, and rewrites as new
//! source generations (implementation plan, Phase 6A).
//!
//! Ships in the first adapter wave alongside the Claude Code adapter. An
//! embedded fingerprint allowlist fails closed on unknown schema versions
//! rather than attempting a best-effort parse.
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
