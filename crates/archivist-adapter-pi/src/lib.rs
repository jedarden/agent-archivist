// SPDX-License-Identifier: Apache-2.0

//! Pi source adapter.
//!
//! Discovers configured Pi roots and its supported durable session formats.
//! JSONL sources follow the complete-record and generation rules of the file
//! adapters; immutable session files are captured one object per fingerprinted
//! file, with a new generation whenever the file identity or digest changes.
//! No-session and ephemeral modes are reported as coverage gaps rather than
//! silently skipped (implementation plan, Phase 6C).
//!
//! # Status
//!
//! Skeleton scaffold (Phase 0). Implementation arrives with Phase 6C and its
//! golden projection, active-growth, replacement, permission, and missing-root
//! tests. It deliberately contains no placeholder production code.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-adapter-sdk` only. Must not depend on the other
//! adapters, the client engine, storage, or the server.
