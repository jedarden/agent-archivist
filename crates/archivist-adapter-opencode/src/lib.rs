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
//! Skeleton scaffold (Phase 0). Implementation arrives with Phase 6B and its
//! parity oracle: a transactionally consistent read-only snapshot and the
//! adapter must produce identical allowlisted keys, row counts, null/presence
//! bits, and per-field digests. It deliberately contains no placeholder
//! production code.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-adapter-sdk` only. Must not depend on the other
//! adapters, the client engine, storage, or the server.
