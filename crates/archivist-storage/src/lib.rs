// SPDX-License-Identifier: Apache-2.0

//! Archivist storage contract: the capability model (conditional create,
//! multipart commit/abort, stored checksums, versioning, server-side
//! encryption) and the store traits that split storage authority into
//! deliberately disjoint identities:
//!
//! - `RawWriteStore` — the only identity with begin/write/commit/abort
//!   semantics, scoped to the tenant raw prefix;
//! - `ControlReadStore` — read-only access to signed tenant control records;
//! - `ControlAdminStore` — offline administrator writes of validated,
//!   tenant-authority-signed control records;
//! - `AuditRestoreStore` — offline enumeration that freezes an immutable
//!   `inventory-v1` before rebuild, restore, or reference scans.
//!
//! Traits here are owned by this project so an implementation can be replaced
//! without changing the wire contract; backend SDK types never cross this
//! boundary (implementation plan, Section 4).
//!
//! # Status
//!
//! Skeleton scaffold (Phase 0). Behavior arrives with Phase 2 (storage core
//! and backend compatibility) implementing the Section 7.7 and 7.10
//! contracts. It deliberately contains no placeholder production code.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` only. Must not name or depend on any
//! concrete backend (S3, `MinIO`, B2, ARMOR), transport, or client component.
