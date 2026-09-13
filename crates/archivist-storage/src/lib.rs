// SPDX-License-Identifier: Apache-2.0

//! Archivist storage contract: the capability model (conditional create,
//! multipart commit/abort, stored checksums, versioning, server-side
//! encryption) and the store traits that split storage authority into
//! deliberately disjoint identities:
//!
//! - [`raw_write::RawWriteStore`] — the only identity with begin/write/commit/abort
//!   semantics, scoped to the tenant raw prefix;
//! - [`control::ControlReadStore`] — read-only access to signed tenant control records;
//! - [`control::ControlAdminStore`] — offline administrator writes of validated,
//!   tenant-authority-signed control records;
//! - [`audit_restore::AuditRestoreStore`] — offline enumeration that freezes an immutable
//!   `inventory-v1` before rebuild, restore, or reference scans.
//!
//! An ingestion replica is configured with exactly the first two
//! ([`ingest::IngestStorage`]); because the traits are disjoint by
//! construction — no read, delete, list, audit, catalog, derived, or
//! control-write method exists on any trait the ingest path binds — the
//! authority split is structural, not a runtime policy (plan Section 5).
//!
//! Traits here are owned by this project so an implementation can be replaced
//! without changing the wire contract; backend SDK types never cross this
//! boundary (implementation plan, Section 4).
//!
//! # Layout
//!
//! - [`error`] — the closed failure classes a store call reports and the
//!   content-safe error type that carries them.
//! - [`capability`] — the capability model every raw writer reports;
//!   observed optional capabilities are advisory, never assumed.
//! - [`metadata`] — observation metadata (`ETag`, storage version, observation
//!   time) shared by reads, listings, and the inventory.
//! - [`raw_write`] — the raw writer: multipart blob commits and
//!   deterministic manifest writes, and nothing else.
//! - [`multipart`] — the streaming multipart writer: bounded 8 MiB part
//!   sessions over [`raw_write::RawWriteStore`], cancellation-safe cleanup,
//!   and the bounded manifest `PUT`.
//! - [`control`] — the control-plane boundary: the read-only replica view,
//!   the offline administrator store, and the record-kind vocabulary their
//!   keys are derived from.
//! - [`audit_restore`] — the offline audit/restore identity: paginated
//!   enumeration, the frozen `inventory-v1` contract, and object inspection
//!   and bounded reads.
//! - [`ingest`] — the composition of the two ingest identities, proving the
//!   authority boundary at the type level.
//!
//! # Status
//!
//! Phase 2 (storage core): the authority traits, the capability model, and
//! the `inventory-v1` freeze contract are defined, and the streaming
//! multipart writer ([`multipart`]) orchestrates raw-write sessions with
//! bounded memory, validate-before-complete, and cancellation-safe cleanup.
//! Backend behavior — the portable S3 adapter, capability probing, and the
//! deterministic commits that drive this writer — arrives with its own
//! deliverables (plan Section 8, Phase 2).
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` only. Must not name or depend on any
//! concrete backend (S3, `MinIO`, B2, ARMOR), transport, or client component.

pub mod audit_restore;
pub mod capability;
pub mod control;
pub mod error;
pub mod ingest;
pub mod metadata;
pub mod multipart;
pub mod raw_write;
