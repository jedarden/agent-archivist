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
//!   `inventory-v1` before rebuild, restore, or reference scans;
//! - [`scoped_write::CatalogWriteStore`] and
//!   [`scoped_write::DerivedWriteStore`] — the Phase 10 append identities:
//!   `put` and `list` below one derived namespace each (catalog
//!   checkpoints, derived projections), and nothing else.
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
//! - [`probe`] — the capability probe: it observes conditional create,
//!   multipart commit/abort, stored checksum form, versioning, and
//!   server-side encryption without mutating arbitrary keys, reduces every
//!   unestablished fact to the weaker model value, caches only advisory
//!   results, and renders each run as a digestible
//!   `archivist.capability-report/v1` evidence record.
//! - [`metadata`] — observation metadata (`ETag`, storage version, observation
//!   time) shared by reads, listings, and the inventory.
//! - [`raw_write`] — the raw writer: multipart blob commits and
//!   deterministic manifest writes, and nothing else.
//! - [`multipart`] — the streaming multipart writer: bounded 8 MiB part
//!   sessions over [`raw_write::RawWriteStore`], cancellation-safe cleanup,
//!   and the bounded manifest `PUT`.
//! - [`commit`] — the deterministic commit decision layer over
//!   [`raw_write::RawWriteStore`]: primitive selection from the reported
//!   capability (atomic conditional create when established, deterministic
//!   overwrite when writer-only), already-exists convergence with
//!   integrity-conflict validation, and the honest writer-only outcome.
//! - [`blob`] — the content-addressed blob commit path: one canonical
//!   payload streamed through the pinned encoder and an uncommitted
//!   multipart session at the derived blob key, completed only after the
//!   declared digest and size verify — validate-before-complete with
//!   retry convergence and honest outcome pass-through.
//! - [`manifests`] — the occurrence-manifest and upload-attestation commit
//!   path: the two durable raw-provenance documents built from a validated
//!   envelope and committed at their derived keys with server-side
//!   identity re-derivation and dedupe-not-conflict semantics.
//! - [`zstd_v1`] — the pinned `zstd-v1` storage codec: the deterministic
//!   Zstandard encoder behind the blob commit path's
//!   [`blob::BlobEncoder`] seam and the matching window-capped decoder,
//!   the exact parameter set plan Section 7.6 freezes for the profile.
//! - [`control`] — the control-plane boundary: the read-only replica view,
//!   the offline administrator store, and the record-kind vocabulary their
//!   keys are derived from.
//! - [`audit_restore`] — the offline audit/restore identity: paginated
//!   enumeration, the frozen `inventory-v1` contract, and object inspection
//!   and bounded reads.
//! - [`catalog_source`] — the raw catalog source reader: deterministic,
//!   validating iteration over a frozen tenant raw prefix (occurrences,
//!   attestations, referenced blobs) for offline catalog rebuild and
//!   reference scans; reachable only through the audit/restore identity.
//! - [`collection`] — the disabled-by-default two-pass blob collector:
//!   retention-aware reference planning, simulation, pre-delete metadata
//!   revalidation, and canonical audit evidence.
//! - [`ingest`] — the composition of the two ingest identities, proving the
//!   authority boundary at the type level.
//! - [`scoped_write`] — the Phase 10 scoped writers: catalog checkpoints
//!   and derived projections, appended and enumerated below one derived
//!   namespace each.
//!
//! # Status
//!
//! Phase 2 (storage core): the authority traits, the capability model, the
//! capability probe ([`probe`]), and the `inventory-v1` freeze contract
//! are defined. The streaming multipart writer ([`multipart`])
//! orchestrates raw-write sessions with bounded memory,
//! validate-before-complete, and cancellation-safe cleanup. The
//! deterministic commit decision layer ([`commit`]) selects the write
//! primitive from the reported capability and resolves replays honestly,
//! the content-addressed blob commit path ([`blob`]) drives one
//! payload through encoder and session, completing only on verified
//! identity, and the manifest commit path ([`manifests`]) lands the
//! occurrence manifest and upload attestation at their derived keys with
//! server-side identity re-derivation and dedupe-not-conflict semantics,
//! and the pinned `zstd-v1` codec ([`zstd_v1`]) is the storage transform
//! that path drives. The raw catalog source reader ([`catalog_source`]) reads that committed
//! raw provenance back — validating, deterministic iteration over a frozen
//! tenant raw prefix for offline catalog rebuild and reference scans
//! (plan Section 8, Phase 10).
//! Backend behavior — the portable S3 adapter's probe source and store,
//! which implement the primitives these layers drive — arrives with its own
//! deliverables (plan Section 8, Phase 2).
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` only. Must not name or depend on any
//! concrete backend (S3, `MinIO`, B2, ARMOR), transport, or client component.

pub mod audit_restore;
pub mod blob;
pub mod capability;
pub mod catalog_source;
pub mod collection;
pub mod commit;
pub mod control;
pub mod error;
pub mod ingest;
pub mod manifests;
pub mod metadata;
pub mod multipart;
pub mod probe;
pub mod raw_write;
pub mod scoped_write;
pub mod zstd_v1;
