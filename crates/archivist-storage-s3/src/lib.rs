// SPDX-License-Identifier: Apache-2.0

//! Portable S3 implementation of the Archivist storage traits.
//!
//! One adapter serves every S3-compatible backend (reference `MinIO`, AWS S3,
//! B2, ARMOR's S3 path, Garage) through configurable endpoint, region,
//! path-style, and TLS settings, and reports observed backend capabilities
//! instead of assuming them. Content-addressed blob commits stream canonical
//! bytes through the pinned `zstd-v1` encoder into uncommitted multipart
//! uploads and complete only after size, digest, and signature validation;
//! deterministic occurrence and upload-attestation manifests commit after the
//! objects they depend on (implementation plan, Sections 7.6 and 7.7).
//!
//! # Status
//!
//! Phase 2, first slice: the portable configuration surface
//! ([`config`]) — endpoint, region, path style, transport security,
//! at-rest encryption policy, buckets, and the four-role credential
//! identity mapping — validated fail-closed before any store is built.
//! Second slice: the offline control administrator ([`control_admin`]) —
//! the portable `ControlAdminStore` over the dedicated, protected
//! credential reference the [`config`] module's `ControlAdminConfig`
//! surface validates, deriving each object key from the record envelope's
//! own validated members, writing immutable families once and replacing
//! current pointers only on a strictly higher signed epoch. Third slice:
//! the raw writer ([`raw_write`]) — the portable `RawWriteStore` over the
//! raw-writer credential for one pinned tenant: bounded manifest `PUT`s
//! through the atomic conditional-create decision layer when the observed
//! capability report establishes it and deterministic overwrite otherwise,
//! multipart sessions committed on exactly their own recorded
//! commitments, and idempotent abort as the cancellation-safe cleanup.
//! Fourth slice: the Phase 10 scoped writers ([`scoped_write`]) — the
//! portable `CatalogWriteStore` and `DerivedWriteStore` over the two
//! provisioned `put+list` identities, appending and enumerating catalog
//! checkpoints and derived projections below one namespace each. Fifth
//! slice: the ingestion replica's control reads ([`control_read`]) — the
//! portable `ControlReadStore` over the dedicated read-only credential
//! the [`config`] module's `ControlReadConfig` surface validates, five
//! bounded signed-record reads and their head inspections derived through
//! the same key grammar the administration store writes with. The
//! remaining adapter behavior arrives with its own deliverables:
//! capability probing, the synthetic compatibility suite against the
//! local reference backend, B2, and ARMOR, and the ingest reads.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-storage` (and through it `archivist-protocol`).
//! Backend SDK types must not leak past this crate: only the composition root
//! (`archivist-cli`) selects this implementation.

pub mod config;
pub mod control_admin;
pub mod control_read;
pub mod raw_write;
pub mod scoped_write;
