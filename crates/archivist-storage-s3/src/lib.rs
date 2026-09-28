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
//! the same key grammar the administration store writes with. Sixth
//! slice: the offline lifecycle audit ([`lifecycle_audit`]) — the
//! portable `LifecycleAuditStore` over the optional offline-restore
//! credential, listing every physical version under the identity's
//! tenant scopes and reporting the noncurrent accumulation requirements
//! STO-009 makes a deployment duty. Seventh slice: the live capability
//! probe ([`probe`]) — the portable `CapabilitySource` over the probe
//! authority's write-shaped instrument, reserved probe namespace
//! included, that binds the five-axis report every qualification run
//! opens with. Eighth slice: the community qualification runner
//! ([`qualify`]) — the operator-side engine that executes the
//! community kit's three legs in order over the public seams and files
//! the honest outcome, no subset waived. The remaining adapter behavior
//! arrives with its own deliverable: the ingest reads.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-storage` (and through it `archivist-protocol`).
//! Backend SDK types must not leak past this crate: only the composition root
//! (`archivist-cli`) selects this implementation.

pub mod config;
pub mod control_admin;
pub mod control_read;
pub mod lifecycle_audit;
pub mod probe;
pub mod qualify;
pub mod raw_write;
pub mod request;
pub mod scoped_write;
