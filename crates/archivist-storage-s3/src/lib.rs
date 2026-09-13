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
//! The adapter behavior arrives with its own deliverables: capability
//! probing, the synthetic compatibility suite against the local reference
//! backend, B2, and ARMOR, and the deterministic commits.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-storage` (and through it `archivist-protocol`).
//! Backend SDK types must not leak past this crate: only the composition root
//! (`archivist-cli`) selects this implementation.

pub mod config;
