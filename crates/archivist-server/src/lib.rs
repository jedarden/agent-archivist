// SPDX-License-Identifier: Apache-2.0

//! Stateless Archivist ingestion data plane: the `/v1/ingest` route,
//! `/health/live`, `/health/ready`, and `/metrics`, bounded parsing,
//! authorization, validation, rate-limiting, and concurrency-limiting
//! middleware, streaming validation of the payload through decompression and
//! hashing, the blob → occurrence → upload-attestation commit order, signed
//! receipts, content-free structured errors, and graceful shutdown that aborts
//! unfinished multipart uploads.
//!
//! Replicas hold no state between requests; S3-compatible storage is the only
//! durable server-side truth, and an identical retry after a partial commit
//! repairs the same deterministic objects (implementation plan, Sections 5 and
//! 7.7). Every limit — 64 KiB envelope, 256 MiB record, 100:1 expansion,
//! 15-minute deadline, 8 MiB multipart part, 16 in-flight uploads — is applied
//! before payload-scale resources are allocated (Section 7.6).
//!
//! # Status
//!
//! Skeleton scaffold (Phase 0). Implementation arrives with Phase 4 on the
//! Phase 1–3 contracts. It deliberately contains no placeholder production
//! code.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol`, `archivist-auth`, and the
//! `archivist-storage` traits only — never on a concrete backend crate, which
//! the composition root (`archivist-cli`) selects. Must not depend on the
//! client engine or any source adapter.
