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
//! The **validated server configuration** (plan Section 8, Phase 4, first
//! slice) is implemented: [`config`] carries the registered `server.*`
//! settings as typed values and assembles them through a fail-closed
//! builder that performs no I/O and creates no durable local state.
//!
//! The **trust anchors** and the **shared replica state with its readiness
//! ledger** are implemented: [`trust`] pins, per served tenant, the one
//! authority key whose signatures count as that tenant's control-plane
//! voice, validated fail-closed before a replica can start; [`state`]
//! composes the validated configuration, the anchor set, and the two
//! storage identities into the value every handler shares, and carries
//! [`state::ReadinessTracker`], the per-tenant trust-evidence ledger that
//! starts not-ready, expires evidence after 60 seconds, and holds no
//! durable local state.
//!
//! The **registered metrics families** and the **four routes** are
//! implemented: [`metrics`] holds the process-local snapshot and renders
//! the Prometheus text exposition for exactly the registered
//! `archivist.server.*` families, omitting a series rather than
//! inventing a value; [`routes`] mounts `/health/live` (process-only),
//! `/health/ready` (derived strictly from the readiness ledger),
//! `/metrics`, and `/v1/ingest` — registered but fail-closed, refusing
//! every attempt with the stable retryable `server.unavailable` body
//! until the pipeline slices land.
//!
//! The rest of the Phase 4 bootstrap surface — cancellation-aware
//! startup and graceful shutdown — lands module by module, each with its
//! `mod` declaration; the ingestion pipeline (bounded parsing,
//! authorization, and validation middleware, streaming envelope
//! validation, the blob → occurrence → attestation commit order, signed
//! receipts) arrives on those contracts. Until then this crate contributes
//! configuration, trust anchors, replica state, metrics, and the routes.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol`, `archivist-auth`, and the
//! `archivist-storage` traits only — never on a concrete backend crate, which
//! the composition root (`archivist-cli`) selects. Must not depend on the
//! client engine or any source adapter.

pub mod config;
pub mod metrics;
pub mod routes;
pub mod state;
pub mod trust;
