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
//! The **serve lifecycle** is implemented: [`serve`] composes the
//! bootstrap surface into the three-step replica lifecycle —
//! [`serve::ArchivistServer::new`] holds the validated parts with no
//! I/O, [`serve::ArchivistServer::bind`] opens the listening socket as
//! the replica's first syscall (allocating nothing durable; its only
//! failure is [`serve::StartupError`], naming the address), and
//! [`serve::BoundServer::serve`] runs until cancelled, then drains
//! in-flight work within the configured `server.shutdown_drain_seconds`
//! window and reports [`serve::ShutdownOutcome`] to the composition
//! root. Cancellation is explicit — [`serve::shutdown_channel`] hands
//! out one trigger and one signal, and [`serve::shutdown_on_signal`] is
//! the SIGTERM/SIGINT future a service deployment wires in.
//!
//! The **liveness probe** is implemented: [`probe`] is the one bounded GET
//! on the process-only liveness route that the release image's
//! `HEALTHCHECK` invokes through the binary's registered `probe` command
//! (release-container RC-020) — the image's own binary is the probe
//! mechanism, the runtime base shipping no probe tooling to fetch one
//! with and the runtime stage installing no packages.
//!
//! The **request resource guards** are implemented: [`guard`] holds the
//! admission gate — the process-wide 16-slot in-flight cap, the
//! four-per-client in-flight share, the 60/minute burst-8 per-client
//! new-request token bucket, and the 15-minute request deadline —
//! composed into the shared state and enforced before anything
//! request-derived happens, refusing with the retryable `throttle`-class
//! bodies the registry pins. The route-level half (deadline, process
//! cap) runs on the bootstrap surface today; the per-client half admits
//! through `AdmissionGate::admit_client` at the point the pipeline's
//! authorization middleware knows the uploader identity.
//!
//! The **multipart/related framing layer** is implemented: [`parse`] holds
//! [`parse::framing`], which validates the request Content-Type against
//! the pinned `multipart/related; boundary=<token>` grammar before any
//! body byte is read and then tokenizes the body into part boundaries,
//! part headers, and payload runs while buffering no more than a fixed
//! small window — bounded memory for any body size (protocol Section 1.2;
//! VAL-008). Every framing rejection is the registry's
//! `request.framing_invalid`, typed by stage and content-free. The
//! pipeline slices consume it when they land, still replacing the
//! fail-closed ingest stub.
//!
//! The **parser's public error surface** is implemented: [`parse::ingest`]
//! hands the extracted part-one bytes to `archivist-protocol`'s envelope
//! parser and maps every rejection — media, part order, identifier,
//! coordinate, encoding, size, schema — onto a frozen registry code with
//! the pinned message template rendered content-free, before any commit.
//!
//! The **bounded transport-decode stage** is implemented: [`transport`]
//! turns part two's declared `TransportEncoding` — identity
//! pass-through, or one Zstandard frame through the storage profile's
//! window-capped decoder — into bounded canonical chunks, enforcing the
//! 256 MiB single-record cap and the 100:1 expansion ratio mid-stream
//! against the bytes actually produced, so a violating attempt fails
//! before anything commits; once failed, the stage is closed — it
//! re-yields that first failure on every later call and never reads the
//! source again. Memory follows the chunk and concurrency buffers,
//! never the body. The **ingest route** now drives that stage end to
//! end: a well-formed attempt streams through the bounded parse into the
//! decode stage and a `commit_blob` session begun under the envelope's
//! derived key, with the store-side abort its failures demand — the
//! drain's verdict gates the encoder, a failed attempt aborts its live
//! session, and nothing is stored. Behind the durable blob the
//! provenance tail lands the occurrence manifest and then the upload
//! attestation, and when all three objects stand the receipt strand
//! renders success: the tenant's retained signing schedule issues the
//! authenticated receipt — identities, server-derived object keys,
//! per-object outcomes, successful authorization key and epoch, signer
//! chain, and commit time — as the HTTP 200 body (RCPT-001, RCPT-002,
//! RCPT-006). The store's physical answer passes through untouched
//! (RCPT-003), and the payload limits and digest verification are the
//! real checks, not placeholders. A tenant with no retained schedule —
//! and any attempt whose provenance tail fails — still answers the
//! retryable `server.partial_commit` class with no receipt (RCPT-005).
//!
//! The **receipt signing schedules** are implemented: [`receipts`]
//! holds the per-tenant [`receipts::ReceiptSigners`], composed once at
//! startup from certified keys loaded through protected references and
//! threaded through [`state`] into the commit path, plus the one
//! assembly site that signs a complete commit's evidence; the offline
//! chain a client verifies — pinned authority root over the embedded
//! certificate, certificate key over the receipt — is `archivist-auth`'s
//! receipt module.
//!
//! The Phase 4 bootstrap surface is complete: configuration, trust
//! anchors, replica state, metrics, the routes, the serve lifecycle, the
//! request resource guards, and signed receipts.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol`, `archivist-auth`, and the
//! `archivist-storage` traits only — never on a concrete backend crate, which
//! the composition root (`archivist-cli`) selects. Must not depend on the
//! client engine or any source adapter.

pub mod authorize;
pub mod config;
pub mod error;
pub mod guard;
pub mod metrics;
pub mod parse;
pub mod probe;
pub mod receipts;
pub mod routes;
pub mod serve;
pub mod state;
pub mod transport;
pub mod trust;
