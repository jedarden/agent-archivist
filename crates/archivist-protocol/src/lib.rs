// SPDX-License-Identifier: Apache-2.0

//! Archivist wire protocol: versioned envelope, occurrence, upload-attestation,
//! control, receipt, and error types, their validation and compatibility rules,
//! deterministic identifier and object-key derivation, and canonical (RFC 8785)
//! serialization.
//!
//! This crate is the foundation of the dependency graph and depends on nothing
//! else in the workspace. Every other crate speaks Archivist through the types
//! defined here, which is what keeps the wire contract independent of any
//! transport, storage backend, source harness, or SDK.
//!
//! # Layout
//!
//! - [`vocabulary`] — the project-owned wire vocabulary: identifier grammars,
//!   digests, and the closed v1 enum sets, each a validated newtype over text
//!   or bytes rather than a borrowed SDK shape.
//! - [`json`] — RFC 8785 canonical JSON over the protocol's no-float value
//!   domain, with bounded parsing (length and depth).
//! - [`sha256`] — the SHA-256 implementation and lowercase-hex codec every
//!   digest on the wire uses, owned here so the crate stays dependency-free.
//! - [`correlation`] — `UUIDv7` trace, logical-inference, and provider-attempt
//!   handles, with the lifecycle rules that keep their scopes distinct.
//! - [`attempt_sequence`] — the capture-side sequencing layer over
//!   [`inference_artifact`] (plan Phase 9): the per-inference state machine
//!   that mints each transport attempt's identity, stamps every record with
//!   it, orders retry transitions, and enforces the per-attempt shapes the
//!   reconstruction fold relies on — attempt boundaries, dense attempt and
//!   event ordinals, and the exactly-one transport-error rule below the
//!   decoded-content boundary.
//! - [`attempt_reconstruction`] — the read-side fold over an ordered
//!   artifact stream: independent attempt timelines, retry edges, usage,
//!   stream prefixes, and explicit completed, transport-failed,
//!   abandoned-mid-stream, or truncated terminal states.
//! - [`derivation`] — the domain-separated, length-prefixed identity
//!   constructions ([`schemas/v1/ingest-identifiers.json`], plan Section 7.4)
//!   and the ingest-attempt signing preimage.
//! - [`object_key`] — server-derived object keys assembled only from validated
//!   identifiers, sharded digests, and the pinned storage profile (plan
//!   Section 7.5).
//! - [`inference_artifact`] — the exact-inference capture artifact of plan
//!   Phase 9 (CAP-008; [`schemas/v1/inference-artifact.json`]): one typed
//!   record per observed provider-boundary event, six closed kinds, the
//!   closed metadata allowlist, and the capture-boundary rules carried
//!   structurally (post-transfer-decoded payloads only, credentials
//!   unrepresentable).
//! - [`usage_summary`] — the derived usage-summary record of plan Phase 10
//!   (token accounting): the deterministic derivation from an adapter
//!   projection's reading of captured inference records to the canonical
//!   record, its digest, and its object key.
//! - [`envelope`] — the version 1 ingest envelope: field-level bounded
//!   validation, unknown-field retention, reserved-name rejection, and
//!   identity re-derivation.
//!
//! # Crate boundary
//!
//! The crate has **no external dependencies** — not even a JSON or hashing
//! crate — so no public type here can expose a replaceable third-party SDK
//! shape (plan Section 4). Every wire value is project-owned; swapping an
//! internal implementation changes no public signature. Correctness of the
//! owned primitives is pinned by the language-neutral conformance corpus
//! ([`schemas/v1/examples/conformance`]) and the standard FIPS 180-4 vectors,
//! which the integration tests replay byte for byte.
//!
//! # Status
//!
//! Phase 1 contract core: the envelope wire type, canonicalization,
//! validation, identifier and object-key derivation, and the corpus-pinned
//! tests of plan Sections 7.1 through 7.5 are implemented. The plan Phase 9
//! exact-inference capture artifact is implemented alongside it, pinned by
//! the [`schemas/v1/examples/inference`] corpus. Signing and signature
//! verification live in `archivist-auth`; multipart framing, compression,
//! and the occurrence/attestation durable records arrive with their owning
//! phases.
//!
//! [`schemas/v1/ingest-identifiers.json`]: ../../../schemas/v1/ingest-identifiers.json
//! [`schemas/v1/examples/conformance`]: ../../../schemas/v1/examples/conformance
//! [`schemas/v1/examples/inference`]: ../../../schemas/v1/examples/inference
//! [`schemas/v1/inference-artifact.json`]: ../../../schemas/v1/inference-artifact.json

pub mod attempt_reconstruction;
pub mod attempt_sequence;
pub mod correlation;
pub mod derivation;
pub mod envelope;
pub mod inference_artifact;
pub mod json;
pub mod object_key;
pub mod sha256;
pub mod usage_summary;
pub mod vocabulary;
