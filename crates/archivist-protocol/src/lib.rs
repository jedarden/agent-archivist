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
//! - [`derivation`] — the domain-separated, length-prefixed identity
//!   constructions ([`schemas/v1/ingest-identifiers.json`], plan Section 7.4)
//!   and the ingest-attempt signing preimage.
//! - [`object_key`] — server-derived object keys assembled only from validated
//!   identifiers, sharded digests, and the pinned storage profile (plan
//!   Section 7.5).
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
//! tests of plan Sections 7.1 through 7.5 are implemented. Signing and
//! signature verification live in `archivist-auth`; multipart framing,
//! compression, and the occurrence/attestation durable records arrive with
//! their owning phases.
//!
//! [`schemas/v1/ingest-identifiers.json`]: ../../../schemas/v1/ingest-identifiers.json
//! [`schemas/v1/examples/conformance`]: ../../../schemas/v1/examples/conformance

pub mod derivation;
pub mod envelope;
pub mod json;
pub mod object_key;
pub mod sha256;
pub mod vocabulary;
