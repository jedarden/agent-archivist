// SPDX-License-Identifier: Apache-2.0

//! Bounded request parsing for the ingestion pipeline, layered beneath the
//! envelope and signature validation it feeds.
//!
//! # Status
//!
//! The **multipart/related framing layer** is implemented:
//! [`framing`] validates the request Content-Type against the pinned
//! `multipart/related; boundary=<token>` grammar before any body byte is
//! read, then tokenizes the body into part boundaries, part headers, and
//! payload runs while buffering no more than a fixed small window — the
//! bounded-memory streaming the plan requires of every parser (plan Section
//! 7.6; VAL-008). The pipeline slices consume it when they land, replacing
//! the fail-closed ingest stub.
//!
//! The **two-part policy** over that tokenizer is implemented:
//! [`parts`] enforces the protocol Section 1.2 part order — part one must
//! declare the pinned envelope media type and is capped at the configured
//! canonical-envelope size, rejected at the cap before further body bytes
//! are read — and hands part two to the caller as an incremental reader
//! whose buffering stays within the framing window regardless of body
//! size. Every rejection is a content-free typed error; the later envelope
//! and payload pipeline slices consume it when they land.
//!
//! The **parser's public error surface** is implemented: [`ingest`]
//! composes the split with `archivist-protocol`'s envelope parser — the
//! extracted part-one bytes are validated in full, so identifier,
//! coordinate, encoding, and schema field violations surface the
//! field-level `envelope.schema_invalid` codes, a non-JSON part one
//! `envelope.malformed`, and the framing-layer violations the frozen
//! registry codes [`parts`] maps — each as an
//! [`ingest::IngestParseError`] carrying the registry code and the
//! pinned message template rendered content-free (ERR-011–ERR-013).
//!
//! # Conformance corpus: what this parser owns and what it does not
//!
//! The corpus replay in
//! `crates/archivist-server/tests/ingest_conformance_corpus.rs` drives
//! every `schemas/v1/examples/conformance` scenario through this chain and
//! pins the outcome each layer owes. The strand boundaries, so the corpus's
//! non-parser outcomes are never mistaken for this chain's:
//!
//! - **This parser owns** the seven accepted scenarios (parse to the
//!   canonical envelope, stream the payload byte-identically) and the
//!   three field-violation scenarios (`invalid-occurrence-id-mismatch`,
//!   `invalid-unknown-enum-value`, `invalid-reserved-field`) — exactly
//!   their pinned `envelope.*` codes and messages.
//! - `invalid-altered-framing-boundary` pins
//!   `auth.authorization_rejected`, **not** this parser's outcome: the
//!   transmitted delimiters no longer match the signed boundary, the
//!   request content digest the signature covered breaks, and the
//!   authorization middleware (strand `aa-834ca705`) rejects before any
//!   parsing runs.
//! - Payload digests, zstd transport decoding, and expansion limits —
//!   `invalid-altered-payload-byte`'s territory — are strand
//!   `aa-d71d8140`, downstream of the split.
//! - `invalid-stale-authorization` and `invalid-cross-tenant-forbidden`
//!   pin the authorization middleware's window and tenant checks (strand
//!   `aa-834ca705`); `invalid-integrity-conflict` pins the storage commit
//!   layer, which alone can see an existing stored object.
//! - HTTP serialization of every rejection, the parser's codes included,
//!   is the route layer's strand (`aa-aebd9a6e`); this chain produces the
//!   code and the pinned message only.

pub mod framing;
pub mod ingest;
pub mod parts;
