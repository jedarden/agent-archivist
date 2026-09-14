// SPDX-License-Identifier: Apache-2.0

//! Archivist identity and trust: client key generation, per-attempt Ed25519
//! request authorization, linked-client records, tenant authority chains,
//! origin/uploader delegation, revocation and rotation epochs, receipt signing
//! keys, and receipt verification.
//!
//! Both sides of the wire use this crate: clients sign uploads and verify
//! receipts against a pinned tenant authority; ingestion replicas verify
//! request signatures and evaluate trust records against the control plane.
//! Signing and verification rest on the owned [`ed25519`] primitives, whose
//! secret-dependent arithmetic — scalar reduction and scalar multiplication
//! — runs fixed schedules without data-dependent branches, and private key
//! material only ever enters through secret references (implementation
//! plan, Section 11).
//!
//! # Layout
//!
//! - [`ed25519`] — the owned Ed25519 (RFC 8032) implementation: key
//!   construction, signing, and verification, pinned by the RFC's own test
//!   vectors including the §7.1 sign/verify pairs.
//! - `sha512` — the FIPS 180-4 hash the key construction and the signing
//!   nonce both use, owned for the same dependency-free policy as the
//!   protocol crate's SHA-256.
//! - [`identity`] — the installation identity: a `UUIDv4` client ID and
//!   Ed25519 signing key minted from OS entropy, persisted at mode `0600`,
//!   and discovered only through a protected reference.
//! - [`crate::reference`] — the protected-reference grammar and resolver
//!   (`file:`/`env:`, CFG-029/CFG-030): the only channel private material
//!   enters through.
//! - [`link`] — the link request: public identity and requested scope, and
//!   nothing else.
//! - [`error`] — the failure taxonomy; every variant names a class and
//!   carries no path, value, or key material.
//!
//! # Private material discipline (SEC-004, SEC-006)
//!
//! A seed is generated here, held in [`identity::SigningKey`], and leaves
//! the process only through the mode-restricted local identity document
//! that a protected reference names. Every type that can hold private
//! material renders redacted in `Debug`; every error names its failure
//! class without echoing its input; and the acceptance tests scan the
//! crate's serializations and diagnostics for leaked seed bytes.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` only. Must not depend on any transport,
//! storage backend, client state machine, or source adapter.
//!
//! # Status
//!
//! Phase 3, first slice: the owned Ed25519 and SHA-512 primitives — key
//! construction, signing, verification, and the hash underneath them —
//! plus identity generation, protected-reference discovery, and the
//! public-only link request built on top. Per-attempt request signing,
//! linked-client records, tenant authority chains, delegation, revocation
//! and rotation epochs, receipt signing keys, and receipt verification
//! arrive with their owning deliverables on these same primitives.
//!
//! The workspace is dependency-free by policy: the curve and hash
//! implementations here are owned, small, and pinned by RFC 8032 and FIPS
//! 180-4 vectors, the same discipline the protocol crate applies to
//! SHA-256. Wire-layer uses of signing must not grow out of these
//! primitives casually — each new surface carries its own vectors pinning
//! every negative case, on top of the RFC §7.1 pairs pinned here.

pub mod ed25519;
pub mod error;
pub mod identity;
pub mod link;
mod random;
pub mod reference;
mod sha512;
