// SPDX-License-Identifier: Apache-2.0

//! Archivist identity and trust: client key generation, per-attempt Ed25519
//! request authorization, linked-client records, tenant authority chains,
//! origin/uploader delegation, revocation and rotation epochs, receipt signing
//! keys, and receipt verification.
//!
//! Both sides of the wire use this crate: clients sign uploads and verify
//! receipts against a pinned tenant authority; ingestion replicas verify
//! request signatures and evaluate trust records against the control plane.
//! Signature verification is constant-time through reviewed cryptographic
//! libraries, and private key material only ever enters through secret
//! references (implementation plan, Section 11).
//!
//! # Status
//!
//! Skeleton scaffold (Phase 0). Behavior arrives with Phase 3 (client identity
//! and linking control plane) on top of the Section 7.2 and 7.3 wire
//! contracts. It deliberately contains no placeholder production code.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` only. Must not depend on any transport,
//! storage backend, client state machine, or source adapter.
