// SPDX-License-Identifier: Apache-2.0

//! Archivist adapter SDK: the lifecycle, capability, status, discovery, and
//! immutable-artifact projection interfaces that every source adapter
//! implements, plus the source-fingerprint allowlist and conformance suite
//! contracts community adapters are held to.
//!
//! Adapters turn one harness's durable session stores into canonical,
//! complete-record artifacts with explicit generation detection and projection
//! versions. They never talk to the network, the spool, or storage; the client
//! engine consumes artifacts through these interfaces, which is what keeps
//! harness-specific dependencies and schema churn out of the protocol and
//! server (implementation plan, Section 6).
//!
//! # Status
//!
//! The bounded, content-free source-status contract — the per-source scan
//! observation, the closed coverage and classification vocabularies, and
//! the aggregate adapter/account status (requirement CAP-010) — arrived
//! ahead of Phase 6D; see [`status`]. The lifecycle, discovery, and
//! projection interfaces and the
//! conformance suite are still the Phase 0 skeleton and deliberately
//! contain no placeholder production code.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` only. Must not know about any specific
//! harness, transport, storage backend, or the server.

pub mod status;
