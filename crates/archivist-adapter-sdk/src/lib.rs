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
//! Skeleton scaffold (Phase 0). Interfaces arrive with Phase 6D on top of the
//! Phase 1 contracts, alongside the synthetic adapter example and its
//! conformance suite. It deliberately contains no placeholder production code.
//!
//! # Dependency boundary
//!
//! Depends on [`archivist-protocol`] only. Must not know about any specific
//! harness, transport, storage backend, or the server.
