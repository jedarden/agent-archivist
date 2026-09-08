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
//! # Status
//!
//! Skeleton scaffold (Phase 0). Behavior arrives with the Phase 1 contract
//! work: schema families, golden vectors, and the compatibility rules of
//! implementation plan Sections 7.1 through 7.5. It deliberately contains no
//! placeholder production code.
