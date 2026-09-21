// SPDX-License-Identifier: Apache-2.0

//! Archivist adapter SDK: the discovery, lifecycle, capability, status,
//! immutable-artifact, generation, and projection interfaces that every
//! source adapter implements, plus the source-fingerprint allowlist and
//! the descriptor contract community adapters are held to.
//!
//! Adapters turn one harness's durable session stores into canonical,
//! complete-record artifacts with explicit generation detection and
//! projection versions. They never talk to the network, the spool, or
//! storage; the client engine consumes artifacts through these
//! interfaces, which is what keeps harness-specific dependencies and
//! schema churn out of the protocol and server (implementation plan,
//! Section 6).
//!
//! # The interfaces
//!
//! - [`descriptor`]: CAP-002's plugin interface, published as data —
//!   identity, declared capabilities, fingerprint allowlist, projection
//!   version; the compatibility-matrix row.
//! - [`capability`]: the closed capture-capability vocabulary
//!   (CAP-002, CAP-008).
//! - [`discovery`]: CAP-001's adapter-specific discovery, reduced to a
//!   bounded, content-free report per configured account.
//! - [`artifact`]: the generation cause vocabulary (CAP-005, `SID-003`)
//!   and `SID-004`'s immutable chunk identification.
//! - [`lifecycle`]: the three-state adapter lifecycle and the idempotent
//!   close contract (plan Phase 6D).
//! - [`status`]: the bounded, content-free source-status contract
//!   (requirement CAP-010) and the aggregate adapter/account status.
//! - [`fingerprint`]: the fail-closed source-fingerprint allowlist
//!   (plan `EC-08`).
//! - [`expected_inference`]: the expected-inference ledger adapters
//!   publish so capture completeness is measurable.
//! - [`file_capture`]: the file-source capture core's complete-JSONL
//!   boundary selection (CAP-003, plan `EC-01`): the torn tail is
//!   measured, never captured, and re-measured on the next pass (AC-02).
//!
//! The synthetic adapter example and the conformance suite that hold
//! community adapters to these contracts are the Phase 6D work that
//! follows this publication (plan Phase 6D).
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` only. Must not know about any specific
//! harness, transport, storage backend, or the server. The manifest-level
//! rule — no adapter dependency reaches protocol, the server, or any
//! other layer — is pinned by the crate's dependency-boundary test.

pub mod artifact;
pub mod capability;
pub mod descriptor;
pub mod discovery;
pub mod expected_inference;
pub mod file_capture;
pub mod fingerprint;
pub mod lifecycle;
pub mod status;

pub use capability::{AdapterCapability, CapabilitySet, MAX_CAPABILITIES};
pub use descriptor::{AdapterDescriptor, DescriptorError};
pub use discovery::{
    DiscoveredSource, DiscoveredSources, DiscoveryError, DiscoveryReport, SourceDiscovery,
};
pub use expected_inference::{
    CaptureRoute, CloseReason, EXPECTATION_VERSION, ExactOutcome, ExpectedEvent, ExpectedEvents,
    ExpectedInference, ExpectedInferenceLedger, ExpectedInferenceRecord, InferenceArtifactKind,
    InferenceIdentity, IntegrationFailure, LedgerError, ObservedArtifact, RoutePolicy,
};
pub use file_capture::{CaptureCursor, CaptureCursorError, PassOutcome, RecordBoundary};
pub use fingerprint::{
    FingerprintAllowlist, FingerprintError, MAX_FINGERPRINTS, SourceFingerprint,
    UnsupportedFingerprint, unsupported_report,
};
pub use lifecycle::{AdapterLifecycle, LifecycleState};
pub use status::{
    AccountLabel, AdapterAccountStatus, ClassificationCounts, CoverageCounts, CoverageState,
    FreshnessLane, ScanClassification, SourceId, SourceScan,
};

pub use artifact::{
    CapturedChunk, ChunkError, ChunkSource, GenerationCause, GenerationError, SourceGeneration,
};
