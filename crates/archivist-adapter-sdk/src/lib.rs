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
//! - [`inference_observer`]: the versioned exact-inference lifecycle around
//!   a supported Rust transport boundary; it emits canonical protocol
//!   artifacts without exposing provider SDK types.
//! - [`capture_alignment`]: the join that aligns reconstructed provider
//!   attempts with the ledger's coverage outcomes, so a bypassed exchange
//!   can only ever resolve unobserved.
//! - [`openai_http1`]: the first-party HTTP/1.1 wire transport — the
//!   actual transport boundary the exact-capture lifecycle wraps
//!   (plan Phase 9). Standard-library sockets only; no third-party
//!   client, no provider SDK.
//! - [`openai_compat`]: the OpenAI-compatible first-party client built
//!   on that transport, driving the versioned observer lifecycle around
//!   every real exchange: decoded request, response or ordered stream
//!   events, usage, retry, transport error, teardown — credentials on
//!   the wire only, never in an artifact.
//! - [`openai_conformance`]: the exact-capture conformance suite that
//!   proves those properties at the real loopback boundary; the only
//!   producer of a compatibility claim.
//! - [`compatibility`]: the compatibility matrix — the registry of
//!   routes whose exact-capture claim conformance evidence backs. A
//!   route earns a row or the project does not claim it.
//! - [`file_capture`]: the file-source capture core's complete-JSONL
//!   boundary selection (CAP-003, plan `EC-01`): the torn tail is
//!   measured, never captured, and re-measured on the next pass (AC-02).
//! - [`file_generation`]: the file-source capture core's generation
//!   detection (plan Phase 6A, CAP-005, `SID-003`, plan `EC-02`): a
//!   discontinuity closes the acknowledged generation and opens a new
//!   `UUIDv7` one with the cause frozen at detection, preserving both
//!   histories (AC-03).
//! - [`file_sidecar`]: the file-source capture core's sidecar artifact
//!   relationships (plan Phase 6A): sidecars captured as artifacts in
//!   their own right, each carrying an explicit relationship to its
//!   parent, independently addressable and enumerable per parent.
//! - [`session_identity`]: the file-source capture core's session-identity
//!   resolution (plan Phase 6A, plan Section 7.4): opaque IDs preserved
//!   byte-for-byte, a minted `UUIDv4` stand-in for absent IDs, and
//!   content-free fail-closed rejection for invalid ones.
//! - [`conformance`]: the append-only conformance suite (plan Phase 6D):
//!   the harness-agnostic runner that drives any adapter built on this
//!   SDK through the synthetic corpus's six scenes — the time dimension
//!   (complete records, a partial tail, growth) and the environment
//!   dimension (replacement, permissions, missing roots) — and names
//!   every capture-contract breach. The `synthetic_append_only` example
//!   is the executable shape a community adapter starts from; this suite
//!   is what it is held to.
//!
//!
//! # Dependency boundary
//!
//! Depends on `archivist-protocol` only. Must not know about any specific
//! harness, transport, storage backend, or the server. The manifest-level
//! rule — no adapter dependency reaches protocol, the server, or any
//! other layer — is pinned by the crate's dependency-boundary test.

pub mod artifact;
pub mod capability;
pub mod capture_alignment;
pub mod compatibility;
pub mod conformance;
pub mod descriptor;
pub mod discovery;
pub mod expected_inference;
pub mod file_capture;
pub mod file_generation;
pub mod file_sidecar;
pub mod fingerprint;
pub mod inference_observer;
pub mod lifecycle;
pub mod openai_compat;
pub mod openai_conformance;
pub mod openai_http1;
pub mod session_identity;
pub mod status;

// Re-exported so a source adapter — which depends on this SDK alone
// (crate-ownership rule 3, pinned by the dependency-boundary test) — can
// assemble its [`AdapterDescriptor`] from the protocol-typed identity
// parts without a protocol edge of its own.
pub use archivist_protocol::vocabulary::{AdapterId, VersionToken};

pub use capability::{AdapterCapability, CapabilitySet, MAX_CAPABILITIES};
pub use capture_alignment::{AlignmentError, CaptureAlignment, InferenceAlignment, align_attempts};
pub use compatibility::{
    CompatibilityMatrix, FIRST_PARTY_OPENAI_HTTP1, MatrixError, QualifiedRoute,
};
pub use conformance::{
    CORPUS_RELATIVE, ConformanceAdapter, ConformanceSuite, CorpusError, GenerationContinuity,
    MountError, PassError, PassReport, SOURCE_FILE_NAME, Scenario, ScenarioOutcome, SuiteReport,
    Violation,
};
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
pub use file_generation::{
    AcknowledgedSource, AcknowledgedSourceError, FileGenerationTracker, FileIdentity,
    GenerationDecision, SourceObservation, detect_generation,
};
pub use file_sidecar::{
    MAX_SIDECARS_PER_PARENT, SidecarError, SidecarKind, SidecarLedger, SidecarRelationship,
};
pub use fingerprint::{
    FingerprintAllowlist, FingerprintError, MAX_FINGERPRINTS, SourceFingerprint,
    UnsupportedFingerprint, unsupported_report,
};
pub use inference_observer::{
    AttemptOutcome, CanonicalArtifact, FlushState, INFERENCE_OBSERVER_VERSION,
    InferenceArtifactSink, InferenceObserver, InferenceObserverError, InferenceObserverV1,
    LogicalInferenceClose, LogicalInferenceOutcome, LogicalInferenceStart, ObserverFailure,
    RecordingArtifactSink, SinkFailure,
};
pub use lifecycle::{AdapterLifecycle, LifecycleState};
pub use openai_conformance::{
    CONFORMANCE_CREDENTIAL, CheckId, ConformanceError, ConformanceReport, ConformanceSink,
    OpenAiWireFixture, ReceivedExchange, SceneId, SceneOutcome, TransportConformance, WireScript,
};
pub use session_identity::{SessionIdentity, SessionIdentityError};
pub use status::{
    AccountLabel, AdapterAccountStatus, ClassificationCounts, CoverageCounts, CoverageState,
    FreshnessLane, ScanClassification, SourceId, SourceScan,
};

pub use artifact::{
    CapturedChunk, ChunkError, ChunkSource, GenerationCause, GenerationError, SourceGeneration,
};
