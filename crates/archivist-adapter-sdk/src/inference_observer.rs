// SPDX-License-Identifier: Apache-2.0

//! The versioned exact-inference observer lifecycle (plan Phase 9).
//!
//! [`InferenceObserver`] is the Archivist-owned boundary a supported Rust
//! integration calls around the actual provider transport. It is intentionally
//! smaller than a provider client API: it names the logical inference and its
//! transport attempts, accepts bytes only after transfer decoding, and emits
//! [`CanonicalArtifact`] values from the protocol's exact-artifact contract.
//! No provider SDK type, package name, or version is part of this interface.
//!
//! The v1 implementation keeps attempt identity and event ordering in the
//! protocol's [`AttemptSequencer`]. A retry therefore gets a fresh
//! `provider_attempt_id` and dense `attempt_ordinal`, while every request,
//! response, stream event, usage record, and transport error remains stamped
//! with the attempt that actually observed it. The sink receives both the
//! project-owned typed record and its RFC 8785 canonical bytes.

use std::fmt;

use archivist_protocol::attempt_sequence::{AttemptSequencer, SequenceError};
use archivist_protocol::correlation::{OrchestratorOperation, ProviderAttempt};
use archivist_protocol::inference_artifact::{InferenceArtifact, Metadata};
use archivist_protocol::vocabulary::{
    ClientId, InferenceRequestId, RetryReason, TenantId, Timestamp, TraceId, TransportErrorClass,
    UsageSource,
};

use crate::expected_inference::IntegrationFailure;

/// Version of the Rust [`InferenceObserver`] lifecycle.
pub const INFERENCE_OBSERVER_VERSION: i64 = 1;

/// The bounded state a canonical-artifact sink reports for a flush.
///
/// `Pending` and `Incomplete` are deliberately distinct: a caller may still
/// be able to finish a pending flush, while `Incomplete` is an explicit
/// acknowledgement that teardown happened without durable artifact delivery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FlushState {
    /// No flush has been requested for this observer yet.
    #[default]
    NotStarted,
    /// A flush was requested but has not been acknowledged.
    Pending,
    /// The sink acknowledged all artifacts emitted so far.
    Acknowledged,
    /// The sink could not acknowledge all artifacts before teardown.
    Incomplete,
}

impl FlushState {
    /// Every v1 flush state in stable order.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::NotStarted,
            Self::Pending,
            Self::Acknowledged,
            Self::Incomplete,
        ]
    }

    /// The bounded token used in diagnostics and status projections.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Pending => "pending",
            Self::Acknowledged => "acknowledged",
            Self::Incomplete => "incomplete",
        }
    }

    /// Parse one v1 token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`archivist_protocol::vocabulary::GrammarError::NotCanonical`] when
    /// `text` is not a v1 flush-state token.
    pub fn parse(text: &str) -> Result<Self, archivist_protocol::vocabulary::GrammarError> {
        match text {
            "not_started" => Ok(Self::NotStarted),
            "pending" => Ok(Self::Pending),
            "acknowledged" => Ok(Self::Acknowledged),
            "incomplete" => Ok(Self::Incomplete),
            _ => Err(archivist_protocol::vocabulary::GrammarError::NotCanonical),
        }
    }

    /// Whether this state is the durable acknowledgement required before
    /// logical-inference teardown can claim a complete flush.
    #[must_use]
    pub const fn is_acknowledged(self) -> bool {
        matches!(self, Self::Acknowledged)
    }
}

impl fmt::Display for FlushState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// A bounded failure returned by an observer integration.
///
/// The type is an alias of the expected-inference ledger's shared failure
/// vocabulary, so a close report can be recorded without translating an
/// observer-specific error string. `RouteSelectionFailed` belongs to the
/// caller that selects a route; the observer itself emits the other three
/// classes.
pub type ObserverFailure = IntegrationFailure;

/// Why a canonical-artifact sink refused an emission.
///
/// Sink implementations map their internal details to this closed vocabulary;
/// paths, provider messages, and third-party error values never cross the
/// observer boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SinkFailure {
    /// The sink is unavailable for this capture.
    Unavailable,
    /// The sink rejected an otherwise valid canonical artifact.
    Rejected,
}

impl SinkFailure {
    /// The bounded token for this sink failure.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Rejected => "rejected",
        }
    }
}

impl fmt::Display for SinkFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

impl std::error::Error for SinkFailure {}

/// A lifecycle misuse or bounded capture failure returned by the v1
/// implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferenceObserverError {
    /// The logical inference has not been started.
    NotStarted,
    /// The logical inference has already been closed.
    Closed,
    /// A logical inference was started twice.
    AlreadyStarted,
    /// A provider attempt is already active.
    AttemptAlreadyStarted,
    /// An operation requiring an active attempt arrived before attempt start.
    NoOpenAttempt,
    /// A new attempt was requested before the previous attempt had an
    /// outcome.
    AttemptNotFinished,
    /// The underlying protocol sequencer refused the observation.
    Sequence(SequenceError),
    /// The sink refused a canonical artifact.
    Sink(SinkFailure),
    /// The observer was already placed in a bounded failure state.
    Failed(ObserverFailure),
    /// A timestamp had the right grammar but not a real calendar instant.
    InvalidCaptureTime,
}

impl InferenceObserverError {
    /// The bounded integration failure represented by this error, when it is
    /// a capture failure rather than a caller lifecycle mistake.
    #[must_use]
    pub const fn failure(self) -> Option<ObserverFailure> {
        match self {
            Self::Sequence(_)
            | Self::Sink(_)
            | Self::InvalidCaptureTime
            | Self::Failed(ObserverFailure::CaptureFailed) => Some(ObserverFailure::CaptureFailed),
            Self::Failed(failure) => Some(failure),
            Self::NotStarted
            | Self::Closed
            | Self::AlreadyStarted
            | Self::AttemptAlreadyStarted
            | Self::NoOpenAttempt
            | Self::AttemptNotFinished => None,
        }
    }
}

impl fmt::Display for InferenceObserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::NotStarted => "not_started",
            Self::Closed => "closed",
            Self::AlreadyStarted => "already_started",
            Self::AttemptAlreadyStarted => "attempt_already_started",
            Self::NoOpenAttempt => "no_open_attempt",
            Self::AttemptNotFinished => "attempt_not_finished",
            Self::Sequence(_) => "sequence_refused",
            Self::Sink(_) => "sink_refused",
            Self::Failed(_) => "failed",
            Self::InvalidCaptureTime => "invalid_capture_time",
        };
        formatter.write_str(token)
    }
}

impl std::error::Error for InferenceObserverError {}

/// One logical inference's correlation identity and start observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalInferenceStart {
    trace_id: TraceId,
    inference_request_id: InferenceRequestId,
    started_at: Option<Timestamp>,
}

impl LogicalInferenceStart {
    /// The orchestrator-operation trace identity shared by this inference.
    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// The logical-inference identity that groups all provider attempts.
    #[must_use]
    pub fn inference_request_id(&self) -> &InferenceRequestId {
        &self.inference_request_id
    }

    /// The optional start timestamp observed by the integration.
    #[must_use]
    pub const fn started_at(&self) -> Option<&Timestamp> {
        self.started_at.as_ref()
    }
}

/// The bounded outcome reported when one provider attempt ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptOutcome {
    /// The decoded response boundary completed normally.
    Completed,
    /// The attempt ended below the decoded-response boundary.
    TransportError {
        /// The closed transport-failure class.
        error_class: TransportErrorClass,
        /// The observed timeout in milliseconds, when one applied.
        timeout_ms: Option<u64>,
    },
    /// The attempt ended without a complete response or transport-error
    /// record; captured prefix artifacts remain evidence of a partial route.
    Incomplete,
}

/// The bounded result of closing a logical inference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LogicalInferenceOutcome {
    /// Every active attempt was given an outcome and flush was acknowledged.
    Complete,
    /// The observer closed with an active attempt or an incomplete flush.
    Incomplete,
}

/// The close report emitted by [`InferenceObserver::close_logical_inference`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalInferenceClose {
    /// The logical inference that was closed.
    pub start: LogicalInferenceStart,
    /// Whether the lifecycle and flush completed cleanly.
    pub outcome: LogicalInferenceOutcome,
    /// The final sink flush state.
    pub flush_state: FlushState,
    /// A bounded integration failure, when close could not claim complete
    /// exact coverage.
    pub failure: Option<ObserverFailure>,
    /// The number of canonical artifacts accepted by the sink.
    pub emitted_artifacts: u64,
}

/// A typed exact-artifact record paired with the canonical bytes that the
/// sink must persist.
///
/// The bytes are calculated once from the owned protocol record and cannot be
/// supplied independently by an integration. This makes an upload retry
/// rewrite the same exact bytes and prevents a sink from accidentally storing
/// a non-canonical representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalArtifact {
    artifact: InferenceArtifact,
    canonical_bytes: Vec<u8>,
}

impl CanonicalArtifact {
    /// Freeze one protocol artifact and compute its canonical representation.
    #[must_use]
    pub fn new(artifact: InferenceArtifact) -> Self {
        let canonical_bytes = artifact.canonical_bytes();
        Self {
            artifact,
            canonical_bytes,
        }
    }

    /// Borrow the project-owned exact-artifact record.
    #[must_use]
    pub const fn artifact(&self) -> &InferenceArtifact {
        &self.artifact
    }

    /// Borrow the canonical exact-artifact bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Consume the wrapper and return the typed artifact.
    #[must_use]
    pub fn into_artifact(self) -> InferenceArtifact {
        self.artifact
    }
}

/// The persistence seam for exact artifacts.
///
/// Implementations may spool, upload, or test-record the bytes, but they only
/// receive Archivist-owned types and must map internal outcomes to the two
/// bounded [`SinkFailure`] variants. `flush` is the acknowledgement gate used
/// by the logical-inference close operation.
pub trait InferenceArtifactSink {
    /// Accept one canonical artifact for durable handling.
    ///
    /// # Errors
    /// [`SinkFailure`] when the sink cannot accept the artifact.
    fn emit(&mut self, artifact: CanonicalArtifact) -> Result<(), SinkFailure>;

    /// Flush all artifacts emitted so far and report the bounded state.
    fn flush(&mut self) -> FlushState;
}

/// A deterministic in-memory sink useful for conformance tests and small
/// integrations that hand the canonical records to their own queue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordingArtifactSink {
    artifacts: Vec<CanonicalArtifact>,
    flush_state: FlushState,
}

impl RecordingArtifactSink {
    /// Construct an empty sink whose first flush is acknowledged.
    #[must_use]
    pub fn new() -> Self {
        Self {
            artifacts: Vec::new(),
            flush_state: FlushState::Acknowledged,
        }
    }

    /// Set the state returned by future flushes, for fault-path tests.
    pub fn set_flush_state(&mut self, state: FlushState) {
        self.flush_state = state;
    }

    /// The canonical artifacts accepted by this sink, in emission order.
    #[must_use]
    pub fn artifacts(&self) -> &[CanonicalArtifact] {
        &self.artifacts
    }
}

impl InferenceArtifactSink for RecordingArtifactSink {
    fn emit(&mut self, artifact: CanonicalArtifact) -> Result<(), SinkFailure> {
        if matches!(self.flush_state, FlushState::Incomplete) {
            return Err(SinkFailure::Unavailable);
        }
        self.artifacts.push(artifact);
        Ok(())
    }

    fn flush(&mut self) -> FlushState {
        self.flush_state
    }
}

/// The versioned observer interface around one logical inference.
pub trait InferenceObserver {
    /// The lifecycle version implemented by this observer.
    const VERSION: i64 = INFERENCE_OBSERVER_VERSION;

    /// Return the lifecycle version.
    #[must_use]
    fn version(&self) -> i64 {
        Self::VERSION
    }

    /// Start one logical inference and mint its `UUIDv7` correlation pair.
    ///
    /// # Errors
    /// [`InferenceObserverError::AlreadyStarted`] when the logical
    /// inference was already started, or
    /// [`InferenceObserverError::InvalidCaptureTime`] for a non-calendar
    /// timestamp.
    fn start_logical_inference(
        &mut self,
        started_at: Option<Timestamp>,
    ) -> Result<LogicalInferenceStart, InferenceObserverError>;

    /// Start the first provider transport attempt.
    ///
    /// # Errors
    /// [`InferenceObserverError::NotStarted`] before logical start,
    /// [`InferenceObserverError::AttemptAlreadyStarted`] when an attempt is
    /// active, or [`InferenceObserverError::Sequence`] when the protocol
    /// cannot mint the next bounded attempt identity.
    fn start_provider_attempt(&mut self) -> Result<ProviderAttempt, InferenceObserverError>;

    /// Record decoded request bytes for the active provider attempt.
    ///
    /// # Errors
    /// [`InferenceObserverError`] when the lifecycle is not active, the
    /// protocol refuses the request shape, or the sink refuses the artifact.
    fn decoded_request_bytes(
        &mut self,
        bytes: &[u8],
        metadata: Option<Metadata>,
        capture_time: Option<Timestamp>,
    ) -> Result<(), InferenceObserverError>;

    /// Record one ordered decoded response event for the active attempt.
    ///
    /// # Errors
    /// [`InferenceObserverError`] when the lifecycle is not active, the
    /// protocol refuses the event or its ordering, or the sink refuses the
    /// artifact.
    fn decoded_response_event(
        &mut self,
        bytes: &[u8],
        metadata: Option<Metadata>,
        capture_time: Option<Timestamp>,
    ) -> Result<(), InferenceObserverError>;

    /// Record one complete, non-streamed decoded response body.
    ///
    /// # Errors
    /// [`InferenceObserverError`] when the lifecycle is not active, the
    /// protocol refuses the response shape, or the sink refuses the
    /// artifact.
    fn decoded_response_bytes(
        &mut self,
        bytes: &[u8],
        metadata: Option<Metadata>,
        capture_time: Option<Timestamp>,
    ) -> Result<(), InferenceObserverError>;

    /// Record the bounded outcome of the active provider attempt.
    ///
    /// # Errors
    /// [`InferenceObserverError`] when there is no active attempt, the
    /// transport-error artifact is refused, or the sink refuses it.
    fn attempt_outcome(
        &mut self,
        outcome: AttemptOutcome,
        capture_time: Option<Timestamp>,
    ) -> Result<(), InferenceObserverError>;

    /// Start a retry attempt, emitting the canonical retry transition that
    /// points back to the completed predecessor.
    ///
    /// # Errors
    /// [`InferenceObserverError::AttemptNotFinished`] when the prior attempt
    /// has no outcome, or [`InferenceObserverError`] when the lifecycle,
    /// sequence, timestamp, or sink contract refuses the transition.
    fn start_retry_attempt(
        &mut self,
        retry_reason: RetryReason,
        backoff_ms: Option<u64>,
        capture_time: Option<Timestamp>,
    ) -> Result<ProviderAttempt, InferenceObserverError>;

    /// Flush currently emitted artifacts without closing the logical
    /// inference.
    ///
    /// # Errors
    /// [`InferenceObserverError::NotStarted`] before logical start or
    /// [`InferenceObserverError::Closed`] after close.
    fn flush(&mut self) -> Result<FlushState, InferenceObserverError>;

    /// Close the logical inference and report bounded outcome and flush
    /// state. The report is also returned for incomplete flushes, so teardown
    /// cannot silently claim a complete capture.
    ///
    /// # Errors
    /// [`InferenceObserverError::NotStarted`] before logical start or
    /// [`InferenceObserverError::Closed`] after close.
    fn close_logical_inference(&mut self) -> Result<LogicalInferenceClose, InferenceObserverError>;
}

#[derive(Debug)]
struct ActiveAttempt {
    attempt: ProviderAttempt,
}

/// The concrete v1 observer implementation.
///
/// The generic parameter is only the project-owned artifact sink. It lets a
/// first-party transport choose its delivery mechanism without making that
/// mechanism, or any provider SDK, part of the observer contract.
#[derive(Debug)]
pub struct InferenceObserverV1<S> {
    tenant_id: TenantId,
    origin_client_id: ClientId,
    sink: S,
    start: Option<LogicalInferenceStart>,
    sequencer: Option<AttemptSequencer>,
    active_attempt: Option<ActiveAttempt>,
    unclosed_attempt: bool,
    failure: Option<ObserverFailure>,
    flush_state: FlushState,
    emitted_artifacts: u64,
    closed: bool,
}

impl<S> InferenceObserverV1<S> {
    /// Construct an idle v1 observer for one tenant and capturing client.
    #[must_use]
    pub fn new(tenant_id: TenantId, origin_client_id: ClientId, sink: S) -> Self {
        Self {
            tenant_id,
            origin_client_id,
            sink,
            start: None,
            sequencer: None,
            active_attempt: None,
            unclosed_attempt: false,
            failure: None,
            flush_state: FlushState::NotStarted,
            emitted_artifacts: 0,
            closed: false,
        }
    }

    /// Borrow the sink, for integrations that need to hand off its captured
    /// records after close.
    #[must_use]
    pub const fn sink(&self) -> &S {
        &self.sink
    }

    /// Mutably borrow the sink, for integrations that own its delivery
    /// controls (fault injection, delivery toggles, post-close draining)
    /// and drive them between lifecycle calls without wrapping the whole
    /// observer.
    #[must_use]
    pub const fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// The active logical-inference start record, when started.
    #[must_use]
    pub const fn logical_inference(&self) -> Option<&LogicalInferenceStart> {
        self.start.as_ref()
    }

    /// The current flush state.
    #[must_use]
    pub const fn flush_state(&self) -> FlushState {
        self.flush_state
    }

    /// The number of canonical artifacts accepted by the sink.
    #[must_use]
    pub const fn emitted_artifacts(&self) -> u64 {
        self.emitted_artifacts
    }

    /// The current provider attempt, when one is active.
    #[must_use]
    pub fn current_attempt(&self) -> Option<&ProviderAttempt> {
        self.active_attempt.as_ref().map(|active| &active.attempt)
    }

    /// Record usage counters from a decoded response body or stream event.
    ///
    /// This is an additive convenience over the required lifecycle methods;
    /// it emits the protocol's canonical `usage` artifact and retains no
    /// provider-specific usage object. `reporting_bytes` carries the
    /// reporting event's own bytes for a stream-sourced report — the
    /// artifact names the event through its payload digest — and `None`
    /// for a response-body report, whose bytes the response artifact
    /// already carries.
    ///
    /// # Errors
    /// [`InferenceObserverError`] when the lifecycle, protocol, or sink
    /// refuses the usage artifact.
    pub fn usage(
        &mut self,
        usage_source: UsageSource,
        reporting_bytes: Option<&[u8]>,
        input_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
        capture_time: Option<Timestamp>,
    ) -> Result<(), InferenceObserverError>
    where
        S: InferenceArtifactSink,
    {
        self.ensure_event_ready()?;
        let artifact = self
            .sequencer
            .as_mut()
            .ok_or(InferenceObserverError::NotStarted)?
            .usage(
                usage_source,
                reporting_bytes,
                input_tokens,
                output_tokens,
                total_tokens,
                capture_time,
            )
            .map_err(Self::sequence_error)?;
        self.emit(artifact)
    }

    fn ensure_started(&self) -> Result<(), InferenceObserverError> {
        if self.closed {
            return Err(InferenceObserverError::Closed);
        }
        if let Some(failure) = self.failure {
            return Err(InferenceObserverError::Failed(failure));
        }
        if self.start.is_none() {
            return Err(InferenceObserverError::NotStarted);
        }
        Ok(())
    }

    fn ensure_closeable(&self) -> Result<(), InferenceObserverError> {
        if self.closed {
            return Err(InferenceObserverError::Closed);
        }
        if self.start.is_none() {
            return Err(InferenceObserverError::NotStarted);
        }
        Ok(())
    }

    fn ensure_event_ready(&self) -> Result<(), InferenceObserverError> {
        self.ensure_started()?;
        if self.active_attempt.is_none() {
            return Err(InferenceObserverError::NoOpenAttempt);
        }
        Ok(())
    }

    fn checked_time(time: Option<&Timestamp>) -> Result<(), InferenceObserverError> {
        if time.is_some_and(|value| !value.calendar_valid()) {
            return Err(InferenceObserverError::InvalidCaptureTime);
        }
        Ok(())
    }

    fn sequence_error(error: SequenceError) -> InferenceObserverError {
        match error {
            SequenceError::NoOpenAttempt => InferenceObserverError::NoOpenAttempt,
            other => InferenceObserverError::Sequence(other),
        }
    }

    fn emit(&mut self, artifact: InferenceArtifact) -> Result<(), InferenceObserverError>
    where
        S: InferenceArtifactSink,
    {
        let canonical = CanonicalArtifact::new(artifact);
        match self.sink.emit(canonical) {
            Ok(()) => {
                self.emitted_artifacts = self.emitted_artifacts.saturating_add(1);
                Ok(())
            }
            Err(error) => {
                self.failure = Some(ObserverFailure::CaptureFailed);
                Err(InferenceObserverError::Sink(error))
            }
        }
    }
}

impl<S: InferenceArtifactSink> InferenceObserver for InferenceObserverV1<S> {
    fn start_logical_inference(
        &mut self,
        started_at: Option<Timestamp>,
    ) -> Result<LogicalInferenceStart, InferenceObserverError> {
        if self.closed {
            return Err(InferenceObserverError::Closed);
        }
        if self.start.is_some() {
            return Err(InferenceObserverError::AlreadyStarted);
        }
        Self::checked_time(started_at.as_ref())?;
        let inference = OrchestratorOperation::new().start_inference();
        let start = LogicalInferenceStart {
            trace_id: inference.trace_id().clone(),
            inference_request_id: inference.inference_request_id().clone(),
            started_at,
        };
        self.sequencer = Some(AttemptSequencer::new(
            self.tenant_id.clone(),
            self.origin_client_id.clone(),
            inference,
        ));
        self.start = Some(start.clone());
        Ok(start)
    }

    fn start_provider_attempt(&mut self) -> Result<ProviderAttempt, InferenceObserverError> {
        self.ensure_started()?;
        if self.active_attempt.is_some() {
            return Err(InferenceObserverError::AttemptAlreadyStarted);
        }
        let attempt = self
            .sequencer
            .as_mut()
            .ok_or(InferenceObserverError::NotStarted)?
            .start_attempt()
            .map_err(Self::sequence_error)?;
        self.active_attempt = Some(ActiveAttempt {
            attempt: attempt.clone(),
        });
        Ok(attempt)
    }

    fn decoded_request_bytes(
        &mut self,
        bytes: &[u8],
        metadata: Option<Metadata>,
        capture_time: Option<Timestamp>,
    ) -> Result<(), InferenceObserverError> {
        self.ensure_event_ready()?;
        let artifact = self
            .sequencer
            .as_mut()
            .ok_or(InferenceObserverError::NotStarted)?
            .provider_request(bytes, metadata, capture_time)
            .map_err(Self::sequence_error)?;
        self.emit(artifact)
    }

    fn decoded_response_event(
        &mut self,
        bytes: &[u8],
        metadata: Option<Metadata>,
        capture_time: Option<Timestamp>,
    ) -> Result<(), InferenceObserverError> {
        self.ensure_event_ready()?;
        let artifact = self
            .sequencer
            .as_mut()
            .ok_or(InferenceObserverError::NotStarted)?
            .stream_event(bytes, metadata, capture_time)
            .map_err(Self::sequence_error)?;
        self.emit(artifact)
    }

    fn decoded_response_bytes(
        &mut self,
        bytes: &[u8],
        metadata: Option<Metadata>,
        capture_time: Option<Timestamp>,
    ) -> Result<(), InferenceObserverError> {
        self.ensure_event_ready()?;
        let artifact = self
            .sequencer
            .as_mut()
            .ok_or(InferenceObserverError::NotStarted)?
            .provider_response(bytes, metadata, capture_time)
            .map_err(Self::sequence_error)?;
        self.emit(artifact)
    }

    fn attempt_outcome(
        &mut self,
        outcome: AttemptOutcome,
        capture_time: Option<Timestamp>,
    ) -> Result<(), InferenceObserverError> {
        self.ensure_event_ready()?;
        Self::checked_time(capture_time.as_ref())?;
        if let AttemptOutcome::TransportError {
            error_class,
            timeout_ms,
        } = outcome
        {
            let artifact = self
                .sequencer
                .as_mut()
                .ok_or(InferenceObserverError::NotStarted)?
                .transport_error(error_class, timeout_ms, capture_time)
                .map_err(Self::sequence_error)?;
            self.emit(artifact)?;
        }
        self.active_attempt = None;
        Ok(())
    }

    fn start_retry_attempt(
        &mut self,
        retry_reason: RetryReason,
        backoff_ms: Option<u64>,
        capture_time: Option<Timestamp>,
    ) -> Result<ProviderAttempt, InferenceObserverError> {
        self.ensure_started()?;
        if self.active_attempt.is_some() {
            return Err(InferenceObserverError::AttemptNotFinished);
        }
        Self::checked_time(capture_time.as_ref())?;
        let (artifact, attempt) = {
            let sequencer = self
                .sequencer
                .as_mut()
                .ok_or(InferenceObserverError::NotStarted)?;
            let artifact = sequencer
                .retry(retry_reason, backoff_ms, capture_time)
                .map_err(Self::sequence_error)?;
            let attempt = sequencer
                .current_attempt()
                .cloned()
                .ok_or(InferenceObserverError::NoOpenAttempt)?;
            (artifact, attempt)
        };
        self.emit(artifact)?;
        self.active_attempt = Some(ActiveAttempt {
            attempt: attempt.clone(),
        });
        Ok(attempt)
    }

    fn flush(&mut self) -> Result<FlushState, InferenceObserverError> {
        self.ensure_started()?;
        let state = self.sink.flush();
        self.flush_state = state;
        Ok(state)
    }

    fn close_logical_inference(&mut self) -> Result<LogicalInferenceClose, InferenceObserverError> {
        self.ensure_closeable()?;
        let start = self
            .start
            .clone()
            .ok_or(InferenceObserverError::NotStarted)?;
        if self.active_attempt.is_some() {
            self.unclosed_attempt = true;
            self.active_attempt = None;
        }
        let flush_state = self.sink.flush();
        self.flush_state = flush_state;
        let failure = self.failure.or_else(|| {
            (!flush_state.is_acknowledged())
                .then_some(ObserverFailure::FlushIncomplete)
                .or_else(|| {
                    self.unclosed_attempt
                        .then_some(ObserverFailure::CaptureFailed)
                })
        });
        let outcome = if failure.is_none() {
            LogicalInferenceOutcome::Complete
        } else {
            LogicalInferenceOutcome::Incomplete
        };
        self.closed = true;
        Ok(LogicalInferenceClose {
            start,
            outcome,
            flush_state,
            failure,
            emitted_artifacts: self.emitted_artifacts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use archivist_protocol::inference_artifact::InferenceArtifact;
    use archivist_protocol::vocabulary::{InferenceArtifactKind, UsageSource};

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const ORIGIN: &str = "aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f";
    const TIME: &str = "2026-09-12T16:44:05Z";

    fn observer() -> InferenceObserverV1<RecordingArtifactSink> {
        InferenceObserverV1::new(
            TenantId::parse(TENANT).expect("tenant"),
            ClientId::parse(ORIGIN).expect("origin"),
            RecordingArtifactSink::new(),
        )
    }

    fn time() -> Timestamp {
        Timestamp::parse(TIME).expect("timestamp")
    }

    #[test]
    fn lifecycle_emits_canonical_records_with_attempt_boundaries() {
        let mut observer = observer();
        let start = observer
            .start_logical_inference(Some(time()))
            .expect("logical start");
        let first = observer.start_provider_attempt().expect("first attempt");
        observer
            .decoded_request_bytes(b"request", None, Some(time()))
            .expect("request");
        observer
            .decoded_response_event(b"event-0", None, Some(time()))
            .expect("stream event");
        observer
            .attempt_outcome(AttemptOutcome::Completed, Some(time()))
            .expect("completed attempt");
        let second = observer
            .start_retry_attempt(RetryReason::TransportError, None, Some(time()))
            .expect("retry");
        observer
            .attempt_outcome(
                AttemptOutcome::TransportError {
                    error_class: TransportErrorClass::Connect,
                    timeout_ms: None,
                },
                Some(time()),
            )
            .expect("transport error");
        let close = observer.close_logical_inference().expect("logical close");

        assert_eq!(start.trace_id(), second.trace_id());
        assert_eq!(start.inference_request_id(), second.inference_request_id());
        assert_ne!(first.provider_attempt_id(), second.provider_attempt_id());
        assert_eq!(first.attempt_ordinal(), 0);
        assert_eq!(second.attempt_ordinal(), 1);
        assert_eq!(close.outcome, LogicalInferenceOutcome::Complete);
        assert_eq!(close.flush_state, FlushState::Acknowledged);
        assert_eq!(observer.sink().artifacts().len(), 4);

        let artifacts: Vec<_> = observer
            .sink()
            .artifacts()
            .iter()
            .map(|item| {
                assert_eq!(item.canonical_bytes(), item.artifact().canonical_bytes());
                InferenceArtifact::parse(item.canonical_bytes()).expect("canonical artifact")
            })
            .collect();
        assert_eq!(artifacts[0].kind(), InferenceArtifactKind::ProviderRequest);
        assert_eq!(artifacts[1].kind(), InferenceArtifactKind::StreamingEvent);
        assert_eq!(artifacts[2].kind(), InferenceArtifactKind::Retry);
        assert_eq!(artifacts[3].kind(), InferenceArtifactKind::TransportError);
        assert_eq!(artifacts[0].attempt_ordinal, 0);
        assert_eq!(artifacts[3].attempt_ordinal, 1);
    }

    #[test]
    fn usage_is_the_protocol_usage_artifact_and_flush_failure_is_explicit() {
        let mut observer = observer();
        observer
            .start_logical_inference(Some(time()))
            .expect("logical start");
        observer.start_provider_attempt().expect("attempt");
        observer
            .usage(UsageSource::ResponseBody, None, 2, 3, 5, Some(time()))
            .expect("usage");
        observer
            .attempt_outcome(AttemptOutcome::Incomplete, Some(time()))
            .expect("incomplete");
        observer.sink.set_flush_state(FlushState::Incomplete);
        let close = observer
            .close_logical_inference()
            .expect("close reports bounded failure");

        assert_eq!(close.outcome, LogicalInferenceOutcome::Incomplete);
        assert_eq!(close.flush_state, FlushState::Incomplete);
        assert_eq!(close.failure, Some(ObserverFailure::FlushIncomplete));
        assert_eq!(close.emitted_artifacts, 1);
    }

    #[test]
    fn lifecycle_refuses_cross_attempt_observations() {
        let mut observer = observer();
        assert_eq!(
            observer.start_provider_attempt(),
            Err(InferenceObserverError::NotStarted)
        );
        observer
            .start_logical_inference(Some(time()))
            .expect("logical start");
        observer.start_provider_attempt().expect("attempt");
        assert_eq!(
            observer.start_provider_attempt(),
            Err(InferenceObserverError::AttemptAlreadyStarted)
        );
        observer
            .attempt_outcome(AttemptOutcome::Incomplete, Some(time()))
            .expect("end attempt");
        assert_eq!(
            observer.decoded_response_event(b"late", None, Some(time())),
            Err(InferenceObserverError::NoOpenAttempt)
        );
    }
}
