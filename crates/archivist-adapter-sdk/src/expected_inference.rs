// SPDX-License-Identifier: Apache-2.0

//! The content-free expected-inference ledger for Phase 9 exact coverage.
//!
//! An expectation is frozen before an instrumented route is selected.  It
//! carries only bounded identity, session, route, timing, and event-shape
//! information; it never carries a prompt, response, provider name, or
//! transport detail.  Provider-boundary artifacts are joined by the pair of
//! [`TraceId`] and [`InferenceRequestId`], not by either identifier alone.
//!
//! The ledger deliberately separates three states that are easy to conflate:
//!
//! - a closed expectation with no matching artifacts is [`ExactOutcome::Unobserved`];
//! - a matching but incomplete event set is [`ExactOutcome::Partial`]; and
//! - a session with neither an expectation nor an artifact is
//!   [`ExactOutcome::Unknown`].
//!
//! This module is the SDK-side persistence seam.  The ledger owns the frozen
//! records and exposes content-free snapshots for a durable client or
//! orchestrator store to write.  It does not depend on a database or a
//! provider SDK, so integrations cannot accidentally make a third-party type
//! part of Archivist's compatibility contract.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{
    InferenceRequestId, OpaqueId, ProviderAttemptId, Timestamp, TraceId,
};

/// The largest expected-attempt count representable by the protocol's `u63`
/// shape.  The ledger validates this at persistence time, before a record can
/// become durable.
const MAX_EXPECTED_ATTEMPTS: u64 = 9_223_372_036_854_775_807;

/// Version of the frozen expected-inference record representation.
pub const EXPECTATION_VERSION: i64 = 1;

/// A correlation pair used to join one expectation to exact artifacts.
///
/// Matching both members is intentional: an inference ID reused under a
/// different orchestrator operation is not evidence for the original
/// expectation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InferenceIdentity {
    /// The orchestrator operation's trace identity.
    pub trace_id: TraceId,
    /// The logical inference identity within that operation.
    pub inference_request_id: InferenceRequestId,
}

impl InferenceIdentity {
    /// Construct a correlation pair from the protocol-owned identifiers.
    #[must_use]
    pub fn new(trace_id: TraceId, inference_request_id: InferenceRequestId) -> Self {
        Self {
            trace_id,
            inference_request_id,
        }
    }

    /// Borrow the trace identity.
    #[must_use]
    pub const fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// Borrow the logical-inference identity.
    #[must_use]
    pub const fn inference_request_id(&self) -> &InferenceRequestId {
        &self.inference_request_id
    }
}

/// The exact-capture route an expectation permits or declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RoutePolicy {
    /// The request is expected to traverse the Archivist proxy.
    Proxy,
    /// The request is expected to use the supported SDK hook.
    SdkHook,
}

/// Alias used by metrics and route integrations.
pub type CaptureRoute = RoutePolicy;

impl RoutePolicy {
    /// The closed route tokens in registry order.
    #[must_use]
    pub const fn all() -> [Self; 2] {
        [Self::Proxy, Self::SdkHook]
    }

    /// The bounded wire/metric token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::SdkHook => "sdk_hook",
        }
    }

    /// Parse a route token, failing closed on unknown routes.
    ///
    /// # Errors
    /// [`LedgerError::UnknownRoute`] when `text` is not one of the two
    /// supported Phase 9 route tokens.
    pub fn parse(text: &str) -> Result<Self, LedgerError> {
        match text {
            "proxy" => Ok(Self::Proxy),
            "sdk_hook" => Ok(Self::SdkHook),
            _ => Err(LedgerError::UnknownRoute),
        }
    }
}

impl fmt::Display for RoutePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// The six bounded provider-boundary artifact kinds from the exact-artifact
/// schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InferenceArtifactKind {
    /// A decoded provider request body.
    ProviderRequest,
    /// A decoded non-streamed provider response body.
    ProviderResponse,
    /// One decoded event from a streamed response.
    StreamingEvent,
    /// A transition that started another transport attempt.
    Retry,
    /// A bounded usage report.
    Usage,
    /// A transport failure with no decodable provider response.
    TransportError,
}

impl InferenceArtifactKind {
    /// Every artifact kind in schema order.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::ProviderRequest,
            Self::ProviderResponse,
            Self::StreamingEvent,
            Self::Retry,
            Self::Usage,
            Self::TransportError,
        ]
    }

    /// The schema token for this kind.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::ProviderRequest => "provider-request",
            Self::ProviderResponse => "provider-response",
            Self::StreamingEvent => "streaming-event",
            Self::Retry => "retry",
            Self::Usage => "usage",
            Self::TransportError => "transport-error",
        }
    }

    /// Parse one schema token, failing closed.
    ///
    /// # Errors
    /// [`LedgerError::UnknownArtifactKind`] for a token outside the closed
    /// v1 set.
    pub fn parse(text: &str) -> Result<Self, LedgerError> {
        match text {
            "provider-request" => Ok(Self::ProviderRequest),
            "provider-response" => Ok(Self::ProviderResponse),
            "streaming-event" => Ok(Self::StreamingEvent),
            "retry" => Ok(Self::Retry),
            "usage" => Ok(Self::Usage),
            "transport-error" => Ok(Self::TransportError),
            _ => Err(LedgerError::UnknownArtifactKind),
        }
    }
}

impl fmt::Display for InferenceArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// An event requirement in a frozen expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExpectedEvent {
    /// A decoded provider request is required.
    ProviderRequest,
    /// A decoded non-streamed response is required.
    ProviderResponse,
    /// At least one decoded stream event is required.
    StreamingEvent,
    /// A retry transition is required.
    Retry,
    /// A usage record is required.
    Usage,
    /// A transport-error record is required.
    TransportError,
    /// Any one terminal event: response, stream event, or transport error.
    Terminal,
}

impl ExpectedEvent {
    /// Every requirement token in stable order.
    #[must_use]
    pub const fn all() -> [Self; 7] {
        [
            Self::ProviderRequest,
            Self::ProviderResponse,
            Self::StreamingEvent,
            Self::Retry,
            Self::Usage,
            Self::TransportError,
            Self::Terminal,
        ]
    }

    /// The bounded token used by the frozen record.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::ProviderRequest => "provider-request",
            Self::ProviderResponse => "provider-response",
            Self::StreamingEvent => "streaming-event",
            Self::Retry => "retry",
            Self::Usage => "usage",
            Self::TransportError => "transport-error",
            Self::Terminal => "terminal",
        }
    }
}

/// A fixed-size set of event requirements.  Keeping this as a bit mask makes
/// the frozen expectation bounded independently of session size or provider
/// payload volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExpectedEvents(u8);

impl ExpectedEvents {
    const PROVIDER_REQUEST: u8 = 1 << 0;
    const PROVIDER_RESPONSE: u8 = 1 << 1;
    const STREAMING_EVENT: u8 = 1 << 2;
    const RETRY: u8 = 1 << 3;
    const USAGE: u8 = 1 << 4;
    const TRANSPORT_ERROR: u8 = 1 << 5;
    const TERMINAL: u8 = 1 << 6;

    /// The normal one-attempt contract: request plus one terminal event.
    #[must_use]
    pub const fn request_and_terminal() -> Self {
        Self(Self::PROVIDER_REQUEST | Self::TERMINAL)
    }

    /// An empty requirement set, useful for callers that define their own
    /// event contract before adding requirements.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Add one event requirement.
    #[must_use]
    pub const fn with(self, event: ExpectedEvent) -> Self {
        Self(self.0 | event.bit())
    }

    /// Whether one event requirement is present.
    #[must_use]
    pub const fn contains(self, event: ExpectedEvent) -> bool {
        self.0 & event.bit() != 0
    }

    /// Iterate requirements in stable order.
    pub fn iter(self) -> impl Iterator<Item = ExpectedEvent> {
        ExpectedEvent::all()
            .into_iter()
            .filter(move |event| self.contains(*event))
    }

    /// The number of required event kinds.
    #[must_use]
    pub fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Whether no event kinds are required.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl Default for ExpectedEvents {
    fn default() -> Self {
        Self::request_and_terminal()
    }
}

impl ExpectedEvent {
    const fn bit(self) -> u8 {
        match self {
            Self::ProviderRequest => ExpectedEvents::PROVIDER_REQUEST,
            Self::ProviderResponse => ExpectedEvents::PROVIDER_RESPONSE,
            Self::StreamingEvent => ExpectedEvents::STREAMING_EVENT,
            Self::Retry => ExpectedEvents::RETRY,
            Self::Usage => ExpectedEvents::USAGE,
            Self::TransportError => ExpectedEvents::TRANSPORT_ERROR,
            Self::Terminal => ExpectedEvents::TERMINAL,
        }
    }
}

/// One frozen, content-free expectation record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedInferenceRecord {
    /// The correlation pair used for artifact matching.
    pub identity: InferenceIdentity,
    /// The logical session whose exact denominator this record contributes to.
    pub session_id: OpaqueId,
    /// The declared route policy frozen before route selection.
    pub route_policy: RoutePolicy,
    /// The orchestrator's start time for this logical inference.
    pub started_at: Timestamp,
    /// The number of transport attempts the closed expectation requires.
    pub expected_attempts: u64,
    /// The event kinds required for each expected attempt.
    pub required_events: ExpectedEvents,
    /// The final bounded result, absent while the expectation remains open.
    pub outcome: Option<ExactOutcome>,
    /// The bounded integration-failure class, present only for a failed
    /// expectation.
    pub failure: Option<IntegrationFailure>,
}

/// Short name for one frozen expected-inference record.
pub type ExpectedInference = ExpectedInferenceRecord;

impl ExpectedInferenceRecord {
    /// Freeze one expectation with the normal request-plus-terminal contract.
    #[must_use]
    pub fn new(
        identity: InferenceIdentity,
        session_id: OpaqueId,
        route_policy: RoutePolicy,
        started_at: Timestamp,
    ) -> Self {
        Self {
            identity,
            session_id,
            route_policy,
            started_at,
            expected_attempts: 1,
            required_events: ExpectedEvents::default(),
            outcome: None,
            failure: None,
        }
    }

    /// Construct directly from the protocol correlation identities.
    #[must_use]
    pub fn from_parts(
        trace_id: TraceId,
        inference_request_id: InferenceRequestId,
        session_id: OpaqueId,
        route_policy: RoutePolicy,
        started_at: Timestamp,
    ) -> Self {
        Self::new(
            InferenceIdentity::new(trace_id, inference_request_id),
            session_id,
            route_policy,
            started_at,
        )
    }

    /// The correlation key used by the ledger.
    #[must_use]
    pub fn key(&self) -> &InferenceIdentity {
        &self.identity
    }

    /// Set the expected number of attempts.
    ///
    /// The value is validated by [`ExpectedInferenceLedger::persist`].  A
    /// separate fallible setter is provided for callers that want validation
    /// while building a record.
    #[must_use]
    pub const fn with_expected_attempts(mut self, attempts: u64) -> Self {
        self.expected_attempts = attempts;
        self
    }

    /// Set the expected number of attempts with immediate validation.
    ///
    /// # Errors
    /// [`LedgerError::InvalidAttemptCount`] when `attempts` is zero or does
    /// not fit the protocol's `u63` value.
    pub fn try_with_expected_attempts(mut self, attempts: u64) -> Result<Self, LedgerError> {
        validate_attempt_count(attempts)?;
        self.expected_attempts = attempts;
        Ok(self)
    }

    /// Replace the per-attempt event contract.
    #[must_use]
    pub const fn with_required_events(mut self, required_events: ExpectedEvents) -> Self {
        self.required_events = required_events;
        self
    }

    /// Add one event requirement to the per-attempt contract.
    #[must_use]
    pub const fn requiring(mut self, event: ExpectedEvent) -> Self {
        self.required_events = self.required_events.with(event);
        self
    }

    /// Render the frozen record as canonical protocol JSON.
    ///
    /// This is the persistence representation.  It has a fixed key set and
    /// contains no event payload, provider detail, or free-form failure text.
    /// Closed outcome fields are included only after the ledger closes it.
    ///
    /// # Errors
    /// [`LedgerError::InvalidAttemptCount`] when a record built outside the
    /// ledger is not representable by the versioned JSON shape.
    pub fn to_json(&self) -> Result<Value, LedgerError> {
        validate_attempt_count(self.expected_attempts)?;
        let mut object = Object::new();
        object
            .insert("expectation_version", Value::Int(EXPECTATION_VERSION))
            .map_err(|_| LedgerError::DuplicateField)?;
        object
            .insert(
                "expected_attempts",
                Value::Int(
                    i64::try_from(self.expected_attempts)
                        .map_err(|_| LedgerError::InvalidAttemptCount)?,
                ),
            )
            .map_err(|_| LedgerError::DuplicateField)?;
        object
            .insert(
                "inference_request_id",
                Value::Text(self.identity.inference_request_id.to_string()),
            )
            .map_err(|_| LedgerError::DuplicateField)?;
        object
            .insert(
                "required_events",
                Value::Array(
                    self.required_events
                        .iter()
                        .map(|event| Value::Text(event.token().to_owned()))
                        .collect(),
                ),
            )
            .map_err(|_| LedgerError::DuplicateField)?;
        object
            .insert(
                "route_policy",
                Value::Text(self.route_policy.token().to_owned()),
            )
            .map_err(|_| LedgerError::DuplicateField)?;
        object
            .insert("session_id", Value::Text(self.session_id.to_string()))
            .map_err(|_| LedgerError::DuplicateField)?;
        object
            .insert("started_at", Value::Text(self.started_at.to_string()))
            .map_err(|_| LedgerError::DuplicateField)?;
        object
            .insert("trace_id", Value::Text(self.identity.trace_id.to_string()))
            .map_err(|_| LedgerError::DuplicateField)?;
        if let Some(outcome) = self.outcome {
            object
                .insert("outcome", Value::Text(outcome.token().to_owned()))
                .map_err(|_| LedgerError::DuplicateField)?;
        }
        if let Some(failure) = self.failure {
            object
                .insert("failure", Value::Text(failure.token().to_owned()))
                .map_err(|_| LedgerError::DuplicateField)?;
        }
        Ok(Value::Object(object))
    }
}

/// The result assigned to a closed expectation, or the unknown denominator
/// assigned to a session with no exact evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExactOutcome {
    /// Every required event of every expected attempt was observed.
    Observed,
    /// Some matching artifacts exist, but a required event or attempt is absent.
    Partial,
    /// The instrumented integration reported a bounded failure.
    Failed,
    /// The expectation closed without any matching artifact.
    Unobserved,
    /// The session has neither an expectation nor an exact artifact.
    Unknown,
}

impl ExactOutcome {
    /// Every metric/report token in registry order.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::Observed,
            Self::Partial,
            Self::Failed,
            Self::Unobserved,
            Self::Unknown,
        ]
    }

    /// The bounded metric/report token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Unobserved => "unobserved",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ExactOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Closed classes for failures in the instrumented integration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IntegrationFailure {
    /// The hook or proxy could not be installed or reached.
    ObserverUnavailable,
    /// The integration could not emit a provider-boundary event.
    CaptureFailed,
    /// Required artifacts could not be flushed before teardown.
    FlushIncomplete,
    /// The route could not be selected after the expectation was frozen.
    RouteSelectionFailed,
}

impl IntegrationFailure {
    /// The bounded failure token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::ObserverUnavailable => "observer_unavailable",
            Self::CaptureFailed => "capture_failed",
            Self::FlushIncomplete => "flush_incomplete",
            Self::RouteSelectionFailed => "route_selection_failed",
        }
    }
}

/// Why an expectation is being closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// Reconcile the recorded artifact set.
    Complete,
    /// Record a bounded integration failure; artifacts, if any, remain
    /// evidence but cannot turn the failed integration into observed coverage.
    IntegrationFailure(IntegrationFailure),
}

/// An observed artifact's content-free correlation envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedArtifact {
    /// The trace/inference pair used for matching.
    pub identity: InferenceIdentity,
    /// The session this artifact belongs to.
    pub session_id: OpaqueId,
    /// The provider transport attempt identity.
    pub provider_attempt_id: ProviderAttemptId,
    /// The dense attempt ordinal within the logical inference.
    pub attempt_ordinal: u64,
    /// The bounded artifact kind.
    pub kind: InferenceArtifactKind,
    /// The stream-event ordinal, when the kind is `streaming-event`.
    pub event_ordinal: Option<u64>,
}

impl ObservedArtifact {
    /// Construct one content-free artifact envelope.
    #[must_use]
    pub fn new(
        identity: InferenceIdentity,
        session_id: OpaqueId,
        provider_attempt_id: ProviderAttemptId,
        attempt_ordinal: u64,
        kind: InferenceArtifactKind,
    ) -> Self {
        Self {
            identity,
            session_id,
            provider_attempt_id,
            attempt_ordinal,
            kind,
            event_ordinal: None,
        }
    }

    /// Add the dense ordinal of a streaming event.
    #[must_use]
    pub const fn with_event_ordinal(mut self, event_ordinal: u64) -> Self {
        self.event_ordinal = Some(event_ordinal);
        self
    }
}

/// A content-free count of exact outcomes and session denominator state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoverageReport {
    /// Closed expectations with all required artifacts.
    pub observed: u64,
    /// Closed expectations with some but not all required artifacts.
    pub partial: u64,
    /// Closed expectations whose integration failed.
    pub failed: u64,
    /// Closed expectations with no matching artifacts.
    pub unobserved: u64,
    /// Sessions with neither expectations nor artifacts.
    pub unknown: u64,
    /// Expectations persisted but not closed yet.
    pub open_expectations: u64,
    /// Sessions known to the ledger through registration, expectations, or artifacts.
    pub sessions: u64,
    /// Artifacts retained by the ledger, including unmatched pending evidence.
    pub artifacts: u64,
}

impl CoverageReport {
    /// Count one outcome using the registry vocabulary.
    #[must_use]
    pub const fn count(&self, outcome: ExactOutcome) -> u64 {
        match outcome {
            ExactOutcome::Observed => self.observed,
            ExactOutcome::Partial => self.partial,
            ExactOutcome::Failed => self.failed,
            ExactOutcome::Unobserved => self.unobserved,
            ExactOutcome::Unknown => self.unknown,
        }
    }

    /// The number of closed expectation records.
    #[must_use]
    pub const fn closed_expectations(&self) -> u64 {
        self.observed + self.partial + self.failed + self.unobserved
    }
}

/// Why a ledger operation was refused.  All variants are closed and contain
/// no identifiers or provider text, keeping errors safe for status/metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// An expectation with the same trace/inference pair already exists.
    DuplicateExpectation,
    /// The expectation is already closed and cannot accept more artifacts.
    ExpectationClosed,
    /// The requested expectation does not exist.
    UnknownExpectation,
    /// A record's expected-attempt count is zero or outside `u63`.
    InvalidAttemptCount,
    /// A route token is outside the closed route vocabulary.
    UnknownRoute,
    /// An artifact token is outside the closed exact-artifact vocabulary.
    UnknownArtifactKind,
    /// An attempt or stream-event ordinal is outside the protocol's `u63`.
    InvalidArtifactOrdinal,
    /// An artifact tried to associate a different session with an expectation.
    SessionMismatch,
    /// A record builder attempted to insert the same JSON member twice.
    DuplicateField,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::DuplicateExpectation => "duplicate_expectation",
            Self::ExpectationClosed => "expectation_closed",
            Self::UnknownExpectation => "unknown_expectation",
            Self::InvalidAttemptCount => "invalid_attempt_count",
            Self::UnknownRoute => "unknown_route",
            Self::UnknownArtifactKind => "unknown_artifact_kind",
            Self::InvalidArtifactOrdinal => "invalid_artifact_ordinal",
            Self::SessionMismatch => "session_mismatch",
            Self::DuplicateField => "duplicate_field",
        };
        f.write_str(token)
    }
}

impl std::error::Error for LedgerError {}

/// The persisted expectation and its bounded evidence set.
#[derive(Clone, Debug)]
struct LedgerEntry {
    record: ExpectedInferenceRecord,
    artifacts: Vec<ObservedArtifact>,
}

/// The expected-inference ledger.
///
/// `persist` is the first operation an instrumented caller performs.  It
/// registers the session and freezes the identity, route policy, start time,
/// and event contract before any route-selection side effect.  Artifact
/// events may arrive before their expectation is loaded (for restart
/// recovery); they stay as bounded pending evidence and join when the exact
/// same trace/inference pair is persisted.
#[derive(Clone, Debug, Default)]
pub struct ExpectedInferenceLedger {
    expectations: BTreeMap<InferenceIdentity, LedgerEntry>,
    pending_artifacts: BTreeMap<InferenceIdentity, Vec<ObservedArtifact>>,
    sessions: BTreeSet<OpaqueId>,
}

impl ExpectedInferenceLedger {
    /// Create an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a session before capture starts.  This is what preserves an
    /// `unknown` denominator when the session emits no exact evidence at all.
    pub fn register_session(&mut self, session_id: OpaqueId) {
        self.sessions.insert(session_id);
    }

    /// Alias for integrations that call the operation an observation pass.
    pub fn observe_session(&mut self, session_id: OpaqueId) {
        self.register_session(session_id);
    }

    /// Persist one frozen expectation before route selection.
    ///
    /// A retry of an identical persisted record is idempotent and returns its
    /// key.  A different record with the same matching key is refused rather
    /// than silently rewriting the denominator.
    ///
    /// # Errors
    /// [`LedgerError::InvalidAttemptCount`] for an invalid record;
    /// [`LedgerError::DuplicateExpectation`] for a conflicting key.
    pub fn persist(
        &mut self,
        record: ExpectedInferenceRecord,
    ) -> Result<InferenceIdentity, LedgerError> {
        validate_attempt_count(record.expected_attempts)?;
        if record.outcome.is_some() || record.failure.is_some() {
            return Err(LedgerError::ExpectationClosed);
        }
        let key = record.identity.clone();
        if let Some(existing) = self.expectations.get(&key) {
            if existing.record == record {
                return Ok(key);
            }
            return Err(LedgerError::DuplicateExpectation);
        }

        if let Some(pending) = self.pending_artifacts.get(&key)
            && pending
                .iter()
                .any(|artifact| artifact.session_id != record.session_id)
        {
            return Err(LedgerError::SessionMismatch);
        }

        self.sessions.insert(record.session_id.clone());
        let artifacts = self.pending_artifacts.remove(&key).unwrap_or_default();
        self.expectations
            .insert(key.clone(), LedgerEntry { record, artifacts });
        Ok(key)
    }

    /// Freeze one expectation before route selection.  This name makes the
    /// ordering requirement explicit at integration call sites.
    ///
    /// # Errors
    /// See [`Self::persist`].
    pub fn freeze(
        &mut self,
        record: ExpectedInferenceRecord,
    ) -> Result<InferenceIdentity, LedgerError> {
        self.persist(record)
    }

    /// Restore persisted records after a process restart.
    ///
    /// Closed records are accepted because their bounded outcome is already
    /// durable.  No provider event payload is needed to restore the
    /// denominator; any event evidence is retained by the caller's artifact
    /// store and can be replayed after restoration.
    ///
    /// # Errors
    /// [`LedgerError::InvalidAttemptCount`] for an invalid record,
    /// [`LedgerError::DuplicateExpectation`] for a repeated identity, or
    /// [`LedgerError::ExpectationClosed`] for inconsistent outcome/failure
    /// fields.
    pub fn restore<I>(records: I) -> Result<Self, LedgerError>
    where
        I: IntoIterator<Item = ExpectedInferenceRecord>,
    {
        let mut ledger = Self::new();
        for record in records {
            validate_attempt_count(record.expected_attempts)?;
            if matches!(record.outcome, Some(ExactOutcome::Failed)) != record.failure.is_some() {
                return Err(LedgerError::ExpectationClosed);
            }
            let key = record.identity.clone();
            if ledger.expectations.contains_key(&key) {
                return Err(LedgerError::DuplicateExpectation);
            }
            ledger.sessions.insert(record.session_id.clone());
            ledger.expectations.insert(
                key,
                LedgerEntry {
                    record,
                    artifacts: Vec::new(),
                },
            );
        }
        Ok(ledger)
    }

    /// Return the persisted record for a matching identity.
    #[must_use]
    pub fn get(&self, identity: &InferenceIdentity) -> Option<&ExpectedInferenceRecord> {
        self.expectations.get(identity).map(|entry| &entry.record)
    }

    /// Iterate all persisted records in correlation-key order.
    pub fn records(&self) -> impl Iterator<Item = &ExpectedInferenceRecord> {
        self.expectations.values().map(|entry| &entry.record)
    }

    /// Retain one provider-boundary artifact and join it by both correlation
    /// identities.  Unknown identities are retained as pending evidence so a
    /// restart can load the expectation afterward.
    ///
    /// # Errors
    /// [`LedgerError::ExpectationClosed`] when the matching expectation has
    /// already been closed; [`LedgerError::SessionMismatch`] when its
    /// session identity disagrees with the frozen record;
    /// [`LedgerError::InvalidArtifactOrdinal`] when an ordinal is outside
    /// the protocol's `u63` range.
    pub fn record_artifact(&mut self, artifact: ObservedArtifact) -> Result<(), LedgerError> {
        if artifact.attempt_ordinal > MAX_EXPECTED_ATTEMPTS
            || artifact
                .event_ordinal
                .is_some_and(|ordinal| ordinal > MAX_EXPECTED_ATTEMPTS)
        {
            return Err(LedgerError::InvalidArtifactOrdinal);
        }
        let key = artifact.identity.clone();
        if let Some(entry) = self.expectations.get_mut(&key) {
            if entry.record.session_id != artifact.session_id {
                return Err(LedgerError::SessionMismatch);
            }
            if entry.record.outcome.is_some() {
                return Err(LedgerError::ExpectationClosed);
            }
            self.sessions.insert(artifact.session_id.clone());
            if !entry.artifacts.contains(&artifact) {
                entry.artifacts.push(artifact);
            }
        } else {
            self.sessions.insert(artifact.session_id.clone());
            let pending = self.pending_artifacts.entry(key).or_default();
            if !pending.contains(&artifact) {
                pending.push(artifact);
            }
        }
        Ok(())
    }

    /// Convenience method for recording one artifact's correlation envelope.
    ///
    /// # Errors
    /// See [`Self::record_artifact`].
    pub fn record_event(
        &mut self,
        identity: InferenceIdentity,
        session_id: OpaqueId,
        provider_attempt_id: ProviderAttemptId,
        attempt_ordinal: u64,
        kind: InferenceArtifactKind,
    ) -> Result<(), LedgerError> {
        self.record_artifact(ObservedArtifact::new(
            identity,
            session_id,
            provider_attempt_id,
            attempt_ordinal,
            kind,
        ))
    }

    /// Close an expectation and derive its bounded outcome from matching
    /// artifacts, or mark it failed when the integration reports a failure.
    ///
    /// A missing artifact is classified as `unobserved` only here, after the
    /// expectation is explicitly closed.  Open expectations never enter that
    /// bucket.
    ///
    /// # Errors
    /// [`LedgerError::UnknownExpectation`] when no matching record exists;
    /// [`LedgerError::ExpectationClosed`] when it was closed previously.
    pub fn close(
        &mut self,
        identity: &InferenceIdentity,
        reason: CloseReason,
    ) -> Result<ExactOutcome, LedgerError> {
        let entry = self
            .expectations
            .get_mut(identity)
            .ok_or(LedgerError::UnknownExpectation)?;
        if entry.record.outcome.is_some() {
            return Err(LedgerError::ExpectationClosed);
        }

        let (outcome, failure) = match reason {
            CloseReason::Complete => (evaluate(&entry.record, &entry.artifacts), None),
            CloseReason::IntegrationFailure(failure) => (ExactOutcome::Failed, Some(failure)),
        };
        entry.record.outcome = Some(outcome);
        entry.record.failure = failure;
        Ok(outcome)
    }

    /// Close successfully using artifact reconciliation.
    ///
    /// # Errors
    /// See [`Self::close`].
    pub fn close_completed(
        &mut self,
        identity: &InferenceIdentity,
    ) -> Result<ExactOutcome, LedgerError> {
        self.close(identity, CloseReason::Complete)
    }

    /// Close with a bounded integration failure.
    ///
    /// # Errors
    /// See [`Self::close`].
    pub fn close_failed(
        &mut self,
        identity: &InferenceIdentity,
        failure: IntegrationFailure,
    ) -> Result<ExactOutcome, LedgerError> {
        self.close(identity, CloseReason::IntegrationFailure(failure))
    }

    /// Reconcile every session and closed expectation into content-free
    /// counters.  Open expectations are reported separately and do not count
    /// as unobserved.
    #[must_use]
    pub fn reconcile(&self) -> CoverageReport {
        let mut report = CoverageReport {
            sessions: self.sessions.len() as u64,
            artifacts: self
                .expectations
                .values()
                .map(|entry| entry.artifacts.len() as u64)
                .sum::<u64>()
                + self
                    .pending_artifacts
                    .values()
                    .map(|artifacts| artifacts.len() as u64)
                    .sum::<u64>(),
            ..CoverageReport::default()
        };

        let mut sessions_with_evidence = BTreeSet::new();
        for entry in self.expectations.values() {
            sessions_with_evidence.insert(entry.record.session_id.clone());
            match entry.record.outcome {
                Some(ExactOutcome::Observed) => report.observed += 1,
                Some(ExactOutcome::Partial) => report.partial += 1,
                Some(ExactOutcome::Failed) => report.failed += 1,
                Some(ExactOutcome::Unobserved) => report.unobserved += 1,
                Some(ExactOutcome::Unknown) => report.unknown += 1,
                None => report.open_expectations += 1,
            }
            for artifact in &entry.artifacts {
                sessions_with_evidence.insert(artifact.session_id.clone());
            }
        }
        for artifacts in self.pending_artifacts.values() {
            for artifact in artifacts {
                sessions_with_evidence.insert(artifact.session_id.clone());
            }
        }
        report.unknown = self
            .sessions
            .iter()
            .filter(|session| !sessions_with_evidence.contains(*session))
            .count() as u64;
        report
    }

    /// The number of pending artifacts whose expectation has not been loaded.
    #[must_use]
    pub fn pending_artifacts(&self) -> usize {
        self.pending_artifacts.values().map(Vec::len).sum()
    }
}

fn validate_attempt_count(attempts: u64) -> Result<(), LedgerError> {
    if attempts == 0 || attempts > MAX_EXPECTED_ATTEMPTS {
        Err(LedgerError::InvalidAttemptCount)
    } else {
        Ok(())
    }
}

fn evaluate(record: &ExpectedInferenceRecord, artifacts: &[ObservedArtifact]) -> ExactOutcome {
    if artifacts.is_empty() {
        return ExactOutcome::Unobserved;
    }

    let mut attempts: BTreeMap<u64, Vec<&ObservedArtifact>> = BTreeMap::new();
    for artifact in artifacts {
        attempts
            .entry(artifact.attempt_ordinal)
            .or_default()
            .push(artifact);
    }

    let expected = record.expected_attempts;
    let expected_range_count = attempts.range(..expected).count();
    let expected_count_fits = usize::try_from(expected).is_ok();
    let has_extra_attempt = attempts.keys().any(|ordinal| *ordinal >= expected);
    if !expected_count_fits
        || expected_range_count != usize::try_from(expected).unwrap_or(usize::MAX)
        || has_extra_attempt
    {
        return ExactOutcome::Partial;
    }

    if attempts
        .range(..expected)
        .any(|(_, events)| !attempt_complete(events, record.required_events))
    {
        ExactOutcome::Partial
    } else {
        ExactOutcome::Observed
    }
}

fn attempt_complete(events: &[&ObservedArtifact], required: ExpectedEvents) -> bool {
    required.iter().all(|requirement| match requirement {
        ExpectedEvent::ProviderRequest => has_kind(events, InferenceArtifactKind::ProviderRequest),
        ExpectedEvent::ProviderResponse => {
            has_kind(events, InferenceArtifactKind::ProviderResponse)
        }
        ExpectedEvent::StreamingEvent => has_kind(events, InferenceArtifactKind::StreamingEvent),
        ExpectedEvent::Retry => has_kind(events, InferenceArtifactKind::Retry),
        ExpectedEvent::Usage => has_kind(events, InferenceArtifactKind::Usage),
        ExpectedEvent::TransportError => has_kind(events, InferenceArtifactKind::TransportError),
        ExpectedEvent::Terminal => {
            has_kind(events, InferenceArtifactKind::ProviderResponse)
                || has_kind(events, InferenceArtifactKind::StreamingEvent)
                || has_kind(events, InferenceArtifactKind::TransportError)
        }
    })
}

fn has_kind(events: &[&ObservedArtifact], kind: InferenceArtifactKind) -> bool {
    events.iter().any(|event| event.kind == kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> InferenceIdentity {
        InferenceIdentity::new(
            TraceId::parse(&format!("0000000{seed}-1111-7111-8111-000000000001")).expect("trace"),
            InferenceRequestId::parse(&format!("0000000{seed}-2222-7222-8222-000000000002"))
                .expect("inference"),
        )
    }

    fn session(seed: u8) -> OpaqueId {
        OpaqueId::parse(&format!("session-{seed}")).expect("session")
    }

    fn timestamp() -> Timestamp {
        Timestamp::parse("2026-09-20T12:00:00Z").expect("timestamp")
    }

    fn record(seed: u8) -> ExpectedInferenceRecord {
        ExpectedInferenceRecord::new(id(seed), session(seed), RoutePolicy::SdkHook, timestamp())
    }

    fn artifact(seed: u8, ordinal: u64, kind: InferenceArtifactKind) -> ObservedArtifact {
        ObservedArtifact::new(
            id(seed),
            session(seed),
            ProviderAttemptId::parse(&format!("0000000{seed}-3333-7333-8333-{ordinal:012x}"))
                .expect("attempt"),
            ordinal,
            kind,
        )
    }

    #[test]
    fn frozen_records_are_content_free_and_match_both_correlation_members() {
        let record = record(1);
        let json = record.to_json().expect("valid record");
        let bytes = json.canonical_bytes();
        let text = String::from_utf8(bytes).expect("json is utf8");
        assert!(text.contains("trace_id"));
        assert!(text.contains("inference_request_id"));
        assert!(text.contains("sdk_hook"));
        assert!(!text.contains("prompt"));
        assert!(!text.contains("response"));

        let mut ledger = ExpectedInferenceLedger::new();
        ledger.persist(record).expect("persist");
        let wrong_trace = InferenceIdentity::new(
            TraceId::parse("00000002-1111-7111-8111-000000000001").expect("trace"),
            id(1).inference_request_id.clone(),
        );
        ledger
            .record_artifact(ObservedArtifact::new(
                wrong_trace,
                session(1),
                ProviderAttemptId::parse("00000001-3333-7333-8333-000000000001").expect("attempt"),
                0,
                InferenceArtifactKind::ProviderResponse,
            ))
            .expect("unmatched evidence is retained");
        assert_eq!(ledger.pending_artifacts(), 1);
        assert_eq!(ledger.close_completed(&id(1)), Ok(ExactOutcome::Unobserved));
    }

    #[test]
    fn absent_attempt_is_unobserved_only_after_explicit_close() {
        let mut ledger = ExpectedInferenceLedger::new();
        let key = id(2);
        ledger.persist(record(2)).expect("persist");
        assert_eq!(ledger.reconcile().open_expectations, 1);
        assert_eq!(ledger.reconcile().unobserved, 0);
        assert_eq!(ledger.close_completed(&key), Ok(ExactOutcome::Unobserved));
        assert_eq!(ledger.reconcile().unobserved, 1);
    }

    #[test]
    fn partial_event_set_is_partial_but_a_complete_pair_is_observed() {
        let mut ledger = ExpectedInferenceLedger::new();
        let partial = id(3);
        ledger.persist(record(3)).expect("persist");
        ledger
            .record_artifact(artifact(3, 0, InferenceArtifactKind::ProviderRequest))
            .expect("request");
        assert_eq!(ledger.close_completed(&partial), Ok(ExactOutcome::Partial));

        let complete = id(4);
        ledger.persist(record(4)).expect("persist");
        ledger
            .record_artifact(artifact(4, 0, InferenceArtifactKind::ProviderRequest))
            .expect("request");
        ledger
            .record_artifact(artifact(4, 0, InferenceArtifactKind::ProviderResponse))
            .expect("response");
        assert_eq!(
            ledger.close_completed(&complete),
            Ok(ExactOutcome::Observed)
        );
    }

    #[test]
    fn integration_failure_is_failed_even_without_provider_artifacts() {
        let mut ledger = ExpectedInferenceLedger::new();
        let key = id(5);
        ledger.persist(record(5)).expect("persist");
        assert_eq!(
            ledger.close_failed(&key, IntegrationFailure::ObserverUnavailable),
            Ok(ExactOutcome::Failed)
        );
        assert_eq!(
            ledger.get(&key).expect("record").failure,
            Some(IntegrationFailure::ObserverUnavailable)
        );

        let persisted = ledger.records().cloned().collect::<Vec<_>>();
        let restored = ExpectedInferenceLedger::restore(persisted).expect("restore");
        assert_eq!(restored.reconcile().failed, 1);
    }

    #[test]
    fn sessions_without_any_evidence_are_unknown_not_unobserved() {
        let mut ledger = ExpectedInferenceLedger::new();
        ledger.register_session(session(6));
        let report = ledger.reconcile();
        assert_eq!(report.unknown, 1);
        assert_eq!(report.unobserved, 0);
    }

    #[test]
    fn retries_and_streams_use_bounded_event_contracts() {
        let mut ledger = ExpectedInferenceLedger::new();
        let retry = record(7)
            .with_expected_attempts(2)
            .requiring(ExpectedEvent::Retry);
        let key = retry.key().clone();
        ledger.persist(retry).expect("persist");
        for ordinal in 0..2 {
            ledger
                .record_artifact(artifact(7, ordinal, InferenceArtifactKind::ProviderRequest))
                .expect("request");
            ledger
                .record_artifact(artifact(
                    7,
                    ordinal,
                    InferenceArtifactKind::ProviderResponse,
                ))
                .expect("response");
        }
        // The explicit retry requirement is deliberately per-attempt, so the
        // missing retry transition remains visible as partial rather than
        // silently treating two requests as one complete exchange.
        assert_eq!(ledger.close_completed(&key), Ok(ExactOutcome::Partial));

        let stream = record(8).with_required_events(
            ExpectedEvents::empty()
                .with(ExpectedEvent::ProviderRequest)
                .with(ExpectedEvent::StreamingEvent),
        );
        let stream_key = stream.key().clone();
        ledger.persist(stream).expect("persist");
        ledger
            .record_artifact(artifact(8, 0, InferenceArtifactKind::ProviderRequest))
            .expect("request");
        ledger
            .record_artifact(
                artifact(8, 0, InferenceArtifactKind::StreamingEvent).with_event_ordinal(0),
            )
            .expect("stream event");
        assert_eq!(
            ledger.close_completed(&stream_key),
            Ok(ExactOutcome::Observed)
        );
    }

    #[test]
    fn invalid_closed_vocabularies_fail_closed() {
        assert_eq!(
            RoutePolicy::parse("transparent"),
            Err(LedgerError::UnknownRoute)
        );
        assert_eq!(
            InferenceArtifactKind::parse("provider-body"),
            Err(LedgerError::UnknownArtifactKind)
        );
        assert_eq!(RoutePolicy::Proxy.token(), "proxy");
        assert_eq!(
            InferenceArtifactKind::TransportError.token(),
            "transport-error"
        );
        assert_eq!(ExpectedEvent::Terminal.token(), "terminal");
    }
}
