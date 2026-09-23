// SPDX-License-Identifier: Apache-2.0

//! The exact-capture conformance suite for the first-party
//! OpenAI-compatible integration (plan Phase 9; threat `EC-04`).
//!
//! [`TransportConformance::run`] drives the real [`crate::openai_compat`]
//! client — the same [`crate::openai_http1`] wire transport first-party
//! code uses — against a caller-supplied loopback wire fixture, and
//! proves at that boundary:
//!
//! - the decoded **request** the observer captured is byte-for-byte the
//!   body the server received;
//! - the decoded **response** (buffered or as ordered **stream** events
//!   behind chunked transfer framing) is exactly the body the server
//!   sent, with usage extracted from the reporting event;
//! - a **retry** opens a fresh attempt identity that cites its closed
//!   predecessor, whether the predecessor failed below the boundary
//!   (connection reset, truncated stream, read deadline) or decoded
//!   into a retryable status (rate limit);
//! - an **error** is a closed transport-error class — never raw framing
//!   or free text — and a truncated stream is never mistaken for a
//!   terminal response;
//! - **teardown** reports the acknowledged or explicitly incomplete
//!   flush, so an ephemeral job cannot claim a capture the sink never
//!   acknowledged;
//! - **credentials** ride the wire's `authorization` header and appear
//!   in no artifact: not in the metadata allowlist, not in any canonical
//!   bytes;
//! - **failed observation is visible**: a sink that refuses an emission
//!   or an unacknowledged flush closes the lifecycle `Incomplete` with
//!   a bounded failure, never `Complete`;
//! - and the **hook-boundary negatives** hold: an uninstrumented
//!   transport call closes its expectation `Unobserved`, an integration
//!   that misses a hook event closes `Partial`, the lifecycle version is
//!   pinned, and none of it mints a compatibility claim.
//!
//! A run that passes every scene is the only producer of a
//! [`crate::compatibility::QualifiedRoute`]: the compatibility matrix
//! grows through this suite or not at all.

use std::fmt::Write as _;

use archivist_protocol::correlation::OrchestratorOperation;
use archivist_protocol::derivation::blob_digest;
use archivist_protocol::inference_artifact::BoundaryEvent;
use archivist_protocol::sha256::{digest, encode_hex};
use archivist_protocol::vocabulary::{
    ClientId, InferenceArtifactKind as ArtifactKind, OpaqueId, RetryReason, TenantId, Timestamp,
    TransportErrorClass, UsageSource,
};

use crate::capture_alignment::align_attempts;
use crate::compatibility::{QualifiedRoute, FIRST_PARTY_OPENAI_HTTP1};
use crate::expected_inference::{
    ExactOutcome, ExpectedInferenceLedger, ExpectedInferenceRecord,
    InferenceArtifactKind as LedgerKind, InferenceIdentity, ObservedArtifact, RoutePolicy,
};
use crate::inference_observer::{
    AttemptOutcome, CanonicalArtifact, FlushState, InferenceArtifactSink, InferenceObserver,
    InferenceObserverError, InferenceObserverV1, LogicalInferenceClose, LogicalInferenceOutcome,
    ObserverFailure, SinkFailure, INFERENCE_OBSERVER_VERSION,
};
use crate::openai_compat::{
    ChatMessage, ChatRequest, ChatRole, OpenAiEndpoint, OpenAiInference, RetryPolicy,
    response_metadata,
};
use crate::openai_http1::{Http1Transport, TransportFailure, WireEndpoint, WireRequest};

/// The bearer credential the conformance client presents on the wire.
/// Synthetic by construction: publishing it proves nothing and leaks
/// nothing, which is what makes the credential-exclusion scene honest —
/// the exact bytes can be asserted absent everywhere else.
pub const CONFORMANCE_CREDENTIAL: &str = "conformance-credential-not-a-secret";

const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
const ORIGIN: &str = "aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f";
const SESSION: &str = "conformance-session-0001";
const EXPECTATION_TIME: &str = "2026-09-21T12:00:00Z";
const MODEL: &str = "gpt-conformance";

/// One scripted connection: what the fixture does after reading the
/// request bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireScript {
    /// Write these raw bytes after the request, then close. The bytes
    /// are a complete or truncated HTTP/1.1 response exactly as they
    /// should appear on the wire — the suite builds them with
    /// [`raw_response`] and [`chunked_stream`], including deliberately
    /// truncated streams.
    Raw(Vec<u8>),
    /// Read the request, then drop the connection without a response —
    /// the below-the-boundary teardown the client must classify as a
    /// reset, never decode.
    Reset,
    /// Read the request, then hold the connection silent for
    /// `hold_ms` milliseconds, exhausting the client's read deadline.
    Stall {
        /// How long to hold the socket silent.
        hold_ms: u64,
    },
}

/// The raw request bytes of one served exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedExchange {
    /// Everything the server read from the client, head and body.
    pub raw_request: Vec<u8>,
}

/// Why the fixture could not present an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConformanceError {
    /// The fixture's endpoint failed the bounded hostname grammar.
    EndpointInvalid,
}

impl std::fmt::Display for ConformanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("conformance fixture endpoint is invalid")
    }
}

impl std::error::Error for ConformanceError {}

/// The loopback wire fixture the suite drives: a real TCP server the
/// real transport connects to, scripted one connection at a time.
pub trait OpenAiWireFixture {
    /// The endpoint every attempt of this run connects to. The fixture
    /// is bound before the run starts; the address is stable.
    ///
    /// # Errors
    /// [`ConformanceError::EndpointInvalid`] when the fixture cannot
    /// present a bounded endpoint.
    fn endpoint(&mut self) -> Result<WireEndpoint, ConformanceError>;

    /// Script the next accepted connection.
    fn queue(&mut self, script: WireScript);

    /// The raw request bytes of every served exchange, in order — a
    /// snapshot, so a threaded fixture can hand the suite its record
    /// without holding a lock across the check.
    fn received(&self) -> Vec<ReceivedExchange>;
}

/// The suite's artifact sink: records every canonical artifact and can
/// be told to refuse emissions or withhold the flush acknowledgement —
/// the fault injection the failure-visibility scenes are built on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConformanceSink {
    records: Vec<CanonicalArtifact>,
    reject_emits: bool,
    flush_state: FlushState,
}

impl ConformanceSink {
    /// A recording sink whose emissions are accepted and whose flush is
    /// acknowledged.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            reject_emits: false,
            flush_state: FlushState::Acknowledged,
        }
    }

    /// Refuse every emission (sink failure injection).
    #[must_use]
    pub const fn with_rejected_emits(mut self) -> Self {
        self.reject_emits = true;
        self
    }

    /// Report `state` for every flush (flush fault injection).
    #[must_use]
    pub const fn with_flush_state(mut self, state: FlushState) -> Self {
        self.flush_state = state;
        self
    }

    /// The canonical artifacts accepted so far, in emission order.
    #[must_use]
    pub fn artifacts(&self) -> &[CanonicalArtifact] {
        &self.records
    }
}

impl InferenceArtifactSink for ConformanceSink {
    fn emit(&mut self, artifact: CanonicalArtifact) -> Result<(), SinkFailure> {
        if self.reject_emits {
            return Err(SinkFailure::Unavailable);
        }
        self.records.push(artifact);
        Ok(())
    }

    fn flush(&mut self) -> FlushState {
        self.flush_state
    }
}

/// One conformance scene, by identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SceneId {
    /// Single non-streamed attempt: request, response, usage, metadata.
    SingleAttempt,
    /// Streamed attempt behind chunked transfer framing: ordered events
    /// and stream-event usage.
    StreamedAttempt,
    /// A stream truncated mid-body: classified, retried, never terminal.
    StreamInterrupted,
    /// A connection dropped below the boundary: classified, retried.
    RetriedAfterReset,
    /// A decoded 429: captured, retried by route policy.
    RateLimitRetry,
    /// Every attempt fails: the provider failure is visible while the
    /// observation stays complete.
    ExhaustedFailures,
    /// A read deadline elapses: classified with its observed timeout.
    ReadTimeout,
    /// The credential rides the wire and appears in no artifact.
    CredentialsExcluded,
    /// A refusing sink makes the observation explicitly failed.
    ObservationFailureVisible,
    /// An unacknowledged flush makes teardown explicitly incomplete.
    IncompleteFlushVisible,
    /// Ambient use, missed hook events, and version drift never become
    /// coverage or compatibility claims.
    HookBoundaryNegatives,
}

impl SceneId {
    /// Every scene in run order.
    #[must_use]
    pub const fn all() -> [Self; 11] {
        [
            Self::SingleAttempt,
            Self::StreamedAttempt,
            Self::StreamInterrupted,
            Self::RetriedAfterReset,
            Self::RateLimitRetry,
            Self::ExhaustedFailures,
            Self::ReadTimeout,
            Self::CredentialsExcluded,
            Self::ObservationFailureVisible,
            Self::IncompleteFlushVisible,
            Self::HookBoundaryNegatives,
        ]
    }

    /// The bounded scene token used in evidence and reports.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::SingleAttempt => "single-attempt",
            Self::StreamedAttempt => "streamed-attempt",
            Self::StreamInterrupted => "stream-interrupted",
            Self::RetriedAfterReset => "retried-after-reset",
            Self::RateLimitRetry => "rate-limit-retry",
            Self::ExhaustedFailures => "exhausted-failures",
            Self::ReadTimeout => "read-timeout",
            Self::CredentialsExcluded => "credentials-excluded",
            Self::ObservationFailureVisible => "observation-failure-visible",
            Self::IncompleteFlushVisible => "incomplete-flush-visible",
            Self::HookBoundaryNegatives => "hook-boundary-negatives",
        }
    }
}

impl std::fmt::Display for SceneId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.token())
    }
}

/// One bounded conformance check, by identity. A failed check names the
/// property that did not hold — never the payload bytes that tripped it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckId {
    /// The fixture and client could be constructed.
    FixtureReady,
    /// The scripted exchange ran to a close report.
    ExchangeRan,
    /// The lifecycle close reported the bounded outcome and flush state.
    TeardownOutcome,
    /// The wire-level attempt summary matched the scene's script.
    WireOutcome,
    /// The emitted artifact kind sequence matched.
    ArtifactKinds,
    /// Captured payload digests matched the wire bytes.
    PayloadBytes,
    /// Event and attempt ordinals were dense and ordered.
    EventOrdering,
    /// Response metadata carried exactly the allowlisted entries.
    MetadataEntries,
    /// Usage counters matched the provider report.
    UsageCounters,
    /// The retry record cited its closed predecessor with the right
    /// reason.
    RetryCitation,
    /// No credential material appeared in any artifact.
    CredentialExcluded,
    /// The server received the request the integration serialized.
    RequestOnWire,
    /// A failed observation was visible in the close report.
    ObservationFailureVisible,
    /// Ledger outcomes classified as the taxonomy requires.
    LedgerOutcome,
    /// The lifecycle version is pinned by the qualification.
    LifecycleVersion,
}

/// The result of one scene.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SceneOutcome {
    /// Which scene ran.
    pub scene: SceneId,
    /// Whether every check held.
    pub passed: bool,
    /// The checks that failed, in check order.
    pub failed_checks: Vec<CheckId>,
    /// How many canonical artifacts the scene's sink accepted.
    pub artifacts: usize,
}

impl SceneOutcome {
    /// Whether the scene passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }
}

/// The full result of one conformance run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformanceReport {
    scenes: Vec<SceneOutcome>,
    qualification: Option<QualifiedRoute>,
}

impl ConformanceReport {
    /// Every scene outcome, in run order.
    #[must_use]
    pub fn scenes(&self) -> &[SceneOutcome] {
        &self.scenes
    }

    /// Whether every scene passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.scenes.iter().all(SceneOutcome::passed)
    }

    /// The qualification a fully-passing run minted.
    #[must_use]
    pub const fn qualification(&self) -> Option<&QualifiedRoute> {
        self.qualification.as_ref()
    }

    /// The SHA-256 hex digest of the canonical evidence text, when the
    /// run qualified the route.
    #[must_use]
    pub fn evidence_digest(&self) -> Option<&str> {
        self.qualification.as_ref().map(QualifiedRoute::evidence_digest)
    }
}

/// The transport conformance suite.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransportConformance;

impl TransportConformance {
    /// Run every scene against fresh fixtures from `factory`, in run
    /// order. A run in which every scene passes mints the route
    /// qualification; any other run mints nothing.
    pub fn run(mut factory: impl FnMut() -> Box<dyn OpenAiWireFixture>) -> ConformanceReport {
        let mut scenes = Vec::new();
        for scene in SceneId::all() {
            let mut fixture = factory();
            let outcome = match scene {
                SceneId::SingleAttempt => scene_single_attempt(&mut *fixture),
                SceneId::StreamedAttempt => scene_streamed_attempt(&mut *fixture),
                SceneId::StreamInterrupted => scene_stream_interrupted(&mut *fixture),
                SceneId::RetriedAfterReset => scene_retried_after_reset(&mut *fixture),
                SceneId::RateLimitRetry => scene_rate_limit_retry(&mut *fixture),
                SceneId::ExhaustedFailures => scene_exhausted_failures(&mut *fixture),
                SceneId::ReadTimeout => scene_read_timeout(&mut *fixture),
                SceneId::CredentialsExcluded => scene_credentials_excluded(&mut *fixture),
                SceneId::ObservationFailureVisible => scene_observation_failure(&mut *fixture),
                SceneId::IncompleteFlushVisible => scene_incomplete_flush(&mut *fixture),
                SceneId::HookBoundaryNegatives => scene_hook_boundary_negatives(&mut *fixture),
            };
            scenes.push(outcome);
        }
        let passed = scenes.iter().all(SceneOutcome::passed);
        let qualification = passed.then(|| {
            let mut evidence = String::new();
            for outcome in &scenes {
                let _ = writeln!(
                    evidence,
                    "scene={}\npassed={}\nartifacts={}",
                    outcome.scene.token(),
                    u8::from(outcome.passed),
                    outcome.artifacts,
                );
            }
            QualifiedRoute::new_sdk_hook(
                FIRST_PARTY_OPENAI_HTTP1,
                INFERENCE_OBSERVER_VERSION,
                encode_hex(&digest(evidence.as_bytes())),
            )
        });
        ConformanceReport {
            scenes,
            qualification,
        }
    }
}

// ---------------------------------------------------------------------
// Scene scaffolding
// ---------------------------------------------------------------------

/// The check accumulator one scene asserts through.
struct Checks {
    scene: SceneId,
    failed: Vec<CheckId>,
}

impl Checks {
    fn new(scene: SceneId) -> Self {
        Self {
            scene,
            failed: Vec::new(),
        }
    }

    fn require(&mut self, held: bool, check: CheckId) {
        if !held && !self.failed.contains(&check) {
            self.failed.push(check);
        }
    }

    fn finish(self, artifacts: usize) -> SceneOutcome {
        SceneOutcome {
            scene: self.scene,
            passed: self.failed.is_empty(),
            failed_checks: self.failed,
            artifacts,
        }
    }
}

/// A scene step that failed: the scene stops at the first broken
/// precondition, which is the bounded outcome the report records.
struct SceneAbort;

/// The steps of one scene; `Err(SceneAbort)` after the failed check was
/// recorded against the scene's [`Checks`].
type SceneStep<T> = Result<T, SceneAbort>;

/// Record `check` when `attempted` fails, and stop the scene's steps.
fn step<T, E>(attempted: Result<T, E>, checks: &mut Checks, check: CheckId) -> SceneStep<T> {
    attempted.map_err(|_| {
        checks.require(false, check);
        SceneAbort
    })
}

fn tenant() -> Result<TenantId, ConformanceError> {
    TenantId::parse(TENANT).map_err(|_| ConformanceError::EndpointInvalid)
}

fn origin() -> Result<ClientId, ConformanceError> {
    ClientId::parse(ORIGIN).map_err(|_| ConformanceError::EndpointInvalid)
}

fn session() -> Result<OpaqueId, ConformanceError> {
    OpaqueId::parse(SESSION).map_err(|_| ConformanceError::EndpointInvalid)
}

fn expectation_time() -> Result<Timestamp, ConformanceError> {
    Timestamp::parse(EXPECTATION_TIME).map_err(|_| ConformanceError::EndpointInvalid)
}

/// The chat request every scene sends; `streamed` selects SSE.
fn chat_request(streamed: bool) -> ChatRequest {
    let base = ChatRequest::new(
        MODEL,
        vec![
            ChatMessage::new(ChatRole::System, "answer conformance probes briefly"),
            ChatMessage::new(ChatRole::User, "probe"),
        ],
    );
    let base = match base {
        Ok(request) => request,
        Err(_) => unreachable!("the conformance model and messages are valid consts"),
    };
    if streamed {
        base.streamed()
    } else {
        base
    }
}

/// The request body every scene's client serializes.
fn chat_body(streamed: bool) -> Vec<u8> {
    chat_request(streamed).body_bytes()
}

/// Build the scene's client against the fixture's endpoint.
fn scene_client(
    fixture: &mut dyn OpenAiWireFixture,
    sink: ConformanceSink,
    transport: Http1Transport,
    policy: RetryPolicy,
) -> Result<OpenAiInference<ConformanceSink>, ConformanceError> {
    let wire = fixture.endpoint()?;
    let endpoint = OpenAiEndpoint::new(
        wire.host().to_owned(),
        wire.port(),
        CONFORMANCE_CREDENTIAL.to_owned(),
    )
    .map_err(|_| ConformanceError::EndpointInvalid)?;
    Ok(OpenAiInference::new(tenant()?, origin()?, endpoint, sink)
        .with_transport(transport)
        .with_retry_policy(policy))
}

/// The body bytes the fixture received in the last exchange.
fn last_received_body(fixture: &dyn OpenAiWireFixture) -> Option<Vec<u8>> {
    let received = fixture.received();
    let exchange = received.last()?;
    let (_, body) = split_request(&exchange.raw_request);
    Some(body.to_vec())
}

/// Split a raw request into head and body at the blank line.
fn split_request(raw: &[u8]) -> (&[u8], &[u8]) {
    match raw.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(position) => (&raw[..position], &raw[position + 4..]),
        None => (raw, &[]),
    }
}

/// One full HTTP/1.1 response with `content-length` framing.
fn raw_response(status: u16, reason: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut head = String::new();
    let _ = write!(head, "HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    let _ = write!(head, "content-length: {}\r\n\r\n", body.len());
    let mut response = head.into_bytes();
    response.extend_from_slice(body);
    response
}

/// One SSE frame: the `data:` line and the blank-line dispatch.
fn sse_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = b"data: ".to_vec();
    frame.extend_from_slice(payload);
    frame.extend_from_slice(b"\n\n");
    frame
}

/// A complete chunked `text/event-stream` response: one chunk per
/// frame, terminal chunk included.
fn chunked_stream(headers: &[(&str, &str)], frames: &[Vec<u8>]) -> Vec<u8> {
    let mut head = String::from("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n");
    for (name, value) in headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    head.push_str("transfer-encoding: chunked\r\n\r\n");
    let mut response = head.into_bytes();
    for frame in frames {
        response.extend_from_slice(format!("{:x}\r\n", frame.len()).as_bytes());
        response.extend_from_slice(frame);
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"0\r\n\r\n");
    response
}

/// A truncated chunked stream: the head and one chunk, then nothing —
/// the connection the fixture closes mid-body.
fn truncated_stream(first_frame: &[u8]) -> Vec<u8> {
    let mut response =
        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n"
            .to_vec();
    response.extend_from_slice(format!("{:x}\r\n", first_frame.len()).as_bytes());
    response.extend_from_slice(first_frame);
    response.extend_from_slice(b"\r\n");
    response
}

/// The successful non-streamed completion body with usage.
const COMPLETION_BODY: &str = r#"{"id":"c-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"done"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#;

fn success_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("content-type", "application/json"),
        ("x-request-id", "req-conformance-1"),
        ("x-ratelimit-limit-requests", "60"),
        ("x-ratelimit-limit-tokens", "9000"),
        ("x-ratelimit-remaining-requests", "59"),
        ("x-ratelimit-remaining-tokens", "8997"),
        ("x-ratelimit-reset-requests", "1s"),
    ]
}

fn success_response() -> Vec<u8> {
    raw_response(200, "OK", &success_headers(), COMPLETION_BODY.as_bytes())
}

/// The kind sequence of every artifact the sink accepted.
fn kinds(sink: &ConformanceSink) -> Vec<ArtifactKind> {
    sink.artifacts()
        .iter()
        .map(|artifact| artifact.artifact().kind())
        .collect()
}

/// The kind sequence of one attempt's artifacts.
fn kinds_at(sink: &ConformanceSink, ordinal: u64) -> Vec<ArtifactKind> {
    sink.artifacts()
        .iter()
        .filter(|artifact| artifact.artifact().attempt_ordinal == ordinal)
        .map(|artifact| artifact.artifact().kind())
        .collect()
}

/// Whether the artifact's payload is exactly `bytes` (by content
/// digest, the only identity payload bytes have in the archive).
fn payload_is(artifact: &CanonicalArtifact, bytes: &[u8]) -> bool {
    artifact
        .artifact()
        .payload
        .as_ref()
        .is_some_and(|payload| payload.payload_digest == blob_digest(bytes))
}

/// Whether the artifact's canonical bytes contain `needle`.
fn canonical_contains(artifact: &CanonicalArtifact, needle: &[u8]) -> bool {
    artifact
        .canonical_bytes()
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------
// Scenes
// ---------------------------------------------------------------------

fn scene_single_attempt(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::SingleAttempt);
    let artifacts = single_attempt(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn single_attempt(checks: &mut Checks, fixture: &mut dyn OpenAiWireFixture) -> SceneStep<usize> {
    let body = chat_body(false);
    fixture.queue(WireScript::Raw(success_response()));
    let mut client = step(
        scene_client(
            fixture,
            ConformanceSink::new(),
            Http1Transport::new(),
            RetryPolicy::default(),
        ),
        checks,
        CheckId::FixtureReady,
    )?;
    let report = step(client.complete(&chat_request(false)), checks, CheckId::ExchangeRan)?;
    let sink = client.sink();
    let artifacts = sink.artifacts();

    checks.require(
        report.close.outcome == LogicalInferenceOutcome::Complete
            && report.close.failure.is_none()
            && report.close.flush_state == FlushState::Acknowledged
            && report.observation_error.is_none(),
        CheckId::TeardownOutcome,
    );
    checks.require(
        report.attempt.succeeded
            && report.attempt.final_status == Some(200)
            && report.attempt.final_failure.is_none()
            && report.attempts == 1,
        CheckId::WireOutcome,
    );
    checks.require(
        kinds(sink)
            == [
                ArtifactKind::ProviderRequest,
                ArtifactKind::ProviderResponse,
                ArtifactKind::Usage,
            ],
        CheckId::ArtifactKinds,
    );
    checks.require(
        artifacts.first().is_some_and(|artifact| payload_is(artifact, &body)),
        CheckId::PayloadBytes,
    );
    checks.require(
        artifacts
            .get(1)
            .is_some_and(|artifact| payload_is(artifact, COMPLETION_BODY.as_bytes())),
        CheckId::PayloadBytes,
    );
    // The decoded request the observer captured is the body the server
    // received: one content digest covers both.
    checks.require(
        last_received_body(fixture).is_some_and(|received| received == body),
        CheckId::RequestOnWire,
    );
    checks.require(
        fixture.received().first().is_some_and(|exchange| {
            let (head, _) = split_request(&exchange.raw_request);
            let head = String::from_utf8_lossy(head);
            head.contains("POST /v1/chat/completions HTTP/1.1")
                && head.contains("content-type: application/json")
        }),
        CheckId::RequestOnWire,
    );
    if let Some(response) = artifacts.get(1) {
        let metadata = response.artifact().metadata.as_ref();
        checks.require(
            metadata.is_some_and(|metadata| {
                metadata.content_type.as_deref() == Some("application/json")
                    && metadata.provider_request_id.as_deref() == Some("req-conformance-1")
                    && metadata.http_status == Some(200)
                    && metadata.rate_limit_limit == Some(60)
                    && metadata.rate_limit_remaining == Some(59)
                    // Non-integer reset values stay out of the archive.
                    && metadata.rate_limit_reset.is_none()
            }),
            CheckId::MetadataEntries,
        );
    } else {
        checks.require(false, CheckId::MetadataEntries);
    }
    if let Some(usage) = artifacts.get(2) {
        let metadata = usage.artifact().metadata.as_ref();
        checks.require(
            usage.artifact().event
                == BoundaryEvent::Usage {
                    usage_source: UsageSource::ResponseBody,
                }
                && metadata.is_some_and(|metadata| {
                    metadata.usage_input_tokens == Some(3)
                        && metadata.usage_output_tokens == Some(5)
                        && metadata.usage_total_tokens == Some(8)
                }),
            CheckId::UsageCounters,
        );
    } else {
        checks.require(false, CheckId::UsageCounters);
    }
    Ok(artifacts.len())
}

fn scene_streamed_attempt(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::StreamedAttempt);
    let artifacts = streamed_attempt(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn streamed_attempt(checks: &mut Checks, fixture: &mut dyn OpenAiWireFixture) -> SceneStep<usize> {
    let body = chat_body(true);
    let events: Vec<Vec<u8>> = vec![
        br#"{"id":"s-1","choices":[{"delta":{"content":"hel"}}]}"#.to_vec(),
        br#"{"id":"s-1","choices":[{"delta":{"content":"lo"}}]}"#.to_vec(),
        br#"{"id":"s-1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#.to_vec(),
        b"[DONE]".to_vec(),
    ];
    let frames: Vec<Vec<u8>> = events.iter().map(|event| sse_frame(event)).collect();
    fixture.queue(WireScript::Raw(chunked_stream(
        &[("x-request-id", "req-conformance-2")],
        &frames,
    )));
    let mut client = step(
        scene_client(
            fixture,
            ConformanceSink::new(),
            Http1Transport::new(),
            RetryPolicy::default(),
        ),
        checks,
        CheckId::FixtureReady,
    )?;
    let report = step(client.complete(&chat_request(true)), checks, CheckId::ExchangeRan)?;
    let sink = client.sink();
    let artifacts = sink.artifacts();

    checks.require(
        report.close.outcome == LogicalInferenceOutcome::Complete
            && report.close.flush_state == FlushState::Acknowledged
            && report.attempt.succeeded
            && report.attempts == 1,
        CheckId::TeardownOutcome,
    );
    checks.require(
        kinds(sink)
            == [
                ArtifactKind::ProviderRequest,
                ArtifactKind::StreamingEvent,
                ArtifactKind::StreamingEvent,
                ArtifactKind::StreamingEvent,
                ArtifactKind::StreamingEvent,
                ArtifactKind::Usage,
            ],
        CheckId::ArtifactKinds,
    );
    checks.require(
        artifacts.first().is_some_and(|artifact| payload_is(artifact, &body)),
        CheckId::PayloadBytes,
    );
    // Every decoded event, in order, is exactly the data payload the
    // server framed — dense ordinals, chunked transfer decoding in
    // between.
    for (ordinal, event) in events.iter().enumerate() {
        let artifact = artifacts.get(1 + ordinal);
        checks.require(
            artifact.is_some_and(|artifact| {
                payload_is(artifact, event)
                    && artifact.artifact().event
                        == BoundaryEvent::StreamingEvent {
                            event_ordinal: ordinal as u64,
                        }
            }),
            CheckId::EventOrdering,
        );
    }
    // The response head's allowlisted metadata rides the first event
    // only; later events carry none (the committed corpus's shape).
    checks.require(
        artifacts.get(1).is_some_and(|artifact| {
            artifact
                .artifact()
                .metadata
                .as_ref()
                .is_some_and(|metadata| {
                    metadata.content_type.as_deref() == Some("text/event-stream")
                        && metadata.provider_request_id.as_deref() == Some("req-conformance-2")
                        && metadata.http_status == Some(200)
                })
        }) && artifacts.get(2).is_some_and(|artifact| artifact.artifact().metadata.is_none()),
        CheckId::MetadataEntries,
    );
    // The usage record is joined to the reporting event's bytes.
    checks.require(
        artifacts.last().is_some_and(|artifact| {
            artifact.artifact().event
                == BoundaryEvent::Usage {
                    usage_source: UsageSource::StreamEvent,
                }
                && artifact.artifact().payload.as_ref().is_some_and(|payload| {
                    payload.payload_digest == blob_digest(&events[2])
                })
                && artifact.artifact().metadata.as_ref().is_some_and(|metadata| {
                    metadata.usage_input_tokens == Some(3)
                        && metadata.usage_output_tokens == Some(5)
                        && metadata.usage_total_tokens == Some(8)
                })
        }),
        CheckId::UsageCounters,
    );
    checks.require(!kinds(sink).contains(&ArtifactKind::ProviderResponse), CheckId::ArtifactKinds);
    Ok(artifacts.len())
}

fn scene_stream_interrupted(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::StreamInterrupted);
    let artifacts = stream_interrupted(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn stream_interrupted(
    checks: &mut Checks,
    fixture: &mut dyn OpenAiWireFixture,
) -> SceneStep<usize> {
    fixture.queue(WireScript::Raw(truncated_stream(&sse_frame(
        br#"{"id":"t-1","choices":[{"delta":{"content":"par"}}"#,
    ))));
    fixture.queue(WireScript::Raw(success_response()));
    let mut client = step(
        scene_client(
            fixture,
            ConformanceSink::new(),
            Http1Transport::new(),
            RetryPolicy {
                max_attempts: 2,
                backoff_ms: 0,
            },
        ),
        checks,
        CheckId::FixtureReady,
    )?;
    let report = step(client.complete(&chat_request(true)), checks, CheckId::ExchangeRan)?;
    let sink = client.sink();
    let artifacts = sink.artifacts();

    checks.require(
        report.attempts == 2 && report.attempt.succeeded && report.attempt.final_status == Some(200),
        CheckId::WireOutcome,
    );
    checks.require(
        report.close.outcome == LogicalInferenceOutcome::Complete
            && report.close.flush_state == FlushState::Acknowledged,
        CheckId::TeardownOutcome,
    );
    // Attempt 0: its request, one decoded event, then the bounded
    // transport error — never a terminal response for a truncated
    // stream.
    checks.require(
        kinds_at(sink, 0)
            == [
                ArtifactKind::ProviderRequest,
                ArtifactKind::StreamingEvent,
                ArtifactKind::TransportError,
            ],
        CheckId::ArtifactKinds,
    );
    let truncated = artifacts.iter().find(|artifact| {
        artifact.artifact().attempt_ordinal == 0
            && artifact.artifact().kind() == ArtifactKind::TransportError
    });
    checks.require(
        truncated.is_some_and(|artifact| {
            artifact.artifact().event
                == BoundaryEvent::TransportError {
                    error_class: TransportErrorClass::StreamInterrupted,
                    timeout_ms: None,
                }
        }),
        CheckId::EventOrdering,
    );
    // The retry cites its closed predecessor with the stream-incomplete
    // reason, under the successor's identity.
    let retry = artifacts.iter().find(|artifact| {
        artifact.artifact().attempt_ordinal == 1 && artifact.artifact().kind() == ArtifactKind::Retry
    });
    checks.require(
        retry.is_some_and(|artifact| {
            artifact.artifact().event
                == BoundaryEvent::Retry {
                    retry_of_attempt_ordinal: 0,
                    retry_reason: RetryReason::StreamIncomplete,
                    backoff_ms: Some(0),
                }
        }),
        CheckId::RetryCitation,
    );
    checks.require(
        kinds_at(sink, 1)
            == [
                ArtifactKind::Retry,
                ArtifactKind::ProviderRequest,
                ArtifactKind::ProviderResponse,
                ArtifactKind::Usage,
            ],
        CheckId::ArtifactKinds,
    );
    // Two attempts, two identities: the retry never reuses the
    // truncated attempt's identity.
    let request_ids: Vec<_> = artifacts
        .iter()
        .filter(|artifact| artifact.artifact().kind() == ArtifactKind::ProviderRequest)
        .map(|artifact| artifact.artifact().provider_attempt_id.clone())
        .collect();
    checks.require(
        request_ids.len() == 2 && request_ids[0] != request_ids[1],
        CheckId::EventOrdering,
    );
    Ok(artifacts.len())
}

fn scene_retried_after_reset(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::RetriedAfterReset);
    let artifacts = retried_after_reset(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn retried_after_reset(
    checks: &mut Checks,
    fixture: &mut dyn OpenAiWireFixture,
) -> SceneStep<usize> {
    fixture.queue(WireScript::Reset);
    fixture.queue(WireScript::Raw(success_response()));
    let mut client = step(
        scene_client(
            fixture,
            ConformanceSink::new(),
            Http1Transport::new(),
            RetryPolicy {
                max_attempts: 2,
                backoff_ms: 0,
            },
        ),
        checks,
        CheckId::FixtureReady,
    )?;
    let report = step(client.complete(&chat_request(false)), checks, CheckId::ExchangeRan)?;
    let sink = client.sink();
    let artifacts = sink.artifacts();

    checks.require(
        report.attempts == 2 && report.attempt.succeeded && report.attempt.final_status == Some(200),
        CheckId::WireOutcome,
    );
    checks.require(
        kinds_at(sink, 0) == [ArtifactKind::ProviderRequest, ArtifactKind::TransportError],
        CheckId::ArtifactKinds,
    );
    let reset = artifacts.iter().find(|artifact| {
        artifact.artifact().attempt_ordinal == 0
            && artifact.artifact().kind() == ArtifactKind::TransportError
    });
    checks.require(
        reset.is_some_and(|artifact| {
            artifact.artifact().event
                == BoundaryEvent::TransportError {
                    error_class: TransportErrorClass::ConnectionReset,
                    timeout_ms: None,
                }
        }),
        CheckId::EventOrdering,
    );
    let retry = artifacts.iter().find(|artifact| artifact.artifact().kind() == ArtifactKind::Retry);
    checks.require(
        retry.is_some_and(|artifact| {
            artifact.artifact().attempt_ordinal == 1
                && artifact.artifact().event
                    == BoundaryEvent::Retry {
                        retry_of_attempt_ordinal: 0,
                        retry_reason: RetryReason::TransportError,
                        backoff_ms: Some(0),
                    }
        }),
        CheckId::RetryCitation,
    );
    checks.require(
        kinds_at(sink, 1)
            == [
                ArtifactKind::Retry,
                ArtifactKind::ProviderRequest,
                ArtifactKind::ProviderResponse,
                ArtifactKind::Usage,
            ],
        CheckId::ArtifactKinds,
    );
    // The retried request reuses the first attempt's exact bytes and
    // therefore the same payload digest, on a fresh attempt identity.
    let body = chat_body(false);
    let request_digests: Vec<_> = artifacts
        .iter()
        .filter(|artifact| artifact.artifact().kind() == ArtifactKind::ProviderRequest)
        .map(|artifact| artifact.artifact().payload.as_ref().map(|payload| payload.payload_digest))
        .collect();
    checks.require(
        request_digests.len() == 2
            && request_digests[0] == request_digests[1]
            && request_digests[0].is_some_and(|claimed| claimed == blob_digest(&body)),
        CheckId::PayloadBytes,
    );
    Ok(artifacts.len())
}

fn scene_rate_limit_retry(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::RateLimitRetry);
    let artifacts = rate_limit_retry(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn rate_limit_retry(checks: &mut Checks, fixture: &mut dyn OpenAiWireFixture) -> SceneStep<usize> {
    let rejected = raw_response(
        429,
        "Too Many Requests",
        &[
            ("content-type", "application/json"),
            ("x-request-id", "req-conformance-429"),
            ("retry-after", "0"),
        ],
        br#"{"error":{"message":"slow down","type":"rate_limit_error"}}"#,
    );
    fixture.queue(WireScript::Raw(rejected));
    fixture.queue(WireScript::Raw(success_response()));
    let mut client = step(
        scene_client(
            fixture,
            ConformanceSink::new(),
            Http1Transport::new(),
            RetryPolicy {
                max_attempts: 2,
                backoff_ms: 0,
            },
        ),
        checks,
        CheckId::FixtureReady,
    )?;
    let report = step(client.complete(&chat_request(false)), checks, CheckId::ExchangeRan)?;
    let sink = client.sink();
    let artifacts = sink.artifacts();

    checks.require(
        report.attempts == 2 && report.attempt.succeeded && report.attempt.final_status == Some(200),
        CheckId::WireOutcome,
    );
    // The decoded failure response was captured first: a 429 with its
    // payload is evidence, not silence.
    checks.require(
        kinds_at(sink, 0) == [ArtifactKind::ProviderRequest, ArtifactKind::ProviderResponse],
        CheckId::ArtifactKinds,
    );
    checks.require(
        artifacts.get(1).is_some_and(|artifact| {
            artifact
                .artifact()
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.http_status == Some(429))
        }),
        CheckId::MetadataEntries,
    );
    let retry = artifacts.iter().find(|artifact| artifact.artifact().kind() == ArtifactKind::Retry);
    checks.require(
        retry.is_some_and(|artifact| {
            artifact.artifact().attempt_ordinal == 1
                && artifact.artifact().event
                    == BoundaryEvent::Retry {
                        retry_of_attempt_ordinal: 0,
                        retry_reason: RetryReason::RateLimit,
                        backoff_ms: Some(0),
                    }
        }),
        CheckId::RetryCitation,
    );
    checks.require(
        kinds_at(sink, 1)
            == [
                ArtifactKind::Retry,
                ArtifactKind::ProviderRequest,
                ArtifactKind::ProviderResponse,
                ArtifactKind::Usage,
            ],
        CheckId::ArtifactKinds,
    );
    Ok(artifacts.len())
}

fn scene_exhausted_failures(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::ExhaustedFailures);
    let artifacts = exhausted_failures(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn exhausted_failures(
    checks: &mut Checks,
    fixture: &mut dyn OpenAiWireFixture,
) -> SceneStep<usize> {
    fixture.queue(WireScript::Reset);
    fixture.queue(WireScript::Reset);
    fixture.queue(WireScript::Reset);
    let mut client = step(
        scene_client(
            fixture,
            ConformanceSink::new(),
            Http1Transport::new(),
            RetryPolicy {
                max_attempts: 3,
                backoff_ms: 0,
            },
        ),
        checks,
        CheckId::FixtureReady,
    )?;
    let report = step(client.complete(&chat_request(false)), checks, CheckId::ExchangeRan)?;
    let sink = client.sink();
    let artifacts = sink.artifacts();

    // The provider failure is visible at the wire level...
    checks.require(
        !report.attempt.succeeded
            && report.attempt.final_status.is_none()
            && report.attempt.final_failure
                == Some(TransportFailure::of(TransportErrorClass::ConnectionReset)),
        CheckId::WireOutcome,
    );
    // ...while the observation itself is complete: every attempt has its
    // bounded outcome, and the flush was acknowledged.
    checks.require(
        report.attempts == 3
            && report.close.outcome == LogicalInferenceOutcome::Complete
            && report.close.failure.is_none(),
        CheckId::TeardownOutcome,
    );
    checks.require(
        kinds_at(sink, 0) == [ArtifactKind::ProviderRequest, ArtifactKind::TransportError]
            && kinds_at(sink, 1)
                == [
                    ArtifactKind::Retry,
                    ArtifactKind::ProviderRequest,
                    ArtifactKind::TransportError,
                ]
            && kinds_at(sink, 2)
                == [
                    ArtifactKind::Retry,
                    ArtifactKind::ProviderRequest,
                    ArtifactKind::TransportError,
                ],
        CheckId::ArtifactKinds,
    );
    // Retry links point strictly backward: 1 cites 0, 2 cites 1.
    let retries: Vec<_> = artifacts
        .iter()
        .filter_map(|artifact| match artifact.artifact().event {
            BoundaryEvent::Retry {
                retry_of_attempt_ordinal,
                ..
            } => Some((artifact.artifact().attempt_ordinal, retry_of_attempt_ordinal)),
            _ => None,
        })
        .collect();
    checks.require(retries == vec![(1, 0), (2, 1)], CheckId::RetryCitation);
    Ok(artifacts.len())
}

fn scene_read_timeout(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::ReadTimeout);
    let artifacts = read_timeout(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn read_timeout(checks: &mut Checks, fixture: &mut dyn OpenAiWireFixture) -> SceneStep<usize> {
    fixture.queue(WireScript::Stall { hold_ms: 1_500 });
    let mut client = step(
        scene_client(
            fixture,
            ConformanceSink::new(),
            Http1Transport::with_timeouts(
                std::time::Duration::from_secs(2),
                std::time::Duration::from_millis(250),
            ),
            RetryPolicy {
                max_attempts: 1,
                backoff_ms: 0,
            },
        ),
        checks,
        CheckId::FixtureReady,
    )?;
    let report = step(client.complete(&chat_request(false)), checks, CheckId::ExchangeRan)?;
    let sink = client.sink();
    let artifacts = sink.artifacts();

    checks.require(
        !report.attempt.succeeded
            && report.attempt.final_failure
                == Some(TransportFailure {
                    class: TransportErrorClass::ReadTimeout,
                    timeout_ms: Some(250),
                }),
        CheckId::WireOutcome,
    );
    checks.require(
        artifacts.iter().any(|artifact| {
            artifact.artifact().attempt_ordinal == 0
                && artifact.artifact().event
                    == BoundaryEvent::TransportError {
                        error_class: TransportErrorClass::ReadTimeout,
                        timeout_ms: Some(250),
                    }
        }),
        CheckId::EventOrdering,
    );
    checks.require(
        report.close.outcome == LogicalInferenceOutcome::Complete,
        CheckId::TeardownOutcome,
    );
    Ok(artifacts.len())
}

fn scene_credentials_excluded(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::CredentialsExcluded);
    let artifacts = credentials_excluded(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn credentials_excluded(
    checks: &mut Checks,
    fixture: &mut dyn OpenAiWireFixture,
) -> SceneStep<usize> {
    // The provider echoes hostile headers back; the mapping must never
    // give them a channel into the archive.
    let hostile = raw_response(
        200,
        "OK",
        &[
            ("content-type", "application/json"),
            ("authorization", "Bearer server-echo-credential"),
            ("set-cookie", "session=xyz-456"),
            ("www-authenticate", "Bearer realm=hostile"),
        ],
        COMPLETION_BODY.as_bytes(),
    );
    fixture.queue(WireScript::Raw(hostile));
    let mut client = step(
        scene_client(
            fixture,
            ConformanceSink::new(),
            Http1Transport::new(),
            RetryPolicy::default(),
        ),
        checks,
        CheckId::FixtureReady,
    )?;
    let report = step(client.complete(&chat_request(false)), checks, CheckId::ExchangeRan)?;
    let sink = client.sink();
    let artifacts = sink.artifacts();

    // The credential really did ride the wire the server saw.
    checks.require(
        fixture.received().first().is_some_and(|exchange| {
            let (head, _) = split_request(&exchange.raw_request);
            let head = String::from_utf8_lossy(head);
            head.contains(&format!("authorization: bearer {CONFORMANCE_CREDENTIAL}"))
        }),
        CheckId::RequestOnWire,
    );
    // ...and none of it — client credential, server echo, cookie, or any
    // credential-shaped header name — appears in any artifact.
    let forbidden: [&[u8]; 6] = [
        CONFORMANCE_CREDENTIAL.as_bytes(),
        b"server-echo-credential",
        b"session=xyz-456",
        b"authorization",
        b"set-cookie",
        b"www-authenticate",
    ];
    checks.require(
        !artifacts
            .iter()
            .any(|artifact| forbidden.iter().any(|needle| canonical_contains(artifact, needle))),
        CheckId::CredentialExcluded,
    );
    checks.require(
        report.close.outcome == LogicalInferenceOutcome::Complete,
        CheckId::TeardownOutcome,
    );
    Ok(artifacts.len())
}

fn scene_observation_failure(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::ObservationFailureVisible);
    let artifacts = observation_failure(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn observation_failure(
    checks: &mut Checks,
    fixture: &mut dyn OpenAiWireFixture,
) -> SceneStep<usize> {
    fixture.queue(WireScript::Raw(success_response()));
    let mut client = step(
        scene_client(
            fixture,
            ConformanceSink::new().with_rejected_emits(),
            Http1Transport::new(),
            RetryPolicy::default(),
        ),
        checks,
        CheckId::FixtureReady,
    )?;
    let report = step(client.complete(&chat_request(false)), checks, CheckId::ExchangeRan)?;
    let sink = client.sink();

    // The wire exchange itself succeeded — the failure is the
    // observation's, and it is visible, not swallowed.
    checks.require(report.attempt.succeeded, CheckId::WireOutcome);
    checks.require(
        report.observation_error == Some(InferenceObserverError::Sink(SinkFailure::Unavailable)),
        CheckId::ObservationFailureVisible,
    );
    checks.require(
        report.close.outcome == LogicalInferenceOutcome::Incomplete
            && report.close.failure == Some(ObserverFailure::CaptureFailed)
            && report.close.emitted_artifacts == 0
            && sink.artifacts().is_empty(),
        CheckId::ObservationFailureVisible,
    );
    Ok(sink.artifacts().len())
}

fn scene_incomplete_flush(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::IncompleteFlushVisible);
    let artifacts = incomplete_flush(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn incomplete_flush(checks: &mut Checks, fixture: &mut dyn OpenAiWireFixture) -> SceneStep<usize> {
    fixture.queue(WireScript::Raw(success_response()));
    let mut client = step(
        scene_client(
            fixture,
            ConformanceSink::new().with_flush_state(FlushState::Incomplete),
            Http1Transport::new(),
            RetryPolicy::default(),
        ),
        checks,
        CheckId::FixtureReady,
    )?;
    let report = step(client.complete(&chat_request(false)), checks, CheckId::ExchangeRan)?;
    let sink = client.sink();

    // Every emission was accepted; teardown still refuses to claim a
    // complete capture the sink never acknowledged.
    checks.require(
        report.observation_error.is_none()
            && report.close.emitted_artifacts == 3
            && report.close.flush_state == FlushState::Incomplete
            && report.close.failure == Some(ObserverFailure::FlushIncomplete)
            && report.close.outcome == LogicalInferenceOutcome::Incomplete,
        CheckId::TeardownOutcome,
    );
    checks.require(
        kinds(sink)
            == [
                ArtifactKind::ProviderRequest,
                ArtifactKind::ProviderResponse,
                ArtifactKind::Usage,
            ],
        CheckId::ArtifactKinds,
    );
    Ok(sink.artifacts().len())
}

fn scene_hook_boundary_negatives(fixture: &mut dyn OpenAiWireFixture) -> SceneOutcome {
    let mut checks = Checks::new(SceneId::HookBoundaryNegatives);
    let artifacts = hook_boundary_negatives(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn hook_boundary_negatives(
    checks: &mut Checks,
    fixture: &mut dyn OpenAiWireFixture,
) -> SceneStep<usize> {
    // One wire exchange, consumed by the ambient call; the defective
    // hook runs purely against the observer, without a boundary.
    fixture.queue(WireScript::Raw(success_response()));
    let session = step(session(), checks, CheckId::FixtureReady)?;
    hook_negatives_ambient(checks, fixture, &session)?;
    let artifacts = hook_negatives_missed_event(checks, &session)?;
    // The lifecycle version is pinned: the qualification names the
    // version the suite actually exercised, and the concrete observer
    // implements exactly that version.
    checks.require(
        InferenceObserverV1::<ConformanceSink>::VERSION == INFERENCE_OBSERVER_VERSION
            && INFERENCE_OBSERVER_VERSION == 1,
        CheckId::LifecycleVersion,
    );
    Ok(artifacts)
}

/// (a) Ambient tracing: the transport runs uninstrumented. Whatever the
/// wire carried, no exact artifact exists, and a frozen expectation
/// closes `Unobserved` — never `Observed`, and never a compatibility
/// claim.
fn hook_negatives_ambient(
    checks: &mut Checks,
    fixture: &mut dyn OpenAiWireFixture,
    session: &OpaqueId,
) -> SceneStep<()> {
    let mut ledger = ExpectedInferenceLedger::new();
    let inference = OrchestratorOperation::new().start_inference();
    let identity =
        InferenceIdentity::new(inference.trace_id().clone(), inference.inference_request_id().clone());
    let time = step(expectation_time(), checks, CheckId::FixtureReady)?;
    step(
        ledger.freeze(ExpectedInferenceRecord::new(
            identity.clone(),
            session.clone(),
            RoutePolicy::SdkHook,
            time,
        )),
        checks,
        CheckId::LedgerOutcome,
    )?;
    let endpoint = step(fixture.endpoint(), checks, CheckId::FixtureReady)?;
    let ambient = Http1Transport::new().execute(
        &endpoint,
        &WireRequest {
            path: "/v1/chat/completions".to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: chat_body(false),
        },
        1 << 20,
    );
    checks.require(ambient.is_ok(), CheckId::FixtureReady);
    if let Ok(alignment) = align_attempts(&mut ledger, &[]) {
        // The ambient exchange minted nothing: nothing aligned.
        checks.require(
            alignment.unmatched_artifacts == 0 && alignment.inferences.is_empty(),
            CheckId::LedgerOutcome,
        );
    } else {
        checks.require(false, CheckId::LedgerOutcome);
    }
    checks.require(
        ledger.close_completed(&identity) == Ok(ExactOutcome::Unobserved),
        CheckId::LedgerOutcome,
    );
    Ok(())
}

/// (b) A hook that misses an event: the response is recorded but the
/// decoded request never was. The expectation — frozen before the
/// (defective) route ran — closes `Partial`, never `Observed`.
fn hook_negatives_missed_event(checks: &mut Checks, session: &OpaqueId) -> SceneStep<usize> {
    let tenant_id = step(tenant(), checks, CheckId::FixtureReady)?;
    let origin_id = step(origin(), checks, CheckId::FixtureReady)?;
    let mut observer = InferenceObserverV1::new(tenant_id, origin_id, ConformanceSink::new());
    let start = step(observer.start_logical_inference(None), checks, CheckId::ExchangeRan)?;
    let missing_identity =
        InferenceIdentity::new(start.trace_id().clone(), start.inference_request_id().clone());
    let mut ledger = ExpectedInferenceLedger::new();
    let time = step(expectation_time(), checks, CheckId::FixtureReady)?;
    step(
        ledger.freeze(ExpectedInferenceRecord::new(
            missing_identity.clone(),
            session.clone(),
            RoutePolicy::SdkHook,
            time,
        )),
        checks,
        CheckId::LedgerOutcome,
    )?;
    let defective = (|| -> Result<LogicalInferenceClose, InferenceObserverError> {
        observer.start_provider_attempt()?;
        // The missed hook event: no `decoded_request_bytes` call.
        observer.decoded_response_bytes(
            COMPLETION_BODY.as_bytes(),
            Some(response_metadata(
                200,
                &[("content-type".to_owned(), "application/json".to_owned())],
            )),
            None,
        )?;
        observer.attempt_outcome(AttemptOutcome::Completed, None)?;
        observer.close_logical_inference()
    })();
    let close = step(defective, checks, CheckId::ExchangeRan)?;
    checks.require(
        close.outcome == LogicalInferenceOutcome::Complete,
        CheckId::ExchangeRan,
    );
    for artifact in observer.sink().artifacts() {
        let record = artifact.artifact();
        let entry = ObservedArtifact::new(
            missing_identity.clone(),
            session.clone(),
            record.provider_attempt_id.clone(),
            record.attempt_ordinal,
            match record.kind() {
                ArtifactKind::ProviderRequest => LedgerKind::ProviderRequest,
                ArtifactKind::ProviderResponse => LedgerKind::ProviderResponse,
                ArtifactKind::StreamingEvent => LedgerKind::StreamingEvent,
                ArtifactKind::Retry => LedgerKind::Retry,
                ArtifactKind::Usage => LedgerKind::Usage,
                ArtifactKind::TransportError => LedgerKind::TransportError,
            },
        );
        step(ledger.record_artifact(entry), checks, CheckId::LedgerOutcome)?;
    }
    checks.require(
        ledger.close_completed(&missing_identity) == Ok(ExactOutcome::Partial),
        CheckId::LedgerOutcome,
    );
    Ok(observer.sink().artifacts().len())
}

// Unit-level pinning of the pure helpers the scenes rely on.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::openai_compat::usage_from_bytes;
    use crate::openai_http1::{DEFAULT_MAX_BODY_BYTES, Direction};

    #[test]
    fn sse_frames_round_trip_through_usage_extraction() {
        let event = br#"{"id":"s","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#;
        assert!(usage_from_bytes(event).is_some());
        let frame = sse_frame(event);
        assert!(frame.starts_with(b"data: {"));
        assert!(frame.ends_with(b"\n\n"));
    }

    #[test]
    fn raw_response_carries_exact_body_under_content_length() {
        let response = raw_response(200, "OK", &[("x-request-id", "r1")], COMPLETION_BODY.as_bytes());
        let text = String::from_utf8(response).expect("utf-8 response");
        let declared = format!("content-length: {}", COMPLETION_BODY.len());
        assert!(text.contains(&declared));
        assert!(text.ends_with(COMPLETION_BODY));
    }

    #[test]
    fn chunked_stream_frames_are_hex_framed() {
        let frames = vec![sse_frame(b"one"), sse_frame(b"two")];
        let raw = chunked_stream(&[], &frames);
        let text = String::from_utf8(raw).expect("utf-8 stream");
        assert!(text.contains("transfer-encoding: chunked"));
        assert!(text.contains("\r\n0\r\n\r\n"));
    }

    #[test]
    fn the_conformance_credential_never_appears_in_metadata() {
        let metadata = response_metadata(
            200,
            &[("authorization".to_owned(), format!("Bearer {CONFORMANCE_CREDENTIAL}"))],
        );
        assert!(metadata.is_empty());
        let _ = Direction::Read;
        let _ = DEFAULT_MAX_BODY_BYTES;
    }
}
