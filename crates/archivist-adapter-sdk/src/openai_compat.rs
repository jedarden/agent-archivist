// SPDX-License-Identifier: Apache-2.0

//! The first-party OpenAI-compatible integration: the one Rust client
//! transport route the version 1 [`InferenceObserver`] lifecycle
//! supports, driven end to end around the actual provider boundary
//! (plan Phase 9).
//!
//! [`OpenAiInference`] is the integration an orchestrator embeds. One
//! client instance runs exactly one logical inference: it starts the
//! lifecycle, serializes the chat-completion request, sends it through
//! the first-party [`Http1Transport`], records the decoded request,
//! every decoded response event, usage, retry transitions, and the
//! bounded attempt outcome, then closes the lifecycle with an explicit
//! flush report. Nothing about the provider SDK is part of the observer
//! contract — this module is a client, not an SDK adapter, and its
//! compatibility claim is exactly the conformance evidence
//! [`crate::openai_conformance`] produces.
//!
//! Credential discipline is structural: the endpoint's bearer credential
//! is rendered into the request's `authorization` header and never
//! reaches the capture boundary. The response-side header mapping is the
//! protocol's closed nine-entry [`Metadata`] allowlist only —
//! authorization, cookies, and any unlisted header are excluded by
//! construction, and rate-limit values the provider does not report as
//! integers stay out of the archive rather than being coerced.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{
    ClientId, RetryReason, TenantId, Timestamp, TransportErrorClass, UsageSource,
};
use archivist_protocol::{inference_artifact::Metadata, json};

use crate::inference_observer::{
    AttemptOutcome, FlushState, InferenceObserver, InferenceObserverError, InferenceObserverV1,
    LogicalInferenceClose, LogicalInferenceStart,
};
use crate::openai_http1::{
    DEFAULT_MAX_BODY_BYTES, Http1Transport, TransportFailure, WireBody, WireEndpoint, WireRequest,
    WireResponse,
};

/// Upper bound on one retry's effective backoff, so a hostile
/// `retry-after` cannot stall teardown without bound.
const MAX_BACKOFF_MS: u64 = 30_000;

/// The HTTP status the OpenAI-compatible rate-limit rejection uses.
const RATE_LIMIT_STATUS: u16 = 429;

/// Where the first-party integration publishes its chat completions.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenAiEndpoint {
    wire: WireEndpoint,
    path: String,
    credential: String,
}

impl OpenAiEndpoint {
    /// An endpoint at `host`:`port` authenticated by a bearer
    /// credential, serving the default `/v1/chat/completions` path.
    ///
    /// # Errors
    /// [`EndpointError`] when the host, the credential, or the default
    /// path fails its bounded grammar. The credential is retained by the
    /// endpoint and rendered only into the request's `authorization`
    /// header; it has no accessor and its [`fmt::Debug`] is redacted.
    pub fn new(
        host: String,
        port: u16,
        credential: String,
    ) -> Result<Self, EndpointError> {
        let wire = WireEndpoint::new(host, port).map_err(|_| EndpointError::InvalidHost)?;
        Self::assemble(wire, "/v1/chat/completions".to_owned(), credential)
    }

    /// Override the request path (including any query string).
    ///
    /// # Errors
    /// [`EndpointError::InvalidPath`] when the path is empty, longer
    /// than 2048 bytes, does not start with `/`, or carries a byte
    /// outside printable ASCII.
    pub fn with_path(mut self, path: String) -> Result<Self, EndpointError> {
        Self::checked_path(&path)?;
        self.path = path;
        Ok(self)
    }

    fn assemble(
        wire: WireEndpoint,
        path: String,
        credential: String,
    ) -> Result<Self, EndpointError> {
        Self::checked_path(&path)?;
        Self::checked_credential(&credential)?;
        Ok(Self {
            wire,
            path,
            credential,
        })
    }

    fn checked_path(path: &str) -> Result<(), EndpointError> {
        let valid = path.len() <= 2048
            && path.starts_with('/')
            && path
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte));
        if valid {
            Ok(())
        } else {
            Err(EndpointError::InvalidPath)
        }
    }

    fn checked_credential(credential: &str) -> Result<(), EndpointError> {
        let valid = !credential.is_empty()
            && credential.len() <= 4096
            && credential
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte));
        if valid {
            Ok(())
        } else {
            Err(EndpointError::InvalidCredential)
        }
    }

    /// The wire address the transport connects to.
    #[must_use]
    pub const fn wire(&self) -> &WireEndpoint {
        &self.wire
    }

    /// The request path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Debug for OpenAiEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiEndpoint")
            .field("host", &self.wire.host())
            .field("port", &self.wire.port())
            .field("path", &self.path)
            .field("credential", &"<redacted>")
            .finish()
    }
}

/// Why an endpoint was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointError {
    /// The host failed its bounded hostname grammar.
    InvalidHost,
    /// The path is empty, oversized, or carries forbidden bytes.
    InvalidPath,
    /// The credential is empty, oversized, or carries bytes that would
    /// break header framing.
    InvalidCredential,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidHost => "endpoint host is not a bounded hostname",
            Self::InvalidPath => "endpoint path is not a bounded printable path",
            Self::InvalidCredential => "endpoint credential is not a bounded printable token",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for EndpointError {}

/// The closed set of OpenAI-compatible chat roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChatRole {
    /// `system`.
    System,
    /// `user`.
    User,
    /// `assistant`.
    Assistant,
    /// `tool`.
    Tool,
}

impl ChatRole {
    /// The wire token for this role.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }
}

impl fmt::Display for ChatRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// One chat message: a closed role and its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatMessage {
    /// The message's role.
    pub role: ChatRole,
    /// The message content.
    pub content: String,
}

impl ChatMessage {
    /// A message with `role` and `content`.
    #[must_use]
    pub fn new(role: ChatRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }
}

/// A chat-completion request the integration serializes itself, so the
/// decoded request bytes the observer records are the exact bytes the
/// transport puts on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    max_tokens: Option<u32>,
}

impl ChatRequest {
    /// A non-streaming request for `model` with `messages`.
    ///
    /// # Errors
    /// [`ChatRequestError::InvalidModel`] when the model is empty or
    /// longer than 256 bytes, or [`ChatRequestError::NoMessages`] when
    /// `messages` is empty.
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Result<Self, ChatRequestError> {
        let model = model.into();
        if model.is_empty() || model.len() > 256 {
            return Err(ChatRequestError::InvalidModel);
        }
        if messages.is_empty() {
            return Err(ChatRequestError::NoMessages);
        }
        Ok(Self {
            model,
            messages,
            stream: false,
            max_tokens: None,
        })
    }

    /// Request a streamed (`text/event-stream`) response.
    #[must_use]
    pub const fn streamed(mut self) -> Self {
        self.stream = true;
        self
    }

    /// Bound the completion length.
    #[must_use]
    pub const fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// The serialized JSON document sent as the request body: the exact
    /// decoded request bytes the boundary observes.
    #[must_use]
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut object = Object::new();
        let _ = object.insert("model", Value::Text(self.model.clone()));
        let messages = self
            .messages
            .iter()
            .map(|message| {
                let mut member = Object::new();
                let _ = member.insert("role", Value::Text(message.role.token().to_owned()));
                let _ = member.insert("content", Value::Text(message.content.clone()));
                Value::Object(member)
            })
            .collect();
        let _ = object.insert("messages", Value::Array(messages));
        if self.stream {
            let _ = object.insert("stream", Value::Bool(true));
        }
        if let Some(max_tokens) = self.max_tokens {
            let _ = object.insert(
                "max_tokens",
                Value::Int(i64::from(max_tokens)),
            );
        }
        Value::Object(object).canonical_bytes()
    }
}

/// Why a chat request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatRequestError {
    /// The model name is empty or oversized.
    InvalidModel,
    /// No messages were supplied.
    NoMessages,
}

impl fmt::Display for ChatRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidModel => "chat request model is empty or oversized",
            Self::NoMessages => "chat request carries no messages",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for ChatRequestError {}

/// The bounded retry schedule: how many transport attempts one logical
/// inference may make, and the backoff between them when the provider
/// supplies no `retry-after`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// The attempt budget, including the first attempt. A zero is
    /// treated as one attempt.
    pub max_attempts: u32,
    /// Backoff between attempts, in milliseconds, when the provider
    /// supplies no `retry-after`.
    pub backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff_ms: 0,
        }
    }
}

/// Usage counters extracted from a provider response body or stream
/// event, in the OpenAI-compatible field vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsageCounters {
    /// `prompt_tokens`.
    pub input_tokens: u64,
    /// `completion_tokens`.
    pub output_tokens: u64,
    /// `total_tokens`, retained as reported.
    pub total_tokens: u64,
}

/// The result of the final transport attempt of a logical inference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttemptSummary {
    /// Whether the final attempt ended in a 2xx decoded response.
    pub succeeded: bool,
    /// The final attempt's decoded response status, when one completed.
    pub final_status: Option<u16>,
    /// The final attempt's transport failure, when it ended below the
    /// decoded-response boundary.
    pub final_failure: Option<TransportFailure>,
}

/// The full report of one logical inference: the lifecycle close report
/// plus the wire-level outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionReport {
    /// The logical inference's correlation identity.
    pub start: LogicalInferenceStart,
    /// The lifecycle close: bounded outcome, flush state, and any
    /// integration failure. Teardown can never claim a complete capture
    /// the sink did not acknowledge.
    pub close: LogicalInferenceClose,
    /// How many transport attempts ran.
    pub attempts: u64,
    /// The final attempt's wire-level outcome.
    pub attempt: AttemptSummary,
    /// The observation error that aborted the exchange, when the
    /// observer, protocol, or sink refused an emission. The close report
    /// carries the same failure as a bounded class.
    pub observation_error: Option<InferenceObserverError>,
}

/// The one first-party OpenAI-compatible client integration.
///
/// A client instance runs exactly one logical inference:
/// [`OpenAiInference::complete`] starts the lifecycle, drives every
/// transport attempt through [`Http1Transport`], and closes it with an
/// acknowledged or explicitly incomplete flush. A second `complete` on
/// the same instance is an [`InferenceObserverError::AlreadyStarted`].
pub struct OpenAiInference<S> {
    observer: InferenceObserverV1<S>,
    endpoint: OpenAiEndpoint,
    transport: Http1Transport,
    policy: RetryPolicy,
    max_body_bytes: usize,
}

impl<S> OpenAiInference<S> {
    /// A client for `endpoint` capturing into `sink` for one tenant and
    /// originating client.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        origin_client_id: ClientId,
        endpoint: OpenAiEndpoint,
        sink: S,
    ) -> Self {
        Self {
            observer: InferenceObserverV1::new(tenant_id, origin_client_id, sink),
            endpoint,
            transport: Http1Transport::new(),
            policy: RetryPolicy::default(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Pin the transport (for explicit timeouts).
    #[must_use]
    pub fn with_transport(mut self, transport: Http1Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Pin the retry schedule.
    #[must_use]
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Pin the decoded-body cap.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// The endpoint this client calls.
    #[must_use]
    pub const fn endpoint(&self) -> &OpenAiEndpoint {
        &self.endpoint
    }

    /// Borrow the artifact sink, for draining captured records after
    /// close.
    #[must_use]
    pub const fn sink(&self) -> &S {
        self.observer.sink()
    }

    /// Mutably borrow the artifact sink — the integration's own
    /// delivery seam (fault injection, delivery toggles). The lifecycle
    /// contract is unchanged: a sink that refuses an emission makes the
    /// whole observation explicitly failed and visible.
    #[must_use]
    pub fn sink_mut(&mut self) -> &mut S {
        self.observer.sink_mut()
    }
}

impl<S: crate::inference_observer::InferenceArtifactSink> OpenAiInference<S> {
    /// Run one logical inference to completion: lifecycle start, every
    /// transport attempt with its retry transitions, and lifecycle close
    /// with the flush report.
    ///
    /// Transport failures and retryable statuses are captured and
    /// retried inside the lifecycle; they do not abort the exchange.
    /// The only [`Err`] is a lifecycle misuse (a second `complete` on
    /// the same instance). An observation failure — a sink refusal —
    /// aborts the exchange and is reported through
    /// [`CompletionReport::observation_error`] and the close report's
    /// bounded failure, never swallowed.
    ///
    /// # Errors
    /// [`InferenceObserverError::AlreadyStarted`] when this client
    /// already ran its one logical inference.
    pub fn complete(
        &mut self,
        request: &ChatRequest,
    ) -> Result<CompletionReport, InferenceObserverError> {
        let start = self.observer.start_logical_inference(now())?;
        let body = request.body_bytes();
        let max_attempts = u64::from(self.policy.max_attempts.max(1));
        let mut summary = AttemptSummary::default();
        let mut pending_retry: Option<(RetryReason, u64)> = None;
        let mut attempts = 0_u64;
        let mut observation_error: Option<InferenceObserverError> = None;

        loop {
            let step = if attempts == 0 {
                self.observer.start_provider_attempt()
            } else {
                let (reason, backoff_ms) =
                    pending_retry.take().expect("a retry decision is pending");
                self.rest(backoff_ms);
                self.observer
                    .start_retry_attempt(reason, Some(backoff_ms), now())
            };
            if let Err(error) = step {
                observation_error = Some(error);
                break;
            }
            attempts += 1;
            summary = AttemptSummary::default();

            let emitted = self
                .observer
                .decoded_request_bytes(&body, None, now())
                .map(|_| ());
            if let Err(error) = emitted {
                observation_error = Some(error);
                break;
            }

            let response = self.send(&body);
            match response {
                Err(failure) => {
                    summary.final_failure = Some(failure);
                    let recorded = self.observer.attempt_outcome(
                        AttemptOutcome::TransportError {
                            error_class: failure.class,
                            timeout_ms: failure.timeout_ms,
                        },
                        now(),
                    );
                    if let Err(error) = recorded {
                        observation_error = Some(error);
                        break;
                    }
                    if attempts >= max_attempts {
                        break;
                    }
                    pending_retry = Some((RetryReason::TransportError, self.policy.backoff_ms));
                }
                Ok(response) => match self.record_response(response, &mut summary) {
                    Ok(Some((reason, backoff_ms))) => {
                        if attempts >= max_attempts {
                            break;
                        }
                        pending_retry = Some((reason, backoff_ms));
                    }
                    Ok(None) => break,
                    Err(error) => {
                        observation_error = Some(error);
                        break;
                    }
                },
            }
        }

        let close = self.observer.close_logical_inference()?;
        Ok(CompletionReport {
            start,
            close,
            attempts,
            attempt: summary,
            observation_error,
        })
    }

    /// Flush currently emitted artifacts without closing the logical
    /// inference.
    ///
    /// # Errors
    /// See [`InferenceObserver::flush`].
    pub fn flush(&mut self) -> Result<FlushState, InferenceObserverError> {
        self.observer.flush()
    }

    /// Send one serialized request; the credential rides only here.
    fn send(&self, body: &[u8]) -> Result<WireResponse, TransportFailure> {
        let request = WireRequest {
            path: self.endpoint.path().to_owned(),
            headers: vec![
                (
                    "content-type".to_owned(),
                    "application/json".to_owned(),
                ),
                (
                    "authorization".to_owned(),
                    format!("Bearer {}", self.endpoint.credential),
                ),
            ],
            body: body.to_owned(),
        };
        self.transport
            .execute(self.endpoint.wire(), &request, self.max_body_bytes)
    }

    /// Record one decoded response at the boundary: the buffered body
    /// or every ordered stream event, usage when reported, the attempt
    /// outcome, and the retry decision the status implies.
    ///
    /// `Ok(Some(..))` names the retry to start; `Ok(None)` is terminal.
    fn record_response(
        &mut self,
        response: WireResponse,
        summary: &mut AttemptSummary,
    ) -> Result<Option<(RetryReason, u64)>, InferenceObserverError> {
        let status = response.status;
        summary.final_status = Some(status);
        let retry_after = retry_after_seconds(&response);
        let metadata = response_metadata(status, &response.headers);

        match response.body {
            WireBody::Full(bytes) => {
                self.observer
                    .decoded_response_bytes(&bytes, Some(metadata), now())?;
                if let Some(usage) = usage_from_bytes(&bytes) {
                    self.observer.usage(
                        UsageSource::ResponseBody,
                        usage.input_tokens,
                        usage.output_tokens,
                        usage.total_tokens,
                        now(),
                    )?;
                }
            }
            WireBody::Stream(mut stream) => {
                let mut first_event = true;
                loop {
                    match stream.next_event() {
                        Ok(Some(event)) => {
                            let event_metadata = if first_event {
                                first_event = false;
                                Some(metadata.clone())
                            } else {
                                None
                            };
                            self.observer
                                .decoded_response_event(&event, event_metadata, now())?;
                            if let Some(usage) = usage_from_bytes(&event) {
                                self.observer.usage(
                                    UsageSource::StreamEvent,
                                    usage.input_tokens,
                                    usage.output_tokens,
                                    usage.total_tokens,
                                    now(),
                                )?;
                            }
                        }
                        Ok(None) => break,
                        Err(failure) => {
                            // The decoded stream ended abnormally: a
                            // below-boundary failure, never a terminal
                            // response. A connection reset mid-stream is
                            // classified `stream-interrupted`, the
                            // closed class for an abnormal stream end.
                            let class = if failure.class == TransportErrorClass::ConnectionReset {
                                TransportErrorClass::StreamInterrupted
                            } else {
                                failure.class
                            };
                            summary.final_failure = Some(TransportFailure {
                                class,
                                timeout_ms: failure.timeout_ms,
                            });
                            summary.final_status = None;
                            summary.succeeded = false;
                            self.observer.attempt_outcome(
                                AttemptOutcome::TransportError {
                                    error_class: class,
                                    timeout_ms: failure.timeout_ms,
                                },
                                now(),
                            )?;
                            return Ok(Some((
                                RetryReason::StreamIncomplete,
                                self.effective_backoff(retry_after),
                            )));
                        }
                    }
                }
            }
        }

        // The decoded-response boundary completed; the attempt is
        // `Completed` whether the status is success or a decoded
        // provider error.
        summary.succeeded = (200..300).contains(&status);
        self.observer
            .attempt_outcome(AttemptOutcome::Completed, now())?;
        let reason = if status == RATE_LIMIT_STATUS {
            Some(RetryReason::RateLimit)
        } else if status >= 500 {
            Some(RetryReason::HttpStatus)
        } else {
            None
        };
        Ok(reason.map(|reason| (reason, self.effective_backoff(retry_after))))
    }

    fn effective_backoff(&self, retry_after: Option<u64>) -> u64 {
        retry_after
            .unwrap_or(self.policy.backoff_ms)
            .min(MAX_BACKOFF_MS)
    }

    fn rest(&self, backoff_ms: u64) {
        if backoff_ms > 0 {
            std::thread::sleep(Duration::from_millis(backoff_ms));
        }
    }
}

/// The bounded capture instant, when the host clock supplies a real
/// UTC calendar instant. A clock before the epoch (or a timestamp the
/// protocol grammar refuses) yields `None`, and the record simply
/// carries no capture time — never a fabricated one.
fn now() -> Option<Timestamp> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let seconds = elapsed.as_secs();
    let (year, month, day) = civil_from_days(i64::try_from(seconds / 86_400).ok()?)?;
    let rest = seconds % 86_400;
    let text = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    );
    Timestamp::parse(&text).ok()
}

/// Days since 1970-01-01 to a proleptic-Gregorian (year, month, day),
/// by Howard Hinnant's `civil_from_days`. Returns `None` only for day
/// counts whose year would leave the four-digit protocol grammar.
fn civil_from_days(days: i64) -> Option<(i64, u32, u32)> {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year + i64::from(month <= 2);
    if !(0..=9999).contains(&year) {
        return None;
    }
    Some((
        year,
        u32::try_from(month).ok()?,
        u32::try_from(day).ok()?,
    ))
}

/// The first header value for lowercase `name`.
fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

/// The first header in `names` whose value parses as a non-negative
/// integer. Values the provider does not report as integers stay out of
/// the archive; they are never coerced.
fn first_integer_header(headers: &[(String, String)], names: &[&str]) -> Option<u64> {
    names
        .iter()
        .filter_map(|name| header_value(headers, name))
        .find_map(|value| value.parse::<u64>().ok())
}

/// Normalize a response head into the protocol's closed metadata
/// allowlist. Every unlisted header — authorization, cookies, provider
/// credentials, anything else — is excluded by construction.
#[must_use]
pub fn response_metadata(status: u16, headers: &[(String, String)]) -> Metadata {
    Metadata {
        content_type: header_value(headers, "content-type").map(str::to_owned),
        provider_request_id: header_value(headers, "x-request-id")
            .or_else(|| header_value(headers, "request-id"))
            .map(str::to_owned),
        http_status: Some(u64::from(status)),
        rate_limit_limit: first_integer_header(
            headers,
            &[
                "x-ratelimit-limit-requests",
                "x-ratelimit-limit-tokens",
            ],
        ),
        rate_limit_remaining: first_integer_header(
            headers,
            &[
                "x-ratelimit-remaining-requests",
                "x-ratelimit-remaining-tokens",
            ],
        ),
        rate_limit_reset: first_integer_header(
            headers,
            &["x-ratelimit-reset-requests", "x-ratelimit-reset-tokens"],
        ),
        usage_input_tokens: None,
        usage_output_tokens: None,
        usage_total_tokens: None,
    }
}

/// The `retry-after` header as whole seconds, when it is one.
fn retry_after_seconds(response: &WireResponse) -> Option<u64> {
    response.header("retry-after").and_then(|value| value.parse::<u64>().ok())
}

/// Extract the OpenAI-compatible usage object from decoded bytes, when
/// the bytes parse as a JSON object carrying all three counters.
/// Stream framing such as the `[DONE]` sentinel simply yields `None`.
#[must_use]
pub fn usage_from_bytes(bytes: &[u8]) -> Option<UsageCounters> {
    let value = json::parse(bytes).ok()?;
    let Value::Object(object) = &value else {
        return None;
    };
    let Value::Object(usage) = object.get("usage")? else {
        return None;
    };
    let counter = |name: &str| -> Option<u64> {
        match usage.get(name) {
            Some(Value::Int(count)) => u64::try_from(*count).ok(),
            _ => None,
        }
    };
    Some(UsageCounters {
        input_tokens: counter("prompt_tokens")?,
        output_tokens: counter("completion_tokens")?,
        total_tokens: counter("total_tokens")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDENTIAL: &str = "test-credential-not-a-secret";

    fn endpoint() -> OpenAiEndpoint {
        OpenAiEndpoint::new("127.0.0.1".to_owned(), 8080, CREDENTIAL.to_owned())
            .expect("loopback endpoint")
    }

    fn request() -> ChatRequest {
        ChatRequest::new(
            "gpt-test",
            vec![
                ChatMessage::new(ChatRole::System, "be brief"),
                ChatMessage::new(ChatRole::User, "hello"),
            ],
        )
        .expect("chat request")
    }

    #[test]
    fn endpoint_debug_redacts_credential() {
        let rendered = format!("{:?}", endpoint());
        assert!(!rendered.contains(CREDENTIAL));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn endpoint_refuses_framing_breaking_credentials() {
        let error = OpenAiEndpoint::new("h".to_owned(), 1, "bad\r\ninject".to_owned())
            .expect_err("control bytes refused");
        assert_eq!(error, EndpointError::InvalidCredential);
        let error = OpenAiEndpoint::new("h".to_owned(), 1, String::new())
            .expect_err("empty refused");
        assert_eq!(error, EndpointError::InvalidCredential);
    }

    #[test]
    fn chat_request_body_is_deterministic_and_complete() {
        let body = request().streamed().with_max_tokens(16).body_bytes();
        let again = request().streamed().with_max_tokens(16).body_bytes();
        assert_eq!(body, again);
        let text = String::from_utf8(body).expect("utf-8 body");
        assert!(text.contains("\"model\":\"gpt-test\""));
        assert!(text.contains("\"role\":\"system\""));
        assert!(text.contains("\"stream\":true"));
        assert!(text.contains("\"max_tokens\":16"));
    }

    #[test]
    fn response_metadata_maps_only_the_allowlist() {
        let headers = vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("x-request-id".to_owned(), "req-7".to_owned()),
            (
                "x-ratelimit-limit-requests".to_owned(),
                "60".to_owned(),
            ),
            (
                "x-ratelimit-remaining-requests".to_owned(),
                "59".to_owned(),
            ),
            // Non-integer reset values stay out of the archive.
            ("x-ratelimit-reset-requests".to_owned(), "1s".to_owned()),
            // Hostile and merely-unlisted headers never enter metadata.
            ("authorization".to_owned(), "Bearer echo".to_owned()),
            ("set-cookie".to_owned(), "session=xyz".to_owned()),
            ("server".to_owned(), "synthetic".to_owned()),
        ];
        let metadata = response_metadata(200, &headers);
        assert_eq!(metadata.content_type.as_deref(), Some("application/json"));
        assert_eq!(metadata.provider_request_id.as_deref(), Some("req-7"));
        assert_eq!(metadata.http_status, Some(200));
        assert_eq!(metadata.rate_limit_limit, Some(60));
        assert_eq!(metadata.rate_limit_remaining, Some(59));
        assert_eq!(metadata.rate_limit_reset, None);
    }

    #[test]
    fn usage_extraction_reads_openai_field_names() {
        let body = br#"{"id":"1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#;
        let usage = usage_from_bytes(body).expect("usage object");
        assert_eq!(
            usage,
            UsageCounters {
                input_tokens: 3,
                output_tokens: 5,
                total_tokens: 8,
            }
        );
        assert_eq!(usage_from_bytes(b"[DONE]"), None);
        assert_eq!(usage_from_bytes(b"{\"usage\":null}"), None);
        assert_eq!(usage_from_bytes(b"{}"), None);
        // Negative counters are refused rather than truncated.
        assert_eq!(
            usage_from_bytes(br#"{"usage":{"prompt_tokens":-1,"completion_tokens":5,"total_tokens":4}}"#),
            None
        );
    }

    #[test]
    fn capture_time_is_a_real_calendar_instant() {
        let stamp = now().expect("post-epoch host clock");
        assert!(stamp.calendar_valid());
        let rendered = stamp.to_string();
        assert_eq!(rendered.len(), 20);
        assert!(rendered.ends_with('Z'));
        // The civil conversion agrees with known instants.
        assert_eq!(civil_from_days(0), Some((1970, 1, 1)));
        assert_eq!(civil_from_days(19_723), Some((2023, 12, 31)));
    }

    #[test]
    fn retry_policy_defaults_bound_the_exchange() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.backoff_ms, 0);
    }
}
