// SPDX-License-Identifier: Apache-2.0

//! The explicitly routed OpenAI-compatible capture proxy (plan Phase 9).
//!
//! A harness points its OpenAI-compatible client at a local [`CaptureProxy`]
//! instead of at the provider. The proxy serves exactly one declared
//! route on a loopback port: it accepts a bounded HTTP/1.1 request,
//! drops every caller header at the boundary, forwards the decoded body
//! to the provider under the route's own credential on the wire, and
//! relays the provider's response — buffered or streamed, in order —
//! back to the caller while the same [`InferenceObserverV1`] lifecycle
//! captures every provider attempt exactly as the first-party client
//! does: decoded request, response or ordered stream events, usage,
//! retry, transport error, teardown.
//!
//! The boundary the caller sees is narrow on purpose. A request that is
//! not a bounded `POST` to the declared route is answered with a
//! bounded, content-free refusal and produces no artifacts; every
//! caller header — authorization, cookies, anything the caller believed
//! it was sending to its provider — is dropped unread. Archived
//! response metadata is the closed allowlist [`response_metadata`]
//! alone. And buffering is bounded end to end: request bodies are
//! capped at [`openai_http1::DEFAULT_MAX_BODY_BYTES`] by default, and
//! the relay between the provider read and the caller write holds at
//! most one decoded event, so a slow caller cannot grow it past
//! [`RELAY_MAX_BUFFERED_BYTES`] — the provider's own bytes stay in the
//! provider's socket, backpressured.

use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use archivist_protocol::vocabulary::{
    ClientId, RetryReason, TenantId, TransportErrorClass, UsageSource,
};

use crate::inference_observer::{
    AttemptOutcome, InferenceArtifactSink, InferenceObserver, InferenceObserverError,
    InferenceObserverV1, LogicalInferenceClose,
};
use crate::openai_compat::{
    MAX_BACKOFF_MS, OpenAiEndpoint, RetryPolicy, UsageCounters, now, response_metadata,
    usage_from_bytes,
};
use crate::openai_http1::{
    DEFAULT_MAX_BODY_BYTES, Http1Transport, TransportFailure, WireBody, WireRequest, WireResponse,
};

/// The only host the proxy binds: a local capture boundary for a local
/// harness, never a network service.
const LOOPBACK: &str = "127.0.0.1";

/// Default bound on exchanges forwarded concurrently.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 16;

/// Bound on one caller head line, mirroring the transport's own
/// head-line bound: a hostile peer cannot grow the reader's buffer
/// without bound.
const HEAD_LINE_MAX_BYTES: usize = 16 * 1024;

/// Bound on the caller's request head as a whole.
const REQUEST_HEAD_MAX_BYTES: usize = 32 * 1024;

/// The caller-facing socket timeouts. Every read and write the proxy
/// does on a caller connection is bounded by this deadline, so a silent
/// peer cannot hold a capture slot forever.
const CALLER_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The relay's declared bound: the most decoded bytes the proxy can
/// hold between a provider read and a caller write.
///
/// The relay is a pass-through, not a buffer: every decoded event is
/// written to the caller the moment it is read, so the relay never
/// holds more than the one event in flight — and one event can never
/// exceed the body cap every decoded response is held to. A caller
/// that stops reading therefore cannot grow the relay: its socket
/// fills, the relay's write blocks, the proxy stops reading the
/// provider, and the provider's own bytes stay in the provider's
/// socket — the backpressure the bounded-relay property is stated in.
pub const RELAY_MAX_BUFFERED_BYTES: usize = DEFAULT_MAX_BODY_BYTES;

/// Why a connection was refused before capture. A refusal is a bounded
/// wire answer — status, reason, and one fixed content-free body — and
/// produces no artifacts, forwards nothing, and names no payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The request head could not be parsed into a bounded HTTP/1.1
    /// request line and header block.
    MalformedHead,
    /// The request was not a `POST`.
    MethodNotAllowed,
    /// The request path was not the one declared route.
    UnknownRoute,
    /// The request carried a `transfer-encoding` header: the proxy
    /// captures only content-length-framed bodies.
    TransferFramed,
    /// The request carried no valid, self-consistent `content-length`.
    LengthRequired,
    /// The declared body exceeds the proxy's decoded-body cap.
    BodyOversized,
    /// The body ended before its declared length; nothing was captured.
    IncompleteBody,
    /// Every in-flight slot was spent: the proxy never queues, so the
    /// caller is refused immediately.
    Backpressured,
}

impl Refusal {
    /// The HTTP status the refusal answers with.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::MalformedHead | Self::IncompleteBody => 400,
            Self::MethodNotAllowed => 405,
            Self::UnknownRoute => 404,
            Self::TransferFramed | Self::LengthRequired => 411,
            Self::BodyOversized => 413,
            Self::Backpressured => 503,
        }
    }

    /// The reason phrase the refusal answers with.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::MalformedHead | Self::IncompleteBody => "Bad Request",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::UnknownRoute => "Not Found",
            Self::TransferFramed | Self::LengthRequired => "Length Required",
            Self::BodyOversized => "Content Too Large",
            Self::Backpressured => "Service Unavailable",
        }
    }

    /// The bounded scene token for evidence and reports.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::MalformedHead => "malformed-head",
            Self::MethodNotAllowed => "method-not-allowed",
            Self::UnknownRoute => "unknown-route",
            Self::TransferFramed => "transfer-framed",
            Self::LengthRequired => "length-required",
            Self::BodyOversized => "body-oversized",
            Self::IncompleteBody => "incomplete-body",
            Self::Backpressured => "backpressured",
        }
    }

    /// The fixed, content-free JSON body the refusal answers with. It
    /// names the boundary rule that refused the request and nothing
    /// else — never payload, headers, or identity material.
    #[must_use]
    pub const fn body_text(self) -> &'static str {
        match self {
            Self::MalformedHead => {
                "{\"error\":{\"message\":\"request head is not a bounded HTTP/1.1 request\"}}"
            }
            Self::MethodNotAllowed => "{\"error\":{\"message\":\"only POST is routed\"}}",
            Self::UnknownRoute => "{\"error\":{\"message\":\"path is not the declared route\"}}",
            Self::TransferFramed => {
                "{\"error\":{\"message\":\"transfer-framed requests are not captured\"}}"
            }
            Self::LengthRequired => {
                "{\"error\":{\"message\":\"one valid content-length is required\"}}"
            }
            Self::BodyOversized => {
                "{\"error\":{\"message\":\"declared body exceeds the capture cap\"}}"
            }
            Self::IncompleteBody => {
                "{\"error\":{\"message\":\"body ended before its declared length\"}}"
            }
            Self::Backpressured => {
                "{\"error\":{\"message\":\"capture budget is spent; retry later\"}}"
            }
        }
    }
}

/// How one served exchange ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExchangeOutcome {
    /// The exchange was captured and forwarded; the report carries the
    /// lifecycle close and the wire-level summary.
    Captured(ProxyCapture),
    /// The request was refused before capture: bounded refusal, no
    /// artifacts, nothing forwarded.
    Refused(Refusal),
}

impl ExchangeOutcome {
    /// The capture report, when the exchange was captured.
    #[must_use]
    pub const fn captured(&self) -> Option<&ProxyCapture> {
        match self {
            Self::Captured(capture) => Some(capture),
            Self::Refused(_) => None,
        }
    }

    /// The refusal, when the exchange was refused.
    #[must_use]
    pub const fn refusal(&self) -> Option<Refusal> {
        match self {
            Self::Captured(_) => None,
            Self::Refused(refusal) => Some(*refusal),
        }
    }
}

/// The wire-level and observation summary of one captured exchange.
///
/// The shape mirrors the first-party client's completion report: the
/// final attempt's decoded-response status when one completed, its
/// transport failure when it ended below the boundary, the observation
/// error the sink or lifecycle refused — never swallowed — and the
/// lifecycle close itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyCapture {
    /// The lifecycle close: bounded outcome, flush state, and any
    /// observation failure. Teardown can never claim a complete capture
    /// the sink did not acknowledge.
    pub close: LogicalInferenceClose,
    /// How many provider attempts the exchange made.
    pub attempts: u64,
    /// The final attempt's decoded response status, when one completed.
    pub final_status: Option<u16>,
    /// The final attempt's transport failure, when it ended below the
    /// decoded-response boundary.
    pub final_failure: Option<TransportFailure>,
    /// The observation error that was noted during the exchange, when
    /// the observer, protocol, or sink refused an emission.
    pub observation_error: Option<InferenceObserverError>,
    /// Whether the caller received a streamed relay — the exchange
    /// crossed the stream head boundary and its events were relayed as
    /// they arrived.
    pub streamed: bool,
}

/// The result of one served connection: the bounded outcome plus the
/// artifact sink, handed back so the captured records continue through
/// the normal authenticated client path after the exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyExchangeReport<S> {
    outcome: ExchangeOutcome,
    sink: S,
}

impl<S> ProxyExchangeReport<S> {
    /// The outcome the exchange ended with.
    #[must_use]
    pub const fn outcome(&self) -> &ExchangeOutcome {
        &self.outcome
    }

    /// Borrow the artifact sink, for draining captured records in place.
    #[must_use]
    pub const fn sink_ref(&self) -> &S {
        &self.sink
    }

    /// Consume the report and return the artifact sink.
    #[must_use]
    pub fn into_sink(self) -> S {
        self.sink
    }
}

impl<S: fmt::Debug> fmt::Debug for ProxyExchangeReport<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyExchangeReport")
            .field("outcome", &self.outcome)
            .field("sink", &self.sink)
            .finish()
    }
}

/// The proxy's declared route: identity, provider endpoint, and every
/// bound the exchange is held to.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    tenant_id: TenantId,
    origin_client_id: ClientId,
    endpoint: OpenAiEndpoint,
    transport: Http1Transport,
    retry: RetryPolicy,
    max_in_flight: usize,
    max_body_bytes: usize,
}

impl ProxyConfig {
    /// A route that captures for `tenant_id` and `origin_client_id` and
    /// forwards to `endpoint` under the default transport, retry
    /// policy, in-flight budget, and body cap.
    #[must_use]
    pub fn new(tenant_id: TenantId, origin_client_id: ClientId, endpoint: OpenAiEndpoint) -> Self {
        Self {
            tenant_id,
            origin_client_id,
            endpoint,
            transport: Http1Transport::new(),
            retry: RetryPolicy::default(),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Pin the forwarding transport (for explicit timeouts).
    #[must_use]
    pub fn with_transport(mut self, transport: Http1Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Pin the retry schedule the proxy applies on its own provider
    /// attempts.
    #[must_use]
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry = policy;
        self
    }

    /// Pin the in-flight budget: at most `max_in_flight` exchanges are
    /// forwarded at once and excess callers are refused `503` — the
    /// proxy never queues. A zero is treated as one.
    #[must_use]
    pub fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight.max(1);
        self
    }

    /// Pin the decoded-body cap. Declared request bodies over the cap
    /// are refused uncaptured; provider responses over the cap fail the
    /// forwarding attempt below the boundary.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// The declared route path — the only request path served.
    #[must_use]
    pub fn route(&self) -> &str {
        self.endpoint.path()
    }

    /// The provider endpoint the route forwards to.
    #[must_use]
    pub const fn endpoint(&self) -> &OpenAiEndpoint {
        &self.endpoint
    }

    /// The in-flight budget.
    #[must_use]
    pub const fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    /// The decoded-body cap.
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }
}

/// The shared server state behind a clonable proxy handle.
#[derive(Debug)]
struct ProxyInner {
    config: ProxyConfig,
    listener: TcpListener,
    in_flight: AtomicUsize,
}

/// The explicitly routed OpenAI-compatible capture proxy.
///
/// A proxy is bound to an ephemeral loopback port and serves one
/// declared route. It is clonable and thread-safe: every concurrent
/// [`CaptureProxy::serve_one`] call serves one connection against the
/// shared in-flight budget. Serving is blocking, thread-per-connection,
/// standard-library sockets only — the same wire discipline as the
/// first-party transport.
#[derive(Clone, Debug)]
pub struct CaptureProxy {
    inner: Arc<ProxyInner>,
}

impl CaptureProxy {
    /// Bind a proxy for `config` to an ephemeral loopback port. The
    /// route is served from the first [`CaptureProxy::serve_one`] call.
    ///
    /// # Errors
    /// [`std::io::Error`] when the loopback listener cannot be bound.
    pub fn bind(config: ProxyConfig) -> std::io::Result<Self> {
        let listener = TcpListener::bind((LOOPBACK, 0))?;
        Ok(Self {
            inner: Arc::new(ProxyInner {
                config,
                listener,
                in_flight: AtomicUsize::new(0),
            }),
        })
    }

    /// The address the proxy listens on.
    ///
    /// # Panics
    /// Only if the bound listener somehow forgot its own address, which
    /// the operating system's API does not allow.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner
            .listener
            .local_addr()
            .expect("a bound listener knows its address")
    }

    /// The declared route path — the only request path served.
    #[must_use]
    pub fn route(&self) -> &str {
        self.inner.config.route()
    }

    /// The route's configuration.
    #[must_use]
    pub fn config(&self) -> &ProxyConfig {
        &self.inner.config
    }

    /// Accept exactly one connection and serve it to completion,
    /// capturing into `sink`.
    ///
    /// The call blocks until the exchange ends: a refused request
    /// returns as soon as its bounded answer is written; a captured
    /// exchange returns after its final provider attempt and the
    /// lifecycle close. All connection errors inside the exchange are
    /// bounded refusals — the only [`Err`] is the listener itself
    /// failing to accept.
    ///
    /// # Errors
    /// [`std::io::Error`] when the listener cannot accept a
    /// connection.
    ///
    /// # Panics
    /// Only if lifecycle bookkeeping is corrupted: the exchange owns a
    /// fresh observer, so its start and close cannot fail. The exchange
    /// closes exactly the lifecycle it started.
    pub fn serve_one<S: InferenceArtifactSink>(
        &self,
        sink: S,
    ) -> std::io::Result<ProxyExchangeReport<S>> {
        let (stream, _) = self.inner.listener.accept()?;
        Ok(self.serve_connection(stream, sink))
    }

    fn serve_connection<S: InferenceArtifactSink>(
        &self,
        mut stream: TcpStream,
        sink: S,
    ) -> ProxyExchangeReport<S> {
        let _ = stream.set_read_timeout(Some(CALLER_IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(CALLER_IO_TIMEOUT));

        let head = match read_request_head(&mut stream) {
            Ok(head) => head,
            Err(HeadError::Aborted) => {
                // The peer vanished before a parseable head arrived:
                // nothing was captured and nothing can be answered.
                return refused(Refusal::MalformedHead, sink);
            }
            Err(HeadError::Malformed) => {
                answer_refusal(&mut stream, Refusal::MalformedHead);
                return refused(Refusal::MalformedHead, sink);
            }
        };

        let refusal = if head.method != "POST" {
            Some(Refusal::MethodNotAllowed)
        } else if head.path != self.route() {
            Some(Refusal::UnknownRoute)
        } else if head.transfer_encoding {
            Some(Refusal::TransferFramed)
        } else {
            match head.content_length {
                None => Some(Refusal::LengthRequired),
                Some(length) if length > self.inner.config.max_body_bytes as u64 => {
                    Some(Refusal::BodyOversized)
                }
                Some(_) => None,
            }
        };
        if let Some(refusal) = refusal {
            answer_refusal(&mut stream, refusal);
            return refused(refusal, sink);
        }

        // The budget is spent: refuse immediately. The proxy never
        // queues — a queued exchange would grow the capture backlog
        // without bound and delay every caller behind it.
        let Some(guard) = acquire(&self.inner.in_flight, self.inner.config.max_in_flight) else {
            answer_refusal(&mut stream, Refusal::Backpressured);
            return refused(Refusal::Backpressured, sink);
        };

        let length =
            usize::try_from(head.content_length.unwrap_or(0)).map_err(|_| Refusal::BodyOversized);
        let body = match length.and_then(|length| read_body(&mut stream, length)) {
            Ok(body) => body,
            Err(refusal) => {
                answer_refusal(&mut stream, refusal);
                return refused(refusal, sink);
            }
        };

        let (outcome, sink) = capture_exchange(&self.inner.config, &mut stream, body, sink);
        drop(guard);
        report(outcome, sink)
    }
}

fn refused<S>(refusal: Refusal, sink: S) -> ProxyExchangeReport<S> {
    report(ExchangeOutcome::Refused(refusal), sink)
}

fn report<S>(outcome: ExchangeOutcome, sink: S) -> ProxyExchangeReport<S> {
    ProxyExchangeReport { outcome, sink }
}

/// The exchange's capture and forwarding core: drive the observer
/// lifecycle around every provider attempt, relay the response the
/// moment the boundary produces it, and close with the acknowledged or
/// explicitly incomplete flush.
#[allow(clippy::too_many_lines)] // one exchange's full state machine, read top to bottom
fn capture_exchange<S: InferenceArtifactSink>(
    config: &ProxyConfig,
    stream: &mut TcpStream,
    caller_body: Vec<u8>,
    sink: S,
) -> (ExchangeOutcome, S) {
    let mut observer = InferenceObserverV1::new(
        config.tenant_id.clone(),
        config.origin_client_id.clone(),
        sink,
    );
    observer
        .start_logical_inference(now())
        .expect("a fresh observer per exchange starts unconditionally");

    // The provider request is the declared route's request: the
    // caller's decoded body byte-for-byte, with the proxy's own
    // credential rendered into `authorization` — the caller's headers
    // were dropped at the boundary and ride nowhere.
    let provider_request = WireRequest {
        path: config.route().to_owned(),
        headers: vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            (
                "authorization".to_owned(),
                format!("Bearer {}", config.endpoint.credential()),
            ),
        ],
        body: caller_body,
    };

    let max_attempts = u64::from(config.retry.max_attempts.max(1));
    let mut relay = CallerRelay {
        stream,
        live: true,
        streamed: false,
    };
    let mut observation_error: Option<InferenceObserverError> = None;
    let mut pending_retry: Option<(RetryReason, u64)> = None;
    let mut attempts = 0_u64;
    let mut final_status: Option<u16>;
    let mut final_failure: Option<TransportFailure>;

    loop {
        let step = if attempts == 0 {
            observer.start_provider_attempt()
        } else {
            let (reason, backoff_ms) = pending_retry.take().expect("a retry decision is pending");
            rest(backoff_ms);
            observer.start_retry_attempt(reason, Some(backoff_ms), now())
        };
        // A refused attempt transition is an observation failure:
        // noted, never a gate on the forwarding that follows.
        if let Err(error) = step
            && observation_error.is_none()
        {
            observation_error = Some(error);
        }
        attempts += 1;
        final_status = None;
        final_failure = None;

        note(
            &mut observation_error,
            observer.decoded_request_bytes(&provider_request.body, None, now()),
        );

        let response = config.transport.execute(
            config.endpoint.wire(),
            &provider_request,
            config.max_body_bytes,
        );
        match response {
            Err(failure) => {
                final_failure = Some(failure);
                note(
                    &mut observation_error,
                    observer.attempt_outcome(
                        AttemptOutcome::TransportError {
                            error_class: failure.class,
                            timeout_ms: failure.timeout_ms,
                        },
                        now(),
                    ),
                );
                if attempts >= max_attempts {
                    break;
                }
                pending_retry = Some((RetryReason::TransportError, config.retry.backoff_ms));
            }
            Ok(response) => match forward_response(
                config,
                &mut observer,
                &mut relay,
                response,
                attempts,
                max_attempts,
                &mut observation_error,
                &mut final_status,
                &mut final_failure,
            ) {
                Next::Retry(reason, backoff_ms) => {
                    pending_retry = Some((reason, backoff_ms));
                }
                Next::Terminal => break,
            },
        }
    }

    // A provider failure that exhausted the budget below the response
    // boundary is never answered with a fabricated provider response:
    // the caller's connection closes exactly as it would against an
    // unreachable provider.
    if relay.live && !relay.streamed && final_status.is_none() {
        relay.abort();
    }

    let close = observer
        .close_logical_inference()
        .expect("the exchange closes the lifecycle it started");
    let capture = ProxyCapture {
        close,
        attempts,
        final_status,
        final_failure,
        observation_error,
        streamed: relay.streamed,
    };
    (ExchangeOutcome::Captured(capture), observer.into_sink())
}

/// What one forwarded response asks the attempt loop to do next.
enum Next {
    /// Open another provider attempt citing the closed one.
    Retry(RetryReason, u64),
    /// The exchange is over for the caller: the response was relayed,
    /// the relay was truncated mid-stream, or nothing relayable remains.
    Terminal,
}

/// Record one decoded response at the boundary and relay it to the
/// caller. Buffered responses are relayed only when the attempt is
/// terminal — a retryable status is retried while nothing has been sent
/// — while streams are relayed from their first event: once the relay
/// has started, a provider failure is terminal for the caller, because
/// delivered bytes cannot be retracted.
#[allow(clippy::too_many_arguments)] // one forwarded response, assembled in place
#[allow(clippy::too_many_lines)] // one forwarded response's boundary, read top to bottom
fn forward_response<S: InferenceArtifactSink>(
    config: &ProxyConfig,
    observer: &mut InferenceObserverV1<S>,
    relay: &mut CallerRelay<'_>,
    response: WireResponse,
    attempts: u64,
    max_attempts: u64,
    observation_error: &mut Option<InferenceObserverError>,
    final_status: &mut Option<u16>,
    final_failure: &mut Option<TransportFailure>,
) -> Next {
    let status = response.status;
    let retry_after = retry_after_seconds(&response);
    let metadata = response_metadata(status, &response.headers);

    match response.body {
        WireBody::Full(bytes) => {
            note(
                observation_error,
                observer.decoded_response_bytes(&bytes, Some(metadata), now()),
            );
            if let Some(usage) = usage_from_bytes(&bytes) {
                note(
                    observation_error,
                    observer.usage(
                        UsageSource::ResponseBody,
                        None,
                        usage.input_tokens,
                        usage.output_tokens,
                        usage.total_tokens,
                        now(),
                    ),
                );
            }
            note(
                observation_error,
                observer.attempt_outcome(AttemptOutcome::Completed, now()),
            );
            *final_status = Some(status);
            if let Some(reason) = retry_reason(status)
                && attempts < max_attempts
            {
                return Next::Retry(reason, effective_backoff(retry_after, config));
            }
            relay.full(status, &response.headers, &bytes);
            Next::Terminal
        }
        WireBody::Stream(mut events) => {
            relay.stream_head(status, &response.headers);
            relay.streamed = true;
            let mut first_event = true;
            // The usage artifact names its reporting event through the
            // payload member and is recorded once the stream has
            // drained — the same events-then-usage shape the first-party
            // client commits, never an inline record between events.
            let mut stream_usage: Option<(UsageCounters, Vec<u8>)> = None;
            loop {
                match events.next_event() {
                    Ok(Some(event)) => {
                        let event_metadata = if first_event {
                            first_event = false;
                            Some(metadata.clone())
                        } else {
                            None
                        };
                        note(
                            observation_error,
                            observer.decoded_response_event(&event, event_metadata, now()),
                        );
                        relay.event(&event);
                        if let Some(usage) = usage_from_bytes(&event) {
                            stream_usage = Some((usage, event));
                        }
                    }
                    Ok(None) => {
                        if let Some((usage, reporting_bytes)) = stream_usage {
                            note(
                                observation_error,
                                observer.usage(
                                    UsageSource::StreamEvent,
                                    Some(&reporting_bytes),
                                    usage.input_tokens,
                                    usage.output_tokens,
                                    usage.total_tokens,
                                    now(),
                                ),
                            );
                        }
                        note(
                            observation_error,
                            observer.attempt_outcome(AttemptOutcome::Completed, now()),
                        );
                        *final_status = Some(status);
                        relay.finish_stream();
                        return Next::Terminal;
                    }
                    Err(failure) => {
                        // The decoded stream ended abnormally: a
                        // below-boundary failure classified exactly as
                        // the first-party client classifies one.
                        let class = if failure.class == TransportErrorClass::ConnectionReset {
                            TransportErrorClass::StreamInterrupted
                        } else {
                            failure.class
                        };
                        *final_failure = Some(TransportFailure {
                            class,
                            timeout_ms: failure.timeout_ms,
                        });
                        *final_status = None;
                        note(
                            observation_error,
                            observer.attempt_outcome(
                                AttemptOutcome::TransportError {
                                    error_class: class,
                                    timeout_ms: failure.timeout_ms,
                                },
                                now(),
                            ),
                        );
                        // The caller is mid-stream: the truncation is
                        // relayed as it happened, and no retry can
                        // follow — delivered bytes cannot be retracted.
                        relay.abort();
                        return Next::Terminal;
                    }
                }
            }
        }
    }
}

/// Note the first observation failure and keep the exchange running:
/// observation never gates forwarding, but its failure stays visible in
/// the exchange report rather than being swallowed.
fn note(
    observation_error: &mut Option<InferenceObserverError>,
    result: Result<(), InferenceObserverError>,
) {
    if let Err(error) = result
        && observation_error.is_none()
    {
        *observation_error = Some(error);
    }
}

/// The retry decision a decoded status implies, matching the
/// first-party client's policy: rate-limit rejections and server
/// errors retry, everything else is terminal.
fn retry_reason(status: u16) -> Option<RetryReason> {
    if status == 429 {
        Some(RetryReason::RateLimit)
    } else if status >= 500 {
        Some(RetryReason::HttpStatus)
    } else {
        None
    }
}

/// The effective backoff for one retry: the provider's `retry-after`
/// when it supplies a whole-number one, the route's configured backoff
/// otherwise, always under the shared ceiling.
fn effective_backoff(retry_after: Option<u64>, config: &ProxyConfig) -> u64 {
    retry_after
        .unwrap_or(config.retry.backoff_ms)
        .min(MAX_BACKOFF_MS)
}

fn rest(backoff_ms: u64) {
    if backoff_ms > 0 {
        std::thread::sleep(Duration::from_millis(backoff_ms));
    }
}

/// The `retry-after` header as whole seconds, when it is one.
fn retry_after_seconds(response: &WireResponse) -> Option<u64> {
    response
        .header("retry-after")
        .and_then(|value| value.parse::<u64>().ok())
}

/// The caller-facing relay: every byte the caller receives passes
/// through here, and once the caller is gone the relay goes silent —
/// capture of the provider's own bytes continues unaffected.
struct CallerRelay<'a> {
    stream: &'a mut TcpStream,
    live: bool,
    streamed: bool,
}

impl CallerRelay<'_> {
    /// Write one buffer, best-effort: a caller that hung up is noted
    /// and never retried.
    fn send(&mut self, bytes: &[u8]) {
        if !self.live {
            return;
        }
        if self.stream.write_all(bytes).is_err() {
            self.live = false;
        } else {
            let _ = self.stream.flush();
        }
    }

    /// Relay one terminal buffered response: the provider's status and
    /// headers with the framing rewritten for the close-delimited
    /// connection, then the exact decoded body.
    fn full(&mut self, status: u16, headers: &[(String, String)], body: &[u8]) {
        let mut head = String::new();
        head.push_str("HTTP/1.1 ");
        head.push_str(&status.to_string());
        head.push(' ');
        head.push_str(reason_phrase(status));
        head.push_str("\r\n");
        for (name, value) in headers {
            if name == "content-length" || name == "transfer-encoding" {
                continue;
            }
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("content-length: ");
        head.push_str(&body.len().to_string());
        head.push_str("\r\nconnection: close\r\n\r\n");
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(body);
        self.send(&bytes);
    }

    /// Relay a stream response's head the moment it is decoded: the
    /// caller's delivery starts here, before any event has arrived.
    fn stream_head(&mut self, status: u16, headers: &[(String, String)]) {
        let mut head = String::new();
        head.push_str("HTTP/1.1 ");
        head.push_str(&status.to_string());
        head.push(' ');
        head.push_str(reason_phrase(status));
        head.push_str("\r\n");
        for (name, value) in headers {
            if name == "content-length" || name == "transfer-encoding" {
                continue;
            }
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("transfer-encoding: chunked\r\nconnection: close\r\n\r\n");
        self.send(head.as_bytes());
    }

    /// Relay one decoded event as its own chunk, re-framed as valid SSE.
    fn event(&mut self, payload: &[u8]) {
        let frame = reframe_event(payload);
        let chunk = format!("{:x}\r\n", frame.len());
        self.send(chunk.as_bytes());
        self.send(&frame);
        self.send(b"\r\n");
    }

    /// End a drained stream honestly: the terminal chunk tells the
    /// caller the body really was complete.
    fn finish_stream(&mut self) {
        self.send(b"0\r\n\r\n");
    }

    /// End the relay without a completing frame: a truncated provider
    /// stream or a dead provider is a truncated relay, never a fabricated
    /// clean end.
    fn abort(&mut self) {
        self.live = false;
    }
}

/// Re-frame one decoded event's payload as valid SSE: each line of a
/// multi-line payload becomes its own `data:` line, and the blank line
/// dispatches the block. A single-line payload — every OpenAI-compatible
/// JSON event — round-trips exactly.
fn reframe_event(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 8);
    for (index, line) in payload.split(|byte| *byte == b'\n').enumerate() {
        if index > 0 {
            frame.push(b'\n');
        }
        frame.extend_from_slice(b"data: ");
        frame.extend_from_slice(line);
    }
    frame.extend_from_slice(b"\r\n\r\n");
    frame
}

/// The reason phrase for a status the proxy or a forwarded response
/// carries. The first-party transport's head parse does not retain the
/// peer's phrase, so well-known statuses get their canonical phrase and
/// anything else a bounded neutral one — never payload material.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Response",
    }
}

/// Write a refusal's bounded answer. Best-effort: a caller that already
/// hung up simply never reads it.
fn answer_refusal(stream: &mut TcpStream, refusal: Refusal) {
    let body = refusal.body_text();
    let mut head = String::new();
    head.push_str("HTTP/1.1 ");
    head.push_str(&refusal.status().to_string());
    head.push(' ');
    head.push_str(refusal.reason());
    head.push_str("\r\ncontent-type: application/json\r\ncontent-length: ");
    head.push_str(&body.len().to_string());
    head.push_str("\r\nconnection: close\r\n\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

/// Why a request head could not be served. `Aborted` means the socket
/// died or went silent mid-read — nothing reliable can be answered;
/// `Malformed` means the peer sent bytes that are not a bounded
/// HTTP/1.1 head and deserves the explicit `400`.
#[derive(Debug)]
enum HeadError {
    Aborted,
    Malformed,
}

/// One parsed caller request head.
struct RequestHead {
    method: String,
    path: String,
    transfer_encoding: bool,
    /// The declared body length, `None` when the head carries no valid,
    /// self-consistent `content-length` (missing, unparseable, or
    /// disagreeing duplicates — a smuggling shape the proxy refuses).
    content_length: Option<u64>,
}

fn read_request_head(stream: &mut TcpStream) -> Result<RequestHead, HeadError> {
    let mut head_bytes = 0_usize;
    let mut request_line: Option<(String, String)> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut line = Vec::new();
        let aborted = read_line_bounded(stream, &mut line).is_err();
        if aborted && request_line.is_none() && line.is_empty() {
            return Err(HeadError::Aborted);
        }
        if aborted {
            // Bytes arrived but the head never completed: the peer is
            // gone or went silent mid-head.
            return Err(HeadError::Aborted);
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        head_bytes += line.len();
        if head_bytes > REQUEST_HEAD_MAX_BYTES {
            return Err(HeadError::Malformed);
        }
        if request_line.is_none() {
            request_line = Some(parse_request_line(&line).ok_or(HeadError::Malformed)?);
        } else {
            headers.push(parse_header_line(&line).ok_or(HeadError::Malformed)?);
        }
    }
    let request_line = request_line.ok_or(HeadError::Malformed)?;

    let transfer_encoding = headers.iter().any(|(name, _)| name == "transfer-encoding");
    let declared: Vec<u64> = headers
        .iter()
        .filter(|(name, _)| name == "content-length")
        .map(|(_, value)| value)
        .map(|value| value.parse::<u64>())
        .collect::<Result<_, _>>()
        .map_err(|_| HeadError::Malformed)?;
    let content_length = match declared.as_slice() {
        [only] => Some(*only),
        [first, rest @ ..] if rest.iter().all(|length| length == first) => Some(*first),
        // Disagreeing duplicates are a smuggling shape: no valid,
        // self-consistent length, so the request is refused below.
        _ => None,
    };
    Ok(RequestHead {
        method: request_line.0,
        path: request_line.1,
        transfer_encoding,
        content_length,
    })
}

/// Parse the request line into `(method, target)`. Anything that is not
/// a three-token `POST <path> HTTP/1.x` line is malformed — the proxy
/// routes nothing else.
fn parse_request_line(line: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(line).ok()?;
    let text = text.trim_end_matches(['\r', '\n']);
    let mut tokens = text.split_whitespace();
    let method = tokens.next()?.to_owned();
    let path = tokens.next()?.to_owned();
    let version = tokens.next()?;
    if !version.starts_with("HTTP/") || tokens.next().is_some() {
        return None;
    }
    Some((method, path))
}

/// Parse one header line into its lowercase name and trimmed value.
fn parse_header_line(line: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(line).ok()?;
    let text = text.trim_end_matches(['\r', '\n']);
    let (name, value) = text.split_once(':')?;
    Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
}

/// Read one CRLF-terminated line, bounded. Any I/O end — EOF, reset, or
/// the caller deadline — aborts the head.
fn read_line_bounded(stream: &mut TcpStream, line: &mut Vec<u8>) -> Result<(), ()> {
    line.clear();
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte) {
            // Every I/O end — EOF, reset, or the caller deadline —
            // aborts the head.
            Ok(0) | Err(_) => return Err(()),
            Ok(_) => {
                line.push(byte[0]);
                if line.len() > HEAD_LINE_MAX_BYTES {
                    return Err(());
                }
                if byte[0] == b'\n' {
                    return Ok(());
                }
            }
        }
    }
}

/// Read exactly `length` body bytes; a body that ends early is the
/// explicit `incomplete-body` refusal, never a truncated capture.
fn read_body(stream: &mut TcpStream, length: usize) -> Result<Vec<u8>, Refusal> {
    let mut body = vec![0_u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|_| Refusal::IncompleteBody)?;
    Ok(body)
}

/// The in-flight budget's guard: acquired before a body is read,
/// released when the exchange ends — however it ends.
struct InFlightGuard<'a> {
    counter: &'a AtomicUsize,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Take one in-flight slot, or `None` when the budget is spent. The
/// compare-and-exchange loop makes the bound hold under concurrent
/// callers without locking.
fn acquire(counter: &AtomicUsize, max: usize) -> Option<InFlightGuard<'_>> {
    loop {
        let current = counter.load(Ordering::Acquire);
        if current >= max {
            return None;
        }
        if counter
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(InFlightGuard { counter });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    use super::*;
    use archivist_protocol::derivation::blob_digest;

    use crate::inference_observer::{LogicalInferenceOutcome, RecordingArtifactSink};

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const ORIGIN: &str = "2b6a5f10-4c1e-4a7e-9d0a-5f3b8c1e2d40";

    fn head_from(raw: &[u8]) -> Result<RequestHead, HeadError> {
        let mut stream = pipe_over(raw);
        read_request_head(&mut stream)
    }

    /// Serve `raw` through a real socket pair so the head reader runs
    /// against a `TcpStream` exactly as it does in production.
    fn pipe_over(raw: &[u8]) -> TcpStream {
        let listener = TcpListener::bind((LOOPBACK, 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut client = TcpStream::connect(addr).expect("connect");
        let (stream, _) = listener.accept().expect("accept");
        client.write_all(raw).expect("write");
        stream
    }

    /// A route bound to a one-shot provider at `addr`, under the given
    /// planted credential, with a bounded transport and no retry sleep.
    fn config_to(addr: SocketAddr, credential: &str) -> ProxyConfig {
        let endpoint =
            OpenAiEndpoint::new(addr.ip().to_string(), addr.port(), credential.to_owned())
                .expect("a loopback endpoint");
        ProxyConfig::new(
            TenantId::parse(TENANT).expect("valid tenant grammar"),
            ClientId::parse(ORIGIN).expect("valid client grammar"),
            endpoint,
        )
        .with_transport(Http1Transport::with_timeouts(
            Duration::from_secs(2),
            Duration::from_secs(5),
        ))
        .with_retry_policy(RetryPolicy {
            max_attempts: 2,
            backoff_ms: 0,
        })
    }

    /// What the provider received from the proxy.
    struct ForwardedRequest {
        raw_head: Vec<u8>,
        body: Vec<u8>,
    }

    /// Read the forwarded request head off the provider socket.
    fn read_until_head_end(stream: &mut TcpStream) -> Vec<u8> {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            match stream.read(&mut byte) {
                Ok(0) | Err(_) => return head,
                Ok(_) => {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") || head.len() > REQUEST_HEAD_MAX_BYTES {
                        return head;
                    }
                }
            }
        }
    }

    /// The forwarded head's declared body length.
    fn declared_length(head: &[u8]) -> Option<usize> {
        let text = std::str::from_utf8(head).ok()?;
        text.split("\r\n").find_map(|line| {
            line.strip_prefix("content-length:")?
                .trim()
                .parse::<usize>()
                .ok()
        })
    }

    /// A one-shot provider: answers the proxy's forwarded request with
    /// `response` and reports what it received over the channel.
    fn spawn_provider(
        response: Vec<u8>,
    ) -> (SocketAddr, std::sync::mpsc::Receiver<ForwardedRequest>) {
        let listener = TcpListener::bind((LOOPBACK, 0)).expect("provider binds");
        let addr = listener.local_addr().expect("provider address");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("provider accepts");
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let raw_head = read_until_head_end(&mut stream);
            let length = declared_length(&raw_head).unwrap_or(0);
            let mut body = vec![0_u8; length];
            let _ = stream.read_exact(&mut body);
            let _ = tx.send(ForwardedRequest { raw_head, body });
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            // Hold the socket briefly so the response delivers before
            // the close the close-delimited transport expects.
            std::thread::sleep(Duration::from_millis(50));
        });
        (addr, rx)
    }

    #[test]
    fn a_bounded_head_parses_to_its_route_facts() {
        let head = head_from(
            b"POST /v1/chat/completions HTTP/1.1\r\nhost: harness\r\ncontent-type: application/json\r\ncontent-length: 5\r\n\r\n",
        )
        .expect("valid head");
        assert_eq!(head.method, "POST");
        assert_eq!(head.path, "/v1/chat/completions");
        assert!(!head.transfer_encoding);
        assert_eq!(head.content_length, Some(5));
    }

    #[test]
    fn framing_facts_are_read_from_the_head() {
        let head =
            head_from(b"POST /v1/chat/completions HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n")
                .expect("head with transfer encoding");
        assert!(head.transfer_encoding);
        assert_eq!(head.content_length, None);

        // Disagreeing content-length duplicates are a smuggling shape:
        // refused as no valid length at all.
        let head = head_from(
            b"POST /v1/chat/completions HTTP/1.1\r\ncontent-length: 5\r\ncontent-length: 7\r\n\r\n",
        )
        .expect("head parses");
        assert_eq!(head.content_length, None);

        // Unparseable lengths are refused, never guessed.
        assert!(
            head_from(b"POST /v1/chat/completions HTTP/1.1\r\ncontent-length: many\r\n\r\n")
                .is_err()
        );
    }

    #[test]
    fn malformed_request_lines_are_refused() {
        assert!(head_from(b"BOGUS\r\n\r\n").is_err());
        assert!(head_from(b"POST /path HTTP/1.1 extra\r\n\r\n").is_err());
        assert!(head_from(b"POST /path\r\n\r\n").is_err());
        assert!(head_from(b"POST /path NOTHTTP/1.1\r\n\r\n").is_err());
        // A header line without a colon has no place in a bounded head.
        assert!(head_from(b"POST /p HTTP/1.1\r\nhostless\r\n\r\n").is_err());
    }

    #[test]
    fn refusal_statuses_are_the_bounded_contract() {
        assert_eq!(Refusal::MalformedHead.status(), 400);
        assert_eq!(Refusal::UnknownRoute.status(), 404);
        assert_eq!(Refusal::MethodNotAllowed.status(), 405);
        assert_eq!(Refusal::TransferFramed.status(), 411);
        assert_eq!(Refusal::LengthRequired.status(), 411);
        assert_eq!(Refusal::BodyOversized.status(), 413);
        assert_eq!(Refusal::Backpressured.status(), 503);
        // Every refusal answers with a content-free fixed body and a
        // distinct evidence token.
        let mut tokens = [
            Refusal::MalformedHead,
            Refusal::MethodNotAllowed,
            Refusal::UnknownRoute,
            Refusal::TransferFramed,
            Refusal::LengthRequired,
            Refusal::BodyOversized,
            Refusal::IncompleteBody,
            Refusal::Backpressured,
        ]
        .map(Refusal::token)
        .to_vec();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), 8);
        for refusal in [
            Refusal::MalformedHead,
            Refusal::MethodNotAllowed,
            Refusal::UnknownRoute,
            Refusal::TransferFramed,
            Refusal::LengthRequired,
            Refusal::BodyOversized,
            Refusal::IncompleteBody,
            Refusal::Backpressured,
        ] {
            assert!(refusal.body_text().contains("\"error\""));
            assert!(!refusal.body_text().contains("Bearer"));
        }
    }

    #[test]
    fn sse_reframing_round_trips_openai_events() {
        let frame = reframe_event(br#"{"id":"s-1","choices":[]}"#);
        assert_eq!(frame, b"data: {\"id\":\"s-1\",\"choices\":[]}\r\n\r\n");
        // A multi-line payload re-frames as one `data:` line per line.
        let frame = reframe_event(b"alpha\nbeta");
        assert_eq!(frame, b"data: alpha\ndata: beta\r\n\r\n");
    }

    #[test]
    fn reason_phrases_are_bounded_and_never_payload() {
        assert_eq!(reason_phrase(200), "OK");
        assert_eq!(reason_phrase(429), "Too Many Requests");
        assert_eq!(reason_phrase(599), "Response");
    }

    #[test]
    fn the_in_flight_bound_holds_under_contention() {
        let counter = AtomicUsize::new(0);
        let guards: Vec<_> = (0..4).filter_map(|_| acquire(&counter, 4)).collect();
        assert_eq!(guards.len(), 4);
        assert!(acquire(&counter, 4).is_none());
        drop(guards);
        assert_eq!(counter.load(Ordering::Acquire), 0);
        assert!(acquire(&counter, 4).is_some());
    }

    #[test]
    fn retry_decisions_match_the_first_party_policy() {
        assert_eq!(retry_reason(200), None);
        assert_eq!(retry_reason(404), None);
        assert_eq!(retry_reason(429), Some(RetryReason::RateLimit));
        assert_eq!(retry_reason(500), Some(RetryReason::HttpStatus));
        assert_eq!(retry_reason(503), Some(RetryReason::HttpStatus));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one planted-credential sweep, read top to bottom
    fn a_planted_credential_never_reaches_an_artifact() {
        const PROVIDER_CREDENTIAL: &str = "sk-proxy-planted-3f9c1a7d-secret";
        const CALLER_AUTHORIZATION: &str = "sk-caller-planted-8fd2a6e1-secret";
        const CALLER_COOKIE: &str = "caller-cookie-planted-4b9e2c-secret";
        const PROVIDER_SET_COOKIE: &str = "provider-set-cookie-planted-7a3f9b-secret";

        let body =
            br#"{"model":"capture-model","messages":[{"role":"user","content":"capture me"}]}"#;
        let response_body = br#"{"id":"c-1","object":"chat.completion","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#;
        let mut response = String::new();
        response.push_str("HTTP/1.1 200 OK\r\n");
        response.push_str("content-type: application/json\r\n");
        response.push_str("x-request-id: req-planted-1\r\n");
        response.push_str("set-cookie: ");
        response.push_str(PROVIDER_SET_COOKIE);
        response.push_str("=1\r\n");
        response.push_str("content-length: ");
        response.push_str(&response_body.len().to_string());
        response.push_str("\r\n\r\n");
        let mut response = response.into_bytes();
        response.extend_from_slice(response_body);

        let (addr, received) = spawn_provider(response);
        let proxy = CaptureProxy::bind(config_to(addr, PROVIDER_CREDENTIAL)).expect("binds");
        let expected_request_digest = blob_digest(body);

        // The caller carries its own credentials — the harness's
        // provider key and session cookie. They name the caller, not
        // the route, and the boundary drops both.
        let mut request = format!(
            "POST {} HTTP/1.1\r\nhost: harness\r\nauthorization: Bearer {CALLER_AUTHORIZATION}\r\ncookie: session={CALLER_COOKIE}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            proxy.route(),
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);

        let (relayed, report) = std::thread::scope(|scope| {
            let mut caller = TcpStream::connect(proxy.local_addr()).expect("caller connects");
            let _ = caller.set_read_timeout(Some(Duration::from_secs(10)));
            let serve = scope.spawn(move || {
                proxy
                    .serve_one(RecordingArtifactSink::new())
                    .expect("serves")
            });
            caller.write_all(&request).expect("caller writes");
            let mut relayed = Vec::new();
            let _ = caller.read_to_end(&mut relayed);
            let report = serve.join().expect("serve_one joins");
            (relayed, report)
        });

        // The exchange was captured and reported complete.
        let ExchangeOutcome::Captured(capture) = report.outcome() else {
            panic!("the routed exchange is captured, not refused");
        };
        assert_eq!(capture.final_status, Some(200));
        assert_eq!(capture.attempts, 1);
        assert!(capture.observation_error.is_none());
        assert_eq!(capture.close.outcome, LogicalInferenceOutcome::Complete);

        // The provider received the route's own credential on the wire
        // — and none of the caller's header material.
        let forwarded = received
            .recv_timeout(Duration::from_secs(5))
            .expect("the provider saw the forwarded exchange");
        let head_text = std::str::from_utf8(&forwarded.raw_head).expect("an ascii head");
        assert!(
            head_text.contains(&format!("authorization: Bearer {PROVIDER_CREDENTIAL}")),
            "the route's own credential rides the provider wire"
        );
        assert!(
            !head_text.contains(CALLER_AUTHORIZATION),
            "the caller's credential was dropped"
        );
        assert!(
            !head_text.contains("cookie"),
            "the caller's cookie was dropped"
        );
        assert_eq!(forwarded.body, body);

        // The relay was faithful: the provider's status line and the
        // exact decoded body reached the caller.
        assert!(relayed.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(relayed.ends_with(response_body));

        // No planted credential appears in any captured artifact or
        // its metadata — not the route's provider credential, not the
        // caller's authorization or cookie, not the provider's
        // set-cookie.
        let sink = report.into_sink();
        let artifacts = sink.artifacts();
        assert!(!artifacts.is_empty(), "the exchange was captured");
        let secrets = [
            PROVIDER_CREDENTIAL,
            CALLER_AUTHORIZATION,
            CALLER_COOKIE,
            PROVIDER_SET_COOKIE,
        ];
        for artifact in artifacts {
            let canonical =
                std::str::from_utf8(artifact.canonical_bytes()).expect("canonical json");
            let debug = format!("{:?}", artifact.artifact());
            for secret in secrets {
                assert!(
                    !canonical.contains(secret),
                    "a planted credential reached a captured artifact"
                );
                assert!(
                    !debug.contains(secret),
                    "a planted credential reached a captured record"
                );
            }
        }

        // The request itself was captured exactly as routed: an
        // artifact whose payload digests the caller's body bytes.
        let request_artifact = artifacts.iter().find(|artifact| {
            artifact
                .artifact()
                .payload
                .as_ref()
                .is_some_and(|payload| payload.payload_digest == expected_request_digest)
        });
        assert!(
            request_artifact.is_some(),
            "the routed request body was captured"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one backpressure scenario, read top to bottom
    fn a_slow_caller_cannot_grow_the_relay_past_its_declared_bound() {
        // The streamed route declares its own body cap — large enough
        // for the long stream the scenario needs — and one event stays
        // far below it.
        // The provider's progress is therefore the observable of the
        // relay's bound: when the silent caller's socket fills, the
        // relay's write blocks, the proxy stops reading, and the
        // provider itself stalls — backpressure reached it, because the
        // relay never buffered the stream.
        const EVENT_COUNT: usize = 256;
        const STREAM_BODY_CAP: usize = 256 * 1024 * 1024;
        let payload = vec![b'a'; 256 * 1024 - 16];
        let mut frame = b"data: ".to_vec();
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(b"\r\n\r\n");
        assert!(
            frame.len() <= STREAM_BODY_CAP,
            "one relayed event fits the route's declared relay bound"
        );
        let mut chunk = format!("{:x}\r\n", frame.len()).into_bytes();
        chunk.extend_from_slice(&frame);
        chunk.extend_from_slice(b"\r\n");
        let chunk_len = chunk.len();

        let head =
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n";
        let terminal: &[u8] = b"0\r\n\r\n";

        let listener = TcpListener::bind((LOOPBACK, 0)).expect("provider binds");
        let provider_addr = listener.local_addr().expect("provider address");
        let written = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicBool::new(false));
        let writer = {
            let written = Arc::clone(&written);
            let finished = Arc::clone(&finished);
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("provider accepts");
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                let head_end = read_until_head_end(&mut stream);
                let length = declared_length(&head_end).unwrap_or(0);
                let mut body = vec![0_u8; length];
                let _ = stream.read_exact(&mut body);

                // Push every byte through the stalled socket, retrying
                // would-block writes until the deadline, and count the
                // event bytes that made it.
                let deadline = Instant::now() + Duration::from_secs(20);
                let mut push = |mut bytes: &[u8], per_event: bool, written: &AtomicUsize| -> bool {
                    while !bytes.is_empty() {
                        if Instant::now() > deadline {
                            return false;
                        }
                        match stream.write(bytes) {
                            Ok(0) => return false,
                            Ok(count) => {
                                bytes = &bytes[count..];
                                if per_event {
                                    written.fetch_add(count, Ordering::Relaxed);
                                }
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    ErrorKind::WouldBlock | ErrorKind::TimedOut
                                ) =>
                            {
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            Err(_) => return false,
                        }
                    }
                    true
                };
                if !push(head, false, &written) {
                    return;
                }
                for _ in 0..EVENT_COUNT {
                    if !push(&chunk, true, &written) {
                        return;
                    }
                }
                push(terminal, false, &written);
                finished.store(true, Ordering::Relaxed);
            })
        };

        let proxy = CaptureProxy::bind(
            config_to(provider_addr, "sk-proxy-stream-credential-not-planted")
                .with_max_body_bytes(STREAM_BODY_CAP),
        )
        .expect("binds");
        assert!(
            frame.len() <= proxy.config().max_body_bytes(),
            "one relayed event fits the route's declared relay bound"
        );
        let proxy_addr = proxy.local_addr();
        let request = format!(
            "POST {} HTTP/1.1\r\nhost: harness\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            proxy.route(),
            caller_body().len()
        );

        let (report_tx, report_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let _ = report_tx.send(
                proxy
                    .serve_one(RecordingArtifactSink::new())
                    .expect("serves"),
            );
        });

        let mut caller = TcpStream::connect(proxy_addr).expect("caller connects");
        let _ = caller.set_write_timeout(Some(Duration::from_secs(10)));
        caller.write_all(request.as_bytes()).expect("caller writes");
        caller
            .write_all(&caller_body())
            .expect("caller writes body");

        // Phase A: the caller says nothing. The provider may stream,
        // but its progress must stall — the relay holds at most one
        // event, so backpressure reaches the provider instead of the
        // relay growing.
        let mut last = 0_usize;
        let mut stalled_since: Option<Instant> = None;
        let mut stalled = false;
        let phase_a = Instant::now();
        while !finished.load(Ordering::Relaxed) {
            if phase_a.elapsed() > Duration::from_secs(20) {
                break;
            }
            let progress = written.load(Ordering::Relaxed);
            if progress != last {
                last = progress;
                stalled_since = None;
            } else if let Some(since) = stalled_since {
                if since.elapsed() > Duration::from_millis(800) {
                    stalled = true;
                    break;
                }
            } else {
                stalled_since = Some(Instant::now());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            stalled,
            "the provider stalled while the caller read nothing: the relay does not buffer the stream"
        );

        // Phase B: the caller reads; the relay resumes and the
        // exchange completes — the stall was backpressure, not a wedge.
        let _ = caller.set_read_timeout(Some(Duration::from_secs(30)));
        let mut relayed = Vec::new();
        let _ = caller.read_to_end(&mut relayed);

        server.join().expect("serve_one joins");
        writer.join().expect("the provider joins");

        assert!(
            finished.load(Ordering::Relaxed),
            "the provider completed every event once the caller drained"
        );
        assert_eq!(
            written.load(Ordering::Relaxed),
            EVENT_COUNT * chunk_len,
            "every streamed byte passed through the relay"
        );

        let report = report_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("serve_one reported");
        let ExchangeOutcome::Captured(capture) = report.outcome() else {
            panic!("the streamed exchange is captured, not refused");
        };
        assert!(capture.streamed, "the exchange crossed the stream boundary");
        assert_eq!(capture.final_status, Some(200));
        assert!(capture.observation_error.is_none());
        assert_eq!(capture.close.outcome, LogicalInferenceOutcome::Complete);

        // The caller received the whole relayed stream, terminated
        // honestly.
        assert!(relayed.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(
            relayed.ends_with(terminal),
            "the relay's terminal chunk ended the stream"
        );
        assert!(
            relayed.len() >= EVENT_COUNT * chunk_len,
            "the caller received every relayed event"
        );
    }

    /// The streamed route's request body.
    fn caller_body() -> Vec<u8> {
        br#"{"model":"capture-model","messages":[{"role":"user","content":"stream"}],"stream":true}"#
            .to_vec()
    }
}
