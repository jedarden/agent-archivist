// SPDX-License-Identifier: Apache-2.0

//! The provider-attempt reconstruction conformance suite (plan Phase 9,
//! the reconstruction exit gate): synthetic exchanges drive the two
//! supported capture routes — the SDK hook ([`InferenceObserverV1`]) and
//! the explicitly routed OpenAI-compatible capture proxy
//! ([`CaptureProxy`], the drop-in replacement route for existing
//! clients) — and every emitted artifact set is folded back through the
//! protocol's read-side `reconstruct_inference`.
//!
//! The dimensions, one or more tests each:
//!
//! - **streaming order** — a decoded stream's events reconstruct in
//!   dense ordinal order regardless of the order the artifacts are
//!   supplied to the fold;
//! - **retry separation** — a retried exchange is two attempts with two
//!   identities and one successor-stamped citation, never one merged
//!   exchange;
//! - **lost response** — a request whose response never arrived stays a
//!   truncated first-class attempt, not silence and never a fabricated
//!   response;
//! - **partial output** — every prefix of an abandoned stream
//!   reconstructs as one partial attempt retaining exactly that prefix;
//! - **transport error** — a below-the-boundary failure is one
//!   classified attempt, separated from the retry that follows it;
//! - **proxy replacement** — the same guarantees hold for attempts
//!   captured through the replacement proxy route, and its evidence
//!   never merges with the hook route's;
//! - **hook failure** — a capture that fails mid-exchange or flushes
//!   without acknowledgement keeps its landed evidence partial and its
//!   teardown claim explicit; and
//! - **semantic/exact divergence** — semantic session coverage and
//!   exact inference coverage describe the same sessions in two
//!   vocabularies that never merge in either direction: a semantic
//!   transcript implies nothing exact, and the exact buckets stay
//!   separately counted.
//!
//! The acceptance sentence every test holds: *every provider attempt
//! reconstructs in order and no two attempts — or coverage dimensions —
//! are merged.*  [`assert_separate_ordered_attempts`] is that sentence
//! as a check: dense ordinals from zero, one identity per ordinal,
//! every artifact grouped under exactly its own attempt, and no fold
//! anomalies.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use archivist_adapter_sdk::capture_alignment::align_attempts;
use archivist_adapter_sdk::expected_inference::{
    ExactOutcome, ExpectedInferenceLedger, ExpectedInferenceRecord, InferenceIdentity,
    IntegrationFailure, RouteCoverage, RoutePolicy,
};
use archivist_adapter_sdk::inference_observer::{
    AttemptOutcome, CanonicalArtifact, FlushState, InferenceArtifactSink, InferenceObserver,
    InferenceObserverError, InferenceObserverV1, LogicalInferenceOutcome, ObserverFailure,
    SinkFailure,
};
use archivist_adapter_sdk::openai_compat::{OpenAiEndpoint, RetryPolicy};
use archivist_adapter_sdk::openai_conformance::ConformanceSink;
use archivist_adapter_sdk::openai_http1::Http1Transport;
use archivist_adapter_sdk::openai_proxy::{
    CaptureProxy, ProxyConfig, ProxyExchangeReport, Refusal,
};
use archivist_adapter_sdk::status::{CoverageCounts, CoverageState};
use archivist_protocol::attempt_reconstruction::{
    AttemptReconstruction, AttemptTerminalState, InferenceReconstruction, ReconstructionError,
    reconstruct_inference,
};
use archivist_protocol::derivation::blob_digest;
use archivist_protocol::inference_artifact::InferenceArtifact;
use archivist_protocol::vocabulary::{
    ClientId, InferenceRequestId, OpaqueId, RetryReason, TenantId, Timestamp, TraceId,
    TransportErrorClass, UsageSource,
};

const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
const ORIGIN: &str = "aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f";
const TIME: &str = "2026-09-25T10:00:00Z";
const CREDENTIAL: &str = "reconstruction-credential-not-a-secret";

// ---------------------------------------------------------------------
// The hook-route harness
// ---------------------------------------------------------------------

fn tenant() -> TenantId {
    TenantId::parse(TENANT).expect("tenant")
}

fn origin() -> ClientId {
    ClientId::parse(ORIGIN).expect("origin")
}

fn time() -> Timestamp {
    Timestamp::parse(TIME).expect("timestamp")
}

/// A fresh hook-route observer over the conformance recording sink.
fn hook_observer() -> InferenceObserverV1<ConformanceSink> {
    InferenceObserverV1::new(tenant(), origin(), ConformanceSink::new())
}

/// The typed artifacts a sink accepted, in emission order.
fn artifacts_of(sink: &ConformanceSink) -> Vec<InferenceArtifact> {
    sink.artifacts()
        .iter()
        .map(|item| item.artifact().clone())
        .collect()
}

/// The acceptance sentence as one check: clean fold, dense ordinals
/// from zero in order, one identity per attempt, and every artifact
/// grouped under exactly the attempt that observed it.  Two attempts
/// that shared an ordinal, an identity, or each other's artifacts
/// cannot pass through here.
fn assert_separate_ordered_attempts(
    reconstruction: &InferenceReconstruction,
) -> &[AttemptReconstruction] {
    assert!(
        reconstruction.is_clean(),
        "fold anomalies: {:?}",
        reconstruction.anomalies()
    );
    let attempts = reconstruction.attempts();
    for (index, attempt) in attempts.iter().enumerate() {
        let ordinal = u64::try_from(index).expect("small index");
        assert_eq!(
            attempt.attempt_ordinal(),
            ordinal,
            "attempt at position {index} is not the dense ordinal"
        );
        for artifact in attempt.artifacts() {
            assert_eq!(
                artifact.attempt_ordinal, ordinal,
                "artifact left its attempt"
            );
            assert_eq!(
                artifact.provider_attempt_id,
                *attempt.provider_attempt_id(),
                "artifact crossed an attempt identity"
            );
        }
    }
    for (index, attempt) in attempts.iter().enumerate() {
        for other in &attempts[index + 1..] {
            assert_ne!(
                attempt.provider_attempt_id(),
                other.provider_attempt_id(),
                "two attempts share one provider identity"
            );
        }
    }
    attempts
}

/// One plain hook exchange: request, response, usage, completed.
fn single_hook_exchange() -> (InferenceIdentity, Vec<InferenceArtifact>) {
    let mut observer = hook_observer();
    let start = observer
        .start_logical_inference(Some(time()))
        .expect("start");
    observer.start_provider_attempt().expect("attempt");
    observer
        .decoded_request_bytes(b"single-request", None, Some(time()))
        .expect("request");
    observer
        .decoded_response_bytes(b"single-response", None, Some(time()))
        .expect("response");
    observer
        .usage(UsageSource::ResponseBody, None, 3, 5, 8, Some(time()))
        .expect("usage");
    observer
        .attempt_outcome(AttemptOutcome::Completed, Some(time()))
        .expect("completed");
    observer.close_logical_inference().expect("close");
    let identity = InferenceIdentity::new(
        start.trace_id().clone(),
        start.inference_request_id().clone(),
    );
    (identity, artifacts_of(&observer.into_sink()))
}

/// A retried hook exchange: a decoded rate-limit response, one retry
/// transition, then a successful second attempt with usage.
fn retried_hook_exchange() -> (InferenceIdentity, Vec<InferenceArtifact>) {
    let mut observer = hook_observer();
    let start = observer
        .start_logical_inference(Some(time()))
        .expect("start");
    observer.start_provider_attempt().expect("first attempt");
    observer
        .decoded_request_bytes(b"first-request", None, Some(time()))
        .expect("request");
    observer
        .decoded_response_bytes(b"rate-limited-body", None, Some(time()))
        .expect("429 response");
    observer
        .attempt_outcome(AttemptOutcome::Completed, Some(time()))
        .expect("decoded response completed");
    let second = observer
        .start_retry_attempt(RetryReason::RateLimit, Some(120), Some(time()))
        .expect("retry");
    assert_eq!(second.attempt_ordinal(), 1);
    observer
        .decoded_request_bytes(b"second-request", None, Some(time()))
        .expect("request");
    observer
        .decoded_response_bytes(b"success-body", None, Some(time()))
        .expect("response");
    observer
        .usage(UsageSource::ResponseBody, None, 3, 5, 8, Some(time()))
        .expect("usage");
    observer
        .attempt_outcome(AttemptOutcome::Completed, Some(time()))
        .expect("completed");
    observer.close_logical_inference().expect("close");
    let identity = InferenceIdentity::new(
        start.trace_id().clone(),
        start.inference_request_id().clone(),
    );
    (identity, artifacts_of(&observer.into_sink()))
}

// ---------------------------------------------------------------------
// The proxy-route harness
// ---------------------------------------------------------------------

/// One scripted provider connection.
enum ProviderScript {
    /// Write these complete HTTP/1.1 response bytes, then close.
    Respond(Vec<u8>),
}

/// The shared state between a scripted provider and its server thread.
struct Shared {
    scripts: Mutex<VecDeque<ProviderScript>>,
    bodies: Mutex<Vec<Vec<u8>>>,
}

/// A real loopback TCP provider, scripted one connection at a time: the
/// replacement route's own transport connects here exactly as it would
/// connect to a provider.
struct ScriptedProvider {
    addr: SocketAddr,
    listener: Option<TcpListener>,
    shared: Arc<Shared>,
}

impl ScriptedProvider {
    /// Bind a listener on an ephemeral loopback port.
    fn bind() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let addr = listener.local_addr().expect("local address");
        Self {
            addr,
            listener: Some(listener),
            shared: Arc::new(Shared {
                scripts: Mutex::new(VecDeque::new()),
                bodies: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Queue the next connection's script; the server thread starts with
    /// the first script so it cannot race setup and drop the exchange.
    fn queue(&mut self, script: ProviderScript) {
        self.shared
            .scripts
            .lock()
            .expect("script lock")
            .push_back(script);
        if let Some(listener) = self.listener.take() {
            let shared = Arc::clone(&self.shared);
            std::thread::spawn(move || serve(&listener, &shared));
        }
    }

    /// The port the proxy's forwarding transport connects to.
    fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The decoded request bodies the provider received, in order.
    fn bodies(&self) -> Vec<Vec<u8>> {
        self.shared.bodies.lock().expect("body lock").clone()
    }
}

/// Serve queued scripts until the queue drains: each accepted
/// connection reads one full request, records its body, and answers
/// with its script's response bytes.
fn serve(listener: &TcpListener, shared: &Shared) {
    loop {
        let Some(script) = shared.scripts.lock().expect("script lock").pop_front() else {
            return;
        };
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let raw = read_request(&mut stream);
        let body = split_request_body(&raw).to_vec();
        shared.bodies.lock().expect("body lock").push(body);
        match script {
            ProviderScript::Respond(bytes) => {
                let _ = stream.write_all(&bytes);
                let _ = stream.shutdown(Shutdown::Write);
                // Hold the read side open until the proxy hangs up, so
                // the response delivery stays orderly end to end.
                let _ = stream.read(&mut [0_u8; 16]);
            }
        }
    }
}

/// Read one full HTTP/1.1 request: head to the blank line, then
/// `content-length` body bytes.
fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return raw,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
    let content_length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while raw.len() < head_end + content_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
        }
    }
    raw
}

/// Split a raw request into head and body at the blank line.
fn split_request_body(raw: &[u8]) -> &[u8] {
    match raw.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(position) => &raw[position + 4..],
        None => &[],
    }
}

/// One complete HTTP/1.1 response with `content-length` framing.
fn raw_response(status: u16, reason: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut head = String::new();
    let _ = std::fmt::Write::write_fmt(&mut head, format_args!("HTTP/1.1 {status} {reason}\r\n"));
    for (name, value) in headers {
        let _ = std::fmt::Write::write_fmt(&mut head, format_args!("{name}: {value}\r\n"));
    }
    let _ = std::fmt::Write::write_fmt(
        &mut head,
        format_args!("content-length: {}\r\n\r\n", body.len()),
    );
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
fn chunked_sse(headers: &[(&str, &str)], frames: &[Vec<u8>]) -> Vec<u8> {
    let mut head = String::from("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n");
    for (name, value) in headers {
        let _ = std::fmt::Write::write_fmt(&mut head, format_args!("{name}: {value}\r\n"));
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

/// The decoded rate-limit body the scripted provider rejects with.
const RATE_LIMIT_BODY: &[u8] = br#"{"error":{"message":"slow down","type":"rate_limit_error"}}"#;

/// A decoded 429 with a zero retry-after: the rejection the proxy's
/// route policy retries.
fn rate_limited_response() -> Vec<u8> {
    raw_response(
        429,
        "Too Many Requests",
        &[
            ("content-type", "application/json"),
            ("x-request-id", "req-reconstruction-429"),
            ("retry-after", "0"),
        ],
        RATE_LIMIT_BODY,
    )
}

/// The streamed events of a successful retried exchange: two content
/// deltas, the usage-bearing event, and the terminal marker.
fn streamed_events() -> Vec<Vec<u8>> {
    vec![
        br#"{"id":"s-1","choices":[{"delta":{"content":"or"}}]}"#.to_vec(),
        br#"{"id":"s-1","choices":[{"delta":{"content":"der"}}]}"#.to_vec(),
        br#"{"id":"s-1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#
            .to_vec(),
        b"[DONE]".to_vec(),
    ]
}

/// A complete chunked SSE response over [`streamed_events`].
fn streamed_usage_response() -> Vec<u8> {
    let frames: Vec<Vec<u8>> = streamed_events()
        .iter()
        .map(|event| sse_frame(event))
        .collect();
    chunked_sse(&[("x-request-id", "req-reconstruction-stream")], &frames)
}

/// The caller's bounded `POST` to the proxy's declared route.
fn caller_request(route: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!("POST {route} HTTP/1.1\r\nhost: harness\r\n");
    let _ = std::fmt::Write::write_fmt(
        &mut request,
        format_args!("content-length: {}\r\n\r\n", body.len()),
    );
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Bind the replacement route against the scripted provider: the
/// proxy a harness points its existing OpenAI-compatible client at.
fn replacement_proxy(provider: &ScriptedProvider, max_attempts: u32) -> CaptureProxy {
    let endpoint = OpenAiEndpoint::new(
        "127.0.0.1".to_owned(),
        provider.port(),
        CREDENTIAL.to_owned(),
    )
    .expect("endpoint");
    let config = ProxyConfig::new(tenant(), origin(), endpoint)
        .with_transport(Http1Transport::with_timeouts(
            Duration::from_secs(2),
            Duration::from_secs(10),
        ))
        .with_retry_policy(RetryPolicy {
            max_attempts,
            backoff_ms: 0,
        });
    CaptureProxy::bind(config).expect("bind proxy")
}

/// Serve one exchange: the proxy serves while the caller writes its
/// request and reads exactly what the proxy relays back.
fn serve_and_read(
    proxy: &CaptureProxy,
    request: &[u8],
) -> (Vec<u8>, ProxyExchangeReport<ConformanceSink>) {
    std::thread::scope(|scope| {
        let server = scope.spawn({
            let proxy = proxy.clone();
            move || {
                proxy
                    .serve_one(ConformanceSink::new())
                    .expect("the proxy serves")
            }
        });
        let mut caller = TcpStream::connect(proxy.local_addr()).expect("the caller connects");
        let _ = caller.set_read_timeout(Some(Duration::from_secs(30)));
        caller.write_all(request).expect("the caller writes");
        let mut relayed = Vec::new();
        let _ = caller.read_to_end(&mut relayed);
        let report = server.join().expect("serve_one joins");
        (relayed, report)
    })
}

// ---------------------------------------------------------------------
// Streaming order
// ---------------------------------------------------------------------

/// A decoded stream reconstructs in dense ordinal order even when the
/// fold's input arrives in another order: the ordinal is the order,
/// not the supply position.
#[test]
fn streaming_order_reconstructs_dense_ordinals_from_any_supply_order() {
    let mut observer = hook_observer();
    observer
        .start_logical_inference(Some(time()))
        .expect("start");
    observer.start_provider_attempt().expect("attempt");
    observer
        .decoded_request_bytes(b"streamed-request", None, Some(time()))
        .expect("request");
    let events: [&[u8]; 4] = [
        b"event-alpha",
        b"event-beta",
        b"event-gamma",
        b"event-delta",
    ];
    for event in events {
        observer
            .decoded_response_event(event, None, Some(time()))
            .expect("stream event");
    }
    observer
        .attempt_outcome(AttemptOutcome::Incomplete, Some(time()))
        .expect("stream ended without a terminal event");
    observer.close_logical_inference().expect("close");

    // Supply the fold newest-first: reconstruction must still order the
    // prefix by event ordinal, exactly as the wire emitted it.
    let mut artifacts = artifacts_of(&observer.into_sink());
    artifacts.reverse();
    let reconstruction = reconstruct_inference(&artifacts).expect("one inference");
    let attempts = assert_separate_ordered_attempts(&reconstruction);
    assert_eq!(attempts.len(), 1);
    let attempt = &attempts[0];
    assert_eq!(attempt.stream_prefix_len(), 4);
    assert_eq!(
        attempt
            .stream_events()
            .iter()
            .map(|event| event.event_ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3],
        "ordinals are dense from zero"
    );
    for (ordinal, event) in events.iter().enumerate() {
        let retained = &attempt.stream_events()[ordinal];
        assert_eq!(
            *retained.payload.digest(),
            blob_digest(event),
            "ordinal {ordinal} did not retain the wire's payload order"
        );
    }
    // The prefix without a terminal observation is a partial attempt,
    // never a fabricated complete response.
    assert_eq!(
        attempt.terminal_state(),
        AttemptTerminalState::AbandonedMidStream { events: 4 }
    );
    assert!(!attempt.response_complete());
}

// ---------------------------------------------------------------------
// Retry separation
// ---------------------------------------------------------------------

/// A decoded rate-limit response followed by a retry is two attempts
/// with two identities and one successor-stamped citation — the retry
/// never completes or merges the predecessor.
#[test]
fn retry_separation_keeps_attempts_independent() {
    let (_, artifacts) = retried_hook_exchange();
    let reconstruction = reconstruct_inference(&artifacts).expect("one inference");
    let attempts = assert_separate_ordered_attempts(&reconstruction);
    assert_eq!(attempts.len(), 2);

    let first = &attempts[0];
    assert!(first.request_present());
    assert!(first.response_complete());
    assert_eq!(
        *first.response().expect("response").digest(),
        blob_digest(b"rate-limited-body")
    );
    assert!(
        first.entered_via().is_none(),
        "the predecessor has no retry edge"
    );
    assert_eq!(first.terminal_state(), AttemptTerminalState::Completed);

    let second = &attempts[1];
    assert!(second.request_present());
    assert!(second.response_complete());
    assert_eq!(second.terminal_state(), AttemptTerminalState::Completed);
    assert_eq!(
        second.entered_via().map(|transition| {
            (
                transition.reason,
                transition.of_attempt_ordinal,
                transition.backoff_ms,
            )
        }),
        Some((RetryReason::RateLimit, 0, Some(120))),
        "the retry cites its closed predecessor"
    );
    assert_eq!(
        second
            .usage_reports()
            .iter()
            .map(|report| {
                (
                    report.source,
                    report.input_tokens,
                    report.output_tokens,
                    report.total_tokens,
                )
            })
            .collect::<Vec<_>>(),
        vec![(UsageSource::ResponseBody, 3, 5, 8)],
        "usage joins the attempt that reported it"
    );
    // The one citation in the chain is the successor's: the retry edge
    // count equals the retry count, never zero and never two-on-one.
    assert_eq!(reconstruction.retry_edges().len(), 1);
}

// ---------------------------------------------------------------------
// Lost response
// ---------------------------------------------------------------------

/// A request whose response never arrived — teardown without an
/// attempt outcome — stays one truncated attempt with its request
/// evidence; nothing is dropped, nothing is fabricated.
#[test]
fn lost_response_stays_a_truncated_attempt() {
    let mut observer = hook_observer();
    observer
        .start_logical_inference(Some(time()))
        .expect("start");
    observer.start_provider_attempt().expect("attempt");
    observer
        .decoded_request_bytes(b"lost-response-request", None, Some(time()))
        .expect("request landed");
    let close = observer
        .close_logical_inference()
        .expect("close still reports");
    assert_eq!(close.outcome, LogicalInferenceOutcome::Incomplete);
    assert_eq!(close.failure, Some(ObserverFailure::CaptureFailed));

    let artifacts = artifacts_of(&observer.into_sink());
    let reconstruction = reconstruct_inference(&artifacts).expect("one inference");
    let attempts = assert_separate_ordered_attempts(&reconstruction);
    assert_eq!(attempts.len(), 1);
    let attempt = &attempts[0];
    assert!(attempt.request_present());
    assert_eq!(
        *attempt.request().expect("request").digest(),
        blob_digest(b"lost-response-request")
    );
    assert!(!attempt.response_complete(), "no response was fabricated");
    assert!(attempt.stream_events().is_empty());
    assert_eq!(attempt.terminal_state(), AttemptTerminalState::Truncated);
    assert_eq!(
        attempt.outcome(),
        archivist_protocol::attempt_reconstruction::AttemptOutcome::Requested
    );
}

// ---------------------------------------------------------------------
// Partial output
// ---------------------------------------------------------------------

/// Every prefix of an abandoned stream reconstructs as one partial
/// attempt retaining exactly that prefix — and each prefix is the
/// stable head of every longer one.
#[test]
fn partial_output_retains_every_stream_prefix() {
    let mut observer = hook_observer();
    observer
        .start_logical_inference(Some(time()))
        .expect("start");
    observer.start_provider_attempt().expect("attempt");
    observer
        .decoded_request_bytes(b"partial-request", None, Some(time()))
        .expect("request");
    for ordinal in 0..3 {
        let event = format!("partial-event-{ordinal}");
        observer
            .decoded_response_event(event.as_bytes(), None, Some(time()))
            .expect("stream event");
    }
    observer
        .attempt_outcome(AttemptOutcome::Incomplete, Some(time()))
        .expect("stream abandoned");
    observer.close_logical_inference().expect("close");

    let artifacts = artifacts_of(&observer.into_sink());
    let full = reconstruct_inference(&artifacts).expect("one inference");
    let attempts = assert_separate_ordered_attempts(&full);
    assert_eq!(attempts.len(), 1);
    let attempt = &attempts[0];
    assert_eq!(
        attempt.terminal_state(),
        AttemptTerminalState::AbandonedMidStream { events: 3 }
    );
    assert!(!attempt.response_complete());

    // The request plus the first k events: a partial attempt with
    // exactly k ordered events, byte-stable against the full prefix.
    for count in 1..=3_usize {
        let prefix = &artifacts[..=count];
        let prefix_reconstruction = reconstruct_inference(prefix).expect("one inference");
        let prefix_attempts = assert_separate_ordered_attempts(&prefix_reconstruction);
        assert_eq!(prefix_attempts.len(), 1);
        let prefix_attempt = &prefix_attempts[0];
        assert_eq!(prefix_attempt.stream_prefix_len(), count);
        assert_eq!(
            prefix_attempt.terminal_state(),
            AttemptTerminalState::AbandonedMidStream {
                events: u64::try_from(count).expect("small count")
            }
        );
        assert_eq!(
            prefix_attempt.stream_events(),
            &attempt.stream_events()[..count],
            "prefix {count} is not the stable head of the full stream"
        );
    }
}

// ---------------------------------------------------------------------
// Transport error
// ---------------------------------------------------------------------

/// A below-the-boundary failure is one classified attempt — a
/// transport-error artifact, no decoded payload — and the retry that
/// follows it is a separate successor, not a continuation.
#[test]
fn transport_error_classifies_and_separates_from_its_retry() {
    let mut observer = hook_observer();
    observer
        .start_logical_inference(Some(time()))
        .expect("start");
    let first = observer.start_provider_attempt().expect("first attempt");
    observer
        .decoded_request_bytes(b"doomed-request", None, Some(time()))
        .expect("request");
    observer
        .attempt_outcome(
            AttemptOutcome::TransportError {
                error_class: TransportErrorClass::Connect,
                timeout_ms: None,
            },
            Some(time()),
        )
        .expect("transport failure recorded");
    let second = observer
        .start_retry_attempt(RetryReason::TransportError, Some(250), Some(time()))
        .expect("retry after the failure");
    assert_ne!(
        second.provider_attempt_id(),
        first.provider_attempt_id(),
        "the retry is a fresh transport identity"
    );
    assert_eq!(first.attempt_ordinal(), 0);
    assert_eq!(second.attempt_ordinal(), 1);
    observer
        .decoded_request_bytes(b"second-request", None, Some(time()))
        .expect("request");
    observer
        .decoded_response_bytes(b"second-response", None, Some(time()))
        .expect("response");
    observer
        .attempt_outcome(AttemptOutcome::Completed, Some(time()))
        .expect("completed");
    observer.close_logical_inference().expect("close");

    let artifacts = artifacts_of(&observer.into_sink());
    let reconstruction = reconstruct_inference(&artifacts).expect("one inference");
    let attempts = assert_separate_ordered_attempts(&reconstruction);
    assert_eq!(attempts.len(), 2);

    let failed = &attempts[0];
    assert_eq!(
        failed.terminal_state(),
        AttemptTerminalState::TransportFailed {
            class: TransportErrorClass::Connect
        }
    );
    let error_kinds = failed
        .artifacts()
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.event,
                archivist_protocol::inference_artifact::BoundaryEvent::TransportError { .. }
            )
        })
        .count();
    assert_eq!(error_kinds, 1, "exactly one transport-error artifact");
    assert!(!failed.response_complete());
    assert!(failed.stream_events().is_empty());
    assert_eq!(
        *failed.request().expect("request").digest(),
        blob_digest(b"doomed-request")
    );

    let successor = &attempts[1];
    assert_eq!(successor.terminal_state(), AttemptTerminalState::Completed);
    assert_eq!(
        successor.entered_via().map(|transition| {
            (
                transition.reason,
                transition.of_attempt_ordinal,
                transition.backoff_ms,
            )
        }),
        Some((RetryReason::TransportError, 0, Some(250)))
    );
}

// ---------------------------------------------------------------------
// Proxy replacement
// ---------------------------------------------------------------------

/// The replacement route reconstructs exactly as the hook route does:
/// a rate-limited attempt and its retried streamed successor stay two
/// in-order attempts, a refused exchange fabricates nothing, and the
/// proxy's evidence never folds together with the hook's.
#[test]
fn proxy_replacement_reconstructs_the_relayed_attempts() {
    let body = br#"{"model":"reconstruction","messages":[{"role":"user","content":"probe"}],"stream":true}"#;
    let mut provider = ScriptedProvider::bind();
    provider.queue(ProviderScript::Respond(rate_limited_response()));
    provider.queue(ProviderScript::Respond(streamed_usage_response()));
    let proxy = replacement_proxy(&provider, 2);
    let (relayed, report) = serve_and_read(&proxy, &caller_request(proxy.route(), body));

    // The exchange itself captured cleanly: two wire attempts, the
    // second one streamed, teardown complete.
    let capture = report
        .outcome()
        .captured()
        .expect("the exchange was captured");
    assert_eq!(capture.attempts, 2);
    assert_eq!(capture.close.outcome, LogicalInferenceOutcome::Complete);
    assert!(capture.streamed);
    assert_eq!(capture.final_status, Some(200));

    let reconstruction =
        reconstruct_inference(&artifacts_of(report.sink_ref())).expect("one inference");
    let attempts = assert_separate_ordered_attempts(&reconstruction);
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].attempt_ordinal(), 0);
    assert_eq!(attempts[1].attempt_ordinal(), 1);

    // The rejected attempt: its decoded 429 is captured evidence.
    let rejected = &attempts[0];
    assert!(rejected.request_present());
    assert_eq!(
        *rejected.response().expect("429 response").digest(),
        blob_digest(RATE_LIMIT_BODY)
    );
    assert_eq!(rejected.terminal_state(), AttemptTerminalState::Completed);

    // The retried attempt: a fresh identity, the predecessor citation,
    // four ordered stream events, and usage joined to its reporting
    // event — never merged into the rejected exchange.
    let streamed = &attempts[1];
    assert_eq!(
        streamed.entered_via().map(|transition| {
            (
                transition.reason,
                transition.of_attempt_ordinal,
                transition.backoff_ms,
            )
        }),
        Some((RetryReason::RateLimit, 0, Some(0)))
    );
    assert!(!streamed.response_complete(), "a stream is not a response");
    assert_eq!(
        streamed
            .stream_events()
            .iter()
            .map(|event| event.event_ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    let events = streamed_events();
    for (ordinal, event) in events.iter().enumerate() {
        assert_eq!(
            *streamed.stream_events()[ordinal].payload.digest(),
            blob_digest(event)
        );
    }
    assert_eq!(streamed.usage_reports().len(), 1);
    assert_eq!(streamed.usage_reports()[0].source, UsageSource::StreamEvent);
    assert_eq!(
        streamed.usage_reports()[0]
            .payload
            .map(|payload| *payload.digest()),
        Some(blob_digest(&events[2])),
        "usage names its reporting event"
    );

    // Both provider attempts forwarded the same decoded body under two
    // fresh identities — the attempts reconstruct side by side.
    assert_eq!(
        provider.bodies(),
        vec![body.to_vec(), body.to_vec()],
        "each attempt forwarded the caller's body itself"
    );
    assert!(
        relayed.ends_with(b"0\r\n\r\n"),
        "the caller drained the relay"
    );

    // A request off the declared route is refused before capture: no
    // artifacts were minted, and therefore no attempt exists to
    // reconstruct — the empty fold is empty.
    let (_, refused) = serve_and_read(&proxy, &caller_request("/v1/elsewhere", body));
    assert_eq!(refused.outcome().refusal(), Some(Refusal::UnknownRoute));
    assert!(refused.sink_ref().artifacts().is_empty());
    let empty = reconstruct_inference(&[]).expect("empty fold");
    assert!(empty.attempts().is_empty());

    // And the two routes' evidence never folds together: the hook's
    // logical inference and the proxy's are two inferences, and the
    // fold refuses to merge them into one chain.
    let (_, hook_artifacts) = single_hook_exchange();
    let mut mixed = hook_artifacts;
    mixed.extend(artifacts_of(report.sink_ref()));
    assert_eq!(
        reconstruct_inference(&mixed).unwrap_err(),
        ReconstructionError::MixedInference
    );
}

// ---------------------------------------------------------------------
// Hook failure
// ---------------------------------------------------------------------

/// A sink that accepts the first `budget` emissions and refuses every
/// later one: the mid-exchange capture failure the dimension scripts.
struct BudgetedSink {
    budget: usize,
    accepted: Vec<CanonicalArtifact>,
}

impl BudgetedSink {
    /// A sink that will accept `budget` artifacts, then fail.
    fn new(budget: usize) -> Self {
        Self {
            budget,
            accepted: Vec::new(),
        }
    }

    /// The artifacts that landed before the failure.
    fn landed(&self) -> Vec<InferenceArtifact> {
        self.accepted
            .iter()
            .map(|item| item.artifact().clone())
            .collect()
    }
}

impl InferenceArtifactSink for BudgetedSink {
    fn emit(&mut self, artifact: CanonicalArtifact) -> Result<(), SinkFailure> {
        if self.accepted.len() >= self.budget {
            return Err(SinkFailure::Unavailable);
        }
        self.accepted.push(artifact);
        Ok(())
    }

    fn flush(&mut self) -> FlushState {
        FlushState::Acknowledged
    }
}

/// A capture whose sink fails mid-exchange keeps the evidence that
/// landed as one partial attempt, reports the bounded failure
/// explicitly, and never fabricates the evidence that did not land.
#[test]
fn a_mid_exchange_sink_failure_keeps_landed_evidence_partial() {
    let mut observer = InferenceObserverV1::new(tenant(), origin(), BudgetedSink::new(1));
    observer
        .start_logical_inference(Some(time()))
        .expect("start");
    observer.start_provider_attempt().expect("attempt");
    observer
        .decoded_request_bytes(b"request-that-landed", None, Some(time()))
        .expect("the request landed");

    let refused =
        observer.decoded_response_bytes(b"response-that-never-landed", None, Some(time()));
    assert_eq!(
        refused,
        Err(InferenceObserverError::Sink(SinkFailure::Unavailable))
    );
    assert_eq!(
        refused.unwrap_err().failure(),
        Some(ObserverFailure::CaptureFailed),
        "the sink refusal is a bounded capture failure"
    );
    // The observer is now in its failure state: later emissions stay
    // refused instead of silently resuming.
    assert_eq!(
        observer.decoded_response_event(b"late-event", None, Some(time())),
        Err(InferenceObserverError::Failed(
            ObserverFailure::CaptureFailed
        ))
    );
    let close = observer
        .close_logical_inference()
        .expect("close still reports");
    assert_eq!(close.outcome, LogicalInferenceOutcome::Incomplete);
    assert_eq!(close.failure, Some(ObserverFailure::CaptureFailed));

    let landed = observer.into_sink().landed();
    let reconstruction = reconstruct_inference(&landed).expect("one inference");
    let attempts = assert_separate_ordered_attempts(&reconstruction);
    assert_eq!(attempts.len(), 1);
    let attempt = &attempts[0];
    assert_eq!(
        *attempt.request().expect("request").digest(),
        blob_digest(b"request-that-landed")
    );
    assert!(
        !attempt.response_complete(),
        "the refused response is absent"
    );
    assert!(attempt.stream_events().is_empty());
    assert_eq!(attempt.terminal_state(), AttemptTerminalState::Truncated);
}

/// A teardown the sink never acknowledged is reported incomplete
/// without losing any evidence: every artifact landed, the attempt
/// reconstructs complete, and only the flush claim stays honest.
#[test]
fn an_unacknowledged_flush_is_explicit_and_loses_no_evidence() {
    let sink = ConformanceSink::new().with_flush_state(FlushState::Incomplete);
    let mut observer = InferenceObserverV1::new(tenant(), origin(), sink);
    observer
        .start_logical_inference(Some(time()))
        .expect("start");
    observer.start_provider_attempt().expect("attempt");
    observer
        .decoded_request_bytes(b"flushed-request", None, Some(time()))
        .expect("request");
    observer
        .decoded_response_bytes(b"flushed-response", None, Some(time()))
        .expect("response");
    observer
        .attempt_outcome(AttemptOutcome::Completed, Some(time()))
        .expect("completed");
    let close = observer
        .close_logical_inference()
        .expect("close still reports");
    assert_eq!(close.outcome, LogicalInferenceOutcome::Incomplete);
    assert_eq!(close.flush_state, FlushState::Incomplete);
    assert_eq!(close.failure, Some(ObserverFailure::FlushIncomplete));

    let artifacts = artifacts_of(&observer.into_sink());
    let reconstruction = reconstruct_inference(&artifacts).expect("one inference");
    let attempts = assert_separate_ordered_attempts(&reconstruction);
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts[0].terminal_state(),
        AttemptTerminalState::Completed
    );
    assert!(attempts[0].response_complete());
    assert_eq!(
        close.emitted_artifacts,
        u64::try_from(artifacts.len()).expect("small count")
    );
}

// ---------------------------------------------------------------------
// Semantic/exact divergence
// ---------------------------------------------------------------------

/// A synthetic correlation pair for an exchange that bypassed both
/// supported routes: it has an expectation and no artifacts.
fn bypassed_identity() -> InferenceIdentity {
    InferenceIdentity::new(
        TraceId::parse("00000000-0000-7000-8000-0000000000b1").expect("trace"),
        InferenceRequestId::parse("00000000-0000-7000-8000-0000000000b2").expect("inference"),
    )
}

/// One session's semantic and exact coverage diverge in every direction
/// at once, and no dimension borrows a verdict from the other: the
/// retried exchange is partial (its retry never merges into one
/// satisfying exchange), the bypassed exchange is unobserved (no
/// fabricated attempt), the failed capture is failed (evidence does not
/// override the bounded failure), the semantic-only session is unknown
/// (never unobserved), and the semantic transcript's own counts ride
/// beside the exact report without touching it.
#[test]
#[allow(clippy::too_many_lines)] // one session's divergence, read top to bottom
fn semantic_and_exact_coverage_diverge_without_merging() {
    let session = OpaqueId::parse("session-divergent").expect("session");
    let semantic_only = OpaqueId::parse("session-semantic-only").expect("session");
    let mut ledger = ExpectedInferenceLedger::new();
    ledger.register_session(session.clone());
    ledger.register_session(semantic_only);

    // The instrumented exchange: two transport attempts through the
    // hook, with its expectation frozen before the evidence joins.
    let (captured, captured_artifacts) = retried_hook_exchange();
    ledger
        .persist(ExpectedInferenceRecord::new(
            captured.clone(),
            session.clone(),
            RoutePolicy::SdkHook,
            time(),
        ))
        .expect("persist the captured expectation");

    // The bypassed exchange declared for the replacement route, whose
    // traffic never traversed any instrumented boundary.
    let bypassed = bypassed_identity();
    ledger
        .persist(ExpectedInferenceRecord::new(
            bypassed.clone(),
            session.clone(),
            RoutePolicy::Proxy,
            time(),
        ))
        .expect("persist the bypassed expectation");

    // The failed capture: partial evidence under a bounded integration
    // failure.
    let mut failing = InferenceObserverV1::new(tenant(), origin(), BudgetedSink::new(1));
    let failed_start = failing
        .start_logical_inference(Some(time()))
        .expect("start");
    failing.start_provider_attempt().expect("attempt");
    failing
        .decoded_request_bytes(b"failed-capture-request", None, Some(time()))
        .expect("the request landed");
    let _ = failing.decoded_response_bytes(b"never-lands", None, Some(time()));
    let failed = InferenceIdentity::new(
        failed_start.trace_id().clone(),
        failed_start.inference_request_id().clone(),
    );
    ledger
        .persist(ExpectedInferenceRecord::new(
            failed.clone(),
            session.clone(),
            RoutePolicy::SdkHook,
            time(),
        ))
        .expect("persist the failed expectation");
    let failed_artifacts = failing.into_sink().landed();

    let mut evidence = captured_artifacts;
    evidence.extend(failed_artifacts);
    let mut aligned = align_attempts(&mut ledger, &evidence).expect("alignment");

    // Three separate expectations, three separate joins: the retry
    // chain stays two attempts (six envelopes), the bypass has none,
    // and the failed capture keeps its single landed artifact.
    let captured_entry = aligned.inferences.get(&captured).expect("captured");
    assert_eq!(captured_entry.reconstructed_attempts, 2);
    assert_eq!(captured_entry.recorded_artifacts, 6);
    assert_eq!(aligned.reconstructed_attempts(&bypassed), Some(0));
    let failed_entry = aligned.inferences.get(&failed).expect("failed");
    assert_eq!(failed_entry.reconstructed_attempts, 1);
    assert_eq!(failed_entry.recorded_artifacts, 1);

    // Closing derives each verdict from its own evidence alone.
    assert_eq!(
        ledger.close_completed(&captured),
        Ok(ExactOutcome::Partial),
        "two separate attempts never merge into one satisfying exchange"
    );
    assert_eq!(
        ledger.close_completed(&bypassed),
        Ok(ExactOutcome::Unobserved)
    );
    assert_eq!(
        ledger.close_failed(&failed, IntegrationFailure::CaptureFailed),
        Ok(ExactOutcome::Failed),
        "the bounded failure decides despite the landed artifact"
    );

    let report = ledger.reconcile();
    assert_eq!(report.sessions, 2);
    assert_eq!(report.observed, 0);
    assert_eq!(report.partial, 1);
    assert_eq!(report.failed, 1);
    assert_eq!(report.unobserved, 1);
    assert_eq!(report.unknown, 1, "the semantic-only session is unknown");
    assert_eq!(report.closed_expectations(), 3);

    // Per-route state keeps each integration's bypass on its own
    // denominator: the sums over routes equal the closed total.
    let routes = ledger.route_states();
    assert_eq!(routes[0].route, RoutePolicy::Proxy);
    assert_eq!(routes[0].unobserved, 1);
    assert_eq!(routes[0].closed_expectations(), 1);
    assert_eq!(routes[1].route, RoutePolicy::SdkHook);
    assert_eq!(routes[1].partial, 1);
    assert_eq!(routes[1].failed, 1);
    assert_eq!(routes[1].closed_expectations(), 2);
    assert_eq!(
        routes
            .iter()
            .map(RouteCoverage::closed_expectations)
            .sum::<u64>(),
        report.closed_expectations()
    );

    // Closed verdicts survive later evidence: re-alignment counts the
    // projection without rewriting any outcome.
    aligned = align_attempts(&mut ledger, &evidence).expect("re-alignment");
    assert_eq!(aligned.outcome(&captured), Some(ExactOutcome::Partial));
    assert_eq!(aligned.outcome(&bypassed), Some(ExactOutcome::Unobserved));
    assert_eq!(aligned.outcome(&failed), Some(ExactOutcome::Failed));
    let closed_entry = aligned.inferences.get(&captured).expect("captured");
    assert_eq!(closed_entry.projected_artifacts, 6);
    assert_eq!(
        closed_entry.recorded_artifacts, 0,
        "a closed verdict records nothing"
    );

    // The semantic dimension: both sessions' harness transcripts are
    // fully captured in the semantic vocabulary — counted here in its
    // own tallies, which no exact API reads and no exact verdict
    // feeds.  Semantic capture of both sessions implies nothing exact:
    // the exact report keeps observed at zero and keeps the
    // semantic-only session unknown rather than unobserved.
    let mut semantic = CoverageCounts::default();
    semantic.record(CoverageState::Current);
    semantic.record(CoverageState::Current);
    assert_eq!(semantic.get(CoverageState::Current), 2);
    assert_eq!(
        ledger.reconcile(),
        report,
        "semantic tallies leave the exact report untouched"
    );
}

// ---------------------------------------------------------------------
// Model boundary
// ---------------------------------------------------------------------

/// Two logical inferences refuse a shared fold: no API of the model can
/// express one attempt chain over two inferences' artifacts.
#[test]
fn two_logical_inferences_refuse_a_shared_fold() {
    let (_, first) = single_hook_exchange();
    let (_, second) = single_hook_exchange();
    let mut mixed = first;
    mixed.extend(second);
    assert_eq!(
        reconstruct_inference(&mixed).unwrap_err(),
        ReconstructionError::MixedInference
    );
}
