// SPDX-License-Identifier: Apache-2.0

//! The capture-proxy parse-and-forward fuzz suite (bead `aa-a23b606a`):
//! deterministic pseudo-random hostile input against the one always-on
//! network surface the inference phase added — the OpenAI-compatible
//! capture proxy — driven end to end through its public seam
//! ([`CaptureProxy::serve_one`]) so every stage a hostile byte crosses
//! is exercised as wired: the caller head parse, the refusal boundary,
//! the caller body read, the provider forwarding, the provider response
//! decode, the SSE event assembly, and the chunked relay back.
//!
//! The bead names the hazards this suite exists for: malformed streaming
//! bodies, truncated SSE events, and adversarial content-length/chunking
//! combinations. The contract under fuzz, one clause per property:
//!
//! - **Every exchange terminates**: however hostile the caller head or
//!   the provider's response bytes, `serve_one` returns — no panic, no
//!   hang.
//! - **Refusals are bounded and content-free**: a refused request is
//!   answered with exactly the fixed status, reason, headers, and
//!   content-free body its [`Refusal`] token declares — never payload,
//!   caller headers, or identity material.
//! - **Forwarding is faithful in both directions**: a captured body
//!   reaches the provider byte-for-byte under exactly the route's own
//!   two headers (the caller's planted credential-shaped headers are
//!   dropped unread), a buffered response reaches the caller
//!   byte-for-byte under rewritten framing, and a streamed response
//!   relays exactly one chunk per decoded event whose frame decodes
//!   back to the boundary's event — `decode ∘ reframe = decode` over
//!   arbitrary hostile bytes.
//! - **Truncation is never fabricated**: a provider body that dies
//!   mid-chunking relays as truncated — no terminal chunk on a stream,
//!   an empty connection for a buffered body — and names the
//!   below-boundary class in the report.
//! - **The closed metadata allowlist holds under hostile heads**:
//!   denial-shaped header values planted in every response never reach
//!   any archived artifact's canonical bytes, while the allowlisted
//!   request-id does.
//! - **Usage is recorded iff the bytes declare it and the stream
//!   drains**: exactly one usage artifact with the extracted counters,
//!   from the response body when buffered and from the reporting event
//!   when streamed, and none from a stream that died before its drain.
//!
//! Every loop is driven by a fixed-seed `xorshift64*` stream in the
//! house style of the other fuzz suites, so a failure replays from the
//! seed named in the assertion message. Iteration counts keep the whole
//! binary fast under the fleet's cgroup-limited test lanes.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use archivist_adapter_sdk::CanonicalArtifact;
use archivist_adapter_sdk::inference_observer::{LogicalInferenceOutcome, RecordingArtifactSink};
use archivist_adapter_sdk::openai_compat::{OpenAiEndpoint, RetryPolicy, usage_from_bytes};
use archivist_adapter_sdk::openai_http1::{
    DEFAULT_MAX_BODY_BYTES, Http1Transport, SseDecoder, WireBody, WireEndpoint, WireRequest,
};
use archivist_adapter_sdk::openai_proxy::{CaptureProxy, ExchangeOutcome, ProxyConfig, Refusal};
use archivist_protocol::inference_artifact::{BoundaryEvent, InferenceArtifact};
use archivist_protocol::vocabulary::{ClientId, TenantId, TransportErrorClass};

/// The declared route every captured request must target.
const ROUTE: &str = "/v1/chat/completions";

/// The route's own credential on the wire. Test fixture material — the
/// property under test is that it appears exactly once, in the
/// forwarded `authorization` header, and nowhere caller-facing or
/// archived.
const CREDENTIAL: &str = "fuzz-route-credential-not-a-secret";

/// Planted in the hostile caller's own headers: must never survive the
/// boundary into any caller-facing answer.
const CALLER_SECRET: &str = "ZPROXYCALLERQ7";

/// Planted in denial-shaped provider headers: must never reach any
/// archived artifact's canonical bytes or, via them, any caller answer.
const DENIED_MARKER: &str = "ZPROXYDENIEDQ5";

/// The tenant and origin identities the capture route declares.
const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
const ORIGIN: &str = "2b6a5f10-4c1e-4a7e-9d0a-5f3b8c1e2d40";

/// Every read the harness itself does is bounded by this deadline, so a
/// suite failure is a failed assertion, never a wedged lane.
const HARNESS_IO_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Deterministic generator
// ---------------------------------------------------------------------------

/// `xorshift64*`: the whole state is one nonzero word, so a test seeded
/// from a constant replays identically on every run and platform.
struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value below `bound`; modulo bias is irrelevant at fuzz-suite
    /// granularity.
    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    /// The same draw as [`Prng::below`] in the `usize` domain the
    /// harness indexes with. Every bound passed here is constructed far
    /// below `usize::MAX`, so the widening round trip cannot truncate.
    #[allow(clippy::cast_possible_truncation)]
    fn below_usize(&mut self, bound: usize) -> usize {
        self.below(bound as u64) as usize
    }

    /// A hostile byte: mostly printable and framing-adjacent so the
    /// grammar under test is actually reached, occasionally arbitrary.
    fn hostile_byte(&mut self) -> u8 {
        const FLAVOR: &[u8] = br#"{}[]":,data \nret0123456789abcdef-x-"#;
        if self.chance(85) {
            FLAVOR[self.below_usize(FLAVOR.len())]
        } else {
            (self.next_u64() & 0xFF) as u8
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.hostile_byte()).collect()
    }
}

// ---------------------------------------------------------------------------
// Reference decoders — independent of the code under test
// ---------------------------------------------------------------------------

/// The boundary's SSE decode, re-derived from its documented contract:
/// lines end at `\n`, one trailing `\r` is framing, `data:` fields
/// carry the payload joined with `\n`, a blank line dispatches, and a
/// final unterminated line with pending data still counts. This is the
/// oracle the relay's `decode ∘ reframe = decode` property is stated
/// against.
fn reference_sse_parse(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut events: Vec<Vec<u8>> = Vec::new();
    let mut data_lines: Vec<Vec<u8>> = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = if let Some(without_cr) = line.strip_suffix(b"\r") {
            without_cr
        } else {
            line
        };
        if line.is_empty() {
            if !data_lines.is_empty() {
                events.push(data_lines.join(&b'\n'));
                data_lines.clear();
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix(b"data:".as_slice()) {
            let value = if rest.first() == Some(&b' ') {
                &rest[1..]
            } else {
                rest
            };
            data_lines.push(value.to_vec());
        }
    }
    if !data_lines.is_empty() {
        events.push(data_lines.join(&b'\n'));
    }
    events
}

/// Parse a caller answer's chunked body strictly: a sequence of
/// `size\r\n frame \r\n` chunks, optionally ending in the terminal
/// `0\r\n\r\n`. Returns the frames and whether the terminal chunk
/// completed the body.
fn reference_chunk_parse(body: &[u8]) -> (Vec<Vec<u8>>, bool) {
    let mut frames = Vec::new();
    let mut at = 0usize;
    loop {
        let line_end = body[at..]
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or_else(|| panic!("chunked body ended without a size line at {at}"));
        let size_line = &body[at..at + line_end];
        at += line_end + 1;
        let size_text = std::str::from_utf8(size_line)
            .unwrap_or_else(|_| panic!("chunk size line is not UTF-8: {size_line:?}"));
        let digits = size_text.trim_end_matches('\r');
        let size = usize::from_str_radix(digits.split(';').next().unwrap_or_default().trim(), 16)
            .unwrap_or_else(|_| panic!("chunk size line is not hex: {digits:?}"));
        if size == 0 {
            let terminal = &body[at..];
            assert!(
                terminal == b"\r\n" || terminal.is_empty(),
                "terminal chunk followed by unexpected bytes: {terminal:?}"
            );
            return (frames, true);
        }
        assert!(
            at + size + 2 <= body.len(),
            "chunk of {size} overruns the answer body at offset {at}"
        );
        let frame = &body[at..at + size];
        at += size;
        assert!(
            body[at..].starts_with(b"\r\n"),
            "chunk frame not followed by CRLF at offset {at}"
        );
        at += 2;
        frames.push(frame.to_vec());
    }
}

/// The exact buffered answer the relay owes the caller for a response:
/// the provider's head with the framing headers rewritten, the body
/// byte-for-byte.
fn expected_full_answer(status: u16, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let phrase = known_reason_phrase(status);
    let mut answer = format!("HTTP/1.1 {status} {phrase}\r\n").into_bytes();
    for (name, value) in headers {
        if name == "content-length" || name == "transfer-encoding" {
            continue;
        }
        answer.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    answer.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    answer.extend_from_slice(b"connection: close\r\n\r\n");
    answer.extend_from_slice(body);
    answer
}

/// The exact stream head the relay owes the caller.
fn expected_stream_head(status: u16, headers: &[(String, String)]) -> Vec<u8> {
    let phrase = known_reason_phrase(status);
    let mut answer = format!("HTTP/1.1 {status} {phrase}\r\n").into_bytes();
    for (name, value) in headers {
        if name == "content-length" || name == "transfer-encoding" {
            continue;
        }
        answer.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    answer.extend_from_slice(b"transfer-encoding: chunked\r\nconnection: close\r\n\r\n");
    answer
}

/// The relay's SSE frame for one event payload, per its documented
/// shape: one `data: ` line per payload line, blank-line dispatch.
fn expected_frame(event: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(event.len() + 8);
    for (index, line) in event.split(|byte| *byte == b'\n').enumerate() {
        if index > 0 {
            frame.push(b'\n');
        }
        frame.extend_from_slice(b"data: ");
        frame.extend_from_slice(line);
    }
    frame.extend_from_slice(b"\r\n\r\n");
    frame
}

/// The exact chunked relay body for a drained stream: one chunk per
/// event frame plus the terminal chunk.
fn expected_stream_body(events: &[Vec<u8>], drained: bool) -> Vec<u8> {
    let mut body = Vec::new();
    for event in events {
        let frame = expected_frame(event);
        body.extend_from_slice(format!("{:x}\r\n", frame.len()).as_bytes());
        body.extend_from_slice(&frame);
        body.extend_from_slice(b"\r\n");
    }
    if drained {
        body.extend_from_slice(b"0\r\n\r\n");
    }
    body
}

/// Reason phrases for exactly the statuses this suite generates — the
/// ones whose phrase the relay's bounded table pins.
fn known_reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => unreachable!("generated status {status} has no pinned phrase"),
    }
}

/// The one normalization SSE wire framing forces on an event payload:
/// `\r\n` *inside* the data is indistinguishable from a line
/// terminator — the reframe joins data lines with a bare LF, so the CR
/// fuses with that join and no spec-compliant decoder — the boundary's
/// included — can tell it from a boundary. Every other byte survives:
/// a `\r` not followed by `\n` (mid-data or data-final) rides the
/// `\r\n\r\n` event terminator unharmed, which a hostile round proved
/// at the wire. `decode(reframe(e)) = normalize(e)` is the exact relay
/// contract for streamed events; the archive holds `e` itself,
/// byte-for-byte.
fn normalize_line_boundaries(event: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(event.len());
    let mut index = 0;
    while index < event.len() {
        if event[index] == b'\r' && event.get(index + 1) == Some(&b'\n') {
            index += 1;
        }
        normalized.push(event[index]);
        index += 1;
    }
    normalized
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// What one proxy exchange produced, gathered from both live parties.
struct Scene {
    outcome: ExchangeOutcome,
    answer: Vec<u8>,
    sink: RecordingArtifactSink,
}

/// What the provider received from the proxy.
struct ForwardedRequest {
    raw_head: Vec<u8>,
    body: Vec<u8>,
}

/// A one-shot provider: reads the proxy's forwarded request, reports
/// it, answers with `response`, and closes — the close being what
/// EOF-delimited and truncated framings are decoded against.
fn spawn_provider(response: Vec<u8>) -> (SocketAddr, Receiver<ForwardedRequest>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("provider binds");
    let addr = listener.local_addr().expect("provider address");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("provider accepts");
        let _ = stream.set_read_timeout(Some(HARNESS_IO_TIMEOUT));
        let raw_head = read_until_head_end(&mut stream);
        let length = declared_length(&raw_head).unwrap_or(0);
        let mut body = vec![0_u8; length];
        let _ = stream.read_exact(&mut body);
        let _ = tx.send(ForwardedRequest { raw_head, body });
        if !response.is_empty() {
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        }
        // Held briefly so a complete response delivers before the close
        // the close-delimited transport decodes against.
        std::thread::sleep(Duration::from_millis(30));
    });
    (addr, rx)
}

fn read_until_head_end(stream: &mut TcpStream) -> Vec<u8> {
    let _ = stream.set_read_timeout(Some(HARNESS_IO_TIMEOUT));
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => return head,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") || head.len() > 32 * 1024 {
                    return head;
                }
            }
        }
    }
}

fn declared_length(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").find_map(|line| {
        line.strip_prefix("content-length:")?
            .trim()
            .parse::<usize>()
            .ok()
    })
}

/// A route bound to a one-shot provider, single attempt, no backoff:
/// one attempt keeps every scene's wall clock bounded by one provider
/// exchange.
fn fuzz_config(provider: SocketAddr) -> ProxyConfig {
    let endpoint = OpenAiEndpoint::new(
        provider.ip().to_string(),
        provider.port(),
        CREDENTIAL.to_owned(),
    )
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
        max_attempts: 1,
        backoff_ms: 0,
    })
}

/// Run one full exchange against a fresh proxy: the caller sends
/// `caller_bytes` then half-closes, the proxy serves exactly one
/// connection, and the answer is read to EOF. The provider socket is
/// the address the route forwards to.
fn run_scene(caller_bytes: &[u8], provider: SocketAddr) -> Scene {
    let proxy = CaptureProxy::bind(fuzz_config(provider)).expect("proxy binds");
    let address = proxy.local_addr();
    let wire = caller_bytes.to_vec();
    let caller = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(address).expect("caller connects");
        let _ = stream.set_read_timeout(Some(HARNESS_IO_TIMEOUT));
        stream.write_all(&wire).expect("caller writes");
        let _ = stream.shutdown(Shutdown::Write);
        let mut answer = Vec::new();
        let _ = stream.read_to_end(&mut answer);
        answer
    });
    let report = proxy
        .serve_one(RecordingArtifactSink::new())
        .expect("the listener accepts");
    let outcome = report.outcome().clone();
    let sink = report.into_sink();
    let answer = caller.join().expect("the caller thread finishes");
    Scene {
        outcome,
        answer,
        sink,
    }
}

/// The forwarded request, when the scene's provider reported one.
fn forwarded(rx: &Receiver<ForwardedRequest>) -> Option<ForwardedRequest> {
    rx.recv_timeout(Duration::from_secs(2)).ok()
}

/// The archived artifacts a scene's sink accepted, in emission order.
fn archived(scene: &Scene) -> Vec<InferenceArtifact> {
    scene
        .sink
        .artifacts()
        .iter()
        .map(|recorded| recorded.artifact().clone())
        .collect()
}

/// The fixed provider response the caller-head scenes answer with. The
/// declared length is computed, never transcribed — a fixture that lies
/// about its own framing reads as a transport reset, not as a test
/// failure (reduced from fuzz round 9 the hard way).
fn ok_json_response() -> Vec<u8> {
    let body = b"{\"ok\":true}";
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// Neither any caller-facing answer nor any archived artifact carries a
/// planted denial marker or the route credential.
fn assert_content_free(scene: &Scene, round: u64) {
    for marker in [CALLER_SECRET, DENIED_MARKER, CREDENTIAL, "Bearer "] {
        assert!(
            !contains(&scene.answer, marker.as_bytes()),
            "round {round}: the caller answer carries {marker:?}: {:?}",
            scene.answer
        );
        for artifact in archived(scene) {
            let bytes = artifact.canonical_bytes();
            assert!(
                !contains(&bytes, marker.as_bytes()),
                "round {round}: an archived artifact carries {marker:?}: {:?}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Target 1: hostile caller heads
// ---------------------------------------------------------------------------

/// A hostile header line, content-length-aware so body framing stays
/// self-consistent where the scene wants it to be.
fn hostile_header(prng: &mut Prng, declared: &mut Option<usize>) -> String {
    match prng.below(12) {
        0 => {
            *declared = Some(prng.below_usize(48));
            format!("content-length: {}", declared.unwrap_or(0))
        }
        // A second, disagreeing length: the smuggling shape.
        1 => "content-length: 99".to_owned(),
        2 => "transfer-encoding: chunked".to_owned(),
        3 => format!("x-caller-secret: {CALLER_SECRET}"),
        4 => "authorization: Bearer caller-credential".to_owned(),
        5 => "host: fuzz-harness".to_owned(),
        6 => "content-type: application/json".to_owned(),
        // An unparseable length: refused, never guessed.
        7 => "content-length: many".to_owned(),
        8 => {
            *declared = None;
            format!("content-length: {}", u64::from(u32::MAX))
        }
        9 => "x-empty:".to_owned(),
        // A header line without a colon: no place in a bounded head.
        10 => "no-colon-here".to_owned(),
        // Whitespace and case variants of the framing headers.
        _ => "  CONTENT-LENGTH : 7  ".to_owned(),
    }
}

fn generate_hostile_head(prng: &mut Prng) -> Vec<u8> {
    let method = ["POST", "GET", "post", "DELETE", "BOGUS", "POST"][prng.below_usize(6)];
    let route = prng.chance(80);
    let mut declared: Option<usize> = None;
    let count = prng.below(4);
    let headers: Vec<String> = (0..count)
        .map(|_| hostile_header(prng, &mut declared))
        .collect();
    let body = match declared {
        Some(length) if prng.chance(75) => prng.bytes(length),
        // A short body: the explicit incomplete-body refusal.
        Some(length) => prng.bytes(length.saturating_sub(1)),
        None => Vec::new(),
    };
    let path = if route { ROUTE } else { "/elsewhere" };
    let mut wire = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    for header in &headers {
        wire.extend_from_slice(header.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(&body);
    wire
}

/// A byte-level mutation of a valid, complete request: flips, cuts,
/// and spliced garbage at randomized offsets.
fn mutate_valid_request(prng: &mut Prng) -> Vec<u8> {
    let body = br#"{"model":"fuzz","messages":[{"role":"user","content":"hi"}]}"#;
    let mut wire = format!(
        "POST {ROUTE} HTTP/1.1\r\nhost: fuzz\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend_from_slice(body);
    let mutations = 1 + prng.below(3);
    for _ in 0..mutations {
        match prng.below(3) {
            0 => {
                let at = prng.below_usize(wire.len() + 1);
                if at < wire.len() {
                    wire[at] = prng.hostile_byte();
                }
            }
            1 => {
                let at = prng.below_usize(wire.len() + 1);
                wire.truncate(at);
            }
            _ => {
                let at = prng.below_usize(wire.len() + 1);
                let garbage_len = prng.below_usize(9);
                let garbage = prng.bytes(garbage_len);
                wire.splice(at..at, garbage);
            }
        }
    }
    wire
}

#[test]
#[allow(clippy::too_many_lines)] // one round walks every clause of the contract, read top to bottom
fn hostile_caller_heads_terminate_bounded_and_content_free() {
    let mut prng = Prng::new(0xA23B_606A);
    for round in 0..96u64 {
        let wire = if round % 2 == 0 {
            generate_hostile_head(&mut prng)
        } else {
            mutate_valid_request(&mut prng)
        };
        // A provider always listens: mutated heads that still parse as
        // valid requests are captured and forwarded, never stalled.
        let (provider, rx) = spawn_provider(ok_json_response());
        let scene = run_scene(&wire, provider);
        let context = || {
            format!(
                "round {round}\ncaller bytes: {wire:?}\nanswer: {:?}",
                scene.answer
            )
        };
        match &scene.outcome {
            ExchangeOutcome::Refused(refusal) => {
                if scene.answer.is_empty() {
                    // The peer died before a parseable head arrived:
                    // nothing could be answered.
                    assert_eq!(*refusal, Refusal::MalformedHead, "{}", context());
                } else {
                    let expected = format!(
                        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        refusal.status(),
                        refusal.reason(),
                        refusal.body_text().len(),
                        refusal.body_text()
                    );
                    assert_eq!(scene.answer, expected.as_bytes(), "{}", context());
                }
                // A refusal never captured: no artifacts exist.
                assert!(
                    archived(&scene).is_empty(),
                    "a refusal produced artifacts: {}",
                    context()
                );
            }
            ExchangeOutcome::Captured(capture) => {
                const FORWARDED_HEADER_NAMES: [&str; 5] = [
                    "host",
                    "content-type",
                    "authorization",
                    "content-length",
                    "connection",
                ];
                assert_eq!(capture.attempts, 1, "{}", context());
                assert_eq!(
                    capture.close.outcome,
                    LogicalInferenceOutcome::Complete,
                    "{}",
                    context()
                );
                assert!(
                    capture.final_failure.is_none(),
                    "a single healthy provider attempt cannot fail below the boundary: {} (failure {:?}, status {:?})",
                    context(),
                    capture.final_failure,
                    capture.final_status
                );
                assert!(
                    capture.observation_error.is_none(),
                    "a known-good provider response cannot fail observation: {}",
                    context()
                );
                // The buffered answer is the provider's response
                // byte-for-byte under rewritten framing.
                assert_eq!(
                    scene.answer,
                    expected_full_answer(
                        200,
                        &[("content-type".to_owned(), "application/json".to_owned())],
                        b"{\"ok\":true}"
                    ),
                    "{}",
                    context()
                );
                // Forwarding: the decoded body byte-for-byte, and a
                // forwarded head whose every header is either the
                // route's own or the transport's standard framing —
                // no caller header survives the boundary.
                let forwarded = forwarded(&rx)
                    .unwrap_or_else(|| panic!("a captured exchange forwards: {}", context()));
                let head_text = std::str::from_utf8(&forwarded.raw_head)
                    .unwrap_or_else(|_| panic!("forwarded head is not UTF-8: {}", context()));
                let mut lines = head_text.split("\r\n").filter(|line| !line.is_empty());
                let request_line = lines.next().unwrap_or_default();
                assert!(
                    request_line.starts_with(&format!("POST {ROUTE} ")),
                    "forwarded request line is not the route's: {request_line:?}: {}",
                    context()
                );
                let headers: Vec<(&str, &str)> = lines
                    .map(|line| {
                        let (name, value) = line
                            .split_once(':')
                            .unwrap_or_else(|| panic!("unparseable forwarded header {line:?}"));
                        (name.trim(), value.trim())
                    })
                    .collect();
                for (name, _) in &headers {
                    assert!(
                        FORWARDED_HEADER_NAMES.contains(name),
                        "a header outside the boundary's set was forwarded: {name:?}: {headers:?}: {}",
                        context()
                    );
                }
                assert!(
                    headers.contains(&("content-type", "application/json")),
                    "{}",
                    context()
                );
                assert!(
                    headers.contains(&("authorization", format!("Bearer {CREDENTIAL}").as_str())),
                    "the forwarded authorization is not the route's: {headers:?}: {}",
                    context()
                );
                // The caller's planted secret rode in a header named
                // outside the boundary's set and in its own
                // authorization value; neither may appear.
                assert!(
                    !contains(&forwarded.raw_head, CALLER_SECRET.as_bytes()),
                    "the caller's planted header survived the boundary: {}",
                    context()
                );
                assert!(
                    !contains(&forwarded.raw_head, b"caller-credential"),
                    "the caller's own authorization survived the boundary: {}",
                    context()
                );
                // The forwarded body is the caller's decoded body:
                // exactly `content-length` bytes starting at the head's
                // first blank line. A mutated wire may carry MORE body
                // bytes than it declares (a spliced pipelining shape);
                // the proxy reads the declared prefix and leaves the
                // rest unread on the socket, so the oracle slices from
                // the head boundary, never from the wire's tail.
                let head_end = wire
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map_or(wire.len(), |position| position + 4);
                let head_text = String::from_utf8_lossy(&wire[..head_end]);
                let declared = head_text
                    .split("\r\n")
                    .find_map(|line| {
                        line.strip_prefix("content-length:")?
                            .trim()
                            .parse::<usize>()
                            .ok()
                    })
                    .unwrap_or(0);
                let expected_body = &wire[head_end..std::cmp::min(head_end + declared, wire.len())];
                assert_eq!(
                    forwarded.body,
                    expected_body,
                    "the forwarded body is not the caller's declared bytes: {}",
                    context()
                );
            }
        }
        assert_content_free(&scene, round);
    }
}

/// The refusal contract's closed vocabulary, swept exhaustively: every
/// token answers with its own status, a distinct evidence token, and a
/// fixed content-free body.
#[test]
fn refusal_tokens_are_the_bounded_contract() {
    let all = [
        Refusal::MalformedHead,
        Refusal::MethodNotAllowed,
        Refusal::UnknownRoute,
        Refusal::TransferFramed,
        Refusal::LengthRequired,
        Refusal::BodyOversized,
        Refusal::IncompleteBody,
        Refusal::Backpressured,
    ];
    let mut tokens: Vec<&'static str> = all.map(Refusal::token).to_vec();
    tokens.sort_unstable();
    tokens.dedup();
    assert_eq!(tokens.len(), all.len(), "evidence tokens collide");
    for refusal in all {
        let body = refusal.body_text();
        assert!(body.starts_with("{\"error\":{\"message\":"));
        assert!(body.ends_with("\"}}"));
        assert!(!body.contains("Bearer"));
    }
}

/// A declared body over the cap is refused without reading it, the
/// refusal is exactly the bounded answer, and nothing is forwarded or
/// archived.
#[test]
fn an_oversized_declared_body_is_refused_before_capture() {
    let (provider, rx) = spawn_provider(ok_json_response());
    let declared = DEFAULT_MAX_BODY_BYTES + 1;
    let caller =
        format!("POST {ROUTE} HTTP/1.1\r\nhost: fuzz\r\ncontent-length: {declared}\r\n\r\n");
    let scene = run_scene(caller.as_bytes(), provider);
    assert_eq!(
        scene.outcome,
        ExchangeOutcome::Refused(Refusal::BodyOversized)
    );
    let refusal = Refusal::BodyOversized;
    let expected = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        refusal.status(),
        refusal.reason(),
        refusal.body_text().len(),
        refusal.body_text()
    );
    assert_eq!(scene.answer, expected.as_bytes());
    assert!(archived(&scene).is_empty());
    assert!(forwarded(&rx).is_none(), "nothing was forwarded");
}

// ---------------------------------------------------------------------------
// Target 2: hostile provider responses through the relay
// ---------------------------------------------------------------------------

/// How the generated response frames its body on the wire.
#[derive(Clone, Copy, PartialEq)]
enum Framing {
    Length,
    Chunked,
    Eof,
}

/// One generated provider response: its wire bytes, what the boundary
/// is expected to decode from them, and the reference SSE event
/// sequence when the body streams.
struct GeneratedResponse {
    wire: Vec<u8>,
    status: u16,
    headers: Vec<(String, String)>,
    /// The exact bytes the boundary decodes, when the framing
    /// completes; `None` when it dies mid-decode.
    decoded: Option<Vec<u8>>,
    /// The reference SSE event sequence when the body streams.
    events: Option<Vec<Vec<u8>>>,
    truncated: bool,
}

/// A hostile-but-decodable body: usage-bearing JSON, plain JSON,
/// marker-bearing garbage, or an empty body.
fn generated_json_body(prng: &mut Prng) -> Vec<u8> {
    match prng.below(4) {
        0 => br#"{"id":"fuzz-1","usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}"#.to_vec(),
        1 => br#"{"id":"fuzz-2"}"#.to_vec(),
        2 => Vec::new(),
        _ => {
            let body_len = prng.below_usize(40);
            let mut body = prng.bytes(body_len);
            body.extend_from_slice(DENIED_MARKER.as_bytes());
            body
        }
    }
}

/// A hostile SSE body: data lines, framing lines, blank dispatches,
/// CRLF and LF mixes, interior `\r` padding, `[DONE]`, empty data
/// values, and an occasionally unterminated tail.
fn generated_sse_body(prng: &mut Prng) -> Vec<u8> {
    let mut body = Vec::new();
    let blocks = prng.below(5);
    for _ in 0..blocks {
        let data_lines = 1 + prng.below(3);
        for index in 0..data_lines {
            if prng.chance(25) {
                body.extend_from_slice(b"event: delta\r\n");
            }
            if prng.chance(15) {
                body.extend_from_slice(b": comment frame\r\n");
            }
            if prng.chance(15) {
                body.extend_from_slice(b"id: 7\r\n");
            }
            body.extend_from_slice(b"data:");
            if prng.chance(80) {
                body.push(b' ');
            }
            match prng.below(6) {
                0 => body.extend_from_slice(br#"{"choices":[{"delta":{"content":"a"}}]}"#),
                1 => body.extend_from_slice(b"[DONE]"),
                2 => {
                    let line_len = prng.below_usize(24);
                    let mut line = prng.bytes(line_len);
                    line.extend_from_slice(DENIED_MARKER.as_bytes());
                    // Interior \r padding: the hostile shape the SSE
                    // line split is graded on.
                    if prng.chance(50) {
                        line.push(b'\r');
                    }
                    body.extend_from_slice(&line);
                }
                3 => body.extend_from_slice(
                    br#"{"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}"#,
                ),
                // An empty data value.
                4 => {}
                _ => body.extend_from_slice(b"tail-bytes"),
            }
            if index + 1 < data_lines {
                body.push(b'\n');
            }
        }
        if prng.chance(60) {
            body.extend_from_slice(b"\r\n");
        } else {
            body.push(b'\n');
        }
    }
    if prng.chance(30) {
        // An unterminated final data line.
        body.extend_from_slice(b"data: tail");
    }
    body
}

/// Chunk `raw` into transfer-encoded bytes. When `truncate` is set a
/// final chunk declares 64 bytes and delivers 14, so the decode dies
/// mid-chunking after every real chunk was delivered.
fn chunk_encode(prng: &mut Prng, raw: &[u8], truncate: bool) -> Vec<u8> {
    let mut wire = Vec::new();
    let mut at = 0usize;
    while at < raw.len() {
        let take = 1 + prng.below_usize((raw.len() - at).max(1));
        let take = take.min(raw.len() - at);
        let size_line = if prng.chance(30) {
            format!("{take:X};ext=1\r\n")
        } else {
            format!("{take:x}\r\n")
        };
        wire.extend_from_slice(size_line.as_bytes());
        wire.extend_from_slice(&raw[at..at + take]);
        wire.extend_from_slice(if prng.chance(80) { b"\r\n" } else { b"\n" });
        at += take;
    }
    if truncate {
        wire.extend_from_slice(b"40\r\nonly-14-bytes\r\n");
        return wire;
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    wire
}

/// A generated provider response over the adversarial framing space the
/// bead names: content-length, chunked, and EOF framing; truncated
/// chunking; streaming and buffered bodies.
fn generate_provider_response(prng: &mut Prng) -> GeneratedResponse {
    let status = [200, 200, 200, 201, 400, 404, 429, 500, 503][prng.below_usize(9)];
    let streaming = prng.chance(55);
    let truncated_frame = prng.chance(30);
    let framing = if prng.chance(55) {
        Framing::Chunked
    } else if prng.chance(20) {
        Framing::Eof
    } else {
        Framing::Length
    };
    let truncated = truncated_frame && framing == Framing::Chunked;
    let content_type = if streaming {
        "text/event-stream"
    } else {
        "application/json"
    };

    let mut headers = vec![("content-type".to_owned(), content_type.to_owned())];
    if prng.chance(60) {
        headers.push((
            "x-request-id".to_owned(),
            format!("pr-{}", prng.below(1000)),
        ));
    }
    // Denial-shaped headers: recognized by no allowlist, relayed
    // verbatim (forwarding is faithful) but archived never.
    headers.push(("x-denied-marker".to_owned(), DENIED_MARKER.to_owned()));
    if prng.chance(30) {
        headers.push(("set-cookie".to_owned(), "fuzz=1; Path=/".to_owned()));
    }
    if prng.chance(25) {
        headers.push((
            "x-ratelimit-remaining-requests".to_owned(),
            format!("{}", prng.below(500)),
        ));
    }

    let raw = if streaming {
        generated_sse_body(prng)
    } else {
        generated_json_body(prng)
    };
    let (body_wire, decoded) = match framing {
        Framing::Chunked => {
            let wire = chunk_encode(prng, &raw, truncated);
            let decoded = if truncated { None } else { Some(raw.clone()) };
            (wire, decoded)
        }
        Framing::Length => (raw.clone(), Some(raw.clone())),
        Framing::Eof => {
            // No framing header at all: the boundary reads to the
            // provider's close, so bytes beyond the logical body are
            // decoded too.
            let mut all = raw.clone();
            if prng.chance(40) {
                all.extend_from_slice(b"--beyond-the-body--");
            }
            (all.clone(), Some(all))
        }
    };
    // The reference event sequence is computed over the exact bytes the
    // boundary decodes — never over the logical body alone.
    let decoded_bytes = decoded.clone().unwrap_or_default();
    let events = streaming.then(|| reference_sse_parse(&decoded_bytes));

    let phrase = known_reason_phrase(status);
    let mut wire = format!("HTTP/1.1 {status} {phrase}\r\n").into_bytes();
    for (name, value) in &headers {
        wire.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    match framing {
        Framing::Chunked => wire.extend_from_slice(b"transfer-encoding: chunked\r\n"),
        Framing::Length => {
            wire.extend_from_slice(format!("content-length: {}\r\n", body_wire.len()).as_bytes());
        }
        Framing::Eof => {}
    }
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(&body_wire);

    GeneratedResponse {
        wire,
        status,
        headers,
        decoded,
        events,
        truncated,
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one round walks every clause of the contract, read top to bottom
fn hostile_provider_responses_relay_faithfully_or_truncate_honestly() {
    let mut prng = Prng::new(0x0158_C25F);
    for round in 0..64u64 {
        let response = generate_provider_response(&mut prng);
        let caller_body = br#"{"model":"fuzz","messages":[]}"#;
        let mut caller = format!(
            "POST {ROUTE} HTTP/1.1\r\nhost: fuzz\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            caller_body.len()
        )
        .into_bytes();
        caller.extend_from_slice(caller_body);

        let (provider, rx) = spawn_provider(response.wire.clone());
        let proxy = CaptureProxy::bind(fuzz_config(provider)).expect("proxy binds");
        let address = proxy.local_addr();
        let caller = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("caller connects");
            let _ = stream.set_read_timeout(Some(HARNESS_IO_TIMEOUT));
            stream.write_all(&caller).expect("caller writes");
            let _ = stream.shutdown(Shutdown::Write);
            let mut answer = Vec::new();
            let _ = stream.read_to_end(&mut answer);
            answer
        });
        let report = proxy
            .serve_one(RecordingArtifactSink::new())
            .expect("accepts");
        let outcome = report.outcome().clone();
        let sink = report.into_sink();
        let answer = caller.join().expect("the caller thread finishes");
        let _ = forwarded(&rx);

        let context = || {
            format!(
                "round {round}\nprovider wire: {:?}\nanswer: {answer:?}",
                response.wire
            )
        };
        let ExchangeOutcome::Captured(capture) = outcome else {
            panic!("a valid caller request is never refused: {}", context());
        };
        assert_eq!(capture.attempts, 1, "{}", context());

        // The credential is never caller-facing, and neither the
        // credential nor the denial marker is ever archived — the
        // provider's own hostile headers relay faithfully to the caller
        // (forwarding is faithful), but the archive keeps the closed
        // allowlist alone.
        assert!(
            !contains(&answer, CREDENTIAL.as_bytes()),
            "round {round}: the caller answer carries the credential: {}",
            context()
        );
        for artifact in sink.artifacts() {
            let bytes = artifact.artifact().canonical_bytes();
            for marker in [DENIED_MARKER, CREDENTIAL] {
                assert!(
                    !contains(&bytes, marker.as_bytes()),
                    "round {round}: an archived artifact carries {marker:?}: {}",
                    context()
                );
            }
        }

        if response.truncated {
            // The framing died mid-chunk after every real chunk was
            // delivered: the report names the below-boundary class, and
            // nothing clean is fabricated.
            let failure = capture.final_failure.as_ref().unwrap_or_else(|| {
                panic!(
                    "a truncated body must fail below the boundary: {}",
                    context()
                )
            });
            if let Some(events) = &response.events {
                assert_eq!(
                    failure.class,
                    TransportErrorClass::StreamInterrupted,
                    "{}",
                    context()
                );
                let expected = (
                    expected_stream_head(response.status, &response.headers),
                    expected_stream_body(events, false),
                );
                assert_eq!(
                    answer,
                    expected
                        .0
                        .iter()
                        .copied()
                        .chain(expected.1)
                        .collect::<Vec<u8>>(),
                    "the truncated relay is not exactly head-plus-relayed-events: {}",
                    context()
                );
            } else {
                assert_eq!(
                    failure.class,
                    TransportErrorClass::ConnectionReset,
                    "{}",
                    context()
                );
                assert!(
                    answer.is_empty(),
                    "a buffered body that died below the boundary is never relayed: {}",
                    context()
                );
            }
            // Usage is recorded at the drain; a dead stream records none.
            let usage_artifacts = sink.artifacts().iter().filter(|recorded| {
                matches!(recorded.artifact().event, BoundaryEvent::Usage { .. })
            });
            assert_eq!(
                usage_artifacts.count(),
                0,
                "a stream that never drained recorded usage: {}",
                context()
            );
            continue;
        }

        let decoded = response
            .decoded
            .as_ref()
            .expect("a non-truncated framing completes");
        assert!(
            capture.final_failure.is_none(),
            "a complete framing cannot fail below the boundary: {}",
            context()
        );
        assert_eq!(capture.final_status, Some(response.status), "{}", context());
        match (&response.events, capture.streamed) {
            (Some(events), true) => {
                // The streamed relay is exactly the documented head, one
                // exact chunk per reference event, and the terminal
                // chunk — every frame decoding back to its event.
                let expected_answer = expected_stream_head(response.status, &response.headers)
                    .iter()
                    .copied()
                    .chain(expected_stream_body(events, true))
                    .collect::<Vec<u8>>();
                assert_eq!(answer, expected_answer, "{}", context());
                for event in events {
                    let frame = expected_frame(event);
                    assert_eq!(
                        reference_sse_parse(&frame),
                        vec![normalize_line_boundaries(event)],
                        "the relayed frame does not decode to the boundary's event: {}",
                        context()
                    );
                }
            }
            (None, false) => {
                assert_eq!(
                    answer,
                    expected_full_answer(response.status, &response.headers, decoded),
                    "{}",
                    context()
                );
            }
            (Some(_), false) | (None, true) => {
                panic!(
                    "relay mode disagrees with the response framing: {}",
                    context()
                )
            }
        }

        // Exactly one usage artifact when the decoded bytes declare
        // usage — from the body when buffered, from the reporting event
        // when streamed — with the extracted counters.
        let expected_usage = match &response.events {
            None => usage_from_bytes(decoded),
            Some(events) => events
                .iter()
                .rev()
                .find_map(|event| usage_from_bytes(event)),
        };
        let usage_artifacts: Vec<&InferenceArtifact> = sink
            .artifacts()
            .iter()
            .map(CanonicalArtifact::artifact)
            .filter(|artifact| matches!(artifact.event, BoundaryEvent::Usage { .. }))
            .collect();
        match expected_usage {
            Some(usage) => {
                assert_eq!(
                    usage_artifacts.len(),
                    1,
                    "usage-bearing bytes must record exactly one usage artifact: {}",
                    context()
                );
                let metadata = usage_artifacts[0]
                    .metadata
                    .as_ref()
                    .expect("a usage artifact carries its counters");
                assert_eq!(metadata.usage_input_tokens, Some(usage.input_tokens));
                assert_eq!(metadata.usage_output_tokens, Some(usage.output_tokens));
                assert_eq!(metadata.usage_total_tokens, Some(usage.total_tokens));
            }
            None => assert!(
                usage_artifacts.is_empty(),
                "usage was recorded from bytes that declare none: {}",
                context()
            ),
        }

        // The streamed events' sink records are dense and sized to the
        // decoded events; the allowlisted request-id is retained.
        if let Some(events) = &response.events {
            let stream_records: Vec<(u64, u64)> = sink
                .artifacts()
                .iter()
                .filter_map(|recorded| match recorded.artifact().event {
                    BoundaryEvent::StreamingEvent { event_ordinal } => {
                        let size = recorded
                            .artifact()
                            .payload
                            .as_ref()
                            .map_or(0, |payload| payload.payload_size);
                        Some((event_ordinal, size))
                    }
                    _ => None,
                })
                .collect();
            let non_empty = events.iter().filter(|event| !event.is_empty()).count();
            assert_eq!(
                stream_records.len(),
                non_empty,
                "stream records are not one per non-empty event: {} (events {events:?})",
                context()
            );
            for (ordinal, expected) in stream_records.iter().enumerate() {
                assert_eq!(ordinal as u64, expected.0, "{}", context());
                assert_eq!(
                    expected.1,
                    events[ordinal].len() as u64,
                    "record {} is not sized to its event: {}",
                    ordinal,
                    context()
                );
            }
            // Metadata rides the artifacts that exist: the buffered
            // response artifact, or the FIRST streamed event. A stream
            // whose body declares zero events produces no artifacts at
            // all, so there is nothing to carry the request-id — that
            // scene is honest truncation of the metadata channel, not a
            // retention failure.
            let any_metadata = sink
                .artifacts()
                .iter()
                .any(|recorded| recorded.artifact().metadata.is_some());
            if any_metadata {
                let request_ids: Vec<String> = sink
                    .artifacts()
                    .iter()
                    .filter_map(|recorded| recorded.artifact().metadata.as_ref())
                    .filter_map(|metadata| metadata.provider_request_id.clone())
                    .collect();
                if let Some((_, value)) = response
                    .headers
                    .iter()
                    .find(|(name, _)| name == "x-request-id")
                {
                    assert!(
                        request_ids.iter().any(|seen| seen == value),
                        "the allowlisted request-id was dropped: {}",
                        context()
                    );
                }
            }
        }
        assert_eq!(
            capture.close.outcome,
            LogicalInferenceOutcome::Complete,
            "{}",
            context()
        );
    }
}

// ---------------------------------------------------------------------------
// Target 3: the SSE decoder under arbitrary chunking
// ---------------------------------------------------------------------------

/// The pure decoder differential: a hostile byte stream fed in
/// randomized chunk splits must decode to exactly the reference parse
/// of the whole stream — chunk boundaries are never observable.
#[test]
fn sse_decoder_decodes_chunk_boundary_independently() {
    let mut prng = Prng::new(0x5EED_0003);
    for round in 0..512u64 {
        let raw = generated_sse_body(&mut prng);
        // Occasionally: fully arbitrary bytes, not SSE-shaped at all.
        let raw = if round % 5 == 4 {
            prng.bytes(raw.len())
        } else {
            raw
        };

        let mut decoder = SseDecoder::new();
        let mut assembled: Vec<Vec<u8>> = Vec::new();
        let mut at = 0usize;
        while at < raw.len() {
            let take = 1 + prng.below_usize((raw.len() - at).max(1));
            let take = take.min(raw.len() - at);
            decoder.feed(&raw[at..at + take]);
            at += take;
            while let Some(event) = decoder.take_complete_event() {
                assembled.push(event);
            }
        }
        while let Some(event) = decoder.take_complete_event() {
            assembled.push(event);
        }
        if let Some(event) = decoder.finish() {
            assembled.push(event);
        }
        // Idempotent ends: nothing remains after the flush.
        assert_eq!(decoder.finish(), None, "round {round}");
        assert_eq!(decoder.take_complete_event(), None, "round {round}");
        assert_eq!(
            assembled,
            reference_sse_parse(&raw),
            "chunked decode diverged from the reference parse, round {round}",
        );
    }
}

/// The transport-level decoder under hostile chunked framing: a real
/// `Http1Transport` against a chunked SSE body decodes exactly the
/// reference events, in order, and a truncated chunking is an error —
/// never a silent clean end.
#[test]
fn transport_stream_decode_matches_reference_under_hostile_chunking() {
    let mut prng = Prng::new(0x5EED_0004);
    for round in 0..48u64 {
        let raw = generated_sse_body(&mut prng);
        let truncated = prng.chance(30);
        let body = chunk_encode(&mut prng, &raw, truncated);
        let mut wire =
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n"
                .to_vec();
        wire.extend_from_slice(&body);

        let (provider, rx) = spawn_provider(wire.clone());
        let transport =
            Http1Transport::with_timeouts(Duration::from_secs(2), Duration::from_secs(5));
        let endpoint =
            WireEndpoint::new(provider.ip().to_string(), provider.port()).expect("loopback");
        let request = WireRequest {
            path: ROUTE.to_owned(),
            headers: vec![],
            body: Vec::new(),
        };
        let decoded = transport.execute(&endpoint, &request, DEFAULT_MAX_BODY_BYTES);
        let _ = rx.recv_timeout(Duration::from_secs(2));

        let context = || format!("round {round}\nwire: {wire:?}");
        if truncated {
            match decoded {
                Err(_) => {}
                Ok(response) => match response.body {
                    WireBody::Stream(mut events) => {
                        // The failure may surface on the first event or
                        // after some events; either way it surfaces.
                        loop {
                            match events.next_event() {
                                Ok(Some(_)) => {}
                                Ok(None) => panic!(
                                    "a truncated chunked body decoded as a clean end: {}",
                                    context()
                                ),
                                Err(_) => break,
                            }
                        }
                    }
                    WireBody::Full(_) => {
                        panic!(
                            "a text/event-stream response decoded as buffered: {}",
                            context()
                        )
                    }
                },
            }
            continue;
        }
        let response = decoded.expect("a complete body decodes");
        let WireBody::Stream(mut events) = response.body else {
            panic!(
                "a text/event-stream response decoded as buffered: {}",
                context()
            )
        };
        let mut decoded_events = Vec::new();
        while let Some(event) = events.next_event().expect("stream decodes") {
            decoded_events.push(event);
        }
        assert_eq!(
            decoded_events,
            reference_sse_parse(&raw),
            "transport decode diverged from the reference parse: {}",
            context()
        );
    }
}

// ---------------------------------------------------------------------------
// The body cap at its boundary
// ---------------------------------------------------------------------------

/// A streamed body whose cumulative decoded bytes cross the cap dies
/// below the boundary: the relay truncates mid-stream, the class names
/// the stream, and the terminal chunk is never fabricated.
#[test]
fn a_streamed_body_over_the_cap_truncates_without_the_terminal_chunk() {
    let mut raw = Vec::new();
    while raw.len() <= DEFAULT_MAX_BODY_BYTES + 64 {
        raw.extend_from_slice(b"data: {\"n\":1}\n\n");
    }
    let mut wire = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n",
        raw.len()
    )
    .into_bytes();
    wire.extend_from_slice(&raw);

    let (provider, rx) = spawn_provider(wire);
    let caller = format!("POST {ROUTE} HTTP/1.1\r\nhost: fuzz\r\ncontent-length: 2\r\n\r\n{{}}");
    let scene = run_scene(caller.as_bytes(), provider);
    let _ = forwarded(&rx);

    let ExchangeOutcome::Captured(capture) = scene.outcome else {
        panic!("a valid caller request is never refused");
    };
    let failure = capture
        .final_failure
        .expect("a cap-crossing stream dies below the boundary");
    // The cap is a boundary decision, not a wire failure: it carries the
    // transport's own "other" class, never a fabricated reset.
    assert_eq!(failure.class, TransportErrorClass::Other);
    assert!(capture.streamed, "the relay had already started");
    assert!(
        !scene.answer.ends_with(b"0\r\n\r\n"),
        "a truncated relay must not carry the terminal chunk: {:?}",
        scene.answer
    );
}

// ---------------------------------------------------------------------------
// Reductions — the concrete inputs the fuzz rounds flagged, pinned
// ---------------------------------------------------------------------------

/// Reduced from the relay fuzz rounds: a multi-line data block whose
/// first line ends in `\r` before the line separator. SSE wire framing
/// cannot represent a data line's trailing `\r` — it reads as a line
/// terminator to every spec-compliant decoder, the boundary's included
/// — so the caller's decode of the relayed frame is the boundary's
/// event with that one frame-boundary `\r` normalized away. The archive
/// still holds the event bytes exactly as the boundary decoded them.
#[test]
fn reduction_carriage_return_padded_multi_line_event_relays_to_the_same_decode() {
    let raw = b"data: alpha\r\r\ndata: beta\r\n\r\n";
    let boundary_events = reference_sse_parse(raw);
    assert_eq!(boundary_events, vec![b"alpha\r\nbeta".to_vec()]);

    let mut response =
        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: 28\r\n\r\n"
            .to_vec();
    response.extend_from_slice(raw);
    let (provider, rx) = spawn_provider(response);
    let caller = format!("POST {ROUTE} HTTP/1.1\r\nhost: fuzz\r\ncontent-length: 2\r\n\r\n{{}}");
    let scene = run_scene(caller.as_bytes(), provider);
    let _ = forwarded(&rx);

    let ExchangeOutcome::Captured(capture) = scene.outcome else {
        panic!("a valid caller request is never refused");
    };
    assert!(capture.streamed);
    assert!(capture.final_failure.is_none());
    let head = expected_stream_head(
        200,
        &[("content-type".to_owned(), "text/event-stream".to_owned())],
    );
    assert!(
        scene.answer.starts_with(&head),
        "answer: {:?}",
        scene.answer
    );
    let (frames, completed) = reference_chunk_parse(&scene.answer[head.len()..]);
    assert!(completed, "a drained stream owes its terminal chunk");
    assert_eq!(frames.len(), boundary_events.len());
    for (frame, event) in frames.iter().zip(&boundary_events) {
        assert_eq!(
            reference_sse_parse(frame),
            vec![normalize_line_boundaries(event)],
            "the relayed frame does not decode to the normalized boundary event"
        );
    }
}

/// Reduced from the truncation grammar: a chunked body whose terminal
/// chunk is withheld ends the relay without one and names the
/// interruption — never a fabricated clean end.
#[test]
fn reduction_withheld_terminal_chunk_relays_as_truncated() {
    let raw = b"data: one\n\n";
    let body = chunk_encode(&mut Prng::new(7), raw, false);
    let cut = body
        .windows(5)
        .position(|window| window == b"0\r\n\r\n")
        .expect("the encoder wrote a terminal chunk");
    let body = &body[..cut];
    let mut wire =
        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n"
            .to_vec();
    wire.extend_from_slice(body);

    let (provider, rx) = spawn_provider(wire);
    let caller = format!("POST {ROUTE} HTTP/1.1\r\nhost: fuzz\r\ncontent-length: 2\r\n\r\n{{}}");
    let scene = run_scene(caller.as_bytes(), provider);
    let _ = forwarded(&rx);

    let ExchangeOutcome::Captured(capture) = scene.outcome else {
        panic!("a valid caller request is never refused");
    };
    let failure = capture
        .final_failure
        .expect("the framing died below the boundary");
    assert_eq!(failure.class, TransportErrorClass::StreamInterrupted);
    assert!(!scene.answer.ends_with(b"0\r\n\r\n"));
}
