// SPDX-License-Identifier: Apache-2.0

//! The exact-capture conformance suite for the explicitly routed
//! OpenAI-compatible capture proxy (plan Phase 9; threat `EC-04`).
//!
//! [`ProxyConformance::run`] drives the real [`crate::openai_proxy`]
//! proxy — bound to a loopback port, serving its one declared route —
//! against a caller-supplied provider fixture scripted one connection
//! at a time, with the suite's caller writing real HTTP/1.1 requests
//! to the proxy and reading exactly what the proxy relays back. A
//! passing run proves at that boundary:
//!
//! - a **single exchange** captures the decoded request and response
//!   byte-for-byte and extracts usage, exactly as the first-party
//!   client's own conformance run does;
//! - a **multi-event stream** relays the provider's SSE events in
//!   order behind chunked framing and records each with its dense
//!   ordinal, usage joined to its reporting event;
//! - an **ordered retry** opens a fresh attempt identity that cites
//!   its closed predecessor, so the two attempts stay reconstructable
//!   and are never merged into one;
//! - a **transport error** below the boundary is classified, never
//!   decoded, and the caller's connection closes without a fabricated
//!   provider response;
//! - **forwarding is faithful**: the provider's status, headers, and
//!   exact decoded bytes reach the caller as they left the provider;
//! - the **conformance credential never appears in a captured
//!   artifact or its metadata** — not the route's own credential, not
//!   the caller's dropped headers, not a hostile provider echo; and
//! - **buffering stays bounded**: under a scripted slow-drain caller
//!   the provider itself stalls, because the relay holds at most one
//!   decoded event and backpressures the provider's socket instead of
//!   growing.
//!
//! A run that passes every scene is the only producer of the proxy
//! route's [`QualifiedRoute`] evidence, minted through the crate-
//! private mint for the compatibility matrix to record.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use archivist_protocol::derivation::blob_digest;
use archivist_protocol::inference_artifact::BoundaryEvent;
#[cfg(test)]
use archivist_protocol::inference_artifact::Metadata;
use archivist_protocol::sha256::{digest, encode_hex};
use archivist_protocol::vocabulary::{
    InferenceArtifactKind as ArtifactKind, RetryReason, TransportErrorClass, UsageSource,
};

use crate::compatibility::{FIRST_PARTY_OPENAI_PROXY, QualifiedRoute};
use crate::inference_observer::{
    CanonicalArtifact, FlushState, INFERENCE_OBSERVER_VERSION, LogicalInferenceOutcome,
};
use crate::openai_compat::{OpenAiEndpoint, RetryPolicy};
use crate::openai_conformance::{
    COMPLETION_BODY, CONFORMANCE_CREDENTIAL, ConformanceError, ConformanceSink, ReceivedExchange,
    chat_body, chunked_stream, origin, raw_response, split_request, sse_frame, success_response,
    tenant,
};
use crate::openai_http1::{Http1Transport, TransportFailure, WireEndpoint};
use crate::openai_proxy::{CaptureProxy, ExchangeOutcome, ProxyConfig, ProxyExchangeReport};

/// One scripted provider connection: what the fixture does after
/// reading the proxy's forwarded request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyWireScript {
    /// Write these raw bytes after the request, then close. The bytes
    /// are a complete HTTP/1.1 response exactly as it should appear on
    /// the wire — the suite builds them with the shared response
    /// builders.
    Raw(Vec<u8>),
    /// Read the request, then drop the connection without a response —
    /// the below-the-boundary teardown the proxy must classify as a
    /// transport error, never decode.
    Reset,
    /// Write `head`, then every chunk in order, then `terminal`, under
    /// a write deadline with would-block retries. Every byte that
    /// reaches the wire is counted into the fixture's measured
    /// progress — the observable the bounded-relay scene samples while
    /// its caller refuses to drain.
    MeasuredStream {
        /// The response head, written first.
        head: Vec<u8>,
        /// One chunked-transfer chunk per streamed event, written in
        /// order.
        chunks: Vec<Vec<u8>>,
        /// The terminal chunk, written last.
        terminal: Vec<u8>,
    },
}

/// The provider fixture the proxy suite drives: a real loopback TCP
/// server the proxy's own transport connects to, scripted one
/// connection at a time, with the measured-stream observables the
/// bounded-relay scene samples.
pub trait ProxyWireFixture {
    /// The endpoint every provider attempt of this run connects to.
    /// The fixture is bound before the run starts; the address is
    /// stable.
    ///
    /// # Errors
    /// [`ConformanceError::EndpointInvalid`] when the fixture cannot
    /// present a bounded endpoint.
    fn endpoint(&mut self) -> Result<WireEndpoint, ConformanceError>;

    /// Script the next accepted connection.
    fn queue(&mut self, script: ProxyWireScript);

    /// The raw request bytes of every served exchange, in order — a
    /// snapshot, so a threaded fixture can hand the suite its record
    /// without holding a lock across the check.
    fn received(&self) -> Vec<ReceivedExchange>;

    /// The provider-side bytes written so far for the measured stream.
    fn measured_progress(&self) -> usize;

    /// Whether the measured stream finished writing to the wire.
    fn measured_done(&self) -> bool;
}

/// One proxy conformance scene, by identity. Every scene exercises the
/// proxy through its public API only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProxySceneId {
    /// One routed request and one buffered response: request, response,
    /// usage, metadata, and a faithful relay.
    SingleExchange,
    /// A multi-event SSE response behind chunked framing: ordered
    /// events, dense ordinals, stream-event usage.
    StreamedRelay,
    /// A decoded 429 retried to completion: two attempts, two
    /// identities, one citation — reconstructable, never merged.
    OrderedRetry,
    /// A connection dropped below the boundary: classified, captured,
    /// and never answered with a fabricated response.
    TransportErrorBelow,
    /// A terminal non-200 provider response forwarded with its status,
    /// headers, and exact bytes intact.
    FaithfulForwarding,
    /// The conformance credential, the caller's dropped headers, and a
    /// hostile provider echo appear in no captured artifact.
    CredentialExclusion,
    /// A scripted slow-drain caller cannot grow the relay: the provider
    /// stalls, then finishes every byte once the caller drains.
    BoundedRelay,
}

impl ProxySceneId {
    /// Every scene in run order.
    #[must_use]
    pub const fn all() -> [Self; 7] {
        [
            Self::SingleExchange,
            Self::StreamedRelay,
            Self::OrderedRetry,
            Self::TransportErrorBelow,
            Self::FaithfulForwarding,
            Self::CredentialExclusion,
            Self::BoundedRelay,
        ]
    }

    /// The bounded scene token used in evidence and reports.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::SingleExchange => "single-exchange",
            Self::StreamedRelay => "streamed-relay",
            Self::OrderedRetry => "ordered-retry",
            Self::TransportErrorBelow => "transport-error-below",
            Self::FaithfulForwarding => "faithful-forwarding",
            Self::CredentialExclusion => "credential-exclusion",
            Self::BoundedRelay => "bounded-relay",
        }
    }
}

/// One bounded conformance check, by identity. A failed check names the
/// property that did not hold — never the payload bytes that tripped
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProxyCheckId {
    /// The fixture and the proxy could be constructed.
    FixtureReady,
    /// The scripted exchange ran to a close report.
    ExchangeRan,
    /// The lifecycle close reported the bounded outcome and flush
    /// state.
    TeardownOutcome,
    /// The wire-level attempt summary matched the scene's script.
    WireOutcome,
    /// The provider received the route's own request: the caller's
    /// body under the route's credential, the caller's headers dropped.
    ForwardedRequest,
    /// The emitted artifact kind sequence matched.
    ArtifactKinds,
    /// Captured payload digests matched the wire bytes.
    PayloadBytes,
    /// Event ordinals were dense and ordered.
    EventOrdering,
    /// Response metadata carried exactly the allowlisted entries.
    MetadataEntries,
    /// Usage counters matched the provider report.
    UsageCounters,
    /// The retry record cited its closed predecessor with the right
    /// reason.
    RetryCitation,
    /// The attempts stayed distinct and individually reconstructable.
    AttemptIdentity,
    /// What the caller received was the provider's own answer.
    CallerRelay,
    /// No credential material appeared in any artifact.
    CredentialExcluded,
    /// The relay stayed bounded under the slow-drain caller.
    BufferBound,
}

/// The result of one scene.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxySceneOutcome {
    /// Which scene ran.
    pub scene: ProxySceneId,
    /// Whether every check held.
    pub passed: bool,
    /// The checks that failed, in check order.
    pub failed_checks: Vec<ProxyCheckId>,
    /// How many canonical artifacts the scene's sink accepted.
    pub artifacts: usize,
}

impl ProxySceneOutcome {
    /// Whether the scene passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }
}

/// The full result of one proxy conformance run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyConformanceReport {
    scenes: Vec<ProxySceneOutcome>,
    qualification: Option<QualifiedRoute>,
}

impl ProxyConformanceReport {
    /// Every scene outcome, in run order.
    #[must_use]
    pub fn scenes(&self) -> &[ProxySceneOutcome] {
        &self.scenes
    }

    /// Whether every scene passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.scenes.iter().all(ProxySceneOutcome::passed)
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
        self.qualification
            .as_ref()
            .map(QualifiedRoute::evidence_digest)
    }
}

/// The proxy conformance suite.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxyConformance;

impl ProxyConformance {
    /// Run every scene against fresh fixtures from `factory`, in run
    /// order. A run in which every scene passes mints the proxy route's
    /// qualification through the crate-private mint; any other run
    /// mints nothing.
    pub fn run(mut factory: impl FnMut() -> Box<dyn ProxyWireFixture>) -> ProxyConformanceReport {
        let mut scenes = Vec::new();
        for scene in ProxySceneId::all() {
            let mut fixture = factory();
            let outcome = match scene {
                ProxySceneId::SingleExchange => scene_single_exchange(&mut *fixture),
                ProxySceneId::StreamedRelay => scene_streamed_relay(&mut *fixture),
                ProxySceneId::OrderedRetry => scene_ordered_retry(&mut *fixture),
                ProxySceneId::TransportErrorBelow => scene_transport_error(&mut *fixture),
                ProxySceneId::FaithfulForwarding => scene_faithful_forwarding(&mut *fixture),
                ProxySceneId::CredentialExclusion => scene_credential_exclusion(&mut *fixture),
                ProxySceneId::BoundedRelay => scene_bounded_relay(&mut *fixture),
            };
            scenes.push(outcome);
        }
        let passed = scenes.iter().all(ProxySceneOutcome::passed);
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
            QualifiedRoute::new_proxy(
                FIRST_PARTY_OPENAI_PROXY,
                INFERENCE_OBSERVER_VERSION,
                encode_hex(&digest(evidence.as_bytes())),
            )
        });
        ProxyConformanceReport {
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
    scene: ProxySceneId,
    failed: Vec<ProxyCheckId>,
}

impl Checks {
    fn new(scene: ProxySceneId) -> Self {
        Self {
            scene,
            failed: Vec::new(),
        }
    }

    fn require(&mut self, held: bool, check: ProxyCheckId) {
        if !held && !self.failed.contains(&check) {
            self.failed.push(check);
        }
    }

    fn finish(self, artifacts: usize) -> ProxySceneOutcome {
        ProxySceneOutcome {
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
fn step<T, E>(attempted: Result<T, E>, checks: &mut Checks, check: ProxyCheckId) -> SceneStep<T> {
    attempted.map_err(|_| {
        checks.require(false, check);
        SceneAbort
    })
}

/// Bind the scene's proxy against the fixture's endpoint: the route's
/// credential is the shared [`CONFORMANCE_CREDENTIAL`], whose exclusion
/// from every artifact the scenes assert.
fn scene_proxy(
    fixture: &mut dyn ProxyWireFixture,
    checks: &mut Checks,
    policy: RetryPolicy,
    max_body_bytes: usize,
) -> SceneStep<CaptureProxy> {
    let wire = step(fixture.endpoint(), checks, ProxyCheckId::FixtureReady)?;
    let identity = step(
        tenant().and_then(|tenant| origin().map(|origin| (tenant, origin))),
        checks,
        ProxyCheckId::FixtureReady,
    )?;
    let endpoint = step(
        OpenAiEndpoint::new(
            wire.host().to_owned(),
            wire.port(),
            CONFORMANCE_CREDENTIAL.to_owned(),
        ),
        checks,
        ProxyCheckId::FixtureReady,
    )?;
    let config = ProxyConfig::new(identity.0, identity.1, endpoint)
        .with_transport(Http1Transport::with_timeouts(
            Duration::from_secs(2),
            Duration::from_secs(10),
        ))
        .with_retry_policy(policy)
        .with_max_body_bytes(max_body_bytes);
    step(
        CaptureProxy::bind(config),
        checks,
        ProxyCheckId::FixtureReady,
    )
}

/// The bounded HTTP/1.1 request the scene's caller writes to the proxy:
/// a bounded `POST` to the declared route with the caller's decoded
/// body and any extra headers the scene plants.
fn caller_request(route: &str, body: &[u8], extra_headers: &[(&str, &str)]) -> Vec<u8> {
    let mut request = format!("POST {route} HTTP/1.1\r\nhost: harness\r\n");
    for (name, value) in extra_headers {
        let _ = write!(request, "{name}: {value}\r\n");
    }
    let _ = write!(request, "content-length: {}\r\n\r\n", body.len());
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Serve one connection and drive one caller exchange against it: the
/// caller writes `request`, reads the relay to the proxy's close, and
/// the exchange report comes back with its sink.
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

/// One relayed response's status line, its lowercase header pairs, and
/// its body.
type RelayedParts<'a> = (String, Vec<(String, String)>, &'a [u8]);

/// Split a relayed response into its status line, its lowercase header
/// pairs, and its body.
fn split_relay(relayed: &[u8]) -> Option<RelayedParts<'_>> {
    let position = relayed
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&relayed[..position]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.to_owned();
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect::<Option<Vec<_>>>()?;
    Some((status, headers, &relayed[position + 4..]))
}

/// The first position at or after `from` where `needle` occurs.
fn contains_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    (from..=hay.len().saturating_sub(needle.len()))
        .find(|&start| &hay[start..start + needle.len()] == needle)
}

/// The bodies the fixture received, in order.
fn forwarded_bodies(fixture: &dyn ProxyWireFixture) -> Vec<Vec<u8>> {
    fixture
        .received()
        .iter()
        .map(|exchange| split_request(&exchange.raw_request).1.to_vec())
        .collect()
}

/// The kind sequence of every artifact the sink accepted.
fn kinds(artifacts: &[CanonicalArtifact]) -> Vec<ArtifactKind> {
    artifacts
        .iter()
        .map(|artifact| artifact.artifact().kind())
        .collect()
}

/// The kind sequence of one attempt's artifacts.
fn kinds_at(artifacts: &[CanonicalArtifact], ordinal: u64) -> Vec<ArtifactKind> {
    artifacts
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

/// Whether any captured artifact carries `needles` in its canonical
/// bytes or its rendered record — the credential-exclusion check. A
/// record's payload bytes never render into the record: the record
/// carries the payload digest by construction, so the channels a
/// capture bug can leak through are the record's own fields —
/// metadata, event members, unknown fields. The Debug rendering
/// patrols the same record a second way, so a field type whose
/// canonical form escapes text cannot carry the material silently
/// either. The negative-detection unit test below poisons the opaque
/// `provider_request_id` metadata field through the real lifecycle, so
/// a mapping bug that copies credential material into a record field
/// demonstrably fails this check.
fn artifacts_leak_any(artifacts: &[CanonicalArtifact], needles: &[&[u8]]) -> bool {
    artifacts.iter().any(|artifact| {
        let canonical = artifact.canonical_bytes();
        let debug = format!("{:?}", artifact.artifact());
        needles.iter().any(|needle| {
            canonical
                .windows(needle.len())
                .any(|window| window == *needle)
                || std::str::from_utf8(needle).is_ok_and(|text| debug.contains(text))
        })
    })
}

/// Whether sampled provider-write progress ended in a stall: the last
/// value the samples held must have held unchanged across at least
/// `quiet` of sampling. A relay that buffered the stream would keep the
/// provider writing — strictly increasing progress, no quiet suffix —
/// and this classifier refuses to call that a stall, which is what
/// makes the bounded-relay scene's check fail on a violated invariant.
fn stall_observed(samples: &[(Duration, usize)], quiet: Duration) -> bool {
    let Some(&(start, first)) = samples.first() else {
        return false;
    };
    let mut last_value = first;
    let mut last_change = start;
    for &(at, value) in &samples[1..] {
        if value != last_value {
            last_value = value;
            last_change = at;
        }
    }
    samples.last().is_some_and(|&(end, end_value)| {
        end_value == last_value && end.saturating_sub(last_change) >= quiet
    })
}

/// How long the bounded-relay scene samples before it accepts a stall.
const QUIET_WINDOW: Duration = Duration::from_millis(800);
/// How often the bounded-relay scene samples provider progress.
const SAMPLE_PERIOD: Duration = Duration::from_millis(20);

// ---------------------------------------------------------------------
// Scenes
// ---------------------------------------------------------------------

fn scene_single_exchange(fixture: &mut dyn ProxyWireFixture) -> ProxySceneOutcome {
    let mut checks = Checks::new(ProxySceneId::SingleExchange);
    let artifacts = single_exchange(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

#[allow(clippy::too_many_lines)] // one scripted scene, read top to bottom
fn single_exchange(checks: &mut Checks, fixture: &mut dyn ProxyWireFixture) -> SceneStep<usize> {
    let body = chat_body(false);
    fixture.queue(ProxyWireScript::Raw(success_response()));
    let proxy = scene_proxy(
        fixture,
        checks,
        RetryPolicy {
            max_attempts: 1,
            backoff_ms: 0,
        },
        crate::openai_http1::DEFAULT_MAX_BODY_BYTES,
    )?;
    let (relayed, report) = serve_and_read(&proxy, &caller_request(proxy.route(), &body, &[]));

    {
        let ExchangeOutcome::Captured(capture) = report.outcome() else {
            checks.require(false, ProxyCheckId::ExchangeRan);
            return Err(SceneAbort);
        };
        checks.require(
            capture.close.outcome == LogicalInferenceOutcome::Complete
                && capture.close.flush_state == FlushState::Acknowledged
                && capture.close.failure.is_none()
                && capture.observation_error.is_none(),
            ProxyCheckId::TeardownOutcome,
        );
        checks.require(
            capture.attempts == 1
                && capture.final_status == Some(200)
                && capture.final_failure.is_none()
                && !capture.streamed,
            ProxyCheckId::WireOutcome,
        );
    }

    let sink = report.into_sink();
    let artifacts = sink.artifacts();
    checks.require(
        kinds(artifacts)
            == [
                ArtifactKind::ProviderRequest,
                ArtifactKind::ProviderResponse,
                ArtifactKind::Usage,
            ],
        ProxyCheckId::ArtifactKinds,
    );
    checks.require(
        artifacts
            .first()
            .is_some_and(|artifact| payload_is(artifact, &body)),
        ProxyCheckId::PayloadBytes,
    );
    checks.require(
        artifacts
            .get(1)
            .is_some_and(|artifact| payload_is(artifact, COMPLETION_BODY.as_bytes())),
        ProxyCheckId::PayloadBytes,
    );
    // The provider received exactly the routed body...
    checks.require(
        forwarded_bodies(fixture)
            .first()
            .is_some_and(|received| received == &body),
        ProxyCheckId::ForwardedRequest,
    );
    // ...under the route's own credential, on the route's own request
    // shape — the caller's headers ride nowhere.
    checks.require(
        fixture.received().first().is_some_and(|exchange| {
            let (head, _) = split_request(&exchange.raw_request);
            let head = String::from_utf8_lossy(head);
            head.contains(&format!("POST {} HTTP/1.1", proxy.route()))
                && head.contains(&format!("authorization: Bearer {CONFORMANCE_CREDENTIAL}"))
                && head.contains("content-type: application/json")
        }),
        ProxyCheckId::ForwardedRequest,
    );
    if let Some(response) = artifacts.get(1) {
        let metadata = response.artifact().metadata.as_ref();
        checks.require(
            metadata.is_some_and(|metadata| {
                metadata.content_type.as_deref() == Some("application/json")
                    && metadata.provider_request_id.as_deref() == Some("req-conformance-1")
                    && metadata.http_status == Some(200)
            }),
            ProxyCheckId::MetadataEntries,
        );
    } else {
        checks.require(false, ProxyCheckId::MetadataEntries);
    }
    if let Some(usage) = artifacts.get(2) {
        checks.require(
            usage.artifact().event
                == BoundaryEvent::Usage {
                    usage_source: UsageSource::ResponseBody,
                }
                && usage.artifact().metadata.as_ref().is_some_and(|metadata| {
                    metadata.usage_input_tokens == Some(3)
                        && metadata.usage_output_tokens == Some(5)
                        && metadata.usage_total_tokens == Some(8)
                }),
            ProxyCheckId::UsageCounters,
        );
    } else {
        checks.require(false, ProxyCheckId::UsageCounters);
    }
    // The caller was relayed the provider's own answer.
    checks.require(
        relayed.starts_with(b"HTTP/1.1 200 OK\r\n")
            && relayed.ends_with(COMPLETION_BODY.as_bytes()),
        ProxyCheckId::CallerRelay,
    );
    Ok(artifacts.len())
}

fn scene_streamed_relay(fixture: &mut dyn ProxyWireFixture) -> ProxySceneOutcome {
    let mut checks = Checks::new(ProxySceneId::StreamedRelay);
    let artifacts = streamed_relay(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

#[allow(clippy::too_many_lines)] // one scripted scene, read top to bottom
fn streamed_relay(checks: &mut Checks, fixture: &mut dyn ProxyWireFixture) -> SceneStep<usize> {
    let body = chat_body(true);
    let events: Vec<Vec<u8>> = vec![
        br#"{"id":"s-1","choices":[{"delta":{"content":"hel"}}]}"#.to_vec(),
        br#"{"id":"s-1","choices":[{"delta":{"content":"lo"}}]}"#.to_vec(),
        br#"{"id":"s-1","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#.to_vec(),
        b"[DONE]".to_vec(),
    ];
    let frames: Vec<Vec<u8>> = events.iter().map(|event| sse_frame(event)).collect();
    fixture.queue(ProxyWireScript::Raw(chunked_stream(
        &[("x-request-id", "req-conformance-2")],
        &frames,
    )));
    let proxy = scene_proxy(
        fixture,
        checks,
        RetryPolicy {
            max_attempts: 1,
            backoff_ms: 0,
        },
        crate::openai_http1::DEFAULT_MAX_BODY_BYTES,
    )?;
    let (relayed, report) = serve_and_read(&proxy, &caller_request(proxy.route(), &body, &[]));

    {
        let ExchangeOutcome::Captured(capture) = report.outcome() else {
            checks.require(false, ProxyCheckId::ExchangeRan);
            return Err(SceneAbort);
        };
        checks.require(
            capture.close.outcome == LogicalInferenceOutcome::Complete
                && capture.close.flush_state == FlushState::Acknowledged
                && capture.observation_error.is_none(),
            ProxyCheckId::TeardownOutcome,
        );
        checks.require(
            capture.streamed && capture.attempts == 1 && capture.final_status == Some(200),
            ProxyCheckId::WireOutcome,
        );
    }

    let sink = report.into_sink();
    let artifacts = sink.artifacts();
    checks.require(
        kinds(artifacts)
            == [
                ArtifactKind::ProviderRequest,
                ArtifactKind::StreamingEvent,
                ArtifactKind::StreamingEvent,
                ArtifactKind::StreamingEvent,
                ArtifactKind::StreamingEvent,
                ArtifactKind::Usage,
            ],
        ProxyCheckId::ArtifactKinds,
    );
    checks.require(
        artifacts
            .first()
            .is_some_and(|artifact| payload_is(artifact, &body)),
        ProxyCheckId::PayloadBytes,
    );
    // Every decoded event, in order, is exactly the data payload the
    // provider framed — dense ordinals across the relay.
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
            ProxyCheckId::EventOrdering,
        );
    }
    // The response head's allowlisted metadata rides the first event
    // only; later events carry none.
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
        }) && artifacts
            .get(2)
            .is_some_and(|artifact| artifact.artifact().metadata.is_none()),
        ProxyCheckId::MetadataEntries,
    );
    // The usage record is joined to the reporting event's bytes.
    checks.require(
        artifacts.last().is_some_and(|artifact| {
            artifact.artifact().event
                == BoundaryEvent::Usage {
                    usage_source: UsageSource::StreamEvent,
                }
                && artifact
                    .artifact()
                    .payload
                    .as_ref()
                    .is_some_and(|payload| payload.payload_digest == blob_digest(&events[2]))
                && artifact
                    .artifact()
                    .metadata
                    .as_ref()
                    .is_some_and(|metadata| {
                        metadata.usage_input_tokens == Some(3)
                            && metadata.usage_output_tokens == Some(5)
                            && metadata.usage_total_tokens == Some(8)
                    })
        }),
        ProxyCheckId::UsageCounters,
    );
    checks.require(
        !kinds(artifacts).contains(&ArtifactKind::ProviderResponse),
        ProxyCheckId::ArtifactKinds,
    );
    // The caller received every event, in order, and an honest
    // terminal chunk.
    let mut cursor = 0;
    for event in &events {
        let mut needle = b"data: ".to_vec();
        needle.extend_from_slice(event);
        let found = contains_from(&relayed, &needle, cursor);
        checks.require(found.is_some(), ProxyCheckId::CallerRelay);
        if let Some(found) = found {
            cursor = found;
        }
    }
    checks.require(relayed.ends_with(b"0\r\n\r\n"), ProxyCheckId::CallerRelay);
    Ok(artifacts.len())
}

fn scene_ordered_retry(fixture: &mut dyn ProxyWireFixture) -> ProxySceneOutcome {
    let mut checks = Checks::new(ProxySceneId::OrderedRetry);
    let artifacts = ordered_retry(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

#[allow(clippy::too_many_lines)] // one scripted scene, read top to bottom
fn ordered_retry(checks: &mut Checks, fixture: &mut dyn ProxyWireFixture) -> SceneStep<usize> {
    let body = chat_body(false);
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
    fixture.queue(ProxyWireScript::Raw(rejected));
    fixture.queue(ProxyWireScript::Raw(success_response()));
    let proxy = scene_proxy(
        fixture,
        checks,
        RetryPolicy {
            max_attempts: 2,
            backoff_ms: 0,
        },
        crate::openai_http1::DEFAULT_MAX_BODY_BYTES,
    )?;
    let (relayed, report) = serve_and_read(&proxy, &caller_request(proxy.route(), &body, &[]));

    {
        let ExchangeOutcome::Captured(capture) = report.outcome() else {
            checks.require(false, ProxyCheckId::ExchangeRan);
            return Err(SceneAbort);
        };
        checks.require(
            capture.close.outcome == LogicalInferenceOutcome::Complete
                && capture.close.flush_state == FlushState::Acknowledged,
            ProxyCheckId::TeardownOutcome,
        );
        checks.require(
            capture.attempts == 2 && capture.final_status == Some(200),
            ProxyCheckId::WireOutcome,
        );
    }

    let sink = report.into_sink();
    let artifacts = sink.artifacts();
    // Attempt 0: the decoded failure response was captured — a 429 with
    // its payload is evidence, not silence.
    checks.require(
        kinds_at(artifacts, 0)
            == [
                ArtifactKind::ProviderRequest,
                ArtifactKind::ProviderResponse,
            ],
        ProxyCheckId::ArtifactKinds,
    );
    checks.require(
        artifacts.get(1).is_some_and(|artifact| {
            artifact
                .artifact()
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.http_status == Some(429))
        }),
        ProxyCheckId::MetadataEntries,
    );
    // The retry cites its closed predecessor, under the successor's
    // identity.
    checks.require(
        artifacts.iter().any(|artifact| {
            artifact.artifact().attempt_ordinal == 1
                && artifact.artifact().kind() == ArtifactKind::Retry
                && artifact.artifact().event
                    == BoundaryEvent::Retry {
                        retry_of_attempt_ordinal: 0,
                        retry_reason: RetryReason::RateLimit,
                        backoff_ms: Some(0),
                    }
        }),
        ProxyCheckId::RetryCitation,
    );
    checks.require(
        kinds_at(artifacts, 1)
            == [
                ArtifactKind::Retry,
                ArtifactKind::ProviderRequest,
                ArtifactKind::ProviderResponse,
                ArtifactKind::Usage,
            ],
        ProxyCheckId::ArtifactKinds,
    );
    // Two attempts, two identities: the retry never reuses or merges
    // the rate-limited attempt's identity, and each attempt's records
    // group under exactly one of them.
    let request_ids: Vec<_> = artifacts
        .iter()
        .filter(|artifact| artifact.artifact().kind() == ArtifactKind::ProviderRequest)
        .map(|artifact| artifact.artifact().provider_attempt_id.clone())
        .collect();
    checks.require(
        request_ids.len() == 2 && request_ids[0] != request_ids[1],
        ProxyCheckId::AttemptIdentity,
    );
    for artifact in artifacts {
        let expected = if artifact.artifact().attempt_ordinal == 0 {
            &request_ids[0]
        } else {
            &request_ids[1]
        };
        checks.require(
            &artifact.artifact().provider_attempt_id == expected,
            ProxyCheckId::AttemptIdentity,
        );
    }
    // The retried request forwarded the same bytes on a fresh identity,
    // so the attempts reconstruct side by side.
    checks.require(
        forwarded_bodies(fixture) == vec![body.clone(), body],
        ProxyCheckId::PayloadBytes,
    );
    // The caller saw only the final attempt's answer — nothing of the
    // rate-limited one leaked into the relay.
    checks.require(
        relayed.starts_with(b"HTTP/1.1 200 OK\r\n")
            && relayed.ends_with(COMPLETION_BODY.as_bytes())
            && !relayed.windows(3).any(|window| window == b"429")
            && !relayed
                .windows(b"rate_limit_error".len())
                .any(|window| window == b"rate_limit_error"),
        ProxyCheckId::CallerRelay,
    );
    Ok(artifacts.len())
}

fn scene_transport_error(fixture: &mut dyn ProxyWireFixture) -> ProxySceneOutcome {
    let mut checks = Checks::new(ProxySceneId::TransportErrorBelow);
    let artifacts = transport_error(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

fn transport_error(checks: &mut Checks, fixture: &mut dyn ProxyWireFixture) -> SceneStep<usize> {
    let body = chat_body(false);
    fixture.queue(ProxyWireScript::Reset);
    let proxy = scene_proxy(
        fixture,
        checks,
        RetryPolicy {
            max_attempts: 1,
            backoff_ms: 0,
        },
        crate::openai_http1::DEFAULT_MAX_BODY_BYTES,
    )?;
    let (relayed, report) = serve_and_read(&proxy, &caller_request(proxy.route(), &body, &[]));

    let ExchangeOutcome::Captured(capture) = report.outcome() else {
        checks.require(false, ProxyCheckId::ExchangeRan);
        return Err(SceneAbort);
    };
    // The attempt was observed even though it failed below the
    // boundary: the observation itself stays complete.
    checks.require(
        capture.close.outcome == LogicalInferenceOutcome::Complete
            && capture.close.flush_state == FlushState::Acknowledged
            && capture.observation_error.is_none(),
        ProxyCheckId::TeardownOutcome,
    );
    checks.require(
        capture.attempts == 1
            && capture.final_status.is_none()
            && capture.final_failure
                == Some(TransportFailure::of(TransportErrorClass::ConnectionReset)),
        ProxyCheckId::WireOutcome,
    );
    checks.require(
        kinds_at(report.sink_ref().artifacts(), 0)
            == [ArtifactKind::ProviderRequest, ArtifactKind::TransportError],
        ProxyCheckId::ArtifactKinds,
    );
    checks.require(
        report.sink_ref().artifacts().iter().any(|artifact| {
            artifact.artifact().attempt_ordinal == 0
                && artifact.artifact().event
                    == BoundaryEvent::TransportError {
                        error_class: TransportErrorClass::ConnectionReset,
                        timeout_ms: None,
                    }
        }),
        ProxyCheckId::EventOrdering,
    );
    // A provider failure below the boundary is never answered with a
    // fabricated response: the caller's connection closes empty.
    checks.require(relayed.is_empty(), ProxyCheckId::CallerRelay);
    Ok(report.sink_ref().artifacts().len())
}

fn scene_faithful_forwarding(fixture: &mut dyn ProxyWireFixture) -> ProxySceneOutcome {
    let mut checks = Checks::new(ProxySceneId::FaithfulForwarding);
    let artifacts = faithful_forwarding(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

#[allow(clippy::too_many_lines)] // one scripted scene, read top to bottom
fn faithful_forwarding(
    checks: &mut Checks,
    fixture: &mut dyn ProxyWireFixture,
) -> SceneStep<usize> {
    let body = chat_body(false);
    let not_found_body =
        br#"{"error":{"message":"model not found","type":"invalid_request_error"}}"#;
    let response = raw_response(
        404,
        "Not Found",
        &[
            ("content-type", "application/json"),
            ("x-request-id", "req-conformance-404"),
            ("x-ratelimit-limit-requests", "60"),
        ],
        not_found_body,
    );
    fixture.queue(ProxyWireScript::Raw(response));
    let proxy = scene_proxy(
        fixture,
        checks,
        RetryPolicy {
            max_attempts: 1,
            backoff_ms: 0,
        },
        crate::openai_http1::DEFAULT_MAX_BODY_BYTES,
    )?;
    let (relayed, report) = serve_and_read(&proxy, &caller_request(proxy.route(), &body, &[]));

    {
        let ExchangeOutcome::Captured(capture) = report.outcome() else {
            checks.require(false, ProxyCheckId::ExchangeRan);
            return Err(SceneAbort);
        };
        checks.require(
            capture.close.outcome == LogicalInferenceOutcome::Complete
                && capture.attempts == 1
                && capture.final_status == Some(404),
            ProxyCheckId::WireOutcome,
        );
    }

    let sink = report.into_sink();
    let artifacts = sink.artifacts();
    checks.require(
        kinds(artifacts)
            == [
                ArtifactKind::ProviderRequest,
                ArtifactKind::ProviderResponse,
            ],
        ProxyCheckId::ArtifactKinds,
    );
    // The decoded failure was captured with its allowlisted metadata.
    checks.require(
        artifacts.get(1).is_some_and(|artifact| {
            let metadata = artifact.artifact().metadata.as_ref();
            payload_is(artifact, not_found_body)
                && metadata.is_some_and(|metadata| {
                    metadata.http_status == Some(404)
                        && metadata.content_type.as_deref() == Some("application/json")
                        && metadata.provider_request_id.as_deref() == Some("req-conformance-404")
                })
        }),
        ProxyCheckId::MetadataEntries,
    );
    // The caller received the provider's status line, every forwarded
    // header, and the exact bytes.
    let Some((status, headers, relayed_body)) = split_relay(&relayed) else {
        checks.require(false, ProxyCheckId::CallerRelay);
        return Ok(artifacts.len());
    };
    checks.require(
        status == "HTTP/1.1 404 Not Found",
        ProxyCheckId::CallerRelay,
    );
    for (name, value) in [
        ("x-request-id", "req-conformance-404"),
        ("x-ratelimit-limit-requests", "60"),
        ("content-type", "application/json"),
        ("connection", "close"),
    ] {
        checks.require(
            headers
                .iter()
                .any(|(header_name, header_value)| header_name == name && header_value == value),
            ProxyCheckId::CallerRelay,
        );
    }
    checks.require(
        headers.iter().any(|(name, value)| {
            name == "content-length" && value == &not_found_body.len().to_string()
        }) && !headers.iter().any(|(name, _)| name == "transfer-encoding"),
        ProxyCheckId::CallerRelay,
    );
    checks.require(relayed_body == not_found_body, ProxyCheckId::CallerRelay);
    Ok(artifacts.len())
}

fn scene_credential_exclusion(fixture: &mut dyn ProxyWireFixture) -> ProxySceneOutcome {
    let mut checks = Checks::new(ProxySceneId::CredentialExclusion);
    let artifacts = credential_exclusion(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

#[allow(clippy::too_many_lines)] // one scripted scene, read top to bottom
fn credential_exclusion(
    checks: &mut Checks,
    fixture: &mut dyn ProxyWireFixture,
) -> SceneStep<usize> {
    const CALLER_AUTHORIZATION: &str = "sk-caller-planted-8fd2a6e1-secret";
    const CALLER_COOKIE: &str = "caller-cookie-planted-4b9e2c-secret";
    const SERVER_ECHO: &str = "server-echo-credential";
    const SERVER_COOKIE: &str = "session=xyz-456";

    let body = chat_body(false);
    // The provider echoes hostile headers back; the mapping must never
    // give them a channel into the archive.
    let hostile = raw_response(
        200,
        "OK",
        &[
            ("content-type", "application/json"),
            ("authorization", &format!("Bearer {SERVER_ECHO}")),
            ("set-cookie", SERVER_COOKIE),
            ("www-authenticate", "Bearer realm=hostile"),
        ],
        COMPLETION_BODY.as_bytes(),
    );
    fixture.queue(ProxyWireScript::Raw(hostile));
    let proxy = scene_proxy(
        fixture,
        checks,
        RetryPolicy {
            max_attempts: 1,
            backoff_ms: 0,
        },
        crate::openai_http1::DEFAULT_MAX_BODY_BYTES,
    )?;
    // The caller carries its own credentials — headers that name the
    // caller, not the route. The boundary drops them unread.
    let (relayed, report) = serve_and_read(
        &proxy,
        &caller_request(
            proxy.route(),
            &body,
            &[
                ("authorization", &format!("Bearer {CALLER_AUTHORIZATION}")),
                ("cookie", &format!("session={CALLER_COOKIE}")),
            ],
        ),
    );

    {
        let ExchangeOutcome::Captured(capture) = report.outcome() else {
            checks.require(false, ProxyCheckId::ExchangeRan);
            return Err(SceneAbort);
        };
        checks.require(
            capture.close.outcome == LogicalInferenceOutcome::Complete
                && capture.observation_error.is_none(),
            ProxyCheckId::TeardownOutcome,
        );
    }

    // The route's credential really did ride the wire the provider saw
    // — and none of the caller's header material did.
    checks.require(
        fixture.received().first().is_some_and(|exchange| {
            let (head, _) = split_request(&exchange.raw_request);
            let head = String::from_utf8_lossy(head).to_ascii_lowercase();
            head.contains(&format!("authorization: bearer {CONFORMANCE_CREDENTIAL}"))
                && !head.contains(&CALLER_AUTHORIZATION.to_ascii_lowercase())
                && !head.contains(&CALLER_COOKIE.to_ascii_lowercase())
        }),
        ProxyCheckId::ForwardedRequest,
    );
    // ...and none of it — route credential, caller authorization or
    // cookie, server echo, or any credential-shaped header name —
    // appears in any artifact.
    let forbidden: [&[u8]; 7] = [
        CONFORMANCE_CREDENTIAL.as_bytes(),
        CALLER_AUTHORIZATION.as_bytes(),
        CALLER_COOKIE.as_bytes(),
        SERVER_ECHO.as_bytes(),
        SERVER_COOKIE.as_bytes(),
        b"set-cookie",
        b"www-authenticate",
    ];
    let sink = report.into_sink();
    let artifacts = sink.artifacts();
    checks.require(
        !artifacts.is_empty() && !artifacts_leak_any(artifacts, &forbidden),
        ProxyCheckId::CredentialExcluded,
    );
    checks.require(
        relayed.starts_with(b"HTTP/1.1 200 OK\r\n")
            && relayed.ends_with(COMPLETION_BODY.as_bytes()),
        ProxyCheckId::CallerRelay,
    );
    Ok(artifacts.len())
}

fn scene_bounded_relay(fixture: &mut dyn ProxyWireFixture) -> ProxySceneOutcome {
    let mut checks = Checks::new(ProxySceneId::BoundedRelay);
    let artifacts = bounded_relay(&mut checks, fixture).unwrap_or(0);
    checks.finish(artifacts)
}

#[allow(clippy::too_many_lines)] // one backpressure scenario, read top to bottom
fn bounded_relay(checks: &mut Checks, fixture: &mut dyn ProxyWireFixture) -> SceneStep<usize> {
    // The streamed route declares its own body cap — large enough for
    // the long stream the scenario needs — and one event stays far
    // below it. The provider's progress is therefore the observable of
    // the relay's bound: when the silent caller's socket fills, the
    // relay's write blocks, the proxy stops reading, and the provider
    // itself stalls — backpressure reached it, because the relay never
    // buffered the stream.
    const EVENT_COUNT: usize = 256;
    const STREAM_BODY_CAP: usize = 256 * 1024 * 1024;
    const WRITE_DEADLINE: Duration = Duration::from_secs(30);
    let payload = vec![b'a'; 256 * 1024 - 16];
    let frame = sse_frame(&payload);
    let mut chunk = format!("{:x}\r\n", frame.len()).into_bytes();
    chunk.extend_from_slice(&frame);
    chunk.extend_from_slice(b"\r\n");
    let chunk_len = chunk.len();
    let head =
        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n"
            .to_vec();
    fixture.queue(ProxyWireScript::MeasuredStream {
        head,
        chunks: vec![chunk.clone(); EVENT_COUNT],
        terminal: b"0\r\n\r\n".to_vec(),
    });
    let proxy = scene_proxy(
        fixture,
        checks,
        RetryPolicy {
            max_attempts: 1,
            backoff_ms: 0,
        },
        STREAM_BODY_CAP,
    )?;
    let request = caller_request(proxy.route(), &chat_body(true), &[]);

    let (relayed, report) = std::thread::scope(|scope| {
        let server = scope.spawn({
            let proxy = proxy.clone();
            move || {
                proxy
                    .serve_one(ConformanceSink::new())
                    .expect("the proxy serves")
            }
        });
        let mut caller = TcpStream::connect(proxy.local_addr()).expect("the caller connects");
        let _ = caller.set_write_timeout(Some(Duration::from_secs(10)));
        caller.write_all(&request).expect("the caller writes");

        // Phase A: the caller says nothing. The provider may stream,
        // but its progress must stall — the relay holds at most one
        // event, so backpressure reaches the provider instead of the
        // relay growing.
        let phase_a = Instant::now();
        let mut samples: Vec<(Duration, usize)> = Vec::new();
        while phase_a.elapsed() < WRITE_DEADLINE {
            samples.push((phase_a.elapsed(), fixture.measured_progress()));
            if stall_observed(&samples, QUIET_WINDOW) {
                break;
            }
            std::thread::sleep(SAMPLE_PERIOD);
        }
        checks.require(
            stall_observed(&samples, QUIET_WINDOW),
            ProxyCheckId::BufferBound,
        );

        // Phase B: the caller drains; the relay resumes and the
        // exchange completes — the stall was backpressure, not a wedge.
        let _ = caller.set_read_timeout(Some(WRITE_DEADLINE));
        let mut relayed = Vec::new();
        let _ = caller.read_to_end(&mut relayed);
        let report = server.join().expect("serve_one joins");
        (relayed, report)
    });

    // Every streamed byte passed through the relay once the caller
    // drained, and the provider really finished its script.
    checks.require(fixture.measured_done(), ProxyCheckId::BufferBound);
    checks.require(
        fixture.measured_progress() == EVENT_COUNT * chunk_len,
        ProxyCheckId::BufferBound,
    );

    {
        let ExchangeOutcome::Captured(capture) = report.outcome() else {
            checks.require(false, ProxyCheckId::ExchangeRan);
            return Err(SceneAbort);
        };
        checks.require(
            capture.streamed
                && capture.attempts == 1
                && capture.final_status == Some(200)
                && capture.observation_error.is_none(),
            ProxyCheckId::WireOutcome,
        );
        checks.require(
            capture.close.outcome == LogicalInferenceOutcome::Complete
                && capture.close.flush_state == FlushState::Acknowledged,
            ProxyCheckId::TeardownOutcome,
        );
    }
    let artifacts = report.sink_ref().artifacts();
    checks.require(
        artifacts.len() > 1
            && kinds_at(artifacts, 0).first() == Some(&ArtifactKind::ProviderRequest),
        ProxyCheckId::ArtifactKinds,
    );
    checks.require(
        relayed.starts_with(b"HTTP/1.1 200 OK\r\n")
            && relayed.ends_with(b"0\r\n\r\n")
            && relayed.len() >= EVENT_COUNT * chunk_len,
        ProxyCheckId::CallerRelay,
    );
    Ok(artifacts.len())
}

// Unit-level pinning of the checks the parent acceptance clauses ride
// on: both must demonstrably fail when their invariant is violated.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference_observer::{InferenceObserver, InferenceObserverV1};

    /// Drive the real observer lifecycle to capture `bytes` as a
    /// provider request — the same emission path a capture bug would
    /// route credential material through.
    fn capture_as_request(bytes: &[u8]) -> Vec<CanonicalArtifact> {
        capture_as_request_with(bytes, None)
    }

    /// The same capture, with `metadata` handed to the observer — the
    /// parameter a capture mapping fills with header-derived values,
    /// and so the channel a capture bug leaks credential material
    /// through.
    fn capture_as_request_with(bytes: &[u8], metadata: Option<Metadata>) -> Vec<CanonicalArtifact> {
        let mut observer = InferenceObserverV1::new(
            tenant().expect("a valid tenant"),
            origin().expect("a valid origin"),
            ConformanceSink::new(),
        );
        observer.start_logical_inference(None).expect("starts");
        observer.start_provider_attempt().expect("an attempt");
        observer
            .decoded_request_bytes(bytes, metadata, None)
            .expect("records");
        observer.close_logical_inference().expect("closes");
        observer.into_sink().artifacts().to_vec()
    }

    #[test]
    fn the_credential_check_fires_when_a_record_carries_the_credential() {
        // A record's payload bytes never render into the record — the
        // record carries the payload digest by construction — so the
        // channel a capture bug leaks through is a record field. The
        // opaque `provider_request_id` is the realistic one: a mapping
        // that copies a header value there is exactly the leak, and
        // the observer's metadata parameter is how it gets in.
        let leak = Metadata {
            content_type: None,
            provider_request_id: Some(CONFORMANCE_CREDENTIAL.to_owned()),
            http_status: None,
            rate_limit_limit: None,
            rate_limit_remaining: None,
            rate_limit_reset: None,
            usage_input_tokens: None,
            usage_output_tokens: None,
            usage_total_tokens: None,
        };
        let poisoned = capture_as_request_with(&chat_body(false), Some(leak));
        assert!(!poisoned.is_empty());
        assert!(
            artifacts_leak_any(&poisoned, &[CONFORMANCE_CREDENTIAL.as_bytes()]),
            "a record that carries credential material must fail the exclusion check"
        );

        // The scene's own records carry no credential: the clean
        // capture passes the same check the poisoned record fails.
        let clean = capture_as_request(&chat_body(false));
        assert!(!clean.is_empty());
        assert!(!artifacts_leak_any(
            &clean,
            &[CONFORMANCE_CREDENTIAL.as_bytes()]
        ));
    }

    #[test]
    fn the_buffer_bound_check_fires_only_on_a_real_stall() {
        let quiet = QUIET_WINDOW;
        let period = SAMPLE_PERIOD;
        // A relay that buffered the stream would keep the provider
        // writing: strictly increasing progress has no quiet suffix, so
        // the classifier refuses the stall and the scene's check fails.
        let mut streaming: Vec<(Duration, usize)> = Vec::new();
        let mut progress = 0_usize;
        for step in 0_u32..60 {
            progress += 4096;
            streaming.push((period * step, progress));
        }
        assert!(!stall_observed(&streaming, quiet));
        assert!(!stall_observed(&[], quiet));

        let mut checks = Checks::new(ProxySceneId::BoundedRelay);
        checks.require(stall_observed(&streaming, quiet), ProxyCheckId::BufferBound);
        let outcome = checks.finish(0);
        assert!(!outcome.passed);
        assert!(
            outcome.failed_checks.contains(&ProxyCheckId::BufferBound),
            "a never-stalling provider must record the violated bound"
        );

        // Progress frozen across the quiet window is the stall the
        // bound promises: backpressure reached the provider.
        let mut stalled = streaming.clone();
        let frozen_at = stalled.last().expect("samples").1;
        for step in 60_u32..110 {
            stalled.push((period * step, frozen_at));
        }
        assert!(stall_observed(&stalled, quiet));
    }

    #[test]
    fn caller_requests_are_content_length_framed_posts() {
        let request = caller_request(
            "/v1/chat/completions",
            b"abcde",
            &[("cookie", "session=abc")],
        );
        let text = String::from_utf8(request).expect("an ascii request");
        assert!(text.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
        assert!(text.contains("cookie: session=abc\r\n"));
        assert!(text.ends_with("content-length: 5\r\n\r\nabcde"));
    }
}
