// SPDX-License-Identifier: Apache-2.0

//! The captured proxy attempt's proof that uploads go through the normal
//! authenticated client path (plan client data flow steps 4–6, the third
//! acceptance clause of the capture proxy): a real proxy capture — one
//! retryable provider attempt, one streamed completion — flows through the
//! standard spool into the upload state machine and comes out frozen,
//! claimed, and authorized, with no uploader but the existing one.
//!
//! **Which end proves the join: the client-core end.** The SDK boundary
//! test pins that the SDK cannot depend on this crate, so the fixture
//! lives here, where depending on the SDK is the declared direction
//! (`Cargo.toml`). The join itself is pinned by byte identity, not by two
//! green halves: the exact canonical bytes the lifecycle handed the sink —
//! and nothing else — are what the spool materializes to disk, what the
//! frozen request digests name, and what the attempt authorization's
//! signing preimage covers. Any side-channel re-rendering, re-derivation,
//! or second upload path breaks a byte-equality assertion below.
//!
//! The capture bundle is one canonical artifact per JSONL line, in
//! emission order; the spool treats those bytes as an opaque payload, and
//! this fixture's framing choice is the composing engine's stand-in. The
//! adapter coordinates the occurrence derivation consumes (harness,
//! upstream session, adapter identity, generation, event range) are fixed
//! fixture values: they are the identity inputs an engine supplies from
//! its own configuration, and the proof is that once chosen they flow
//! through freeze, claim, and mint unchanged — not which values an engine
//! will eventually choose.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use archivist_adapter_sdk::openai_compat::{OpenAiEndpoint, RetryPolicy as ProviderRetryPolicy};
use archivist_adapter_sdk::openai_http1::Http1Transport;
use archivist_adapter_sdk::openai_proxy::CaptureProxy;
use archivist_adapter_sdk::{
    CanonicalArtifact, ExchangeOutcome, FlushState, LogicalInferenceOutcome, ProxyConfig,
    RecordingArtifactSink,
};
use archivist_client_core::spool::pressure::{PressureGate, PressureLimits};
use archivist_client_core::spool::{SPOOL_DIR_NAME, Spool};
use archivist_client_core::state::StateStore;
use archivist_client_core::upload::{
    AttemptAuthorization, FreezeUpload, Jitter, RetryPolicy as UploadRetryPolicy, UploadError,
    UploadRelation, claim_due_upload, freeze_upload, state_now,
};
use archivist_protocol::derivation::{
    artifact_hash, attestation_id, blob_digest, occurrence_id, session_hash,
};
use archivist_protocol::envelope::Envelope;
use archivist_protocol::inference_artifact::{BoundaryEvent, InferenceArtifact};
use archivist_protocol::json::Object;
use archivist_protocol::vocabulary::{
    AdapterId, ArtifactKind, ChecksumAlgorithm, ClientId, GenerationId, HarnessId, IdSource,
    IncomingChecksum, KeyId, OpaqueId, RangeKind, RequestContentDigest, RetryReason,
    StorageProfile, TenantId, Timestamp, TransportEncoding, UsageSource, VersionToken,
};

const LOOPBACK: &str = "127.0.0.1";
const CREDENTIAL: &str = "conformance-proxy-credential";
const TENANT: &str = "33333333-3333-4333-8333-333333333333";
const ORIGIN: &str = "11111111-1111-4111-8111-111111111111";
const UPLOADER: &str = "22222222-2222-4222-8222-222222222222";
const UPSTREAM_SESSION: &str = "4f9c2f1e-8a3d-4b67-9c2f-1e8a3d4b679c";
const HARNESS: &str = "capture-harness";
const ADAPTER: &str = "openai-proxy";
const PROJECTION: &str = "1";
const ADAPTER_ARTIFACT_ID: &str = "v1-chat-completions-capture";
const GENERATION: &str = "1a07a111-7000-7000-8000-0000000000c9";
const CAPTURED_AT: &str = "2026-09-25T12:00:00Z";
const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const LATER_AUTHORIZATION: &str = "2026-09-25T12:05:00Z";

/// The caller's request body, forwarded to the provider byte-for-byte and
/// captured once per provider attempt.
const CALLER_BODY: &[u8] = br#"{"model":"first-party-model","messages":[{"role":"user","content":"capture through the proxy"}],"stream":true}"#;

/// The first (failed) attempt's decoded response body.
const RETRY_BODY: &[u8] = br#"{"error":{"message":"upstream exploded"}}"#;

/// The streamed attempt's decoded events, in order; the second carries the
/// usage counters the boundary extracts after the stream drains.
const STREAM_EVENTS: [&[u8]; 2] = [
    br#"{"choices":[{"delta":{"content":"hello"}}]}"#,
    br#"{"choices":[{"delta":{"content":" done"}}],"usage":{"prompt_tokens":12,"completion_tokens":34,"total_tokens":46}}"#,
];

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    /// A mode-`0700` state directory no other test shares.
    fn new(name: &str) -> Self {
        let serial = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "archivist-proxy-upload-{name}-{}-{serial}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&path).expect("proxy-upload temp directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("pin temp directory mode");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Draw zero every time: the first claim schedules a zero delay, so the
/// retry is due again immediately and the retry discipline (frozen
/// identity, fresh authorization) is observable without sleeping.
struct FixedJitter;

impl Jitter for FixedJitter {
    fn random_bits(&mut self) -> Result<u64, UploadError> {
        Ok(0)
    }
}

fn timestamp(text: &str) -> Timestamp {
    Timestamp::parse(text).expect("test timestamp")
}

/// Lowercase-hex SHA-256, through the protocol derivation the identity
/// path itself uses.
fn sha256_hex(bytes: &[u8]) -> String {
    blob_digest(bytes).to_hex()
}

/// The failed attempt's bounded provider response: a retryable decoded 500
/// with a `content-length` body.
fn retry_response() -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(
        b"HTTP/1.1 500 Internal Server Error\r\ncontent-type: application/json\r\n",
    );
    raw.extend_from_slice(format!("content-length: {}\r\n", RETRY_BODY.len()).as_bytes());
    raw.extend_from_slice(b"connection: close\r\n\r\n");
    raw.extend_from_slice(RETRY_BODY);
    raw
}

/// The streamed attempt's provider response: an SSE stream behind chunked
/// transfer framing, one chunk per event, honestly terminated.
fn stream_response() -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(
        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
    );
    for event in STREAM_EVENTS {
        let mut frame = Vec::new();
        frame.extend_from_slice(b"data: ");
        frame.extend_from_slice(event);
        frame.extend_from_slice(b"\n\n");
        raw.extend_from_slice(format!("{:x}\r\n", frame.len()).as_bytes());
        raw.extend_from_slice(&frame);
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    raw
}

/// Bind a real loopback provider scripted one connection at a time: the
/// proxy's transport connects here for every provider attempt, each
/// accepted connection consumes the next queued response, and the server
/// thread exits when the queue drains.
fn bind_scripted_provider(scripts: Vec<Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind((LOOPBACK, 0)).expect("bind scripted provider");
    let addr = listener.local_addr().expect("provider address");
    let queue = Mutex::new(VecDeque::from(scripts));
    std::thread::spawn(move || serve_provider(&listener, &queue));
    addr
}

/// Serve the provider's connections until the script queue drains: read
/// the forwarded request, write the scripted response, half-close, and
/// hold until the proxy hangs up.
fn serve_provider(listener: &TcpListener, scripts: &Mutex<VecDeque<Vec<u8>>>) {
    loop {
        let Some(response) = scripts.lock().expect("provider script lock").pop_front() else {
            return;
        };
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
        let _ = read_forwarded_request(&mut stream);
        let _ = stream.write_all(&response);
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Write);
        // Hold the read side until the proxy closes: an early provider
        // exit could truncate the relay mid-exchange.
        let mut held = [0_u8; 64];
        let _ = stream.read(&mut held);
    }
}

/// Read one content-length-framed HTTP/1.1 request off the provider
/// socket; the bytes themselves are the proxy's business.
fn read_forwarded_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 2048];
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

/// The caller side of the proxy: POST the declared route with a bounded
/// body and read the relay to EOF.
fn post_to_proxy(addr: SocketAddr, route: &str, body: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).expect("connect to the proxy");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let mut request = format!(
        "POST {route} HTTP/1.1\r\nhost: {LOOPBACK}\r\ncontent-type: application/json\r\n\
         authorization: Bearer caller-credential-the-proxy-must-drop\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    stream.write_all(&request).expect("send caller request");
    let mut relayed = Vec::new();
    stream
        .read_to_end(&mut relayed)
        .expect("read the relayed response");
    relayed
}

/// Capture one exchange for real: a scripted provider answers the first
/// attempt with a retryable 500 and the second with a streamed 200, and
/// the proxy serves one caller connection against them.
fn capture_through_the_proxy() -> (ProxyCaptureShape, Vec<CanonicalArtifact>) {
    let provider_addr = bind_scripted_provider(vec![retry_response(), stream_response()]);
    let endpoint = OpenAiEndpoint::new(
        LOOPBACK.to_owned(),
        provider_addr.port(),
        CREDENTIAL.to_owned(),
    )
    .expect("a loopback provider endpoint");
    let config = ProxyConfig::new(
        TenantId::parse(TENANT).expect("valid tenant grammar"),
        ClientId::parse(ORIGIN).expect("valid client grammar"),
        endpoint,
    )
    .with_transport(Http1Transport::with_timeouts(
        Duration::from_secs(2),
        Duration::from_secs(5),
    ))
    .with_retry_policy(ProviderRetryPolicy {
        max_attempts: 2,
        backoff_ms: 0,
    });
    let proxy = CaptureProxy::bind(config).expect("bind the capture proxy");
    let caller_addr = proxy.local_addr();
    let route = proxy.route().to_owned();

    let sink = RecordingArtifactSink::new();
    let server = {
        let proxy = proxy.clone();
        std::thread::spawn(move || proxy.serve_one(sink))
    };
    let relayed = post_to_proxy(caller_addr, &route, CALLER_BODY);

    let report = server
        .join()
        .expect("the proxy serve thread does not panic")
        .expect("the proxy listener accepts");
    assert!(
        relayed.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "the streamed relay answers the caller with the provider's own status"
    );
    let outcome = report.outcome();
    let capture = match outcome {
        ExchangeOutcome::Captured(capture) => capture.clone(),
        ExchangeOutcome::Refused(refusal) => {
            panic!("the routed request was never captured: {refusal:?}")
        }
    };
    let artifacts = report.into_sink().artifacts().to_vec();
    (ProxyCaptureShape::from(&capture), artifacts)
}

/// The capture report's fields the proof asserts, copied out of the
/// generic sink report so the main test reads flat.
#[derive(Clone, Debug)]
struct ProxyCaptureShape {
    attempts: u64,
    streamed: bool,
    final_status: Option<u16>,
    observation_error: Option<String>,
    outcome: LogicalInferenceOutcome,
    flush_state: FlushState,
    emitted_artifacts: u64,
}

impl From<&archivist_adapter_sdk::ProxyCapture> for ProxyCaptureShape {
    fn from(capture: &archivist_adapter_sdk::ProxyCapture) -> Self {
        Self {
            attempts: capture.attempts,
            streamed: capture.streamed,
            final_status: capture.final_status,
            observation_error: capture.observation_error.map(|error| error.to_string()),
            outcome: capture.close.outcome,
            flush_state: capture.close.flush_state,
            emitted_artifacts: capture.close.emitted_artifacts,
        }
    }
}

/// The end-to-end proof: the capture's artifacts are exactly what the
/// spool materializes, exactly what the freeze digests, and exactly what
/// the attempt authorization signs — through `freeze_upload`,
/// `claim_due_upload`, and `AttemptAuthorization::mint` alone.
#[test]
#[allow(clippy::too_many_lines)] // one end-to-end proof, read top to bottom
fn captured_proxy_attempt_reaches_a_frozen_authorized_upload() {
    let (capture, artifacts) = capture_through_the_proxy();

    // --- The capture side: one retry, one streamed response ---------------
    assert_eq!(capture.attempts, 2, "one retryable failure, one retry");
    assert!(
        capture.streamed,
        "the completing attempt was relayed as a stream"
    );
    assert_eq!(capture.final_status, Some(200));
    assert_eq!(
        capture.observation_error, None,
        "the sink accepted every emission"
    );
    assert_eq!(capture.outcome, LogicalInferenceOutcome::Complete);
    assert_eq!(capture.flush_state, FlushState::Acknowledged);
    let artifact_count = u64::try_from(artifacts.len()).expect("bounded artifact count");
    assert_eq!(capture.emitted_artifacts, artifact_count);

    // Every emitted record is canonical protocol material that parses back.
    for artifact in &artifacts {
        InferenceArtifact::parse(artifact.canonical_bytes())
            .expect("every emitted artifact parses back from its canonical bytes");
    }

    // Both attempts captured the caller's decoded request byte-for-byte.
    let requests: Vec<_> = artifacts
        .iter()
        .filter(|artifact| matches!(artifact.artifact().event, BoundaryEvent::ProviderRequest))
        .collect();
    assert_eq!(
        requests.len(),
        2,
        "one decoded request per provider attempt"
    );
    for request in &requests {
        let payload = request
            .artifact()
            .payload
            .as_ref()
            .expect("a request artifact carries the decoded body");
        assert_eq!(payload.payload_digest, blob_digest(CALLER_BODY));
        assert_eq!(
            u64::try_from(CALLER_BODY.len()).expect("bounded body"),
            payload.payload_size
        );
    }

    // The failed attempt's decoded response is captured, and the retry
    // cites it by ordinal — reconstructable, never merged.
    let failed_response = artifacts
        .iter()
        .find(|artifact| {
            artifact.artifact().attempt_ordinal == 0
                && matches!(artifact.artifact().event, BoundaryEvent::ProviderResponse)
        })
        .expect("the failed attempt's decoded response is captured");
    assert_eq!(
        failed_response
            .artifact()
            .payload
            .as_ref()
            .expect("response payload")
            .payload_digest,
        blob_digest(RETRY_BODY)
    );
    assert!(
        artifacts.iter().any(|artifact| {
            artifact.artifact().attempt_ordinal == 1
                && matches!(
                    artifact.artifact().event,
                    BoundaryEvent::Retry {
                        retry_of_attempt_ordinal: 0,
                        retry_reason: RetryReason::HttpStatus,
                        ..
                    }
                )
        }),
        "the retry artifact cites the failed attempt's ordinal and reason"
    );

    // The streamed attempt's events are dense from zero and digest to the
    // exact scripted provider bytes.
    let streamed: Vec<_> = artifacts
        .iter()
        .filter_map(|artifact| match artifact.artifact().event {
            BoundaryEvent::StreamingEvent { event_ordinal } => {
                Some((artifact.artifact().attempt_ordinal, event_ordinal, artifact))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        streamed.len(),
        STREAM_EVENTS.len(),
        "every event captured once"
    );
    for (position, (attempt, ordinal, artifact)) in streamed.iter().enumerate() {
        assert_eq!(*attempt, 1, "the stream belongs to the completing attempt");
        assert_eq!(*ordinal, u64::try_from(position).expect("bounded position"));
        let payload = artifact
            .artifact()
            .payload
            .as_ref()
            .expect("a stream event carries its payload");
        assert_eq!(payload.payload_digest, blob_digest(STREAM_EVENTS[position]));
    }

    // The usage counters came out of the stream event after the drain.
    let usage = artifacts
        .iter()
        .find(|artifact| {
            matches!(
                artifact.artifact().event,
                BoundaryEvent::Usage {
                    usage_source: UsageSource::StreamEvent
                }
            )
        })
        .expect("the stream's usage record is captured");
    let usage_metadata = usage
        .artifact()
        .metadata
        .as_ref()
        .expect("a usage record carries its counters");
    assert_eq!(usage_metadata.usage_input_tokens, Some(12));
    assert_eq!(usage_metadata.usage_output_tokens, Some(34));
    assert_eq!(usage_metadata.usage_total_tokens, Some(46));

    // --- The capture bundle: exactly the emitted bytes, nothing else -----
    let mut bundle_bytes = Vec::new();
    for artifact in &artifacts {
        bundle_bytes.extend_from_slice(artifact.canonical_bytes());
        bundle_bytes.push(b'\n');
    }
    let canonical_digest = blob_digest(&bundle_bytes);

    // --- Step 4: materialize the immutable canonical bundle ---------------
    let temp = TempDir::new("upload-path");
    let mut store = StateStore::open(&temp.path().join("state.db")).expect("state store");
    store.migrate().expect("state migrations");
    let spool = Spool::open(temp.path()).expect("spool directory");
    let mut gate = PressureGate::new(PressureLimits::new(1 << 30, 0, 80));
    let bundle = spool
        .materialize(&store, &mut gate, &bundle_bytes)
        .expect("the capture materializes through the standard gate");

    // The spool row's digest names exactly the bytes the lifecycle emitted,
    // and those bytes are what is on disk under the entry's name.
    assert_eq!(bundle.envelope_digest(), sha256_hex(&bundle_bytes));
    assert_eq!(
        bundle.size_bytes(),
        u64::try_from(bundle_bytes.len()).expect("bounded bundle")
    );
    let on_disk = std::fs::read(temp.path().join(SPOOL_DIR_NAME).join(bundle.bundle_name()))
        .expect("read the materialized bundle");
    assert_eq!(
        on_disk, bundle_bytes,
        "the spool holds exactly the emitted bytes"
    );

    // --- Step 5: the capture path's content-derived identity --------------
    let tenant = TenantId::parse(TENANT).expect("tenant");
    let origin = ClientId::parse(ORIGIN).expect("origin");
    let uploader = ClientId::parse(UPLOADER).expect("uploader");
    let harness = HarnessId::parse(HARNESS).expect("harness");
    let adapter = AdapterId::parse(ADAPTER).expect("adapter");
    let projection = VersionToken::parse(PROJECTION).expect("projection");
    let adapter_artifact_id = OpaqueId::parse(ADAPTER_ARTIFACT_ID).expect("adapter artifact id");
    let generation = GenerationId::parse(GENERATION).expect("generation");
    let session = session_hash(&tenant, &origin, &harness, UPSTREAM_SESSION);
    let artifact = artifact_hash(
        &session,
        ArtifactKind::DatabaseProjection,
        &adapter,
        &projection,
        adapter_artifact_id.as_str(),
    );
    let occurrence = occurrence_id(
        &session,
        &artifact,
        &generation,
        RangeKind::Event,
        0,
        artifact_count - 1,
        &canonical_digest,
    );

    // --- Step 6: freeze the canonical upload envelope ---------------------
    let checksum = IncomingChecksum::parse(&canonical_digest.to_hex())
        .expect("identity transport couples the checksum to the blob digest");
    let captured_at = timestamp(CAPTURED_AT);
    let envelope_version = VersionToken::parse("envelope-v1").expect("envelope version");
    let fields = FreezeUpload {
        spool_entry_id: bundle.spool_entry_id(),
        tenant_id: &tenant,
        origin_client_id: &origin,
        uploader_client_id: &uploader,
        occurrence_id: &occurrence,
        envelope_version: &envelope_version,
        storage_profile: StorageProfile::ZstdV1,
        transport_encoding: Some(TransportEncoding::Identity),
        canonical_digest: &canonical_digest,
        incoming_checksum: &checksum,
        canonical_size: bundle.size_bytes(),
        transport_size: bundle.size_bytes(),
        source_at: None,
        captured_at: &captured_at,
        envelope_created_at: &captured_at,
        relation: UploadRelation::Direct,
    };
    let frozen = freeze_upload(&mut store, &fields).expect("the capture freezes");

    // The frozen identity is the identity derived from the capture's bytes:
    // the upload path froze the proxy capture, not some other material.
    assert_eq!(frozen.occurrence_id(), &occurrence);
    let attestation = attestation_id(&occurrence, &uploader, frozen.request_id());
    assert_eq!(frozen.attestation_id(), &attestation);
    let (frozen_rows, attestation_rows): (i64, i64) = store
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM frozen_requests),
                    (SELECT COUNT(*) FROM upload_attestations)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("frozen row counts");
    assert_eq!(
        (frozen_rows, attestation_rows),
        (1, 1),
        "one freeze, one attestation"
    );

    // --- Step 7: claim due uploads and mint fresh authorization ----------
    let now = state_now(&store).expect("the state database clock");
    let mut jitter = FixedJitter;
    let claim_one = claim_due_upload(&mut store, &now, &UploadRetryPolicy::plan(), &mut jitter)
        .expect("claim")
        .expect("the frozen capture is due");
    assert_eq!(
        claim_one.frozen(),
        &frozen,
        "the attempt re-sends the frozen identity"
    );
    assert_eq!(claim_one.envelope_digest(), bundle.envelope_digest());
    assert_eq!(claim_one.bundle_name(), bundle.bundle_name());
    assert_eq!(claim_one.attempt_count(), 1);

    // The first attempt's outcome was never recorded — the schedule laid
    // down at claim time makes the identical promise due again.
    let claim_two = claim_due_upload(&mut store, &now, &UploadRetryPolicy::plan(), &mut jitter)
        .expect("claim")
        .expect("the unrecorded attempt is due again");
    assert_eq!(
        claim_two.frozen(),
        claim_one.frozen(),
        "retries never regenerate identity"
    );
    assert_eq!(claim_two.envelope_digest(), claim_one.envelope_digest());
    assert_eq!(claim_two.attempt_count(), 2);

    // Fresh authorization per attempt, over the one frozen envelope.
    let key = KeyId::parse(KEY).expect("uploader key id");
    let auth_one = AttemptAuthorization::mint(key, 1, now).expect("first authorization");
    let auth_two = AttemptAuthorization::mint(key, 2, timestamp(LATER_AUTHORIZATION))
        .expect("fresh authorization");
    assert_ne!(
        auth_one.authorization_epoch(),
        auth_two.authorization_epoch()
    );

    // The attempt-time envelope is protocol-valid and its declared
    // identities re-derive to exactly the frozen ones.
    let envelope = Envelope {
        tenant_id: tenant.clone(),
        origin_client_id: origin.clone(),
        uploader_client_id: uploader.clone(),
        harness: harness.clone(),
        upstream_session_id: OpaqueId::parse(UPSTREAM_SESSION).expect("upstream session id"),
        id_source: IdSource::Upstream,
        artifact_kind: ArtifactKind::DatabaseProjection,
        adapter_id: adapter.clone(),
        adapter_projection_version: projection.clone(),
        adapter_artifact_id: adapter_artifact_id.clone(),
        generation: generation.clone(),
        range_kind: RangeKind::Event,
        range_start: 0,
        range_end: artifact_count - 1,
        blob_digest: canonical_digest,
        incoming_checksum: checksum,
        incoming_checksum_algorithm: ChecksumAlgorithm::Sha256,
        storage_profile: StorageProfile::ZstdV1,
        transport_encoding: TransportEncoding::Identity,
        compressed_size: bundle.size_bytes(),
        uncompressed_size: bundle.size_bytes(),
        occurrence_id: *frozen.occurrence_id(),
        attestation_id: *frozen.attestation_id(),
        request_id: frozen.request_id().clone(),
        capture_time: captured_at.clone(),
        envelope_creation_time: captured_at,
        source_time: None,
        parent_session_id: None,
        orchestrator_attempt_id: None,
        trace_id: None,
        inference_request_id: None,
        unknown_fields: Object::new(),
    };
    envelope
        .verify_identities()
        .expect("the envelope presents exactly the frozen occurrence and attestation");

    // The signing preimage covers the envelope built from the frozen facts
    // and the exact payload bytes the spool holds — this fixture's framing
    // of the ingest request body stands in for the transport seam's
    // multipart assembly.
    let mut request_body = envelope.canonical_bytes();
    request_body.push(b'\n');
    request_body.extend_from_slice(&bundle_bytes);
    let request_digest =
        RequestContentDigest::parse(&sha256_hex(&request_body)).expect("request content digest");
    let signature_one = auth_one.signing_input(
        "POST",
        "/v1/ingest",
        "multipart/related; boundary=archivist",
        &request_digest,
        &envelope.envelope_digest(),
        &canonical_digest,
        &checksum,
    );
    let signature_two = auth_two.signing_input(
        "POST",
        "/v1/ingest",
        "multipart/related; boundary=archivist",
        &request_digest,
        &envelope.envelope_digest(),
        &canonical_digest,
        &checksum,
    );
    assert_ne!(
        signature_one, signature_two,
        "each attempt's authorization is fresh over the same frozen bytes"
    );
    let tampered_payload = blob_digest(b"not the capture bytes");
    let signature_tampered = auth_one.signing_input(
        "POST",
        "/v1/ingest",
        "multipart/related; boundary=archivist",
        &request_digest,
        &envelope.envelope_digest(),
        &tampered_payload,
        &checksum,
    );
    assert_ne!(
        signature_one, signature_tampered,
        "the authorization is bound to the exact frozen payload digest"
    );

    // The entry is still live materialized state: nothing acknowledged,
    // nothing removed — the receipt and acknowledgement steps are the
    // server-side continuation of this same path.
    let (state, entries): (String, i64) = store
        .connection()
        .query_row(
            "SELECT state, (SELECT COUNT(*) FROM spool_entries) FROM spool_entries
             WHERE spool_entry_id = ?1",
            rusqlite::params![bundle.spool_entry_id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("spool entry state");
    assert_eq!(state, "materialized");
    assert_eq!(
        entries, 1,
        "one capture, one spool entry, one upload promise"
    );
}
