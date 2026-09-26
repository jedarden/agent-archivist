// SPDX-License-Identifier: Apache-2.0

//! The published inference-coverage manifest over a real compatibility
//! claim (plan Phase 9 exit gate): [`TransportConformance::run`] drives
//! the first-party client at its real loopback boundary and mints the
//! only qualification that can put a client row in the published
//! manifest. The tests here pin what a publish names — claimed routes,
//! known bypasses, schema version, flush outcome, coverage evidence —
//! and what it refuses to name: an unclaimed route's activity stays
//! visible without a client row, a claimed client without traffic reports
//! explicit zeroes, and the exact counters never merge with the semantic
//! session states.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use archivist_adapter_sdk::compatibility::{CompatibilityMatrix, FIRST_PARTY_OPENAI_HTTP1};
use archivist_adapter_sdk::coverage_manifest::{
    INFERENCE_COVERAGE_SCHEMA, INFERENCE_COVERAGE_SCHEMA_VERSION, InferenceCoverageManifest,
};
use archivist_adapter_sdk::ephemeral_flush::{EphemeralCapturePolicy, EphemeralFlushGate};
use archivist_adapter_sdk::expected_inference::{
    ExactOutcome, ExpectedInferenceLedger, ExpectedInferenceRecord, InferenceArtifactKind,
    InferenceIdentity, RoutePolicy,
};
use archivist_adapter_sdk::inference_observer::INFERENCE_OBSERVER_VERSION;
use archivist_adapter_sdk::openai_conformance::{
    ConformanceError, OpenAiWireFixture, ReceivedExchange, TransportConformance, WireScript,
};
use archivist_adapter_sdk::openai_http1::WireEndpoint;
use archivist_adapter_sdk::status::{CoverageCounts, CoverageState};
use archivist_protocol::vocabulary::{InferenceRequestId, OpaqueId, ProviderAttemptId, TraceId};

const LOOPBACK: &str = "127.0.0.1";

/// The shared state between the fixture handle and its server thread.
struct Shared {
    scripts: Mutex<VecDeque<WireScript>>,
    received: Mutex<Vec<ReceivedExchange>>,
}

/// A real loopback TCP server, scripted one connection at a time. Every
/// scene gets a fresh listener on an ephemeral port; the server thread
/// serves exactly the queued scripts and exits when the script queue
/// drains, so no connection outlives its scene.
struct LoopbackFixture {
    endpoint: WireEndpoint,
    listener: Option<TcpListener>,
    shared: Arc<Shared>,
}

impl LoopbackFixture {
    /// Bind a listener on an ephemeral loopback port; its server thread
    /// starts with the first queued script.
    fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind((LOOPBACK, 0))?;
        let port = listener.local_addr()?.port();
        let endpoint =
            WireEndpoint::new(LOOPBACK.to_owned(), port).expect("the loopback hostname is valid");
        let shared = Arc::new(Shared {
            scripts: Mutex::new(VecDeque::new()),
            received: Mutex::new(Vec::new()),
        });
        Ok(Self {
            endpoint,
            listener: Some(listener),
            shared,
        })
    }
}

/// Serve connections until the script queue drains.
fn serve(listener: &TcpListener, shared: &Shared) {
    loop {
        if shared.scripts.lock().expect("script lock").is_empty() {
            return;
        }
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let Some(script) = shared.scripts.lock().expect("script lock").pop_front() else {
            return;
        };
        let raw_request = read_request(&mut stream);
        shared
            .received
            .lock()
            .expect("received lock")
            .push(ReceivedExchange { raw_request });
        match script {
            WireScript::Raw(bytes) => {
                let _ = stream.write_all(&bytes);
                let _ = stream.shutdown(Shutdown::Write);
                let _ = stream.read(&mut [0_u8; 16]);
            }
            WireScript::Reset => {
                drop(stream);
            }
            WireScript::Stall { hold_ms } => {
                std::thread::sleep(Duration::from_millis(hold_ms));
                drop(stream);
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

impl OpenAiWireFixture for LoopbackFixture {
    fn endpoint(&mut self) -> Result<WireEndpoint, ConformanceError> {
        Ok(self.endpoint.clone())
    }

    fn queue(&mut self, script: WireScript) {
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

    fn received(&self) -> Vec<ReceivedExchange> {
        self.shared.received.lock().expect("received lock").clone()
    }
}

/// Panic with the per-scene failed checks when any scene fails, so a
/// regression names its property instead of just its scene.
fn assert_every_scene_passed(
    report: &archivist_adapter_sdk::openai_conformance::ConformanceReport,
) {
    for scene in report.scenes() {
        assert!(
            scene.passed(),
            "conformance scene {} failed checks {:#?}",
            scene.scene,
            scene.failed_checks
        );
    }
    assert!(report.passed(), "the conformance run passed every scene");
}

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

fn record_on(seed: u8, route: RoutePolicy) -> ExpectedInferenceRecord {
    ExpectedInferenceRecord::new(
        id(seed),
        session(seed),
        route,
        archivist_protocol::vocabulary::Timestamp::parse("2026-09-20T12:00:00Z")
            .expect("timestamp"),
    )
}

fn artifact(
    seed: u8,
    ordinal: u64,
    kind: InferenceArtifactKind,
) -> archivist_adapter_sdk::expected_inference::ObservedArtifact {
    archivist_adapter_sdk::expected_inference::ObservedArtifact::new(
        id(seed),
        session(seed),
        ProviderAttemptId::parse(&format!("0000000{seed}-3333-7333-8333-{ordinal:012x}"))
            .expect("attempt"),
        ordinal,
        kind,
    )
}

/// A ledger with hook-route traffic (an observed exchange and a known
/// bypass) and proxy-route activity (a bypass) — the proxy route stays
/// unclaimed in every publish below.
fn mixed_ledger() -> ExpectedInferenceLedger {
    let mut ledger = ExpectedInferenceLedger::new();
    ledger
        .persist(record_on(1, RoutePolicy::SdkHook))
        .expect("persist");
    ledger
        .record_artifact(artifact(1, 0, InferenceArtifactKind::ProviderRequest))
        .expect("request");
    ledger
        .record_artifact(artifact(1, 0, InferenceArtifactKind::ProviderResponse))
        .expect("response");
    assert_eq!(ledger.close_completed(&id(1)), Ok(ExactOutcome::Observed));

    ledger
        .persist(record_on(2, RoutePolicy::SdkHook))
        .expect("persist");
    assert_eq!(ledger.close_completed(&id(2)), Ok(ExactOutcome::Unobserved));

    ledger
        .persist(record_on(3, RoutePolicy::Proxy))
        .expect("persist");
    assert_eq!(ledger.close_completed(&id(3)), Ok(ExactOutcome::Unobserved));
    ledger
}

fn idle_flush_report() -> archivist_adapter_sdk::ephemeral_flush::EphemeralFlushReport {
    EphemeralFlushGate::new(EphemeralCapturePolicy::RequireCompleteCapture).finish()
}

#[test]
fn a_real_claim_publishes_a_client_row_and_the_unclaimed_route_stays_visible() {
    let report = TransportConformance::run(|| Box::new(LoopbackFixture::new().expect("bind")));
    assert_every_scene_passed(&report);

    let mut matrix = CompatibilityMatrix::new();
    matrix
        .record(&report)
        .expect("the qualified run earns its row");

    let mut semantic = CoverageCounts::default();
    semantic.record(CoverageState::Current);

    let manifest = InferenceCoverageManifest::publish(
        &matrix,
        &mixed_ledger(),
        semantic,
        &idle_flush_report(),
    );

    // Exactly one client row: the claim the conformance run minted.
    assert_eq!(manifest.clients().len(), 1);
    let client = &manifest.clients()[0];
    assert_eq!(client.integration, FIRST_PARTY_OPENAI_HTTP1);
    assert_eq!(client.route, RoutePolicy::SdkHook);
    assert_eq!(client.lifecycle_version, INFERENCE_OBSERVER_VERSION);
    assert_eq!(client.evidence.len(), 64, "the evidence digest is named");
    assert_eq!(
        client.evidence,
        report
            .qualification()
            .as_ref()
            .map(|qualification| qualification.evidence_digest().to_owned())
            .expect("the qualified run carries its digest"),
    );

    // The client's counters are its route's partition: the observed
    // exchange and the known bypass stay counted, the open denominator is
    // separate.
    assert_eq!(client.coverage.observed, 1);
    assert_eq!(client.coverage.unobserved, 1);
    assert_eq!(client.coverage.open_expectations, 0);

    // The unclaimed proxy route keeps its bypass visible in the route
    // partition — counted, but never promoted to a client row.
    assert_eq!(manifest.routes()[0].route, RoutePolicy::Proxy);
    assert_eq!(manifest.routes()[0].unobserved, 1);
    assert_eq!(manifest.known_bypasses(), [1, 1]);
    assert_eq!(manifest.known_bypass_total(), 2);

    // The published document names the schema version, the claimed route,
    // the bypasses per declared route, the flush outcome, and the
    // coverage evidence — and never names a session, a host, or a path.
    let text = String::from_utf8(manifest.canonical_bytes()).expect("manifest is utf8");
    assert!(text.contains("\"schema\":\"archivist.inference-coverage/v1\""));
    assert_eq!(INFERENCE_COVERAGE_SCHEMA, "archivist.inference-coverage/v1");
    assert_eq!(INFERENCE_COVERAGE_SCHEMA_VERSION, 1);
    assert!(text.contains("\"schema_version\":1"));
    assert!(text.contains("\"expectation_version\":1"));
    assert!(
        text.contains(&format!(
            "\"clients\":[{{\"evidence\":\"{}\"",
            client.evidence
        )),
        "the client row leads with its evidence: {text}"
    );
    assert!(
        text.contains("\"known_bypasses\":{\"proxy\":1,\"sdk_hook\":1,\"total\":2}"),
        "bypasses are named against their declared route: {text}"
    );
    assert!(
        text.contains("\"outcome\":\"incomplete\""),
        "a gate that never ran still names its flush outcome: {text}"
    );
    assert!(text.contains("\"state\":\"not_started\""));
    assert!(
        text.contains("\"semantic_sessions\":{\"backfilled\":0,\"current\":1"),
        "the semantic dimension rides in its own subtree: {text}"
    );
    assert!(
        !text.contains("session-"),
        "no session identifier enters the published document: {text}"
    );

    // The manifest is content-addressed: the digest a verification run
    // records is derived from exactly these bytes.
    assert_eq!(manifest.evidence_digest().len(), 64);
}

#[test]
fn a_claimed_client_without_traffic_reports_zeroes_not_coverage() {
    let report = TransportConformance::run(|| Box::new(LoopbackFixture::new().expect("bind")));
    assert_every_scene_passed(&report);

    let mut matrix = CompatibilityMatrix::new();
    matrix
        .record(&report)
        .expect("the qualified run earns its row");

    let manifest = InferenceCoverageManifest::publish(
        &matrix,
        &ExpectedInferenceLedger::new(),
        CoverageCounts::default(),
        &idle_flush_report(),
    );

    assert_eq!(manifest.clients().len(), 1);
    let client = &manifest.clients()[0];
    assert_eq!(client.coverage.observed, 0);
    assert_eq!(client.coverage.partial, 0);
    assert_eq!(client.coverage.failed, 0);
    assert_eq!(client.coverage.unobserved, 0);
    assert_eq!(client.coverage.open_expectations, 0);
    assert_eq!(manifest.known_bypass_total(), 0);
}
