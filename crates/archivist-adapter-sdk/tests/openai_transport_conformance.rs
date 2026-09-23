// SPDX-License-Identifier: Apache-2.0

//! The real-boundary execution of the exact-capture conformance suite
//! (plan Phase 9): [`TransportConformance::run`] drives the first-party
//! OpenAI-compatible client over actual TCP loopback connections —
//! scripted raw bytes, resets, and stalls on real sockets — and this
//! file holds the qualification and compatibility-matrix consequences:
//! a passing run is the one thing that can put the first-party route in
//! the matrix, and a failing run puts nothing anywhere.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use archivist_adapter_sdk::compatibility::{CompatibilityMatrix, FIRST_PARTY_OPENAI_HTTP1};
use archivist_adapter_sdk::expected_inference::RoutePolicy;
use archivist_adapter_sdk::openai_conformance::{
    ConformanceError, ConformanceReport, OpenAiWireFixture, ReceivedExchange, TransportConformance,
    WireScript,
};
use archivist_adapter_sdk::openai_http1::WireEndpoint;

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
    shared: Arc<Shared>,
}

impl LoopbackFixture {
    /// Bind a listener on an ephemeral loopback port and spawn its
    /// server thread.
    fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind((LOOPBACK, 0))?;
        let port = listener.local_addr()?.port();
        let endpoint =
            WireEndpoint::new(LOOPBACK.to_owned(), port).expect("the loopback hostname is valid");
        let shared = Arc::new(Shared {
            scripts: Mutex::new(VecDeque::new()),
            received: Mutex::new(Vec::new()),
        });
        let server_shared = Arc::clone(&shared);
        std::thread::spawn(move || serve(listener, server_shared));
        Ok(Self { endpoint, shared })
    }
}

/// Serve connections until the script queue drains. Each accepted
/// connection reads one full request, records it, and executes the next
/// script against the same socket the request arrived on.
fn serve(listener: TcpListener, shared: Arc<Shared>) {
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
                // Hold the read side open until the client hangs up, so
                // the response delivery stays orderly end to end.
                let _ = stream.read(&mut [0_u8; 16]);
            }
            WireScript::Reset => {
                // The request is read and the connection is dropped
                // without a response byte: the below-the-boundary
                // teardown the client must classify as a reset.
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
    }

    fn received(&self) -> Vec<ReceivedExchange> {
        self.shared.received.lock().expect("received lock").clone()
    }
}

/// A fixture that cannot present an endpoint: every scene fails at
/// construction, producing the unqualified report the matrix must
/// reject.
struct BrokenFixture;

impl OpenAiWireFixture for BrokenFixture {
    fn endpoint(&mut self) -> Result<WireEndpoint, ConformanceError> {
        Err(ConformanceError::EndpointInvalid)
    }

    fn queue(&mut self, _script: WireScript) {}

    fn received(&self) -> Vec<ReceivedExchange> {
        Vec::new()
    }
}

/// Panic with the per-scene failed checks when any scene fails, so a
/// regression names its property instead of just its scene.
fn assert_every_scene_passed(report: &ConformanceReport) {
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

#[test]
fn the_real_boundary_qualifies_the_first_party_route() {
    let report = TransportConformance::run(|| Box::new(LoopbackFixture::new().expect("bind")));
    assert_every_scene_passed(&report);

    let qualification = report
        .qualification()
        .expect("a fully-passing run mints the qualification");
    assert_eq!(qualification.route(), RoutePolicy::SdkHook);
    assert_eq!(qualification.integration(), FIRST_PARTY_OPENAI_HTTP1);
    assert_eq!(qualification.lifecycle_version(), 1);
    assert_eq!(qualification.evidence_digest().len(), 64);
}

#[test]
fn the_matrix_admits_exactly_the_qualified_route() {
    let report = TransportConformance::run(|| Box::new(LoopbackFixture::new().expect("bind")));
    assert_every_scene_passed(&report);

    let mut matrix = CompatibilityMatrix::new();
    assert!(matrix.is_empty());

    matrix
        .record(&report)
        .expect("a qualified report earns its row");
    assert_eq!(matrix.len(), 1);
    assert!(matrix.is_qualified(RoutePolicy::SdkHook));
    assert!(!matrix.is_qualified(RoutePolicy::Proxy));

    let row = matrix.route(RoutePolicy::SdkHook).expect("the row");
    assert_eq!(row.integration(), FIRST_PARTY_OPENAI_HTTP1);

    // Re-recording the same evidence is idempotent: one route, one row.
    matrix
        .record(&report)
        .expect("re-recording identical evidence is idempotent");
    assert_eq!(matrix.len(), 1);
}

#[test]
fn an_unqualified_run_earns_no_matrix_row() {
    let report = TransportConformance::run(|| Box::new(BrokenFixture));
    assert!(!report.passed());
    assert!(report.qualification().is_none());
    assert!(report.evidence_digest().is_none());

    let mut matrix = CompatibilityMatrix::new();
    assert!(
        matches!(
            matrix.record(&report),
            Err(archivist_adapter_sdk::compatibility::MatrixError::Unqualified)
        ),
        "an unqualified run must be refused, not recorded"
    );
    assert!(matrix.is_empty());
}
