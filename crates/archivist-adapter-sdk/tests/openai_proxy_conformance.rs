// SPDX-License-Identifier: Apache-2.0

//! The real-boundary execution of the proxy exact-capture conformance
//! suite (plan Phase 9): [`ProxyConformance::run`] drives the capture
//! proxy over actual TCP loopback connections — the proxy's own
//! transport connects to this file's scripted provider fixture, and the
//! suite's caller connects to the proxy — and this file holds the
//! qualification and compatibility-matrix consequences: a passing run
//! is the one thing that mints the proxy route's qualification
//! evidence and puts the proxy route in the matrix, and a failing run
//! puts nothing anywhere.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use archivist_adapter_sdk::compatibility::{
    CompatibilityMatrix, FIRST_PARTY_OPENAI_HTTP1, FIRST_PARTY_OPENAI_PROXY, MatrixError,
};
use archivist_adapter_sdk::expected_inference::RoutePolicy;
use archivist_adapter_sdk::openai_conformance::{
    ConformanceError, ConformanceReport, OpenAiWireFixture, ReceivedExchange, TransportConformance,
    WireScript,
};
use archivist_adapter_sdk::openai_http1::WireEndpoint;
use archivist_adapter_sdk::openai_proxy_conformance::{
    ProxyConformance, ProxyConformanceReport, ProxyWireFixture, ProxyWireScript,
};

const LOOPBACK: &str = "127.0.0.1";

/// The shared state between the fixture handle and its server thread.
struct Shared {
    scripts: Mutex<VecDeque<ProxyWireScript>>,
    received: Mutex<Vec<ReceivedExchange>>,
    progress: AtomicUsize,
    done: AtomicBool,
}

/// A real loopback TCP server, scripted one connection at a time. Every
/// scene gets a fresh listener on an ephemeral port; the server thread
/// serves exactly the queued scripts and exits when the script queue
/// drains, so no connection outlives its scene.
struct LoopbackProvider {
    endpoint: WireEndpoint,
    listener: Option<TcpListener>,
    shared: Arc<Shared>,
}

impl LoopbackProvider {
    /// Bind a listener on an ephemeral loopback port; its server thread
    /// starts with the first queued script (see [`Self::queue`]).
    fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind((LOOPBACK, 0))?;
        let port = listener.local_addr()?.port();
        let endpoint =
            WireEndpoint::new(LOOPBACK.to_owned(), port).expect("the loopback hostname is valid");
        let shared = Arc::new(Shared {
            scripts: Mutex::new(VecDeque::new()),
            received: Mutex::new(Vec::new()),
            progress: AtomicUsize::new(0),
            done: AtomicBool::new(false),
        });
        Ok(Self {
            endpoint,
            listener: Some(listener),
            shared,
        })
    }
}

/// Serve connections until the script queue drains. Each accepted
/// connection reads one full request, records it, and executes the next
/// script against the same socket the request arrived on.
fn serve(listener: &TcpListener, shared: &Shared) {
    loop {
        let Some(script) = shared.scripts.lock().expect("script lock").pop_front() else {
            return;
        };
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let raw_request = read_request(&mut stream);
        shared
            .received
            .lock()
            .expect("received lock")
            .push(ReceivedExchange { raw_request });
        match script {
            ProxyWireScript::Raw(bytes) => {
                let _ = stream.write_all(&bytes);
                let _ = stream.shutdown(Shutdown::Write);
                // Hold the read side open until the proxy hangs up, so
                // the response delivery stays orderly end to end.
                let _ = stream.read(&mut [0_u8; 16]);
            }
            ProxyWireScript::Reset => {
                // The request is read and the connection is dropped
                // without a response byte: the below-the-boundary
                // teardown the proxy must classify as a transport
                // error, never decode.
                drop(stream);
            }
            ProxyWireScript::MeasuredStream {
                head,
                chunks,
                terminal,
            } => {
                // Push every byte through the socket, retrying
                // would-block writes until the deadline, and count the
                // bytes that made it: a stalled socket freezes the
                // measured progress instead of the relay growing.
                let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                let deadline = Instant::now() + Duration::from_secs(30);
                let push = |stream: &mut TcpStream, bytes: &[u8], counted: bool| -> bool {
                    let mut bytes = bytes;
                    while !bytes.is_empty() {
                        if Instant::now() > deadline {
                            return false;
                        }
                        match stream.write(bytes) {
                            Ok(0) => return false,
                            Ok(count) => {
                                // Only streamed body bytes count as
                                // progress: the scene's bound check
                                // pins the delivered body length, and
                                // the head and terminal frames are
                                // framing, not body.
                                if counted {
                                    shared.progress.fetch_add(count, Ordering::Relaxed);
                                }
                                bytes = &bytes[count..];
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            Err(_) => return false,
                        }
                    }
                    true
                };
                if !push(&mut stream, &head, false) {
                    return;
                }
                for chunk in &chunks {
                    if !push(&mut stream, chunk, true) {
                        return;
                    }
                }
                push(&mut stream, &terminal, false);
                shared.done.store(true, Ordering::Relaxed);
                let _ = stream.shutdown(Shutdown::Write);
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

/// The shared state between the HTTP/1.1 suite's fixture handle and its
/// server thread. The first-party client suite keeps its own state
/// type: the proxy fixture's shared state carries relay-measurement
/// fields the client suite does not use.
struct Http1Shared {
    scripts: Mutex<VecDeque<WireScript>>,
    received: Mutex<Vec<ReceivedExchange>>,
}

/// A real loopback TCP server for the first-party client suite, so one
/// compatibility matrix can be recorded from both first-party routes'
/// conformance runs. The script execution is the transport suite's
/// fixture's: raw bytes, resets, and stalls on real sockets.
struct Http1Loopback {
    endpoint: WireEndpoint,
    listener: Option<TcpListener>,
    shared: Arc<Http1Shared>,
}

impl Http1Loopback {
    /// Bind a listener on an ephemeral loopback port; its server thread
    /// starts with the first queued script (see [`Self::queue`]).
    fn new() -> std::io::Result<Self> {
        let listener = TcpListener::bind((LOOPBACK, 0))?;
        let port = listener.local_addr()?.port();
        let endpoint =
            WireEndpoint::new(LOOPBACK.to_owned(), port).expect("the loopback hostname is valid");
        let shared = Arc::new(Http1Shared {
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

/// Serve the first-party client's connections until its script queue
/// drains; each accepted connection reads one full request, records
/// it, and executes the next script against the same socket.
fn serve_http1(listener: &TcpListener, shared: &Http1Shared) {
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

impl OpenAiWireFixture for Http1Loopback {
    fn endpoint(&mut self) -> Result<WireEndpoint, ConformanceError> {
        Ok(self.endpoint.clone())
    }

    fn queue(&mut self, script: WireScript) {
        self.shared
            .scripts
            .lock()
            .expect("script lock")
            .push_back(script);
        // Spawn only once a script exists: the server's loop exits when
        // the queue drains, so starting it earlier would race the
        // scene's setup and drop the exchange on the floor.
        if let Some(listener) = self.listener.take() {
            let shared = Arc::clone(&self.shared);
            std::thread::spawn(move || serve_http1(&listener, &shared));
        }
    }

    fn received(&self) -> Vec<ReceivedExchange> {
        self.shared.received.lock().expect("received lock").clone()
    }
}

impl ProxyWireFixture for LoopbackProvider {
    fn endpoint(&mut self) -> Result<WireEndpoint, ConformanceError> {
        Ok(self.endpoint.clone())
    }

    fn queue(&mut self, script: ProxyWireScript) {
        self.shared
            .scripts
            .lock()
            .expect("script lock")
            .push_back(script);
        // Spawn only once a script exists: the server's loop exits when
        // the queue drains, so starting it earlier would race the
        // scene's setup and drop the exchange on the floor.
        if let Some(listener) = self.listener.take() {
            let shared = Arc::clone(&self.shared);
            std::thread::spawn(move || serve(&listener, &shared));
        }
    }

    fn received(&self) -> Vec<ReceivedExchange> {
        self.shared.received.lock().expect("received lock").clone()
    }

    fn measured_progress(&self) -> usize {
        self.shared.progress.load(Ordering::Relaxed)
    }

    fn measured_done(&self) -> bool {
        self.shared.done.load(Ordering::Relaxed)
    }
}

/// A fixture that cannot present an endpoint: every scene fails at
/// construction, producing the unqualified report that mints nothing.
struct BrokenFixture;

impl ProxyWireFixture for BrokenFixture {
    fn endpoint(&mut self) -> Result<WireEndpoint, ConformanceError> {
        Err(ConformanceError::EndpointInvalid)
    }

    fn queue(&mut self, _script: ProxyWireScript) {}

    fn received(&self) -> Vec<ReceivedExchange> {
        Vec::new()
    }

    fn measured_progress(&self) -> usize {
        0
    }

    fn measured_done(&self) -> bool {
        false
    }
}

/// Panic with the per-scene failed checks when any scene fails, so a
/// regression names its property instead of just its scene.
fn assert_every_scene_passed(report: &ProxyConformanceReport) {
    for scene in report.scenes() {
        assert!(
            scene.passed(),
            "proxy conformance scene {:?} failed checks {:#?}",
            scene.scene,
            scene.failed_checks
        );
    }
    assert!(
        report.passed(),
        "the proxy conformance run passed every scene"
    );
}

#[test]
fn the_real_boundary_qualifies_the_proxy_route() {
    let report = ProxyConformance::run(|| Box::new(LoopbackProvider::new().expect("bind")));
    assert_every_scene_passed(&report);

    let qualification = report
        .qualification()
        .expect("a fully-passing run mints the qualification");
    assert_eq!(qualification.route(), RoutePolicy::Proxy);
    assert_eq!(qualification.integration(), FIRST_PARTY_OPENAI_PROXY);
    assert_eq!(qualification.lifecycle_version(), 1);
    assert_eq!(qualification.evidence_digest().len(), 64);
}

#[test]
fn an_unqualified_run_earns_no_qualification() {
    let report = ProxyConformance::run(|| Box::new(BrokenFixture));
    assert!(!report.passed());
    assert!(report.qualification().is_none());
    assert!(report.evidence_digest().is_none());
}

/// Panic with the per-scene failed checks when any scene of the
/// first-party client suite fails, so a regression names its property
/// instead of just its scene.
fn assert_every_client_scene_passed(report: &ConformanceReport) {
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
fn the_matrix_admits_exactly_the_qualified_proxy_route() {
    let report = ProxyConformance::run(|| Box::new(LoopbackProvider::new().expect("bind")));
    assert_every_scene_passed(&report);

    let mut matrix = CompatibilityMatrix::new();
    assert!(matrix.is_empty());

    matrix
        .record_proxy(&report)
        .expect("a qualified report earns its row");
    assert_eq!(matrix.len(), 1);
    assert!(matrix.is_qualified(RoutePolicy::Proxy));
    assert!(!matrix.is_qualified(RoutePolicy::SdkHook));

    let row = matrix.route(RoutePolicy::Proxy).expect("the row");
    assert_eq!(row.integration(), FIRST_PARTY_OPENAI_PROXY);

    // Re-recording the same evidence is idempotent: one route, one row.
    matrix
        .record_proxy(&report)
        .expect("re-recording identical evidence is idempotent");
    assert_eq!(matrix.len(), 1);
}

#[test]
fn an_unqualified_proxy_run_earns_no_matrix_row() {
    let report = ProxyConformance::run(|| Box::new(BrokenFixture));
    assert!(!report.passed());
    assert!(report.qualification().is_none());

    let mut matrix = CompatibilityMatrix::new();
    assert!(matches!(
        matrix.record_proxy(&report),
        Err(MatrixError::Unqualified)
    ));
    assert!(matrix.is_empty());
}

#[test]
fn the_matrix_reports_both_first_party_routes_alongside() {
    let client_report = TransportConformance::run(|| Box::new(Http1Loopback::new().expect("bind")));
    assert_every_client_scene_passed(&client_report);
    let proxy_report = ProxyConformance::run(|| Box::new(LoopbackProvider::new().expect("bind")));
    assert_every_scene_passed(&proxy_report);

    let mut matrix = CompatibilityMatrix::new();
    matrix
        .record(&client_report)
        .expect("the client route earns its row");
    assert_eq!(matrix.len(), 1);
    matrix
        .record_proxy(&proxy_report)
        .expect("the proxy route earns its own row beside it");
    assert_eq!(matrix.len(), 2);

    // Each route's row names its own integration token: recording the
    // proxy route did not displace the client route.
    assert_eq!(
        matrix
            .route(RoutePolicy::SdkHook)
            .expect("client row")
            .integration(),
        FIRST_PARTY_OPENAI_HTTP1
    );
    assert_eq!(
        matrix
            .route(RoutePolicy::Proxy)
            .expect("proxy row")
            .integration(),
        FIRST_PARTY_OPENAI_PROXY
    );

    // Re-recording either run stays at two rows.
    matrix.record(&client_report).expect("idempotent");
    matrix.record_proxy(&proxy_report).expect("idempotent");
    assert_eq!(matrix.len(), 2);
}
