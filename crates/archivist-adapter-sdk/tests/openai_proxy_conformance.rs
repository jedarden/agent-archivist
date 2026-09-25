// SPDX-License-Identifier: Apache-2.0

//! The real-boundary execution of the proxy exact-capture conformance
//! suite (plan Phase 9): [`ProxyConformance::run`] drives the capture
//! proxy over actual TCP loopback connections — the proxy's own
//! transport connects to this file's scripted provider fixture, and the
//! suite's caller connects to the proxy — and this file holds the
//! qualification consequences: a passing run is the one thing that
//! mints the proxy route's qualification evidence, and a failing run
//! mints nothing.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use archivist_adapter_sdk::compatibility::FIRST_PARTY_OPENAI_PROXY;
use archivist_adapter_sdk::expected_inference::RoutePolicy;
use archivist_adapter_sdk::openai_conformance::{ConformanceError, ReceivedExchange};
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
