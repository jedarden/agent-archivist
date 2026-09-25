// SPDX-License-Identifier: Apache-2.0

//! The doctor baselines pinned through the real `doctor --json
//! --non-interactive` binary surface: the compiled `archivist` binary runs
//! as a child process over a synthetic host, so the pinned observation is
//! the process's own — the exit status the registered class allocates, the
//! stdout envelope the router writes for a healthy examination, and the
//! stderr error document a refusal emits. The in-process seams in
//! `src/operator/tests.rs` pin the examination's decisions; this target
//! pins the two baselines an operator script branches on first, where the
//! router, the stream framing, and the exit-code allocation are the
//! behavior under test:
//!
//! - **A healthy fixture exits 0.** The migrated state carries one
//!   verified receipt, so every examination check passes, and the one
//!   permitted readiness request is answered by a loopback responder. The
//!   child exits 0 with the `archivist.cli-output/v1` envelope on stdout
//!   whose result is a findings document reporting nothing — every
//!   registered check `ok` — and empty stderr, because CLI-019 emits the
//!   result document only for a healthy run.
//! - **The missing-state smoke exits 74.** A fixture with no state at all
//!   refuses with the registered `client.state_io` class: exit 74, an
//!   empty stdout, and one `archivist.error/v1` document on stderr whose
//!   code is the only finding — no other registered doctor condition
//!   appears anywhere in the emitted bytes.
//!
//! The readiness responder is the smallest stand-in for the ingestion
//! endpoint the doctor may probe once: a loopback listener that answers
//! `GET /health/ready` with HTTP 200 and no body. It exists so neither
//! baseline depends on the network, and so the missing-state smoke's
//! readiness answer is true — its 74 comes from the state refusal, not
//! from an unreachable server.

use std::fs::Permissions;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use archivist_client_core::state::{STATE_DB_NAME, StateStore};
use archivist_protocol::json::{self, Value};
use rusqlite::params;

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// A private directory removed on drop, so file-backed fixtures never
/// share state and never leave debris behind.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "archivist-doctor-binary-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        // The state layer refuses any directory whose mode is not the
        // pinned 0700 (CFG-023), so the fixture creates the mode the
        // composition requires.
        std::fs::set_permissions(&dir, Permissions::from_mode(0o700))
            .expect("set the pinned directory mode");
        Self(dir)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A distinct 36-character `UUIDv7`-grammar identifier for whichever
/// table needs one. The grammar is the protocol's own (`uuid_grammar`:
/// lowercase hex, version nibble 7, variant `8..=b`), the same fixture
/// shape the operator surface's in-process tests enroll.
// The casts are the point: a fixture identity is the hash's own low
// bits sliced into the grammar's field widths, never a conversion.
#[allow(clippy::cast_possible_truncation)]
fn uid(tag: &str) -> String {
    let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let seed = seed_of(tag);
    format!(
        "{:08x}-{:04x}-7{:03x}-9{:03x}-{n:012x}",
        seed as u32,
        (seed >> 32) as u16,
        (seed >> 48) as u16 & 0x0fff,
        (seed as u16) & 0x0fff,
    )
}

/// A 64-character digest-shape filler.
fn digest(seed: u64) -> String {
    format!("{seed:064x}")
}

/// A distinct 64-bit seed derived from arbitrary text, so fixture rows
/// never collide on the schema's unique identity columns.
fn seed_of(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// A migrated file-backed state store in the directory the fixture
/// configuration names.
fn seeded_store(dir: &TempDir) -> StateStore {
    let mut store = StateStore::open(&dir.path().join(STATE_DB_NAME)).expect("open state store");
    store.migrate().expect("migrate state store");
    store
}

/// One verified receipt with its frozen request, so the doctor's linkage
/// check passes and the healthy fixture's only remaining answer is the
/// document. The schema's open does not pin the database mode, so the
/// fixture restores it.
fn linked_receipt(store: &StateStore, commit_time: &str) {
    let request_id = uid("req");
    store
        .connection()
        .execute(
            "INSERT INTO frozen_requests (
                 request_id, spool_entry_id, tenant_id, origin_client_id,
                 uploader_client_id, occurrence_id, envelope_version,
                 storage_profile, transport_encoding, canonical_digest,
                 incoming_checksum, canonical_size, transport_size, source_at,
                 captured_at, envelope_created_at, frozen_at)
             VALUES (?1, NULL, ?2, ?3, ?4, ?5, 'envelope-v1', 'zstd-v1',
                 'identity', ?6, 'sha256-raw', 1000, 800, NULL, ?7, ?7, ?7)",
            params![
                request_id,
                uid("tenant"),
                uid("origin"),
                uid("uploader"),
                digest(91),
                digest(93),
                commit_time,
            ],
        )
        .expect("insert frozen request");
    store
        .connection()
        .execute(
            "INSERT INTO receipts (
                 request_id, receipt_key_id, signature, receipt_digest,
                 commit_ordinal, commit_time, signature_verified, received_at)
             VALUES (?1, 'rk-2026-36', ?2, ?3, 1, ?4, 1, ?4)",
            params![request_id, "ab".repeat(64), digest(92), commit_time],
        )
        .expect("insert receipt");
    std::fs::set_permissions(
        store.connection().path().expect("file-backed store"),
        Permissions::from_mode(0o600),
    )
    .expect("restore the pinned database mode");
}

/// The loopback stand-in for the ingestion endpoint: a listener whose
/// single accepted connection is answered `200` for `GET /health/ready`,
/// the one readiness request a doctor examination is permitted. The
/// responder polls `accept` until the probe arrives or the deadline
/// passes, so a doctor that never probes fails the test with a named
/// panic instead of hanging the join.
struct ReadinessEndpoint {
    endpoint: String,
    responder: Option<std::thread::JoinHandle<()>>,
}

impl ReadinessEndpoint {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("the loopback listener binds");
        listener
            .set_nonblocking(true)
            .expect("the listener polls accept");
        let port = listener.local_addr().expect("the bound port reads").port();
        Self {
            endpoint: format!("http://127.0.0.1:{port}"),
            responder: Some(std::thread::spawn(move || serve_readiness(&listener))),
        }
    }

    /// The endpoint URL the fixture configuration names for the ingest
    /// service.
    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Wait for the one readiness exchange to complete, propagating the
    /// responder's own failures as test failures.
    fn finish(mut self) {
        self.responder
            .take()
            .expect("the responder joins once")
            .join()
            .expect("the readiness exchange completed");
    }
}

impl Drop for ReadinessEndpoint {
    fn drop(&mut self) {
        if let Some(responder) = self.responder.take() {
            let _ = responder.join();
        }
    }
}

/// Answer one readiness probe: read the request head, require the
/// registered readiness route, answer `200` with no body, and hang up.
fn serve_readiness(listener: &TcpListener) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("the readiness listener accepts: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "the doctor's readiness probe never arrived"
        );
        std::thread::sleep(Duration::from_millis(2));
    };
    let mut request = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        let read = stream.read(&mut chunk).expect("the probe's request reads");
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&request).starts_with("GET /health/ready "),
        "the doctor probes the readiness route, not {:?}",
        String::from_utf8_lossy(&request)
    );
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .and_then(|()| stream.flush())
        .expect("the readiness answer writes");
    let _ = stream.shutdown(Shutdown::Both);
}

/// The synthetic host's configuration, composed exactly the way the
/// operator surface's in-process fixtures are: every required key through
/// the environment tier, `HOME` and the XDG roots inside the fixture so
/// no real host configuration can leak into the child, the credentials as
/// never-resolved references (CLI-024 — the doctor resolves no secret),
/// and the responder as the ingest endpoint the doctor may probe once.
fn child_environment(dir: &TempDir, endpoint: &str) -> Vec<(&'static str, String)> {
    let home = dir.path().to_string_lossy().into_owned();
    vec![
        ("HOME", home.clone()),
        (
            "XDG_CONFIG_HOME",
            dir.path().join("xdg").to_string_lossy().into_owned(),
        ),
        ("ARCHIVIST_CLIENT_STATE_DIR", home),
        ("ARCHIVIST_SPOOL_FREE_FLOOR_BYTES", "1".to_owned()),
        ("ARCHIVIST_INGEST_ENDPOINT_URL", endpoint.to_owned()),
        (
            "ARCHIVIST_STORAGE_ENDPOINT_URL",
            "https://s3.example.invalid".to_owned(),
        ),
        ("ARCHIVIST_STORAGE_REGION", "us-east-1".to_owned()),
        ("ARCHIVIST_STORAGE_ENCRYPTION", "s3_sse".to_owned()),
        (
            "ARCHIVIST_STORAGE_RAW_BUCKET",
            "archivist-raw-example".to_owned(),
        ),
        (
            "ARCHIVIST_STORAGE_CONTROL_BUCKET",
            "archivist-control-example".to_owned(),
        ),
        (
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            "env:TEST_RAW_CREDENTIAL".to_owned(),
        ),
        (
            "ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF",
            "env:TEST_CONTROL_CREDENTIAL".to_owned(),
        ),
        ("ARCHIVIST_SERVER_LISTEN_ADDRESS", "127.0.0.1:0".to_owned()),
    ]
}

/// Run the compiled binary's `doctor` command in JSON non-interactive
/// mode over the fixture and capture its real streams.
fn run_doctor(dir: &TempDir, endpoint: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_archivist"));
    command.args(["doctor", "--json", "--non-interactive"]);
    for (name, value) in child_environment(dir, endpoint) {
        command.env(name, value);
    }
    command.output().expect("the archivist binary runs")
}

/// The named member of a document object, failing the test when absent.
fn member<'a>(document: &'a Value, name: &str) -> &'a Value {
    match document {
        Value::Object(object) => object
            .get(name)
            .unwrap_or_else(|| panic!("the document carries {name}")),
        other => panic!("expected an object carrying {name}, found {other:?}"),
    }
}

/// The named text member, failing the test when the member is absent or
/// not text.
fn text_member<'a>(document: &'a Value, name: &str) -> &'a str {
    match member(document, name) {
        Value::Text(text) => text,
        other => panic!("{name} is a text member, found {other:?}"),
    }
}

/// Parse one stream's canonical document: the router writes exactly one
/// canonical JSON value followed by one newline.
fn stream_document(bytes: &[u8]) -> Value {
    let text = std::str::from_utf8(bytes).expect("the stream is utf-8");
    json::parse(text.trim_end_matches('\n').as_bytes())
        .expect("the stream carries one JSON document")
}

#[test]
fn the_healthy_fixture_exits_zero_emitting_a_document_with_no_findings() {
    let dir = TempDir::new("healthy");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_eq!(output.status.code(), Some(0), "the healthy doctor exits 0");
    assert!(
        output.stderr.is_empty(),
        "a healthy doctor writes no diagnostic, found {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope = stream_document(&output.stdout);
    assert_eq!(text_member(&envelope, "schema"), "archivist.cli-output/v1");
    assert_eq!(text_member(&envelope, "command"), "doctor");
    let result = member(&envelope, "result");
    assert_eq!(text_member(result, "schema"), "archivist.cli-result/v1");
    assert_eq!(text_member(result, "verdict"), "ok");
    // A findings document that reports nothing: every registered check
    // answers, and every answer is `ok`.
    let checks = member(result, "checks");
    match checks {
        Value::Object(object) => {
            assert_eq!(object.iter().count(), 9, "every registered check answers");
            for (name, verdict) in object.iter() {
                assert_eq!(verdict, &Value::Text("ok".to_owned()), "{name} passes");
            }
        }
        other => panic!("the checks are an object, found {other:?}"),
    }
}

#[test]
fn the_missing_state_smoke_exits_seventy_four_with_only_the_state_io_finding() {
    let dir = TempDir::new("missing-state");
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_eq!(
        output.status.code(),
        Some(74),
        "the missing-state refusal is the registered local_state class"
    );
    assert!(
        output.stdout.is_empty(),
        "a failed doctor emits no result document (CLI-019), found {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let document = stream_document(&output.stderr);
    assert_eq!(text_member(&document, "schema"), "archivist.error/v1");
    assert_eq!(text_member(&document, "code"), "client.state_io");
    assert_eq!(member(&document, "retryable"), &Value::Bool(false));
    // The emitted document carries only the state_io finding: no other
    // registered doctor condition appears anywhere in the refusal.
    let stderr = String::from_utf8(output.stderr).expect("the refusal is utf-8");
    for other in [
        "client.permissions",
        "client.state_corrupt",
        "client.source_unreadable",
        "client.disk_floor",
        "client.clock_skew",
        "server.unavailable",
        "auth.unlinked",
    ] {
        assert!(
            !stderr.contains(other),
            "only the state_io finding appears, found {other}"
        );
    }
}
