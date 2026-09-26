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
//! The same surface pins the examination's zero-mutation guarantee, the
//! row of the local-state matrix a healthy run is the strongest witness
//! for — the process examined state and answered `ok`, so any byte that
//! moved is a defect the assertions name. Both tests hold the fixture's
//! write connection open across the child's run, exactly the shape
//! CLI-007 names — the report composes *while a mutator owns the
//! directory* — so the pinned tree is a live one, not a quiescent
//! leftover:
//!
//! - **A foreign-held lock is reported with zero state creation.** The
//!   fixture holds the advisory lock the way a daemon mid-life does, and
//!   the examination answers anyway (CLI-007): exit 0, the registered
//!   `lock_ownership` check `ok`, the evidence's lock state `held`, and
//!   the state directory's whole recursive shape unchanged across the
//!   run — the probe opened the holder's lock file without creating one,
//!   and no spool, journal, or side file of any kind appeared.
//! - **The examination leaves the state database byte-identical.** Over
//!   a populated state the full run — every registered check, every
//!   read-only query — returns the exact bytes the writer left: the
//!   database and its write-ahead log byte-for-byte identical, no
//!   journal, and no residue the examination brought into the directory.
//!   The one file whose bytes a correct reader may mark is `SQLite`'s
//!   wal-index (`-shm`) — the reader's read-mark is what keeps a
//!   concurrent checkpoint behind the read — so its presence is pinned
//!   and its bytes are left to `SQLite`.
//!
//! The same surface completes the induced local-state failure matrix:
//! every row a non-mutating examination reports as a registered refusal,
//! induced hermetically over an otherwise-healthy fixture — one verified
//! receipt, an answered readiness probe — so the induced condition is
//! the only finding and the row's refusal is the whole observable
//! outcome. The rows: a configuration that cannot resolve (the usage
//! class, retired before the examination creates or opens any state),
//! loose state-database, lock-file, and spool modes (the permissions
//! class), a stale migration version, a foreign-key orphan, and a
//! dropped expected index (the corruption class), and a free-space
//! floor above the filesystem's free space (the resource class, with
//! its distinct exit 75). Each pinned observation is the compiled
//! process's own: the exit status the registered class allocates, no
//! result document on stdout (CLI-019), and one content-free
//! `archivist.error/v1` refusal on stderr whose code is the registered
//! finding — never a path, a row, or an object name the examination
//! read.
//!
//! The same surface pins the mutator's own creation posture (CFG-023):
//! the state `run --once` creates over a fresh directory lands at the
//! pinned modes — the database `0600`, never a umask default — a
//! database loosened the way an out-of-band writer would is refused by
//! the mutator itself with the registered local-state class before the
//! driver touches the file, and the binary's own fresh state verifies
//! healthy through the examination once it carries a receipt: the row
//! that cannot pass while the creation mode is unpinned, since a
//! umask-default database mode is itself the permissions refusal.
//!
//! The same surface completes the environment and remote rows of the
//! matrix over the same hermetic otherwise-healthy fixture shape: a
//! persisted adapter-health record left degraded (the source-readability
//! class), a durable event years ahead of the local clock — far beyond
//! the five-minute allowance `CLOCK_SKEW_ALLOWANCE_SECONDS` grants —
//! (the clock-sanity class), an ingest endpoint nothing answers and one
//! that answers without establishing ready (the server-readiness class,
//! exit 75), and a migrated state carrying no server-issued receipt at
//! all (the authorization class, exit 78). One row pins the bound
//! itself: an endpoint that accepts the connection and never answers
//! still leaves the process exiting with the registered refusal inside
//! the probe's own bounded window — never an unbounded network wait.
//! Every new row also carries the zero-mutation guarantee the baselines
//! pin: the recursive state shape — every byte the writer left — is
//! identical across the run.
//!
//! The readiness responder is the smallest stand-in for the ingestion
//! endpoint the doctor may probe once: a loopback listener that answers
//! `GET /health/ready` with HTTP 200 and no body, or — for the
//! not-ready row — with 503. It exists so neither baseline depends on
//! the network, and so the missing-state smoke's readiness answer is
//! true — its 74 comes from the state refusal, not from an unreachable
//! server.
//!
//! Every document the matrix emits is also run through the redaction
//! audit: a byte-level scan asserting that no output document — the
//! healthy result documents and the registered refusals alike — carries
//! an absolute path, an identifier, a secret, `SQL` text, or an
//! operating-system error string, the contract
//! `archivist_client_core::doctor` states: findings are closed enum
//! values, evidence is limited to modes, counters, timestamps, and lock
//! state, and every condition maps to a registered error code. Exactly
//! two by-design contents are excused by value — the emitted namespaces
//! themselves and the error envelope's freshly minted correlation
//! identifier, derived from the wall clock and host randomness and
//! never from anything the examination read. Everything else is
//! scanned: the fixture path, every fixture identifier the harness has
//! minted, absolute-path shapes, identifier- and `UUID`-grammar tokens,
//! the read-only queries' own `SQL` vocabulary, and the classic
//! operating-system error texts. The audit's own rows at the foot of
//! this target plant each forbidden class to prove the scan still
//! detects what it forbids.

use std::ffi::OsStr;
use std::fs::Permissions;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use archivist_client_core::spool::SPOOL_DIR_NAME;
use archivist_client_core::state::lock::{LOCK_FILE_NAME, StateDirLock};
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

/// Every fixture identifier, digest, and secret the harness has minted
/// so far, registered at mint time and audited against every emitted
/// document. The registry accumulates across rows — a superset of any
/// one row's own values, which is safe: no document may carry any of
/// them, whichever row minted it.
static NEEDLES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Register one fixture value the audit must never see in an emitted
/// document.
fn register_needle(value: &str) {
    NEEDLES
        .lock()
        .expect("the needle registry locks")
        .push(value.to_owned());
}

/// The needles registered so far, as the audit reads them.
fn registered_needles() -> Vec<String> {
    NEEDLES.lock().expect("the needle registry locks").clone()
}

/// A distinct 36-character `UUIDv7`-grammar identifier for whichever
/// table needs one. The grammar is the protocol's own (`uuid_grammar`:
/// lowercase hex, version nibble 7, variant `8..=b`), the same fixture
/// shape the operator surface's in-process tests enroll. Every value is
/// registered as an audit needle at mint time.
// The casts are the point: a fixture identity is the hash's own low
// bits sliced into the grammar's field widths, never a conversion.
#[allow(clippy::cast_possible_truncation)]
fn uid(tag: &str) -> String {
    let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let seed = seed_of(tag);
    let identifier = format!(
        "{:08x}-{:04x}-7{:03x}-9{:03x}-{n:012x}",
        seed as u32,
        (seed >> 32) as u16,
        (seed >> 48) as u16 & 0x0fff,
        (seed as u16) & 0x0fff,
    );
    register_needle(&identifier);
    identifier
}

/// A 64-character digest-shape filler, registered as an audit needle at
/// mint time.
fn digest(seed: u64) -> String {
    let digest = format!("{seed:064x}");
    register_needle(&digest);
    digest
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
/// document.
fn linked_receipt(store: &StateStore, commit_time: &str) {
    let request_id = uid("req");
    // The receipt row's own secret material and key identifier are
    // fixture content: registered so the audit would reject any
    // document that echoed them back.
    register_needle("rk-2026-36");
    let signature = "ab".repeat(64);
    register_needle(&signature);
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
            params![request_id, signature, digest(92), commit_time],
        )
        .expect("insert receipt");
}

/// The readiness answer the healthy fixtures receive: HTTP 200 for the
/// registered readiness route, no body.
const READY_ANSWER: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The answer an ingestion endpoint under load gives without establishing
/// ready: HTTP 503. The examination accepts only a `200`, so this is the
/// not-ready row's whole induction.
const BUSY_ANSWER: &str =
    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The loopback stand-in for the ingestion endpoint: a listener whose
/// single accepted connection is answered `200` — or, for the not-ready
/// row, `503` — for `GET /health/ready`, the one readiness request a
/// doctor examination is permitted. The responder polls `accept` until
/// the probe arrives or the deadline passes, so a doctor that never
/// probes fails the test with a named panic instead of hanging the join.
struct ReadinessEndpoint {
    endpoint: String,
    responder: Option<std::thread::JoinHandle<()>>,
}

impl ReadinessEndpoint {
    fn start() -> Self {
        Self::answering(READY_ANSWER)
    }

    /// An ingestion endpoint that is reachable but does not establish
    /// ready: the server-readiness row's completed-request induction.
    fn not_ready() -> Self {
        Self::answering(BUSY_ANSWER)
    }

    fn answering(answer: &'static str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("the loopback listener binds");
        listener
            .set_nonblocking(true)
            .expect("the listener polls accept");
        let port = listener.local_addr().expect("the bound port reads").port();
        Self {
            endpoint: format!("http://127.0.0.1:{port}"),
            responder: Some(std::thread::spawn(move || {
                serve_readiness(&listener, answer);
            })),
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
/// registered readiness route, write the endpoint's fixed answer, and
/// hang up.
fn serve_readiness(listener: &TcpListener, answer: &'static str) {
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
        .write_all(answer.as_bytes())
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
/// The spool free-space floor is the row's own dial: a healthy fixture
/// names `1`, and the spool-space row names a floor above any fixture
/// filesystem's free space.
fn child_environment(dir: &TempDir, endpoint: &str, floor: &str) -> Vec<(&'static str, String)> {
    let home = dir.path().to_string_lossy().into_owned();
    vec![
        ("HOME", home.clone()),
        (
            "XDG_CONFIG_HOME",
            dir.path().join("xdg").to_string_lossy().into_owned(),
        ),
        ("ARCHIVIST_CLIENT_STATE_DIR", home),
        ("ARCHIVIST_SPOOL_FREE_FLOOR_BYTES", floor.to_owned()),
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

/// Assemble the compiled binary's `doctor` invocation over the fixture
/// host — the binary and the synthetic environment — without running
/// it, so a row may add its own global flags before the command word.
fn doctor_command(dir: &TempDir, endpoint: &str, floor: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_archivist"));
    for (name, value) in child_environment(dir, endpoint, floor) {
        command.env(name, value);
    }
    command
}

/// Run the compiled binary's `doctor` command in JSON non-interactive
/// mode over the fixture and capture its real streams, with the spool
/// free-space floor a healthy fixture passes.
fn run_doctor(dir: &TempDir, endpoint: &str) -> Output {
    run_doctor_with_floor(dir, endpoint, "1")
}

/// The spool-space row's invocation: the same examination over the same
/// fixture, with the free-space floor the row itself names.
fn run_doctor_with_floor(dir: &TempDir, endpoint: &str, floor: &str) -> Output {
    let mut command = doctor_command(dir, endpoint, floor);
    command.args(["doctor", "--json", "--non-interactive"]);
    command.output().expect("the archivist binary runs")
}

/// The configuration-resolution row's invocation: an explicit `--config`
/// naming a path the loader must but cannot read, so the refusal retires
/// the examination before it runs.
fn run_doctor_with_config(dir: &TempDir, endpoint: &str, config: &Path) -> Output {
    let mut command = doctor_command(dir, endpoint, "1");
    command.arg("--config").arg(config);
    command.args(["doctor", "--json", "--non-interactive"]);
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

// The redaction audit. `archivist_client_core::doctor`'s contract is that
// nothing an examination returns can carry a path, an identifier, a
// secret, `SQL` text, or an operating-system error string: findings are
// closed enum values, evidence is limited to modes, counters, timestamps,
// and lock state, and every condition maps to a registered error code.
// The audit pins that contract over the emitted bytes themselves, so a
// future member of either document shape that starts carrying any of the
// forbidden classes trips it before a consumer ever sees the document.

/// The namespaces an emitted document names. They are excused from the
/// path scan by value — their tokens are the by-design slash carriers —
/// so the path scan sees every other slash in the document.
const EMITTED_NAMESPACES: [&str; 3] = [
    "archivist.cli-output/v1",
    "archivist.cli-result/v1",
    "archivist.error/v1",
];

/// The identifier threshold: an alphanumeric token of this length or
/// longer is identifier-shaped. Legitimate members stay below it — check
/// names, evidence keys, registry message words, and the counters' and
/// mode literals' numeral runs — while every fixture identifier, digest,
/// and secret sits far above it.
const IDENTIFIER_TOKEN_LENGTH: usize = 20;

/// The `SQL` text the examination's own read-only queries and the state
/// schema's integrity probes use, matched case-folded: statement verbs,
/// the driver's probe names, and the queried tables' underscored names.
/// The collision-prone table names are excluded — the evidence keys and
/// message words legitimately containing them (`receipt_count`,
/// `enrolled_sources`) would trip a looser scan.
const SQL_FRAGMENTS: [&str; 12] = [
    "select",
    "insert",
    "pragma",
    "delete from",
    "union",
    "count(",
    "foreign_key",
    "sqlite_master",
    "schema_migrations",
    "frozen_requests",
    "adapter_health",
    "create table",
];

/// The operating-system error strings a leaked `std::io` or `SQLite`
/// diagnostic would carry, matched case-folded: the classic strerror
/// texts and Rust's own `(os error N)` suffix.
const OS_ERROR_PHRASES: [&str; 10] = [
    "no such file",
    "permission denied",
    "os error",
    "connection refused",
    "broken pipe",
    "address already in use",
    "text file busy",
    "operation not permitted",
    "is a directory",
    "not a directory",
];

/// The URL schemes a leaked endpoint or file reference would carry. No
/// legitimate document member names a location, so any scheme is a leak.
const URL_SCHEMES: [&str; 3] = ["http://", "https://", "file://"];

/// The audit's view of a document: the canonical bytes with the error
/// envelope's minted correlation identifier values removed — the one
/// member whose value is identifier-shaped by design, derived from the
/// wall clock and host randomness and never from anything the
/// examination read — so the identifier scans see every other byte. A
/// value that never closes leaves its tail in the audited text.
fn without_correlation_ids(text: &str) -> String {
    const KEY: &str = "\"correlation_id\"";
    let mut kept = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(relative) = text[cursor..].find(KEY) {
        let at = cursor + relative;
        kept.push_str(&text[cursor..at]);
        // The canonical form is `"correlation_id":"<value>"`: the value
        // opens at the first quote after the key and closes at the next.
        let after_key = at + KEY.len();
        let Some(open) = text[after_key..].find('"') else {
            cursor = after_key;
            break;
        };
        let value = after_key + open + 1;
        if let Some(close) = text[value..].find('"') {
            cursor = value + close + 1;
        } else {
            cursor = value;
            break;
        }
    }
    kept.push_str(&text[cursor..]);
    kept
}

/// The longest alphanumeric token in the text: the identifier-shape
/// scan's measure. Tokens are `ASCII`, so byte length is character
/// length.
fn longest_alphanumeric_run(text: &str) -> usize {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .map(str::len)
        .max()
        .unwrap_or(0)
}

/// Whether the text carries a `UUID`-grammar token — five hex groups in
/// the 8-4-4-4-12 dash layout. Timestamps and registry prose never fit
/// the grammar; a fixture identifier or an unexcused minted correlation
/// value always does.
fn carries_uuid_grammar_token(text: &str) -> bool {
    text.split(|character: char| !matches!(character, '0'..='9' | 'a'..='f' | 'A'..='F' | '-'))
        .any(|token| {
            let groups: Vec<usize> = token.split('-').map(str::len).collect();
            groups == [8, 4, 4, 4, 12]
        })
}

/// Whether the text carries an absolute-path shape: a slash whose next
/// character is a name character and whose preceding character is not —
/// the shape a leaked `/tmp/...` or `/home/...` path has and that prose
/// slash compounds (`I/O`, `input/output`) never do. The fixture path
/// itself and the URL schemes are covered by their own scans.
fn carries_absolute_path_token(text: &str) -> bool {
    text.match_indices('/').any(|(at, _)| {
        let preceded_by_name = at > 0
            && text[..at]
                .chars()
                .next_back()
                .is_some_and(|character: char| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/')
                });
        let followed_by_name = text[at + 1..]
            .chars()
            .next()
            .is_some_and(|character: char| character.is_ascii_alphanumeric());
        !preceded_by_name && followed_by_name
    })
}

/// The redaction audit over one emitted document: no fixture path, no
/// registered fixture identifier, no absolute-path shape, no identifier-
/// or secret-shaped token, no `SQL` text, no operating-system error
/// string. Each failure names the class and carries the document so the
/// leak is diagnosable from the test output alone.
fn assert_content_free(label: &str, document: &[u8], fixture: &Path) {
    let text =
        std::str::from_utf8(document).unwrap_or_else(|error| panic!("{label} is utf-8: {error}"));
    let fixture = fixture.to_string_lossy();
    assert!(
        !text.contains(fixture.as_ref()),
        "{label} leaked the fixture path: {text}"
    );
    for needle in registered_needles() {
        assert!(
            !text.contains(needle.as_str()),
            "{label} leaked a registered fixture identifier: {text}"
        );
    }
    let mut audited = without_correlation_ids(text);
    for namespace in EMITTED_NAMESPACES {
        audited = audited.replace(namespace, "");
    }
    assert!(
        !carries_absolute_path_token(&audited),
        "{label} leaked an absolute path: {audited}"
    );
    for scheme in URL_SCHEMES {
        assert!(
            !audited.contains(scheme),
            "{label} leaked a location ({scheme}): {audited}"
        );
    }
    assert!(
        longest_alphanumeric_run(&audited) < IDENTIFIER_TOKEN_LENGTH,
        "{label} leaked an identifier or secret: {audited}"
    );
    assert!(
        !carries_uuid_grammar_token(&audited),
        "{label} leaked an identifier-shaped token: {audited}"
    );
    let folded = audited.to_ascii_lowercase();
    for fragment in SQL_FRAGMENTS {
        assert!(
            !folded.contains(fragment),
            "{label} leaked SQL text ({fragment}): {audited}"
        );
    }
    for phrase in OS_ERROR_PHRASES {
        assert!(
            !folded.contains(phrase),
            "{label} leaked an operating-system error ({phrase}): {audited}"
        );
    }
}

/// A refused examination's complete observable contract: the exit status
/// the registered class allocates, no result document on stdout
/// (CLI-019), and exactly one `archivist.error/v1` refusal on stderr
/// whose code is the registered finding — content-free, so nothing the
/// examination read (the fixture's own paths included) appears anywhere
/// in the emitted bytes.
fn assert_registered_refusal(output: &Output, code: &str, exit: i32, dir: &TempDir) {
    assert_eq!(
        output.status.code(),
        Some(exit),
        "the registered {code} class allocates exit {exit}"
    );
    assert!(
        output.stdout.is_empty(),
        "a failed doctor emits no result document (CLI-019), found {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr.clone()).expect("the refusal is utf-8");
    assert!(
        !stderr.contains(dir.path().to_string_lossy().as_ref()),
        "the refusal is content-free: no fixture path appears"
    );
    let document = stream_document(&output.stderr);
    assert_eq!(text_member(&document, "schema"), "archivist.error/v1");
    assert_eq!(text_member(&document, "code"), code);
    // The redaction audit over the whole emitted document: no fixture
    // path, identifier, secret, SQL text, or operating-system error
    // anywhere in the bytes.
    assert_content_free("the refusal document", &output.stderr, dir.path());
}

/// Run the compiled binary's `run --once` command in JSON non-interactive
/// mode over the fixture and capture its real streams. The cycle probes
/// nothing — the ingest endpoint is configuration the scheduler plans
/// around, not a request this foreground form makes — so the endpoint may
/// name a port nothing answers.
fn run_once(dir: &TempDir, endpoint: &str) -> Output {
    let mut command = doctor_command(dir, endpoint, "1");
    command.args(["run", "--once", "--json", "--non-interactive"]);
    command.output().expect("the archivist binary runs")
}

/// A path's permission bits, the pinned-mode assertions read.
fn mode_of(path: &Path) -> u32 {
    path.metadata().expect("metadata").permissions().mode() & 0o777
}

/// The state directory's complete recursive shape — every path, every
/// directory, and every regular file's bytes — in sorted order, with the
/// one exemption a correct WAL reader requires: the wal-index scratch
/// (`-shm`) carries the reader's read-mark, so its presence is pinned
/// and its bytes belong to `SQLite`. Comparing two snapshots of this shape
/// proves the examination created, removed, or rewrote nothing without
/// naming the artifacts it must not touch in advance — an unanticipated
/// creation, a spool directory, a journal, a lock file, fails as loudly
/// as a named one.
fn state_tree(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let wal_index = format!("{STATE_DB_NAME}-shm");
    let mut tree = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)
            .expect("the fixture tree reads")
            .flatten()
        {
            let path = entry.path();
            if entry.file_type().expect("the entry type reads").is_dir() {
                stack.push(path.clone());
                tree.push((path, None));
            } else if path.file_name().and_then(OsStr::to_str) == Some(wal_index.as_str()) {
                tree.push((path, None));
            } else {
                let bytes = std::fs::read(&path).expect("the file's bytes read");
                tree.push((path, Some(bytes)));
            }
        }
    }
    tree.sort_by(|left, right| left.0.cmp(&right.0));
    tree
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
    // The redaction audit over the emitted envelope: the healthy
    // document's bytes carry no path, identifier, secret, SQL text, or
    // operating-system error either.
    assert_content_free("the healthy result document", &output.stdout, dir.path());
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
    // The redaction audit over the exit-74 document: no path,
    // identifier, secret, SQL text, or operating-system error anywhere
    // in the bytes the refusal emitted.
    assert_content_free("the missing-state refusal", stderr.as_bytes(), dir.path());
}

// The mutator's own creation posture (CFG-023). The rows above observe
// the examination; these observe the writer: the state the binary
// itself creates must land at the pinned modes, a loosened database
// must be refused by the mutator itself, and the binary's own fresh
// state must verify healthy once it carries a receipt.

#[test]
fn run_once_creates_the_state_at_the_pinned_modes() {
    let dir = TempDir::new("run-once-create");
    let output = run_once(&dir, "http://127.0.0.1:9");
    assert_eq!(
        output.status.code(),
        Some(0),
        "one cycle over a fresh directory succeeds: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The whole layout the mutator created carries its pinned modes
    // (CFG-023): the database 0600 — never the umask default — the lock
    // file 0600, and the spool directory 0700.
    assert_eq!(
        mode_of(&dir.path().join(STATE_DB_NAME)),
        0o600,
        "the binary creates the state database mode 0600"
    );
    assert_eq!(
        mode_of(&dir.path().join(LOCK_FILE_NAME)),
        0o600,
        "the lock file is mode 0600"
    );
    assert_eq!(
        mode_of(&dir.path().join(SPOOL_DIR_NAME)),
        0o700,
        "the spool directory is mode 0700"
    );
}

#[test]
fn a_loose_pre_existing_state_database_refuses_the_mutator() {
    // The mutator side of the permissions row: a database loosened the
    // way an out-of-band writer would is refused by `run --once` itself
    // — the registered local-state class, content-free — before the
    // driver touches the file, and the offending mode survives the
    // refusal untouched.
    let dir = TempDir::new("run-once-db-mode");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    drop(store);
    let database = dir.path().join(STATE_DB_NAME);
    std::fs::set_permissions(&database, Permissions::from_mode(0o644))
        .expect("loosen the database mode");
    let output = run_once(&dir, "http://127.0.0.1:9");
    assert_registered_refusal(&output, "client.state_io", 74, &dir);
    // Refused, never repaired — and the refusal retired before the
    // driver opened anything: no write-ahead log or wal-index appeared
    // beside the database the mutator refused.
    assert_eq!(
        mode_of(&database),
        0o644,
        "the loose mode is left untouched"
    );
    assert!(
        !dir.path().join(format!("{STATE_DB_NAME}-wal")).exists(),
        "the refusal opened no write-ahead log"
    );
    assert!(
        !dir.path().join(format!("{STATE_DB_NAME}-shm")).exists(),
        "the refusal opened no wal-index"
    );
}

#[test]
fn doctor_over_binary_created_state_reports_no_permissions_finding() {
    // The row the fixed creation posture exists for: state the binary
    // itself created — `run --once` over a fresh directory — verifies
    // healthy once it carries a receipt. While the creation mode was
    // unpinned the database landed at the umask default, the
    // examination reported the permissions refusal for every
    // binary-created fixture, and none could ever verify healthy.
    let dir = TempDir::new("run-once-healthy");
    let output = run_once(&dir, "http://127.0.0.1:9");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the cycle over a fresh directory succeeds: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The binary's own database reopens for the fixture receipt — itself
    // proof of the mode it landed at, since the mutator now refuses any
    // other — and the migration it already carries is idempotent.
    let mut store =
        StateStore::open(&dir.path().join(STATE_DB_NAME)).expect("reopen the binary's state");
    store.migrate().expect("migrate is idempotent");
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    drop(store);
    let server = ReadinessEndpoint::start();
    let doctor_output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_eq!(
        doctor_output.status.code(),
        Some(0),
        "the binary's own state verifies healthy: {}",
        String::from_utf8_lossy(&doctor_output.stderr)
    );
    assert!(
        doctor_output.stderr.is_empty(),
        "a healthy doctor writes no diagnostic, found {:?}",
        String::from_utf8_lossy(&doctor_output.stderr)
    );
    let envelope = stream_document(&doctor_output.stdout);
    assert_eq!(text_member(&envelope, "schema"), "archivist.cli-output/v1");
    let result = member(&envelope, "result");
    assert_eq!(text_member(result, "verdict"), "ok");
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
    assert_content_free(
        "the binary-created healthy result document",
        &doctor_output.stdout,
        dir.path(),
    );
}

#[test]
fn a_foreign_held_lock_is_reported_with_zero_state_creation() {
    let dir = TempDir::new("foreign-lock");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    // The foreign mutator owns the directory exactly the way the daemon
    // does: the write connection stays open (its WAL and wal-index are
    // the live coordination files) and the advisory lock is held for the
    // examination's whole life. The lock is a property of the holder's
    // open file description, so the child's no-create probe — a fresh
    // open and a non-blocking try, never a create — must observe it as
    // held.
    let _held = StateDirLock::acquire(dir.path()).expect("the foreign holder acquires");
    let before = state_tree(dir.path());
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    // A held lock is ownership evidence, never a failure (CLI-007): the
    // report stays available, the process exits 0, and the registered
    // lock_ownership check answers ok with the evidence naming the
    // foreign owner's lock state.
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report stays available while a mutator owns the directory"
    );
    assert!(
        output.stderr.is_empty(),
        "a held lock writes no diagnostic, found {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope = stream_document(&output.stdout);
    let result = member(&envelope, "result");
    let checks = member(result, "checks");
    assert_eq!(
        member(checks, "lock_ownership"),
        &Value::Text("ok".to_owned()),
        "a foreign owner is not a failed check"
    );
    let evidence = member(result, "evidence");
    assert_eq!(text_member(evidence, "lock"), "held");
    // Zero state creation: the probe opened the holder's lock file
    // without creating one of its own, opened no spool, and created no
    // database side file — every durable byte in the tree, the holder's
    // lock file and the writer's own WAL included, is identical across
    // the run, and the wal-index is present exactly as the writer left
    // it.
    assert!(
        dir.path().join(LOCK_FILE_NAME).exists(),
        "the holder's own lock file is the only one: it survives untouched"
    );
    assert!(
        !dir.path().join(SPOOL_DIR_NAME).exists(),
        "no spool directory appears"
    );
    assert!(
        !dir.path().join(format!("{STATE_DB_NAME}-journal")).exists(),
        "no rollback journal appears"
    );
    assert_eq!(
        state_tree(dir.path()),
        before,
        "the examination created and modified no state whatsoever"
    );
    assert_content_free(
        "the foreign-lock result document",
        &output.stdout,
        dir.path(),
    );
}

#[test]
fn the_examination_leaves_the_state_database_byte_identical() {
    let dir = TempDir::new("read-only-db");
    let store = seeded_store(&dir);
    // One enrolled source beside the receipt linkage, so the read-only
    // queries walk a populated sources table too — the same row shape
    // the operator surface's fixtures enroll. The write connection
    // stays open across the child's run: the doctor's defining shape is
    // the daemon-live one, its WAL and wal-index present and owned by
    // the writer the read-only report must not disturb.
    store
        .connection()
        .execute(
            "INSERT INTO sources (source_id, harness, upstream_session_id, id_source,
                session_hash, artifact_kind, adapter_id, adapter_projection_version,
                adapter_artifact_id, artifact_hash, freshness_lane, last_cursor,
                created_at, updated_at)
             VALUES ('01900000-0000-7000-8000-000000000001', 'claude',
                'upstream-session', 'natural', ?1, 'transcript', 'adapter-1', 'v1',
                'artifact', ?2, 'freshness', NULL, '2026-09-13T12:00:00Z',
                '2026-09-13T12:00:00Z')",
            params![digest(81), digest(82)],
        )
        .expect("insert source");
    // The enrolled source's own identifiers are fixture content:
    // registered so the audit would reject any document that echoed
    // them back. The harness, kind, and lane words are shared
    // vocabulary, not identifiers, and stay unregistered.
    register_needle("01900000-0000-7000-8000-000000000001");
    register_needle("upstream-session");
    register_needle("adapter-1");
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    let database = dir.path().join(STATE_DB_NAME);
    let before = std::fs::read(&database).expect("the fixture database reads");
    let before_tree = state_tree(dir.path());
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_eq!(output.status.code(), Some(0), "the healthy fixture exits 0");
    // The examination is byte-for-byte read-only: the bytes the writer
    // left are the bytes the report read — no counter, no head, no
    // freelist page moved across every check the doctor ran.
    let after = std::fs::read(&database).expect("the examined database reads");
    assert_eq!(after, before, "the state database is byte-identical");
    // Nothing the examination did reached the write-ahead log either:
    // a reader appends no frame, so the writer's own WAL bytes are the
    // ones still on disk.
    let wal = dir.path().join(format!("{STATE_DB_NAME}-wal"));
    assert!(
        wal.exists(),
        "the writer's live WAL is the coordination the reader joined"
    );
    // No journal — a write transaction is the only thing that could
    // open one — and no residue the examination brought into the
    // directory: the tree is exactly what the writer left, the wal-index
    // included, with no lock file and no spool.
    assert!(
        !dir.path().join(format!("{STATE_DB_NAME}-journal")).exists(),
        "no rollback journal appears"
    );
    assert!(
        !dir.path().join(LOCK_FILE_NAME).exists(),
        "no lock file appears"
    );
    assert!(
        !dir.path().join(SPOOL_DIR_NAME).exists(),
        "no spool directory appears"
    );
    let mut entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("the state directory reads")
        .flatten()
        .map(|entry| entry.file_name())
        .collect();
    entries.sort();
    let mut expected: Vec<_> = [
        STATE_DB_NAME.to_owned(),
        format!("{STATE_DB_NAME}-shm"),
        format!("{STATE_DB_NAME}-wal"),
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect();
    expected.sort();
    assert_eq!(
        entries, expected,
        "only the writer's own files remain: nothing else appears"
    );
    // And the durable shape across the run is identical — the full-tree
    // comparison, wal-index bytes aside, database and WAL included.
    assert_eq!(
        state_tree(dir.path()),
        before_tree,
        "the examination left the state exactly as the writer had it"
    );
    assert_content_free("the read-only result document", &output.stdout, dir.path());
}

// The induced local-state failure matrix. Every fixture below is
// otherwise healthy — one verified receipt so linkage passes, a
// readiness answer so the probe passes, a floor of one byte so the
// spool-space check passes — so the induced condition is the only
// finding, and the row's registered refusal with its exit class is the
// whole observable outcome. The inductions are the library-level
// matrix's own (ade2e43): the same hermetic damage, observed here
// through the compiled process.

#[test]
fn an_unresolvable_configuration_refuses_with_the_usage_class_before_any_state() {
    // The configuration-resolution row: an explicit `--config` the
    // loader must but cannot read is a registered usage refusal taken
    // before the examination runs. The endpoint names a port nothing
    // answers, so a probe that ran would surface its own registered
    // refusal (server.unavailable, exit 75) instead — the usage class is
    // itself the evidence the examination never started.
    let dir = TempDir::new("config-refusal");
    let absent = dir.path().join("absent.toml");
    let output = run_doctor_with_config(&dir, "http://127.0.0.1:9", &absent);
    assert_registered_refusal(&output, "cli.usage_error", 64, &dir);
    // The refusal retired before the examination: the doctor created and
    // opened no state path at all — the named configuration file is
    // absent by construction, and nothing else appears beside it.
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("the fixture directory is readable")
        .collect();
    assert!(
        entries.is_empty(),
        "the configuration refusal opens no state path"
    );
}

#[test]
fn a_loose_state_database_mode_refuses_with_the_permissions_class() {
    // The permissions row for the state database itself: the fixture
    // loosens the database mode the pinned policy requires (0600,
    // CFG-023) the way an out-of-band writer would, over the
    // daemon-live shape — the write connection stays open across the
    // child's run, its WAL and wal-index present.
    let dir = TempDir::new("db-mode");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    std::fs::set_permissions(
        dir.path().join(STATE_DB_NAME),
        Permissions::from_mode(0o644),
    )
    .expect("loosen the database mode");
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_registered_refusal(&output, "client.permissions", 74, &dir);
}

#[test]
fn a_loose_lock_file_mode_refuses_with_the_permissions_class() {
    // The permissions row for the advisory lock file: a lock file whose
    // mode is outside the pinned 0600 is reported whether or not any
    // mutator holds it — the probe answers `free` (a report, never an
    // acquisition) and the mode check carries the refusal.
    let dir = TempDir::new("lock-mode");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    let lock = dir.path().join(LOCK_FILE_NAME);
    std::fs::write(&lock, b"").expect("create the lock file");
    std::fs::set_permissions(&lock, Permissions::from_mode(0o644))
        .expect("loosen the lock file mode");
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_registered_refusal(&output, "client.permissions", 74, &dir);
}

#[test]
fn loose_spool_modes_refuse_with_the_permissions_class() {
    // The permissions row for the spool: a spool directory looser than
    // the pinned 0700 carrying an entry looser than the pinned 0600 —
    // the shape a foreign umask leaves behind. The examination inspects
    // the modes only; it opens no spool of its own.
    let dir = TempDir::new("spool-mode");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    let spool = dir.path().join(SPOOL_DIR_NAME);
    std::fs::create_dir(&spool).expect("create the spool directory");
    std::fs::set_permissions(&spool, Permissions::from_mode(0o755))
        .expect("loosen the spool directory mode");
    let entry = spool.join("bundle.bundle");
    std::fs::write(&entry, b"payload").expect("create a spool entry");
    std::fs::set_permissions(&entry, Permissions::from_mode(0o644))
        .expect("loosen the spool entry mode");
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_registered_refusal(&output, "client.permissions", 74, &dir);
}

#[test]
fn a_stale_migration_version_refuses_with_the_state_corrupt_class() {
    // The integrity row for a stale migration: external damage removed
    // the newest migration history row, so the recorded version is below
    // the schema the binary itself carries — the registered corruption
    // refusal, never a silent upgrade (the examination mutates nothing).
    let dir = TempDir::new("stale-version");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    store
        .connection()
        .execute(
            "DELETE FROM schema_migrations
             WHERE version = (SELECT MAX(version) FROM schema_migrations)",
            [],
        )
        .expect("drop the newest migration history row");
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_registered_refusal(&output, "client.state_corrupt", 74, &dir);
}

#[test]
fn a_foreign_key_orphan_refuses_with_the_state_corrupt_class() {
    // The integrity row for referential damage: the fixture drops the
    // frozen request the way an out-of-band writer would (enforcement
    // relaxed on the fixture's own connection only), leaving the
    // verified receipt orphaned — the foreign-key scan reports the
    // registered refusal without naming the orphaned row.
    let dir = TempDir::new("fk-orphan");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    store
        .connection()
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .expect("relax enforcement for the fixture damage");
    store
        .connection()
        .execute(
            "DELETE FROM frozen_requests
             WHERE request_id = (SELECT request_id FROM frozen_requests LIMIT 1)",
            [],
        )
        .expect("orphan the receipt");
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_registered_refusal(&output, "client.state_corrupt", 74, &dir);
}

#[test]
fn a_dropped_schema_index_refuses_with_the_state_corrupt_class() {
    // The integrity row for a missing expected object: external damage
    // dropped an index the schema expects, so the expected-object scan
    // reports the registered refusal — content-free, naming neither the
    // missing object nor anything the scan read.
    let dir = TempDir::new("dropped-index");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    store
        .connection()
        .execute("DROP INDEX idx_generations_source", [])
        .expect("drop an expected index");
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_registered_refusal(&output, "client.state_corrupt", 74, &dir);
}

#[test]
fn a_floor_above_the_free_space_refuses_with_the_disk_floor_class() {
    // The spool-space row: the configured free-space floor — one
    // tebibyte, above the free space of any host the suite runs on —
    // sits above the fixture filesystem's free space, so the
    // examination reports the registered resource refusal and its
    // distinct exit class: 75, the restore-disk-floor action, not the
    // local-state 74 the rows above allocate.
    let dir = TempDir::new("floor");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    let server = ReadinessEndpoint::start();
    let output = run_doctor_with_floor(&dir, server.endpoint(), "1099511627776");
    server.finish();
    assert_registered_refusal(&output, "client.disk_floor", 75, &dir);
}

// The induced environment and remote rows. Every fixture below is the
// same otherwise-healthy shape the local-state rows use — one verified
// receipt, a readiness answer, a floor of one byte — so the induced
// condition is the only finding, and each row carries the zero-mutation
// guarantee the baselines pin: the recursive state shape is identical
// across the run.

#[test]
fn a_degraded_adapter_health_record_refuses_with_the_source_unreadable_class() {
    // The source-readability row through the evidence the client itself
    // persists: an adapter-health record left degraded the way an
    // adapter's own failed passes leave one. The examination reads the
    // record, reports the registered refusal, and names neither the
    // adapter nor the row it found.
    let dir = TempDir::new("adapter-health");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    store
        .connection()
        .execute(
            "INSERT INTO adapter_health (adapter_id, health_state)
             VALUES ('probe', 'degraded')",
            [],
        )
        .expect("degrade the adapter");
    // The degraded row's adapter identifier is fixture content the
    // examination reads: registered as an audit needle.
    register_needle("probe");
    let before = state_tree(dir.path());
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_registered_refusal(&output, "client.source_unreadable", 74, &dir);
    assert_eq!(
        state_tree(dir.path()),
        before,
        "the examination mutated no state"
    );
}

#[test]
fn a_durable_event_years_ahead_refuses_with_the_clock_skew_class() {
    // The clock-sanity row: the receipt's durable instants sit years
    // ahead of the host's real clock — far beyond the five-minute
    // allowance — so the examination reports the registered refusal
    // against the handler's own reference instant, without adjusting
    // either clock.
    let dir = TempDir::new("clock");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2030-01-01T00:00:00Z");
    let before = state_tree(dir.path());
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_registered_refusal(&output, "client.clock_skew", 74, &dir);
    assert_eq!(
        state_tree(dir.path()),
        before,
        "the examination mutated no state"
    );
}

#[test]
fn an_unreachable_ingest_endpoint_refuses_with_the_server_unavailable_class() {
    // The server-readiness row for a request that never completes: the
    // endpoint is a loopback port whose listener was just released, so
    // the one permitted readiness request is refused by the operating
    // system — the registered server-failure refusal at its own exit 75.
    let dir = TempDir::new("server-down");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("the placeholder listener binds");
    let port = listener.local_addr().expect("the bound port reads").port();
    drop(listener);
    let before = state_tree(dir.path());
    let output = run_doctor(&dir, &format!("http://127.0.0.1:{port}"));
    assert_registered_refusal(&output, "server.unavailable", 75, &dir);
    assert_eq!(
        state_tree(dir.path()),
        before,
        "the examination mutated no state"
    );
}

#[test]
fn a_not_ready_readiness_answer_refuses_with_the_server_unavailable_class() {
    // The server-readiness row for a request that completes without
    // establishing ready: the endpoint answers 503, so the examination
    // reports the same registered refusal — a reachable server is not a
    // ready one.
    let dir = TempDir::new("server-busy");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    let before = state_tree(dir.path());
    let server = ReadinessEndpoint::not_ready();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_registered_refusal(&output, "server.unavailable", 75, &dir);
    assert_eq!(
        state_tree(dir.path()),
        before,
        "the examination mutated no state"
    );
}

#[test]
fn the_readiness_probe_stays_bounded_against_a_silent_endpoint() {
    // The bound itself: an endpoint whose kernel completes the TCP
    // handshake but whose application never answers. An unbounded
    // readiness wait would hang the examination here forever; the probe's
    // own timeout must return the registered refusal and let the process
    // exit. The whole run — child start to exit — must stay far inside
    // the deadline a stuck probe would blow through.
    let dir = TempDir::new("silent-endpoint");
    let store = seeded_store(&dir);
    linked_receipt(&store, "2026-09-13T12:00:00Z");
    let silent = TcpListener::bind(("127.0.0.1", 0)).expect("the silent listener binds");
    let endpoint = format!(
        "http://127.0.0.1:{}",
        silent.local_addr().expect("the bound port reads").port()
    );
    let before = state_tree(dir.path());
    let started = Instant::now();
    let output = run_doctor(&dir, &endpoint);
    let elapsed = started.elapsed();
    drop(silent);
    assert_registered_refusal(&output, "server.unavailable", 75, &dir);
    assert_eq!(
        state_tree(dir.path()),
        before,
        "the examination mutated no state"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "the readiness probe stayed bounded, taking {elapsed:?}"
    );
}

#[test]
fn an_unlinked_state_refuses_with_the_authorization_class() {
    // The client-linkage row: the migrated state carries no server-issued
    // receipt at all, so no local linkage evidence exists. The answered
    // readiness probe is what proves the finding is the missing linkage
    // and not the server — the authorization class at its own exit 78.
    let dir = TempDir::new("unlinked");
    let _store = seeded_store(&dir);
    let before = state_tree(dir.path());
    let server = ReadinessEndpoint::start();
    let output = run_doctor(&dir, server.endpoint());
    server.finish();
    assert_registered_refusal(&output, "auth.unlinked", 78, &dir);
    assert_eq!(
        state_tree(dir.path()),
        before,
        "the examination mutated no state"
    );
}

// The audit's own rows. Every leak class the audit forbids is planted
// in a synthetic refusal envelope — the exact shape the router writes,
// with the message member a leak would reach — and the audit must
// reject it; the envelope's two by-design identifier-shaped contents,
// the namespace and the minted correlation identifier, must pass. A
// scan that silently stopped matching anything fails here first.

/// A synthetic `archivist.error/v1` refusal carrying `message` over the
/// exact canonical shape the router writes, minted correlation
/// identifier included.
fn synthetic_refusal(message: &str) -> String {
    format!(
        "{{\"code\":\"client.state_io\",\"correlation_id\":\
         \"01900000-0000-7000-8000-000000000009\",\"message\":\"{message}\",\
         \"request_id\":null,\"retryable\":false,\
         \"schema\":\"archivist.error/v1\"}}"
    )
}

/// Audit one planted document through the same entry point the matrix
/// rows use.
fn audit_planted(document: &str) {
    assert_content_free(
        "the synthetic refusal",
        document.as_bytes(),
        Path::new("/nonexistent"),
    );
}

#[test]
fn the_audit_accepts_the_registered_envelope_and_its_minted_identifier() {
    // The real `client.state_io` template — its `I/O` the one slash a
    // legitimate message carries — over the envelope with its minted
    // correlation identifier: both by-design contents pass, so the
    // exemptions are the audit's own and not scans that never fire.
    audit_planted(&synthetic_refusal(
        "A local state or spool I/O operation failed; run doctor to diagnose.",
    ));
}

#[test]
#[should_panic(expected = "leaked an absolute path")]
fn the_audit_rejects_a_planted_absolute_path() {
    audit_planted(&synthetic_refusal(
        "state at /tmp/archivist-leaked/state.db is unreadable",
    ));
}

#[test]
#[should_panic(expected = "leaked a location (https://)")]
fn the_audit_rejects_a_planted_endpoint_url() {
    audit_planted(&synthetic_refusal(
        "the ingest endpoint https://127.0.0.1:9 answered nothing",
    ));
}

#[test]
#[should_panic(expected = "leaked an identifier or secret")]
fn the_audit_rejects_a_planted_digest() {
    audit_planted(&synthetic_refusal(&format!(
        "the receipt's digest is {}",
        "a".repeat(64)
    )));
}

#[test]
#[should_panic(expected = "leaked an identifier-shaped token")]
fn the_audit_rejects_a_planted_uuid_grammar_identifier() {
    audit_planted(&synthetic_refusal(
        "row deadbeef-dead-dead-dead-deaddeaddead is orphaned",
    ));
}

#[test]
#[should_panic(expected = "leaked a registered fixture identifier")]
fn the_audit_rejects_a_registered_fixture_needle() {
    let registered = format!("01900000-0000-7000-8000-{:012x}", 1);
    register_needle(&registered);
    audit_planted(&synthetic_refusal(&format!(
        "the enrolled source {registered} is unreadable"
    )));
}

#[test]
#[should_panic(expected = "leaked SQL text")]
fn the_audit_rejects_planted_sql_text() {
    audit_planted(&synthetic_refusal(
        "the query select count(*) from receipts failed",
    ));
}

#[test]
#[should_panic(expected = "leaked an operating-system error")]
fn the_audit_rejects_a_planted_operating_system_error() {
    audit_planted(&synthetic_refusal(
        "open failed: No such file or directory (os error 2)",
    ));
}
