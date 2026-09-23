// SPDX-License-Identifier: Apache-2.0

//! Tests for the operator command surface: the handlers' attachability to
//! the pinned registry, the read-only reports over seeded state, the
//! mutators' one-cycle document and second-mutator refusal, and the
//! daemon loop's stop behavior over deterministic seams.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use archivist_client_core::cli::Router;
use archivist_client_core::config::{ConfigSources, ResolvedConfig};
use archivist_client_core::daemon::{Cancel, LoopStop, ScheduleConfig, Sleeper};
use archivist_client_core::state::lock::StateDirLock;
use archivist_client_core::state::{STATE_DB_NAME, StateStore};
use archivist_client_core::upload::{Jitter, OsJitter, UploadError, UploadErrorKind};
use archivist_protocol::json::Value;
use rusqlite::params;

use super::{
    INTERNAL, LOCK_HELD, daemon_loop, handlers, inventory_over, run_once_over, status_over,
    verify_state_over,
};

/// Render a composed document to canonical text for member assertions.
fn rendered(document: &Value) -> String {
    String::from_utf8(document.canonical_bytes()).expect("canonical bytes are utf-8")
}

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// A private directory removed on drop, so file-backed tests never share
/// state and never leave debris behind.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "archivist-operator-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        // The state layer refuses any directory whose mode is not the
        // pinned 0700 (CFG-023), so the fixture creates the mode the
        // composition requires.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
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

/// The synthetic environment of a fully-declared host: every required
/// key through the snapshot's environment tier, the client state
/// directory the test owns, and the credentials never-resolved
/// references. The secret keys carry references, never values, exactly
/// as the command surface accepts them (CLI-024).
fn resolved_for(dir: &TempDir) -> ResolvedConfig {
    ConfigSources::non_interactive()
        .env("HOME", dir.path().to_string_lossy().to_string())
        .env(
            "ARCHIVIST_CLIENT_STATE_DIR",
            dir.path().to_string_lossy().to_string(),
        )
        .env(
            "ARCHIVIST_INGEST_ENDPOINT_URL",
            "https://ingest.example.invalid",
        )
        .env(
            "ARCHIVIST_STORAGE_ENDPOINT_URL",
            "https://s3.example.invalid",
        )
        .env("ARCHIVIST_STORAGE_REGION", "us-east-1")
        .env("ARCHIVIST_STORAGE_ENCRYPTION", "s3_sse")
        .env("ARCHIVIST_STORAGE_RAW_BUCKET", "archivist-raw-example")
        .env(
            "ARCHIVIST_STORAGE_CONTROL_BUCKET",
            "archivist-control-example",
        )
        .env(
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            "env:TEST_RAW_CREDENTIAL",
        )
        .env(
            "ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF",
            "env:TEST_CONTROL_CREDENTIAL",
        )
        .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "127.0.0.1:0")
        .load()
        .expect("the synthetic configuration loads")
}

/// A distinct 36-character `UUIDv7`-grammar identifier for whichever
/// table needs one. The grammar is the protocol's own (`uuid_grammar`:
/// lowercase hex, version nibble 7, variant `8..=b`), because the spool
/// reconciler only indexes a bundle whose stem parses as a request
/// identity — a fixture identifier outside that grammar is debris, not
/// a row.
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
/// never collide on the schema's unique (session, artifact) pairs.
fn seed_of(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Enroll one source with every CHECK-constrained column populated.
fn enroll(store: &StateStore, source_id: &str, lane: &str) {
    store
        .connection()
        .execute(
            "INSERT INTO sources (source_id, harness, upstream_session_id, id_source,
                session_hash, artifact_kind, adapter_id, adapter_projection_version,
                adapter_artifact_id, artifact_hash, freshness_lane, last_cursor,
                created_at, updated_at)
             VALUES (?1, 'claude', 'upstream-session', 'natural', ?2, 'transcript',
                'adapter-1', 'v1', 'artifact', ?3, ?4, NULL, ?5, ?5)",
            params![
                source_id,
                digest(seed_of(source_id)),
                digest(!seed_of(source_id)),
                lane,
                "2026-09-13T12:00:00Z",
            ],
        )
        .expect("insert source");
}

/// A migrated file-backed state store in the directory the fixture
/// configuration names.
fn seeded_store(dir: &TempDir) -> StateStore {
    let mut store = StateStore::open(&dir.path().join(STATE_DB_NAME)).expect("open state store");
    store.migrate().expect("migrate state store");
    store
}

#[test]
fn handlers_attach_to_the_pinned_registry_and_attach_once() {
    let mut router = Router::new();
    for (path, handler) in handlers() {
        router
            .register_handler(path, handler)
            .unwrap_or_else(|_| panic!("{path} attaches to the pinned registry"));
    }
    // A second attachment of any path is a composition bug the router
    // refuses, not a silent replacement.
    let (path, handler) = handlers()[0];
    assert!(router.register_handler(path, handler).is_err());
}

#[test]
fn status_reports_a_seeded_state_read_only() {
    let dir = TempDir::new("status-seeded");
    let store = seeded_store(&dir);
    enroll(&store, &uid("src"), "freshness");
    enroll(&store, &uid("src"), "backfill");

    let document = status_over(&resolved_for(&dir)).expect("status over seeded state");
    let text = rendered(&document);
    assert!(text.contains("\"schema\":\"archivist.cli-result/v1\""));
    assert!(text.contains("\"enrolled\":2"));
    assert!(text.contains("\"freshness\":1"));
    assert!(text.contains("\"backfill\":1"));
    assert!(text.contains("\"integrity\":\"ok\""));
    assert!(text.contains("\"last_capture_at\":null"));
}

#[test]
fn status_stays_available_while_the_daemon_holds_the_lock() {
    let dir = TempDir::new("status-under-lock");
    let _store = seeded_store(&dir);
    // The daemon's lock is held for its whole life; the read-only class
    // never touches it (CLI-007), so the report still composes.
    let _held = StateDirLock::acquire(dir.path()).expect("acquire the daemon's lock");
    assert!(status_over(&resolved_for(&dir)).is_ok());
}

#[test]
fn status_refuses_a_state_directory_that_has_none() {
    let dir = TempDir::new("status-absent");
    let error = status_over(&resolved_for(&dir)).expect_err("no state to report");
    assert_eq!(error.code(), "client.state_io");
}

#[test]
fn verify_state_flags_a_live_row_whose_bundle_is_missing() {
    let dir = TempDir::new("verify-missing-bundle");
    let store = seeded_store(&dir);
    let entry = uid("ent");
    store
        .connection()
        .execute(
            "INSERT INTO spool_entries (spool_entry_id, bundle_name, state, envelope_digest,
                size_bytes, attempt_count, next_attempt_at, created_at, updated_at)
             VALUES (?1, ?2, 'materialized', ?3, 64, 0, NULL, ?4, ?4)",
            params![
                entry,
                format!("{entry}.bundle"),
                digest(7),
                "2026-09-13T12:00:00Z"
            ],
        )
        .expect("insert live spool entry");

    let document = verify_state_over(&resolved_for(&dir)).expect("verification report");
    let text = rendered(&document);
    assert!(text.contains("\"verdict\":\"degraded\""));
    assert!(text.contains("\"live_bundles_present\":\"degraded\""));
    assert!(text.contains("\"live_rows_missing_bundles\":1"));
}

#[test]
fn inventory_counts_state_sources_the_no_scan_composition_cannot_measure() {
    let dir = TempDir::new("inventory-unscanned");
    let store = seeded_store(&dir);
    enroll(&store, &uid("src"), "freshness");
    enroll(&store, &uid("src"), "freshness");

    let document = inventory_over(&resolved_for(&dir), &[]).expect("inventory report");
    let text = rendered(&document);
    // No adapter has landed, so the composition passes no scan and the
    // document counts both state-known sources as unscanned rather than
    // inventing coverage.
    assert!(text.contains("\"sources_without_scan\":2"));
    assert!(text.contains("\"statuses\":[]"));
}

#[test]
fn run_once_emits_the_one_cycle_document() {
    let dir = TempDir::new("run-once");
    let document = run_once_over(&resolved_for(&dir), &[]).expect("one cycle");
    let text = rendered(&document);
    assert!(text.contains("\"schema\":\"archivist.cli-result/v1\""));
    // The startup reconciliation found nothing to reconcile on a fresh
    // directory, the gate admitted materialization, and the plan's drain
    // and backfill arithmetic over an unmeasured population is zero
    // work.
    assert!(text.contains("\"orphan_bundles_indexed\":0"));
    assert!(text.contains("\"admits_materialization\":true"));
    assert!(text.contains("\"drain_entries\":0"));
    assert!(text.contains("\"planned_bytes\":0"));
    // The capacity is the gate's own headroom: the spool cap minus the
    // empty live usage.
    let resolved = resolved_for(&dir);
    let cap = u64::try_from(resolved.spool_max_bytes()).expect("registry bounds");
    assert!(text.contains(&format!("\"capacity_bytes\":{cap}")));
}

#[test]
fn run_once_reconciles_orphan_bundle_files_into_the_state() {
    let dir = TempDir::new("run-once-orphan");
    let spool_dir = dir
        .path()
        .join(archivist_client_core::spool::SPOOL_DIR_NAME);
    std::fs::create_dir_all(&spool_dir).expect("create spool dir");
    std::fs::set_permissions(&spool_dir, std::fs::Permissions::from_mode(0o700))
        .expect("set the spool directory mode");
    // A complete bundle of the canonical shape with no state row: the
    // debris a crash between the rename and the commit leaves.
    let bundle = format!("{}.bundle", uid("orph"));
    std::fs::write(spool_dir.join(&bundle), b"debris").expect("write orphan bundle");

    let document = run_once_over(&resolved_for(&dir), &[]).expect("one cycle");
    // The cycle's reconciliation indexed the crash debris the directory
    // held; the round plans over a state that knows about it.
    assert!(rendered(&document).contains("\"orphan_bundles_indexed\":1"));
}

#[test]
fn run_once_refuses_a_second_mutator_with_the_registered_exit() {
    let dir = TempDir::new("run-once-lock-held");
    let _store = seeded_store(&dir);
    let _held = StateDirLock::acquire(dir.path()).expect("the daemon holds the lock");
    let error = run_once_over(&resolved_for(&dir), &[]).expect_err("lock held");
    assert_eq!(error.code(), LOCK_HELD);
    assert_eq!(error.exit_code(), 75);
}

/// A sleeper that cancels on its first wait and reports the cancel: the
/// supervisor's stop, delivered at the boundary between cycles.
struct StopAfterFirstCycle {
    waits: AtomicUsize,
}

impl Sleeper for StopAfterFirstCycle {
    fn sleep(&mut self, cancel: &Cancel, _delay: Duration) -> bool {
        self.waits.fetch_add(1, Ordering::Relaxed);
        cancel.cancel();
        false
    }
}

/// A jitter source with no entropy: the failure the loop stops on.
struct DeadJitter;

impl Jitter for DeadJitter {
    fn random_bits(&mut self) -> Result<u64, UploadError> {
        Err(UploadError::of_kind(UploadErrorKind::EntropyUnavailable))
    }
}

/// A sleeper that never waits: entropy fails after the first cycle
/// returns, and the loop must stop before drawing a delay.
struct NoSleep;

impl Sleeper for NoSleep {
    fn sleep(&mut self, _cancel: &Cancel, _delay: Duration) -> bool {
        panic!("the loop never waits when entropy is unavailable")
    }
}

/// The schedule and cancelled stop the loop tests drive.
fn loop_seams(
    dir: &TempDir,
) -> (
    archivist_client_core::config::ResolvedConfig,
    ScheduleConfig,
    Cancel,
) {
    let resolved = resolved_for(dir);
    let schedule =
        ScheduleConfig::from_resolved(&resolved).expect("the synthetic schedule is valid");
    (resolved, schedule, Cancel::new())
}

#[test]
fn daemon_runs_one_cycle_and_stops_at_the_supervisor_signal() {
    let dir = TempDir::new("daemon-one-cycle");
    let (resolved, schedule, cancel) = loop_seams(&dir);
    // The production entropy source: the stop must come from the
    // sleeper, not from a failed draw.
    let mut jitter = OsJitter::open().expect("entropy opens");
    let mut sleeper = StopAfterFirstCycle {
        waits: AtomicUsize::new(0),
    };
    let report = daemon_loop(
        &resolved,
        &[],
        &schedule,
        &cancel,
        &mut jitter,
        &mut sleeper,
    )
    .expect("one cycle, then the stop");
    // The first cycle ran to return; the stop came at the boundary, and
    // no second cycle started.
    assert_eq!(report.cycles_completed, 1);
    assert_eq!(report.stop, LoopStop::Cancelled);
    assert_eq!(sleeper.waits.load(Ordering::Relaxed), 1);
}

#[test]
fn daemon_reports_entropy_exhaustion_instead_of_looping_unjittered() {
    let dir = TempDir::new("daemon-entropy");
    let (resolved, schedule, cancel) = loop_seams(&dir);
    let mut jitter = DeadJitter;
    let mut sleeper = NoSleep;
    let error = daemon_loop(
        &resolved,
        &[],
        &schedule,
        &cancel,
        &mut jitter,
        &mut sleeper,
    )
    .expect_err("entropy exhaustion is a reported stop");
    assert_eq!(error.code(), INTERNAL);
}

#[test]
fn daemon_refuses_a_second_mutator_with_the_registered_exit() {
    let dir = TempDir::new("daemon-lock-held");
    let _store = seeded_store(&dir);
    let _held = StateDirLock::acquire(dir.path()).expect("the daemon holds the lock");
    let (resolved, schedule, cancel) = loop_seams(&dir);
    let mut jitter = DeadJitter;
    let mut sleeper = StopAfterFirstCycle {
        waits: AtomicUsize::new(0),
    };
    let error = daemon_loop(
        &resolved,
        &[],
        &schedule,
        &cancel,
        &mut jitter,
        &mut sleeper,
    )
    .expect_err("a held lock refuses the daemon");
    assert_eq!(error.code(), LOCK_HELD);
    assert_eq!(error.exit_code(), 75);
}
