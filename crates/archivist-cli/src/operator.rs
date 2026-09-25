// SPDX-License-Identifier: Apache-2.0

//! The Phase 5 operator command surface: the read-only `doctor`, `status`,
//! `verify-state`, and `inventory` reports, and the `run --once` and `daemon`
//! mutators that lock the state directory, migrate, reconcile the spool,
//! evaluate pressure, and plan the round.
//!
//! Every handler is the same shape [`crate::approve`] documents: a plain
//! function pointer the binary registers for its command's joined path
//! (`handlers`), over a configuration the invocation itself names. The
//! read-only class opens a [`StateSnapshot`] and never touches the
//! advisory lock, so a report stays available while the daemon owns the
//! directory (CLI-007); the mutator class takes [`StateDirLock`] and
//! never waits, so a second mutator exits 75 with the registered
//! `client.lock_held` surface (plan Section 7.9).
//!
//! The `daemon` command is always non-interactive (CLI-021) whether or
//! not the flag was passed: its composition builds the configuration
//! from [`ConfigSources::daemon`] and ignores the invocation's own
//! interactivity. It runs the scheduling loop until SIGTERM or SIGINT,
//! then returns having released the lock, and — stdout kind `none`
//! (CLI-016) — emits nothing on any path: the value a handler returns is
//! the router's none-stdout placeholder, never a stream.
//!
//! One scheduling cycle is the composition both mutators run: reconcile
//! the spool, evaluate the pressure gate, measure the sources the
//! supplied adapter scans cover, and plan the round. The scans are the
//! Phase 6 adapters' discovery output; until one lands the composition
//! passes none and the cycle drains and plans over the state's own
//! population — the same parameter the `inventory` composition takes,
//! so the adapters hand their scans to one seam.
//!
//! Every document a handler returns is the closed shape its registry
//! entry's `result_schema` pins (CLI-015), composed by
//! [`archivist_client_core::report`]. Failures return registered codes
//! and leave stdout empty: the router writes the diagnostic to stderr.

use std::path::Path;
use std::time::Duration;

use archivist_adapter_sdk::status::SourceScan;
use archivist_client_core::cli::{CliError, CommandHandler, Invocation, now_rfc3339};
use archivist_client_core::config::{ConfigError, ConfigSources, ResolvedConfig};
use archivist_client_core::daemon::{
    Cancel, LoopReport, LoopStop, ScheduleConfig, ScheduleConfigError, Sleeper, ThreadSleeper,
};
use archivist_client_core::doctor::{DoctorError, Finding};
use archivist_client_core::inventory::InventoryOptions;
use archivist_client_core::report::{
    cycle_document, inventory_document, status_report, verification_report,
};
use archivist_client_core::scheduler::{self, DrainLoad, SchedulerLimits, TARGET_CHUNK_BYTES};
use archivist_client_core::spool::pressure::{PressureGate, PressureLimits};
use archivist_client_core::spool::{self, Spool, SpoolError, SpoolErrorKind};
use archivist_client_core::state::lock::StateDirLock;
use archivist_client_core::state::{
    STATE_DB_NAME, StateError, StateErrorKind, StateSnapshot, StateStore,
};
use archivist_client_core::upload::{Jitter, OsJitter};
use archivist_protocol::json::Value;
use archivist_protocol::vocabulary::Timestamp;

/// The registered code for a second mutator the advisory lock refused
/// (`tools/error-codes.toml`, class `lock_contention`, exit 75).
const LOCK_HELD: &str = "client.lock_held";

/// The registered code for a state or spool operation that could not be
/// performed (`tools/error-codes.toml`, class `local_state`).
const STATE_IO: &str = "client.state_io";

/// The registered code for a state database outside its recorded schema
/// (`tools/error-codes.toml`, class `local_state`).
const STATE_CORRUPT: &str = "client.state_corrupt";

/// The registered code for a spool-pressure pause
/// (`tools/error-codes.toml`, class `resource_exhausted`).
const SPOOL_HIGH_WATER: &str = "client.spool_high_water";

/// The registered code for a fault with no narrower class
/// (`tools/error-codes.toml`, class `internal`).
const INTERNAL: &str = "client.internal_error";

/// The composition's attached surface: each registered command path and
/// its handler. The binary attaches every entry; the attachability test
/// proves the pair still names registered commands with a shipped
/// output kind.
#[must_use]
pub fn handlers() -> [(&'static str, CommandHandler); 6] {
    [
        ("daemon", daemon as CommandHandler),
        ("run", run_once as CommandHandler),
        ("inventory", inventory as CommandHandler),
        ("status", status as CommandHandler),
        ("verify-state", verify_state as CommandHandler),
        ("doctor", doctor as CommandHandler),
    ]
}

/// The `status` command: the read-only snapshot's state verdict,
/// per-source counts by scheduling lane, the live spool size, and the
/// freshest acknowledged capture instant.
///
/// # Errors
/// The registered refusal of the first failing act: configuration
/// acquisition, or the snapshot read.
pub fn status(invocation: &Invocation) -> Result<Value, CliError> {
    let resolved = resolve(invocation)?;
    status_over(&resolved)
}

/// Perform `status` over an already-resolved configuration: open the
/// read-only snapshot and compose the pinned document. Split from
/// [`status`] so the behavior is provable over a synthetic
/// configuration, without touching the process environment.
///
/// # Errors
/// The registered refusal of the snapshot read.
pub fn status_over(resolved: &ResolvedConfig) -> Result<Value, CliError> {
    let snapshot = read_snapshot(resolved.state_dir())?;
    let report = status_report(&snapshot, &now_timestamp()).map_err(|error| state_fault(&error))?;
    Ok(report.to_document())
}

/// The `verify-state` command: the state layer's automated checks plus
/// the spool-level correspondence a read-only pass can establish.
///
/// # Errors
/// The registered refusal of the first failing act: configuration
/// acquisition, or the snapshot read.
pub fn verify_state(invocation: &Invocation) -> Result<Value, CliError> {
    let resolved = resolve(invocation)?;
    verify_state_over(&resolved)
}

/// Perform `verify-state` over an already-resolved configuration, the
/// split [`status_over`] documents. Nothing is created, removed, or
/// repaired: the document is the evidence, and reconciliation remains
/// the mutator's act.
///
/// # Errors
/// The registered refusal of the snapshot read.
pub fn verify_state_over(resolved: &ResolvedConfig) -> Result<Value, CliError> {
    let snapshot = read_snapshot(resolved.state_dir())?;
    let report = verification_report(&snapshot, resolved.state_dir(), &now_timestamp())
        .map_err(|error| state_fault(&error))?;
    Ok(report.to_document())
}

/// The `doctor` command: a non-mutating local health examination plus one
/// readiness request to the configured ingestion endpoint. Configuration is
/// resolved before this function runs, so configuration faults retain the
/// ordinary non-interactive exit-64 surface and no secret is resolved.
///
/// # Errors
/// Returns configuration-fault codes from resolution, `client.state_io`
/// when the state cannot be examined read-only, and the registered code for
/// the most severe action-required finding; a failed doctor emits no result
/// document, as required by CLI-019.
pub fn doctor(invocation: &Invocation) -> Result<Value, CliError> {
    let resolved = resolve(invocation)?;
    let server_ready = probe_server_readiness(resolved.ingest_endpoint_url());
    doctor_over(&resolved, &[], server_ready)
}

/// Perform `doctor` over an already-resolved configuration. The readiness
/// boolean is an explicit seam for synthetic tests and for callers that have
/// already performed the one permitted readiness request.
///
/// # Errors
/// Returns the registered code for the most severe action-required finding;
/// a failed doctor emits no result document, as required by CLI-019.
pub fn doctor_over(
    resolved: &ResolvedConfig,
    scans: &[SourceScan],
    server_ready: bool,
) -> Result<Value, CliError> {
    let result =
        archivist_client_core::doctor::inspect(resolved, scans, server_ready, &now_timestamp())
            .map_err(doctor_state_fault)?;
    let Some(finding) = result
        .findings()
        .iter()
        .copied()
        .max_by_key(|finding| finding_severity(*finding))
    else {
        return Ok(result.to_document());
    };
    Err(CliError::registered(finding_code(finding)))
}

/// The `inventory` command: the per-scope coverage statuses and fleet
/// totals one inventory pass measured, over the adapter scans the
/// composition point supplies.
///
/// # Errors
/// The registered refusal of the first failing act: configuration
/// acquisition, or the snapshot read.
pub fn inventory(invocation: &Invocation) -> Result<Value, CliError> {
    let resolved = resolve(invocation)?;
    inventory_over(&resolved, &[])
}

/// Perform `inventory` over an already-resolved configuration, folding
/// in the given adapter scans. The scans are the Phase 6 adapters'
/// discovery output; until one lands the composition passes none, and
/// the document counts the state's own sources as unscanned rather than
/// inventing coverage.
///
/// # Errors
/// The registered refusal of the snapshot read.
pub fn inventory_over(resolved: &ResolvedConfig, scans: &[SourceScan]) -> Result<Value, CliError> {
    let snapshot = read_snapshot(resolved.state_dir())?;
    let report = archivist_client_core::inventory::inventory(
        snapshot.connection(),
        scans,
        &now_timestamp(),
        &InventoryOptions::default(),
    )
    .map_err(|error| state_fault(&error))?;
    Ok(inventory_document(&report))
}

/// The `run --once` command: exactly one scheduling cycle in the
/// foreground, over the state directory the mutator lock owns for the
/// cycle's duration. The `--once` operational flag is required, so the
/// parser refused every invocation without it before this handler ran.
///
/// # Errors
/// The registered refusal of the first failing act: configuration
/// acquisition, the mutator lock, migration, or the cycle's work.
pub fn run_once(invocation: &Invocation) -> Result<Value, CliError> {
    let resolved = resolve(invocation)?;
    run_once_over(&resolved, &[])
}

/// Perform `run --once` over an already-resolved configuration: take the
/// mutator lock, open and migrate the state, run one cycle, and return
/// its document. The lock releases when the returned lock guard drops.
///
/// # Errors
/// The registered refusal of the lock, the migration, or the cycle's
/// work.
pub fn run_once_over(resolved: &ResolvedConfig, scans: &[SourceScan]) -> Result<Value, CliError> {
    let _lock = mutator_lock(resolved.state_dir())?;
    let store = mutator_store(resolved.state_dir())?;
    let spool = Spool::open(resolved.state_dir()).map_err(|error| spool_fault(&error))?;
    let mut gate = PressureGate::new(PressureLimits::from_config(resolved));
    cycle(resolved, &store, &spool, &mut gate, scans, &now_timestamp())
}

/// The `daemon` command: the internal scheduling loop, running until
/// SIGTERM or SIGINT. Always non-interactive (CLI-021); stdout kind
/// `none` (CLI-016), so the returned value carries no document and the
/// loop's operational evidence is `status`, not a stream.
///
/// # Errors
/// The registered refusal of the first failing act: configuration
/// acquisition, the schedule, the mutator lock, migration, entropy, or
/// the first cycle whose work refuses — the supervisor-restart
/// direction the loop's own entropy stop takes.
pub fn daemon(invocation: &Invocation) -> Result<Value, CliError> {
    let resolved = resolve_daemon(invocation)?;
    daemon_over(&resolved, &[])
}

/// Run the daemon over an already-resolved configuration: take the
/// mutator lock for the process's whole life, migrate, and run the
/// scheduling loop until a signal cancels it. A dedicated runtime waits
/// for SIGTERM/SIGINT and cancels the loop — the synchronous loop body
/// never blocks a signal handler, and the cancel lands at the loop's
/// own boundaries, never inside a cycle.
///
/// # Errors
/// The registered refusal of the schedule, the lock, the migration,
/// entropy, or a refused cycle.
///
/// # Panics
/// Never in operation: the signal handlers install unless the operating
/// system refuses every process's signal mask — the same structural
/// guarantee the server's own signal composition restates.
pub fn daemon_over(resolved: &ResolvedConfig, scans: &[SourceScan]) -> Result<Value, CliError> {
    let schedule = ScheduleConfig::from_resolved(resolved).map_err(schedule_fault)?;
    let cancel = Cancel::new();
    let loop_cancel = cancel.clone();
    // One runtime drives the signal wait; the loop itself stays
    // synchronous (the composition discipline `crate::approve` uses for
    // its own async acts). The waiter detaches: a loop that stopped for
    // entropy or a refused cycle must not block on a signal that may
    // never come.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CliError::registered(INTERNAL))?;
    let _signals = std::thread::spawn(move || {
        runtime.block_on(async {
            use tokio::signal::unix::{SignalKind, signal};
            let mut terminate =
                signal(SignalKind::terminate()).expect("the SIGTERM handler installs");
            let mut interrupt =
                signal(SignalKind::interrupt()).expect("the SIGINT handler installs");
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
        });
        loop_cancel.cancel();
    });
    let mut jitter = OsJitter::open().map_err(|_| CliError::registered(INTERNAL))?;
    let mut sleeper = ThreadSleeper;
    daemon_loop(
        resolved,
        scans,
        &schedule,
        &cancel,
        &mut jitter,
        &mut sleeper,
    )
    // Both stops are graceful exits: a signal's own shutdown (CLI-020)
    // or entropy exhaustion the supervisor's restart surfaces. Neither
    // emits a stdout value (CLI-016); the placeholder is the router's
    // none-stdout contract, never a stream.
    .map(|_report| Value::Null)
}

/// Run the scheduling loop over an already-resolved configuration: take
/// the mutator lock, open and migrate the state, and loop. The first
/// cycle starts immediately; each later cycle starts one jittered delay
/// after the previous returned, and the loop never starts a cycle while
/// another is in flight.
///
/// The entropy seam and the sleeper are parameters so the loop is
/// provable without a signal or a clock: the production composition
/// hands [`OsJitter`] and [`ThreadSleeper`], the tests their
/// deterministic stand-ins.
///
/// # Errors
/// The registered refusal of the lock, the migration, entropy, or the
/// first cycle whose work refuses; the refused cycle stops the loop at
/// its own boundary and the error carries the registered code out.
fn daemon_loop<J: Jitter, S: Sleeper>(
    resolved: &ResolvedConfig,
    scans: &[SourceScan],
    schedule: &ScheduleConfig,
    cancel: &Cancel,
    jitter: &mut J,
    sleeper: &mut S,
) -> Result<LoopReport, CliError> {
    let _lock = mutator_lock(resolved.state_dir())?;
    let store = mutator_store(resolved.state_dir())?;
    let spool = Spool::open(resolved.state_dir()).map_err(|error| spool_fault(&error))?;
    let mut gate = PressureGate::new(PressureLimits::from_config(resolved));
    let mut failure: Option<CliError> = None;
    let report = archivist_client_core::daemon::run(schedule, cancel, jitter, sleeper, |cancel| {
        if failure.is_none() {
            match cycle(resolved, &store, &spool, &mut gate, scans, &now_timestamp()) {
                // The daemon's cycle document is the act, not a stream
                // (CLI-016): whatever the cycle planned is durable in the
                // state it drove, and no stdout value carries it.
                Ok(_document) => {}
                Err(error) => {
                    cancel.cancel();
                    failure = Some(error);
                }
            }
        }
    });
    if let Some(error) = failure {
        return Err(error);
    }
    if report.stop == LoopStop::EntropyUnavailable {
        // Entropy failed mid-loop: the schedule would degrade into a
        // synchronized fixed-period draw, so the loop stopped after the
        // in-flight cycle and the exit reports the fault.
        return Err(CliError::registered(INTERNAL));
    }
    Ok(report)
}

/// One scheduling cycle over an open, locked mutator: reconcile the
/// spool, evaluate the pressure gate, measure the sources the given
/// scans cover, and plan the round. Returns the cycle document the
/// `run --once` handler emits and the daemon runs for its effect.
///
/// The plan's capacity is the pressure verdict's own arithmetic: the
/// spool headroom the gate admits for new payload this round (plan
/// `EC-11`), zero while paused. The measurement is degraded exactly
/// when the gate is, so a paused round proposes no cursor movement the
/// spool could not hold.
///
/// # Errors
/// The registered refusal of the first failing act.
fn cycle(
    resolved: &ResolvedConfig,
    store: &StateStore,
    spool: &Spool,
    gate: &mut PressureGate,
    scans: &[SourceScan],
    now: &Timestamp,
) -> Result<Value, CliError> {
    let reconcile = spool
        .reconcile(store)
        .map_err(|error| spool_fault(&error))?;
    let pressure = gate
        .evaluate_spool(spool, store)
        .map_err(|error| spool_fault(&error))?;
    let options = InventoryOptions {
        degraded: pressure.is_degraded(),
    };
    let sources = archivist_client_core::inventory::measured_sources(
        store.connection(),
        scans,
        now,
        &options,
    )
    .map_err(|error| state_fault(&error))?;
    let pending = DrainLoad {
        entries: spool::live_entry_count(store).map_err(|error| spool_fault(&error))?,
        bytes: spool::live_usage_bytes(store).map_err(|error| spool_fault(&error))?,
    };
    let limits = SchedulerLimits::new(
        TARGET_CHUNK_BYTES,
        u64::try_from(resolved.schedule_backfill_quantum_bytes()).unwrap_or(0),
    );
    let capacity_bytes = if pressure.admits_materialization() {
        gate.limits()
            .spool_cap_bytes()
            .saturating_sub(pressure.spool_bytes())
    } else {
        0
    };
    let plan = scheduler::plan(&sources, pending, capacity_bytes, limits);
    Ok(cycle_document(&reconcile, &pressure, &plan.totals, now))
}

/// Open the read-only snapshot a report command reads, never creating
/// the database a state directory without one lacks.
///
/// # Errors
/// The registered refusal of the snapshot open.
fn read_snapshot(state_dir: &Path) -> Result<StateSnapshot, CliError> {
    StateSnapshot::open(&state_dir.join(STATE_DB_NAME)).map_err(|error| state_fault(&error))
}

/// Take the advisory mutator lock, refusing a second mutator with the
/// registered exit-75 surface instead of waiting: the owner may be the
/// daemon, which runs indefinitely (plan Section 7.9).
///
/// # Errors
/// `client.lock_held` for a held lock; `client.state_io` for a lock
/// file that could not be operated.
fn mutator_lock(state_dir: &Path) -> Result<StateDirLock, CliError> {
    StateDirLock::acquire(state_dir).map_err(|error| state_fault(&error))
}

/// Open and migrate the mutator's state store: the migration runs under
/// the lock the caller took, so no other mutator can interleave.
///
/// # Errors
/// The registered refusal of the open or the migration.
fn mutator_store(state_dir: &Path) -> Result<StateStore, CliError> {
    let mut store =
        StateStore::open(&state_dir.join(STATE_DB_NAME)).map_err(|error| state_fault(&error))?;
    store.migrate().map_err(|error| state_fault(&error))?;
    Ok(store)
}

/// Resolve the configuration one invocation names: the invocation's
/// interactivity, `--config`, and key flags over the captured process
/// environment.
///
/// # Errors
/// The registered code of the first configuration fault — in
/// non-interactive mode a missing decision is `cli.decision_missing`
/// (CLI-022).
fn resolve(invocation: &Invocation) -> Result<ResolvedConfig, CliError> {
    let sources = invocation
        .config_sources()
        .capture_environment()
        .map_err(|error| config_fault(&error))?;
    sources.load().map_err(|error| config_fault(&error))
}

/// Resolve the daemon's configuration: always non-interactive (CLI-021)
/// whether or not the flag was passed, with the invocation's `--config`
/// and key flags applied over the captured environment.
///
/// # Errors
/// The registered code of the first configuration fault.
fn resolve_daemon(invocation: &Invocation) -> Result<ResolvedConfig, CliError> {
    let mut sources = ConfigSources::daemon().map_err(|error| config_fault(&error))?;
    if let Some(path) = invocation.config_path() {
        sources = sources.config_path(path.to_path_buf());
    }
    for (name, value) in invocation.key_flags() {
        sources = sources.flag(name, value.to_owned());
    }
    sources.load().map_err(|error| config_fault(&error))
}

/// The invocation's instant, as the documents' `generated_at`. The
/// renderer's output is exactly the protocol Timestamp grammar accepts,
/// so the parse restates a structural guarantee rather than guarding a
/// runtime condition.
fn now_timestamp() -> Timestamp {
    Timestamp::parse(&now_rfc3339()).expect("the rendered current instant parses")
}

/// Map a configuration refusal onto its registered code.
fn config_fault(error: &ConfigError) -> CliError {
    CliError::registered(error.code().token())
}

fn doctor_state_fault(error: DoctorError) -> CliError {
    match error {
        DoctorError::StateUnavailable => CliError::registered(STATE_IO),
    }
}

fn finding_code(finding: Finding) -> &'static str {
    match finding {
        Finding::Permissions => "client.permissions",
        Finding::SqliteIntegrity => STATE_CORRUPT,
        Finding::SourceReadability => "client.source_unreadable",
        Finding::SpoolSpace => "client.disk_floor",
        Finding::ClockSanity => "client.clock_skew",
        Finding::ServerReadiness => "server.unavailable",
        Finding::ClientLinkage => "auth.unlinked",
    }
}

fn finding_severity(finding: Finding) -> u8 {
    match finding {
        Finding::ClientLinkage => 4,
        Finding::ServerReadiness | Finding::SpoolSpace => 3,
        Finding::Permissions
        | Finding::SqliteIntegrity
        | Finding::SourceReadability
        | Finding::ClockSanity => 2,
    }
}

/// Probe the server's read-only readiness endpoint. The probe deliberately
/// has no diagnostic return value: endpoint text, DNS names, and transport
/// errors must never reach the JSON error stream. Both HTTP and HTTPS are
/// supported, with a bounded timeout and no response body inspection.
fn probe_server_readiness(endpoint: &str) -> bool {
    if endpoint
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte == b'\r' || byte == b'\n')
    {
        return false;
    }
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return false;
    }
    let target = format!("{}/health/ready", endpoint.trim_end_matches('/'));
    let Ok(uri) = target.parse::<hyper::Uri>() else {
        return false;
    };
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    runtime.block_on(async move {
        tokio::time::timeout(Duration::from_secs(2), client.get(uri))
            .await
            .ok()
            .and_then(Result::ok)
            .is_some_and(|response| response.status() == hyper::StatusCode::OK)
    })
}

/// Map a state-layer refusal onto its registered code: the lock-held
/// condition is its own class and exit (75), schema corruption is an
/// integrity condition, and everything else is a state operation that
/// could not be performed.
fn state_fault(error: &StateError) -> CliError {
    match error.kind() {
        StateErrorKind::LockHeld => CliError::registered(LOCK_HELD),
        StateErrorKind::SchemaCorruption => CliError::registered(STATE_CORRUPT),
        StateErrorKind::Unavailable
        | StateErrorKind::Busy
        | StateErrorKind::MigrationFailed
        | StateErrorKind::IrreversibleMigration
        | StateErrorKind::VersionOutOfBounds => CliError::registered(STATE_IO),
    }
}

/// Map a spool refusal onto its registered code: a paused gate is a
/// policy outcome with its own code, a fired fault drill is an internal
/// fault, and everything else is a spool operation that could not be
/// performed.
fn spool_fault(error: &SpoolError) -> CliError {
    match error.kind() {
        SpoolErrorKind::MaterializationPaused => CliError::registered(SPOOL_HIGH_WATER),
        SpoolErrorKind::CrashInjected => CliError::registered(INTERNAL),
        SpoolErrorKind::Unavailable
        | SpoolErrorKind::UnsafePermissions
        | SpoolErrorKind::Busy
        | SpoolErrorKind::MalformedName => CliError::registered(STATE_IO),
    }
}

/// Map a schedule fault onto its registered code. The configuration
/// loader range-checks both schedule keys against the registry, so a
/// resolved configuration can only reach these faults by bypassing the
/// loader — an internal fault, not a fix-the-invocation one.
fn schedule_fault(error: ScheduleConfigError) -> CliError {
    match error {
        ScheduleConfigError::NonPositiveInterval
        | ScheduleConfigError::IntervalBelowOneSecond
        | ScheduleConfigError::IntervalUnsupported
        | ScheduleConfigError::JitterOutOfRange => CliError::registered(INTERNAL),
    }
}

#[cfg(test)]
mod tests;
