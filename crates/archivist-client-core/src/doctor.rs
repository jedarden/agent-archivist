// SPDX-License-Identifier: Apache-2.0

//! The non-mutating client health examination (plan Section 7.9).
//!
//! The doctor deliberately does not reuse mutator helpers such as
//! [`crate::state::lock::StateDirLock::acquire`] or [`crate::spool::Spool::open`]:
//! both of those are allowed to create state on behalf of a mutator.  The
//! examination uses metadata, a read-only SQLite snapshot, a no-create lock
//! probe, and a filesystem statistics call instead.  The caller supplies the
//! result of the one server-readiness request so this crate stays independent
//! of a transport implementation.
//!
//! Nothing returned by this module can carry a path, an identifier, a secret,
//! SQL text, or an operating-system error string.  Findings are closed enum
//! values and evidence is limited to modes, counters, timestamps, and the
//! lock state.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use archivist_adapter_sdk::status::{ScanClassification, SourceScan};
use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::Timestamp;
use rusqlite::Connection;

use crate::config::ResolvedConfig;
use crate::spool::SPOOL_DIR_NAME;
use crate::state::lock::LOCK_FILE_NAME;
use crate::state::{LATEST_SCHEMA_VERSION, STATE_DB_NAME, StateSnapshot};

/// The plan's five-minute allowance for a local clock that is ahead of the
/// freshest durable event.
pub const CLOCK_SKEW_ALLOWANCE_SECONDS: i64 = 5 * 60;

/// A condition found by the doctor.  The enum is intentionally content-free:
/// the CLI maps it to a registered error code without interpolating evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Finding {
    /// A state directory or state file has an unsafe mode, or the lock probe
    /// could not be completed safely.
    Permissions,
    /// SQLite integrity, foreign-key, schema-object, or migration-version
    /// evidence is not healthy.
    SqliteIntegrity,
    /// An adapter scan or persisted adapter-health record says a source is
    /// unreadable.
    SourceReadability,
    /// The state filesystem is below the configured free-space floor.
    SpoolSpace,
    /// A durable event is too far in the future for the local clock.
    ClockSanity,
    /// The one readiness request did not establish a ready server.
    ServerReadiness,
    /// No server-issued receipt exists as local linkage evidence.
    ClientLinkage,
}

impl Finding {
    /// Findings in the deterministic order used by the report and tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Permissions,
            Self::SqliteIntegrity,
            Self::SourceReadability,
            Self::SpoolSpace,
            Self::ClockSanity,
            Self::ServerReadiness,
            Self::ClientLinkage,
        ]
    }
}

/// A failure opening or examining the local SQLite file before a useful
/// report can be composed.  The error intentionally contains no path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoctorError {
    /// The state directory/database could not be read.
    StateUnavailable,
}

/// The content-free evidence included in a successful doctor document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    state_dir_mode: String,
    spool_dir_mode: Option<String>,
    state_db_mode: String,
    lock_file_mode: Option<String>,
    lock: &'static str,
    free_bytes: u64,
    free_floor_bytes: u64,
    schema_version: u64,
    enrolled_sources: u64,
    scanned_sources: u64,
    unreadable_sources: u64,
    receipt_count: u64,
    freshest_event_at: Option<String>,
}

/// The successful doctor result and any action-required findings.  A caller
/// must inspect [`Self::findings`] before emitting [`Self::to_document`]; the
/// document is the healthy-result shape and intentionally contains no
/// unbounded failure detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorResult {
    generated_at: String,
    evidence: Evidence,
    findings: Vec<Finding>,
}

impl DoctorResult {
    /// The action-required conditions found by the examination.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Whether every check passed.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.findings.is_empty()
    }

    /// Content-free evidence for tests and callers that need counters.
    #[must_use]
    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// Compose the result document pinned by `schemas/v1/cli-doctor.json`.
    ///
    /// The document is deliberately available even when findings exist so a
    /// caller can inspect a bounded local result in-process. The CLI follows
    /// CLI-019 and emits it only for a healthy run; failures are error bodies
    /// on stderr and produce no stdout document.
    #[must_use]
    pub fn to_document(&self) -> Value {
        let mut checks = Object::new();
        for name in [
            "configuration",
            "permissions",
            "sqlite_integrity",
            "lock_ownership",
            "source_readability",
            "spool_space",
            "clock_sanity",
            "server_readiness",
            "client_linkage",
        ] {
            checks.set(name, Value::Text("ok".to_owned()));
        }

        let mut evidence = Object::new();
        evidence.set(
            "state_dir_mode",
            Value::Text(self.evidence.state_dir_mode.clone()),
        );
        evidence.set(
            "spool_dir_mode",
            self.evidence
                .spool_dir_mode
                .as_ref()
                .map_or(Value::Null, |mode| Value::Text(mode.clone())),
        );
        evidence.set(
            "state_db_mode",
            Value::Text(self.evidence.state_db_mode.clone()),
        );
        evidence.set(
            "lock_file_mode",
            self.evidence
                .lock_file_mode
                .as_ref()
                .map_or(Value::Null, |mode| Value::Text(mode.clone())),
        );
        evidence.set("lock", Value::Text(self.evidence.lock.to_owned()));
        evidence.set("free_bytes", bounded_i64(self.evidence.free_bytes));
        evidence.set(
            "free_floor_bytes",
            bounded_i64(self.evidence.free_floor_bytes),
        );
        evidence.set("schema_version", bounded_i64(self.evidence.schema_version));
        evidence.set(
            "enrolled_sources",
            bounded_i64(self.evidence.enrolled_sources),
        );
        evidence.set(
            "scanned_sources",
            bounded_i64(self.evidence.scanned_sources),
        );
        evidence.set(
            "unreadable_sources",
            bounded_i64(self.evidence.unreadable_sources),
        );
        evidence.set("receipt_count", bounded_i64(self.evidence.receipt_count));
        evidence.set(
            "freshest_event_at",
            self.evidence
                .freshest_event_at
                .as_ref()
                .map_or(Value::Null, |timestamp| Value::Text(timestamp.clone())),
        );

        let mut document = Object::new();
        document.set("schema", Value::Text("archivist.cli-result/v1".to_owned()));
        document.set("generated_at", Value::Text(self.generated_at.clone()));
        document.set("verdict", Value::Text("ok".to_owned()));
        document.set("checks", Value::Object(checks));
        document.set("evidence", Value::Object(evidence));
        Value::Object(document)
    }
}

impl Evidence {
    /// The mode of the state directory, as a four-digit octal token.
    #[must_use]
    pub fn state_dir_mode(&self) -> &str {
        &self.state_dir_mode
    }

    /// The mode of the spool directory, if it exists.
    #[must_use]
    pub fn spool_dir_mode(&self) -> Option<&str> {
        self.spool_dir_mode.as_deref()
    }

    /// The mode of the state database.
    #[must_use]
    pub fn state_db_mode(&self) -> &str {
        &self.state_db_mode
    }

    /// The mode of the lock file, if it exists.
    #[must_use]
    pub fn lock_file_mode(&self) -> Option<&str> {
        self.lock_file_mode.as_deref()
    }

    /// Whether the advisory lock was free or held at examination time.
    #[must_use]
    pub const fn lock(&self) -> &'static str {
        self.lock
    }

    /// Filesystem free bytes available to this process.
    #[must_use]
    pub const fn free_bytes(&self) -> u64 {
        self.free_bytes
    }

    /// Configured filesystem free-space floor.
    #[must_use]
    pub const fn free_floor_bytes(&self) -> u64 {
        self.free_floor_bytes
    }

    /// Recorded state schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u64 {
        self.schema_version
    }

    /// Number of enrolled sources.
    #[must_use]
    pub const fn enrolled_sources(&self) -> u64 {
        self.enrolled_sources
    }

    /// Number of unique sources covered by supplied scans.
    #[must_use]
    pub const fn scanned_sources(&self) -> u64 {
        self.scanned_sources
    }

    /// Number of unreadable source observations.
    #[must_use]
    pub const fn unreadable_sources(&self) -> u64 {
        self.unreadable_sources
    }

    /// Number of retained receipts.
    #[must_use]
    pub const fn receipt_count(&self) -> u64 {
        self.receipt_count
    }

    /// Freshest valid durable event timestamp.
    #[must_use]
    pub fn freshest_event_at(&self) -> Option<&str> {
        self.freshest_event_at.as_deref()
    }
}

/// Run the local half of the doctor.
///
/// `server_ready` is the result of exactly one caller-owned readiness request;
/// no network access occurs here. `generated_at` is also the reference instant
/// for the future-event clock check, which makes the check deterministic in
/// tests and prevents two clocks being sampled in one report.
///
/// # Errors
/// Returns [`DoctorError::StateUnavailable`] when the state directory or
/// database cannot be opened read-only. Corruption that can be represented by
/// SQLite's read-only checks becomes a [`Finding::SqliteIntegrity`] instead.
pub fn inspect(
    config: &ResolvedConfig,
    scans: &[SourceScan],
    server_ready: bool,
    generated_at: &Timestamp,
) -> Result<DoctorResult, DoctorError> {
    let state_dir = config.state_dir();
    let state_dir_metadata = fs::metadata(state_dir).map_err(|_| DoctorError::StateUnavailable)?;
    if !state_dir_metadata.is_dir() {
        return Err(DoctorError::StateUnavailable);
    }

    let database_path = state_dir.join(STATE_DB_NAME);
    let database_metadata =
        fs::metadata(&database_path).map_err(|_| DoctorError::StateUnavailable)?;
    if !database_metadata.is_file() {
        return Err(DoctorError::StateUnavailable);
    }

    let snapshot =
        StateSnapshot::open(&database_path).map_err(|_| DoctorError::StateUnavailable)?;
    let schema_version = snapshot.schema_version().unwrap_or(0);
    let integrity = snapshot
        .integrity()
        .map_err(|_| DoctorError::StateUnavailable)?;

    let spool_path = state_dir.join(SPOOL_DIR_NAME);
    let spool_metadata = fs::metadata(&spool_path).ok();
    let spool_mode = spool_metadata.as_ref().map(mode_literal);
    let lock_path = state_dir.join(LOCK_FILE_NAME);
    let lock_metadata = fs::metadata(&lock_path).ok();
    let lock_mode = lock_metadata.as_ref().map(mode_literal);

    let mut findings = Vec::new();
    let state_mode = mode_literal(&state_dir_metadata);
    let database_mode = mode_literal(&database_metadata);
    let lock = match probe_lock(&lock_path) {
        Ok(lock) => lock,
        Err(ProbeError::Permission) => {
            findings.push(Finding::Permissions);
            "free"
        }
        Err(ProbeError::Unavailable) => {
            findings.push(Finding::Permissions);
            "free"
        }
    };

    let mut permissions_ok = state_dir_metadata.permissions().mode() & 0o777 == 0o700
        && database_metadata.permissions().mode() & 0o777 == 0o600;
    if let Some(metadata) = spool_metadata.as_ref() {
        permissions_ok &= metadata.is_dir() && metadata.permissions().mode() & 0o777 == 0o700;
        if metadata.is_dir() {
            permissions_ok &= spool_files_have_safe_modes(&spool_path);
        }
    }
    if let Some(metadata) = lock_metadata.as_ref() {
        permissions_ok &= metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600;
    }
    if !permissions_ok {
        findings.push(Finding::Permissions);
    }

    let version_ok = schema_version == LATEST_SCHEMA_VERSION;
    if !integrity.healthy() || !version_ok {
        findings.push(Finding::SqliteIntegrity);
    }

    let enrolled_sources =
        query_u64(snapshot.connection(), "SELECT COUNT(*) FROM sources").unwrap_or(0);
    let receipt_count = query_u64(
        snapshot.connection(),
        "SELECT COUNT(*) FROM receipts WHERE signature_verified = 1",
    )
    .unwrap_or(0);
    let adapter_unhealthy = query_u64(
        snapshot.connection(),
        "SELECT COUNT(*) FROM adapter_health WHERE health_state != 'healthy'",
    )
    .unwrap_or(0);

    let mut scanned = HashSet::new();
    let mut unreadable = HashSet::new();
    for scan in scans {
        scanned.insert(scan.source.as_str());
        if matches!(
            scan.classification,
            ScanClassification::TransportUnreachable
                | ScanClassification::ReadError
                | ScanClassification::PermissionDenied
        ) {
            unreadable.insert(scan.source.as_str());
        }
    }
    let scanned_sources = u64::try_from(scanned.len()).unwrap_or(u64::MAX);
    let unreadable_sources = u64::try_from(unreadable.len())
        .unwrap_or(u64::MAX)
        .saturating_add(adapter_unhealthy);
    if unreadable_sources > 0 {
        findings.push(Finding::SourceReadability);
    }

    let free_bytes = free_space_bytes(state_dir).unwrap_or(0);
    let free_floor_bytes = u64::try_from(config.spool_free_floor_bytes()).unwrap_or(u64::MAX);
    if free_bytes < free_floor_bytes {
        findings.push(Finding::SpoolSpace);
    }

    let freshest_event_at = freshest_event(snapshot.connection());
    let clock_ok = freshest_event_at
        .as_deref()
        .and_then(|text| Timestamp::parse(text).ok())
        .and_then(|timestamp| unix_seconds(&timestamp))
        .zip(unix_seconds(generated_at))
        .is_none_or(|(event, now)| event <= now.saturating_add(CLOCK_SKEW_ALLOWANCE_SECONDS));
    if !clock_ok {
        findings.push(Finding::ClockSanity);
    }
    if !server_ready {
        findings.push(Finding::ServerReadiness);
    }
    if receipt_count == 0 {
        findings.push(Finding::ClientLinkage);
    }

    findings.sort_by_key(|finding| {
        Finding::all()
            .iter()
            .position(|candidate| candidate == finding)
            .unwrap_or(usize::MAX)
    });
    findings.dedup();

    Ok(DoctorResult {
        generated_at: generated_at.as_str().to_owned(),
        evidence: Evidence {
            state_dir_mode: state_mode,
            spool_dir_mode: spool_mode,
            state_db_mode: database_mode,
            lock_file_mode: lock_mode,
            lock,
            free_bytes,
            free_floor_bytes,
            schema_version: u64::try_from(schema_version).unwrap_or(0),
            enrolled_sources,
            scanned_sources,
            unreadable_sources,
            receipt_count,
            freshest_event_at,
        },
        findings,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeError {
    Permission,
    Unavailable,
}

fn probe_lock(path: &Path) -> Result<&'static str, ProbeError> {
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok("free"),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(ProbeError::Permission);
        }
        Err(_) => return Err(ProbeError::Unavailable),
    };
    match file.try_lock() {
        Ok(()) => Ok("free"),
        Err(std::fs::TryLockError::WouldBlock) => Ok("held"),
        Err(std::fs::TryLockError::Error(error))
            if error.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            Err(ProbeError::Permission)
        }
        Err(std::fs::TryLockError::Error(_)) => Err(ProbeError::Unavailable),
    }
}

fn spool_files_have_safe_modes(path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };
    entries.flatten().all(|entry| {
        entry.metadata().is_ok_and(|metadata| {
            metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600
        })
    })
}

fn mode_literal(metadata: &std::fs::Metadata) -> String {
    format!("0{:03o}", metadata.permissions().mode() & 0o777)
}

fn free_space_bytes(path: &Path) -> Option<u64> {
    let stats = rustix::fs::statvfs(path).ok()?;
    Some(stats.f_bavail.saturating_mul(stats.f_frsize))
}

fn query_u64(connection: &Connection, sql: &str) -> Option<u64> {
    connection
        .query_row(sql, [], |row| row.get::<_, i64>(0))
        .ok()
        .and_then(|value| u64::try_from(value).ok())
}

fn freshest_event(connection: &Connection) -> Option<String> {
    // Each query is independent so an older/partially migrated database still
    // yields the evidence available to it; the integrity check carries the
    // structural finding instead of exposing a driver error.
    let queries = [
        "SELECT created_at FROM sources UNION ALL SELECT updated_at FROM sources",
        "SELECT detected_at FROM generations",
        "SELECT created_at FROM spool_entries UNION ALL SELECT updated_at FROM spool_entries",
        "SELECT source_at FROM frozen_requests WHERE source_at IS NOT NULL UNION ALL SELECT captured_at FROM frozen_requests UNION ALL SELECT frozen_at FROM frozen_requests",
        "SELECT captured_at FROM ranges",
        "SELECT discovered_at FROM upload_attestations WHERE discovered_at IS NOT NULL UNION ALL SELECT recorded_at FROM upload_attestations",
        "SELECT commit_time FROM receipts UNION ALL SELECT received_at FROM receipts",
        "SELECT last_success_at FROM adapter_health WHERE last_success_at IS NOT NULL",
    ];
    let mut freshest: Option<(i64, String)> = None;
    for sql in queries {
        let Ok(mut statement) = connection.prepare(sql) else {
            continue;
        };
        let Ok(mut rows) = statement.query([]) else {
            continue;
        };
        while let Ok(Some(row)) = rows.next() {
            let Ok(text) = row.get::<_, String>(0) else {
                continue;
            };
            let Ok(timestamp) = Timestamp::parse(&text) else {
                continue;
            };
            if !timestamp.calendar_valid() {
                continue;
            }
            let Some(seconds) = unix_seconds(&timestamp) else {
                continue;
            };
            if freshest
                .as_ref()
                .is_none_or(|(current, _)| seconds > *current)
            {
                freshest = Some((seconds, text));
            }
        }
    }
    freshest.map(|(_, timestamp)| timestamp)
}

fn unix_seconds(timestamp: &Timestamp) -> Option<i64> {
    let text = timestamp.as_str().as_bytes();
    if text.len() < 20 {
        return None;
    }
    let number = |slice: &[u8]| -> i64 {
        slice
            .iter()
            .fold(0_i64, |value, digit| value * 10 + i64::from(digit - b'0'))
    };
    let year = number(&text[0..4]);
    let month = number(&text[5..7]);
    let day = number(&text[8..10]);
    let hour = number(&text[11..13]);
    let minute = number(&text[14..16]);
    let second = number(&text[17..19]);
    let days = days_from_civil(year, month, day)?;
    Some(
        days.saturating_mul(86_400)
            .saturating_add(hour.saturating_mul(3_600))
            .saturating_add(minute.saturating_mul(60))
            .saturating_add(second),
    )
}

// Howard Hinnant's proleptic Gregorian conversion, matching the timestamp
// renderer in the CLI module without adding a date/time dependency.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || day < 1 || day > 31 {
        return None;
    }
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_adjusted = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_adjusted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

fn bounded_i64(value: u64) -> Value {
    Value::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{CLOCK_SKEW_ALLOWANCE_SECONDS, Finding, days_from_civil, inspect, unix_seconds};
    use crate::config::{ConfigSources, ResolvedConfig};
    use crate::state::lock::StateDirLock;
    use crate::state::{STATE_DB_NAME, StateStore};
    use archivist_protocol::vocabulary::Timestamp;

    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "archivist-doctor-{tag}-{}-{id}",
                std::process::id()
            ));
            std::fs::create_dir(&path).expect("create doctor fixture");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("set fixture directory mode");
            Self(path)
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

    fn resolved_for(dir: &TempDir) -> ResolvedConfig {
        ConfigSources::non_interactive()
            .env("HOME", dir.path().to_string_lossy().to_string())
            .env(
                "ARCHIVIST_CLIENT_STATE_DIR",
                dir.path().to_string_lossy().to_string(),
            )
            .env("ARCHIVIST_SPOOL_FREE_FLOOR_BYTES", "1")
            .env("ARCHIVIST_INGEST_ENDPOINT_URL", "http://127.0.0.1:1")
            .env("ARCHIVIST_STORAGE_ENDPOINT_URL", "https://storage.invalid")
            .env("ARCHIVIST_STORAGE_REGION", "us-east-1")
            .env("ARCHIVIST_STORAGE_ENCRYPTION", "s3_sse")
            .env("ARCHIVIST_STORAGE_RAW_BUCKET", "raw-bucket")
            .env("ARCHIVIST_STORAGE_CONTROL_BUCKET", "control-bucket")
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
            .expect("doctor fixture config")
    }

    fn migrated(dir: &TempDir) {
        let database = dir.path().join(STATE_DB_NAME);
        let mut store = StateStore::open(&database).expect("open state");
        store.migrate().expect("migrate state");
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))
            .expect("set database mode");
    }

    fn now() -> Timestamp {
        Timestamp::parse("2026-09-23T12:00:00Z").expect("timestamp")
    }

    #[test]
    fn civil_epoch_conversion_is_stable() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2026, 9, 23), Some(20_719));
    }

    #[test]
    fn timestamp_conversion_keeps_the_clock_window_integer_only() {
        let before = Timestamp::parse("1970-01-01T00:00:00Z").expect("timestamp");
        let after = Timestamp::parse("1970-01-01T00:05:00Z").expect("timestamp");
        assert_eq!(unix_seconds(&before), Some(0));
        assert_eq!(unix_seconds(&after), Some(CLOCK_SKEW_ALLOWANCE_SECONDS));
    }

    #[test]
    fn inspection_does_not_create_spool_or_lock_state() {
        let dir = TempDir::new("no-create");
        migrated(&dir);
        let result = inspect(&resolved_for(&dir), &[], true, &now()).expect("doctor result");
        assert!(result.findings().contains(&Finding::ClientLinkage));
        assert!(!dir.path().join("spool").exists());
        assert!(!dir.path().join("mutator.lock").exists());
        let text = String::from_utf8(result.to_document().canonical_bytes()).expect("json");
        assert!(!text.contains(dir.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn inspection_reports_permission_and_integrity_properties() {
        let dir = TempDir::new("properties");
        migrated(&dir);
        let database = dir.path().join(STATE_DB_NAME);
        let store = StateStore::open(&database).expect("reopen state");
        store
            .connection()
            .execute("DROP INDEX idx_generations_source", [])
            .expect("drop expected index");
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755))
            .expect("make directory unsafe");
        let result = inspect(&resolved_for(&dir), &[], true, &now()).expect("doctor result");
        assert!(result.findings().contains(&Finding::Permissions));
        assert!(result.findings().contains(&Finding::SqliteIntegrity));
        assert_eq!(result.evidence().state_dir_mode(), "0755");
    }

    #[test]
    fn a_held_mutator_lock_is_reported_without_being_a_failure() {
        let dir = TempDir::new("lock");
        migrated(&dir);
        let _lock = StateDirLock::acquire(dir.path()).expect("hold lock");
        let result = inspect(&resolved_for(&dir), &[], true, &now()).expect("doctor result");
        assert_eq!(result.evidence().lock(), "held");
        assert!(!result.findings().contains(&Finding::Permissions));
    }
}
