// SPDX-License-Identifier: Apache-2.0

//! Deterministic interruption fuzzing for the client state machine.
//!
//! The unit tests pin each transition in isolation.  This black-box test
//! composes those transitions in many restartable traces: every step closes
//! and reopens the WAL store, while the same trace also exercises lock
//! ownership, spool reconciliation, frozen retry state, receipt rejection,
//! cursor retention, pressure hysteresis, cleanup, and scheduler planning.
//! The generator is deliberately small and dependency-free so it runs in the
//! normal test lane and remains reproducible from a failing seed.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use archivist_adapter_sdk::status::{
    AccountLabel, CoverageState, FreshnessLane, ScanClassification, SourceId,
};
use archivist_auth::authority::PinnedAuthorityRoot;
use archivist_client_core::acknowledgement::{
    AcknowledgementErrorKind, AcknowledgementRequest, acknowledge_receipt,
};
use archivist_client_core::inventory::{
    CoverageAnomaly, CursorDecision, CursorPosition, SourceInventory, cursor_retention,
};
use archivist_client_core::scheduler::{DrainLoad, SchedulerLimits, plan};
use archivist_client_core::spool::pressure::{PressureGate, PressureLimits};
use archivist_client_core::spool::{
    BUNDLE_SUFFIX, SPOOL_DIR_NAME, STAGING_SUFFIX, Spool, SpoolErrorKind, live_usage_bytes,
};
use archivist_client_core::state::lock::StateDirLock;
use archivist_client_core::state::{LATEST_SCHEMA_VERSION, StateErrorKind, StateStore};
use archivist_client_core::upload::{
    FreezeUpload, Jitter, RetryPolicy, UploadError, UploadRelation, claim_due_upload,
    freeze_upload, frozen_upload,
};
use archivist_protocol::vocabulary::{
    AdapterId, BlobDigest, ClientId, Ed25519PublicKey, IncomingChecksum, OccurrenceId, RequestId,
    TenantId, Timestamp, TransportEncoding, VersionToken,
};

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

const CAPTURED_AT: &str = "2026-09-23T04:45:13.000Z";
const TENANT: &str = "33333333-3333-4333-8333-333333333333";
const ORIGIN: &str = "11111111-1111-4111-8111-111111111111";
const UPLOADER: &str = "22222222-2222-4222-8222-222222222222";
const OCCURRENCE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const BLOB: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const CHECKSUM: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

struct TempDir(PathBuf);

impl TempDir {
    fn new(seed: u64) -> Self {
        let serial = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "archivist-client-recovery-{}-{seed:016x}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("recovery temp directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("pin recovery directory mode");
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

/// A reproducible generator with enough mixing to cover boundary-heavy
/// traces without adding a third-party property-testing dependency.
#[derive(Clone, Copy)]
struct Generator(u64);

impl Generator {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, upper: u64) -> u64 {
        if upper == 0 { 0 } else { self.next() % upper }
    }
}

struct ZeroJitter;

impl Jitter for ZeroJitter {
    fn random_bits(&mut self) -> Result<u64, UploadError> {
        Ok(0)
    }
}

fn timestamp() -> Timestamp {
    Timestamp::parse(CAPTURED_AT).expect("test timestamp")
}

fn id_for(seed: u64) -> String {
    let short = seed & 0xffff_ffff;
    format!("{short:08x}-1111-7222-8333-{short:012x}")
}

fn reopen(dir: &Path) -> StateStore {
    let mut store = StateStore::open(&dir.join("state.db")).expect("reopen state");
    store.migrate().expect("restart migration");
    store
}

fn live_entry_count(store: &StateStore) -> u64 {
    let count: i64 = store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM spool_entries WHERE state != 'acknowledged'",
            [],
            |row| row.get(0),
        )
        .expect("live entry count");
    u64::try_from(count).expect("nonnegative live entry count")
}

fn open_without_migrating(dir: &Path) -> StateStore {
    StateStore::open(&dir.join("state.db")).expect("open state checkpoint")
}

fn materialize(
    spool: &Spool,
    store: &StateStore,
    gate: &mut PressureGate,
    serial: u64,
) -> Option<archivist_client_core::spool::MaterializedBundle> {
    let length = usize::try_from(8 + serial % 24).expect("small payload length");
    let payload = (0..length)
        .map(|offset| (serial.wrapping_add(offset as u64) as u8).wrapping_add(1))
        .collect::<Vec<_>>();
    match spool.materialize(store, gate, &payload) {
        Ok(bundle) => Some(bundle),
        Err(error) if error.kind() == SpoolErrorKind::MaterializationPaused => None,
        Err(error) => panic!("materialization failed in deterministic trace: {error}"),
    }
}

fn freeze_fields<'a>(entry: &'a RequestId, occurrence: &'a OccurrenceId) -> FreezeUpload<'a> {
    let tenant = Box::leak(TenantId::parse(TENANT).expect("tenant").into());
    let origin = Box::leak(ClientId::parse(ORIGIN).expect("origin").into());
    let uploader = Box::leak(ClientId::parse(UPLOADER).expect("uploader").into());
    let version = Box::leak(VersionToken::parse("envelope-v1").expect("version").into());
    let digest = Box::leak(BlobDigest::parse(BLOB).expect("blob").into());
    let checksum = Box::leak(IncomingChecksum::parse(CHECKSUM).expect("checksum").into());
    let captured = Box::leak(timestamp().into());
    FreezeUpload {
        spool_entry_id: entry,
        tenant_id: tenant,
        origin_client_id: origin,
        uploader_client_id: uploader,
        occurrence_id: occurrence,
        envelope_version: version,
        storage_profile: archivist_protocol::vocabulary::StorageProfile::ZstdV1,
        transport_encoding: Some(TransportEncoding::Identity),
        canonical_digest: digest,
        incoming_checksum: checksum,
        canonical_size: 8,
        transport_size: 8,
        source_at: None,
        captured_at: captured,
        envelope_created_at: captured,
        relation: UploadRelation::Direct,
    }
}

fn scheduler_source(seed: u8, bytes: u64, lane: FreshnessLane) -> SourceInventory {
    let source =
        SourceId::parse(&format!("{seed:08x}-1111-4222-8333-{seed:012x}")).expect("source id");
    let has_backlog = bytes > 0;
    SourceInventory {
        source,
        adapter: AdapterId::parse("adapter-1").expect("adapter id"),
        account: AccountLabel::parse("account-1").expect("account label"),
        lane,
        coverage: if has_backlog {
            CoverageState::Partial
        } else if lane == FreshnessLane::Backfill {
            CoverageState::FullyBackfilled
        } else {
            CoverageState::Current
        },
        classification: ScanClassification::Ok,
        complete_bytes: bytes,
        complete_events: bytes / 8,
        acknowledged_bytes: 0,
        acknowledged_events: 0,
        outstanding_bytes: bytes,
        outstanding_events: bytes / 8,
        incomplete_tail_bytes: 0,
        freshness_lag_seconds: 0,
        cursor: CursorPosition::default(),
        decision: CursorDecision::Hold,
        anomaly: None::<CoverageAnomaly>,
        enrolled: true,
    }
}

fn assert_durable(dir: &Path, store: &mut StateStore) {
    assert_eq!(
        store.schema_version().expect("schema version"),
        LATEST_SCHEMA_VERSION
    );
    assert!(store.integrity().expect("state integrity").healthy());

    let mut rows = store
        .connection()
        .prepare(
            "SELECT bundle_name, state, size_bytes
             FROM spool_entries ORDER BY bundle_name",
        )
        .expect("spool rows");
    let records = rows
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .expect("spool row query")
        .collect::<Result<Vec<_>, _>>()
        .expect("spool row values");
    drop(rows);

    let mut live_sum = 0u64;
    for (name, state, size) in &records {
        assert!(*size >= 0, "a recovered row cannot have a negative size");
        let path = dir.join(SPOOL_DIR_NAME).join(name);
        if state != "acknowledged" {
            assert!(path.is_file(), "live row lost its bundle: {name}");
            live_sum = live_sum.saturating_add(u64::try_from(*size).expect("size is nonnegative"));
        } else {
            let receipt_count: i64 = store
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM receipts r
                     JOIN frozen_requests fr ON fr.request_id = r.request_id
                     JOIN spool_entries se ON se.spool_entry_id = fr.spool_entry_id
                     WHERE se.bundle_name = ?1 AND r.signature_verified = 1",
                    [name],
                    |row| row.get(0),
                )
                .expect("acknowledged receipt evidence");
            assert_eq!(
                receipt_count, 1,
                "acknowledged bundle lost its receipt: {name}"
            );
        }
    }
    assert_eq!(live_usage_bytes(store).expect("live usage"), live_sum);
    assert_eq!(
        live_entry_count(store),
        records
            .iter()
            .filter(|(_, state, _)| state != "acknowledged")
            .count() as u64
    );

    for entry in std::fs::read_dir(dir.join(SPOOL_DIR_NAME)).expect("spool directory") {
        let entry = entry.expect("spool entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(BUNDLE_SUFFIX) {
            assert!(
                RequestId::parse(stem).is_ok(),
                "unclassified bundle shape survived: {name}"
            );
        }
    }
}

fn assert_pressure_hysteresis(gate: &mut PressureGate, usage: u64, free: u64) {
    let was_paused = gate.is_paused();
    let status = gate.evaluate(usage, free);
    if was_paused && status.admits_materialization() {
        assert!(usage < status.limits().resume_threshold_bytes());
        assert!(free > status.limits().free_floor_bytes());
    }
    if !was_paused && !status.admits_materialization() {
        assert!(
            usage >= status.limits().spool_cap_bytes()
                || free <= status.limits().free_floor_bytes()
        );
    }
}

fn assert_cursor_never_regresses(
    retained_bytes: u64,
    retained_events: u64,
    complete_bytes: u64,
    complete_events: u64,
    degraded: bool,
) {
    match cursor_retention(
        retained_bytes,
        retained_events,
        complete_bytes,
        complete_events,
        degraded,
    ) {
        CursorDecision::Hold => {}
        CursorDecision::Advance { bytes, events } => {
            assert!(bytes >= retained_bytes);
            assert!(events >= retained_events);
            assert!(bytes >= complete_bytes);
            assert!(events >= complete_events);
        }
    }
}

#[test]
fn deterministic_recovery_fuzz_converges_after_arbitrary_interruptions() {
    for seed in 0..4_u64 {
        let temp = TempDir::new(seed);
        let mut lock = Some(StateDirLock::acquire(temp.path()).expect("initial mutator lock"));
        let mut store = open_without_migrating(temp.path());
        let spool = Spool::open(temp.path()).expect("spool");
        let mut gate = PressureGate::new(PressureLimits::new(192, 0, 80));
        let mut generator = Generator::new(seed.wrapping_mul(0x9e37_79b9) ^ 0xfeed_face);
        let occurrence = OccurrenceId::parse(OCCURRENCE).expect("occurrence");
        let root = PinnedAuthorityRoot::new(
            TenantId::parse(TENANT).expect("tenant"),
            Ed25519PublicKey::from_raw([0; 32]),
        );

        // Each seed takes a different reverse-migration checkpoint, then
        // restarts and migrates forward again. A second pass after every
        // checkpoint is the same recovery action a daemon performs after
        // being killed between migration transactions. The public forward
        // runner validates the complete object set, so partial checkpoints
        // are inspected before the next full forward run.
        store.migrate().expect("initial complete migration");
        for target in (0..=LATEST_SCHEMA_VERSION).rev() {
            store.revert_to(target).expect("migration checkpoint");
            drop(store);
            store = open_without_migrating(temp.path());
            assert_eq!(store.schema_version().expect("checkpoint version"), target);
            store.migrate().expect("resume migration after restart");
        }

        for step in 0..32_u64 {
            match generator.below(9) {
                0 => {
                    // A live owner always refuses a second mutator, while a
                    // read-only snapshot remains available to status/doctor.
                    let refused = StateDirLock::acquire(temp.path()).expect_err("second mutator");
                    assert_eq!(refused.kind(), StateErrorKind::LockHeld);
                    let snapshot = archivist_client_core::state::StateSnapshot::open(
                        &temp.path().join("state.db"),
                    )
                    .expect("reader during mutator ownership");
                    assert_eq!(
                        snapshot.schema_version().expect("snapshot schema"),
                        LATEST_SCHEMA_VERSION
                    );
                }
                1 => {
                    // Release and reacquire around a simulated process
                    // restart.  No state operation occurs without ownership.
                    drop(store);
                    drop(lock.take());
                    lock = Some(StateDirLock::acquire(temp.path()).expect("reacquire lock"));
                    store = reopen(temp.path());
                }
                2 => {
                    let _ = materialize(&spool, &store, &mut gate, seed + step);
                }
                3 => {
                    // Plant the two filesystem states an interrupted write
                    // can leave; reconciliation must delete staging debris
                    // and index a complete orphan rather than discard it.
                    let identity = id_for(seed.wrapping_mul(10_000) + step * 2 + 1);
                    let payload = [seed as u8, step as u8, 0xa5, 0x5a];
                    std::fs::write(
                        temp.path()
                            .join(SPOOL_DIR_NAME)
                            .join(format!("{identity}{STAGING_SUFFIX}")),
                        payload,
                    )
                    .expect("staging debris");
                    let orphan = id_for(seed.wrapping_mul(10_000) + step * 2 + 2);
                    std::fs::write(
                        temp.path()
                            .join(SPOOL_DIR_NAME)
                            .join(format!("{orphan}{BUNDLE_SUFFIX}")),
                        payload,
                    )
                    .expect("orphan bundle");
                    spool
                        .reconcile(&store)
                        .expect("reconcile interruption debris");
                }
                4 => {
                    // Freeze once, freeze again after the same boundary, and
                    // claim repeatedly.  Restarting between claims must not
                    // change the request or attestation identities.
                    if let Some(bundle) = materialize(&spool, &store, &mut gate, seed + step + 1000)
                    {
                        let entry = bundle.spool_entry_id().clone();
                        let fields = freeze_fields(&entry, &occurrence);
                        let first = freeze_upload(&mut store, &fields).expect("freeze upload");
                        let second = freeze_upload(&mut store, &fields).expect("idempotent freeze");
                        assert_eq!(first, second);
                        drop(store);
                        store = reopen(temp.path());
                        assert_eq!(
                            frozen_upload(&store, &entry).expect("frozen lookup"),
                            Some(first)
                        );

                        let now = timestamp();
                        let mut jitter = ZeroJitter;
                        for _ in 0..4 {
                            let claim = claim_due_upload(
                                &mut store,
                                &now,
                                &RetryPolicy::new(1, 64),
                                &mut jitter,
                            )
                            .expect("retry claim");
                            let claim = claim.expect("entry remains retryable");
                            assert_eq!(
                                claim.frozen(),
                                frozen_upload(&store, claim.spool_entry_id())
                                    .expect("frozen after claim")
                                    .as_ref()
                                    .expect("frozen identity")
                            );
                        }
                    }
                }
                5 => {
                    // Receipt bytes are untrusted input.  Every malformed
                    // acknowledgement must leave both cursor and spool
                    // evidence untouched, regardless of the restart point.
                    let before_cursor: Option<String> = store
                        .connection()
                        .query_row(
                            "SELECT last_cursor FROM sources ORDER BY source_id LIMIT 1",
                            [],
                            |row| row.get(0),
                        )
                        .ok();
                    let length = usize::try_from(generator.below(48)).expect("small receipt");
                    let bytes = (0..length)
                        .map(|n| {
                            generator
                                .next()
                                .wrapping_add(u64::try_from(n).expect("small receipt index"))
                                as u8
                        })
                        .collect::<Vec<_>>();
                    let result = acknowledge_receipt(
                        &spool,
                        &mut store,
                        AcknowledgementRequest::new(&bytes, "cursor-fuzz"),
                        &root,
                        |_| None,
                    );
                    assert_eq!(
                        result.expect_err("random receipt must fail").kind(),
                        AcknowledgementErrorKind::MalformedReceipt
                    );
                    let after_cursor: Option<String> = store
                        .connection()
                        .query_row(
                            "SELECT last_cursor FROM sources ORDER BY source_id LIMIT 1",
                            [],
                            |row| row.get(0),
                        )
                        .ok();
                    assert_eq!(before_cursor, after_cursor);
                }
                6 => {
                    // Cleanup is commit-before-delete: retain the durable row
                    // and let reconciliation remove only its acknowledged
                    // payload.  The row is deliberately kept as evidence.
                    let candidate: Option<(String, String)> = store
                        .connection()
                        .query_row(
                            "SELECT se.spool_entry_id, fr.request_id
                             FROM spool_entries se
                             JOIN frozen_requests fr ON fr.spool_entry_id = se.spool_entry_id
                             WHERE se.state != 'acknowledged'
                             ORDER BY se.bundle_name LIMIT 1",
                            [],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .ok();
                    if let Some((entry, request)) = candidate {
                        let ordinal: i64 = store
                            .connection()
                            .query_row(
                                "SELECT COALESCE(MAX(commit_ordinal), -1) + 1 FROM receipts",
                                [],
                                |row| row.get(0),
                            )
                            .expect("receipt ordinal");
                        let signature = "a".repeat(128);
                        store
                            .connection()
                            .execute(
                                "INSERT OR IGNORE INTO receipts (
                                     request_id, receipt_key_id, signature, receipt_digest,
                                     commit_ordinal, commit_time, signature_verified,
                                     received_at, receipt_bytes)
                                 VALUES (?1, 'fuzz-key', ?2, ?3, ?4, ?5, 1, ?5, ?6)",
                                rusqlite::params![
                                    request,
                                    signature,
                                    BLOB,
                                    ordinal,
                                    CAPTURED_AT,
                                    b"synthetic committed receipt".as_slice(),
                                ],
                            )
                            .expect("durable synthetic receipt");
                        store
                            .connection()
                            .execute(
                                "UPDATE spool_entries SET state = 'acknowledged'
                                 WHERE spool_entry_id = ?1",
                                [entry],
                            )
                            .expect("acknowledge cleanup candidate");
                    }
                    spool.reconcile(&store).expect("acknowledged cleanup");
                }
                7 => {
                    let usage = generator.below(384);
                    let free = generator.below(3);
                    assert_pressure_hysteresis(&mut gate, usage, free);
                    assert_cursor_never_regresses(
                        generator.below(100),
                        generator.below(20),
                        generator.below(140),
                        generator.below(40),
                        gate.is_paused(),
                    );
                }
                _ => {
                    // The scheduler has no hidden process-local state.  Its
                    // plan must therefore be identical before and after a
                    // restart, including when source order changes.
                    let sources = vec![
                        scheduler_source(1, 64 + generator.below(192), FreshnessLane::Freshness),
                        scheduler_source(2, generator.below(1024), FreshnessLane::Backfill),
                        scheduler_source(3, generator.below(1024), FreshnessLane::Backfill),
                    ];
                    let pending = DrainLoad {
                        entries: live_entry_count(&store),
                        bytes: live_usage_bytes(&store).expect("pending bytes"),
                    };
                    let expected = plan(&sources, pending, 256, SchedulerLimits::new(64, 128));
                    let mut reordered = sources.clone();
                    reordered.reverse();
                    assert_eq!(
                        expected,
                        plan(&reordered, pending, 256, SchedulerLimits::new(64, 128))
                    );
                }
            }

            // This is the interruption boundary: the process disappears
            // after the step, then startup reruns migration and reconciliation
            // before the next mutator action.
            drop(store);
            store = reopen(temp.path());
            spool.reconcile(&store).expect("restart reconciliation");
            assert_durable(temp.path(), &mut store);
        }

        drop(store);
        drop(lock);
    }
}
