// SPDX-License-Identifier: Apache-2.0

//! Tests for crash-safe spool materialization: the ordered write path,
//! the mode pins, startup reconciliation at both injected crash points,
//! the removal rules, and the content-free diagnostics rule.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use archivist_protocol::sha256::{digest, encode_hex};
use archivist_protocol::vocabulary::{SafeMessage, Timestamp};

use super::Spool;
use super::{
    BUNDLE_SUFFIX, ReconcileReport, SPOOL_DIR_NAME, STAGING_SUFFIX, SpoolError, SpoolErrorKind,
};
use crate::state::StateStore;

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

/// A private directory removed on drop, so file-backed tests never share
/// state and never leave debris behind.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("archivist-spool-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
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

/// A migrated file-backed state store under `dir`, the way the daemon
/// holds one.
fn file_store(dir: &TempDir) -> StateStore {
    let mut store = StateStore::open(&dir.path().join("state.db")).expect("open state store");
    store.migrate().expect("migrate state store");
    store
}

/// The spool directory under `dir`, per the module's fixed layout.
fn spool_path(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join(SPOOL_DIR_NAME)
}

/// A canonical lowercase UUIDv7-shaped identity, distinct per seed, for
/// tests that choose a bundle's file name directly.
fn uuid_like(seed: u32) -> String {
    format!("{seed:08x}-1111-7222-8333-{seed:012x}")
}

/// Deterministic distinct payloads.
fn payload(seed: u8) -> Vec<u8> {
    let mut bytes = vec![seed; usize::from(seed) * 64 + 16];
    bytes.extend_from_slice(format!("payload-{seed}").as_bytes());
    bytes
}

/// The mode bits of a path, masked to the permission triads.
fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

/// Every `spool_entries` row as (`bundle_name`, state, digest, size).
fn all_rows(store: &StateStore) -> Vec<(String, String, String, i64)> {
    let mut statement = store
        .connection()
        .prepare(
            "SELECT bundle_name, state, envelope_digest, size_bytes
             FROM spool_entries ORDER BY bundle_name",
        )
        .expect("prepare");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .expect("query");
    rows.map(|row| row.expect("row")).collect()
}

/// The one bundle file in the spool directory, or a panic naming the
/// test's expectation.
fn sole_bundle(dir: &TempDir, tag: &str) -> std::path::PathBuf {
    let mut bundles = Vec::new();
    for entry in std::fs::read_dir(spool_path(dir)).expect("read spool dir") {
        let entry = entry.expect("entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(BUNDLE_SUFFIX) {
            bundles.push(entry.path());
        }
    }
    assert_eq!(bundles.len(), 1, "{tag}: expected exactly one bundle");
    bundles.remove(0)
}

// --- Directory preparation --------------------------------------------------

#[test]
fn spool_directory_is_created_mode_0700() {
    let dir = TempDir::new("dir-mode");
    Spool::open(dir.path()).expect("open spool");
    assert!(spool_path(&dir).is_dir());
    assert_eq!(mode_of(&spool_path(&dir)), 0o700);
}

#[test]
fn spool_directory_preexisting_at_unsafe_mode_is_refused() {
    let dir = TempDir::new("dir-unsafe");
    std::fs::create_dir_all(spool_path(&dir)).expect("create spool dir");
    std::fs::set_permissions(spool_path(&dir), std::fs::Permissions::from_mode(0o755))
        .expect("set permissive mode");

    let error = Spool::open(dir.path()).expect_err("open must refuse the wide mode");
    assert_eq!(error.kind(), SpoolErrorKind::UnsafePermissions);
    // The refusal names no path.
    let rendered = error.to_string();
    assert!(
        !rendered.contains(dir.path().to_string_lossy().as_ref()),
        "error leaked the path: {rendered}"
    );
}

// --- Materialization --------------------------------------------------------

#[test]
fn materialized_bundle_is_mode_0600_with_a_committed_row() {
    let dir = TempDir::new("materialize");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");
    let bytes = payload(1);

    let bundle = spool.materialize(&store, &bytes).expect("materialize");

    // The final name exists at mode 0600 and no staging file remains.
    let bundle_path = spool_path(&dir).join(bundle.bundle_name());
    assert!(
        bundle_path.is_file(),
        "bundle must exist under its final name"
    );
    assert_eq!(mode_of(&bundle_path), 0o600);
    let staging: Vec<_> = std::fs::read_dir(spool_path(&dir))
        .expect("read dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(STAGING_SUFFIX))
        .collect();
    assert!(staging.is_empty(), "staging debris remained: {staging:?}");

    // The returned identity matches the file name, and the row matches
    // the bytes.
    let stem = bundle
        .bundle_name()
        .strip_suffix(BUNDLE_SUFFIX)
        .expect("suffix");
    assert_eq!(bundle.spool_entry_id().as_str(), stem);
    assert_eq!(bundle.envelope_digest(), encode_hex(&digest(&bytes)));
    assert_eq!(bundle.size_bytes(), bytes.len() as u64);

    let rows = all_rows(&store);
    assert_eq!(rows.len(), 1);
    let (name, state, recorded_digest, size) = &rows[0];
    assert_eq!(name, bundle.bundle_name());
    assert_eq!(state, "materialized");
    assert_eq!(recorded_digest, bundle.envelope_digest());
    assert_eq!(*size, i64::try_from(bytes.len()).expect("size fits"));
}

#[test]
fn materialize_mints_distinct_time_ordered_identities() {
    let dir = TempDir::new("mint");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");

    let first = spool.materialize(&store, &payload(1)).expect("first");
    let second = spool.materialize(&store, &payload(2)).expect("second");
    assert_ne!(first.spool_entry_id(), second.spool_entry_id());
    // UUIDv7 identities carry the mint time, so the timestamp prefix
    // never moves backwards and a directory listing reads in capture
    // order. Within one millisecond the order is random, so only the
    // prefix — the 48-bit timestamp — is pinned here.
    let first_prefix = &first.spool_entry_id().as_str()[..12];
    let second_prefix = &second.spool_entry_id().as_str()[..12];
    assert!(
        first_prefix <= second_prefix,
        "mint time moved backwards: {first_prefix} > {second_prefix}"
    );
}

#[test]
fn spool_rows_carry_grammar_valid_timestamps() {
    let dir = TempDir::new("timestamps");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");
    spool.materialize(&store, &payload(3)).expect("materialize");

    let mut statement = store
        .connection()
        .prepare("SELECT created_at, updated_at, next_attempt_at, attempt_count FROM spool_entries")
        .expect("prepare");
    let (created, updated, next, attempts) = statement
        .query_row([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .expect("row");
    for text in [&created, &updated] {
        let parsed =
            Timestamp::parse(text).unwrap_or_else(|_| panic!("timestamp {text} is invalid"));
        assert!(
            parsed.calendar_valid(),
            "timestamp {text} is not a real instant"
        );
    }
    assert_eq!(next, None, "a fresh entry schedules no attempt");
    assert_eq!(attempts, 0);
}

// --- Crash injection --------------------------------------------------------

#[test]
fn crash_before_rename_leaves_no_row_and_no_committed_range() {
    let dir = TempDir::new("crash-before");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");
    let bytes = payload(4);

    // The drill simulates process death after the payload is durable,
    // before the rename: the call fails as a crash, and nothing cleans
    // up behind it.
    let error = spool
        .materialize_with_injected_crash(&store, &bytes, super::InjectedCrashForTests::BeforeRename)
        .expect_err("the drill must fail the call");
    assert_eq!(error.kind(), SpoolErrorKind::CrashInjected);
    assert!(
        all_rows(&store).is_empty(),
        "no row may exist before the rename"
    );

    // The staging debris is present: exactly what a crash leaves.
    let debris: Vec<_> = std::fs::read_dir(spool_path(&dir))
        .expect("read dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(STAGING_SUFFIX))
        .collect();
    assert_eq!(debris.len(), 1, "the drill must leave one staging file");

    // Startup reconciliation sweeps the staging file and indexes
    // nothing: the range was never committed, and the next capture
    // cycle re-reads it from the source artifact.
    let report = spool.reconcile(&store).expect("reconcile");
    assert_eq!(
        report,
        ReconcileReport {
            staging_files_removed: 1,
            ..ReconcileReport::default()
        }
    );
    assert!(all_rows(&store).is_empty());

    // Re-capture of the same payload succeeds and carries the same
    // digest: no complete range is lost, and content identity is stable.
    let recaptured = spool.materialize(&store, &bytes).expect("re-materialize");
    assert_eq!(recaptured.envelope_digest(), encode_hex(&digest(&bytes)));
}

#[test]
fn crash_after_rename_before_commit_loses_no_complete_range() {
    let dir = TempDir::new("crash-after");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");
    let bytes = payload(5);

    // The drill simulates process death after the rename is durable,
    // before the row commits.
    let error = spool
        .materialize_with_injected_crash(&store, &bytes, super::InjectedCrashForTests::AfterRename)
        .expect_err("the drill must fail the call");
    assert_eq!(error.kind(), SpoolErrorKind::CrashInjected);
    assert!(
        all_rows(&store).is_empty(),
        "no row may exist after the drill"
    );

    // The bundle is present and complete under its final name.
    let bundle_path = sole_bundle(&dir, "after drill");
    assert_eq!(mode_of(&bundle_path), 0o600);
    let bundle_name = bundle_path
        .file_name()
        .expect("file name")
        .to_string_lossy()
        .into_owned();

    // Startup reconciliation indexes the orphan into a row carrying
    // exactly the identity, digest, and size the crashed call would
    // have committed.
    let report = spool.reconcile(&store).expect("reconcile");
    assert_eq!(
        report,
        ReconcileReport {
            orphan_bundles_indexed: 1,
            ..ReconcileReport::default()
        }
    );
    let rows = all_rows(&store);
    assert_eq!(rows.len(), 1, "the orphan must be indexed, never discarded");
    let (name, state, recorded_digest, size) = &rows[0];
    assert_eq!(name, &bundle_name);
    assert_eq!(state, "materialized");
    assert_eq!(recorded_digest, &encode_hex(&digest(&bytes)));
    assert_eq!(*size, i64::try_from(bytes.len()).expect("size fits"));
    // The identity came from the file name, not a fresh mint; the
    // dedicated test below pins that directly.
}

#[test]
fn orphan_identity_comes_from_the_file_name() {
    let dir = TempDir::new("orphan-identity");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");

    // An orphan written by hand under a chosen identity, as a crashed
    // process would have left one.
    let chosen = uuid_like(42);
    let bytes = b"hand-written orphan bundle".to_vec();
    std::fs::write(
        spool_path(&dir).join(format!("{chosen}{BUNDLE_SUFFIX}")),
        &bytes,
    )
    .expect("write orphan");

    let report = spool.reconcile(&store).expect("reconcile");
    assert_eq!(report.orphan_bundles_indexed, 1);

    let rows = all_rows(&store);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, format!("{chosen}{BUNDLE_SUFFIX}"));
    assert_eq!(rows[0].2, encode_hex(&digest(&bytes)));
}

#[test]
fn reconciliation_is_idempotent() {
    let dir = TempDir::new("idempotent");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");
    let bytes = payload(6);

    let _ = spool
        .materialize_with_injected_crash(&store, &bytes, super::InjectedCrashForTests::AfterRename)
        .expect_err("drill");
    let first = spool.reconcile(&store).expect("first reconcile");
    assert_eq!(first.orphan_bundles_indexed, 1);

    let second = spool.reconcile(&store).expect("second reconcile");
    assert!(
        second.is_quiescent(),
        "a second pass must change nothing: {second:?}"
    );
    assert_eq!(all_rows(&store).len(), 1, "indexing must not duplicate");
}

// --- Removal rules ----------------------------------------------------------

#[test]
fn reconcile_removes_only_acknowledged_leftovers() {
    let dir = TempDir::new("removal-rules");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");

    // A live entry: spooled, pending upload.
    let live = spool.materialize(&store, &payload(7)).expect("live");
    // An acknowledged entry whose bundle removal was interrupted: the
    // state committed, the file remains (fault-injection point 9).
    let acked = spool.materialize(&store, &payload(8)).expect("acked");
    store
        .connection()
        .execute(
            "UPDATE spool_entries SET state = 'acknowledged' WHERE bundle_name = ?1",
            rusqlite::params![acked.bundle_name()],
        )
        .expect("acknowledge");

    // An orphan a crash left with no row at all.
    let orphan_id = uuid_like(9);
    std::fs::write(
        spool_path(&dir).join(format!("{orphan_id}{BUNDLE_SUFFIX}")),
        b"orphan",
    )
    .expect("write orphan");
    // Debris of an interrupted materialization.
    let debris_id = uuid_like(10);
    std::fs::write(
        spool_path(&dir).join(format!("{debris_id}{STAGING_SUFFIX}")),
        b"staging",
    )
    .expect("write staging");
    // Two entries the reconciler cannot classify: a foreign name and a
    // staging file outside this module's shape.
    std::fs::write(spool_path(&dir).join("unrecognized.dat"), b"foreign").expect("write foreign");
    std::fs::write(
        spool_path(&dir).join("not-an-identity.staging"),
        b"foreign staging",
    )
    .expect("write foreign staging");

    let report = spool.reconcile(&store).expect("reconcile");
    assert_eq!(
        report,
        ReconcileReport {
            orphan_bundles_indexed: 1,
            acknowledged_bundles_removed: 1,
            staging_files_removed: 1,
            unclassified_entries: 2,
            spool_rows_missing_bundles: 0,
        }
    );

    // The acknowledged leftover is gone; the live bundle remains.
    assert!(
        !spool_path(&dir).join(acked.bundle_name()).exists(),
        "an acknowledged leftover must be removed"
    );
    assert!(
        spool_path(&dir).join(live.bundle_name()).exists(),
        "a live bundle must never be removed"
    );
    // The acknowledged row itself survives: only the payload is cleaned.
    let states: Vec<(String, String)> = all_rows(&store)
        .into_iter()
        .map(|(name, state, _, _)| (name, state))
        .collect();
    assert!(states.contains(&(acked.bundle_name().to_owned(), "acknowledged".to_owned())));
    assert!(states.contains(&(live.bundle_name().to_owned(), "materialized".to_owned())));
    // The orphan was indexed, the debris swept, the unclassified left.
    assert!(
        spool_path(&dir)
            .join(format!("{orphan_id}{BUNDLE_SUFFIX}"))
            .exists()
    );
    assert!(
        !spool_path(&dir)
            .join(format!("{debris_id}{STAGING_SUFFIX}"))
            .exists()
    );
    assert!(spool_path(&dir).join("unrecognized.dat").exists());
    assert!(spool_path(&dir).join("not-an-identity.staging").exists());

    // A settled directory: nothing changes, and only the permanent
    // unclassified count remains.
    let second = spool.reconcile(&store).expect("second reconcile");
    assert_eq!(
        second,
        ReconcileReport {
            unclassified_entries: 2,
            ..ReconcileReport::default()
        }
    );
}

#[test]
fn live_rows_whose_bundle_is_missing_are_counted_not_repaired() {
    let dir = TempDir::new("missing");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");
    let bundle = spool
        .materialize(&store, &payload(11))
        .expect("materialize");
    std::fs::remove_file(spool_path(&dir).join(bundle.bundle_name())).expect("remove bundle");

    let report = spool.reconcile(&store).expect("reconcile");
    assert_eq!(report.spool_rows_missing_bundles, 1);
    assert_eq!(report.orphan_bundles_indexed, 0);
    assert_eq!(all_rows(&store).len(), 1, "the row must not be touched");
}

#[test]
fn remove_refuses_names_outside_the_bundle_grammar() {
    let dir = TempDir::new("remove-grammar");
    let _store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");

    let path_escape = format!("{}{}.bundle", uuid_like(12), "/../x");
    for bad in [
        "../escape.bundle",
        "plain-name.bundle",
        "no-suffix",
        "",
        path_escape.as_str(),
    ] {
        let error = spool.remove(bad).expect_err("must refuse a foreign name");
        assert_eq!(error.kind(), SpoolErrorKind::MalformedName, "{bad:?}");
    }
}

#[test]
fn remove_removes_an_acknowledged_bundle_and_tolerates_absence() {
    let dir = TempDir::new("remove");
    let store = file_store(&dir);
    let spool = Spool::open(dir.path()).expect("open spool");
    let bundle = spool
        .materialize(&store, &payload(13))
        .expect("materialize");

    // The commit-then-cleanup primitive: the file goes, the row stays.
    spool.remove(bundle.bundle_name()).expect("remove");
    assert!(!spool_path(&dir).join(bundle.bundle_name()).exists());
    assert_eq!(all_rows(&store).len(), 1);

    // Already absent is the goal state: success.
    spool.remove(bundle.bundle_name()).expect("second remove");
}

// --- Diagnostics ------------------------------------------------------------

#[test]
fn every_error_detail_is_a_safe_message() {
    for kind in SpoolErrorKind::all() {
        let error = SpoolError::of_kind(*kind);
        SafeMessage::parse(error.detail())
            .unwrap_or_else(|_| panic!("detail of {kind} is not a safe message"));
        let rendered = error.to_string();
        assert!(
            SafeMessage::parse(&rendered).is_ok(),
            "display of {kind} is not a safe message: {rendered}"
        );
        assert!(rendered.starts_with("spool "), "{rendered}");
    }
}

#[test]
fn error_kinds_are_distinct_and_complete() {
    let all = SpoolErrorKind::all();
    assert_eq!(all.len(), 5);
    let displays: Vec<_> = all.iter().map(std::string::ToString::to_string).collect();
    let mut sorted = displays.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(displays.len(), sorted.len(), "display strings collide");

    // Every kind's default detail is its own: no kind silently ships
    // another's message.
    for kind in all {
        assert_eq!(SpoolError::of_kind(*kind).detail(), kind.default_detail());
    }
}

#[test]
fn failure_renderings_never_name_the_spool_path() {
    let dir = TempDir::new("no-paths");
    // A file where the spool directory must be created.
    let blocker = dir.path().join(SPOOL_DIR_NAME);
    std::fs::write(&blocker, b"not a directory").expect("write blocker");

    let error = Spool::open(dir.path()).expect_err("open must fail");
    let rendered = error.to_string();
    assert!(
        !rendered.contains(dir.path().to_string_lossy().as_ref()),
        "error leaked the path: {rendered}"
    );
}
