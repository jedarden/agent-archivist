// SPDX-License-Identifier: Apache-2.0

//! Crash-safe materialization of spool bundles (plan Section 7.9).
//!
//! A spool bundle is the client's only copy of a captured range between
//! the moment the chunker cuts it and the moment the server's receipt is
//! acknowledged, so the write path is ordered so that no crash and no
//! failed call can leave the client believing a range is durable when it
//! is not, or discard a bundle that became durable:
//!
//! 1. the payload is written to a staging file inside the spool
//!    directory, created mode `0600` and pinned against a permissive
//!    umask;
//! 2. the file is synchronized, so the bytes are durable before the
//!    bundle can be mistaken for complete;
//! 3. the staging file is atomically renamed to its final bundle name
//!    and the directory is synchronized, so the rename itself is
//!    durable;
//! 4. only then is the `spool_entries` row committed to the state
//!    database, in a state directory the state module's mutator lock
//!    already holds at mode `0700`.
//!
//! Rename is atomic, so a bundle name that exists is a complete bundle:
//! the name appears in one step, never in a partially written state.
//! That single property is what makes startup reconciliation sound:
//!
//! - **complete orphan bundles** — a bundle file with no state row —
//!   are *indexed*, not discarded: the row the crashed process never
//!   reached is rebuilt from the file name (the entry identity) and the
//!   file content (the digest and size), which are exactly the values
//!   the crashed call would have written, and the bundle re-enters the
//!   upload pipeline;
//! - **acknowledged leftovers** — a bundle whose row is already
//!   `acknowledged` — are removed: the acknowledgement transaction
//!   committed first (plan Section 7.9: payload cleanup happens only
//!   after commit), so the file is post-commit debris and its removal
//!   loses nothing;
//! - **staging files** — a name that was never renamed into place — are
//!   removed. A staging file is never a complete bundle, and no row can
//!   reference one because rows commit only after the rename, so its
//!   content holds no committed range: the source cursor never advanced
//!   past it (cursor advance and acknowledgement share one
//!   transaction), and the next capture cycle re-reads the range from
//!   the source artifact.
//!
//! Anything else — directories, unknown names, names this module does
//! not produce — is counted and left in place: the reconciler removes
//! only what it can prove is safe to remove.
//!
//! The contract is tested at both drill points — before the rename and
//! after it, before the row commit — by the fault-injection tests in
//! this module: either crash loses no complete range, and a second
//! reconciliation pass changes nothing.
//!
//! # Status
//!
//! Materialization, the startup reconciliation pass, the acknowledged
//! cleanup primitive, and the spool/free-disk high-water policy's state
//! and measurements ([`pressure`]) arrived with Phase 5. The upload
//! scheduler, the receipt/acknowledgement transaction that marks
//! entries `acknowledged`, and the policy's scheduling and status
//! consumers consume this module and are later Phase 5 deliverables.
//!
//! # Content-free diagnostics
//!
//! [`SpoolError`] cannot carry runtime text: its detail is a `&'static
//! str`, and operating-system error strings — which can embed the spool
//! path — are dropped at the boundary. The spool directory's path is
//! never rendered by any type in this module; [`Spool`] deliberately
//! has a field-free `Debug`.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::{DirBuilder, File, OpenOptions, Permissions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use archivist_protocol::sha256::{digest, encode_hex};
use archivist_protocol::vocabulary::{RequestId, Timestamp};
use rusqlite::Connection;

use crate::state::StateStore;

pub mod pressure;

#[cfg(test)]
mod tests;

/// The spool directory inside the mode-`0700` state directory. The
/// directory is created mode `0700` and refused at any other mode
/// (CFG-023), the same contract the mutator lock applies to the state
/// directory itself.
pub const SPOOL_DIR_NAME: &str = "spool";

/// The final-name suffix of a complete bundle:
/// `<spool_entry_id>.bundle`.
pub const BUNDLE_SUFFIX: &str = ".bundle";

/// The staging-name suffix of a bundle whose bytes are still being
/// written: `<spool_entry_id>.staging`. It becomes a bundle only by
/// atomic rename.
pub const STAGING_SUFFIX: &str = ".staging";

/// The spool-entry state a materialized or reconciled row is committed
/// with: durable on disk, not yet uploading.
const STATE_MATERIALIZED: &str = "materialized";

/// The spool-entry state whose bundle is post-commit cleanup debris.
const STATE_ACKNOWLEDGED: &str = "acknowledged";

/// The closed set of failure classes a spool operation can report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpoolErrorKind {
    /// The spool directory, a bundle file, or the state database could
    /// not be operated. The path is deliberately absent from the error;
    /// the caller already knows which directory it asked for.
    Unavailable,
    /// A spool directory or bundle file existed with permissions other
    /// than the pinned modes (CFG-023). Refused, never widened or
    /// narrowed in place: `doctor` is the surface that reports the
    /// offending mode.
    UnsafePermissions,
    /// The state database was locked beyond the busy timeout while
    /// committing a spool row.
    Busy,
    /// A caller-supplied bundle name is not a plain bundle file name of
    /// this module's shape (`<spool_entry_id>.bundle`): it could never
    /// resolve inside the spool directory without escaping it.
    MalformedName,
    /// A fault drill fired. Production code never arms a drill, so this
    /// kind is producible only by the fault-injection harness; it lives
    /// in the closed set so a drill's failure is distinguishable from a
    /// real spool failure and can never be mistaken for one.
    CrashInjected,
}

impl SpoolErrorKind {
    /// Every kind, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Unavailable,
            Self::UnsafePermissions,
            Self::Busy,
            Self::MalformedName,
            Self::CrashInjected,
        ]
    }

    /// The content-free default detail shipped with this kind. Pinned
    /// to the protocol's safe-message grammar by a unit test.
    #[must_use]
    pub const fn default_detail(self) -> &'static str {
        match self {
            Self::Unavailable => "spool directory or state database operation failed",
            Self::UnsafePermissions => "spool directory or bundle file permissions are unsafe",
            Self::Busy => "state database is locked by another process",
            Self::MalformedName => "bundle name does not match the spool bundle grammar",
            Self::CrashInjected => "injected crash point reached",
        }
    }
}

impl std::fmt::Display for SpoolErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Unavailable => "unavailable",
            Self::UnsafePermissions => "unsafe-permissions",
            Self::Busy => "busy",
            Self::MalformedName => "malformed-name",
            Self::CrashInjected => "crash-injected",
        };
        f.write_str(text)
    }
}

/// Why a spool operation failed: a closed class plus content-free
/// context.
///
/// The type is incapable of carrying a path or transcript data by
/// construction — the only string field is a static literal, and
/// operating-system error text (which can embed the spool directory's
/// path) is dropped at the boundary, never wrapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpoolError {
    kind: SpoolErrorKind,
    detail: &'static str,
}

impl SpoolError {
    /// Build an error carrying the kind's default detail.
    #[must_use]
    pub const fn of_kind(kind: SpoolErrorKind) -> Self {
        Self {
            kind,
            detail: kind.default_detail(),
        }
    }

    /// Build an error with a static, content-free detail other than the
    /// kind's default.
    #[must_use]
    pub const fn with_detail(kind: SpoolErrorKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// The failure class.
    #[must_use]
    pub const fn kind(&self) -> SpoolErrorKind {
        self.kind
    }

    /// The content-free detail text.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl std::fmt::Display for SpoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "spool {}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for SpoolError {}

/// A bundle whose bytes are durable under their final name and whose
/// state row is committed: the only state in which a capture is
/// reported as spooled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedBundle {
    /// The spool entry identity, minted for this bundle and recoverable
    /// from the bundle's file name after a crash.
    spool_entry_id: RequestId,
    /// The bundle's file name inside the spool directory.
    bundle_name: String,
    /// Lowercase-hex SHA-256 of the bundle bytes.
    envelope_digest: String,
    /// Bundle size in bytes.
    size_bytes: u64,
}

impl MaterializedBundle {
    /// The spool entry identity.
    #[must_use]
    pub fn spool_entry_id(&self) -> &RequestId {
        &self.spool_entry_id
    }

    /// The bundle's file name inside the spool directory.
    #[must_use]
    pub fn bundle_name(&self) -> &str {
        &self.bundle_name
    }

    /// The lowercase-hex SHA-256 of the bundle bytes — the value
    /// recorded in the `spool_entries.envelope_digest` column.
    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    /// The bundle size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// What one startup reconciliation pass found and did. Counts only:
/// never names, paths, or digests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Complete bundles with no state row, indexed back into the
    /// pipeline.
    pub orphan_bundles_indexed: u64,
    /// Bundles of already-`acknowledged` entries removed from disk.
    pub acknowledged_bundles_removed: u64,
    /// Staging files of interrupted materializations removed.
    pub staging_files_removed: u64,
    /// Entries the reconciler could not classify and deliberately left
    /// in place.
    pub unclassified_entries: u64,
    /// Live (not yet acknowledged) state rows whose bundle file is
    /// missing — a corruption signal for `doctor`, never repaired here.
    pub spool_rows_missing_bundles: u64,
}

impl ReconcileReport {
    /// Whether the pass changed nothing and found nothing unexplained:
    /// the signature of an already-reconciled directory.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.orphan_bundles_indexed == 0
            && self.acknowledged_bundles_removed == 0
            && self.staging_files_removed == 0
            && self.unclassified_entries == 0
            && self.spool_rows_missing_bundles == 0
    }
}

/// Where a fault drill fails a materialization. Production calls carry
/// only [`InjectedCrash::None`]; the drill points exist in test builds
/// only and simulate process death at the two boundaries the plan's
/// crash-transition tests name around the local rename (plan Section
/// 7.9, fault-injection points 1 and 2): no cleanup runs, so the spool
/// directory and state database are left exactly as a crash would have
/// left them.
#[derive(Clone, Copy)]
enum InjectedCrash {
    /// No drill.
    None,
    /// Fail after the payload is synchronized, before the rename.
    #[cfg(test)]
    BeforeRename,
    /// Fail after the rename and its directory synchronization, before
    /// the state row commits.
    #[cfg(test)]
    AfterRename,
}

/// The fault-drill selector the fault-injection tests pass to
/// [`Spool::materialize_with_injected_crash`]. Test-only, and deliberately
/// separate from [`InjectedCrash`]: production callers cannot name a
/// drill, and the no-drill case is not expressible through this type.
#[cfg(test)]
#[derive(Clone, Copy)]
enum InjectedCrashForTests {
    /// Die after the payload is durable, before the rename.
    BeforeRename,
    /// Die after the rename is durable, before the row commits.
    AfterRename,
}

#[cfg(test)]
impl Spool {
    /// The production write path with a drill armed at one boundary.
    /// Nothing cleans up behind a drill — no staging sweep, no row —
    /// so the spool directory and state database are left exactly as
    /// a process death at that point would have left them.
    fn materialize_with_injected_crash(
        &self,
        store: &StateStore,
        payload: &[u8],
        crash: InjectedCrashForTests,
    ) -> Result<MaterializedBundle, SpoolError> {
        let crash = match crash {
            InjectedCrashForTests::BeforeRename => InjectedCrash::BeforeRename,
            InjectedCrashForTests::AfterRename => InjectedCrash::AfterRename,
        };
        self.begin_bundle(store, payload, crash)
    }
}

/// The spool directory handle: the materialization and reconciliation
/// operations over one client state directory's `spool/`
/// subdirectory.
///
/// Open with [`Spool::open`] after taking the state directory's mutator
/// lock — filesystem scans and cleanup are safe for exactly one mutator
/// (plan Section 7.9), and the lock is what provides it.
pub struct Spool {
    // The open handle is the directory's path. `Debug` is implemented
    // by hand rather than derived because the derived form would render
    // the path, which must never reach a diagnostic.
    dir: PathBuf,
}

impl std::fmt::Debug for Spool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Spool")
    }
}

impl Spool {
    /// Open (creating if absent) the spool directory inside the state
    /// directory at `state_dir`, as `<state_dir>/spool` in mode `0700`.
    ///
    /// A directory that exists with permissions other than `0700` is
    /// refused rather than widened or narrowed (CFG-023).
    ///
    /// # Errors
    ///
    /// [`SpoolErrorKind::UnsafePermissions`] when the directory cannot
    /// be prepared or pre-exists at an unsafe mode. The path never
    /// appears in the error.
    pub fn open(state_dir: &Path) -> Result<Self, SpoolError> {
        let dir = state_dir.join(SPOOL_DIR_NAME);
        prepare_directory(&dir)?;
        Ok(Self { dir })
    }

    /// Materialize one bundle: write the payload to a mode-`0600`
    /// staging file, synchronize it, atomically rename it to
    /// `<spool_entry_id>.bundle`, synchronize the directory, and only
    /// then commit the `spool_entries` row (state `materialized`).
    ///
    /// The spool entry identity is minted here and recoverable from the
    /// bundle's file name, so a crash between the rename and the row
    /// commit is repaired by [`Spool::reconcile`] into a row with the
    /// same identity, digest, and size this call would have committed.
    ///
    /// The recorded digest is the SHA-256 of the bundle bytes. The
    /// engine layer owns binding that digest to the frozen upload
    /// envelope; this module guarantees only that the row's digest and
    /// size always describe exactly the bytes under the final name.
    ///
    /// A failure after the rename leaves the bundle in place — it is a
    /// complete orphan and safe, so removal is never attempted;
    /// reconciliation indexes it. A failure before the rename is
    /// followed by a best-effort staging cleanup; a drill failure (the
    /// `InjectedCrash` fault points, reachable only from the tests)
    /// skips even that, leaving the exact debris a process death would
    /// leave.
    ///
    /// # Errors
    ///
    /// [`SpoolErrorKind::Unavailable`] when any filesystem step or the
    /// row commit fails; [`SpoolErrorKind::Busy`] when the state
    /// database is locked beyond its timeout. The path and the
    /// operating system's error text never appear.
    pub fn materialize(
        &self,
        store: &StateStore,
        payload: &[u8],
    ) -> Result<MaterializedBundle, SpoolError> {
        self.begin_bundle(store, payload, InjectedCrash::None)
    }

    /// Measure the filesystem free space available to this spool: the
    /// bytes an unprivileged process could still write on the
    /// filesystem holding the spool directory (`statvfs`
    /// `f_bavail * f_frsize`, the number `df` reports). This is the
    /// measurement the policy's free-space floor applies to.
    ///
    /// # Errors
    ///
    /// [`SpoolErrorKind::Unavailable`] when the filesystem cannot be
    /// probed. The path never appears in the error.
    pub fn free_space_bytes(&self) -> Result<u64, SpoolError> {
        let stats = rustix::fs::statvfs(&self.dir)
            .map_err(|_| unavailable("spool filesystem free space could not be measured"))?;
        Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
    }

    /// Reconcile the spool directory with the state database at startup
    /// (plan Section 7.9: "Startup reconciles complete unindexed bundles
    /// and removes acknowledged bundles left after a crash").
    ///
    /// Per directory entry, in one pass:
    ///
    /// - a complete bundle (`*.bundle`) of an `acknowledged` entry is
    ///   removed — post-commit debris (fault-injection point 9);
    /// - a complete bundle with no state row is indexed: the row is
    ///   rebuilt from the file name and the file content with state
    ///   `materialized`, giving the crashed range back to the pipeline;
    /// - a staging file (`*.staging`) whose identity parses and that no
    ///   row references is removed — debris of an interrupted
    ///   materialization, which by the ordering contract can never hold
    ///   a committed range;
    /// - everything else — live bundles, directories, unknown or
    ///   non-UTF-8 names, referenced staging names, unparseable bundle
    ///   identities — is left in place and counted.
    ///
    /// Live rows whose bundle file is missing are counted, never
    /// repaired: the payload is gone and `doctor` must surface that.
    ///
    /// Every per-entry step is independent, so a crash mid-pass is
    /// repaired by re-running the pass; a second pass over a settled
    /// directory changes nothing.
    ///
    /// # Errors
    ///
    /// [`SpoolErrorKind::Unavailable`] when the directory cannot be
    /// scanned, an entry cannot be acted on, or a needed row insert
    /// fails; [`SpoolErrorKind::Busy`] when the state database is
    /// locked. A failure part-way leaves earlier steps applied and the
    /// rest for the next pass.
    pub fn reconcile(&self, store: &StateStore) -> Result<ReconcileReport, SpoolError> {
        let conn = store.connection();
        let rows = load_row_states(conn)?;
        let now = now_utc(conn)?;
        let mut report = ReconcileReport::default();
        let mut seen_files: HashSet<String> = HashSet::new();

        let entries = std::fs::read_dir(&self.dir).map_err(|_| unavailable(SCAN_DETAIL))?;
        for entry in entries {
            let entry = entry.map_err(|_| unavailable(SCAN_DETAIL))?;
            let Ok(name) = entry.file_name().into_string() else {
                report.unclassified_entries += 1;
                continue;
            };
            if !entry
                .file_type()
                .map_err(|_| unavailable(SCAN_DETAIL))?
                .is_file()
            {
                report.unclassified_entries += 1;
                continue;
            }
            if let Some(stem) = name.strip_suffix(BUNDLE_SUFFIX) {
                self.reconcile_bundle(conn, &rows, &now, &name, stem, &mut report)?;
            } else if let Some(stem) = name.strip_suffix(STAGING_SUFFIX) {
                self.reconcile_staging(&rows, &name, stem, &mut report)?;
            } else {
                report.unclassified_entries += 1;
            }
            seen_files.insert(name);
        }

        report.spool_rows_missing_bundles = u64::try_from(
            rows.iter()
                .filter(|(name, state)| {
                    state.as_str() != STATE_ACKNOWLEDGED && !seen_files.contains(*name)
                })
                .count(),
        )
        .unwrap_or(u64::MAX);
        Ok(report)
    }

    /// Classify and act on one `*.bundle` directory entry.
    fn reconcile_bundle(
        &self,
        conn: &Connection,
        rows: &HashMap<String, String>,
        now: &Timestamp,
        name: &str,
        stem: &str,
        report: &mut ReconcileReport,
    ) -> Result<(), SpoolError> {
        match rows.get(name) {
            // The acknowledgement committed, so the bundle is
            // post-commit debris: finish the removal the crash
            // interrupted.
            Some(state) if state.as_str() == STATE_ACKNOWLEDGED => {
                std::fs::remove_file(self.dir.join(name))
                    .map_err(|_| unavailable(REMOVE_DETAIL))?;
                report.acknowledged_bundles_removed += 1;
            }
            // The bundle belongs to a live entry: untouched.
            Some(_) => {}
            // Complete orphan: index it. The identity comes from the
            // file name and the digest and size from the content —
            // exactly the values the crashed process would have
            // committed.
            None => match RequestId::parse(stem) {
                Ok(id) => {
                    index_orphan(self.dir.join(name), conn, &id, name, now)?;
                    report.orphan_bundles_indexed += 1;
                }
                Err(_) => report.unclassified_entries += 1,
            },
        }
        Ok(())
    }

    /// Classify and act on one `*.staging` directory entry.
    fn reconcile_staging(
        &self,
        rows: &HashMap<String, String>,
        name: &str,
        stem: &str,
        report: &mut ReconcileReport,
    ) -> Result<(), SpoolError> {
        // A staging name is removable only when it is this module's
        // shape and no row references it; a referenced staging name
        // would mean the ordering contract was violated, so it is left
        // in place and counted.
        if rows.contains_key(name) || RequestId::parse(stem).is_err() {
            report.unclassified_entries += 1;
            return Ok(());
        }
        std::fs::remove_file(self.dir.join(name)).map_err(|_| unavailable(REMOVE_DETAIL))?;
        report.staging_files_removed += 1;
        Ok(())
    }

    /// Remove one bundle file by its row-recorded name, after the
    /// acknowledgement transaction has committed: the cleanup primitive
    /// the receipt path calls at commit-then-cleanup (plan Section 7.9).
    /// Already absent is success, because the file being gone is the
    /// goal state.
    ///
    /// # Errors
    ///
    /// [`SpoolErrorKind::MalformedName`] when `bundle_name` is not a
    /// plain `<spool_entry_id>.bundle` name — such a name could never
    /// resolve inside the spool directory without escaping it.
    /// [`SpoolErrorKind::Unavailable`] when the file exists but cannot
    /// be removed.
    pub fn remove(&self, bundle_name: &str) -> Result<(), SpoolError> {
        if !is_bundle_name(bundle_name) {
            return Err(SpoolError::of_kind(SpoolErrorKind::MalformedName));
        }
        match std::fs::remove_file(self.dir.join(bundle_name)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(unavailable(REMOVE_DETAIL)),
        }
    }

    /// The ordered write path shared by [`Spool::materialize`] and the
    /// fault-drill entry point in the tests.
    fn begin_bundle(
        &self,
        store: &StateStore,
        payload: &[u8],
        crash: InjectedCrash,
    ) -> Result<MaterializedBundle, SpoolError> {
        let size_bytes = recordable_size(payload)?;
        let spool_entry_id = mint_spool_entry_id()?;
        let bundle_name = format!("{}{BUNDLE_SUFFIX}", spool_entry_id.as_str());
        let staging_path = self
            .dir
            .join(format!("{}{STAGING_SUFFIX}", spool_entry_id.as_str()));

        if let Err(err) = write_and_sync_staging(&staging_path, payload) {
            // A real failure leaves staging debris this call created and
            // no other caller can see; sweep it. A drill failure is
            // process death: nothing runs after it.
            if err.kind() != SpoolErrorKind::CrashInjected {
                let _ = std::fs::remove_file(&staging_path);
            }
            return Err(err);
        }
        if drill_fired_before_rename(crash) {
            return Err(SpoolError::with_detail(
                SpoolErrorKind::CrashInjected,
                "injected crash point reached before the bundle rename",
            ));
        }

        std::fs::rename(&staging_path, self.dir.join(&bundle_name))
            .map_err(|_| unavailable("bundle could not be renamed into place"))?;
        sync_directory(&self.dir).map_err(|_| unavailable(DIR_SYNC_DETAIL))?;
        if drill_fired_after_rename(crash) {
            return Err(SpoolError::with_detail(
                SpoolErrorKind::CrashInjected,
                "injected crash point reached after the bundle rename",
            ));
        }

        let now = now_utc(store.connection())?;
        let envelope_digest = encode_hex(&digest(payload));
        insert_spool_entry(
            store.connection(),
            &spool_entry_id,
            &bundle_name,
            &envelope_digest,
            size_bytes,
            &now,
        )?;
        Ok(MaterializedBundle {
            spool_entry_id,
            bundle_name,
            envelope_digest,
            size_bytes: u64::try_from(size_bytes).unwrap_or(u64::MAX),
        })
    }
}

/// The live spool usage: the summed recorded size of every
/// not-yet-acknowledged entry — exactly the bundles whose bytes are on
/// disk waiting for a receipt. This is the measurement the policy's
/// spool-cap condition ([`pressure`]) applies to: the startup
/// reconciler keeps the `spool_entries` rows and the directory contents
/// in agreement, so the recorded sum is the directory's live bytes.
///
/// Acknowledged entries are excluded: their payload cleanup is the
/// spool's only way to shrink, so bytes already receipted must never
/// count against new capture.
///
/// # Errors
///
/// [`SpoolErrorKind::Unavailable`] or [`SpoolErrorKind::Busy`] when the
/// state database cannot be read.
pub fn live_usage_bytes(store: &StateStore) -> Result<u64, SpoolError> {
    let total: i64 = store
        .connection()
        .query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM spool_entries WHERE state != ?1",
            rusqlite::params![STATE_ACKNOWLEDGED],
            |row| row.get(0),
        )
        .map_err(|ref err| classify_state_operation(err))?;
    u64::try_from(total).map_err(|_| unavailable("live spool usage cannot be represented"))
}

// The static detail texts shared by more than one failure site.
const SCAN_DETAIL: &str = "spool directory could not be scanned";
const REMOVE_DETAIL: &str = "bundle could not be removed";
const DIR_SYNC_DETAIL: &str = "spool directory could not be synchronized";

/// The unavailable class with a specific static detail — the shape of
/// every filesystem failure this module reports.
fn unavailable(detail: &'static str) -> SpoolError {
    SpoolError::with_detail(SpoolErrorKind::Unavailable, detail)
}

/// The drill check before the rename: always `false` outside tests.
#[cfg(test)]
fn drill_fired_before_rename(crash: InjectedCrash) -> bool {
    matches!(crash, InjectedCrash::BeforeRename)
}

#[cfg(not(test))]
fn drill_fired_before_rename(crash: InjectedCrash) -> bool {
    let _ = crash;
    false
}

/// The drill check after the rename: always `false` outside tests.
#[cfg(test)]
fn drill_fired_after_rename(crash: InjectedCrash) -> bool {
    matches!(crash, InjectedCrash::AfterRename)
}

#[cfg(not(test))]
fn drill_fired_after_rename(crash: InjectedCrash) -> bool {
    let _ = crash;
    false
}

/// Create the staging file (mode `0600`, pinned against a permissive
/// umask), write the payload, and synchronize the file — the
/// durability point that must precede the rename.
fn write_and_sync_staging(staging_path: &Path, payload: &[u8]) -> Result<(), SpoolError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(staging_path)
        .map_err(|_| unavailable("bundle staging file could not be created"))?;
    // Pin the mode explicitly so a permissive process umask cannot widen
    // what this process just created: open(2) applies the umask to the
    // `mode` argument.
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|_| unavailable("bundle staging file could not be pinned to mode 0600"))?;
    file.write_all(payload)
        .map_err(|_| unavailable("bundle payload could not be written"))?;
    file.sync_all()
        .map_err(|_| unavailable("bundle payload could not be synchronized"))
}

/// Create the spool directory when absent — mode `0700`, pinned
/// explicitly so a permissive process umask cannot widen it — and
/// refuse anything that pre-exists with other permissions (CFG-023).
fn prepare_directory(dir: &Path) -> Result<(), SpoolError> {
    if !dir.is_dir() {
        DirBuilder::new()
            .recursive(true)
            .create(dir)
            .map_err(|_| SpoolError::of_kind(SpoolErrorKind::UnsafePermissions))?;
        std::fs::set_permissions(dir, Permissions::from_mode(0o700))
            .map_err(|_| SpoolError::of_kind(SpoolErrorKind::UnsafePermissions))?;
    }
    let mode = dir
        .metadata()
        .map_err(|_| SpoolError::of_kind(SpoolErrorKind::UnsafePermissions))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o700 {
        return Err(SpoolError::of_kind(SpoolErrorKind::UnsafePermissions));
    }
    Ok(())
}

/// Synchronize the directory so a completed rename is itself durable.
fn sync_directory(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Whether `name` is a plain bundle file name of this module's shape:
/// the schema's file-name rules plus a parseable spool entry identity
/// and the bundle suffix. Any name outside this shape can never resolve
/// inside the spool directory as a bundle.
fn is_bundle_name(name: &str) -> bool {
    (1..=255).contains(&name.len())
        && !name.contains('/')
        && !name.contains('\\')
        && name
            .strip_suffix(BUNDLE_SUFFIX)
            .is_some_and(|stem| RequestId::parse(stem).is_ok())
}

/// Index one complete orphan bundle: read its content, recompute the
/// digest and size the crashed materialization would have recorded, and
/// commit the `spool_entries` row under the file name's identity.
fn index_orphan(
    path: PathBuf,
    conn: &Connection,
    id: &RequestId,
    name: &str,
    now: &Timestamp,
) -> Result<(), SpoolError> {
    let content =
        std::fs::read(path).map_err(|_| unavailable("bundle content could not be read"))?;
    let size_bytes = recordable_size(&content)?;
    let envelope_digest = encode_hex(&digest(&content));
    insert_spool_entry(conn, id, name, &envelope_digest, size_bytes, now)
}

/// The bundle size as the state schema can record it
/// (`spool_entries.size_bytes` is an `i64`). Unreachable for any
/// in-memory payload on a supported host; refused rather than misrecorded.
fn recordable_size(payload: &[u8]) -> Result<i64, SpoolError> {
    i64::try_from(payload.len())
        .map_err(|_| unavailable("bundle exceeds the size the state schema can record"))
}

/// Mint a spool entry identity: a canonical lowercase `UUIDv7` (plan
/// Section 7.4), time-ordered so a directory listing reads in capture
/// order, from 48 bits of wall-clock milliseconds and 74 bits of host
/// randomness (RFC 9562). Re-validated through the protocol's own
/// grammar so a formatting regression cannot ship.
///
/// # Errors
///
/// [`SpoolErrorKind::Unavailable`] when host randomness cannot be
/// read: a spool entry identity drawn from anything weaker could
/// collide with a concurrent process's bundle name, so materialization
/// refuses rather than guess.
///
/// # Panics
///
/// Never in practice: the minted text is constructed in canonical form
/// and re-validated as a belt-and-braces check.
fn mint_spool_entry_id() -> Result<RequestId, SpoolError> {
    let mut random = [0u8; 10];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|_| unavailable("spool entry identity could not be minted"))?;
    let ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    // UUIDv7 layout: 48-bit unix millisecond timestamp, version 7,
    // 12-bit rand_a, variant `10`, 62 bits of rand_b. Each random byte
    // feeds exactly one field.
    let bytes = [
        ((ms >> 40) & 0xff) as u8,
        ((ms >> 32) & 0xff) as u8,
        ((ms >> 24) & 0xff) as u8,
        ((ms >> 16) & 0xff) as u8,
        ((ms >> 8) & 0xff) as u8,
        (ms & 0xff) as u8,
        0x70 | (random[0] >> 4),
        (random[0] << 4) | (random[1] >> 4),
        0x80 | (random[2] >> 2),
        random[3],
        random[4],
        random[5],
        random[6],
        random[7],
        random[8],
        random[9],
    ];
    let mut text = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        // Writing to a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    Ok(RequestId::parse(&text).expect("the minted identifier is canonical uuid v7"))
}

/// Commit one `spool_entries` row: identity, bundle name, state,
/// digest, size, and timestamps.
fn insert_spool_entry(
    conn: &Connection,
    id: &RequestId,
    bundle_name: &str,
    envelope_digest: &str,
    size_bytes: i64,
    now: &Timestamp,
) -> Result<(), SpoolError> {
    conn.execute(
        "INSERT INTO spool_entries (
             spool_entry_id, bundle_name, state, envelope_digest, size_bytes,
             attempt_count, next_attempt_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?6)",
        rusqlite::params![
            id.as_str(),
            bundle_name,
            STATE_MATERIALIZED,
            envelope_digest,
            size_bytes,
            now.as_str(),
        ],
    )
    .map_err(|ref err| classify_state_operation(err))?;
    Ok(())
}

/// Every spool row: bundle name to entry state. Names are the schema's
/// CHECK-constrained file names; states are its closed set.
fn load_row_states(conn: &Connection) -> Result<HashMap<String, String>, SpoolError> {
    let mut statement = conn
        .prepare("SELECT bundle_name, state FROM spool_entries")
        .map_err(|ref err| classify_state_operation(err))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|ref err| classify_state_operation(err))?
        .collect::<Result<HashMap<_, _>, _>>()
        .map_err(|ref err| classify_state_operation(err))?;
    Ok(rows)
}

/// The RFC 3339 UTC timestamp the state database's own clock provides —
/// the same source the migration history's defaults use, so spool rows
/// and migration rows cannot disagree about what "now" is. Re-validated
/// through the protocol's grammar as a belt-and-braces check.
fn now_utc(conn: &Connection) -> Result<Timestamp, SpoolError> {
    let text: String = conn
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|ref err| classify_state_operation(err))?;
    let parsed = Timestamp::parse(&text)
        .map_err(|_| unavailable("state database returned a malformed timestamp"))?;
    if !parsed.calendar_valid() {
        return Err(unavailable("state database returned a malformed timestamp"));
    }
    Ok(parsed)
}

/// Classify a driver error without keeping any of its text: the busy
/// distinction is the one worth keeping; everything else is the
/// unavailable class. Mirrors the state module's classifier so both
/// surfaces report the same contention signal.
fn classify_state_operation(err: &rusqlite::Error) -> SpoolError {
    let busy = matches!(
        err,
        rusqlite::Error::SqliteFailure(ffi, _)
            if matches!(
                ffi.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    );
    if busy {
        SpoolError::of_kind(SpoolErrorKind::Busy)
    } else {
        SpoolError::of_kind(SpoolErrorKind::Unavailable)
    }
}
