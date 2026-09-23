// SPDX-License-Identifier: Apache-2.0

//! The operator report documents: the read-only `status` and
//! `verify-state` reports, the document composers that pin every CLI
//! result to its `schemas/v1/` wire schema, and the content-free queries
//! behind them (plan Phase 5; requirements CLI-015 and SEC-004).
//!
//! Every figure a command publishes comes from the same state engine the
//! mutator drives, read through [`StateSnapshot`] so a report stays
//! available while the daemon owns the advisory lock (CLI-007). The
//! queries count and classify only: like [`crate::inventory`] and
//! [`crate::state`], a report can never carry a path, a transcript body,
//! or an identifier outside the wire schemas' closed shapes, because no
//! query here selects one. Counters render through the same
//! no-float saturation [`crate::inventory::bounded_i64`] pins.
//!
//! The composers emit the full result document — the
//! `archivist.cli-result/v1` namespace member first, then the schema's
//! closed member set — so a handler's `Ok` value is exactly the document
//! CLI-013 permits on stdout. `inventory` composes
//! [`crate::inventory::InventoryReport`]; the one-cycle `run` document is
//! composed from the reconciliation report, the pressure verdict's own
//! status JSON, and the round's totals.

use std::collections::HashSet;
use std::path::Path;

use archivist_adapter_sdk::status::FreshnessLane;
use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::Timestamp;
use rusqlite::Connection;

use crate::inventory::{InventoryReport, basis_epoch, bounded_i64};
use crate::scheduler::CycleTotals;
use crate::spool::pressure::PressureStatus;
use crate::spool::{BUNDLE_SUFFIX, ReconcileReport, SPOOL_DIR_NAME, STATE_ACKNOWLEDGED};
use crate::state::{IntegrityReport, StateError, StateErrorKind, StateSnapshot};

/// The CLI result namespace (CLI-014): the `schema` member every result
/// document carries, so a consumer always knows which contract it is
/// reading before anything else.
pub const RESULT_NAMESPACE: &str = "archivist.cli-result/v1";

/// The namespace member's JSON value.
fn namespace_member() -> Value {
    Value::Text(RESULT_NAMESPACE.to_owned())
}

/// The `ok`/`degraded` token for a boolean check verdict.
fn verdict_token(ok: bool) -> &'static str {
    if ok { "ok" } else { "degraded" }
}

/// A count the driver reported, widened to the saturating counter domain.
/// The schema's `CHECK` constraints keep every counted column
/// non-negative, so only a `u63` overflow saturates.
fn counted(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// The content-free read failure a report query classifies into. Like
/// [`crate::inventory`], the driver's own text — which can embed a path —
/// is dropped at the boundary.
fn read_failed() -> StateError {
    StateError::with_detail(
        StateErrorKind::Unavailable,
        "report could not read the state database",
    )
}

/// A stored value outside the pinned vocabulary: schema corruption seen
/// from the read side, the same backstop [`crate::inventory`] keeps.
fn corrupted(subject: &'static str) -> StateError {
    StateError::of_kind(StateErrorKind::SchemaCorruption).about(subject)
}

/// The `status` report: the read-only snapshot's state verdict, per-source
/// counts by scheduling lane, the live spool size, and the freshest
/// acknowledged capture instant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReport {
    /// The instant the snapshot was read.
    pub generated_at: Timestamp,
    /// The applied schema migration version; 0 before any migration.
    pub schema_version: i64,
    /// The automated integrity checks' combined verdict.
    pub integrity_ok: bool,
    /// Sources the state knows.
    pub enrolled_sources: u64,
    /// Sources on the freshness lane.
    pub freshness_sources: u64,
    /// Sources on the backfill lane.
    pub backfill_sources: u64,
    /// Bytes of not-yet-acknowledged spool bundles the state database
    /// records.
    pub live_spool_bytes: u64,
    /// The freshest acknowledged capture instant, as the stored RFC 3339
    /// UTC text; `None` when nothing has been captured yet.
    pub last_capture_at: Option<String>,
}

impl StatusReport {
    /// The full `status` result document, pinned by
    /// `schemas/v1/cli-status.json`.
    #[must_use]
    pub fn to_document(&self) -> Value {
        let mut document = Object::new();
        document.set("schema", namespace_member());
        document.set(
            "generated_at",
            Value::Text(self.generated_at.as_str().to_owned()),
        );
        let mut state = Object::new();
        state.set("schema_version", Value::Int(self.schema_version));
        state.set(
            "integrity",
            Value::Text(verdict_token(self.integrity_ok).to_owned()),
        );
        document.set("state", Value::Object(state));
        let mut sources = Object::new();
        sources.set("enrolled", Value::Int(bounded_i64(self.enrolled_sources)));
        sources.set("freshness", Value::Int(bounded_i64(self.freshness_sources)));
        sources.set("backfill", Value::Int(bounded_i64(self.backfill_sources)));
        document.set("sources", Value::Object(sources));
        let mut spool = Object::new();
        spool.set("live_bytes", Value::Int(bounded_i64(self.live_spool_bytes)));
        document.set("spool", Value::Object(spool));
        document.set(
            "last_capture_at",
            match &self.last_capture_at {
                Some(text) => Value::Text(text.clone()),
                None => Value::Null,
            },
        );
        Value::Object(document)
    }
}

/// Read one `status` report from a read-only snapshot. The snapshot's
/// integrity verdict and schema version are the state layer's own
/// checks; the counts come from the migrated schema's tables.
///
/// # Errors
/// [`StateErrorKind::Unavailable`] when a read fails, and
/// [`StateErrorKind::SchemaCorruption`] when a stored lane token is
/// outside the closed vocabulary — the read-side backstop.
pub fn status_report(
    snapshot: &StateSnapshot,
    now: &Timestamp,
) -> Result<StatusReport, StateError> {
    let conn = snapshot.connection();
    let enrolled_sources = counted(
        conn.query_row("SELECT COUNT(*) FROM sources", [], |row| row.get(0))
            .map_err(|_| read_failed())?,
    );
    let (freshness_sources, backfill_sources) = lane_counts(conn)?;
    let live_spool_bytes = live_spool_bytes(conn)?;
    let last_capture_at = last_capture(conn)?;
    let schema_version = snapshot.schema_version()?;
    let integrity_ok = snapshot.integrity()?.healthy();
    Ok(StatusReport {
        generated_at: now.clone(),
        schema_version,
        integrity_ok,
        enrolled_sources,
        freshness_sources,
        backfill_sources,
        live_spool_bytes,
        last_capture_at,
    })
}

/// Per-lane source counts: every stored lane token must parse, or the
/// database is outside the vocabulary the schema pins.
fn lane_counts(conn: &Connection) -> Result<(u64, u64), StateError> {
    let mut statement = conn
        .prepare("SELECT freshness_lane, COUNT(*) FROM sources GROUP BY freshness_lane")
        .map_err(|_| read_failed())?;
    let mut rows = statement.query([]).map_err(|_| read_failed())?;
    let mut freshness = 0u64;
    let mut backfill = 0u64;
    while let Some(row) = rows.next().map_err(|_| read_failed())? {
        let lane: String = row.get(0).map_err(|_| read_failed())?;
        let count = counted(row.get::<_, i64>(1).map_err(|_| read_failed())?);
        match FreshnessLane::parse(&lane) {
            Ok(FreshnessLane::Freshness) => freshness += count,
            Ok(FreshnessLane::Backfill) => backfill += count,
            Err(_) => return Err(corrupted("sources.freshness_lane")),
        }
    }
    Ok((freshness, backfill))
}

/// The live spool byte sum: every row not yet acknowledged, the same
/// population [`crate::spool::live_usage_bytes`] and the pressure gate
/// measure — read here through a snapshot connection instead of a
/// [`crate::spool::Spool`], which would create the spool directory a
/// read-only command must not create.
fn live_spool_bytes(conn: &Connection) -> Result<u64, StateError> {
    conn.query_row(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM spool_entries WHERE state <> ?1",
        rusqlite::params![STATE_ACKNOWLEDGED],
        |row| row.get::<_, i64>(0),
    )
    .map(|sum| counted(sum))
    .map_err(|_| read_failed())
}

/// The freshest capture instant a committed receipt acknowledges: every
/// receipt's frozen request carries the instant its bundle was captured,
/// and a receipt exists only after the acknowledgement transaction
/// committed (plan Section 7.9). Folded in Rust rather than `MAX`-ed in
/// SQL because stored timestamps vary in fractional precision and a
/// lexicographic maximum would order them wrong.
fn last_capture(conn: &Connection) -> Result<Option<String>, StateError> {
    let mut statement = conn
        .prepare(
            "SELECT fr.captured_at FROM receipts rc
             JOIN frozen_requests fr ON fr.request_id = rc.request_id",
        )
        .map_err(|_| read_failed())?;
    let mut rows = statement.query([]).map_err(|_| read_failed())?;
    let mut freshest: Option<(u64, String)> = None;
    while let Some(row) = rows.next().map_err(|_| read_failed())? {
        let text: String = row.get(0).map_err(|_| read_failed())?;
        if let Some(epoch) = basis_epoch(&text) {
            let newer = match &freshest {
                Some((current, _)) => epoch > *current,
                None => true,
            };
            if newer {
                freshest = Some((epoch, text));
            }
        }
    }
    Ok(freshest.map(|(_, text)| text))
}

/// The `verify-state` report: the state layer's automated checks plus the
/// spool-level correspondence a read-only pass can establish — every live
/// row's bundle on disk, complete bundle files with no row, and the
/// receipt chain every acknowledged entry must have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationReport {
    /// The instant the verification ran.
    pub generated_at: Timestamp,
    /// The state layer's automated integrity checks.
    pub integrity: IntegrityReport,
    /// Every not-yet-acknowledged spool row's bundle file is on disk.
    pub live_bundles_present: bool,
    /// Every acknowledged spool entry has a committed receipt through its
    /// frozen request.
    pub acknowledged_receipted: bool,
    /// Live (not yet acknowledged) rows whose bundle file is missing:
    /// corruption, never repaired by a reader.
    pub live_rows_missing_bundles: u64,
    /// Complete bundle files with no spool row: crash debris the next
    /// mutator's reconciliation pass indexes. Expected after a crash;
    /// never corruption.
    pub orphan_bundle_files: u64,
    /// Acknowledged entries whose frozen request has no receipt row.
    pub acknowledged_entries_without_receipts: u64,
}

impl VerificationReport {
    /// The overall verdict: degraded when any named check failed.
    /// Orphan bundle files are evidence, not a failing check.
    #[must_use]
    pub fn verdict_ok(&self) -> bool {
        self.integrity.healthy() && self.live_bundles_present && self.acknowledged_receipted
    }

    /// The full `verify-state` result document, pinned by
    /// `schemas/v1/cli-verify-state.json`.
    #[must_use]
    pub fn to_document(&self) -> Value {
        let mut document = Object::new();
        document.set("schema", namespace_member());
        document.set(
            "generated_at",
            Value::Text(self.generated_at.as_str().to_owned()),
        );
        document.set(
            "verdict",
            Value::Text(verdict_token(self.verdict_ok()).to_owned()),
        );
        let mut checks = Object::new();
        checks.set(
            "sqlite_integrity",
            Value::Text(verdict_token(self.integrity.integrity_ok).to_owned()),
        );
        checks.set(
            "foreign_keys",
            Value::Text(verdict_token(self.integrity.foreign_keys_ok).to_owned()),
        );
        checks.set(
            "schema_objects",
            Value::Text(verdict_token(self.integrity.schema_objects_ok).to_owned()),
        );
        checks.set(
            "live_bundles_present",
            Value::Text(verdict_token(self.live_bundles_present).to_owned()),
        );
        checks.set(
            "acknowledged_receipted",
            Value::Text(verdict_token(self.acknowledged_receipted).to_owned()),
        );
        document.set("checks", Value::Object(checks));
        let mut counts = Object::new();
        counts.set(
            "live_rows_missing_bundles",
            Value::Int(bounded_i64(self.live_rows_missing_bundles)),
        );
        counts.set(
            "orphan_bundle_files",
            Value::Int(bounded_i64(self.orphan_bundle_files)),
        );
        counts.set(
            "acknowledged_entries_without_receipts",
            Value::Int(bounded_i64(self.acknowledged_entries_without_receipts)),
        );
        document.set("counts", Value::Object(counts));
        Value::Object(document)
    }
}

/// Verify one state directory read-only. The snapshot supplies the
/// database and its integrity verdict; `state_dir` locates the spool
/// directory the bundle checks walk. Nothing is created, removed, or
/// repaired: the document is the evidence, and reconciliation remains the
/// mutator's act.
///
/// # Errors
/// [`StateErrorKind::Unavailable`] when a read fails.
pub fn verification_report(
    snapshot: &StateSnapshot,
    state_dir: &Path,
    now: &Timestamp,
) -> Result<VerificationReport, StateError> {
    let integrity = snapshot.integrity()?;
    let conn = snapshot.connection();
    let spool_dir = state_dir.join(SPOOL_DIR_NAME);

    // Every live row's bundle must be on disk. The acknowledged rows are
    // deliberately absent from this population: a mutator removes their
    // bundle files after the acknowledgement transaction commits.
    let mut live_rows_missing_bundles = 0u64;
    {
        let mut statement = conn
            .prepare("SELECT bundle_name FROM spool_entries WHERE state <> ?1")
            .map_err(|_| read_failed())?;
        let mut rows = statement
            .query(rusqlite::params![STATE_ACKNOWLEDGED])
            .map_err(|_| read_failed())?;
        while let Some(row) = rows.next().map_err(|_| read_failed())? {
            let bundle_name: String = row.get(0).map_err(|_| read_failed())?;
            if !spool_dir.join(&bundle_name).exists() {
                live_rows_missing_bundles += 1;
            }
        }
    }

    // Orphan files: complete bundle files on disk with no row of any
    // state. Counted as evidence for the next reconciliation pass; never
    // a failing check.
    let mut known_bundle_names = HashSet::new();
    {
        let mut statement = conn
            .prepare("SELECT bundle_name FROM spool_entries")
            .map_err(|_| read_failed())?;
        let mut rows = statement.query([]).map_err(|_| read_failed())?;
        while let Some(row) = rows.next().map_err(|_| read_failed())? {
            let bundle_name: String = row.get(0).map_err(|_| read_failed())?;
            known_bundle_names.insert(bundle_name);
        }
    }
    let orphan_bundle_files = orphan_bundle_files(&spool_dir, &known_bundle_names);

    // The receipt chain: cleanup never runs ahead of the receipt
    // transaction, so an acknowledged entry without a receipt through its
    // frozen request is a broken invariant.
    let acknowledged_entries_without_receipts = counted(
        conn.query_row(
            "SELECT COUNT(*) FROM spool_entries se
             WHERE se.state = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM frozen_requests fr
                   JOIN receipts rc ON rc.request_id = fr.request_id
                   WHERE fr.spool_entry_id = se.spool_entry_id
               )",
            rusqlite::params![STATE_ACKNOWLEDGED],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| read_failed())?,
    );

    Ok(VerificationReport {
        generated_at: now.clone(),
        integrity,
        live_bundles_present: live_rows_missing_bundles == 0,
        acknowledged_receipted: acknowledged_entries_without_receipts == 0,
        live_rows_missing_bundles,
        orphan_bundle_files,
        acknowledged_entries_without_receipts,
    })
}

/// Count the spool directory's bundle files that no row names. A directory
/// that does not exist yet holds nothing; staging files are interrupted
/// materializations a reconciliation pass removes, not bundles, and
/// non-UTF-8 or unstatable entries are not canonical bundle names.
fn orphan_bundle_files(spool_dir: &Path, known: &HashSet<String>) -> u64 {
    let entries = match std::fs::read_dir(spool_dir) {
        Ok(entries) => entries,
        Err(_) => return 0,
    };
    let mut orphans = 0u64;
    for entry in entries.flatten() {
        let is_file = entry.file_type().map_or(false, |kind| kind.is_file());
        if !is_file {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if name.ends_with(BUNDLE_SUFFIX) && !known.contains(name) {
            orphans += 1;
        }
    }
    orphans
}

/// Compose the `inventory` result document from an inventory pass's
/// report, pinned by `schemas/v1/cli-inventory.json`.
#[must_use]
pub fn inventory_document(report: &InventoryReport) -> Value {
    let mut document = Object::new();
    document.set("schema", namespace_member());
    if let Value::Object(members) = report.to_json() {
        for (name, value) in members.iter() {
            document.set(name, value.clone());
        }
    }
    Value::Object(document)
}

/// Compose the one-cycle `run` result document — the startup
/// reconciliation report, the pressure verdict, and the round's planned
/// arithmetic — pinned by `schemas/v1/cli-run.json`.
#[must_use]
pub fn cycle_document(
    reconcile: &ReconcileReport,
    pressure: &PressureStatus,
    totals: &CycleTotals,
    now: &Timestamp,
) -> Value {
    let mut document = Object::new();
    document.set("schema", namespace_member());
    document.set("generated_at", Value::Text(now.as_str().to_owned()));
    let mut reconcile_object = Object::new();
    reconcile_object.set(
        "orphan_bundles_indexed",
        Value::Int(bounded_i64(reconcile.orphan_bundles_indexed)),
    );
    reconcile_object.set(
        "acknowledged_bundles_removed",
        Value::Int(bounded_i64(reconcile.acknowledged_bundles_removed)),
    );
    reconcile_object.set(
        "staging_files_removed",
        Value::Int(bounded_i64(reconcile.staging_files_removed)),
    );
    reconcile_object.set(
        "unclassified_entries",
        Value::Int(bounded_i64(reconcile.unclassified_entries)),
    );
    reconcile_object.set(
        "spool_rows_missing_bundles",
        Value::Int(bounded_i64(reconcile.spool_rows_missing_bundles)),
    );
    document.set("reconcile", Value::Object(reconcile_object));
    // The pressure verdict's own status JSON is exactly the wire shape the
    // schema pins; it is rendered as-is.
    document.set("pressure", pressure.to_json());
    document.set("plan", totals_document(totals));
    Value::Object(document)
}

/// The round's arithmetic as the `plan` object: the thirteen counters the
/// schema pins, no more.
fn totals_document(totals: &CycleTotals) -> Value {
    let mut plan = Object::new();
    plan.set(
        "capacity_bytes",
        Value::Int(bounded_i64(totals.capacity_bytes)),
    );
    plan.set(
        "drain_entries",
        Value::Int(bounded_i64(totals.drain_entries)),
    );
    plan.set("drain_bytes", Value::Int(bounded_i64(totals.drain_bytes)));
    plan.set(
        "eligible_sources",
        Value::Int(bounded_i64(totals.eligible_sources)),
    );
    plan.set(
        "reserved_sources",
        Value::Int(bounded_i64(totals.reserved_sources)),
    );
    plan.set(
        "reserved_bytes",
        Value::Int(bounded_i64(totals.reserved_bytes)),
    );
    plan.set(
        "reserved_chunks",
        Value::Int(bounded_i64(totals.reserved_chunks)),
    );
    plan.set(
        "backfilled_sources",
        Value::Int(bounded_i64(totals.backfilled_sources)),
    );
    plan.set(
        "backfill_bytes",
        Value::Int(bounded_i64(totals.backfill_bytes)),
    );
    plan.set(
        "backfill_chunks",
        Value::Int(bounded_i64(totals.backfill_chunks)),
    );
    plan.set(
        "planned_bytes",
        Value::Int(bounded_i64(totals.planned_bytes)),
    );
    plan.set(
        "short_reservations",
        Value::Int(bounded_i64(totals.short_reservations)),
    );
    plan.set(
        "deferred_sources",
        Value::Int(bounded_i64(totals.deferred_sources)),
    );
    Value::Object(plan)
}

#[cfg(test)]
mod tests;
