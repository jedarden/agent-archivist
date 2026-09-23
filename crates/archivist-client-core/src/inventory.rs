// SPDX-License-Identifier: Apache-2.0

//! The source backlog inventory: one read-only pass that measures the
//! complete outstanding bytes and events per source, keeps every cursor
//! retained in front of its uncaptured range, and exposes the result as
//! bounded adapter/account status (plan Section 6 client data flow step 2;
//! requirements CAP-010 and SCH-002).
//!
//! The engine joins two content-free evidence sources:
//!
//! - **Adapter scans** ([`SourceScan`], from
//!   `archivist_adapter_sdk::status`): what one read-only pass observed
//!   about a source, measured through the last complete record boundary.
//! - **Client state** (the `sources`, `generations`, and `ranges` tables of
//!   [`crate::state`]): what capture has already acknowledged, and where
//!   each source's cursor was retained.
//!
//! and produces both the per-source detail the scheduler consumes
//! ([`SourceInventory`]) and the bounded per-scope status an operator or
//! the CLI consumes ([`AdapterAccountStatus`], aggregated into an
//! [`InventoryReport`]). The status layer never carries per-source detail:
//! its size is independent of how many sources, sessions, or bytes an
//! account holds, and no field can carry a path or transcript content —
//! the same redaction rule the state schema enforces at the database level.
//!
//! # Definitions the arithmetic implements
//!
//! - **Complete boundary.** A scan's `complete_bytes`/`complete_events`
//!   cover only data through the last complete record. The trailing
//!   partial write is measured as `incomplete_tail_bytes` and is never
//!   part of any backlog figure or cursor decision (plan `EC-01`).
//! - **Outstanding backlog.** The complete extent the state has not
//!   acknowledged for the source's current generation, saturating at zero.
//!   A generation that was closed by truncation or replacement contributes
//!   no backlog: its unread remainder stopped existing with the artifact
//!   (plan `EC-02` preserves both histories; it does not resurrect the old
//!   one as work).
//! - **Freshness lag.** For a source with outstanding data, the age of the
//!   last acknowledged capture progress — or, for a source the state has
//!   not enrolled yet, the age of the scan's observed activity. A caught-up
//!   source reports zero. This is the bounded, clock-skew-tolerant stand-in
//!   for "how far behind is capture" that the freshness lane's two-interval
//!   target (plan Section 2, scenario 1) is checked against.
//! - **Cursor retention.** The cursor is the acknowledged position, and
//!   the uncaptured range always starts exactly there — capture never
//!   moves a cursor past data it has not durably acknowledged, and under
//!   [`InventoryOptions::degraded`] (spool high-water or free-disk floor,
//!   plan `EC-11`) it does not move at all while the backlog stays visible
//!   in status.

use std::collections::HashMap;

use archivist_adapter_sdk::status::{
    AccountLabel, AdapterAccountStatus, ClassificationCounts, CoverageCounts, CoverageState,
    FreshnessLane, ScanClassification, SourceId, SourceScan,
};
use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{AdapterId, Timestamp};
use rusqlite::Connection;

use crate::state::{StateError, StateErrorKind};

/// Inventory-pass options: the capture-side conditions the measurement
/// must respect when it proposes cursor movement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InventoryOptions {
    /// Capture is degraded — the spool reached its high-water mark or the
    /// filesystem fell below its free-space floor (plan `EC-11`). The
    /// cursor is retained in front of the uncaptured range and nothing is
    /// proposed for capture, while the backlog stays fully visible in
    /// status.
    pub degraded: bool,
}

/// Where capture stands on one source: the acknowledged position, and the
/// uncaptured range the cursor is retained in front of.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CursorPosition {
    /// Acknowledged bytes: the last complete boundary a verified receipt
    /// covers.
    pub retained_bytes: u64,
    /// Acknowledged complete records (events).
    pub retained_events: u64,
    /// Complete bytes past the retained position: the uncaptured byte
    /// range starts exactly here.
    pub uncaptured_bytes: u64,
    /// Complete records (events) past the retained position.
    pub uncaptured_events: u64,
}

impl CursorPosition {
    /// Whether an uncaptured range exists in front of the cursor.
    #[must_use]
    pub fn has_uncaptured(&self) -> bool {
        self.uncaptured_bytes > 0 || self.uncaptured_events > 0
    }
}

/// The cursor movement one inventory pass supports for a source. A decision
/// never moves a cursor backwards and never past the last complete boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorDecision {
    /// Keep the cursor where it is: either capture is degraded (plan
    /// `EC-11`) or no new complete data exists. The uncaptured range, if
    /// any, stays in front of the cursor and visible in status.
    Hold,
    /// Move the cursor to the last complete boundary of this pass. The
    /// pending tail is excluded: an incomplete trailing record never
    /// advances anything (plan `EC-01`).
    Advance {
        /// The new retained byte position.
        bytes: u64,
        /// The new retained event position.
        events: u64,
    },
}

/// Decide the cursor movement for one source: forward to the last complete
/// boundary when capture is healthy and new complete data exists, held —
/// retained in front of the uncaptured range — when degraded or when
/// nothing new is complete. Each axis moves independently and neither ever
/// moves backwards.
#[must_use]
pub fn cursor_retention(
    retained_bytes: u64,
    retained_events: u64,
    complete_bytes: u64,
    complete_events: u64,
    degraded: bool,
) -> CursorDecision {
    if degraded || (complete_bytes <= retained_bytes && complete_events <= retained_events) {
        return CursorDecision::Hold;
    }
    CursorDecision::Advance {
        bytes: complete_bytes.max(retained_bytes),
        events: complete_events.max(retained_events),
    }
}

/// A coverage contradiction the inventory refuses to silently absorb:
/// acknowledged state runs ahead of what the current scan can measure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageAnomaly {
    /// The state acknowledges more than the source's current complete
    /// boundary. Either the source shrank without the generation rollover
    /// of plan `EC-02`, or the acknowledged ranges no longer describe this
    /// artifact. The source is reported failed until reconciled.
    AcknowledgedBeyondComplete,
}

/// The per-source inventory record: the full measurement and cursor state
/// the scheduler consumes. Unlike the status layer, this is allowed to be
/// per-source — but every field is still an integer, a closed-vocabulary
/// token, or a derived identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceInventory {
    /// The source this record measures.
    pub source: SourceId,
    /// The adapter whose pass observed it.
    pub adapter: AdapterId,
    /// The configured account label it was discovered under.
    pub account: AccountLabel,
    /// The scheduling lane its outstanding data counts toward: the state's
    /// lane for enrolled sources, activity for new ones.
    pub lane: FreshnessLane,
    /// The coverage state this source reports.
    pub coverage: CoverageState,
    /// The last classification: how this pass (or, for unenrolled sources,
    /// the lack of one) ended.
    pub classification: ScanClassification,
    /// Complete bytes through the last complete record boundary.
    pub complete_bytes: u64,
    /// Complete records (events) through the last complete boundary.
    pub complete_events: u64,
    /// Acknowledged bytes on the current generation.
    pub acknowledged_bytes: u64,
    /// Acknowledged events on the current generation.
    pub acknowledged_events: u64,
    /// Outstanding (unacknowledged) complete bytes: the backlog.
    pub outstanding_bytes: u64,
    /// Outstanding (unacknowledged) complete events.
    pub outstanding_events: u64,
    /// Trailing partial bytes, measured but never captured until complete.
    pub incomplete_tail_bytes: u64,
    /// The freshness lag in seconds; zero when caught up or when no time
    /// basis exists.
    pub freshness_lag_seconds: u64,
    /// The retained cursor and the uncaptured range in front of it.
    pub cursor: CursorPosition,
    /// The cursor movement this pass supports: forward to the last
    /// complete boundary when healthy, held in front of the uncaptured
    /// range when degraded (plan `EC-11`) or when nothing new is complete.
    pub decision: CursorDecision,
    /// A coverage contradiction that needs reconciliation, if any.
    pub anomaly: Option<CoverageAnomaly>,
    /// Whether the client state knows this source.
    pub enrolled: bool,
}

/// Fleet-level totals across every scope in one report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InventoryTotals {
    /// Outstanding bytes on freshness-lane sources.
    pub active_backlog_bytes: u64,
    /// Outstanding events on freshness-lane sources.
    pub active_backlog_events: u64,
    /// Outstanding bytes on backfill-lane sources.
    pub historical_backlog_bytes: u64,
    /// Outstanding events on backfill-lane sources.
    pub historical_backlog_events: u64,
    /// Per-state source counts across the scopes of this report.
    pub sources: CoverageCounts,
}

impl InventoryTotals {
    /// The report-JSON object for the totals.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set(
            "active_backlog_bytes",
            Value::Int(bounded_i64(self.active_backlog_bytes)),
        );
        object.set(
            "active_backlog_events",
            Value::Int(bounded_i64(self.active_backlog_events)),
        );
        object.set(
            "historical_backlog_bytes",
            Value::Int(bounded_i64(self.historical_backlog_bytes)),
        );
        object.set(
            "historical_backlog_events",
            Value::Int(bounded_i64(self.historical_backlog_events)),
        );
        object.set("sources", self.sources.to_json());
        Value::Object(object)
    }
}

/// The complete result of one inventory pass: bounded statuses per
/// adapter/account scope, fleet totals, and the overall coverage state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryReport {
    /// The pass timestamp the lag arithmetic ran against.
    pub generated_at: Timestamp,
    /// The overall coverage state: the scopes' states aggregated, and
    /// partial while any state-known source went unmeasured.
    pub overall: CoverageState,
    /// Fleet-level totals.
    pub totals: InventoryTotals,
    /// One bounded status per observed `(adapter, account)` scope, in
    /// first-seen scan order.
    pub statuses: Vec<AdapterAccountStatus>,
    /// State-known sources no scan covered: their backlog is unmeasured,
    /// so the report counts them instead of guessing.
    pub sources_without_scan: u64,
}

impl InventoryReport {
    /// The report-JSON value: bounded statuses and totals only — no
    /// per-source detail, no identifiers beyond scope labels, no free text.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set(
            "generated_at",
            Value::Text(self.generated_at.as_str().to_owned()),
        );
        object.set("overall", Value::Text(self.overall.token().to_owned()));
        object.set(
            "sources_without_scan",
            Value::Int(bounded_i64(self.sources_without_scan)),
        );
        let statuses = self
            .statuses
            .iter()
            .map(AdapterAccountStatus::to_json)
            .collect::<Vec<_>>();
        object.set("statuses", Value::Array(statuses));
        object.set("totals", self.totals.to_json());
        Value::Object(object)
    }
}

/// The acknowledged-state context one inventory pass measures against,
/// loaded once and shared by every per-source measurement and by the
/// unmeasured-source count: the enrolled sources, each source's current
/// generation, the acknowledged extents on every generation, and the
/// freshest acknowledged capture instant per source.
struct PassContext {
    sources: HashMap<String, SourceRow>,
    current_generation: HashMap<String, String>,
    acknowledged_by_generation: HashMap<String, (u64, u64)>,
    last_captured: HashMap<String, String>,
}

impl PassContext {
    /// Load the whole context in four reads.
    ///
    /// # Errors
    /// Propagates the loaders' [`StateError`]: `Unavailable` for a failed
    /// read, `SchemaCorruption` for a stored value outside the pinned
    /// vocabulary.
    fn load(conn: &Connection) -> Result<Self, StateError> {
        Ok(Self {
            sources: load_sources(conn)?,
            current_generation: current_generation_by_source(conn)?,
            acknowledged_by_generation: acknowledged_by_generation(conn)?,
            last_captured: last_captured_by_source(conn)?,
        })
    }

    /// Measure every scan against the loaded context. Acknowledged
    /// extents come from the source's current generation only: a prior
    /// generation closed by truncation or replacement describes an
    /// artifact that no longer exists, and its extents must not offset
    /// the current one's backlog.
    fn measure(
        &self,
        scans: &[SourceScan],
        now: &Timestamp,
        degraded: bool,
    ) -> Vec<SourceInventory> {
        let now_epoch = epoch_seconds(now);
        scans
            .iter()
            .map(|scan| {
                let acknowledged = self
                    .current_generation
                    .get(scan.source.as_str())
                    .and_then(|generation| self.acknowledged_by_generation.get(generation))
                    .copied()
                    .unwrap_or((0, 0));
                measure(
                    scan,
                    self.sources.get(scan.source.as_str()),
                    acknowledged,
                    self.last_captured
                        .get(scan.source.as_str())
                        .and_then(|text| basis_epoch(text)),
                    now_epoch,
                    degraded,
                )
            })
            .collect()
    }
}

/// Measure every scan against the acknowledged state: the per-source
/// records the scheduling cycle plans over — the inventory-pass step the
/// daemon cycle's own contract names ([`crate::scheduler`]) — each one the
/// same measurement the report aggregation folds.
///
/// # Errors
/// [`StateError`] with [`StateErrorKind::Unavailable`] when the state
/// database cannot be read, or [`StateErrorKind::SchemaCorruption`] when a
/// stored value is outside the vocabulary the schema pins — a read-side
/// backstop matching the write-side `CHECK` constraints. Errors carry no
/// runtime text.
pub fn measured_sources(
    conn: &Connection,
    scans: &[SourceScan],
    now: &Timestamp,
    options: &InventoryOptions,
) -> Result<Vec<SourceInventory>, StateError> {
    Ok(PassContext::load(conn)?.measure(scans, now, options.degraded))
}

/// Run one inventory pass: read the acknowledged state, fold in the
/// adapter scans, and produce the report.
///
/// # Errors
/// [`StateError`] with [`StateErrorKind::Unavailable`] when the state
/// database cannot be read, or [`StateErrorKind::SchemaCorruption`] when a
/// stored value is outside the vocabulary the schema pins — a read-side
/// backstop matching the write-side `CHECK` constraints. Errors carry no
/// runtime text.
pub fn inventory(
    conn: &Connection,
    scans: &[SourceScan],
    now: &Timestamp,
    options: &InventoryOptions,
) -> Result<InventoryReport, StateError> {
    let context = PassContext::load(conn)?;
    let per_source = context.measure(scans, now, options.degraded);
    let sources = context.sources;

    // Aggregate into bounded per-scope statuses, in first-seen scan order.
    let mut scopes: Vec<((String, String), AdapterAccountStatus)> = Vec::new();
    let mut scope_index: HashMap<(String, String), usize> = HashMap::new();
    for record in &per_source {
        let key = (
            record.adapter.as_str().to_owned(),
            record.account.as_str().to_owned(),
        );
        let index = *scope_index.entry(key.clone()).or_insert_with(|| {
            scopes.push((
                key,
                AdapterAccountStatus {
                    adapter: record.adapter.clone(),
                    account: record.account.clone(),
                    coverage: CoverageState::Absent,
                    active_backlog_bytes: 0,
                    active_backlog_events: 0,
                    historical_backlog_bytes: 0,
                    historical_backlog_events: 0,
                    max_freshness_lag_seconds: 0,
                    sources: CoverageCounts::default(),
                    classifications: ClassificationCounts::default(),
                },
            ));
            scopes.len() - 1
        });
        fold_into_status(&mut scopes[index].1, record);
    }

    // State-known sources no scan covered: counted, never guessed.
    let scanned: std::collections::HashSet<&str> =
        scans.iter().map(|scan| scan.source.as_str()).collect();
    let sources_without_scan = sources
        .keys()
        .filter(|source| !scanned.contains(source.as_str()))
        .count();
    let sources_without_scan = u64::try_from(sources_without_scan).unwrap_or(u64::MAX);

    // Fleet totals and the overall state.
    let mut totals = InventoryTotals::default();
    let mut overall = CoverageState::Absent;
    for record in &per_source {
        totals.sources.record(record.coverage);
        match record.lane {
            FreshnessLane::Freshness => {
                totals.active_backlog_bytes += record.outstanding_bytes;
                totals.active_backlog_events += record.outstanding_events;
            }
            FreshnessLane::Backfill => {
                totals.historical_backlog_bytes += record.outstanding_bytes;
                totals.historical_backlog_events += record.outstanding_events;
            }
        }
        overall = overall.combine(record.coverage);
    }
    if sources_without_scan > 0 {
        // The report cannot claim full coverage while known sources are
        // unmeasured.
        overall = overall.combine(CoverageState::Partial);
    }

    let statuses = scopes.into_iter().map(|(_, status)| status).collect();
    Ok(InventoryReport {
        generated_at: now.clone(),
        overall,
        totals,
        statuses,
        sources_without_scan,
    })
}

/// Measure one scanned source against its state, if any.
fn measure(
    scan: &SourceScan,
    state: Option<&SourceRow>,
    acknowledged: (u64, u64),
    last_captured: Option<u64>,
    now_epoch: Option<u64>,
    degraded: bool,
) -> SourceInventory {
    let lane = state.map_or_else(
        || {
            if scan.active_in_window {
                FreshnessLane::Freshness
            } else {
                FreshnessLane::Backfill
            }
        },
        |row: &SourceRow| row.lane,
    );
    let anomaly = (acknowledged.0 > scan.complete_bytes || acknowledged.1 > scan.complete_events)
        .then_some(CoverageAnomaly::AcknowledgedBeyondComplete);
    let outstanding_bytes = scan.complete_bytes.saturating_sub(acknowledged.0);
    let outstanding_events = scan.complete_events.saturating_sub(acknowledged.1);
    let coverage = anomaly.map_or_else(
        || {
            scan.classification.forced_coverage().unwrap_or_else(|| {
                if outstanding_bytes > 0 || outstanding_events > 0 {
                    CoverageState::Partial
                } else if lane == FreshnessLane::Backfill {
                    CoverageState::FullyBackfilled
                } else {
                    CoverageState::Current
                }
            })
        },
        |_| CoverageState::Failed,
    );
    // Freshness lag: the age of the last acknowledged progress (or of the
    // observed activity for a source state has not enrolled), for sources
    // that still have outstanding data. No basis, no claim: zero.
    let basis = last_captured
        .or_else(|| state.and_then(|row| basis_epoch(&row.created_at)))
        .or_else(|| scan.last_activity.as_ref().and_then(epoch_seconds));
    let freshness_lag_seconds = match (
        outstanding_bytes > 0 || outstanding_events > 0,
        basis,
        now_epoch,
    ) {
        (true, Some(basis), Some(now)) => now.saturating_sub(basis),
        _ => 0,
    };
    SourceInventory {
        source: scan.source.clone(),
        adapter: scan.adapter.clone(),
        account: scan.account.clone(),
        lane,
        coverage,
        classification: scan.classification,
        complete_bytes: scan.complete_bytes,
        complete_events: scan.complete_events,
        acknowledged_bytes: acknowledged.0,
        acknowledged_events: acknowledged.1,
        outstanding_bytes,
        outstanding_events,
        incomplete_tail_bytes: scan.incomplete_tail_bytes,
        freshness_lag_seconds,
        cursor: CursorPosition {
            retained_bytes: acknowledged.0,
            retained_events: acknowledged.1,
            uncaptured_bytes: outstanding_bytes,
            uncaptured_events: outstanding_events,
        },
        decision: cursor_retention(
            acknowledged.0,
            acknowledged.1,
            scan.complete_bytes,
            scan.complete_events,
            degraded,
        ),
        anomaly,
        enrolled: state.is_some(),
    }
}

/// Fold one measured source into its scope's bounded status.
fn fold_into_status(status: &mut AdapterAccountStatus, record: &SourceInventory) {
    status.coverage = status.coverage.combine(record.coverage);
    status.sources.record(record.coverage);
    status.classifications.record(record.classification);
    match record.lane {
        FreshnessLane::Freshness => {
            status.active_backlog_bytes += record.outstanding_bytes;
            status.active_backlog_events += record.outstanding_events;
        }
        FreshnessLane::Backfill => {
            status.historical_backlog_bytes += record.outstanding_bytes;
            status.historical_backlog_events += record.outstanding_events;
        }
    }
    status.max_freshness_lag_seconds = status
        .max_freshness_lag_seconds
        .max(record.freshness_lag_seconds);
}

struct SourceRow {
    lane: FreshnessLane,
    created_at: String,
}

/// Load every state-known source. A stored lane outside the pinned
/// vocabulary is schema corruption, the read-side backstop of the
/// write-side `CHECK` constraints.
fn load_sources(conn: &Connection) -> Result<HashMap<String, SourceRow>, StateError> {
    let mut statement = conn
        .prepare("SELECT source_id, freshness_lane, created_at FROM sources")
        .map_err(|_| query_failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| query_failed())?;
    let mut sources = HashMap::new();
    for row in rows {
        let (source_id, lane, created_at) = row.map_err(|_| query_failed())?;
        let lane = FreshnessLane::parse(&lane).map_err(|_| corrupted("sources.freshness_lane"))?;
        sources.insert(source_id, SourceRow { lane, created_at });
    }
    Ok(sources)
}

/// The generation each source's scan compares against: the open generation
/// when one exists (the artifact still growing), otherwise the highest
/// ordinal (a replaced source whose latest artifact is final). Captured
/// generations are never chosen over a higher open ordinal.
fn current_generation_by_source(conn: &Connection) -> Result<HashMap<String, String>, StateError> {
    let mut statement = conn
        .prepare(
            "SELECT source_id, generation_id, state, ordinal FROM generations
             ORDER BY source_id, ordinal",
        )
        .map_err(|_| query_failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|_| query_failed())?;
    let mut current: HashMap<String, (String, bool, i64)> = HashMap::new();
    for row in rows {
        let (source_id, generation_id, state, ordinal) = row.map_err(|_| query_failed())?;
        let open = match state.as_str() {
            "open" => true,
            "closed" => false,
            _ => return Err(corrupted("generations.state")),
        };
        match current.get_mut(&source_id) {
            // Rows arrive by ascending ordinal; an open generation always
            // wins, and within a class the later (higher) ordinal wins.
            Some(entry) if entry.1 && !open => {}
            Some(entry) => {
                *entry = (generation_id, open, ordinal);
            }
            None => {
                current.insert(source_id, (generation_id, open, ordinal));
            }
        }
    }
    Ok(current
        .into_iter()
        .map(|(source, (generation, _, _))| (source, generation))
        .collect())
}

/// Acknowledged extents per generation: the maximum byte and event range
/// end. Capture is a sequential prefix of complete boundaries, so the
/// maximum end is the acknowledged extent. A stored range kind outside the
/// schema's closed pair is schema corruption.
fn acknowledged_by_generation(
    conn: &Connection,
) -> Result<HashMap<String, (u64, u64)>, StateError> {
    let mut statement = conn
        .prepare(
            "SELECT r.generation_id, r.range_kind, MAX(r.range_end)
             FROM ranges r GROUP BY r.generation_id, r.range_kind",
        )
        .map_err(|_| query_failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|_| query_failed())?;
    let mut acknowledged: HashMap<String, (u64, u64)> = HashMap::new();
    for row in rows {
        let (generation_id, kind, end) = row.map_err(|_| query_failed())?;
        let end = u64::try_from(end.max(0)).unwrap_or(0);
        let entry = acknowledged.entry(generation_id).or_insert((0, 0));
        match kind.as_str() {
            "bytes" => entry.0 = entry.0.max(end),
            "events" => entry.1 = entry.1.max(end),
            _ => return Err(corrupted("ranges.range_kind")),
        }
    }
    Ok(acknowledged)
}

/// The freshest acknowledged capture timestamp per source.
fn last_captured_by_source(conn: &Connection) -> Result<HashMap<String, String>, StateError> {
    let mut statement = conn
        .prepare(
            "SELECT g.source_id, r.captured_at
             FROM ranges r JOIN generations g ON g.generation_id = r.generation_id",
        )
        .map_err(|_| query_failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| query_failed())?;
    let mut latest: HashMap<String, String> = HashMap::new();
    for row in rows {
        let (source_id, captured_at) = row.map_err(|_| query_failed())?;
        // Mixed fractional precision makes text order wrong; compare as
        // instants, and keep the first value when neither parses.
        let newer = match (
            latest.get(&source_id).and_then(|text| basis_epoch(text)),
            basis_epoch(&captured_at),
        ) {
            (Some(current_at), Some(candidate_at)) => candidate_at > current_at,
            (None, Some(_)) => true,
            _ => false,
        };
        if newer {
            latest.insert(source_id, captured_at);
        }
    }
    Ok(latest)
}

/// The private state the inventory reads is the same database
/// [`crate::state`] owns; every read failure is classified, content-free,
/// and dropped of driver text that could embed a path.
fn query_failed() -> StateError {
    StateError::with_detail(
        StateErrorKind::Unavailable,
        "inventory could not read the state database",
    )
}

/// A stored value outside the pinned vocabulary: schema corruption seen
/// from the read side.
fn corrupted(subject: &'static str) -> StateError {
    StateError::of_kind(StateErrorKind::SchemaCorruption).about(subject)
}

/// Parse a stored RFC 3339 UTC timestamp into a Unix-second basis,
/// rejecting values outside the calendar.
pub(crate) fn basis_epoch(text: &str) -> Option<u64> {
    let parsed = Timestamp::parse(text).ok()?;
    epoch_seconds(&parsed)
}

/// Convert a validated timestamp to Unix seconds. The optional fractional
/// part truncates; a leap second folds into the following second.
/// Pre-epoch timestamps have no non-negative basis and yield `None`.
pub(crate) fn epoch_seconds(timestamp: &Timestamp) -> Option<u64> {
    if !timestamp.calendar_valid() {
        return None;
    }
    let raw = timestamp.as_str().as_bytes();
    let number = |slice: &[u8]| {
        slice
            .iter()
            .fold(0i64, |acc, c| acc * 10 + i64::from(c - b'0'))
    };
    let year = number(&raw[0..4]);
    let month = number(&raw[5..7]);
    let day = number(&raw[8..10]);
    let hour = number(&raw[11..13]);
    let minute = number(&raw[14..16]);
    let raw_second = number(&raw[17..19]);
    let (second, leap_extra) = if raw_second == 60 {
        (59, 1)
    } else {
        (raw_second, 0)
    };
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second + leap_extra;
    u64::try_from(seconds).ok()
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date
/// (Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = if shifted_year >= 0 {
        shifted_year
    } else {
        shifted_year - 399
    } / 400;
    let year_of_era = shifted_year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// A counter rendered into the no-float JSON domain: saturating at
/// `i64::MAX`, because a status figure that would overflow the wire integer
/// domain is clipped, never wrapped and never a float.
pub(crate) fn bounded_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests;
