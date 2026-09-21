// SPDX-License-Identifier: Apache-2.0

//! The two-lane freshness/backfill scheduler (plan Section 7.9; requirements
//! SCH-001 through SCH-006): one deterministic planning pass over the
//! inventory's per-source backlog that orders a scheduling cycle as
//!
//! 1. **Drain** the durable pending spool (SCH-001). Bundles already on
//!    disk are the client's outstanding promises; they upload before any
//!    new payload is materialized. Draining is also the only way the spool
//!    shrinks, so the drain phase is planned in full regardless of the
//!    round's materialization capacity — under the pressure gate only new
//!    materialization pauses, never the retry of existing entries.
//! 2. **Reserve** one chunk for every active source with measured
//!    outstanding data (SCH-005). The reservation is unconditional and
//!    precedes all backfill spending: a live session is kept current even
//!    while a much larger history waits, which is what bounds
//!    active-source freshness to one round. When the round's capacity
//!    cannot cover every reservation, the shortfall is counted and made
//!    visible, and the unspent capacity is *not* handed to backfill —
//!    spending on history what an active source was denied is exactly the
//!    monopolization the reservation exists to prevent.
//! 3. **Backfill** the remaining capacity largest-measured-backlog-first
//!    (SCH-003), limiting every source to its quantum — 256 MiB per
//!    scheduling round by default (SCH-004). Every source with residual
//!    backlog competes here, freshness-lane ones included: after a marathon
//!    outage an active session's huge gap is drained by the same
//!    largest-first pass once its reservation kept it current (plan
//!    Section 2, scenario 4).
//!
//! # Starvation bounds
//!
//! For closed (non-growing) backlogs — the backfill lane's contract — the
//! bound is computable from one round's inputs. Let `C` be the per-round
//! capacity left after reservations and `A` the measured backlog ranked
//! ahead of a source `S`. Every round spends up to `C` on backlog ranked
//! ahead of `S`, and that backlog never grows, so `S` receives its first
//! chunk by round `ceil(A / C) + 1`. The quantum tightens, never loosens,
//! the bound: a source above the quantum sheds capacity to the next rank
//! each round, which is why small and low-volume sources are served in
//! bounded time rather than after the giants finish. Active sources are
//! bounded harder still: one chunk every round, ahead of all backfill.
//!
//! # Determinism and identity (SCH-006)
//!
//! [`plan`] is a pure function of its inputs: no clock, no randomness, no
//! map iteration in any ordering decision. Input order never matters —
//! candidates are ranked by (outstanding bytes, outstanding events, source
//! id) and reservations by source id, both total orders. Priority changes
//! when work happens, never what the archive ends up holding: a plan names
//! sources, chunk counts, and byte figures only, and the canonical chunk
//! bytes an upload carries are derived from the source by the capture path,
//! so scheduling order cannot change object identity or final archive
//! contents.
//!
//! The scheduler plans; it does not touch the filesystem or the state
//! database. The daemon cycle (later Phase 5 work) measures the pending
//! spool, runs the inventory pass, derives the admitted capacity from the
//! pressure gate, executes the returned plan, and lets the next inventory
//! pass re-measure what the receipts acknowledged.

use archivist_adapter_sdk::status::{FreshnessLane, ScanClassification, SourceId};

use crate::inventory::SourceInventory;

#[cfg(test)]
mod tests;

/// The target canonical chunk size: 16 MiB (plan Section 7.6). Scheduling
/// arithmetic is chunk-granular — reservations are one chunk, quanta are
/// whole chunks — and a source's final partial chunk grants only its
/// remaining bytes.
pub const TARGET_CHUNK_BYTES: u64 = 16 * 1024 * 1024;

/// The default per-source backfill quantum: 256 MiB per scheduling round
/// (plan Section 7.9).
pub const DEFAULT_BACKFILL_QUANTUM_BYTES: u64 = 256 * 1024 * 1024;

/// The scheduler's numeric shape: the chunk granularity and the per-source
/// backfill quantum (SCH-004). The defaults carry the plan's 16 MiB chunk
/// and 256 MiB quantum; [`SchedulerLimits::new`] states both explicitly for
/// synthetic schedules and, later, for the configuration keys that resolve
/// the quota per source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerLimits {
    /// The chunk granularity grants are counted in.
    pub chunk_bytes: u64,
    /// The largest bytes one source may receive from the backfill pass in
    /// one scheduling round.
    pub backfill_quantum_bytes: u64,
}

impl SchedulerLimits {
    /// Limits from explicit numbers, the shape the deterministic
    /// simulations and a future per-source configuration use.
    ///
    /// The arithmetic stays defined for every input: a zero chunk size is
    /// read as one byte (grant counts stay finite); a zero quantum grants
    /// every source no backfill bytes this round, which is how the
    /// historical drain can be paused without pausing the freshness
    /// reservation.
    #[must_use]
    pub const fn new(chunk_bytes: u64, backfill_quantum_bytes: u64) -> Self {
        Self {
            chunk_bytes,
            backfill_quantum_bytes,
        }
    }

    /// The plan's defaults: the 16 MiB chunk and the 256 MiB per-source
    /// quantum.
    #[must_use]
    pub const fn plan_defaults() -> Self {
        Self::new(TARGET_CHUNK_BYTES, DEFAULT_BACKFILL_QUANTUM_BYTES)
    }
}

impl Default for SchedulerLimits {
    fn default() -> Self {
        Self::plan_defaults()
    }
}

/// The pending spool one cycle must drain before anything new is
/// materialized (SCH-001): the count and byte size of the `spool_entries`
/// rows not yet acknowledged — exactly the population
/// [`crate::spool::live_usage_bytes`] measures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DrainLoad {
    /// Pending bundles waiting for a receipt.
    pub entries: u64,
    /// Their bytes on disk.
    pub bytes: u64,
}

/// One source's chunk allocation for one round, from either lane. A grant
/// names positions in a source's backlog — chunk counts and the bytes they
/// cover — never content: the canonical bytes are derived at capture time,
/// so the schedule cannot influence object identity (SCH-006).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkGrant {
    /// The source whose backlog this grant draws down.
    pub source: SourceId,
    /// The lane the source belongs to; a freshness-lane source's grant may
    /// sit in the backfill pass once its reservation kept it current.
    pub lane: FreshnessLane,
    /// The bytes this grant covers: whole chunks, except a final partial
    /// chunk, which covers only the source's remainder.
    pub granted_bytes: u64,
    /// The number of chunks granted. An events-only backlog (no measured
    /// bytes) grants one chunk carrying zero bytes.
    pub chunk_count: u64,
}

/// The round's arithmetic, as the plan spent it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CycleTotals {
    /// The materialization capacity the round was given.
    pub capacity_bytes: u64,
    /// Pending spool entries the drain phase covers (SCH-001).
    pub drain_entries: u64,
    /// Pending spool bytes the drain phase covers.
    pub drain_bytes: u64,
    /// Sources with measured, schedulable backlog this round.
    pub eligible_sources: u64,
    /// Active sources that received their reservation chunk.
    pub reserved_sources: u64,
    /// Bytes the reservations cover.
    pub reserved_bytes: u64,
    /// Chunks the reservations cover.
    pub reserved_chunks: u64,
    /// Sources the backfill pass granted this round.
    pub backfilled_sources: u64,
    /// Bytes the backfill pass granted.
    pub backfill_bytes: u64,
    /// Chunks the backfill pass granted.
    pub backfill_chunks: u64,
    /// Bytes the round plans to materialize: reservations plus backfill.
    pub planned_bytes: u64,
    /// Active sources denied their reservation because the round's
    /// capacity could not cover every one. Never silent: a round this
    /// large reports the shortfall and spends nothing on backfill.
    pub short_reservations: u64,
    /// Sources with residual backlog that received no backfill grant this
    /// round — the quantum, an exhausted capacity, or a frozen backfill
    /// pass after a short reservation.
    pub deferred_sources: u64,
}

/// One cycle's work order: drain first, then the freshness reservations,
/// then largest-first backfill under the per-source quantum.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CyclePlan {
    /// The pending spool this cycle drains before materializing anything
    /// new (SCH-001).
    pub drain: DrainLoad,
    /// One chunk per active source with measured outstanding data, in
    /// source-id order (SCH-005).
    pub reservations: Vec<ChunkGrant>,
    /// The largest-first backfill grants, in spend order (SCH-003).
    pub backfill: Vec<ChunkGrant>,
    /// The round's arithmetic.
    pub totals: CycleTotals,
}

/// The chunk count a backlog measures to: whole chunks for a byte backlog,
/// one byte-less chunk for an events-only backlog, zero when there is
/// nothing to capture.
fn backlog_chunks(outstanding_bytes: u64, outstanding_events: u64, chunk_bytes: u64) -> u64 {
    if outstanding_bytes > 0 {
        outstanding_bytes.div_ceil(chunk_bytes)
    } else {
        u64::from(outstanding_events > 0)
    }
}

/// The freshness reservation pass's outcome (SCH-005).
struct Reservations {
    /// One grant per served active source, in source-id order.
    grants: Vec<ChunkGrant>,
    /// Reserved chunk counts per eligible index, parallel to the eligible
    /// slice the pass ran over.
    covered: Vec<u64>,
    /// Bytes the grants cover.
    reserved_bytes: u64,
    /// Active sources denied their reservation chunk.
    short: u64,
    /// Whether at least one reservation was denied; a round this large
    /// freezes backfill.
    any_short: bool,
}

/// Reserve one chunk for every eligible active source, in source-id order,
/// out of the round's capacity. The first reservation that does not fit
/// denies it and every one after it — capacity is granted id-order, and a
/// denied active source freezes backfill rather than yielding to it.
fn reserve_freshness(
    eligible: &[&SourceInventory],
    chunk_bytes: u64,
    capacity_bytes: u64,
) -> Reservations {
    let mut covered = vec![0u64; eligible.len()];
    let mut grants = Vec::new();
    let mut reserved = 0u64;
    let mut short = 0u64;
    let mut any_short = false;

    let mut freshness: Vec<usize> = (0..eligible.len())
        .filter(|&i| eligible[i].lane == FreshnessLane::Freshness)
        .collect();
    freshness.sort_unstable_by(|a, b| eligible[*a].source.cmp(&eligible[*b].source));
    for &i in &freshness {
        let record = eligible[i];
        if any_short {
            short += 1;
            continue;
        }
        let grant_bytes = chunk_bytes.min(record.outstanding_bytes);
        if grant_bytes <= capacity_bytes - reserved {
            reserved += grant_bytes;
            covered[i] = 1;
            grants.push(ChunkGrant {
                source: record.source.clone(),
                lane: record.lane,
                granted_bytes: grant_bytes,
                chunk_count: 1,
            });
        } else {
            any_short = true;
            short += 1;
        }
    }
    Reservations {
        grants,
        covered,
        reserved_bytes: reserved,
        short,
        any_short,
    }
}

/// Spend the post-reservation capacity largest-backlog-first, every source
/// capped at its quantum in whole chunks. Returns the grants in spend
/// order and the count of residual-backlog sources left ungranted.
fn plan_backfill(
    eligible: &[&SourceInventory],
    covered: &[u64],
    chunk_bytes: u64,
    quantum_bytes: u64,
    capacity_bytes: u64,
    open: bool,
) -> (Vec<ChunkGrant>, u64) {
    let mut order: Vec<usize> = (0..eligible.len()).collect();
    order.sort_unstable_by(|a, b| {
        eligible[*b]
            .outstanding_bytes
            .cmp(&eligible[*a].outstanding_bytes)
            .then_with(|| {
                eligible[*b]
                    .outstanding_events
                    .cmp(&eligible[*a].outstanding_events)
            })
            .then_with(|| eligible[*a].source.cmp(&eligible[*b].source))
    });

    let budget_chunks = quantum_bytes / chunk_bytes;
    let mut grants = Vec::new();
    let mut deferred = 0u64;
    let mut spent = 0u64;
    for &i in &order {
        let record = eligible[i];
        let total_chunks = backlog_chunks(
            record.outstanding_bytes,
            record.outstanding_events,
            chunk_bytes,
        );
        let residual_chunks = total_chunks.saturating_sub(covered[i]);
        if residual_chunks == 0 {
            continue;
        }
        if !open {
            deferred += 1;
            continue;
        }
        let reserved_bytes_here = if covered[i] > 0 {
            chunk_bytes.min(record.outstanding_bytes)
        } else {
            0
        };
        let residual_bytes = record.outstanding_bytes - reserved_bytes_here;
        let mut grant_chunks = residual_chunks
            .min(budget_chunks)
            .min(capacity_bytes.saturating_sub(spent) / chunk_bytes);
        // An events-only residual costs no bytes: the quantum bounds it,
        // the byte capacity does not.
        if grant_chunks == 0 && residual_bytes == 0 && budget_chunks > 0 {
            grant_chunks = residual_chunks.min(budget_chunks);
        }
        if grant_chunks == 0 {
            deferred += 1;
            continue;
        }
        let grant_bytes = residual_bytes.min(grant_chunks.saturating_mul(chunk_bytes));
        spent += grant_bytes;
        grants.push(ChunkGrant {
            source: record.source.clone(),
            lane: record.lane,
            granted_bytes: grant_bytes,
            chunk_count: grant_chunks,
        });
    }
    (grants, deferred)
}

/// Plan one scheduling cycle.
///
/// Eligible work is a source this pass actually measured — classification
/// `ok` — with no coverage anomaly and at least one outstanding complete
/// byte or event. A failed, unobserved, or anomalous source's figures are
/// stale or contradictory; scheduling against them would capture ranges
/// that may not exist, so the plan leaves them out until a clean pass
/// re-measures them.
///
/// `capacity_bytes` is the materialization budget the pressure gate admits
/// for new payload this round (plan `EC-11`); draining the pending spool
/// is planned in full regardless of it.
#[must_use]
pub fn plan(
    sources: &[SourceInventory],
    pending_spool: DrainLoad,
    capacity_bytes: u64,
    limits: SchedulerLimits,
) -> CyclePlan {
    let chunk = limits.chunk_bytes.max(1);
    let quantum = limits.backfill_quantum_bytes;

    let eligible: Vec<&SourceInventory> = sources
        .iter()
        .filter(|record| record.classification == ScanClassification::Ok)
        .filter(|record| record.anomaly.is_none())
        .filter(|record| record.outstanding_bytes > 0 || record.outstanding_events > 0)
        .collect();

    let fresh = reserve_freshness(&eligible, chunk, capacity_bytes);
    let (backfill, deferred) = plan_backfill(
        &eligible,
        &fresh.covered,
        chunk,
        quantum,
        capacity_bytes - fresh.reserved_bytes,
        !fresh.any_short,
    );

    let reserved_chunks: u64 = fresh.grants.iter().map(|grant| grant.chunk_count).sum();
    let backfill_bytes: u64 = backfill.iter().map(|grant| grant.granted_bytes).sum();
    let backfill_chunks: u64 = backfill.iter().map(|grant| grant.chunk_count).sum();
    let count_of = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    let totals = CycleTotals {
        capacity_bytes,
        drain_entries: pending_spool.entries,
        drain_bytes: pending_spool.bytes,
        eligible_sources: count_of(eligible.len()),
        reserved_sources: count_of(fresh.grants.len()),
        reserved_bytes: fresh.reserved_bytes,
        reserved_chunks,
        backfilled_sources: count_of(backfill.len()),
        backfill_bytes,
        backfill_chunks,
        planned_bytes: fresh.reserved_bytes + backfill_bytes,
        short_reservations: fresh.short,
        deferred_sources: deferred,
    };

    CyclePlan {
        drain: pending_spool,
        reservations: fresh.grants,
        backfill,
        totals,
    }
}
