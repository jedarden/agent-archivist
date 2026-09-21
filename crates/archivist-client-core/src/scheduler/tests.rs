// SPDX-License-Identifier: Apache-2.0

//! Deterministic simulations of the freshness/backfill scheduler: the
//! largest-first spend order, the freshness reservation that precedes it,
//! the per-source quantum, and the starvation bounds the plan's exit gate
//! demands — "scheduler tests prove both largest-first progress and
//! bounded starvation" (plan Phase 5; requirements SCH-001 through
//! SCH-006). Every scenario is closed-form: the rounds, grants, and byte
//! figures below are hand-computed constants, so a regression names the
//! exact arithmetic that moved.

use archivist_adapter_sdk::status::{
    AccountLabel, CoverageState, FreshnessLane, ScanClassification, SourceId,
};
use archivist_protocol::vocabulary::AdapterId;

use super::{
    ChunkGrant, CyclePlan, DEFAULT_BACKFILL_QUANTUM_BYTES, DrainLoad, SchedulerLimits,
    TARGET_CHUNK_BYTES, backlog_chunks, plan,
};
use crate::inventory::{CoverageAnomaly, CursorDecision, CursorPosition, SourceInventory};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// A distinct 36-character lowercase UUID-shape source identifier whose
/// lexicographic order follows its numeric seed (the id's tail carries the
/// seed zero-padded to twelve hex digits).
fn sid(seed: u8) -> SourceId {
    SourceId::parse(&format!("{seed:08x}-1111-4222-8333-{seed:012x}")).expect("source id")
}

/// A distinct adapter identifier.
fn adapter() -> AdapterId {
    AdapterId::parse("adapter-1").expect("adapter id")
}

/// A distinct account label.
fn account() -> AccountLabel {
    AccountLabel::parse("account-1").expect("account label")
}

/// A measured, healthy source carrying the given outstanding bytes.
/// Events track bytes at one event per 16 KiB so the byte and event axes
/// rank identically unless a test sets them apart on purpose.
fn measured(seed: u8, lane: FreshnessLane, outstanding_bytes: u64) -> SourceInventory {
    source(
        seed,
        lane,
        outstanding_bytes,
        outstanding_bytes / (16 * 1024),
    )
}

/// A source with explicit figures, for the events-only and zero-backlog
/// shapes.
fn source(
    seed: u8,
    lane: FreshnessLane,
    outstanding_bytes: u64,
    outstanding_events: u64,
) -> SourceInventory {
    let has_backlog = outstanding_bytes > 0 || outstanding_events > 0;
    SourceInventory {
        source: sid(seed),
        adapter: adapter(),
        account: account(),
        lane,
        coverage: if has_backlog {
            CoverageState::Partial
        } else if lane == FreshnessLane::Backfill {
            CoverageState::FullyBackfilled
        } else {
            CoverageState::Current
        },
        classification: ScanClassification::Ok,
        complete_bytes: outstanding_bytes,
        complete_events: outstanding_events,
        acknowledged_bytes: 0,
        acknowledged_events: 0,
        outstanding_bytes,
        outstanding_events,
        incomplete_tail_bytes: 0,
        freshness_lag_seconds: 0,
        cursor: CursorPosition::default(),
        decision: CursorDecision::Hold,
        anomaly: None,
        enrolled: true,
    }
}

/// A historical (backfill-lane) source measured in MiB.
fn history(seed: u8, outstanding_mib: u64) -> SourceInventory {
    measured(seed, FreshnessLane::Backfill, outstanding_mib * MIB)
}

/// An active (freshness-lane) source measured in MiB.
fn active(seed: u8, outstanding_mib: u64) -> SourceInventory {
    measured(seed, FreshnessLane::Freshness, outstanding_mib * MIB)
}

/// One simulated fleet under repeated rounds: each round plans against the
/// current outstanding figures, applies the grants the way completed
/// receipts would (bytes exactly, events at an even per-chunk rate), and
/// records when each source was first served.
struct Simulation {
    seeds: Vec<(u8, SourceId)>,
    sources: Vec<SourceInventory>,
    capacity_bytes: u64,
    limits: SchedulerLimits,
    pending: DrainLoad,
    round: u64,
    first_served: Vec<(u8, u64)>,
    plans: Vec<CyclePlan>,
}

impl Simulation {
    fn new(sources: Vec<SourceInventory>, capacity_bytes: u64) -> Self {
        let seeds = sources
            .iter()
            .map(|record| {
                let text = record.source.as_str();
                let seed = u8::from_str_radix(&text[34..36], 16).expect("seed hex");
                (seed, record.source.clone())
            })
            .collect();
        Self {
            seeds,
            sources,
            capacity_bytes,
            limits: SchedulerLimits::default(),
            pending: DrainLoad::default(),
            round: 0,
            first_served: Vec::new(),
            plans: Vec::new(),
        }
    }

    fn run(&mut self, rounds: u64) {
        for _ in 0..rounds {
            self.round += 1;
            let plan = plan(
                &self.sources,
                self.pending,
                self.capacity_bytes,
                self.limits,
            );
            for grant in plan.reservations.iter().chain(plan.backfill.iter()) {
                self.apply(grant);
            }
            self.plans.push(plan);
        }
    }

    /// Apply one grant the way a completed capture would: the granted
    /// bytes leave the backlog exactly, and the grant's chunks carry an
    /// even share of the events the backlog measured when it was granted.
    fn apply(&mut self, grant: &ChunkGrant) {
        let chunk = self.limits.chunk_bytes.max(1);
        let Some(position) = self
            .sources
            .iter()
            .position(|record| record.source == grant.source)
        else {
            panic!("grant names a source outside the simulation");
        };
        let seed = self
            .seeds
            .iter()
            .find(|(_, id)| *id == grant.source)
            .map_or_else(
                || panic!("grant names an untracked source"),
                |(seed, _)| *seed,
            );
        let record = &mut self.sources[position];
        let total = backlog_chunks(record.outstanding_bytes, record.outstanding_events, chunk);
        let per_chunk_events = record.outstanding_events.div_ceil(total.max(1));
        assert!(
            grant.granted_bytes <= record.outstanding_bytes,
            "round {}: grant of {} bytes exceeds the source's outstanding {}",
            self.round,
            grant.granted_bytes,
            record.outstanding_bytes,
        );
        record.outstanding_bytes -= grant.granted_bytes;
        let covered_events = per_chunk_events
            .saturating_mul(grant.chunk_count)
            .min(record.outstanding_events);
        record.outstanding_events -= covered_events;
        if !self.first_served.iter().any(|(s, _)| *s == seed) {
            self.first_served.push((seed, self.round));
        }
    }

    /// The round a seed was first served, if it ever was.
    fn first_served_of(&self, seed: u8) -> Option<u64> {
        self.first_served
            .iter()
            .find(|(s, _)| *s == seed)
            .map(|(_, round)| *round)
    }

    /// Outstanding bytes for a seed.
    fn outstanding_of(&self, seed: u8) -> u64 {
        let id = sid(seed);
        self.sources
            .iter()
            .find(|record| record.source == id)
            .map_or(0, |record| record.outstanding_bytes)
    }
}

/// The `(source, bytes, chunks)` triples of one grant list, for exact
/// assertions.
fn shape(grants: &[ChunkGrant]) -> Vec<(SourceId, u64, u64)> {
    grants
        .iter()
        .map(|grant| (grant.source.clone(), grant.granted_bytes, grant.chunk_count))
        .collect()
}

// The largest-first spend order (SCH-003): capacity flows down a total
// rank of measured backlog, and the plan names the grants in spend order.
#[test]
fn largest_history_progresses_first() {
    let sources = vec![
        history(1, 1024),
        history(2, 512),
        history(3, 256),
        history(4, 64),
    ];
    let plan = plan(
        &sources,
        DrainLoad::default(),
        400 * MIB,
        SchedulerLimits::default(),
    );

    assert_eq!(
        shape(&plan.backfill),
        vec![(sid(1), 256 * MIB, 16), (sid(2), 144 * MIB, 9)],
        "capacity must spend largest-first until it runs out",
    );
    assert_eq!(plan.backfill[0].lane, FreshnessLane::Backfill);
    assert_eq!(plan.totals.eligible_sources, 4);
    assert_eq!(
        plan.totals.deferred_sources, 2,
        "the two smaller ranks wait"
    );
    assert_eq!(plan.totals.planned_bytes, 400 * MIB);
    assert_eq!(plan.totals.short_reservations, 0);
    assert!(
        plan.reservations.is_empty(),
        "no active sources, no reservations"
    );
}

// The quantum (SCH-004): no source draws more than its per-round quota,
// whatever its backlog and whatever the capacity could have given it.
#[test]
fn quantum_caps_each_source_per_round() {
    let sources = vec![history(1, 1024)];
    let capped = plan(
        &sources,
        DrainLoad::default(),
        GIB,
        SchedulerLimits::default(),
    );
    assert_eq!(
        shape(&capped.backfill),
        vec![(sid(1), DEFAULT_BACKFILL_QUANTUM_BYTES, 16)]
    );
    assert_eq!(capped.totals.deferred_sources, 0, "served, just capped");
    assert_eq!(capped.totals.backfill_bytes, DEFAULT_BACKFILL_QUANTUM_BYTES);

    // A whole backlog smaller than one chunk grants its remainder only.
    let small = vec![history(2, 16), history(3, 1)];
    let small_round = plan(
        &small,
        DrainLoad::default(),
        GIB,
        SchedulerLimits::default(),
    );
    assert_eq!(
        shape(&small_round.backfill),
        vec![(sid(2), 16 * MIB, 1), (sid(3), MIB, 1)],
        "a final partial chunk covers the remainder only",
    );
}

// The freshness reservation (SCH-005): every active source with backlog
// receives one chunk ahead of all backfill spend, whatever the histories
// behind it measure.
#[test]
fn reservations_precede_backfill_spend() {
    let sources = vec![active(1, 16), active(2, 16), history(3, 1024)];
    let plan = plan(
        &sources,
        DrainLoad::default(),
        400 * MIB,
        SchedulerLimits::default(),
    );

    assert_eq!(
        plan.reservations
            .iter()
            .map(|grant| (grant.source.clone(), grant.granted_bytes, grant.chunk_count))
            .collect::<Vec<_>>(),
        vec![(sid(1), 16 * MIB, 1), (sid(2), 16 * MIB, 1)],
        "both actives are reserved, in source-id order",
    );
    assert_eq!(plan.totals.reserved_bytes, 32 * MIB);
    assert_eq!(
        shape(&plan.backfill),
        vec![(sid(3), 256 * MIB, 16)],
        "the giant still takes the largest rank, capped at its quantum",
    );
    assert_eq!(plan.totals.planned_bytes, 288 * MIB);
    assert_eq!(plan.totals.short_reservations, 0);
    assert_eq!(plan.totals.deferred_sources, 0);
}

// A reservation that does not fit is counted short and freezes backfill:
// the round never spends on history what an active source was denied.
#[test]
fn short_reservation_freezes_backfill() {
    let sources = vec![active(1, 16), active(2, 16), history(3, 1024)];

    // One reservation fits, the second does not; the leftover capacity is
    // not handed to the giant.
    let partial = plan(
        &sources,
        DrainLoad::default(),
        16 * MIB,
        SchedulerLimits::default(),
    );
    assert_eq!(
        partial.reservations.len(),
        1,
        "the first active in id order is served"
    );
    assert_eq!(partial.totals.short_reservations, 1);
    assert!(
        partial.backfill.is_empty(),
        "backfill is frozen after the shortfall"
    );
    assert_eq!(
        partial.totals.deferred_sources, 2,
        "the giant and the unserved active wait"
    );
    assert_eq!(partial.totals.planned_bytes, 16 * MIB);

    // Nothing fits: the round spends nothing and says why.
    let starved = plan(
        &sources,
        DrainLoad::default(),
        8 * MIB,
        SchedulerLimits::default(),
    );
    assert!(starved.reservations.is_empty());
    assert_eq!(starved.totals.short_reservations, 2);
    assert!(starved.backfill.is_empty());
    assert_eq!(starved.totals.deferred_sources, 3);
    assert_eq!(starved.totals.planned_bytes, 0);
}

// The spool drain (SCH-001): planned in full ahead of everything else,
// regardless of the round's materialization capacity.
#[test]
fn drain_is_planned_in_full_before_any_discovery() {
    let pending = DrainLoad {
        entries: 3,
        bytes: 48 * MIB,
    };
    let sources = vec![active(1, 16)];

    let starved_round = plan(&sources, pending, 0, SchedulerLimits::default());
    assert_eq!(
        starved_round.drain, pending,
        "a zero-capacity round still drains"
    );
    assert_eq!(starved_round.totals.drain_entries, 3);
    assert_eq!(starved_round.totals.drain_bytes, 48 * MIB);
    assert_eq!(
        starved_round.totals.short_reservations, 1,
        "the active waits for capacity"
    );
    assert_eq!(starved_round.totals.planned_bytes, 0);

    let funded = plan(&sources, pending, 100 * MIB, SchedulerLimits::default());
    assert_eq!(funded.drain, pending);
    assert_eq!(funded.totals.short_reservations, 0);
    assert_eq!(funded.reservations.len(), 1);
}

// The plan is a pure function of its inputs: the same fleet in any input
// order plans identically.
#[test]
fn plan_is_independent_of_input_order() {
    let fleet = vec![
        history(1, 1024),
        active(2, 48),
        history(3, 256),
        active(4, 1),
        history(5, 64),
        history(6, 16),
    ];
    let mut shuffled = fleet.clone();
    shuffled.reverse();
    let forward = plan(
        &fleet,
        DrainLoad::default(),
        512 * MIB,
        SchedulerLimits::default(),
    );
    let backward = plan(
        &shuffled,
        DrainLoad::default(),
        512 * MIB,
        SchedulerLimits::default(),
    );
    assert_eq!(forward, backward, "input order must never reach the plan");
}

// Only measured, anomaly-free backlog is schedulable: failed and
// unobserved passes and coverage anomalies keep their figures out of the
// plan until a clean pass re-measures them.
#[test]
fn unmeasurable_sources_are_never_scheduled() {
    let mut failed = history(1, 64);
    failed.classification = ScanClassification::ReadError;
    let mut unobserved = history(2, 32);
    unobserved.classification = ScanClassification::NotObserved;
    let mut anomalous = history(3, 16);
    anomalous.anomaly = Some(CoverageAnomaly::AcknowledgedBeyondComplete);
    let caught_up = active(4, 0);
    let good = history(5, 64);

    let sources = vec![failed, unobserved, anomalous, caught_up, good];
    let plan = plan(
        &sources,
        DrainLoad::default(),
        GIB,
        SchedulerLimits::default(),
    );
    assert_eq!(
        plan.totals.eligible_sources, 1,
        "only the clean measurement schedules"
    );
    assert_eq!(
        plan.backfill
            .iter()
            .map(|grant| grant.source.clone())
            .collect::<Vec<_>>(),
        vec![sid(5)],
    );
    assert!(
        plan.reservations.is_empty(),
        "the caught-up active needs no reservation"
    );
}

// An events-only backlog schedules as one chunk carrying zero bytes: the
// scheduler's byte figures are source bytes, and a record-only backlog
// still owes capture work the quantum bounds.
#[test]
fn events_only_backlog_gets_one_byteless_chunk() {
    let sources = vec![
        source(1, FreshnessLane::Freshness, 0, 5),
        source(2, FreshnessLane::Backfill, 0, 7),
    ];
    let free_round = plan(
        &sources,
        DrainLoad::default(),
        0,
        SchedulerLimits::default(),
    );

    assert_eq!(
        free_round.reservations.len(),
        1,
        "zero byte capacity still serves the active"
    );
    assert_eq!(free_round.reservations[0].granted_bytes, 0);
    assert_eq!(free_round.reservations[0].chunk_count, 1);
    assert_eq!(
        shape(&free_round.backfill),
        vec![(sid(2), 0, 1)],
        "the events-only history costs no bytes but still grants",
    );
    assert_eq!(free_round.totals.planned_bytes, 0);
    assert_eq!(free_round.totals.backfill_chunks, 1);

    // A zero quantum pauses the historical drain, including its
    // events-only remainder.
    let paused = SchedulerLimits::new(TARGET_CHUNK_BYTES, 0);
    let paused_round = plan(&sources, DrainLoad::default(), 0, paused);
    assert_eq!(
        paused_round.reservations.len(),
        1,
        "the reservation outranks the quantum"
    );
    assert!(paused_round.backfill.is_empty());
    assert_eq!(paused_round.totals.deferred_sources, 1);
}

// An active source's residual backlog flows through the backfill pass
// once its reservation kept it current, and the reservation plus that
// residual stay inside one round.
#[test]
fn active_residual_backlog_flows_through_backfill() {
    let sources = vec![active(1, 40)];
    let plan = plan(
        &sources,
        DrainLoad::default(),
        288 * MIB,
        SchedulerLimits::default(),
    );
    assert_eq!(
        plan.reservations
            .iter()
            .map(|grant| (grant.source.clone(), grant.granted_bytes))
            .collect::<Vec<_>>(),
        vec![(sid(1), 16 * MIB)],
    );
    assert_eq!(
        shape(&plan.backfill),
        vec![(sid(1), 24 * MIB, 2)],
        "the remaining 24 MiB completes in the same round",
    );
    assert_eq!(plan.totals.planned_bytes, 40 * MIB);
    assert_eq!(plan.totals.deferred_sources, 0);
}

// The quota is configurable (SCH-004): a smaller quantum and chunk
// reshape the round.
#[test]
fn limits_reshape_the_round() {
    let sources = vec![history(1, 1024), history(2, 6)];
    let limits = SchedulerLimits::new(4 * MIB, 64 * MIB);
    let plan = plan(&sources, DrainLoad::default(), GIB, limits);
    assert_eq!(
        shape(&plan.backfill),
        vec![(sid(1), 64 * MIB, 16), (sid(2), 6 * MIB, 2)],
        "a 4 MiB chunk counts the 6 MiB backlog as two chunks, the last partial",
    );
}

// Simulation: active sources stay fresh under backfill pressure — one
// chunk each, every round, ahead of a much larger history — and the
// history still makes exactly its quantum of progress per round.
#[test]
fn actives_stay_fresh_while_the_history_drains() {
    let mut sim = Simulation::new(
        vec![active(1, 48), active(2, 1), history(3, 4096)],
        288 * MIB,
    );
    sim.run(17);

    // Round 1: both actives reserved (id order), the history takes its
    // quantum, the active's residual waits one round behind it.
    let round1 = &sim.plans[0];
    assert_eq!(
        round1
            .reservations
            .iter()
            .map(|grant| (grant.source.clone(), grant.granted_bytes))
            .collect::<Vec<_>>(),
        vec![(sid(1), 16 * MIB), (sid(2), MIB)],
    );
    assert_eq!(shape(&round1.backfill), vec![(sid(3), 256 * MIB, 16)],);
    assert_eq!(round1.totals.deferred_sources, 1);

    // Round 2: the caught-up small active drops out; the other still
    // reserves — and after the history takes its quantum, the one chunk
    // of capacity left covers the active's residual exactly.
    let round2 = &sim.plans[1];
    assert_eq!(
        round2
            .reservations
            .iter()
            .map(|grant| grant.source.clone())
            .collect::<Vec<_>>(),
        vec![sid(1)],
    );
    assert_eq!(
        shape(&round2.backfill),
        vec![(sid(3), 256 * MIB, 16), (sid(1), 16 * MIB, 1)],
        "the leftover chunk finishes the active's gap largest-first",
    );
    assert_eq!(round2.totals.deferred_sources, 0);

    // Round 3: the active is fully current; from here the history drains
    // alone at exactly one quantum per round.
    let round3 = &sim.plans[2];
    assert!(round3.reservations.is_empty());
    assert_eq!(round3.backfill[0].granted_bytes, 256 * MIB);
    for plan in &sim.plans[3..16] {
        assert!(plan.reservations.is_empty(), "no active backlog remains");
        assert_eq!(shape(&plan.backfill), vec![(sid(3), 256 * MIB, 16)]);
    }
    let last = &sim.plans[16];
    assert_eq!(
        last.totals.eligible_sources, 0,
        "the history finished in round 16"
    );
    assert_eq!(sim.outstanding_of(1), 0);
    assert_eq!(sim.outstanding_of(2), 0);
    assert_eq!(sim.outstanding_of(3), 0);
}

// Simulation: bounded starvation. Three equal 3 GiB histories and a
// 32 MiB low-volume source, 256 MiB of capacity per round: each round
// serves whichever giant is currently largest (the perpetual tie breaks
// by source id, so the giants rotate), and the small source waits a
// computable `ceil(ahead / capacity) + 1` rounds — 37 here — then
// completes in its first served round.
#[test]
fn low_volume_source_is_starvation_bounded() {
    let mut sim = Simulation::new(
        vec![
            history(1, 3072),
            history(2, 3072),
            history(3, 3072),
            history(4, 32),
        ],
        256 * MIB,
    );
    sim.run(40);

    // Largest-first progress the whole way: the giants measure equal
    // backlogs that shrink in lockstep, so the id tie-break rotates them
    // — three rounds per 256 MiB each, twelve rotations to drain.
    for (index, served) in sim.plans.iter().enumerate() {
        let round = u64::try_from(index).expect("round index fits") + 1;
        if round > 36 {
            break;
        }
        let expected = u8::try_from((round - 1) % 3 + 1).expect("seed fits");
        assert_eq!(
            served
                .backfill
                .iter()
                .map(|grant| grant.source.clone())
                .collect::<Vec<_>>(),
            vec![sid(expected)],
            "round {round} must serve the largest history",
        );
    }

    // The bound: 9216 MiB ranked ahead of the small source, 256 MiB of
    // capacity per round.
    let ahead = 3 * 3072 * MIB;
    let bound = ahead.div_ceil(256 * MIB) + 1;
    assert_eq!(
        sim.first_served_of(4),
        Some(bound),
        "the small source waits exactly the computable bound",
    );
    assert_eq!(
        sim.outstanding_of(4),
        0,
        "and completes in its first served round"
    );
    assert_eq!(sim.outstanding_of(1), 0);
    assert_eq!(sim.outstanding_of(2), 0);
    assert_eq!(sim.outstanding_of(3), 0);

    // After everything drains, the plan carries nothing.
    for empty in &sim.plans[37..] {
        assert!(empty.reservations.is_empty());
        assert!(empty.backfill.is_empty());
        assert_eq!(empty.totals.eligible_sources, 0);
    }
}

// Simulation: a small active source is never starved at all — its
// reservation lands in the very first round, ahead of a giant that still
// makes largest-first progress throughout.
#[test]
fn small_active_source_is_served_every_round() {
    let mut sim = Simulation::new(vec![active(1, 1), history(2, 4096)], 288 * MIB);
    sim.run(5);
    assert_eq!(
        sim.first_served_of(1),
        Some(1),
        "reserved in the very first round"
    );
    assert_eq!(
        sim.outstanding_of(1),
        0,
        "a 1 MiB active completes immediately"
    );
    for (index, plan) in sim.plans.iter().enumerate() {
        if index > 0 {
            assert!(
                plan.reservations.iter().all(|grant| grant.source != sid(1)),
                "no reservation once the active is current",
            );
        }
        let round = index + 1;
        assert_eq!(
            shape(&plan.backfill),
            vec![(sid(2), 256 * MIB, 16)],
            "round {round}: the history progresses at its quantum throughout",
        );
    }
}
