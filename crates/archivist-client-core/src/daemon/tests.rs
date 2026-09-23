// SPDX-License-Identifier: Apache-2.0

//! Deterministic simulations of the daemon loop: the jittered tick
//! arithmetic, the immediate first cycle, non-overlap across long runs,
//! cancellation at every boundary, restart over a shared durable cursor, a
//! wall clock that lurches without moving anything, and a month-scale
//! marathon that advances incrementally with flat bookkeeping. Every
//! scenario runs on a virtual clock — no test sleeps except the
//! [`super::ThreadSleeper`] scenarios, which prove the real sleeper's
//! contract with short, bounded waits.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use super::{Cancel, LoopReport, LoopStop, ScheduleConfig, ScheduleConfigError, Sleeper, run};
use crate::config::ConfigSources;
use crate::upload::{Jitter, UploadError, UploadErrorKind};

const FIFTEEN_MINUTES: Duration = Duration::from_mins(15);
const TEN_PERCENT_SPAN: Duration = Duration::from_secs(90);
/// The month-scale marathon's horizon: 30 days.
const MONTH: Duration = Duration::from_hours(30 * 24);
/// The marathon's tick: the period plus the jitter span less the one
/// nanosecond the draw's floor keeps back — the all-ones bit pattern's
/// delay, and the largest any draw can be.
const MARATHON_TICK: Duration = Duration::from_nanos(990 * 1_000_000_000 - 1);

// --- fixtures -------------------------------------------------------------

/// Deterministic jitter: every draw returns the same 64 bits.
struct FixedBits(u64);

impl Jitter for FixedBits {
    fn random_bits(&mut self) -> Result<u64, UploadError> {
        Ok(self.0)
    }
}

/// A linear-congruential bit stream, so consecutive draws vary while the
/// sequence stays reproducible.
struct LcgBits(u64);

impl Jitter for LcgBits {
    fn random_bits(&mut self) -> Result<u64, UploadError> {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        Ok(self.0)
    }
}

/// A jitter source whose entropy has failed.
struct DeadEntropy;

impl Jitter for DeadEntropy {
    fn random_bits(&mut self) -> Result<u64, UploadError> {
        Err(UploadError::of_kind(UploadErrorKind::EntropyUnavailable))
    }
}

/// A virtual clock plus the delays the loop asked for. Sleeps return
/// instantly, advance the virtual clock by the full delay, and return
/// `false` when cancellation is already pending — the same contract
/// [`super::ThreadSleeper`] gives the loop, minus the wall time.
#[derive(Default)]
struct VirtualSleeper {
    now: Rc<Cell<Duration>>,
    asked: RefCell<Vec<Duration>>,
    /// Outcomes consumed before the flag check, for scenarios that cancel
    /// *during* a wait rather than before one.
    scripted: RefCell<VecDeque<bool>>,
    /// Waits that may complete before the sleeper starts reporting a
    /// cancellation, the way an external stop ends an otherwise endless
    /// loop (`None` waits forever — for scenarios stopped another way).
    budget: Cell<Option<usize>>,
    completed: Cell<usize>,
}

impl VirtualSleeper {
    fn new() -> (Self, Rc<Cell<Duration>>) {
        let sleeper = Self::default();
        let now = Rc::clone(&sleeper.now);
        (sleeper, now)
    }

    /// The delays the completed waits spent, in order: one between each
    /// pair of consecutive cycles. A wait declined for a cancellation is
    /// not a delay the loop spent, so it is not recorded.
    fn delays(&self) -> Vec<Duration> {
        self.asked.borrow().clone()
    }

    /// Make the wait `at_index` cycles in return "cancelled".
    fn script_cancellation(&mut self, at_index: usize) {
        let scripted = self.scripted.get_mut();
        if scripted.len() <= at_index {
            scripted.resize(at_index + 1, true);
        }
        scripted[at_index] = false;
    }

    /// Let `waits` waits complete; the next one reports a cancellation that
    /// arrived mid-sleep.
    fn stop_after_waits(&mut self, waits: usize) {
        self.budget.set(Some(waits));
    }
}

impl Sleeper for VirtualSleeper {
    fn sleep(&mut self, cancel: &Cancel, delay: Duration) -> bool {
        let scripted_ok = self.scripted.borrow_mut().pop_front().unwrap_or(true);
        if cancel.is_cancelled() || !scripted_ok {
            return false;
        }
        if let Some(budget) = self.budget.get() {
            if self.completed.get() >= budget {
                return false;
            }
            self.completed.set(self.completed.get() + 1);
        }
        self.asked.borrow_mut().push(delay);
        self.now.set(self.now.get() + delay);
        true
    }
}

/// What the cycles did, shared between a loop and the test that watches it.
/// The cursor is the scenario's stand-in for the durable state a real
/// cycle maintains: each cycle advances it by exactly one bounded step.
#[derive(Default)]
struct Trace {
    starts: RefCell<Vec<Duration>>,
    cursor: RefCell<Vec<u64>>,
}

type SharedTrace = Rc<Trace>;

/// A cycle body that records its start on the virtual clock, advances the
/// trace cursor by one step, refuses to run reentrantly, and cancels the
/// loop once `stop_after` cycles have completed (`None` keeps going until
/// the scenario stops it some other way).
struct TracedCycle {
    trace: SharedTrace,
    now: Rc<Cell<Duration>>,
    stop_after: Option<u64>,
    running: Cell<bool>,
}

impl TracedCycle {
    fn new(now: &Rc<Cell<Duration>>, trace: &SharedTrace, stop_after: Option<u64>) -> Self {
        Self {
            trace: Rc::clone(trace),
            now: Rc::clone(now),
            stop_after,
            running: Cell::new(false),
        }
    }

    fn tick(&mut self, cancel: &Cancel) {
        assert!(!self.running.replace(true), "the loop reentered a cycle");
        self.trace.starts.borrow_mut().push(self.now.get());
        let mut cursor = self.trace.cursor.borrow_mut();
        let next = cursor.last().copied().unwrap_or(0) + 1;
        cursor.push(next);
        drop(cursor);
        self.running.set(false);
        if self.stop_after == Some(next) {
            cancel.cancel();
        }
    }
}

/// A private directory removed on drop, for the configuration fixtures.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("archivist-daemon-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The synthetic fully-declared host the configuration tests use, so the
/// daemon's resolved-config path loads the same way.
fn base_sources() -> ConfigSources {
    ConfigSources::non_interactive()
        .env("HOME", "/home/operator")
        .env("TEST_RAW_CREDENTIAL", "fixture-raw-credential")
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
        .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "127.0.0.1:8087")
}

// --- schedule arithmetic ---------------------------------------------------

#[test]
fn the_plan_schedule_is_fifteen_minutes_with_ten_percent_jitter() {
    let schedule = ScheduleConfig::plan_defaults();
    assert_eq!(schedule.interval(), FIFTEEN_MINUTES);
    assert_eq!(schedule.jitter_percent(), 10);
    assert_eq!(schedule.tick_delay(0), FIFTEEN_MINUTES);
    // The span is half-open: the all-ones pattern lands a single nanosecond
    // under the period plus the full span, the largest draw there is.
    assert_eq!(
        schedule.tick_delay(u64::MAX) + Duration::from_nanos(1),
        FIFTEEN_MINUTES + TEN_PERCENT_SPAN
    );
}

#[test]
fn a_tick_delay_maps_the_bits_onto_the_jitter_range() {
    let schedule = ScheduleConfig::plan_defaults();
    // The halfway bit pattern lands on half the span: 945 seconds.
    assert_eq!(schedule.tick_delay(1u64 << 63), Duration::from_secs(945));
    // Every draw stays inside [interval, interval + span].
    let mut bits = LcgBits(0x5eed);
    for _ in 0..1_000 {
        let delay = schedule.tick_delay(bits.random_bits().expect("lcg bits"));
        assert!(delay >= FIFTEEN_MINUTES, "{delay:?} below the period");
        assert!(
            delay <= FIFTEEN_MINUTES + TEN_PERCENT_SPAN,
            "{delay:?} above the jitter bound"
        );
    }
}

#[test]
fn tick_delay_is_monotone_in_the_random_bits() {
    let schedule = ScheduleConfig::plan_defaults();
    let mut previous = schedule.tick_delay(0);
    for step in 1..=64u32 {
        let bits = if step == 64 {
            u64::MAX
        } else {
            (1 << step) - 1
        };
        let delay = schedule.tick_delay(bits);
        assert!(delay >= previous, "bits {bits} mapped below smaller bits");
        previous = delay;
    }
}

#[test]
fn zero_jitter_yields_the_exact_period() {
    let schedule = ScheduleConfig::new(FIFTEEN_MINUTES, 0).expect("valid schedule");
    for bits in [0, 1, u64::MAX >> 1, u64::MAX] {
        assert_eq!(schedule.tick_delay(bits), FIFTEEN_MINUTES);
    }
}

#[test]
fn an_unrunnable_interval_or_jitter_is_refused() {
    assert_eq!(
        ScheduleConfig::new(Duration::ZERO, 10),
        Err(ScheduleConfigError::NonPositiveInterval)
    );
    assert_eq!(
        ScheduleConfig::new(Duration::from_millis(999), 10),
        Err(ScheduleConfigError::IntervalBelowOneSecond)
    );
    assert_eq!(
        ScheduleConfig::new(FIFTEEN_MINUTES, 101),
        Err(ScheduleConfigError::JitterOutOfRange)
    );
}

#[test]
fn an_interval_whose_jitter_arithmetic_overflows_is_refused() {
    let absurd = Duration::from_secs(u64::MAX / 1_000_000_000);
    assert_eq!(
        ScheduleConfig::new(absurd, 10),
        Err(ScheduleConfigError::IntervalUnsupported)
    );
    // The same period at zero jitter stays inside the arithmetic.
    assert!(ScheduleConfig::new(absurd, 0).is_ok());
}

#[test]
fn the_resolved_defaults_resolve_to_the_plan_schedule() {
    let config = base_sources().load().expect("fully declared host loads");
    assert_eq!(
        ScheduleConfig::from_resolved(&config).expect("defaults are valid"),
        ScheduleConfig::plan_defaults()
    );
}

#[test]
fn a_configured_zero_interval_is_refused() {
    let dir = TempDir::new("interval-zero");
    let path = dir.0.join("archivist.toml");
    std::fs::write(&path, "[schedule]\ninterval_seconds = 0\n").expect("write config");
    // The configuration layer's registry bounds refuse the period outright;
    // [`ScheduleConfig::from_resolved`] restates the fault only for a
    // resolved config built by another path.
    let error = base_sources()
        .config_path(&path)
        .load()
        .expect_err("a zero scheduling period is refused as a usage error");
    assert_eq!(error.field(), Some("schedule.interval_seconds"), "{error}");
}

#[test]
fn a_configured_jitter_above_100_is_refused() {
    let dir = TempDir::new("jitter-101");
    let path = dir.0.join("archivist.toml");
    std::fs::write(&path, "[schedule]\njitter_percent = 101\n").expect("write config");
    let error = base_sources()
        .config_path(&path)
        .load()
        .expect_err("a jitter above 100 percent is refused as a usage error");
    assert_eq!(error.field(), Some("schedule.jitter_percent"), "{error}");
}

// --- loop sequencing -------------------------------------------------------

#[test]
fn the_first_cycle_runs_immediately_and_later_cycles_one_jittered_delay_apart() {
    let schedule = ScheduleConfig::plan_defaults();
    let (mut sleeper, now) = VirtualSleeper::new();
    // Five waits complete, then the sixth reports the external stop that
    // ends the scenario: six cycles, five inter-cycle gaps.
    sleeper.stop_after_waits(5);
    let trace: SharedTrace = Rc::default();
    let mut cycle = TracedCycle::new(&now, &trace, None);
    let mut body = |cancel: &Cancel| cycle.tick(cancel);

    let report = run(
        &schedule,
        &Cancel::new(),
        &mut LcgBits(0xfeed),
        &mut sleeper,
        &mut body,
    );
    assert_eq!(report.cycles_completed, 6);
    assert_eq!(report.stop, LoopStop::Cancelled);

    let starts = trace.starts.borrow();
    let delays = sleeper.delays();
    assert!(!starts.is_empty());
    assert_eq!(starts[0], Duration::ZERO, "the first cycle starts at once");
    assert_eq!(delays.len(), starts.len() - 1, "one delay between cycles");
    for window in starts.windows(2) {
        let gap = window[1]
            .checked_sub(window[0])
            .expect("the clock advanced between cycles");
        assert!(gap >= FIFTEEN_MINUTES, "gap {gap:?} below the period");
        assert!(
            gap <= FIFTEEN_MINUTES + TEN_PERCENT_SPAN,
            "gap {gap:?} above the jitter bound"
        );
    }
}

#[test]
fn the_loop_never_overlaps_itself_across_a_thousand_cycles() {
    let schedule = ScheduleConfig::plan_defaults();
    let (mut sleeper, now) = VirtualSleeper::new();
    let trace: SharedTrace = Rc::default();
    // The reentrancy assertion inside every tick is the property: a second
    // overlapping cycle would trip it before this report ever read.
    let mut cycle = TracedCycle::new(&now, &trace, Some(1_000));
    let mut body = |cancel: &Cancel| cycle.tick(cancel);

    let report = run(
        &schedule,
        &Cancel::new(),
        &mut FixedBits(0),
        &mut sleeper,
        &mut body,
    );

    assert_eq!(report.cycles_completed, 1_000);
    assert_eq!(report.stop, LoopStop::Cancelled);
    assert_eq!(trace.cursor.borrow().len(), 1_000);
}

#[test]
fn cancellation_before_start_runs_no_cycles() {
    let schedule = ScheduleConfig::plan_defaults();
    let (mut sleeper, now) = VirtualSleeper::new();
    let trace: SharedTrace = Rc::default();
    let mut cycle = TracedCycle::new(&now, &trace, None);
    let mut body = |cancel: &Cancel| cycle.tick(cancel);

    let cancel = Cancel::new();
    cancel.cancel();
    let report = run(
        &schedule,
        &cancel,
        &mut FixedBits(0),
        &mut sleeper,
        &mut body,
    );

    assert_eq!(
        report,
        LoopReport {
            cycles_completed: 0,
            stop: LoopStop::Cancelled,
        }
    );
    assert!(trace.starts.borrow().is_empty());
    assert!(sleeper.delays().is_empty());
}

#[test]
fn a_cancel_during_a_cycle_lets_it_finish_and_stops_the_loop() {
    let schedule = ScheduleConfig::plan_defaults();
    let (mut sleeper, now) = VirtualSleeper::new();
    let trace: SharedTrace = Rc::default();
    // The traced cycle cancels itself only after its full body ran, so the
    // trace records the complete bounded step a restart would resume from.
    let mut cycle = TracedCycle::new(&now, &trace, Some(1));
    let mut body = |cancel: &Cancel| cycle.tick(cancel);

    let report = run(
        &schedule,
        &Cancel::new(),
        &mut FixedBits(0),
        &mut sleeper,
        &mut body,
    );

    assert_eq!(
        report,
        LoopReport {
            cycles_completed: 1,
            stop: LoopStop::Cancelled,
        }
    );
    assert_eq!(
        *trace.cursor.borrow(),
        vec![1],
        "the cycle's full step landed"
    );
    assert!(
        sleeper.delays().is_empty(),
        "a cancelled loop never asks for another delay"
    );
}

#[test]
fn a_cancel_during_the_sleep_stops_before_the_next_cycle() {
    let schedule = ScheduleConfig::plan_defaults();
    let (mut sleeper, now) = VirtualSleeper::new();
    let trace: SharedTrace = Rc::default();
    let mut cycle = TracedCycle::new(&now, &trace, None);
    let mut body = |cancel: &Cancel| cycle.tick(cancel);
    sleeper.script_cancellation(1);

    let report = run(
        &schedule,
        &Cancel::new(),
        &mut FixedBits(0),
        &mut sleeper,
        &mut body,
    );

    assert_eq!(report.cycles_completed, 2);
    assert_eq!(report.stop, LoopStop::Cancelled);
    assert_eq!(trace.cursor.borrow().len(), 2);
}

#[test]
fn an_entropy_failure_stops_the_loop_after_its_in_flight_cycle() {
    let schedule = ScheduleConfig::plan_defaults();
    let (mut sleeper, now) = VirtualSleeper::new();
    let trace: SharedTrace = Rc::default();
    let mut cycle = TracedCycle::new(&now, &trace, None);
    let mut body = |cancel: &Cancel| cycle.tick(cancel);

    let report = run(
        &schedule,
        &Cancel::new(),
        &mut DeadEntropy,
        &mut sleeper,
        &mut body,
    );

    assert_eq!(
        report,
        LoopReport {
            cycles_completed: 1,
            stop: LoopStop::EntropyUnavailable,
        }
    );
    assert_eq!(trace.cursor.borrow().len(), 1);
}

// --- restart, marathon, long run -------------------------------------------

#[test]
fn restart_preserves_incremental_progress() {
    let schedule = ScheduleConfig::plan_defaults();
    let (mut first_sleeper, now) = VirtualSleeper::new();
    let trace: SharedTrace = Rc::default();
    let mut first_cycle = TracedCycle::new(&now, &trace, Some(5));
    let mut first_body = |cancel: &Cancel| first_cycle.tick(cancel);

    let first = run(
        &schedule,
        &Cancel::new(),
        &mut FixedBits(0),
        &mut first_sleeper,
        &mut first_body,
    );
    assert_eq!(first.cycles_completed, 5);

    // A restart is a fresh loop — fresh sleeper, fresh cancel, fresh jitter —
    // over the same durable state (here, the shared trace cursor) the first
    // loop maintained.
    let (mut second_sleeper, second_now) = VirtualSleeper::new();
    second_now.set(now.get());
    let mut second_cycle = TracedCycle::new(&second_now, &trace, Some(8));
    let mut second_body = |cancel: &Cancel| second_cycle.tick(cancel);

    let second = run(
        &schedule,
        &Cancel::new(),
        &mut FixedBits(0),
        &mut second_sleeper,
        &mut second_body,
    );
    assert_eq!(second.cycles_completed, 3);

    let cursor = trace.cursor.borrow();
    assert_eq!(cursor.len(), 8, "the restart continued, not restarted");
    for (index, step) in cursor.iter().enumerate() {
        assert_eq!(*step, index as u64 + 1, "progress is strictly incremental");
    }
}

#[test]
fn a_month_scale_marathon_advances_incrementally_with_bounded_bookkeeping() {
    let schedule = ScheduleConfig::plan_defaults();
    let (mut sleeper, now) = VirtualSleeper::new();
    // 2 619 cycles start within the month at the full-span marathon tick
    // (990 s less a nanosecond): cycle n starts at (n-1) · tick, and 2 618
    // ticks end a hair under 2 591 820 s, inside the month's 2 592 000 s —
    // one more tick would not fit.
    let expected_cycles = 2_619u64;
    let trace: SharedTrace = Rc::default();
    let mut cycle = TracedCycle::new(&now, &trace, Some(expected_cycles));
    let mut body = |cancel: &Cancel| cycle.tick(cancel);

    let report = run(
        &schedule,
        &Cancel::new(),
        &mut FixedBits(u64::MAX),
        &mut sleeper,
        &mut body,
    );

    assert_eq!(report.cycles_completed, expected_cycles);
    assert_eq!(report.stop, LoopStop::Cancelled);

    let starts = trace.starts.borrow();
    assert!(
        *starts.last().expect("the marathon ran") <= MONTH,
        "the last cycle still started within the month"
    );

    let delays = sleeper.delays();
    let expected = usize::try_from(expected_cycles).expect("the cycle count fits usize");
    assert_eq!(starts.len(), expected);
    assert_eq!(delays.len(), expected - 1);
    assert!(
        delays.iter().all(|delay| *delay == MARATHON_TICK),
        "every inter-cycle wait is the full marathon tick"
    );
    assert!(
        now.get() + MARATHON_TICK > MONTH,
        "the simulated month cannot fit another marathon tick"
    );

    // Every cycle advanced exactly one bounded step: incremental progress
    // whose per-cycle bound never grows with the run's length. The loop's
    // own bookkeeping is the two-word report — the trace is the test's.
    for (index, step) in trace.cursor.borrow().iter().enumerate() {
        assert_eq!(*step, index as u64 + 1);
    }
}

#[test]
fn a_hundred_thousand_cycle_long_run_stays_uniform() {
    let schedule = ScheduleConfig::plan_defaults();
    let (mut sleeper, now) = VirtualSleeper::new();
    let trace: SharedTrace = Rc::default();
    let mut cycle = TracedCycle::new(&now, &trace, Some(100_000));
    let mut body = |cancel: &Cancel| cycle.tick(cancel);

    let report = run(
        &schedule,
        &Cancel::new(),
        &mut FixedBits(0),
        &mut sleeper,
        &mut body,
    );

    assert_eq!(report.cycles_completed, 100_000);
    let delays = sleeper.delays();
    assert_eq!(delays.len(), 99_999);
    assert!(
        delays.iter().all(|delay| *delay == FIFTEEN_MINUTES),
        "zero jitter holds the exact period across the whole run"
    );
    assert_eq!(
        now.get(),
        FIFTEEN_MINUTES * 99_999,
        "the virtual clock advanced by exactly the delays asked"
    );
    assert_eq!(trace.cursor.borrow().len(), 100_000);
}

// --- clock change -----------------------------------------------------------

/// The host's wall clock lurches mid-run — NTP correction, a manual
/// `date -s`, a timezone or DST change — and a loop that scheduled off it
/// would refire, stall, or skip a cycle at every step. This loop schedules
/// off the monotonic clock alone, so the schedule under a lurching wall
/// clock is exactly the schedule over an untouched one.
#[test]
fn wall_clock_steps_cannot_move_the_cycle_schedule() {
    let schedule = ScheduleConfig::plan_defaults();
    let (mut sleeper, now) = VirtualSleeper::new();
    let trace: SharedTrace = Rc::default();
    let wall = Rc::new(Cell::new(0i64));
    let mut cycle = TracedCycle::new(&now, &trace, Some(6));
    let mut cycles: u64 = 0;
    let mut body = |cancel: &Cancel| {
        cycles += 1;
        cycle.tick(cancel);
        // An hour back, then two hours forward, after every cycle.
        wall.set(wall.get() + if cycles % 2 == 1 { -3_600 } else { 7_200 });
    };

    let report = run(
        &schedule,
        &Cancel::new(),
        &mut FixedBits(0),
        &mut sleeper,
        &mut body,
    );

    assert_eq!(report.cycles_completed, 6);
    assert_eq!(report.stop, LoopStop::Cancelled);
    // The starts are the pure arithmetic — first at once, then one period
    // after each previous return — the same schedule an undisturbed clock
    // would have produced.
    assert_eq!(
        trace.starts.borrow().as_slice(),
        [0, 15, 30, 45, 60, 75].map(Duration::from_mins).as_slice()
    );
    for (index, step) in trace.cursor.borrow().iter().enumerate() {
        assert_eq!(*step, index as u64 + 1, "progress is strictly incremental");
    }
    // The clock really did lurch, ending three hours ahead of a monotonic
    // timeline that has run barely an hour — and it moved nothing.
    assert_eq!(wall.get(), 10_800);
    assert_eq!(now.get(), Duration::from_mins(75));
    assert!(
        sleeper
            .delays()
            .iter()
            .all(|delay| *delay == FIFTEEN_MINUTES),
        "every wait is the exact period the arithmetic asked for"
    );
}

// --- the production sleeper -------------------------------------------------

#[test]
fn the_thread_sleeper_waits_at_least_the_delay() {
    let delay = Duration::from_millis(120);
    let started = std::time::Instant::now();
    let mut sleeper = super::ThreadSleeper;
    let completed = sleeper.sleep(&Cancel::new(), delay);
    let elapsed = started.elapsed();
    assert!(completed, "an uninterrupted wait returns true");
    assert!(
        elapsed >= delay,
        "{elapsed:?} shorter than the {delay:?} asked"
    );
}

#[test]
fn the_thread_sleeper_returns_promptly_on_cancellation() {
    let cancel = Cancel::new();
    let canceller = {
        let cancel = cancel.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            cancel.cancel();
        })
    };

    let started = std::time::Instant::now();
    let mut sleeper = super::ThreadSleeper;
    let completed = sleeper.sleep(&cancel, Duration::from_mins(1));
    let elapsed = started.elapsed();
    canceller.join().expect("the canceller joins");
    assert!(!completed, "a cancelled wait reports itself cancelled");
    assert!(
        elapsed < Duration::from_secs(5),
        "{elapsed:?} to notice a cancel"
    );
}

#[test]
fn an_already_cancelled_wait_returns_at_once() {
    let cancel = Cancel::new();
    cancel.cancel();
    let started = std::time::Instant::now();
    let mut sleeper = super::ThreadSleeper;
    let completed = sleeper.sleep(&cancel, Duration::from_mins(1));
    let elapsed = started.elapsed();
    assert!(!completed);
    assert!(
        elapsed < Duration::from_secs(1),
        "{elapsed:?} for a dead wait"
    );
}
