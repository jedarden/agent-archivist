// SPDX-License-Identifier: Apache-2.0

//! The collection daemon's scheduling loop (plan Section 7.9): one cycle
//! every 15 minutes with up to 10 percent jitter, on monotonic timing,
//! never overlapping itself, until cancellation or a dead jitter source
//! stops it.
//!
//! The loop is the shell around the scheduler's cycle: each cycle body is
//! injected by the caller, and [`run`] does nothing but decide *when* the
//! next cycle starts. The cycle itself — drain the pending spool, give one
//! chunk to every active source, spend the remaining capacity
//! largest-backlog-first — is planned by [`crate::scheduler`] and executed
//! by the Phase 5 collection engine that attaches at the composition root.
//!
//! # Non-overlap by construction
//!
//! [`run`] is a sequential loop: it starts a cycle only after the previous
//! cycle body returned, so two cycles can never run at once no matter how
//! long a cycle takes. The next cycle's delay is measured from the previous
//! cycle's *completion*, not from its start, so a slow or backlogged cycle
//! shifts the schedule rather than stacking a second pass on top of itself.
//! A reentrancy detector inside a cycle body over one hundred thousand
//! simulated cycles proves the property in the module's simulations.
//!
//! # Jitter
//!
//! Each inter-cycle delay is drawn uniformly over
//! `[interval, interval + interval · jitter_percent / 100)` — with the plan
//! defaults, fifteen to sixteen and a half minutes. [`ScheduleConfig::
//! tick_delay`] maps 64 uniform random bits onto that range as a pure
//! function, so the distribution is testable with fixed bit patterns; the
//! bits come from [`crate::upload::OsJitter`], the same entropy seam the
//! upload retry schedule uses. There is no time-based or process-state
//! fallback: two daemons that fell back together would wake together and
//! stampede the server an outage just released. An entropy failure is
//! therefore a stop condition ([`LoopStop::EntropyUnavailable`]), not a
//! degradation — the supervisor restarts the daemon, which reruns the
//! startup path that surfaced the condition.
//!
//! # Monotonic timing
//!
//! Every duration this module computes comes from [`std::time::Instant`],
//! the monotonic clock, and [`ThreadSleeper`] recomputes the remaining wait
//! from an `Instant` deadline each slice. A wall-clock step — NTP
//! correction, timezone or DST change, a manual `date -s` — cannot lengthen
//! or shorten a wait, reorder cycles, or make the loop skip or repeat one;
//! the loop never reads [`std::time::SystemTime`] at all. The clock-change
//! property is structural: [`ScheduleConfig::tick_delay`] is a pure function of
//! configuration and random bits, the sequencing arithmetic runs on the
//! virtual sleeper in the module's simulations, and the production sleeper's
//! only clock is `Instant`.
//!
//! # Cancellation
//!
//! [`Cancel`] is the stop signal. The loop checks it before starting each
//! cycle, so a cancel that arrives while a cycle runs lets that cycle
//! finish — an in-flight spool bundle lands in its consistent, resumable
//! state rather than being abandoned mid-write. The cycle body receives the
//! same handle and may poll it to stop early at its own safe boundaries;
//! between boundaries the loop does not interrupt a cycle, and the moment
//! one returns cancelled the loop stops — no further delay is drawn, no
//! further cycle starts. A cancel during the inter-cycle sleep interrupts
//! the sleep promptly (within [`SLEEP_SLICE`] for [`ThreadSleeper`]) and
//! the loop exits without starting another cycle.
//!
//! # Restart, incremental progress, bounded resources
//!
//! The loop keeps exactly two words of state — a cycle counter and the stop
//! reason ([`LoopReport`]) — and persists nothing: progress lives in the
//! state database and spool the cycle bodies maintain, so a restarted
//! daemon resumes from the durable cursor, never recapturing or losing
//! acknowledged work. Nothing grows with time held: no per-cycle history,
//! no accumulated schedule. The module's month-scale marathon simulation
//! runs a full month of cycles over a virtual clock and checks that
//! every cycle advances incremental progress by a bounded step and that the
//! loop's own bookkeeping stays flat.
//!
//! The first cycle runs immediately on start, before any wait: a restarted
//! daemon resumes draining the spool right away instead of idling a full
//! period over work that has been pending since the crash.

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::ResolvedConfig;
use crate::upload::Jitter;

#[cfg(test)]
mod tests;

/// The longest single wait [`ThreadSleeper`] issues before re-checking the
/// cancellation flag. It bounds how late a cancel can stop a sleeping
/// daemon: the production sleeper never blocks longer than one slice past
/// the cancel, which keeps a service stop prompt without a dedicated
/// wakeup primitive.
pub const SLEEP_SLICE: Duration = Duration::from_millis(100);

/// The plan's daemon schedule: a 15-minute period with up to 10 percent
/// jitter (plan Section 7.9; the defaults `schedule.interval_seconds` and
/// `schedule.jitter_percent` carry in the registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleConfig {
    interval: Duration,
    jitter_percent: u64,
    jitter_span: Duration,
}

/// Why a [`ScheduleConfig`] was refused.
///
/// The variants name the arithmetic fault alone: no value is ever echoed
/// back, keeping the diagnostic content-free the way the rest of the
/// client's surfaces are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleConfigError {
    /// The period is zero or negative. A daemon that sleeps no time at all
    /// is a busy loop against the coding host, never a schedule.
    NonPositiveInterval,
    /// The period is positive but below one second, the floor below which
    /// the loop's per-cycle bookkeeping would dominate the schedule.
    IntervalBelowOneSecond,
    /// The period's jitter arithmetic does not fit the loop's nanosecond
    /// arithmetic — a misconfiguration by orders of magnitude.
    IntervalUnsupported,
    /// The jitter bound is not a percentage (it must be 0 through 100).
    JitterOutOfRange,
}

impl fmt::Display for ScheduleConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = match self {
            Self::NonPositiveInterval => "the scheduling interval must be positive",
            Self::IntervalBelowOneSecond => "the scheduling interval must be at least one second",
            Self::IntervalUnsupported => {
                "the scheduling interval exceeds the loop's supported range"
            }
            Self::JitterOutOfRange => "the scheduling jitter must be a percentage (0 through 100)",
        };
        formatter.write_str(detail)
    }
}

impl Error for ScheduleConfigError {}

impl ScheduleConfig {
    /// A schedule from explicit numbers: the period and the maximum jitter
    /// as a percentage of it. Each cycle waits a uniform draw over
    /// `[interval, interval · (1 + jitter_percent / 100)]`.
    ///
    /// # Errors
    ///
    /// [`ScheduleConfigError::NonPositiveInterval`] or
    /// [`ScheduleConfigError::IntervalBelowOneSecond`] for a period the
    /// daemon cannot run;
    /// [`ScheduleConfigError::IntervalUnsupported`] when the jitter
    /// arithmetic exceeds the loop's nanosecond range;
    /// [`ScheduleConfigError::JitterOutOfRange`] for a jitter bound outside
    /// 0 through 100.
    ///
    /// # Panics
    ///
    /// Never: the overflow check above bounds the span below `u64::MAX`
    /// before it is narrowed into a [`Duration`].
    pub fn new(interval: Duration, jitter_percent: u64) -> Result<Self, ScheduleConfigError> {
        if interval.is_zero() {
            return Err(ScheduleConfigError::NonPositiveInterval);
        }
        if interval < Duration::from_secs(1) {
            return Err(ScheduleConfigError::IntervalBelowOneSecond);
        }
        if jitter_percent > 100 {
            return Err(ScheduleConfigError::JitterOutOfRange);
        }
        let interval_nanos = interval.as_nanos();
        let span_nanos = interval_nanos * u128::from(jitter_percent) / 100;
        if interval_nanos + span_nanos > u128::from(u64::MAX) {
            return Err(ScheduleConfigError::IntervalUnsupported);
        }
        Ok(Self {
            interval,
            jitter_percent,
            jitter_span: Duration::from_nanos(u64::try_from(span_nanos).expect("span fits u64")),
        })
    }

    /// The plan's schedule: 15 minutes, up to 10 percent jitter.
    ///
    /// # Panics
    ///
    /// Never: the plan's numbers pass [`ScheduleConfig::new`] by
    /// construction.
    #[must_use]
    pub fn plan_defaults() -> Self {
        Self::new(Duration::from_mins(15), 10).expect("the plan's schedule is valid")
    }

    /// The schedule resolved from a loaded configuration through the
    /// `schedule.interval_seconds` and `schedule.jitter_percent` accessors.
    /// The loader range-checks both keys against the registry's bounds and
    /// already refuses a non-positive period or a jitter outside
    /// 0 through 100 as usage errors; this constructor restates those faults
    /// so a [`ResolvedConfig`] built by any other path cannot smuggle them
    /// past [`ScheduleConfig::new`]'s arithmetic.
    ///
    /// # Errors
    ///
    /// The same faults [`ScheduleConfig::new`] reports.
    ///
    /// # Panics
    ///
    /// Never: the sign checks above reject a negative period or jitter
    /// before the conversions.
    pub fn from_resolved(config: &ResolvedConfig) -> Result<Self, ScheduleConfigError> {
        let seconds = config.schedule_interval_seconds();
        if seconds <= 0 {
            return Err(ScheduleConfigError::NonPositiveInterval);
        }
        let percent = config.schedule_jitter_percent();
        if percent < 0 {
            return Err(ScheduleConfigError::JitterOutOfRange);
        }
        Self::new(
            Duration::from_secs(u64::try_from(seconds).expect("positive i64 fits u64")),
            u64::try_from(percent).expect("non-negative i64 fits u64"),
        )
    }

    /// The scheduling period.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// The maximum jitter, as a percentage of the period.
    #[must_use]
    pub const fn jitter_percent(&self) -> u64 {
        self.jitter_percent
    }

    /// One inter-cycle delay: the period plus a uniform fraction of the
    /// jitter span, taken from the high bits of `random_bits`. The map is
    /// pure and monotone — identical bits yield identical delays, and
    /// ordered bits yield ordered delays — so simulations are
    /// deterministic. The span is half-open: the draw stays below the
    /// period plus the full span, and the all-ones pattern lands one
    /// nanosecond under it.
    ///
    /// With zero jitter the draw is exactly the period.
    ///
    /// # Panics
    ///
    /// Never: the offset is mapped strictly below the span the constructor
    /// already bounded into `u64`.
    #[must_use]
    pub fn tick_delay(&self, random_bits: u64) -> Duration {
        let span_nanos = self.jitter_span.as_nanos();
        let offset = (span_nanos * u128::from(random_bits)) >> 64;
        let offset =
            u64::try_from(offset).expect("the offset stays below the span the constructor bounded");
        self.interval + Duration::from_nanos(offset)
    }
}

/// The daemon's stop signal. Cloned handles share one flag: the supervisor
/// cancels, the loop checks between cycles, the sleeping
/// [`ThreadSleeper`] polls each [`SLEEP_SLICE`], and the cycle body can
/// poll to stop early at its own safe boundaries.
#[derive(Clone, Debug, Default)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
}

impl Cancel {
    /// A fresh, un-cancelled signal.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request the loop stop. Idempotent; never un-done, so a restart is a
    /// new process with a new signal.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

/// The wait between cycles. The trait exists so the loop's sequencing is
/// testable on a virtual clock: production passes [`ThreadSleeper`], the
/// simulations pass a scripted sleeper that returns instantly.
pub trait Sleeper {
    /// Wait for `delay`. Returns `true` when the full delay passed without
    /// cancellation, `false` when `cancel` fired first — the contract the
    /// loop's stop decision rests on. A sleeper that hangs past
    /// cancellation only delays the stop; it can never start a second
    /// cycle, because the loop is sequential.
    fn sleep(&mut self, cancel: &Cancel, delay: Duration) -> bool;
}

/// The production sleeper: sliced real waits measured against one
/// monotonic `Instant` deadline.
///
/// The deadline is taken once, before the first slice, and the remaining
/// wait is recomputed from `Instant::now()` each time a slice ends — so a
/// wall-clock step during the wait changes nothing the loop can observe.
/// Each slice is at most [`SLEEP_SLICE`], after which the cancellation
/// flag is re-checked.
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&mut self, cancel: &Cancel, delay: Duration) -> bool {
        let deadline = Instant::now() + delay;
        while !cancel.is_cancelled() {
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            thread::sleep(SLEEP_SLICE.min(deadline - now));
        }
        false
    }
}

/// Why the loop stopped. The daemon runs until one of these two conditions;
/// there is no third — a cycle body's own failures are its business, and
/// the loop keeps scheduling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopStop {
    /// The stop signal fired. This is the normal shutdown, including a
    /// supervisor's service stop.
    Cancelled,
    /// The jitter source failed. The loop never schedules an un-jittered
    /// cycle: without entropy the schedule degrades into a synchronized
    /// fixed-period loop, which the design refuses. The supervisor's
    /// restart surfaces the condition on the next startup.
    EntropyUnavailable,
}

/// What one [`run`] did. Two words, deliberately: the loop's whole
/// bookkeeping, so nothing accumulates over a month-scale run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopReport {
    /// Cycle bodies that ran to return. A cycle that stopped itself early
    /// on cancellation still counts: it returned, and its partial progress
    /// is durable in the state it maintains.
    pub cycles_completed: u64,
    /// Why the loop stopped.
    pub stop: LoopStop,
}

/// Run the daemon loop until cancellation or entropy failure.
///
/// The first cycle starts immediately — a restarted daemon resumes pending
/// work without waiting a period — and each subsequent cycle starts one
/// jittered delay after the previous cycle *returned*. The loop never
/// starts a cycle while another is in flight: it is a single sequential
/// loop, so self-overlap is impossible by construction, not by locking.
///
/// `cycle` receives the [`Cancel`] handle and may poll it to stop early at
/// its own boundaries; whatever it makes durable is the progress a restart
/// resumes from. A cancel that arrives while a cycle runs stops the loop
/// the moment that cycle returns: no further delay is drawn and no further
/// cycle starts.
///
/// `jitter` is the entropy seam ([`crate::upload::OsJitter`] in
/// production). Its failure stops the loop with
/// [`LoopStop::EntropyUnavailable`] *after* the in-flight cycle, which
/// completed and made its progress durable.
#[must_use]
pub fn run(
    schedule: &ScheduleConfig,
    cancel: &Cancel,
    jitter: &mut impl Jitter,
    sleeper: &mut impl Sleeper,
    mut cycle: impl FnMut(&Cancel),
) -> LoopReport {
    let mut cycles_completed = 0u64;
    loop {
        if cancel.is_cancelled() {
            return LoopReport {
                cycles_completed,
                stop: LoopStop::Cancelled,
            };
        }
        cycle(cancel);
        cycles_completed = cycles_completed.saturating_add(1);
        if cancel.is_cancelled() {
            // A cycle that ended on cancellation has made what it will make
            // durable; stop here rather than draw entropy for a wait no
            // cycle will follow.
            return LoopReport {
                cycles_completed,
                stop: LoopStop::Cancelled,
            };
        }
        let Ok(bits) = jitter.random_bits() else {
            return LoopReport {
                cycles_completed,
                stop: LoopStop::EntropyUnavailable,
            };
        };
        if !sleeper.sleep(cancel, schedule.tick_delay(bits)) {
            return LoopReport {
                cycles_completed,
                stop: LoopStop::Cancelled,
            };
        }
    }
}
