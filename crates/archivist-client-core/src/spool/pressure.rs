// SPDX-License-Identifier: Apache-2.0

//! The spool/free-disk high-water policy's state and thresholds (plan
//! Section 7.9, `EC-11`, requirement OPS-003): the limits, the
//! conditions they produce, and the gate that latches the pause
//! decision between evaluations.
//!
//! A client whose server is unreachable must stop growing before it
//! disrupts the coding host, but it must stop *predictably and visibly*:
//! an ingestion outage may never translate into unbounded spool growth
//! that nobody can see. The policy is a pair of high-water conditions and
//! one latched decision over them:
//!
//! - **spool cap** — total live spool bytes at or above
//!   `spool.max_bytes` (default 2 GiB). Live means every `spool_entries`
//!   row not yet `acknowledged`: those are exactly the bundles whose
//!   bytes are on disk waiting for a receipt.
//! - **free-space floor** — filesystem free space at or below
//!   `spool.free_floor_bytes` (default 5 GiB), measured on the filesystem
//!   holding the spool directory as the bytes available to unprivileged
//!   writes (`statvfs` `f_bavail * f_frsize`, the number `df` reports).
//!
//! At either condition the gate pauses **new materialization only**.
//! Retries, uploads, receipt handling, acknowledgement, and the cleanup
//! those acknowledgements trigger are outside the policy — draining
//! pending work is the only way the spool shrinks, so nothing may block
//! it. The cursor side of the same degradation (cursors held in front of
//! the uncaptured range while the backlog stays visible) is the inventory
//! pass's `degraded` flag; this module is the pressure side of that
//! flag.
//!
//! **Resuming is deliberately harder than pausing.** A paused gate
//! resumes only when live usage has fallen strictly below
//! `spool.resume_percent` percent of the cap (default 80) *and* the
//! free-space floor has recovered — strictly more free bytes than the
//! floor. Between the resume point and the cap the gate stays paused
//! and names `draining` as its reason, so a spool hovering at the
//! watermark cannot flap capture on and off. The latch lives in the
//! gate, not the state database: the facts (row states, sizes) are
//! durable and shared, while the pause is a decision one mutator
//! re-derives, and a gate that never observed a pause is open below the
//! cap exactly as a fresh daemon is.
//!
//! **Nothing about the pause is silent.** Every evaluation returns a
//! [`PressureStatus`] that states whether materialization is admitted
//! and, when it is not, names every degraded reason as a closed-set
//! token. Admission is enforced at the one production entry point that
//! puts bytes on disk — [`Spool::materialize`](super::Spool::materialize)
//! evaluates the gate it is handed before it writes anything, and a
//! held admission is the distinct
//! [`super::SpoolErrorKind::MaterializationPaused`]
//! — so there is no ungated materialization path to bypass the policy
//! with. The `status`/`doctor` renderings of the evaluation are later
//! Phase 5 deliverables; the renderings are content-free by the same rule as
//! [`SpoolError`](super::SpoolError): the token set is closed, the
//! numbers are counts, and no rendering can carry the spool path, a
//! bundle name, or transcript content.
//!
//! Unmeasurable is not admissible: when the usage sum or the filesystem
//! probe fails, evaluation fails and the caller must hold materialization
//! — the failure mode of the policy is the same direction as the policy.

use archivist_protocol::json::{Object, Value};

use super::{Spool, SpoolError, live_usage_bytes};
use crate::state::StateStore;

#[cfg(test)]
mod tests;

/// The policy's numeric shape, resolved from `spool.max_bytes`,
/// `spool.free_floor_bytes`, and `spool.resume_percent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PressureLimits {
    spool_cap_bytes: u64,
    free_floor_bytes: u64,
    resume_percent: u64,
}

impl PressureLimits {
    /// Limits from explicit numbers, the shape synthetic tests and future
    /// non-config constructors use.
    ///
    /// The arithmetic stays defined for every input: a cap of zero pauses
    /// at any usage; a floor of zero breaches only when the filesystem
    /// reports no free bytes at all; a resume percent above 100 puts the
    /// resume threshold above the cap, so the cap condition alone governs
    /// the pause; a resume percent of zero never resumes.
    #[must_use]
    pub const fn new(spool_cap_bytes: u64, free_floor_bytes: u64, resume_percent: u64) -> Self {
        Self {
            spool_cap_bytes,
            free_floor_bytes,
            resume_percent,
        }
    }

    /// Limits from a loaded configuration's `spool.*` keys.
    ///
    /// # Panics
    ///
    /// Never in practice: the three keys carry registry defaults and
    /// integer bounds, so a configuration this load returned resolves
    /// all of them to positive in-range values.
    #[must_use]
    pub fn from_config(config: &crate::config::ResolvedConfig) -> Self {
        Self {
            spool_cap_bytes: u64::try_from(config.spool_max_bytes())
                .expect("registry bounds fix spool.max_bytes positive"),
            free_floor_bytes: u64::try_from(config.spool_free_floor_bytes())
                .expect("registry bounds fix spool.free_floor_bytes positive"),
            resume_percent: u64::try_from(config.spool_resume_percent())
                .expect("registry bounds fix spool.resume_percent in 0..=100"),
        }
    }

    /// The spool high-water cap: usage at or above it pauses new
    /// materialization.
    #[must_use]
    pub const fn spool_cap_bytes(&self) -> u64 {
        self.spool_cap_bytes
    }

    /// The filesystem free-space floor: free space at or below it pauses
    /// new materialization.
    #[must_use]
    pub const fn free_floor_bytes(&self) -> u64 {
        self.free_floor_bytes
    }

    /// The resume point as a percentage of the cap.
    #[must_use]
    pub const fn resume_percent(&self) -> u64 {
        self.resume_percent
    }

    /// The usage a paused gate must fall strictly below before it
    /// resumes: the cap scaled by the resume percent, computed so no
    /// intermediate can overflow.
    #[must_use]
    pub fn resume_threshold_bytes(&self) -> u64 {
        self.spool_cap_bytes.saturating_mul(self.resume_percent) / 100
    }
}

/// The degraded reasons one evaluation can name: a closed set of flags,
/// never free text and never a path.
///
/// The spool-cap and free-floor flags name the high-water conditions
/// live right now. The draining flag names the latched hold that remains
/// after both conditions clear but usage is still at or above the resume
/// threshold — degraded, but by the resume rule rather than a limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PressureReasons {
    spool_cap: bool,
    free_floor: bool,
    draining: bool,
}

impl PressureReasons {
    /// No reason: materialization is admitted.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            spool_cap: false,
            free_floor: false,
            draining: false,
        }
    }

    /// Whether any degraded reason is named.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        self.spool_cap || self.free_floor || self.draining
    }

    /// Live spool usage reached the high-water cap.
    #[must_use]
    pub const fn spool_cap_reached(&self) -> bool {
        self.spool_cap
    }

    /// Filesystem free space fell to the floor or below it.
    #[must_use]
    pub const fn free_floor_breached(&self) -> bool {
        self.free_floor
    }

    /// A high-water pause is still holding while usage drains toward the
    /// resume threshold; no high-water condition is live.
    #[must_use]
    pub const fn draining(&self) -> bool {
        self.draining
    }

    /// The reason tokens in canonical order, for the status document.
    #[must_use]
    pub fn tokens(&self) -> Vec<&'static str> {
        let mut tokens = Vec::new();
        if self.spool_cap {
            tokens.push("spool_cap");
        }
        if self.free_floor {
            tokens.push("free_floor");
        }
        if self.draining {
            tokens.push("draining");
        }
        tokens
    }
}

impl std::fmt::Display for PressureReasons {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.is_degraded() {
            return f.write_str("no degraded condition");
        }
        let mut first = true;
        for (live, phrase) in [
            (self.spool_cap, "spool at the high-water cap"),
            (
                self.free_floor,
                "filesystem free space at or below the floor",
            ),
            (self.draining, "spool draining toward the resume point"),
        ] {
            if live {
                if !first {
                    f.write_str("; ")?;
                }
                f.write_str(phrase)?;
                first = false;
            }
        }
        Ok(())
    }
}

/// What one gate evaluation decided: whether new materialization is
/// admitted, the degraded reasons when it is not, and the measurements
/// the decision ran on. Counts and closed tokens only — the type cannot
/// carry a path, a bundle name, or transcript content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PressureStatus {
    paused: bool,
    reasons: PressureReasons,
    spool_bytes: u64,
    free_bytes: u64,
    limits: PressureLimits,
}

impl PressureStatus {
    /// Whether the policy admits new materialization.
    #[must_use]
    pub const fn admits_materialization(&self) -> bool {
        !self.paused
    }

    /// Whether any degraded reason is named.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        self.reasons.is_degraded()
    }

    /// The degraded reasons; empty flags when materialization is
    /// admitted.
    #[must_use]
    pub const fn degraded_reasons(&self) -> PressureReasons {
        self.reasons
    }

    /// The live spool usage this evaluation measured.
    #[must_use]
    pub const fn spool_bytes(&self) -> u64 {
        self.spool_bytes
    }

    /// The filesystem free space this evaluation measured.
    #[must_use]
    pub const fn free_bytes(&self) -> u64 {
        self.free_bytes
    }

    /// The limits this evaluation applied.
    #[must_use]
    pub const fn limits(&self) -> &PressureLimits {
        &self.limits
    }

    /// The status-JSON value: admission, reason tokens, measurements,
    /// and the applied limits. One versioned-shape object the daemon,
    /// `status --json`, and `doctor` can render as-is.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set(
            "admits_materialization",
            Value::Bool(self.admits_materialization()),
        );
        object.set("degraded", Value::Bool(self.is_degraded()));
        let reasons = self
            .reasons
            .tokens()
            .into_iter()
            .map(|token| Value::Text(String::from(token)))
            .collect::<Vec<_>>();
        object.set("reasons", Value::Array(reasons));
        object.set("spool_bytes", Value::Int(bounded_i64(self.spool_bytes)));
        object.set("free_bytes", Value::Int(bounded_i64(self.free_bytes)));
        object.set(
            "spool_cap_bytes",
            Value::Int(bounded_i64(self.limits.spool_cap_bytes)),
        );
        object.set(
            "free_floor_bytes",
            Value::Int(bounded_i64(self.limits.free_floor_bytes)),
        );
        object.set(
            "resume_threshold_bytes",
            Value::Int(bounded_i64(self.limits.resume_threshold_bytes())),
        );
        Value::Object(object)
    }
}

impl std::fmt::Display for PressureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.paused {
            write!(f, "materialization paused: {}", self.reasons)
        } else {
            f.write_str("materialization admitted")
        }
    }
}

/// The high-water gate: the limits plus the one bit of latched state the
/// hysteresis needs.
///
/// One mutator holds one gate for the life of its scheduling loop and
/// evaluates it against fresh measurements before every new
/// materialization — enforced at [`Spool::materialize`](super::Spool::materialize),
/// which evaluates the gate it is handed before it writes anything.
/// The gate is not `Clone` and not shareable by accident: two gates
/// over one spool would have two latches and the hysteresis would mean
/// nothing. The decision itself is always derived from the shared
/// pressure state — the live byte sum in the state database and the
/// filesystem probe — never from a copy taken earlier.
pub struct PressureGate {
    limits: PressureLimits,
    paused: bool,
}

impl PressureGate {
    /// An open gate under `limits`: nothing has paused yet, so materialization
    /// below the cap is admitted exactly as a fresh daemon admits it.
    #[must_use]
    pub const fn new(limits: PressureLimits) -> Self {
        Self {
            limits,
            paused: false,
        }
    }

    /// The limits this gate enforces.
    #[must_use]
    pub const fn limits(&self) -> &PressureLimits {
        &self.limits
    }

    /// Whether the gate is currently holding new materialization.
    #[must_use]
    pub const fn is_paused(&self) -> bool {
        self.paused
    }

    /// Evaluate the policy against explicit measurements — the pure
    /// decision every other entry point funnels through.
    ///
    /// Entering the pause takes one live high-water condition: usage at
    /// or above the cap, or free space at or below the floor. Leaving
    /// it takes both recovered: usage strictly below the resume
    /// threshold *and* free space strictly above the floor. Between the
    /// threshold and the cap a paused gate stays paused and names
    /// `draining`.
    #[must_use]
    pub fn evaluate(&mut self, spool_bytes: u64, free_bytes: u64) -> PressureStatus {
        let cap_live = spool_bytes >= self.limits.spool_cap_bytes;
        let floor_live = free_bytes <= self.limits.free_floor_bytes;
        if self.paused {
            // Usage below the threshold already denies the cap condition,
            // so only the floor needs its own check here.
            if spool_bytes < self.limits.resume_threshold_bytes() && !floor_live {
                self.paused = false;
            }
        } else if cap_live || floor_live {
            self.paused = true;
        }
        let reasons = if !self.paused {
            PressureReasons::none()
        } else if cap_live || floor_live {
            PressureReasons {
                spool_cap: cap_live,
                free_floor: floor_live,
                draining: false,
            }
        } else {
            PressureReasons {
                draining: true,
                ..PressureReasons::none()
            }
        };
        PressureStatus {
            paused: self.paused,
            reasons,
            spool_bytes,
            free_bytes,
            limits: self.limits,
        }
    }

    /// Evaluate against the live spool: sum the not-yet-acknowledged
    /// entry bytes and probe the spool filesystem's free space.
    ///
    /// # Errors
    ///
    /// [`SpoolErrorKind::Unavailable`](super::SpoolErrorKind::Unavailable)
    /// or [`SpoolErrorKind::Busy`](super::SpoolErrorKind::Busy) when
    /// either measurement cannot be taken. A gate that cannot measure
    /// cannot admit: the caller holds materialization and surfaces the
    /// error, the same direction the policy points.
    pub fn evaluate_spool(
        &mut self,
        spool: &Spool,
        store: &StateStore,
    ) -> Result<PressureStatus, SpoolError> {
        let spool_bytes = live_usage_bytes(store)?;
        let free_bytes = spool.free_space_bytes()?;
        Ok(self.evaluate(spool_bytes, free_bytes))
    }
}

/// A `u64` count as the JSON integer type, clamped at its ceiling: the
/// values are disk bytes, and a count that cannot fit `i64` still
/// compares correctly against every bound the registry allows.
fn bounded_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
