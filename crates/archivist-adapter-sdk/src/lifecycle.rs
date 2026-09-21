// SPDX-License-Identifier: Apache-2.0

//! The adapter lifecycle interface (plan Phase 6D: "publish adapter
//! lifecycle, capability, status, and projection interfaces"): the
//! observable states every adapter moves through, and the close contract
//! the client engine relies on.
//!
//! The lifecycle is deliberately minimal — three states, one
//! transition rule — because everything time-varying about a source
//! adapter's health is already a status concern (the coverage and
//! classification vocabularies of [`crate::status`]). What remains for
//! the lifecycle to own is disposal:
//!
//! - **Close is total and idempotent.** `close` always succeeds, and
//!   closing twice is the same as closing once. An adapter holds
//!   source-adjacent resources (file handles, database connections);
//!   the engine must be able to release them exactly once per shutdown
//!   path, including error paths that race each other.
//! - **Closed fails closed.** A closed adapter's reads report
//!   [`ScanClassification::NotObserved`] — the source was simply not
//!   covered — rather than a transport error that would page an
//!   operator for a shutdown the engine itself performed.
//! - **The state is observable without content.** `state` returns a
//!   closed-vocabulary token and nothing else, so the engine can log
//!   and assert on it.

use crate::status::ScanClassification;

/// The observable lifecycle state of one adapter instance. Closed
/// vocabulary, ordered: `Constructed` before first use, `Ready` while
/// capture may proceed, `Closed` once `close` has run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LifecycleState {
    /// Constructed but not yet usable: configuration has not been
    /// validated against the sources.
    #[default]
    Constructed,
    /// Ready: discovery and capture may proceed.
    Ready,
    /// Closed by [`AdapterLifecycle::close`]; terminal. Reads on a
    /// closed adapter report `NotObserved`.
    Closed,
}

impl LifecycleState {
    /// Every state, in transition order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Constructed, Self::Ready, Self::Closed]
    }

    /// The canonical token for this state.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Constructed => "constructed",
            Self::Ready => "ready",
            Self::Closed => "closed",
        }
    }

    /// Parse one token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`archivist_protocol::vocabulary::GrammarError::NotCanonical`]
    /// for a token outside the closed set.
    pub fn parse(text: &str) -> Result<Self, archivist_protocol::vocabulary::GrammarError> {
        match text {
            "constructed" => Ok(Self::Constructed),
            "ready" => Ok(Self::Ready),
            "closed" => Ok(Self::Closed),
            _ => Err(archivist_protocol::vocabulary::GrammarError::NotCanonical),
        }
    }

    /// Whether capture may proceed in this state: only `Ready`.
    #[must_use]
    pub fn allows_capture(self) -> bool {
        matches!(self, Self::Ready)
    }
}

impl std::fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

/// The lifecycle contract every source adapter implements (plan Phase
/// 6D). Construction is the implementing type's own; the interface owns
/// observation and disposal.
pub trait AdapterLifecycle {
    /// The adapter's current lifecycle state.
    fn state(&self) -> LifecycleState;

    /// Release every source-adjacent resource this adapter holds and
    /// enter [`LifecycleState::Closed`]. Idempotent: calling `close` on
    /// an already-closed adapter changes nothing and never fails.
    fn close(&mut self);

    /// The classification a capture attempt gets in this state: `Ok`
    /// only when [`LifecycleState::Ready`], `NotObserved` otherwise —
    /// a read against a non-ready adapter is a shutdown-shaped
    /// non-observation, not a source failure.
    fn capture_classification(&self) -> ScanClassification {
        if self.state().allows_capture() {
            ScanClassification::Ok
        } else {
            ScanClassification::NotObserved
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal adapter exercising the contract's transition and
    /// idempotence rules.
    #[derive(Default)]
    struct FixtureAdapter {
        state: LifecycleState,
        closes: usize,
    }

    impl AdapterLifecycle for FixtureAdapter {
        fn state(&self) -> LifecycleState {
            self.state
        }

        fn close(&mut self) {
            // The release itself is guarded: two shutdown paths racing
            // each other release the resources exactly once.
            if self.state != LifecycleState::Closed {
                self.closes += 1;
                self.state = LifecycleState::Closed;
            }
        }
    }

    #[test]
    fn states_round_trip_and_fail_closed() {
        for state in LifecycleState::all() {
            assert_eq!(LifecycleState::parse(state.token()).as_ref(), Ok(state));
        }
        assert!(LifecycleState::parse("degraded").is_err());
        assert!(LifecycleState::parse("").is_err());
        assert!(LifecycleState::parse("Ready").is_err());
    }

    #[test]
    fn only_ready_allows_capture() {
        assert!(!LifecycleState::Constructed.allows_capture());
        assert!(LifecycleState::Ready.allows_capture());
        assert!(!LifecycleState::Closed.allows_capture());
    }

    #[test]
    fn close_is_idempotent_and_closed_reads_are_not_observations() {
        let mut adapter = FixtureAdapter {
            state: LifecycleState::Ready,
            closes: 0,
        };
        assert_eq!(adapter.capture_classification(), ScanClassification::Ok);

        adapter.close();
        adapter.close();
        assert_eq!(adapter.state(), LifecycleState::Closed);
        // Two shutdown paths raced each other; the resources were
        // released exactly once.
        assert_eq!(adapter.closes, 1);

        // A capture attempt after close is a non-observation, not a
        // transport error: nothing pages an operator for a shutdown the
        // engine itself performed.
        assert_eq!(
            adapter.capture_classification(),
            ScanClassification::NotObserved
        );
    }
}
