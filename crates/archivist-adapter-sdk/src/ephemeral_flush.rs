// SPDX-License-Identifier: Apache-2.0

//! Flush-before-teardown integration for ephemeral work (plan Phase 9;
//! requirement CAP-007; threat `EC-10`).
//!
//! An ephemeral job — a one-shot run whose process exit is the whole
//! lifecycle — cannot lean on a later pass to finish its capture: once
//! teardown runs, nothing retries it. [`EphemeralFlushGate`] makes the
//! flush-before-teardown ordering the only path to a completion claim.
//! Every logical inference the job ran is closed through the gate (the
//! observer's close already drives the sink acknowledgement), and the
//! gate mints [`EphemeralCompletion::Complete`] only when the sink's
//! durable acknowledgement covers every recorded teardown and no
//! bounded cause cut the wait short.
//!
//! The acknowledgement is the sink's own [`FlushState::Acknowledged`]
//! — the same seam [`InferenceObserver::close_logical_inference`]
//! gates a single logical inference on. This integration adds no new
//! acknowledgement path (exact capture cannot invent one); it adds the
//! job-level aggregate, the policy gate, and the bounded abandonment
//! vocabulary.
//!
//! - **Policy.** When complete exact capture is policy-mandated
//!   ([`EphemeralCapturePolicy::RequireCompleteCapture`]; CAP-007's
//!   "if complete coverage is claimed"), an incomplete flush becomes a
//!   bounded [`IntegrationFailure::FlushIncomplete`] that withholds the
//!   job's completion. Under
//!   [`EphemeralCapturePolicy::BestEffort`] the same incomplete flush
//!   is still recorded explicitly — state, cause, outcome — but is not
//!   escalated to a failure: the job reports its coverage gap instead
//!   of claiming coverage.
//! - **Never fabricated.** [`EphemeralCompletion::Complete`] requires
//!   at least one recorded teardown, every one of them acknowledged,
//!   and no abandonment. A teardown that recorded nothing has no
//!   acknowledgement to gate on, so it fails closed rather than
//!   minting a vacuous claim.
//! - **Abandonment is explicit.** Timeout, cancellation, auth pause,
//!   and storage outage each arrive as a [`FlushAbandonment`] cause
//!   and each leaves the report [`EphemeralCompletion::Incomplete`]
//!   with [`FlushState::Incomplete`]. A teardown that abandoned the
//!   wait cannot vouch for an acknowledgement it stopped observing, so
//!   the gate fails closed even when every earlier close happened to
//!   be acknowledged before the cause fired.

use std::fmt;

use archivist_protocol::vocabulary::GrammarError;

use crate::expected_inference::IntegrationFailure;
use crate::inference_observer::{
    FlushState, InferenceObserver, InferenceObserverError, LogicalInferenceClose,
};

/// Why an ephemeral teardown abandoned the acknowledgement wait
/// (threat `EC-10`'s flush negatives).
///
/// The cause is recorded on the teardown report explicitly; it can only
/// withhold completion, never claim it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FlushAbandonment {
    /// The teardown deadline expired before the acknowledgement
    /// arrived.
    Timeout,
    /// The ephemeral work was cancelled — operator interrupt or a
    /// parent's cancellation — before the wait could finish.
    Cancelled,
    /// The authenticated delivery path is paused pending authorization,
    /// so the flush cannot reach the normal client path.
    AuthPause,
    /// The storage path behind the sink is unavailable.
    StorageOutage,
}

impl FlushAbandonment {
    /// Every v1 abandonment cause in stable order.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::Timeout,
            Self::Cancelled,
            Self::AuthPause,
            Self::StorageOutage,
        ]
    }

    /// The bounded token used in diagnostics and status projections.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::AuthPause => "auth_pause",
            Self::StorageOutage => "storage_outage",
        }
    }

    /// Parse one v1 token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] when `text` is not a v1
    /// abandonment-cause token.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "timeout" => Ok(Self::Timeout),
            "cancelled" => Ok(Self::Cancelled),
            "auth_pause" => Ok(Self::AuthPause),
            "storage_outage" => Ok(Self::StorageOutage),
            _ => Err(GrammarError::NotCanonical),
        }
    }
}

impl fmt::Display for FlushAbandonment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// Whether the ephemeral job's completion claim is gated on the
/// durable flush acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EphemeralCapturePolicy {
    /// Complete exact capture is policy-mandated (CAP-007): completion
    /// is withheld — and a bounded
    /// [`IntegrationFailure::FlushIncomplete`] recorded — until the
    /// sink acknowledges the flush.
    RequireCompleteCapture,
    /// Coverage is best-effort: an incomplete flush is still recorded
    /// explicitly and still withholds the completion claim, but it is
    /// reported as the job's coverage gap rather than escalated to an
    /// integration failure.
    BestEffort,
}

impl EphemeralCapturePolicy {
    /// Every v1 policy in stable order.
    #[must_use]
    pub const fn all() -> [Self; 2] {
        [Self::RequireCompleteCapture, Self::BestEffort]
    }

    /// The bounded token used in configuration and diagnostics.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::RequireCompleteCapture => "require_complete_capture",
            Self::BestEffort => "best_effort",
        }
    }

    /// Parse one v1 token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] when `text` is not a v1
    /// policy token.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "require_complete_capture" => Ok(Self::RequireCompleteCapture),
            "best_effort" => Ok(Self::BestEffort),
            _ => Err(GrammarError::NotCanonical),
        }
    }
}

impl fmt::Display for EphemeralCapturePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// The completion claim one ephemeral teardown may publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EphemeralCompletion {
    /// Every recorded teardown was acknowledged and nothing was
    /// abandoned: the job may claim complete exact capture.
    Complete,
    /// The flush did not reach a durable acknowledgement across all
    /// recorded teardowns, or the wait was abandoned: completion is
    /// withheld and the gap is explicit.
    Incomplete,
}

/// The bounded report an ephemeral teardown publishes: the explicit
/// flush state, any bounded abandonment cause, and the completion
/// claim the evidence supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EphemeralFlushReport {
    /// The aggregate flush state across every recorded teardown:
    /// acknowledged only when each close was acknowledged and nothing
    /// was abandoned; incomplete once any close was unacknowledged or
    /// the wait was abandoned; not started when nothing was recorded.
    pub flush_state: FlushState,
    /// The bounded cause the acknowledgement wait was abandoned, when
    /// one applied. Presence alone withholds completion.
    pub abandonment: Option<FlushAbandonment>,
    /// The completion claim: `Complete` only when at least one
    /// teardown was recorded, every one acknowledged, and no
    /// abandonment.
    pub outcome: EphemeralCompletion,
    /// The policy this gate applied.
    pub policy: EphemeralCapturePolicy,
    /// The bounded failure, when the policy mandated complete capture
    /// and the outcome withheld it.
    pub failure: Option<IntegrationFailure>,
    /// How many logical inferences were torn down through this gate.
    pub logical_inferences: u64,
    /// How many of those teardowns the sink acknowledged.
    pub acknowledged: u64,
    /// Canonical artifacts the sinks accepted across recorded
    /// teardowns. Emitted is not acknowledged: when the flush state is
    /// incomplete these artifacts' durability is not covered.
    pub emitted_artifacts: u64,
}

/// The flush-before-teardown integration for one ephemeral job.
///
/// The job closes every logical inference it ran through the gate —
/// directly ([`EphemeralFlushGate::teardown`]) or by recording the
/// close report its integration already produced
/// ([`EphemeralFlushGate::record`]) — and finishes teardown exactly
/// once, either orderly ([`EphemeralFlushGate::finish`]) or abandoned
/// for a bounded cause ([`EphemeralFlushGate::abandon`]). A logical
/// inference that is never closed through the gate counts toward
/// nothing: its work cannot support a completion claim, which is the
/// property that keeps an unflushed exit from fabricating one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EphemeralFlushGate {
    policy: EphemeralCapturePolicy,
    logical_inferences: u64,
    acknowledged: u64,
    unacknowledged: u64,
    emitted_artifacts: u64,
    abandoned: Option<FlushAbandonment>,
}

impl EphemeralFlushGate {
    /// Construct a gate applying `policy` to one ephemeral job.
    #[must_use]
    pub const fn new(policy: EphemeralCapturePolicy) -> Self {
        Self {
            policy,
            logical_inferences: 0,
            acknowledged: 0,
            unacknowledged: 0,
            emitted_artifacts: 0,
            abandoned: None,
        }
    }

    /// The policy this gate applies.
    #[must_use]
    pub const fn policy(&self) -> EphemeralCapturePolicy {
        self.policy
    }

    /// How many logical inferences have been torn down through this
    /// gate so far.
    #[must_use]
    pub const fn logical_inferences(&self) -> u64 {
        self.logical_inferences
    }

    /// How many of the recorded teardowns the sink acknowledged so far.
    #[must_use]
    pub const fn acknowledged(&self) -> u64 {
        self.acknowledged
    }

    /// The aggregate flush state so far. A later abandonment overrides
    /// this to [`FlushState::Incomplete`] in the final report.
    #[must_use]
    pub const fn flush_state(&self) -> FlushState {
        if self.unacknowledged > 0 {
            FlushState::Incomplete
        } else if self.logical_inferences > 0 {
            FlushState::Acknowledged
        } else {
            FlushState::NotStarted
        }
    }

    /// Close one observer's logical inference through the gate: the
    /// observer flushes and reports its bounded close, and the gate
    /// records it. This is the flush-before-teardown step itself — the
    /// only way a logical inference counts toward the job's completion
    /// claim is by being closed here, or recorded from the
    /// integration's own close report, before teardown finishes.
    ///
    /// # Errors
    /// [`InferenceObserverError`] when the observer refuses the close
    /// (not started, or already closed). The gate records nothing in
    /// that case.
    pub fn teardown<O: InferenceObserver>(
        &mut self,
        observer: &mut O,
    ) -> Result<LogicalInferenceClose, InferenceObserverError> {
        let close = observer.close_logical_inference()?;
        self.record(&close);
        Ok(close)
    }

    /// Record one logical inference's close report — flush evidence an
    /// integration collected itself, such as a completion report's
    /// close — into the job's aggregate. Returns the number of
    /// teardowns recorded so far.
    pub fn record(&mut self, close: &LogicalInferenceClose) -> u64 {
        self.logical_inferences = self.logical_inferences.saturating_add(1);
        self.emitted_artifacts = self
            .emitted_artifacts
            .saturating_add(close.emitted_artifacts);
        if close.flush_state.is_acknowledged() {
            self.acknowledged = self.acknowledged.saturating_add(1);
        } else {
            self.unacknowledged = self.unacknowledged.saturating_add(1);
        }
        self.logical_inferences
    }

    /// Finish teardown orderly: publish the completion claim the
    /// recorded evidence supports. Completion requires at least one
    /// recorded teardown, every one acknowledged, and no abandonment.
    #[must_use]
    pub fn finish(self) -> EphemeralFlushReport {
        self.report()
    }

    /// Abandon the acknowledgement wait for `cause` and finish
    /// teardown. The cause is recorded explicitly, the flush state is
    /// reported incomplete, and completion is withheld unconditionally:
    /// the four bounded causes are exactly the teardown conditions that
    /// must never fabricate completion.
    #[must_use]
    pub fn abandon(mut self, cause: FlushAbandonment) -> EphemeralFlushReport {
        self.abandoned = Some(cause);
        self.report()
    }

    fn report(self) -> EphemeralFlushReport {
        let abandoned = self.abandoned.is_some();
        let flush_state = if abandoned || self.unacknowledged > 0 {
            FlushState::Incomplete
        } else if self.logical_inferences > 0 {
            FlushState::Acknowledged
        } else {
            FlushState::NotStarted
        };
        let outcome = if !abandoned && self.unacknowledged == 0 && self.logical_inferences > 0 {
            EphemeralCompletion::Complete
        } else {
            EphemeralCompletion::Incomplete
        };
        let failure = (self.policy == EphemeralCapturePolicy::RequireCompleteCapture
            && outcome == EphemeralCompletion::Incomplete)
            .then_some(IntegrationFailure::FlushIncomplete);
        EphemeralFlushReport {
            flush_state,
            abandonment: self.abandoned,
            outcome,
            policy: self.policy,
            failure,
            logical_inferences: self.logical_inferences,
            acknowledged: self.acknowledged,
            emitted_artifacts: self.emitted_artifacts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference_observer::{AttemptOutcome, InferenceObserverV1, RecordingArtifactSink};
    use archivist_protocol::vocabulary::{ClientId, TenantId};

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const ORIGIN: &str = "aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f";

    fn observer() -> InferenceObserverV1<RecordingArtifactSink> {
        InferenceObserverV1::new(
            TenantId::parse(TENANT).expect("tenant"),
            ClientId::parse(ORIGIN).expect("origin"),
            RecordingArtifactSink::new(),
        )
    }

    /// One acknowledged logical inference, closed through the gate.
    fn acknowledged_inference(gate: &mut EphemeralFlushGate) {
        let mut inference = observer();
        inference
            .start_logical_inference(None)
            .expect("logical start");
        inference.start_provider_attempt().expect("attempt");
        inference
            .attempt_outcome(AttemptOutcome::Completed, None)
            .expect("completed attempt");
        gate.teardown(&mut inference)
            .expect("teardown closes the logical inference");
    }

    #[test]
    fn abandonment_and_policy_tokens_round_trip_and_fail_closed() {
        for cause in FlushAbandonment::all() {
            assert_eq!(FlushAbandonment::parse(cause.token()), Ok(cause));
            assert_eq!(cause.to_string(), cause.token());
        }
        for policy in EphemeralCapturePolicy::all() {
            assert_eq!(EphemeralCapturePolicy::parse(policy.token()), Ok(policy));
            assert_eq!(policy.to_string(), policy.token());
        }
        assert_eq!(
            FlushAbandonment::parse("crash"),
            Err(GrammarError::NotCanonical)
        );
        assert_eq!(
            FlushAbandonment::parse("storage-outage"),
            Err(GrammarError::NotCanonical)
        );
        assert_eq!(
            EphemeralCapturePolicy::parse("mandated"),
            Err(GrammarError::NotCanonical)
        );
    }

    #[test]
    fn mandated_completion_requires_the_acknowledged_flush() {
        let mut gate = EphemeralFlushGate::new(EphemeralCapturePolicy::RequireCompleteCapture);
        acknowledged_inference(&mut gate);
        acknowledged_inference(&mut gate);
        assert_eq!(gate.logical_inferences(), 2);
        assert_eq!(gate.acknowledged(), 2);
        assert_eq!(gate.flush_state(), FlushState::Acknowledged);

        let report = gate.finish();
        assert_eq!(report.flush_state, FlushState::Acknowledged);
        assert_eq!(report.abandonment, None);
        assert_eq!(report.outcome, EphemeralCompletion::Complete);
        assert_eq!(
            report.policy,
            EphemeralCapturePolicy::RequireCompleteCapture
        );
        assert_eq!(report.failure, None);
        assert_eq!(report.logical_inferences, 2);
        assert_eq!(report.acknowledged, 2);
    }

    #[test]
    fn timeout_cancellation_auth_pause_and_storage_outage_never_fabricate_completion() {
        for cause in FlushAbandonment::all() {
            let mut gate = EphemeralFlushGate::new(EphemeralCapturePolicy::RequireCompleteCapture);
            acknowledged_inference(&mut gate);

            let report = gate.abandon(cause);
            assert_eq!(report.flush_state, FlushState::Incomplete, "{cause}");
            assert_eq!(report.abandonment, Some(cause), "{cause}");
            assert_eq!(report.outcome, EphemeralCompletion::Incomplete, "{cause}");
            assert_eq!(
                report.failure,
                Some(IntegrationFailure::FlushIncomplete),
                "{cause}"
            );
            assert_eq!(report.logical_inferences, 1, "{cause}");
            assert_eq!(report.acknowledged, 1, "{cause}");
        }
    }

    #[test]
    fn unacknowledged_close_withholds_completion_under_mandate() {
        let mut gate = EphemeralFlushGate::new(EphemeralCapturePolicy::RequireCompleteCapture);
        acknowledged_inference(&mut gate);

        let mut starved = observer();
        starved
            .start_logical_inference(None)
            .expect("logical start");
        starved.start_provider_attempt().expect("attempt");
        starved
            .attempt_outcome(AttemptOutcome::Completed, None)
            .expect("completed attempt");
        starved.sink_mut().set_flush_state(FlushState::Incomplete);
        let close = gate.teardown(&mut starved).expect("teardown");
        assert_eq!(close.flush_state, FlushState::Incomplete);

        let report = gate.finish();
        assert_eq!(report.flush_state, FlushState::Incomplete);
        assert_eq!(report.abandonment, None);
        assert_eq!(report.outcome, EphemeralCompletion::Incomplete);
        assert_eq!(report.failure, Some(IntegrationFailure::FlushIncomplete));
        assert_eq!(report.logical_inferences, 2);
        assert_eq!(report.acknowledged, 1);
    }

    #[test]
    fn best_effort_records_the_incomplete_flush_without_escalating_it() {
        let mut gate = EphemeralFlushGate::new(EphemeralCapturePolicy::BestEffort);
        acknowledged_inference(&mut gate);

        let report = gate.abandon(FlushAbandonment::StorageOutage);
        assert_eq!(report.flush_state, FlushState::Incomplete);
        assert_eq!(report.abandonment, Some(FlushAbandonment::StorageOutage));
        assert_eq!(report.outcome, EphemeralCompletion::Incomplete);
        assert_eq!(report.policy, EphemeralCapturePolicy::BestEffort);
        assert_eq!(report.failure, None);
    }

    #[test]
    fn abandonment_after_acknowledgement_still_withholds_completion() {
        let mut gate = EphemeralFlushGate::new(EphemeralCapturePolicy::RequireCompleteCapture);
        acknowledged_inference(&mut gate);

        // The wait was abandoned even though every recorded close had
        // been acknowledged: the gate fails closed rather than vouch
        // for an acknowledgement it stopped observing.
        let report = gate.abandon(FlushAbandonment::Cancelled);
        assert_eq!(report.flush_state, FlushState::Incomplete);
        assert_eq!(report.outcome, EphemeralCompletion::Incomplete);
        assert_eq!(report.failure, Some(IntegrationFailure::FlushIncomplete));
    }

    #[test]
    fn a_gate_that_recorded_nothing_cannot_mint_completion() {
        for policy in EphemeralCapturePolicy::all() {
            let report = EphemeralFlushGate::new(policy).finish();
            assert_eq!(report.flush_state, FlushState::NotStarted);
            assert_eq!(report.abandonment, None);
            assert_eq!(report.outcome, EphemeralCompletion::Incomplete);
            assert_eq!(
                report.failure,
                (policy == EphemeralCapturePolicy::RequireCompleteCapture)
                    .then_some(IntegrationFailure::FlushIncomplete)
            );
            assert_eq!(report.logical_inferences, 0);
        }
    }

    #[test]
    fn recording_a_close_report_from_an_integration_counts_its_flush() {
        let mut inference = observer();
        inference
            .start_logical_inference(None)
            .expect("logical start");
        inference.start_provider_attempt().expect("attempt");
        inference
            .decoded_request_bytes(b"request", None, None)
            .expect("request");
        inference
            .attempt_outcome(AttemptOutcome::Completed, None)
            .expect("completed attempt");
        let close = inference.close_logical_inference().expect("logical close");
        assert_eq!(close.emitted_artifacts, 1);

        let mut gate = EphemeralFlushGate::new(EphemeralCapturePolicy::RequireCompleteCapture);
        assert_eq!(gate.record(&close), 1);

        let report = gate.finish();
        assert_eq!(report.emitted_artifacts, 1);
        assert_eq!(report.outcome, EphemeralCompletion::Complete);
    }
}
