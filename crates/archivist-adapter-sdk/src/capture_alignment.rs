// SPDX-License-Identifier: Apache-2.0

//! The join between reconstructed provider attempts and the
//! expected-inference ledger's coverage outcomes (plan Phase 9).
//!
//! [`crate::expected_inference`] freezes content-free expectations and owns
//! the closed [`ExactOutcome`] vocabulary.  `archivist_protocol` folds an
//! ordered artifact stream into first-class transport attempts
//! (`reconstruct_inference`).  This module is the join: it partitions one
//! captured artifact set by the *pair* of `TraceId` and
//! `InferenceRequestId`, folds each pair's slice into attempts, and
//! projects every reconstructed attempt into the content-free
//! [`ObservedArtifact`] envelopes the ledger already understands.
//!
//! The join holds the properties the exact-coverage contract rests on:
//!
//! - **Pair matching.** An artifact joins an expectation only when both
//!   correlation members agree.  Joining either identifier alone would let
//!   an inference ID reused under a different orchestrator operation stand
//!   as evidence for the original expectation.
//! - **No fabricated attempts.** Envelopes exist only where the fold found
//!   evidence.  An expectation whose exchange bypassed the instrumented
//!   route contributes zero envelopes and can only ever close
//!   [`ExactOutcome::Unobserved`] — never [`ExactOutcome::Observed`], and
//!   never with an attempt reconstructed on its behalf.
//! - **Retries stay separate.** Projection is per attempt: a retried
//!   exchange is one attempt per ordinal, never one merged exchange that
//!   would turn partial evidence into a complete claim.
//! - **Closed verdicts are not rewritten.** An expectation that closed
//!   before alignment keeps its durable outcome; artifacts seen afterwards
//!   are counted as projected evidence but are never recorded over the
//!   verdict.
//! - **Unknown stays unknown.** The join registers no session and fabricates
//!   no expectation, so a session with neither expectations nor artifacts
//!   keeps the ledger's `unknown` denominator and is never counted as
//!   `unobserved`.
//! - **No universal-completeness claim.** The report exposes
//!   per-expectation outcomes and content-free counters only.  No function
//!   on the capture model reduces a session — one that can hold an observed
//!   and an unobserved expectation at the same time — to a single
//!   completeness verdict; the vocabulary forces both to stay visible.
//!
//! # Placement
//!
//! The join lives in the SDK beside the ledger rather than in
//! `archivist-protocol`: it speaks the ledger's [`ExactOutcome`] vocabulary,
//! an SDK-side concept, and the protocol crate is sealed against SDK types
//! (the dependency-boundary test pins `archivist-protocol` at zero internal
//! dependencies).  The SDK already depends on the protocol, so the crate
//! graph stays acyclic and the ownership map unchanged.

use std::collections::BTreeMap;
use std::fmt;

use archivist_protocol::attempt_reconstruction::{
    AttemptReconstruction, ReconstructionError, reconstruct_inference,
};
use archivist_protocol::inference_artifact::InferenceArtifact;
use archivist_protocol::vocabulary::OpaqueId;

use crate::expected_inference::{
    ExactOutcome, ExpectedInferenceLedger, InferenceArtifactKind, InferenceIdentity, LedgerError,
    ObservedArtifact,
};

/// Why aligning one captured artifact set with the ledger failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlignmentError {
    /// The protocol fold refused one correlation pair's artifact slice.
    ///
    /// Unreachable for slices produced by partitioning on the pair, and
    /// kept as a variant so the join propagates instead of panicking if
    /// the fold's contract ever widens.
    Reconstruction(ReconstructionError),
    /// The ledger refused one projected envelope.
    Ledger(LedgerError),
}

impl fmt::Display for AlignmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reconstruction(error) => {
                write!(f, "the artifact fold refused a correlation group: {error}")
            }
            Self::Ledger(error) => {
                write!(f, "the ledger refused a projected envelope: {error}")
            }
        }
    }
}

impl std::error::Error for AlignmentError {}

/// One correlation pair's alignment: the ledger's outcome beside the
/// evidence the fold actually reconstructed.  Every member is content-free.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InferenceAlignment {
    /// The expectation's outcome as the ledger holds it: `None` while the
    /// expectation is still open.
    pub outcome: Option<ExactOutcome>,
    /// Transport attempts the fold reconstructed from this pair's
    /// artifacts.  Zero for a bypassed exchange — no attempt exists that
    /// the evidence does not show.
    pub reconstructed_attempts: u64,
    /// Envelopes the reconstructed evidence supports, recorded or not.
    /// For an already-closed expectation this counts the evidence a later
    /// pass saw without being able to record it.
    pub projected_artifacts: u64,
    /// Envelopes the ledger accepted.  Zero when the expectation was
    /// already closed at alignment time or had no artifacts.
    pub recorded_artifacts: u64,
    /// Structured fold anomalies on this pair's artifact slice.  Anomalies
    /// never suppress the evidence; they name where the input was not a
    /// clean attempt chain.
    pub anomalies: u64,
}

/// What aligning one captured artifact set with the ledger established.
///
/// The report is a coverage *view*, not a verdict: a session's claims stay
/// separate per expectation, and the only aggregates anywhere on the
/// capture model are the ledger's own content-free
/// [`crate::expected_inference::CoverageReport`] counters, which count the
/// outcome buckets separately instead of collapsing them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CaptureAlignment {
    /// Per-pair alignment.  Every identity that either holds a ledger
    /// expectation or contributed artifacts appears: expectation-backed
    /// entries are the coverage denominators, artifact-only entries are
    /// evidence outside every denominator, reported so unmatched capture
    /// can never silently vanish.
    pub inferences: BTreeMap<InferenceIdentity, InferenceAlignment>,
    /// Input artifacts whose correlation pair matched no expectation in
    /// the ledger.  They join nothing — not by trace, not by inference ID
    /// — and the ledger is left without them, so orphan capture cannot
    /// inflate any expectation's evidence.
    pub unmatched_artifacts: u64,
}

impl CaptureAlignment {
    /// The ledger's outcome for one expectation: `None` while it is open
    /// or when no expectation and no artifact names the pair.
    #[must_use]
    pub fn outcome(&self, identity: &InferenceIdentity) -> Option<ExactOutcome> {
        self.inferences
            .get(identity)
            .and_then(|entry| entry.outcome)
    }

    /// The attempts the fold reconstructed for one pair: `Some(0)` for an
    /// expectation with no artifacts — a bypassed exchange — and `None`
    /// when nothing at all names the pair.
    #[must_use]
    pub fn reconstructed_attempts(&self, identity: &InferenceIdentity) -> Option<u64> {
        self.inferences
            .get(identity)
            .map(|entry| entry.reconstructed_attempts)
    }
}

/// Align one captured artifact set with the ledger's expectations.
///
/// The artifacts are partitioned by the pair `(TraceId, InferenceRequestId)`
/// — never either identifier alone — and each partition is folded into
/// transport attempts by the protocol's read-side reconstruction.  Every
/// reconstructed attempt is projected into content-free correlation
/// envelopes and recorded on its matching open expectation; a closed
/// expectation's verdict is never rewritten.  Closing remains the ledger's
/// explicit operation: an open expectation is never counted as unobserved
/// by this function.
///
/// The join is safe to re-run.  The ledger deduplicates identical
/// envelopes, and an alignment that fails partway leaves only the
/// envelopes recorded before the failure — a corrected re-run converges.
///
/// # Errors
/// [`AlignmentError::Reconstruction`] when the fold refuses a partition's
/// slice, or [`AlignmentError::Ledger`] when the ledger refuses a
/// projected envelope (an artifact ordinal outside the protocol's `u63`,
/// for an artifact built in memory rather than parsed).
pub fn align_attempts(
    ledger: &mut ExpectedInferenceLedger,
    artifacts: &[InferenceArtifact],
) -> Result<CaptureAlignment, AlignmentError> {
    let mut groups: BTreeMap<InferenceIdentity, Vec<InferenceArtifact>> = BTreeMap::new();
    for artifact in artifacts {
        groups
            .entry(InferenceIdentity::new(
                artifact.trace_id.clone(),
                artifact.inference_request_id.clone(),
            ))
            .or_default()
            .push(artifact.clone());
    }

    let mut alignment = CaptureAlignment::default();
    for (identity, group) in groups {
        let reconstruction =
            reconstruct_inference(&group).map_err(AlignmentError::Reconstruction)?;
        let entry = alignment.inferences.entry(identity.clone()).or_default();
        entry.reconstructed_attempts = reconstruction.attempts().len() as u64;
        entry.anomalies = reconstruction.anomalies().len() as u64;

        // The session association comes from the frozen record itself, so
        // a projected envelope can never disagree with its expectation's
        // session and the ledger's mismatch guard stays a formality.
        let settled = ledger
            .get(&identity)
            .map(|record| (record.session_id.clone(), record.outcome.is_some()));
        match settled {
            Some((session_id, closed)) => {
                for attempt in reconstruction.attempts() {
                    let envelopes = project_attempt(&identity, &session_id, attempt);
                    entry.projected_artifacts += envelopes.len() as u64;
                    if closed {
                        continue;
                    }
                    for envelope in envelopes {
                        ledger
                            .record_artifact(envelope)
                            .map_err(AlignmentError::Ledger)?;
                        entry.recorded_artifacts += 1;
                    }
                }
            }
            None => {
                alignment.unmatched_artifacts += group.len() as u64;
            }
        }
    }

    // Every expectation appears in the report, including one with no
    // artifacts at all: a bypassed exchange is a Some(0) attempt count
    // with an outcome the ledger alone can close, never an absence.
    for record in ledger.records() {
        alignment
            .inferences
            .entry(record.key().clone())
            .or_default()
            .outcome = record.outcome;
    }
    Ok(alignment)
}

/// Project one reconstructed attempt into content-free correlation
/// envelopes — one per observed event kind, in schema order.
///
/// Every envelope exists because the fold found evidence for it.  A
/// partial attempt projects only what it has: a request without a
/// response projects the request, an abandoned stream projects its
/// retained prefix, and a transport failure projects its error record —
/// never a fabricated completion.  The retry transition projects on the
/// successor attempt, matching the wire convention the fold preserves.
fn project_attempt(
    identity: &InferenceIdentity,
    session_id: &OpaqueId,
    attempt: &AttemptReconstruction,
) -> Vec<ObservedArtifact> {
    let envelope = |kind| {
        ObservedArtifact::new(
            identity.clone(),
            session_id.clone(),
            attempt.provider_attempt_id().clone(),
            attempt.attempt_ordinal(),
            kind,
        )
    };

    let mut envelopes = Vec::new();
    if attempt.request_present() {
        envelopes.push(envelope(InferenceArtifactKind::ProviderRequest));
    }
    if attempt.response_complete() {
        envelopes.push(envelope(InferenceArtifactKind::ProviderResponse));
    }
    for event in attempt.stream_events() {
        envelopes.push(
            envelope(InferenceArtifactKind::StreamingEvent).with_event_ordinal(event.event_ordinal),
        );
    }
    if attempt.transport_error().is_some() {
        envelopes.push(envelope(InferenceArtifactKind::TransportError));
    }
    for _report in attempt.usage_reports() {
        envelopes.push(envelope(InferenceArtifactKind::Usage));
    }
    if attempt.entered_via().is_some() {
        envelopes.push(envelope(InferenceArtifactKind::Retry));
    }
    envelopes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expected_inference::{
        ExpectedEvent, ExpectedEvents, ExpectedInferenceLedger as Ledger, ExpectedInferenceRecord,
        RoutePolicy,
    };
    use archivist_protocol::vocabulary::{InferenceRequestId, Timestamp, TraceId};
    use std::fs;
    use std::path::Path;

    fn corpus(path: &str) -> InferenceArtifact {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/v1/examples/inference");
        InferenceArtifact::parse(&fs::read(root.join(path)).expect("corpus file"))
            .unwrap_or_else(|error| panic!("{path}: {error}"))
    }

    fn retried_stream() -> Vec<InferenceArtifact> {
        [
            "retried-attempt/attempt-0-response-429.json",
            "retried-attempt/attempt-0-retry.json",
            "retried-attempt/attempt-1-transport-error.json",
            "retried-attempt/attempt-1-retry.json",
            "retried-attempt/attempt-2-request.json",
            "retried-attempt/attempt-2-response.json",
        ]
        .into_iter()
        .map(corpus)
        .collect()
    }

    fn identity_of(artifact: &InferenceArtifact) -> InferenceIdentity {
        InferenceIdentity::new(
            artifact.trace_id.clone(),
            artifact.inference_request_id.clone(),
        )
    }

    /// A second logical inference in the same session whose exchange
    /// bypassed the instrumented route entirely: it has an expectation
    /// and no artifacts.
    fn bypassed_identity() -> InferenceIdentity {
        InferenceIdentity::new(
            TraceId::parse("00000000-0000-7000-8000-000000000099").expect("trace"),
            InferenceRequestId::parse("00000000-0000-7000-8000-000000000098").expect("inference"),
        )
    }

    fn session() -> OpaqueId {
        OpaqueId::parse("session-exact").expect("session")
    }

    fn timestamp() -> Timestamp {
        Timestamp::parse("2026-09-20T12:00:00Z").expect("timestamp")
    }

    fn record(identity: &InferenceIdentity) -> ExpectedInferenceRecord {
        ExpectedInferenceRecord::new(
            identity.clone(),
            session(),
            RoutePolicy::SdkHook,
            timestamp(),
        )
    }

    #[test]
    fn a_closed_expectation_without_artifacts_is_unobserved_and_never_complete() {
        let mut ledger = Ledger::new();
        let key = bypassed_identity();
        ledger.persist(record(&key)).expect("persist");

        let alignment = align_attempts(&mut ledger, &[]).expect("empty alignment");
        assert_eq!(alignment.reconstructed_attempts(&key), Some(0));
        assert_eq!(alignment.outcome(&key), None, "open is not yet unobserved");
        assert_eq!(alignment.inferences.len(), 1);
        assert_eq!(alignment.unmatched_artifacts, 0);

        assert_eq!(ledger.close_completed(&key), Ok(ExactOutcome::Unobserved));
        assert_eq!(
            ledger.get(&key).expect("record").outcome,
            Some(ExactOutcome::Unobserved)
        );
        assert_ne!(
            ledger.get(&key).expect("record").outcome,
            Some(ExactOutcome::Observed)
        );

        let after = align_attempts(&mut ledger, &[]).expect("re-alignment");
        assert_eq!(after.outcome(&key), Some(ExactOutcome::Unobserved));

        let report = ledger.reconcile();
        assert_eq!(report.observed, 0);
        assert_eq!(report.unobserved, 1);
        assert_eq!(report.unknown, 0);
    }

    #[test]
    fn a_bypassed_exchange_resolves_unobserved_without_a_fabricated_attempt() {
        // Plan scenario 5: one session, one exchange through the supported
        // integration (the retried corpus) and one bypassing it.
        let mut ledger = Ledger::new();
        ledger.register_session(session());
        let stream = retried_stream();
        let captured = identity_of(&stream[0]);
        let bypassed = bypassed_identity();
        for identity in [&captured, &bypassed] {
            ledger
                .persist(
                    record(identity)
                        .with_expected_attempts(3)
                        .with_required_events(
                            ExpectedEvents::empty().with(ExpectedEvent::Terminal),
                        ),
                )
                .expect("persist");
        }

        let alignment = align_attempts(&mut ledger, &stream).expect("alignment");

        // The instrumented side: three separate attempts, six envelopes
        // — each retry transition projects on its own successor, never
        // merged into one exchange.
        let captured_entry = alignment.inferences.get(&captured).expect("captured");
        assert_eq!(captured_entry.reconstructed_attempts, 3);
        assert_eq!(captured_entry.projected_artifacts, 6);
        assert_eq!(captured_entry.recorded_artifacts, 6);
        assert_eq!(captured_entry.anomalies, 0);

        // The bypassed side: zero evidence, zero attempts, nothing
        // fabricated — and its own outcome, independent of its sibling's.
        let bypassed_entry = alignment.inferences.get(&bypassed).expect("bypassed");
        assert_eq!(bypassed_entry.reconstructed_attempts, 0);
        assert_eq!(bypassed_entry.projected_artifacts, 0);
        assert_eq!(bypassed_entry.recorded_artifacts, 0);

        assert_eq!(
            ledger.close_completed(&captured),
            Ok(ExactOutcome::Observed)
        );
        assert_eq!(
            ledger.close_completed(&bypassed),
            Ok(ExactOutcome::Unobserved)
        );

        let report = ledger.reconcile();
        assert_eq!(report.observed, 1);
        assert_eq!(report.unobserved, 1);
        assert_eq!(report.unknown, 0);
        assert_eq!(report.sessions, 1);

        // The two claims never collapse into one verdict: the model's
        // report carries both outcomes side by side, and there is no
        // completeness predicate anywhere on the capture model to reduce
        // this session to a single claim.
        let settled = align_attempts(&mut ledger, &stream).expect("re-alignment");
        assert_eq!(settled.outcome(&captured), Some(ExactOutcome::Observed));
        assert_eq!(settled.outcome(&bypassed), Some(ExactOutcome::Unobserved));
    }

    #[test]
    fn an_empty_session_is_unknown_not_unobserved() {
        let mut ledger = Ledger::new();
        ledger.register_session(session());

        let alignment = align_attempts(&mut ledger, &[]).expect("alignment");
        assert!(alignment.inferences.is_empty());
        assert_eq!(alignment.unmatched_artifacts, 0);

        let report = ledger.reconcile();
        assert_eq!(report.unknown, 1);
        assert_eq!(report.unobserved, 0);
        assert_eq!(report.open_expectations, 0);
    }

    #[test]
    fn retried_attempts_project_separately_and_partial_evidence_stays_partial() {
        let mut ledger = Ledger::new();
        let stream = retried_stream();
        let key = identity_of(&stream[0]);
        // The default contract: one attempt needing a request and a
        // terminal event.  A naive merge of the retry chain would satisfy
        // it; three separate attempts cannot.
        ledger.persist(record(&key)).expect("persist");

        let alignment = align_attempts(&mut ledger, &stream).expect("alignment");
        let entry = alignment.inferences.get(&key).expect("aligned");
        assert_eq!(entry.reconstructed_attempts, 3);
        assert_eq!(entry.recorded_artifacts, 6);

        assert_eq!(ledger.close_completed(&key), Ok(ExactOutcome::Partial));
        let report = ledger.reconcile();
        assert_eq!(report.partial, 1);
        assert_eq!(report.observed, 0);
    }

    #[test]
    fn an_abandoned_stream_prefix_never_becomes_a_complete_response() {
        let mut ledger = Ledger::new();
        let events: Vec<InferenceArtifact> = [
            "streamed-attempt/event-0.json",
            "streamed-attempt/event-1.json",
            "streamed-attempt/event-2.json",
        ]
        .into_iter()
        .map(corpus)
        .collect();
        let key = identity_of(&events[0]);
        ledger
            .persist(
                record(&key).with_required_events(
                    ExpectedEvents::empty()
                        .with(ExpectedEvent::ProviderRequest)
                        .with(ExpectedEvent::StreamingEvent),
                ),
            )
            .expect("persist");

        let alignment = align_attempts(&mut ledger, &events).expect("alignment");
        let entry = alignment.inferences.get(&key).expect("aligned");
        assert_eq!(entry.reconstructed_attempts, 1);
        // Three stream events project — the retained prefix, event
        // ordinals intact — and no request or response is fabricated.
        assert_eq!(entry.projected_artifacts, 3);
        assert_eq!(entry.recorded_artifacts, 3);

        assert_eq!(ledger.close_completed(&key), Ok(ExactOutcome::Partial));
        assert_eq!(ledger.reconcile().partial, 1);
    }

    #[test]
    fn artifacts_join_by_the_pair_never_either_identifier_alone() {
        let mut ledger = Ledger::new();
        let artifact = corpus("single-attempt/request.json");
        // Same trace, different logical inference: not evidence.
        let wrong_pair = InferenceIdentity::new(
            artifact.trace_id.clone(),
            InferenceRequestId::parse("00000000-0000-7000-8000-000000000011").expect("inference"),
        );
        ledger.persist(record(&wrong_pair)).expect("persist");

        let alignment = align_attempts(&mut ledger, &[artifact]).expect("alignment");
        assert_eq!(alignment.unmatched_artifacts, 1);
        assert_eq!(alignment.reconstructed_attempts(&wrong_pair), Some(0));

        assert_eq!(
            ledger.close_completed(&wrong_pair),
            Ok(ExactOutcome::Unobserved)
        );
        assert_eq!(ledger.pending_artifacts(), 0);
        let report = ledger.reconcile();
        assert_eq!(report.unobserved, 1);
        assert_eq!(report.observed, 0);
    }

    #[test]
    fn evidence_outside_every_denominator_is_reported_never_joined() {
        let mut ledger = Ledger::new();
        let artifact = corpus("single-attempt/request.json");
        let orphan = identity_of(&artifact);

        let alignment = align_attempts(&mut ledger, &[artifact]).expect("alignment");
        assert_eq!(alignment.unmatched_artifacts, 1);
        let entry = alignment.inferences.get(&orphan).expect("orphan");
        assert_eq!(entry.reconstructed_attempts, 1);
        assert_eq!(entry.outcome, None);
        // The join fabricated no expectation and fed the ledger nothing.
        assert!(ledger.records().next().is_none());
        assert_eq!(ledger.pending_artifacts(), 0);
        let report = ledger.reconcile();
        assert_eq!(report.sessions, 0);
        assert_eq!(report.artifacts, 0);
    }

    #[test]
    fn a_closed_verdict_is_never_rewritten_by_later_evidence() {
        let mut ledger = Ledger::new();
        let request = corpus("single-attempt/request.json");
        let key = identity_of(&request);
        ledger.persist(record(&key)).expect("persist");

        let first = align_attempts(&mut ledger, &[request]).expect("first alignment");
        let entry = first.inferences.get(&key).expect("aligned");
        assert_eq!(entry.recorded_artifacts, 1);
        assert_eq!(ledger.close_completed(&key), Ok(ExactOutcome::Partial));

        let late_response = corpus("single-attempt/response.json");
        let second = align_attempts(&mut ledger, &[late_response]).expect("second alignment");
        let entry = second.inferences.get(&key).expect("aligned");
        assert_eq!(entry.projected_artifacts, 1);
        assert_eq!(entry.recorded_artifacts, 0, "closed: nothing recorded");
        assert_eq!(second.outcome(&key), Some(ExactOutcome::Partial));

        let report = ledger.reconcile();
        assert_eq!(report.partial, 1);
        assert_eq!(report.observed, 0);
    }

    #[test]
    fn an_integration_failure_closes_failed_regardless_of_evidence() {
        let mut ledger = Ledger::new();
        let key = bypassed_identity();
        ledger.persist(record(&key)).expect("persist");
        assert_eq!(
            ledger.close_failed(
                &key,
                crate::expected_inference::IntegrationFailure::CaptureFailed
            ),
            Ok(ExactOutcome::Failed)
        );

        let alignment = align_attempts(&mut ledger, &[]).expect("alignment");
        assert_eq!(
            alignment.outcome(&key),
            Some(ExactOutcome::Failed),
            "the bounded failure, not the absent evidence, decides"
        );
        assert_eq!(ledger.reconcile().failed, 1);
        assert_eq!(ledger.reconcile().unobserved, 0);
    }
}
