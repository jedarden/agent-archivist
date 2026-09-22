// SPDX-License-Identifier: Apache-2.0

//! The read-side fold for exact-inference artifacts.
//!
//! An artifact is one observation at the provider boundary.  This module
//! folds an ordered set of those observations back into transport attempts.
//! The fold is deliberately evidence-preserving: an attempt that has only a
//! request, a stream prefix, or a transport error is still an attempt, and a
//! retry record opens a distinct successor rather than completing or merging
//! the predecessor.
//!
//! The fold does not infer provider semantics that are absent from the wire.
//! In particular, a sequence of streaming events without a provider
//! response is an [`AttemptTerminalState::AbandonedMidStream`] attempt, not a
//! fabricated complete response.  A request (or retry transition) without a
//! later terminal observation is [`AttemptTerminalState::Truncated`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::inference_artifact::{BoundaryEvent, InferenceArtifact, Payload};
use crate::vocabulary::{
    BlobDigest, InferenceArtifactKind, InferenceRequestId, ProviderAttemptId, RetryReason, TraceId,
    TransportErrorClass, UsageSource,
};

/// A payload reference copied out of an artifact without exposing storage.
/// The digest is the plain content digest and the size is the captured byte
/// count; neither carries an attempt identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PayloadRef {
    digest: BlobDigest,
    size: u64,
}

impl PayloadRef {
    /// The plain SHA-256 digest of the captured bytes.
    #[must_use]
    pub const fn digest(&self) -> &BlobDigest {
        &self.digest
    }

    /// The captured byte count.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
}

impl From<&Payload> for PayloadRef {
    fn from(payload: &Payload) -> Self {
        Self {
            digest: payload.payload_digest,
            size: payload.payload_size,
        }
    }
}

/// The transport failure observed for one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptTransportError {
    /// The closed transport-failure classification.
    pub class: TransportErrorClass,
    /// The deadline in milliseconds, when the artifact carried one.
    pub timeout_ms: Option<u64>,
}

/// The retry transition that entered an attempt.
///
/// Retry artifacts are stamped with the successor's identity.  Therefore a
/// transition is stored on the successor and its `of_attempt_ordinal` names
/// the predecessor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryTransition {
    /// Why the boundary started the retry.
    pub reason: RetryReason,
    /// The ordinal of the attempt this retry follows.
    pub of_attempt_ordinal: u64,
    /// The observed spacing between attempts, when clocked.
    pub backoff_ms: Option<u64>,
}

/// One usage observation extracted at the provider boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsageObservation {
    /// Where the counters were extracted from.
    pub source: UsageSource,
    /// Input tokens as reported by the provider.
    pub input_tokens: u64,
    /// Output tokens as reported by the provider.
    pub output_tokens: u64,
    /// Total tokens as reported by the provider; never recomputed here.
    pub total_tokens: u64,
    /// The reporting payload reference, when the usage artifact carried one.
    pub payload: Option<PayloadRef>,
}

/// One ordered decoded event in an attempt's stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamEventRef {
    /// The zero-based event ordinal.
    pub event_ordinal: u64,
    /// The event's decoded payload reference.
    pub payload: PayloadRef,
}

/// The terminal state supported by the read-side model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptTerminalState {
    /// A complete provider response was captured.
    Completed,
    /// A transport error was captured for this attempt.
    TransportFailed {
        /// The closed failure class.
        class: TransportErrorClass,
    },
    /// Decoded stream events were captured but no complete response or
    /// transport-error terminal observation was captured.
    AbandonedMidStream {
        /// Number of ordered stream events retained.
        events: u64,
    },
    /// The evidence ended before a response, stream termination, or
    /// transport error was observed.
    Truncated,
}

/// The older evidence-oriented outcome view retained for callers that want
/// to distinguish a bare request or retry entry from the explicit terminal
/// state.  [`AttemptReconstruction::terminal_state`] is the authoritative
/// four-state terminal classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// A transport error was captured.
    Failed(TransportErrorClass),
    /// A provider response was captured, including an error status such as
    /// 429.
    Responded,
    /// Stream events were captured without a response terminator.
    Streamed {
        /// Number of stream events.
        events: u64,
    },
    /// A request was captured without an outcome.
    Requested,
    /// Only a retry transition entered the attempt.
    Entered,
    /// Only non-boundary evidence, such as usage, was captured.
    Unevidenced,
}

/// A structured disclosure produced when an artifact set is not a clean
/// attempt chain.  Valid prefixes do not produce anomalies merely because
/// their final attempt is partial; partiality is represented by the attempt
/// itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconstructionAnomaly {
    /// More than one provider-attempt identity claimed an ordinal.
    ConflictingAttemptOrdinal {
        /// The contested ordinal.
        attempt_ordinal: u64,
    },
    /// One provider-attempt identity appeared under more than one ordinal.
    InconsistentAttemptIdentity,
    /// A retry cites an ordinal absent from the supplied prefix.
    UnresolvedRetryCitation {
        /// The successor carrying the retry artifact.
        attempt_ordinal: u64,
        /// The predecessor ordinal named by the retry.
        cited_ordinal: u64,
    },
    /// Two stream artifacts claimed the same event ordinal.
    DuplicateEventOrdinal {
        /// The affected attempt.
        attempt_ordinal: u64,
        /// The repeated event ordinal.
        event_ordinal: u64,
    },
    /// The stream event ordinals are not dense from zero.
    EventOrdinalGap {
        /// The affected attempt.
        attempt_ordinal: u64,
        /// The first missing ordinal.
        expected_ordinal: u64,
    },
    /// More than one artifact of a single-attempt kind was supplied.
    ConflictingAttemptEvidence {
        /// The affected attempt.
        attempt_ordinal: u64,
        /// The duplicated kind.
        kind: InferenceArtifactKind,
    },
    /// Partition or correlation provenance disagreed within the input.
    InconsistentPartition {
        /// The member that disagreed.
        field: PartitionField,
    },
}

/// A partition member that must be unanimous for a clean inference view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PartitionField {
    /// The orchestrator trace identity.
    TraceId,
    /// The tenant partition.
    TenantId,
    /// The capturing client.
    OriginClientId,
}

/// Why a reconstruction could not be made from the supplied artifact slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconstructionError {
    /// The slice names more than one logical inference.
    MixedInference,
}

impl fmt::Display for ReconstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MixedInference => {
                f.write_str("artifacts span more than one inference_request_id")
            }
        }
    }
}

impl std::error::Error for ReconstructionError {}

/// One provider transport attempt reconstructed from its artifacts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptReconstruction {
    provider_attempt_id: ProviderAttemptId,
    attempt_ordinal: u64,
    request: Option<PayloadRef>,
    response: Option<PayloadRef>,
    stream_events: Vec<StreamEventRef>,
    transport_error: Option<AttemptTransportError>,
    entered_via: Option<RetryTransition>,
    usage_reports: Vec<UsageObservation>,
    artifacts: Vec<InferenceArtifact>,
    terminal_state: AttemptTerminalState,
    outcome: AttemptOutcome,
}

impl AttemptReconstruction {
    /// The provider-attempt UUID.
    #[must_use]
    pub fn provider_attempt_id(&self) -> &ProviderAttemptId {
        &self.provider_attempt_id
    }

    /// The dense attempt ordinal.
    #[must_use]
    pub const fn attempt_ordinal(&self) -> u64 {
        self.attempt_ordinal
    }

    /// The decoded request payload, when present.
    #[must_use]
    pub const fn request(&self) -> Option<PayloadRef> {
        self.request
    }

    /// Whether a provider request artifact was observed.
    #[must_use]
    pub const fn request_present(&self) -> bool {
        self.request.is_some()
    }

    /// The decoded response payload, when present.
    #[must_use]
    pub const fn response(&self) -> Option<PayloadRef> {
        self.response
    }

    /// Whether a complete provider response artifact was observed.
    #[must_use]
    pub const fn response_complete(&self) -> bool {
        self.response.is_some()
    }

    /// Ordered stream events, retaining their wire event ordinals.
    #[must_use]
    pub fn stream_events(&self) -> &[StreamEventRef] {
        &self.stream_events
    }

    /// The number of decoded stream events in the retained prefix.
    #[must_use]
    pub const fn stream_prefix_len(&self) -> usize {
        self.stream_events.len()
    }

    /// The transport error, when present.
    #[must_use]
    pub const fn transport_error(&self) -> Option<AttemptTransportError> {
        self.transport_error
    }

    /// The retry transition that entered this attempt, when present.
    #[must_use]
    pub const fn entered_via(&self) -> Option<RetryTransition> {
        self.entered_via
    }

    /// Usage observations in artifact-stream order.
    #[must_use]
    pub fn usage_reports(&self) -> &[UsageObservation] {
        &self.usage_reports
    }

    /// All artifacts belonging to this attempt, in supplied stream order.
    #[must_use]
    pub fn artifacts(&self) -> &[InferenceArtifact] {
        &self.artifacts
    }

    /// The explicit four-state terminal classification.
    #[must_use]
    pub const fn terminal_state(&self) -> AttemptTerminalState {
        self.terminal_state
    }

    /// The evidence-oriented outcome classification.
    #[must_use]
    pub const fn outcome(&self) -> AttemptOutcome {
        self.outcome
    }
}

/// One logical inference reconstructed from an ordered artifact stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceReconstruction {
    inference_request_id: Option<InferenceRequestId>,
    trace_id: Option<TraceId>,
    attempts: Vec<AttemptReconstruction>,
    anomalies: Vec<ReconstructionAnomaly>,
}

impl InferenceReconstruction {
    /// The logical inference identity, when the input was non-empty.
    #[must_use]
    pub fn inference_request_id(&self) -> Option<&InferenceRequestId> {
        self.inference_request_id.as_ref()
    }

    /// The trace identity, when all artifacts agreed on it.
    #[must_use]
    pub fn trace_id(&self) -> Option<&TraceId> {
        self.trace_id.as_ref()
    }

    /// Attempts ordered by dense attempt ordinal.
    #[must_use]
    pub fn attempts(&self) -> &[AttemptReconstruction] {
        &self.attempts
    }

    /// Structured inconsistencies found while folding.
    #[must_use]
    pub fn anomalies(&self) -> &[ReconstructionAnomaly] {
        &self.anomalies
    }

    /// Whether all supplied artifacts formed a clean chain.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.anomalies.is_empty()
    }

    /// Find an attempt by its provider-attempt identity.
    #[must_use]
    pub fn attempt(
        &self,
        provider_attempt_id: &ProviderAttemptId,
    ) -> Option<&AttemptReconstruction> {
        self.attempts
            .iter()
            .find(|attempt| attempt.provider_attempt_id == *provider_attempt_id)
    }

    /// Return every retry edge as `(successor ordinal, transition)` pairs.
    #[must_use]
    pub fn retry_edges(&self) -> Vec<(u64, RetryTransition)> {
        self.attempts
            .iter()
            .filter_map(|attempt| {
                attempt
                    .entered_via
                    .map(|transition| (attempt.attempt_ordinal, transition))
            })
            .collect()
    }
}

/// Fold one logical inference's ordered artifacts into independent attempts.
///
/// The input must name one `inference_request_id`.  An empty slice yields an
/// empty reconstruction.  A prefix that ends in the middle of an attempt is
/// still returned: its request, response, stream prefix, usage, retry edge,
/// and terminal state contain only evidence in that prefix.
///
/// # Errors
/// Returns [`ReconstructionError::MixedInference`] when the slice contains
/// more than one logical inference.
#[allow(clippy::too_many_lines)]
pub fn reconstruct_inference(
    artifacts: &[InferenceArtifact],
) -> Result<InferenceReconstruction, ReconstructionError> {
    let Some(first) = artifacts.first() else {
        return Ok(InferenceReconstruction {
            inference_request_id: None,
            trace_id: None,
            attempts: Vec::new(),
            anomalies: Vec::new(),
        });
    };
    let inference_request_id = first.inference_request_id.clone();
    if artifacts
        .iter()
        .any(|artifact| artifact.inference_request_id != inference_request_id)
    {
        return Err(ReconstructionError::MixedInference);
    }

    let mut anomalies = Vec::new();
    let trace_id = artifacts
        .iter()
        .all(|artifact| artifact.trace_id == first.trace_id)
        .then(|| first.trace_id.clone());
    if trace_id.is_none() {
        anomalies.push(ReconstructionAnomaly::InconsistentPartition {
            field: PartitionField::TraceId,
        });
    }
    if !artifacts
        .iter()
        .all(|artifact| artifact.tenant_id == first.tenant_id)
    {
        anomalies.push(ReconstructionAnomaly::InconsistentPartition {
            field: PartitionField::TenantId,
        });
    }
    if !artifacts
        .iter()
        .all(|artifact| artifact.origin_client_id == first.origin_client_id)
    {
        anomalies.push(ReconstructionAnomaly::InconsistentPartition {
            field: PartitionField::OriginClientId,
        });
    }

    // Keep the provider identity in the partition key.  A reused ordinal or
    // a reused provider ID therefore creates separate views and an anomaly,
    // never a merged attempt.
    let mut groups: BTreeMap<(u64, ProviderAttemptId), Vec<InferenceArtifact>> = BTreeMap::new();
    for artifact in artifacts {
        groups
            .entry((
                artifact.attempt_ordinal,
                artifact.provider_attempt_id.clone(),
            ))
            .or_default()
            .push(artifact.clone());
    }

    let mut ordinal_identities: BTreeMap<u64, Vec<ProviderAttemptId>> = BTreeMap::new();
    let mut identity_ordinals: BTreeMap<ProviderAttemptId, Vec<u64>> = BTreeMap::new();
    for (ordinal, identity) in groups.keys() {
        ordinal_identities
            .entry(*ordinal)
            .or_default()
            .push(identity.clone());
        identity_ordinals
            .entry(identity.clone())
            .or_default()
            .push(*ordinal);
    }
    for (ordinal, identities) in ordinal_identities {
        if identities.len() > 1 {
            anomalies.push(ReconstructionAnomaly::ConflictingAttemptOrdinal {
                attempt_ordinal: ordinal,
            });
        }
    }
    if identity_ordinals
        .values()
        .any(|ordinals| ordinals.len() > 1)
    {
        anomalies.push(ReconstructionAnomaly::InconsistentAttemptIdentity);
    }

    let mut attempts = Vec::with_capacity(groups.len());
    for ((attempt_ordinal, provider_attempt_id), members) in groups {
        let mut view = AttemptReconstruction {
            provider_attempt_id,
            attempt_ordinal,
            request: None,
            response: None,
            stream_events: Vec::new(),
            transport_error: None,
            entered_via: None,
            usage_reports: Vec::new(),
            artifacts: members.clone(),
            terminal_state: AttemptTerminalState::Truncated,
            outcome: AttemptOutcome::Unevidenced,
        };
        let mut event_ordinals = BTreeSet::new();

        for member in &members {
            match &member.event {
                BoundaryEvent::ProviderRequest => {
                    if view.request.is_some() {
                        anomalies.push(ReconstructionAnomaly::ConflictingAttemptEvidence {
                            attempt_ordinal,
                            kind: InferenceArtifactKind::ProviderRequest,
                        });
                    } else {
                        view.request = member.payload.as_ref().map(PayloadRef::from);
                    }
                }
                BoundaryEvent::ProviderResponse => {
                    if view.response.is_some() {
                        anomalies.push(ReconstructionAnomaly::ConflictingAttemptEvidence {
                            attempt_ordinal,
                            kind: InferenceArtifactKind::ProviderResponse,
                        });
                    } else {
                        view.response = member.payload.as_ref().map(PayloadRef::from);
                    }
                }
                BoundaryEvent::StreamingEvent { event_ordinal } => {
                    if !event_ordinals.insert(*event_ordinal) {
                        anomalies.push(ReconstructionAnomaly::DuplicateEventOrdinal {
                            attempt_ordinal,
                            event_ordinal: *event_ordinal,
                        });
                    }
                    if let Some(payload) = member.payload.as_ref() {
                        view.stream_events.push(StreamEventRef {
                            event_ordinal: *event_ordinal,
                            payload: payload.into(),
                        });
                    }
                }
                BoundaryEvent::Retry {
                    retry_of_attempt_ordinal,
                    retry_reason,
                    backoff_ms,
                } => {
                    if view.entered_via.is_some() {
                        anomalies.push(ReconstructionAnomaly::ConflictingAttemptEvidence {
                            attempt_ordinal,
                            kind: InferenceArtifactKind::Retry,
                        });
                    } else {
                        view.entered_via = Some(RetryTransition {
                            reason: *retry_reason,
                            of_attempt_ordinal: *retry_of_attempt_ordinal,
                            backoff_ms: *backoff_ms,
                        });
                    }
                }
                BoundaryEvent::Usage { usage_source } => {
                    let metadata = member.metadata.as_ref();
                    if let Some(metadata) = metadata
                        && let (Some(input_tokens), Some(output_tokens), Some(total_tokens)) = (
                            metadata.usage_input_tokens,
                            metadata.usage_output_tokens,
                            metadata.usage_total_tokens,
                        )
                    {
                        view.usage_reports.push(UsageObservation {
                            source: *usage_source,
                            input_tokens,
                            output_tokens,
                            total_tokens,
                            payload: member.payload.as_ref().map(PayloadRef::from),
                        });
                    }
                }
                BoundaryEvent::TransportError {
                    error_class,
                    timeout_ms,
                } => {
                    if view.transport_error.is_some() {
                        anomalies.push(ReconstructionAnomaly::ConflictingAttemptEvidence {
                            attempt_ordinal,
                            kind: InferenceArtifactKind::TransportError,
                        });
                    } else {
                        view.transport_error = Some(AttemptTransportError {
                            class: *error_class,
                            timeout_ms: *timeout_ms,
                        });
                    }
                }
            }
        }

        view.stream_events.sort_by_key(|event| event.event_ordinal);
        let mut expected = 0;
        for event in &view.stream_events {
            if event.event_ordinal != expected {
                anomalies.push(ReconstructionAnomaly::EventOrdinalGap {
                    attempt_ordinal,
                    expected_ordinal: expected,
                });
                break;
            }
            expected = expected.saturating_add(1);
        }

        view.terminal_state = if let Some(error) = view.transport_error {
            AttemptTerminalState::TransportFailed { class: error.class }
        } else if view.response.is_some() {
            AttemptTerminalState::Completed
        } else if !view.stream_events.is_empty() {
            AttemptTerminalState::AbandonedMidStream {
                events: view.stream_events.len() as u64,
            }
        } else {
            AttemptTerminalState::Truncated
        };
        view.outcome = if let Some(error) = view.transport_error {
            AttemptOutcome::Failed(error.class)
        } else if view.response.is_some() {
            AttemptOutcome::Responded
        } else if !view.stream_events.is_empty() {
            AttemptOutcome::Streamed {
                events: view.stream_events.len() as u64,
            }
        } else if view.request.is_some() {
            AttemptOutcome::Requested
        } else if view.entered_via.is_some() {
            AttemptOutcome::Entered
        } else {
            AttemptOutcome::Unevidenced
        };
        attempts.push(view);
    }

    let present_ordinals: Vec<u64> = attempts
        .iter()
        .map(|attempt| attempt.attempt_ordinal)
        .collect();
    for attempt in &attempts {
        if let Some(transition) = attempt.entered_via
            && !present_ordinals.contains(&transition.of_attempt_ordinal)
        {
            anomalies.push(ReconstructionAnomaly::UnresolvedRetryCitation {
                attempt_ordinal: attempt.attempt_ordinal,
                cited_ordinal: transition.of_attempt_ordinal,
            });
        }
    }

    Ok(InferenceReconstruction {
        inference_request_id: Some(inference_request_id),
        trace_id,
        attempts,
        anomalies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn retried_example_reconstructs_three_independent_attempts() {
        let reconstruction = reconstruct_inference(&retried_stream()).expect("one inference");
        assert_eq!(reconstruction.attempts().len(), 3);
        assert_eq!(reconstruction.retry_edges().len(), 2);

        let first = &reconstruction.attempts()[0];
        assert_eq!(first.attempt_ordinal(), 0);
        assert_eq!(first.terminal_state(), AttemptTerminalState::Completed);
        assert!(first.response_complete());

        let second = &reconstruction.attempts()[1];
        assert_eq!(second.attempt_ordinal(), 1);
        assert_eq!(
            second.terminal_state(),
            AttemptTerminalState::TransportFailed {
                class: TransportErrorClass::Connect
            }
        );
        assert_eq!(
            second.entered_via().expect("retry edge").of_attempt_ordinal,
            0
        );

        let third = &reconstruction.attempts()[2];
        assert_eq!(third.attempt_ordinal(), 2);
        assert!(third.request_present());
        assert_eq!(third.terminal_state(), AttemptTerminalState::Completed);
        assert_eq!(
            third.entered_via().expect("retry edge").of_attempt_ordinal,
            1
        );
    }

    #[test]
    fn prefixes_keep_prior_attempts_and_retain_the_partial_successor() {
        let stream = retried_stream();
        let full = reconstruct_inference(&stream).expect("one inference");
        for prefix_len in 1..=stream.len() {
            let prefix = reconstruct_inference(&stream[..prefix_len]).expect("one inference");
            // The last attempt may gain evidence as the prefix grows.  Every
            // attempt before that open tail must remain byte-for-byte stable.
            let earlier = prefix.attempts().len().saturating_sub(1);
            assert_eq!(
                &prefix.attempts()[..earlier],
                &full.attempts()[..earlier],
                "prefix {prefix_len} changed an earlier attempt"
            );
            assert!(
                !prefix.attempts().is_empty(),
                "prefix {prefix_len} must retain evidence"
            );
        }

        let after_first_retry = reconstruct_inference(&stream[..2]).expect("one inference");
        assert_eq!(after_first_retry.attempts().len(), 2);
        assert_eq!(
            after_first_retry.attempts()[1].terminal_state(),
            AttemptTerminalState::Truncated
        );
    }

    #[test]
    fn every_stream_prefix_is_one_ordered_partial_attempt() {
        let events: Vec<_> = (0..=2)
            .map(|ordinal| corpus(&format!("streamed-attempt/event-{ordinal}.json")))
            .collect();
        for count in 1..=events.len() {
            let reconstruction = reconstruct_inference(&events[..count]).expect("one inference");
            assert_eq!(reconstruction.attempts().len(), 1);
            let attempt = &reconstruction.attempts()[0];
            assert_eq!(attempt.stream_prefix_len(), count);
            assert_eq!(
                attempt
                    .stream_events()
                    .iter()
                    .map(|event| event.event_ordinal)
                    .collect::<Vec<_>>(),
                (0..u64::try_from(count).expect("small count")).collect::<Vec<_>>()
            );
            assert_eq!(
                attempt.terminal_state(),
                AttemptTerminalState::AbandonedMidStream {
                    events: u64::try_from(count).expect("small count")
                }
            );
        }
    }

    #[test]
    fn request_without_response_is_truncated_and_usage_is_retained() {
        let request = corpus("single-attempt/request.json");
        let reconstruction = reconstruct_inference(&[request]).expect("one inference");
        let attempt = &reconstruction.attempts()[0];
        assert!(attempt.request_present());
        assert!(!attempt.response_complete());
        assert_eq!(attempt.terminal_state(), AttemptTerminalState::Truncated);

        let streamed_usage = corpus("streamed-attempt/usage.json");
        let reconstruction = reconstruct_inference(&[streamed_usage]).expect("one inference");
        assert_eq!(reconstruction.attempts()[0].usage_reports().len(), 1);
        assert_eq!(
            reconstruction.attempts()[0].terminal_state(),
            AttemptTerminalState::Truncated
        );
    }
}
