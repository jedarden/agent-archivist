// SPDX-License-Identifier: Apache-2.0

//! The capture-side sequencing layer over the exact-inference artifact
//! (plan Phase 9): the state machine that turns one boundary's
//! observations of one logical inference into a correctly partitioned
//! artifact stream.
//!
//! [`crate::inference_artifact`] types one record; this module types the
//! *sequence* of records one capture session produces. Two properties the
//! wire cannot recover after the fact are enforced here, at the moment a
//! record is built, so a mis-stamped record cannot exist rather than must
//! be detected later:
//!
//! - **Attempt boundaries.** Every record is stamped with the current
//!   transport attempt's identity — the fresh [`ProviderAttemptId`] and
//!   dense zero-based `attempt_ordinal` minted by
//!   [`crate::correlation::LogicalInference::start_attempt`] — and the
//!   caller has no way to name an attempt. Once an attempt ends (a
//!   [`transport_error`](AttemptSequencer::transport_error) below the
//!   decoded-content boundary, or a
//!   [`retry`](AttemptSequencer::retry) transition) no further record can
//!   carry its identity: the boundary records the failure and the retry
//!   supersedes it, or the emission is refused.
//! - **Retry-transition ordering.** A retry closes the current attempt
//!   and opens the next; the `retry` record it emits is stamped with the
//!   *successor's* identity (its own `attempt_ordinal` and
//!   `provider_attempt_id`) and cites the closed attempt through
//!   `retry_of_attempt_ordinal` — exactly the
//!   [`schemas/v1/examples/inference/retried-attempt`] shape: ordinals
//!   0→1→2, each retry citing the attempt it follows, artifacts
//!   partitioned per attempt and never merged.
//!
//! Within one attempt the layer enforces the per-attempt shapes the
//! reconstruction fold relies on: at most one decoded request and one
//! decoded response; stream events dense from zero and strictly
//! monotonic, never after the decoded response (the events of one
//! attempt, ordered by `event_ordinal`, concatenate byte-for-byte to the
//! attempt's decoded body); and exactly one `transport-error` record,
//! produced while the failure is still below the decoded-content boundary
//! and carrying only `error_class` and `timeout_ms` — never silence, and
//! never a fabricated decoded payload, because the failure path takes no
//! bytes argument at all.
//!
//! Payload members are built only from the bytes the boundary actually
//! observed: each emitter takes the decoded bytes and derives their plain
//! SHA-256 digest and size itself (the one label-less digest,
//! [`crate::derivation::blob_digest`]), so a record cannot name bytes
//! that never arrived. The digest covers content only — the retried
//! request reuses the first attempt's exact bytes and therefore the same
//! payload digest across two attempts; correlation handles are join keys
//! and enter no digest.
//!
//! The sequencer owns one logical inference's whole attempt history. It
//! holds no artifacts: each method returns the record it built, and the
//! caller records it in emission order. Ending a capture is simply
//! stopping — a completed attempt and an attempt closed by a
//! `transport-error` record are both first-class terminal states.
//!
//! [`ProviderAttemptId`]: crate::vocabulary::ProviderAttemptId
//! [`schemas/v1/examples/inference/retried-attempt`]:
//!     ../../../schemas/v1/examples/inference/retried-attempt

use crate::correlation::{LogicalInference, ProviderAttempt};
use crate::derivation::blob_digest;
use crate::inference_artifact::{BoundaryEvent, InferenceArtifact, Metadata, Payload};
use crate::json::Object;
use crate::vocabulary::{
    ClientId, RetryReason, TenantId, Timestamp, TransportErrorClass, UsageSource,
};

/// Why the boundary could not record an observation in sequence.
///
/// Every variant is a sequencing refusal: the observation may be real,
/// but recording it would break an attempt boundary, a retry edge, or a
/// per-attempt shape the reconstruction fold depends on. None of them is
/// recoverable by dropping the record silently — the caller sees the
/// refusal and decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceError {
    /// The logical inference has exhausted every `u63` attempt ordinal,
    /// so the next retry transition could not mint a fresh attempt
    /// identity.
    AttemptOrdinalExhausted,
    /// [`AttemptSequencer::start_attempt`] was called while the exchange
    /// already runs attempt `attempt_ordinal`. Only
    /// [`AttemptSequencer::retry`] closes one attempt and opens the next;
    /// a second `start_attempt` would mint an attempt with no retry edge
    /// naming its predecessor.
    AttemptAlreadyStarted {
        /// The attempt already running for this exchange.
        attempt_ordinal: u64,
    },
    /// The observation arrived before the exchange's first attempt
    /// started. Every record is stamped with the current attempt's
    /// identity, and until [`AttemptSequencer::start_attempt`] there is
    /// none to stamp.
    NoOpenAttempt,
    /// The attempt already produced its one `transport-error` record and
    /// is closed. A retry transition supersedes it; nothing else may name
    /// it again — this is what keeps a below-boundary failure exactly one
    /// record, never silence and never a second account of it.
    AttemptClosed {
        /// The closed attempt the observation tried to name.
        attempt_ordinal: u64,
    },
    /// The attempt already produced its decoded `provider-request` record.
    /// One transport attempt sends one request; a second request on the
    /// same attempt means the boundary missed an attempt transition, not
    /// that two requests share an identity.
    RequestAlreadyCaptured {
        /// The attempt that already carries its request record.
        attempt_ordinal: u64,
    },
    /// The attempt already produced its decoded `provider-response`
    /// record.
    ResponseAlreadyCaptured {
        /// The attempt that already carries its response record.
        attempt_ordinal: u64,
    },
    /// A stream event arrived after the attempt's decoded response. The
    /// stream was complete, and a later event would break the
    /// concatenation rule — the attempt's events, ordered by
    /// `event_ordinal`, are its decoded body.
    StreamEventAfterResponse {
        /// The attempt whose response already completed the stream.
        attempt_ordinal: u64,
    },
    /// A transport failure was reported after the attempt's decoded
    /// response. The failure is above the decoded-content boundary, and a
    /// `transport-error` record for it would claim a second outcome for
    /// an attempt that already has one.
    TransportErrorAfterResponse {
        /// The attempt whose response already completed.
        attempt_ordinal: u64,
    },
    /// The attempt's next `event_ordinal` would overflow the protocol's
    /// `u63` wire shape; the attempt's stream cannot continue to be
    /// recorded.
    EventOrdinalExhausted {
        /// The attempt whose stream ran out of ordinals.
        attempt_ordinal: u64,
    },
    /// The observation carries no decoded bytes. A decoded request,
    /// response, or stream event is at least one byte by schema; an empty
    /// body is the payload member's absence, and these kinds have no
    /// payload-less form.
    EmptyPayload {
        /// The attempt the empty observation tried to name.
        attempt_ordinal: u64,
    },
    /// The observation's `capture_time` is not a real calendar instant
    /// (VAL-002), so the record it would stamp would fail the protocol's
    /// own validation.
    InvalidCaptureTime,
}

impl std::fmt::Display for SequenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AttemptOrdinalExhausted => {
                f.write_str("logical inference attempt ordinal is exhausted")
            }
            Self::AttemptAlreadyStarted { attempt_ordinal } => write!(
                f,
                "attempt {attempt_ordinal} is already this exchange's current attempt; \
                 only a retry transition opens the next one"
            ),
            Self::NoOpenAttempt => f.write_str("no transport attempt is running; start one first"),
            Self::AttemptClosed { attempt_ordinal } => write!(
                f,
                "attempt {attempt_ordinal} ended in its transport-error record and is \
                 closed; only a retry transition may supersede it"
            ),
            Self::RequestAlreadyCaptured { attempt_ordinal } => write!(
                f,
                "attempt {attempt_ordinal} already carries its decoded request record"
            ),
            Self::ResponseAlreadyCaptured { attempt_ordinal } => write!(
                f,
                "attempt {attempt_ordinal} already carries its decoded response record"
            ),
            Self::StreamEventAfterResponse { attempt_ordinal } => write!(
                f,
                "attempt {attempt_ordinal}'s stream is complete; no event may follow its \
                 decoded response"
            ),
            Self::TransportErrorAfterResponse { attempt_ordinal } => write!(
                f,
                "attempt {attempt_ordinal} already decoded its response; the failure is \
                 above the decoded-content boundary"
            ),
            Self::EventOrdinalExhausted { attempt_ordinal } => write!(
                f,
                "attempt {attempt_ordinal}'s stream has exhausted its event ordinals"
            ),
            Self::EmptyPayload { attempt_ordinal } => write!(
                f,
                "attempt {attempt_ordinal}'s observation carries no decoded bytes; an \
                 empty body is the payload's absence"
            ),
            Self::InvalidCaptureTime => f.write_str("capture_time is not a real calendar instant"),
        }
    }
}

impl std::error::Error for SequenceError {}

/// One transport attempt the sequencer is currently tracking, with the
/// per-attempt progress the sequencing rules read and advance.
#[derive(Debug, PartialEq, Eq)]
struct AttemptTrack {
    attempt: ProviderAttempt,
    /// The ordinal the attempt's next stream event carries; dense from
    /// zero, so the events of one attempt are strictly monotonic and the
    /// next attempt restarts at zero with its own fresh track.
    next_event_ordinal: u64,
    request_captured: bool,
    response_captured: bool,
    /// The attempt produced its one `transport-error` record. Emissions
    /// are refused until a retry transition supersedes the attempt.
    failed: bool,
}

impl AttemptTrack {
    fn for_attempt(attempt: ProviderAttempt) -> Self {
        Self {
            attempt,
            next_event_ordinal: 0,
            request_captured: false,
            response_captured: false,
            failed: false,
        }
    }

    fn attempt_ordinal(&self) -> u64 {
        self.attempt.attempt_ordinal()
    }

    /// Refuse any further record for an attempt that already ended in its
    /// transport-error record.
    fn ensure_open(&self) -> Result<(), SequenceError> {
        if self.failed {
            return Err(SequenceError::AttemptClosed {
                attempt_ordinal: self.attempt_ordinal(),
            });
        }
        Ok(())
    }
}

/// The capture-side sequencer for one logical inference: it mints each
/// transport attempt's identity, stamps every record with it, and orders
/// retry transitions.
///
/// Construct it with the logical inference a
/// [`crate::correlation::OrchestratorOperation`] started, then drive the
/// boundary's observations through it in the order they happened. Every
/// method returns the [`InferenceArtifact`] it built; the caller records
/// it in emission order. The sequencer keeps no copies — the record, once
/// returned, is the caller's.
#[derive(Debug)]
pub struct AttemptSequencer {
    tenant_id: TenantId,
    origin_client_id: ClientId,
    inference: LogicalInference,
    current: Option<AttemptTrack>,
}

impl AttemptSequencer {
    /// A sequencer for `inference`, which does not yet have a running
    /// transport attempt; [`Self::start_attempt`] opens the first one.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        origin_client_id: ClientId,
        inference: LogicalInference,
    ) -> Self {
        Self {
            tenant_id,
            origin_client_id,
            inference,
            current: None,
        }
    }

    /// Start the exchange's first transport attempt: a fresh
    /// [`ProviderAttemptId`] with the dense ordinal `0`, minted by the
    /// logical inference itself so the correlation semantics stay in one
    /// place.
    ///
    /// # Errors
    ///
    /// [`SequenceError::AttemptAlreadyStarted`] when an attempt is
    /// already running — only [`Self::retry`] opens a second attempt — or
    /// [`SequenceError::AttemptOrdinalExhausted`] when the logical
    /// inference has exhausted its `u63` ordinals.
    pub fn start_attempt(&mut self) -> Result<ProviderAttempt, SequenceError> {
        if let Some(track) = &self.current {
            return Err(SequenceError::AttemptAlreadyStarted {
                attempt_ordinal: track.attempt_ordinal(),
            });
        }
        let attempt = self.mint_attempt()?;
        self.current = Some(AttemptTrack::for_attempt(attempt.clone()));
        Ok(attempt)
    }

    /// The attempt records are currently stamped with, until the caller
    /// ends the exchange without a final retry.
    #[must_use]
    pub fn current_attempt(&self) -> Option<&ProviderAttempt> {
        self.current.as_ref().map(|track| &track.attempt)
    }

    /// Record the attempt's decoded request body.
    ///
    /// # Errors
    ///
    /// [`SequenceError::NoOpenAttempt`] before the first attempt,
    /// [`SequenceError::AttemptClosed`] once the attempt ended in its
    /// transport-error record, [`SequenceError::RequestAlreadyCaptured`]
    /// on a second request, [`SequenceError::EmptyPayload`] for empty
    /// bytes, [`SequenceError::InvalidCaptureTime`] for a non-calendar
    /// instant.
    pub fn provider_request(
        &mut self,
        bytes: &[u8],
        metadata: Option<Metadata>,
        capture_time: Option<Timestamp>,
    ) -> Result<InferenceArtifact, SequenceError> {
        Self::checked_time(capture_time.as_ref())?;
        let track = self.current.as_mut().ok_or(SequenceError::NoOpenAttempt)?;
        track.ensure_open()?;
        if track.request_captured {
            return Err(SequenceError::RequestAlreadyCaptured {
                attempt_ordinal: track.attempt_ordinal(),
            });
        }
        let payload = Self::payload(bytes, track)?;
        track.request_captured = true;
        Ok(Self::stamp(
            track,
            &self.tenant_id,
            &self.origin_client_id,
            BoundaryEvent::ProviderRequest,
            Some(payload),
            metadata,
            capture_time,
        ))
    }

    /// Record the attempt's decoded response body.
    ///
    /// # Errors
    ///
    /// [`SequenceError::NoOpenAttempt`] before the first attempt,
    /// [`SequenceError::AttemptClosed`] once the attempt ended in its
    /// transport-error record, [`SequenceError::ResponseAlreadyCaptured`]
    /// on a second response, [`SequenceError::EmptyPayload`] for empty
    /// bytes, [`SequenceError::InvalidCaptureTime`] for a non-calendar
    /// instant.
    pub fn provider_response(
        &mut self,
        bytes: &[u8],
        metadata: Option<Metadata>,
        capture_time: Option<Timestamp>,
    ) -> Result<InferenceArtifact, SequenceError> {
        Self::checked_time(capture_time.as_ref())?;
        let track = self.current.as_mut().ok_or(SequenceError::NoOpenAttempt)?;
        track.ensure_open()?;
        if track.response_captured {
            return Err(SequenceError::ResponseAlreadyCaptured {
                attempt_ordinal: track.attempt_ordinal(),
            });
        }
        let payload = Self::payload(bytes, track)?;
        track.response_captured = true;
        Ok(Self::stamp(
            track,
            &self.tenant_id,
            &self.origin_client_id,
            BoundaryEvent::ProviderResponse,
            Some(payload),
            metadata,
            capture_time,
        ))
    }

    /// Record one decoded event of the attempt's stream, stamped with the
    /// attempt's next dense `event_ordinal`.
    ///
    /// # Errors
    ///
    /// [`SequenceError::NoOpenAttempt`] before the first attempt,
    /// [`SequenceError::AttemptClosed`] once the attempt ended in its
    /// transport-error record, [`SequenceError::StreamEventAfterResponse`]
    /// once the decoded response completed the stream,
    /// [`SequenceError::EventOrdinalExhausted`] when the attempt's `u63`
    /// event ordinals run out, [`SequenceError::EmptyPayload`] for empty
    /// bytes, [`SequenceError::InvalidCaptureTime`] for a non-calendar
    /// instant.
    pub fn stream_event(
        &mut self,
        bytes: &[u8],
        metadata: Option<Metadata>,
        capture_time: Option<Timestamp>,
    ) -> Result<InferenceArtifact, SequenceError> {
        Self::checked_time(capture_time.as_ref())?;
        let track = self.current.as_mut().ok_or(SequenceError::NoOpenAttempt)?;
        track.ensure_open()?;
        if track.response_captured {
            return Err(SequenceError::StreamEventAfterResponse {
                attempt_ordinal: track.attempt_ordinal(),
            });
        }
        let event_ordinal = track.next_event_ordinal;
        let payload = Self::payload(bytes, track)?;
        track.next_event_ordinal =
            event_ordinal
                .checked_add(1)
                .ok_or(SequenceError::EventOrdinalExhausted {
                    attempt_ordinal: track.attempt_ordinal(),
                })?;
        Ok(Self::stamp(
            track,
            &self.tenant_id,
            &self.origin_client_id,
            BoundaryEvent::StreamingEvent { event_ordinal },
            Some(payload),
            metadata,
            capture_time,
        ))
    }

    /// Record the usage counters the boundary extracted from the
    /// attempt's response body or one of its stream events. The three
    /// counters are required — a `usage` record without them fails the
    /// protocol's own validation, so there is no way to emit a partial
    /// one.
    ///
    /// The record carries no payload member of its own: the counters are
    /// joined to the bytes they were read from through `usage_source` and
    /// the attempt identity, not by copying the bytes.
    ///
    /// # Errors
    ///
    /// [`SequenceError::NoOpenAttempt`] before the first attempt,
    /// [`SequenceError::AttemptClosed`] once the attempt ended in its
    /// transport-error record, [`SequenceError::InvalidCaptureTime`] for
    /// a non-calendar instant.
    pub fn usage(
        &mut self,
        usage_source: UsageSource,
        input_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
        capture_time: Option<Timestamp>,
    ) -> Result<InferenceArtifact, SequenceError> {
        Self::checked_time(capture_time.as_ref())?;
        let track = self.current.as_ref().ok_or(SequenceError::NoOpenAttempt)?;
        track.ensure_open()?;
        let metadata = Metadata {
            content_type: None,
            provider_request_id: None,
            http_status: None,
            rate_limit_limit: None,
            rate_limit_remaining: None,
            rate_limit_reset: None,
            usage_input_tokens: Some(input_tokens),
            usage_output_tokens: Some(output_tokens),
            usage_total_tokens: Some(total_tokens),
        };
        Ok(Self::stamp(
            track,
            &self.tenant_id,
            &self.origin_client_id,
            BoundaryEvent::Usage { usage_source },
            None,
            Some(metadata),
            capture_time,
        ))
    }

    /// Record a transport failure below the decoded-content boundary:
    /// exactly one `transport-error` record for the attempt, carrying
    /// only `error_class` and `timeout_ms`. The method takes no bytes
    /// argument, so it cannot fabricate a decoded payload, and after it
    /// returns the attempt is closed — a second failure on the same
    /// attempt is [`SequenceError::AttemptClosed`], never a second
    /// record.
    ///
    /// # Errors
    ///
    /// [`SequenceError::NoOpenAttempt`] before the first attempt,
    /// [`SequenceError::AttemptClosed`] when the attempt already ended in
    /// its transport-error record,
    /// [`SequenceError::TransportErrorAfterResponse`] once the decoded
    /// response completed (the failure would be above the
    /// decoded-content boundary), [`SequenceError::InvalidCaptureTime`]
    /// for a non-calendar instant.
    pub fn transport_error(
        &mut self,
        error_class: TransportErrorClass,
        timeout_ms: Option<u64>,
        capture_time: Option<Timestamp>,
    ) -> Result<InferenceArtifact, SequenceError> {
        Self::checked_time(capture_time.as_ref())?;
        let track = self.current.as_mut().ok_or(SequenceError::NoOpenAttempt)?;
        track.ensure_open()?;
        if track.response_captured {
            return Err(SequenceError::TransportErrorAfterResponse {
                attempt_ordinal: track.attempt_ordinal(),
            });
        }
        track.failed = true;
        Ok(Self::stamp(
            track,
            &self.tenant_id,
            &self.origin_client_id,
            BoundaryEvent::TransportError {
                error_class,
                timeout_ms,
            },
            None,
            None,
            capture_time,
        ))
    }

    /// Close the current attempt and start the next one, emitting the
    /// retry record that joins them. The record is stamped with the
    /// *successor's* identity — its own `attempt_ordinal` and
    /// `provider_attempt_id` — and cites the closed attempt through
    /// `retry_of_attempt_ordinal`, which the dense ordinals keep strictly
    /// below it. Every later record of the exchange carries the new
    /// attempt's identity, because the new attempt is the only one there
    /// is to stamp with.
    ///
    /// A retry may follow a decoded failure response (a 429 with its
    /// payload recorded) or a closed transport-error attempt; both are
    /// the corpus's retried-exchange shape. The record carries no payload
    /// or metadata of its own.
    ///
    /// # Errors
    ///
    /// [`SequenceError::NoOpenAttempt`] before the first attempt (retry
    /// citations must name a real predecessor),
    /// [`SequenceError::AttemptOrdinalExhausted`] when the logical
    /// inference has exhausted its `u63` ordinals,
    /// [`SequenceError::InvalidCaptureTime`] for a non-calendar instant.
    pub fn retry(
        &mut self,
        retry_reason: RetryReason,
        backoff_ms: Option<u64>,
        capture_time: Option<Timestamp>,
    ) -> Result<InferenceArtifact, SequenceError> {
        Self::checked_time(capture_time.as_ref())?;
        let retry_of_attempt_ordinal = self
            .current
            .as_ref()
            .ok_or(SequenceError::NoOpenAttempt)?
            .attempt_ordinal();
        let next = self.mint_attempt()?;
        let artifact = Self::stamp(
            &AttemptTrack::for_attempt(next.clone()),
            &self.tenant_id,
            &self.origin_client_id,
            BoundaryEvent::Retry {
                retry_of_attempt_ordinal,
                retry_reason,
                backoff_ms,
            },
            None,
            None,
            capture_time,
        );
        self.current = Some(AttemptTrack::for_attempt(next));
        Ok(artifact)
    }

    /// Mint the next attempt identity from the logical inference, mapping
    /// the correlation error.
    fn mint_attempt(&mut self) -> Result<ProviderAttempt, SequenceError> {
        self.inference.start_attempt().map_err(|error| match error {
            crate::correlation::CorrelationError::AttemptOrdinalExhausted => {
                SequenceError::AttemptOrdinalExhausted
            }
        })
    }

    /// Build the payload member from bytes the boundary actually
    /// observed: the plain SHA-256 digest of those bytes and their size,
    /// nothing else. Refuses empty bytes — an empty body is the payload
    /// member's absence, never a zero entry.
    fn payload(bytes: &[u8], track: &AttemptTrack) -> Result<Payload, SequenceError> {
        if bytes.is_empty() {
            return Err(SequenceError::EmptyPayload {
                attempt_ordinal: track.attempt_ordinal(),
            });
        }
        Ok(Payload {
            payload_digest: blob_digest(bytes),
            payload_size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            unknown_fields: Object::new(),
        })
    }

    /// Reject a non-calendar `capture_time` before it can be frozen into
    /// a record the protocol's own validation would refuse.
    fn checked_time(capture_time: Option<&Timestamp>) -> Result<(), SequenceError> {
        if let Some(time) = capture_time
            && !time.calendar_valid()
        {
            return Err(SequenceError::InvalidCaptureTime);
        }
        Ok(())
    }

    /// Stamp the common members: the exchange's provenance pair and the
    /// track attempt's identity, plus the kind-specific payload and
    /// observation. No correlation member enters any digest — the payload
    /// digest was already taken over content only.
    #[allow(clippy::too_many_arguments)]
    fn stamp(
        track: &AttemptTrack,
        tenant_id: &TenantId,
        origin_client_id: &ClientId,
        event: BoundaryEvent,
        payload: Option<Payload>,
        metadata: Option<Metadata>,
        capture_time: Option<Timestamp>,
    ) -> InferenceArtifact {
        let attempt = &track.attempt;
        InferenceArtifact {
            tenant_id: tenant_id.clone(),
            origin_client_id: origin_client_id.clone(),
            trace_id: attempt.trace_id().clone(),
            inference_request_id: attempt.inference_request_id().clone(),
            provider_attempt_id: attempt.provider_attempt_id().clone(),
            attempt_ordinal: attempt.attempt_ordinal(),
            capture_time,
            payload,
            metadata,
            event,
            unknown_fields: Object::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation::OrchestratorOperation;
    use crate::sha256::{digest, encode_hex};
    use crate::vocabulary::InferenceArtifactKind;
    use crate::vocabulary::ProviderAttemptId;

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const ORIGIN: &str = "aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f";
    const TIME: &str = "2026-09-12T16:44:05Z";

    /// A sequencer over a freshly minted logical inference.
    fn sequencer() -> AttemptSequencer {
        AttemptSequencer::new(
            TenantId::parse(TENANT).expect("tenant parses"),
            ClientId::parse(ORIGIN).expect("origin parses"),
            OrchestratorOperation::new().start_inference(),
        )
    }

    fn time() -> Timestamp {
        Timestamp::parse(TIME).expect("timestamp parses")
    }

    fn metadata_with_status(status: u64) -> Option<Metadata> {
        Some(Metadata {
            content_type: Some("application/json".to_owned()),
            provider_request_id: None,
            http_status: Some(status),
            rate_limit_limit: None,
            rate_limit_remaining: None,
            rate_limit_reset: None,
            usage_input_tokens: None,
            usage_output_tokens: None,
            usage_total_tokens: None,
        })
    }

    /// Every emitted record is a fixed point of the protocol's own
    /// validation: it parses from its canonical bytes to an equal value.
    fn assert_round_trips(artifact: &InferenceArtifact) {
        let canonical = artifact.canonical_bytes();
        let reparsed = InferenceArtifact::parse(&canonical).expect("emitted record validates");
        assert_eq!(reparsed, *artifact, "emission must round-trip");
    }

    /// (a) No two transport attempts of one logical inference share an
    /// attempt ordinal or a provider attempt ID: the ordinals are dense
    /// from zero and every minted identity is fresh.
    #[test]
    fn attempts_never_share_an_ordinal_or_provider_attempt_id() {
        let mut sequencer = sequencer();
        let first = sequencer.start_attempt().expect("first attempt");
        let mut ordinals = vec![first.attempt_ordinal()];
        let mut ids = vec![first.provider_attempt_id().clone()];
        for expected_ordinal in 1..=4u64 {
            sequencer
                .retry(RetryReason::TransportError, None, Some(time()))
                .expect("retry transition");
            let attempt = sequencer.current_attempt().expect("current attempt");
            assert_eq!(attempt.attempt_ordinal(), expected_ordinal);
            ordinals.push(attempt.attempt_ordinal());
            ids.push(attempt.provider_attempt_id().clone());
        }
        for index in 0..ordinals.len() {
            assert_eq!(ordinals[index], index as u64, "ordinals are dense");
            for other in (index + 1)..ordinals.len() {
                assert_ne!(ordinals[index], ordinals[other]);
                assert_ne!(ids[index], ids[other], "attempt ids never repeat");
            }
        }
    }

    /// (b) A retried exchange yields artifacts partitioned per attempt
    /// with a retry edge between consecutive attempts and never merged
    /// into one attempt — the corpus's retried-attempt shape: a 429
    /// response, a retry, a transport error, a retry, then the retried
    /// request and its 200 response.
    #[test]
    fn retried_exchange_partitions_per_attempt_with_retry_edges() {
        let mut sequencer = sequencer();
        let request_bytes = b"{\"model\":\"synthetic\",\"prompt\":\"hi\"}";
        let mut artifacts = Vec::new();

        let _first = sequencer.start_attempt().expect("first attempt");
        artifacts.push(
            sequencer
                .provider_request(request_bytes, None, Some(time()))
                .expect("request"),
        );
        artifacts.push(
            sequencer
                .provider_response(
                    b"{\"error\":\"rate_limited\"}",
                    metadata_with_status(429),
                    Some(time()),
                )
                .expect("429 response"),
        );
        artifacts.push(
            sequencer
                .retry(RetryReason::RateLimit, Some(20_000), Some(time()))
                .expect("retry after 429"),
        );
        artifacts.push(
            sequencer
                .transport_error(TransportErrorClass::Connect, None, Some(time()))
                .expect("transport error"),
        );
        artifacts.push(
            sequencer
                .retry(RetryReason::TransportError, None, Some(time()))
                .expect("retry after transport error"),
        );
        artifacts.push(
            sequencer
                .provider_request(request_bytes, None, Some(time()))
                .expect("retried request"),
        );
        artifacts.push(
            sequencer
                .provider_response(
                    b"{\"output\":\"hello\"}",
                    metadata_with_status(200),
                    Some(time()),
                )
                .expect("200 response"),
        );

        // Three attempts, never merged: 0 (the 429), 1 (the transport
        // error), 2 (the success). Each retry record is stamped with its
        // successor's identity, so the exchange ends on attempt 2.
        assert_eq!(
            sequencer
                .current_attempt()
                .expect("live attempt")
                .attempt_ordinal(),
            2
        );

        // Partition per attempt: every artifact of an ordinal carries one
        // provider attempt id, and the identities differ across ordinals.
        let mut seen_ordinals: Vec<u64> = Vec::new();
        let mut seen_ids: Vec<&ProviderAttemptId> = Vec::new();
        for artifact in &artifacts {
            match seen_ordinals
                .iter()
                .position(|ordinal| *ordinal == artifact.attempt_ordinal)
            {
                Some(index) => assert_eq!(
                    seen_ids[index], &artifact.provider_attempt_id,
                    "attempt {} must carry exactly one identity",
                    artifact.attempt_ordinal
                ),
                None => {
                    seen_ordinals.push(artifact.attempt_ordinal);
                    seen_ids.push(&artifact.provider_attempt_id);
                }
            }
        }
        assert_eq!(seen_ordinals.len(), 3, "three attempts, never merged");
        for index in 0..seen_ordinals.len() {
            assert_eq!(seen_ordinals[index], index as u64, "dense ordinals");
            for other in (index + 1)..seen_ordinals.len() {
                assert_ne!(seen_ids[index], seen_ids[other]);
            }
        }

        // The retry edges: exactly two retry records, each naming the
        // attempt it follows and stamped with its successor.
        let retries: Vec<&InferenceArtifact> = artifacts
            .iter()
            .filter(|artifact| artifact.kind() == InferenceArtifactKind::Retry)
            .collect();
        assert_eq!(retries.len(), 2, "one retry edge per transition");
        for (edge, retry) in retries.iter().enumerate() {
            let BoundaryEvent::Retry {
                retry_of_attempt_ordinal,
                ..
            } = &retry.event
            else {
                panic!("filtered to retry records");
            };
            assert_eq!(*retry_of_attempt_ordinal, edge as u64);
            assert_eq!(retry.attempt_ordinal, edge as u64 + 1);
        }

        // The partition is byte-stable once captured: every record is a
        // fixed point of the protocol's own validation.
        for artifact in &artifacts {
            assert_round_trips(artifact);
        }
    }

    /// (c) Event ordinals are strictly monotonic within an attempt, dense
    /// from zero, and restart for the next attempt.
    #[test]
    fn event_ordinals_are_monotonic_within_an_attempt_and_restart() {
        let mut sequencer = sequencer();
        let _first = sequencer.start_attempt().expect("first attempt");
        let mut ordinals = Vec::new();
        for _ in 0..3 {
            let artifact = sequencer
                .stream_event(b"event-bytes", None, Some(time()))
                .expect("stream event");
            let BoundaryEvent::StreamingEvent { event_ordinal } = artifact.event else {
                panic!("stream events are streaming-event records");
            };
            ordinals.push(event_ordinal);
        }
        assert_eq!(ordinals, [0, 1, 2], "dense and strictly monotonic");
        sequencer
            .retry(RetryReason::StreamIncomplete, Some(100), Some(time()))
            .expect("retry");
        let artifact = sequencer
            .stream_event(b"retry-event", None, Some(time()))
            .expect("stream event on the retry");
        let BoundaryEvent::StreamingEvent { event_ordinal } = artifact.event else {
            panic!("stream events are streaming-event records");
        };
        assert_eq!(event_ordinal, 0, "the next attempt restarts at zero");
        assert_round_trips(&artifact);
    }

    /// (d) A below-boundary failure yields exactly one transport-error
    /// artifact and zero decoded payload artifacts; the attempt is closed
    /// afterwards, and a retry transition is the only way forward.
    #[test]
    fn below_boundary_failure_yields_one_transport_error_and_no_decoded_payloads() {
        let mut sequencer = sequencer();
        let _first = sequencer.start_attempt().expect("first attempt");
        let mut artifacts = Vec::new();
        artifacts.push(
            sequencer
                .provider_request(b"{\"model\":\"synthetic\"}", None, Some(time()))
                .expect("request"),
        );
        artifacts.push(
            sequencer
                .transport_error(TransportErrorClass::ReadTimeout, Some(30_000), Some(time()))
                .expect("the one transport error"),
        );

        let decoded_payloads = artifacts
            .iter()
            .filter(|artifact| {
                matches!(
                    artifact.kind(),
                    InferenceArtifactKind::ProviderResponse | InferenceArtifactKind::StreamingEvent
                )
            })
            .count();
        assert_eq!(decoded_payloads, 0, "no decoded payload is fabricated");
        let transport_errors = artifacts
            .iter()
            .filter(|artifact| artifact.kind() == InferenceArtifactKind::TransportError)
            .count();
        assert_eq!(transport_errors, 1, "exactly one transport-error record");
        let error = artifacts
            .last()
            .expect("the transport error closes the stream");
        assert_eq!(
            error.provider_attempt_id, artifacts[0].provider_attempt_id,
            "the failure names the attempt that failed"
        );
        let BoundaryEvent::TransportError { timeout_ms, .. } = &error.event else {
            panic!("filtered to the transport error");
        };
        assert_eq!(*timeout_ms, Some(30_000));
        assert_round_trips(error);

        // The attempt is closed: nothing else may be recorded for it, and
        // a second transport error is refused rather than emitted.
        for attempted in ["request", "response", "stream", "usage", "error"] {
            let outcome = match attempted {
                "request" => sequencer
                    .provider_request(b"bytes", None, Some(time()))
                    .map(|_| ()),
                "response" => sequencer
                    .provider_response(b"bytes", None, Some(time()))
                    .map(|_| ()),
                "stream" => sequencer
                    .stream_event(b"bytes", None, Some(time()))
                    .map(|_| ()),
                "usage" => sequencer
                    .usage(UsageSource::ResponseBody, 1, 1, 2, Some(time()))
                    .map(|_| ()),
                _ => sequencer
                    .transport_error(TransportErrorClass::Other, None, Some(time()))
                    .map(|_| ()),
            };
            assert_eq!(
                outcome,
                Err(SequenceError::AttemptClosed { attempt_ordinal: 0 }),
                "{attempted} after the transport error must be refused"
            );
        }

        // The retry transition is the only way forward, and the new
        // attempt records normally.
        sequencer
            .retry(RetryReason::TransportError, None, Some(time()))
            .expect("retry");
        sequencer
            .provider_request(b"bytes", None, Some(time()))
            .expect("the retried attempt records its request");
    }

    /// A transport failure after the decoded response is refused: the
    /// failure is above the decoded-content boundary, and the attempt
    /// already has its outcome.
    #[test]
    fn transport_error_after_the_decoded_response_is_refused() {
        let mut sequencer = sequencer();
        let _first = sequencer.start_attempt().expect("first attempt");
        sequencer
            .provider_request(b"bytes", None, Some(time()))
            .expect("request");
        sequencer
            .provider_response(b"bytes", None, Some(time()))
            .expect("response");
        assert_eq!(
            sequencer.transport_error(TransportErrorClass::ConnectionReset, None, Some(time())),
            Err(SequenceError::TransportErrorAfterResponse { attempt_ordinal: 0 })
        );
    }

    /// Every observation before the first attempt is refused, including a
    /// retry (its citation would name a predecessor that never existed).
    #[test]
    fn observations_before_the_first_attempt_are_refused() {
        let mut sequencer = sequencer();
        assert_eq!(
            sequencer.provider_request(b"bytes", None, None),
            Err(SequenceError::NoOpenAttempt)
        );
        assert_eq!(
            sequencer.provider_response(b"bytes", None, None),
            Err(SequenceError::NoOpenAttempt)
        );
        assert_eq!(
            sequencer.stream_event(b"bytes", None, None),
            Err(SequenceError::NoOpenAttempt)
        );
        assert_eq!(
            sequencer.usage(UsageSource::ResponseBody, 1, 2, 3, None),
            Err(SequenceError::NoOpenAttempt)
        );
        assert_eq!(
            sequencer.transport_error(TransportErrorClass::Dns, None, None),
            Err(SequenceError::NoOpenAttempt)
        );
        assert_eq!(
            sequencer.retry(RetryReason::Timeout, None, None),
            Err(SequenceError::NoOpenAttempt)
        );
        assert!(sequencer.current_attempt().is_none());
        let _first = sequencer.start_attempt().expect("first attempt");
        sequencer
            .provider_request(b"bytes", None, Some(time()))
            .expect("records normally once started");
    }

    /// One request and one response per attempt: a second of either is a
    /// boundary bug, and a stream event after the decoded response would
    /// break the concatenation rule.
    #[test]
    fn per_attempt_shapes_are_enforced() {
        let mut sequencer = sequencer();
        let _first = sequencer.start_attempt().expect("first attempt");
        sequencer
            .provider_request(b"bytes", None, Some(time()))
            .expect("first request");
        assert_eq!(
            sequencer.provider_request(b"bytes", None, Some(time())),
            Err(SequenceError::RequestAlreadyCaptured { attempt_ordinal: 0 })
        );
        sequencer
            .provider_response(b"bytes", None, Some(time()))
            .expect("first response");
        assert_eq!(
            sequencer.provider_response(b"bytes", None, Some(time())),
            Err(SequenceError::ResponseAlreadyCaptured { attempt_ordinal: 0 })
        );
        assert_eq!(
            sequencer.stream_event(b"bytes", None, Some(time())),
            Err(SequenceError::StreamEventAfterResponse { attempt_ordinal: 0 })
        );
    }

    /// A second `start_attempt` is refused: only a retry transition opens
    /// the next attempt, so no attempt can be minted without an edge
    /// naming its predecessor.
    #[test]
    fn start_attempt_twice_is_refused() {
        let mut sequencer = sequencer();
        let _first = sequencer.start_attempt().expect("first attempt");
        assert_eq!(
            sequencer.start_attempt(),
            Err(SequenceError::AttemptAlreadyStarted { attempt_ordinal: 0 })
        );
        sequencer
            .retry(RetryReason::HttpStatus, Some(250), Some(time()))
            .expect("retry opens the next attempt");
        assert_eq!(
            sequencer.start_attempt(),
            Err(SequenceError::AttemptAlreadyStarted { attempt_ordinal: 1 })
        );
    }

    /// The usage record carries the three counters the schema requires
    /// and round-trips through the protocol's own validation.
    #[test]
    fn usage_carries_the_three_required_counters() {
        let mut sequencer = sequencer();
        let _first = sequencer.start_attempt().expect("first attempt");
        let artifact = sequencer
            .usage(UsageSource::ResponseBody, 3, 5, 8, Some(time()))
            .expect("usage");
        assert_eq!(artifact.kind(), InferenceArtifactKind::Usage);
        let metadata = artifact.metadata.as_ref().expect("usage metadata");
        assert_eq!(metadata.usage_input_tokens, Some(3));
        assert_eq!(metadata.usage_output_tokens, Some(5));
        assert_eq!(metadata.usage_total_tokens, Some(8));
        assert_eq!(artifact.payload, None);
        assert_round_trips(&artifact);
    }

    /// The payload member is derived from the bytes the boundary
    /// observed: the digest is the plain SHA-256 of those bytes, the size
    /// matches, and the retried request's identical bytes produce the
    /// identical digest across two attempts — correlation handles enter
    /// no digest.
    #[test]
    fn payload_digests_cover_content_only() {
        let mut sequencer = sequencer();
        let _first = sequencer.start_attempt().expect("first attempt");
        let first = sequencer
            .provider_request(b"identical-bytes", None, Some(time()))
            .expect("first request");
        sequencer
            .retry(RetryReason::HttpStatus, None, Some(time()))
            .expect("retry");
        let second = sequencer
            .provider_request(b"identical-bytes", None, Some(time()))
            .expect("retried request");
        let first_payload = first.payload.as_ref().expect("first payload");
        let second_payload = second.payload.as_ref().expect("second payload");
        assert_eq!(
            first_payload.payload_digest.to_hex(),
            encode_hex(&digest(b"identical-bytes")),
            "the digest is the plain SHA-256 of the captured bytes"
        );
        assert_eq!(first_payload.payload_size, 15);
        assert_eq!(
            first_payload.payload_digest, second_payload.payload_digest,
            "identical bytes share one digest across attempts"
        );
        assert_ne!(first.provider_attempt_id, second.provider_attempt_id);
    }

    /// Empty captured bytes and a non-calendar capture time are refused
    /// rather than frozen into a record the protocol would reject.
    #[test]
    fn degenerate_observations_are_refused() {
        let mut sequencer = sequencer();
        let _first = sequencer.start_attempt().expect("first attempt");
        assert_eq!(
            sequencer.provider_request(b"", None, Some(time())),
            Err(SequenceError::EmptyPayload { attempt_ordinal: 0 })
        );
        let impossible = Timestamp::parse("2026-13-45T99:99:99Z")
            .expect("the grammar alone accepts impossible dates");
        assert_eq!(
            sequencer.provider_request(b"bytes", None, Some(impossible)),
            Err(SequenceError::InvalidCaptureTime)
        );
        sequencer
            .provider_request(b"bytes", None, Some(time()))
            .expect("a valid observation still records");
    }
}
