// SPDX-License-Identifier: Apache-2.0

//! `UUIDv7` correlation identities for exact inference capture (plan Phase 9).
//!
//! The lifecycle types make the intended scopes explicit:
//!
//! - one [`OrchestratorOperation`] owns one [`TraceId`];
//! - each logical inference started by that operation gets one
//!   [`InferenceRequestId`];
//! - each transport attempt started by that inference gets a fresh
//!   [`ProviderAttemptId`] and a dense attempt ordinal.
//!
//! The identifiers are join handles, not identity inputs. In particular,
//! this module does not participate in the session, artifact, blob, or
//! occurrence derivations in [`crate::derivation`]. A retry therefore joins
//! the same logical inference while remaining distinguishable as a provider
//! attempt, and changing any of these handles cannot change an archive
//! object's identity.

use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::vocabulary::{GenerationId, InferenceRequestId, ProviderAttemptId, RequestId, TraceId};

/// The largest attempt ordinal representable by the protocol's `u63` wire
/// shape.
const MAX_ATTEMPT_ORDINAL: u64 = 9_223_372_036_854_775_807;

/// Failure returned when a logical inference has exhausted every `u63`
/// attempt ordinal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrelationError {
    /// No further provider attempt can be assigned a valid dense ordinal.
    AttemptOrdinalExhausted,
}

impl fmt::Display for CorrelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttemptOrdinalExhausted => {
                f.write_str("logical inference attempt ordinal is exhausted")
            }
        }
    }
}

impl std::error::Error for CorrelationError {}

/// One orchestrator operation and its operation-wide trace identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchestratorOperation {
    trace_id: TraceId,
}

impl OrchestratorOperation {
    /// Start an operation with a fresh `UUIDv7` trace identity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trace_id: mint_trace_id(),
        }
    }

    /// The `UUIDv7` identity shared by all logical inferences in this
    /// operation.
    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// Start one logical inference under this operation's trace.
    #[must_use]
    pub fn start_inference(&self) -> LogicalInference {
        LogicalInference {
            trace_id: self.trace_id.clone(),
            inference_request_id: mint_inference_request_id(),
            next_attempt_ordinal: 0,
        }
    }
}

impl Default for OrchestratorOperation {
    fn default() -> Self {
        Self::new()
    }
}

/// One logical inference within an orchestrator operation.
///
/// The value owns the next attempt ordinal, so retries cannot accidentally
/// reuse an earlier attempt's ordinal. It is intentionally mutable only at
/// [`Self::start_attempt`]; the IDs already issued remain immutable.
#[derive(Debug, PartialEq, Eq)]
pub struct LogicalInference {
    trace_id: TraceId,
    inference_request_id: InferenceRequestId,
    next_attempt_ordinal: u64,
}

impl LogicalInference {
    /// The parent orchestrator operation's trace identity.
    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// The `UUIDv7` identity shared by every provider attempt in this logical
    /// inference.
    #[must_use]
    pub fn inference_request_id(&self) -> &InferenceRequestId {
        &self.inference_request_id
    }

    /// Start the next provider transport attempt.
    ///
    /// Every call returns a fresh `UUIDv7` provider-attempt identity and the
    /// next dense zero-based ordinal. The only failure is exhaustion of the
    /// protocol's non-negative `u63` ordinal range.
    ///
    /// # Errors
    ///
    /// Returns [`CorrelationError::AttemptOrdinalExhausted`] after the
    /// largest representable `u63` ordinal has already been issued.
    pub fn start_attempt(&mut self) -> Result<ProviderAttempt, CorrelationError> {
        if self.next_attempt_ordinal > MAX_ATTEMPT_ORDINAL {
            return Err(CorrelationError::AttemptOrdinalExhausted);
        }
        let attempt_ordinal = self.next_attempt_ordinal;
        self.next_attempt_ordinal = self.next_attempt_ordinal.saturating_add(1);
        Ok(ProviderAttempt {
            trace_id: self.trace_id.clone(),
            inference_request_id: self.inference_request_id.clone(),
            id: mint_provider_attempt_id(),
            attempt_ordinal,
        })
    }
}

/// One provider transport attempt, including all IDs needed to join it to
/// its orchestrator operation and logical inference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderAttempt {
    trace_id: TraceId,
    inference_request_id: InferenceRequestId,
    id: ProviderAttemptId,
    attempt_ordinal: u64,
}

impl ProviderAttempt {
    /// The parent orchestrator operation's trace identity.
    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// The parent logical inference's identity.
    #[must_use]
    pub fn inference_request_id(&self) -> &InferenceRequestId {
        &self.inference_request_id
    }

    /// The fresh `UUIDv7` identity of this one transport attempt.
    #[must_use]
    pub fn provider_attempt_id(&self) -> &ProviderAttemptId {
        &self.id
    }

    /// The dense zero-based ordinal of this attempt within its logical
    /// inference.
    #[must_use]
    pub fn attempt_ordinal(&self) -> u64 {
        self.attempt_ordinal
    }
}

/// Mint a `UUIDv7` trace identity for one orchestrator operation.
#[must_use]
pub fn mint_trace_id() -> TraceId {
    let text = mint_uuid_v7_text();
    parse_minted("trace_id", &text, TraceId::parse)
}

/// Mint a `UUIDv7` identity for one logical inference.
#[must_use]
pub fn mint_inference_request_id() -> InferenceRequestId {
    let text = mint_uuid_v7_text();
    parse_minted("inference_request_id", &text, InferenceRequestId::parse)
}

/// Mint a `UUIDv7` identity for one provider transport attempt.
#[must_use]
pub fn mint_provider_attempt_id() -> ProviderAttemptId {
    let text = mint_uuid_v7_text();
    parse_minted("provider_attempt_id", &text, ProviderAttemptId::parse)
}

/// Mint one correlation identifier (`UUIDv7`, the ERR-026 shape): the fresh
/// per-attempt handle an ingest server attempt or a client-local diagnostic
/// carries alongside a request's stable identifier. Like every identifier
/// here it is a correlation handle only and never an input to a content or
/// provenance identity derivation.
///
/// # Panics
/// Never in practice: the minted text is constructed in canonical form and
/// re-validated through the protocol's own grammar as a belt-and-braces
/// check.
#[must_use]
pub fn mint_correlation_id() -> RequestId {
    let text = mint_uuid_v7_text();
    RequestId::parse(&text)
        .unwrap_or_else(|_| panic!("minted correlation id is not canonical UUIDv7"))
}

/// Mint a `UUIDv7` source-generation identity: the fresh generation a
/// source adapter opens when a detected discontinuity — replacement,
/// truncation, rewind, incompatible rewrite, tail mismatch, or digest
/// change — closes the previous one (SID-003; plan `EC-02`). The identity
/// is frozen at detection, minted exactly once and never re-derived from
/// content, so two rotations of the same cause are still distinct
/// generations and both histories stay separable.
///
/// # Panics
/// Never in practice: the minted text is constructed in canonical form and
/// re-validated through the protocol's own grammar as a belt-and-braces
/// check.
#[must_use]
pub fn mint_generation_id() -> GenerationId {
    let text = mint_uuid_v7_text();
    parse_minted("generation_id", &text, GenerationId::parse)
}

fn parse_minted<T>(
    name: &str,
    text: &str,
    parse: fn(&str) -> Result<T, crate::vocabulary::GrammarError>,
) -> T {
    parse(text).unwrap_or_else(|_| panic!("minted {name} is not canonical UUIDv7"))
}

/// Make one canonical `UUIDv7` text value using the Unix millisecond clock and
/// 74 random bits. `/dev/urandom` is the normal source; the fallback keeps
/// local generation unique enough for environments without that device by
/// mixing a process-local atomic sequence into the clock and process ID.
fn mint_uuid_v7_text() -> String {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });
    let mut random = [0u8; 9];
    if File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .is_err()
    {
        fill_fallback(&mut random);
    }

    let timestamp = milliseconds.to_be_bytes();
    let mut bytes = [0u8; 16];
    bytes[..6].copy_from_slice(&timestamp[2..]);
    // UUIDv7: version 7, 12-bit rand_a, RFC 9562 variant 10, and
    // 62-bit rand_b. The nine source bytes provide exactly 74 random bits.
    bytes[6] = 0x70 | (random[0] >> 4);
    bytes[7] = (random[0] << 4) | (random[1] >> 4);
    bytes[8] = 0x80 | (random[1] & 0x3f);
    bytes[9..].copy_from_slice(&random[2..]);

    let mut text = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        let _ = write!(text, "{byte:02x}");
    }
    text
}

static FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fill_fallback(buffer: &mut [u8; 9]) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        });
    let sequence = FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut state = now ^ u64::from(std::process::id()).rotate_left(17) ^ sequence;
    for (index, byte) in buffer.iter_mut().enumerate() {
        state = splitmix64(state.wrapping_add(u64::try_from(index).expect("index fits u64")));
        *byte = u8::try_from(state >> 56).expect("top byte fits u8");
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::{artifact_hash, blob_digest, occurrence_id, session_hash};
    use crate::vocabulary::{
        AdapterId, ArtifactKind, ClientId, GenerationId, HarnessId, RangeKind, TenantId,
        VersionToken,
    };

    #[test]
    fn generated_ids_are_canonical_uuid_v7_values() {
        let trace = mint_trace_id();
        let request = mint_inference_request_id();
        let attempt = mint_provider_attempt_id();
        let correlation = mint_correlation_id();
        let generation = mint_generation_id();
        for text in [
            trace.as_str(),
            request.as_str(),
            attempt.as_str(),
            correlation.as_str(),
            generation.as_str(),
        ] {
            assert_eq!(text.len(), 36);
            assert_eq!(text.as_bytes()[14], b'7');
            assert!(matches!(text.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
            assert!(
                text.bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
            );
        }
        assert_ne!(trace.as_str(), request.as_str());
        assert_ne!(request.as_str(), attempt.as_str());
        assert_ne!(trace.as_str(), attempt.as_str());
        // Each minted correlation id is fresh: two calls never share one.
        assert_ne!(correlation.as_str(), mint_correlation_id().as_str());
        // Each minted generation id is fresh too: two rotations of the
        // same cause are still distinct generations.
        assert_ne!(generation.as_str(), mint_generation_id().as_str());
    }

    #[test]
    fn lifecycle_scopes_trace_inference_and_attempt_ids() {
        let operation = OrchestratorOperation::new();
        let mut first = operation.start_inference();
        let first_attempt = first.start_attempt().expect("first attempt");
        let second_attempt = first.start_attempt().expect("retry attempt");
        let mut second = operation.start_inference();
        let other_attempt = second.start_attempt().expect("second inference attempt");

        assert_eq!(first_attempt.trace_id(), operation.trace_id());
        assert_eq!(second_attempt.trace_id(), operation.trace_id());
        assert_eq!(other_attempt.trace_id(), operation.trace_id());
        assert_eq!(
            first_attempt.inference_request_id(),
            first.inference_request_id()
        );
        assert_eq!(
            second_attempt.inference_request_id(),
            first.inference_request_id()
        );
        assert_ne!(first.inference_request_id(), second.inference_request_id());
        assert_ne!(
            first_attempt.provider_attempt_id(),
            second_attempt.provider_attempt_id()
        );
        assert_ne!(
            second_attempt.provider_attempt_id(),
            other_attempt.provider_attempt_id()
        );
        assert_eq!(first_attempt.attempt_ordinal(), 0);
        assert_eq!(second_attempt.attempt_ordinal(), 1);
        assert_eq!(other_attempt.attempt_ordinal(), 0);
    }

    #[test]
    fn correlation_handles_do_not_change_archive_identities() {
        let tenant = TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").unwrap();
        let origin = ClientId::parse("aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f").unwrap();
        let harness = HarnessId::parse("claude-code").unwrap();
        let session = session_hash(&tenant, &origin, &harness, "upstream-session");
        let artifact = artifact_hash(
            &session,
            ArtifactKind::FileSlice,
            &AdapterId::parse("adapter").unwrap(),
            &VersionToken::parse("1").unwrap(),
            "artifact",
        );
        let generation = GenerationId::parse("1a07a111-7000-7000-8000-000000000001").unwrap();
        let blob = blob_digest(b"same canonical provider bytes");
        let occurrence = occurrence_id(
            &session,
            &artifact,
            &generation,
            RangeKind::Byte,
            0,
            31,
            &blob,
        );
        let operation = OrchestratorOperation::new();
        let mut inference = operation.start_inference();
        let attempt = inference.start_attempt().expect("attempt");
        let mut retry_inference = operation.start_inference();
        let retry = retry_inference.start_attempt().expect("retry attempt");

        assert_ne!(attempt.provider_attempt_id(), retry.provider_attempt_id());
        assert_eq!(blob, blob_digest(b"same canonical provider bytes"));
        assert_eq!(
            occurrence,
            occurrence_id(
                &session,
                &artifact,
                &generation,
                RangeKind::Byte,
                0,
                31,
                &blob,
            )
        );
        assert_eq!(
            session,
            session_hash(&tenant, &origin, &harness, "upstream-session")
        );
    }
}
