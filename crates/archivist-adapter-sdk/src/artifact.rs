// SPDX-License-Identifier: Apache-2.0

//! The immutable-artifact and generation interfaces (plan client data
//! flow steps 3–4; requirements `SID-003` through `SID-005`, CAP-005):
//! how an adapter names *why* a source generation started, and the fixed
//! identification every captured chunk carries.
//!
//! Two contract layers meet here. Protocol owns identity —
//! `GenerationId`, `ArtifactHash`, `BlobDigest`, `OccurrenceId` are
//! layer-0 wire material derived by `archivist-protocol` — and this
//! module never re-derives any of them. What the SDK owns is the
//! adapter-side vocabulary the identity inputs come from:
//!
//! - [`GenerationCause`]: the closed set of source observations that
//!   start a generation (CAP-005: replacement, truncation, rewind, and
//!   incompatible rewrite; plan 6A's inode/identity, tail-mismatch, and
//!   digest detection).
//! - [`CapturedChunk`]: `SID-004`'s identification — artifact kind,
//!   generation, byte or event range, ordering, and the canonical
//!   payload digest — stamped with the projection version that produced
//!   it (CAP-004).
//!
//! A chunk is immutable by contract, not by enforcement: its identity
//! inputs are content-derived, its payload digest is computed over the
//! canonical uncompressed bytes, and nothing in the SDK mutates one after
//! construction. Retry and scheduling decisions may reorder *occurrences*
//! (SCH-006) but never redefine what a chunk is.

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{
    ArtifactKind, BlobDigest, GenerationId, GrammarError, RangeKind, VersionToken,
};

use crate::status::ScanClassification;

/// Why a source generation started (CAP-005, `SID-003`; plan Phase 6A's
/// detection list and Phase 6C's identity/digest rule). Closed and
/// wire-stable: the cause travels with the generation's identity inputs,
/// so the same observation must always produce the same token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GenerationCause {
    /// First observation of a source: no earlier generation exists.
    Initial,
    /// The source file's identity changed (inode or device/identity
    /// tuple) under the same name — plan Phase 6A.
    FileIdentityChange,
    /// The source content's digest changed without an identity change —
    /// plan Phase 6C's in-place rewrite detection.
    DigestChange,
    /// The source shrank: bytes or records the previous generation
    /// counted are gone (CAP-005 truncation).
    Truncation,
    /// The source moved backwards: earlier content reappeared at the
    /// tail, displacing newer content (CAP-005 rewind).
    Rewind,
    /// The source was replaced by a layout this adapter cannot read
    /// in-place: the rewrite is incompatible with the previous
    /// generation's format (CAP-005, plan `EC-08`'s fail-closed rule
    /// applied to rewrites).
    IncompatibleRewrite,
    /// The tail no longer continues the previous generation's last
    /// complete record — plan Phase 6A's tail-mismatch detection.
    TailMismatch,
}

impl GenerationCause {
    /// Every cause, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Initial,
            Self::FileIdentityChange,
            Self::DigestChange,
            Self::Truncation,
            Self::Rewind,
            Self::IncompatibleRewrite,
            Self::TailMismatch,
        ]
    }

    /// The canonical token for this cause.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::FileIdentityChange => "file-identity-change",
            Self::DigestChange => "digest-change",
            Self::Truncation => "truncation",
            Self::Rewind => "rewind",
            Self::IncompatibleRewrite => "incompatible-rewrite",
            Self::TailMismatch => "tail-mismatch",
        }
    }

    /// Parse one token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for a token outside the closed set.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "initial" => Ok(Self::Initial),
            "file-identity-change" => Ok(Self::FileIdentityChange),
            "digest-change" => Ok(Self::DigestChange),
            "truncation" => Ok(Self::Truncation),
            "rewind" => Ok(Self::Rewind),
            "incompatible-rewrite" => Ok(Self::IncompatibleRewrite),
            "tail-mismatch" => Ok(Self::TailMismatch),
            _ => Err(GrammarError::NotCanonical),
        }
    }

    /// Whether this cause can start a *subsequent* generation. Every
    /// cause except `initial` is a detection: something was observed
    /// about the source that the previous generation cannot account for.
    #[must_use]
    pub fn is_detection(self) -> bool {
        !matches!(self, Self::Initial)
    }
}

impl std::fmt::Display for GenerationCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

/// Why a generation value could not be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationError {
    /// The `initial` cause was used where a detection is required: only
    /// the first generation of a source starts without an observation.
    InitialCauseNotADetection,
}

impl std::fmt::Display for GenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = match self {
            Self::InitialCauseNotADetection => "generation_initial_cause_not_a_detection",
        };
        f.write_str(token)
    }
}

impl std::error::Error for GenerationError {}

/// One source generation: the protocol `GenerationId` minted for it,
/// paired with the observation that started it. The pairing is the
/// audit trail CAP-005 requires — a new generation always names why the
/// previous one stopped being authoritative, and both generations are
/// preserved (`SID-003`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceGeneration {
    /// The generation identifier, minted when the generation was
    /// detected (protocol `GenerationId`, `uuid-v7`).
    pub generation: GenerationId,
    /// The observation that started this generation.
    pub cause: GenerationCause,
}

impl SourceGeneration {
    /// The first generation of a source: its cause is fixed as
    /// [`GenerationCause::Initial`].
    #[must_use]
    pub fn initial(generation: GenerationId) -> Self {
        Self {
            generation,
            cause: GenerationCause::Initial,
        }
    }

    /// A subsequent generation, started by a detected observation.
    ///
    /// # Errors
    /// [`GenerationError::InitialCauseNotADetection`] when `cause` is
    /// [`GenerationCause::Initial`] — a source has exactly one initial
    /// generation, and a second one would silently orphan the first.
    pub fn detected(
        generation: GenerationId,
        cause: GenerationCause,
    ) -> Result<Self, GenerationError> {
        if !cause.is_detection() {
            return Err(GenerationError::InitialCauseNotADetection);
        }
        Ok(Self { generation, cause })
    }

    /// The status-JSON value for this generation: the identifier, the
    /// cause token, nothing else.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set("cause", Value::Text(self.cause.token().to_owned()));
        object.set(
            "generation",
            Value::Text(self.generation.as_str().to_owned()),
        );
        Value::Object(object)
    }
}

/// One immutable canonical chunk, carrying exactly `SID-004`'s
/// identification — artifact kind, generation, byte or event range,
/// ordering information, and the canonical payload digest — plus the
/// projection version that produced it (CAP-004) and its canonical
/// uncompressed size.
///
/// The identity inputs are the protocol derivation's, not re-derived
/// here: `archivist-protocol` folds kind, adapter, projection version,
/// and the adapter's artifact identity into the [`archivist_protocol::vocabulary::ArtifactHash`],
/// and generation, range, and the blob digest into the occurrence ID
/// (`SID-005`). This struct is what the adapter hands the engine to do
/// that folding; it holds no derived value itself, so it can never drift
/// from the derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedChunk {
    /// What kind of artifact this chunk is a slice of.
    pub artifact_kind: ArtifactKind,
    /// The source generation this chunk was captured from.
    pub generation: GenerationId,
    /// The range coordinate kind: byte offsets or event ordinals.
    pub range_kind: RangeKind,
    /// Inclusive range start in `range_kind` coordinates.
    pub range_start: u64,
    /// Inclusive range end in `range_kind` coordinates.
    pub range_end: u64,
    /// Ordering information: the chunk's zero-based position among the
    /// chunks captured from one generation (`SID-004`).
    pub sequence: u64,
    /// The canonical uncompressed payload digest (protocol `BlobDigest`:
    /// plain SHA-256, `STO-001`).
    pub blob: BlobDigest,
    /// The canonical uncompressed payload size in bytes — the declared
    /// size the server validates the range arithmetic against.
    pub payload_bytes: u64,
    /// The adapter projection version that produced this chunk
    /// (CAP-004): a projection change is a different artifact, not a
    /// rewrite of the same one.
    pub projection: VersionToken,
}

/// Why a chunk could not be constructed. The identity inputs are typed
/// and validated by protocol, so only the range arithmetic is checked
/// here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkError {
    /// The range end preceded its start.
    RangeInverted,
}

impl std::fmt::Display for ChunkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = match self {
            Self::RangeInverted => "chunk_range_inverted",
        };
        f.write_str(token)
    }
}

impl std::error::Error for ChunkError {}

impl CapturedChunk {
    /// Assemble a chunk, checking the range arithmetic.
    ///
    /// # Errors
    /// [`ChunkError::RangeInverted`] when `range_end < range_start`.
    // SID-004's identification is exactly nine fields; the arity is the
    // contract, matching protocol's own occurrence derivation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_kind: ArtifactKind,
        generation: GenerationId,
        range_kind: RangeKind,
        range_start: u64,
        range_end: u64,
        sequence: u64,
        blob: BlobDigest,
        payload_bytes: u64,
        projection: VersionToken,
    ) -> Result<Self, ChunkError> {
        if range_end < range_start {
            return Err(ChunkError::RangeInverted);
        }
        Ok(Self {
            artifact_kind,
            generation,
            range_kind,
            range_start,
            range_end,
            sequence,
            blob,
            payload_bytes,
            projection,
        })
    }

    /// The status-JSON value for this chunk's identification: every
    /// `SID-004` field, the payload size, and the projection version, in
    /// a fixed key set.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set(
            "artifact_kind",
            Value::Text(self.artifact_kind.token().to_owned()),
        );
        object.set("blob", Value::Text(self.blob.to_hex()));
        object.set(
            "generation",
            Value::Text(self.generation.as_str().to_owned()),
        );
        object.set(
            "payload_bytes",
            Value::Int(i64::try_from(self.payload_bytes).unwrap_or(i64::MAX)),
        );
        object.set(
            "projection",
            Value::Text(self.projection.as_str().to_owned()),
        );
        object.set("range_end", Value::Int(u63_to_i64(self.range_end)));
        object.set(
            "range_kind",
            Value::Text(self.range_kind.token().to_owned()),
        );
        object.set("range_start", Value::Int(u63_to_i64(self.range_start)));
        object.set("sequence", Value::Int(u63_to_i64(self.sequence)));
        Value::Object(object)
    }
}

/// `u64` rendered into the no-float JSON integer domain, saturating.
fn u63_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// The capture interface every source adapter implements (plan client
/// data flow steps 3–4): yield complete-record-bounded immutable chunks
/// from one source, one pull at a time.
///
/// The engine pulls; the adapter never pushes, buffers on the engine's
/// behalf, or touches the spool. `Ok(None)` means no complete record is
/// available now — an incomplete tail waits for a later pass (CAP-003,
/// plan `EC-01`) and is never truncated into a chunk. A failed pull
/// names itself through the closed [`ScanClassification`] vocabulary, the
/// same words the inventory and status contracts use, so a source that
/// stops being capturable keeps saying why.
pub trait ChunkSource {
    /// Pull the next chunk from the source, in [`CapturedChunk`]
    /// sequence order within one generation.
    ///
    /// # Errors
    /// A [`ScanClassification`] other than [`ScanClassification::Ok`]
    /// when the pull could not read the source; the classification is
    /// the error contract, not a side channel.
    fn next_chunk(&mut self) -> Result<Option<CapturedChunk>, ScanClassification>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation() -> GenerationId {
        GenerationId::parse("1a07a111-7000-7000-8000-000000000001").expect("valid generation id")
    }

    fn blob() -> BlobDigest {
        BlobDigest::from_raw([7u8; 32])
    }

    fn projection() -> VersionToken {
        VersionToken::parse("1.0.0").expect("valid version token")
    }

    #[test]
    fn generation_causes_round_trip_and_fail_closed() {
        for cause in GenerationCause::all() {
            assert_eq!(GenerationCause::parse(cause.token()).as_ref(), Ok(cause));
        }
        assert!(GenerationCause::parse("identity-change").is_err());
        assert!(GenerationCause::parse("").is_err());
        assert!(GenerationCause::parse("Initial").is_err());
        assert!(!GenerationCause::Initial.is_detection());
        for cause in GenerationCause::all() {
            if *cause != GenerationCause::Initial {
                assert!(cause.is_detection());
            }
        }
    }

    #[test]
    fn the_initial_generation_is_the_only_non_detection() {
        let first = SourceGeneration::initial(generation());
        assert_eq!(first.cause, GenerationCause::Initial);
        assert_eq!(
            String::from_utf8(first.to_json().canonical_bytes()).expect("utf8"),
            format!(
                r#"{{"cause":"initial","generation":"{}"}}"#,
                first.generation.as_str()
            )
        );

        // A second generation must name its observation.
        assert_eq!(
            SourceGeneration::detected(generation(), GenerationCause::Initial),
            Err(GenerationError::InitialCauseNotADetection)
        );
        let replaced = SourceGeneration::detected(
            GenerationId::parse("1a07a111-7000-7000-8000-000000000002")
                .expect("valid generation id"),
            GenerationCause::Truncation,
        )
        .expect("a detection");
        assert_eq!(replaced.cause, GenerationCause::Truncation);
    }

    #[test]
    fn chunks_carry_every_sid_004_field_and_reject_inverted_ranges() {
        let chunk = CapturedChunk::new(
            ArtifactKind::FileSlice,
            generation(),
            RangeKind::Byte,
            0,
            4095,
            0,
            blob(),
            4096,
            projection(),
        )
        .expect("well-formed chunk");
        assert_eq!(chunk.range_end - chunk.range_start + 1, chunk.payload_bytes);
        let text = String::from_utf8(chunk.to_json().canonical_bytes()).expect("utf8");
        // Every SID-004 identification is present in the fixed key set.
        for key in [
            "artifact_kind",
            "blob",
            "generation",
            "payload_bytes",
            "projection",
            "range_end",
            "range_kind",
            "range_start",
            "sequence",
        ] {
            assert!(text.contains(&format!(r#""{key}":"#)), "missing {key}");
        }
        assert_eq!(
            CapturedChunk::new(
                ArtifactKind::DatabaseProjection,
                generation(),
                RangeKind::Event,
                5,
                4,
                0,
                blob(),
                0,
                projection(),
            ),
            Err(ChunkError::RangeInverted)
        );
    }
}
