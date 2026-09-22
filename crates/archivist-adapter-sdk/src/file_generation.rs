// SPDX-License-Identifier: Apache-2.0

//! The file-source capture core's generation detection (plan Phase 6A,
//! CAP-005, `SID-003`, plan `EC-02`, threat-model AC-03): compare one
//! prior acknowledged observation against the current one and decide
//! whether the source's generation continues, or a detected
//! discontinuity closes it and opens a new one.
//!
//! A file source is only ever captured *through* a generation: the
//! identity inputs, content digest, and acknowledged complete-byte length
//! one pass observed are the contract the next pass is held to. When the
//! next observation agrees — same file identity, acknowledged prefix
//! intact, whatever grew is ordinary append — the same generation
//! continues and nothing rotates. When it does not, the previous
//! generation stops being authoritative and a new `UUIDv7` generation
//! opens with a cause naming exactly what was observed; the caller keeps
//! both histories (`EC-02`), and capture restarts at the new generation's
//! first complete record (AC-03's mitigation).
//!
//! Each detection cause maps to exactly one observation shape, resolved
//! by fixed precedence so one observation produces exactly one cause:
//!
//! | Precedence | Observation shape | Cause |
//! |---|---|---|
//! | 1 | the file identity changed under the same name | [`GenerationCause::FileIdentityChange`] |
//! | 2 | the complete prefix shrank and the surviving head contradicts the acknowledged head digest | [`GenerationCause::Rewind`] |
//! | 3 | the complete prefix shrank (surviving head intact, or too short to consult) | [`GenerationCause::Truncation`] |
//! | 4 | the acknowledged prefix digest is intact | no rotation — the generation continues |
//! | 5 | the prefix differs but the head before the last acknowledged record is unchanged | [`GenerationCause::TailMismatch`] |
//! | 6 | the prefix and head differ at the acknowledged scale (`L1 == L0`) | [`GenerationCause::IncompatibleRewrite`] |
//! | 7 | the prefix and head differ and the source grew past it (`L1 > L0`) | [`GenerationCause::DigestChange`] |
//!
//! The head and tail regions are cut with the lexical rule of the
//! boundary module — the acknowledged tail region is the acknowledged
//! prefix's last complete record — so tail-mismatch detection and
//! boundary selection can never disagree about where a record ends.
//! Digests are plain SHA-256 over complete-prefix bytes only: an
//! incomplete tail is measured by the boundary module and enters no
//! digest, no acknowledgement, and no decision.
//!
//! [`RecordBoundary`]: crate::file_capture::RecordBoundary

use archivist_protocol::correlation::mint_generation_id;
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::BlobDigest;

use crate::artifact::{GenerationCause, SourceGeneration};
use crate::file_capture::RecordBoundary;

/// The operating-system identity of the observed source file (plan Phase
/// 6A's inode/identity detection): the device and inode tuple a `stat`
/// reports, carried as plain data so the detection contract never touches
/// the filesystem itself. An adapter reads the tuple from its own stat
/// call and presents it here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    /// The device the file lives on.
    pub device: u64,
    /// The inode number on that device.
    pub inode: u64,
}

impl FileIdentity {
    /// Present one stat tuple as the file identity.
    #[must_use]
    pub fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }
}

/// Why an acknowledged state could not be reconstructed from persisted
/// parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcknowledgedSourceError {
    /// The tail-record start exceeded the acknowledged prefix length:
    /// the persisted parts do not describe any byte range the
    /// acknowledgement could have covered.
    TailStartBeyondPrefix,
}

impl std::fmt::Display for AcknowledgedSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = match self {
            Self::TailStartBeyondPrefix => "acknowledged_tail_start_beyond_prefix",
        };
        f.write_str(token)
    }
}

impl std::error::Error for AcknowledgedSourceError {}

/// The prior observation a detection compares against: the source file's
/// identity, the acknowledged complete-byte length, and the plain
/// SHA-256 digests of the regions the decision table consults — the whole
/// acknowledged prefix, the head before its last complete record, and
/// that last complete record (the acknowledged tail).
///
/// The digests are complete-prefix material only: an incomplete tail is
/// the boundary module's to measure and enters nothing here. Build one
/// from a snapshot with [`AcknowledgedSource::acknowledge`], or
/// reconstruct the persisted parts of an earlier acknowledgement with
/// [`AcknowledgedSource::from_parts`] — the engine persists the parts,
/// not the snapshot, so detection survives a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcknowledgedSource {
    identity: FileIdentity,
    complete_bytes: u64,
    content: BlobDigest,
    head: BlobDigest,
    tail_start: u64,
    tail: BlobDigest,
}

impl AcknowledgedSource {
    /// Acknowledge one observation of the source: the complete-record
    /// prefix the boundary module selects is the acknowledged region, and
    /// its digest regions are computed here. The incomplete tail is
    /// measured and never acknowledged.
    #[must_use]
    pub fn acknowledge(identity: FileIdentity, snapshot: &[u8]) -> Self {
        let boundary = RecordBoundary::select(snapshot);
        let prefix = RecordBoundary::complete_prefix(snapshot);
        let complete_bytes = boundary.complete_bytes;
        let tail_start = last_record_start(prefix);
        Self {
            identity,
            complete_bytes,
            content: digest_range(prefix, 0, complete_bytes),
            head: digest_range(prefix, 0, tail_start),
            tail_start,
            tail: digest_range(prefix, tail_start, complete_bytes),
        }
    }

    /// Reconstruct the persisted parts of an earlier acknowledgement.
    ///
    /// # Errors
    /// [`AcknowledgedSourceError::TailStartBeyondPrefix`] when the
    /// tail-record start exceeds the acknowledged prefix length.
    pub fn from_parts(
        identity: FileIdentity,
        complete_bytes: u64,
        content: BlobDigest,
        head: BlobDigest,
        tail_start: u64,
        tail: BlobDigest,
    ) -> Result<Self, AcknowledgedSourceError> {
        if tail_start > complete_bytes {
            return Err(AcknowledgedSourceError::TailStartBeyondPrefix);
        }
        Ok(Self {
            identity,
            complete_bytes,
            content,
            head,
            tail_start,
            tail,
        })
    }

    /// The file identity this acknowledgement observed.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// The acknowledged complete-byte length: bytes inside complete
    /// records only, the same figure the boundary module selects.
    #[must_use]
    pub const fn complete_bytes(&self) -> u64 {
        self.complete_bytes
    }

    /// The offset where the acknowledged prefix's last complete record —
    /// the acknowledged tail — begins.
    #[must_use]
    pub const fn tail_start(&self) -> u64 {
        self.tail_start
    }

    /// The digest of the whole acknowledged prefix.
    #[must_use]
    pub const fn content_digest(&self) -> BlobDigest {
        self.content
    }

    /// The digest of the head before the acknowledged tail record.
    #[must_use]
    pub const fn head_digest(&self) -> BlobDigest {
        self.head
    }

    /// The digest of the acknowledged tail record.
    #[must_use]
    pub const fn tail_digest(&self) -> BlobDigest {
        self.tail
    }
}

/// The current observation of one file source: the file identity a stat
/// reports and the snapshot's own bytes, with the boundary module's
/// complete-record split selected once and reused by every comparison.
#[derive(Clone, Copy, Debug)]
pub struct SourceObservation<'a> {
    identity: FileIdentity,
    snapshot: &'a [u8],
    boundary: RecordBoundary,
}

impl<'a> SourceObservation<'a> {
    /// Observe one snapshot: the boundary is selected here, so the
    /// detection and any later capture split agree on where completeness
    /// ends.
    #[must_use]
    pub fn observe(identity: FileIdentity, snapshot: &'a [u8]) -> Self {
        Self {
            identity,
            snapshot,
            boundary: RecordBoundary::select(snapshot),
        }
    }

    /// The observed file identity.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// The boundary module's split of this snapshot: the complete prefix
    /// the detection consults, and the measured tail it never does.
    #[must_use]
    pub const fn boundary(&self) -> RecordBoundary {
        self.boundary
    }

    /// The observed snapshot's complete-record prefix: every byte the
    /// detection may reason about.
    #[must_use]
    pub fn complete_prefix(&self) -> &'a [u8] {
        RecordBoundary::complete_prefix(self.snapshot)
    }
}

/// What one observation means for the source's generation.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenerationDecision {
    /// The observation agrees with the acknowledged state: the same
    /// generation continues and nothing rotates.
    Continue,
    /// A detected discontinuity closed the acknowledged generation and a
    /// new one opened: the carried [`SourceGeneration`] names the
    /// detection cause and the `UUIDv7` identifier frozen at detection.
    /// The caller preserves both histories (`EC-02`).
    Rotated(SourceGeneration),
}

impl GenerationDecision {
    /// The cause a rotation carried, or [`Option::None`] when the
    /// generation continues.
    #[must_use]
    pub fn cause(&self) -> Option<GenerationCause> {
        match self {
            Self::Continue => None,
            Self::Rotated(opened) => Some(opened.cause),
        }
    }

    /// The opened generation, when the decision rotated.
    #[must_use]
    pub const fn opened(&self) -> Option<&SourceGeneration> {
        match self {
            Self::Continue => None,
            Self::Rotated(opened) => Some(opened),
        }
    }
}

/// Decide what the current observation means for the acknowledged
/// generation: continue it, or close it and open a new one.
///
/// The decision table in the [module documentation](self) resolves the
/// shapes by fixed precedence, so one observation produces exactly one
/// cause. A rotated generation's `UUIDv7` identifier is minted here —
/// frozen at detection, never re-derived from content — so two rotations
/// of the same cause are still distinct generations.
///
/// [`RecordBoundary`]: crate::file_capture::RecordBoundary
pub fn detect_generation(
    acknowledged: &AcknowledgedSource,
    observed: &SourceObservation<'_>,
) -> GenerationDecision {
    let prefix = observed.complete_prefix();
    let complete = observed.boundary().complete_bytes;

    // Precedence 1: the file under the same name is a different file.
    // Replacement wins over every content signal — the bytes are not
    // comparable evidence once the identity is gone.
    if observed.identity() != acknowledged.identity() {
        return rotated(GenerationCause::FileIdentityChange);
    }

    // The source lost acknowledged bytes: a shrink is decided by whether
    // the surviving head still agrees with what was acknowledged.
    if complete < acknowledged.complete_bytes() {
        let head_observable = complete >= acknowledged.tail_start();
        if head_observable
            && digest_range(prefix, 0, acknowledged.tail_start()) != acknowledged.head_digest()
        {
            // Precedence 2: the surviving head contradicts the
            // acknowledged head — earlier content re-observed, newer
            // content displaced.
            return rotated(GenerationCause::Rewind);
        }
        // Precedence 3: the acknowledged head survives intact (or the
        // source is too short to consult it) and the complete prefix is
        // simply shorter than acknowledged.
        return rotated(GenerationCause::Truncation);
    }

    // Precedence 4: the acknowledged prefix is byte-intact. Growth past
    // it is ordinary append, and an identical observation changes
    // nothing — the same generation continues either way.
    if digest_range(prefix, 0, acknowledged.complete_bytes()) == acknowledged.content_digest() {
        return GenerationDecision::Continue;
    }

    // Precedence 5: the acknowledged region changed in place, but the
    // head before the last acknowledged record is unchanged — the
    // acknowledged tail no longer matches the source tail.
    if digest_range(prefix, 0, acknowledged.tail_start()) == acknowledged.head_digest() {
        return rotated(GenerationCause::TailMismatch);
    }

    // Precedence 6: same scale, different bytes.
    if complete == acknowledged.complete_bytes() {
        return rotated(GenerationCause::IncompatibleRewrite);
    }

    // Precedence 7: an in-place rewrite that also grew past the
    // acknowledged scale — the general digest signal.
    rotated(GenerationCause::DigestChange)
}

/// Open the generation a detection cause starts, minting its `UUIDv7`
/// identifier at exactly this moment.
fn rotated(cause: GenerationCause) -> GenerationDecision {
    // Every cause the decision table returns is a detection; the initial
    // cause is unreachable here by construction.
    let generation = SourceGeneration::detected(mint_generation_id(), cause)
        .expect("a detection cause always starts a generation");
    GenerationDecision::Rotated(generation)
}

/// The generation history of one file source: the open generation with
/// its acknowledged observation, and every generation detection has
/// closed before it.
///
/// The tracker is the history-preserving composition of
/// [`detect_generation`] across passes: a rotation moves the closed
/// generation onto the history unchanged — its cause and identifier stay
/// exactly as detection froze them — and acknowledges the current
/// snapshot as the new generation's starting state, so the two histories
/// can never merge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileGenerationTracker {
    current: SourceGeneration,
    acknowledged: AcknowledgedSource,
    closed: Vec<SourceGeneration>,
}

impl FileGenerationTracker {
    /// Begin tracking a source at its first observation: the initial
    /// generation is minted here, and this snapshot's complete-record
    /// prefix is the first acknowledgement.
    #[must_use]
    pub fn begin(identity: FileIdentity, snapshot: &[u8]) -> Self {
        Self {
            current: SourceGeneration::initial(mint_generation_id()),
            acknowledged: AcknowledgedSource::acknowledge(identity, snapshot),
            closed: Vec::new(),
        }
    }

    /// Observe one pass over the source: decide, rotate when detection
    /// says so, and acknowledge the snapshot either way — the new
    /// generation's starting state after a rotation, the advanced
    /// acknowledgement after ordinary growth.
    pub fn observe(&mut self, identity: FileIdentity, snapshot: &[u8]) -> GenerationDecision {
        let observed = SourceObservation::observe(identity, snapshot);
        let decision = detect_generation(&self.acknowledged, &observed);
        if let GenerationDecision::Rotated(opened) = &decision {
            self.closed.push(self.current.clone());
            self.current = opened.clone();
        }
        self.acknowledged = AcknowledgedSource::acknowledge(identity, snapshot);
        decision
    }

    /// The open generation.
    #[must_use]
    pub const fn current(&self) -> &SourceGeneration {
        &self.current
    }

    /// The closed generations, in rotation order. Each entry keeps the
    /// cause and identifier detection froze it with; the open generation
    /// is never in this list.
    #[must_use]
    pub fn history(&self) -> &[SourceGeneration] {
        &self.closed
    }

    /// The open generation's acknowledged observation.
    #[must_use]
    pub const fn acknowledged(&self) -> &AcknowledgedSource {
        &self.acknowledged
    }
}

/// The offset where a complete prefix's last record begins: the byte
/// after the previous newline, by the boundary module's lexical rule. An
/// empty or single-record prefix starts its tail record at zero.
fn last_record_start(prefix: &[u8]) -> u64 {
    let Some(last) = prefix.iter().rposition(|&byte| byte == b'\n') else {
        return 0;
    };
    // A complete prefix is newline-terminated, so `last` indexes the
    // final byte and the scan below stays in bounds.
    match prefix[..last].iter().rposition(|&byte| byte == b'\n') {
        Some(previous) => u64::try_from(previous + 1).unwrap_or(u64::MAX),
        None => 0,
    }
}

/// Digest one byte range of a complete prefix, `[start..end)`. Every
/// bound is an acknowledged or boundary length measured from the same
/// slice, so the arithmetic is total for anything this module observes.
fn digest_range(prefix: &[u8], start: u64, end: u64) -> BlobDigest {
    let from = usize::try_from(start).expect("a digest bound is a measured length");
    let to = usize::try_from(end).expect("a digest bound is a measured length");
    BlobDigest::from_raw(sha256::digest(&prefix[from..to]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use archivist_protocol::vocabulary::GenerationId;

    const ALPHA: &[u8] = b"alpha-record-1\n";
    const BETA: &[u8] = b"beta-record-2\n";
    const GAMMA: &[u8] = b"gamma-record-3\n";
    const DELTA: &[u8] = b"delta-record-4\n";
    const EPSILON: &[u8] = b"epsilon-recd-5\n";

    /// Stale replacements: byte-for-byte lengths, different content.
    const ALPHA_STALE: &[u8] = b"alpha-stale--1\n";
    const BETA_STALE: &[u8] = b"beta-stale--2\n";
    const EPSILON_STALE: &[u8] = b"epsilon-stale5\n";

    fn identity() -> FileIdentity {
        FileIdentity::new(7, 1)
    }

    fn replaced_identity() -> FileIdentity {
        FileIdentity::new(7, 2)
    }

    fn concatenate(records: &[&[u8]]) -> Vec<u8> {
        let mut snapshot = Vec::new();
        for record in records {
            snapshot.extend_from_slice(record);
        }
        snapshot
    }

    fn base_snapshot() -> Vec<u8> {
        concatenate(&[ALPHA, BETA, GAMMA, DELTA, EPSILON])
    }

    fn uuid_v7_assertions(id: &GenerationId) {
        let text = id.as_str();
        assert_eq!(text.len(), 36, "canonical uuid text length");
        assert_eq!(&text[14..15], "7", "the version nibble must be 7");
        assert!(
            matches!(&text[19..20], "8" | "9" | "a" | "b"),
            "the variant nibble must be the RFC 9562 one"
        );
    }

    /// One fault vector: the identity presented on the next pass, the
    /// snapshot it observes, and the cause the decision table owes.
    struct FaultVector {
        name: &'static str,
        identity: FileIdentity,
        snapshot: Vec<u8>,
        expected: Option<GenerationCause>,
    }

    fn fault_vectors() -> Vec<FaultVector> {
        vec![
            FaultVector {
                name: "agreeing-observation",
                identity: identity(),
                snapshot: base_snapshot(),
                expected: None,
            },
            FaultVector {
                name: "ordinary-append-growth",
                identity: identity(),
                snapshot: concatenate(&[ALPHA, BETA, GAMMA, DELTA, EPSILON, b"zeta-record-6\n"]),
                expected: None,
            },
            FaultVector {
                name: "file-replaced-under-the-same-name",
                identity: replaced_identity(),
                snapshot: base_snapshot(),
                expected: Some(GenerationCause::FileIdentityChange),
            },
            // The acknowledged tail record is gone; the head survives.
            FaultVector {
                name: "tail-truncated",
                identity: identity(),
                snapshot: concatenate(&[ALPHA, BETA, GAMMA, DELTA]),
                expected: Some(GenerationCause::Truncation),
            },
            // Shorter than the head itself: the length rule alone.
            FaultVector {
                name: "deep-truncation",
                identity: identity(),
                snapshot: concatenate(&[ALPHA, BETA]),
                expected: Some(GenerationCause::Truncation),
            },
            // A shrink whose surviving head contradicts the acknowledged
            // head: an earlier state is back.
            FaultVector {
                name: "rollback-to-earlier-content",
                identity: identity(),
                snapshot: concatenate(&[ALPHA_STALE, BETA_STALE, GAMMA, DELTA]),
                expected: Some(GenerationCause::Rewind),
            },
            // Same scale, only the acknowledged tail record rewritten.
            FaultVector {
                name: "acknowledged-tail-rewritten",
                identity: identity(),
                snapshot: concatenate(&[ALPHA, BETA, GAMMA, DELTA, EPSILON_STALE]),
                expected: Some(GenerationCause::TailMismatch),
            },
            // Same scale, head rewritten too.
            FaultVector {
                name: "same-scale-rewrite",
                identity: identity(),
                snapshot: concatenate(&[ALPHA_STALE, BETA_STALE, GAMMA, DELTA, EPSILON]),
                expected: Some(GenerationCause::IncompatibleRewrite),
            },
            // An in-place rewrite that also grew.
            FaultVector {
                name: "in-place-rewrite-that-grew",
                identity: identity(),
                snapshot: concatenate(&[
                    ALPHA_STALE,
                    BETA_STALE,
                    GAMMA,
                    DELTA,
                    EPSILON,
                    b"zeta-record-6\n",
                ]),
                expected: Some(GenerationCause::DigestChange),
            },
        ]
    }

    #[test]
    fn every_fault_vector_produces_its_own_cause_and_noop_continues() {
        let snapshot = base_snapshot();
        let acknowledged = AcknowledgedSource::acknowledge(identity(), &snapshot);

        for vector in fault_vectors() {
            let observed = SourceObservation::observe(vector.identity, &vector.snapshot);
            let decision = detect_generation(&acknowledged, &observed);
            assert_eq!(
                decision.cause(),
                vector.expected,
                "vector {} decided the wrong cause",
                vector.name
            );
            if let GenerationDecision::Rotated(opened) = &decision {
                uuid_v7_assertions(&opened.generation);
                assert_eq!(
                    opened.cause,
                    vector.expected.expect("a rotation has a cause")
                );
            }
        }

        // The detection vectors cover the whole closed detection
        // vocabulary — each cause maps to exactly one shape, and the
        // no-op case maps to none of them.
        let exercised: Vec<_> = fault_vectors()
            .iter()
            .filter_map(|vector| vector.expected)
            .collect();
        for cause in GenerationCause::all() {
            assert_eq!(
                exercised.contains(cause),
                cause.is_detection(),
                "{} is {} the table",
                cause.token(),
                if cause.is_detection() {
                    "missing from"
                } else {
                    "wrongly in"
                }
            );
        }
    }

    #[test]
    fn two_rotations_of_the_same_cause_freeze_distinct_uuidv7_ids() {
        let snapshot = base_snapshot();
        let acknowledged = AcknowledgedSource::acknowledge(identity(), &snapshot);

        // The same truncation fault observed twice: the cause is
        // identical, but each detection mints its own generation.
        let truncated = concatenate(&[ALPHA, BETA, GAMMA, DELTA]);
        let first = detect_generation(
            &acknowledged,
            &SourceObservation::observe(identity(), &truncated),
        );
        let second = detect_generation(
            &acknowledged,
            &SourceObservation::observe(identity(), &truncated),
        );
        let GenerationDecision::Rotated(first) = first else {
            panic!("a truncation rotates");
        };
        let GenerationDecision::Rotated(second) = second else {
            panic!("the repeated detection rotates");
        };
        assert_eq!(first.cause, second.cause);
        assert_ne!(first.generation, second.generation);
        uuid_v7_assertions(&first.generation);
        uuid_v7_assertions(&second.generation);
    }

    #[test]
    fn the_initial_generation_never_rotates_an_empty_acknowledgement() {
        // Nothing acknowledged yet: content can never contradict an empty
        // prefix, so observation never rotates it.
        let acknowledged = AcknowledgedSource::acknowledge(identity(), b"");
        for snapshot in [Vec::new(), concatenate(&[ALPHA]), base_snapshot()] {
            let observed = SourceObservation::observe(identity(), &snapshot);
            assert_eq!(
                detect_generation(&acknowledged, &observed),
                GenerationDecision::Continue,
                "an empty acknowledgement continues"
            );
        }
        // Identity still rules: a replaced file rotates even with nothing
        // acknowledged.
        let snapshot = base_snapshot();
        let observed = SourceObservation::observe(replaced_identity(), &snapshot);
        assert_eq!(
            detect_generation(&acknowledged, &observed).cause(),
            Some(GenerationCause::FileIdentityChange)
        );
    }

    #[test]
    fn a_single_record_source_still_detects_tail_and_length_faults() {
        let snapshot = concatenate(&[ALPHA]);
        let acknowledged = AcknowledgedSource::acknowledge(identity(), &snapshot);
        assert_eq!(acknowledged.tail_start(), 0, "one record is all tail");

        // The head region is empty and vacuously intact, so a same-scale
        // rewrite of the only record is a tail mismatch.
        let rewritten_snapshot = concatenate(&[ALPHA_STALE]);
        let rewritten = SourceObservation::observe(identity(), &rewritten_snapshot);
        assert_eq!(
            detect_generation(&acknowledged, &rewritten).cause(),
            Some(GenerationCause::TailMismatch)
        );

        // A shrink survives the vacuous head check and stays truncation:
        // an entirely-torn snapshot acknowledges nothing complete.
        let torn = SourceObservation::observe(identity(), b"alpha-reco");
        assert_eq!(
            detect_generation(&acknowledged, &torn).cause(),
            Some(GenerationCause::Truncation)
        );
    }

    #[test]
    fn replacement_wins_over_every_content_signal() {
        let snapshot = base_snapshot();
        let acknowledged = AcknowledgedSource::acknowledge(identity(), &snapshot);
        // A replaced file that also shrank to contradicting content is
        // named by the identity, not the bytes.
        let shrunk_snapshot = concatenate(&[ALPHA_STALE, BETA_STALE]);
        let observed = SourceObservation::observe(replaced_identity(), &shrunk_snapshot);
        assert_eq!(
            detect_generation(&acknowledged, &observed).cause(),
            Some(GenerationCause::FileIdentityChange)
        );
    }

    #[test]
    fn the_tracker_preserves_every_history_it_closes() {
        let mut tracker = FileGenerationTracker::begin(identity(), &base_snapshot());
        assert_eq!(tracker.current().cause, GenerationCause::Initial);
        uuid_v7_assertions(&tracker.current().generation);
        assert!(tracker.history().is_empty());

        let initial = tracker.current().clone();

        // An agreeing pass and ordinary growth both continue the initial
        // generation: no spurious rotation, empty history.
        let grown_snapshot = concatenate(&[ALPHA, BETA, GAMMA, DELTA, EPSILON, b"zeta-record-6\n"]);
        let continuing = tracker.observe(identity(), &base_snapshot());
        assert_eq!(continuing, GenerationDecision::Continue);
        let grown = tracker.observe(identity(), &grown_snapshot);
        assert_eq!(grown, GenerationDecision::Continue);
        assert_eq!(tracker.current(), &initial);
        assert!(tracker.history().is_empty());
        assert_eq!(
            tracker.acknowledged().complete_bytes(),
            widened(grown_snapshot.len()),
            "growth advanced the acknowledgement"
        );

        // Replacement closes the initial generation; its history entry
        // keeps the frozen cause and identifier.
        let replaced = tracker.observe(replaced_identity(), &base_snapshot());
        let GenerationDecision::Rotated(opened) = replaced else {
            panic!("a replacement rotates");
        };
        assert_eq!(opened.cause, GenerationCause::FileIdentityChange);
        assert_eq!(tracker.current(), &opened);
        assert_eq!(tracker.history(), std::slice::from_ref(&initial));
        assert_eq!(tracker.history()[0].cause, GenerationCause::Initial);

        // A second fault closes the replacement generation too: the
        // histories accumulate, each entry still its own generation.
        let truncated = tracker.observe(replaced_identity(), &concatenate(&[ALPHA, BETA]));
        let GenerationDecision::Rotated(second) = truncated else {
            panic!("a truncation rotates");
        };
        assert_eq!(second.cause, GenerationCause::Truncation);
        assert_ne!(second.generation, opened.generation);
        assert_eq!(
            tracker
                .history()
                .iter()
                .map(|generation| generation.cause)
                .collect::<Vec<_>>(),
            vec![
                GenerationCause::Initial,
                GenerationCause::FileIdentityChange
            ]
        );
        let identifiers: Vec<_> = tracker
            .history()
            .iter()
            .map(|generation| &generation.generation)
            .chain(std::iter::once(&tracker.current().generation))
            .collect();
        for (index, identifier) in identifiers.iter().enumerate() {
            assert!(
                !identifiers[..index].contains(identifier),
                "generations never merge: {identifier} repeated"
            );
        }
    }

    #[test]
    fn the_acknowledgement_measures_the_complete_prefix_only() {
        // A torn tail: the complete prefix is acknowledged, the tail is
        // measured and enters no digest.
        let mut snapshot = base_snapshot();
        snapshot.extend_from_slice(b"epsilon-torn");
        let acknowledged = AcknowledgedSource::acknowledge(identity(), &snapshot);
        let prefix = RecordBoundary::complete_prefix(&snapshot);

        assert_eq!(
            acknowledged.complete_bytes(),
            widened(prefix.len()),
            "only the complete prefix is acknowledged"
        );
        assert_eq!(
            acknowledged.content_digest().to_hex(),
            BlobDigest::from_raw(sha256::digest(prefix)).to_hex()
        );
        // The tail record starts after the previous newline, and the
        // head digest covers everything before it.
        assert_eq!(
            acknowledged.tail_start(),
            widened(prefix.len() - EPSILON.len())
        );
        assert_eq!(
            acknowledged.head_digest().to_hex(),
            BlobDigest::from_raw(sha256::digest(&prefix[..prefix.len() - EPSILON.len()])).to_hex()
        );
        assert_eq!(
            acknowledged.tail_digest().to_hex(),
            BlobDigest::from_raw(sha256::digest(&prefix[prefix.len() - EPSILON.len()..])).to_hex()
        );

        // The same acknowledgement reconstructed from its persisted parts
        // decides identically.
        let resumed = AcknowledgedSource::from_parts(
            acknowledged.identity(),
            acknowledged.complete_bytes(),
            acknowledged.content_digest(),
            acknowledged.head_digest(),
            acknowledged.tail_start(),
            acknowledged.tail_digest(),
        )
        .expect("parts measured from one slice are consistent");
        assert_eq!(resumed, acknowledged);
        assert_eq!(
            AcknowledgedSource::from_parts(
                identity(),
                4,
                acknowledged.content_digest(),
                acknowledged.head_digest(),
                5,
                acknowledged.tail_digest()
            ),
            Err(AcknowledgedSourceError::TailStartBeyondPrefix)
        );
    }

    fn widened(bytes: usize) -> u64 {
        u64::try_from(bytes).expect("test sizes are small")
    }
}
