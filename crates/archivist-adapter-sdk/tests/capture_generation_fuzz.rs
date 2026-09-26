// SPDX-License-Identifier: Apache-2.0

//! The adapter capture-and-projection fuzz suite (plan Phase 11 "Fuzz ...
//! adapter projections"): deterministic pseudo-random hostile inputs
//! against the SDK surfaces the adapters compose — complete-record
//! boundary selection, incremental capture cursors, generation-transition
//! detection, fingerprint grammar and allowlist admission, and the parity
//! oracle's divergence naming — asserting:
//!
//! - **Complete-boundary parsing** partitions every hostile byte source
//!   exactly: the complete prefix and the measured tail are disjoint and
//!   exhaustive, every captured record is terminated, the tail appears in
//!   no record, and the figures hold over arbitrary bytes, not just
//!   well-formed JSONL.
//! - **Capture cursors** never capture a torn tail, never move backwards,
//!   and report a shrunken source instead of assuming.
//! - **Generation transitions** name every observation shape with exactly
//!   one cause from the closed detection set: identity replacement wins
//!   over every content signal, an intact prefix continues, and shrink,
//!   rewind, tail mismatch, incompatible rewrite, and digest change each
//!   land on their own shape and never on `initial`.
//! - **Fingerprint detection** admits exactly the grammar-valid members of
//!   an allowlist — no prefix, suffix, case, or padding variant of a
//!   supported token is admitted — and every denial fails closed.
//! - **Parity calculations** name exactly the divergence injected: a lost
//!   trailing run is truncation, an interior hole is omission, an
//!   inversion is reordering, a changed field is corruption, an appended
//!   key is invention — and identical observations compare equal however
//!   they were built. No planted value ever reaches a rendering.
//!
//! Every loop is driven by a fixed-seed linear-congruential generator, so
//! a failure reproduces from the seed named in the assertion message.

use std::fmt::Write as _;
use std::ops::Range;

use archivist_adapter_sdk::file_capture::{CaptureCursor, CaptureCursorError, RecordBoundary};
use archivist_adapter_sdk::file_generation::{
    AcknowledgedSource, FileGenerationTracker, FileIdentity, GenerationDecision,
};
use archivist_adapter_sdk::parity::{
    DatabaseObservation, Divergence, ObservedValue, RowObservation, TableObservation, Verdict,
    compare,
};
use archivist_adapter_sdk::{
    FingerprintAllowlist, FingerprintError, GenerationCause, SourceFingerprint,
};

/// A deterministic linear-congruential generator: the property tests must
/// be reproducible, so no external RNG and no time seeding.
struct Deterministic(u64);

impl Deterministic {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }

    /// One arbitrary byte: the full alphabet, hostile bytes included.
    fn byte(&mut self) -> u8 {
        u8::try_from(self.next() & 0xff).expect("masked to eight bits")
    }

    /// One byte biased toward the shapes boundary selection cares about:
    /// record ends dominate the draw alongside hostile bytes.
    fn biased_byte(&mut self) -> u8 {
        const ALPHABET: &[u8] = b"\n\n\n\r\0\xff{}\",: a0";
        let draw = usize::try_from(self.below(u64::try_from(ALPHABET.len()).expect("small")))
            .expect("fits usize");
        ALPHABET[draw]
    }

    fn fragment(&mut self, bound: u64, hostile: bool) -> Vec<u8> {
        let len = usize::try_from(self.below(bound)).expect("fits usize");
        (0..len)
            .map(|_| {
                if hostile {
                    self.byte()
                } else {
                    self.biased_byte()
                }
            })
            .collect()
    }

    fn offset_within(&mut self, len: usize) -> usize {
        usize::try_from(self.below(u64::try_from(len).expect("length fits u64"))).expect("fits")
    }
}

/// The count of record terminators in `bytes`: one per record.
fn newline_count(bytes: &[u8]) -> u64 {
    u64::try_from(
        bytes
            .iter()
            .fold(0_usize, |count, byte| count + usize::from(*byte == b'\n')),
    )
    .expect("fits u64")
}

/// The host-side invariants of one boundary selection over any bytes.
fn assert_selection_partitions(source: &[u8]) {
    let selected = RecordBoundary::select(source);
    let length = u64::try_from(source.len()).expect("length fits u64");

    // The two byte figures partition the snapshot exactly.
    assert_eq!(
        selected.complete_bytes + selected.incomplete_tail_bytes,
        length,
        "the boundary figures must sum to the source length"
    );

    let prefix = RecordBoundary::complete_prefix(source);
    let tail = RecordBoundary::incomplete_tail(source);
    assert_eq!(
        selected.complete_bytes,
        u64::try_from(prefix.len()).expect("fits u64"),
        "complete_bytes is the prefix length"
    );
    // The prefix is empty or newline-terminated; the tail holds no newline
    // at all; and prefix + tail is the whole source.
    assert!(
        prefix.last().is_none_or(|&end| end == b'\n'),
        "the complete prefix is newline-terminated"
    );
    assert!(!tail.contains(&b'\n'), "the tail holds no record end");
    let mut joined = prefix.to_vec();
    joined.extend_from_slice(tail);
    assert_eq!(joined, source, "prefix and tail reconstruct the source");

    // The records concatenate byte-for-byte to the prefix, so the tail
    // appears in no captured record; and the published record figure is
    // the prefix's newline count — one terminator per record.
    let concatenated: Vec<u8> = RecordBoundary::records(source).flatten().copied().collect();
    assert_eq!(concatenated, prefix, "records concatenate to the prefix");
    let newlines = newline_count(prefix);
    assert_eq!(
        selected.complete_records, newlines,
        "complete_records is the prefix's newline count"
    );
}

#[test]
fn fuzz_hostile_byte_sources_partition_exactly() {
    let mut deterministic = Deterministic::new(0x0b5d_1e55_fa11_e550);
    for round in 0..512_u64 {
        // Half the sources are pure arbitrary bytes — NULs, 0xFF, random
        // control characters — and half are biased toward record shapes;
        // selection is lexical, so both must partition identically.
        let source = deterministic.fragment(8192, round % 2 == 0);
        assert_selection_partitions(&source);
    }

    // The oversized tail of the space budget: one multi-megabyte hostile
    // source, still partitioned exactly.
    let mut source = Vec::new();
    for _ in 0..(256 * 1024) {
        source.push(deterministic.byte());
    }
    assert_selection_partitions(&source);
}

#[test]
fn fuzz_cursor_passes_concatenate_to_the_prefix_and_hold_on_shrink() {
    // Monotone growth: every pass captures exactly what completed since
    // the last one, the captures concatenate to the whole complete
    // prefix, the cursor never moves backwards, and the tail it measures
    // is the tail the whole-source selection reports.
    let mut deterministic = Deterministic::new(0x0dd1_70f5_eed5_eed5);
    for round in 0..96_u64 {
        let mut source: Vec<u8> = deterministic.fragment(4096, round % 3 == 0);
        let mut cursor = CaptureCursor::new();
        let mut captured: Vec<u8> = Vec::new();
        for _ in 0..12 {
            // Appends may be large, may hold no record end at all, and may
            // complete several records at once.
            let size = 1 + deterministic.below(8192);
            source.extend(deterministic.fragment(size, round % 2 == 0));
            let outcome = cursor.observe(&source).expect("a growing source");
            captured.extend_from_slice(outcome.captured);
            assert_eq!(
                cursor.position(),
                outcome.boundary.complete_bytes,
                "round {round}: the cursor sits at the boundary it advanced to"
            );
            let newlines = newline_count(&captured);
            assert_eq!(
                cursor.complete_records(),
                newlines,
                "round {round}: the record count is the captured newline count"
            );
        }
        assert_eq!(
            captured,
            RecordBoundary::complete_prefix(&source),
            "round {round}: the passes concatenate to the complete prefix"
        );
        let source_len = u64::try_from(source.len()).expect("fits u64");
        assert_eq!(
            cursor.position() + RecordBoundary::select(&source).incomplete_tail_bytes,
            source_len,
            "round {round}: complete bytes plus the tail are the whole source"
        );
    }

    // Shrinks: a snapshot shorter than the cursor's boundary is an error,
    // the cursor holds its boundary and count, and once the source grows
    // back past the boundary the capture resumes exactly where it held.
    let mut deterministic = Deterministic::new(0x5c0a_e550_0000_5c0a);
    for round in 0..96_u64 {
        let mut source: Vec<u8> = deterministic.fragment(2048, round % 2 == 0);
        let mut cursor = CaptureCursor::new();
        let first = cursor.observe(&source).expect("an initial source");
        let first_records = first.boundary.complete_records;
        let held = usize::try_from(cursor.position()).expect("held boundary fits usize");

        // Cut below the held boundary — possibly to zero. A cursor that
        // never advanced (position zero) has nothing to shrink beneath.
        let cut = deterministic.offset_within(held.max(1));
        source.truncate(cut.min(held));
        if held == 0 {
            let outcome = cursor
                .observe(&source)
                .expect("position zero cannot shrink");
            assert!(outcome.captured.is_empty());
        } else {
            assert_eq!(
                cursor.observe(&source),
                Err(CaptureCursorError::SourceShrank),
                "round {round}: a shrunken source is reported, never assumed"
            );
            assert_eq!(
                cursor.position(),
                u64::try_from(held).expect("fits u64"),
                "round {round}: the cursor holds its boundary across the shrink"
            );
            assert_eq!(
                cursor.complete_records(),
                first_records,
                "round {round}: the record count holds too"
            );

            // Grow back past the boundary with fresh bytes: the capture
            // resumes at the held boundary and covers the suffix exactly.
            let resume = held + 1 + deterministic.offset_within(2048);
            while source.len() < resume {
                source.extend(deterministic.fragment(256, false));
            }
            let resumed = cursor.observe(&source).expect("a regrown source");
            let boundary = usize::try_from(resumed.boundary.complete_bytes).expect("fits usize");
            assert_eq!(
                resumed.captured,
                &source[held..boundary],
                "round {round}: the capture resumes exactly at the held boundary"
            );
        }
    }
}

/// The byte a rewrite plants: not a record end, so a same-length rewrite
/// can never move the boundary the acknowledged digests were computed
/// over — which is what lets each detection cause be pinned to exactly
/// one observation shape.
const PLANTED: u8 = b'X';

/// The first position in `range` whose byte is neither the planted byte
/// nor a record end, starting from a random offset: writing it is
/// guaranteed to change the content while leaving every record boundary
/// where it was. `None` when the range holds nothing writable.
fn pick_writable(
    source: &[u8],
    range: Range<usize>,
    deterministic: &mut Deterministic,
) -> Option<usize> {
    let width = range.len();
    let start = deterministic.offset_within(width);
    for step in 0..width {
        let at = range.start + ((start + step) % width);
        if source[at] != PLANTED && source[at] != b'\n' {
            return Some(at);
        }
    }
    None
}

/// One observation event applied to the tracked source, with the cause
/// the precedence table must produce for exactly that shape.
enum Event {
    /// Append bytes: the acknowledged prefix stays byte-intact, so the
    /// generation continues whatever the fragment holds.
    Append(Vec<u8>),
    /// Truncate below the acknowledged complete length: acknowledged
    /// records vanished, the surviving head untouched.
    Truncate(usize),
    /// Overwrite one byte inside the acknowledged last record: the head
    /// before it stays intact.
    RewriteTail,
    /// Overwrite one byte in the head before the acknowledged last
    /// record, keeping the length: same scale, different bytes.
    RewriteHead,
    /// A head byte changed and the surviving source is shorter than
    /// acknowledged but still reaches the head's end: earlier content
    /// contradicted, newer content displaced.
    RewindShape,
    /// A different file appears under the same name: the identity signal
    /// wins over every content shape.
    ReplaceIdentity(Vec<u8>),
    /// A head byte changed and the source grew past the acknowledged
    /// scale: the general digest signal.
    RewriteAndGrow,
}

/// Apply one event to the snapshot, returning the observing identity, the
/// next bytes, and whether any byte actually changed — a rewrite whose
/// target range holds nothing writable degrades to a no-op, which the
/// detection table must read as ordinary continuation.
fn apply_event(
    acknowledged: &AcknowledgedSource,
    snapshot: &[u8],
    event: &Event,
    deterministic: &mut Deterministic,
) -> (FileIdentity, Vec<u8>, bool, bool) {
    let ack_complete = acknowledged.complete_bytes();
    // Every event observes under the CURRENTLY acknowledged identity —
    // after a replacement, the replacement's identity is the base — so
    // only a replacement event itself is an identity change.
    let identity = acknowledged.identity();
    let complete = usize::try_from(acknowledged.complete_bytes()).expect("fits usize");
    let tail_start = usize::try_from(acknowledged.tail_start()).expect("fits usize");
    // Whether the observation's complete-record prefix actually grew past
    // the acknowledged scale: appended bytes without a record end widen
    // the tail only, leaving the boundary where it was.
    let grew_of = |next: &[u8]| RecordBoundary::select(next).complete_bytes > ack_complete;
    match event {
        Event::Append(fragment) => {
            let mut next = snapshot.to_vec();
            next.extend_from_slice(fragment);
            let grew = grew_of(&next);
            (identity, next, false, grew)
        }
        Event::Truncate(at) => {
            let mut next = snapshot.to_vec();
            next.truncate(*at);
            (identity, next, false, false)
        }
        Event::RewriteTail => {
            let mut next = snapshot.to_vec();
            let changed = match pick_writable(&next, tail_start..complete, deterministic) {
                Some(at) => {
                    next[at] = PLANTED;
                    true
                }
                None => false,
            };
            (identity, next, changed, false)
        }
        Event::RewriteHead => {
            let mut next = snapshot.to_vec();
            let changed = match pick_writable(&next, 0..tail_start, deterministic) {
                Some(at) => {
                    next[at] = PLANTED;
                    true
                }
                None => false,
            };
            (identity, next, changed, false)
        }
        Event::RewindShape => {
            let mut next = snapshot.to_vec();
            let changed = match pick_writable(&next, 0..tail_start, deterministic) {
                Some(at) => {
                    next[at] = PLANTED;
                    true
                }
                None => false,
            };
            // Shorten the source to somewhere inside the acknowledged
            // region but no earlier than the head's end: the head stays
            // observable, and it contradicts exactly when a byte of it
            // was rewritten.
            let end = tail_start + deterministic.offset_within(complete - tail_start);
            next.truncate(end);
            (identity, next, changed, false)
        }
        Event::ReplaceIdentity(bytes) => {
            // Flip the current identity: two replacements in one round
            // must still change it.
            (
                FileIdentity::new(identity.device ^ 0xffff, identity.inode),
                bytes.clone(),
                false,
                false,
            )
        }
        Event::RewriteAndGrow => {
            let mut next = snapshot.to_vec();
            let changed = if tail_start > 0 {
                match pick_writable(&next, 0..tail_start, deterministic) {
                    Some(at) => {
                        next[at] = PLANTED;
                        true
                    }
                    None => false,
                }
            } else {
                false
            };
            // The growth must be real: appended bytes without a record
            // end widen the tail only, leaving the acknowledged scale
            // unchanged.
            let size = 1 + deterministic.below(16);
            next.extend(deterministic.fragment(size, false));
            let grew = grew_of(&next);
            (identity, next, changed, grew)
        }
    }
}

#[test]
fn fuzz_generation_transitions_match_the_observation_shape() {
    let mut deterministic = Deterministic::new(0x9e4e_1a71_00bd_c0de);
    for round in 0..128_u64 {
        let identity = FileIdentity::new(1_000 + round, 2_000 + round);
        let initial: Vec<u8> = deterministic.fragment(512, round % 4 == 0);
        let mut tracker = FileGenerationTracker::begin(identity, &initial);
        let mut snapshot = initial;
        let mut history: Vec<GenerationCause> = Vec::new();

        for step in 0..12 {
            let acknowledged = *tracker.acknowledged();
            let complete = usize::try_from(acknowledged.complete_bytes()).expect("fits usize");
            let tail_start = usize::try_from(acknowledged.tail_start()).expect("fits usize");
            // Only shape events whose acknowledged state supports them:
            // truncation and rewrites need at least one complete record,
            // and head rewrites need a head to rewrite.
            let event = match deterministic.below(7) {
                0 => Event::Append(deterministic.fragment(256, false)),
                1 if complete > 0 => Event::Truncate(deterministic.offset_within(complete)),
                2 if complete > 0 => Event::RewriteTail,
                3 if tail_start > 0 => Event::RewriteHead,
                4 if tail_start > 0 => Event::RewindShape,
                5 => Event::ReplaceIdentity(deterministic.fragment(256, round % 2 == 0)),
                _ => Event::RewriteAndGrow,
            };

            let (observed_identity, next, changed, grew) =
                apply_event(&acknowledged, &snapshot, &event, &mut deterministic);
            let decision = tracker.observe(observed_identity, &next);

            // The decision matches the shape — continuation, or exactly
            // the precedence row the shape lands on.
            let expected_cause = match event {
                Event::Append(_) => None,
                Event::Truncate(_) => Some(GenerationCause::Truncation),
                Event::RewriteTail => changed.then_some(GenerationCause::TailMismatch),
                Event::RewriteHead => changed.then_some(GenerationCause::IncompatibleRewrite),
                // The shape always shortens the source: with a rewritten
                // head byte it is a rewind, without one a plain
                // truncation.
                Event::RewindShape => Some(if changed {
                    GenerationCause::Rewind
                } else {
                    GenerationCause::Truncation
                }),
                Event::ReplaceIdentity(_) => Some(GenerationCause::FileIdentityChange),
                // A rewritten head with real prefix growth is the general
                // digest signal; with the scale unchanged it is an
                // incompatible same-scale rewrite.
                Event::RewriteAndGrow => match (changed, grew) {
                    (true, true) => Some(GenerationCause::DigestChange),
                    (true, false) => Some(GenerationCause::IncompatibleRewrite),
                    (false, _) => None,
                },
            };
            match (&decision, expected_cause) {
                (GenerationDecision::Continue, None) => {}
                (GenerationDecision::Rotated(opened), Some(expected)) => {
                    assert_eq!(
                        opened.cause, expected,
                        "round {round} step {step}: the cause must match the observation shape"
                    );
                    assert!(opened.cause.is_detection());
                    history.push(opened.cause);
                }
                (decision, expected) => panic!(
                    "round {round} step {step}: decision {decision:?} does not match the \
                     expected cause {expected:?}"
                ),
            }

            // The tracker acknowledged the observation either way: the
            // next pass over identical bytes always continues.
            let replay = tracker.observe(observed_identity, &next);
            assert_eq!(
                replay,
                GenerationDecision::Continue,
                "round {round} step {step}: an acknowledged observation replays as a continue"
            );
            snapshot = next;
        }

        // The closed history preserves every rotation but the last in
        // order behind the closed initial generation; the last rotation's
        // generation is still open and carries its cause with it. Every
        // rotation entry carries a detection cause.
        let closed = tracker.history();
        let causes: Vec<GenerationCause> = closed.iter().map(|entry| entry.cause).collect();
        let mut expected_history: Vec<GenerationCause> = vec![GenerationCause::Initial];
        expected_history.extend(history.iter().rev().skip(1).rev().copied());
        assert_eq!(
            causes, expected_history,
            "round {round}: the history is preserved in rotation order"
        );
        assert_eq!(
            tracker.current().cause,
            history.last().copied().unwrap_or(GenerationCause::Initial),
            "round {round}: the open generation carries the last rotation's cause"
        );
        assert!(
            causes.iter().skip(1).all(|cause| cause.is_detection()),
            "round {round}: a rotation never carries the initial cause"
        );
        let mut ids: Vec<String> = closed
            .iter()
            .map(|entry| entry.generation.as_str().to_owned())
            .collect();
        ids.push(tracker.current().generation.as_str().to_owned());
        ids.sort();
        let count = ids.len();
        ids.dedup();
        assert_eq!(
            ids.len(),
            count,
            "round {round}: generation identifiers are distinct"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one admission scene, token grammar to set rules, read top to bottom
fn fuzz_fingerprint_grammar_and_admission_stay_exact() {
    // The grammar oracle, restated from the token contract: 1..=128
    // characters of [A-Za-z0-9._:-] with an alphanumeric first character.
    // Any byte outside the set, any overlong token, and an empty token
    // must fail the parse — whatever else the bytes look like.
    let grammar_valid = |text: &str| -> bool {
        let raw = text.as_bytes();
        !raw.is_empty()
            && raw.len() <= 128
            && raw[0].is_ascii_alphanumeric()
            && raw[1..].iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
    };

    let mut deterministic = Deterministic::new(0xf1a9_9e20_000f_f00d);
    let supported = ["claude-jsonl-v1", "opencode-sqlite-v1", "Schema.2026_09:b"];
    let allowlist = FingerprintAllowlist::parse(supported).expect("a valid allowlist");

    for round in 0..1024_u64 {
        // Random candidate tokens: mostly mutations of supported tokens,
        // sometimes raw hostile bytes.
        let candidate = if round % 4 == 3 {
            let len = usize::try_from(deterministic.below(140)).expect("fits usize");
            let raw: Vec<u8> = (0..len).map(|_| deterministic.byte()).collect();
            String::from_utf8_lossy(&raw).into_owned()
        } else {
            let base = supported[usize::try_from(deterministic.below(3)).expect("fits usize")];
            let mut candidate = base.to_owned();
            let mutations = 1 + deterministic.below(3);
            for _ in 0..mutations {
                match deterministic.below(7) {
                    0 => candidate.push(
                        char::from_u32(
                            0x21 + u32::try_from(deterministic.below(0x5f)).expect("fits u32"),
                        )
                        .expect("in the printable range"),
                    ),
                    1 => candidate.insert(0, '-'),
                    2 => {
                        candidate.pop();
                    }
                    3 => candidate.push(' '),
                    4 => candidate.push('/'),
                    5 => candidate.push('"'),
                    _ => candidate.push('\u{10ffff}'),
                }
            }
            candidate
        };

        // Parse admission is exactly the grammar, nothing else.
        assert_eq!(
            SourceFingerprint::parse(&candidate).is_ok(),
            grammar_valid(&candidate),
            "round {round}: parse admission is the grammar over {candidate:?}"
        );

        // Grammar-valid but unsupported tokens still fail the allowlist:
        // near-misses of supported tokens never admit.
        if grammar_valid(&candidate) {
            let parsed = SourceFingerprint::parse(&candidate).expect("the oracle admits it");
            let should_admit = supported.contains(&candidate.as_str());
            assert_eq!(
                allowlist.contains(&parsed),
                should_admit,
                "round {round}: membership is exact for {candidate:?}"
            );
            if !should_admit {
                let denial = allowlist.admit(&parsed).expect_err("fails closed");
                assert_eq!(
                    denial.fingerprint, parsed,
                    "round {round}: the denial carries the observed token"
                );
                assert_eq!(
                    denial.classification().token(),
                    "fingerprint-unsupported",
                    "round {round}: the denial classifies unsupported"
                );
            }
        }
    }

    // Case flips of a supported token are grammar-valid near-misses that
    // never admit: the allowlist is exact, not normalized.
    let flipped = "CLAUDE-JSONL-V1";
    let parsed = SourceFingerprint::parse(flipped).expect("grammar-valid");
    assert!(!allowlist.contains(&parsed));
    assert!(allowlist.admit(&parsed).is_err());

    // The canonical row is sorted and duplicate-free however the set was
    // written, and the set-level rules still bound construction.
    let shuffled = FingerprintAllowlist::parse(["zz-v9", "aa-v1", "mm-v5"]).expect("a valid list");
    let names: Vec<&str> = shuffled
        .iter()
        .map(archivist_adapter_sdk::SourceFingerprint::as_str)
        .collect();
    assert_eq!(names, ["aa-v1", "mm-v5", "zz-v9"]);
    let mut bytes = Vec::new();
    shuffled.to_json().write_canonical(&mut bytes);
    assert_eq!(
        String::from_utf8(bytes).expect("utf8"),
        r#"["aa-v1","mm-v5","zz-v9"]"#,
        "the compatibility-matrix row renders sorted"
    );
    assert_eq!(
        FingerprintAllowlist::parse(["a-v1", "a-v1"]),
        Err(FingerprintError::Duplicate)
    );
    assert_eq!(
        FingerprintAllowlist::parse(Vec::<String>::new()),
        Err(FingerprintError::Empty)
    );
    let overlong: Vec<String> = (0..=33).map(|index| format!("f{index}")).collect();
    assert_eq!(
        FingerprintAllowlist::parse(overlong),
        Err(FingerprintError::TooMany)
    );
    assert_eq!(
        FingerprintAllowlist::parse(["-not-a-token"]),
        Err(FingerprintError::Malformed)
    );
}

/// A planted field marker no rendering may carry.
const ROW_MARKER: &[u8] = b"PARITYLEAK";

/// A random row key: text, unique within one table's draw.
fn random_key(deterministic: &mut Deterministic, salt: u64) -> ObservedValue {
    ObservedValue::Text(format!("key-{salt}-{}", deterministic.below(1 << 30)).into_bytes())
}

/// A random field spanning the observed value classes, one of which
/// plants `ROW_MARKER` no rendering may ever carry.
fn random_field(deterministic: &mut Deterministic) -> ObservedValue {
    match deterministic.below(10) {
        0 => ObservedValue::Null,
        1 => ObservedValue::Integer(i64::from_le_bytes(deterministic.next().to_le_bytes())),
        2 => {
            let drawn = f64::from_bits(deterministic.next());
            ObservedValue::Real(if drawn.is_nan() { 1.5 } else { drawn })
        }
        3 => ObservedValue::Text(ROW_MARKER.to_vec()),
        4 => ObservedValue::Blob(vec![0xff, 0x00, deterministic.byte()]),
        _ => ObservedValue::Text(format!("field-{}", deterministic.below(1 << 30)).into_bytes()),
    }
}

/// A random table observation: rows in canonical key order, distinct keys.
fn random_table(deterministic: &mut Deterministic, salt: u64) -> (TableObservation, usize) {
    let drawn = usize::try_from(1 + deterministic.below(8)).expect("fits usize");
    let mut keys: Vec<ObservedValue> = (0..drawn)
        .map(|index| {
            let index = u64::try_from(index).expect("small");
            random_key(deterministic, salt * 1000 + index)
        })
        .collect();
    keys.sort();
    keys.dedup();
    let rows: Vec<RowObservation> = keys
        .iter()
        .map(|key| {
            let fields: Vec<ObservedValue> = (0..4).map(|_| random_field(deterministic)).collect();
            RowObservation::observe(vec![key.clone()], fields)
        })
        .collect();
    (TableObservation::new(rows), keys.len())
}

/// The verdict's rendering — Debug of the verdict and Display and Debug
/// of every divergence — carries no planted value bytes: ordinals only.
fn assert_verdict_rendering_is_content_free(verdict: &Verdict) {
    let mut rendered = format!("{verdict:?}");
    if let Verdict::Diverges(divergences) = verdict {
        for divergence in divergences {
            let _ = write!(rendered, "{divergence}{divergence:?}");
        }
    }
    assert!(
        !rendered.contains("PARITYLEAK"),
        "a verdict rendering carried planted bytes: {rendered}"
    );
}

/// The row-sequence shapes: a lost trailing run, an interior hole, and
/// an adjacent transposition each name exactly themselves.
fn assert_row_sequence_shapes(
    source: &DatabaseObservation,
    source_rows: &[RowObservation],
    row_count: usize,
    deterministic: &mut Deterministic,
    round: u64,
) {
    let projection_of = |rows: Vec<RowObservation>| project_against(source, rows);

    // A lost trailing run — whatever its size — is truncation.
    if row_count >= 2 {
        let lost = 1 + deterministic.offset_within(row_count - 1);
        let verdict = projection_of(source_rows[..row_count - lost].to_vec());
        assert_eq!(
            verdict,
            Verdict::Diverges(vec![Divergence::TruncatedRows {
                table: 0,
                rows: lost
            }]),
            "round {round}: a lost trailing run is truncation"
        );
        assert_verdict_rendering_is_content_free(&verdict);
    }

    // An interior hole is omission — exactly the lost row.
    if row_count >= 3 {
        let hole = deterministic.offset_within(row_count - 1);
        let mut rows = source_rows.to_vec();
        rows.remove(hole);
        let verdict = projection_of(rows);
        assert_eq!(
            verdict,
            Verdict::Diverges(vec![Divergence::OmittedRow {
                table: 0,
                source_row: hole,
            }]),
            "round {round}: an interior hole is omission"
        );
    }

    // An adjacent transposition is reordering at the first inversion.
    if row_count >= 3 {
        let at = 1 + deterministic.offset_within(row_count - 2);
        let mut rows = source_rows.to_vec();
        rows.swap(at, at + 1);
        let verdict = projection_of(rows);
        assert_eq!(
            verdict,
            Verdict::Diverges(vec![Divergence::Reordered {
                table: 0,
                row: at + 1,
            }]),
            "round {round}: a transposition is reordering, not a cascade"
        );
    }
}

/// The row-content shapes: a fully rewritten row is corruption at each
/// field ordinal in order, and a trailing invented row is invention.
fn assert_row_content_shapes(
    source: &DatabaseObservation,
    source_rows: &[RowObservation],
    row_count: usize,
    deterministic: &mut Deterministic,
    round: u64,
) {
    // A rewritten row with every field changed is corruption at each
    // field ordinal, named in field order.
    if row_count >= 1 {
        let at = deterministic.offset_within(row_count);
        let mut rows = source_rows.to_vec();
        let key = rows[at].key()[0].clone();
        rows[at] = RowObservation::observe(
            vec![key],
            vec![
                ObservedValue::Text(b"changed-value".to_vec()),
                ObservedValue::Text(b"changed-again".to_vec()),
                ObservedValue::Text(b"changed-third".to_vec()),
                ObservedValue::Text(b"changed-fourth".to_vec()),
            ],
        );
        let verdict = project_against(source, rows);
        assert_eq!(
            verdict,
            Verdict::Diverges(vec![
                Divergence::CorruptedField {
                    table: 0,
                    source_row: at,
                    field: 0
                },
                Divergence::CorruptedField {
                    table: 0,
                    source_row: at,
                    field: 1
                },
                Divergence::CorruptedField {
                    table: 0,
                    source_row: at,
                    field: 2
                },
                Divergence::CorruptedField {
                    table: 0,
                    source_row: at,
                    field: 3
                },
            ]),
            "round {round}: every changed field of the row is named, in order"
        );
        assert_verdict_rendering_is_content_free(&verdict);
    }

    // A trailing invented row is invention — exactly one.
    if row_count >= 1 {
        let mut rows = source_rows.to_vec();
        rows.push(RowObservation::observe(
            vec![ObservedValue::Text(b"zzzz-invented-key".to_vec())],
            vec![
                ObservedValue::Null,
                ObservedValue::Null,
                ObservedValue::Null,
                ObservedValue::Null,
            ],
        ));
        let verdict = project_against(source, rows);
        assert_eq!(
            verdict,
            Verdict::Diverges(vec![Divergence::InventedRow {
                table: 0,
                projection_row: row_count,
            }]),
            "round {round}: a trailing invented row is invention"
        );
    }
}

/// The verdict a projection-side table observation earns against the
/// source's.
fn project_against(source: &DatabaseObservation, rows: Vec<RowObservation>) -> Verdict {
    compare(
        source,
        &DatabaseObservation::new(vec![TableObservation::new(rows)]),
    )
}

#[test]
fn fuzz_parity_compare_names_exactly_the_injected_divergence() {
    let mut deterministic = Deterministic::new(0xb00b_5eed_c0de_fa11);
    for round in 0..256_u64 {
        let salt = round * 97 + 13;
        let (source_table, row_count) = random_table(&mut deterministic, salt);
        let source_rows: Vec<RowObservation> = source_table.rows().to_vec();
        let source = DatabaseObservation::new(vec![source_table.clone()]);

        // Identity, rebuilt independently from the same rows: equal.
        let rebuilt = DatabaseObservation::new(vec![TableObservation::new(source_rows.clone())]);
        assert!(
            compare(&source, &rebuilt).is_equal(),
            "round {round}: identical observations compare equal"
        );

        assert_row_sequence_shapes(&source, &source_rows, row_count, &mut deterministic, round);
        assert_row_content_shapes(&source, &source_rows, row_count, &mut deterministic, round);

        // A table-sequence mismatch is named once, before any per-table
        // comparison.
        let empty_side = DatabaseObservation::new(Vec::new());
        assert_eq!(
            compare(&source, &empty_side),
            Verdict::Diverges(vec![Divergence::TableSequence]),
            "round {round}: a table mismatch is named once"
        );
    }
}

#[test]
fn fuzz_multi_table_observations_stay_independently_comparable() {
    let mut deterministic = Deterministic::new(0xfa11_e550_7a61_e500);
    for round in 0..128_u64 {
        // Two independent observations built from equal seeds over the
        // same random content always compare equal — and the comparison
        // stays content-free whatever the content was.
        let salt = round * 31 + 7;
        let mut draw_a = Deterministic::new(0x7a61_e500_0000_0000 ^ salt);
        let mut draw_b = Deterministic::new(0x7a61_e500_0000_0000 ^ salt);
        let mut tables_a: Vec<TableObservation> = Vec::new();
        let mut tables_b: Vec<TableObservation> = Vec::new();
        let table_count = 1 + deterministic.offset_within(5);
        for table in 0..table_count {
            let table = u64::try_from(table).expect("small");
            let (a, _) = random_table(&mut draw_a, table);
            let (b, _) = random_table(&mut draw_b, table);
            tables_a.push(a);
            tables_b.push(b);
        }
        let observation_a = DatabaseObservation::new(tables_a);
        let observation_b = DatabaseObservation::new(tables_b);
        let verdict = compare(&observation_a, &observation_b);
        assert!(
            verdict.is_equal(),
            "round {round}: independently built equal observations compare equal"
        );
        assert_verdict_rendering_is_content_free(&verdict);
    }
}
