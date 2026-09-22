// SPDX-License-Identifier: Apache-2.0

//! The file-source capture core's complete-record boundary selection
//! (CAP-003, plan `EC-01`, plan Phase 6A, threat-model AC-02): split a
//! JSONL byte source at its last newline-terminated record, so a harness
//! that is still writing never has its torn tail captured, digested, or
//! advanced past.
//!
//! A harness appends records as it produces them, and a reader racing it
//! observes sources that end mid-record. Splitting on bytes instead of
//! complete records would archive the partial prefix as if it were final
//! and advance a cursor the source will never satisfy again — AC-02's
//! unrecoverable gap. The rule here is purely lexical: every byte through
//! the last `\n` is the complete-record prefix, and the trailing bytes
//! after it are the incomplete tail. The tail is measured —
//! [`RecordBoundary::incomplete_tail_bytes`], the same figure
//! [`SourceScan`] reports — and re-measured on the next pass; it is never
//! returned as a record, never counted as complete bytes, and never part
//! of any backlog figure.
//!
//! Boundary selection is all this module does. The surrounding Phase 6
//! work composes on top of it — generation detection
//! ([`crate::file_generation`]), sidecar artifact relationships
//! ([`crate::file_sidecar`]), and session-identity resolution
//! ([`crate::session_identity`]) — so this contract stays free of any
//! policy that could change under it.
//!
//! [`SourceScan`]: crate::status::SourceScan

/// The split of one source snapshot at its last complete-record boundary
/// (CAP-003, plan `EC-01`). [`RecordBoundary::complete_bytes`] ends
/// exactly at the last newline-terminated record, and
/// [`RecordBoundary::incomplete_tail_bytes`] covers the remainder. The
/// two byte figures always sum to the snapshot's length — the
/// byte-for-byte guarantee capture is held to: every byte is either
/// inside a complete record or inside the measured tail, never both and
/// never neither.
///
/// The figures mirror [`SourceScan`]'s capture split (its `complete_bytes`
/// and `incomplete_tail_bytes` fields), so an adapter can fill the
/// inventory observation straight from a selection.
///
/// [`SourceScan`]: crate::status::SourceScan
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordBoundary {
    /// Bytes through the last complete record boundary.
    pub complete_bytes: u64,
    /// Complete records — newline-terminated lines — through the last
    /// complete boundary.
    pub complete_records: u64,
    /// Bytes after the last complete boundary: the pending tail,
    /// measured but never captured until it completes.
    pub incomplete_tail_bytes: u64,
}

impl RecordBoundary {
    /// Select one source snapshot's boundary: scan for the last
    /// newline-terminated record and split exactly there.
    ///
    /// A source with no newline at all is entirely tail — nothing is
    /// complete yet, and [`CaptureCursor::observe`] keeps the cursor at
    /// zero until one terminates.
    #[must_use]
    pub fn select(source: &[u8]) -> Self {
        let mut complete_bytes = 0;
        let mut complete_records = 0;
        for (index, byte) in source.iter().enumerate() {
            if *byte == b'\n' {
                complete_records += 1;
                complete_bytes = index + 1;
            }
        }
        Self {
            complete_bytes: measured(complete_bytes),
            complete_records: measured(complete_records),
            incomplete_tail_bytes: measured(source.len() - complete_bytes),
        }
    }

    /// The complete-record prefix: every byte through the last `\n`, or
    /// empty when no record has terminated yet. The prefix is the
    /// source's own bytes — a `\r\n` ending keeps the `\r` inside its
    /// record, because selection is lexical and never rewrites content.
    #[must_use]
    pub fn complete_prefix(source: &[u8]) -> &[u8] {
        match source.iter().rposition(|&byte| byte == b'\n') {
            Some(last) => &source[..=last],
            None => &[],
        }
    }

    /// The incomplete trailing tail: the bytes after the last `\n`.
    /// Measured on every pass, captured on none (CAP-003, plan `EC-01`).
    #[must_use]
    pub fn incomplete_tail(source: &[u8]) -> &[u8] {
        &source[Self::complete_prefix(source).len()..]
    }

    /// The complete records, in source order, each including its
    /// terminating `\n`. Concatenating the yielded records equals
    /// [`RecordBoundary::complete_prefix`] byte-for-byte, so the tail
    /// appears in no record. A blank line is a complete record —
    /// selection is lexical, not a JSON validator — and yields its `\n`
    /// like any other record.
    pub fn records(source: &[u8]) -> impl Iterator<Item = &[u8]> {
        Self::complete_prefix(source).split_inclusive(|&byte| byte == b'\n')
    }

    /// The complete-prefix length as an index into the measured slice.
    fn complete_len(&self) -> usize {
        usize::try_from(self.complete_bytes)
            .expect("complete_bytes is measured from a slice length")
    }
}

/// One pass's capture: the bytes that completed since the last pass, and
/// the whole-source boundary after the pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassOutcome<'a> {
    /// The bytes that completed since the last pass, each terminating
    /// `\n` included and the tail excluded. Empty when nothing completed
    /// — a tail waiting for its writer is the normal CAP-003 posture,
    /// not an error.
    pub captured: &'a [u8],
    /// The snapshot's boundary after this pass: the figures a
    /// [`SourceScan`] fills its capture split from, with the tail still
    /// measured and still uncaptured.
    ///
    /// [`SourceScan`]: crate::status::SourceScan
    pub boundary: RecordBoundary,
}

/// Why a pass could not be observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureCursorError {
    /// The snapshot is shorter than the cursor's boundary: bytes the
    /// cursor counted as complete are gone. The cursor is left
    /// untouched; deciding what the loss means for the source's
    /// generation is detection work outside this module.
    SourceShrank,
}

impl std::fmt::Display for CaptureCursorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = match self {
            Self::SourceShrank => "capture_source_shrank",
        };
        f.write_str(token)
    }
}

impl std::error::Error for CaptureCursorError {}

/// The pass cursor behind CAP-003's "wait for a later pass": it holds
/// the offset of the last complete boundary and never advances past it,
/// so a torn tail stays local (plan `EC-01`) and is captured whole once
/// the harness finishes writing it.
///
/// The cursor observes whole source snapshots, not deltas: a file source
/// grows at its tail, and each pass re-selects the boundary over
/// everything after the cursor's offset — the AC-02 posture of the
/// cursor at the last complete boundary with the tail re-measured. The
/// position is monotonic by construction; the one impossible observation
/// is a snapshot shorter than the boundary, which is reported rather
/// than assumed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureCursor {
    position: u64,
    complete_records: u64,
}

impl CaptureCursor {
    /// A cursor at the start of a source: nothing captured, nothing
    /// advanced.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The byte offset of the last complete boundary — the offset the
    /// cursor will never advance past until more records terminate.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.position
    }

    /// The complete records captured so far.
    #[must_use]
    pub fn complete_records(&self) -> u64 {
        self.complete_records
    }

    /// Observe one pass over the source's current bytes: capture
    /// everything that completed since the last pass, and re-measure the
    /// tail without capturing it.
    ///
    /// # Errors
    /// [`CaptureCursorError::SourceShrank`] when the snapshot is shorter
    /// than the cursor's boundary; the cursor keeps its position and the
    /// caller decides what the loss means.
    ///
    /// # Panics
    /// Never on the observations the cursor produces itself: the boundary
    /// it advances by is always a slice length it measured. The offset
    /// arithmetic is total for any snapshot that fits in memory.
    pub fn observe<'a>(&mut self, source: &'a [u8]) -> Result<PassOutcome<'a>, CaptureCursorError> {
        let position =
            usize::try_from(self.position).expect("the position is a previous snapshot's length");
        if source.len() < position {
            return Err(CaptureCursorError::SourceShrank);
        }
        let suffix = &source[position..];
        let suffix_boundary = RecordBoundary::select(suffix);
        let captured = &suffix[..suffix_boundary.complete_len()];
        let boundary = RecordBoundary {
            complete_bytes: self.position.saturating_add(suffix_boundary.complete_bytes),
            complete_records: self
                .complete_records
                .saturating_add(suffix_boundary.complete_records),
            incomplete_tail_bytes: suffix_boundary.incomplete_tail_bytes,
        };
        self.position = boundary.complete_bytes;
        self.complete_records = boundary.complete_records;
        Ok(PassOutcome { captured, boundary })
    }
}

/// A slice measurement widened into the byte-count domain: `usize` fits
/// `u64` on every supported target, so the saturating fallback is dead
/// arithmetic kept for the conversion's totality.
fn measured(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn widened(bytes: usize) -> u64 {
        u64::try_from(bytes).expect("test sizes are small")
    }

    #[test]
    fn an_empty_source_has_no_records_and_no_tail() {
        let selected = RecordBoundary::select(b"");
        assert_eq!(
            selected,
            RecordBoundary {
                complete_bytes: 0,
                complete_records: 0,
                incomplete_tail_bytes: 0,
            }
        );
        assert_eq!(RecordBoundary::complete_prefix(b""), b"");
        assert_eq!(RecordBoundary::incomplete_tail(b""), b"");
        assert_eq!(RecordBoundary::records(b"").count(), 0);
    }

    #[test]
    fn a_trailing_newline_completes_the_final_record_with_zero_tail() {
        let source = b"{\"a\":1}\n";
        let selected = RecordBoundary::select(source);
        assert_eq!(selected.complete_bytes, 8);
        assert_eq!(selected.complete_records, 1);
        assert_eq!(selected.incomplete_tail_bytes, 0);
        assert_eq!(
            RecordBoundary::records(source).collect::<Vec<_>>(),
            vec![&source[..]]
        );
    }

    #[test]
    fn a_source_without_a_newline_is_entirely_tail() {
        let source = b"{\"a\":1";
        let selected = RecordBoundary::select(source);
        assert_eq!(selected.complete_bytes, 0);
        assert_eq!(selected.complete_records, 0);
        assert_eq!(selected.incomplete_tail_bytes, 6);
        assert_eq!(RecordBoundary::complete_prefix(source), b"");
        assert_eq!(RecordBoundary::incomplete_tail(source), source);
        assert_eq!(RecordBoundary::records(source).count(), 0);
    }

    #[test]
    fn blank_lines_are_lexically_complete_records() {
        let source = b"\n\n{\"a\":1}\n\n";
        let selected = RecordBoundary::select(source);
        assert_eq!(selected.complete_records, 4);
        assert_eq!(selected.complete_bytes, widened(source.len()));
        assert_eq!(selected.incomplete_tail_bytes, 0);
        let concatenated: Vec<u8> = RecordBoundary::records(source).flatten().copied().collect();
        assert_eq!(concatenated, source.to_vec());
    }

    #[test]
    fn a_torn_tail_is_measured_and_never_captured() {
        let source = b"{\"a\":1}\n{\"b\":2";
        let selected = RecordBoundary::select(source);
        assert_eq!(selected.complete_bytes, 8);
        assert_eq!(selected.complete_records, 1);
        assert_eq!(selected.incomplete_tail_bytes, 6);
        assert_eq!(RecordBoundary::complete_prefix(source), b"{\"a\":1}\n");
        assert_eq!(RecordBoundary::incomplete_tail(source), b"{\"b\":2");
        // The tail appears in no record: the only complete record is the
        // newline-terminated one.
        assert_eq!(
            RecordBoundary::records(source).collect::<Vec<_>>(),
            vec![&b"{\"a\":1}\n"[..]]
        );
    }

    #[test]
    fn a_record_completing_across_passes_is_captured_whole() {
        let mut source = b"{\"a\":1}\n{\"b\":2".to_vec();
        let mut cursor = CaptureCursor::new();

        let first = cursor.observe(&source).expect("a growing source");
        assert_eq!(first.captured, b"{\"a\":1}\n");
        assert_eq!(first.boundary.incomplete_tail_bytes, 6);
        assert_eq!(cursor.position(), 8);
        assert_eq!(cursor.complete_records(), 1);

        let first_captured = first.captured.to_vec();

        // The harness finishes the torn record and writes another.
        source.extend_from_slice(b"}\n{\"c\":3}\n");
        let second = cursor.observe(&source).expect("a growing source");
        assert_eq!(second.captured, b"{\"b\":2}\n{\"c\":3}\n");
        assert_eq!(second.boundary.complete_records, 3);
        assert_eq!(second.boundary.incomplete_tail_bytes, 0);
        assert_eq!(cursor.position(), widened(source.len()));

        // The ordered captures concatenate byte-for-byte to the source's
        // complete-record prefix.
        let mut captured = Vec::new();
        captured.extend_from_slice(&first_captured);
        captured.extend_from_slice(second.captured);
        assert_eq!(captured, RecordBoundary::complete_prefix(&source));
    }

    #[test]
    fn an_unchanged_source_recaptures_nothing() {
        let source = b"{\"a\":1}\n{\"b\":2";
        let mut cursor = CaptureCursor::new();
        let first = cursor.observe(source).expect("an unchanged source");
        let second = cursor.observe(source).expect("an unchanged source");
        assert_eq!(second.captured, b"");
        assert_eq!(second.boundary, first.boundary);
        assert_eq!(cursor.position(), 8);
    }

    #[test]
    fn a_shrunken_source_is_reported_and_the_cursor_holds_its_boundary() {
        let source = b"{\"a\":1}\n{\"b\":2}\n";
        let mut cursor = CaptureCursor::new();
        let observed = cursor.observe(source).expect("a full source");
        assert_eq!(observed.boundary.complete_bytes, widened(source.len()));

        let torn = &source[..10];
        assert_eq!(cursor.observe(torn), Err(CaptureCursorError::SourceShrank));
        // The cursor did not advance past its last complete boundary.
        assert_eq!(cursor.position(), widened(source.len()));
        assert_eq!(cursor.complete_records(), 2);
    }

    /// A deterministic linear-congruential generator: the property tests
    /// must be reproducible, so no external RNG and no time seeding.
    struct Deterministic(u64);

    impl Deterministic {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }

        /// One byte from a JSONL-ish alphabet, biased toward record ends.
        fn byte(&mut self) -> u8 {
            const ALPHABET: &[u8] = b"{\"}:\n,10a \n";
            let draw = self.next() % u64::try_from(ALPHABET.len()).unwrap_or(1);
            ALPHABET[usize::try_from(draw).unwrap_or(0)]
        }

        fn flip(&mut self) -> bool {
            self.next() & 1 == 0
        }

        fn source(&mut self, bound: u64) -> Vec<u8> {
            let len = usize::try_from(self.next() % bound).unwrap_or(0);
            (0..len).map(|_| self.byte()).collect()
        }
    }

    #[test]
    fn every_selection_partitions_the_source_exactly() {
        let mut deterministic = Deterministic(0x5eed_1e55_02c0_ffee);
        for _ in 0..512 {
            let source = deterministic.source(24);
            let selected = RecordBoundary::select(&source);

            // The two byte figures partition the snapshot exactly.
            let length = widened(source.len());
            assert_eq!(
                selected.complete_bytes + selected.incomplete_tail_bytes,
                length
            );

            let prefix = RecordBoundary::complete_prefix(&source);
            let tail = RecordBoundary::incomplete_tail(&source);
            assert_eq!(selected.complete_bytes, widened(prefix.len()));
            // The prefix is empty or newline-terminated; the tail holds
            // no newline at all.
            assert!(prefix.last().is_none_or(|&end| end == b'\n'));
            assert!(!tail.contains(&b'\n'));

            // The records concatenate byte-for-byte to the prefix, so the
            // tail appears in no captured record.
            let concatenated: Vec<u8> = RecordBoundary::records(&source)
                .flatten()
                .copied()
                .collect();
            assert_eq!(concatenated, prefix);
        }
    }

    #[test]
    fn incremental_capture_concatenates_to_the_complete_prefix() {
        let mut deterministic = Deterministic(0x0dd1_70f5_eed5_eed5);
        for _ in 0..64 {
            let mut source = deterministic.source(16);
            let mut cursor = CaptureCursor::new();
            let mut captured = Vec::new();

            for _ in 0..8 {
                // Each pass may append a fragment — records terminate
                // across pass boundaries, never inside a capture.
                if deterministic.flip() {
                    source.extend_from_slice(&deterministic.source(12));
                }
                let outcome = cursor.observe(&source).expect("a growing source");
                captured.extend_from_slice(outcome.captured);
                assert_eq!(cursor.position(), outcome.boundary.complete_bytes);
            }

            assert_eq!(captured, RecordBoundary::complete_prefix(&source));
            // Complete bytes plus the measured tail are the whole source:
            // nothing was captured twice and nothing was dropped.
            assert_eq!(
                cursor.position() + RecordBoundary::select(&source).incomplete_tail_bytes,
                widened(source.len()),
            );
        }
    }
}
