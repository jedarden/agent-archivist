// SPDX-License-Identifier: Apache-2.0

//! The bounded transport-decode stage: part two's declared
//! [`TransportEncoding`] decoded into bounded canonical chunks under the two
//! hard payload limits (plan Section 7.6; PI-03; EC-07).
//!
//! The parse split ([`crate::parse::parts`]) hands the pipeline part two as
//! an incremental [`io::Read`]. This stage sits directly on that read
//! surface and turns it into the canonical byte stream the rest of the
//! pipeline consumes — hashing, `zstd-v1` storage encoding, multipart
//! output — without ever holding payload scale:
//!
//! - **Identity** transport passes the bytes through unchanged.
//! - **Zstd** transport decodes exactly one Zstandard frame through the
//!   storage profile's [`ZstdV1Decoder`], so the decoder window cap
//!   ([`archivist_storage::zstd_v1::DECODER_WINDOW_LOG_MAX`]) rejects a
//!   frame demanding a larger window before the allocation exists, the
//!   embedded checksum is verified during read-back, and bytes past the
//!   first frame fail the attempt.
//!
//! # The two hard limits, enforced mid-stream
//!
//! Both ceilings fire against the bytes the decoder has *actually produced*
//! — never against a declared value, which buys nothing once the stream
//! overruns (PI-03) — and they fire as the bytes arrive, so the attempt
//! aborts before any commit exists (plan Section 5 steps 5–6; EC-07: the
//! store ends with no stored object and no live multipart session; the
//! caller that owns the multipart session aborts it on the error):
//!
//! - **Single structured record** — canonical output past the
//!   `record_max_bytes` ceiling is
//!   [`TransportDecodeError::RecordTooLarge`] (`request.record_too_large`).
//!   The record is the whole canonical payload: the server receives
//!   record-boundary chunks, so one record alone crossing the cap is the
//!   unsplittable class.
//! - **Expansion ratio** — canonical output past the `max_expansion_ratio`
//!   ceiling in input bytes per input byte is
//!   [`TransportDecodeError::ExpansionRatioExceeded`]
//!   (`request.expansion_ratio_exceeded`). The ratio is cumulative over the
//!   streamed totals on both sides, so a small compressed body cannot
//!   balloon memory before the guard fires: with the feed slice below, the
//!   output a violating frame adds between two guard checks is bounded by
//!   the Zstandard block ceiling (each block regenerates at most 128 KiB),
//!   not by the frame's claimed extent.
//!
//! Exactly at a cap is lawful; the first byte past it is not. Both limits
//! travel as [`PayloadLimit`] values via
//! [`TransportDecodeError::payload_limit`], so the route layer renders them
//! through the error contract's existing 413 path.
//!
//! # Bounded memory
//!
//! The stage holds two buffers, both fixed: the canonical chunk
//! accumulator (target [`TARGET_CHUNK_BYTES`], allowed to overshoot by one
//! decode step) and the decoder's own window bounded by
//! [`archivist_storage::zstd_v1::DECODER_WINDOW_LOG_MAX`]; the
//! `FEED_SLICE_BYTES` staging slice every source read and decoder call
//! goes through is a stack array living exactly as long as one
//! [`TransportDecoder::next_chunk`] call. Nothing sizes with the body. The
//! feed slice
//! is deliberately small: a hostile frame of run-length blocks regenerates
//! up to 128 KiB per 4 input bytes, so feeding 256 bytes at a time bounds
//! the output any single decode step can add before the guards run at about
//! 8 MiB — the piece that makes the ratio guard a memory bound and not
//! merely a byte count.
//!
//! # Failure
//!
//! Every failure is closed and content-free ([`TransportDecodeError`]): the
//! two limit classes, the codec's static detail for a frame that does not
//! decode (truncated, hostile window, lying content size, trailing bytes —
//! rendered as the registry's `request.framing_invalid`, the
//! request-shape-invalid class), the source's closed [`io::ErrorKind`] on a
//! read failure, and a decoder construction failure that names a build or
//! version drift. Nothing can panic on any input byte sequence, and nothing
//! echoes a request byte.

use std::io;

use archivist_protocol::vocabulary::{ErrorCode, TransportEncoding};
use archivist_storage::error::StorageError;
use archivist_storage::zstd_v1::ZstdV1Decoder;

use crate::config::{DEFAULT_MAX_EXPANSION_RATIO, DEFAULT_RECORD_MAX_BYTES};
use crate::error::PayloadLimit;

/// The target canonical chunk size: 16 MiB (plan Section 7.6, "Target
/// canonical chunk").
///
/// [`TransportDecoder::next_chunk`] yields chunks of exactly this many
/// canonical bytes (the last chunk shorter, never larger targets). A chunk
/// may overshoot the target by one decode step's output — bounded as the
/// module docs describe — because the step runs before the flush check; the
/// overshoot is memory the caller's part writer re-slices, never a second
/// payload-scale buffer.
pub const TARGET_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// The staging slice every source read and every decoder call goes
/// through, in bytes.
///
/// This is the ratio guard's cadence, chosen from the Zstandard block
/// ceiling: one block regenerates at most 128 KiB from a header plus one
/// byte, so a step feeds at most `FEED_SLICE_BYTES / 4` blocks — about
/// 8 MiB of output at 256 bytes — before the guards run again. The
/// corresponding decode throughput stays far above what the 15-minute
/// request deadline needs for a 256 MiB record, which is the trade the
/// guard exists to make.
const FEED_SLICE_BYTES: usize = 256;

/// The ceilings one decode attempt enforces, in the units the validated
/// server configuration carries (`server.record_max_bytes`,
/// `server.max_expansion_ratio`).
#[derive(Clone, Copy, Debug)]
pub struct DecodeLimits {
    /// The single-structured-record cap, in canonical bytes.
    record_max_bytes: u64,
    /// The expansion cap, as a whole number of canonical bytes per
    /// transport byte.
    max_expansion_ratio: u64,
}

impl DecodeLimits {
    /// Cap the record at `record_max_bytes` canonical bytes and the
    /// expansion at `max_expansion_ratio` canonical bytes per transport
    /// byte.
    #[must_use]
    pub const fn new(record_max_bytes: u64, max_expansion_ratio: u64) -> Self {
        Self {
            record_max_bytes,
            max_expansion_ratio,
        }
    }

    /// The registry defaults: the 256 MiB record and the 100:1 expansion
    /// ratio (plan Section 7.6).
    #[must_use]
    // `u64::from` is not const-stable, and this constructor must stay
    // const for the configuration path; the widening is lossless.
    #[allow(clippy::cast_lossless)]
    pub const fn registry_defaults() -> Self {
        Self::new(DEFAULT_RECORD_MAX_BYTES, DEFAULT_MAX_EXPANSION_RATIO as u64)
    }

    /// The single-structured-record cap, in canonical bytes.
    #[must_use]
    pub const fn record_max_bytes(&self) -> u64 {
        self.record_max_bytes
    }

    /// The expansion cap, in canonical bytes per transport byte.
    #[must_use]
    pub const fn max_expansion_ratio(&self) -> u64 {
        self.max_expansion_ratio
    }
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self::registry_defaults()
    }
}

/// Why a decode attempt refused to produce more canonical bytes.
///
/// Every variant is closed and content-free (SEC-004): the counts are the
/// configuration caps and the pre-commit measurements the plan's limits are
/// stated in, and the frame detail is the codec's static text — no variant
/// carries a request byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportDecodeError {
    /// The canonical payload crossed the single-structured-record cap
    /// mid-stream: `request.record_too_large`, 413.
    RecordTooLarge {
        /// The canonical bytes produced when the cap was crossed.
        actual_bytes: u64,
        /// The cap that was crossed, in bytes.
        limit_bytes: u64,
    },
    /// The cumulative expansion crossed its cap mid-stream:
    /// `request.expansion_ratio_exceeded`, 413.
    ExpansionRatioExceeded {
        /// The cap that was crossed, in canonical bytes per transport
        /// byte.
        max_ratio: u64,
    },
    /// The declared transport encoding did not decode the part-two bytes:
    /// a truncated frame, a window demand above the decoder cap, a failed
    /// frame checksum, a content-size lie the stream exposed, or bytes
    /// past the one frame a transport may carry. The detail is the codec's
    /// static text; the wire class is `request.framing_invalid` — the
    /// request is not the byte layout the protocol pins, and no rendering
    /// of it echoes the frame.
    MalformedFrame {
        /// The codec's static, content-free detail.
        detail: &'static str,
    },
    /// The byte source itself failed with the carried closed
    /// [`io::ErrorKind`] — the body ended inside the payload, or the
    /// bridge feeding the parse went away. Nothing has committed; the
    /// wire class is `request.framing_invalid` when a response can still
    /// be delivered at all.
    SourceRead(io::ErrorKind),
    /// The Zstandard decoder could not be constructed with the profile's
    /// window cap: a build or version drift, not a wire condition. The
    /// wire class is `server.internal`.
    CodecSetup,
}

impl TransportDecodeError {
    /// The registry code this failure resolves to: the two limit classes
    /// name their 413 codes, and every other variant fails closed to its
    /// class without carrying a request byte.
    ///
    /// # Panics
    /// Never in practice: every literal below is a registered code the
    /// module tests resolve against the embedded registry, so a panic is a
    /// programming error introduced alongside a rename, not a wire
    /// condition.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::RecordTooLarge { .. } => ErrorCode::parse("request.record_too_large"),
            Self::ExpansionRatioExceeded { .. } => {
                ErrorCode::parse("request.expansion_ratio_exceeded")
            }
            Self::MalformedFrame { .. } | Self::SourceRead(_) => {
                ErrorCode::parse("request.framing_invalid")
            }
            Self::CodecSetup => ErrorCode::parse("server.internal"),
        }
        .expect("every transport-decode code is registry-grammar-clean")
    }

    /// The payload limit behind this failure, when one exists — the value
    /// the route layer's [`ServerFailure::PayloadLimit`] arm renders. The
    /// two limit classes carry it; every other failure is not a size
    /// refusal and resolves to `None`.
    ///
    /// [`ServerFailure::PayloadLimit`]: crate::error::ServerFailure::PayloadLimit
    #[must_use]
    pub fn payload_limit(&self) -> Option<PayloadLimit> {
        match *self {
            Self::RecordTooLarge {
                actual_bytes,
                limit_bytes,
            } => Some(PayloadLimit::UnsplittableRecord {
                actual_bytes,
                limit_bytes,
            }),
            Self::ExpansionRatioExceeded { max_ratio } => {
                Some(PayloadLimit::SplittableRatio { max_ratio })
            }
            Self::MalformedFrame { .. } | Self::SourceRead(_) | Self::CodecSetup => None,
        }
    }

    /// The codec's static detail behind a frame rejection, flattened into
    /// the closed [`Self::MalformedFrame`] shape.
    fn from_storage(error: StorageError) -> Self {
        Self::MalformedFrame {
            detail: error.detail(),
        }
    }
}

impl From<StorageError> for TransportDecodeError {
    fn from(error: StorageError) -> Self {
        Self::from_storage(error)
    }
}

/// The bounded transport-decode stage over any blocking byte source.
///
/// Constructed with the declared [`TransportEncoding`] the envelope carries
/// (the caller has already checked part two's media type against it) and
/// consumed through [`TransportDecoder::next_chunk`] until it yields
/// [`None`]; the totals accessors then report what the attempt produced and
/// consumed for the digest and size validation the commit path performs.
///
/// The type is [`Debug`] with a structural rendering only: nothing
/// request-derived — not even a byte count that could size a payload —
/// appears beyond the fixed buffer names and the mode (SEC-004).
pub struct TransportDecoder<R> {
    encoding: TransportEncoding,
    source: R,
    limits: DecodeLimits,
    /// Present exactly in [`TransportEncoding::Zstd`] mode: the single
    /// decoder consuming the one frame.
    decoder: Option<ZstdV1Decoder>,
    /// The canonical chunk accumulator. Cleared as each chunk is handed
    /// out, so its allocation — target [`TARGET_CHUNK_BYTES`] — is the
    /// stage's only payload-scale buffer.
    chunk: Vec<u8>,
    /// Transport bytes consumed from the source so far.
    transport_total: u64,
    /// Canonical bytes produced so far (emitted chunks plus any still in
    /// `chunk`).
    canonical_total: u64,
    /// The source returned end-of-stream.
    source_ended: bool,
    /// Every canonical byte has been emitted (`next_chunk` returned
    /// [`None`]).
    drained: bool,
    /// The first failure this attempt met, if any. Every later
    /// `next_chunk` call re-yields it without touching the source, so a
    /// stage already past a limit can never be resumed into producing
    /// more canonical bytes.
    failure: Option<TransportDecodeError>,
}

impl<R> std::fmt::Debug for TransportDecoder<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportDecoder")
            .field("encoding", &self.encoding.token())
            .field("drained", &self.drained)
            .finish_non_exhaustive()
    }
}

impl<R: io::Read> TransportDecoder<R> {
    /// Build the stage for one attempt over `source` at the declared
    /// transport encoding under `limits`.
    ///
    /// # Errors
    /// [`TransportDecodeError::CodecSetup`] when the Zstandard decoder
    /// could not be constructed — with the pinned dependency this cannot
    /// happen, and the failure names a build or version drift.
    pub fn new(
        encoding: TransportEncoding,
        source: R,
        limits: DecodeLimits,
    ) -> Result<Self, TransportDecodeError> {
        let decoder = match encoding {
            TransportEncoding::Identity => None,
            // A construction failure is a build or version drift, not a
            // wire condition, so it must not ride the wire-class
            // conversion the frame failures use.
            TransportEncoding::Zstd => {
                Some(ZstdV1Decoder::new().map_err(|_| TransportDecodeError::CodecSetup)?)
            }
        };
        Ok(Self {
            encoding,
            source,
            limits,
            decoder,
            chunk: Vec::new(),
            transport_total: 0,
            canonical_total: 0,
            source_ended: false,
            drained: false,
            failure: None,
        })
    }

    /// Record the attempt's first failure and hand it back: from here on
    /// the stage is closed.
    fn fail(&mut self, error: TransportDecodeError) -> TransportDecodeError {
        self.failure = Some(error);
        error
    }

    /// The declared transport encoding this stage decodes.
    #[must_use]
    pub const fn encoding(&self) -> TransportEncoding {
        self.encoding
    }

    /// Canonical bytes produced so far — emitted chunks plus any still
    /// buffered. At a completed stream this is the payload's canonical
    /// size, the number the record cap and the digest validation are
    /// stated in.
    #[must_use]
    pub const fn canonical_bytes(&self) -> u64 {
        self.canonical_total
    }

    /// Transport bytes consumed from the source so far — for
    /// [`TransportEncoding::Zstd`] the compressed extent, for
    /// [`TransportEncoding::Identity`] identical to
    /// [`Self::canonical_bytes`]. At a completed stream this is the number
    /// the ratio guard and the declared `compressed_size` check are stated
    /// in.
    #[must_use]
    pub const fn transport_bytes(&self) -> u64 {
        self.transport_total
    }

    /// Whether the stream is complete: every canonical byte has been
    /// emitted and `next_chunk` has returned [`None`].
    #[must_use]
    pub const fn is_drained(&self) -> bool {
        self.drained
    }

    /// Return the source after the decoder has been drained.
    ///
    /// Callers that use the decoder as a verification preflight can then
    /// finish the source's framing contract without opening a storage
    /// session. The source is returned unchanged; no bytes are copied.
    #[must_use]
    pub fn into_source(self) -> R {
        self.source
    }

    /// Produce the next bounded canonical chunk, or [`None`] once the
    /// stream is complete.
    ///
    /// The returned slice is borrowed from the stage and is invalidated by
    /// the next call. Every chunk except the last is
    /// [`TARGET_CHUNK_BYTES`] canonical bytes. Identity transport fills
    /// chunks straight from the source; zstd transport decodes through the
    /// profile decoder, draining any frame-buffered output at end of
    /// stream and failing there if the frame arrived incomplete. The two
    /// hard limits run against the running totals after every step, so a
    /// violation surfaces here — mid-stream, before anything committed.
    ///
    /// After an error the attempt is over: the stage re-yields the same
    /// failure on every later call and never reads the source again, and
    /// the caller that owns the multipart session aborts it.
    ///
    /// # Errors
    /// The first [`TransportDecodeError`] the stream meets.
    pub fn next_chunk(&mut self) -> Result<Option<&[u8]>, TransportDecodeError> {
        // The previous chunk's borrow ended with the last call; reuse its
        // allocation.
        self.chunk.clear();
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.drained {
            return Ok(None);
        }
        // The one stack slice every read and every decode step goes
        // through — the ratio guard's cadence (module docs). It lives
        // exactly this long and never enters `self`, so no payload-scale
        // staging survives a call.
        let mut feed = [0u8; FEED_SLICE_BYTES];
        loop {
            if self.chunk.len() >= TARGET_CHUNK_BYTES {
                return Ok(Some(self.chunk.as_slice()));
            }
            if self.source_ended {
                return self.finish_chunk();
            }
            let consumed = match self.source.read(&mut feed) {
                Ok(consumed) => consumed,
                Err(error) => {
                    return Err(self.fail(TransportDecodeError::SourceRead(error.kind())));
                }
            };
            if consumed == 0 {
                self.source_ended = true;
                continue;
            }
            let slice = &feed[..consumed];
            let produced = match self.decode_step(slice) {
                Ok(produced) => produced,
                Err(error) => return Err(self.fail(error)),
            };
            self.transport_total += consumed as u64;
            self.canonical_total += produced as u64;
            if let Err(error) = self.enforce_limits() {
                return Err(self.fail(error));
            }
        }
    }

    /// Decode one feed slice into the chunk accumulator, returning the
    /// canonical bytes the step produced.
    fn decode_step(&mut self, slice: &[u8]) -> Result<usize, TransportDecodeError> {
        match &mut self.decoder {
            None => {
                self.chunk.extend_from_slice(slice);
                Ok(slice.len())
            }
            Some(decoder) => {
                let before = self.chunk.len();
                decoder.update(slice, &mut self.chunk)?;
                Ok(self.chunk.len() - before)
            }
        }
    }

    /// End of source: drain any frame-buffered output, then emit the
    /// final chunk or close the stream.
    fn finish_chunk(&mut self) -> Result<Option<&[u8]>, TransportDecodeError> {
        if self.decoder.is_some() {
            let before = self.chunk.len();
            // Bind the result so the decoder borrow ends before the
            // failure can be recorded against `self`.
            let finished = match &mut self.decoder {
                Some(decoder) => decoder.finish(&mut self.chunk),
                None => Ok(()),
            };
            if let Err(error) = finished {
                return Err(self.fail(error.into()));
            }
            let produced = self.chunk.len() - before;
            self.canonical_total += produced as u64;
            if let Err(error) = self.enforce_limits() {
                return Err(self.fail(error));
            }
        }
        if self.chunk.is_empty() {
            self.drained = true;
            return Ok(None);
        }
        Ok(Some(self.chunk.as_slice()))
    }

    /// Run both hard limits against the running totals.
    fn enforce_limits(&self) -> Result<(), TransportDecodeError> {
        if self.canonical_total > self.limits.record_max_bytes {
            return Err(TransportDecodeError::RecordTooLarge {
                actual_bytes: self.canonical_total,
                limit_bytes: self.limits.record_max_bytes,
            });
        }
        // u128: the product of a 10,000-cap ratio and a streamed total
        // stays exact for every input the deadline admits, and the
        // comparison must not wrap into a false pass.
        let allowance =
            u128::from(self.limits.max_expansion_ratio) * u128::from(self.transport_total);
        if u128::from(self.canonical_total) > allowance {
            return Err(TransportDecodeError::ExpansionRatioExceeded {
                max_ratio: self.limits.max_expansion_ratio,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use archivist_protocol::derivation::blob_digest;
    use archivist_protocol::object_key::BlobObjectKey;
    use archivist_protocol::sha256;
    use archivist_protocol::vocabulary::{
        StorageOutcome, StorageProfile, TenantId, TransportEncoding,
    };
    use archivist_storage::blob::BlobEncoder;
    use archivist_storage::capability::StoreCapabilities;
    use archivist_storage::error::StorageError;
    use archivist_storage::metadata::ObjectTag;
    use archivist_storage::multipart::{MultipartWriter, OpenUploads, PART_BYTES};
    use archivist_storage::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };
    use archivist_storage::zstd_v1::ZstdV1Encoder;

    use super::{
        DecodeLimits, FEED_SLICE_BYTES, TARGET_CHUNK_BYTES, TransportDecodeError, TransportDecoder,
    };
    use crate::error::PayloadLimit;

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";

    /// Deterministic pseudo-random bytes: incompressible, so a payload's
    /// transport form stays within a known ratio of its canonical size.
    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut bytes = Vec::with_capacity(len);
        while bytes.len() < len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.extend_from_slice(&state.to_le_bytes());
        }
        bytes.truncate(len);
        bytes
    }

    /// The `zstd` transport frame of `canonical`, exactly as a client
    /// would transmit it: one Zstandard frame of the canonical bytes.
    fn zstd_frame(canonical: &[u8]) -> Vec<u8> {
        let mut encoder = ZstdV1Encoder::new(canonical.len() as u64).expect("profile encoder");
        let mut frame = Vec::new();
        BlobEncoder::update(&mut encoder, canonical, &mut frame).expect("frame body");
        BlobEncoder::finish(&mut encoder, &mut frame).expect("frame epilogue");
        frame
    }

    /// Pull `decoder` to completion, returning every canonical byte.
    fn drain_all<R: std::io::Read>(
        decoder: &mut TransportDecoder<R>,
    ) -> Result<Vec<u8>, TransportDecodeError> {
        let mut canonical = Vec::new();
        while let Some(chunk) = decoder.next_chunk()? {
            canonical.extend_from_slice(chunk);
        }
        Ok(canonical)
    }

    fn identity_decoder(payload: &[u8], limits: DecodeLimits) -> TransportDecoder<Cursor<&[u8]>> {
        TransportDecoder::new(TransportEncoding::Identity, Cursor::new(payload), limits)
            .expect("identity decoder needs no codec setup")
    }

    fn zstd_decoder(frame: &[u8], limits: DecodeLimits) -> TransportDecoder<Cursor<&[u8]>> {
        TransportDecoder::new(TransportEncoding::Zstd, Cursor::new(frame), limits)
            .expect("profile decoder setup")
    }

    #[test]
    fn identity_pass_through_yields_bounded_chunks_in_order() {
        let payload = pseudo_random(TARGET_CHUNK_BYTES + 1234);
        let mut decoder = identity_decoder(&payload, DecodeLimits::registry_defaults());
        let mut pulled = 0;
        let mut chunks = 0;
        while let Some(chunk) = decoder.next_chunk().expect("identity chunk") {
            assert_eq!(chunk, &payload[pulled..pulled + chunk.len()]);
            pulled += chunk.len();
            chunks += 1;
        }
        // Every chunk but the last is the target; the tail is what
        // remains.
        assert_eq!(pulled, payload.len());
        assert!(chunks >= 1);
        assert_eq!(decoder.canonical_bytes(), payload.len() as u64);
        assert_eq!(decoder.transport_bytes(), payload.len() as u64);
        assert!(decoder.is_drained());
    }

    #[test]
    fn identity_empty_stream_drains_with_zero_totals() {
        let mut decoder = identity_decoder(b"", DecodeLimits::registry_defaults());
        assert!(decoder.next_chunk().expect("empty identity").is_none());
        assert!(decoder.is_drained());
        assert_eq!(decoder.canonical_bytes(), 0);
    }

    #[test]
    fn zstd_transport_round_trips_the_canonical_bytes() {
        let payload = pseudo_random(TARGET_CHUNK_BYTES + FEED_SLICE_BYTES * 3);
        let frame = zstd_frame(&payload);
        // The xorshift payload is incompressible: the frame carries it
        // near 1:1 (frame overhead makes it slightly larger), which is
        // the ratio neighborhood the default guard must admit while the
        // attempt still crosses chunk and feed-slice boundaries.
        assert!(
            frame.len() >= payload.len(),
            "xorshift bytes do not compress"
        );
        let mut decoder = zstd_decoder(&frame, DecodeLimits::registry_defaults());
        let canonical = drain_all(&mut decoder).expect("round trip");
        assert_eq!(canonical, payload);
        assert_eq!(decoder.canonical_bytes(), payload.len() as u64);
        assert_eq!(decoder.transport_bytes(), frame.len() as u64);
    }

    #[test]
    fn identity_record_cap_boundary_exactly_at_cap_passes_one_past_fails() {
        let limit = DecodeLimits::new(4096, 100);
        let payload = pseudo_random(4096);
        let mut decoder = identity_decoder(&payload, limit);
        assert_eq!(
            drain_all(&mut decoder).expect("exactly at cap is lawful"),
            payload
        );
        let payload = pseudo_random(4097);
        let mut decoder = identity_decoder(&payload, limit);
        assert_eq!(
            decoder.next_chunk().expect_err("one past the cap"),
            TransportDecodeError::RecordTooLarge {
                actual_bytes: 4097,
                limit_bytes: 4096,
            }
        );
    }

    #[test]
    fn zstd_record_cap_fires_against_produced_bytes_not_declared_ones() {
        // The frame is well formed; the canonical extent alone crosses
        // the cap — the compressed body is tiny by comparison, which is
        // the lying-declaration case the ceiling exists for. Where the
        // crossing lands inside the decoder's block output is the
        // codec's business; that it lands against produced bytes, past
        // the cap but never past the real payload, is the stage's.
        let payload = pseudo_random(8192);
        let frame = zstd_frame(&payload);
        let mut decoder = zstd_decoder(&frame, DecodeLimits::new(4096, 100));
        let error = loop {
            match decoder.next_chunk() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("8192 canonical bytes fit no 4096 cap"),
                Err(error) => break error,
            }
        };
        match error {
            TransportDecodeError::RecordTooLarge {
                actual_bytes,
                limit_bytes: 4096,
            } => {
                assert!(actual_bytes > 4096, "fired at the cap, not past it");
                assert!(actual_bytes <= 8192, "fired against bytes never produced");
            }
            other => panic!("record cap crossed as {other:?}, not a record-cap refusal"),
        }
        assert_eq!(error.code().as_str(), "request.record_too_large");
        assert!(error.payload_limit().is_some());
    }

    #[test]
    fn expansion_ratio_boundary_straddles_the_measured_frame_exactly() {
        // One well-formed frame, two caps on either side of the ratio it
        // actually achieves: the just-under cap admits the attempt, the
        // just-over cap refuses it mid-stream.
        let payload = vec![0u8; 4096];
        let frame = zstd_frame(&payload);
        let canonical = payload.len() as u64;
        let compressed = frame.len() as u64;
        assert!(compressed > 0);
        // Passes iff canonical <= cap * compressed, so the largest
        // lawful cap is ceil(canonical / compressed).
        let under = canonical.div_ceil(compressed);
        let mut decoder = zstd_decoder(&frame, DecodeLimits::new(4096, under));
        assert_eq!(
            drain_all(&mut decoder).expect("cap admits the frame's own ratio"),
            payload
        );
        // One lower and the same frame crosses the ratio mid-stream.
        let over = under - 1;
        let mut decoder = zstd_decoder(&frame, DecodeLimits::new(4096, over));
        let error = loop {
            match decoder.next_chunk() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("the frame exceeds its own ratio cap by construction"),
                Err(error) => break error,
            }
        };
        assert_eq!(
            error,
            TransportDecodeError::ExpansionRatioExceeded { max_ratio: over }
        );
        assert_eq!(error.code().as_str(), "request.expansion_ratio_exceeded");
    }

    #[test]
    fn ratio_guard_runs_at_the_default_cap_against_streamed_totals() {
        // Highly compressible content crosses 100:1 well before the
        // record cap; the guard fires from the totals the decoder
        // actually produced.
        let payload = vec![0u8; 256 * 1024];
        let frame = zstd_frame(&payload);
        assert!(frame.len() as u64 * 100 < payload.len() as u64);
        let mut decoder = zstd_decoder(&frame, DecodeLimits::registry_defaults());
        let error = loop {
            match decoder.next_chunk() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("zeros exceed the default 100:1 ratio"),
                Err(error) => break error,
            }
        };
        assert!(matches!(
            error,
            TransportDecodeError::ExpansionRatioExceeded { max_ratio: 100 }
        ));
        // The guard fired against streamed totals, and the whole frame
        // rode one feed slice: the canonical bytes ever produced are the
        // payload itself and the transport bytes consumed fit one read —
        // the small-compressed-body property the ratio limit exists to
        // pin, memory bounded by the guard's cadence rather than the
        // frame's claimed extent.
        assert_eq!(decoder.canonical_bytes(), payload.len() as u64);
        assert!(decoder.transport_bytes() <= FEED_SLICE_BYTES as u64);
        // Incompressible content stays near 1:1 and passes the same
        // default.
        let payload = pseudo_random(64 * 1024);
        let frame = zstd_frame(&payload);
        let mut decoder = zstd_decoder(&frame, DecodeLimits::registry_defaults());
        assert_eq!(
            drain_all(&mut decoder).expect("random bytes sit far below 100:1"),
            payload
        );
    }

    #[test]
    fn truncated_frame_fails_closed_at_finish() {
        let frame = zstd_frame(&pseudo_random(4096));
        let cut = frame.len() / 2;
        let mut decoder = zstd_decoder(&frame[..cut], DecodeLimits::registry_defaults());
        let error = loop {
            match decoder.next_chunk() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("a cut frame is not a complete stream"),
                Err(error) => break error,
            }
        };
        assert!(matches!(error, TransportDecodeError::MalformedFrame { .. }));
        assert_eq!(error.code().as_str(), "request.framing_invalid");
        assert!(error.payload_limit().is_none());
    }

    #[test]
    fn empty_transport_body_is_a_truncated_frame() {
        // A zstd transport body of zero bytes carries no frame at all:
        // the attempt fails at the drain, with the codec's own truncated
        // detail — never a lawful empty stream.
        let mut decoder = zstd_decoder(&[], DecodeLimits::registry_defaults());
        let error = decoder
            .next_chunk()
            .expect_err("an absent frame is not a stream");
        assert!(matches!(error, TransportDecodeError::MalformedFrame { .. }));
        assert_eq!(error.code().as_str(), "request.framing_invalid");
    }

    #[test]
    fn hostile_window_demand_fails_closed_without_allocating() {
        // A frame header whose window descriptor demands a window far
        // above the decoder cap: the decoder must refuse it before any
        // window allocation, whatever follows the header.
        let mut hostile = Vec::new();
        hostile.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]); // frame magic
        hostile.push(0xFF); // window descriptor: exponent 31
        hostile.extend_from_slice(&pseudo_random(64));
        let mut decoder = zstd_decoder(&hostile, DecodeLimits::registry_defaults());
        let error = loop {
            match decoder.next_chunk() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("a hostile window is not a decodable frame"),
                Err(error) => break error,
            }
        };
        assert!(matches!(error, TransportDecodeError::MalformedFrame { .. }));
    }

    #[test]
    fn lying_content_size_fails_when_the_stream_ends_short() {
        // A frame header pledging a content size the body never
        // delivers: the decoder drains at end of stream and fails there —
        // the declared value bought nothing.
        let mut lying = Vec::new();
        lying.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]); // frame magic
        // Frame header descriptor: content-size flag set, single
        // segment cleared, checksum cleared, dictionary ID absent,
        // content size as 8 bytes (FCS field code 3).
        lying.push(0b1000_0000 | 0b11);
        lying.extend_from_slice(&1_000_000u64.to_le_bytes());
        lying.extend_from_slice(b"short body");
        let mut decoder = zstd_decoder(&lying, DecodeLimits::registry_defaults());
        let error = loop {
            match decoder.next_chunk() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("a pledge the body never meets is not a stream"),
                Err(error) => break error,
            }
        };
        assert!(matches!(error, TransportDecodeError::MalformedFrame { .. }));
    }

    #[test]
    fn bytes_past_the_first_frame_fail_the_attempt() {
        let mut frame = zstd_frame(&pseudo_random(1024));
        frame.extend_from_slice(b"trailing");
        let mut decoder = zstd_decoder(&frame, DecodeLimits::registry_defaults());
        let error = loop {
            match decoder.next_chunk() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("trailing bytes are not more content"),
                Err(error) => break error,
            }
        };
        assert!(matches!(error, TransportDecodeError::MalformedFrame { .. }));
    }

    #[test]
    fn source_read_failure_surfaces_closed_and_content_free() {
        struct Failing;
        impl std::io::Read for Failing {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }
        let mut decoder = TransportDecoder::new(
            TransportEncoding::Identity,
            Failing,
            DecodeLimits::registry_defaults(),
        )
        .expect("identity decoder");
        let error = decoder.next_chunk().expect_err("the source failed");
        assert_eq!(
            error,
            TransportDecodeError::SourceRead(std::io::ErrorKind::BrokenPipe)
        );
        assert_eq!(error.code().as_str(), "request.framing_invalid");
    }

    #[test]
    fn a_failed_stage_stays_closed_and_reyields_its_failure() {
        // The poison contract: once an attempt has failed, every later
        // `next_chunk` call re-yields the same failure and the source is
        // never read again — a stream already past a limit cannot be
        // resumed into producing more canonical bytes.
        struct Counting<'a>(&'a AtomicUsize);
        impl std::io::Read for Counting<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0.fetch_add(1, Ordering::SeqCst);
                let taken = buf.len().min(4);
                buf[..taken].fill(0x7F);
                Ok(taken)
            }
        }
        let reads = AtomicUsize::new(0);
        let mut decoder = TransportDecoder::new(
            TransportEncoding::Identity,
            Counting(&reads),
            DecodeLimits::new(8, 100),
        )
        .expect("identity decoder");
        let first = decoder
            .next_chunk()
            .expect_err("a stream past the cap fails");
        assert!(matches!(first, TransportDecodeError::RecordTooLarge { .. }));
        let reads_at_failure = reads.load(Ordering::SeqCst);
        for _ in 0..3 {
            assert_eq!(decoder.next_chunk().expect_err("still failed"), first);
        }
        assert_eq!(
            reads.load(Ordering::SeqCst),
            reads_at_failure,
            "a failed stage reads no further"
        );
    }

    #[test]
    fn fuzzed_frames_never_panic_and_fail_closed_with_registry_classes() {
        // Deterministic pseudo-fuzz: frames whose prefixes are valid
        // magic, headers, or real frame bodies and whose bodies drift
        // through every byte value. Every outcome must be a lawful
        // stream, a limit class, or a closed frame/source class — never a
        // panic.
        const FRAME_CLASSES: [&str; 4] = [
            "request.framing_invalid",
            "request.record_too_large",
            "request.expansion_ratio_exceeded",
            "server.internal",
        ];
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for case in 0..256u32 {
            let mut frame = Vec::new();
            // Half the cases open with the real magic; the rest start
            // anywhere.
            if case % 2 == 0 {
                frame.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
            }
            let len = (case as usize * 37) % 2048;
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                frame.push(state.to_le_bytes()[0]);
            }
            let mut decoder = zstd_decoder(&frame, DecodeLimits::registry_defaults());
            let outcome = drain_all(&mut decoder);
            if let Err(error) = outcome {
                let code = error.code();
                let token = code.as_str();
                assert!(
                    FRAME_CLASSES.contains(&token),
                    "case {case}: {token} is not a registered class"
                );
            }
        }
    }

    #[test]
    fn codec_setup_failure_fails_closed_to_the_internal_class() {
        // The error type must render the build-drift case without
        // carrying a wire condition: constructed directly, it maps to
        // server.internal and no payload limit.
        let error = TransportDecodeError::CodecSetup;
        assert_eq!(error.code().as_str(), "server.internal");
        assert!(error.payload_limit().is_none());
    }

    #[test]
    fn debug_rendering_carries_no_payload_shape() {
        let payload = pseudo_random(1024);
        let frame = zstd_frame(&payload);
        let decoder = zstd_decoder(&frame, DecodeLimits::registry_defaults());
        let rendered = format!("{decoder:?}");
        assert!(rendered.contains("TransportDecoder"));
        assert!(rendered.contains("zstd"));
        assert!(!rendered.contains(&payload.len().to_string()));
    }

    #[test]
    fn registry_defaults_carry_the_plan_limits() {
        let limits = DecodeLimits::registry_defaults();
        assert_eq!(limits.record_max_bytes(), 268_435_456);
        assert_eq!(limits.max_expansion_ratio(), 100);
    }

    #[test]
    fn limit_errors_carry_their_payload_limits() {
        let record = TransportDecodeError::RecordTooLarge {
            actual_bytes: 300_000_000,
            limit_bytes: 268_435_456,
        };
        assert_eq!(
            record.payload_limit(),
            Some(PayloadLimit::UnsplittableRecord {
                actual_bytes: 300_000_000,
                limit_bytes: 268_435_456,
            })
        );
        let ratio = TransportDecodeError::ExpansionRatioExceeded { max_ratio: 100 };
        assert_eq!(
            ratio.payload_limit(),
            Some(PayloadLimit::SplittableRatio { max_ratio: 100 })
        );
    }

    /// A compile-time guard that the frame helpers stay honest: the
    /// digest of a decoded frame matches the digest of its canonical
    /// bytes, the identity the commit path validates downstream.
    #[test]
    fn decoded_frame_digest_matches_canonical_digest() {
        let payload = pseudo_random(2048);
        let frame = zstd_frame(&payload);
        let mut decoder = zstd_decoder(&frame, DecodeLimits::registry_defaults());
        let canonical = drain_all(&mut decoder).expect("round trip");
        assert_eq!(
            sha256::digest(&canonical),
            sha256::digest(&payload),
            "the transport frame carries the canonical bytes"
        );
    }

    /// Silence the unused-import lint when `TenantId` is only needed by
    /// the integration suite: the mock tenant grammar stays pinned here.
    #[test]
    fn mock_tenant_grammar_stays_valid() {
        assert!(TenantId::parse(TENANT).is_ok());
        assert_eq!(StorageProfile::ZstdV1.token(), "zstd-v1");
    }

    // ------------------------------------------------------------------
    // Abort-before-commit, against a store. The decode stage never
    // touches the store itself — the caller that owns the multipart
    // session does — so these tests pin the caller contract the route
    // wiring inherits: chunks flow into a live session as they are
    // produced, and a limit violation ends in the caller's abort, leaving
    // the store with no committed object and no live session. The
    // at-cap side of each boundary commits exactly once, which is what
    // the abort side is measured against.
    // ------------------------------------------------------------------

    /// A store double that records what an attempt did to it. The
    /// counters are the assertion surface; `write_manifest` is out of
    /// this stage's reach by construction and panics if a later slice
    /// ever routes one through a decode attempt.
    struct RecordingStore {
        parts: AtomicUsize,
        commits: AtomicUsize,
        aborts: AtomicUsize,
    }

    impl RecordingStore {
        fn new() -> Self {
            Self {
                parts: AtomicUsize::new(0),
                commits: AtomicUsize::new(0),
                aborts: AtomicUsize::new(0),
            }
        }
    }

    impl RawWriteStore for RecordingStore {
        fn capabilities(&self) -> StoreCapabilities {
            StoreCapabilities::unprobed()
        }

        async fn write_manifest(
            &self,
            _key: &ManifestKey,
            _bytes: &[u8],
        ) -> Result<StorageOutcome, StorageError> {
            panic!("the decode stage reached a manifest write");
        }

        async fn begin_multipart(
            &self,
            _blob: &BlobObjectKey,
        ) -> Result<MultipartUploadId, StorageError> {
            Ok(MultipartUploadId::parse("transport-decode-guard-test").expect("session grammar"))
        }

        async fn write_part(
            &self,
            _upload: &MultipartUploadId,
            part: PartNumber,
            _bytes: &[u8],
        ) -> Result<PartCommitment, StorageError> {
            self.parts.fetch_add(1, Ordering::SeqCst);
            let tag = ObjectTag::parse("transport-decode-guard-test").expect("tag grammar");
            Ok(PartCommitment::new(part, tag))
        }

        async fn commit_multipart(
            &self,
            _upload: &MultipartUploadId,
            _parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(StorageOutcome::Created)
        }

        async fn abort_multipart(&self, _upload: &MultipartUploadId) -> Result<(), StorageError> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Drive one attempt the way the ingest route will: every produced
    /// chunk goes straight into the live session, and the first decode
    /// failure comes back to the caller with the session still open —
    /// exactly the state the abort-on-error contract answers.
    async fn streamed_into_store<R: std::io::Read>(
        decoder: &mut TransportDecoder<R>,
        writer: &mut MultipartWriter<'_, RecordingStore>,
    ) -> Result<(), TransportDecodeError> {
        loop {
            match decoder.next_chunk() {
                Ok(Some(chunk)) => {
                    writer
                        .write_chunk(chunk)
                        .await
                        .expect("the recording store never refuses a part");
                }
                Ok(None) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    #[tokio::test]
    async fn record_cap_over_fires_mid_stream_and_leaves_the_store_untouched() {
        let store = RecordingStore::new();
        let open = OpenUploads::new();
        let tenant = TenantId::parse(TENANT).expect("tenant grammar");
        // One byte past the cap: the attempt dies inside the decode loop
        // with the session still live, and the caller's abort — not a
        // commit — is what closes it.
        let cap = PART_BYTES + 1;
        let payload = vec![0u8; cap + 1];
        let blob = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &blob_digest(&payload));
        let mut writer = MultipartWriter::begin(&store, &blob, &open)
            .await
            .expect("session begins");
        let cap = u64::try_from(cap).expect("part bound fits u64");
        let mut decoder = identity_decoder(&payload, DecodeLimits::new(cap, 100));
        let failure = streamed_into_store(&mut decoder, &mut writer)
            .await
            .expect_err("one byte past the cap is past the cap");
        assert!(matches!(
            failure,
            TransportDecodeError::RecordTooLarge { .. }
        ));
        writer.abort().await.expect("abort releases the session");
        assert_eq!(store.commits.load(Ordering::SeqCst), 0, "nothing committed");
        assert_eq!(store.aborts.load(Ordering::SeqCst), 1);
        assert_eq!(open.live_count(), 0, "no live session survives");
    }

    #[tokio::test]
    async fn record_cap_at_cap_attempt_streams_and_commits_once() {
        let store = RecordingStore::new();
        let open = OpenUploads::new();
        let tenant = TenantId::parse(TENANT).expect("tenant grammar");
        // Exactly at the cap is lawful: the attempt streams, the writer
        // crosses one part boundary and flushes the tail, and the caller
        // commits exactly once.
        let cap = PART_BYTES + 1;
        let payload = vec![0u8; cap];
        let blob = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &blob_digest(&payload));
        let mut writer = MultipartWriter::begin(&store, &blob, &open)
            .await
            .expect("session begins");
        let cap = u64::try_from(cap).expect("part bound fits u64");
        let mut decoder = identity_decoder(&payload, DecodeLimits::new(cap, 100));
        streamed_into_store(&mut decoder, &mut writer)
            .await
            .expect("exactly at the cap is lawful");
        writer.finish().await.expect("the tail part flushes");
        writer.commit().await.expect("the attempt commits");
        assert_eq!(store.commits.load(Ordering::SeqCst), 1);
        assert_eq!(store.aborts.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.parts.load(Ordering::SeqCst),
            2,
            "one full part and the tail"
        );
        assert_eq!(open.live_count(), 0, "commit releases the session");
    }

    #[tokio::test]
    async fn expansion_ratio_over_fires_mid_stream_and_leaves_the_store_untouched() {
        let store = RecordingStore::new();
        let open = OpenUploads::new();
        let tenant = TenantId::parse(TENANT).expect("tenant grammar");
        // Zeros from a tiny frame cross the default 100:1 well inside the
        // record cap: the ratio guard is the limit that fires, and the
        // attempt aborts with the store untouched.
        let payload = vec![0u8; 256 * 1024];
        let blob = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &blob_digest(&payload));
        let frame = zstd_frame(&payload);
        let mut writer = MultipartWriter::begin(&store, &blob, &open)
            .await
            .expect("session begins");
        let mut decoder = zstd_decoder(&frame, DecodeLimits::registry_defaults());
        let failure = streamed_into_store(&mut decoder, &mut writer)
            .await
            .expect_err("zeros exceed the default ratio");
        assert!(matches!(
            failure,
            TransportDecodeError::ExpansionRatioExceeded { .. }
        ));
        writer.abort().await.expect("abort releases the session");
        assert_eq!(store.commits.load(Ordering::SeqCst), 0, "nothing committed");
        assert_eq!(store.aborts.load(Ordering::SeqCst), 1);
        assert_eq!(open.live_count(), 0, "no live session survives");
    }

    #[tokio::test]
    async fn expansion_ratio_at_cap_attempt_streams_and_commits_once() {
        let store = RecordingStore::new();
        let open = OpenUploads::new();
        let tenant = TenantId::parse(TENANT).expect("tenant grammar");
        // The cap set exactly to the ratio the frame achieves is lawful
        // end to end: the whole frame lands in one feed slice, so the
        // streamed totals the guard sees are the frame's final ones, and
        // the attempt streams, flushes its tail part, and commits.
        let payload = vec![0u8; 4096];
        let blob = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &blob_digest(&payload));
        let frame = zstd_frame(&payload);
        assert!(frame.len() <= FEED_SLICE_BYTES, "one-step decode");
        let canonical = payload.len() as u64;
        let compressed = frame.len() as u64;
        let cap = canonical.div_ceil(compressed);
        let mut writer = MultipartWriter::begin(&store, &blob, &open)
            .await
            .expect("session begins");
        let mut decoder = zstd_decoder(&frame, DecodeLimits::new(u64::MAX, cap));
        streamed_into_store(&mut decoder, &mut writer)
            .await
            .expect("the frame's own ratio is lawful at the cap");
        writer.finish().await.expect("the tail part flushes");
        writer.commit().await.expect("the attempt commits");
        assert_eq!(store.commits.load(Ordering::SeqCst), 1);
        assert_eq!(store.aborts.load(Ordering::SeqCst), 0);
        assert_eq!(store.parts.load(Ordering::SeqCst), 1, "the tail part alone");
        assert_eq!(open.live_count(), 0, "commit releases the session");
    }
}
