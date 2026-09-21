// SPDX-License-Identifier: Apache-2.0

//! The `zstd-v1` storage codec: the pinned Zstandard transform behind the
//! [`crate::blob::BlobEncoder`] seam (plan Section 7.6).
//!
//! Version 1 has exactly one storage profile, and this module is its whole
//! codec surface: [`ZstdV1Encoder`] produces the stored form, and
//! [`ZstdV1Decoder`] is the matching incremental read-back primitive the
//! streaming pipeline consumes. The parameter set is the plan's, exactly:
//!
//! - **Level 3** — the pinned quality point; it is one half of what makes
//!   the stored form a function of the canonical bytes alone.
//! - **Single-threaded** — `zstdmt` stays off in the dependency (the
//!   workspace pin carries the rationale), so the C library has no
//!   multithreaded emission path at all. A test asserts this structurally
//!   rather than trusting the feature declaration.
//! - **No dictionary** — the frame carries no dictionary ID, and the
//!   decoder accepts none; the profile is self-describing.
//! - **Pledged content size** — the encoder is constructed with the
//!   stream's declared uncompressed extent, and the frame header records
//!   it, so every reader can bound its work before allocating.
//! - **Embedded checksum** — the frame carries the XXH64 of the canonical
//!   content, and the decoder verifies it during read-back.
//!
//! Together these deliver the deterministic canonical form VAL-006 pins:
//! identical canonical bytes produce identical stored bytes on every
//! platform and retry, which is what makes a content-addressed replay
//! converge. The pinned dependency version is part of that contract — the
//! golden vector test fails if the linked libzstd is not the version the
//! profile was pinned with — and a version bump is a new named profile,
//! never a silent rewrite (plan Section 7.5).
//!
//! The commit layer ([`crate::blob`]) drives the encoder through the
//! [`crate::blob::BlobEncoder`] trait; the decoder is not part of that
//! trait — it is the primitive the transport stage (which owns decode,
//! expansion checks, and deadlines) consumes directly.

use zstd_safe::zstd_sys::ZSTD_EndDirective;
use zstd_safe::{CCtx, CParameter, DCtx, DParameter, InBuffer, OutBuffer};

use crate::blob::BlobEncoder;
use crate::error::{StorageError, StorageErrorKind};

/// The pinned Zstandard compression level (plan Section 7.6). Part of the
/// `zstd-v1` profile identity: changing it changes stored bytes and
/// requires a new named profile.
pub const COMPRESSION_LEVEL: zstd_safe::CompressionLevel = 3;

/// The decoder window cap, expressed as a base-2 logarithm: 2^23 = 8 MiB.
///
/// The level-3 encoder's default window is at most 2 MiB (2^21), so every
/// frame this profile emits decodes under the cap with headroom, while a
/// hostile or foreign frame demanding a larger window is rejected before
/// the decoder allocates for it. Raising the cap is a decoder-only change
/// and does not alter stored bytes; it is still a reviewed profile
/// decision, because the cap is what bounds decompressor memory.
pub const DECODER_WINDOW_LOG_MAX: u32 = 23;

/// The static detail for an encoder or decoder that could not be
/// configured with the profile's parameters.
const CODEC_SETUP_DETAIL: &str = "zstd codec setup failed";
/// The static detail for a canonical stream the encoder rejected.
const COMPRESSION_FAILED_DETAIL: &str = "zstd compression of the canonical stream failed";
/// The static detail for a stored frame the decoder rejected, including a
/// failed embedded checksum.
const DECOMPRESSION_FAILED_DETAIL: &str = "zstd decompression of the stored frame failed";
/// The static detail for stored bytes that continue past the end of the
/// first frame — a stored form is exactly one frame.
const TRAILING_BYTES_DETAIL: &str = "stored form carries bytes beyond the first zstd frame";
/// The static detail for a stored form that ends inside an incomplete
/// frame.
const TRUNCATED_FRAME_DETAIL: &str = "stored form ends inside an incomplete zstd frame";
/// The static detail for a stream that made no progress while input
/// remained and output room existed — a compressor or decompressor
/// contract violation, failed loudly rather than spun on.
const STALLED_STREAM_DETAIL: &str = "zstd stream stalled with input and output room remaining";

/// The pinned `zstd-v1` encoder: level 3, single-threaded, no dictionary,
/// pledged content size, embedded checksum (plan Section 7.6).
///
/// Constructed with the stream's declared uncompressed extent — the pledge
/// the frame header records — and driven through [`BlobEncoder`] one
/// canonical chunk at a time. The pledge is enforced, not decorative: a
/// canonical stream longer than the pledged size fails the encode, so a
/// wrong declaration can never quietly produce a frame whose header
/// promises bytes the content does not have.
pub struct ZstdV1Encoder {
    cctx: CCtx<'static>,
}

impl ZstdV1Encoder {
    /// Build the encoder for one canonical stream of `pledged_bytes`
    /// uncompressed extent.
    ///
    /// # Errors
    /// [`StorageErrorKind::MalformedInput`] when the profile's parameters
    /// are rejected by the linked libzstd — with the pinned dependency this
    /// cannot happen, and the failure names a build or version drift.
    pub fn new(pledged_bytes: u64) -> Result<Self, StorageError> {
        let mut cctx = CCtx::create();
        for parameter in [
            CParameter::CompressionLevel(COMPRESSION_LEVEL),
            CParameter::ContentSizeFlag(true),
            CParameter::ChecksumFlag(true),
        ] {
            cctx.set_parameter(parameter).map_err(|_| {
                StorageError::new(StorageErrorKind::MalformedInput, CODEC_SETUP_DETAIL)
            })?;
        }
        cctx.set_pledged_src_size(Some(pledged_bytes))
            .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, CODEC_SETUP_DETAIL))?;
        Ok(Self { cctx })
    }

    /// Drive the compressor over `canonical` with `end_op`, appending
    /// stored output to `out`.
    ///
    /// The loop keeps one invariant above all: `Ok` is returned only when
    /// every input byte is consumed (and, for `ZSTD_e_end`, the frame
    /// epilogue is fully emitted). A call that neither consumes input nor
    /// writes output is a stall the C library cannot legitimately produce,
    /// and is reported rather than spun on.
    fn drive(
        &mut self,
        canonical: &[u8],
        out: &mut Vec<u8>,
        end_op: ZSTD_EndDirective,
    ) -> Result<(), StorageError> {
        let mut input = InBuffer::around(canonical);
        loop {
            let had_room = out.len() < out.capacity();
            let input_before = input.pos();
            let output_before = out.len();
            let hint = {
                let mut output = OutBuffer::around_pos(out, out.len());
                self.cctx
                    .compress_stream2(&mut output, &mut input, end_op)
                    .map_err(|_| {
                        StorageError::new(
                            StorageErrorKind::MalformedInput,
                            COMPRESSION_FAILED_DETAIL,
                        )
                    })?
            };
            let consumed_all = input.pos() >= canonical.len();
            if hint == 0 && consumed_all {
                return Ok(());
            }
            if input.pos() > input_before || out.len() > output_before {
                if hint > 0 {
                    out.reserve(hint);
                }
                continue;
            }
            if consumed_all && end_op == ZSTD_EndDirective::ZSTD_e_continue {
                // Nothing pending to flush and nothing more to feed it: the
                // stream simply waits for the next chunk. (`ZSTD_e_end` is
                // deliberately excluded — there the call only reports done
                // through `hint == 0`, and the frame epilogue is drained
                // across repeated calls, so falling through to the
                // reserve-and-retry below is what emits it.)
                return Ok(());
            }
            if had_room {
                return Err(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    STALLED_STREAM_DETAIL,
                ));
            }
            out.reserve(hint.max(1));
        }
    }
}

impl BlobEncoder for ZstdV1Encoder {
    fn update(&mut self, canonical: &[u8], out: &mut Vec<u8>) -> Result<(), StorageError> {
        self.drive(canonical, out, ZSTD_EndDirective::ZSTD_e_continue)
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), StorageError> {
        self.drive(&[], out, ZSTD_EndDirective::ZSTD_e_end)
    }
}

/// The matching `zstd-v1` decoder: incremental read-back under the pinned
/// decoder window cap.
///
/// One decoder consumes exactly one frame — the whole of a stored form.
/// Input arrives chunk by chunk through [`ZstdV1Decoder::update`]; decoded
/// canonical bytes are appended to the caller's buffer as they are
/// recovered, so nothing at payload scale is ever held by the decoder
/// itself. [`ZstdV1Decoder::finish`] drains any buffered output and fails
/// when the frame is incomplete. The embedded content checksum and the
/// pledged content size are verified by the codec during read-back; the
/// window cap rejects any frame whose declared window exceeds
/// [`DECODER_WINDOW_LOG_MAX`] before it can force the allocation.
pub struct ZstdV1Decoder {
    dctx: DCtx<'static>,
    frame_complete: bool,
}

impl ZstdV1Decoder {
    /// Build a decoder capped at [`DECODER_WINDOW_LOG_MAX`].
    ///
    /// # Errors
    /// [`StorageErrorKind::MalformedInput`] when the cap parameter is
    /// rejected by the linked libzstd — with the pinned dependency this
    /// cannot happen, and the failure names a build or version drift.
    pub fn new() -> Result<Self, StorageError> {
        let mut dctx = DCtx::create();
        dctx.set_parameter(DParameter::WindowLogMax(DECODER_WINDOW_LOG_MAX))
            .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, CODEC_SETUP_DETAIL))?;
        Ok(Self {
            dctx,
            frame_complete: false,
        })
    }

    /// Decode one chunk of stored bytes, appending canonical output.
    ///
    /// Once the frame is complete, a further non-empty chunk is rejected:
    /// the stored form is exactly one frame, and bytes after it are a
    /// corrupted or hostile stored form, not more content.
    ///
    /// # Errors
    /// [`StorageErrorKind::MalformedInput`] when the frame is malformed,
    /// fails its embedded checksum, declares a window above the decoder
    /// cap, ends before the input does, or carries trailing bytes.
    pub fn update(&mut self, stored: &[u8], out: &mut Vec<u8>) -> Result<(), StorageError> {
        if self.frame_complete {
            return Self::reject_trailing(stored);
        }
        let mut input = InBuffer::around(stored);
        while input.pos() < stored.len() {
            let had_room = out.len() < out.capacity();
            let input_before = input.pos();
            let output_before = out.len();
            let hint = {
                let mut output = OutBuffer::around_pos(out, out.len());
                self.dctx
                    .decompress_stream(&mut output, &mut input)
                    .map_err(|_| {
                        StorageError::new(
                            StorageErrorKind::MalformedInput,
                            DECOMPRESSION_FAILED_DETAIL,
                        )
                    })?
            };
            if hint == 0 {
                self.frame_complete = true;
                return Self::reject_trailing(&stored[input.pos()..]);
            }
            if input.pos() > input_before || out.len() > output_before {
                continue;
            }
            if had_room {
                return Err(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    STALLED_STREAM_DETAIL,
                ));
            }
            out.reserve(hint.max(1));
        }
        Ok(())
    }

    /// End the stored stream: drain any buffered output and require that
    /// the frame arrived complete.
    ///
    /// # Errors
    /// [`StorageErrorKind::MalformedInput`] when the input ended inside an
    /// incomplete frame.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), StorageError> {
        if self.frame_complete {
            return Ok(());
        }
        let mut input = InBuffer::around(&[]);
        loop {
            let had_room = out.len() < out.capacity();
            let output_before = out.len();
            let hint = {
                let mut output = OutBuffer::around_pos(out, out.len());
                self.dctx
                    .decompress_stream(&mut output, &mut input)
                    .map_err(|_| {
                        StorageError::new(
                            StorageErrorKind::MalformedInput,
                            DECOMPRESSION_FAILED_DETAIL,
                        )
                    })?
            };
            if hint == 0 {
                self.frame_complete = true;
                return Ok(());
            }
            if out.len() > output_before {
                continue;
            }
            if had_room {
                return Err(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    TRUNCATED_FRAME_DETAIL,
                ));
            }
            out.reserve(hint.max(1));
        }
    }

    /// `Ok` for nothing left over, [`TRAILING_BYTES_DETAIL`] for bytes
    /// beyond the one frame a stored form may carry.
    fn reject_trailing(stored: &[u8]) -> Result<(), StorageError> {
        if stored.is_empty() {
            Ok(())
        } else {
            Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                TRAILING_BYTES_DETAIL,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use archivist_protocol::sha256;
    use archivist_protocol::vocabulary::SafeMessage;

    use super::{COMPRESSION_LEVEL, DECODER_WINDOW_LOG_MAX};
    use super::{ZstdV1Decoder, ZstdV1Encoder};
    use crate::blob::BlobEncoder;
    use crate::error::StorageError;

    /// The linked libzstd version the `zstd-v1` profile is pinned against.
    /// The golden vector test asserts it at run time: the stored bytes are a
    /// function of the encoder version as much as of the parameters.
    const PINNED_LIBZSTD_VERSION: &str = "1.5.7";

    /// The static detail literals this module ships, for the safe-message
    /// grammar pin.
    const DETAILS: &[&str] = &[
        super::CODEC_SETUP_DETAIL,
        super::COMPRESSION_FAILED_DETAIL,
        super::DECOMPRESSION_FAILED_DETAIL,
        super::TRAILING_BYTES_DETAIL,
        super::TRUNCATED_FRAME_DETAIL,
        super::STALLED_STREAM_DETAIL,
    ];

    /// The committed golden vector's canonical input: 768 numbered
    /// occurrence lines (~66 KiB of mixed repetition and variation —
    /// enough for the level-3 compressor to do real work). The generator
    /// is deterministic, and the golden test pins its digest so the
    /// pattern cannot drift silently.
    fn canonical_pattern() -> Vec<u8> {
        let mut pattern = Vec::new();
        for line in 0..768u32 {
            let _ = writeln!(
                pattern,
                "archivist occurrence {line:04} of tenant 0f1e2d3c session zstd-v1 golden vector"
            );
        }
        pattern
    }

    /// The committed golden vector: the stored form the pinned profile
    /// produces for `canonical_pattern()` (libzstd 1.5.7, level 3,
    /// pledged content size, embedded checksum, single-threaded), plus
    /// the SHA-256 of both sides. Generated once and committed: a change
    /// here is a change of stored bytes, and therefore a new profile.
    const GOLDEN_CANONICAL_SHA256_HEX: &str =
        "dc947c3d6137b78ae12ae05549674af468cc5a47999942413f94227dae08f7ae";
    const GOLDEN_STORED_SHA256_HEX: &str =
        "b5efc0dea4db5322d0bed98a576153446fa50f48c99f5bc35e01247f464c3c16";
    const GOLDEN_STORED_HEX: &str = "28b52ffd6400e02d1a0036356516902b6b185af243ef2f0133233a6d4a4aca17b3bf1f4f8700500050004992244992244992244992288ebb9c622814c75d4e310ec57197538c2b8ebb9c625871dce514a38ae32ea718541c7739c598e2b8cb298614c75d4e31a238ee720a00c382c3c00222a1b02048583048042280c0a12122a1b080d0d0b068480c8c408b141809070501858543a2602161188691580c282c18181e060616120e0d08100807030c0201dbb66ddbb66ddbb66ddbb66ddbb66ddb244992244992244992244992244992244992244992244992244992244992244992244992242949922449922449922449922449922449922449922449922449926ddbb66ddbb66ddbb66ddbb66ddbb66ddbb66ddbb624499224499224499224499224499224499224499224499224499224499224499224499224b96ddbb66ddbb66ddbb66ddbb66ddbb66ddbb66ddbb6ffffffffffffffffffffffffffffffffffffffffffffffffff6fdbb66ddbb66ddbb66ddbb66ddbb66ddbb66ddbb66ddbb66ddbb66ddbb66ddbb66ddbb66ddb6ddbb66ddbb66ddbb66ddbb66ddbb66d1b8300a812c06ffdff0cf2d7d90d12f87f0581ff1104f803b9bbbbbbbbbb77777777777777f7eeeeeeeeeeeeeeeeeeeeddb9bb7b77777777777777777777777777efeeeeeedcddddbbbbbbbbbbbbbb777777777777777777e7eeeeeeeeddddddbbbbbbbbbbbbbbbbbbbb7b77e7eeeeeeeeeeeeeeeeeeeeeebdbbbbbbbbbbbb3b777777777777efeeeeeeeeeeeeeeeeeedddddd9d77777777777777777777777777f7eeeeeeeeeedcbbbbbbbbbbbbbb7b7777777777777777777777eeeededdddbbbbbbbbbbbbbbbbbbbbbb777777e7eeeeeeeeeeeeeeeeeeddbbbbbbbbbbbbbbbbbb73777777f7eeeeeeeeeeeeeeeeeeddddddddbd3b777777777777777777777777efeeeeeeeeeedd9dbbbbbbbbbbbb77777777777777777777777777eeddddbbbbbbbbbbbbbbbbbbbbbb7b7777777777eeeeeeeeeeeeeeddbdbbbbbbbbbbbbbbbbbbbb737777efeeeeeeeeeeeeeeeeddddddddddbbbbbb73777777777777777777f7eeeeeeeeeedddddd9d83dc53d7ddddddbbe1eceeeeee6e3dbbbb7777b79eddddddb95bcfeeeeeeeed6b3bbbbbbbbf5eceeeeee6e3d7677e7ee6e3dbbbbbbbb5bcfeeeeeeee7cc6d5e200b4ad17208b92";

    fn sha256_hex(bytes: &[u8]) -> String {
        sha256::encode_hex(&sha256::digest(bytes))
    }

    fn unhex(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii hex"), 16)
                    .expect("hex digit pair")
            })
            .collect()
    }

    /// Encode `canonical` in the given chunk sizes through the profile
    /// encoder, returning the stored form.
    fn encode_chunked(canonical: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut encoder = ZstdV1Encoder::new(canonical.len() as u64).expect("profile encoder");
        let mut stored = Vec::new();
        for chunk in canonical.chunks(chunk_size) {
            encoder.update(chunk, &mut stored).expect("chunk encodes");
        }
        encoder.finish(&mut stored).expect("frame finishes");
        stored
    }

    /// Decode `stored` in the given chunk sizes through the profile
    /// decoder, returning the canonical form.
    fn decode_chunked(stored: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut decoder = ZstdV1Decoder::new().expect("profile decoder");
        let mut canonical = Vec::new();
        for chunk in stored.chunks(chunk_size) {
            decoder
                .update(chunk, &mut canonical)
                .expect("chunk decodes");
        }
        decoder.finish(&mut canonical).expect("frame completes");
        canonical
    }

    #[test]
    fn golden_vector_round_trips_and_pins_determinism() {
        assert_eq!(
            zstd_safe::version_string(),
            PINNED_LIBZSTD_VERSION,
            "the golden vector is only valid for the pinned libzstd"
        );
        let canonical = canonical_pattern();
        assert_eq!(
            sha256_hex(&canonical),
            GOLDEN_CANONICAL_SHA256_HEX,
            "the golden pattern generator must not drift"
        );

        let whole = encode_chunked(&canonical, canonical.len());
        let odd = encode_chunked(&canonical, 997);
        let tiny = encode_chunked(&canonical, 1);
        assert_eq!(
            sha256_hex(&whole),
            GOLDEN_STORED_SHA256_HEX,
            "the stored form matches the committed golden vector"
        );
        assert_eq!(whole, unhex(GOLDEN_STORED_HEX));
        assert_eq!(whole, odd, "chunking does not change the stored bytes");
        assert_eq!(whole, tiny, "byte-at-a-time feeding changes nothing");
        assert_eq!(
            decode_chunked(&whole, canonical.len()),
            canonical,
            "the golden stored form decodes back to the canonical bytes"
        );
        assert_eq!(
            decode_chunked(&whole, 13),
            canonical,
            "decode chunking does not change the read-back"
        );
    }

    #[test]
    fn round_trips_over_varied_chunkings_and_shapes() {
        // Empty content, one byte, no redundancy, heavy redundancy, and a
        // body spanning several compressor blocks — each through whole,
        // odd-sized, and byte-at-a-time chunkings on both sides.
        let empty: Vec<u8> = Vec::new();
        let one = b"x".to_vec();
        // A xorshift64 stream: no short-range repetition for the compressor
        // to exploit, and no truncating cast to build the bytes.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let incompressible: Vec<u8> = (0..70_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect();
        let redundant = vec![7u8; 70_000];
        let mut mixed = Vec::new();
        for block in 0..40 {
            let _ = writeln!(mixed, "record-{block:03}-{}", "payload ".repeat(block + 1));
        }
        let bodies: Vec<Vec<u8>> = vec![empty, one, incompressible, redundant, mixed];
        for body in &bodies {
            for chunk_size in [body.len().max(1), 64 * 1024, 997, 1] {
                let stored = encode_chunked(body, chunk_size);
                assert_eq!(
                    decode_chunked(&stored, chunk_size),
                    *body,
                    "round trip over {chunk_size}-byte chunks"
                );
            }
        }
    }

    #[test]
    fn frame_parameters_match_the_profile() {
        let canonical = canonical_pattern();
        let stored = encode_chunked(&canonical, 4096);

        assert_eq!(&stored[..4], &[0x28, 0xB5, 0x2F, 0xFD], "zstd magic");
        let descriptor = stored[4];
        assert_eq!(descriptor & 0x08, 0, "the reserved bit stays zero");
        assert_ne!(
            descriptor & 0x04,
            0,
            "the frame embeds the content checksum"
        );
        assert_eq!(descriptor & 0x03, 0, "the frame names no dictionary");
        assert_eq!(
            zstd_safe::get_frame_content_size(&stored).ok().flatten(),
            Some(canonical.len() as u64),
            "the pledged content size is written into the frame header"
        );
        assert_eq!(
            zstd_safe::get_dict_id_from_frame(&stored),
            None,
            "the profile is dictionary-free"
        );
    }

    #[test]
    fn single_threaded_emission_is_enforced_by_the_build() {
        // `zstdmt` stays off, so the linked C library has no multithreaded
        // support and rejects a nonzero worker count out of hand. This
        // asserts the property at run time instead of trusting the feature
        // declaration — multithreaded emission is one half of stored-byte
        // determinism (VAL-006).
        let mut cctx = zstd_safe::CCtx::create();
        assert!(
            cctx.set_parameter(zstd_safe::CParameter::NbWorkers(1))
                .is_err(),
            "the C library must be built without multithreading"
        );
        let _ = COMPRESSION_LEVEL;
        let _ = DECODER_WINDOW_LOG_MAX;
    }

    #[test]
    fn encoder_rejects_a_stream_longer_than_the_pledge() {
        let canonical = canonical_pattern();
        let mut encoder =
            ZstdV1Encoder::new((canonical.len() - 1) as u64).expect("pledge is grammatical");
        let mut stored = Vec::new();
        for chunk in canonical.chunks(4096) {
            // The overrun may surface at any call after the pledge is
            // exceeded; the encoder must simply fail somewhere before the
            // frame is complete.
            if let Err(error) = encoder.update(chunk, &mut stored) {
                assert_eq!(error.kind(), crate::error::StorageErrorKind::MalformedInput);
                return;
            }
        }
        assert!(
            encoder.finish(&mut stored).is_err(),
            "a stream longer than the pledge never completes a frame"
        );
    }

    #[test]
    fn decoder_rejects_oversized_windows() {
        // A frame whose declared window exceeds the decoder cap is
        // rejected before it can force the allocation — the cap is what
        // bounds decompressor memory. The profile compressor cannot be
        // coaxed into emitting this shape (it right-sizes its window to
        // the source), so the frame is written by hand per the Zstandard
        // format (RFC 8878): the magic, a header descriptor with a window
        // descriptor and no checksum, content size, or dictionary, the
        // window descriptor declaring a 2^27 (128 MiB) window — exponent
        // 17, mantissa 0 — and a final empty raw block closing a
        // well-formed frame. This is exactly what a hostile or foreign
        // stored form looks like before the decoder allocates for it.
        let stored: &[u8] = &[0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88, 0x01, 0x00, 0x00];

        let mut decoder = ZstdV1Decoder::new().expect("profile decoder");
        let mut canonical = Vec::new();
        let error = decoder
            .update(stored, &mut canonical)
            .expect_err("a frame above the window cap is rejected");
        assert_eq!(error.kind(), crate::error::StorageErrorKind::MalformedInput);
    }

    #[test]
    fn decoder_rejects_trailing_bytes_after_the_frame() {
        let canonical = b"archivist stored form discipline";
        let mut stored = encode_chunked(canonical, canonical.len());
        stored.extend_from_slice(b"trailer");

        let mut decoder = ZstdV1Decoder::new().expect("profile decoder");
        let mut recovered = Vec::new();
        let error = decoder
            .update(&stored, &mut recovered)
            .expect_err("bytes past the frame are rejected");
        assert_eq!(error.kind(), crate::error::StorageErrorKind::MalformedInput);

        // A no-op chunk after a complete frame stays a no-op.
        let mut decoder = ZstdV1Decoder::new().expect("profile decoder");
        let mut recovered = Vec::new();
        let whole = encode_chunked(canonical, canonical.len());
        decoder
            .update(&whole, &mut recovered)
            .expect("frame decodes");
        decoder
            .update(b"", &mut recovered)
            .expect("empty is a no-op");
        assert_eq!(recovered, canonical);
    }

    #[test]
    fn decoder_rejects_truncated_frames() {
        let canonical = canonical_pattern();
        let stored = encode_chunked(&canonical, 4096);
        let cut = &stored[..stored.len() - 3];

        let mut decoder = ZstdV1Decoder::new().expect("profile decoder");
        let mut recovered = Vec::new();
        decoder.update(cut, &mut recovered).expect("prefix decodes");
        let error = decoder
            .finish(&mut recovered)
            .expect_err("a frame cut short never completes");
        assert_eq!(error.kind(), crate::error::StorageErrorKind::MalformedInput);
    }

    #[test]
    fn decoder_rejects_a_corrupted_payload() {
        let canonical = canonical_pattern();
        let mut stored = encode_chunked(&canonical, 4096);
        let middle = stored.len() / 2;
        stored[middle] ^= 0xff;

        let mut decoder = ZstdV1Decoder::new().expect("profile decoder");
        let mut recovered = Vec::new();
        let outcome = (|| -> Result<(), StorageError> {
            for chunk in stored.chunks(4096) {
                decoder.update(chunk, &mut recovered)?;
            }
            decoder.finish(&mut recovered)
        })();
        assert!(
            outcome.is_err(),
            "a corrupted stored form never reads back cleanly"
        );
        assert_ne!(recovered, canonical, "corruption is not silently tolerated");
    }

    #[test]
    fn encoder_and_decoder_are_send() {
        // One commit future may run on any worker thread, and the decoder
        // is consumed by the streaming pipeline's tasks: both primitives
        // must be movable across threads.
        fn assert_send<T: Send>() {}
        assert_send::<ZstdV1Encoder>();
        assert_send::<ZstdV1Decoder>();
    }

    #[test]
    fn details_stay_inside_the_safe_message_grammar() {
        for &detail in DETAILS {
            assert_eq!(
                SafeMessage::parse(detail)
                    .unwrap_or_else(|_| panic!("detail is not safe: {detail}"))
                    .as_str(),
                detail
            );
        }
    }
}
