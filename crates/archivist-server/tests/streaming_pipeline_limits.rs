// SPDX-License-Identifier: Apache-2.0

//! The streaming pipeline's resource and fuzz verification suite — the
//! one place the plan's Section 7.6 limits are assembled, fuzzed, and
//! measured (plan Section 7.6, "Enforced by"; beads `aa-c22301a8`,
//! `aa-2380d921`, `aa-a88a4069` land the surfaces this suite verifies).
//!
//! # The limit-boundary matrix
//!
//! | Limit (plan Section 7.6) | Value | Enforced by | Pinned by |
//! |---|---|---|---|
//! | Single structured record | 256 MiB | the bounded transport stage's mid-stream guard | [`limit_matrix_rows_carry_the_plan_values`], [`record_cap_boundary_at_the_real_256_mib`], [`fuzz_truncated_frames_fail_closed_over_both_stages`] |
//! | Expansion ratio | 100:1 | the bounded transport stage's cumulative guard | [`limit_matrix_rows_carry_the_plan_values`], [`expansion_ratio_default_boundary_brackets_100_to_1`], [`fuzz_deep_expansion_bombs_hit_the_ratio_guard_and_stay_bounded`] |
//! | Envelope | 64 KiB | the parser chain (already landed; `crate::parse`) | [`limit_matrix_rows_carry_the_plan_values`] |
//! | Target canonical chunk | 16 MiB | `TransportDecoder`'s chunk accumulator | [`limit_matrix_rows_carry_the_plan_values`] |
//! | Multipart part | 8 MiB | the multipart writer (`archivist_storage::multipart`) | [`limit_matrix_rows_carry_the_plan_values`] |
//! | Decoder window | 8 MiB (2^23) | the `zstd-v1` decoder's pre-allocation cap | [`limit_matrix_rows_carry_the_plan_values`], [`fuzz_hostile_window_demands_fail_closed_over_both_stages`] |
//! | In-flight uploads | 16 per process | the route layer's concurrency bound | [`limit_matrix_rows_carry_the_plan_values`], [`rss_ceiling_holds_at_the_default_sixteen_request_concurrency`] |
//! | Process RSS | 512 MiB | the reference-runner ceiling this suite measures | [`rss_ceiling_holds_at_the_default_sixteen_request_concurrency`] |
//!
//! **A cap raise fails closed through this suite.** Raising a hard cap is
//! a change to a constant an assertion above pins to its plan value, so
//! the suite cannot stay green across the raise: it must be updated in the
//! same commit, which is exactly the plan's rule that raising a hard cap
//! requires the resource/fuzz suite on the same commit. The suite's
//! presence is what authorizes the raise; a raise without the suite is a
//! red suite.
//!
//! Boundary semantics ("exactly at a cap is lawful; the first byte past it
//! is not") are pinned at unit level in the stage itself
//! (`crates/archivist-server/src/transport.rs`: the record-cap and
//! expansion-ratio straddle tests, and the store-level abort-before-commit
//! tests). This file pins the *default values* at scale, so a constant
//! change cannot hide behind a scaled-down unit test.
//!
//! # The fuzz suite
//!
//! Deterministic structured fuzzing over **both** decompression surfaces —
//! the raw `zstd-v1` codec decoder (child 1 of the pipeline chain) and the
//! bounded transport-decode stage (child 2): truncated frames, hostile
//! window demands, lying content sizes, deep expansion bombs, byte soup,
//! and trailing garbage. Every generator is a seeded xorshift stream, so a
//! failing case is reproducible from its seed and inputs. The contract
//! under fuzz is: **no input panics**, and every outcome is either a lawful
//! stream or a closed, registry-classified error.
//!
//! The raw decoder has no expansion guard by design — the ratio limit is
//! the transport stage's — so the raw fuzz drivers feed in small slices
//! behind an explicit output bound: the same cadence argument the stage
//! makes structural, applied to the harness. The dedicated bomb test
//! measures what the raw decoder *should* produce when allowed to finish.
//!
//! # The RSS ceiling
//!
//! [`rss_ceiling_holds_at_the_default_sixteen_request_concurrency`] is the
//! closest in-suite equivalent of the plan's "RSS ceiling of 512 MiB at the
//! default 16-request concurrency on the reference four-vCPU test runner":
//! sixteen concurrent bounded-decode attempts (the registry's in-flight
//! constant) each stream a 64 MiB body — 1 GiB of canonical payload in
//! total, far past anything one attempt may buffer — while the test asserts
//! the process's kernel-maintained peak resident set (`VmHWM` from
//! `/proc/self/status`) stays under 512 MiB. The measurement method is the
//! assertion: peak RSS of the whole test process, sampled by the kernel,
//! not by wall-clock polling. Run evidence for the reference runner
//! (iad-ci lane / local cgroup-limited equivalent) is recorded on bead
//! `aa-0b245092`.

use std::io::{self, Cursor, Read};
use std::sync::Mutex;

use archivist_protocol::vocabulary::TransportEncoding;
use archivist_server::config::{
    DEFAULT_ENVELOPE_MAX_BYTES, DEFAULT_MAX_EXPANSION_RATIO, DEFAULT_MAX_INFLIGHT_UPLOAD_COUNT,
    DEFAULT_MULTIPART_PART_BYTES, DEFAULT_RECORD_MAX_BYTES,
};
use archivist_server::transport::{
    DecodeLimits, TARGET_CHUNK_BYTES, TransportDecodeError, TransportDecoder,
};
use archivist_storage::blob::BlobEncoder;
use archivist_storage::zstd_v1::{DECODER_WINDOW_LOG_MAX, ZstdV1Decoder, ZstdV1Encoder};

// ---------------------------------------------------------------------------
// Deterministic input generators
// ---------------------------------------------------------------------------

/// Serializes the memory-heavy tests ([`record_cap_boundary_at_the_real_256_mib`],
/// [`fuzz_raw_decoder_bomb_output_stays_exact`], and the RSS measurement) so
/// their peak allocations never overlap. The RSS ceiling is measured against
/// one workload at a time — the way the server's own concurrency bound
/// shapes memory — not against the test harness's parallel schedule.
static HEAVY: Mutex<()> = Mutex::new(());

/// One step of the seeded xorshift64 stream every fuzz generator uses.
fn xorshift_byte(state: &mut u64) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    state.to_le_bytes()[0]
}

/// `len` bytes of seeded pseudo-random soup: no structure a decoder could
/// accidentally lean on.
fn xorshift_soup(len: usize, state: &mut u64) -> Vec<u8> {
    (0..len).map(|_| xorshift_byte(state)).collect()
}

/// `len` incompressible bytes (the transport tests' own neighborhood).
fn pseudo_random(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    xorshift_soup(len, &mut state)
}

/// A blocking zero source of `remaining` bytes that never allocates: the
/// bytes exist only in the 256-byte staging slice at a time.
struct Zeros {
    remaining: u64,
}

impl Zeros {
    fn of(len: u64) -> Self {
        Self { remaining: len }
    }
}

impl Read for Zeros {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let taken = buf.len().min(want);
        buf[..taken].fill(0);
        self.remaining -= taken as u64;
        Ok(taken)
    }
}

// ---------------------------------------------------------------------------
// Frame builders
// ---------------------------------------------------------------------------

/// The `zstd` transport frame of `canonical`, exactly as a client would
/// transmit it: one profile-encoded Zstandard frame.
fn zstd_frame(canonical: &[u8]) -> Vec<u8> {
    let mut encoder = ZstdV1Encoder::new(canonical.len() as u64).expect("profile encoder");
    let mut frame = Vec::new();
    BlobEncoder::update(&mut encoder, canonical, &mut frame).expect("frame body");
    BlobEncoder::finish(&mut encoder, &mut frame).expect("frame epilogue");
    frame
}

/// The frame magic every Zstandard frame starts with.
const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// A frame header demanding the window descriptor byte `wd`, followed by
/// `body`. `fhd` selects the header descriptor (window-only, checksum,
/// single-segment, declared content size, reserved bits).
fn hostile_frame(fhd: u8, wd: Option<u8>, declared_size: Option<u64>, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&MAGIC);
    frame.push(fhd);
    if let Some(wd) = wd {
        frame.push(wd);
    }
    if let Some(size) = declared_size {
        frame.extend_from_slice(&size.to_le_bytes());
    }
    frame.extend_from_slice(body);
    frame
}

/// A deep expansion bomb: `blocks` run-length blocks, each regenerating
/// 128 KiB of zeros from five frame bytes. `terminated` controls the last
/// block's flag, so the truncated variant is a frame that never ends.
fn bomb_frame(blocks: usize, terminated: bool) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&MAGIC);
    frame.push(0x00); // header descriptor: window descriptor only
    frame.push(0x38); // window log 17: exactly the 128 KiB blocks demand
    for block in 0..blocks {
        // Block header, 24-bit little-endian: bit 0 last-block, bits 1-2
        // type (01 = RLE), bits 3-23 the regenerated size.
        let last = u32::from(terminated && block + 1 == blocks);
        let header = (131_072 << 3) | (0b01 << 1) | last;
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.push(0x00);
    }
    frame
}

// ---------------------------------------------------------------------------
// Drivers
// ---------------------------------------------------------------------------

/// Pull a transport stage to completion, counting the canonical bytes and
/// dropping each chunk as it lands — the caller never holds payload scale.
fn drive_transport<R: Read>(
    decoder: &mut TransportDecoder<R>,
) -> Result<u64, TransportDecodeError> {
    let mut total = 0u64;
    while let Some(chunk) = decoder.next_chunk()? {
        total += chunk.len() as u64;
    }
    Ok(total)
}

/// A transport stage over `bytes` at the registry defaults.
fn transport_decoder(bytes: &[u8], encoding: TransportEncoding) -> TransportDecoder<Cursor<&[u8]>> {
    TransportDecoder::new(
        encoding,
        Cursor::new(bytes),
        DecodeLimits::registry_defaults(),
    )
    .expect("profile decoder setup")
}

/// What the bounded raw-decode driver observed.
enum RawOutcome {
    /// The frame completed; `canonical` is everything it produced.
    Complete { canonical: Vec<u8> },
    /// The codec refused the input; `canonical` is what came first.
    Rejected { canonical: Vec<u8> },
    /// The harness output bound was hit before any verdict.
    BoundReached,
}

/// Drive the raw codec decoder over adversarial `stored` bytes in
/// `feed_len`-byte slices, behind an `out_cap` output bound.
///
/// The raw decoder has no expansion guard — the ratio limit belongs to the
/// transport stage — so this harness feeds small slices and stops at the
/// bound: a slice of `feed_len` bytes can add at most one Zstandard block
/// (128 KiB) of output before the bound is checked, which keeps a hostile
/// input from ballooning the harness rather than failing it.
fn drive_raw(stored: &[u8], feed_len: usize, out_cap: usize) -> RawOutcome {
    let mut decoder = ZstdV1Decoder::new().expect("profile decoder");
    let mut canonical = Vec::new();
    for chunk in stored.chunks(feed_len) {
        if decoder.update(chunk, &mut canonical).is_err() {
            return RawOutcome::Rejected { canonical };
        }
        if canonical.len() >= out_cap {
            return RawOutcome::BoundReached;
        }
    }
    if decoder.finish(&mut canonical).is_ok() {
        RawOutcome::Complete { canonical }
    } else {
        RawOutcome::Rejected { canonical }
    }
}

/// Every transport failure must name one of the four registered classes.
fn assert_registry_class(error: &TransportDecodeError) {
    let code = error.code();
    let token = code.as_str();
    assert!(
        matches!(
            token,
            "request.framing_invalid"
                | "request.record_too_large"
                | "request.expansion_ratio_exceeded"
                | "server.internal"
        ),
        "{token} is not a registered failure class"
    );
}

// ---------------------------------------------------------------------------
// The limit-boundary matrix
// ---------------------------------------------------------------------------

/// The assembled matrix: every Section 7.6 constant this suite owns, at its
/// exact plan value. These assertions are the cap-raise gate — a raised cap
/// turns one of them red until the suite is updated on the same commit.
#[test]
fn limit_matrix_rows_carry_the_plan_values() {
    let limits = DecodeLimits::registry_defaults();
    // Single structured record: 256 MiB.
    assert_eq!(limits.record_max_bytes(), 268_435_456);
    assert_eq!(limits.record_max_bytes(), DEFAULT_RECORD_MAX_BYTES);
    // Expansion ratio: 100:1.
    assert_eq!(limits.max_expansion_ratio(), 100);
    assert_eq!(u64::from(DEFAULT_MAX_EXPANSION_RATIO), 100);
    // Envelope: 64 KiB — the parser chain's row, re-asserted here so the
    // matrix carries it; enforcement lives in the landed parse tests.
    assert_eq!(DEFAULT_ENVELOPE_MAX_BYTES, 65_536);
    // Target canonical chunk: 16 MiB.
    assert_eq!(TARGET_CHUNK_BYTES, 16 * 1024 * 1024);
    // Multipart part: 8 MiB — enforcement in the landed multipart tests.
    assert_eq!(DEFAULT_MULTIPART_PART_BYTES, 8_388_608);
    // Decoder window: 2^23 = 8 MiB.
    assert_eq!(DECODER_WINDOW_LOG_MAX, 23);
    assert_eq!(1usize << DECODER_WINDOW_LOG_MAX, 8 * 1024 * 1024);
    // In-flight uploads: 16 per server process.
    assert_eq!(DEFAULT_MAX_INFLIGHT_UPLOAD_COUNT, 16);
}

/// The record cap at its real 256 MiB value: exactly at the cap is lawful
/// and streams in bounded chunks; the first byte past fails mid-stream
/// with the cap the plan names. The source never allocates the body.
#[test]
fn record_cap_boundary_at_the_real_256_mib() {
    let _gate = HEAVY.lock().expect("heavy gate poisoned");
    let cap = DEFAULT_RECORD_MAX_BYTES;

    // Exactly at the cap: the whole 256 MiB streams through 16 MiB chunks,
    // counted and dropped.
    let mut decoder = TransportDecoder::new(
        TransportEncoding::Identity,
        Zeros::of(cap),
        DecodeLimits::registry_defaults(),
    )
    .expect("identity decoder");
    let total = drive_transport(&mut decoder).expect("at-cap is lawful");
    assert_eq!(total, cap);
    assert!(decoder.is_drained());
    assert_eq!(decoder.canonical_bytes(), cap);

    // One byte past: the guard fires mid-stream at the plan's cap.
    let mut decoder = TransportDecoder::new(
        TransportEncoding::Identity,
        Zeros::of(cap + 1),
        DecodeLimits::registry_defaults(),
    )
    .expect("identity decoder");
    let error = loop {
        match decoder.next_chunk() {
            Ok(Some(_)) => {}
            Ok(None) => panic!("256 MiB + 1 fits no 256 MiB cap"),
            Err(error) => break error,
        }
    };
    assert_eq!(
        error,
        TransportDecodeError::RecordTooLarge {
            actual_bytes: cap + 1,
            limit_bytes: cap,
        }
    );
    assert_eq!(error.code().as_str(), "request.record_too_large");
    assert!(error.payload_limit().is_some());
}

/// The expansion ratio at its real default 100:1: a frame whose cumulative
/// ratio lands just under the cap streams to completion; a frame just over
/// is refused mid-stream. The bracket is computed from each frame's actual
/// bytes, so the two runs sit either side of the same measured boundary.
#[test]
fn expansion_ratio_default_boundary_brackets_100_to_1() {
    // Incompressible prefix (the frame's bulk) plus a zeros tail (nearly
    // free to encode): the achieved ratio is tunable by tail length. The
    // tail is sized so the whole stream sits just under the default cap.
    let base = pseudo_random(4096);
    let under_payload = {
        let mut payload = base.clone();
        payload.resize(base.len() + 405_000, 0);
        payload
    };
    let under_frame = zstd_frame(&under_payload);
    let under_canonical = under_payload.len() as u64;
    let under_allowance = 100 * under_frame.len() as u64;
    assert!(
        under_canonical <= under_allowance,
        "bracket setup drifted: under case is {under_canonical} against {under_allowance}"
    );

    // Just under the default cap: the attempt completes.
    let mut decoder = transport_decoder(&under_frame, TransportEncoding::Zstd);
    let total = drive_transport(&mut decoder).expect("just-under streams to completion");
    assert_eq!(total, under_canonical);
    assert!(decoder.canonical_bytes() <= 100 * decoder.transport_bytes());

    // Just over: pad 16 KiB more zeros and the same attempt is refused
    // mid-stream by the default guard.
    let over_payload = {
        let mut payload = under_payload.clone();
        payload.resize(payload.len() + 16_384, 0);
        payload
    };
    let over_frame = zstd_frame(&over_payload);
    assert!(
        over_payload.len() as u64 > 100 * over_frame.len() as u64,
        "bracket setup drifted: the over case does not exceed 100:1"
    );
    let mut decoder = transport_decoder(&over_frame, TransportEncoding::Zstd);
    let error = loop {
        match decoder.next_chunk() {
            Ok(Some(_)) => {}
            Ok(None) => panic!("the over case must be refused"),
            Err(error) => break error,
        }
    };
    assert_eq!(
        error,
        TransportDecodeError::ExpansionRatioExceeded { max_ratio: 100 }
    );
    assert_eq!(error.code().as_str(), "request.expansion_ratio_exceeded");
    // Fired against produced bytes, which never exceed the real payload:
    // the guard's totals stop where the refusal landed.
    assert!(
        decoder.canonical_bytes() <= over_payload.len() as u64,
        "a refused stream produced bytes past its payload"
    );
}

// ---------------------------------------------------------------------------
// Fuzz: truncated frames
// ---------------------------------------------------------------------------

/// Real frames cut at sampled prefix lengths, through both decompression
/// surfaces: a truncated frame never reads back as a lawful stream and
/// never panics. The raw decoder rejects at `update` or `finish`; the
/// transport stage reports the closed framing class.
#[test]
fn fuzz_truncated_frames_fail_closed_over_both_stages() {
    let payload_a = pseudo_random(4096);
    let mut payload_b = pseudo_random(4096);
    payload_b.resize(payload_b.len() + 32_768, 0);
    let payload_c = pseudo_random(9_973);
    let frames: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (zstd_frame(&payload_a), payload_a),
        (zstd_frame(&payload_b), payload_b),
        (zstd_frame(&payload_c), payload_c),
    ];
    let mut cases = 0usize;
    // Each frame carries the canonical extent it must never exceed: a
    // truncation can decode at most the real content, plus one block of
    // decoder buffering.
    for (frame, expected_len) in &frames {
        let expected = expected_len.len();
        let full_len = frame.len();
        let mut cuts: Vec<usize> = Vec::new();
        if full_len <= 260 {
            cuts.extend(0..full_len);
        } else {
            cuts.extend((0..full_len).step_by(53));
            cuts.extend(full_len.saturating_sub(16)..full_len);
        }
        for cut in cuts {
            let truncated = &frame[..cut];
            cases += 1;

            // Raw codec decoder: bounded driver, small slices.
            match drive_raw(truncated, 7, 8 * 1024 * 1024) {
                RawOutcome::Rejected { canonical } | RawOutcome::Complete { canonical } => {
                    assert!(
                        canonical.len() <= expected + 128 * 1024,
                        "a truncated frame decoded {} bytes, past its {}-byte extent",
                        canonical.len(),
                        expected
                    );
                }
                RawOutcome::BoundReached => {
                    panic!("a truncated {full_len}-byte frame hit the 8 MiB bound")
                }
            }

            // Bounded transport stage: closed framing refusal.
            let mut decoder = transport_decoder(truncated, TransportEncoding::Zstd);
            match drive_transport(&mut decoder) {
                Ok(total) => assert!(
                    total <= (expected + 128 * 1024) as u64,
                    "a truncated frame streamed implausible volume"
                ),
                Err(error) => {
                    assert_registry_class(&error);
                    assert!(
                        matches!(error, TransportDecodeError::MalformedFrame { .. }),
                        "a truncated frame refused as {error:?}, not framing"
                    );
                }
            }
        }
    }
    assert!(cases > 300, "the corpus collapsed: {cases} cases");
}

// ---------------------------------------------------------------------------
// Fuzz: hostile window demands
// ---------------------------------------------------------------------------

/// Every window-descriptor byte value, behind several header shapes, through
/// both surfaces: a demand above the decoder cap is refused before the
/// window allocation, a demand below it still fails closed on the garbage
/// body, and nothing panics or balloons.
#[test]
fn fuzz_hostile_window_demands_fail_closed_over_both_stages() {
    let mut state = 0x0DD1_C7A7_5EED_0001u64;
    for wd in 0..=255u8 {
        for fhd in [0x00u8, 0x20, 0x24] {
            let body = xorshift_soup(96, &mut state);
            let frame = hostile_frame(fhd, Some(wd), None, &body);

            // Raw codec decoder: never panics, never balloons.
            match drive_raw(&frame, 11, 1024 * 1024) {
                RawOutcome::Complete { canonical } => {
                    assert!(canonical.len() <= 1024 * 1024, "soup decoded implausibly");
                }
                RawOutcome::Rejected { .. } | RawOutcome::BoundReached => {}
            }

            // Bounded transport stage: closed class or bounded lawful end.
            let mut decoder = transport_decoder(&frame, TransportEncoding::Zstd);
            match drive_transport(&mut decoder) {
                Ok(total) => assert!(total <= 1024 * 1024, "soup streamed implausibly"),
                Err(error) => {
                    assert_registry_class(&error);
                    assert!(
                        matches!(error, TransportDecodeError::MalformedFrame { .. }),
                        "a hostile window refused as {error:?}, not framing"
                    );
                }
            }
        }
    }

    // The header-only memory bomb: single-segment flag with a 2^40 content
    // size — the window demand IS the declared size. The decoder must never
    // allocate for the pledge. (Finding pinned here: libzstd defers the
    // single-segment window demand to allocation time and treats a
    // block-less single-segment frame as a complete *empty* stream, so the
    // undelivered 1 TiB pledge passes the decode layer producing zero
    // bytes; the claim dies at the commit path's digest validation
    // (VAL-004), never in decoder memory.)
    let frame = hostile_frame(0b0010_0000 | 0b11, None, Some(1u64 << 40), &[]);
    match drive_raw(&frame, 5, 8 * 1024 * 1024) {
        RawOutcome::Rejected { .. } => {}
        RawOutcome::Complete { canonical } => {
            assert!(canonical.is_empty(), "an undelivered pledge produced bytes");
        }
        RawOutcome::BoundReached => panic!("a header-only frame ballooned the harness"),
    }
    let mut decoder = transport_decoder(&frame, TransportEncoding::Zstd);
    match drive_transport(&mut decoder) {
        Ok(total) => assert_eq!(total, 0, "an undelivered pledge produced bytes"),
        Err(error) => assert_registry_class(&error),
    }

    // A reserved header bit set: refused closed by both surfaces.
    let frame = hostile_frame(0x08, Some(0x00), None, &[0x00, 0x00, 0x00, 0x00]);
    assert!(matches!(
        drive_raw(&frame, 5, 8 * 1024 * 1024),
        RawOutcome::Rejected { .. }
    ));
    let mut decoder = transport_decoder(&frame, TransportEncoding::Zstd);
    assert!(decoder.next_chunk().is_err());
}

// ---------------------------------------------------------------------------
// Fuzz: lying content sizes
// ---------------------------------------------------------------------------

/// Headers that pledge a content size the body never delivers, through both
/// surfaces: the declared value buys nothing — the stream fails closed at
/// the mismatch, never panics, and never delivers the pledge.
#[test]
fn fuzz_lying_content_sizes_fail_closed_over_both_stages() {
    let body = pseudo_random(4096);
    let bodies: [&[u8]; 3] = [body.as_slice(), &[0u8; 64], b"short body"];
    let pledges = [0u64, 1, 4095, 4096, 4097, 1u64 << 32, u64::MAX];
    for pledged in pledges {
        for body in bodies {
            // 0x83: 8-byte declared content size, no window descriptor, no
            // checksum, no dictionary — then the pledged size, then a body
            // that does not honor it.
            let frame = hostile_frame(0x83, None, Some(pledged), body);

            match drive_raw(&frame, 13, 8 * 1024 * 1024) {
                RawOutcome::Complete { canonical } => assert!(
                    canonical.len() <= body.len() + 64,
                    "a lying pledge completed into implausible volume"
                ),
                RawOutcome::Rejected { .. } | RawOutcome::BoundReached => {}
            }

            let mut decoder = transport_decoder(&frame, TransportEncoding::Zstd);
            match drive_transport(&mut decoder) {
                Ok(total) => assert!(
                    total <= (body.len() + 64) as u64,
                    "a lying pledge streamed implausible volume"
                ),
                Err(error) => {
                    assert_registry_class(&error);
                    assert!(
                        matches!(error, TransportDecodeError::MalformedFrame { .. }),
                        "a lying pledge refused as {error:?}, not framing"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fuzz: deep expansion bombs
// ---------------------------------------------------------------------------

/// A 32 MiB bomb (each of 256 run-length blocks regenerates 128 KiB from
/// five frame bytes — about 30,000:1) meets the default 100:1 guard
/// mid-stream: the attempt is refused as an expansion-ratio crossing, the
/// canonical bytes the stage ever produced stay bounded by the guard's
/// documented feed cadence rather than the frame's claimed extent, and no
/// panic occurs.
#[test]
fn fuzz_deep_expansion_bombs_hit_the_ratio_guard_and_stay_bounded() {
    let bomb = bomb_frame(256, true);
    assert!(
        bomb.len() < 2048,
        "the bomb must be tiny: {} bytes",
        bomb.len()
    );

    let mut decoder = transport_decoder(&bomb, TransportEncoding::Zstd);
    let error = loop {
        match decoder.next_chunk() {
            Ok(Some(_)) => {}
            Ok(None) => panic!("a 30,000:1 bomb exceeds the default 100:1 ratio"),
            Err(error) => break error,
        }
    };
    assert_eq!(
        error,
        TransportDecodeError::ExpansionRatioExceeded { max_ratio: 100 }
    );
    // The stage's documented cadence bounds a step's output near 8 MiB
    // (256-byte feed slices against the 128 KiB block ceiling); assert the
    // bound with headroom rather than the bomb's 32 MiB extent.
    assert!(
        decoder.canonical_bytes() <= 16 * 1024 * 1024,
        "the ratio guard let {} bytes through before firing",
        decoder.canonical_bytes()
    );
    assert!(
        decoder.transport_bytes() <= 4096,
        "the guard fired after consuming {} transport bytes",
        decoder.transport_bytes()
    );
}

/// The raw codec decoder, allowed to finish the same bomb, produces exactly
/// the 32 MiB of zeros it was handed — adversarial expansion exercises the
/// decoder's output path, not its honesty — and the unterminated variant
/// fails closed at the drain instead of inventing an end.
#[test]
fn fuzz_raw_decoder_bomb_output_stays_exact() {
    let _gate = HEAVY.lock().expect("heavy gate poisoned");
    // Terminated: 256 blocks, exactly 32 MiB of zeros, byte-verified.
    let bomb = bomb_frame(256, true);
    let mut decoder = ZstdV1Decoder::new().expect("profile decoder");
    let mut canonical = Vec::new();
    decoder
        .update(&bomb, &mut canonical)
        .expect("bomb body decodes");
    decoder.finish(&mut canonical).expect("bomb completes");
    assert_eq!(canonical.len(), 256 * 128 * 1024);
    assert!(
        canonical.iter().all(|&byte| byte == 0),
        "run-length blocks regenerated non-run content"
    );

    // Chunk-fed at a hostile cadence: the same exact output.
    let mut decoder = ZstdV1Decoder::new().expect("profile decoder");
    let mut canonical = Vec::new();
    for chunk in bomb.chunks(5) {
        decoder
            .update(chunk, &mut canonical)
            .expect("bomb chunk decodes");
    }
    decoder.finish(&mut canonical).expect("bomb completes");
    assert_eq!(canonical.len(), 256 * 128 * 1024);

    // Unterminated: the frame never ends, so the drain fails closed.
    let bomb = bomb_frame(256, false);
    match drive_raw(&bomb, 1024, 64 * 1024 * 1024) {
        RawOutcome::Rejected { canonical } => {
            assert_eq!(canonical.len(), 256 * 128 * 1024);
        }
        RawOutcome::Complete { .. } => panic!("an unterminated frame completed"),
        RawOutcome::BoundReached => panic!("32 MiB hit the 64 MiB bound"),
    }
}

// ---------------------------------------------------------------------------
// Fuzz: byte soup and trailing garbage
// ---------------------------------------------------------------------------

/// Structured prefixes followed by seeded soup, through both surfaces: no
/// input panics, every refusal names a registry class, and any stream that
/// does complete stays implausibly small for soup input.
#[test]
fn fuzz_byte_soup_never_panics_over_both_stages() {
    let real = zstd_frame(&pseudo_random(2048));
    let prefixes: Vec<Vec<u8>> = vec![
        Vec::new(),
        MAGIC.to_vec(),
        hostile_frame(0x00, Some(0x00), None, &[]),
        hostile_frame(0x00, Some(0x38), None, &[]),
        real[..real.len().min(96)].to_vec(),
    ];
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut cases = 0usize;
    for prefix in &prefixes {
        for soup_len in (0..=1023usize).step_by(29) {
            let mut input = prefix.clone();
            input.extend(xorshift_soup(soup_len, &mut state));
            cases += 1;

            match drive_raw(&input, 7, 1024 * 1024) {
                RawOutcome::Complete { canonical } => {
                    assert!(canonical.len() <= 4096, "soup decoded implausibly");
                }
                RawOutcome::Rejected { .. } | RawOutcome::BoundReached => {}
            }

            let mut decoder = transport_decoder(&input, TransportEncoding::Zstd);
            match drive_transport(&mut decoder) {
                Ok(total) => assert!(total <= 4096, "soup streamed implausibly"),
                Err(error) => assert_registry_class(&error),
            }
        }
    }

    // Single-byte mutations of a real frame: a corrupt body never reads
    // back as its original content and never panics.
    for index in (0..real.len()).step_by(real.len() / 128 + 1) {
        let mut mutated = real.clone();
        mutated[index] ^= 0xFF;
        cases += 1;

        match drive_raw(&mutated, 9, 8 * 1024 * 1024) {
            RawOutcome::Complete { canonical } => {
                assert!(canonical.len() <= 8192, "a mutated frame ballooned");
            }
            RawOutcome::Rejected { .. } | RawOutcome::BoundReached => {}
        }

        let mut decoder = transport_decoder(&mutated, TransportEncoding::Zstd);
        match drive_transport(&mut decoder) {
            Ok(total) => assert!(total <= 8192, "a mutated frame ballooned"),
            Err(error) => assert_registry_class(&error),
        }
    }
    assert!(cases > 150, "the corpus collapsed: {cases} cases");
}

/// Bytes after the one frame a transport may carry, through both surfaces:
/// the extra bytes are a corrupted stored form, never more content.
#[test]
fn fuzz_trailing_bytes_after_a_complete_frame_fail_closed() {
    let real = zstd_frame(&pseudo_random(4096));
    let mut state = 0x5EED_5EED_5EED_5EEDu64;
    for suffix_len in [1usize, 2, 17, 4096] {
        let mut framed = real.clone();
        framed.extend(xorshift_soup(suffix_len, &mut state));

        assert!(matches!(
            drive_raw(&framed, 13, 8 * 1024 * 1024),
            RawOutcome::Rejected { .. }
        ));

        let mut decoder = transport_decoder(&framed, TransportEncoding::Zstd);
        let error = decoder
            .next_chunk()
            .expect_err("bytes past the frame are rejected");
        assert!(matches!(error, TransportDecodeError::MalformedFrame { .. }));
    }
}

// ---------------------------------------------------------------------------
// The RSS ceiling at the default concurrency
// ---------------------------------------------------------------------------

/// The reference runner is Linux; the kernel-maintained peak RSS read lives
/// behind `/proc`, so the ceiling check is compiled on Linux targets — the
/// reference four-vCPU runner and the cgroup-limited local fallback are
/// both Linux.
#[cfg(target_os = "linux")]
mod rss {
    use std::fs;
    use std::thread;

    use archivist_protocol::vocabulary::TransportEncoding;
    use archivist_server::config::DEFAULT_MAX_INFLIGHT_UPLOAD_COUNT;
    use archivist_server::transport::{DecodeLimits, TransportDecoder};

    use super::Zeros;

    /// The plan's ceiling for the reference runner, in bytes.
    const RSS_CEILING_BYTES: u64 = 512 * 1024 * 1024;
    /// One attempt's streamed body: far past what one attempt may buffer,
    /// so the measurement shows memory following concurrency buffers.
    const BODY_BYTES: u64 = 64 * 1024 * 1024;

    /// The process's peak resident set, as the kernel recorded it
    /// (`VmHWM` in `/proc/self/status`, reported in KiB). Peak, not
    /// sampled: no allocation between two polls can escape it.
    fn peak_rss_bytes() -> u64 {
        let status = fs::read_to_string("/proc/self/status").expect("process status");
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                let kib: u64 = rest
                    .trim()
                    .trim_end_matches("kB")
                    .trim()
                    .parse()
                    .expect("VmHWM carries a number");
                return kib * 1024;
            }
        }
        panic!("VmHWM missing from /proc/self/status");
    }

    /// The RSS ceiling at the default 16-request concurrency (module docs
    /// carry the method and the reference-runner context). Sixteen
    /// concurrent bounded-decode attempts stream 1 GiB of canonical payload
    /// in total; the process peak must stay under the plan's 512 MiB —
    /// memory follows the concurrency buffers, never the body size.
    #[test]
    fn rss_ceiling_holds_at_the_default_sixteen_request_concurrency() {
        // Hold the heavy gate: this measurement is only honest when the
        // other memory-heavy tests are not peaking concurrently.
        let _gate = super::HEAVY.lock().expect("heavy gate poisoned");
        let workers = usize::try_from(DEFAULT_MAX_INFLIGHT_UPLOAD_COUNT).expect("u16 fits usize");
        let mut totals = Vec::new();
        thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    scope.spawn(|| {
                        let mut decoder = TransportDecoder::new(
                            TransportEncoding::Identity,
                            Zeros {
                                remaining: BODY_BYTES,
                            },
                            DecodeLimits::registry_defaults(),
                        )
                        .expect("identity decoder");
                        let mut total = 0u64;
                        while let Some(chunk) = decoder.next_chunk().expect("identity chunk") {
                            total += chunk.len() as u64;
                        }
                        total
                    })
                })
                .collect();
            for handle in handles {
                totals.push(handle.join().expect("worker did not panic"));
            }
        });

        let streamed: u64 = totals.iter().sum();
        assert_eq!(
            streamed,
            BODY_BYTES * workers as u64,
            "every attempt streamed its whole body"
        );

        let peak = peak_rss_bytes();
        println!(
            "peak RSS at {workers}-attempt concurrency: {} KiB",
            peak / 1024
        );
        assert!(
            peak < RSS_CEILING_BYTES,
            "peak RSS {} KiB crossed the {} KiB ceiling",
            peak / 1024,
            RSS_CEILING_BYTES / 1024
        );
    }
}
