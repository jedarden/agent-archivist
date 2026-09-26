// SPDX-License-Identifier: Apache-2.0

//! The protocol data path's deterministic fuzz suite (bead `aa-7a21c387`).
//!
//! One file drives every stage a `POST /v1/ingest` byte travels — request
//! parsing, canonicalization, signature inputs, identifier and key
//! derivation, multipart framing, decompression, limit transitions, and
//! receipt parsing — because the hazards the bead names only show at the
//! seams between stages. It lives in `archivist-server`'s test tree since
//! that crate is the one place the whole path is reachable: the protocol
//! crate owns the envelope and derivations, the server owns the request
//! framing and transport decode, `archivist-auth` owns receipts, and
//! `archivist-storage` owns the multipart writer the pipeline feeds.
//!
//! The contract under fuzz, one clause per acceptance word:
//!
//! - **no panic**: every stage is driven only through its public API over
//!   generated hostile input, and the suite failing *is* the panic report;
//! - **no prefix escape**: signing preimages are pairwise prefix-free and
//!   decode to exactly their fields, so one attempt's bytes can never
//!   validate as another's;
//! - **no over-allocation**: the framing window, the envelope-part cap,
//!   and the transport record cap are asserted at their exact boundaries,
//!   and preimage length is asserted byte-exact against the documented
//!   layout rather than an upper bound;
//! - **no invalid commit**: the multipart writer commits only after
//!   `finish` on a non-empty validated stream, and a transport stage that
//!   failed once never yields canonical bytes again;
//! - **no identity ambiguity**: perturbing any single identity input of a
//!   parsed envelope can never keep the declared occurrence or attestation
//!   identity, and every derivation input changes its output;
//! - **no content-bearing crash output**: every error this path can emit
//!   is rendered to string and debug, and neither rendering may contain a
//!   marker byte-string planted in every part of the generated request.
//!
//! Every generator is a seeded `xorshift64*` stream in the house style of
//! `archivist-protocol`'s property tests, so a failure replays from the
//! seed named in the test. Iteration counts keep the whole binary fast
//! under the fleet's cgroup-limited test lanes.

use std::fmt::Write as _;
use std::io::{self, Cursor, Read};

use archivist_auth::authority::PinnedAuthorityRoot;
use archivist_auth::identity::SigningKey;
use archivist_auth::receipt::{
    AuthoritySigner, CertifiedReceiptKey, Receipt, ReceiptKeyError, ReceiptKeySchedule,
    ReceiptSigningKey,
};
use archivist_auth::reference::ProtectedReference;
use archivist_protocol::derivation::{
    artifact_hash, export_selection_digest, ingest_attempt_signing_input, occurrence_id,
    session_hash,
};
use archivist_protocol::envelope::{CANONICAL_MAX_BYTES, Envelope, EnvelopeError};
use archivist_protocol::json::{self, Object, ParseError, Value};
use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::sha256::encode_hex;
use archivist_protocol::vocabulary::{
    AdapterId, ArtifactHash, ArtifactKind, AttestationId, BlobDigest, ChecksumAlgorithm, ClientId,
    Ed25519PublicKey, EnvelopeDigest, GenerationId, HarnessId, IdSource, IncomingChecksum, KeyId,
    OccurrenceId, OpaqueId, RangeKind, RequestContentDigest, RequestId, SafeMessage, SessionHash,
    StorageOutcome, StorageProfile, TenantId, Timestamp, TransportEncoding, VersionToken,
};
use archivist_server::parse::framing::{
    ByteSource, FRAMING_WINDOW_BYTES, FramingError, FramingEvent, FramingTokenizer, RequestFraming,
};
use archivist_server::parse::ingest::parse_ingest_with_cap;
use archivist_server::parse::parts::{ENVELOPE_PART_MEDIA_TYPE, TwoPartError, TwoPartRequest};
use archivist_server::transport::{DecodeLimits, TransportDecodeError, TransportDecoder};
use archivist_storage::blob::BlobEncoder;
use archivist_storage::capability::{
    ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::metadata::ObjectTag;
use archivist_storage::multipart::{MultipartWriter, OpenUploads, PART_BYTES};
use archivist_storage::raw_write::{
    ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
};
use archivist_storage::zstd_v1::ZstdV1Encoder;

/// The boundary every generated body is framed under.
const BOUNDARY: &str = "archivist-fuzz-01";

/// The part-two media type of the identity transport.
const IDENTITY_MEDIA_TYPE: &str = "application/octet-stream";

/// A marker byte-string planted in every generated request part. No error
/// rendering the path can produce may ever contain it — the observable
/// half of the content-free contract.
const FUZZ_MARKER: &str = "ZFUZZMARKQ7";

// ---------------------------------------------------------------------------
// Deterministic generator
// ---------------------------------------------------------------------------

/// `xorshift64*`: the whole state is one nonzero word, so a test seeded
/// from a constant replays identically on every run and platform.
struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value below `bound`; modulo bias is irrelevant at fuzz-suite
    /// granularity.
    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    fn below_usize(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound).expect("bound fits u64");
        usize::try_from(self.below(bound)).expect("result fits usize")
    }

    fn u63(&mut self) -> u64 {
        self.next_u64() >> 1
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.below(256)).expect("byte fits u8")
    }

    fn boolean(&mut self) -> bool {
        self.below(2) == 0
    }
}

/// Regenerate until the value differs from `current` (an exact repeat is
/// astronomically unlikely; the loop keeps the intent explicit).
fn distinct<T: PartialEq>(current: &T, mut generate: impl FnMut() -> T) -> T {
    loop {
        let candidate = generate();
        if candidate != *current {
            return candidate;
        }
    }
}

fn distinct_digest(current: &[u8; 32], prng: &mut Prng) -> [u8; 32] {
    let mut fresh = *current;
    while fresh == *current {
        fresh = digest32(prng);
    }
    fresh
}

/// Printable text mixing identifier-safe characters with bytes needing
/// canonical-JSON escapes; safe for every opaque identifier grammar.
const TEXT_BYTES: &[u8] = b"abcXYZ019 ._-/\\\"{}'()+_?,.:=?-";

fn opaque_text(prng: &mut Prng) -> String {
    let len = 1 + prng.below_usize(48);
    (0..len)
        .map(|_| char::from(TEXT_BYTES[prng.below_usize(TEXT_BYTES.len())]))
        .collect()
}

/// A `short-token` (`^[a-z0-9][a-z0-9._-]{0,63}$`).
fn short_token(prng: &mut Prng) -> String {
    const HEAD: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const TAIL: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789._-";
    let len = 1 + prng.below_usize(16);
    let mut token = String::new();
    token.push(char::from(HEAD[prng.below_usize(HEAD.len())]));
    for _ in 1..len {
        token.push(char::from(TAIL[prng.below_usize(TAIL.len())]));
    }
    token
}

/// A `version-token` (`^[0-9A-Za-z._+-]{1,32}$`).
fn version_token_text(prng: &mut Prng) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._+-";
    let len = 1 + prng.below_usize(12);
    (0..len)
        .map(|_| char::from(ALPHABET[prng.below_usize(ALPHABET.len())]))
        .collect()
}

/// Canonical `uuid-v4`/`uuid-v7` wire text with the version and variant
/// nibbles pinned so a generated value always parses.
fn uuid_text(prng: &mut Prng, version: u8) -> String {
    let mut bytes = [0u8; 16];
    for byte in &mut bytes {
        *byte = prng.byte();
    }
    bytes[6] = (bytes[6] & 0x0f) | (version << 4);
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = encode_hex(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// A lowercase hex string of exactly `len` digits.
fn hex_text(prng: &mut Prng, len: usize) -> String {
    const HEX_DIGITS: &[u8] = b"0123456789abcdef";
    (0..len)
        .map(|_| char::from(HEX_DIGITS[prng.below_usize(HEX_DIGITS.len())]))
        .collect()
}

/// A random 32-byte digest.
fn digest32(prng: &mut Prng) -> [u8; 32] {
    let mut raw = [0u8; 32];
    for byte in &mut raw {
        *byte = prng.byte();
    }
    raw
}

/// A grammar- and calendar-valid UTC instant (`YYYY-MM-DDTHH:MM:SSZ` with
/// day ≤ 28, so no month length is ever consulted).
fn timestamp_text(prng: &mut Prng) -> String {
    let year = 2020 + prng.below(30);
    let month = 1 + prng.below(12);
    let day = 1 + prng.below(28);
    let hour = prng.below(24);
    let minute = prng.below(60);
    let second = prng.below(60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// A boundary-charset token (`[0-9A-Za-z'()+_,.:=?-]{1,70}`) — the only
/// text the content-type grammar admits after `boundary=`.
fn boundary_text(prng: &mut Prng) -> String {
    const CHARSET: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'()+_,.:=?-";
    let len = 1 + prng.below_usize(CHARSET.len().min(70));
    (0..len)
        .map(|_| char::from(CHARSET[prng.below_usize(CHARSET.len())]))
        .collect()
}

/// `len` bytes of seeded soup: no structure a parser could lean on.
fn soup(prng: &mut Prng, len: usize) -> Vec<u8> {
    (0..len).map(|_| prng.byte()).collect()
}

/// Assert a rendered error carries no request content: the marker planted
/// in the generated input must not appear. The panic message deliberately
/// does not quote the rendering — echoing it would itself be the leak.
fn assert_rendering_content_free(context: &str, rendered: &str) {
    assert!(
        !rendered.contains(FUZZ_MARKER),
        "{context} leaked request content ({} byte rendering)",
        rendered.len(),
    );
}

/// Both the Display and Debug renderings of an error carrying Display.
fn assert_error_content_free(context: &str, error: impl std::fmt::Display + std::fmt::Debug) {
    assert_rendering_content_free(context, &error.to_string());
    assert_rendering_content_free(context, &format!("{error:?}"));
}

/// The Debug rendering of an error with no Display of its own.
fn assert_debug_content_free(context: &str, error: &impl std::fmt::Debug) {
    assert_rendering_content_free(context, &format!("{error:?}"));
}

// ---------------------------------------------------------------------------
// The baseline request every mutation leg starts from
// ---------------------------------------------------------------------------

/// The conformance corpus's `valid-direct-baseline` envelope, plus one
/// retained unknown member carrying the fuzz marker so the content-free
/// property is observable in every downstream error. The declared
/// identities match the derivation of the fixed inputs.
fn baseline_envelope() -> Envelope {
    let mut unknown = Object::new();
    unknown
        .insert("fuzz_marker", Value::Text(FUZZ_MARKER.to_owned()))
        .expect("marker member is unique");
    Envelope {
        tenant_id: TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").unwrap(),
        origin_client_id: ClientId::parse("11111111-2222-4333-8444-555555555555").unwrap(),
        uploader_client_id: ClientId::parse("11111111-2222-4333-8444-555555555555").unwrap(),
        harness: HarnessId::parse("claude-code").unwrap(),
        upstream_session_id: OpaqueId::parse("4f9c2f1e-8a3d-4b67-9c2f-1e8a3d4b679c").unwrap(),
        id_source: IdSource::Upstream,
        artifact_kind: ArtifactKind::FileSlice,
        adapter_id: AdapterId::parse("claude-jsonl").unwrap(),
        adapter_projection_version: VersionToken::parse("1").unwrap(),
        adapter_artifact_id: OpaqueId::parse("session-file-4f9c2f1e").unwrap(),
        generation: GenerationId::parse("1a07a111-7000-7000-8000-000000000001").unwrap(),
        range_kind: RangeKind::Byte,
        range_start: 0,
        range_end: 0,
        blob_digest: BlobDigest::parse(
            "1954362cfdaf85cb2a0dd5825a303964da1fb31cf96d0f9739db3c4882327175",
        )
        .unwrap(),
        incoming_checksum: IncomingChecksum::parse(
            "1954362cfdaf85cb2a0dd5825a303964da1fb31cf96d0f9739db3c4882327175",
        )
        .unwrap(),
        incoming_checksum_algorithm: ChecksumAlgorithm::Sha256,
        storage_profile: StorageProfile::ZstdV1,
        transport_encoding: TransportEncoding::Identity,
        compressed_size: 176,
        uncompressed_size: 176,
        occurrence_id: OccurrenceId::parse(
            "d4987eccc7f41c78d90416b3ddbd2e7850341b0497cec0565ac074869dfcafe5",
        )
        .unwrap(),
        attestation_id: AttestationId::parse(
            "95fa374c2e4113ddc39e5548d26b06757dcf5ca7e40ab0dbc632a847e6b90f1f",
        )
        .unwrap(),
        request_id: RequestId::parse("1a07b201-7000-7000-8000-000000000001").unwrap(),
        capture_time: Timestamp::parse("2026-09-11T16:44:10Z").unwrap(),
        envelope_creation_time: Timestamp::parse("2026-09-11T16:44:11Z").unwrap(),
        source_time: Some(Timestamp::parse("2026-09-11T16:44:02Z").unwrap()),
        parent_session_id: None,
        orchestrator_attempt_id: None,
        trace_id: None,
        inference_request_id: None,
        unknown_fields: unknown,
    }
}

/// The baseline envelope's canonical bytes — part one of every generated
/// request body.
fn baseline_envelope_bytes() -> Vec<u8> {
    baseline_envelope().canonical_bytes()
}

/// One generic byte mutation: a bit flip, a truncation, a soup insertion,
/// a structural overwrite, a duplication, or a deletion at a seeded
/// position. The one primitive every mutation leg composes.
fn mutate(bytes: &[u8], prng: &mut Prng) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if out.is_empty() {
        out.push(prng.byte());
        return out;
    }
    match prng.below(6) {
        0 => {
            let at = prng.below_usize(out.len());
            let bit = prng.below(8);
            out[at] ^= u8::try_from(1u64 << bit).expect("bit is below 8");
        }
        1 => {
            let at = prng.below_usize(out.len());
            out.truncate(at);
        }
        2 => {
            let at = prng.below_usize(out.len() + 1);
            let run_len = 1 + prng.below_usize(32);
            let run = soup(prng, run_len);
            out.splice(at..at, run);
        }
        3 => {
            const STRUCTURAL: &[u8] = b"{}[]\":,0123456789 \t\n\r-";
            let at = prng.below_usize(out.len());
            let len = 1 + prng.below_usize((out.len() - at).min(8));
            for byte in &mut out[at..at + len] {
                *byte = STRUCTURAL[prng.below_usize(STRUCTURAL.len())];
            }
        }
        4 => {
            let at = prng.below_usize(out.len());
            let len = 1 + prng.below_usize(out.len() - at);
            let run = out[at..at + len].to_vec();
            let insert_at = prng.below_usize(out.len() + 1);
            out.splice(insert_at..insert_at, run);
        }
        _ => {
            let at = prng.below_usize(out.len());
            let len = 1 + prng.below_usize(out.len() - at);
            out.drain(at..at + len);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Leg 1 — request parsing: the envelope under mutation
// ---------------------------------------------------------------------------

/// Mutation never panics the envelope parser, and every acceptance it
/// produces is self-consistent: canonical bytes are a reparse fixed
/// point, and the declared identities still match the inputs. Every
/// rejection is content-free in both renderings.
#[test]
fn envelope_parse_survives_mutation_and_fails_closed() {
    let canonical = baseline_envelope_bytes();
    let mut prng = Prng::new(0x5EED_F001);
    let mut accepted = 0;
    for _ in 0..512 {
        let hostile = mutate(&canonical, &mut prng);
        match Envelope::parse(&hostile) {
            Ok(envelope) => {
                accepted += 1;
                let recanonicalized = envelope.canonical_bytes();
                assert_eq!(
                    Envelope::parse(&recanonicalized).expect("canonical bytes reparse"),
                    envelope,
                    "canonical form is not a fixed point after mutation"
                );
                envelope
                    .verify_identities()
                    .expect("an accepted envelope re-derives its identities");
            }
            Err(error) => {
                assert_error_content_free("envelope parse rejection", error);
            }
        }
    }
    assert!(accepted > 0, "mutation never produced a parseable envelope");
}

/// The identity-bearing members the envelope's declared identifiers are
/// re-derived from.
const IDENTITY_MEMBERS: [&str; 15] = [
    "tenant_id",
    "origin_client_id",
    "uploader_client_id",
    "harness",
    "upstream_session_id",
    "artifact_kind",
    "adapter_id",
    "adapter_projection_version",
    "adapter_artifact_id",
    "generation",
    "range_kind",
    "range_start",
    "range_end",
    "blob_digest",
    "request_id",
];

fn current_text(value: &Value) -> String {
    let Value::Text(text) = value else {
        unreachable!("baseline identity members are text");
    };
    text.clone()
}

fn current_int(value: &Value) -> i64 {
    let Value::Int(n) = value else {
        unreachable!("baseline range members are integers");
    };
    *n
}

/// One fresh, grammar-valid wire value for an identity member, guaranteed
/// distinct from the value the baseline carries.
fn fresh_identity_value(member: &str, current: &Value, prng: &mut Prng) -> Value {
    match member {
        "tenant_id" | "origin_client_id" | "uploader_client_id" => {
            Value::Text(distinct(&current_text(current), || uuid_text(prng, 4)))
        }
        "harness" | "adapter_id" => {
            Value::Text(distinct(&current_text(current), || short_token(prng)))
        }
        "upstream_session_id" | "adapter_artifact_id" => {
            Value::Text(distinct(&current_text(current), || opaque_text(prng)))
        }
        "artifact_kind" => Value::Text(distinct(&current_text(current), || {
            ArtifactKind::tokens()[prng.below_usize(ArtifactKind::tokens().len())].to_owned()
        })),
        "adapter_projection_version" => Value::Text(distinct(&current_text(current), || {
            version_token_text(prng)
        })),
        "generation" | "request_id" => {
            Value::Text(distinct(&current_text(current), || uuid_text(prng, 7)))
        }
        "range_kind" => Value::Text(distinct(&current_text(current), || {
            RangeKind::tokens()[prng.below_usize(RangeKind::tokens().len())].to_owned()
        })),
        "range_start" | "range_end" => Value::Int(
            i64::try_from(distinct(
                &(u64::try_from(current_int(current)).expect("baseline range is a u63")),
                || prng.u63(),
            ))
            .expect("u63 fits i64"),
        ),
        "blob_digest" => Value::Text(distinct(&current_text(current), || hex_text(prng, 64))),
        _ => unreachable!("every identity member is covered"),
    }
}

/// Identity ambiguity is impossible: swapping any single identity input
/// for a fresh valid value can never leave the envelope parseable with
/// its old declared occurrence or attestation identity. The re-derivation
/// gate refuses, or a consistency check does — but never a silent accept.
#[test]
fn identity_perturbations_never_parse_with_stale_declared_ids() {
    let baseline = baseline_envelope();
    let mut prng = Prng::new(0x5EED_F002);
    for round in 0..64 {
        for member in IDENTITY_MEMBERS {
            let mut value = baseline.to_value();
            let Value::Object(object) = &mut value else {
                unreachable!("baseline value is an object");
            };
            let current = object
                .get(member)
                .unwrap_or_else(|| panic!("baseline carries {member}"))
                .clone();
            object.set(member, fresh_identity_value(member, &current, &mut prng));
            assert!(
                Envelope::from_value(value).is_err(),
                "round {round}: perturbing {member} left the declared identities valid"
            );
        }
    }
}

/// The canonical envelope padded to an exact length with one unknown
/// member: each filler character adds exactly one canonical byte.
fn padded_envelope(filler: usize) -> Envelope {
    let mut padded = baseline_envelope();
    padded.unknown_fields = Object::new();
    padded
        .unknown_fields
        .insert("padding", Value::Text("x".repeat(filler)))
        .expect("padding member is unique");
    padded
}

/// The canonical-size cap transitions exactly at its boundary: an
/// envelope whose canonical bytes are exactly `CANONICAL_MAX_BYTES` parses
/// (exactly-at is lawful), and one more byte refuses with
/// [`EnvelopeError::SizeExceeded`] — never a panic, never a parse of an
/// oversized form.
#[test]
fn envelope_size_cap_transitions_exactly_at_the_boundary() {
    let probe = padded_envelope(0);
    let base = probe.canonical_bytes().len();
    let at_cap = CANONICAL_MAX_BYTES - base;
    for (filler, accepts) in [(at_cap, true), (at_cap + 1, false)] {
        let bytes = padded_envelope(filler).canonical_bytes();
        assert_eq!(
            bytes.len() <= CANONICAL_MAX_BYTES,
            accepts,
            "the filler length missed its target"
        );
        match Envelope::parse(&bytes) {
            Ok(parsed) => {
                assert!(accepts, "one byte past the cap parsed");
                parsed
                    .verify_identities()
                    .expect("an in-cap envelope is self-consistent");
            }
            Err(EnvelopeError::SizeExceeded { limit_bytes }) => {
                assert!(!accepts, "the at-cap envelope was refused");
                assert_eq!(limit_bytes, CANONICAL_MAX_BYTES);
            }
            Err(other) => panic!("unexpected failure at the cap: {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Leg 2 — canonicalization
// ---------------------------------------------------------------------------

const GENERATED_CHARS: &[char] = &[
    'a',
    'Z',
    '0',
    ' ',
    '"',
    '\\',
    '/',
    '\u{7}',
    '\t',
    '\n',
    '\r',
    '\u{1f}',
    'é',
    'ß',
    '€',
    '\u{e000}',
    '\u{10000}',
    '😀',
    'ᛮ',
];

fn generated_text(prng: &mut Prng) -> String {
    let len = prng.below_usize(24);
    (0..len)
        .map(|_| GENERATED_CHARS[prng.below_usize(GENERATED_CHARS.len())])
        .collect()
}

/// A random protocol value: depth-bounded, every kind represented, text
/// drawn from a pool including control characters, escapes, and astral
/// planes.
fn generated_value(prng: &mut Prng, depth: usize) -> Value {
    let spread = if depth >= 3 { 4 } else { 6 };
    match prng.below(spread) {
        0 => Value::Null,
        1 => Value::Bool(prng.boolean()),
        2 => {
            let magnitude = i64::try_from(prng.u63()).expect("u63 fits i64");
            Value::Int(if prng.boolean() {
                -magnitude
            } else {
                magnitude
            })
        }
        3 => Value::Text(generated_text(prng)),
        4 => Value::Array(
            (0..prng.below_usize(4))
                .map(|_| generated_value(prng, depth + 1))
                .collect(),
        ),
        _ => {
            let mut object = Object::new();
            for index in 0..prng.below_usize(4) {
                let name = format!("{}{index}", short_token(prng));
                object.set(&name, generated_value(prng, depth + 1));
            }
            Value::Object(object)
        }
    }
}

/// Serialize one string as *transmission* form: the characters JSON
/// requires escaping (`"`, `\`, controls) escaped, ordinary characters
/// randomly re-escaped as `\u00xx`, and astral characters randomly split
/// into surrogate-pair escapes — shapes the parser must accept yet never
/// canonicalize to.
fn write_transmitted_string(text: &str, out: &mut String, prng: &mut Prng) {
    out.push('"');
    for c in text.chars() {
        if c == '"' {
            out.push_str("\\\"");
        } else if c == '\\' {
            out.push_str("\\\\");
        } else if u32::from(c) < 0x20 {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        } else if u32::from(c) > 0xffff && prng.boolean() {
            let combined = u32::from(c) - 0x1_0000;
            let high = 0xd800 + (combined >> 10);
            let low = 0xdc00 + (combined & 0x3ff);
            let _ = write!(out, "\\u{high:04x}\\u{low:04x}");
        } else if c.is_ascii() && c.is_ascii_alphanumeric() && prng.below(4) == 0 {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        } else {
            let mut buffer = [0u8; 4];
            out.push_str(c.encode_utf8(&mut buffer));
        }
    }
    out.push('"');
}

/// Serialize a value as deliberately non-canonical transmission:
/// whitespace around every token and object members in reverse order.
fn write_transmitted(value: &Value, out: &mut String, prng: &mut Prng) {
    fn ws(out: &mut String, prng: &mut Prng) {
        for _ in 0..prng.below_usize(3) {
            out.push([' ', '\t', '\n', '\r'][prng.below_usize(4)]);
        }
    }
    ws(out, prng);
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(n) => out.push_str(&n.to_string()),
        Value::Text(text) => write_transmitted_string(text, out, prng),
        Value::Array(items) => {
            out.push('[');
            let mut first = true;
            for item in items {
                if !first {
                    out.push(',');
                }
                first = false;
                write_transmitted(item, out, prng);
            }
            out.push(']');
        }
        Value::Object(object) => {
            out.push('{');
            let members: Vec<(&str, &Value)> = object.iter().collect();
            let mut first = true;
            for (name, item) in members.iter().rev() {
                if !first {
                    out.push(',');
                }
                first = false;
                write_transmitted_string(name, out, prng);
                out.push(':');
                write_transmitted(item, out, prng);
            }
            out.push('}');
        }
    }
    ws(out, prng);
}

/// Canonical form is a reparse fixed point over generated values: the
/// canonical bytes parse back to the same value, recanonicalize to the
/// same bytes, and the parser never panics on them no matter what the
/// text pool contains.
#[test]
fn canonical_form_is_a_reparse_fixed_point_over_generated_values() {
    let mut prng = Prng::new(0x5EED_F003);
    for _ in 0..384 {
        let value = generated_value(&mut prng, 0);
        let canonical = value.canonical_bytes();
        let reparsed = json::parse(&canonical)
            .unwrap_or_else(|error| panic!("canonical bytes do not reparse: {error}"));
        assert_eq!(reparsed, value, "reparse changed the value");
        assert_eq!(
            reparsed.canonical_bytes(),
            canonical,
            "recanonicalization changed the bytes"
        );
    }
}

/// Canonicalization absorbs non-canonical transmission: parse the
/// transmitted form of a generated value and the canonical bytes come back
/// byte-identical to the original's. Surrogate pairs, `\u` escapes of
/// ordinary characters, reordered members, and arbitrary whitespace all
/// collapse to the one canonical form every digest covers.
#[test]
fn canonicalization_absorbs_noncanonical_transmission() {
    let mut prng = Prng::new(0x5EED_F004);
    for _ in 0..256 {
        let value = generated_value(&mut prng, 0);
        let canonical = value.canonical_bytes();
        let mut transmitted = String::new();
        write_transmitted(&value, &mut transmitted, &mut prng);
        let parsed = json::parse(transmitted.as_bytes())
            .unwrap_or_else(|error| panic!("transmission form rejected: {error}"));
        assert_eq!(
            parsed.canonical_bytes(),
            canonical,
            "canonicalization did not absorb the transmission form"
        );
    }
}

/// The parser's bounds transition exactly at their boundaries and never
/// panic: one byte below the length bound is `LengthExceeded`, exactly at
/// it the outcome equals the effectively-unbounded one; nesting of depth D
/// parses at `max_depth = D` and refuses with `DepthExceeded` at `D - 1`;
/// `max_depth = 0` still accepts scalars and refuses the shallowest
/// nesting; the empty input is malformed at any bound.
#[test]
fn json_bound_transitions_are_exact_and_never_panic() {
    let mut prng = Prng::new(0x5EED_F005);
    for _ in 0..128 {
        let input_len = prng.below_usize(64);
        let input = soup(&mut prng, input_len);
        let reference = json::parse_with_limits(&input, 1024, 64);
        if input.is_empty() {
            assert!(
                json::parse_with_limits(&input, 0, 64).is_err(),
                "the empty input is malformed, never a panic"
            );
            continue;
        }
        assert_eq!(
            json::parse_with_limits(&input, input.len() - 1, 64),
            Err(ParseError::LengthExceeded)
        );
        assert_eq!(
            json::parse_with_limits(&input, input.len(), 64),
            reference,
            "exactly at the length bound must not change the outcome"
        );
    }
    for depth in 2..=24usize {
        let deep = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert!(
            json::parse_with_limits(deep.as_bytes(), 1024, depth).is_ok(),
            "depth {depth} must parse at max_depth {depth}"
        );
        match json::parse_with_limits(deep.as_bytes(), 1024, depth - 1) {
            Err(ParseError::DepthExceeded { offset }) => {
                assert!(offset <= deep.len(), "offset inside the input");
            }
            other => panic!("depth {depth} at max_depth {} gave {other:?}", depth - 1),
        }
    }
    assert_eq!(
        json::parse_with_limits(b"0", 1024, 0),
        Ok(Value::Int(0)),
        "a scalar needs no nesting depth"
    );
    assert!(matches!(
        json::parse_with_limits(b"[0]", 1024, 0),
        Err(ParseError::DepthExceeded { .. })
    ));
    assert!(json::parse_with_limits(b"", 0, 0).is_err());
    assert_eq!(
        json::parse_with_limits(b"x", 0, 0),
        Err(ParseError::LengthExceeded)
    );
}

// ---------------------------------------------------------------------------
// Leg 3 — signature inputs: the ingest-attempt preimage
// ---------------------------------------------------------------------------

/// The ten covered inputs of the `ingest-attempt-v1` construction, in
/// registry order.
struct AttemptInputs {
    http_method: String,
    route: String,
    content_type: String,
    request_content_digest: [u8; 32],
    envelope_digest: [u8; 32],
    payload_canonical_digest: [u8; 32],
    payload_transport_digest: [u8; 32],
    uploader_key_id: [u8; 32],
    authorization_epoch: u64,
    authorization_timestamp: String,
}

impl AttemptInputs {
    fn generate(prng: &mut Prng) -> Self {
        Self {
            http_method: ["POST", "PUT", "GET", "post"][prng.below_usize(4)].to_owned(),
            route: ["/v1/ingest", "/v1/export", "/healthz"][prng.below_usize(3)].to_owned(),
            content_type: format!("multipart/related; boundary={}", boundary_text(prng)),
            request_content_digest: digest32(prng),
            envelope_digest: digest32(prng),
            payload_canonical_digest: digest32(prng),
            payload_transport_digest: digest32(prng),
            uploader_key_id: digest32(prng),
            authorization_epoch: prng.u63(),
            authorization_timestamp: timestamp_text(prng),
        }
    }

    fn preimage(&self) -> Vec<u8> {
        ingest_attempt_signing_input(
            &self.http_method,
            &self.route,
            &self.content_type,
            &RequestContentDigest::from_raw(self.request_content_digest),
            &EnvelopeDigest::from_raw(self.envelope_digest),
            &BlobDigest::from_raw(self.payload_canonical_digest),
            &IncomingChecksum::from_raw(self.payload_transport_digest),
            &KeyId::from_public_key(&Ed25519PublicKey::from_raw(self.uploader_key_id)),
            self.authorization_epoch,
            &Timestamp::parse(&self.authorization_timestamp).expect("generated instant parses"),
        )
    }

    /// The field bytes of each input in registry order — the model the
    /// layout assertion compares against. The eighth field is the uploader
    /// *key identifier* (the SHA-256 derivation of the public key), which
    /// is what the registry frames — not the raw public key.
    fn field_bytes(&self) -> Vec<Vec<u8>> {
        vec![
            self.http_method.as_bytes().to_vec(),
            self.route.as_bytes().to_vec(),
            self.content_type.as_bytes().to_vec(),
            self.request_content_digest.to_vec(),
            self.envelope_digest.to_vec(),
            self.payload_canonical_digest.to_vec(),
            self.payload_transport_digest.to_vec(),
            KeyId::from_public_key(&Ed25519PublicKey::from_raw(self.uploader_key_id))
                .as_raw()
                .to_vec(),
            self.authorization_epoch.to_be_bytes().to_vec(),
            self.authorization_timestamp.as_bytes().to_vec(),
        ]
    }
}

/// Decode `label || 0x00 || u64be(len)||content..` back to its field
/// contents — an independent model written from the framing documentation,
/// not by calling the crate.
fn decode_frame(preimage: &[u8]) -> Option<(String, Vec<Vec<u8>>)> {
    let split = preimage.iter().position(|byte| *byte == 0x00)?;
    let label = String::from_utf8(preimage[..split].to_vec()).ok()?;
    let mut fields = Vec::new();
    let mut rest = &preimage[split + 1..];
    while !rest.is_empty() {
        if rest.len() < 8 {
            return None;
        }
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&rest[..8]);
        let len = usize::try_from(u64::from_be_bytes(len_bytes)).ok()?;
        rest = &rest[8..];
        if rest.len() < len {
            return None;
        }
        fields.push(rest[..len].to_vec());
        rest = &rest[len..];
    }
    Some((label, fields))
}

/// The signing preimage is byte-exact against the documented layout —
/// `ingest-attempt-v1`, 0x00, then ten `u64be(len) || content` fields in
/// registry order — so its length is exactly determined (no
/// over-allocation slack) and it decodes back to exactly its inputs.
#[test]
fn signing_preimage_matches_the_documented_layout_exactly() {
    const LABEL: &str = "ingest-attempt-v1";
    let mut prng = Prng::new(0x5EED_F006);
    for _ in 0..256 {
        let inputs = AttemptInputs::generate(&mut prng);
        let preimage = inputs.preimage();
        let expected_len = LABEL.len()
            + 1
            + inputs
                .field_bytes()
                .iter()
                .map(|field| 8 + field.len())
                .sum::<usize>();
        assert_eq!(
            preimage.len(),
            expected_len,
            "preimage length drifted from the pinned layout"
        );
        let (label, fields) = decode_frame(&preimage)
            .unwrap_or_else(|| panic!("preimage is undecodable: {}", encode_hex(&preimage)));
        assert_eq!(label, LABEL);
        assert_eq!(
            fields,
            inputs.field_bytes(),
            "framing drifted from the registry"
        );
        // Deterministic: the same inputs frame to the same preimage bytes.
        assert_eq!(inputs.preimage(), preimage);
    }
}

/// The preimage with exactly one covered input replaced by a fresh valid
/// value; `which` indexes the ten registry fields.
fn perturbed_preimage(base: &AttemptInputs, which: u8, prng: &mut Prng) -> Vec<u8> {
    let mut variant = AttemptInputs {
        http_method: base.http_method.clone(),
        route: base.route.clone(),
        content_type: base.content_type.clone(),
        request_content_digest: base.request_content_digest,
        envelope_digest: base.envelope_digest,
        payload_canonical_digest: base.payload_canonical_digest,
        payload_transport_digest: base.payload_transport_digest,
        uploader_key_id: base.uploader_key_id,
        authorization_epoch: base.authorization_epoch,
        authorization_timestamp: base.authorization_timestamp.clone(),
    };
    match which {
        0 => {
            variant.http_method = distinct(&base.http_method, || {
                ["POST", "PUT", "GET", "post"][prng.below_usize(4)].to_owned()
            });
        }
        1 => {
            variant.route = distinct(&base.route, || {
                ["/v1/ingest", "/v1/export", "/healthz"][prng.below_usize(3)].to_owned()
            });
        }
        2 => {
            variant.content_type = distinct(&base.content_type, || {
                format!("multipart/related; boundary={}", boundary_text(prng))
            });
        }
        3 => {
            variant.request_content_digest = distinct_digest(&base.request_content_digest, prng);
        }
        4 => variant.envelope_digest = distinct_digest(&base.envelope_digest, prng),
        5 => {
            variant.payload_canonical_digest =
                distinct_digest(&base.payload_canonical_digest, prng);
        }
        6 => {
            variant.payload_transport_digest =
                distinct_digest(&base.payload_transport_digest, prng);
        }
        7 => variant.uploader_key_id = distinct_digest(&base.uploader_key_id, prng),
        8 => variant.authorization_epoch = distinct(&base.authorization_epoch, || prng.u63()),
        _ => {
            variant.authorization_timestamp =
                distinct(&base.authorization_timestamp, || timestamp_text(prng));
        }
    }
    variant.preimage()
}

/// No preimage is a proper prefix of another's (prefix escape is
/// impossible), and changing any single covered input changes the
/// preimage — the two properties a signature input must hold for one
/// attempt's signature to be unable to certify another's.
#[test]
fn signing_preimages_never_prefix_escape_and_stay_input_sensitive() {
    let mut prng = Prng::new(0x5EED_F007);
    let mut preimages = Vec::new();
    for _ in 0..256 {
        preimages.push(AttemptInputs::generate(&mut prng).preimage());
    }
    for (left_index, left) in preimages.iter().enumerate() {
        for (right_index, right) in preimages.iter().enumerate() {
            if left_index == right_index {
                continue;
            }
            let shorter = left.len().min(right.len());
            assert_ne!(
                &left[..shorter],
                &right[..shorter],
                "preimages {left_index} and {right_index} share a framing prefix"
            );
        }
    }

    for _ in 0..128 {
        let base = AttemptInputs::generate(&mut prng);
        let base_preimage = base.preimage();
        for which in 0..10u8 {
            assert_ne!(
                perturbed_preimage(&base, which, &mut prng),
                base_preimage,
                "covered input {which} did not change the preimage"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Leg 4 — identifier and key derivation
// ---------------------------------------------------------------------------

/// A generated identity tuple and its downstream derived identities.
struct DerivedIdentities {
    tenant: TenantId,
    origin: ClientId,
    harness: HarnessId,
    upstream: String,
    session: SessionHash,
    artifact: ArtifactHash,
    generation: GenerationId,
    range_start: u64,
    range_end: u64,
    blob: BlobDigest,
}

impl DerivedIdentities {
    fn generate(prng: &mut Prng) -> Self {
        let tenant = TenantId::parse(&uuid_text(prng, 4)).expect("generated uuid-v4 parses");
        let origin = ClientId::parse(&uuid_text(prng, 4)).expect("generated uuid-v4 parses");
        let harness = HarnessId::parse(&short_token(prng)).expect("generated short-token parses");
        let upstream = opaque_text(prng);
        let session = session_hash(&tenant, &origin, &harness, &upstream);
        let adapter = AdapterId::parse(&short_token(prng)).expect("generated short-token parses");
        let projection =
            VersionToken::parse(&version_token_text(prng)).expect("generated version parses");
        let artifact_kind = ArtifactKind::parse(
            ArtifactKind::tokens()[prng.below_usize(ArtifactKind::tokens().len())],
        )
        .expect("registry token parses");
        let artifact = artifact_hash(
            &session,
            artifact_kind,
            &adapter,
            &projection,
            &opaque_text(prng),
        );
        let range_start = prng.u63();
        Self {
            tenant,
            origin,
            harness,
            upstream,
            session,
            artifact,
            generation: GenerationId::parse(&uuid_text(prng, 7)).expect("generated uuid-v7 parses"),
            range_start,
            range_end: range_start + prng.u63() / 2,
            blob: BlobDigest::parse(&hex_text(prng, 64)).expect("generated hex parses"),
        }
    }

    /// A copy of `base` with every field except `upstream` (and the
    /// session it feeds) replaced by fresh values — the one way to change
    /// the session while pinning everything else.
    fn with_fresh_session(base: &Self, prng: &mut Prng) -> Self {
        let mut fresh = Self::generate(prng);
        fresh.tenant = base.tenant.clone();
        fresh.origin = base.origin.clone();
        fresh.harness = base.harness.clone();
        fresh.upstream = distinct(&base.upstream, || opaque_text(prng));
        fresh.session = session_hash(
            &fresh.tenant,
            &fresh.origin,
            &fresh.harness,
            &fresh.upstream,
        );
        fresh
    }

    fn occurrence(&self) -> OccurrenceId {
        occurrence_id(
            &self.session,
            &self.artifact,
            &self.generation,
            RangeKind::Byte,
            self.range_start,
            self.range_end,
            &self.blob,
        )
    }
}

/// The occurrence identity is sensitive to every one of its inputs: a
/// fresh session, artifact, generation, range end, blob digest, or range
/// kind each changes the derived identity, so no two distinct input
/// tuples can share one occurrence on the wire.
#[test]
fn occurrence_identity_is_sensitive_to_every_input() {
    let mut prng = Prng::new(0x5EED_F008);
    for _ in 0..256 {
        let base = DerivedIdentities::generate(&mut prng);
        let base_occurrence = base.occurrence();

        let mut variant = DerivedIdentities::with_fresh_session(&base, &mut prng);
        variant.artifact = base.artifact;
        variant.generation = base.generation.clone();
        variant.range_start = base.range_start;
        variant.range_end = base.range_end;
        variant.blob = base.blob;
        assert_ne!(
            variant.occurrence(),
            base_occurrence,
            "session change collided"
        );

        let mut variant = DerivedIdentities::generate(&mut prng);
        variant.session = base.session;
        variant.artifact = ArtifactHash::parse(&distinct(&base.artifact.to_hex(), || {
            hex_text(&mut prng, 64)
        }))
        .expect("generated hex parses");
        variant.generation = base.generation.clone();
        variant.range_start = base.range_start;
        variant.range_end = base.range_end;
        variant.blob = base.blob;
        assert_ne!(
            variant.occurrence(),
            base_occurrence,
            "artifact change collided"
        );

        let mut variant = DerivedIdentities::generate(&mut prng);
        variant.session = base.session;
        variant.artifact = base.artifact;
        variant.generation =
            GenerationId::parse(&distinct(&base.generation.as_str().to_owned(), || {
                uuid_text(&mut prng, 7)
            }))
            .expect("generated uuid-v7 parses");
        variant.range_start = base.range_start;
        variant.range_end = base.range_end;
        variant.blob = base.blob;
        assert_ne!(
            variant.occurrence(),
            base_occurrence,
            "generation change collided"
        );

        let mut variant = DerivedIdentities::generate(&mut prng);
        variant.session = base.session;
        variant.artifact = base.artifact;
        variant.generation = base.generation.clone();
        variant.range_start = base.range_start;
        variant.range_end = base.range_end + 1;
        variant.blob = base.blob;
        assert_ne!(
            variant.occurrence(),
            base_occurrence,
            "range_end change collided"
        );

        let mut variant = DerivedIdentities::generate(&mut prng);
        variant.session = base.session;
        variant.artifact = base.artifact;
        variant.generation = base.generation.clone();
        variant.range_start = base.range_start;
        variant.range_end = base.range_end;
        variant.blob =
            BlobDigest::parse(&distinct(&base.blob.to_hex(), || hex_text(&mut prng, 64)))
                .expect("generated hex parses");
        assert_ne!(
            variant.occurrence(),
            base_occurrence,
            "blob change collided"
        );

        let event_kind = occurrence_id(
            &base.session,
            &base.artifact,
            &base.generation,
            RangeKind::Event,
            base.range_start,
            base.range_end,
            &base.blob,
        );
        assert_ne!(event_kind, base_occurrence, "range kind change collided");
    }
}

/// The export-selection digest is order-insensitive (any permutation of
/// the same occurrence keys digests identically — the canonicalization the
/// construction owes its callers) yet member-sensitive (adding or removing
/// one key changes it) and tenant-pinned.
#[test]
fn export_selection_digest_is_order_insensitive_but_member_sensitive() {
    let mut prng = Prng::new(0x5EED_F009);
    for _ in 0..256 {
        let tenant = TenantId::parse(&uuid_text(&mut prng, 4)).expect("generated uuid-v4 parses");
        let inventory = BlobDigest::parse(&hex_text(&mut prng, 64)).expect("generated hex parses");
        let keys: Vec<String> = (0..prng.below_usize(8))
            .map(|_| {
                format!(
                    "tenants/{}/v1/raw/blobs/zstd-v1/sha256/ab/{}.zst",
                    tenant.as_str(),
                    hex_text(&mut prng, 64)
                )
            })
            .collect();
        let references: Vec<&str> = keys.iter().map(String::as_str).collect();
        let base = export_selection_digest(&tenant, &inventory, &references);

        let mut shuffled = keys.clone();
        let mut index = shuffled.len();
        while index > 1 {
            index -= 1;
            shuffled.swap(index, prng.below_usize(index + 1));
        }
        let shuffled_references: Vec<&str> = shuffled.iter().map(String::as_str).collect();
        assert_eq!(
            export_selection_digest(&tenant, &inventory, &shuffled_references),
            base,
            "key order changed the export digest"
        );

        let other_tenant = TenantId::parse(&distinct(&tenant.as_str().to_owned(), || {
            uuid_text(&mut prng, 4)
        }))
        .expect("generated uuid-v4 parses");
        assert_ne!(
            export_selection_digest(&other_tenant, &inventory, &shuffled_references),
            base,
            "tenant change collided"
        );

        let mut extended = keys.clone();
        extended.push(format!(
            "tenants/{}/v1/raw/blobs/zstd-v1/sha256/ab/{}.zst",
            tenant.as_str(),
            hex_text(&mut prng, 64)
        ));
        let extended_references: Vec<&str> = extended.iter().map(String::as_str).collect();
        assert_ne!(
            export_selection_digest(&tenant, &inventory, &extended_references),
            base,
            "an added key did not change the digest"
        );

        if !keys.is_empty() {
            let mut reduced = keys.clone();
            reduced.pop();
            let reduced_references: Vec<&str> = reduced.iter().map(String::as_str).collect();
            assert_ne!(
                export_selection_digest(&tenant, &inventory, &reduced_references),
                base,
                "a removed key did not change the digest"
            );
        }
    }
}

/// Object keys round-trip their own parse, stay inside their tenant
/// prefix, shard by the digest they carry, contain no empty or dot
/// segment, and never collide across distinct digests — the properties
/// that keep a derived key from escaping the layout the storage profile
/// pins.
#[test]
fn object_keys_round_trip_and_stay_inside_their_tenant_prefix() {
    let mut prng = Prng::new(0x5EED_F00A);
    for _ in 0..256 {
        let tenant = TenantId::parse(&uuid_text(&mut prng, 4)).expect("generated uuid-v4 parses");
        let origin = ClientId::parse(&uuid_text(&mut prng, 4)).expect("generated uuid-v4 parses");
        let harness = HarnessId::parse(&short_token(&mut prng)).expect("generated token parses");
        let blob = BlobDigest::parse(&hex_text(&mut prng, 64)).expect("generated hex parses");
        let session = SessionHash::parse(&hex_text(&mut prng, 64)).expect("generated hex parses");
        let occurrence = OccurrenceId::parse(&hex_text(&mut prng, 64)).expect("hex parses");
        let attestation = AttestationId::parse(&hex_text(&mut prng, 64)).expect("hex parses");

        let blob_key = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &blob);
        let blob_text = blob_key.as_str().to_owned();
        assert_eq!(
            BlobObjectKey::parse(&blob_text)
                .expect("blob key round-trips")
                .as_str(),
            blob_text
        );
        let occurrence_key =
            OccurrenceObjectKey::new(&tenant, &origin, &harness, &session, &occurrence);
        let occurrence_text = occurrence_key.as_str().to_owned();
        assert_eq!(
            OccurrenceObjectKey::parse(&occurrence_text)
                .expect("occurrence key round-trips")
                .as_str(),
            occurrence_text
        );
        let attestation_key = AttestationObjectKey::new(&tenant, &occurrence, &attestation);
        let attestation_text = attestation_key.as_str().to_owned();
        assert_eq!(
            AttestationObjectKey::parse(&attestation_text)
                .expect("attestation key round-trips")
                .as_str(),
            attestation_text
        );

        let prefix = format!("tenants/{}/v1/raw/", tenant.as_str());
        for key in [&blob_text, &occurrence_text, &attestation_text] {
            assert!(
                key.starts_with(&prefix),
                "key escaped its tenant prefix: {key}"
            );
            for segment in key.split('/') {
                assert!(!segment.is_empty(), "empty segment in {key}");
                assert_ne!(segment, "..", "dot segment in {key}");
            }
        }
        assert!(
            blob_text.contains(&format!("sha256/{}/{}", &blob.to_hex()[..2], blob.to_hex())),
            "blob key lost its sharded digest"
        );

        let other_blob = BlobDigest::parse(&distinct(&blob.to_hex(), || hex_text(&mut prng, 64)))
            .expect("generated hex parses");
        assert_ne!(
            BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &other_blob).as_str(),
            blob_text,
            "distinct digests collided into one blob key"
        );
    }
}

// ---------------------------------------------------------------------------
// Leg 5 — multipart framing (the request side)
// ---------------------------------------------------------------------------

fn request_framing(boundary: &str) -> RequestFraming {
    RequestFraming::validate_content_type(&format!("multipart/related; boundary={boundary}"))
        .expect("the generated content type is valid")
}

/// A body framed exactly as the corpus pins: per part, the boundary line,
/// one lowercase `content-type` header, a blank line, the part bytes, and
/// CRLF; the closing boundary with `--` and CRLF ends the body.
fn framed_body(boundary: &str, parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (media_type, bytes) in parts {
        body.extend_from_slice(
            format!("--{boundary}\r\ncontent-type: {media_type}\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

/// A source handing out seeded-random small slices per pull, so every
/// fuzzed body crosses arbitrary refill edges inside the framing window.
struct Chunked<'a> {
    body: &'a [u8],
    state: u64,
}

impl<'a> Chunked<'a> {
    fn new(body: &'a [u8], seed: u64) -> Self {
        Self {
            body,
            state: seed | 1,
        }
    }
}

impl ByteSource for Chunked<'_> {
    fn pull(&mut self, window: &mut [u8]) -> Result<usize, io::ErrorKind> {
        if self.body.is_empty() {
            return Ok(0);
        }
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        let max = window.len().min(self.body.len()).min(64);
        let take = (1 + usize::try_from(x).expect("u64 fits usize") % max).min(self.body.len());
        window[..take].copy_from_slice(&self.body[..take]);
        self.body = &self.body[take..];
        Ok(take)
    }
}

/// Content-type validation never panics: every header over the boundary
/// charset (1–70 characters) is accepted with its boundary intact, and
/// every violation — a boundary carrying the marker plus an out-of-charset
/// byte, an empty boundary, an overlong boundary, an extra parameter, a
/// soup header — fails closed with a content-free error (the marker rides
/// in the rejected header as the leak probe).
#[test]
fn content_type_validation_never_panics_and_fails_closed() {
    const PREFIX: &str = "multipart/related; boundary=";
    let mut prng = Prng::new(0x5EED_F00B);
    for _ in 0..384 {
        let boundary = boundary_text(&mut prng);
        let header = format!("{PREFIX}{boundary}");
        let framing = RequestFraming::validate_content_type(&header)
            .unwrap_or_else(|error| panic!("valid header rejected: {error:?}"));
        assert_eq!(framing.boundary(), boundary);
    }
    for _ in 0..384 {
        let hostile = match prng.below(7) {
            0 => format!("multipart/related; boundary={FUZZ_MARKER}@"),
            1 => "multipart/related; boundary=".to_owned(),
            2 => format!("{PREFIX}{}", "a".repeat(71)),
            3 => format!("{PREFIX}{FUZZ_MARKER}; charset=utf-8"),
            4 => format!("multipart/form-data; boundary={}", boundary_text(&mut prng)),
            5 => format!("Multipart/Related; boundary={}", boundary_text(&mut prng)),
            _ => {
                let soup_len = 1 + prng.below_usize(64);
                soup(&mut prng, soup_len).into_iter()
            }
            .filter(|byte| *byte != 0)
            .map(char::from)
            .collect(),
        };
        match RequestFraming::validate_content_type(&hostile) {
            Ok(framing) => {
                // Only charset-clean boundaries can pass; the marker never
                // does, and the retained boundary is the suffix verbatim.
                assert!(!framing.boundary().contains(FUZZ_MARKER));
                assert_eq!(framing.boundary(), &hostile[PREFIX.len()..]);
            }
            Err(error) => {
                assert_debug_content_free("content-type rejection", &error);
            }
        }
    }
}

/// Split one body into its two parts and drain part two, bounding the
/// payload buffering at the documented ceiling: the composed outcome every
/// framing leg measures.
fn split_and_drain(
    framing: &RequestFraming,
    body: &[u8],
    seed: u64,
) -> Result<(Vec<u8>, Vec<u8>), TwoPartError> {
    let mut request = TwoPartRequest::new(framing, Chunked::new(body, seed));
    let part_one = request.envelope()?;
    let mut stream = request.payload()?;
    let mut drained = Vec::new();
    let mut read_buffer = [0u8; 97];
    loop {
        assert!(
            stream.buffered_bytes() <= 2 * FRAMING_WINDOW_BYTES,
            "payload buffering crossed the framing-window ceiling"
        );
        match stream.read(&mut read_buffer) {
            Ok(0) => break,
            Ok(n) => drained.extend_from_slice(&read_buffer[..n]),
            Err(error) => {
                assert_debug_content_free("payload read failure", &error);
                return Err(TwoPartError::Framing(FramingError::UnexpectedEndOfStream));
            }
        }
    }
    stream.finish()?;
    Ok((part_one, drained))
}

/// The unmutated body splits exactly through arbitrary refill edges: part
/// one byte-for-byte, part two byte-identical, the split closing exactly.
#[test]
fn the_well_formed_body_splits_exactly_through_random_refills() {
    let envelope_bytes = baseline_envelope_bytes();
    let payload: Vec<u8> = format!("payload-{FUZZ_MARKER}-").into_bytes();
    let body = framed_body(
        BOUNDARY,
        &[
            (ENVELOPE_PART_MEDIA_TYPE, &envelope_bytes),
            (IDENTITY_MEDIA_TYPE, &payload),
        ],
    );
    let framing = request_framing(BOUNDARY);
    for seed in 0x5EED_F00C..0x5EED_F00C + 16 {
        let (part_one, drained) = split_and_drain(&framing, &body, seed)
            .unwrap_or_else(|error| panic!("unmutated body split failed: {error:?}"));
        assert_eq!(part_one, envelope_bytes, "part one was altered in transit");
        assert_eq!(drained, payload, "payload bytes were altered in transit");
    }
}

/// The two-part split over mutated bodies: no panic, every rejection
/// content-free, and any acceptance a structurally exact split — part one
/// never grows past its cap and the payload never buffers past the
/// framing-window ceiling whatever the refill edges are.
#[test]
fn two_part_split_over_mutation_stays_bounded_and_content_free() {
    let envelope_bytes = baseline_envelope_bytes();
    let payload: Vec<u8> = format!("payload-{FUZZ_MARKER}-").into_bytes();
    let body = framed_body(
        BOUNDARY,
        &[
            (ENVELOPE_PART_MEDIA_TYPE, &envelope_bytes),
            (IDENTITY_MEDIA_TYPE, &payload),
        ],
    );
    let framing = request_framing(BOUNDARY);
    let mut prng = Prng::new(0x5EED_F00D);
    let mut accepted = 0;
    for _ in 0..384 {
        let hostile = mutate(&body, &mut prng);
        match split_and_drain(&framing, &hostile, prng.next_u64()) {
            Ok((part_one, drained)) => {
                accepted += 1;
                // A split acceptance is framing-level only; part one may
                // be any bytes, but never the empty part and never both
                // parts collapsed into one.
                assert!(!part_one.is_empty(), "an empty envelope part was accepted");
                assert!(
                    drained.len()
                        <= payload.len() + envelope_bytes.len() + 4 * FRAMING_WINDOW_BYTES,
                    "the drained payload outgrew the body"
                );
            }
            Err(error) => {
                assert_debug_content_free("two-part rejection", &error);
            }
        }
    }
    assert!(accepted > 0, "mutation never produced a splittable body");
}

/// The envelope-part cap transitions exactly: a part one of exactly the
/// configured cap is accepted byte-for-byte, and one byte less of cap
/// refuses with the cap named — before any further body byte is read.
#[test]
fn envelope_part_cap_transitions_exactly_at_the_boundary() {
    let part_one: Vec<u8> = vec![b'e'; 2048];
    let payload = b"p";
    let body = framed_body(
        BOUNDARY,
        &[
            (ENVELOPE_PART_MEDIA_TYPE, &part_one),
            (IDENTITY_MEDIA_TYPE, payload),
        ],
    );
    let framing = request_framing(BOUNDARY);
    let at_cap_len = u64::try_from(part_one.len()).expect("part size fits u64");
    for seed in [0x11, 0x22, 0x33] {
        let mut at_cap =
            TwoPartRequest::with_envelope_cap(&framing, Chunked::new(&body, seed), at_cap_len);
        assert_eq!(
            at_cap
                .envelope()
                .expect("exactly at the cap is lawful")
                .len(),
            part_one.len()
        );
        let mut below_cap =
            TwoPartRequest::with_envelope_cap(&framing, Chunked::new(&body, seed), at_cap_len - 1);
        match below_cap.envelope() {
            Err(TwoPartError::EnvelopeExceedsCap { limit_bytes }) => {
                assert_eq!(limit_bytes, at_cap_len - 1);
            }
            other => panic!("one below the cap gave {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Leg 6 — the composed path: parse, decode, and the limit transitions
// ---------------------------------------------------------------------------

/// The pinned-profile zstd frame of `canonical`, exactly as a client
/// transmits it.
fn zstd_frame(canonical: &[u8]) -> Vec<u8> {
    let mut encoder = ZstdV1Encoder::new(u64::try_from(canonical.len()).expect("fits u64"))
        .expect("profile encoder builds");
    let mut frame = Vec::new();
    encoder.update(canonical, &mut frame).expect("frame body");
    encoder.finish(&mut frame).expect("frame epilogue");
    frame
}

/// A canonical payload mixing compressible and incompressible regions and
/// carrying the marker.
fn canonical_payload(prng: &mut Prng) -> Vec<u8> {
    let mut payload = Vec::new();
    for _ in 0..4 {
        let region = prng.below_usize(512);
        payload.extend((0..region).map(|_| prng.byte()));
        payload.extend(std::iter::repeat_n(b'z', prng.below_usize(512)));
    }
    payload.extend_from_slice(FUZZ_MARKER.as_bytes());
    payload
}

/// A framed identity or zstd attempt around the baseline envelope and a
/// transported payload.
fn framed_attempt(boundary: &str, encoding: TransportEncoding, payload: &[u8]) -> Vec<u8> {
    let media = match encoding {
        TransportEncoding::Identity => IDENTITY_MEDIA_TYPE,
        TransportEncoding::Zstd => "application/zstd",
    };
    framed_body(
        boundary,
        &[
            (ENVELOPE_PART_MEDIA_TYPE, &baseline_envelope_bytes()),
            (media, payload),
        ],
    )
}

/// Drain a decoder to its end, asserting the closed-stays-closed contract
/// on the first failure.
fn drain<R: Read>(decoder: &mut TransportDecoder<R>) -> Result<Vec<u8>, TransportDecodeError> {
    let mut out = Vec::new();
    loop {
        match decoder.next_chunk() {
            Ok(Some(chunk)) => out.extend_from_slice(chunk),
            Ok(None) => return Ok(out),
            Err(first) => {
                match decoder.next_chunk() {
                    Err(second) => assert_eq!(
                        second, first,
                        "a failed transport stage re-yields its first failure"
                    ),
                    other => panic!("a failed stage resumed with {other:?}"),
                }
                return Err(first);
            }
        }
    }
}

/// The composed well-formed path streams the exact canonical bytes: the
/// envelope splits, the transport decode (identity and zstd) reproduces
/// the payload byte-for-byte, the totals match, and the stage reports
/// drained. This is the positive control every mutation leg measures
/// against.
#[test]
fn well_formed_attempts_stream_the_exact_canonical_bytes() {
    let mut prng = Prng::new(0x5EED_F00E);
    let framing = request_framing(BOUNDARY);
    for _ in 0..16 {
        let canonical = canonical_payload(&mut prng);
        for encoding in [TransportEncoding::Identity, TransportEncoding::Zstd] {
            let transported = match encoding {
                TransportEncoding::Identity => canonical.clone(),
                TransportEncoding::Zstd => zstd_frame(&canonical),
            };
            let body = framed_attempt(BOUNDARY, encoding, &transported);
            let (envelope, payload) =
                parse_ingest_with_cap(&framing, Chunked::new(&body, prng.next_u64()), 65_536)
                    .expect("the well-formed attempt parses");
            envelope
                .verify_identities()
                .expect("the parsed envelope is self-consistent");
            let mut decoder =
                TransportDecoder::new(encoding, payload, DecodeLimits::new(268_435_456, 100))
                    .expect("the stage builds");
            let drained = drain(&mut decoder).expect("the well-formed attempt decodes");
            assert!(decoder.is_drained(), "the stage reports drained");
            assert_eq!(
                drained, canonical,
                "decoded bytes differ from the canonical"
            );
            assert_eq!(
                decoder.canonical_bytes(),
                u64::try_from(canonical.len()).expect("fits u64")
            );
            assert_eq!(
                decoder.transport_bytes(),
                u64::try_from(transported.len()).expect("fits u64")
            );
        }
    }
}

/// Mutated framed bodies fail closed end to end: through the composed
/// parse-then-decode path no mutation panics, every rejection carries a
/// grammar-clean content-free message, and any acceptance is
/// self-consistent — the envelope re-derives its identities and the
/// decoder's totals match the bytes it emitted. Nothing that failed ever
/// produces canonical bytes again.
#[test]
fn mutated_framed_bodies_fail_closed_without_ever_committing() {
    let mut prng = Prng::new(0x5EED_F00F);
    let framing = request_framing(BOUNDARY);
    let canonical = canonical_payload(&mut prng);
    let body = framed_attempt(BOUNDARY, TransportEncoding::Zstd, &zstd_frame(&canonical));
    let mut accepted = 0;
    for _ in 0..256 {
        let hostile = mutate(&body, &mut prng);
        match parse_ingest_with_cap(&framing, Chunked::new(&hostile, prng.next_u64()), 65_536) {
            Ok((envelope, payload)) => {
                accepted += 1;
                envelope
                    .verify_identities()
                    .expect("an accepted envelope re-derives its identities");
                let mut decoder = TransportDecoder::new(
                    TransportEncoding::Zstd,
                    payload,
                    DecodeLimits::new(268_435_456, 100),
                )
                .expect("the stage builds");
                match drain(&mut decoder) {
                    Ok(bytes) => {
                        assert_eq!(
                            decoder.canonical_bytes(),
                            u64::try_from(bytes.len()).expect("fits u64"),
                            "totals diverged from the emitted bytes"
                        );
                    }
                    Err(error) => {
                        assert_debug_content_free("transport rejection", &error);
                    }
                }
            }
            Err(rejection) => {
                let message = rejection.error.message();
                assert!(
                    SafeMessage::parse(message.as_str()).is_ok(),
                    "rendered message left the safe grammar"
                );
                assert_rendering_content_free("ingest rejection message", message.as_str());
                assert_debug_content_free("ingest rejection", &rejection.error);
            }
        }
    }
    assert!(accepted > 0, "no mutation left the request parseable");
}

/// Transport limit transitions are exact: at the record cap the attempt
/// decodes, one byte below it the refusal names the cap; the expansion
/// ratio admits a truthful frame and refuses a compressible one under a
/// ratio tighter than its true expansion.
#[test]
fn transport_limit_transitions_are_exact_at_record_cap_and_ratio() {
    let mut prng = Prng::new(0x5EED_F010);
    let framing = request_framing(BOUNDARY);
    let canonical = canonical_payload(&mut prng);
    let body = framed_attempt(BOUNDARY, TransportEncoding::Identity, &canonical);
    let len = u64::try_from(canonical.len()).expect("fits u64");

    let (_, payload_at) = parse_ingest_with_cap(&framing, Chunked::new(&body, 0x51), 65_536)
        .expect("the attempt parses");
    let mut at_cap = TransportDecoder::new(
        TransportEncoding::Identity,
        payload_at,
        DecodeLimits::new(len, 100),
    )
    .expect("the stage builds");
    assert_eq!(
        u64::try_from(
            drain(&mut at_cap)
                .expect("exactly at the cap decodes")
                .len()
        )
        .expect("fits u64"),
        len
    );

    let (_, payload_below) = parse_ingest_with_cap(&framing, Chunked::new(&body, 0x52), 65_536)
        .expect("the attempt parses");
    let mut below_cap = TransportDecoder::new(
        TransportEncoding::Identity,
        payload_below,
        DecodeLimits::new(len - 1, 100),
    )
    .expect("the stage builds");
    match drain(&mut below_cap) {
        Err(TransportDecodeError::RecordTooLarge {
            actual_bytes,
            limit_bytes,
        }) => {
            assert_eq!(limit_bytes, len - 1);
            assert!(actual_bytes >= limit_bytes);
        }
        other => panic!("one below the cap gave {other:?}"),
    }

    // Ratio: zeros expand over a thousand-fold, so a cap at the measured
    // expansion decodes them and a 1:1 ratio refuses mid-stream with the
    // splittable class.
    let zeros = vec![0u8; 65_536];
    let frame = zstd_frame(&zeros);
    let measured_ratio = u64::try_from(zeros.len() / frame.len()).expect("fits u64") + 1;
    let mut generous = TransportDecoder::new(
        TransportEncoding::Zstd,
        Cursor::new(frame.clone()),
        DecodeLimits::new(268_435_456, measured_ratio),
    )
    .expect("the stage builds");
    assert_eq!(
        drain(&mut generous)
            .expect("a truthful frame decodes under the default ratio")
            .len(),
        zeros.len()
    );
    let mut tight = TransportDecoder::new(
        TransportEncoding::Zstd,
        Cursor::new(frame),
        DecodeLimits::new(268_435_456, 1),
    )
    .expect("the stage builds");
    match drain(&mut tight) {
        Err(TransportDecodeError::ExpansionRatioExceeded { max_ratio }) => {
            assert_eq!(max_ratio, 1);
        }
        other => panic!("the 1:1 ratio gave {other:?}"),
    }
}

/// Hostile transport input stays closed and bounded: mutated frames never
/// panic and every failure is a closed, content-free frame rejection, and
/// raw soup under a tiny record cap emits no byte past the cap before the
/// refusal fires.
#[test]
fn hostile_transport_input_stays_closed_and_bounded() {
    let mut prng = Prng::new(0x5EED_F011);
    let canonical = canonical_payload(&mut prng);
    let frame = zstd_frame(&canonical);
    let mut frame_rejections = 0;
    for _ in 0..192 {
        let hostile = mutate(&frame, &mut prng);
        let mut decoder = TransportDecoder::new(
            TransportEncoding::Zstd,
            Cursor::new(hostile),
            DecodeLimits::new(268_435_456, 100),
        )
        .expect("the stage builds");
        match drain(&mut decoder) {
            Ok(bytes) => {
                assert_eq!(
                    decoder.canonical_bytes(),
                    u64::try_from(bytes.len()).expect("fits u64"),
                    "totals diverged from the emitted bytes"
                );
            }
            Err(error) => {
                if matches!(error, TransportDecodeError::MalformedFrame { .. }) {
                    frame_rejections += 1;
                }
                assert_debug_content_free("transport frame rejection", &error);
            }
        }
    }
    assert!(
        frame_rejections > 0,
        "no mutated frame was rejected as malformed"
    );

    for _ in 0..64 {
        let soup_len = prng.below_usize(256);
        let hostile = soup(&mut prng, soup_len);
        let mut decoder = TransportDecoder::new(
            TransportEncoding::Zstd,
            Cursor::new(hostile),
            DecodeLimits::new(64, 100),
        )
        .expect("the stage builds");
        let mut emitted = 0u64;
        loop {
            match decoder.next_chunk() {
                Ok(Some(chunk)) => {
                    emitted += u64::try_from(chunk.len()).expect("fits u64");
                    assert!(emitted <= 64, "the stage emitted past its record cap");
                }
                Ok(None) => break,
                Err(error) => {
                    assert_debug_content_free("bounded soup rejection", &error);
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Leg 7 — receipt parsing
// ---------------------------------------------------------------------------

/// The fixed seeds the receipt leg's keys load from; the public halves
/// are derived from the same constants, so the pinned root matches the
/// authority that certified the receipt key.
const RECEIPT_SIGNING_SEED: [u8; 32] = [0x42; 32];
const RECEIPT_AUTHORITY_SEED: [u8; 32] = [0x7A; 32];
const RECEIPT_TENANT: &str = "2b3c4d5e-6f70-4a1b-9c2d-3e4f5a6b7c8d";
const RECEIPT_WINDOW_START: &str = "2026-01-01T00:00:00Z";
const RECEIPT_COMMIT_TIME: &str = "2026-01-15T12:00:00Z";

/// Write one 32-byte seed as a mode-restricted file and return its
/// protected reference. The file is removed by the caller once the key
/// material is loaded — the same startup shape a replica follows.
fn seed_reference(seed: [u8; 32], slot: u8) -> (ProtectedReference, std::path::PathBuf) {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!(
        "archivist-fuzz-receipt-{}-{slot}.key",
        std::process::id()
    ));
    let mut file = std::fs::File::create(&path).expect("seed file");
    file.write_all(&seed).expect("seed bytes");
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("seed mode");
    let reference =
        ProtectedReference::parse(&format!("file:{}", path.display())).expect("reference");
    (reference, path)
}

/// One certified receipt-key schedule pinned to the authority root this
/// suite derives from the same seed.
fn receipt_schedule_and_root() -> (ReceiptKeySchedule, PinnedAuthorityRoot) {
    let tenant = TenantId::parse(RECEIPT_TENANT).expect("tenant grammar");
    let (signing_reference, signing_path) = seed_reference(RECEIPT_SIGNING_SEED, 1);
    let signing = ReceiptSigningKey::from_secret_reference(tenant.clone(), &signing_reference)
        .expect("receipt key loads");
    let (authority_reference, authority_path) = seed_reference(RECEIPT_AUTHORITY_SEED, 2);
    let authority = AuthoritySigner::from_secret_reference(tenant.clone(), &authority_reference)
        .expect("authority key loads");
    let start = Timestamp::parse(RECEIPT_WINDOW_START).expect("window start");
    let certified = CertifiedReceiptKey::certify(signing, &authority, start.clone(), start)
        .expect("certification");
    let _ = std::fs::remove_file(signing_path);
    let _ = std::fs::remove_file(authority_path);
    let root_public =
        Ed25519PublicKey::from_raw(SigningKey::from_seed(RECEIPT_AUTHORITY_SEED).public_key());
    (
        ReceiptKeySchedule::new(certified),
        PinnedAuthorityRoot::new(tenant, root_public),
    )
}

/// One signed receipt over generated facts, carrying the fuzz marker in a
/// signed member so the content-free property is observable.
fn signed_receipt(schedule: &ReceiptKeySchedule, prng: &mut Prng) -> Receipt {
    let mut object = Object::new();
    object.set("tenant_id", Value::Text(RECEIPT_TENANT.to_owned()));
    object.set("request_id", Value::Text(uuid_text(prng, 7)));
    object.set("blob_digest", Value::Text(hex_text(prng, 64)));
    object.set(
        "blob_object_key",
        Value::Text(format!(
            "tenants/{RECEIPT_TENANT}/v1/raw/blobs/zstd-v1/sha256/ab/{}.zst",
            hex_text(prng, 64)
        )),
    );
    object.set("note", Value::Text(FUZZ_MARKER.to_owned()));
    object.set("commit_time", Value::Text(RECEIPT_COMMIT_TIME.to_owned()));
    schedule.sign_receipt(object).expect("the schedule signs")
}

/// Receipt parsing absorbs canonical-neutral transmission (whitespace,
/// reordered members, `\u` escapes): parse accepts it, the canonical bytes
/// come back identical, and the signature still verifies — proof the
/// canonical form is the signed form. The signer refuses protected
/// members outright.
#[test]
fn receipt_parse_and_verify_survive_canonical_neutral_mutation() {
    let (schedule, root) = receipt_schedule_and_root();
    let mut prng = Prng::new(0x5EED_F012);
    for _ in 0..256 {
        let receipt = signed_receipt(&schedule, &mut prng);
        let canonical = receipt.canonical_bytes();
        let parsed = Receipt::parse(&canonical).expect("canonical bytes parse");
        assert_eq!(parsed.canonical_bytes(), canonical);

        let value = json::parse(&canonical).expect("canonical bytes are JSON");
        let mut transmitted = String::new();
        write_transmitted(&value, &mut transmitted, &mut prng);
        let reparsed = Receipt::parse(transmitted.as_bytes())
            .unwrap_or_else(|error| panic!("transmission form rejected: {error}"));
        assert_eq!(reparsed.canonical_bytes(), canonical);
        let _ = reparsed
            .verify(&root, |_key_id| None)
            .expect("the signature covers the canonical form, not the transmission");
    }

    // The signer refuses a caller-supplied protected member.
    let mut object = Object::new();
    object.set("tenant_id", Value::Text(RECEIPT_TENANT.to_owned()));
    object.set("commit_time", Value::Text(RECEIPT_COMMIT_TIME.to_owned()));
    object.set("signature", Value::Text(hex_text(&mut prng, 128)));
    match schedule.sign_receipt(object) {
        Err(ReceiptKeyError::ProtectedField) => {}
        other => panic!("a protected member was signed: {other:?}"),
    }
}

/// Canonical-breaking mutations and soup fail closed: any byte change to
/// the receipt either breaks the parse or breaks the verification, a
/// canonical-neutral mutation by luck still verifies, and no error
/// rendering carries the marker. Nothing ever panics.
#[test]
fn receipt_mutations_and_soup_fail_closed() {
    let (schedule, root) = receipt_schedule_and_root();
    let mut prng = Prng::new(0x5EED_F013);
    let mut rejected = 0;
    for _ in 0..384 {
        let receipt = signed_receipt(&schedule, &mut prng);
        let canonical = receipt.canonical_bytes();
        let hostile = mutate(&canonical, &mut prng);
        match Receipt::parse(&hostile) {
            Ok(parsed) => {
                if parsed.canonical_bytes() == canonical {
                    // A canonical-neutral mutation: verification must hold.
                    let _ = parsed
                        .verify(&root, |_key_id| None)
                        .expect("a canonical-neutral mutation broke verification");
                } else {
                    rejected += 1;
                    match parsed.verify(&root, |_key_id| None) {
                        Ok(_) => panic!("a canonical-breaking mutation verified"),
                        Err(error) => {
                            assert_error_content_free("receipt rejection", error);
                        }
                    }
                }
            }
            Err(error) => {
                rejected += 1;
                assert_error_content_free("receipt parse rejection", error);
            }
        }
    }
    assert!(rejected > 0, "no receipt mutation was refused");

    for _ in 0..256 {
        let soup_len = prng.below_usize(512);
        let hostile = soup(&mut prng, soup_len);
        match Receipt::parse(&hostile) {
            Ok(_) => panic!("soup parsed as a receipt"),
            Err(error) => {
                assert_eq!(error, ReceiptKeyError::MalformedRecord);
                assert_error_content_free("receipt soup rejection", error);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Leg 8 — the multipart writer: commit gating under cadence fuzz
// ---------------------------------------------------------------------------

/// A no-dependency executor for the mock futures: every mock future
/// completes without pending, so first-poll-until-ready terminates.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(output) => return output,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// A raw writer recording every part, commit, and abort, in the shape of
/// the multipart module's own mock. `Mutex` (not `RefCell`) so the
/// trait's `Send` futures hold.
#[derive(Default)]
struct RecordingStore {
    state: std::sync::Mutex<RecordingState>,
}

#[derive(Default)]
struct RecordingState {
    parts: Vec<(String, u16, usize)>,
    completes: Vec<String>,
    aborts: Vec<String>,
    next_upload: u32,
}

fn blob_key(prng: &mut Prng) -> BlobObjectKey {
    BlobObjectKey::new(
        &TenantId::parse(&uuid_text(prng, 4)).expect("generated uuid-v4 parses"),
        StorageProfile::ZstdV1,
        &BlobDigest::parse(&hex_text(prng, 64)).expect("generated hex parses"),
    )
}

impl RawWriteStore for RecordingStore {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            conditional_create: ConditionalCreate::Unavailable,
            stored_checksum: StoredChecksum::Sha256,
            versioning: VersioningState::Unknown,
            server_side_encryption: EncryptionState::Unavailable,
        }
    }

    async fn write_manifest(
        &self,
        key: &ManifestKey,
        bytes: &[u8],
    ) -> Result<StorageOutcome, StorageError> {
        self.state
            .lock()
            .expect("mock lock")
            .parts
            .push((key.as_str().to_owned(), 0, bytes.len()));
        Ok(StorageOutcome::Created)
    }

    async fn begin_multipart(
        &self,
        _blob: &BlobObjectKey,
    ) -> Result<MultipartUploadId, StorageError> {
        let mut state = self.state.lock().expect("mock lock");
        state.next_upload += 1;
        let id = MultipartUploadId::parse(&format!("fuzz-upload-{}", state.next_upload))
            .expect("grammatical mock id");
        Ok(id)
    }

    async fn write_part(
        &self,
        upload: &MultipartUploadId,
        part: PartNumber,
        bytes: &[u8],
    ) -> Result<PartCommitment, StorageError> {
        let mut state = self.state.lock().expect("mock lock");
        state
            .parts
            .push((upload.as_str().to_owned(), part.get(), bytes.len()));
        let tag = ObjectTag::parse(&format!("\"tag-{}\"", part.get())).expect("tag grammar");
        Ok(PartCommitment::new(part, tag))
    }

    async fn commit_multipart(
        &self,
        upload: &MultipartUploadId,
        _parts: &[PartCommitment],
    ) -> Result<StorageOutcome, StorageError> {
        let mut state = self.state.lock().expect("mock lock");
        state.completes.push(upload.as_str().to_owned());
        Ok(StorageOutcome::Created)
    }

    async fn abort_multipart(&self, upload: &MultipartUploadId) -> Result<(), StorageError> {
        let mut state = self.state.lock().expect("mock lock");
        state.aborts.push(upload.as_str().to_owned());
        Ok(())
    }
}

/// The totals the cadence fuzz crosses: every part-boundary neighborhood.
const CADENCE_TOTALS: [usize; 7] = [
    0,
    1,
    PART_BYTES - 1,
    PART_BYTES,
    PART_BYTES + 1,
    2 * PART_BYTES,
    2 * PART_BYTES + 3,
];

/// One writer session over `total` bytes in random chunk cadences. The
/// per-session invariants — buffering below one part, the exact part
/// count, and `uploaded_bytes` equal to the stream — hold on the writer
/// itself; the part-shape invariants are asserted by the caller against
/// the recording.
fn run_cadence(store: &RecordingStore, total: usize, prng: &mut Prng) {
    let open = OpenUploads::new();
    let mut writer =
        block_on(MultipartWriter::begin(store, &blob_key(prng), &open)).expect("mock begin");
    let marker = FUZZ_MARKER.as_bytes().to_vec();
    let mut written = 0;
    while written < total {
        let remaining = total - written;
        let chunk_len = match prng.below(4) {
            0 => 1 + prng.below_usize(16),
            1 => remaining,
            2 => remaining.min(PART_BYTES + prng.below_usize(3)),
            _ => remaining.min(1 + prng.below_usize(2 * PART_BYTES)),
        };
        let mut chunk = vec![0xA5; chunk_len];
        if chunk_len >= marker.len() + 2 {
            chunk[..marker.len()].clone_from_slice(&marker);
        }
        block_on(writer.write_chunk(&chunk)).expect("chunks upload");
        written += chunk_len;
        assert!(
            writer.buffered_bytes() < PART_BYTES,
            "buffering reached a full part mid-stream"
        );
    }
    block_on(writer.finish()).expect("finish flushes the tail");
    assert_eq!(writer.part_count(), total.div_ceil(PART_BYTES));
    assert_eq!(
        writer.uploaded_bytes(),
        u64::try_from(total).expect("fits u64")
    );
    assert!(writer.buffered_bytes() < PART_BYTES);

    if total == 0 {
        let error = block_on(writer.commit()).expect_err("an empty stream cannot commit");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_error_content_free("empty-stream refusal", error);
    } else {
        let outcome = block_on(writer.commit()).expect("commit after validation");
        assert_eq!(outcome, StorageOutcome::Created);
    }
    assert_eq!(open.live_count() + open.abandoned_count(), 0);
}

/// Random chunk cadences over every part-boundary neighborhood keep the
/// writer's invariants: non-final parts are exactly the pinned part size,
/// ordinals ascend from one, and the commit — the only path to a
/// completed object — succeeds exactly on a finished non-empty stream,
/// with the empty session aborted instead.
#[test]
fn writer_cadence_fuzz_keeps_parts_exact_and_commits_only_after_validation() {
    let store = RecordingStore::default();
    let mut prng = Prng::new(0x5EED_F014);
    for repetition in 0..4 {
        for (case, &total) in CADENCE_TOTALS.iter().enumerate() {
            let uploads_before = store.state.lock().expect("mock lock").next_upload;
            run_cadence(&store, total, &mut prng);
            let state = store.state.lock().expect("mock lock");
            let upload = format!("fuzz-upload-{}", uploads_before + 1);
            let parts: Vec<(u16, usize)> = state
                .parts
                .iter()
                .filter(|(id, _, _)| *id == upload)
                .map(|(_, number, size)| (*number, *size))
                .collect();
            let expected_parts = total.div_ceil(PART_BYTES);
            assert_eq!(
                parts.len(),
                expected_parts,
                "case {case}/repetition {repetition} produced the wrong part count"
            );
            for (index, (number, size)) in parts.iter().enumerate() {
                assert_eq!(
                    *number,
                    u16::try_from(index + 1).expect("ordinal fits u16"),
                    "ordinals ascend from one"
                );
                let expected = if index + 1 == expected_parts {
                    total - (expected_parts - 1) * PART_BYTES
                } else {
                    PART_BYTES
                };
                assert_eq!(*size, expected, "part {number} has the pinned size");
            }
            assert_eq!(state.completes.contains(&upload), total > 0);
            if total == 0 {
                assert!(state.aborts.contains(&upload), "the empty session aborts");
            }
        }
    }
}

/// The refusals that gate an invalid commit: committing before `finish`
/// aborts without completing anything, and writing after `finish` is a
/// rejection that leaves the session committable after validation. Every
/// refusal rendering stays content-free even when the buffered bytes
/// carry the marker.
#[test]
fn writer_refusals_abort_and_stay_content_free() {
    let store = RecordingStore::default();
    let mut prng = Prng::new(0x5EED_F015);
    let open = OpenUploads::new();
    let key = blob_key(&mut prng);
    let mut writer = block_on(MultipartWriter::begin(&store, &key, &open)).expect("mock begin");
    let mut chunk = FUZZ_MARKER.as_bytes().to_vec();
    chunk.extend(std::iter::repeat_n(b'm', 64));
    block_on(writer.write_chunk(&chunk)).expect("chunk uploads");

    // Commit before finish: refused, aborted, nothing completed.
    let upload = writer.session_id().as_str().to_owned();
    let error = block_on(writer.commit()).expect_err("an unfinished stream cannot commit");
    assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
    assert_error_content_free("commit-before-finish refusal", error);
    {
        let state = store.state.lock().expect("mock lock");
        assert!(state.completes.is_empty(), "no object completed");
        assert!(state.aborts.contains(&upload), "the session aborted");
    }

    // A fresh session: write-after-finish is a rejection, not a failure —
    // the session still commits after validation.
    let mut writer = block_on(MultipartWriter::begin(&store, &key, &open)).expect("mock begin");
    block_on(writer.write_chunk(&chunk)).expect("chunk uploads");
    block_on(writer.finish()).expect("finish");
    let error = block_on(writer.write_chunk(b"late")).expect_err("stream is closed");
    assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
    assert_error_content_free("write-after-finish rejection", error);
    let outcome = block_on(writer.commit()).expect("commit still allowed after validation");
    assert_eq!(outcome, StorageOutcome::Created);
}

// ---------------------------------------------------------------------------
// Shared framing-event sanity: the raw tokenizer over generated bodies
// ---------------------------------------------------------------------------

/// The raw tokenizer yields a lawful event stream over generated two-part
/// bodies through arbitrary refill edges: it opens at a part boundary,
/// closes at `EndOfParts`, carries exactly two part media types, and
/// never holds more than the framing window whatever the body weighs.
#[test]
fn framing_tokenizer_events_stay_lawful_and_window_bounded() {
    let mut prng = Prng::new(0x5EED_F016);
    let framing = request_framing(BOUNDARY);
    for case in 0..64u64 {
        let payload_len = prng.below_usize(2048) + FUZZ_MARKER.len();
        let payload = soup(&mut prng, payload_len);
        let body = framed_body(
            BOUNDARY,
            &[
                (ENVELOPE_PART_MEDIA_TYPE, &baseline_envelope_bytes()),
                (IDENTITY_MEDIA_TYPE, &payload),
            ],
        );
        let mut tokenizer = FramingTokenizer::new(&framing, Chunked::new(&body, 0x5EED + case));
        let mut opened_at_part = false;
        let mut closed_at_end = false;
        let mut content_types = 0;
        let mut first = true;
        loop {
            assert!(
                tokenizer.window_len() <= FRAMING_WINDOW_BYTES,
                "tokenizer window exceeded the pinned bound"
            );
            match tokenizer.next_event() {
                Ok(Some(event)) => {
                    if first {
                        opened_at_part = matches!(event, FramingEvent::PartStarted);
                        first = false;
                    }
                    if matches!(event, FramingEvent::PartContentType(_)) {
                        content_types += 1;
                    }
                    closed_at_end = matches!(event, FramingEvent::EndOfParts);
                }
                Ok(None) => break,
                Err(error) => panic!("valid body tokenized to an error: {error:?}"),
            }
        }
        assert!(opened_at_part, "the event stream opens at a part boundary");
        assert!(closed_at_end, "the event stream closes at the end of parts");
        assert_eq!(content_types, 2, "exactly two parts carry media types");
    }
}
