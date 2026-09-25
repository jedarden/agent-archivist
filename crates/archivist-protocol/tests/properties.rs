// SPDX-License-Identifier: Apache-2.0

//! Deterministic property tests for the wire contract's framing invariant
//! (plan Sections 7.1 and 7.4).
//!
//! Every loop is seeded from a fixed constant and driven by a hand-rolled
//! `xorshift64*` generator — the crate declares no dependencies, so no
//! property framework is available, and determinism matters more than
//! coverage heuristics: a failure must be reproducible from the seed named
//! in the test. Iteration counts are bounded so the whole file stays fast
//! in CI.
//!
//! The properties:
//!
//! 1. framing is faithful and self-describing: `FrameBuilder` hashes
//!    exactly `label || 0x00 || u64be(len) || content` per field, and every
//!    tuple's framing decodes back to its fields. Prefix escape is
//!    therefore impossible within a construction: the registry fixes each
//!    construction's field-kind sequence, and over any pinned shape no two
//!    distinct value tuples have one framing as a proper prefix of the
//!    other — hammered with random values plus adversarial empty,
//!    1-byte, sizing-boundary, and `u63`-extreme fields.
//! 2. domain separation: an identical field tuple framed under two
//!    different labels never hashes to one digest, and the four labeled
//!    identity constructions stay pairwise distinct — while the one
//!    label-less construction, `blob_digest`, never equals a labeled
//!    frame over the same payload bytes or over its own raw digest.
//! 3. identity disjointness: changing any single component of a
//!    `(tenant, client, harness, upstream)` tuple changes the session
//!    hash, and the derived occurrence and attestation identities and
//!    the object keys downstream of them never collide within one
//!    session namespace.

use archivist_protocol::derivation::{
    FrameBuilder, artifact_hash, attestation_id, blob_digest, occurrence_id, session_hash,
};
use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::sha256::{digest, encode_hex};
use archivist_protocol::vocabulary::{
    AdapterId, ArtifactHash, ArtifactKind, BlobDigest, ClientId, GenerationId, HarnessId,
    RangeKind, RequestId, SessionHash, StorageProfile, TenantId, VersionToken,
};

// --- deterministic generator -------------------------------------------------

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

    /// A uniform-ish value below `bound`; modulo bias is irrelevant at
    /// property-test granularity.
    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    fn below_usize(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound).expect("bound fits u64");
        usize::try_from(self.below(bound)).expect("result fits usize")
    }

    /// A `u63`-range integer.
    fn u63(&mut self) -> u64 {
        self.next_u64() >> 1
    }

    fn byte(&mut self) -> u8 {
        u8::try_from(self.below(256)).expect("byte fits u8")
    }
}

const TEXT_BYTES: &[u8] = b"abcXYZ019 ._-/\\\"{}\x07\t\n\x1b";

/// An opaque identifier body: printable ASCII mixed with bytes needing
/// canonical-JSON escapes. Bounded well under the wire's 1024-byte maximum.
fn opaque_text(prng: &mut Prng) -> String {
    let len = 1 + prng.below_usize(64);
    (0..len)
        .map(|_| TEXT_BYTES[prng.below_usize(TEXT_BYTES.len())] as char)
        .collect()
}

/// A `short-token` (`^[a-z0-9][a-z0-9._-]{0,63}$`) — the grammar of the
/// harness and adapter identifiers and of the registry's own labels.
fn short_token(prng: &mut Prng) -> String {
    const HEAD: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const TAIL: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789._-";
    let len = 1 + prng.below_usize(16);
    let mut token = String::new();
    token.push(HEAD[prng.below_usize(HEAD.len())] as char);
    for _ in 1..len {
        token.push(TAIL[prng.below_usize(TAIL.len())] as char);
    }
    token
}

/// A `version-token` (`^[0-9A-Za-z._+-]{1,32}$`) adapter projection
/// version.
fn version_token_text(prng: &mut Prng) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._+-";
    let len = 1 + prng.below_usize(12);
    (0..len)
        .map(|_| ALPHABET[prng.below_usize(ALPHABET.len())] as char)
        .collect()
}

/// Canonical `uuid-v4`/`uuid-v7` wire text: random bytes with the version
/// and variant nibbles pinned exactly as the vocabulary's UUID grammar
/// requires, so a generated value always parses.
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
        .map(|_| HEX_DIGITS[prng.below_usize(HEX_DIGITS.len())] as char)
        .collect()
}

// --- independent framing -----------------------------------------------------

/// One framed field, the test's own model of the registry's field kinds.
#[derive(Clone, Debug, PartialEq)]
enum Field {
    Text(String),
    Digest32([u8; 32]),
    U63(u64),
    Bytes(Vec<u8>),
}

impl Field {
    /// A value from the boundary neighborhood of its kind: empty and
    /// 1-byte text, sizing boundaries, `u63` extremes, prefix-shaped
    /// byte strings.
    fn adversarial(kind_hint: usize, prng: &mut Prng) -> Field {
        match kind_hint % 4 {
            0 => Field::Text(
                [String::new(), "a".to_owned(), "x".repeat(1024)][prng.below_usize(3)].clone(),
            ),
            1 => {
                let mut raw = [0u8; 32];
                for byte in &mut raw {
                    *byte = prng.byte();
                }
                Field::Digest32(raw)
            }
            2 => Field::U63(
                [
                    0,
                    1,
                    (1 << 63) - 1, // the `u63` maximum the wire pins
                    u64::MAX,
                ][prng.below_usize(4)],
            ),
            _ => Field::Bytes(match prng.below_usize(3) {
                0 => Vec::new(),
                1 => vec![0u8; 8],
                _ => vec![0x61; 1 + prng.below_usize(64)],
            }),
        }
    }

    /// A random value of this field's kind.
    fn random(kind_hint: usize, prng: &mut Prng) -> Field {
        match kind_hint % 4 {
            0 => Field::Text(opaque_text(prng)),
            1 => {
                let mut raw = [0u8; 32];
                for byte in &mut raw {
                    *byte = prng.byte();
                }
                Field::Digest32(raw)
            }
            2 => Field::U63(prng.u63()),
            _ => {
                let len = prng.below_usize(1024);
                Field::Bytes((0..len).map(|_| prng.byte()).collect())
            }
        }
    }

    /// The test's independent implementation of the pinned framing:
    /// `u64be(len) || content`, written from the documentation, not by
    /// calling the crate.
    fn push(&self, out: &mut Vec<u8>) {
        match self {
            Field::Text(text) => {
                let bytes = text.as_bytes();
                let len = u64::try_from(bytes.len()).expect("len fits u64");
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Field::Digest32(raw) => {
                out.extend_from_slice(&32u64.to_be_bytes());
                out.extend_from_slice(raw);
            }
            Field::U63(value) => {
                out.extend_from_slice(&8u64.to_be_bytes());
                out.extend_from_slice(&value.to_be_bytes());
            }
            Field::Bytes(bytes) => {
                let len = u64::try_from(bytes.len()).expect("len fits u64");
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(bytes);
            }
        }
    }
}

/// Frame `label || 0x00 || field_1..field_n` exactly as the registry pins.
fn frame(label: &str, fields: &[Field]) -> Vec<u8> {
    let mut out = label.as_bytes().to_vec();
    out.push(0x00);
    for field in fields {
        field.push(&mut out);
    }
    out
}

/// Feed the same fields through the crate's `FrameBuilder`.
fn crate_digest(label: &str, fields: &[Field]) -> [u8; 32] {
    let mut builder = FrameBuilder::new(label);
    for field in fields {
        match field {
            Field::Text(text) => builder.push_text(text),
            Field::Digest32(raw) => builder.push_digest32(raw),
            Field::U63(value) => builder.push_u63(*value),
            Field::Bytes(bytes) => builder.push_bytes(bytes),
        }
    }
    builder.finish()
}

/// One decoded frame: the label length and each field's `(length, content)`.
type DecodedFrame = (usize, Vec<(u64, Vec<u8>)>);

/// Decode `label || 0x00 || len||content..` back to length/content pairs,
/// or `None` if the bytes are not a well-formed frame. The framing is
/// self-describing exactly when every framing decodes uniquely, so the
/// kinds need not be recovered — only the byte structure.
fn decode_field_bounds(bytes: &[u8]) -> Option<DecodedFrame> {
    let split = bytes.iter().position(|byte| *byte == 0x00)?;
    String::from_utf8(bytes[..split].to_vec()).ok()?;
    let mut fields = Vec::new();
    let mut rest = &bytes[split + 1..];
    while !rest.is_empty() {
        if rest.len() < 8 {
            return None;
        }
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&rest[..8]);
        let len = u64::from_be_bytes(len_bytes);
        rest = &rest[8..];
        let len = usize::try_from(len).ok()?;
        if rest.len() < len {
            return None;
        }
        fields.push((
            u64::try_from(len).expect("len fits u64"),
            rest[..len].to_vec(),
        ));
        rest = &rest[len..];
    }
    Some((split, fields))
}

/// The registry's pinned field-kind sequences: one per labeled
/// construction (`session-v1`, `artifact-v1`, `occurrence-v1`,
/// `attestation-v1`, `ingest-attempt-v1` in registry order).
fn pinned_shapes() -> Vec<Vec<Field>> {
    vec![
        vec![Field::Text(String::new()); 4],
        vec![
            Field::Digest32([0u8; 32]),
            Field::Text(String::new()),
            Field::Text(String::new()),
            Field::Text(String::new()),
            Field::Text(String::new()),
        ],
        vec![
            Field::Digest32([0u8; 32]),
            Field::Digest32([0u8; 32]),
            Field::Text(String::new()),
            Field::Text(String::new()),
            Field::U63(0),
            Field::U63(0),
            Field::Digest32([0u8; 32]),
        ],
        vec![
            Field::Digest32([0u8; 32]),
            Field::Text(String::new()),
            Field::Text(String::new()),
        ],
        vec![
            Field::Text(String::new()),
            Field::Text(String::new()),
            Field::Text(String::new()),
            Field::Digest32([0u8; 32]),
            Field::Digest32([0u8; 32]),
            Field::Digest32([0u8; 32]),
            Field::Digest32([0u8; 32]),
            Field::Digest32([0u8; 32]),
            Field::U63(0),
            Field::Text(String::new()),
        ],
    ]
}

/// The registry's labeled constructions (registry order) — the frames the
/// one label-less construction must never reproduce.
const REGISTRY_LABELS: &[&str] = &[
    "session-v1",
    "artifact-v1",
    "occurrence-v1",
    "attestation-v1",
    "ingest-attempt-v1",
    "export-selection-v1",
];

// --- the properties ----------------------------------------------------------

/// Framing fidelity plus self-description: the crate's digest is the hash
/// of the independently framed bytes, and every framing decodes back to
/// exactly its field byte-structure.
#[test]
fn framing_matches_the_documented_layout_and_decodes() {
    let mut prng = Prng::new(0x5EED_0001);
    let mut tuples = Vec::new();
    for shape in pinned_shapes() {
        for index in 0..12 {
            let mut tuple = Vec::new();
            for (position, field) in shape.iter().enumerate() {
                let kind = match field {
                    Field::Text(_) => 0,
                    Field::Digest32(_) => 1,
                    Field::U63(_) => 2,
                    Field::Bytes(_) => 3,
                };
                if (index + position) % 3 == 0 {
                    tuple.push(Field::adversarial(kind, &mut prng));
                } else {
                    tuple.push(Field::random(kind, &mut prng));
                }
            }
            tuples.push(tuple);
        }
    }
    for _ in 0..256 {
        let shape = &pinned_shapes()[prng.below_usize(pinned_shapes().len())];
        let tuple: Vec<Field> = shape
            .iter()
            .map(|field| {
                let kind = match field {
                    Field::Text(_) => 0,
                    Field::Digest32(_) => 1,
                    Field::U63(_) => 2,
                    Field::Bytes(_) => 3,
                };
                Field::random(kind, &mut prng)
            })
            .collect();
        tuples.push(tuple);
    }

    for fields in &tuples {
        let label = "property-v1";
        let preimage = frame(label, fields);
        let framed_len = preimage.len();
        // The hashed preimage is the whole framed byte string.
        assert_eq!(
            crate_digest(label, fields),
            digest(&preimage),
            "framing drifted from the documented layout for {fields:?}"
        );

        let (label_len, decoded) = decode_field_bounds(&preimage)
            .unwrap_or_else(|| panic!("framing of {fields:?} is undecodable"));
        assert_eq!(label_len, label.len());
        let mut reassembled = preimage[..label_len].to_vec();
        reassembled.push(0x00);
        for (len, content) in &decoded {
            reassembled.extend_from_slice(&len.to_be_bytes());
            reassembled.extend_from_slice(content);
        }
        assert_eq!(reassembled.len(), framed_len);
        assert_eq!(
            reassembled, preimage,
            "decode did not round-trip {fields:?}"
        );
    }
}

/// Prefix escape is impossible within a construction: the registry fixes
/// each construction's field-kind sequence, and over any one pinned shape
/// no two distinct value tuples have one framing as a proper prefix of the
/// other — otherwise one identity's preimage would validate as another's.
/// The tuples draw only from the boundary pools: under the pinned framing
/// the frames stay pairwise prefix-free, while a degenerate framing (a
/// dropped length prefix, say) collapses the tiny value space into frame
/// collisions this loop must catch.
#[test]
fn framings_of_distinct_tuples_are_never_prefixes_of_each_other() {
    let mut prng = Prng::new(0x5EED_0002);
    for shape in pinned_shapes() {
        let mut tuples = Vec::new();
        for _ in 0..24 {
            tuples.push(
                shape
                    .iter()
                    .map(|field| {
                        let kind = match field {
                            Field::Text(_) => 0,
                            Field::Digest32(_) => 1,
                            Field::U63(_) => 2,
                            Field::Bytes(_) => 3,
                        };
                        Field::adversarial(kind, &mut prng)
                    })
                    .collect::<Vec<Field>>(),
            );
        }

        for left in &tuples {
            let left_frame = frame("property-v1", left);
            for right in &tuples {
                if left == right {
                    continue;
                }
                let right_frame = frame("property-v1", right);
                let shorter = left_frame.len().min(right_frame.len());
                assert_ne!(
                    left_frame[..shorter],
                    right_frame[..shorter],
                    "distinct tuples {left:?} and {right:?} share a framing prefix"
                );
            }
        }
    }
}

/// Domain separation over the label alone: one identical field tuple
/// framed under two different labels never hashes to one digest —
/// otherwise two constructions could silently certify each other's
/// identities. The label pairs are drawn from the same `short-token`
/// grammar the registry's labels speak, and every fourth pair is a
/// deliberate prefix extension — the shape a delimiter-splicing framing
/// bug collapses first, since the two frames then share their whole
/// label byte-run and must still diverge at the 0x00 delimiter.
#[test]
fn different_labels_never_share_a_digest_over_identical_fields() {
    const ITERATIONS: usize = 2000;
    let mut prng = Prng::new(0x5EED_0003);
    for index in 0..ITERATIONS {
        let field_count = prng.below_usize(7);
        let fields: Vec<Field> = (0..field_count)
            .map(|position| Field::random(position, &mut prng))
            .collect();
        let left = short_token(&mut prng);
        let right = if index % 4 == 0 {
            let mut extended = left.clone();
            extended.push('-');
            extended.push_str(&short_token(&mut prng));
            extended
        } else {
            let mut candidate = short_token(&mut prng);
            while candidate == left {
                candidate = short_token(&mut prng);
            }
            candidate
        };
        assert_ne!(left, right, "label generation produced one label twice");
        assert_ne!(
            crate_digest(&left, &fields),
            crate_digest(&right, &fields),
            "labels {left:?} and {right:?} collided over {fields:?}"
        );
    }
}

/// Random payload bytes for the label-less digest: usually opaque, but
/// every fourth draw is itself a well-formed labeled frame, which the
/// plain digest must still read as opaque bytes.
fn generated_payload(prng: &mut Prng) -> Vec<u8> {
    if prng.below_usize(4) == 0 {
        let fields: Vec<Field> = (0..prng.below_usize(4))
            .map(|position| Field::random(position, prng))
            .collect();
        frame(&short_token(prng), &fields)
    } else {
        let length = prng.below_usize(256);
        (0..length).map(|_| prng.byte()).collect()
    }
}

/// Derive the four labeled identity constructions over one generated
/// identity tuple, each digest paired with its construction's wire name.
fn named_digests(prng: &mut Prng, blob: &BlobDigest) -> [(&'static str, [u8; 32]); 4] {
    let tenant = TenantId::parse(&uuid_text(prng, 4)).expect("generated uuid-v4 parses");
    let origin = ClientId::parse(&uuid_text(prng, 4)).expect("generated uuid-v4 parses");
    let harness = HarnessId::parse(&short_token(prng)).expect("generated short-token parses");
    let session = session_hash(&tenant, &origin, &harness, &opaque_text(prng));

    let artifact_kind =
        ArtifactKind::parse(ArtifactKind::tokens()[prng.below_usize(ArtifactKind::tokens().len())])
            .expect("registry token parses");
    let adapter = AdapterId::parse(&short_token(prng)).expect("generated short-token parses");
    let projection =
        VersionToken::parse(&version_token_text(prng)).expect("generated version-token parses");
    let artifact = artifact_hash(
        &session,
        artifact_kind,
        &adapter,
        &projection,
        &opaque_text(prng),
    );

    let generation = GenerationId::parse(&uuid_text(prng, 7)).expect("generated uuid-v7 parses");
    let range_kind =
        RangeKind::parse(RangeKind::tokens()[prng.below_usize(RangeKind::tokens().len())])
            .expect("registry token parses");
    let range_start = prng.u63();
    let range_end = prng.u63();
    let occurrence = occurrence_id(
        &session,
        &artifact,
        &generation,
        range_kind,
        range_start,
        range_end,
        blob,
    );

    let uploader = ClientId::parse(&uuid_text(prng, 4)).expect("generated uuid-v4 parses");
    let request = RequestId::parse(&uuid_text(prng, 7)).expect("generated uuid-v7 parses");
    let attestation = attestation_id(&occurrence, &uploader, &request);

    [
        ("session-v1", *session.as_raw()),
        ("artifact-v1", *artifact.as_raw()),
        ("occurrence-v1", *occurrence.as_raw()),
        ("attestation-v1", *attestation.as_raw()),
    ]
}

/// The four labeled identity constructions stay pairwise distinct over
/// generated identity tuples — `session-v1`, `artifact-v1`,
/// `occurrence-v1`, and `attestation-v1` may never agree on one digest,
/// whatever the inputs, or two different identities would be
/// indistinguishable on the wire. The single label-less construction,
/// `blob_digest`, must additionally never equal a labeled frame: not
/// over the same payload bytes, and not over its own raw digest.
#[test]
fn named_constructions_are_pairwise_distinct() {
    const ITERATIONS: usize = 512;
    let mut prng = Prng::new(0x5EED_0004);
    for index in 0..ITERATIONS {
        let payload = generated_payload(&mut prng);
        let blob = blob_digest(&payload);
        let named = named_digests(&mut prng, &blob);

        for (position, (left_name, left)) in named.iter().enumerate() {
            for (right_name, right) in named.iter().skip(position + 1) {
                assert_ne!(
                    left, right,
                    "constructions {left_name} and {right_name} agreed on one digest"
                );
            }
        }

        // The label-less construction never agrees with a labeled frame:
        // one registry label per iteration, cycled, plus one ad-hoc
        // short-token label.
        let label = REGISTRY_LABELS[index % REGISTRY_LABELS.len()];
        let ad_hoc_label = short_token(&mut prng);
        let raw = *blob.as_raw();
        assert_ne!(
            blob.as_raw(),
            &crate_digest(label, &[Field::Bytes(payload.clone())]),
            "blob_digest collided with a {label} frame over the same payload bytes"
        );
        assert_ne!(
            blob.as_raw(),
            &crate_digest(&ad_hoc_label, &[Field::Bytes(payload.clone())]),
            "blob_digest collided with an ad-hoc {ad_hoc_label:?} frame over the same payload bytes"
        );
        assert_ne!(
            blob.as_raw(),
            &crate_digest(label, &[Field::Digest32(raw)]),
            "blob_digest collided with a {label} frame over its own raw digest"
        );
    }
}

// --- identity disjointness ---------------------------------------------------

/// Regenerate until the value differs from `current` (an exact repeat is
/// astronomically unlikely and the loop keeps the intent explicit).
fn distinct<T: PartialEq>(current: &T, mut generate: impl FnMut() -> T) -> T {
    loop {
        let candidate = generate();
        if candidate != *current {
            return candidate;
        }
    }
}

/// One generated `(tenant, origin, harness, upstream)` identity tuple.
#[derive(Clone)]
struct IdentityTuple {
    tenant: TenantId,
    origin: ClientId,
    harness: HarnessId,
    upstream: String,
}

impl IdentityTuple {
    fn generate(prng: &mut Prng) -> Self {
        Self {
            tenant: TenantId::parse(&uuid_text(prng, 4)).expect("generated uuid-v4 parses"),
            origin: ClientId::parse(&uuid_text(prng, 4)).expect("generated uuid-v4 parses"),
            harness: HarnessId::parse(&short_token(prng)).expect("generated short-token parses"),
            upstream: opaque_text(prng),
        }
    }

    fn session(&self) -> SessionHash {
        session_hash(&self.tenant, &self.origin, &self.harness, &self.upstream)
    }
}

/// Identity ambiguity is impossible: changing any single component of an
/// identity tuple changes the session hash.
#[test]
fn changing_any_identity_component_changes_the_session_hash() {
    let mut prng = Prng::new(0x5EED_0005);
    for _ in 0..512 {
        let base = IdentityTuple::generate(&mut prng);
        let base_session = base.session();

        let mut variant = base.clone();
        variant.tenant =
            TenantId::parse(&uuid_text(&mut prng, 4)).expect("generated uuid-v4 parses");
        assert_ne!(variant.session(), base_session, "tenant change collided");

        let mut variant = base.clone();
        variant.origin =
            ClientId::parse(&uuid_text(&mut prng, 4)).expect("generated uuid-v4 parses");
        assert_ne!(variant.session(), base_session, "origin change collided");

        let mut variant = base.clone();
        // `distinct` matters here: the short-token space includes
        // single-character names, so an unguarded regenerate can mint the
        // same harness the tuple already carries and fail the property
        // vacuously.
        let fresh = distinct(&base.harness.to_string(), || short_token(&mut prng));
        variant.harness = HarnessId::parse(&fresh).expect("generated short-token parses");
        assert_ne!(variant.session(), base_session, "harness change collided");

        let mut variant = base.clone();
        variant.upstream = distinct(&base.upstream, || opaque_text(&mut prng));
        assert_ne!(variant.session(), base_session, "upstream change collided");
    }
}

/// Downstream identity: distinct artifacts, occurrences, attestations, and
/// object keys over the same session namespace never collide.
#[test]
fn downstream_ids_and_object_keys_stay_distinct() {
    let mut prng = Prng::new(0x5EED_0006);
    for _ in 0..512 {
        let tenant = TenantId::parse(&uuid_text(&mut prng, 4)).expect("generated uuid-v4 parses");
        let origin = ClientId::parse(&uuid_text(&mut prng, 4)).expect("generated uuid-v4 parses");
        let harness =
            HarnessId::parse(&short_token(&mut prng)).expect("generated short-token parses");
        let session = IdentityTuple {
            tenant: tenant.clone(),
            origin: origin.clone(),
            harness: harness.clone(),
            upstream: opaque_text(&mut prng),
        }
        .session();

        // Guaranteed-distinct digest pairs via a single flipped hex digit.
        let base_hex = hex_text(&mut prng, 64);
        let mut other_hex = base_hex.clone();
        let flip = if other_hex.starts_with('0') { "1" } else { "0" };
        other_hex.replace_range(0..1, flip);
        let base_blob = BlobDigest::parse(&base_hex).expect("generated hex parses");
        let other_blob = BlobDigest::parse(&other_hex).expect("generated hex parses");
        let base_key = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &base_blob);
        let other_key = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &other_blob);
        assert_ne!(base_key.as_str(), other_key.as_str(), "blob keys collided");

        let base_artifact = ArtifactHash::parse(&base_hex).expect("generated hex parses");
        let other_artifact = ArtifactHash::parse(&other_hex).expect("generated hex parses");
        let base_generation =
            GenerationId::parse(&uuid_text(&mut prng, 7)).expect("generated uuid-v7 parses");
        let other_generation = distinct(&base_generation.to_string(), || uuid_text(&mut prng, 7));
        let other_generation =
            GenerationId::parse(&other_generation).expect("generated uuid-v7 parses");
        let base_occurrence = occurrence_id(
            &session,
            &base_artifact,
            &base_generation,
            RangeKind::Byte,
            0,
            1,
            &base_blob,
        );
        let other_occurrence = occurrence_id(
            &session,
            &other_artifact,
            &other_generation,
            RangeKind::Event,
            2,
            3,
            &other_blob,
        );
        assert_ne!(base_occurrence, other_occurrence, "occurrences collided");

        let base_uploader =
            ClientId::parse(&uuid_text(&mut prng, 4)).expect("generated uuid-v4 parses");
        let other_uploader =
            ClientId::parse(&uuid_text(&mut prng, 4)).expect("generated uuid-v4 parses");
        let base_request =
            RequestId::parse(&uuid_text(&mut prng, 7)).expect("generated uuid-v7 parses");
        let other_request =
            RequestId::parse(&uuid_text(&mut prng, 7)).expect("generated uuid-v7 parses");
        let base_attestation = attestation_id(&base_occurrence, &base_uploader, &base_request);
        let other_attestation = attestation_id(&other_occurrence, &other_uploader, &other_request);
        assert_ne!(base_attestation, other_attestation, "attestations collided");

        let occurrence_key =
            OccurrenceObjectKey::new(&tenant, &origin, &harness, &session, &base_occurrence);
        let other_occurrence_key =
            OccurrenceObjectKey::new(&tenant, &origin, &harness, &session, &other_occurrence);
        assert_ne!(
            occurrence_key.as_str(),
            other_occurrence_key.as_str(),
            "occurrence keys collided"
        );
        let attestation_key =
            AttestationObjectKey::new(&tenant, &base_occurrence, &base_attestation);
        let other_attestation_key =
            AttestationObjectKey::new(&tenant, &other_occurrence, &other_attestation);
        assert_ne!(
            attestation_key.as_str(),
            other_attestation_key.as_str(),
            "attestation keys collided"
        );
    }
}
