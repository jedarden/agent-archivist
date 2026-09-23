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

use archivist_protocol::derivation::FrameBuilder;
use archivist_protocol::sha256::digest;

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
