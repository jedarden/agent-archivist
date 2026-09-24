// SPDX-License-Identifier: Apache-2.0

//! The cross-platform golden blob set for the `zstd-v1` storage profile
//! (VAL-006; plan Section 7.6).
//!
//! VAL-006 requires compression to have a deterministic canonical form when
//! its bytes are persisted beneath an uncompressed content address: identical
//! canonical bytes must produce identical stored bytes on every platform and
//! every retry. The `zstd-v1` profile delivers that through its pinned
//! parameter set — libzstd 1.5.7, level 3, single-threaded, no dictionary,
//! pledged content size, embedded checksum — and this suite pins the *bytes*
//! that parameter set produces:
//!
//! - `fixtures/zstd-v1/*.zst` are the committed stored forms, generated once
//!   by [`regenerate_fixtures`] through the profile's own encoder and never
//!   rewritten by hand.
//! - Every verification run re-encodes each vector's canonical form through
//!   [`ZstdV1Encoder`] and requires the output to be **byte-for-byte
//!   identical** to the committed file. A platform whose libzstd, feature
//!   set, or parameter wiring drifts produces different stored bytes and
//!   fails here.
//! - The committed digests double-pin the files against silent
//!   regeneration: the digest constants below change only in a commit that
//!   deliberately regenerates the set, which is the plan's new-profile
//!   decision, never a routine edit.
//! - `fixtures/zstd-v1/manifest.json` records the pin (version, parameters,
//!   per-file digests) and is itself byte-pinned: this file renders the
//!   manifest and requires the committed bytes to match, so the manifest
//!   cannot drift from the files it describes.
//!
//! This is the set, not the single vector: the module unit test
//! (`crates/archivist-storage/src/zstd_v1.rs`) pins one flagship vector;
//! this suite adds the shapes that stress the parameter space the profile
//! claims to cover — empty, minimal, odd-length, pure redundancy,
//! incompressible, and sparse — because a cross-platform promise is only as
//! good as the inputs it has been shown on.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use archivist_protocol::sha256;
use archivist_storage::blob::BlobEncoder;
use archivist_storage::error::StorageError;
use archivist_storage::zstd_v1::{ZstdV1Decoder, ZstdV1Encoder};

/// The linked libzstd version the set was generated with (and the profile is
/// pinned against). Every test in this file asserts it at run time: the
/// committed bytes are a function of the codec version as much as of the
/// parameters.
const PINNED_LIBZSTD_VERSION: &str = "1.5.7";

/// The golden vector set, in manifest order: `(file name, shape name)`.
/// Appending a vector is a deliberate extension of VAL-006's evidence —
/// add the shape here, regenerate, and commit both in one change.
const VECTORS: &[(&str, &str)] = &[
    ("empty.zst", "empty"),
    ("single-byte.zst", "single-byte"),
    ("text-lines-768.zst", "text-lines-768"),
    ("mixed-lines-40.zst", "mixed-lines-40"),
    ("odd-9997.zst", "odd-9997"),
    ("redundant-64k.zst", "redundant-64k"),
    ("sparse-noise-16k.zst", "sparse-noise-16k"),
    ("incompressible-64k.zst", "incompressible-64k"),
];

/// The committed digests: `(file name, canonical sha256 hex, canonical
/// length, stored sha256 hex, stored length)`. Generated once by
/// [`regenerate_fixtures`] and committed beside the bytes; a change here is
/// a change of stored bytes, and therefore a profile decision.
const DIGESTS: &[(&str, &str, usize, &str, usize)] = &[
    (
        "empty.zst",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        0,
        "f96deff1816083fdff8bc3e46c3fe6ca46a6bb49f4d5a00627616c13237a512c",
        13,
    ),
    (
        "single-byte.zst",
        "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
        1,
        "a381180f02b3220490a6a96473cc5b1cdc1e773815be503a889dcbf2ad76b883",
        14,
    ),
    (
        "text-lines-768.zst",
        "dc947c3d6137b78ae12ae05549674af468cc5a47999942413f94227dae08f7ae",
        57_600,
        "b5efc0dea4db5322d0bed98a576153446fa50f48c99f5bc35e01247f464c3c16",
        851,
    ),
    (
        "mixed-lines-40.zst",
        "1443a4ffeac64c2455fa71b7d518550118d91f1ec17b3d45b1d5e64a71772105",
        7_040,
        "78c21bb0d72f3d5651d0abbaaf2bb9e86b2189196efd57fbb351aa42fe2a58cf",
        251,
    ),
    (
        "odd-9997.zst",
        "fb9745be9ecb4b006f695d4010b3c6da581a6676b9f277295fe1e78f83f67495",
        9_997,
        "de9b0bb98ae34226fcffc2294d45ad11e6cbdcbae6f9052563b8047309fd157e",
        10_011,
    ),
    (
        "redundant-64k.zst",
        "4f772cad45a568461aeb93ed8e3451422e5ba92d94c01a3355cb02e75c4b387e",
        70_000,
        "b7b33bd5d6751ad1182f0086a87fc2e4960373084e5b2a21d5c2115e26903b83",
        26,
    ),
    (
        "sparse-noise-16k.zst",
        "57f2cedf72e0332528fd957bccf64d3727c9d5352aea539b93aecc3ebaeb64db",
        16_384,
        "5b3fcb91488101b1338a7529bf4c634d094bf046611264643aef5733bdee1c62",
        173,
    ),
    (
        "incompressible-64k.zst",
        "9727cc1b765ff667fd7d006fb6a5679be589c62cb6ccb0a475e7dc115bb015df",
        70_000,
        "3933b0cbcde571c18cc6baa4dfdd07ee47a71e2e3fb56b36bc7893207782edbb",
        70_016,
    ),
];

/// The committed golden set, relative to this crate's manifest directory.
fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zstd-v1")
}

fn sha256_hex(bytes: &[u8]) -> String {
    sha256::encode_hex(&sha256::digest(bytes))
}

/// One step of the deterministic xorshift64 bit generator the shapes use.
/// The generator lives here — not in `rand` — so the canonical forms are
/// reproducible from this file alone, on every platform, forever.
fn xorshift_byte(state: &mut u64) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    state.to_le_bytes()[0]
}

/// The canonical bytes of one shape, rebuilt deterministically at every
/// run. The generators are the single source of truth for the canonical
/// side; the manifest's `canonical_sha256` values catch any drift in this
/// function before it could silently pass.
fn canonical_bytes(shape: &str) -> Vec<u8> {
    match shape {
        // The degenerate streams: nothing, and one byte.
        "empty" => Vec::new(),
        "single-byte" => b"x".to_vec(),
        // The flagship pattern the module unit test's golden vector also
        // pins: mixed repetition and variation, enough for level 3 to do
        // real work. Must stay textually identical to that generator.
        "text-lines-768" => {
            let mut pattern = Vec::new();
            for line in 0..768u32 {
                let _ = writeln!(
                    pattern,
                    "archivist occurrence {line:04} of tenant 0f1e2d3c session zstd-v1 golden vector"
                );
            }
            pattern
        }
        // Structured repetition with growing lines: the record-per-line
        // shape the pipeline actually stores.
        "mixed-lines-40" => {
            let mut pattern = Vec::new();
            for block in 0..40usize {
                let _ = writeln!(
                    pattern,
                    "record-{block:03}-{}",
                    "payload ".repeat(block + 1)
                );
            }
            pattern
        }
        // An odd, prime-ish length crossing compressor block boundaries.
        "odd-9997" => {
            let mut state = 0x9E37_79B9_7F4A_7C15u64;
            (0..9_997).map(|_| xorshift_byte(&mut state)).collect()
        }
        // Pure redundancy: the extreme of what level 3 collapses.
        "redundant-64k" => vec![7u8; 70_000],
        // Mostly zeros with a deterministic byte of noise every 251
        // positions: sparse data, compressible but not trivially so.
        "sparse-noise-16k" => {
            let mut state = 0x0DD1_C7A7_5EED_0001u64;
            (0..16_384usize)
                .map(|index| {
                    if index % 251 == 0 {
                        xorshift_byte(&mut state)
                    } else {
                        0
                    }
                })
                .collect()
        }
        // No short-range repetition for the compressor to exploit: the
        // stored form carries the payload at roughly its own size.
        "incompressible-64k" => {
            let mut state = 0x2545_F491_4F6C_DD1Du64;
            (0..70_000).map(|_| xorshift_byte(&mut state)).collect()
        }
        other => panic!("unknown golden vector shape: {other}"),
    }
}

/// Encode `canonical` through the profile encoder in odd-sized chunks and
/// return the stored form. Chunked feeding is deliberate: chunk boundaries
/// must not change the stored bytes, here or anywhere.
fn encode_stored(canonical: &[u8]) -> Result<Vec<u8>, StorageError> {
    let mut encoder = ZstdV1Encoder::new(canonical.len() as u64)?;
    let mut stored = Vec::new();
    for chunk in canonical.chunks(1009) {
        encoder.update(chunk, &mut stored)?;
    }
    encoder.finish(&mut stored)?;
    Ok(stored)
}

/// Decode `stored` through the profile decoder in odd-sized chunks and
/// return the canonical form.
fn decode_canonical(stored: &[u8]) -> Result<Vec<u8>, StorageError> {
    let mut decoder = ZstdV1Decoder::new()?;
    let mut canonical = Vec::new();
    for chunk in stored.chunks(1013) {
        decoder.update(chunk, &mut canonical)?;
    }
    decoder.finish(&mut canonical)?;
    Ok(canonical)
}

/// A `StoredVector`: the digests and lengths one committed file must carry.
struct StoredVector {
    name: &'static str,
    canonical_sha256: &'static str,
    canonical_len: usize,
    stored_sha256: &'static str,
    stored_len: usize,
}

/// The [`DIGESTS`] table, parsed into named fields.
fn stored_vectors() -> Vec<StoredVector> {
    DIGESTS
        .iter()
        .map(
            |(name, canonical_sha256, canonical_len, stored_sha256, stored_len)| StoredVector {
                name,
                canonical_sha256,
                canonical_len: *canonical_len,
                stored_sha256,
                stored_len: *stored_len,
            },
        )
        .collect()
}

/// Render the committed `manifest.json` bytes from the vector set's live
/// digests. The verifier re-renders this and compares against the
/// committed file byte-for-byte, so the manifest cannot drift from the
/// bytes it describes.
fn render_manifest(vectors: &[(&str, &str, usize, String, usize, String)]) -> String {
    let files: Vec<String> = vectors
        .iter()
        .map(
            |(name, shape, canonical_len, canonical_sha256, stored_len, stored_sha256)| {
                format!(
                    "    {{\n      \"name\": \"{name}\",\n      \"shape\": \"{shape}\",\n      \"canonical_len\": {canonical_len},\n      \"canonical_sha256\": \"{canonical_sha256}\",\n      \"stored_len\": {stored_len},\n      \"stored_sha256\": \"{stored_sha256}\"\n    }}"
                )
            },
        )
        .collect();
    format!(
        "{{\n  \"schema\": \"archivist.zstd-v1.golden-blobs/v1\",\n  \"profile\": \"zstd-v1\",\n  \"encoder\": {{\n    \"libzstd\": \"{PINNED_LIBZSTD_VERSION}\",\n    \"compression_level\": 3,\n    \"single_threaded\": true,\n    \"dictionary\": \"none\",\n    \"pledged_content_size\": true,\n    \"embedded_checksum\": true\n  }},\n  \"generator\": \"crates/archivist-storage/tests/zstd_v1_golden_blobs.rs regenerate_fixtures\",\n  \"files\": [\n{}\n  ]\n}}\n",
        files.join(",\n")
    )
}

/// The vector set's live digests, in manifest order: `(file name, shape,
/// canonical len, canonical sha256, stored len, stored sha256)`. Every
/// value is computed fresh from the generators and the profile encoder.
fn live_vectors() -> Vec<(&'static str, &'static str, usize, String, usize, String)> {
    VECTORS
        .iter()
        .map(|(name, shape)| {
            let canonical = canonical_bytes(shape);
            let stored = encode_stored(&canonical).expect("profile encoder encodes");
            (
                *name,
                *shape,
                canonical.len(),
                sha256_hex(&canonical),
                stored.len(),
                sha256_hex(&stored),
            )
        })
        .collect()
}

/// Every committed file reproduces byte-for-byte from the profile encoder,
/// and its digests match the committed table.
#[test]
fn golden_blobs_reproduce_from_the_profile_encoder() {
    assert_eq!(
        zstd_safe_version_string(),
        PINNED_LIBZSTD_VERSION,
        "the golden set is only valid for the pinned libzstd"
    );
    let vectors = stored_vectors();
    assert_eq!(vectors.len(), VECTORS.len(), "digest table covers the set");
    for (index, (name, shape)) in VECTORS.iter().enumerate() {
        let vector = &vectors[index];
        assert_eq!(vector.name, *name, "digest table order matches the set");

        let canonical = canonical_bytes(shape);
        let stored = encode_stored(&canonical).expect("profile encoder encodes");
        let committed =
            fs::read(fixtures_root().join(name)).unwrap_or_else(|error| panic!("{name}: {error}"));

        assert_eq!(
            stored, committed,
            "{name}: the committed stored form is not what the pinned profile produces"
        );
        assert_eq!(
            sha256_hex(&committed),
            vector.stored_sha256,
            "{name}: committed stored digest drifted from the pinned table"
        );
        assert_eq!(committed.len(), vector.stored_len, "{name}: stored length");
        assert_eq!(
            sha256_hex(&canonical),
            vector.canonical_sha256,
            "{name}: the canonical generator drifted from the pinned table"
        );
        assert_eq!(
            canonical.len(),
            vector.canonical_len,
            "{name}: canonical length"
        );
    }
}

/// Every committed file decodes back to exactly its canonical form — the
/// read-back half of VAL-006's content-addressing premise.
#[test]
fn golden_blobs_decode_to_their_canonical_forms() {
    assert_eq!(
        zstd_safe_version_string(),
        PINNED_LIBZSTD_VERSION,
        "the golden set is only valid for the pinned libzstd"
    );
    for (name, shape) in VECTORS {
        let committed =
            fs::read(fixtures_root().join(name)).unwrap_or_else(|error| panic!("{name}: {error}"));
        let canonical = canonical_bytes(shape);
        let decoded = decode_canonical(&committed)
            .unwrap_or_else(|error| panic!("{name}: committed form does not decode: {error}"));
        assert_eq!(decoded, canonical, "{name}: read-back diverged");
        assert_eq!(
            sha256_hex(&decoded),
            sha256_hex(&canonical),
            "{name}: read-back digest diverged"
        );
    }
}

/// The manifest's committed bytes are exactly what the generator renders
/// from the live set — the manifest and the files cannot drift apart.
#[test]
fn manifest_bytes_match_the_generator() {
    let live = live_vectors();
    let rendered = render_manifest(&live);
    let committed = fs::read(fixtures_root().join("manifest.json")).expect("manifest.json exists");
    assert_eq!(
        committed,
        rendered.as_bytes(),
        "manifest.json drifted from the rendered generator output"
    );
}

/// The directory carries exactly the manifest set: no stray files, no
/// missing files, nothing the manifest does not describe.
#[test]
fn fixture_directory_carries_exactly_the_manifest_set() {
    let mut expected: Vec<String> = VECTORS.iter().map(|(name, _)| (*name).to_owned()).collect();
    expected.push("manifest.json".to_owned());
    expected.sort();

    let mut found: Vec<String> = fs::read_dir(fixtures_root())
        .expect("fixtures/zstd-v1 exists")
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();

    assert_eq!(found, expected, "fixtures/zstd-v1 carries exactly the set");
}

/// Regenerate the committed golden set: rewrite every `.zst` file and the
/// manifest from the live encoder, and print the [`DIGESTS`] table to paste
/// into this file. `#[ignore]`d because it writes; run with
/// `cargo test -p archivist-storage --test zstd_v1_golden_blobs
/// regenerate_fixtures -- --ignored --nocapture`. Regeneration is a profile
/// decision (plan Section 7.5): the pinned libzstd version, the parameter
/// set, and this suite change together or not at all.
#[test]
#[ignore = "rewrites the committed fixtures; run explicitly with --ignored"]
fn regenerate_fixtures() {
    assert_eq!(
        zstd_safe_version_string(),
        PINNED_LIBZSTD_VERSION,
        "refusing to regenerate under a different libzstd"
    );
    let root = fixtures_root();
    fs::create_dir_all(&root).expect("fixtures directory");

    let mut manifest_vectors = Vec::new();
    let mut table = Vec::new();
    for (name, shape) in VECTORS {
        let canonical = canonical_bytes(shape);
        let stored = encode_stored(&canonical).expect("profile encoder encodes");
        fs::write(root.join(name), &stored).unwrap_or_else(|error| panic!("{name}: {error}"));
        let canonical_sha256 = sha256_hex(&canonical);
        let stored_sha256 = sha256_hex(&stored);
        manifest_vectors.push((
            *name,
            *shape,
            canonical.len(),
            canonical_sha256.clone(),
            stored.len(),
            stored_sha256.clone(),
        ));
        table.push(format!(
            "        (\n            \"{name}\",\n            \"{canonical_sha256}\",\n            {},\n            \"{stored_sha256}\",\n            {},\n        ),",
            canonical.len(),
            stored.len()
        ));
    }
    fs::write(
        root.join("manifest.json"),
        render_manifest(&manifest_vectors),
    )
    .expect("manifest.json writes");

    println!("Paste into DIGESTS:");
    println!("{}", table.join("\n"));
}

/// The linked libzstd's version string.
fn zstd_safe_version_string() -> &'static str {
    zstd_safe::version_string()
}
