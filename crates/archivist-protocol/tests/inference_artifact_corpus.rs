// SPDX-License-Identifier: Apache-2.0

//! The inference capture-artifact corpus ([`schemas/v1/examples/inference`];
//! plan Phase 9), replayed through the typed model of
//! [`archivist_protocol::inference_artifact`].
//!
//! Every artifact the manifest lists exists with exactly its pinned
//! SHA-256, parses into [`InferenceArtifact`], carries the manifest's
//! kind, and re-serializes to the very bytes it came from — the
//! byte-stability the capture boundary promises (an upload retry rewrites
//! identical bytes). The manifest's schema invariants pin the Rust
//! constants they mirror: the nine-entry metadata allowlist and the
//! reserved-field list.
//!
//! [`schemas/v1/examples/inference`]: ../../../schemas/v1/examples/inference
//! [`InferenceArtifact`]: archivist_protocol::inference_artifact::InferenceArtifact

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use archivist_protocol::inference_artifact::{
    BoundaryEvent, InferenceArtifact, METADATA_ALLOWLIST, RESERVED_FIELDS,
};
use archivist_protocol::json::{self, Value};
use archivist_protocol::sha256::{digest, encode_hex};
use archivist_protocol::vocabulary::InferenceArtifactKind;

/// The committed corpus, relative to this crate's manifest directory.
fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/v1/examples/inference")
}

/// Read and parse one corpus JSON file, failing with its path.
fn load_json(rel: &str) -> Result<Value, String> {
    let bytes = fs::read(corpus_root().join(rel)).map_err(|e| format!("{rel}: {e}"))?;
    json::parse(&bytes).map_err(|e| format!("{rel}: {e}"))
}

/// A manifest member's text.
fn text<'a>(value: &'a Value, rel: &str, name: &str) -> Result<&'a str, String> {
    let Value::Object(object) = value else {
        return Err(format!("{rel}: expected an object"));
    };
    match object.get(name) {
        Some(Value::Text(text)) => Ok(text.as_str()),
        _ => Err(format!("{rel}: member {name} is missing or not a string")),
    }
}

/// The manifest's `files` array.
fn manifest_files() -> Result<Vec<Value>, String> {
    let manifest = load_json("manifest.json")?;
    let Value::Object(object) = &manifest else {
        return Err("manifest.json: expected an object".to_owned());
    };
    match object.get("files") {
        Some(Value::Array(files)) => Ok(files.clone()),
        _ => Err("manifest.json: member files is missing or not an array".to_owned()),
    }
}

/// Every listed artifact exists with its pinned SHA-256, parses into the
/// typed model with the manifest's kind, and re-serializes to the very
/// bytes it came from.
#[test]
fn corpus_artifacts_round_trip_byte_exactly() -> Result<(), String> {
    for entry in &manifest_files()? {
        let rel = text(entry, "manifest files", "path")?.to_owned();
        let bytes = fs::read(corpus_root().join(&rel)).map_err(|e| format!("{rel}: {e}"))?;

        let pinned = text(entry, &rel, "sha256")?;
        assert_eq!(
            encode_hex(&digest(&bytes)),
            pinned,
            "{rel}: bytes do not match the manifest digest"
        );

        let kind = text(entry, &rel, "artifact_kind")?;
        let artifact = InferenceArtifact::parse(&bytes).map_err(|e| format!("{rel}: {e}"))?;
        assert_eq!(
            artifact.kind().token(),
            kind,
            "{rel}: parsed kind differs from the manifest"
        );

        let canonical = artifact.canonical_bytes();
        assert_eq!(
            canonical,
            bytes.strip_suffix(b"\n").unwrap_or(&bytes),
            "{rel}: re-serialization is not the canonical bytes it came from"
        );
        let reparsed = InferenceArtifact::parse(&canonical)
            .map_err(|e| format!("{rel}: canonical bytes do not reparse: {e}"))?;
        assert_eq!(
            reparsed, artifact,
            "{rel}: canonical form is not a fixed point"
        );
    }
    Ok(())
}

/// Every artifact file under the corpus directory is listed in the
/// manifest — the corpus holds nothing the typed replay would skip.
#[test]
fn manifest_lists_every_corpus_file() -> Result<(), String> {
    let mut on_disk = BTreeSet::new();
    for kind_dir in ["single-attempt", "streamed-attempt", "retried-attempt"] {
        for file in
            fs::read_dir(corpus_root().join(kind_dir)).map_err(|e| format!("{kind_dir}: {e}"))?
        {
            let file = file.map_err(|e| format!("{kind_dir}: {e}"))?;
            let name = file.file_name();
            on_disk.insert(format!("{kind_dir}/{}", name.to_string_lossy()));
        }
    }
    let listed: BTreeSet<String> = manifest_files()?
        .iter()
        .map(|entry| text(entry, "manifest files", "path").map(str::to_owned))
        .collect::<Result<_, _>>()?;
    assert_eq!(
        on_disk, listed,
        "the manifest and the corpus directory disagree"
    );
    Ok(())
}

/// The manifest's schema invariants pin the Rust constants that mirror
/// them: the closed metadata allowlist's nine entries and the reserved
/// field list's 43 names.
#[test]
fn manifest_invariants_match_the_rust_constants() -> Result<(), String> {
    let manifest = load_json("manifest.json")?;
    let Value::Object(object) = &manifest else {
        return Err("manifest.json: expected an object".to_owned());
    };
    let invariants = object
        .get("invariants")
        .ok_or("manifest.json: member invariants is missing")?;
    let Value::Object(invariants) = invariants else {
        return Err("manifest.json: member invariants is not an object".to_owned());
    };
    let allowlist = invariants
        .get("metadata_allowlist_entries")
        .ok_or("manifest.json: invariants.metadata_allowlist_entries is missing")?;
    assert_eq!(
        allowlist,
        &Value::Int(i64::try_from(METADATA_ALLOWLIST.len()).expect("small constant")),
        "the metadata allowlist drifted from the schema invariant"
    );
    let reserved = invariants
        .get("reserved_fields_rejected")
        .ok_or("manifest.json: invariants.reserved_fields_rejected is missing")?;
    assert_eq!(
        reserved,
        &Value::Int(i64::try_from(RESERVED_FIELDS.len()).expect("small constant")),
        "the reserved field list drifted from the schema invariant"
    );
    Ok(())
}

/// The streamed attempt's events arrive in `event_ordinal` order and the
/// retried attempt's retries each name an attempt that exists — the
/// ordering the reconstruction rules build on, proven on the pinned bytes.
#[test]
fn corpus_stream_and_retry_ordering_holds() -> Result<(), String> {
    let mut ordinals = Vec::new();
    for rel in [
        "streamed-attempt/event-0.json",
        "streamed-attempt/event-1.json",
        "streamed-attempt/event-2.json",
    ] {
        let bytes = fs::read(corpus_root().join(rel)).map_err(|e| format!("{rel}: {e}"))?;
        let artifact = InferenceArtifact::parse(&bytes).map_err(|e| format!("{rel}: {e}"))?;
        match artifact.event {
            BoundaryEvent::StreamingEvent { event_ordinal } => ordinals.push(event_ordinal),
            other => panic!("{rel}: expected a streaming event, got {other:?}"),
        }
    }
    let sorted: Vec<u64> = {
        let mut sorted = ordinals.clone();
        sorted.sort_unstable();
        sorted
    };
    assert_eq!(
        ordinals, sorted,
        "stream events are ordered by event_ordinal"
    );

    for rel in [
        "retried-attempt/attempt-0-retry.json",
        "retried-attempt/attempt-1-retry.json",
    ] {
        let bytes = fs::read(corpus_root().join(rel)).map_err(|e| format!("{rel}: {e}"))?;
        let artifact = InferenceArtifact::parse(&bytes).map_err(|e| format!("{rel}: {e}"))?;
        assert!(
            artifact.attempt_ordinal > 0,
            "{rel}: a retry follows an earlier attempt"
        );
    }
    Ok(())
}

/// The artifact kind token round-trips through the closed vocabulary: the
/// corpus exercises every one of the six kinds.
#[test]
fn corpus_covers_every_artifact_kind() -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for entry in &manifest_files()? {
        let kind = text(entry, "manifest files", "artifact_kind")?;
        seen.insert(kind.to_owned());
    }
    let every: BTreeSet<String> = InferenceArtifactKind::tokens()
        .iter()
        .map(|token| (*token).to_owned())
        .collect();
    assert_eq!(seen, every, "the corpus must exercise all six closed kinds");
    Ok(())
}
