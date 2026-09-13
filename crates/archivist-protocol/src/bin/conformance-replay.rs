// SPDX-License-Identifier: Apache-2.0

//! The Rust implementation's answer sheet over the committed conformance
//! corpus (`schemas/v1/examples/conformance`).
//!
//! This binary walks every golden vector — the pure derivation cases, the
//! canonicalization accept and rejection cases, the pinned verification keys,
//! and every complete scenario — and prints one RFC 8785 canonical JSON line
//! per vector carrying the values this crate computes from the vector's own
//! inputs. It asserts nothing against the goldens itself: the answer sheet is
//! consumed by `tools/contract-verifier.py` — the standalone verifier that
//! imports nothing from this crate — which computes the same answer sheet from
//! the same vectors with independent canonicalization, framing, and digest
//! code, checks it against the goldens, and then requires the two sheets to be
//! byte-identical (plan Section 8, Phase 1 exit gate: the Rust implementation
//! and a standalone verifier that does not import the protocol crate produce
//! identical canonical bytes, signatures, IDs, and keys).
//!
//! # Answer-sheet rows
//!
//! Rows are emitted sorted by `(row, id, source)`; each line is the canonical
//! serialization of its row object plus one LF. Field presence is pinned by
//! rule so both implementations emit the same shape from the same inputs:
//!
//! - `{"row":"canonicalization","id":…,"source":"object"|"noncanonical_text"|`
//!   `"nfc"|"nfd","canonical_hex":…}` — one row per canonicalizable source
//!   the case carries.
//! - `{"row":"canonicalization_rejection","id":…,"error_code":…}` — the wire
//!   code the bounded parser's failure maps to (`envelope.malformed` for
//!   syntax, duplicate members, lone surrogates, and bounds;
//!   `envelope.schema_invalid` for numbers outside the integer domain).
//! - `{"row":"derivation","id":…,"session_hash":…,"artifact_hash":…,`
//!   `"occurrence_id":…,"attestation_id":…,"blob_digest":…,`
//!   `"blob_object_key":…,"occurrence_object_key":…,`
//!   `"attestation_object_key":…}` — every identity construction and object
//!   key re-derived from the case inputs.
//! - `{"row":"key_id","id":<key name>,"key_id":…}` — the key-ID derivation
//!   (lowercase-hex SHA-256 of the raw public key) of every pinned key.
//! - `{"row":"scenario","id":…,"envelope_outcome":"accepted"|`
//!   `"rejected:<code>",…}` — for every scenario: the envelope validation
//!   outcome; when accepted, additionally `canonical_hex`,
//!   `envelope_digest`, `wire_canonical`, the re-derived `session_hash`,
//!   `artifact_hash`, `occurrence_id`, `attestation_id`, and the three
//!   `*_object_key` values; always, the recomputed `payload_digest`,
//!   `transport_digest`, `request_digest` of the transmitted bytes and the
//!   `signing_input_sha256` of the `ingest-attempt-v1` preimage framed from
//!   the attempt record's own fields.
//!
//! The attempt-level signature itself (Ed25519 verification, the receipt
//! chain, authorization-window and key-linkage decisions) is verified by the
//! standalone verifier against the pinned public keys and golden outcomes;
//! those layers live in `archivist-auth` (Phase 3), so they are deliberately
//! absent from this crate's answer sheet.
//!
//! Usage: `cargo run -p archivist-protocol --bin conformance-replay [-- <corpus dir>]`

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use archivist_protocol::derivation;
use archivist_protocol::envelope::Envelope;
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{
    AdapterId, ArtifactHash, ArtifactKind, AttestationId, BlobDigest, ClientId, ContentType,
    EnvelopeDigest, GenerationId, HarnessId, IncomingChecksum, KeyId, OccurrenceId, OpaqueId,
    RangeKind, RequestContentDigest, RequestId, SessionHash, StorageProfile, TenantId, Timestamp,
    VersionToken,
};

fn main() -> ExitCode {
    let root = std::env::args().nth(1).unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/v1/examples/conformance")
            .to_string_lossy()
            .into_owned()
    });
    match replay(Path::new(&root)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("conformance-replay: {error}");
            ExitCode::from(2)
        }
    }
}

/// One pending report line with its sort key.
struct Row {
    sort: String,
    line: String,
}

/// Load and parse a corpus file, failing with its path in the message.
fn load(root: &Path, rel: &str) -> Result<(Vec<u8>, Value), String> {
    let bytes = fs::read(root.join(rel)).map_err(|e| format!("{rel}: {e}"))?;
    let value = json::parse(&bytes).map_err(|e| format!("{rel}: {e}"))?;
    Ok((bytes, value))
}

/// Require an object member, failing with file, member, and reason.
fn member<'a>(value: &'a Value, rel: &str, name: &str) -> Result<&'a Value, String> {
    let Value::Object(object) = value else {
        return Err(format!("{rel}: expected an object"));
    };
    object
        .get(name)
        .ok_or_else(|| format!("{rel}: member {name} is missing"))
}

/// An optional member of an object value, `None` when absent or the parent
/// is not an object.
fn optional<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    match value {
        Value::Object(object) => object.get(name),
        _ => None,
    }
}

/// Require a text member.
fn text<'a>(value: &'a Value, rel: &str, name: &str) -> Result<&'a str, String> {
    match member(value, rel, name)? {
        Value::Text(text) => Ok(text),
        _ => Err(format!("{rel}: member {name} is not a string")),
    }
}

/// Require a `u63` member.
fn u63(value: &Value, rel: &str, name: &str) -> Result<u64, String> {
    match member(value, rel, name)? {
        Value::Int(n) if *n >= 0 => {
            u64::try_from(*n).map_err(|_| format!("{rel}: member {name} is not a u63 integer"))
        }
        _ => Err(format!("{rel}: member {name} is not a u63 integer")),
    }
}

/// Parse a text member through a grammar newtype.
fn parsed<T>(value: &Value, rel: &str, name: &str) -> Result<T, String>
where
    T: std::str::FromStr<Err = archivist_protocol::vocabulary::GrammarError>,
{
    let raw = text(value, rel, name)?;
    T::from_str(raw).map_err(|_| format!("{rel}: member {name} fails its grammar: {raw}"))
}

/// Lowercase hex of the SHA-256 digest of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    sha256::encode_hex(&sha256::digest(bytes))
}

/// Assemble one report line from ordered members.
fn line_of(row: &str, id: &str, source: &str, members: Vec<(&str, Value)>) -> Row {
    let mut object = Object::new();
    // The coordinates ride in the line itself, so a cross-implementation
    // divergence names its vector instead of pointing at a bare digest.
    object.set("row", Value::Text(row.to_owned()));
    object.set("id", Value::Text(id.to_owned()));
    if !source.is_empty() {
        object.set("source", Value::Text(source.to_owned()));
    }
    for (name, value) in members {
        object.set(name, value);
    }
    let mut line = String::from_utf8(Value::Object(object).canonical_bytes())
        .expect("canonical JSON is ASCII-safe UTF-8");
    line.push('\n');
    Row {
        sort: format!("{row}\u{1f}{id}\u{1f}{source}"),
        line,
    }
}

/// Replay the whole corpus, printing the answer sheet to stdout.
fn replay(root: &Path) -> Result<(), String> {
    if !root.join("manifest.json").is_file() {
        return Err(format!("{} is not a conformance corpus", root.display()));
    }
    let mut rows = Vec::new();
    derivation_rows(root, &mut rows)?;
    canonicalization_rows(root, &mut rows)?;
    key_rows(root, &mut rows)?;
    scenario_rows(root, &mut rows)?;
    rows.sort_by(|a, b| a.sort.cmp(&b.sort));
    let mut out = String::new();
    for row in rows {
        out.push_str(&row.line);
    }
    print!("{out}");
    Ok(())
}

/// The pure derivation table: inputs → every identity and object key.
fn derivation_rows(root: &Path, rows: &mut Vec<Row>) -> Result<(), String> {
    let rel = "derivations.json";
    let (_, table) = load(root, rel)?;
    let Value::Array(cases) = member(&table, rel, "cases")? else {
        return Err(format!("{rel}: cases is not an array"));
    };
    for case in cases {
        let id = text(case, rel, "id")?.to_owned();
        let inputs = member(case, rel, "inputs")?;
        let tenant: TenantId = parsed(inputs, rel, "tenant_id")?;
        let origin: ClientId = parsed(inputs, rel, "origin_client_id")?;
        let harness: HarnessId = parsed(inputs, rel, "harness")?;
        let upstream: OpaqueId = parsed(inputs, rel, "upstream_session_id")?;
        let kind: ArtifactKind = parsed(inputs, rel, "artifact_kind")?;
        let adapter: AdapterId = parsed(inputs, rel, "adapter_id")?;
        let projection: VersionToken = parsed(inputs, rel, "adapter_projection_version")?;
        let artifact_id: OpaqueId = parsed(inputs, rel, "adapter_artifact_id")?;
        let generation: GenerationId = parsed(inputs, rel, "generation")?;
        let range_kind: RangeKind = parsed(inputs, rel, "range_kind")?;
        let range_start = u63(inputs, rel, "range_start")?;
        let range_end = u63(inputs, rel, "range_end")?;
        let uploader: ClientId = parsed(inputs, rel, "uploader_client_id")?;
        let request: RequestId = parsed(inputs, rel, "request_id")?;
        let payload = text(inputs, rel, "canonical_payload")?;

        let session: SessionHash =
            derivation::session_hash(&tenant, &origin, &harness, upstream.as_str());
        let artifact: ArtifactHash =
            derivation::artifact_hash(&session, kind, &adapter, &projection, artifact_id.as_str());
        let blob: BlobDigest = derivation::blob_digest(payload.as_bytes());
        let occurrence: OccurrenceId = derivation::occurrence_id(
            &session,
            &artifact,
            &generation,
            range_kind,
            range_start,
            range_end,
            &blob,
        );
        let attestation: AttestationId =
            derivation::attestation_id(&occurrence, &uploader, &request);

        rows.push(line_of(
            "derivation",
            &id,
            "",
            vec![
                ("session_hash", Value::Text(session.to_hex())),
                ("artifact_hash", Value::Text(artifact.to_hex())),
                ("occurrence_id", Value::Text(occurrence.to_hex())),
                ("attestation_id", Value::Text(attestation.to_hex())),
                ("blob_digest", Value::Text(blob.to_hex())),
                (
                    "blob_object_key",
                    Value::Text(
                        BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &blob).to_string(),
                    ),
                ),
                (
                    "occurrence_object_key",
                    Value::Text(
                        OccurrenceObjectKey::new(&tenant, &origin, &harness, &session, &occurrence)
                            .to_string(),
                    ),
                ),
                (
                    "attestation_object_key",
                    Value::Text(
                        AttestationObjectKey::new(&tenant, &occurrence, &attestation).to_string(),
                    ),
                ),
            ],
        ));
    }
    Ok(())
}

/// The canonicalization table: accept cases to canonical bytes, rejection
/// cases to the wire code the parser failure maps to.
fn canonicalization_rows(root: &Path, rows: &mut Vec<Row>) -> Result<(), String> {
    let rel = "canonicalization.json";
    let (_, table) = load(root, rel)?;
    let Value::Array(cases) = member(&table, rel, "cases")? else {
        return Err(format!("{rel}: cases is not an array"));
    };
    for case in cases {
        let id = text(case, rel, "id")?.to_owned();
        if let Some(Value::Object(_)) = optional(case, "object") {
            let hex = canonical_hex_of_value(case, rel, "object")?;
            rows.push(line_of(
                "canonicalization",
                &id,
                "object",
                vec![("canonical_hex", Value::Text(hex))],
            ));
        }
        // Optional members are detected by kind: a `noncanonical_text` entry
        // is always a string, `object`/`nfc`/`nfd` always objects.
        if let Some(Value::Text(wire)) = optional(case, "noncanonical_text") {
            let value = json::parse(wire.as_bytes())
                .map_err(|e| format!("{rel} case {id}: noncanonical_text: {e}"))?;
            let hex = hex_encode(&value.canonical_bytes());
            rows.push(line_of(
                "canonicalization",
                &id,
                "noncanonical_text",
                vec![("canonical_hex", Value::Text(hex))],
            ));
        }
        for source in ["nfc", "nfd"] {
            if let Some(Value::Object(_)) = optional(case, source) {
                let hex = canonical_hex_of_value(case, rel, source)?;
                rows.push(line_of(
                    "canonicalization",
                    &id,
                    source,
                    vec![("canonical_hex", Value::Text(hex))],
                ));
            }
        }
    }
    let Value::Array(rejections) = member(&table, rel, "rejections")? else {
        return Err(format!("{rel}: rejections is not an array"));
    };
    for rejection in rejections {
        let id = text(rejection, rel, "id")?.to_owned();
        let wire = text(rejection, rel, "text")?;
        let code = match json::parse(wire.as_bytes()) {
            Ok(_) => {
                return Err(format!(
                    "{rel} case {id}: expected rejection, parsed cleanly"
                ));
            }
            Err(json::ParseError::NumberOutsideDomain { .. }) => "envelope.schema_invalid",
            Err(_) => "envelope.malformed",
        };
        rows.push(line_of(
            "canonicalization_rejection",
            &id,
            "",
            vec![("error_code", Value::Text(code.to_owned()))],
        ));
    }
    Ok(())
}

/// Canonical bytes of an embedded value member, as lowercase hex.
fn canonical_hex_of_value(parent: &Value, rel: &str, name: &str) -> Result<String, String> {
    let value = member(parent, rel, name)?;
    Ok(hex_encode(&value.canonical_bytes()))
}

/// The pinned keys: the `key-id` derivation over every published public key.
fn key_rows(root: &Path, rows: &mut Vec<Row>) -> Result<(), String> {
    let rel = "keys.json";
    let (_, table) = load(root, rel)?;
    let Value::Array(keys) = member(&table, rel, "keys")? else {
        return Err(format!("{rel}: keys is not an array"));
    };
    for key in keys {
        let name = text(key, rel, "name")?.to_owned();
        let public =
            archivist_protocol::vocabulary::Ed25519PublicKey::parse(text(key, rel, "public_key")?)
                .map_err(|_| format!("{rel} key {name}: public_key fails its grammar"))?;
        let key_id = KeyId::from_public_key(&public);
        rows.push(line_of(
            "key_id",
            &name,
            "",
            vec![("key_id", Value::Text(key_id.to_hex()))],
        ));
    }
    Ok(())
}

/// Every scenario: envelope validation outcome plus the digests and signing
/// preimage the transmitted and declared bytes pin.
// One function per report row kind keeps the row assembly readable as a
// unit; the row's members are the answer sheet's contract, not reusable
// logic worth splitting further.
#[allow(clippy::too_many_lines)]
fn scenario_rows(root: &Path, rows: &mut Vec<Row>) -> Result<(), String> {
    let rel = "manifest.json";
    let (_, manifest) = load(root, rel)?;
    let Value::Array(scenarios) = member(&manifest, rel, "scenarios")? else {
        return Err(format!("{rel}: scenarios is not an array"));
    };
    for scenario in scenarios {
        let id = text(scenario, rel, "id")?.to_owned();
        let files = member(scenario, rel, "files")?;
        let envelope_rel = text(files, rel, "envelope")?.to_owned();
        let payload_rel = text(files, rel, "payload")?.to_owned();
        let body_rel = text(files, rel, "request_body")?.to_owned();
        let attempt_rel = text(files, rel, "attempt")?.to_owned();

        let envelope_bytes =
            fs::read(root.join(&envelope_rel)).map_err(|e| format!("{envelope_rel}: {e}"))?;
        let payload_bytes =
            fs::read(root.join(&payload_rel)).map_err(|e| format!("{payload_rel}: {e}"))?;
        let body_bytes = fs::read(root.join(&body_rel)).map_err(|e| format!("{body_rel}: {e}"))?;
        let (_, attempt) = load(root, &attempt_rel)?;

        let mut members = Vec::new();
        match Envelope::parse(&envelope_bytes) {
            Ok(envelope) => {
                let canonical = envelope.canonical_bytes();
                let session = envelope.rederive_session_hash();
                let occurrence = envelope.rederive_occurrence_id();
                let attestation = envelope.rederive_attestation_id();
                members.push(("envelope_outcome", Value::Text("accepted".to_owned())));
                members.push(("canonical_hex", Value::Text(hex_encode(&canonical))));
                members.push((
                    "envelope_digest",
                    Value::Text(envelope.envelope_digest().to_hex()),
                ));
                members.push(("wire_canonical", Value::Bool(canonical == envelope_bytes)));
                members.push(("session_hash", Value::Text(session.to_hex())));
                members.push((
                    "artifact_hash",
                    Value::Text(envelope.rederive_artifact_hash().to_hex()),
                ));
                members.push(("occurrence_id", Value::Text(occurrence.to_hex())));
                members.push(("attestation_id", Value::Text(attestation.to_hex())));
                members.push((
                    "blob_object_key",
                    Value::Text(
                        BlobObjectKey::new(
                            &envelope.tenant_id,
                            envelope.storage_profile,
                            &envelope.blob_digest,
                        )
                        .to_string(),
                    ),
                ));
                members.push((
                    "occurrence_object_key",
                    Value::Text(
                        OccurrenceObjectKey::new(
                            &envelope.tenant_id,
                            &envelope.origin_client_id,
                            &envelope.harness,
                            &session,
                            &occurrence,
                        )
                        .to_string(),
                    ),
                ));
                members.push((
                    "attestation_object_key",
                    Value::Text(
                        AttestationObjectKey::new(&envelope.tenant_id, &occurrence, &attestation)
                            .to_string(),
                    ),
                ));
            }
            Err(error) => {
                members.push((
                    "envelope_outcome",
                    Value::Text(format!("rejected:{}", error.code().as_str())),
                ));
            }
        }

        let payload_hex = sha256_hex(&payload_bytes);
        members.push(("payload_digest", Value::Text(payload_hex.clone())));
        members.push(("transport_digest", Value::Text(payload_hex)));
        members.push(("request_digest", Value::Text(sha256_hex(&body_bytes))));

        let method = text(&attempt, &attempt_rel, "http_method")?.to_owned();
        let route = text(&attempt, &attempt_rel, "route")?.to_owned();
        let content_type = ContentType::parse(text(&attempt, &attempt_rel, "content_type")?)
            .map_err(|_| format!("{attempt_rel}: content_type fails its grammar"))?;
        let request_digest =
            RequestContentDigest::parse(text(&attempt, &attempt_rel, "request_content_digest")?)
                .map_err(|_| format!("{attempt_rel}: request_content_digest fails its grammar"))?;
        let envelope_digest =
            EnvelopeDigest::parse(text(&attempt, &attempt_rel, "envelope_digest")?)
                .map_err(|_| format!("{attempt_rel}: envelope_digest fails its grammar"))?;
        let canonical_digest =
            BlobDigest::parse(text(&attempt, &attempt_rel, "payload_canonical_digest")?).map_err(
                |_| format!("{attempt_rel}: payload_canonical_digest fails its grammar"),
            )?;
        let transport_digest =
            IncomingChecksum::parse(text(&attempt, &attempt_rel, "payload_transport_digest")?)
                .map_err(|_| {
                    format!("{attempt_rel}: payload_transport_digest fails its grammar")
                })?;
        let key_id = KeyId::parse(text(&attempt, &attempt_rel, "uploader_key_id")?)
            .map_err(|_| format!("{attempt_rel}: uploader_key_id fails its grammar"))?;
        let epoch = u63(&attempt, &attempt_rel, "authorization_epoch")?;
        let authorization =
            Timestamp::parse(text(&attempt, &attempt_rel, "authorization_timestamp")?)
                .map_err(|_| format!("{attempt_rel}: authorization_timestamp fails its grammar"))?;
        let signing_input = derivation::ingest_attempt_signing_input(
            &method,
            &route,
            content_type.as_str(),
            &request_digest,
            &envelope_digest,
            &canonical_digest,
            &transport_digest,
            &key_id,
            epoch,
            &authorization,
        );
        members.push((
            "signing_input_sha256",
            Value::Text(sha256_hex(&signing_input)),
        ));

        rows.push(line_of("scenario", &id, "", members));
    }
    Ok(())
}

/// Lowercase hex of `bytes`.
fn hex_encode(bytes: &[u8]) -> String {
    sha256::encode_hex(bytes)
}
