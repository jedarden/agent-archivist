// SPDX-License-Identifier: Apache-2.0

//! Corpus-driven integration replay of the ingest parser chain —
//! [`archivist_server::parse::framing`], [`archivist_server::parse::parts`],
//! and [`archivist_server::parse::ingest`] — over the language-neutral
//! conformance corpus (`schemas/v1/examples/conformance`; plan Sections
//! 7.1–7.5 and 8).
//!
//! The protocol crate's corpus replay
//! (`archivist-protocol/tests/conformance.rs`) drives `Envelope::parse` on
//! each scenario's `envelope.json` fixture. This file drives the *request*
//! surface instead: the transmitted `request.body` bytes, framed by the
//! attempt's pinned Content-Type, split and validated and streamed exactly
//! as the `/v1/ingest` handler will consume them. Every assertion compares
//! bytes against the pinned fixtures — the canonical envelope form, the
//! payload stream, the registry code and pinned message — and names the
//! scenario in the failure.
//!
//! # Strand boundaries: the corpus scenarios this parser does not own
//!
//! The corpus pins one end-to-end wire outcome per scenario, but five of
//! them are decided by layers the parser chain sits beneath or above; the
//! parser's own outcome for those bytes is deliberately unpinned here:
//!
//! | Scenario | Pinned wire outcome | Owning strand |
//! |---|---|---|
//! | `invalid-altered-framing-boundary` | `auth.authorization_rejected` | The authorization middleware (bead `aa-834ca705`): the transmitted body's delimiters no longer match the boundary the signature covered, so the signed request content digest fails and the request is rejected before any parsing runs. |
//! | `invalid-altered-payload-byte` | `auth.authorization_rejected` | The streaming payload-validation strand (bead `aa-d71d8140`): the altered byte breaks the payload digests the signature covered; digest verification is that strand's job, not the parser's. |
//! | `invalid-stale-authorization` | `auth.authorization_rejected` | The authorization middleware (bead `aa-834ca705`): the authorization timestamp falls outside the pinned window. |
//! | `invalid-cross-tenant-forbidden` | `auth.forbidden` | The authorization middleware (bead `aa-834ca705`): the uploader's key is not authorized for the declared tenant/origin. |
//! | `invalid-integrity-conflict` | `storage.integrity_conflict` | The storage commit layer: the conflict is with an *existing* stored object, so it can only surface at commit time, after parsing succeeded. |
//!
//! HTTP serialization of every rejection — including the parser's own
//! codes — is the route layer's strand (bead `aa-aebd9a6e`); this file
//! asserts the parser's code and pinned message, never a wire body.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use archivist_protocol::json::{self, Value};
use archivist_server::parse::framing::RequestFraming;
use archivist_server::parse::ingest::{IngestParseError, parse_ingest};

/// The committed corpus, relative to this crate's manifest directory.
fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/v1/examples/conformance")
}

/// Read one corpus file, failing with its repository-relative path.
fn read(root: &Path, rel: &str) -> Vec<u8> {
    fs::read(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Read and parse one corpus JSON file.
fn load_json(root: &Path, rel: &str) -> Value {
    let bytes = read(root, rel);
    json::parse(&bytes).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Require an object member.
fn member<'a>(value: &'a Value, rel: &str, name: &str) -> &'a Value {
    let Value::Object(object) = value else {
        panic!("{rel}: expected an object");
    };
    object
        .get(name)
        .unwrap_or_else(|| panic!("{rel}: member {name} is missing"))
}

/// Require a text member.
fn text<'a>(value: &'a Value, rel: &str, name: &str) -> &'a str {
    match member(value, rel, name) {
        Value::Text(text) => text,
        other => panic!("{rel}: member {name} is not text, found {other:?}"),
    }
}

/// The corpus manifest's scenario objects, in pinned order.
fn scenarios<'a>(manifest: &'a Value) -> &'a [Value] {
    match member(manifest, "manifest.json", "scenarios") {
        Value::Array(scenarios) => scenarios,
        other => panic!("manifest.json scenarios is not an array, found {other:?}"),
    }
}

/// A scenario's manifest `files` entry: repository-relative corpus paths.
fn files<'a>(scenario: &'a Value, id: &str) -> &'a Value {
    member(scenario, id, "files")
}

/// A scenario's manifest `expect` entry: the pinned end-to-end outcome.
fn expect<'a>(scenario: &'a Value, id: &str) -> &'a Value {
    member(scenario, id, "expect")
}

/// The scenarios the manifest pins as accepted end to end. All seven are
/// parser-reachable: the parser must admit each transmitted body, surface
/// its envelope in canonical form, and stream its payload part byte-for-byte.
const VALID_SCENARIOS: [&str; 7] = [
    "valid-direct-baseline",
    "valid-reordered-envelope-framing",
    "valid-relay-upload",
    "valid-unicode-session",
    "valid-synthetic-session-id",
    "valid-cross-tenant-second",
    "valid-retry-after-window",
];

/// The scenarios whose pinned rejection is this parser's own outcome: a
/// field violation the two-part split or the envelope validation raises.
const FIELD_VIOLATION_SCENARIOS: [&str; 3] = [
    "invalid-occurrence-id-mismatch",
    "invalid-unknown-enum-value",
    "invalid-reserved-field",
];

/// The scenarios whose pinned rejection belongs to a strand other than the
/// parser chain (see the module docs for the per-scenario owner).
const STRAND_BOUNDARY_SCENARIOS: [&str; 5] = [
    "invalid-altered-framing-boundary",
    "invalid-altered-payload-byte",
    "invalid-stale-authorization",
    "invalid-cross-tenant-forbidden",
    "invalid-integrity-conflict",
];

/// Every registry code the ingest parser's surface can emit: the framing
/// split's codes plus the envelope validation's. Anything outside this set
/// is another strand's outcome by construction.
const PARSER_SURFACE_CODES: [&str; 6] = [
    "request.framing_invalid",
    "envelope.media_type_unsupported",
    "envelope.malformed",
    "envelope.version_unsupported",
    "envelope.schema_invalid",
    "envelope.size_exceeded",
];

/// A scenario's pinned Content-Type, validated through the framing layer
/// the way the handler validates the request header.
fn corpus_framing(root: &Path, id: &str) -> RequestFraming {
    let attempt_rel = format!("scenarios/{id}/attempt.json");
    let attempt = load_json(root, &attempt_rel);
    let content_type = text(&attempt, &attempt_rel, "content_type");
    RequestFraming::validate_content_type(content_type)
        .unwrap_or_else(|e| panic!("{id}: content_type {content_type:?}: {e:?}"))
}

/// One scenario's pinned file, by manifest role (`envelope`, `payload`,
/// `request_body`, `error`).
fn corpus_file(root: &Path, id: &str, role: &str) -> Vec<u8> {
    let manifest = load_json(root, "manifest.json");
    for scenario in scenarios(&manifest) {
        if text(scenario, "manifest.json", "id") == id {
            let rel = text(files(scenario, id), id, role);
            return read(root, rel);
        }
    }
    panic!("{id} is not in the corpus manifest");
}

/// The canonical bytes of a scenario's pinned envelope fixture: the fixture
/// parsed and re-serialized. For the wire-canonical scenarios this equals
/// the fixture bytes themselves; `valid-reordered-envelope-framing` is the
/// deliberate exception whose fixture is pretty-printed.
fn canonical_envelope_fixture(root: &Path, id: &str) -> Vec<u8> {
    let rel = format!("scenarios/{id}/envelope.json");
    let value = load_json(root, &rel);
    value.canonical_bytes()
}

/// The registry code the manifest pins for a scenario, absent for the
/// accepted ones.
fn pinned_error_code(scenario: &Value, id: &str) -> Option<String> {
    let Value::Object(expectation) = expect(scenario, id) else {
        panic!("{id}: expect is not an object");
    };
    match expectation.get("error_code") {
        Some(Value::Text(code)) => Some(code.clone()),
        Some(other) => panic!("{id}: error_code is text or absent, found {other:?}"),
        None => None,
    }
}

#[test]
fn every_manifest_scenario_is_classified_for_the_parser() {
    let root = corpus_root();
    let manifest = load_json(&root, "manifest.json");
    let mut classified = 0;

    for scenario in scenarios(&manifest) {
        let id = text(scenario, "manifest.json", "id").to_owned();
        let outcome = text(expect(scenario, &id), &id, "outcome");
        let code = pinned_error_code(scenario, &id);

        if VALID_SCENARIOS.contains(&id.as_str()) {
            assert_eq!(
                outcome, "accepted",
                "{id}: classified as parser-reachable but the corpus pins {outcome}"
            );
            assert!(code.is_none(), "{id}: an accepted scenario pins {code:?}");
        } else if FIELD_VIOLATION_SCENARIOS.contains(&id.as_str()) {
            assert_eq!(
                outcome, "rejected",
                "{id}: classified as a parser rejection but the corpus pins {outcome}"
            );
            let code = code.unwrap_or_else(|| panic!("{id}: no pinned error code"));
            assert!(
                PARSER_SURFACE_CODES.contains(&code.as_str()),
                "{id}: {code} is not a code the ingest parser's surface emits"
            );
        } else if STRAND_BOUNDARY_SCENARIOS.contains(&id.as_str()) {
            assert_eq!(
                outcome, "rejected",
                "{id}: classified as a strand-boundary scenario but the corpus pins {outcome}"
            );
            let code = code.unwrap_or_else(|| panic!("{id}: no pinned error code"));
            assert!(
                !PARSER_SURFACE_CODES.contains(&code.as_str()),
                "{id}: {code} moved into the parser's surface — reclassify the scenario"
            );
            let error_rel = format!("scenarios/{id}/error.json");
            let error = load_json(&root, &error_rel);
            assert_eq!(
                text(&error, &error_rel, "code"),
                code,
                "{id}: error.json and the manifest disagree on the pinned code"
            );
        } else {
            panic!(
                "{id}: a corpus scenario no parser assertion covers — classify it in \
                 VALID_SCENARIOS, FIELD_VIOLATION_SCENARIOS, or STRAND_BOUNDARY_SCENARIOS \
                 and pin its outcome"
            );
        }
        classified += 1;
    }

    assert_eq!(
        classified,
        VALID_SCENARIOS.len() + FIELD_VIOLATION_SCENARIOS.len() + STRAND_BOUNDARY_SCENARIOS.len(),
        "the manifest lists scenarios the classification double-counts"
    );
}

#[test]
fn every_valid_scenario_parses_to_its_pinned_envelope_and_streaming_payload() {
    let root = corpus_root();

    for id in VALID_SCENARIOS {
        let framing = corpus_framing(&root, id);
        let body = corpus_file(&root, id, "request_body");
        let (envelope, mut stream) = parse_ingest(&framing, &body[..])
            .unwrap_or_else(|e| panic!("{id}: the valid scenario was rejected as {e:?}"));

        // Part one parsed to the protocol type and re-serializes to the
        // canonical form of the pinned envelope — the identity inputs
        // survived the split and re-derivation byte-for-byte. The
        // wire-canonical scenarios pin the stronger fact that the fixture
        // bytes are already that canonical form.
        let fixture = corpus_file(&root, id, "envelope");
        assert_eq!(
            envelope.canonical_bytes(),
            canonical_envelope_fixture(&root, id),
            "{id}: the parsed envelope does not canonicalize to the pinned fixture"
        );
        let manifest = load_json(&root, "manifest.json");
        let wire_canonical = scenarios(&manifest)
            .iter()
            .find(|scenario| text(scenario, "manifest.json", "id") == id)
            .map(
                |scenario| match member(scenario, id, "envelope_wire_canonical") {
                    Value::Bool(flag) => *flag,
                    other => panic!("{id}: envelope_wire_canonical is a bool, found {other:?}"),
                },
            )
            .unwrap_or_else(|| panic!("{id}: not in the corpus manifest"));
        if wire_canonical {
            assert_eq!(
                envelope.canonical_bytes(),
                fixture,
                "{id}: the wire-canonical fixture is not the canonical bytes"
            );
        }

        // Part two streams byte-identical to the pinned payload under the
        // identity transport the v1 vectors pin, and closes clean.
        assert_eq!(
            stream.media_type(),
            "application/octet-stream",
            "{id}: the v1 vectors pin the identity transport"
        );
        let mut payload = Vec::new();
        stream
            .read_to_end(&mut payload)
            .unwrap_or_else(|e| panic!("{id}: the payload stream failed: {e}"));
        stream
            .finish()
            .unwrap_or_else(|e| panic!("{id}: the payload stream did not close clean: {e:?}"));
        assert_eq!(
            payload,
            corpus_file(&root, id, "payload"),
            "{id}: the streamed payload is not byte-identical to the pinned fixture"
        );
    }
}

#[test]
fn every_field_violation_rejects_with_its_pinned_code_and_message() {
    let root = corpus_root();

    for id in FIELD_VIOLATION_SCENARIOS {
        let framing = corpus_framing(&root, id);
        let body = corpus_file(&root, id, "request_body");
        let error = parse_ingest(&framing, &body[..])
            .err()
            .unwrap_or_else(|| panic!("{id}: the violating scenario parsed"));

        // The parser's code is exactly the corpus's pinned code — the
        // registry entry the scenario's error record carries.
        let error_rel = format!("scenarios/{id}/error.json");
        let pinned = load_json(&root, &error_rel);
        let pinned_code = text(&pinned, &error_rel, "code");
        assert_eq!(
            error.code().as_str(),
            pinned_code,
            "{id}: the parser rejected with a different code than the scenario pins"
        );
        // And the rendered message is the pinned template with its
        // structural substitution, byte-for-byte the corpus's error body.
        assert_eq!(
            error.message().as_str(),
            text(&pinned, &error_rel, "message"),
            "{id}: the rendered message is not the pinned one"
        );
        // The typed error names a field inside the parser's static schema
        // vocabulary; a request value never reaches the rendering.
        if let IngestParseError::Envelope(
            archivist_protocol::envelope::EnvelopeError::SchemaInvalid { field, .. },
        ) = &error
        {
            assert!(
                field.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{id}: the reported field {field:?} is not a schema member name"
            );
        } else {
            panic!("{id}: a field violation surfaced as {error:?}");
        }
    }
}

#[test]
fn the_non_parser_rejections_belong_to_other_strands() {
    let root = corpus_root();

    for id in STRAND_BOUNDARY_SCENARIOS {
        // The pinned code stays outside the parser's surface, and the
        // scenario's own error record agrees with the manifest. The
        // per-strand ownership is documented in the module docs; this
        // assertion is the tripwire: if one of these codes ever moves into
        // the parser's mapping, the strand boundary moved with it.
        let manifest = load_json(&root, "manifest.json");
        let scenario = scenarios(&manifest)
            .iter()
            .find(|scenario| text(scenario, "manifest.json", "id") == id)
            .unwrap_or_else(|| panic!("{id}: not in the corpus manifest"));
        let code =
            pinned_error_code(scenario, id).unwrap_or_else(|| panic!("{id}: no pinned error code"));
        assert!(
            !PARSER_SURFACE_CODES.contains(&code.as_str()),
            "{id}: {code} is the parser's outcome now — move the scenario into \
             FIELD_VIOLATION_SCENARIOS and pin the parser's behavior"
        );
        let error_rel = format!("scenarios/{id}/error.json");
        let pinned = load_json(&root, &error_rel);
        assert_eq!(
            text(&pinned, &error_rel, "code"),
            code,
            "{id}: error.json and the manifest disagree on the pinned code"
        );
        assert_eq!(
            text(expect(scenario, id), id, "outcome"),
            "rejected",
            "{id}: a strand-boundary scenario must pin rejection"
        );
    }
}
