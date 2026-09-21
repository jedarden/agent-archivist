// SPDX-License-Identifier: Apache-2.0

//! The ingest parser's public error surface: the two-part split of
//! [`super::parts`] handed to `archivist-protocol`'s envelope parser, with
//! every rejection mapped to a stable, content-free registry code and the
//! registry's pinned message template.
//!
//! [`parse_ingest`] composes the bounded pipeline in the order the plan
//! pins it (plan Section 7.2; VAL-002): validate the request framing, split
//! part one under the envelope cap, hand the extracted part-one bytes to
//! [`Envelope::parse`] for the full bounded validation — reserved names,
//! version axes, member grammars, calendar and consistency checks,
//! identity re-derivation, the canonical size cap — and only then expose
//! part two as the streaming payload handle. Every violation in that
//! sequence is rejected with an [`IngestParseError`] before any commit
//! exists to undo: this layer touches no store, so a rejected request
//! commits nothing by construction.
//!
//! # The seven acceptance classes
//!
//! The parent acceptance's seven violation classes each land on one frozen
//! `tools/error-codes.toml` code:
//!
//! | Class | Violation | Code |
//! |---|---|---|
//! | media | part one declares a type other than the pinned envelope media type | `envelope.media_type_unsupported` |
//! | part order | no payload part, a third part, a malformed delimiter, or a truncated body | `request.framing_invalid` |
//! | identifier | declared `occurrence_id`/`attestation_id` fails re-derivation | `envelope.schema_invalid` at the field |
//! | coordinate | `range_end` precedes `range_start` | `envelope.schema_invalid` at the field |
//! | encoding | unknown enum token (e.g. `transport_encoding`) | `envelope.schema_invalid` at the field |
//! | size | part one crosses the envelope cap, or the canonical form crosses it | `envelope.size_exceeded` |
//! | schema | part one is not canonical-domain JSON, or a member fails its grammar | `envelope.malformed` / `envelope.schema_invalid` at the field |
//!
//! The conformance corpus pins the schema-invalid renderings:
//! `invalid-occurrence-id-mismatch/error.json` and
//! `invalid-unknown-enum-value/error.json` both carry the
//! `envelope.schema_invalid` template with the field name substituted, and
//! the tests here render exactly those bytes.
//!
//! # Content-freedom (SEC-004; ERR-003; ERR-011–ERR-013)
//!
//! [`IngestParseError::message`] renders a registered template verbatim,
//! interpolating only bounded structural values under the ERR-012
//! allowlist: field names are the parser's own static schema vocabulary,
//! byte counts are configuration caps, and a rejected version major is a
//! bounded integer. No placeholder ever carries request bytes, the
//! boundary string, or a request field *value*: the observed part media
//! type is request content, so the media-type template renders both of its
//! placeholders in the bracket degradation ERR-013 pins (the pinned
//! envelope media type itself carries `;` and `=`, outside the frozen
//! token grammar, so it could not be emitted verbatim either). A value
//! that fails its constraint renders as the placeholder's name in square
//! brackets — deterministic, bounded, and visibly wrong — and the tests
//! hold every path to that under adversarial canary bodies.

use archivist_protocol::envelope::{Envelope, EnvelopeError};
use archivist_protocol::vocabulary::{ErrorCode, SafeMessage};

use super::framing::{ByteSource, RequestFraming};
use super::parts::{PayloadStream, TwoPartError, TwoPartRequest};
use crate::config::DEFAULT_ENVELOPE_MAX_BYTES;

/// The `request.framing_invalid` pinned message, verbatim from the
/// registry; the typed variant names the stage, never the wire body.
const MESSAGE_REQUEST_FRAMING_INVALID: &str = "The request is not the pinned two-part \
multipart/related framing; send the identical bytes the signature covered.";

/// The `envelope.malformed` pinned message, verbatim from the registry.
const MESSAGE_ENVELOPE_MALFORMED: &str =
    "The request envelope is not valid canonical JSON for the declared schema version.";

/// The `envelope.version_unsupported` template, verbatim from the registry;
/// `{version}` is the rejected major the envelope declared.
const TEMPLATE_ENVELOPE_VERSION_UNSUPPORTED: &str =
    "Envelope schema version {version} is not supported by this server.";

/// The `envelope.schema_invalid` template, verbatim from the registry;
/// `{field}` is the member the validation failed at — the corpus error
/// bodies pin exactly this rendering with the field substituted.
const TEMPLATE_ENVELOPE_SCHEMA_INVALID: &str =
    "The envelope fails schema validation at field {field}.";

/// The `envelope.size_exceeded` template, verbatim from the registry;
/// `{limit_bytes}` is the cap that was exceeded — a configuration value.
const TEMPLATE_ENVELOPE_SIZE_EXCEEDED: &str =
    "The canonical envelope exceeds the {limit_bytes} byte limit.";

/// The `envelope.media_type_unsupported` template, verbatim from the
/// registry. Both placeholders degrade on this path (see the module docs):
/// the observed media type is request content and the pinned envelope
/// media type is outside the frozen token grammar.
const TEMPLATE_ENVELOPE_MEDIA_TYPE_UNSUPPORTED: &str =
    "Media type {media_type} is not accepted; this path accepts {expected_media_type}.";

/// Why the pinned ingest parse did not produce an envelope and a payload.
///
/// Closed and content-free like the layers beneath it: the framing half
/// carries the two-part split's typed stage, the envelope half the
/// protocol parser's typed failure — between them no variant holds a byte
/// of the request, so no rendering of one can echo request bytes, the
/// boundary, or a field value (SEC-004; ERR-003).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestParseError {
    /// The two-part split rejected the request: part order, the part-one
    /// media type, the envelope cap, or the body framing itself.
    Framing(TwoPartError),
    /// The extracted part-one bytes failed [`Envelope::parse`]: not
    /// canonical-domain JSON, an unsupported version axis, a member
    /// outside its grammar, or a canonical form over the cap.
    Envelope(EnvelopeError),
}

impl IngestParseError {
    /// The stable wire code for this failure — one of the registry's
    /// `request.framing_invalid` or `envelope.*` entries; the HTTP status,
    /// retryability, and class travel with the code in the registry, and
    /// the wire body rendering is the route layer's strand.
    ///
    /// # Panics
    /// Never in practice: every literal beneath the two inner `code()`
    /// calls matches the registry grammar pinned by
    /// `tools/check-error-codes.py`, so a panic is a programming error
    /// introduced alongside this match, not a wire condition.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Framing(framing) => framing.code(),
            Self::Envelope(envelope) => envelope.code(),
        }
    }

    /// The registry's pinned message template rendered for this failure
    /// (ERR-011–ERR-013): template text verbatim, placeholders filled only
    /// with bounded structural values that pass their frozen constraints
    /// and the bracket degradation otherwise. Deterministic for a given
    /// failure — the same violation renders the same bytes — and safe for
    /// the wire: no placeholder carries request-derived text (the module
    /// docs hold the media-type path to this explicitly).
    ///
    /// # Panics
    /// Never in practice: every rendering is printable ASCII under the
    /// 200-character bound by construction (the longest template is 96
    /// characters and the largest interpolations are bracket names and
    /// sub-20-digit integers), so a panic is a template edit that broke
    /// the grammar, caught by the tests the same commit carries.
    #[must_use]
    pub fn message(&self) -> SafeMessage {
        let rendered = match self {
            Self::Framing(TwoPartError::EnvelopeNotFirst) => {
                TEMPLATE_ENVELOPE_MEDIA_TYPE_UNSUPPORTED
                    .replace("{media_type}", "[media_type]")
                    .replace("{expected_media_type}", "[expected_media_type]")
            }
            Self::Framing(TwoPartError::EnvelopeExceedsCap { limit_bytes }) => {
                TEMPLATE_ENVELOPE_SIZE_EXCEEDED
                    .replace("{limit_bytes}", &render_bytes(*limit_bytes))
            }
            Self::Framing(_) => MESSAGE_REQUEST_FRAMING_INVALID.to_owned(),
            Self::Envelope(EnvelopeError::Malformed { .. }) => {
                MESSAGE_ENVELOPE_MALFORMED.to_owned()
            }
            Self::Envelope(EnvelopeError::VersionUnsupported { found, .. }) => {
                TEMPLATE_ENVELOPE_VERSION_UNSUPPORTED.replace("{version}", &render_version(*found))
            }
            Self::Envelope(EnvelopeError::SchemaInvalid { field, .. }) => {
                TEMPLATE_ENVELOPE_SCHEMA_INVALID.replace("{field}", &render_field(field))
            }
            Self::Envelope(EnvelopeError::SizeExceeded { limit_bytes }) => {
                TEMPLATE_ENVELOPE_SIZE_EXCEEDED.replace(
                    "{limit_bytes}",
                    &render_bytes(u64::try_from(*limit_bytes).unwrap_or(u64::MAX)),
                )
            }
        };
        SafeMessage::parse(&rendered).expect("rendered registry templates are safe messages")
    }
}

/// Render a `{version}` placeholder (ERR-012: token, `[0-9A-Za-z._+-]{1,
/// 32}`): the declared major as plain decimal. An `i64` always renders —
/// at worst 20 characters of digits and a sign — and the bracket
/// degradation stands in for anything outside the frozen grammar.
fn render_version(found: i64) -> String {
    let text = found.to_string();
    let in_grammar = text.len() <= 32
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'));
    if in_grammar {
        text
    } else {
        "[version]".to_owned()
    }
}

/// Render a `{field}` placeholder (ERR-012: identifier,
/// `[a-z0-9_.-]{1,64}`). The parser reports failures at its own static
/// schema member names, which all match; the bracket degradation stands in
/// for anything else, and a request value never reaches this function at
/// all.
fn render_field(field: &str) -> String {
    let in_grammar = !field.is_empty()
        && field.len() <= 64
        && field.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        });
    if in_grammar {
        field.to_owned()
    } else {
        "[field]".to_owned()
    }
}

/// Render a `{limit_bytes}` placeholder (ERR-012: integer, decimal, at
/// most 19 digits, below 2^63 at render time). Caps are configuration
/// values; the bracket degradation keeps an out-of-domain value off the
/// wire.
fn render_bytes(limit: u64) -> String {
    if i64::try_from(limit).is_ok() {
        limit.to_string()
    } else {
        "[limit_bytes]".to_owned()
    }
}

/// Parse a bounded ingest request: the validated framing split into its
/// pinned two parts, part one validated as the canonical envelope, part
/// two exposed as the streaming payload handle.
///
/// The registry default envelope cap ([`DEFAULT_ENVELOPE_MAX_BYTES`])
/// bounds part one; the configured cap travels through
/// [`parse_ingest_with_cap`]. Every rejection is an [`IngestParseError`]
/// carrying its registry code and pinned message, raised before anything
/// is committed — this layer holds no store.
///
/// # Errors
/// The first violation in the pinned order: request framing, the
/// part-one media type, the envelope cap, part-one envelope validation,
/// then the payload part's presence.
pub fn parse_ingest<S: ByteSource>(
    framing: &RequestFraming,
    source: S,
) -> Result<(Envelope, PayloadStream<S>), IngestParseError> {
    parse_ingest_with_cap(framing, source, DEFAULT_ENVELOPE_MAX_BYTES)
}

/// Like [`parse_ingest`], with the validated `server.envelope_max_bytes`
/// configuration value as part one's cap in bytes.
///
/// # Errors
/// As [`parse_ingest`].
pub fn parse_ingest_with_cap<S: ByteSource>(
    framing: &RequestFraming,
    source: S,
    envelope_cap: u64,
) -> Result<(Envelope, PayloadStream<S>), IngestParseError> {
    let mut request = TwoPartRequest::with_envelope_cap(framing, source, envelope_cap);
    let part_one = request.envelope().map_err(IngestParseError::Framing)?;
    let envelope = Envelope::parse(&part_one).map_err(IngestParseError::Envelope)?;
    let stream = request.payload().map_err(IngestParseError::Framing)?;
    Ok((envelope, stream))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::path::{Path, PathBuf};

    use archivist_protocol::envelope::{CANONICAL_MAX_BYTES, Envelope, EnvelopeError};
    use archivist_protocol::json::{self, Object, Value};

    use super::{
        IngestParseError, MESSAGE_ENVELOPE_MALFORMED, MESSAGE_REQUEST_FRAMING_INVALID,
        TEMPLATE_ENVELOPE_MEDIA_TYPE_UNSUPPORTED, TEMPLATE_ENVELOPE_SCHEMA_INVALID,
        TEMPLATE_ENVELOPE_SIZE_EXCEEDED, TEMPLATE_ENVELOPE_VERSION_UNSUPPORTED, parse_ingest,
        parse_ingest_with_cap,
    };
    use crate::parse::framing::RequestFraming;
    use crate::parse::parts::{ENVELOPE_PART_MEDIA_TYPE, TwoPartError};

    /// The boundary the conformance corpus pins for the valid-direct
    /// baseline scenario.
    const BOUNDARY: &str = "archivist-conformance-01";
    /// Part two's media type under the identity transport the v1 vectors pin.
    const IDENTITY_MEDIA_TYPE: &str = "application/octet-stream";

    /// An alphanumeric boundary that exists only to prove nothing echoes
    /// it: every error path this module exposes is asserted against it.
    const CANARY_BOUNDARY: &str = "canary7delimQ9x2W";

    /// A body framed exactly as the conformance corpus transmits one.
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

    /// The corpus-pinned framing for [`BOUNDARY`] bodies.
    fn request_framing() -> RequestFraming {
        RequestFraming::validate_content_type(&format!("multipart/related; boundary={BOUNDARY}"))
            .expect("valid content type")
    }

    /// The framing for [`CANARY_BOUNDARY`] bodies.
    fn canary_framing() -> RequestFraming {
        RequestFraming::validate_content_type(&format!(
            "multipart/related; boundary={CANARY_BOUNDARY}"
        ))
        .expect("the canary boundary is grammatical")
    }

    /// The conformance corpus directory, reached the way every corpus test
    /// reaches it: relative to this crate's manifest.
    fn corpus_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/v1/examples/conformance")
    }

    /// One scenario's pinned file bytes, walked from the manifest the
    /// generator writes.
    fn corpus_file(id: &str, name: &str) -> Vec<u8> {
        let dir = corpus_dir();
        let manifest_bytes = fs::read(dir.join("manifest.json")).expect("manifest.json reads");
        let manifest = json::parse(&manifest_bytes).expect("manifest.json parses");
        let Value::Object(manifest_object) = &manifest else {
            panic!("manifest.json is an object");
        };
        let Some(Value::Array(scenarios)) = manifest_object.get("scenarios") else {
            panic!("manifest.json scenarios is an array");
        };
        let Some(scenario) = scenarios.iter().find(|scenario| {
            matches!(
                scenario,
                Value::Object(object)
                    if object.get("id") == Some(&Value::Text(id.to_owned()))
            )
        }) else {
            panic!("{id} is in the corpus manifest");
        };
        let Value::Object(scenario) = scenario else {
            panic!("{id} is an object");
        };
        let Some(Value::Object(files)) = scenario.get("files") else {
            panic!("{id}: files");
        };
        let Some(Value::Text(relative)) = files.get(name) else {
            panic!("{id}: files.{name} is a path");
        };
        fs::read(dir.join(relative)).unwrap_or_else(|error| panic!("{id}: {relative}: {error}"))
    }

    /// One scenario's pinned error message, from its `error.json`.
    fn corpus_error_message(id: &str) -> String {
        let bytes = corpus_file(id, "error");
        let error = json::parse(&bytes).unwrap_or_else(|error| panic!("{id}: {error}"));
        let Value::Object(object) = &error else {
            panic!("{id}: error.json is an object");
        };
        match object.get("message") {
            Some(Value::Text(message)) => message.clone(),
            other => panic!("{id}: error.json message is text, found {other:?}"),
        }
    }

    /// One text member of a parsed JSON object.
    fn text_member<'a>(object: &'a Object, name: &str) -> &'a str {
        match object.get(name) {
            Some(Value::Text(text)) => text,
            other => panic!("{name} is text, found {other:?}"),
        }
    }

    /// The valid baseline envelope, parsed for mutation.
    fn valid_envelope_object() -> Object {
        let bytes = corpus_file("valid-direct-baseline", "envelope");
        match json::parse(&bytes).expect("the baseline envelope parses") {
            Value::Object(object) => object,
            other => panic!("the baseline envelope is an object, found {other:?}"),
        }
    }

    /// A scenario's Content-Type, validated.
    fn corpus_framing(id: &str) -> RequestFraming {
        let attempt = json::parse(&corpus_file(id, "attempt")).expect("attempt parses");
        let Value::Object(object) = &attempt else {
            panic!("{id}: attempt.json is an object");
        };
        let content_type = text_member(object, "content_type");
        RequestFraming::validate_content_type(content_type)
            .unwrap_or_else(|error| panic!("{id}: {content_type}: {error:?}"))
    }

    /// `Envelope::parse`'s error for `bytes`, raised through the public
    /// surface type, so direct and composed parses assert identically.
    fn envelope_parse_error(bytes: &[u8]) -> IngestParseError {
        match Envelope::parse(bytes) {
            Ok(_) => panic!("the bytes were expected to fail envelope validation"),
            Err(error) => IngestParseError::Envelope(error),
        }
    }

    // -- the seven acceptance classes of the parent ----------------------

    #[test]
    fn the_media_class_maps_to_envelope_media_type_unsupported() {
        // Part one declaring anything but the pinned envelope media type
        // is the content-negotiation failure the registry's 415 code
        // names — detected at the split, before a part byte is kept.
        let body = framed_body(
            BOUNDARY,
            &[
                ("text/plain", b"not the envelope"),
                (ENVELOPE_PART_MEDIA_TYPE, b"{}"),
            ],
        );
        let framing = request_framing();
        let error = parse_ingest(&framing, &body[..]).expect_err("the media type is not accepted");
        assert_eq!(
            error,
            IngestParseError::Framing(TwoPartError::EnvelopeNotFirst)
        );
        assert_eq!(error.code().as_str(), "envelope.media_type_unsupported");
        // The pinned template with both placeholders in the ERR-013
        // bracket degradation: neither value is echoable.
        assert_eq!(
            error.message().as_str(),
            TEMPLATE_ENVELOPE_MEDIA_TYPE_UNSUPPORTED
                .replace("{media_type}", "[media_type]")
                .replace("{expected_media_type}", "[expected_media_type]")
        );
    }

    #[test]
    fn the_part_order_class_maps_to_request_framing_invalid() {
        let framing = request_framing();
        let envelope_bytes = corpus_file("valid-direct-baseline", "envelope");

        // The body closes after the envelope part: no payload part. The
        // part-order failure surfaces only after part one validates, so
        // part one here is a valid envelope.
        let body = framed_body(BOUNDARY, &[(ENVELOPE_PART_MEDIA_TYPE, &envelope_bytes)]);
        let error = parse_ingest(&framing, &body[..]).expect_err("no payload part");
        assert_eq!(
            error,
            IngestParseError::Framing(TwoPartError::PayloadPartMissing)
        );
        assert_eq!(error.code().as_str(), "request.framing_invalid");
        assert_eq!(error.message().as_str(), MESSAGE_REQUEST_FRAMING_INVALID);

        // The remaining part-order stages map through the same code and
        // the same pinned message: a third part (rejected at the caller's
        // finish, which `parse_ingest` does not run) and the framing
        // shape failures.
        for stage in [
            TwoPartError::TrailingPart,
            TwoPartError::Framing(crate::parse::framing::FramingError::MalformedDelimiter),
        ] {
            let error = IngestParseError::Framing(stage);
            assert_eq!(error.code().as_str(), "request.framing_invalid");
            assert_eq!(error.message().as_str(), MESSAGE_REQUEST_FRAMING_INVALID);
        }
    }

    #[test]
    fn the_identifier_class_maps_to_schema_invalid_at_occurrence_id() {
        // The corpus vector flips occurrence_id and pins the re-derivation
        // refusal — the parser surfaces the registry's schema-invalid
        // template with that field name, byte-for-byte the corpus's
        // pinned error body message.
        let id = "invalid-occurrence-id-mismatch";
        let error = parse_ingest(&corpus_framing(id), &corpus_file(id, "request_body")[..])
            .expect_err("the declared identity is refused");
        assert_eq!(
            error,
            IngestParseError::Envelope(EnvelopeError::SchemaInvalid {
                field: "occurrence_id",
                reason: "declared identity does not match the re-derived one",
            })
        );
        assert_eq!(error.code().as_str(), "envelope.schema_invalid");
        assert_eq!(
            error.message().as_str(),
            TEMPLATE_ENVELOPE_SCHEMA_INVALID.replace("{field}", "occurrence_id")
        );
        assert_eq!(error.message().as_str(), corpus_error_message(id));
        // The direct envelope parse of the pinned part-one bytes agrees
        // with the composed pipeline.
        assert_eq!(envelope_parse_error(&corpus_file(id, "envelope")), error);
    }

    #[test]
    fn the_coordinate_class_maps_to_schema_invalid_at_range_end() {
        // range_end before range_start is the VAL-002 ordering violation,
        // reported at range_end before identity re-derivation runs. The
        // baseline's coordinates are the zero-length byte range [0, 0],
        // so the start moves past the end to invert the ordering.
        let mut envelope = valid_envelope_object();
        let past_end = match envelope.get("range_end") {
            Some(Value::Int(end)) => end + 1,
            other => panic!("range_end is an integer, found {other:?}"),
        };
        envelope.set("range_start", Value::Int(past_end));
        let bytes = Value::Object(envelope).canonical_bytes();
        let error = envelope_parse_error(&bytes);
        assert_eq!(
            error,
            IngestParseError::Envelope(EnvelopeError::SchemaInvalid {
                field: "range_end",
                reason: "range_end precedes range_start",
            })
        );
        assert_eq!(error.code().as_str(), "envelope.schema_invalid");
        assert_eq!(
            error.message().as_str(),
            TEMPLATE_ENVELOPE_SCHEMA_INVALID.replace("{field}", "range_end")
        );
    }

    #[test]
    fn the_encoding_class_maps_to_schema_invalid_at_transport_encoding() {
        // The corpus vector carries an unknown transport_encoding token;
        // the parser fails closed at that field with the registry
        // template, matching the corpus's pinned error body message.
        let id = "invalid-unknown-enum-value";
        let error = parse_ingest(&corpus_framing(id), &corpus_file(id, "request_body")[..])
            .expect_err("the unknown enum token fails closed");
        assert_eq!(
            error,
            IngestParseError::Envelope(EnvelopeError::SchemaInvalid {
                field: "transport_encoding",
                reason: "value does not match the canonical grammar",
            })
        );
        assert_eq!(error.code().as_str(), "envelope.schema_invalid");
        assert_eq!(
            error.message().as_str(),
            TEMPLATE_ENVELOPE_SCHEMA_INVALID.replace("{field}", "transport_encoding")
        );
        assert_eq!(error.message().as_str(), corpus_error_message(id));
    }

    #[test]
    fn the_size_class_maps_to_envelope_size_exceeded() {
        // Part one crossing the cap is rejected at the cap, with the
        // registry template carrying the configured limit.
        let cap = 16u64;
        let oversized = vec![b'e'; usize::try_from(cap).expect("cap fits usize") + 1];
        let body = framed_body(
            BOUNDARY,
            &[
                (ENVELOPE_PART_MEDIA_TYPE, &oversized),
                (IDENTITY_MEDIA_TYPE, b"x"),
            ],
        );
        let framing = request_framing();
        let error =
            parse_ingest_with_cap(&framing, &body[..], cap).expect_err("the part crosses the cap");
        assert_eq!(
            error,
            IngestParseError::Framing(TwoPartError::EnvelopeExceedsCap { limit_bytes: cap })
        );
        assert_eq!(error.code().as_str(), "envelope.size_exceeded");
        assert_eq!(
            error.message().as_str(),
            TEMPLATE_ENVELOPE_SIZE_EXCEEDED.replace("{limit_bytes}", "16")
        );

        // The protocol-level cap: a canonical serialization over
        // CANONICAL_MAX_BYTES is the same code at the envelope layer. An
        // unknown member inflates the canonical bytes without touching
        // the identity inputs, so validation reaches the size check.
        let mut envelope = valid_envelope_object();
        let filler = "x".repeat(70 * 1024);
        envelope
            .insert("unknown_padding_for_size_check", Value::Text(filler))
            .expect("a new member inserts");
        let bytes = Value::Object(envelope).canonical_bytes();
        assert!(bytes.len() > CANONICAL_MAX_BYTES);
        let error = envelope_parse_error(&bytes);
        assert_eq!(
            error,
            IngestParseError::Envelope(EnvelopeError::SizeExceeded {
                limit_bytes: CANONICAL_MAX_BYTES,
            })
        );
        assert_eq!(error.code().as_str(), "envelope.size_exceeded");
        assert_eq!(
            error.message().as_str(),
            TEMPLATE_ENVELOPE_SIZE_EXCEEDED
                .replace("{limit_bytes}", &CANONICAL_MAX_BYTES.to_string())
        );
    }

    #[test]
    fn the_schema_class_maps_to_envelope_malformed_and_schema_invalid() {
        // Part one that is not canonical-domain JSON is envelope.malformed
        // — the registry's pre-schema parse failure — and the message is
        // the pinned template, carrying none of the bytes.
        let body = framed_body(
            BOUNDARY,
            &[
                (ENVELOPE_PART_MEDIA_TYPE, b"{not json at all"),
                (IDENTITY_MEDIA_TYPE, b"x"),
            ],
        );
        let framing = request_framing();
        let error = parse_ingest(&framing, &body[..]).expect_err("not JSON");
        assert_eq!(error.code().as_str(), "envelope.malformed", "{error:?}");
        assert_eq!(error.message().as_str(), MESSAGE_ENVELOPE_MALFORMED);

        // A reserved per-attempt/server member is the corpus's pinned
        // schema-invalid case, rejected before any field is read.
        let id = "invalid-reserved-field";
        let error = parse_ingest(&corpus_framing(id), &corpus_file(id, "request_body")[..])
            .expect_err("the reserved member is refused");
        assert_eq!(
            error,
            IngestParseError::Envelope(EnvelopeError::SchemaInvalid {
                field: "commit_time",
                reason: "reserved per-attempt or server member",
            })
        );
        assert_eq!(error.code().as_str(), "envelope.schema_invalid");
        assert_eq!(error.message().as_str(), corpus_error_message(id));
    }

    // -- the happy path ---------------------------------------------------

    #[test]
    fn the_valid_baseline_parses_to_the_envelope_and_streaming_payload() {
        let id = "valid-direct-baseline";
        let framing = corpus_framing(id);
        let body = corpus_file(id, "request_body");
        let payload_file = corpus_file(id, "payload");
        let (envelope, mut stream) =
            parse_ingest(&framing, &body[..]).expect("the baseline parses");
        // Part one parsed to the protocol type: the parsed envelope
        // re-serializes to exactly the pinned canonical bytes, so the
        // identity inputs survived re-derivation unchanged.
        assert_eq!(envelope.canonical_bytes(), corpus_file(id, "envelope"));
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).expect("streams");
        stream.finish().expect("closes");
        assert_eq!(payload, payload_file);
    }

    // -- content-freedom under adversarial canaries -----------------------

    #[test]
    fn no_error_path_echoes_an_adversarial_canary() {
        let canaries = [
            CANARY_BOUNDARY,
            "CANARY-MEDIA-TYPE-9q",
            "CANARY-PAYLOAD-BYTES-7w",
            "CANARY-FIELD-VALUE-3e",
            "CANARY-JSON-BYTES-5r",
        ];

        // An envelope whose identity-bearing field value carries a canary:
        // the grammar refuses it, and neither the typed error nor the
        // rendered message may echo the value.
        let canary_envelope = {
            let mut envelope = valid_envelope_object();
            envelope.set(
                "adapter_artifact_id",
                Value::Text("CANARY-FIELD-VALUE-3e".to_owned()),
            );
            Value::Object(envelope).canonical_bytes()
        };
        let valid_envelope = corpus_file("valid-direct-baseline", "envelope");
        let broken_json: &[u8] = b"{\"leaked\": \"CANARY-JSON-BYTES-5r\"";
        let cap = u64::try_from(CANONICAL_MAX_BYTES).expect("the cap fits u64");

        // Every rejection path, each built over a body carrying canaries
        // in the position that path touches: the boundary (all cases, via
        // the framing), the part media-type header, the part-one byte
        // count, the part-one JSON bytes, and an envelope field value.
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "media: the canary rides the part media type",
                framed_body(
                    CANARY_BOUNDARY,
                    &[
                        ("text/x-CANARY-MEDIA-TYPE-9q", b"x"),
                        (ENVELOPE_PART_MEDIA_TYPE, &valid_envelope),
                    ],
                ),
            ),
            (
                "part order: the canary rides the boundary of a one-part body",
                framed_body(
                    CANARY_BOUNDARY,
                    &[(ENVELOPE_PART_MEDIA_TYPE, &valid_envelope)],
                ),
            ),
            (
                "size: the canary rides the oversized part",
                framed_body(
                    CANARY_BOUNDARY,
                    &[
                        (ENVELOPE_PART_MEDIA_TYPE, &vec![b'C'; 70 * 1024]),
                        (IDENTITY_MEDIA_TYPE, b"CANARY-PAYLOAD-BYTES-7w"),
                    ],
                ),
            ),
            (
                "schema: the canary rides the broken JSON",
                framed_body(
                    CANARY_BOUNDARY,
                    &[
                        (ENVELOPE_PART_MEDIA_TYPE, broken_json),
                        (IDENTITY_MEDIA_TYPE, b"x"),
                    ],
                ),
            ),
            (
                "identifier: the canary rides the field value",
                framed_body(
                    CANARY_BOUNDARY,
                    &[
                        (ENVELOPE_PART_MEDIA_TYPE, &canary_envelope),
                        (IDENTITY_MEDIA_TYPE, b"CANARY-PAYLOAD-BYTES-7w"),
                    ],
                ),
            ),
        ];

        for (label, body) in cases {
            let error = parse_ingest_with_cap(&canary_framing(), &body[..], cap).expect_err(label);
            let message = error.message();
            let debug = format!("{error:?}");
            for canary in canaries {
                assert!(
                    !debug.contains(canary),
                    "{label}: {debug:?} leaks {canary:?}"
                );
                assert!(
                    !message.as_str().contains(canary),
                    "{label}: {:?} leaks {canary:?}",
                    message.as_str()
                );
            }
            // Braces are banned from the rendered message entirely, so an
            // unreplaced template placeholder can never reach the wire.
            assert!(!message.as_str().contains('{'), "{label}: {message:?}");
            assert!(message.as_str().len() <= 200, "{label}: {message:?}");
        }
    }

    #[test]
    fn every_ingest_parse_error_maps_to_a_registered_code_and_bounded_message() {
        let errors = [
            IngestParseError::Framing(TwoPartError::EnvelopeNotFirst),
            IngestParseError::Framing(TwoPartError::EnvelopeExceedsCap { limit_bytes: 1 }),
            IngestParseError::Framing(TwoPartError::PayloadPartMissing),
            IngestParseError::Framing(TwoPartError::TrailingPart),
            IngestParseError::Envelope(EnvelopeError::Malformed {
                reason: "bounded parse of the envelope bytes failed",
                source: None,
            }),
            IngestParseError::Envelope(EnvelopeError::VersionUnsupported {
                field: "protocol_version",
                found: 2,
            }),
            IngestParseError::Envelope(EnvelopeError::SchemaInvalid {
                field: "range_end",
                reason: "range_end precedes range_start",
            }),
            IngestParseError::Envelope(EnvelopeError::SizeExceeded {
                limit_bytes: 65_536,
            }),
        ];
        let registered = [
            "request.framing_invalid",
            "envelope.media_type_unsupported",
            "envelope.malformed",
            "envelope.version_unsupported",
            "envelope.schema_invalid",
            "envelope.size_exceeded",
        ];
        for error in errors {
            let code = error.code().as_str().to_owned();
            assert!(
                registered.contains(&code.as_str()),
                "{code} is not one of the registry codes this surface maps to"
            );
            let message = error.message();
            assert!(
                message.as_str().len() <= 200,
                "{message:?} exceeds the bound"
            );
            assert!(
                !message.as_str().contains('{'),
                "{message:?} carries a placeholder"
            );
        }

        // The version template carries the declared major; a negative
        // integer renders as decimal too (the token grammar admits `-`).
        let error = IngestParseError::Envelope(EnvelopeError::VersionUnsupported {
            field: "envelope_version",
            found: -1,
        });
        assert_eq!(
            error.message().as_str(),
            TEMPLATE_ENVELOPE_VERSION_UNSUPPORTED.replace("{version}", "-1")
        );
    }
}
