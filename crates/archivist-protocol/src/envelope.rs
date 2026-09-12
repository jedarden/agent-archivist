// SPDX-License-Identifier: Apache-2.0

//! The version 1 ingest envelope (plan Sections 7.2 and 7.3;
//! [`schemas/v1/ingest-envelope.json`]).
//!
//! The envelope is the immutable, client-frozen metadata part of
//! `POST /v1/ingest`: RFC 8785 canonical JSON, no floats, at most 65,536
//! canonical bytes. It carries the identity *inputs* (tenant, origin client,
//! harness, upstream session, artifact tuple, generation, range, blob digest)
//! plus the two derived identifiers the plan names, and it deliberately
//! excludes every per-attempt and server field — those names are rejected
//! outright, which is what lets a retry outside the authorization window
//! re-authorize without changing occurrence or attestation identity.
//!
//! Parsing is the full bounded-validation path (VAL-001/VAL-002):
//!
//! - the bytes must parse as canonical-domain JSON and be an object;
//! - the six reserved per-attempt/server names are rejected before anything
//!   else (the schema's `not` block, mirrored);
//! - `protocol_version` and `envelope_version` are const-pinned — an unknown
//!   major fails closed, never best-effort parses (plan Section 7.1);
//! - every required member is present and matches its grammar from
//!   [`crate::vocabulary`]; unknown enum tokens fail closed;
//! - unknown *optional* members are retained verbatim and re-serialized
//!   inside the canonical bytes (`unknownFields: retain-ignore`) so an old
//!   reader can hold a newer writer's envelope without losing signed
//!   material — the additive-optional rule the compatibility corpus pins;
//! - timestamps are real calendar instants, `range_start` does not exceed
//!   `range_end`, `u63` fields are non-negative, and an `identity` transport
//!   declares equal sizes and an incoming checksum equal to the blob digest;
//! - the declared `occurrence_id` and `attestation_id` are re-derived from
//!   the identity inputs and a mismatch is refused (SID-005; the server-side
//!   check the conformance scenario `invalid-occurrence-id-mismatch` pins);
//! - the canonical serialization fits the 64 KiB cap.
//!
//! The wire error each failure maps to is from
//! [`tools/error-codes.toml`]: `envelope.malformed`,
//! `envelope.version_unsupported`, `envelope.schema_invalid` (with the field
//! name the registry message template carries), and `envelope.size_exceeded`.
//!
//! [`schemas/v1/ingest-envelope.json`]: ../../../schemas/v1/ingest-envelope.json
//! [`tools/error-codes.toml`]: ../../../tools/error-codes.toml

use crate::derivation;
use crate::json::{self, Object, Value};
use crate::sha256;
use crate::vocabulary::{
    AdapterId, ArtifactHash, ArtifactKind, AttestationId, BlobDigest, ChecksumAlgorithm, ClientId,
    ErrorCode, GenerationId, HarnessId, IdSource, IncomingChecksum, OccurrenceId, OpaqueId,
    RangeKind, RequestId, SessionHash, StorageProfile, TenantId, Timestamp, TransportEncoding,
    VersionToken,
};

/// The wire protocol family of the `/v1/ingest` route (plan Section 7.1).
pub const PROTOCOL_VERSION: i64 = 1;

/// The envelope schema major version (plan Section 7.1).
pub const ENVELOPE_VERSION: i64 = 1;

/// Maximum size of the canonical envelope serialization
/// (`ingest-envelope.json` `canonicalMaxBytes`; plan Section 7.6).
pub const CANONICAL_MAX_BYTES: usize = 65_536;

/// Per-attempt and server member names an envelope must never carry: freezing
/// any of them would break the retry contract (see the module docs and the
/// schema's `not` block).
pub const RESERVED_FIELDS: [&str; 6] = [
    "authorization_epoch",
    "authorization_key_id",
    "authorization_timestamp",
    "commit_time",
    "correlation_id",
    "signature",
];

/// Why an envelope byte sequence or value is not a valid version 1 envelope.
///
/// Each variant names the wire error it maps to
/// ([`EnvelopeError::code`]), with the field name where the registry message
/// template carries one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// `envelope.malformed`: the bytes are not protocol-domain JSON, or the
    /// value is not an object.
    Malformed {
        /// What failed, in one line.
        reason: &'static str,
        /// The bounded parser's detail, when the failure came from it.
        source: Option<json::ParseError>,
    },
    /// `envelope.version_unsupported`: a version axis holds an unknown major.
    VersionUnsupported {
        /// The version field that failed (`protocol_version` or
        /// `envelope_version`).
        field: &'static str,
        /// The major the writer declared.
        found: i64,
    },
    /// `envelope.schema_invalid`: a field is missing, mistyped, outside its
    /// grammar, or fails a consistency check.
    SchemaInvalid {
        /// The member name the failure is reported at.
        field: &'static str,
        /// What failed, in one line.
        reason: &'static str,
    },
    /// `envelope.size_exceeded`: the canonical serialization exceeds the cap.
    SizeExceeded {
        /// The cap that was exceeded, in bytes.
        limit_bytes: usize,
    },
}

impl EnvelopeError {
    /// The stable wire code for this failure (ERR-007 grammar; the four
    /// `envelope.*` entries of the error registry).
    ///
    /// # Panics
    /// Never in practice: every literal below matches the registry grammar
    /// pinned by `tools/check-error-codes.py`, so a panic is a programming
    /// error introduced alongside this match, not a wire condition.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Malformed { .. } => ErrorCode::parse("envelope.malformed"),
            Self::VersionUnsupported { .. } => ErrorCode::parse("envelope.version_unsupported"),
            Self::SchemaInvalid { .. } => ErrorCode::parse("envelope.schema_invalid"),
            Self::SizeExceeded { .. } => ErrorCode::parse("envelope.size_exceeded"),
        }
        .expect("the envelope error codes match the registry grammar")
    }

    /// The member name this failure is reported at, when the code's message
    /// template carries one.
    #[must_use]
    pub fn field(&self) -> Option<&'static str> {
        match self {
            Self::Malformed { .. } | Self::SizeExceeded { .. } => None,
            Self::VersionUnsupported { field, .. } | Self::SchemaInvalid { field, .. } => {
                Some(field)
            }
        }
    }
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { reason, source } => match source {
                None => write!(f, "envelope is not valid canonical JSON: {reason}"),
                Some(parse) => write!(f, "envelope is not valid canonical JSON: {parse}"),
            },
            Self::VersionUnsupported { field, found } => {
                write!(
                    f,
                    "envelope fails at {field}: version {found} is not supported"
                )
            }
            Self::SchemaInvalid { field, reason } => {
                write!(
                    f,
                    "envelope fails schema validation at field {field}: {reason}"
                )
            }
            Self::SizeExceeded { limit_bytes } => {
                write!(f, "canonical envelope exceeds the {limit_bytes} byte limit")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// The version 1 ingest envelope: typed, validated identity and provenance
/// fields plus retained unknown members (the additive-optional rule).
///
/// Every field is a project-owned newtype from [`crate::vocabulary`] — the
/// public surface exposes no replaceable SDK type. Construction from parts is
/// by struct literal (producers fill every required field); the wire path is
/// [`Envelope::parse`], which performs the full bounded validation the module
/// docs list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Issuer-created tenant identifier.
    pub tenant_id: TenantId,
    /// Installation that captured the source.
    pub origin_client_id: ClientId,
    /// Installation presenting this request (may differ under relay).
    pub uploader_client_id: ClientId,
    /// Harness identifier.
    pub harness: HarnessId,
    /// The harness's own session identifier, or the adapter-minted stand-in.
    pub upstream_session_id: OpaqueId,
    /// Whether `upstream_session_id` came from the harness or was minted.
    pub id_source: IdSource,
    /// Kind of source artifact this occurrence projects.
    pub artifact_kind: ArtifactKind,
    /// Identifier of the projecting adapter.
    pub adapter_id: AdapterId,
    /// Version of the adapter's projection.
    pub adapter_projection_version: VersionToken,
    /// The adapter's opaque identifier for the source artifact.
    pub adapter_artifact_id: OpaqueId,
    /// Source generation of this artifact snapshot.
    pub generation: GenerationId,
    /// Whether range coordinates are byte offsets or event ordinals.
    pub range_kind: RangeKind,
    /// Inclusive start coordinate of this chunk.
    pub range_start: u64,
    /// Inclusive end coordinate of this chunk.
    pub range_end: u64,
    /// SHA-256 of the canonical uncompressed payload bytes.
    pub blob_digest: BlobDigest,
    /// Checksum of the payload as transported.
    pub incoming_checksum: IncomingChecksum,
    /// Algorithm of `incoming_checksum`.
    pub incoming_checksum_algorithm: ChecksumAlgorithm,
    /// Named canonical storage encoder for this occurrence's blob.
    pub storage_profile: StorageProfile,
    /// Wire encoding of the payload part.
    pub transport_encoding: TransportEncoding,
    /// Size in bytes of the payload as transported.
    pub compressed_size: u64,
    /// Size in bytes of the canonical uncompressed payload.
    pub uncompressed_size: u64,
    /// Declared deterministic occurrence identity (re-derived on parse).
    pub occurrence_id: OccurrenceId,
    /// Declared deterministic attestation identity (re-derived on parse).
    pub attestation_id: AttestationId,
    /// Frozen upload-request identifier.
    pub request_id: RequestId,
    /// UTC time the client captured this chunk.
    pub capture_time: Timestamp,
    /// UTC time the client froze this envelope.
    pub envelope_creation_time: Timestamp,
    /// Optional UTC timestamp embedded in or derived from the source.
    pub source_time: Option<Timestamp>,
    /// Optional upstream identifier of the parent session (correlation only).
    pub parent_session_id: Option<OpaqueId>,
    /// Optional orchestrator attempt correlation identifier.
    pub orchestrator_attempt_id: Option<OpaqueId>,
    /// Optional provider trace correlation identifier.
    pub trace_id: Option<OpaqueId>,
    /// Optional inference-request correlation identifier.
    pub inference_request_id: Option<OpaqueId>,
    /// Members this version does not define, retained verbatim so the
    /// canonical bytes round-trip a newer writer's additive fields
    /// (`unknownFields: retain-ignore`). Reserved names never reach here:
    /// [`Envelope::parse`] rejects them outright.
    pub unknown_fields: Object,
}

/// Shorthand for a validation failure at one member.
fn invalid(field: &'static str, reason: &'static str) -> EnvelopeError {
    EnvelopeError::SchemaInvalid { field, reason }
}

/// Require `object` to hold `field`.
fn require<'a>(object: &'a Object, field: &'static str) -> Result<&'a Value, EnvelopeError> {
    object
        .get(field)
        .ok_or_else(|| invalid(field, "required member is missing"))
}

/// Require `value` to be text.
fn text<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, EnvelopeError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(invalid(field, "member must be a string")),
    }
}

/// Require `value` to be a non-negative integer below 2^63 (the `u63` shape).
fn u63(value: &Value, field: &'static str) -> Result<u64, EnvelopeError> {
    match value {
        Value::Int(n) if *n >= 0 => Ok(u64::try_from(*n).expect("non-negative i64 fits u64")),
        Value::Int(_) => Err(invalid(field, "integer is below zero")),
        _ => Err(invalid(field, "member must be an integer")),
    }
}

/// Require and grammar-validate a text member as `T`.
fn typed<T>(object: &Object, field: &'static str) -> Result<T, EnvelopeError>
where
    T: std::str::FromStr<Err = crate::vocabulary::GrammarError>,
{
    let raw = text(require(object, field)?, field)?;
    T::from_str(raw).map_err(|_| invalid(field, "value does not match the canonical grammar"))
}

/// Require an integer member pinned to a known major, failing closed on any
/// other value (plan Section 7.1).
fn version(object: &Object, field: &'static str, known: i64) -> Result<(), EnvelopeError> {
    match require(object, field)? {
        Value::Int(found) if *found == known => Ok(()),
        Value::Int(found) => Err(EnvelopeError::VersionUnsupported {
            field,
            found: *found,
        }),
        _ => Err(invalid(field, "member must be an integer")),
    }
}

/// Require an optional text member: `None` when absent, an error when present
/// but not a string or not grammatical. The schema omits optional members
/// rather than nulling them.
fn optional<T>(object: &Object, field: &'static str) -> Result<Option<T>, EnvelopeError>
where
    T: std::str::FromStr<Err = crate::vocabulary::GrammarError>,
{
    match object.get(field) {
        None => Ok(None),
        Some(Value::Text(raw)) => T::from_str(raw)
            .map(Some)
            .map_err(|_| invalid(field, "value does not match the canonical grammar")),
        Some(_) => Err(invalid(
            field,
            "member must be a string when present, never null",
        )),
    }
}

impl Envelope {
    /// Parse and fully validate an envelope from its wire bytes (multipart
    /// part one). Transmission need not be canonical — reordered members and
    /// insignificant whitespace parse to the same value — but every other
    /// rule in the module docs applies.
    ///
    /// # Errors
    /// The first [`EnvelopeError`] in the validation order: reserved names,
    /// version axes, required-member grammar, optional-member grammar,
    /// calendar and consistency checks, identity re-derivation, size cap.
    pub fn parse(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let value = json::parse(bytes).map_err(|source| EnvelopeError::Malformed {
            reason: "bounded parse of the envelope bytes failed",
            source: Some(source),
        })?;
        Self::from_value(value)
    }

    /// Validate an already-parsed JSON value as an envelope.
    ///
    /// # Errors
    /// As [`Envelope::parse`].
    pub fn from_value(value: Value) -> Result<Self, EnvelopeError> {
        let Value::Object(object) = value else {
            return Err(EnvelopeError::Malformed {
                reason: "envelope part is not a JSON object",
                source: None,
            });
        };

        // Per-attempt and server names are rejected before any field is read:
        // the schema's `not` block, mirrored (and the conformance scenario
        // `invalid-reserved-field` pins the reported field name).
        for field in RESERVED_FIELDS {
            if object.contains(field) {
                return Err(invalid(field, "reserved per-attempt or server member"));
            }
        }

        version(&object, "protocol_version", PROTOCOL_VERSION)?;
        version(&object, "envelope_version", ENVELOPE_VERSION)?;

        let envelope = Self {
            adapter_artifact_id: typed(&object, "adapter_artifact_id")?,
            adapter_id: typed(&object, "adapter_id")?,
            adapter_projection_version: typed(&object, "adapter_projection_version")?,
            artifact_kind: typed(&object, "artifact_kind")?,
            attestation_id: typed(&object, "attestation_id")?,
            blob_digest: typed(&object, "blob_digest")?,
            capture_time: typed(&object, "capture_time")?,
            compressed_size: u63(require(&object, "compressed_size")?, "compressed_size")?,
            envelope_creation_time: typed(&object, "envelope_creation_time")?,
            generation: typed(&object, "generation")?,
            harness: typed(&object, "harness")?,
            id_source: typed(&object, "id_source")?,
            incoming_checksum: typed(&object, "incoming_checksum")?,
            incoming_checksum_algorithm: typed(&object, "incoming_checksum_algorithm")?,
            occurrence_id: typed(&object, "occurrence_id")?,
            origin_client_id: typed(&object, "origin_client_id")?,
            range_end: u63(require(&object, "range_end")?, "range_end")?,
            range_kind: typed(&object, "range_kind")?,
            range_start: u63(require(&object, "range_start")?, "range_start")?,
            request_id: typed(&object, "request_id")?,
            storage_profile: typed(&object, "storage_profile")?,
            tenant_id: typed(&object, "tenant_id")?,
            transport_encoding: typed(&object, "transport_encoding")?,
            uncompressed_size: u63(require(&object, "uncompressed_size")?, "uncompressed_size")?,
            upstream_session_id: typed(&object, "upstream_session_id")?,
            uploader_client_id: typed(&object, "uploader_client_id")?,
            source_time: optional(&object, "source_time")?,
            parent_session_id: optional(&object, "parent_session_id")?,
            orchestrator_attempt_id: optional(&object, "orchestrator_attempt_id")?,
            trace_id: optional(&object, "trace_id")?,
            inference_request_id: optional(&object, "inference_request_id")?,
            unknown_fields: retained(&object),
        };

        envelope.semantic_checks()?;
        envelope.verify_identities()?;
        envelope.size_check()?;
        Ok(envelope)
    }

    /// Calendar and consistency checks (VAL-002): real timestamps, ordered
    /// range, non-negative integers (already enforced by the `u63` reader),
    /// and the `identity` transport coupling — the transported bytes *are*
    /// the canonical bytes, so the declared sizes are equal and the incoming
    /// checksum equals the blob digest.
    fn semantic_checks(&self) -> Result<(), EnvelopeError> {
        if !self.capture_time.calendar_valid() {
            return Err(invalid(
                "capture_time",
                "timestamp is not a real calendar instant",
            ));
        }
        if !self.envelope_creation_time.calendar_valid() {
            return Err(invalid(
                "envelope_creation_time",
                "timestamp is not a real calendar instant",
            ));
        }
        if let Some(source_time) = &self.source_time
            && !source_time.calendar_valid()
        {
            return Err(invalid(
                "source_time",
                "timestamp is not a real calendar instant",
            ));
        }
        if self.range_end < self.range_start {
            return Err(invalid("range_end", "range_end precedes range_start"));
        }
        if self.transport_encoding == TransportEncoding::Identity {
            if self.compressed_size != self.uncompressed_size {
                return Err(invalid(
                    "compressed_size",
                    "identity transport must declare equal compressed and uncompressed sizes",
                ));
            }
            if self.incoming_checksum.as_raw() != self.blob_digest.as_raw() {
                return Err(invalid(
                    "incoming_checksum",
                    "identity transport checksum must equal the blob digest",
                ));
            }
        }
        Ok(())
    }

    /// Re-derive both declared identities from the identity inputs and
    /// refuse a mismatch (the server-side check of SID-005; conformance
    /// scenario `invalid-occurrence-id-mismatch`).
    ///
    /// # Errors
    /// [`EnvelopeError::SchemaInvalid`] at `occurrence_id` or
    /// `attestation_id`.
    pub fn verify_identities(&self) -> Result<(), EnvelopeError> {
        if self.rederive_occurrence_id().as_raw() != self.occurrence_id.as_raw() {
            return Err(invalid(
                "occurrence_id",
                "declared identity does not match the re-derived one",
            ));
        }
        if self.rederive_attestation_id().as_raw() != self.attestation_id.as_raw() {
            return Err(invalid(
                "attestation_id",
                "declared identity does not match the re-derived one",
            ));
        }
        Ok(())
    }

    /// Fail when the canonical serialization exceeds the cap.
    fn size_check(&self) -> Result<(), EnvelopeError> {
        let bytes = self.canonical_bytes();
        if bytes.len() > CANONICAL_MAX_BYTES {
            return Err(EnvelopeError::SizeExceeded {
                limit_bytes: CANONICAL_MAX_BYTES,
            });
        }
        Ok(())
    }

    /// The session-namespace hash of this envelope's session inputs.
    #[must_use]
    pub fn rederive_session_hash(&self) -> SessionHash {
        derivation::session_hash(
            &self.tenant_id,
            &self.origin_client_id,
            &self.harness,
            self.upstream_session_id.as_str(),
        )
    }

    /// The artifact hash of this envelope's artifact tuple.
    #[must_use]
    pub fn rederive_artifact_hash(&self) -> ArtifactHash {
        derivation::artifact_hash(
            &self.rederive_session_hash(),
            self.artifact_kind,
            &self.adapter_id,
            &self.adapter_projection_version,
            self.adapter_artifact_id.as_str(),
        )
    }

    /// The deterministic occurrence identity of this envelope's inputs.
    #[must_use]
    pub fn rederive_occurrence_id(&self) -> OccurrenceId {
        derivation::occurrence_id(
            &self.rederive_session_hash(),
            &self.rederive_artifact_hash(),
            &self.generation,
            self.range_kind,
            self.range_start,
            self.range_end,
            &self.blob_digest,
        )
    }

    /// The deterministic attestation identity of this envelope's inputs.
    #[must_use]
    pub fn rederive_attestation_id(&self) -> AttestationId {
        derivation::attestation_id(
            &self.occurrence_id,
            &self.uploader_client_id,
            &self.request_id,
        )
    }

    /// The envelope as a protocol JSON value, known members typed back to
    /// wire text and retained unknown members preserved verbatim.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut object = Object::new();
        // Insert-order is irrelevant: the object keeps canonical order.
        // An upsert over distinct names: every name below is unique and
        // absent from `unknown_fields` by construction of `retained`.
        let mut put = |name: &str, value: Value| object.set(name, value);
        put("protocol_version", Value::Int(PROTOCOL_VERSION));
        put("envelope_version", Value::Int(ENVELOPE_VERSION));
        put("tenant_id", text_value(&self.tenant_id));
        put("origin_client_id", text_value(&self.origin_client_id));
        put("uploader_client_id", text_value(&self.uploader_client_id));
        put("harness", text_value(&self.harness));
        put(
            "upstream_session_id",
            Value::Text(self.upstream_session_id.as_str().to_owned()),
        );
        put("id_source", Value::Text(self.id_source.token().to_owned()));
        put(
            "artifact_kind",
            Value::Text(self.artifact_kind.token().to_owned()),
        );
        put("adapter_id", text_value(&self.adapter_id));
        put(
            "adapter_projection_version",
            text_value(&self.adapter_projection_version),
        );
        put(
            "adapter_artifact_id",
            Value::Text(self.adapter_artifact_id.as_str().to_owned()),
        );
        put("generation", text_value(&self.generation));
        put(
            "range_kind",
            Value::Text(self.range_kind.token().to_owned()),
        );
        put("range_start", u63_value(self.range_start));
        put("range_end", u63_value(self.range_end));
        put("blob_digest", Value::Text(self.blob_digest.to_hex()));
        put(
            "incoming_checksum",
            Value::Text(self.incoming_checksum.to_hex()),
        );
        put(
            "incoming_checksum_algorithm",
            Value::Text(self.incoming_checksum_algorithm.token().to_owned()),
        );
        put(
            "storage_profile",
            Value::Text(self.storage_profile.token().to_owned()),
        );
        put(
            "transport_encoding",
            Value::Text(self.transport_encoding.token().to_owned()),
        );
        put("compressed_size", u63_value(self.compressed_size));
        put("uncompressed_size", u63_value(self.uncompressed_size));
        put("occurrence_id", Value::Text(self.occurrence_id.to_hex()));
        put("attestation_id", Value::Text(self.attestation_id.to_hex()));
        put("request_id", text_value(&self.request_id));
        put("capture_time", text_value(&self.capture_time));
        put(
            "envelope_creation_time",
            text_value(&self.envelope_creation_time),
        );
        if let Some(source_time) = &self.source_time {
            put("source_time", text_value(source_time));
        }
        if let Some(id) = &self.parent_session_id {
            put("parent_session_id", Value::Text(id.as_str().to_owned()));
        }
        if let Some(id) = &self.orchestrator_attempt_id {
            put(
                "orchestrator_attempt_id",
                Value::Text(id.as_str().to_owned()),
            );
        }
        if let Some(id) = &self.trace_id {
            put("trace_id", Value::Text(id.as_str().to_owned()));
        }
        if let Some(id) = &self.inference_request_id {
            put("inference_request_id", Value::Text(id.as_str().to_owned()));
        }
        for (name, value) in self.unknown_fields.iter() {
            object.set(name, value.clone());
        }
        Value::Object(object)
    }

    /// The RFC 8785 canonical bytes of this envelope — the exact bytes of
    /// multipart part one and the input to the envelope digest.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.to_value().canonical_bytes()
    }

    /// SHA-256 over the canonical bytes — the digest the per-attempt
    /// signature covers.
    #[must_use]
    pub fn envelope_digest(&self) -> crate::vocabulary::EnvelopeDigest {
        crate::vocabulary::EnvelopeDigest::from_raw(sha256::digest(&self.canonical_bytes()))
    }
}

/// Render a text newtype as a JSON string value.
fn text_value<T: std::fmt::Display>(value: &T) -> Value {
    Value::Text(value.to_string())
}

/// Render a `u63` field: parsing guarantees the bound, so a value that no
/// longer fits the wire integer domain is a programmatic-construction bug,
/// not a wire condition.
fn u63_value(value: u64) -> Value {
    Value::Int(i64::try_from(value).expect("u63 fields stay below 2^63"))
}

/// Collect the members this version does not define. Reserved names cannot
/// appear here (they were rejected before any field was read); the debug
/// assertion keeps that coupling honest if the up-front check is ever
/// reordered away.
fn retained(object: &Object) -> Object {
    let mut unknown = Object::new();
    for (name, value) in object.iter() {
        debug_assert!(
            !RESERVED_FIELDS.contains(&name),
            "reserved names are rejected before retention"
        );
        if ENVELOPE_FIELD_NAMES.contains(&name) {
            continue;
        }
        unknown.set(name, value.clone());
    }
    unknown
}

/// The member names this envelope version defines (required plus optional),
/// in schema order.
const ENVELOPE_FIELD_NAMES: [&str; 33] = [
    "adapter_artifact_id",
    "adapter_id",
    "adapter_projection_version",
    "artifact_kind",
    "attestation_id",
    "blob_digest",
    "capture_time",
    "compressed_size",
    "envelope_creation_time",
    "envelope_version",
    "generation",
    "harness",
    "id_source",
    "inference_request_id",
    "incoming_checksum",
    "incoming_checksum_algorithm",
    "occurrence_id",
    "orchestrator_attempt_id",
    "origin_client_id",
    "parent_session_id",
    "protocol_version",
    "range_end",
    "range_kind",
    "range_start",
    "request_id",
    "source_time",
    "storage_profile",
    "tenant_id",
    "trace_id",
    "transport_encoding",
    "uncompressed_size",
    "upstream_session_id",
    "uploader_client_id",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The conformance corpus's `valid-direct-baseline` envelope, inlined so
    /// the unit tests need no filesystem access. `tests/conformance.rs`
    /// replays the corpus itself.
    fn baseline() -> Envelope {
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
            unknown_fields: Object::new(),
        }
    }

    #[test]
    fn baseline_round_trips_byte_exactly() {
        let envelope = baseline();
        let bytes = envelope.canonical_bytes();
        let reparsed = Envelope::parse(&bytes).expect("canonical bytes reparse");
        assert_eq!(reparsed, envelope);
        assert_eq!(reparsed.canonical_bytes(), bytes);
    }

    #[test]
    fn reserved_names_are_rejected_with_the_field_named() {
        let mut value = baseline().to_value();
        if let Value::Object(object) = &mut value {
            object.set("commit_time", Value::Text("2026-09-11T17:59:59Z".into()));
        }
        let error = Envelope::from_value(value).unwrap_err();
        assert_eq!(error.field(), Some("commit_time"));
        assert_eq!(error.code().as_str(), "envelope.schema_invalid");
        for field in RESERVED_FIELDS {
            let mut value = baseline().to_value();
            if let Value::Object(object) = &mut value {
                object.set(field, Value::Null);
            }
            assert_eq!(
                Envelope::from_value(value).unwrap_err().field(),
                Some(field),
                "reserved field {field} must be reported by name"
            );
        }
    }

    #[test]
    fn unknown_majors_fail_closed() {
        for field in ["protocol_version", "envelope_version"] {
            let mut value = baseline().to_value();
            if let Value::Object(object) = &mut value {
                object.set(field, Value::Int(2));
            }
            let error = Envelope::from_value(value).unwrap_err();
            assert_eq!(error, EnvelopeError::VersionUnsupported { field, found: 2 });
            assert_eq!(error.code().as_str(), "envelope.version_unsupported");
        }
    }

    #[test]
    fn additive_unknown_members_are_retained_inside_canonical_bytes() {
        let mut value = baseline().to_value();
        if let Value::Object(object) = &mut value {
            object
                .insert("client_build", Value::Text("9.9.1-compat".into()))
                .unwrap();
        }
        let parsed = Envelope::from_value(value).expect("additive optional member is accepted");
        assert!(parsed.unknown_fields.get("client_build").is_some());
        // Retained inside the canonical bytes: the member survives a
        // round-trip untouched.
        let bytes = parsed.canonical_bytes();
        let reparsed = Envelope::parse(&bytes).unwrap();
        assert_eq!(
            reparsed.unknown_fields.get("client_build"),
            Some(&Value::Text("9.9.1-compat".into()))
        );
    }

    #[test]
    fn missing_and_mistyped_members_are_reported_at_the_field() {
        let mut value = baseline().to_value();
        if let Value::Object(object) = &mut value {
            assert!(object.remove("harness").is_some());
        }
        assert_eq!(
            Envelope::from_value(value).unwrap_err(),
            invalid("harness", "required member is missing")
        );

        let mut value = baseline().to_value();
        if let Value::Object(object) = &mut value {
            object.set("tenant_id", Value::Int(7));
        }
        assert_eq!(
            Envelope::from_value(value).unwrap_err().field(),
            Some("tenant_id")
        );
    }

    #[test]
    fn closed_enums_fail_closed_at_their_field() {
        let mut value = baseline().to_value();
        if let Value::Object(object) = &mut value {
            object.set("transport_encoding", Value::Text("gzip".into()));
        }
        let error = Envelope::from_value(value).unwrap_err();
        assert_eq!(error.field(), Some("transport_encoding"));
        assert_eq!(error.code().as_str(), "envelope.schema_invalid");
    }

    #[test]
    fn semantic_checks_reject_impossible_values() {
        // Reversed range.
        let mut envelope = baseline();
        envelope.range_start = 10;
        envelope.range_end = 9;
        let error = envelope.semantic_checks().unwrap_err();
        assert_eq!(error.field(), Some("range_end"));

        // Calendar-invalid capture time.
        let mut envelope = baseline();
        envelope.capture_time = Timestamp::parse("2026-02-30T16:44:10Z").unwrap();
        let error = envelope.semantic_checks().unwrap_err();
        assert_eq!(error.field(), Some("capture_time"));

        // Identity transport must declare equal sizes.
        let mut envelope = baseline();
        envelope.compressed_size = 175;
        let error = envelope.semantic_checks().unwrap_err();
        assert_eq!(error.field(), Some("compressed_size"));

        // ...and an incoming checksum equal to the blob digest.
        let mut envelope = baseline();
        envelope.incoming_checksum = IncomingChecksum::parse(&"ab".repeat(32)).unwrap();
        let error = envelope.semantic_checks().unwrap_err();
        assert_eq!(error.field(), Some("incoming_checksum"));
    }

    #[test]
    fn identity_mismatch_is_refused_at_the_declared_field() {
        let mut envelope = baseline();
        envelope.occurrence_id = OccurrenceId::parse(&"cd".repeat(32)).unwrap();
        let error = envelope.verify_identities().unwrap_err();
        assert_eq!(error.field(), Some("occurrence_id"));

        // Repair the occurrence, break the attestation.
        envelope.occurrence_id = envelope.rederive_occurrence_id();
        envelope.attestation_id = AttestationId::parse(&"ef".repeat(32)).unwrap();
        let error = envelope.verify_identities().unwrap_err();
        assert_eq!(error.field(), Some("attestation_id"));
    }

    #[test]
    fn canonical_size_cap_is_enforced() {
        let mut envelope = baseline();
        // A 70 KiB unknown member trips the 64 KiB canonical cap.
        let padding = "x".repeat(70 * 1024);
        envelope
            .unknown_fields
            .insert("padding", Value::Text(padding))
            .unwrap();
        assert_eq!(
            envelope.size_check().unwrap_err(),
            EnvelopeError::SizeExceeded {
                limit_bytes: CANONICAL_MAX_BYTES
            }
        );
    }

    #[test]
    fn floats_never_parse() {
        let bytes = br#"{"tenant_id": 1.5}"#;
        assert!(matches!(
            Envelope::parse(bytes),
            Err(EnvelopeError::Malformed { .. })
        ));
    }

    #[test]
    fn non_object_root_is_malformed() {
        assert!(matches!(
            Envelope::parse(b"[1, 2]"),
            Err(EnvelopeError::Malformed { .. })
        ));
    }
}
