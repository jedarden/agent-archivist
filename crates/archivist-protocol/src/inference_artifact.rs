// SPDX-License-Identifier: Apache-2.0

//! The exact-inference capture artifact (plan Phase 9, CAP-008;
//! [`schemas/v1/inference-artifact.json`]): the typed record for one
//! observed provider-boundary event.
//!
//! One artifact per event, six closed kinds: a decoded provider request, a
//! decoded provider response, one ordered decoded streaming event, a retry
//! decision, a usage report, or a transport error. The record is captured
//! once at the proxy/SDK hook boundary and is then byte-stable — an upload
//! retry rewrites identical bytes — so this module's wire path is the usual
//! full bounded validation ([`InferenceArtifact::parse`]) and its output is
//! the RFC 8785 canonical serialization.
//!
//! # Capture boundary, in the types
//!
//! The types carry the capture-boundary rules structurally, not by
//! convention:
//!
//! - a [`Payload`] is digest and size of the *post-transfer-decoded* bytes
//!   — the transferred content exactly as the boundary saw it. No member
//!   can name TLS/TCP framing or transfer-encoding framing: those names
//!   (`tls_record`, `tcp_segment`, `transport_encoding`, `ip_packet`, …)
//!   are on the reserved list and are refused outright, never stripped;
//! - [`Metadata`] is the closed nine-entry allowlist of header-derived
//!   values. There is no member a credential could inhabit: a tenth key —
//!   `authorization`, `api_key`, a provider header, anything — is refused
//!   at validation with the key named, and at construction it has no field
//!   to be assigned to. Growth of the allowlist is a new schema major,
//!   never an additive v1 field;
//! - the correlation handles ([`TraceId`], [`InferenceRequestId`],
//!   [`ProviderAttemptId`], the attempt ordinal) are join keys only. The
//!   payload digest is the plain SHA-256 of the captured bytes — the one
//!   label-less digest — and no correlation field is an input to any
//!   digest or storage key.
//!
//! # Validation order
//!
//! Parsing is the full bounded-validation path: the bytes must be
//! canonical-domain JSON and an object; the schema's reserved `not` block
//! is mirrored (a reserved name is refused before any field is read);
//! `inference_artifact_version` is const-pinned and an unknown major fails
//! closed; every required member is present and grammatical; the kind's
//! own specific members are required and a *foreign* kind's specific
//! members are refused (the schema's not-required arms — they are never
//! silently retained as unknown); `metadata` refuses every name outside
//! the closed allowlist and is never empty when present; and the semantic
//! checks (VAL-002) hold: a real calendar `capture_time`, a
//! `retry_of_attempt_ordinal` strictly below the record's own
//! `attempt_ordinal`, the three usage counters present on a `usage`
//! record, `http_status` within 100–599, and a `payload_size` of at least
//! 1.
//!
//! Unknown members — at the record level and inside `payload` — are
//! retained verbatim and re-serialized into the canonical bytes
//! (`x-archivist.unknownFields: retain-ignore`), so an old reader holds a
//! newer writer's additive fields without losing material. `metadata` is
//! the one closed object: nothing unknown is retained there.
//!
//! [`schemas/v1/inference-artifact.json`]: ../../../schemas/v1/inference-artifact.json

use crate::json::{self, Object, Value};
use crate::vocabulary::{
    BlobDigest, ClientId, InferenceArtifactKind, InferenceRequestId, ProviderAttemptId,
    RetryReason, TenantId, Timestamp, TraceId, TransportErrorClass, UsageSource,
};

/// The exact-inference artifact schema major (`inference_artifact_version`;
/// plan Section 7.1: this family's own version axis, independent of the
/// occurrence/attestation/episode axes).
pub const INFERENCE_ARTIFACT_VERSION: i64 = 1;

/// The closed metadata allowlist (`metadata`; plan Phase 9): the only
/// header-derived values the boundary may normalize into the record. A new
/// entry is a new schema major, never an additive v1 field — the closure is
/// the boundary that keeps header and body material from drifting into
/// archive metadata.
pub const METADATA_ALLOWLIST: [&str; 9] = [
    "content_type",
    "http_status",
    "provider_request_id",
    "rate_limit_limit",
    "rate_limit_remaining",
    "rate_limit_reset",
    "usage_input_tokens",
    "usage_output_tokens",
    "usage_total_tokens",
];

/// The reserved member names the schema rejects anywhere at the record's
/// top level (`x-archivist.reservedFields` and the matching `not` block):
/// authorization, cookie, and provider-credential material, TLS/TCP and
/// transfer-encoding framing, and storage-location names. A record is
/// refused when it carries one — never stripped, so a producer that
/// misroutes material sees the failure instead of losing the bytes.
pub const RESERVED_FIELDS: [&str; 43] = [
    "access_token",
    "alpn",
    "api_key",
    "api_token",
    "authorization",
    "authorization_epoch",
    "authorization_key_id",
    "authorization_timestamp",
    "bearer_token",
    "blob_key",
    "blob_url",
    "certificate",
    "certificate_chain",
    "cipher_suite",
    "client_certificate",
    "client_secret",
    "cookie",
    "credential",
    "endpoint",
    "ip_packet",
    "object_key",
    "password",
    "private_key",
    "proxy_authorization",
    "refresh_token",
    "request_id",
    "secret",
    "session_token",
    "set_cookie",
    "signature",
    "signature_algorithm",
    "storage_path",
    "tcp_segment",
    "tls_handshake",
    "tls_record",
    "tls_session_ticket",
    "tls_version",
    "transport_encoding",
    "upload_url",
    "uri",
    "url",
    "www_authenticate",
    "x_api_key",
];

/// The member names this schema version defines, in schema order: the
/// common envelope members plus every kind's specific members.
const RECORD_FIELD_NAMES: [&str; 18] = [
    "artifact_kind",
    "attempt_ordinal",
    "backoff_ms",
    "capture_time",
    "error_class",
    "event_ordinal",
    "inference_artifact_version",
    "inference_request_id",
    "metadata",
    "origin_client_id",
    "payload",
    "provider_attempt_id",
    "retry_of_attempt_ordinal",
    "retry_reason",
    "tenant_id",
    "timeout_ms",
    "trace_id",
    "usage_source",
];

/// Why a candidate record is not a valid exact-inference artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InferenceArtifactError {
    /// The bytes are not canonical-domain JSON, or the value is not an
    /// object.
    Malformed {
        /// What failed, in one line.
        reason: &'static str,
        /// The bounded parser's detail, when the failure came from it.
        source: Option<json::ParseError>,
    },
    /// `inference_artifact_version` holds an unknown major.
    VersionUnsupported {
        /// The major the writer declared.
        found: i64,
    },
    /// A member is missing, mistyped, outside its grammar or allowlist, or
    /// fails a semantic check. The field is the member the failure is
    /// reported at (`metadata` refusals name the offending key in the
    /// reason — allowlist keys are data, not static field names).
    SchemaInvalid {
        /// The member name the failure is reported at.
        field: String,
        /// What failed, in one line.
        reason: String,
    },
}

impl std::fmt::Display for InferenceArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { reason, source } => match source {
                None => write!(f, "inference artifact is not valid JSON: {reason}"),
                Some(parse) => write!(f, "inference artifact is not valid JSON: {parse}"),
            },
            Self::VersionUnsupported { found } => {
                write!(f, "inference artifact version {found} is not supported")
            }
            Self::SchemaInvalid { field, reason } => {
                write!(f, "inference artifact fails at {field}: {reason}")
            }
        }
    }
}

impl std::error::Error for InferenceArtifactError {}

/// The captured bytes, when any were: the decoded request body
/// (`provider-request`), the decoded response body (`provider-response`),
/// one decoded stream event (`streaming-event`), or the bytes of the event
/// that reported usage (`usage`, optional). Present for `retry` and
/// `transport-error` only when partial bytes were captured before the
/// failure.
///
/// The members are digest and size only — never a storage location, and
/// never the framing of any transfer: the digest is the plain SHA-256 of
/// the decoded bytes (the one label-less digest, so identical bytes
/// deduplicate to one stored blob and no correlation field is folded in),
/// and the size is at least 1 (an empty body is the member's absence, not
/// a zero entry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    /// SHA-256 of the captured payload bytes, lowercase hex.
    pub payload_digest: BlobDigest,
    /// Size in bytes of the captured payload, at least 1.
    pub payload_size: u64,
    /// Members this version does not define, retained verbatim
    /// (`unknownFields: retain-ignore`).
    pub unknown_fields: Object,
}

impl Payload {
    /// Validate an already-parsed `payload` member.
    ///
    /// # Errors
    /// [`InferenceArtifactError::SchemaInvalid`] at `payload` when the
    /// member is not an object, a digest or size is missing or mistyped,
    /// or the size is zero.
    pub fn from_value(value: &Value) -> Result<Self, InferenceArtifactError> {
        let Value::Object(object) = value else {
            return Err(invalid(
                "payload",
                "member must be an object when present, never null",
            ));
        };
        let payload_digest = typed(object, "payload_digest")?;
        let payload_size = u63(require(object, "payload_size")?, "payload_size")?;
        if payload_size < 1 {
            return Err(invalid(
                "payload",
                "payload_size must be at least 1; an empty body is the member's absence",
            ));
        }
        let mut unknown_fields = Object::new();
        for (name, member) in object.iter() {
            if matches!(name, "payload_digest" | "payload_size") {
                continue;
            }
            unknown_fields.set(name, member.clone());
        }
        Ok(Self {
            payload_digest,
            payload_size,
            unknown_fields,
        })
    }

    /// The `payload` member as a protocol value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut payload = Object::new();
        payload.set("payload_digest", Value::Text(self.payload_digest.to_hex()));
        payload.set("payload_size", u63_value(self.payload_size));
        for (name, value) in self.unknown_fields.iter() {
            payload.set(name, value.clone());
        }
        Value::Object(payload)
    }
}

/// The closed nine-entry metadata allowlist as a value: the header-derived
/// material the boundary observed — content type, the provider's request
/// ID, HTTP status, rate-limit metadata, and the bounded usage counters.
///
/// Closure is structural. Every entry is a named `Option`; a credential,
/// cookie, or authorization value has no member it can be assigned to, so
/// it is unrepresentable at construction. On the wire path an unknown name
/// is refused outright with the key named — never silently stripped
/// ([`Metadata::from_value`]). Present only when at least one allowlisted
/// value was observed; omitted — never empty and never null — otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// Media type the boundary observed for these bytes, retained verbatim
    /// including parameters. Printable ASCII, at most 256 bytes.
    pub content_type: Option<String>,
    /// The provider's own request identifier as the boundary observed it.
    /// Printed opaque: bounded printable ASCII, never grammar-matched.
    pub provider_request_id: Option<String>,
    /// HTTP status code of the response, 100–599.
    pub http_status: Option<u64>,
    /// Rate-limit window allowance, as the boundary normalized it.
    pub rate_limit_limit: Option<u64>,
    /// Rate-limit remaining allowance.
    pub rate_limit_remaining: Option<u64>,
    /// Rate-limit reset metadata, retained in the unit the provider
    /// reported (interpreted downstream, never guessed here).
    pub rate_limit_reset: Option<u64>,
    /// Input token count extracted from the usage report. Required for the
    /// `usage` kind, optional nowhere else.
    pub usage_input_tokens: Option<u64>,
    /// Output token count.
    pub usage_output_tokens: Option<u64>,
    /// Total token count as reported — retained, never recomputed, so a
    /// provider's own arithmetic is never silently rewritten.
    pub usage_total_tokens: Option<u64>,
}

impl Metadata {
    /// Validate an already-parsed `metadata` member against the closed
    /// allowlist.
    ///
    /// # Errors
    /// [`InferenceArtifactError::SchemaInvalid`] at `metadata` when the
    /// member is not an object, carries any name outside
    /// [`METADATA_ALLOWLIST`] (the key is named in the reason — refusal,
    /// never stripping), mistypes an entry, violates an entry's grammar,
    /// or is present but empty.
    pub fn from_value(value: &Value) -> Result<Self, InferenceArtifactError> {
        let Value::Object(object) = value else {
            return Err(invalid(
                "metadata",
                "member must be an object when present, never null",
            ));
        };
        let mut metadata = Self {
            content_type: None,
            provider_request_id: None,
            http_status: None,
            rate_limit_limit: None,
            rate_limit_remaining: None,
            rate_limit_reset: None,
            usage_input_tokens: None,
            usage_output_tokens: None,
            usage_total_tokens: None,
        };
        for (name, member) in object.iter() {
            match name {
                "content_type" => metadata.content_type = Some(printable_ascii(member)?),
                "provider_request_id" => {
                    metadata.provider_request_id = Some(printable_ascii(member)?);
                }
                "http_status" => {
                    let status = u63(member, "metadata")?;
                    if !(100..=599).contains(&status) {
                        return Err(invalid(
                            "metadata",
                            "metadata.http_status must be between 100 and 599",
                        ));
                    }
                    metadata.http_status = Some(status);
                }
                "rate_limit_limit" => {
                    metadata.rate_limit_limit = Some(u63(member, "metadata")?);
                }
                "rate_limit_remaining" => {
                    metadata.rate_limit_remaining = Some(u63(member, "metadata")?);
                }
                "rate_limit_reset" => metadata.rate_limit_reset = Some(u63(member, "metadata")?),
                "usage_input_tokens" => {
                    metadata.usage_input_tokens = Some(u63(member, "metadata")?);
                }
                "usage_output_tokens" => {
                    metadata.usage_output_tokens = Some(u63(member, "metadata")?);
                }
                "usage_total_tokens" => {
                    metadata.usage_total_tokens = Some(u63(member, "metadata")?);
                }
                other => {
                    return Err(invalid(
                        "metadata",
                        format!("member name {other:?} is outside the closed allowlist"),
                    ));
                }
            }
        }
        if metadata.is_empty() {
            return Err(invalid(
                "metadata",
                "member is present but carries no allowlisted entry; omit it instead of an \
                 empty object",
            ));
        }
        Ok(metadata)
    }

    /// Whether no allowlisted entry is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.content_type.is_none()
            && self.provider_request_id.is_none()
            && self.http_status.is_none()
            && self.rate_limit_limit.is_none()
            && self.rate_limit_remaining.is_none()
            && self.rate_limit_reset.is_none()
            && self.usage_input_tokens.is_none()
            && self.usage_output_tokens.is_none()
            && self.usage_total_tokens.is_none()
    }

    /// The `metadata` member as a protocol value, or `None` when no entry
    /// is present — the wire form is omitted, never an empty object.
    #[must_use]
    pub fn to_value(&self) -> Option<Value> {
        if self.is_empty() {
            return None;
        }
        let mut metadata = Object::new();
        if let Some(content_type) = &self.content_type {
            metadata.set("content_type", Value::Text(content_type.clone()));
        }
        if let Some(provider_request_id) = &self.provider_request_id {
            metadata.set(
                "provider_request_id",
                Value::Text(provider_request_id.clone()),
            );
        }
        if let Some(http_status) = self.http_status {
            metadata.set("http_status", u63_value(http_status));
        }
        if let Some(rate_limit_limit) = self.rate_limit_limit {
            metadata.set("rate_limit_limit", u63_value(rate_limit_limit));
        }
        if let Some(rate_limit_remaining) = self.rate_limit_remaining {
            metadata.set("rate_limit_remaining", u63_value(rate_limit_remaining));
        }
        if let Some(rate_limit_reset) = self.rate_limit_reset {
            metadata.set("rate_limit_reset", u63_value(rate_limit_reset));
        }
        if let Some(usage_input_tokens) = self.usage_input_tokens {
            metadata.set("usage_input_tokens", u63_value(usage_input_tokens));
        }
        if let Some(usage_output_tokens) = self.usage_output_tokens {
            metadata.set("usage_output_tokens", u63_value(usage_output_tokens));
        }
        if let Some(usage_total_tokens) = self.usage_total_tokens {
            metadata.set("usage_total_tokens", u63_value(usage_total_tokens));
        }
        Some(Value::Object(metadata))
    }
}

/// The kind and its specific members: the interpretive frame for every
/// other member of the record, kept as one value so a record's kind and
/// its kind-specific fields cannot disagree.
///
/// The schema's required/forbidden pairs become the variant shape: a
/// `streaming-event` without an `event_ordinal` is not a value of this
/// enum, and no variant but `Retry` has a `backoff_ms` to carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoundaryEvent {
    /// One decoded HTTP request body (`provider-request`): requires
    /// `payload`.
    ProviderRequest,
    /// One decoded HTTP response body (`provider-response`): requires
    /// `payload`.
    ProviderResponse,
    /// One ordered decoded event of a streamed attempt
    /// (`streaming-event`): requires `event_ordinal` and `payload`; the
    /// events of one `provider_attempt_id`, ordered by `event_ordinal`,
    /// concatenate byte-for-byte to the attempt's decoded response body.
    StreamingEvent {
        /// Zero-based dense ordinal of this event within its attempt's
        /// decoded stream.
        event_ordinal: u64,
    },
    /// That a further transport attempt was started, and why (`retry`):
    /// requires `retry_of_attempt_ordinal` (strictly below the record's
    /// own `attempt_ordinal`) and `retry_reason`.
    Retry {
        /// The `attempt_ordinal` of the attempt this retry follows.
        retry_of_attempt_ordinal: u64,
        /// Why the retry was started, classified at the boundary.
        retry_reason: RetryReason,
        /// Optional observed delay between the failed attempt and the
        /// retried one, in milliseconds.
        backoff_ms: Option<u64>,
    },
    /// The bounded usage counters the boundary extracted from a response
    /// body or stream event (`usage`): requires `usage_source` and a
    /// `metadata` member carrying the three usage counters.
    Usage {
        /// Where the counters were extracted from.
        usage_source: UsageSource,
    },
    /// A failure that produced no decodable provider response
    /// (`transport-error`): requires `error_class`. The class names the
    /// failing layer and carries no bytes or text — there is no free-text
    /// detail member, because error strings are a known credential-leak
    /// route.
    TransportError {
        /// Closed transport-failure classification.
        error_class: TransportErrorClass,
        /// Optional deadline in milliseconds for a timeout-classified
        /// error.
        timeout_ms: Option<u64>,
    },
}

impl BoundaryEvent {
    /// The record's `artifact_kind`.
    #[must_use]
    pub fn kind(&self) -> InferenceArtifactKind {
        match self {
            Self::ProviderRequest => InferenceArtifactKind::ProviderRequest,
            Self::ProviderResponse => InferenceArtifactKind::ProviderResponse,
            Self::StreamingEvent { .. } => InferenceArtifactKind::StreamingEvent,
            Self::Retry { .. } => InferenceArtifactKind::Retry,
            Self::Usage { .. } => InferenceArtifactKind::Usage,
            Self::TransportError { .. } => InferenceArtifactKind::TransportError,
        }
    }
}

/// The kind-specific members each kind owns, for the schema's
/// required/forbidden arms: a member of a kind this record is not is
/// refused, never retained as unknown.
fn kind_specific_members(kind: InferenceArtifactKind) -> &'static [&'static str] {
    match kind {
        InferenceArtifactKind::ProviderRequest | InferenceArtifactKind::ProviderResponse => &[],
        InferenceArtifactKind::StreamingEvent => &["event_ordinal"],
        InferenceArtifactKind::Retry => &["retry_of_attempt_ordinal", "retry_reason", "backoff_ms"],
        InferenceArtifactKind::Usage => &["usage_source"],
        InferenceArtifactKind::TransportError => &["error_class", "timeout_ms"],
    }
}

/// One exact-inference capture artifact: the common correlation and
/// provenance members plus the kind and its specific members.
///
/// Every field is a project-owned type from [`crate::vocabulary`] — the
/// public surface exposes no replaceable SDK type. Construction from parts
/// is by struct literal (producers fill every member; the kind-specific
/// members travel in [`BoundaryEvent`]); the wire path is
/// [`InferenceArtifact::parse`], which performs the full bounded
/// validation the module docs list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceArtifact {
    /// Issuer-created tenant identifier (`uuid-v4`).
    pub tenant_id: TenantId,
    /// The linked installation whose proxy or SDK hook captured the
    /// boundary (`uuid-v4`). Capture provenance, not upload provenance.
    pub origin_client_id: ClientId,
    /// `UUIDv7` of the orchestrator operation. Correlation only: never an
    /// input to any digest or storage key.
    pub trace_id: TraceId,
    /// `UUIDv7` of the logical inference — one orchestrator request that
    /// may span several transport attempts. Correlation only.
    pub inference_request_id: InferenceRequestId,
    /// `UUIDv7` of the one transport attempt this artifact belongs to.
    /// Every artifact of an attempt shares it. Correlation only.
    pub provider_attempt_id: ProviderAttemptId,
    /// Zero-based dense ordinal of the transport attempt within the
    /// logical inference.
    pub attempt_ordinal: u64,
    /// Optional UTC time the boundary captured these bytes; omitted —
    /// never null — when the boundary cannot clock the event. Frozen at
    /// capture, so an upload retry reproduces identical bytes.
    pub capture_time: Option<Timestamp>,
    /// The captured bytes, when any were.
    pub payload: Option<Payload>,
    /// The closed allowlist of header-derived values, when at least one
    /// was observed.
    pub metadata: Option<Metadata>,
    /// The kind and its specific members.
    pub event: BoundaryEvent,
    /// Members this version does not define, retained verbatim
    /// (`unknownFields: retain-ignore`). Reserved names never reach here:
    /// [`InferenceArtifact::parse`] refuses them outright.
    pub unknown_fields: Object,
}

impl InferenceArtifact {
    /// Parse and fully validate an artifact from its wire bytes.
    /// Transmission need not be canonical — reordered members and
    /// insignificant whitespace parse to the same value — but every other
    /// rule in the module docs applies.
    ///
    /// # Errors
    /// The first [`InferenceArtifactError`] in the validation order:
    /// reserved names, the version axis, required-member grammar, the
    /// kind's required and forbidden members, the closed metadata
    /// allowlist, and the semantic checks.
    pub fn parse(bytes: &[u8]) -> Result<Self, InferenceArtifactError> {
        let value = json::parse(bytes).map_err(|source| InferenceArtifactError::Malformed {
            reason: "bounded parse of the artifact bytes failed",
            source: Some(source),
        })?;
        Self::from_value(value)
    }

    /// Validate an already-parsed JSON value as an artifact.
    ///
    /// # Errors
    /// As [`InferenceArtifact::parse`].
    pub fn from_value(value: Value) -> Result<Self, InferenceArtifactError> {
        let Value::Object(object) = value else {
            return Err(InferenceArtifactError::Malformed {
                reason: "inference artifact is not a JSON object",
                source: None,
            });
        };

        // The reserved `not` block is mirrored before any field is read:
        // credential, framing, and storage-location names are refused, so
        // misrouted material fails loudly instead of being retained or
        // stripped.
        for field in RESERVED_FIELDS {
            if object.contains(field) {
                return Err(invalid(field, "reserved member of the capture boundary"));
            }
        }

        version(&object)?;
        let artifact = Self {
            tenant_id: typed(&object, "tenant_id")?,
            origin_client_id: typed(&object, "origin_client_id")?,
            trace_id: typed(&object, "trace_id")?,
            inference_request_id: typed(&object, "inference_request_id")?,
            provider_attempt_id: typed(&object, "provider_attempt_id")?,
            attempt_ordinal: u63(require(&object, "attempt_ordinal")?, "attempt_ordinal")?,
            capture_time: optional(&object, "capture_time")?,
            payload: match object.get("payload") {
                None => None,
                Some(member) => Some(Payload::from_value(member)?),
            },
            metadata: match object.get("metadata") {
                None => None,
                Some(member) => Some(Metadata::from_value(member)?),
            },
            event: parse_event(&object)?,
            unknown_fields: retained(&object),
        };
        artifact.semantic_checks()?;
        Ok(artifact)
    }

    /// The record's `artifact_kind`.
    #[must_use]
    pub fn kind(&self) -> InferenceArtifactKind {
        self.event.kind()
    }

    /// Calendar and semantic checks (VAL-002): a real calendar
    /// `capture_time`, a `retry_of_attempt_ordinal` strictly below the
    /// record's own `attempt_ordinal`, and the three usage counters
    /// present on a `usage` record's metadata.
    fn semantic_checks(&self) -> Result<(), InferenceArtifactError> {
        if let Some(capture_time) = &self.capture_time
            && !capture_time.calendar_valid()
        {
            return Err(invalid(
                "capture_time",
                "timestamp is not a real calendar instant",
            ));
        }
        if let BoundaryEvent::Retry {
            retry_of_attempt_ordinal,
            ..
        } = &self.event
            && *retry_of_attempt_ordinal >= self.attempt_ordinal
        {
            return Err(invalid(
                "retry_of_attempt_ordinal",
                "must be strictly less than this record's attempt_ordinal",
            ));
        }
        if let BoundaryEvent::Usage { .. } = &self.event {
            let Some(metadata) = &self.metadata else {
                return Err(invalid(
                    "metadata",
                    "a usage record requires the usage counters",
                ));
            };
            let counters = [
                ("usage_input_tokens", metadata.usage_input_tokens.is_some()),
                (
                    "usage_output_tokens",
                    metadata.usage_output_tokens.is_some(),
                ),
                ("usage_total_tokens", metadata.usage_total_tokens.is_some()),
            ];
            for (counter, present) in counters {
                if !present {
                    return Err(invalid(
                        "metadata",
                        format!("a usage record requires metadata.{counter}"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The complete record as a protocol value: every typed member rendered
    /// to its wire form, the retained unknown members verbatim. The kind
    /// travels as `artifact_kind`, and each kind's specific members appear
    /// exactly when their variant carries them.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut record = Object::new();
        record.set("artifact_kind", Value::Text(self.kind().token().to_owned()));
        record.set("attempt_ordinal", u63_value(self.attempt_ordinal));
        if let Some(capture_time) = &self.capture_time {
            record.set(
                "capture_time",
                Value::Text(capture_time.as_str().to_owned()),
            );
        }
        record.set(
            "inference_artifact_version",
            Value::Int(INFERENCE_ARTIFACT_VERSION),
        );
        record.set(
            "inference_request_id",
            Value::Text(self.inference_request_id.as_str().to_owned()),
        );
        record.set(
            "origin_client_id",
            Value::Text(self.origin_client_id.as_str().to_owned()),
        );
        if let Some(payload) = &self.payload {
            record.set("payload", payload.to_value());
        }
        if let Some(metadata) = &self.metadata
            && let Some(member) = metadata.to_value()
        {
            record.set("metadata", member);
        }
        record.set(
            "provider_attempt_id",
            Value::Text(self.provider_attempt_id.as_str().to_owned()),
        );
        record.set("tenant_id", Value::Text(self.tenant_id.as_str().to_owned()));
        record.set("trace_id", Value::Text(self.trace_id.as_str().to_owned()));
        match &self.event {
            BoundaryEvent::ProviderRequest | BoundaryEvent::ProviderResponse => {}
            BoundaryEvent::StreamingEvent { event_ordinal } => {
                record.set("event_ordinal", u63_value(*event_ordinal));
            }
            BoundaryEvent::Retry {
                retry_of_attempt_ordinal,
                retry_reason,
                backoff_ms,
            } => {
                record.set(
                    "retry_of_attempt_ordinal",
                    u63_value(*retry_of_attempt_ordinal),
                );
                record.set("retry_reason", Value::Text(retry_reason.token().to_owned()));
                if let Some(backoff_ms) = backoff_ms {
                    record.set("backoff_ms", u63_value(*backoff_ms));
                }
            }
            BoundaryEvent::Usage { usage_source } => {
                record.set("usage_source", Value::Text(usage_source.token().to_owned()));
            }
            BoundaryEvent::TransportError {
                error_class,
                timeout_ms,
            } => {
                record.set("error_class", Value::Text(error_class.token().to_owned()));
                if let Some(timeout_ms) = timeout_ms {
                    record.set("timeout_ms", u63_value(*timeout_ms));
                }
            }
        }
        for (name, value) in self.unknown_fields.iter() {
            record.set(name, value.clone());
        }
        Value::Object(record)
    }

    /// The RFC 8785 canonical serialization of the record: the byte-stable
    /// form the capture freezes, the upload retry rewrites, and every
    /// digest over the record names.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.to_value().canonical_bytes()
    }
}

/// Read the kind and its required specific members, refusing a foreign
/// kind's specific members outright (the schema's not-required arms).
fn parse_event(object: &Object) -> Result<BoundaryEvent, InferenceArtifactError> {
    let kind: InferenceArtifactKind = typed(object, "artifact_kind")?;
    for owner in [
        InferenceArtifactKind::ProviderRequest,
        InferenceArtifactKind::ProviderResponse,
        InferenceArtifactKind::StreamingEvent,
        InferenceArtifactKind::Retry,
        InferenceArtifactKind::Usage,
        InferenceArtifactKind::TransportError,
    ] {
        if owner == kind {
            continue;
        }
        for member in kind_specific_members(owner) {
            if object.contains(member) {
                return Err(invalid(
                    *member,
                    format!(
                        "member is specific to the {} kind and never present on a {} record",
                        owner.token(),
                        kind.token()
                    ),
                ));
            }
        }
    }
    let payload_required = matches!(
        kind,
        InferenceArtifactKind::ProviderRequest
            | InferenceArtifactKind::ProviderResponse
            | InferenceArtifactKind::StreamingEvent
    );
    if payload_required && !object.contains("payload") {
        return Err(invalid(
            "payload",
            format!("a {} record requires the captured bytes", kind.token()),
        ));
    }
    Ok(match kind {
        InferenceArtifactKind::ProviderRequest => BoundaryEvent::ProviderRequest,
        InferenceArtifactKind::ProviderResponse => BoundaryEvent::ProviderResponse,
        InferenceArtifactKind::StreamingEvent => BoundaryEvent::StreamingEvent {
            event_ordinal: u63(require(object, "event_ordinal")?, "event_ordinal")?,
        },
        InferenceArtifactKind::Retry => BoundaryEvent::Retry {
            retry_of_attempt_ordinal: u63(
                require(object, "retry_of_attempt_ordinal")?,
                "retry_of_attempt_ordinal",
            )?,
            retry_reason: typed(object, "retry_reason")?,
            backoff_ms: optional_u63(object, "backoff_ms")?,
        },
        InferenceArtifactKind::Usage => BoundaryEvent::Usage {
            usage_source: typed(object, "usage_source")?,
        },
        InferenceArtifactKind::TransportError => BoundaryEvent::TransportError {
            error_class: typed(object, "error_class")?,
            timeout_ms: optional_u63(object, "timeout_ms")?,
        },
    })
}

/// Shorthand for a validation failure at one member.
fn invalid(field: impl Into<String>, reason: impl Into<String>) -> InferenceArtifactError {
    InferenceArtifactError::SchemaInvalid {
        field: field.into(),
        reason: reason.into(),
    }
}

/// Require `object` to hold `field`.
fn require<'a>(
    object: &'a Object,
    field: &'static str,
) -> Result<&'a Value, InferenceArtifactError> {
    object
        .get(field)
        .ok_or_else(|| invalid(field, "required member is missing"))
}

/// Require `value` to be text.
fn text<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, InferenceArtifactError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(invalid(field, "member must be a string")),
    }
}

/// Require `value` to be a non-negative integer below 2^63 (the `u63` shape).
fn u63(value: &Value, field: &'static str) -> Result<u64, InferenceArtifactError> {
    match value {
        Value::Int(n) if *n >= 0 => Ok(u64::try_from(*n).expect("non-negative i64 fits u64")),
        Value::Int(_) => Err(invalid(field, "integer is below zero")),
        _ => Err(invalid(field, "member must be an integer")),
    }
}

/// Require and grammar-validate a text member as `T`.
fn typed<T>(object: &Object, field: &'static str) -> Result<T, InferenceArtifactError>
where
    T: std::str::FromStr<Err = crate::vocabulary::GrammarError>,
{
    let raw = text(require(object, field)?, field)?;
    T::from_str(raw).map_err(|_| invalid(field, "value does not match the canonical grammar"))
}

/// Require the const-pinned `inference_artifact_version`, failing closed on
/// any other major (plan Section 7.1).
fn version(object: &Object) -> Result<(), InferenceArtifactError> {
    match require(object, "inference_artifact_version")? {
        Value::Int(found) if *found == INFERENCE_ARTIFACT_VERSION => Ok(()),
        Value::Int(found) => Err(InferenceArtifactError::VersionUnsupported { found: *found }),
        _ => Err(invalid(
            "inference_artifact_version",
            "member must be an integer",
        )),
    }
}

/// Read an optional text member: `None` when absent, an error when present
/// but not grammatical. The schema omits optional members rather than
/// nulling them.
fn optional<T>(object: &Object, field: &'static str) -> Result<Option<T>, InferenceArtifactError>
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

/// Read an optional `u63` member.
fn optional_u63(
    object: &Object,
    field: &'static str,
) -> Result<Option<u64>, InferenceArtifactError> {
    match object.get(field) {
        None => Ok(None),
        Some(member) => Ok(Some(u63(member, field)?)),
    }
}

/// The bounded printable-ASCII text grammar shared by `content_type` and
/// `provider_request_id`: `^[ -~]{1,256}$`, retained verbatim.
fn printable_ascii(value: &Value) -> Result<String, InferenceArtifactError> {
    let Value::Text(raw) = value else {
        return Err(invalid("metadata", "metadata entry must be a string"));
    };
    if raw.is_empty() || raw.len() > 256 || !raw.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(invalid(
            "metadata",
            "metadata entry must be 1-256 printable ASCII bytes",
        ));
    }
    Ok(raw.clone())
}

/// Render a `u63` field: parsing guarantees the bound, so a value that no
/// longer fits the wire integer domain is a programmatic-construction bug,
/// not a wire condition.
fn u63_value(value: u64) -> Value {
    Value::Int(i64::try_from(value).expect("u63 fields stay below 2^63"))
}

/// Collect the members this version does not define. Reserved names cannot
/// appear here (they were refused before any field was read); the debug
/// assertion keeps that coupling honest if the up-front check is ever
/// reordered away.
fn retained(object: &Object) -> Object {
    let mut unknown = Object::new();
    for (name, value) in object.iter() {
        debug_assert!(
            !RESERVED_FIELDS.contains(&name),
            "reserved names are refused before retention"
        );
        if RECORD_FIELD_NAMES.contains(&name) {
            continue;
        }
        unknown.set(name, value.clone());
    }
    unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The corpus's `single-attempt/request.json`, inlined so the unit
    /// tests need no filesystem access. `tests/inference_artifact_corpus.rs`
    /// replays the corpus itself.
    const REQUEST: &str = r#"{"artifact_kind":"provider-request","attempt_ordinal":0,"capture_time":"2026-09-12T16:44:05Z","inference_artifact_version":1,"inference_request_id":"00000000-0000-7000-8000-000000000010","metadata":{"content_type":"application/json"},"origin_client_id":"00000000-0000-4000-8000-000000000002","payload":{"payload_digest":"d7fa600529fa24ecdcd3e8f008f9c7853fa8442ede4182a79c31c82c872f896a","payload_size":90},"provider_attempt_id":"00000000-0000-7000-8000-000000000101","tenant_id":"00000000-0000-4000-8000-000000000001","trace_id":"00000000-0000-7000-8000-000000000003"}"#;

    /// The corpus's `single-attempt/response.json`.
    const RESPONSE: &str = r#"{"artifact_kind":"provider-response","attempt_ordinal":0,"capture_time":"2026-09-12T16:44:06Z","inference_artifact_version":1,"inference_request_id":"00000000-0000-7000-8000-000000000010","metadata":{"content_type":"application/json","http_status":200,"provider_request_id":"synthetic-provider-request-1","rate_limit_limit":60,"rate_limit_remaining":59,"rate_limit_reset":1},"origin_client_id":"00000000-0000-4000-8000-000000000002","payload":{"payload_digest":"26c1eea15d3526a0bda5304fe48709c1289c7df7a6a3d297ce7e074bf1f81dfc","payload_size":164},"provider_attempt_id":"00000000-0000-7000-8000-000000000101","tenant_id":"00000000-0000-4000-8000-000000000001","trace_id":"00000000-0000-7000-8000-000000000003"}"#;

    /// The corpus's `streamed-attempt/event-0.json`.
    const STREAM_EVENT: &str = r#"{"artifact_kind":"streaming-event","attempt_ordinal":0,"capture_time":"2026-09-12T16:45:01Z","event_ordinal":0,"inference_artifact_version":1,"inference_request_id":"00000000-0000-7000-8000-000000000030","metadata":{"content_type":"text/event-stream"},"origin_client_id":"00000000-0000-4000-8000-000000000002","payload":{"payload_digest":"c5f879614f84e62724b703ca4d71096da7149f29eb630181705fe3f4f6da233e","payload_size":49},"provider_attempt_id":"00000000-0000-7000-8000-000000000301","tenant_id":"00000000-0000-4000-8000-000000000001","trace_id":"00000000-0000-7000-8000-000000000005"}"#;

    /// The corpus's `retried-attempt/attempt-0-retry.json`.
    const RETRY: &str = r#"{"artifact_kind":"retry","attempt_ordinal":1,"backoff_ms":20000,"capture_time":"2026-09-12T16:44:27Z","inference_artifact_version":1,"inference_request_id":"00000000-0000-7000-8000-000000000020","origin_client_id":"00000000-0000-4000-8000-000000000002","provider_attempt_id":"00000000-0000-7000-8000-000000000202","retry_of_attempt_ordinal":0,"retry_reason":"rate-limit","tenant_id":"00000000-0000-4000-8000-000000000001","trace_id":"00000000-0000-7000-8000-000000000004"}"#;

    /// The corpus's `single-attempt/usage.json`.
    const USAGE: &str = r#"{"artifact_kind":"usage","attempt_ordinal":0,"capture_time":"2026-09-12T16:44:06Z","inference_artifact_version":1,"inference_request_id":"00000000-0000-7000-8000-000000000010","metadata":{"usage_input_tokens":3,"usage_output_tokens":5,"usage_total_tokens":8},"origin_client_id":"00000000-0000-4000-8000-000000000002","provider_attempt_id":"00000000-0000-7000-8000-000000000101","tenant_id":"00000000-0000-4000-8000-000000000001","trace_id":"00000000-0000-7000-8000-000000000003","usage_source":"response-body"}"#;

    /// The corpus's `retried-attempt/attempt-1-transport-error.json`.
    const TRANSPORT_ERROR: &str = r#"{"artifact_kind":"transport-error","attempt_ordinal":1,"error_class":"connect","inference_artifact_version":1,"inference_request_id":"00000000-0000-7000-8000-000000000020","origin_client_id":"00000000-0000-4000-8000-000000000002","provider_attempt_id":"00000000-0000-7000-8000-000000000202","tenant_id":"00000000-0000-4000-8000-000000000001","trace_id":"00000000-0000-7000-8000-000000000004"}"#;

    /// Re-serialize `record` with one extra member added — at the top level
    /// when `container` is `None`, inside that member's object otherwise —
    /// and return the canonical bytes of the result.
    fn with_member(record: &str, container: Option<&str>, name: &str, value: Value) -> Vec<u8> {
        let Value::Object(mut object) = json::parse(record.as_bytes()).expect("baseline parses")
        else {
            panic!("baseline record is an object");
        };
        match container {
            None => object.set(name, value),
            Some(container) => {
                let Some(Value::Object(mut inner)) = object.remove(container) else {
                    panic!("baseline carries the {container} object");
                };
                inner.set(name, value);
                object.set(container, Value::Object(inner));
            }
        }
        Value::Object(object).canonical_bytes()
    }

    /// Re-serialize `record` without the named member — at the top level
    /// when `container` is `None`, inside that member's object otherwise.
    fn without_member(record: &str, container: Option<&str>, name: &str) -> Vec<u8> {
        let Value::Object(mut object) = json::parse(record.as_bytes()).expect("baseline parses")
        else {
            panic!("baseline record is an object");
        };
        match container {
            None => {
                assert!(object.remove(name).is_some(), "baseline carries {name}");
            }
            Some(container) => {
                let Some(Value::Object(mut inner)) = object.remove(container) else {
                    panic!("baseline carries the {container} object");
                };
                assert!(
                    inner.remove(name).is_some(),
                    "baseline carries {container}.{name}"
                );
                object.set(container, Value::Object(inner));
            }
        }
        Value::Object(object).canonical_bytes()
    }

    /// Assert the record is refused with `SchemaInvalid` at `field`, with a
    /// reason naming `needle` — the refusal is loud and names the offending
    /// member, never a silent strip.
    fn assert_refused_at(record: &[u8], field: &str, needle: &str) {
        match InferenceArtifact::parse(record) {
            Err(InferenceArtifactError::SchemaInvalid { field: at, reason }) => {
                assert_eq!(at, field, "refused at the wrong member");
                assert!(
                    reason.contains(needle),
                    "reason must name {needle}: {reason}"
                );
            }
            Err(other) => panic!("expected a refusal at {field}, got {other}"),
            Ok(_) => panic!("expected a refusal at {field}, got an accepted record"),
        }
    }

    /// Every corpus kind parses, re-serializes to the very bytes it came
    /// from, and is a fixed point of parse-canonicalize.
    #[test]
    fn every_kind_round_trips_to_its_canonical_bytes() {
        for (record, kind) in [
            (REQUEST, InferenceArtifactKind::ProviderRequest),
            (RESPONSE, InferenceArtifactKind::ProviderResponse),
            (STREAM_EVENT, InferenceArtifactKind::StreamingEvent),
            (RETRY, InferenceArtifactKind::Retry),
            (USAGE, InferenceArtifactKind::Usage),
            (TRANSPORT_ERROR, InferenceArtifactKind::TransportError),
        ] {
            let artifact = InferenceArtifact::parse(record.as_bytes()).expect("corpus parses");
            assert_eq!(artifact.kind(), kind);
            let canonical = artifact.canonical_bytes();
            assert_eq!(
                canonical,
                record.as_bytes(),
                "{kind} must round-trip byte-exactly"
            );
            let reparsed = InferenceArtifact::parse(&canonical).expect("canonical reparse");
            assert_eq!(reparsed, artifact);
        }
    }

    /// A metadata key outside the closed nine-entry allowlist — a tenth
    /// allowlist entry, which under the schema can only ever arrive with a
    /// new schema major — is refused outright, with the key named.
    #[test]
    fn metadata_key_outside_the_closed_allowlist_is_refused() {
        let mutated = with_member(
            RESPONSE,
            Some("metadata"),
            "user_agent",
            Value::Text("synthetic-agent/1.0".to_owned()),
        );
        assert_refused_at(&mutated, "metadata", "user_agent");
    }

    /// A credential-bearing metadata entry — authorization material, an
    /// API key, a cookie — is refused, never stripped: the closure of the
    /// allowlist is the boundary that keeps provider credentials out of
    /// archive metadata.
    #[test]
    fn credential_bearing_metadata_entries_are_refused() {
        for credential in [
            (
                "authorization",
                Value::Text("Bearer synthetic-token".to_owned()),
            ),
            ("api_key", Value::Text("sk-synthetic-key".to_owned())),
            ("cookie", Value::Text("session=synthetic".to_owned())),
        ] {
            let mutated = with_member(RESPONSE, Some("metadata"), credential.0, credential.1);
            assert_refused_at(&mutated, "metadata", credential.0);
        }
    }

    /// A reserved member at the record's top level — TLS or TCP framing, a
    /// storage location, an authorization header — is refused before any
    /// field is read: misrouted material fails loudly instead of being
    /// retained or stripped.
    #[test]
    fn reserved_top_level_members_are_refused() {
        for reserved in ["tls_record", "tcp_segment", "authorization", "blob_url"] {
            let mutated = with_member(REQUEST, None, reserved, Value::Text("x".to_owned()));
            assert_refused_at(&mutated, reserved, "reserved");
        }
    }

    /// Unknown members — at the record level and inside `payload` — are
    /// retained verbatim and re-serialized into the canonical bytes
    /// (`x-archivist.unknownFields: retain-ignore`), and they are ignored:
    /// their presence neither fails validation nor changes the typed
    /// members. `metadata` stays closed: nothing unknown is retained there.
    #[test]
    fn unknown_members_are_retained_and_ignored() {
        let record = with_member(
            &String::from_utf8(with_member(
                REQUEST,
                Some("payload"),
                "future_payload_note",
                Value::Text("chunked".to_owned()),
            ))
            .expect("canonical bytes are UTF-8"),
            None,
            "x_future_member",
            Value::Int(1),
        );
        let artifact = InferenceArtifact::parse(&record).expect("unknown members are accepted");
        assert_eq!(
            artifact
                .payload
                .as_ref()
                .and_then(|payload| payload.unknown_fields.get("future_payload_note"))
                .and_then(|value| match value {
                    Value::Text(text) => Some(text.as_str()),
                    _ => None,
                }),
            Some("chunked"),
            "the payload's unknown member is retained verbatim"
        );
        assert!(
            artifact.unknown_fields.get("x_future_member").is_some(),
            "the record-level unknown member is retained"
        );
        let canonical = artifact.canonical_bytes();
        let text = String::from_utf8(canonical.clone()).expect("canonical bytes are UTF-8");
        assert!(text.contains(r#""future_payload_note":"chunked""#));
        assert!(text.contains(r#""x_future_member":1"#));
        let reparsed = InferenceArtifact::parse(&canonical).expect("canonical reparse");
        assert_eq!(reparsed, artifact, "retention is a fixed point");
    }

    /// A kind's specific members on a record of a foreign kind are
    /// refused — never retained as unknown, so a kind mismatch can never
    /// pass silently.
    #[test]
    fn foreign_kind_members_are_refused() {
        for (record, member) in [
            (STREAM_EVENT, "retry_reason"),
            (RETRY, "event_ordinal"),
            (TRANSPORT_ERROR, "usage_source"),
            (REQUEST, "error_class"),
            (USAGE, "timeout_ms"),
        ] {
            let mutated = with_member(record, None, member, Value::Int(0));
            assert_refused_at(&mutated, member, "specific to the");
        }
    }

    /// A retry's `retry_of_attempt_ordinal` must be strictly below the
    /// record's own `attempt_ordinal`.
    #[test]
    fn retry_ordinal_must_name_an_earlier_attempt() {
        let mutated = with_member(RETRY, None, "retry_of_attempt_ordinal", Value::Int(1));
        assert_refused_at(&mutated, "retry_of_attempt_ordinal", "strictly less");
    }

    /// A `usage` record requires all three counters in its metadata.
    #[test]
    fn usage_record_requires_all_three_counters() {
        for dropped in [
            "usage_input_tokens",
            "usage_output_tokens",
            "usage_total_tokens",
        ] {
            let mutated = without_member(USAGE, Some("metadata"), dropped);
            assert_refused_at(&mutated, "metadata", dropped);
        }
        let mutated = without_member(USAGE, None, "metadata");
        assert_refused_at(&mutated, "metadata", "usage counters");
    }

    /// An unknown schema major fails closed.
    #[test]
    fn unknown_version_fails_closed() {
        let mutated = with_member(USAGE, None, "inference_artifact_version", Value::Int(2));
        match InferenceArtifact::parse(&mutated) {
            Err(InferenceArtifactError::VersionUnsupported { found }) => assert_eq!(found, 2),
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }

    /// A present-but-empty `metadata` object is refused: the wire form is
    /// the member's absence, never an empty entry.
    #[test]
    fn empty_metadata_object_is_refused() {
        let Value::Object(mut object) = json::parse(RESPONSE.as_bytes()).expect("baseline parses")
        else {
            panic!("baseline record is an object");
        };
        assert!(
            object.remove("metadata").is_some(),
            "baseline carries metadata"
        );
        object.set("metadata", Value::Object(Object::new()));
        let mutated = Value::Object(object).canonical_bytes();
        assert_refused_at(&mutated, "metadata", "empty");
    }

    /// Unknown closed-enum tokens fail closed: the kind, the retry reason,
    /// and the error class are provenance classifications, and an unknown
    /// value is never best-effort parsed.
    #[test]
    fn unknown_enum_tokens_fail_closed() {
        let mutated = with_member(
            USAGE,
            None,
            "artifact_kind",
            Value::Text("provider-hint".to_owned()),
        );
        assert_refused_at(&mutated, "artifact_kind", "grammar");
        let mutated = with_member(RETRY, None, "retry_reason", Value::Text("vibes".to_owned()));
        assert_refused_at(&mutated, "retry_reason", "grammar");
        let mutated = with_member(
            TRANSPORT_ERROR,
            None,
            "error_class",
            Value::Text("router-flap".to_owned()),
        );
        assert_refused_at(&mutated, "error_class", "grammar");
    }

    /// A captured payload is at least one byte: an empty body is the
    /// member's absence, never a zero entry.
    #[test]
    fn empty_payload_size_is_refused() {
        let mutated = with_member(REQUEST, Some("payload"), "payload_size", Value::Int(0));
        assert_refused_at(&mutated, "payload", "at least 1");
    }

    /// `capture_time` is optional (the corpus's transport-error record
    /// omits it) but grammatical when present.
    #[test]
    fn capture_time_is_optional_but_grammatical() {
        let artifact = InferenceArtifact::parse(TRANSPORT_ERROR.as_bytes()).expect("corpus parses");
        assert!(artifact.capture_time.is_none());
        let mutated = with_member(
            TRANSPORT_ERROR,
            None,
            "capture_time",
            Value::Text("yesterday, roughly".to_owned()),
        );
        assert_refused_at(&mutated, "capture_time", "grammar");
    }
}
