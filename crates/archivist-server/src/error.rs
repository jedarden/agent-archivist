// SPDX-License-Identifier: Apache-2.0

//! The stable server error surface: one serialization of every plan
//! Section 7.8 server-side HTTP outcome as the `archivist.error/v1` body
//! pinned by `schemas/v1/ingest-error.json` and governed by
//! `docs/notes/error-codes.md`.
//!
//! Every error body carries exactly the six schema members — the versioned
//! namespace, the stable registry code, the class-fixed `retryable`
//! boolean, the bounded content-safe message, the request identifier, and
//! the fresh per-attempt correlation identifier — and nothing else. The
//! registry drives it: this module embeds `tools/error-codes.toml` with
//! [`include_str!`] and resolves every code's HTTP status and every
//! class's retryability from those committed bytes at first use, so a
//! template reword or an appended code lands here without a code change
//! (ERR-035) and a drift from the registry is a startup failure, not a
//! silent divergence.
//!
//! # The ten Section 7.8 server-side paths
//!
//! [`ServerFailure`] closes the acceptance matrix one variant per path,
//! each carrying only bounded structural values — configuration caps and
//! byte counts, never request bytes (SEC-004, ERR-003):
//!
//! | Path | Variants | Codes |
//! |---|---|---|
//! | parser | [`ServerFailure::Parse`] (framing and envelope halves) | `request.framing_invalid`, `envelope.*` |
//! | media | [`ServerFailure::Parse`] ([`crate::parse::parts::TwoPartError::EnvelopeNotFirst`]) | `envelope.media_type_unsupported` |
//! | authorization | [`ServerFailure::Authorization`] | `auth.unlinked`, `auth.revoked`, `auth.authorization_rejected`, `auth.forbidden` |
//! | integrity | [`ServerFailure::IntegrityConflict`] | `storage.integrity_conflict` |
//! | size | [`ServerFailure::PayloadLimit`] | `request.payload_too_large`, `request.expansion_ratio_exceeded`, `request.record_too_large` |
//! | throttling | [`ServerFailure::RateLimited`] | `request.rate_limited` |
//! | timeout | [`ServerFailure::DeadlineElapsed`], [`ServerFailure::TooEarly`], [`ServerFailure::UpstreamTimeout`] | `request.deadline_exceeded`, `request.too_early`, `server.upstream_timeout` |
//! | registry | [`ServerFailure::RegistryUnavailable`] | `server.unavailable` (the retryable 503 of plan EC-09) |
//! | storage | [`ServerFailure::StorageFailure`], [`ServerFailure::Internal`], [`ServerFailure::Unavailable`] | `server.storage_failure`, `server.internal`, `server.unavailable` |
//! | partial-commit | [`ServerFailure::PartialCommit`] | `server.partial_commit` |
//!
//! # No client state transitions
//!
//! The body decides nothing for the client: it carries the authoritative
//! `retryable` boolean (ERR-004) and the stable code a consumer resolves
//! against its own action table, and it never serializes a client action,
//! a state name, or any other steering field (ERR-003). The registry's
//! `client_action` and `exit` columns stay consumer and tooling data;
//! this surface never reads them — the no-client-state-decisions rule
//! holding at the data level too.
//!
//! # Identifiers (ERR-025 through ERR-027)
//!
//! `request_id` is null exactly when the attempt holds no envelope
//! identifier — a guard refusal or a framing/media rejection precedes the
//! envelope; a pipeline strand that holds a parsed envelope passes its
//! `request_id` in. `correlation_id` is a freshly minted canonical
//! `UUIDv7` for every response this module builds (ERR-026) and always
//! present, even beside a null `request_id`; both travel as the
//! `x-archivist-request-id` (when known) and `x-archivist-correlation-id`
//! response headers as well as body members.
//!
//! # Content-freedom (SEC-004, VAL-007; ERR-011 through ERR-014)
//!
//! Messages are registry templates rendered under the frozen ERR-012
//! allowlist: the only interpolable values on any server path are byte
//! counts and a size ratio, rendered as plain decimal when they fit the
//! frozen integer grammar and as the bracketed placeholder name when they
//! do not (ERR-013's deterministic degradation — visibly wrong, never
//! request content). No rendering ever carries request bytes, an
//! identifier value, a path, or a provider string; the tests hold every
//! variant to the schema's message grammar under the largest and
//! smallest values the platform can represent.

use std::collections::HashMap;
use std::sync::OnceLock;

use archivist_protocol::correlation::mint_correlation_id;
use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{ErrorCode, RequestId, SafeMessage};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_TYPE, HeaderName};
use axum::response::Response;

use crate::parse::ingest::IngestParseError;

/// The embedded machine-readable registry: the same committed bytes
/// `tools/check-error-codes.py` gates, embedded so the server's statuses,
/// retryability, and templates cannot drift from the registry the checker
/// enforces.
const ERROR_REGISTRY_TEXT: &str = include_str!("../../../tools/error-codes.toml");

/// The registry schema this module knows how to read. A committed registry
/// that declares anything else is a format this server has not learned;
/// fail at startup instead of guessing.
const REGISTRY_SCHEMA: &str = "archivist.error-registry/v1";

/// The error namespace (`archivist.error/v1`): appears in every body,
/// never implied by context (ERR-001).
pub const ERROR_NAMESPACE: &str = "archivist.error/v1";

/// Media type of the stable error body (`schemas/v1/ingest-error.json`).
pub const ERROR_MEDIA_TYPE: &str = "application/vnd.agent-archivist.error+json";

/// The response header carrying the body's `request_id` when known
/// (ERR-026).
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-archivist-request-id");

/// The response header carrying the body's `correlation_id`, always
/// present (ERR-026).
pub const CORRELATION_ID_HEADER: HeaderName = HeaderName::from_static("x-archivist-correlation-id");

/// Why a request was refused by the authorization path — the closed set
/// of registry `authorization`-class conditions the ingest surface can
/// name (plan Section 7.8: unlinked, revoked, rejected proof, forbidden).
/// No variant carries a client, tenant, or key identifier (SEC-004).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRejection {
    /// The uploader presents no tenant link: `auth.unlinked`, 401.
    Unlinked,
    /// The presented authorization was revoked: `auth.revoked`, 401.
    Revoked,
    /// The authorization proof is stale, altered, or replayed:
    /// `auth.authorization_rejected`, 401.
    ProofRejected,
    /// The uploader is not authorized for the declared origin client or
    /// tenant: `auth.forbidden`, 403.
    Forbidden,
}

impl AuthRejection {
    /// The registry token for this refusal.
    fn code_token(self) -> &'static str {
        match self {
            Self::Unlinked => "auth.unlinked",
            Self::Revoked => "auth.revoked",
            Self::ProofRejected => "auth.authorization_rejected",
            Self::Forbidden => "auth.forbidden",
        }
    }
}

/// A payload size or expansion limit the pipeline enforced — the two
/// splittable classes a client resolves by rechunking at a record
/// boundary, and the one unsplittable class it quarantines instead. The
/// counts are the configuration caps and the pre-commit measurements the
/// plan's limits are stated in; both are ERR-012 `integer` placeholders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadLimit {
    /// The whole payload exceeds a limit smaller record-boundary chunks
    /// satisfy: `request.payload_too_large`, 413.
    SplittableBytes {
        /// The measured payload size, in bytes.
        actual_bytes: u64,
        /// The cap that was exceeded, in bytes.
        limit_bytes: u64,
    },
    /// The decompression expansion ratio exceeds its cap:
    /// `request.expansion_ratio_exceeded`, 413.
    SplittableRatio {
        /// The cap the expansion exceeded, as a whole number of input
        /// units per output unit.
        max_ratio: u64,
    },
    /// One record alone exceeds an unsplittable limit:
    /// `request.record_too_large`, 413.
    UnsplittableRecord {
        /// The measured record size, in bytes.
        actual_bytes: u64,
        /// The cap that was exceeded, in bytes.
        limit_bytes: u64,
    },
}

impl PayloadLimit {
    /// The registry token for this limit.
    fn code_token(self) -> &'static str {
        match self {
            Self::SplittableBytes { .. } => "request.payload_too_large",
            Self::SplittableRatio { .. } => "request.expansion_ratio_exceeded",
            Self::UnsplittableRecord { .. } => "request.record_too_large",
        }
    }
}

/// Every plan Section 7.8 server-side failure path, closed. Each variant
/// resolves to exactly one registry code — which fixes the HTTP status
/// and, through its class, the authoritative `retryable` boolean — and
/// renders the registry's pinned message. No variant carries request
/// bytes, identifiers, or free text (SEC-004; ERR-003).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerFailure {
    /// The bounded parse layer rejected the request before any commit
    /// existed: framing, part order, the part-one media type, the
    /// envelope cap, or envelope validation — the parser and media paths
    /// of the acceptance matrix, each already mapped to its registry code
    /// and rendered message by [`IngestParseError`].
    Parse(IngestParseError),
    /// The authorization path refused the uploader.
    Authorization(AuthRejection),
    /// Existing stored state is incompatible with this submission: the
    /// integrity path, 409.
    IntegrityConflict,
    /// A payload size or expansion limit was enforced: the size path, 413.
    PayloadLimit(PayloadLimit),
    /// The replica is over its admission inventory: the throttling path,
    /// 429.
    RateLimited,
    /// The configured request deadline elapsed before the attempt
    /// finished: the request-timeout path, 408.
    DeadlineElapsed,
    /// The server is not ready to accept this request yet: 425.
    TooEarly,
    /// The trust registry is unavailable and no valid cached evidence
    /// covers the attempt: the registry path's retryable 503 without
    /// storage writes (plan EC-09).
    RegistryUnavailable,
    /// The storage backend rejected or failed the operation: 502.
    StorageFailure,
    /// The storage backend timed out with an unknown physical outcome:
    /// 504.
    UpstreamTimeout,
    /// A blob-only or blob-plus-occurrence partial commit returned
    /// without a receipt: the identical retry repairs the same occurrence
    /// and attestation, 503 (plan RCPT-005).
    PartialCommit,
    /// An internal server fault that committed nothing: 500.
    Internal,
    /// The replica cannot attempt the request at all — the fail-closed
    /// bootstrap answer until the pipeline slices land: 503.
    Unavailable,
}

impl ServerFailure {
    /// The registry code this failure resolves to — the stable wire token
    /// exactly as `tools/error-codes.toml` registers it.
    ///
    /// # Panics
    /// Never in practice: every literal beneath the non-`Parse` arms of
    /// [`Self::code_token`] is a registered code the module tests resolve
    /// against the embedded registry, so a panic is a programming error
    /// introduced alongside a rename, not a wire condition.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Parse(parse) => parse.code(),
            other => ErrorCode::parse(other.code_token())
                .expect("every mapped code is registry-grammar-clean"),
        }
    }

    /// The registry token behind [`Self::code`] for the fixed-code
    /// variants; the `Parse` variant's code comes from the parse layer
    /// and has no static token here.
    fn code_token(&self) -> &'static str {
        match self {
            Self::Parse(_) => unreachable!("the Parse variant carries its own code"),
            Self::Authorization(rejection) => rejection.code_token(),
            Self::IntegrityConflict => "storage.integrity_conflict",
            Self::PayloadLimit(limit) => limit.code_token(),
            Self::RateLimited => "request.rate_limited",
            Self::DeadlineElapsed => "request.deadline_exceeded",
            Self::TooEarly => "request.too_early",
            Self::RegistryUnavailable | Self::Unavailable => "server.unavailable",
            Self::StorageFailure => "server.storage_failure",
            Self::UpstreamTimeout => "server.upstream_timeout",
            Self::PartialCommit => "server.partial_commit",
            Self::Internal => "server.internal",
        }
    }

    /// The registry's message template for this failure, rendered where
    /// the variant carries ERR-012-allowlisted values: parse failures
    /// render through [`IngestParseError::message`] (which owns the
    /// field-name, version, and media-type degradations), size limits
    /// render their integer placeholders here, and every fixed-message
    /// variant renders its template verbatim.
    ///
    /// # Panics
    /// Never in practice: the same commit's tests resolve every template
    /// and every rendering against the embedded registry's grammar, so a
    /// panic is a template edit that broke the frozen message rules.
    #[must_use]
    pub fn rendered_message(&self) -> SafeMessage {
        let rendered = match self {
            Self::Parse(parse) => parse.message().as_str().to_owned(),
            Self::PayloadLimit(limit) => {
                let template = template_of(&self.code());
                match limit {
                    PayloadLimit::SplittableBytes {
                        actual_bytes,
                        limit_bytes,
                    }
                    | PayloadLimit::UnsplittableRecord {
                        actual_bytes,
                        limit_bytes,
                    } => render_integer_template(
                        template,
                        &[
                            ("actual_bytes", *actual_bytes),
                            ("limit_bytes", *limit_bytes),
                        ],
                    ),
                    PayloadLimit::SplittableRatio { max_ratio } => {
                        render_integer_template(template, &[("max_ratio", *max_ratio)])
                    }
                }
            }
            other => template_of(&other.code()).to_owned(),
        };
        // ERR-011: the rendered message is truncated to at most 200
        // characters. Every interpolable value is charset-constrained, so
        // truncation cannot introduce content; registry templates are
        // bounded well below the cap and the integer placeholders are
        // bounded above it, so in practice this is a no-op belt.
        let truncated: String = rendered.chars().take(200).collect();
        SafeMessage::parse(&truncated).expect("rendered registry templates are safe messages")
    }
}

/// The registered message template for a resolved code.
///
/// # Panics
/// Never in practice: every caller resolves codes the module tests pin
/// against the embedded registry.
fn template_of(code: &ErrorCode) -> &'static str {
    registry()
        .template(code.as_str())
        .expect("every mapped code is registered")
}

/// Render an integer template under ERR-012 and ERR-013: each named
/// placeholder receives the value as plain decimal when it fits the frozen
/// integer grammar (below 2^63, at most 19 digits) and the bracketed
/// placeholder name when it does not — deterministic, bounded, visibly
/// wrong, never request content. Placeholders absent from the template are
/// ignored.
fn render_integer_template(template: &str, values: &[(&'static str, u64)]) -> String {
    let mut rendered = template.to_owned();
    for (name, value) in values {
        let placeholder = format!("{{{name}}}");
        let replacement = if integer_in_grammar(*value) {
            value.to_string()
        } else {
            format!("[{name}]")
        };
        rendered = rendered.replace(&placeholder, &replacement);
    }
    rendered
}

/// The ERR-012 integer grammar at render time: plain decimal, at most 19
/// digits, values below 2^63.
fn integer_in_grammar(value: u64) -> bool {
    value < 2_u64.pow(63)
}

/// One registered error code as the embedded registry carries it.
#[derive(Clone, Copy, Debug)]
struct RegisteredCode {
    /// The class the code belongs to (ERR-005: exactly one).
    class: &'static str,
    /// The one HTTP status the code declares from its class's allowed set
    /// (ERR-009). `None` for the client-only families (`transport.*`,
    /// `cli.*`, `client.*`) that never surface as an HTTP status — they
    /// register so their templates exist, but cannot resolve to a response.
    http: Option<u16>,
    /// The registered message template (ERR-011).
    message: &'static str,
}

/// The parsed embedded registry: exactly the attributes the wire contract
/// needs — the class retryability and, per code, the status and template.
/// The registry's `client_action`, `exit`, and `description` attributes
/// are consumer and tooling data; this surface never reads them.
#[derive(Default)]
struct ErrorRegistry {
    /// Per class name: the frozen retryable attribute (ERR-006).
    retryable_by_class: HashMap<&'static str, bool>,
    /// Per code token: the registered code.
    codes: HashMap<&'static str, RegisteredCode>,
}

impl ErrorRegistry {
    /// The code's registered status and its class's retryable attribute.
    /// `None` for unregistered codes and for the client-only families that
    /// declare no HTTP status at all.
    fn resolve(&self, code: &str) -> Option<(u16, bool)> {
        let registered = self.codes.get(code)?;
        let http = registered.http?;
        let retryable = self.retryable_by_class.get(registered.class).copied()?;
        Some((http, retryable))
    }

    /// The code's registered message template.
    fn template(&self, code: &str) -> Option<&'static str> {
        self.codes.get(code).map(|registered| registered.message)
    }
}

/// The process-wide parsed registry, built once from the embedded bytes.
///
/// # Panics
/// On first use if the embedded registry violates the format this module
/// reads. `tools/check-error-codes.py` gates the same committed bytes in
/// the fast lane and this module's tests parse them on every test run, so
/// a panic is a same-commit registry format change nobody adapted, never
/// a runtime wire condition.
fn registry() -> &'static ErrorRegistry {
    static REGISTRY: OnceLock<ErrorRegistry> = OnceLock::new();
    REGISTRY
        .get_or_init(|| parse_registry(ERROR_REGISTRY_TEXT).expect("the committed registry parses"))
}

/// The per-code attributes as gathered from the text, before the
/// completeness check that turns them into a [`RegisteredCode`].
#[derive(Default)]
struct GatheredCode {
    class: Option<&'static str>,
    http: Option<u16>,
    message: Option<&'static str>,
}

/// Parse the embedded registry text: the minimal TOML subset the file
/// uses — top-level `schema`, `[classes.NAME]` tables with `retryable`,
/// and `[codes."d.c"]` tables with `class`, `http`, and `message`.
/// Unknown keys are ignored (the registry format grows optional keys
/// compatibly, ERR-035); anything this module needs and cannot parse is
/// an error, never a guess. Every returned slice borrows the `&'static`
/// input.
fn parse_registry(text: &'static str) -> Result<ErrorRegistry, &'static str> {
    let mut retryable_by_class: HashMap<&'static str, Option<bool>> = HashMap::new();
    let mut gathered: HashMap<&'static str, GatheredCode> = HashMap::new();
    let mut schema_seen = false;
    let mut current = SectionKind::Root;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            current = section_kind(line)?;
            match &current {
                SectionKind::Root => {}
                SectionKind::Class(name) => {
                    retryable_by_class.entry(name).or_insert(None);
                }
                SectionKind::Code(token) => {
                    gathered.entry(token).or_default();
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err("registry line carries no key = value pair");
        };
        let key = key.trim();
        let value = value.trim();
        match &current {
            SectionKind::Root => {
                if key == "schema" {
                    let declared = unquote(value).ok_or("schema is not a quoted string")?;
                    if declared != REGISTRY_SCHEMA {
                        return Err("registry declares an unknown schema");
                    }
                    schema_seen = true;
                }
            }
            SectionKind::Class(name) => {
                if key == "retryable" {
                    let retryable = parse_bool(value).ok_or("retryable is not a boolean")?;
                    if let Some(slot) = retryable_by_class.get_mut(name) {
                        *slot = Some(retryable);
                    }
                }
            }
            SectionKind::Code(token) => {
                let Some(entry) = gathered.get_mut(token) else {
                    return Err("attribute outside a known code section");
                };
                match key {
                    "class" => {
                        entry.class = Some(unquote(value).ok_or("class is not a quoted string")?);
                    }
                    "http" => {
                        entry.http = Some(
                            value
                                .parse()
                                .map_err(|_| "http status is not a u16 integer")?,
                        );
                    }
                    "message" => {
                        entry.message =
                            Some(unquote(value).ok_or("message is not a quoted string")?);
                    }
                    // `description`, `deprecated`, and future optional
                    // keys are consumer and tooling data this surface
                    // never reads.
                    _ => {}
                }
            }
        }
    }

    if !schema_seen {
        return Err("registry declares no schema");
    }
    if retryable_by_class.is_empty() || gathered.is_empty() {
        return Err("registry carries no classes or no codes");
    }

    let mut registry = ErrorRegistry::default();
    for (name, retryable) in retryable_by_class {
        let retryable = retryable.ok_or("class entry declares no retryable attribute")?;
        registry.retryable_by_class.insert(name, retryable);
    }
    for (token, entry) in gathered {
        let class = entry.class.ok_or("code entry declares no class")?;
        let message = entry.message.ok_or("code entry declares no message")?;
        if !registry.retryable_by_class.contains_key(class) {
            return Err("code names an unregistered class");
        }
        registry.codes.insert(
            token,
            RegisteredCode {
                class,
                http: entry.http,
                message,
            },
        );
    }
    Ok(registry)
}

/// Classify one section header line. The returned slices borrow the
/// registry text the line came from — `'static` for every call site,
/// because the only input is the embedded `&'static str`.
fn section_kind(line: &'static str) -> Result<SectionKind, &'static str> {
    let header = line
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or("unterminated section header")?;
    if let Some(class) = header.strip_prefix("classes.") {
        if class.is_empty()
            || !class
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err("unrecognized class section name");
        }
        Ok(SectionKind::Class(class))
    } else if let Some(code) = header.strip_prefix("codes.") {
        let token = code
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or("code section is not a quoted token")?;
        if ErrorCode::parse(token).is_err() {
            return Err("code section name violates the code grammar");
        }
        Ok(SectionKind::Code(token))
    } else {
        Err("unrecognized section kind")
    }
}

/// The section currently being parsed.
enum SectionKind {
    Root,
    Class(&'static str),
    Code(&'static str),
}

/// Strip the quotes of a single-line basic string with no escape
/// sequences. The registry's templates are printable ASCII without
/// backslashes; an escaped or unterminated string is an error, not a
/// guess.
fn unquote(value: &str) -> Option<&str> {
    let inner = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))?;
    if inner.contains('\\') || inner.contains('"') {
        return None;
    }
    Some(inner)
}

/// Parse a TOML boolean.
fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// The complete stable error response: the six-member `archivist.error/v1`
/// body, its registered HTTP status, and the correlation headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    /// The registry-declared HTTP status of the failure's code.
    status: u16,
    /// The failure's registry code token.
    code: String,
    /// The class-fixed authoritative retryable boolean (ERR-004, ERR-015).
    retryable: bool,
    /// The rendered bounded content-safe message (ERR-011).
    message: String,
    /// The request identifier, when the attempt holds one (ERR-025,
    /// ERR-027).
    request_id: Option<RequestId>,
    /// The fresh per-attempt correlation identifier (ERR-026).
    correlation_id: RequestId,
}

impl ErrorResponse {
    /// Build the response for a Section 7.8 failure whose envelope never
    /// yielded a request identifier: guard refusals and the parse paths
    /// that precede the envelope (ERR-027's null `request_id`).
    ///
    /// # Panics
    /// Never in practice: only if the embedded registry stops parsing or
    /// a mapped code stops being registered — both same-commit
    /// programming errors the tests pin, never wire conditions.
    #[must_use]
    pub fn for_failure(failure: ServerFailure) -> Self {
        Self::for_failure_with(failure, None)
    }

    /// Build the response for a Section 7.8 failure, carrying the parsed
    /// envelope's request identifier when the attempt holds one (ERR-025);
    /// `None` renders the schema's null.
    ///
    /// # Panics
    /// As [`Self::for_failure`].
    #[must_use]
    pub fn for_failure_with(failure: ServerFailure, request_id: Option<RequestId>) -> Self {
        Self::with_correlation(failure, request_id, mint_correlation_id())
    }

    /// Build the response with an explicit correlation identifier — the
    /// deterministic core [`Self::for_failure_with`] wraps a mint around.
    ///
    /// # Panics
    /// As [`Self::for_failure`].
    #[must_use]
    pub fn with_correlation(
        failure: ServerFailure,
        request_id: Option<RequestId>,
        correlation_id: RequestId,
    ) -> Self {
        let code = failure.code();
        let token = code.as_str();
        let (status, retryable) = registry()
            .resolve(token)
            .expect("every mapped code is registered with its class");
        Self {
            status,
            code: token.to_owned(),
            retryable,
            message: failure.rendered_message().as_str().to_owned(),
            request_id,
            correlation_id,
        }
    }

    /// The registered HTTP status of this failure's code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// The stable registry code of this failure.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The authoritative retryable boolean (ERR-004).
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// The rendered bounded content-safe message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The request identifier, when the attempt holds one.
    #[must_use]
    pub fn request_id(&self) -> Option<&RequestId> {
        self.request_id.as_ref()
    }

    /// The fresh per-attempt correlation identifier.
    #[must_use]
    pub const fn correlation_id(&self) -> &RequestId {
        &self.correlation_id
    }

    /// The exact canonical body bytes: the six schema members and nothing
    /// else, rendered through the protocol's RFC 8785 writer.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut object = Object::new();
        let _ = object.insert("code", Value::Text(self.code.clone()));
        let _ = object.insert(
            "correlation_id",
            Value::Text(self.correlation_id.as_str().to_owned()),
        );
        let _ = object.insert("message", Value::Text(self.message.clone()));
        let _ = object.insert(
            "request_id",
            self.request_id.as_ref().map_or(Value::Null, |request_id| {
                Value::Text(request_id.as_str().to_owned())
            }),
        );
        let _ = object.insert("retryable", Value::Bool(self.retryable));
        let _ = object.insert("schema", Value::Text(ERROR_NAMESPACE.to_owned()));
        Value::Object(object).canonical_bytes()
    }

    /// The wire response: registered status, the error media type, the
    /// correlation headers (ERR-021, ERR-026 — `request_id` only when
    /// known), and the canonical body.
    ///
    /// # Panics
    /// Never in practice: the registry's statuses are validated HTTP
    /// status codes and the media type and header names are static
    /// constants, so a panic is a corrupted registry, not a wire
    /// condition.
    #[must_use]
    pub fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status)
            .expect("registry statuses are valid HTTP status codes");
        let mut builder = Response::builder()
            .status(status)
            .header(CONTENT_TYPE, ERROR_MEDIA_TYPE)
            .header(CORRELATION_ID_HEADER, self.correlation_id.as_str());
        if let Some(request_id) = &self.request_id {
            builder = builder.header(REQUEST_ID_HEADER, request_id.as_str());
        }
        builder
            .body(axum::body::Body::from(self.canonical_bytes()))
            .expect("static status, headers, and body build a response")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthRejection, CORRELATION_ID_HEADER, ERROR_MEDIA_TYPE, ERROR_NAMESPACE, ErrorResponse,
        PayloadLimit, REQUEST_ID_HEADER, ServerFailure, parse_registry, registry,
    };
    use crate::parse::framing::FramingError;
    use crate::parse::ingest::IngestParseError;
    use crate::parse::parts::TwoPartError;
    use archivist_protocol::envelope::EnvelopeError;
    use archivist_protocol::json;
    use archivist_protocol::vocabulary::RequestId;
    use axum::http::header::CONTENT_TYPE;

    const TEST_REQUEST_ID: &str = "1a07b201-7000-7000-8000-000000000001";
    const TEST_CORRELATION_ID: &str = "1a07c201-7000-7000-8000-000000000001";

    /// One instance of every Section 7.8 server-side failure path — the
    /// acceptance matrix, walked end to end.
    fn every_failure() -> Vec<ServerFailure> {
        vec![
            ServerFailure::Parse(IngestParseError::Framing(TwoPartError::PayloadPartMissing)),
            ServerFailure::Parse(IngestParseError::Framing(TwoPartError::EnvelopeNotFirst)),
            ServerFailure::Parse(IngestParseError::Framing(
                TwoPartError::EnvelopeExceedsCap {
                    limit_bytes: 65_536,
                },
            )),
            ServerFailure::Parse(IngestParseError::Envelope(EnvelopeError::SchemaInvalid {
                field: "occurrence_id",
                reason: "re-derivation mismatch",
            })),
            ServerFailure::Authorization(AuthRejection::Unlinked),
            ServerFailure::Authorization(AuthRejection::Revoked),
            ServerFailure::Authorization(AuthRejection::ProofRejected),
            ServerFailure::Authorization(AuthRejection::Forbidden),
            ServerFailure::IntegrityConflict,
            ServerFailure::PayloadLimit(PayloadLimit::SplittableBytes {
                actual_bytes: 1024,
                limit_bytes: 256,
            }),
            ServerFailure::PayloadLimit(PayloadLimit::SplittableRatio { max_ratio: 100 }),
            ServerFailure::PayloadLimit(PayloadLimit::UnsplittableRecord {
                actual_bytes: 1024,
                limit_bytes: 256,
            }),
            ServerFailure::RateLimited,
            ServerFailure::DeadlineElapsed,
            ServerFailure::TooEarly,
            ServerFailure::RegistryUnavailable,
            ServerFailure::StorageFailure,
            ServerFailure::UpstreamTimeout,
            ServerFailure::PartialCommit,
            ServerFailure::Internal,
            ServerFailure::Unavailable,
        ]
    }

    /// The `(code, status, retryable)` the error-codes conventions pin per
    /// failure — the class table of `docs/notes/error-codes.md` Section 2,
    /// restated here as the wire contract each body must carry.
    fn expected_wire(failure: &ServerFailure) -> (&'static str, u16, bool) {
        match failure {
            ServerFailure::Parse(parse) => match parse {
                IngestParseError::Framing(TwoPartError::EnvelopeNotFirst) => {
                    ("envelope.media_type_unsupported", 415, false)
                }
                IngestParseError::Framing(TwoPartError::EnvelopeExceedsCap { .. }) => {
                    ("envelope.size_exceeded", 400, false)
                }
                IngestParseError::Framing(_) => ("request.framing_invalid", 400, false),
                IngestParseError::Envelope(_) => ("envelope.schema_invalid", 400, false),
            },
            ServerFailure::Authorization(rejection) => match rejection {
                AuthRejection::Unlinked => ("auth.unlinked", 401, false),
                AuthRejection::Revoked => ("auth.revoked", 401, false),
                AuthRejection::ProofRejected => ("auth.authorization_rejected", 401, false),
                AuthRejection::Forbidden => ("auth.forbidden", 403, false),
            },
            ServerFailure::IntegrityConflict => ("storage.integrity_conflict", 409, false),
            ServerFailure::PayloadLimit(PayloadLimit::SplittableRatio { .. }) => {
                ("request.expansion_ratio_exceeded", 413, false)
            }
            ServerFailure::PayloadLimit(PayloadLimit::UnsplittableRecord { .. }) => {
                ("request.record_too_large", 413, false)
            }
            ServerFailure::PayloadLimit(PayloadLimit::SplittableBytes { .. }) => {
                ("request.payload_too_large", 413, false)
            }
            ServerFailure::RateLimited => ("request.rate_limited", 429, true),
            ServerFailure::DeadlineElapsed => ("request.deadline_exceeded", 408, true),
            ServerFailure::TooEarly => ("request.too_early", 425, true),
            ServerFailure::RegistryUnavailable | ServerFailure::Unavailable => {
                ("server.unavailable", 503, true)
            }
            ServerFailure::StorageFailure => ("server.storage_failure", 502, true),
            ServerFailure::UpstreamTimeout => ("server.upstream_timeout", 504, true),
            ServerFailure::PartialCommit => ("server.partial_commit", 503, true),
            ServerFailure::Internal => ("server.internal", 500, true),
        }
    }

    fn request_id() -> RequestId {
        RequestId::parse(TEST_REQUEST_ID).expect("test request id parses")
    }

    fn correlation_id() -> RequestId {
        RequestId::parse(TEST_CORRELATION_ID).expect("test correlation id parses")
    }

    #[test]
    fn the_embedded_registry_parses_with_every_mapped_code_registered() {
        let parsed = registry();
        for failure in every_failure() {
            let code = failure.code();
            let token = code.as_str();
            let (status, retryable) = parsed
                .resolve(token)
                .unwrap_or_else(|| panic!("{token} resolves to status and class"));
            let (expected_code, expected_status, expected_retryable) = expected_wire(&failure);
            assert_eq!(token, expected_code, "{token} is the pinned code");
            assert_eq!(status, expected_status, "{token} status is pinned");
            assert_eq!(retryable, expected_retryable, "{token} retryable is pinned");
            let template = parsed
                .template(token)
                .unwrap_or_else(|| panic!("{token} has a template"));
            assert!(
                template.len() <= 160,
                "{token} template is within the ERR-011 pre-render bound"
            );
            assert!(
                !template.contains('\\'),
                "{token} template is a plain single-line basic string"
            );
        }
    }

    #[test]
    fn every_path_returns_the_exact_contract() {
        for failure in every_failure() {
            let response =
                ErrorResponse::with_correlation(failure, Some(request_id()), correlation_id());
            let (expected_code, expected_status, expected_retryable) = expected_wire(&failure);
            assert_eq!(response.status(), expected_status, "{failure:?} status");
            assert_eq!(response.code(), expected_code, "{failure:?} code");
            assert_eq!(
                response.retryable(),
                expected_retryable,
                "{failure:?} retryable"
            );
            assert_eq!(response.request_id(), Some(&request_id()));
            assert_eq!(response.correlation_id(), &correlation_id());

            let body = response.canonical_bytes();
            let value = json::parse(&body).expect("every body is canonical-domain JSON");
            let json::Value::Object(ref object) = value else {
                panic!("every body is an object");
            };
            let fields: Vec<&str> = object.iter().map(|(name, _)| name).collect();
            assert_eq!(
                fields,
                [
                    "code",
                    "correlation_id",
                    "message",
                    "request_id",
                    "retryable",
                    "schema"
                ],
                "{failure:?}: exactly the six schema members, canonically sorted"
            );
            let text = String::from_utf8(body).expect("body is text");
            assert!(
                text.contains(&format!("\"code\":\"{expected_code}\"")),
                "{failure:?}: body carries the registry code: {text}"
            );
            assert!(
                text.contains(&format!("\"retryable\":{expected_retryable}")),
                "{failure:?}: body carries the class retryable"
            );
            assert!(
                text.contains(&format!("\"schema\":\"{ERROR_NAMESPACE}\"")),
                "{failure:?}: body carries the versioned namespace"
            );
            assert!(
                text.contains(&format!("\"request_id\":\"{TEST_REQUEST_ID}\"")),
                "{failure:?}: body carries the passed request id"
            );
            assert!(
                text.contains(&format!("\"correlation_id\":\"{TEST_CORRELATION_ID}\"")),
                "{failure:?}: body carries the correlation id"
            );
        }
    }

    #[test]
    fn a_failure_without_an_envelope_renders_null_request_id() {
        for failure in every_failure() {
            let response = ErrorResponse::with_correlation(failure, None, correlation_id());
            let text = String::from_utf8(response.canonical_bytes()).expect("body is text");
            assert!(
                text.contains("\"request_id\":null"),
                "{failure:?}: no envelope means the schema's null, not an omission"
            );
            assert!(
                text.contains(&format!("\"correlation_id\":\"{TEST_CORRELATION_ID}\"")),
                "{failure:?}: correlation id is present even beside a null request id"
            );
            assert!(response.request_id().is_none());
        }
    }

    #[test]
    fn every_rendered_message_is_bounded_and_content_free() {
        for failure in every_failure() {
            let message = failure.rendered_message();
            let text = message.as_str();
            assert!(
                text.chars().count() <= 200,
                "{failure:?}: 200-character bound"
            );
            assert!(
                text.bytes()
                    .all(|b| (0x20..=0x7a).contains(&b) || b == 0x7c || b == 0x7e),
                "{failure:?}: printable ASCII, no braces, one line: {text}"
            );
        }
    }

    #[test]
    fn integer_placeholders_render_as_plain_decimal_and_degrade_outside_the_frozen_grammar() {
        let in_grammar = ServerFailure::PayloadLimit(PayloadLimit::SplittableBytes {
            actual_bytes: 2_u64.pow(53),
            limit_bytes: 256,
        });
        let text = in_grammar.rendered_message().as_str().to_owned();
        assert!(
            text.contains("9007199254740992"),
            "an in-grammar count renders as plain decimal: {text}"
        );
        // At and above 2^63 the value is outside the frozen grammar: the
        // deterministic bracket degradation stands in — never the raw
        // number, and never anything request-derived.
        let degraded = ServerFailure::PayloadLimit(PayloadLimit::SplittableBytes {
            actual_bytes: u64::MAX,
            limit_bytes: 256,
        });
        let text = degraded.rendered_message().as_str().to_owned();
        assert!(
            text.contains("[actual_bytes]"),
            "an out-of-grammar count degrades to the bracketed name: {text}"
        );
        assert!(
            !text.contains("18446744073709551615"),
            "the raw out-of-grammar value never reaches the wire: {text}"
        );
        let ratio = ServerFailure::PayloadLimit(PayloadLimit::SplittableRatio {
            max_ratio: u64::MAX,
        });
        assert!(
            ratio.rendered_message().as_str().contains("[max_ratio]"),
            "the ratio placeholder degrades under its own name"
        );
    }

    #[test]
    fn the_body_is_byte_deterministic_for_fixed_identifiers() {
        let failure = ServerFailure::PartialCommit;
        let first = ErrorResponse::with_correlation(failure, Some(request_id()), correlation_id());
        let second = ErrorResponse::with_correlation(failure, Some(request_id()), correlation_id());
        assert_eq!(
            first.canonical_bytes(),
            second.canonical_bytes(),
            "same failure and identifiers, same bytes"
        );
        // The registry's pinned template, rendered verbatim on a
        // fixed-message path, in canonical field order.
        assert_eq!(
            String::from_utf8(first.canonical_bytes()).expect("body is text"),
            format!(
                "{{\"code\":\"server.partial_commit\",\"correlation_id\":\"\
                 {TEST_CORRELATION_ID}\",\"message\":\"The request committed partially and \
                 no receipt was issued; retry the identical envelope to repair it.\",\
                 \"request_id\":\"{TEST_REQUEST_ID}\",\"retryable\":true,\
                 \"schema\":\"archivist.error/v1\"}}"
            )
        );
    }

    #[test]
    fn parse_paths_render_the_corpus_pinned_envelope_rendering() {
        let failure =
            ServerFailure::Parse(IngestParseError::Envelope(EnvelopeError::SchemaInvalid {
                field: "occurrence_id",
                reason: "re-derivation mismatch",
            }));
        assert_eq!(
            failure.rendered_message().as_str(),
            "The envelope fails schema validation at field occurrence_id.",
            "the parser strand's rendering flows through unchanged"
        );
        let framing = ServerFailure::Parse(IngestParseError::Framing(TwoPartError::Framing(
            FramingError::MalformedDelimiter,
        )));
        assert_eq!(
            framing.rendered_message().as_str(),
            "The request is not the pinned two-part multipart/related framing; \
             send the identical bytes the signature covered.",
        );
    }

    #[test]
    fn every_failure_has_a_registered_code_token() {
        for failure in every_failure() {
            let code = failure.code();
            assert!(
                registry().codes.contains_key(code.as_str()),
                "{} is registered in the embedded registry",
                code.as_str()
            );
        }
    }

    #[test]
    fn the_registry_reader_rejects_drift() {
        // Not a full TOML parser and not trying to be: the bytes it reads
        // are the checker-gated registry, and drift fails closed.
        assert!(parse_registry("").is_err(), "an empty registry is refused");
        assert!(
            parse_registry("schema = \"archivist.error-registry/v2\"\n").is_err(),
            "an unknown registry schema is refused"
        );
        assert!(
            parse_registry(concat!(
                "schema = \"archivist.error-registry/v1\"\n",
                "[codes.\"x.y\"]\n",
                "class = \"no_such_class\"\n",
                "http = 400\n",
                "message = \"x\"\n",
            ))
            .is_err(),
            "a code naming an unregistered class is refused"
        );
        assert!(
            parse_registry(concat!(
                "schema = \"archivist.error-registry/v1\"\n",
                "[classes.thing]\n",
                "[codes.\"x.y\"]\n",
                "http = 400\n",
                "message = \"x\"\n",
            ))
            .is_err(),
            "an incomplete class entry is refused"
        );
    }

    #[test]
    fn responses_carry_the_correlation_headers_and_media_type() {
        let response = ErrorResponse::with_correlation(
            ServerFailure::RateLimited,
            Some(request_id()),
            correlation_id(),
        )
        .into_response();
        assert_eq!(response.status(), 429);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(CONTENT_TYPE)
                .map(|value| value.to_str().expect("media type is text")),
            Some(ERROR_MEDIA_TYPE)
        );
        assert_eq!(
            headers
                .get(&CORRELATION_ID_HEADER)
                .map(|value| value.to_str().expect("correlation id is text")),
            Some(TEST_CORRELATION_ID)
        );
        assert_eq!(
            headers
                .get(&REQUEST_ID_HEADER)
                .map(|value| value.to_str().expect("request id is text")),
            Some(TEST_REQUEST_ID)
        );

        // Without a request id the header is absent — never an empty
        // value (the schema: "the body request_id when known").
        let without =
            ErrorResponse::with_correlation(ServerFailure::RateLimited, None, correlation_id())
                .into_response();
        assert!(without.headers().get(&REQUEST_ID_HEADER).is_none());
        assert_eq!(
            without
                .headers()
                .get(&CORRELATION_ID_HEADER)
                .map(|value| value.to_str().expect("correlation id is text")),
            Some(TEST_CORRELATION_ID)
        );
    }

    #[test]
    fn minted_correlations_are_fresh_per_response() {
        let first = ErrorResponse::for_failure(ServerFailure::StorageFailure);
        let second = ErrorResponse::for_failure(ServerFailure::StorageFailure);
        assert_ne!(
            first.correlation_id(),
            second.correlation_id(),
            "every response mints its own attempt correlation id"
        );
    }

    #[test]
    fn registry_lookup_refuses_unregistered_codes() {
        assert!(registry().resolve("not.a_code_at_all").is_none());
        assert!(registry().template("not.a_code_at_all").is_none());
        // Client-only codes are registered as data (their template exists)
        // but declare no HTTP status, so they can never resolve to a
        // response — the server surface cannot accidentally serve one.
        assert!(registry().template("cli.usage_error").is_some());
        assert!(registry().resolve("cli.usage_error").is_none());
    }
}
