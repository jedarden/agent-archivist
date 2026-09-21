// SPDX-License-Identifier: Apache-2.0

//! Route registration for the ingestion data plane: the four routes of
//! plan Phase 4, mounted on one router over the shared
//! [`ServerState`].
//!
//! | Route | Method | This surface's behavior |
//! |---|---|---|
//! | `/health/live` | GET | Process-only liveness: answered from the process, never from storage or configuration. |
//! | `/health/ready` | GET | The readiness snapshot: valid configuration plus fresh trust evidence for every configured tenant. |
//! | `/metrics` | GET | The registered server families in Prometheus text exposition. |
//! | `/v1/ingest` | POST | Admission-guarded, then bounded-parse: the request deadline bounds the whole attempt, the process-wide in-flight cap admits before anything request-derived is read, and an overloaded replica refuses with the retryable `request.rate_limited` body; admitted attempts validate the pinned framing and parse the envelope, every request-shape violation rendering its registry code through [`crate::error`] (`request.framing_invalid`/`envelope.*` 400s, the `envelope.media_type_unsupported` 415, and the payload-limit 413s as the pipeline grows their triggers), and a well-formed attempt is still refused with the stable `server.unavailable` body until the commit slice lands. |
//!
//! Fail-closed is the operative rule for every body: responses render
//! canonical bytes through `archivist-protocol`'s RFC 8785 writer, carry
//! counts and closed-vocabulary tokens only, and never echo request
//! content, identifiers, or paths (SEC-004, SEC-005). Error bodies are
//! the `archivist.error/v1` shape pinned by `schemas/v1/ingest-error.json`
//! — exactly six members, `request_id` carrying the parsed envelope's
//! identifier when one yielded (ERR-025) and null before that (ERR-027),
//! and a fresh per-attempt `correlation_id` always present (ERR-026) —
//! serialized by [`crate::error`] from the registry's pinned code,
//! retryability, and message.

use std::io;
use std::sync::Arc;

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::RequestId;
use archivist_storage::control::ControlReadStore;
use archivist_storage::raw_write::RawWriteStore;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;
use axum::routing::{get, post};
use tokio::sync::mpsc;

use crate::error::{ErrorResponse, ServerFailure};
use crate::guard::{DeadlineElapsed, within_deadline};
use crate::metrics::IngestOutcome;
use crate::parse::framing::{ByteSource, RequestFraming};
use crate::parse::ingest::{IngestParseError, parse_ingest_with_cap};
use crate::parse::parts::TwoPartError;
use crate::state::{ReadinessSnapshot, ServerState};

/// Media type of the content-free health bodies.
pub const HEALTH_MEDIA_TYPE: &str = "application/json";

/// Media type of the Prometheus text exposition served at `/metrics`.
pub const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The liveness body: process-only by design. A const so the handler
/// cannot grow fields it does not have; a unit test pins it against the
/// canonical writer.
const LIVE_BODY: &str = "{\"live\":true}";

/// Mount the four routes over shared state.
///
/// The state must be shareable across the connection tasks, which is
/// what the `Send + Sync` bounds state: the stores' futures are already
/// `Send` by their trait contracts.
pub fn router<W, C>(state: Arc<ServerState<W, C>>) -> Router
where
    W: RawWriteStore + Send + Sync + 'static,
    C: ControlReadStore + Send + Sync + 'static,
{
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready::<W, C>))
        .route("/metrics", get(metrics::<W, C>))
        .route("/v1/ingest", post(ingest::<W, C>))
        .with_state(state)
}

/// `GET /health/live` — process-only liveness.
///
/// The handler consults nothing but its own execution: no storage call,
/// no configuration read, no lock. A replica that can answer here is
/// alive as a process, whatever else is wrong — readiness is `/health/
/// ready`'s contract, and merging the two would let a storage outage
/// kill healthy pods (plan Phase 4: "Make liveness process-only").
async fn live() -> Response {
    response(
        StatusCode::OK,
        HEALTH_MEDIA_TYPE,
        LIVE_BODY.as_bytes().to_vec(),
    )
}

/// `GET /health/ready` — the readiness snapshot.
async fn ready<W, C>(State(state): State<Arc<ServerState<W, C>>>) -> Response {
    let snapshot = state.readiness();
    let status = if snapshot.ready {
        StatusCode::OK
    } else {
        // SERVICE_UNAVAILABLE: not ready is a transient replica
        // condition the orchestrator retries; the body carries the
        // closed reason class, never a tenant identifier.
        StatusCode::SERVICE_UNAVAILABLE
    };
    response(status, HEALTH_MEDIA_TYPE, ready_body(snapshot))
}

/// `GET /metrics` — the registered families in text exposition.
async fn metrics<W, C>(State(state): State<Arc<ServerState<W, C>>>) -> Response {
    let text = state.metrics().exposition(state.newest_trust_age_seconds());
    response(StatusCode::OK, METRICS_MEDIA_TYPE, text.into_bytes())
}

/// `POST /v1/ingest` — admission-guarded, then bounded-parse.
///
/// The guards run in the plan's order, ahead of everything
/// request-derived: the configured deadline bounds the whole
/// attempt (admission included), and the process-wide in-flight cap
/// admits or refuses before a single request byte is read or a
/// payload-scale buffer allocated — an overloaded replica's refusal is
/// content-free while the request's bytes are still sitting unread in
/// the socket. No guard refusal is ever counted as ingest work: both
/// land in the `throttled` outcome, carrying no client, tenant, or
/// request identifier.
///
/// An admitted attempt then validates the pinned two-part framing from
/// the `Content-Type` header alone and parses part one under the
/// configured envelope cap, the body streaming into the parse through a
/// bounded channel so no attempt ever buffers payload scale (VAL-008).
/// Every request-shape violation — framing, part-one media type,
/// envelope malformed/version/schema/size — renders its registry code
/// and pinned message through [`failure_response`] with the envelope's
/// request identifier carried once one has parsed (ERR-025, ERR-027).
/// A well-formed attempt is still refused with the stable retryable
/// body: no commit pipeline exists yet, so nothing can be committed and
/// no receipt can be issued, and saying so through `server.unavailable`
/// is the honest response (plan Section 7.8: server-failure class,
/// retryable, no receipt). The commit slice replaces that refusal —
/// holding the admission across its streaming attempt — behind the same
/// route.
async fn ingest<W, C>(State(state): State<Arc<ServerState<W, C>>>, request: Request) -> Response {
    let attempt = within_deadline(state.config().request_deadline(), async {
        match state.gate().try_admit_process() {
            Err(_rejection) => (
                IngestOutcome::Throttled,
                ErrorResponse::for_failure(ServerFailure::RateLimited).into_response(),
            ),
            // The admission is held across the whole parse attempt —
            // that is the concurrency bound doing its job — and released
            // when the outcome is rendered.
            Ok(admission) => {
                let (outcome, response) = attempt_parse(&state, request).await;
                drop(admission);
                (outcome, response)
            }
        }
    })
    .await;
    match attempt {
        // The deadline is a real bound on the attempt, so its elapse is
        // the deadline guard's refusal — throttle class, retryable.
        Err(DeadlineElapsed) => {
            state.metrics().record_ingest(IngestOutcome::Throttled);
            ErrorResponse::for_failure(ServerFailure::DeadlineElapsed).into_response()
        }
        Ok((outcome, response)) => {
            state.metrics().record_ingest(outcome);
            response
        }
    }
}

/// The one rendering site for every Section 7.8 failure this route maps:
/// [`crate::error`] builds the exact six-member canonical body at the
/// registry's status with the class retryable, the error media type, and
/// the correlation headers; the parsed envelope's request identifier
/// travels when the attempt holds one and the schema's null renders
/// before that.
fn failure_response(failure: ServerFailure, request_id: Option<RequestId>) -> Response {
    ErrorResponse::for_failure_with(failure, request_id).into_response()
}

/// The parse phase of an admitted attempt: framing from the header, then
/// the bounded two-part parse over the streamed body. Every outcome is a
/// rendered response paired with the metric outcome the attempt earned:
/// request-shape violations are rejections (the `request_invalid` and
/// `payload_limit_*` classes committed nothing and admitted nothing),
/// while a well-formed attempt under the fail-closed bootstrap and a
/// parse-phase fault are failures.
async fn attempt_parse<W, C>(
    state: &ServerState<W, C>,
    request: Request,
) -> (IngestOutcome, Response) {
    // The framing is validated from the header alone, before any body
    // byte is read: a wrong Content-Type never opens the body.
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let framing = match RequestFraming::validate_content_type(content_type) {
        Ok(framing) => framing,
        Err(error) => {
            return (
                IngestOutcome::Rejected,
                failure_response(
                    ServerFailure::Parse(IngestParseError::Framing(TwoPartError::from(error))),
                    None,
                ),
            );
        }
    };

    // The body streams into the blocking parse through a bounded
    // channel: the async feeder task never buffers beyond one chunk, the
    // channel holds a fixed handful, and the parse side consumes through
    // the framing tokenizer's small window — buffered request bytes stay
    // bounded for any body size (VAL-008). When the parse outcome is
    // known the stream is dropped, the feeder's sends fail, and the
    // (possibly huge) unread tail of the body is simply abandoned; the
    // connection layer owns that path.
    let (sender, receiver) = mpsc::channel(PARSE_BRIDGE_CHUNKS);
    let mut body = request.into_body();
    tokio::spawn(async move {
        while let Some(frame) = http_body_util::BodyExt::frame(&mut body).await {
            let Ok(frame) = frame else {
                break; // a failed stream is a truncated body to the parse
            };
            let Some(data) = frame.data_ref() else {
                continue;
            };
            if sender.send(data.to_vec()).await.is_err() {
                break; // the parse finished; the unread tail is abandoned
            }
        }
    });

    let envelope_cap = state.config().envelope_max_bytes();
    let parse = tokio::task::spawn_blocking(move || {
        parse_ingest_with_cap(
            &framing,
            BodyChannel {
                receiver,
                chunk: Vec::new(),
                cursor: 0,
            },
            envelope_cap,
        )
    });
    match parse.await {
        // A panicked parse committed nothing and is a defect, not a wire
        // condition: the internal-failure class, never a 200-shaped lie.
        Err(_join) => (
            IngestOutcome::Failed,
            failure_response(ServerFailure::Internal, None),
        ),
        Ok(Err(rejection)) => (
            IngestOutcome::Rejected,
            failure_response(ServerFailure::Parse(rejection.error), rejection.request_id),
        ),
        // Well-formed: the commit pipeline lands later. The parsed
        // envelope's identifier is known, so the refusal carries it
        // (ERR-025) — a client correlating its attempt sees the server
        // that read it.
        Ok(Ok((envelope, _stream))) => (
            IngestOutcome::Failed,
            failure_response(ServerFailure::Unavailable, Some(envelope.request_id)),
        ),
    }
}

/// Buffering budget of the async-to-blocking body bridge: a fixed
/// handful of fed chunks, each at most one HTTP frame, so the attempt's
/// buffered request bytes stay bounded for any body size (VAL-008).
const PARSE_BRIDGE_CHUNKS: usize = 4;

/// The blocking side of the body bridge: a [`ByteSource`] fed by the
/// async feeder task through the bounded channel. [`Self::pull`] blocks
/// on the channel, which is legal only off the async runtime — exactly
/// where the parse runs, inside [`tokio::task::spawn_blocking`].
struct BodyChannel {
    /// The fed chunks; `None`-equivalent (all senders dropped) is the
    /// body's end.
    receiver: mpsc::Receiver<Vec<u8>>,
    /// The chunk currently being drained.
    chunk: Vec<u8>,
    /// The read offset into [`Self::chunk`].
    cursor: usize,
}

impl ByteSource for BodyChannel {
    fn pull(&mut self, window: &mut [u8]) -> Result<usize, io::ErrorKind> {
        loop {
            if self.cursor < self.chunk.len() {
                let buffered = &self.chunk[self.cursor..];
                let copied = buffered.len().min(window.len());
                window[..copied].copy_from_slice(&buffered[..copied]);
                self.cursor += copied;
                return Ok(copied);
            }
            match self.receiver.blocking_recv() {
                // An empty chunk carries nothing: the next iteration
                // drains the next one.
                Some(chunk) if chunk.is_empty() => {}
                Some(chunk) => {
                    self.chunk = chunk;
                    self.cursor = 0;
                }
                // The feeders are gone: the body ended (or the parse
                // outcome ended the attempt). Either way the tokenizer
                // reads a closed stream.
                None => return Ok(0),
            }
        }
    }
}

fn response(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(axum::body::Body::from(body))
        .expect("static status and content type are valid")
}

/// The canonical readiness body: a boolean, two counts, and — when not
/// ready — one closed reason token. No tenant identifier, no path, no
/// clock reading (SEC-004).
fn ready_body(snapshot: ReadinessSnapshot) -> Vec<u8> {
    let mut object = Object::new();
    let _ = object.insert("ready", Value::Bool(snapshot.ready));
    if let Some(reason) = snapshot.reason {
        let _ = object.insert("reason", Value::Text(reason.token().to_owned()));
    }
    let _ = object.insert(
        "tenants_configured",
        Value::Int(i64::try_from(snapshot.tenants_configured).expect("tenant count fits i64")),
    );
    let _ = object.insert(
        "tenants_ready",
        Value::Int(i64::try_from(snapshot.tenants_ready).expect("tenant count fits i64")),
    );
    Value::Object(object).canonical_bytes()
}

#[cfg(test)]
mod tests {
    use super::{HEALTH_MEDIA_TYPE, LIVE_BODY, METRICS_MEDIA_TYPE, failure_response, ready_body};
    use crate::error::{
        CORRELATION_ID_HEADER, ERROR_MEDIA_TYPE, PayloadLimit, REQUEST_ID_HEADER, ServerFailure,
    };
    use crate::guard::ProcessAdmission;
    use crate::parse::parts::ENVELOPE_PART_MEDIA_TYPE;
    use crate::state::{NotReadyReason, ReadinessSnapshot, ServerState};
    use crate::trust::{TenantTrustRoot, TrustConfig};
    use archivist_protocol::json;
    use archivist_protocol::object_key::BlobObjectKey;
    use archivist_protocol::vocabulary::{ClientId, KeyId, RequestId, StorageOutcome, TenantId};
    use archivist_storage::capability::StoreCapabilities;
    use archivist_storage::control::{AuthorizationEpoch, ControlReadStore, ControlRecord};
    use archivist_storage::error::{StorageError, StorageErrorKind};
    use archivist_storage::ingest::IngestStorage;
    use archivist_storage::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };
    use std::fs;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// The boundary the conformance corpus pins for the valid-direct
    /// baseline scenario.
    const BOUNDARY: &str = "archivist-conformance-01";
    /// Part two's media type under the identity transport the v1 vectors pin.
    const IDENTITY_MEDIA_TYPE: &str = "application/octet-stream";
    /// A fixed canonical request identifier the direct mapping tests
    /// carry; grammar-clean so `RequestId::parse` accepts it.
    const REQUEST_ID: &str = "1a07b201-7000-7000-8000-000000000001";

    /// The parsed [`REQUEST_ID`].
    fn request_id_fixture() -> RequestId {
        RequestId::parse(REQUEST_ID).expect("the fixture identifier is canonical")
    }

    /// Assert an error body is the exact six-member `archivist.error/v1`
    /// contract for `expected_code`, with the class retryable, the
    /// expected `request_id` (null or a carried canonical identifier),
    /// and a correlation id that parses as a canonical `UUIDv7`. Returns
    /// the body text for the caller's extra assertions.
    fn assert_pinned_error_shape(
        body: &[u8],
        expected_code: &str,
        expected_retryable: bool,
        expected_request_id: Option<&str>,
    ) -> String {
        let value = json::parse(body).expect("every error body is canonical-domain JSON");
        let json::Value::Object(ref object) = value else {
            panic!("every error body is an object");
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
            "{expected_code}: exactly the six schema members, canonically sorted"
        );
        let text = String::from_utf8(body.to_vec()).expect("error body is text");
        assert!(
            text.contains(&format!("\"code\":\"{expected_code}\"")),
            "{expected_code}: body carries the registry code: {text}"
        );
        assert!(
            text.contains(&format!("\"retryable\":{expected_retryable}")),
            "{expected_code}: body carries the class retryable"
        );
        assert!(
            text.contains("\"schema\":\"archivist.error/v1\""),
            "{expected_code}: body carries the versioned namespace"
        );
        match expected_request_id {
            None => assert!(
                text.contains("\"request_id\":null"),
                "{expected_code}: no envelope identifier, so the schema's null: {text}"
            ),
            Some(request_id) => {
                let json::Value::Text(carried) = object
                    .iter()
                    .find_map(|(name, value)| (name.eq("request_id")).then_some(value))
                    .expect("request_id is one of the six members")
                else {
                    panic!("{expected_code}: request_id is text");
                };
                assert_eq!(
                    carried, request_id,
                    "{expected_code}: the envelope's identifier travels verbatim"
                );
                RequestId::parse(carried).expect("a carried request id is itself canonical");
                assert!(
                    text.contains(&format!("\"request_id\":\"{request_id}\"")),
                    "{expected_code}: the carried identifier is in the body: {text}"
                );
            }
        }
        let correlation_text = object
            .iter()
            .find_map(|(name, value)| (name.eq("correlation_id")).then_some(value))
            .expect("correlation_id is one of the six members");
        let json::Value::Text(correlation_text) = correlation_text else {
            panic!("correlation_id is text");
        };
        RequestId::parse(correlation_text)
            .expect("every minted correlation id is a canonical UUIDv7");
        text
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
        let json::Value::Object(manifest_object) = &manifest else {
            panic!("manifest.json is an object");
        };
        let Some(json::Value::Array(scenarios)) = manifest_object.get("scenarios") else {
            panic!("manifest.json scenarios is an array");
        };
        let Some(scenario) = scenarios.iter().find(|scenario| {
            matches!(
                scenario,
                json::Value::Object(object)
                    if object.get("id") == Some(&json::Value::Text(id.to_owned()))
            )
        }) else {
            panic!("{id} is in the corpus manifest");
        };
        let json::Value::Object(scenario) = scenario else {
            panic!("{id} is an object");
        };
        let Some(json::Value::Object(files)) = scenario.get("files") else {
            panic!("{id}: files");
        };
        let Some(json::Value::Text(relative)) = files.get(name) else {
            panic!("{id}: files.{name} is a path");
        };
        fs::read(dir.join(relative)).unwrap_or_else(|error| panic!("{id}: {relative}: {error}"))
    }

    /// One scenario's pinned Content-Type header, as transmitted.
    fn corpus_content_type(id: &str) -> String {
        let attempt_bytes = corpus_file(id, "attempt");
        let attempt = json::parse(&attempt_bytes).expect("attempt parses");
        let json::Value::Object(object) = &attempt else {
            panic!("{id}: attempt.json is an object");
        };
        match object.get("content_type") {
            Some(json::Value::Text(text)) => text.clone(),
            other => panic!("{id}: attempt.json content_type is text, found {other:?}"),
        }
    }

    /// One scenario's pinned error message, from its `error.json`.
    fn corpus_error_message(id: &str) -> String {
        let bytes = corpus_file(id, "error");
        let error = json::parse(&bytes).unwrap_or_else(|error| panic!("{id}: {error}"));
        let json::Value::Object(object) = &error else {
            panic!("{id}: error.json is an object");
        };
        match object.get("message") {
            Some(json::Value::Text(message)) => message.clone(),
            other => panic!("{id}: error.json message is text, found {other:?}"),
        }
    }

    /// One scenario's pinned request identifier, from its envelope
    /// fixture.
    fn corpus_request_id(id: &str) -> String {
        let bytes = corpus_file(id, "envelope");
        let envelope = json::parse(&bytes).expect("the envelope fixture parses");
        let json::Value::Object(object) = &envelope else {
            panic!("{id}: the envelope fixture is an object");
        };
        match object.get("request_id") {
            Some(json::Value::Text(text)) => text.clone(),
            other => panic!("{id}: request_id is text, found {other:?}"),
        }
    }

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

    /// A full raw POST of `body` under `content_type`, the request the
    /// route tests drive — built as bytes, so corpus bodies that carry
    /// non-UTF-8 payload bytes transmit verbatim.
    fn ingest_request(content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut request = format!(
            "POST /v1/ingest HTTP/1.1\r\nHost: test\r\n\
             Content-Type: {content_type}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        request
    }

    fn ready_snapshot(ready: bool, up: usize, total: usize) -> ReadinessSnapshot {
        ReadinessSnapshot {
            ready,
            tenants_ready: up,
            tenants_configured: total,
            reason: if ready {
                None
            } else {
                Some(NotReadyReason::TrustEvidenceStale)
            },
        }
    }

    #[test]
    fn the_live_body_is_canonical() {
        // Parse-and-rewrite proves the literal is exactly what the
        // canonical writer produces for the same object.
        let value = json::parse(LIVE_BODY.as_bytes()).unwrap();
        assert_eq!(value.canonical_bytes(), LIVE_BODY.as_bytes());
        assert_eq!(LIVE_BODY, "{\"live\":true}");
    }

    #[test]
    fn the_ready_body_carries_counts_and_one_closed_reason() {
        let up = String::from_utf8(ready_body(ready_snapshot(true, 2, 2))).unwrap();
        assert_eq!(
            up,
            "{\"ready\":true,\"tenants_configured\":2,\"tenants_ready\":2}"
        );
        let down = String::from_utf8(ready_body(ready_snapshot(false, 1, 2))).unwrap();
        assert_eq!(
            down,
            "{\"ready\":false,\"reason\":\"trust_evidence_stale\",\"tenants_configured\":2,\
             \"tenants_ready\":1}"
        );
        // No reason member exists when ready — the closed body has no
        // empty-reason convention to misread.
        assert!(!up.contains("reason"));
    }

    #[test]
    fn the_fail_closed_refusal_carries_the_registry_pinned_message() {
        // The full wire shape is pinned module-for-module in
        // `crate::error`'s own tests against a fixed correlation id; here
        // the fail-closed refusal's exact template and class are what the
        // route pins.
        let refusal =
            crate::error::ErrorResponse::for_failure(crate::error::ServerFailure::Unavailable);
        assert_eq!(refusal.code(), "server.unavailable");
        assert!(refusal.retryable());
        assert_eq!(refusal.status(), 503);
        assert_eq!(
            refusal.message(),
            "The service is temporarily unable to handle the request; \
             retry the identical envelope."
        );
    }

    // ------------------------------------------------------------------
    // Router-level tests: each registered route over a real socket. The
    // stores are silent trait objects — no handler on this surface calls
    // them, so every method reports the closed unavailable class; they
    // exist to prove the routes compose the real state shape.
    // ------------------------------------------------------------------

    const TEST_TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const TEST_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn unavailable<T>() -> Result<T, StorageError> {
        Err(StorageError::of_kind(StorageErrorKind::Unavailable))
    }

    #[derive(Clone, Copy, Debug)]
    struct SilentRawStore;

    impl RawWriteStore for SilentRawStore {
        fn capabilities(&self) -> StoreCapabilities {
            StoreCapabilities::unprobed()
        }

        async fn write_manifest(
            &self,
            _key: &ManifestKey,
            _bytes: &[u8],
        ) -> Result<StorageOutcome, StorageError> {
            unavailable()
        }

        async fn begin_multipart(
            &self,
            _blob: &BlobObjectKey,
        ) -> Result<MultipartUploadId, StorageError> {
            unavailable()
        }

        async fn write_part(
            &self,
            _upload: &MultipartUploadId,
            _part: PartNumber,
            _bytes: &[u8],
        ) -> Result<PartCommitment, StorageError> {
            unavailable()
        }

        async fn commit_multipart(
            &self,
            _upload: &MultipartUploadId,
            _parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            unavailable()
        }

        async fn abort_multipart(&self, _upload: &MultipartUploadId) -> Result<(), StorageError> {
            unavailable()
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct SilentControlStore;

    impl ControlReadStore for SilentControlStore {
        async fn read_linked_client(
            &self,
            _tenant: &TenantId,
            _client: &ClientId,
        ) -> Result<Option<ControlRecord>, StorageError> {
            unavailable()
        }

        async fn read_delegation(
            &self,
            _tenant: &TenantId,
            _relay: &ClientId,
            _origin: &ClientId,
        ) -> Result<Option<ControlRecord>, StorageError> {
            unavailable()
        }

        async fn read_revocation(
            &self,
            _tenant: &TenantId,
            _client: &ClientId,
            _epoch: AuthorizationEpoch,
        ) -> Result<Option<ControlRecord>, StorageError> {
            unavailable()
        }

        async fn read_rotation(
            &self,
            _tenant: &TenantId,
            _client: &ClientId,
            _epoch: AuthorizationEpoch,
        ) -> Result<Option<ControlRecord>, StorageError> {
            unavailable()
        }

        async fn read_receipt_key(
            &self,
            _tenant: &TenantId,
            _key: &KeyId,
        ) -> Result<Option<ControlRecord>, StorageError> {
            unavailable()
        }
    }

    fn test_state() -> Arc<ServerState<SilentRawStore, SilentControlStore>> {
        let config = crate::config::ServerConfig::builder()
            .listen_address("127.0.0.1:0")
            .build()
            .expect("test configuration validates");
        let trust = TrustConfig::from_roots(vec![
            TenantTrustRoot::new(TEST_TENANT, TEST_KEY).expect("test tenant root validates"),
        ])
        .expect("one-tenant anchor set validates");
        Arc::new(ServerState::new(
            config,
            trust,
            IngestStorage::compose(SilentRawStore, SilentControlStore),
        ))
    }

    /// Serve the real router on an ephemeral socket; the task detaches
    /// and dies with the test runtime.
    async fn serve(state: Arc<ServerState<SilentRawStore, SilentControlStore>>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let address = listener.local_addr().expect("test listener has an address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, super::router(state)).await;
        });
        // The listener accepts as soon as bind returned; yield so the
        // spawned task starts before the first request arrives.
        tokio::task::yield_now().await;
        address
    }

    struct Exchanged {
        status: u16,
        headers: Vec<(String, String)>,
        content_type: Option<String>,
        body: Vec<u8>,
    }

    impl Exchanged {
        /// The last value of a named response header, case-insensitively.
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .rev()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    /// One raw HTTP/1.1 exchange against the running router: the request
    /// goes out whole, and the answer is read to EOF (`Connection:
    /// close` makes the server close first — a client half-close here
    /// would kill the exchange instead of ending the request).
    async fn exchange(address: SocketAddr, request: &str) -> Exchanged {
        exchange_bytes(address, request.as_bytes()).await
    }

    /// [`exchange`] over raw bytes, for corpus bodies that carry
    /// non-UTF-8 payload bytes.
    async fn exchange_bytes(address: SocketAddr, request: &[u8]) -> Exchanged {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("test client connects");
        stream.write_all(request).await.expect("request writes");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("response reads");
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("response has a header block");
        let head = String::from_utf8(raw[..split].to_vec()).expect("headers are text");
        let status: u16 = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .expect("response has a status code");
        let mut headers = Vec::new();
        let mut content_type = None;
        for line in head.lines().skip(1) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim().to_owned();
            if name.eq_ignore_ascii_case("content-type") {
                content_type = Some(value.clone());
            }
            headers.push((name.to_ascii_lowercase(), value));
        }
        Exchanged {
            status,
            headers,
            content_type,
            body: raw[split + 4..].to_vec(),
        }
    }

    fn get_request(path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
    }

    #[tokio::test]
    async fn live_answers_while_the_replica_has_proven_nothing() {
        let address = serve(test_state()).await;
        let response = exchange(address, &get_request("/health/live")).await;
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type.as_deref(), Some(HEALTH_MEDIA_TYPE));
        assert_eq!(response.body, LIVE_BODY.as_bytes());
    }

    #[tokio::test]
    async fn ready_derives_strictly_from_the_readiness_ledger() {
        let state = test_state();
        let address = serve(Arc::clone(&state)).await;

        // A fresh replica has proven nothing: not ready, with the closed
        // reason class naming absent evidence — while liveness still
        // answers (the two probes never merge).
        let before = exchange(address, &get_request("/health/ready")).await;
        assert_eq!(before.status, 503);
        assert_eq!(
            String::from_utf8(before.body).expect("readiness body is text"),
            "{\"ready\":false,\"reason\":\"trust_evidence_absent\",\
             \"tenants_configured\":1,\"tenants_ready\":0}"
        );
        let live = exchange(address, &get_request("/health/live")).await;
        assert_eq!(live.status, 200);

        // Evidence recorded through the ledger is the only thing that
        // flips the answer.
        let tenant: TenantId = TEST_TENANT.parse().expect("test tenant parses");
        assert!(state.record_trust_evidence(&tenant));
        let after = exchange(address, &get_request("/health/ready")).await;
        assert_eq!(after.status, 200);
        assert_eq!(
            String::from_utf8(after.body).expect("readiness body is text"),
            "{\"ready\":true,\"tenants_configured\":1,\"tenants_ready\":1}"
        );
    }

    #[tokio::test]
    async fn metrics_exposes_the_registered_families_and_nothing_user_derived() {
        let address = serve(test_state()).await;
        let response = exchange(address, &get_request("/metrics")).await;
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type.as_deref(), Some(METRICS_MEDIA_TYPE));
        let text = String::from_utf8(response.body).expect("exposition is text");
        for family in [
            "# TYPE archivist_server_ingest_requests_total counter",
            "# TYPE archivist_server_ingest_inflight_requests gauge",
            "# TYPE archivist_server_shutdown gauge",
            "# TYPE archivist_server_trust_refresh_attempts_total counter",
        ] {
            assert!(text.contains(family), "missing family: {family}");
        }
        // No evidence exists on a fresh replica, so the age family is
        // omitted — an invented age would be a fabricated fact.
        assert!(!text.contains("trust_age"));
    }

    /// Assert the full wire contract of a rendered failure — the exact
    /// six-member body, the registered status, the error media type, and
    /// the correlation headers — over a live exchange.
    fn assert_exchange_contract(
        response: &Exchanged,
        expected_status: u16,
        expected_code: &str,
        expected_retryable: bool,
        expected_request_id: Option<&str>,
    ) -> String {
        assert_eq!(response.status, expected_status, "{expected_code}");
        assert_eq!(
            response.content_type.as_deref(),
            Some(ERROR_MEDIA_TYPE),
            "{expected_code}: the error media type"
        );
        let text = assert_pinned_error_shape(
            &response.body,
            expected_code,
            expected_retryable,
            expected_request_id,
        );
        // The correlation id travels as a header too, and matches the
        // body (ERR-026); the request id header travels exactly when the
        // body carries the identifier (ERR-025).
        let correlation = response
            .header(CORRELATION_ID_HEADER.as_str())
            .expect("correlation header present");
        assert!(
            text.contains(&format!("\"correlation_id\":\"{correlation}\"")),
            "{expected_code}: the header id matches the body"
        );
        match expected_request_id {
            None => assert!(
                response.header(REQUEST_ID_HEADER.as_str()).is_none(),
                "{expected_code}: no identifier, no request id header"
            ),
            Some(request_id) => assert_eq!(
                response.header(REQUEST_ID_HEADER.as_str()),
                Some(request_id),
                "{expected_code}: the request id header carries the identifier"
            ),
        }
        text
    }

    #[tokio::test]
    async fn a_request_without_the_pinned_content_type_is_a_framing_rejection() {
        let address = serve(test_state()).await;
        // Bytes with no Content-Type at all: the framing is validated
        // from the header alone, before any body byte is read, and the
        // canary riding the body can never reach the wire.
        let payload = b"envelope-zq9-marker-never-echoed";
        let request = format!(
            "POST /v1/ingest HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            payload.len()
        );
        let response = exchange(address, &request).await;
        let text = assert_exchange_contract(&response, 400, "request.framing_invalid", false, None);
        assert!(!text.contains("zq9-marker"));
        // The pinned framing message, verbatim from the registry.
        assert!(
            text.contains(
                "\"message\":\"The request is not the pinned two-part \
                 multipart/related framing; send the identical bytes the signature \
                 covered.\""
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_well_formed_attempt_is_refused_unavailable_until_the_commit_slice_lands() {
        let address = serve(test_state()).await;
        let id = "valid-direct-baseline";
        let body = corpus_file(id, "request_body");
        let response =
            exchange_bytes(address, &ingest_request(&corpus_content_type(id), &body)).await;
        // The envelope parsed, so the stable retryable refusal carries
        // its identifier (ERR-025) in body and header alike.
        let request_id = corpus_request_id(id);
        let text = assert_exchange_contract(
            &response,
            503,
            "server.unavailable",
            true,
            Some(&request_id),
        );
        assert!(response.header(REQUEST_ID_HEADER.as_str()).is_some());
        // The pinned unavailable message, verbatim from the registry.
        assert!(
            text.contains(
                "\"message\":\"The service is temporarily unable to handle the \
                 request; retry the identical envelope.\""
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_non_envelope_first_part_is_the_media_type_rejection() {
        let address = serve(test_state()).await;
        let body = framed_body(
            BOUNDARY,
            &[
                ("text/x-CANARY-MEDIA-TYPE-9q", b"not the envelope"),
                (IDENTITY_MEDIA_TYPE, b"x"),
            ],
        );
        let response = exchange_bytes(
            address,
            &ingest_request(
                "multipart/related; boundary=archivist-conformance-01",
                &body,
            ),
        )
        .await;
        // Part one is not the pinned envelope media type: the
        // content-negotiation 415, and neither placeholder — the observed
        // type least of all — is echoable (ERR-013's degradation).
        let text = assert_exchange_contract(
            &response,
            415,
            "envelope.media_type_unsupported",
            false,
            None,
        );
        assert!(
            text.contains(
                "\"message\":\"Media type [media_type] is not accepted; this path \
                 accepts [expected_media_type].\""
            ),
            "{text}"
        );
        assert!(!text.contains("CANARY-MEDIA-TYPE-9q"));
    }

    #[tokio::test]
    async fn a_malformed_envelope_part_is_the_malformed_rejection() {
        let address = serve(test_state()).await;
        let body = framed_body(
            BOUNDARY,
            &[
                (
                    ENVELOPE_PART_MEDIA_TYPE,
                    b"{\"leaked\": \"CANARY-JSON-BYTES-5r\"",
                ),
                (IDENTITY_MEDIA_TYPE, b"CANARY-PAYLOAD-BYTES-7w"),
            ],
        );
        let response = exchange_bytes(
            address,
            &ingest_request(
                "multipart/related; boundary=archivist-conformance-01",
                &body,
            ),
        )
        .await;
        let text = assert_exchange_contract(&response, 400, "envelope.malformed", false, None);
        // Not canonical-domain JSON, so no identifier and none of the
        // canary bytes: the pinned message, verbatim.
        assert!(
            text.contains(
                "\"message\":\"The request envelope is not valid canonical JSON for \
                 the declared schema version.\""
            ),
            "{text}"
        );
        assert!(!text.contains("CANARY-JSON-BYTES-5r"));
        assert!(!text.contains("CANARY-PAYLOAD-BYTES-7w"));
    }

    #[tokio::test]
    async fn an_unsupported_envelope_version_is_the_version_rejection() {
        let address = serve(test_state()).await;
        // The baseline envelope with its protocol major bumped: refused
        // at the version axis, with the envelope's own identifier
        // carried (ERR-025).
        let envelope_bytes = corpus_file("valid-direct-baseline", "envelope");
        let mut envelope = match json::parse(&envelope_bytes).expect("fixture parses") {
            json::Value::Object(object) => object,
            other => panic!("the envelope fixture is an object, found {other:?}"),
        };
        envelope.set("protocol_version", json::Value::Int(2));
        let body = framed_body(
            BOUNDARY,
            &[
                (
                    ENVELOPE_PART_MEDIA_TYPE,
                    json::Value::Object(envelope).canonical_bytes().as_slice(),
                ),
                (IDENTITY_MEDIA_TYPE, b"x"),
            ],
        );
        let response = exchange_bytes(
            address,
            &ingest_request(
                "multipart/related; boundary=archivist-conformance-01",
                &body,
            ),
        )
        .await;
        let request_id = corpus_request_id("valid-direct-baseline");
        let text = assert_exchange_contract(
            &response,
            400,
            "envelope.version_unsupported",
            false,
            Some(&request_id),
        );
        assert!(
            text.contains(
                "\"message\":\"Envelope schema version 2 is not supported by this \
                 server.\""
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn the_corpus_field_violations_render_their_pinned_bodies_through_the_route() {
        let address = serve(test_state()).await;
        for id in [
            "invalid-occurrence-id-mismatch",
            "invalid-unknown-enum-value",
            "invalid-reserved-field",
        ] {
            let body = corpus_file(id, "request_body");
            let response =
                exchange_bytes(address, &ingest_request(&corpus_content_type(id), &body)).await;
            // The pinned registry code and message travel verbatim from
            // the parser through the contract, and the envelope's own
            // identifier is carried in body and header (ERR-025).
            let request_id = corpus_request_id(id);
            let text = assert_exchange_contract(
                &response,
                400,
                "envelope.schema_invalid",
                false,
                Some(&request_id),
            );
            let pinned_message = corpus_error_message(id);
            assert!(
                text.contains(&format!("\"message\":\"{pinned_message}\"")),
                "{id}: the pinned message is rendered verbatim: {text}"
            );
        }
    }

    #[tokio::test]
    async fn both_payload_limit_classes_render_their_registry_413_through_the_route_mapping() {
        // The payload-limit triggers are the streaming pipeline's to
        // raise; the route's rendering of both classes is this surface's
        // contract, so the mapping is pinned directly per class — the
        // same single rendering site every live path above exercises.
        let splittable = ServerFailure::PayloadLimit(PayloadLimit::SplittableBytes {
            actual_bytes: 5_000_000,
            limit_bytes: 4_194_304,
        });
        let unsplittable = ServerFailure::PayloadLimit(PayloadLimit::UnsplittableRecord {
            actual_bytes: 300_000_000,
            limit_bytes: 268_435_456,
        });
        let ratio = ServerFailure::PayloadLimit(PayloadLimit::SplittableRatio { max_ratio: 100 });
        for (failure, code, message) in [
            (
                splittable,
                "request.payload_too_large",
                "The payload of 5000000 bytes exceeds the 4194304 byte limit; \
                 rechunk at a record boundary and resubmit.",
            ),
            (
                unsplittable,
                "request.record_too_large",
                "One record of 300000000 bytes exceeds the 268435456 byte \
                 unsplittable limit; the coverage gap is reported.",
            ),
            (
                ratio,
                "request.expansion_ratio_exceeded",
                "The decompression expansion ratio exceeds 100 to 1; rechunk and \
                 resubmit.",
            ),
        ] {
            // No envelope parsed on a size refusal before an envelope
            // exists: the schema's null, no request id header, and the
            // same correlation headers every contract response carries.
            let response = failure_response(failure, None);
            assert_eq!(response.status().as_u16(), 413, "{code}");
            assert_eq!(
                response.headers().get(axum::http::header::CONTENT_TYPE),
                Some(&ERROR_MEDIA_TYPE.parse().expect("media type header")),
                "{code}"
            );
            assert!(
                response.headers().get(REQUEST_ID_HEADER).is_none(),
                "{code}: no identifier, no request id header"
            );
            let correlation = response
                .headers()
                .get(CORRELATION_ID_HEADER)
                .expect("correlation header present")
                .to_str()
                .expect("the minted id is ASCII")
                .to_owned();
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .expect("body reads");
            let text = assert_pinned_error_shape(&body, code, false, None);
            assert!(
                text.contains(&format!("\"message\":\"{message}\"")),
                "{code}: the rendered integers, verbatim: {text}"
            );
            assert!(
                text.contains(&format!("\"correlation_id\":\"{correlation}\"")),
                "{code}: the header id matches the body: {text}"
            );
        }

        // A size refusal raised after an envelope parsed carries its
        // identifier exactly as any other path does.
        let carried = failure_response(splittable, Some(request_id_fixture()));
        assert_eq!(carried.status().as_u16(), 413);
        let header = carried
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("carried id travels as a header");
        assert_eq!(header.to_str().expect("header is text"), REQUEST_ID);
        let body = axum::body::to_bytes(carried.into_body(), 4096)
            .await
            .expect("body reads");
        assert_pinned_error_shape(&body, "request.payload_too_large", false, Some(REQUEST_ID));
    }

    #[tokio::test]
    async fn the_fail_closed_refusals_land_in_the_failed_outcome() {
        let address = serve(test_state()).await;
        let id = "valid-direct-baseline";
        let refused = exchange_bytes(
            address,
            &ingest_request(&corpus_content_type(id), &corpus_file(id, "request_body")),
        )
        .await;
        assert_eq!(refused.status, 503);
        // A shape violation on the same replica is a rejection, never a
        // failure: the two outcomes never blur.
        let rejected = exchange(
            address,
            "POST /v1/ingest HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n",
        )
        .await;
        assert_eq!(rejected.status, 400);
        let rendered = exchange(address, &get_request("/metrics")).await;
        assert_eq!(rendered.status, 200);
        let text = String::from_utf8(rendered.body).expect("exposition is text");
        assert!(text.contains(
            "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"failed\"} 1\n"
        ));
        assert!(text.contains(
            "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"rejected\"} 1\n"
        ));
        assert!(text.contains(
            "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"committed\"} 0\n"
        ));
    }

    #[tokio::test]
    async fn ingest_is_registered_for_post_only() {
        let address = serve(test_state()).await;
        let response = exchange(address, &get_request("/v1/ingest")).await;
        assert_eq!(response.status, 405);
    }

    // ------------------------------------------------------------------
    // Admission-guard tests: the resource guards refuse before anything
    // request-derived happens, and every refusal is the throttle class.
    // ------------------------------------------------------------------

    /// Saturate the replica's whole concurrency inventory on its gate, as
    /// sixteen concurrent admitted attempts would.
    fn saturate(state: &ServerState<SilentRawStore, SilentControlStore>) -> Vec<ProcessAdmission> {
        let mut admissions = Vec::new();
        for _ in 0..16 {
            admissions.push(state.gate().try_admit_process().expect("slot admits"));
        }
        admissions
    }

    #[test]
    fn the_rate_limited_refusal_carries_the_registry_pinned_message() {
        let refusal =
            crate::error::ErrorResponse::for_failure(crate::error::ServerFailure::RateLimited);
        assert_eq!(refusal.code(), "request.rate_limited");
        assert!(refusal.retryable());
        assert_eq!(refusal.status(), 429);
        assert_eq!(
            refusal.message(),
            "The per-client request rate was exceeded; \
             retry after the indicated interval."
        );
        let deadline =
            crate::error::ErrorResponse::for_failure(crate::error::ServerFailure::DeadlineElapsed);
        assert_eq!(deadline.code(), "request.deadline_exceeded");
        assert!(deadline.retryable());
        assert_eq!(deadline.status(), 408);
        assert_eq!(
            deadline.message(),
            "The request exceeded the request deadline; retry the identical envelope."
        );
    }

    #[tokio::test]
    async fn an_overloaded_replica_refuses_with_the_rate_limited_body() {
        let state = test_state();
        let address = serve(Arc::clone(&state)).await;
        let admissions = saturate(&state);
        let payload = "envelope-zq9-marker-never-echoed";
        let request = format!(
            "POST /v1/ingest HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{payload}",
            payload.len()
        );
        let response = exchange(address, &request).await;
        assert_eq!(response.status, 429);
        assert_eq!(response.content_type.as_deref(), Some(ERROR_MEDIA_TYPE));
        // The exact six-member contract: no guard name, no client, no
        // count, and none of the request's own bytes. The guard refusal
        // precedes any parse, so the request id is the schema's null.
        let text = assert_pinned_error_shape(&response.body, "request.rate_limited", true, None);
        assert!(!text.contains("zq9-marker"));
        assert!(response.header(CORRELATION_ID_HEADER.as_str()).is_some());
        // Retryable is real: releasing one slot admits the very next
        // attempt, which parses a well-formed body and reaches the
        // fail-closed stable answer with the envelope's identifier
        // carried.
        drop(admissions);
        let retried = exchange_bytes(
            address,
            &ingest_request(
                &corpus_content_type("valid-direct-baseline"),
                &corpus_file("valid-direct-baseline", "request_body"),
            ),
        )
        .await;
        assert_eq!(retried.status, 503);
        assert_pinned_error_shape(
            &retried.body,
            "server.unavailable",
            true,
            Some(&corpus_request_id("valid-direct-baseline")),
        );
    }

    #[tokio::test]
    async fn the_throttled_refusals_land_in_the_throttled_outcome_only() {
        let state = test_state();
        let address = serve(Arc::clone(&state)).await;
        let admissions = saturate(&state);
        let refused = exchange(
            address,
            "POST /v1/ingest HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n",
        )
        .await;
        assert_eq!(refused.status, 429);
        // Overload is never ingest work: the throttle outcome carries it
        // and the failed outcome stays untouched. The gauge counts
        // exactly the sixteen admissions — one unlabeled series, no
        // per-client or per-request cardinality anywhere (SEC-004).
        let during = exchange(address, &get_request("/metrics")).await;
        let text = String::from_utf8(during.body).expect("exposition is text");
        assert!(text.contains("archivist_server_ingest_inflight_requests 16\n"));
        assert!(text.contains(
            "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"throttled\"} 1\n"
        ));
        assert!(text.contains(
            "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"failed\"} 0\n"
        ));
        // Release drains the gauge back to zero exactly; the counter floors
        // at zero, so a stray double-release cannot mint negative inventory.
        drop(admissions);
        let after = exchange(address, &get_request("/metrics")).await;
        assert!(
            String::from_utf8(after.body)
                .expect("exposition is text")
                .contains("archivist_server_ingest_inflight_requests 0\n")
        );
    }

    #[tokio::test]
    async fn admission_refuses_before_any_request_byte_is_read() {
        let state = test_state();
        let address = serve(Arc::clone(&state)).await;
        let _admissions = saturate(&state);
        // Declare a body and never send it: an overloaded replica must
        // still answer, because admission reads nothing request-derived —
        // the refusal cannot be waiting on payload bytes that never
        // arrive, and no payload-scale buffer was allocated to hold them.
        let head_only = "POST /v1/ingest HTTP/1.1\r\nHost: test\r\nContent-Length: 64\r\n\
             Connection: close\r\n\r\n";
        let response = exchange(address, head_only).await;
        assert_eq!(response.status, 429);
        assert_pinned_error_shape(&response.body, "request.rate_limited", true, None);
    }

    #[tokio::test]
    async fn unregistered_paths_answer_not_found() {
        let address = serve(test_state()).await;
        let response = exchange(address, &get_request("/health")).await;
        assert_eq!(response.status, 404);
    }
}
