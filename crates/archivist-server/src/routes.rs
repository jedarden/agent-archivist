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
//! | `/v1/ingest` | POST | Registered, fail-closed: every attempt is refused with the stable `server.unavailable` body until the pipeline slice lands. |
//!
//! Fail-closed is the operative rule for every body: responses render
//! canonical bytes through `archivist-protocol`'s RFC 8785 writer, carry
//! counts and closed-vocabulary tokens only, and never echo request
//! content, identifiers, or paths (SEC-004, SEC-005). Error bodies are
//! the `archivist.error/v1` shape pinned by `schemas/v1/ingest-error.json`
//! — six members, both request identifiers null exactly because no
//! envelope was parsed (ERR-027) — carrying the registry's pinned code,
//! retryability, and message for `server.unavailable`.

use std::sync::Arc;

use archivist_protocol::json::{Object, Value};
use archivist_storage::control::ControlReadStore;
use archivist_storage::raw_write::RawWriteStore;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;
use axum::routing::{get, post};

use crate::state::{ReadinessSnapshot, ServerState};

/// Media type of the stable error body (`schemas/v1/ingest-error.json`).
pub const ERROR_MEDIA_TYPE: &str = "application/vnd.agent-archivist.error+json";

/// Media type of the content-free health bodies.
pub const HEALTH_MEDIA_TYPE: &str = "application/json";

/// Media type of the Prometheus text exposition served at `/metrics`.
pub const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The `server.unavailable` code as registered in
/// `tools/error-codes.toml`.
const CODE_SERVER_UNAVAILABLE: &str = "server.unavailable";

/// The `server.unavailable` pinned message, verbatim from the registry.
const MESSAGE_SERVER_UNAVAILABLE: &str =
    "The service is temporarily unable to handle the request; retry the identical envelope.";

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

/// `POST /v1/ingest` — registered and fail-closed.
///
/// The bootstrap surface mounts the route and refuses every attempt with
/// the stable retryable body: no pipeline exists yet, so nothing can be
/// committed and no receipt can be issued, and saying so through
/// `server.unavailable` is the honest response (plan Section 7.8:
/// server-failure class, retryable, no receipt). The pipeline slice
/// replaces this handler behind the same route.
async fn ingest<W, C>(State(state): State<Arc<ServerState<W, C>>>) -> Response {
    state
        .metrics()
        .record_ingest(crate::metrics::IngestOutcome::Failed);
    response(
        StatusCode::SERVICE_UNAVAILABLE,
        ERROR_MEDIA_TYPE,
        unavailable_error_body(),
    )
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

/// The canonical `archivist.error/v1` body for `server.unavailable`:
/// both request identifiers are null because no envelope was parsed
/// (ERR-027), and the code, retryability, and message are the registry's
/// pinned values.
fn unavailable_error_body() -> Vec<u8> {
    let mut object = Object::new();
    let _ = object.insert("code", Value::Text(CODE_SERVER_UNAVAILABLE.to_owned()));
    let _ = object.insert("correlation_id", Value::Null);
    let _ = object.insert(
        "message",
        Value::Text(MESSAGE_SERVER_UNAVAILABLE.to_owned()),
    );
    let _ = object.insert("request_id", Value::Null);
    let _ = object.insert("retryable", Value::Bool(true));
    let _ = object.insert("schema", Value::Text("archivist.error/v1".to_owned()));
    Value::Object(object).canonical_bytes()
}

#[cfg(test)]
mod tests {
    use super::{
        ERROR_MEDIA_TYPE, HEALTH_MEDIA_TYPE, LIVE_BODY, METRICS_MEDIA_TYPE, ready_body,
        unavailable_error_body,
    };
    use crate::state::{NotReadyReason, ReadinessSnapshot, ServerState};
    use crate::trust::{TenantTrustRoot, TrustConfig};
    use archivist_protocol::json;
    use archivist_protocol::object_key::BlobObjectKey;
    use archivist_protocol::vocabulary::{ClientId, KeyId, StorageOutcome, TenantId};
    use archivist_storage::capability::StoreCapabilities;
    use archivist_storage::control::{AuthorizationEpoch, ControlReadStore, ControlRecord};
    use archivist_storage::error::{StorageError, StorageErrorKind};
    use archivist_storage::ingest::IngestStorage;
    use archivist_storage::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

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
    fn the_unavailable_body_is_the_registry_pinned_error_shape() {
        let body = unavailable_error_body();
        // Canonical bytes: the golden error bodies are produced by the
        // same writer, so this is byte-comparable with the corpus.
        let value = json::parse(&body).unwrap();
        let json::Value::Object(ref object) = value else {
            panic!("error body is an object");
        };
        assert_eq!(object.len(), 6);
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
            ]
        );
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("\"code\":\"server.unavailable\""));
        assert!(text.contains("\"retryable\":true"));
        assert!(text.contains("\"schema\":\"archivist.error/v1\""));
        assert!(text.contains("\"request_id\":null"));
        assert!(text.contains("\"correlation_id\":null"));
        assert!(text.contains(
            "\"message\":\"The service is temporarily unable to handle the request; \
             retry the identical envelope.\""
        ));
        // The pinned message survives its own charset rules: printable
        // ASCII, no braces, one line, at most 200 characters.
        let message = "The service is temporarily unable to handle the request; retry the identical envelope.";
        assert!(message.len() <= 200);
        assert!(
            message
                .bytes()
                .all(|b| (0x20..=0x7a).contains(&b) || b == 0x7c || b == 0x7e)
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
        content_type: Option<String>,
        body: Vec<u8>,
    }

    /// One raw HTTP/1.1 exchange against the running router: the request
    /// goes out whole, and the answer is read to EOF (`Connection:
    /// close` makes the server close first — a client half-close here
    /// would kill the exchange instead of ending the request).
    async fn exchange(address: SocketAddr, request: &str) -> Exchanged {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("test client connects");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("request writes");
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
        let content_type = head.lines().skip(1).find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-type")
                .then(|| value.trim().to_owned())
        });
        Exchanged {
            status,
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
            "# TYPE archivist_server_shutdown gauge",
            "# TYPE archivist_server_trust_refresh_attempts_total counter",
        ] {
            assert!(text.contains(family), "missing family: {family}");
        }
        // No evidence exists on a fresh replica, so the age family is
        // omitted — an invented age would be a fabricated fact.
        assert!(!text.contains("trust_age"));
    }

    #[tokio::test]
    async fn ingest_refuses_every_attempt_with_the_stable_retryable_error() {
        let address = serve(test_state()).await;
        let payload = "envelope-zq9-marker-never-echoed";
        let request = format!(
            "POST /v1/ingest HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{payload}",
            payload.len()
        );
        let response = exchange(address, &request).await;
        assert_eq!(response.status, 503);
        assert_eq!(response.content_type.as_deref(), Some(ERROR_MEDIA_TYPE));
        // The body is byte-identical to the pinned canonical refusal and
        // never carries the request's own bytes.
        assert_eq!(response.body, unavailable_error_body());
        let text = String::from_utf8(response.body).expect("error body is text");
        assert!(text.contains("\"code\":\"server.unavailable\""));
        assert!(text.contains("\"retryable\":true"));
        assert!(!text.contains("zq9-marker"));
    }

    #[tokio::test]
    async fn the_fail_closed_refusals_land_in_the_failed_outcome() {
        let address = serve(test_state()).await;
        let refused = exchange(
            address,
            "POST /v1/ingest HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n",
        )
        .await;
        assert_eq!(refused.status, 503);
        let rendered = exchange(address, &get_request("/metrics")).await;
        assert_eq!(rendered.status, 200);
        let text = String::from_utf8(rendered.body).expect("exposition is text");
        assert!(text.contains(
            "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"failed\"} 1\n"
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

    #[tokio::test]
    async fn unregistered_paths_answer_not_found() {
        let address = serve(test_state()).await;
        let response = exchange(address, &get_request("/health")).await;
        assert_eq!(response.status, 404);
    }
}
