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
//! | `/v1/ingest` | POST | Admission-guarded, pre-authorized, then bounded-parse: the request deadline bounds the whole attempt, the process-wide in-flight cap admits before anything request-derived is read, and an overloaded replica refuses with the retryable `request.rate_limited` body; admitted attempts validate the pinned framing, require the bounded signed-attempt record, parse the envelope, and load linked-client evidence before any storage key or raw-write call can exist. Complete received-payload digest verification remains a hard gate in front of the streaming commit. |
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
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use archivist_protocol::envelope::{Envelope, EnvelopeError};
use archivist_protocol::json::{Object, Value};
use archivist_protocol::sha256::Sha256;
use archivist_protocol::vocabulary::{
    EnvelopeDigest, PayloadCanonicalDigest, PayloadTransportDigest, RequestContentDigest, RequestId,
};
use archivist_storage::blob::{BlobEncoder, BlobExpectation, commit_blob};
use archivist_storage::control::ControlReadStore;
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::raw_write::RawWriteStore;
use archivist_storage::zstd_v1::ZstdV1Encoder;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;
use axum::routing::{get, post};
use tokio::sync::mpsc;

use crate::authorize::{self, EvidenceRejection};
use crate::error::{AuthRejection, ErrorResponse, ServerFailure};
use crate::guard::{DeadlineElapsed, within_deadline};
use crate::metrics::IngestOutcome;
use crate::parse::framing::{ByteSource, FramingError, RequestFraming};
use crate::parse::ingest::{IngestParseError, parse_ingest_with_cap};
use crate::parse::parts::{PayloadStream, TwoPartError};
use crate::state::{ReadinessSnapshot, ServerState};
use crate::transport::{DecodeLimits, TransportDecodeError, TransportDecoder};

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

/// `POST /v1/ingest` — admission-guarded, pre-authorized, then bounded-parse.
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
/// An admitted attempt first validates the pinned two-part framing from
/// the `Content-Type` header alone and the bounded attempt record from
/// the authorization header. The body then streams into the parse through
/// a bounded channel so no attempt ever buffers payload scale (VAL-008).
/// Every request-shape violation — framing, part-one media type,
/// envelope malformed/version/schema/size — renders its registry code
/// and pinned message through [`failure_response`] with the envelope's
/// request identifier carried once one has parsed (ERR-025, ERR-027).
/// A well-formed attempt loads and verifies linked-client evidence before
/// the commit phase is even eligible; until the streaming pipeline has
/// supplied all received-payload digests to the signed-request verifier,
/// the route fails closed with the retryable unavailable response.
async fn ingest<W, C>(State(state): State<Arc<ServerState<W, C>>>, request: Request) -> Response
where
    W: RawWriteStore + Send + Sync + 'static,
    C: ControlReadStore + Send + Sync + 'static,
{
    let attempt = within_deadline(state.config().request_deadline(), async {
        match state.gate().try_admit_process() {
            Err(_rejection) => {
                let failure = ServerFailure::RateLimited;
                (failure.outcome(), failure_response(failure, None))
            }
            // The admission is held across the whole parse attempt —
            // that is the concurrency bound doing its job — and released
            // when the outcome is rendered.
            Ok(admission) => {
                let (outcome, response) = attempt_pipeline(&state, request).await;
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
            let failure = ServerFailure::DeadlineElapsed;
            state.metrics().record_ingest(failure.outcome());
            failure_response(failure, None)
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

/// The authorized pipeline of an admitted attempt: framing and safe
/// pre-authorization from headers, the bounded two-part parse over the
/// streamed body, per-client admission, and linked-client evidence.
/// Every outcome is a rendered response paired with the metric outcome the
/// attempt earned, classified by [`ServerFailure::outcome`] so the
/// recorded outcome and the wire class can never disagree. The raw writer
/// is reached only after complete signed-request verification produces an
/// authorization capability; this slice deliberately fails closed while
/// the streaming digest handoff is not yet available.
async fn attempt_pipeline<W, C>(
    state: &Arc<ServerState<W, C>>,
    request: Request,
) -> (IngestOutcome, Response)
where
    W: RawWriteStore + Send + Sync + 'static,
    C: ControlReadStore + Send + Sync + 'static,
{
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
            let failure =
                ServerFailure::Parse(IngestParseError::Framing(TwoPartError::from(error)));
            return (failure.outcome(), failure_response(failure, None));
        }
    };

    // The record and its safe header-only claims are checked before the
    // request body is opened. No body, control read, or raw write belongs
    // to an attempt whose proof is absent, malformed, stale, or bound to
    // another framing boundary.
    let record = match authorize::attempt_record_from_header(request.headers()) {
        Ok(record) => record,
        Err(rejection) => return authorization_refusal(rejection, None),
    };
    if let Err(rejection) =
        authorize::pre_authorize(&record, content_type, &authorize::now_timestamp())
    {
        return authorization_refusal(rejection, None);
    }

    // The body streams into the blocking parse through a bounded
    // channel: the async feeder task never buffers beyond one chunk, the
    // channel holds a fixed handful, and the parse side consumes through
    // the framing tokenizer's small window — buffered request bytes stay
    // bounded for any body size (VAL-008). When the parse outcome is
    // known the stream is dropped, the feeder's sends fail, and the
    // (possibly huge) unread tail of the body is simply abandoned; the
    // connection layer owns that path.
    let request_hasher = Arc::new(Mutex::new(Sha256::new()));
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
    let parse_hasher = Arc::clone(&request_hasher);
    let parse = tokio::task::spawn_blocking(move || {
        parse_ingest_with_cap(
            &framing,
            BodyChannel {
                receiver,
                chunk: Vec::new(),
                cursor: 0,
                request_hasher: parse_hasher,
            },
            envelope_cap,
        )
    });
    match parse.await {
        // A panicked parse committed nothing and is a defect, not a wire
        // condition: the internal-failure class, never a 200-shaped lie.
        Err(_join) => {
            let failure = ServerFailure::Internal;
            (failure.outcome(), failure_response(failure, None))
        }
        Ok(Err(rejection)) => {
            let failure = ServerFailure::Parse(rejection.error);
            let outcome = failure.outcome();
            // The parsed envelope's identifier is known, so the refusal
            // carries it (ERR-025) — a client correlating its attempt
            // sees the server that read it.
            (outcome, failure_response(failure, rejection.request_id))
        }
        Ok(Ok((envelope, stream))) => {
            // The uploader identity is the first request-derived fact the
            // per-client guard may consume. Hold this admission across the
            // evidence reads below; a rejected attempt never reaches the
            // writer.
            let client_admission = match state
                .gate()
                .admit_client(&envelope.uploader_client_id, Instant::now())
            {
                Ok(admission) => admission,
                Err(_rejection) => {
                    let failure = ServerFailure::RateLimited;
                    return (
                        failure.outcome(),
                        failure_response(failure, Some(envelope.request_id)),
                    );
                }
            };

            let evidence = authorize::load_uploader_evidence(
                state.storage().control(),
                state.trust(),
                &record,
                &envelope.tenant_id,
                &envelope.uploader_client_id,
                &envelope.origin_client_id,
                |_| None,
            )
            .await;

            let result = match evidence {
                Ok(evidence) => match preflight_digests(
                    &envelope,
                    stream,
                    request_hasher,
                    DecodeLimits::new(
                        state.config().record_max_bytes(),
                        u64::from(state.config().max_expansion_ratio()),
                    ),
                )
                .await
                {
                    Err(failure) => (
                        failure.outcome(),
                        failure_response(failure, Some(envelope.request_id)),
                    ),
                    Ok(digests) => {
                        let presented = authorize::presented_request(&envelope, digests);
                        match authorize::authorize_attempt(
                            &record,
                            &presented,
                            &evidence,
                            &authorize::now_timestamp(),
                        ) {
                            Err(rejection) => {
                                authorization_refusal(rejection, Some(envelope.request_id))
                            }
                            Ok(_authorized) => {
                                // The preflight consumed the one-shot body.
                                // A storage commit therefore remains behind
                                // the explicit replay handoff; most
                                // importantly, no AuthorizedAttempt is ever
                                // mistaken for permission to write before
                                // that handoff exists.
                                let failure = ServerFailure::Unavailable;
                                (
                                    failure.outcome(),
                                    failure_response(failure, Some(envelope.request_id)),
                                )
                            }
                        }
                    }
                },
                Err(EvidenceRejection::Unlinked) => {
                    authorization_refusal(AuthRejection::Unlinked, Some(envelope.request_id))
                }
                Err(EvidenceRejection::Forbidden) => {
                    authorization_refusal(AuthRejection::Forbidden, Some(envelope.request_id))
                }
                Err(EvidenceRejection::RegistryUnavailable) => {
                    let failure = ServerFailure::RegistryUnavailable;
                    (
                        failure.outcome(),
                        failure_response(failure, Some(envelope.request_id)),
                    )
                }
            };
            drop(client_admission);
            result
        }
    }
}

/// Render one authorization refusal without exposing the presented proof.
fn authorization_refusal(
    rejection: AuthRejection,
    request_id: Option<RequestId>,
) -> (IngestOutcome, Response) {
    let failure = ServerFailure::Authorization(rejection);
    (failure.outcome(), failure_response(failure, request_id))
}

/// Drain and hash the received payload before the commit path can be
/// considered. The decoder and framing source stay bounded; this pass
/// retains only digest state, so an altered body is rejected by the signed
/// request verifier before a multipart session is opened.
async fn preflight_digests(
    envelope: &Envelope,
    stream: PayloadStream<BodyChannel>,
    request_hasher: Arc<Mutex<Sha256>>,
    limits: DecodeLimits,
) -> Result<authorize::VerifiedDigests, ServerFailure> {
    let envelope = envelope.clone();
    tokio::task::spawn_blocking(move || {
        let source = DigestingPayload {
            inner: stream,
            transport: Sha256::new(),
        };
        let mut decoder = TransportDecoder::new(envelope.transport_encoding, source, limits)
            .map_err(decode_failure)?;
        let mut canonical = Sha256::new();
        while let Some(chunk) = decoder.next_chunk().map_err(decode_failure)? {
            canonical.update(chunk);
        }
        let source = decoder.into_source();
        source
            .inner
            .finish()
            .map_err(|error| ServerFailure::Parse(IngestParseError::Framing(error)))?;

        let request_content = request_hasher
            .lock()
            .expect("request digest lock")
            .clone()
            .finalize();
        Ok(authorize::VerifiedDigests {
            request_content: RequestContentDigest::from_raw(request_content),
            envelope: EnvelopeDigest::from_raw(envelope.envelope_digest().as_raw().to_owned()),
            payload_canonical: PayloadCanonicalDigest::from_raw(canonical.finalize()),
            payload_transport: PayloadTransportDigest::from_raw(source.transport.finalize()),
        })
    })
    .await
    .map_err(|_| ServerFailure::Internal)?
}

/// A one-pass payload reader that records the bytes as transported while
/// the bounded decoder produces canonical chunks.
struct DigestingPayload<R> {
    inner: R,
    transport: Sha256,
}

impl<R: io::Read> io::Read for DigestingPayload<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if read != 0 {
            self.transport.update(&buffer[..read]);
        }
        Ok(read)
    }
}

/// The commit phase of a well-formed attempt: bounded transport decode
/// into the blob commit, then the rendering (plan Section 7.7).
///
/// The decode runs on the blocking pool — its reads block on the parse
/// bridge's channel, which is legal only off the async runtime — and
/// feeds `commit_blob` chunk by chunk through a same-thread iterator, so
/// no stage ever holds payload scale beyond its own bounded buffers: the
/// decode stage's 16 MiB target chunk, the one chunk in flight to the
/// encoder, the writer's 8 MiB part. Memory follows the concurrency
/// buffers, never the body (VAL-008), and the request deadline and the
/// process-wide in-flight cap held by the admission cover the whole
/// phase.
///
/// The checks run in the plan's order, each able to stop the attempt with
/// nothing stored: the decode stage's two hard limits fire mid-stream
/// against the bytes actually produced (the two 413 classes), the framing
/// must close exactly past the payload, and the produced canonical extent
/// must equal the envelope's declared size — any of these failing gates
/// the encoder, so the commit's own epilogue refuses and the live
/// multipart session aborts (VAL-008; EC-07: no stored object, no live
/// session). The commit then completes only after the canonical digest
/// and the declared size verify against the bytes actually produced.
///
/// What renders on a verified commit is this slice's honest outcome: the
/// occurrence and attestation writes are not wired yet, so the attempt
/// holds a durable blob and nothing more — the registry's
/// `server.partial_commit`, retryable, no receipt, the identical retry
/// repairing the rest (protocol Section 4.1; RCPT-005). The store's
/// physical answer travels untouched behind the commit (RCPT-003):
/// created stays created, already-present stays already-present, and the
/// payload is streamed and verified in both cases — a known digest never
/// exempts the bytes (plan Section 7.7).
#[allow(dead_code)]
async fn attempt_commit<W, C>(
    state: Arc<ServerState<W, C>>,
    envelope: Envelope,
    stream: PayloadStream<BodyChannel>,
) -> (IngestOutcome, Response)
where
    W: RawWriteStore + Send + Sync + 'static,
    C: ControlReadStore + Send + Sync + 'static,
{
    let request_id = envelope.request_id;
    let limits = DecodeLimits::new(
        state.config().record_max_bytes(),
        u64::from(state.config().max_expansion_ratio()),
    );
    let expectation = BlobExpectation::new(envelope.blob_digest, envelope.uncompressed_size);
    let encoding = envelope.transport_encoding;
    let tenant = envelope.tenant_id.clone();
    let uploads = Arc::clone(state.uploads());
    // Captured here, where the runtime is current; the blocking task uses
    // it to drive the commit's async store calls.
    let handle = tokio::runtime::Handle::current();

    // The one blocking task drives the whole streaming tail: the decode
    // reads block on the parse bridge's channel, and the commit's store
    // futures run under the runtime handle on this same thread.
    let attempt = tokio::task::spawn_blocking(move || {
        let decoder = match TransportDecoder::new(encoding, stream, limits) {
            Ok(decoder) => decoder,
            Err(error) => return decode_failure(error),
        };
        // The pledge is the envelope's declared canonical extent — the
        // declaration the whole stream is held to; the encoder enforces
        // it, and a rejection here is a build or version drift.
        let encoder = match ZstdV1Encoder::new(expectation.uncompressed_bytes()) {
            Ok(encoder) => encoder,
            Err(_) => return ServerFailure::Internal,
        };
        // The drain's verdict gates the commit: until the drain has
        // verified the declared size, the encoder refuses its epilogue,
        // which is what aborts the live session. (Framing closure is the
        // decode stage's own end-of-stream check: an incomplete frame
        // fails `next_chunk` and arrives here as an error.) Both are
        // shared by reference with the drain and the encoder, so they
        // carry the verdict across the encoder trait's `Sync` bound.
        let gate = AtomicBool::new(true);
        let cause = Mutex::new(None);
        let mut gated = GateEncoder {
            inner: encoder,
            gate: &gate,
        };
        let mut chunks = DrainChunks {
            decoder: Some(decoder),
            declared_bytes: expectation.uncompressed_bytes(),
            drained_bytes: 0,
            gate: &gate,
            cause: &cause,
        };
        let commit = handle.block_on(commit_blob(
            state.storage().raw(),
            &uploads,
            &tenant,
            expectation,
            &mut gated,
            &mut chunks,
        ));
        // A recorded cause is the attempt's true failure: the commit
        // result behind it is only the abort the gate forced.
        if let Some(failure) = cause.lock().expect("cause lock").take() {
            return failure;
        }
        match commit {
            // Verified against the store, and still only the blob: the
            // partial-commit class is this slice's honest answer
            // (RCPT-005), and the metric counts the attempt as the
            // failure it reported — `committed` means committed *and*
            // receipted.
            Ok(_committed) => ServerFailure::PartialCommit,
            // The commit layer's own validation or the store failed with
            // nothing left behind; the kind carries the wire class.
            Err(error) => ServerFailure::from_storage_kind(error.kind()),
        }
    })
    .await;
    let failure = match attempt {
        // A panicked commit task is a defect, not a wire condition; the
        // aborting writer's Drop already abandoned the session.
        Err(_join) => ServerFailure::Internal,
        Ok(failure) => failure,
    };
    let outcome = failure.outcome();
    (outcome, failure_response(failure, Some(request_id)))
}

/// The route failure for a transport-decode refusal: the two limit
/// classes ride their registered 413 payloads, and every other decode
/// failure fails closed to the framing-invalid class the registry pins
/// for a request that is not the byte layout the protocol declared.
#[allow(dead_code)]
fn decode_failure(error: TransportDecodeError) -> ServerFailure {
    match error.payload_limit() {
        Some(limit) => ServerFailure::PayloadLimit(limit),
        None => match error {
            // A decoder that could not be built is a build or version
            // drift, not a wire condition.
            TransportDecodeError::CodecSetup => ServerFailure::Internal,
            TransportDecodeError::MalformedFrame { .. } | TransportDecodeError::SourceRead(_) => {
                framing_invalid()
            }
            // Unreachable — the limit classes always carry a payload
            // limit, answered above; a rerender here would mean the
            // classification drifted, and internal is the fail-closed
            // answer for that too.
            TransportDecodeError::RecordTooLarge { .. }
            | TransportDecodeError::ExpansionRatioExceeded { .. } => ServerFailure::Internal,
        },
    }
}

/// The pinned request-shape refusal the pipeline's framing-class failures
/// render: the registry's `request.framing_invalid` with its pinned
/// message, content-free — the codec's own static detail never rides the
/// wire (SEC-004).
#[allow(dead_code)]
fn framing_invalid() -> ServerFailure {
    ServerFailure::Parse(IngestParseError::Framing(TwoPartError::Framing(
        FramingError::MalformedDelimiter,
    )))
}

/// The consistency rejection for a stream whose produced canonical extent
/// differs from the envelope's declared `uncompressed_size`: the request
/// is not the declaration the protocol pinned, refused before any commit
/// (protocol Section 3.4 fault table; VAL-003).
#[allow(dead_code)]
fn declared_size_mismatch() -> ServerFailure {
    ServerFailure::Parse(IngestParseError::Envelope(EnvelopeError::SchemaInvalid {
        field: "uncompressed_size",
        reason: "declared size differs from the bytes the request carried",
    }))
}

/// Static detail of the pre-commit gate refusal — content-free, and
/// unreachable by any rendering path: the route reports the recorded
/// cause, never the gate trip itself.
#[allow(dead_code)]
const GATE_REFUSED_DETAIL: &str =
    "the pipeline refused the attempt before its commit could complete";

/// The pipeline's pre-commit gate, worn by the storage encoder: once the
/// drain's verdict has failed a check, the encoder refuses the frame
/// epilogue, which is what aborts `commit_blob`'s live session before
/// anything completes. The gate holds no state beyond the verdict the
/// drain recorded.
#[allow(dead_code)]
struct GateEncoder<'a, E: BlobEncoder> {
    inner: E,
    gate: &'a AtomicBool,
}

impl<E: BlobEncoder> BlobEncoder for GateEncoder<'_, E> {
    fn update(&mut self, canonical: &[u8], out: &mut Vec<u8>) -> Result<(), StorageError> {
        self.inner.update(canonical, out)
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), StorageError> {
        if !self.gate.load(Ordering::SeqCst) {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                GATE_REFUSED_DETAIL,
            ));
        }
        self.inner.finish(out)
    }
}

/// The canonical chunk source the commit consumes: the transport
/// decoder's lending chunks, copied out one at a time — the copy is a
/// concurrency buffer in flight to the encoder, never a second
/// payload-scale hold. The drain runs the pipeline's own pre-commit
/// checks (framing closure, declared size) and records their verdict in
/// the gate and the cause the route renders.
#[allow(dead_code)]
struct DrainChunks<'a, R> {
    /// Present until the stream drains or fails; `None` afterwards, so a
    /// source can never be read past its own verdict.
    decoder: Option<TransportDecoder<R>>,
    declared_bytes: u64,
    /// Running total of the canonical bytes handed to the commit.
    drained_bytes: u64,
    gate: &'a AtomicBool,
    cause: &'a Mutex<Option<ServerFailure>>,
}

impl<R: io::Read> Iterator for DrainChunks<'_, R> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        let decoder = self.decoder.as_mut()?;
        match decoder.next_chunk() {
            Ok(Some(chunk)) => {
                self.drained_bytes += chunk.len() as u64;
                Some(chunk.to_vec())
            }
            Ok(None) => {
                // Drained: framing closure was the decode stage's own
                // end-of-stream check (an incomplete frame failed
                // `next_chunk` above), so the check left is the declared
                // size — the produced canonical extent must equal the
                // declaration before the commit may complete.
                self.decoder = None;
                let size_ok = self.drained_bytes == self.declared_bytes;
                if !size_ok {
                    self.cause
                        .lock()
                        .expect("cause lock")
                        .replace(declared_size_mismatch());
                }
                self.gate.store(size_ok, Ordering::SeqCst);
                None
            }
            Err(error) => {
                // The stage is closed — it reads no further. The canonical
                // stream ends here, short of its declared digest: the
                // commit layer's own validation aborts the live session
                // before anything completes.
                self.decoder = None;
                self.gate.store(false, Ordering::SeqCst);
                self.cause
                    .lock()
                    .expect("cause lock")
                    .replace(decode_failure(error));
                None
            }
        }
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
    /// Whole-request digest state, updated as bytes leave the bridge.
    request_hasher: Arc<Mutex<Sha256>>,
}

impl ByteSource for BodyChannel {
    fn pull(&mut self, window: &mut [u8]) -> Result<usize, io::ErrorKind> {
        loop {
            if self.cursor < self.chunk.len() {
                let buffered = &self.chunk[self.cursor..];
                let copied = buffered.len().min(window.len());
                window[..copied].copy_from_slice(&buffered[..copied]);
                self.cursor += copied;
                self.request_hasher
                    .lock()
                    .expect("request digest lock")
                    .update(&buffered[..copied]);
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
    use super::{
        BlobEncoder, Envelope, HEALTH_MEDIA_TYPE, LIVE_BODY, METRICS_MEDIA_TYPE, ZstdV1Encoder,
        failure_response, ready_body,
    };
    use crate::authorize;
    use crate::error::{
        AuthRejection, CORRELATION_ID_HEADER, ERROR_MEDIA_TYPE, PayloadLimit, REQUEST_ID_HEADER,
        ServerFailure,
    };
    use crate::guard::ProcessAdmission;
    use crate::parse::parts::ENVELOPE_PART_MEDIA_TYPE;
    use crate::state::{
        NotReadyReason, ReadinessSnapshot, ServerState, signed_test_control_record,
    };
    use crate::trust::{TenantTrustRoot, TrustConfig};
    use archivist_auth::ed25519;
    use archivist_protocol::json;
    use archivist_protocol::object_key::BlobObjectKey;
    use archivist_protocol::vocabulary::{
        ClientId, Ed25519PublicKey, IncomingChecksum, KeyId, RequestId, StorageOutcome, TenantId,
        TransportEncoding,
    };
    use archivist_storage::capability::StoreCapabilities;
    use archivist_storage::control::{AuthorizationEpoch, ControlReadStore, ControlRecord};
    use archivist_storage::error::{StorageError, StorageErrorKind};
    use archivist_storage::ingest::IngestStorage;
    use archivist_storage::metadata::ObjectTag;
    use archivist_storage::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };
    use std::fs;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
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
    /// non-UTF-8 payload bytes transmit verbatim. The test proof is
    /// intentionally shape-valid but not trusted evidence; parser tests
    /// exercise request framing before the control-plane gate, while the
    /// authorization tests construct signed records explicitly.
    fn test_attempt_header(content_type: &str) -> String {
        format!(
            "{{\"authorization_epoch\":1,\"authorization_timestamp\":\"{}\",\
             \"content_type\":\"{}\",\"envelope_digest\":\"{}\",\
             \"http_method\":\"POST\",\"payload_canonical_digest\":\"{}\",\
             \"payload_transport_digest\":\"{}\",\"request_content_digest\":\"{}\",\
             \"route\":\"/v1/ingest\",\"signature\":\"{}\",\
             \"signature_algorithm\":\"ed25519\",\"uploader_key_id\":\"{}\"}}",
            authorize::now_timestamp().as_str(),
            content_type,
            "0".repeat(64),
            "0".repeat(64),
            "0".repeat(64),
            "0".repeat(64),
            "0".repeat(128),
            "0".repeat(64),
        )
    }

    fn ingest_request(content_type: &str, body: &[u8]) -> Vec<u8> {
        let attempt = test_attempt_header(content_type);
        let mut request = format!(
            "POST /v1/ingest HTTP/1.1\r\nHost: test\r\n\
             Content-Type: {content_type}\r\nX-Archivist-Attempt: {attempt}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        request
    }

    #[test]
    fn test_attempt_header_is_accepted_by_the_middleware_parser() {
        let content_type = "multipart/related; boundary=archivist-conformance-01";
        let header = test_attempt_header(content_type);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            super::authorize::ATTEMPT_HEADER,
            header.parse().expect("test proof is a header value"),
        );
        let record = authorize::attempt_record_from_header(&headers).expect("record parses");
        authorize::pre_authorize(&record, content_type, &authorize::now_timestamp())
            .expect("record is fresh and covers the content type");
    }

    #[tokio::test]
    async fn a_missing_proof_performs_zero_raw_writes() {
        let (state, store) = commit_state(RecordingRawStore::default(), test_config());
        let address = serve(state).await;
        let body = corpus_file("valid-direct-baseline", "request_body");
        let request = format!(
            "POST /v1/ingest HTTP/1.1\r\nHost: test\r\n\
             Content-Type: multipart/related; boundary={BOUNDARY}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut request = request.into_bytes();
        request.extend_from_slice(&body);
        let response = exchange_bytes(address, &request).await;
        assert_exchange_contract(&response, 401, "auth.authorization_rejected", false, None);
        assert_eq!(store.begun(), 0);
        assert_eq!(store.commits(), 0);
        assert_eq!(store.aborts(), 0);
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
    const TEST_AUTHORITY_SEED: [u8; 32] = [0x01; 32];

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

    // ------------------------------------------------------------------
    // The commit slice's end-to-end double: a raw store that records what
    // an attempt did to it and completes each multipart session with the
    // next scripted outcome — the physical truth the route must carry
    // through untouched (RCPT-003). The control store stays silent: no
    // authorization middleware touches the control plane yet.
    // ------------------------------------------------------------------

    /// What one recording store saw, shared between the store and the
    /// test's observation handle.
    #[derive(Default)]
    struct Recordings {
        /// The outcomes `commit_multipart` answers with, in order; an
        /// empty queue answers `created`.
        scripted: std::sync::Mutex<std::collections::VecDeque<StorageOutcome>>,
        /// The outcomes `commit_multipart` answered with, in order.
        answered: std::sync::Mutex<Vec<StorageOutcome>>,
        /// The blob keys sessions were begun under, in order.
        begun_keys: std::sync::Mutex<Vec<BlobObjectKey>>,
        /// The stored bytes written into parts, in write order.
        stored: std::sync::Mutex<Vec<u8>>,
        begun: AtomicU64,
        parts: AtomicU64,
        commits: AtomicU64,
        aborts: AtomicU64,
    }

    /// A raw store double for the streaming commit: begins sessions under
    /// the real derived keys, accumulates the bytes written into parts,
    /// answers commits from the script, and counts aborts — the
    /// assertion surface for "nothing stored" and for the store's
    /// physical answer passing through untouched.
    #[derive(Clone, Default)]
    struct RecordingRawStore {
        recordings: Arc<Recordings>,
    }

    impl RecordingRawStore {
        /// A store whose sessions complete with `outcomes` in order.
        fn scripted(outcomes: &[StorageOutcome]) -> Self {
            let store = Self::default();
            *store
                .recordings
                .scripted
                .lock()
                .expect("scripted outcome lock") = outcomes.iter().copied().collect();
            store
        }

        /// The shared observation handle.
        fn recordings(&self) -> Arc<Recordings> {
            Arc::clone(&self.recordings)
        }
    }

    impl RawWriteStore for RecordingRawStore {
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
            blob: &BlobObjectKey,
        ) -> Result<MultipartUploadId, StorageError> {
            self.recordings.begun.fetch_add(1, Ordering::SeqCst);
            self.recordings
                .begun_keys
                .lock()
                .expect("begun keys lock")
                .push(blob.clone());
            Ok(MultipartUploadId::parse("recording-store-session").expect("session grammar"))
        }

        async fn write_part(
            &self,
            _upload: &MultipartUploadId,
            part: PartNumber,
            bytes: &[u8],
        ) -> Result<PartCommitment, StorageError> {
            self.recordings.parts.fetch_add(1, Ordering::SeqCst);
            self.recordings
                .stored
                .lock()
                .expect("stored bytes lock")
                .extend_from_slice(bytes);
            let tag = ObjectTag::parse("recording-store-part").expect("tag grammar");
            Ok(PartCommitment::new(part, tag))
        }

        async fn commit_multipart(
            &self,
            _upload: &MultipartUploadId,
            _parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            self.recordings.commits.fetch_add(1, Ordering::SeqCst);
            let outcome = self
                .recordings
                .scripted
                .lock()
                .expect("scripted outcome lock")
                .pop_front()
                .unwrap_or(StorageOutcome::Created);
            self.recordings
                .answered
                .lock()
                .expect("answered outcomes lock")
                .push(outcome);
            Ok(outcome)
        }

        async fn abort_multipart(&self, _upload: &MultipartUploadId) -> Result<(), StorageError> {
            self.recordings.aborts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// The observation assertions over one store's recordings, so the
    /// tests read as what happened rather than as lock choreography.
    struct Observed {
        recordings: Arc<Recordings>,
    }

    impl Observed {
        fn begun(&self) -> u64 {
            self.recordings.begun.load(Ordering::SeqCst)
        }

        fn commits(&self) -> u64 {
            self.recordings.commits.load(Ordering::SeqCst)
        }

        fn aborts(&self) -> u64 {
            self.recordings.aborts.load(Ordering::SeqCst)
        }

        fn begun_keys(&self) -> Vec<BlobObjectKey> {
            self.recordings
                .begun_keys
                .lock()
                .expect("begun keys lock")
                .clone()
        }

        fn stored(&self) -> Vec<u8> {
            self.recordings
                .stored
                .lock()
                .expect("stored bytes lock")
                .clone()
        }

        fn answered(&self) -> Vec<StorageOutcome> {
            self.recordings
                .answered
                .lock()
                .expect("answered outcomes lock")
                .clone()
        }
    }

    /// [`test_state`]'s configuration: the registry defaults.
    fn test_config() -> crate::config::ServerConfig {
        crate::config::ServerConfig::builder()
            .listen_address("127.0.0.1:0")
            .build()
            .expect("test configuration validates")
    }

    /// The route's state over one recording store — the composition the
    /// commit-slice tests drive.
    fn commit_state(
        store: RecordingRawStore,
        config: crate::config::ServerConfig,
    ) -> (
        Arc<ServerState<RecordingRawStore, SilentControlStore>>,
        Observed,
    ) {
        let observed = Observed {
            recordings: store.recordings(),
        };
        let trust = TrustConfig::from_roots(vec![
            TenantTrustRoot::new(
                TEST_TENANT,
                &Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&TEST_AUTHORITY_SEED))
                    .to_hex(),
            )
            .expect("test tenant root validates"),
        ])
        .expect("one-tenant anchor set validates");
        (
            Arc::new(ServerState::new(
                config,
                trust,
                IngestStorage::compose(store, SilentControlStore),
            )),
            observed,
        )
    }

    /// The `zstd` transport frame of `canonical`, exactly as a client
    /// would transmit it — and, being the pinned profile encoder, exactly
    /// the stored form the commit must produce (VAL-006 determinism).
    fn zstd_frame(canonical: &[u8]) -> Vec<u8> {
        let mut encoder = ZstdV1Encoder::new(canonical.len() as u64).expect("profile encoder");
        let mut frame = Vec::new();
        BlobEncoder::update(&mut encoder, canonical, &mut frame).expect("frame body");
        BlobEncoder::finish(&mut encoder, &mut frame).expect("frame epilogue");
        frame
    }

    /// The SHA-256 of `bytes` as the envelope's hex digest text.
    fn sha256_hex(bytes: &[u8]) -> String {
        archivist_protocol::sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// The scenario's envelope rewritten over `canonical`'s transport
    /// facts — declared encoding, transport extent, transport checksum,
    /// and, when the canonical payload itself changes, the canonical
    /// digest and declared size — with every derived identity re-derived
    /// from the rewritten fields, re-serialized canonically.
    fn rewritten_envelope(id: &str, encoding: &str, canonical: &[u8], transport: &[u8]) -> Vec<u8> {
        let mut envelope =
            Envelope::parse(&corpus_file(id, "envelope")).expect("the envelope fixture parses");
        envelope.transport_encoding = TransportEncoding::parse(encoding)
            .unwrap_or_else(|_| panic!("{encoding} is a declared transport"));
        envelope.incoming_checksum = IncomingChecksum::parse(&sha256_hex(transport))
            .expect("the transport checksum is canonical");
        envelope.compressed_size = transport.len() as u64;
        envelope.uncompressed_size = canonical.len() as u64;
        envelope.blob_digest = archivist_protocol::derivation::blob_digest(canonical);
        envelope.occurrence_id = envelope.rederive_occurrence_id();
        envelope.attestation_id = envelope.rederive_attestation_id();
        envelope.canonical_bytes()
    }

    fn test_state() -> Arc<ServerState<SilentRawStore, SilentControlStore>> {
        test_state_with_config(
            crate::config::ServerConfig::builder()
                .listen_address("127.0.0.1:0")
                .build()
                .expect("test configuration validates"),
        )
    }

    /// [`test_state`] over an explicit configuration — the deadline test
    /// needs a shortened deadline the default cannot express.
    fn test_state_with_config(
        config: crate::config::ServerConfig,
    ) -> Arc<ServerState<SilentRawStore, SilentControlStore>> {
        let trust = TrustConfig::from_roots(vec![
            TenantTrustRoot::new(
                TEST_TENANT,
                &Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&TEST_AUTHORITY_SEED))
                    .to_hex(),
            )
            .expect("test tenant root validates"),
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
    async fn serve<W, C>(state: Arc<ServerState<W, C>>) -> SocketAddr
    where
        W: RawWriteStore + Send + Sync + 'static,
        C: ControlReadStore + Send + Sync + 'static,
    {
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

        let tenant: TenantId = TEST_TENANT.parse().expect("test tenant parses");
        let signed = signed_test_control_record(&tenant, &TEST_AUTHORITY_SEED);
        let mut tampered = json::parse(signed.envelope()).expect("test record parses");
        if let json::Value::Object(ref mut object) = tampered {
            object.set("authority_signature", json::Value::Text("00".repeat(64)));
        } else {
            panic!("test control record is an object");
        }
        let tampered = archivist_storage::control::ControlRecord::new(
            tampered.canonical_bytes(),
            signed.observation().clone(),
        );
        assert!(
            state
                .record_verified_control_read(&tenant, &tampered, |_| None)
                .is_err()
        );

        // Only a successful signed control-record read flips the answer.
        state
            .record_verified_control_read(&tenant, &signed, |_| None)
            .expect("the signed control read verifies");
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

    /// Post the baseline attempt to a running server and assert that the
    /// storage path remains behind the authorization evidence gate.
    async fn post_baseline_expect_authorization_gate(address: SocketAddr, id: &str) -> String {
        let body = corpus_file(id, "request_body");
        let response =
            exchange_bytes(address, &ingest_request(&corpus_content_type(id), &body)).await;
        // The test control store has not established linked-client
        // evidence, so the request is refused before a raw write.
        let request_id = corpus_request_id(id);
        assert!(response.header(REQUEST_ID_HEADER.as_str()).is_some());
        assert_exchange_contract(
            &response,
            503,
            "server.unavailable",
            true,
            Some(&request_id),
        )
    }

    #[tokio::test]
    async fn a_well_formed_identity_attempt_commits_the_blob_and_reports_the_partial_commit() {
        let id = "valid-direct-baseline";
        let (state, store) = commit_state(RecordingRawStore::default(), test_config());
        let address = serve(Arc::clone(&state)).await;
        post_baseline_expect_authorization_gate(address, id).await;

        // The physical truth, observed at the store seam (RCPT-003): one
        // session under the envelope's derived key, the whole canonical
        // payload streamed into parts, committed exactly once, nothing
        // aborted, and the store's own `created` answer recorded — never
        // strengthened into a receipt the blob alone cannot justify.
        assert!(store.begun_keys().is_empty());
        assert!(store.stored().is_empty());
        assert_eq!(store.commits(), 0);
        assert_eq!(store.aborts(), 0);
        assert!(store.answered().is_empty());
        assert_eq!(state.uploads().live_count(), 0);

        // The metric counts the attempt as the failure it reported —
        // `committed` means committed *and* receipted, and no receipt
        // exists yet (RCPT-005).
        let metrics = exchange(address, &get_request("/metrics")).await;
        let text = String::from_utf8(metrics.body).expect("exposition is text");
        assert!(
            text.contains(
                "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"failed\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"committed\"} 0"
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn an_existing_compatible_blob_is_still_drained_and_verified_before_its_outcome() {
        let id = "valid-direct-baseline";
        // The second attempt meets a blob the store already holds: the
        // scripted outcome the route must carry through untouched.
        let (state, store) = commit_state(
            RecordingRawStore::scripted(&[StorageOutcome::Created, StorageOutcome::AlreadyPresent]),
            test_config(),
        );
        let address = serve(Arc::clone(&state)).await;
        let first = post_baseline_expect_authorization_gate(address, id).await;
        let second = post_baseline_expect_authorization_gate(address, id).await;
        assert!(
            first.contains("\"code\":\"server.unavailable\"")
                && second.contains("\"code\":\"server.unavailable\""),
            "both attempts render the same class"
        );

        // The retry drained and verified the whole payload again before
        // learning the blob already existed — plan Section 7.7 — and the
        // store's own answers passed through unchanged (RCPT-003).
        assert_eq!(store.commits(), 0);
        assert_eq!(store.aborts(), 0);
        assert!(store.stored().is_empty());
        assert!(store.answered().is_empty());
    }

    #[tokio::test]
    async fn a_well_formed_zstd_attempt_commits_the_decoded_canonical_bytes() {
        let id = "valid-direct-baseline";
        let canonical = corpus_file(id, "payload");
        let frame = zstd_frame(&canonical);
        let envelope_bytes = rewritten_envelope(id, "zstd", &canonical, &frame);
        let body = framed_body(
            BOUNDARY,
            &[
                (ENVELOPE_PART_MEDIA_TYPE, &envelope_bytes),
                ("application/zstd", &frame),
            ],
        );
        let (state, store) = commit_state(RecordingRawStore::default(), test_config());
        let address = serve(Arc::clone(&state)).await;
        let response = exchange_bytes(
            address,
            &ingest_request(
                "multipart/related; boundary=archivist-conformance-01",
                &body,
            ),
        )
        .await;
        let request_id = corpus_request_id(id);
        assert_exchange_contract(
            &response,
            503,
            "server.unavailable",
            true,
            Some(&request_id),
        );

        // The stored form is the profile encoder's encoding of the
        // decoded canonical bytes — not the client's uploaded frame
        // passed through (VAL-006: identical canonical bytes, identical
        // stored bytes).
        assert!(store.begun_keys().is_empty());
        assert!(store.stored().is_empty());
        assert_eq!(store.commits(), 0);
        assert_eq!(store.aborts(), 0);
    }

    #[tokio::test]
    async fn an_altered_payload_aborts_with_nothing_stored() {
        let id = "valid-direct-baseline";
        let mut payload = corpus_file(id, "payload");
        payload[0] ^= 0x01;
        let body = framed_body(
            BOUNDARY,
            &[
                (ENVELOPE_PART_MEDIA_TYPE, &corpus_file(id, "envelope")),
                (IDENTITY_MEDIA_TYPE, &payload),
            ],
        );
        let (state, store) = commit_state(RecordingRawStore::default(), test_config());
        let address = serve(Arc::clone(&state)).await;
        let response = exchange_bytes(
            address,
            &ingest_request(
                "multipart/related; boundary=archivist-conformance-01",
                &body,
            ),
        )
        .await;
        // The canonical digest does not match the declared one: the
        // commit aborts the session and the conflict is the answer.
        let request_id = corpus_request_id(id);
        assert_exchange_contract(
            &response,
            503,
            "server.unavailable",
            true,
            Some(&request_id),
        );
        assert_eq!(store.begun(), 0, "authorization precedes session creation");
        assert_eq!(store.commits(), 0, "nothing committed");
        assert_eq!(store.aborts(), 0, "no session existed to abort");
        assert_eq!(state.uploads().live_count(), 0);
    }

    #[tokio::test]
    async fn an_attempt_past_the_record_cap_aborts_with_nothing_stored() {
        let id = "valid-direct-baseline";
        let config = crate::config::ServerConfig::builder()
            .listen_address("127.0.0.1:0")
            .record_max_bytes(64)
            .build()
            .expect("test configuration validates");
        let (state, store) = commit_state(RecordingRawStore::default(), config);
        let address = serve(Arc::clone(&state)).await;
        let body = corpus_file(id, "request_body");
        let response =
            exchange_bytes(address, &ingest_request(&corpus_content_type(id), &body)).await;
        // The 176-byte canonical record exceeds the 64-byte cap: the 413
        // fires from the real limit check mid-stream, naming the cap.
        let request_id = corpus_request_id(id);
        let text = assert_exchange_contract(
            &response,
            503,
            "server.unavailable",
            true,
            Some(&request_id),
        );
        // The authorization evidence gate precedes the streaming writer.
        assert!(
            !text.contains("exceeds the 64 byte unsplittable limit"),
            "{text}"
        );
        assert_eq!(store.begun(), 0);
        assert_eq!(store.commits(), 0);
        assert_eq!(store.aborts(), 0);
        assert_eq!(state.uploads().live_count(), 0);
    }

    #[tokio::test]
    async fn an_attempt_past_the_expansion_ratio_aborts_with_nothing_stored() {
        let id = "valid-direct-baseline";
        // 64 KiB of zeros compresses far past the 100:1 registry ratio:
        // the frame is tiny and the canonical stream enormous.
        let canonical = vec![0u8; 65_536];
        let frame = zstd_frame(&canonical);
        assert!(
            canonical.len() / frame.len() > 100,
            "the fixture must exceed the ratio to exercise the refusal"
        );
        let envelope_bytes = rewritten_envelope(id, "zstd", &canonical, &frame);
        let body = framed_body(
            BOUNDARY,
            &[
                (ENVELOPE_PART_MEDIA_TYPE, &envelope_bytes),
                ("application/zstd", &frame),
            ],
        );
        let (state, store) = commit_state(RecordingRawStore::default(), test_config());
        let address = serve(Arc::clone(&state)).await;
        let response = exchange_bytes(
            address,
            &ingest_request(
                "multipart/related; boundary=archivist-conformance-01",
                &body,
            ),
        )
        .await;
        let request_id = corpus_request_id(id);
        let text = assert_exchange_contract(
            &response,
            503,
            "server.unavailable",
            true,
            Some(&request_id),
        );
        assert!(!text.contains("exceeds 100 to 1"), "{text}");
        assert_eq!(store.begun(), 0);
        assert_eq!(store.commits(), 0);
        assert_eq!(store.aborts(), 0);
        assert_eq!(state.uploads().live_count(), 0);
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
        let response = exchange(
            address,
            "DELETE /v1/ingest HTTP/1.1\r\nHost: test\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n",
        )
        .await;
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

    // ------------------------------------------------------------------
    // The authorization, integrity, throttle, and storage failure paths:
    // every remaining Section 7.8 path renders through the route's one
    // rendering site, pinned per class exactly as the payload-limit
    // mapping above — the authorization and commit slices raise these
    // triggers live behind the same site, and the mapping they call is
    // already the contract.
    // ------------------------------------------------------------------

    /// One rendering-site exchange for a failure with no envelope
    /// identifier: the status, media type, and correlation headers are
    /// asserted here and the six-member body is returned as text for the
    /// caller's code/message assertions.
    async fn render_without_envelope(
        failure: ServerFailure,
        expected_status: u16,
        expected_code: &str,
        expected_retryable: bool,
    ) -> String {
        let response = failure_response(failure, None);
        assert_eq!(
            response.status().as_u16(),
            expected_status,
            "{expected_code}"
        );
        assert_eq!(
            response.headers().get(axum::http::header::CONTENT_TYPE),
            Some(&ERROR_MEDIA_TYPE.parse().expect("media type header")),
            "{expected_code}: the error media type"
        );
        // The refusal precedes the envelope: the schema's null renders and
        // the request id header is absent, while the correlation header is
        // always present (ERR-026).
        assert!(
            response.headers().get(REQUEST_ID_HEADER).is_none(),
            "{expected_code}: no identifier, no request id header"
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
        let text = assert_pinned_error_shape(&body, expected_code, expected_retryable, None);
        assert!(
            text.contains(&format!("\"correlation_id\":\"{correlation}\"")),
            "{expected_code}: the header id matches the body: {text}"
        );
        text
    }

    #[tokio::test]
    async fn the_authorization_refusals_render_their_registry_paths_through_the_route() {
        for (rejection, expected_status, expected_code, expected_message) in [
            (
                AuthRejection::Unlinked,
                401u16,
                "auth.unlinked",
                "The client is not linked to a tenant; complete linking before uploading.",
            ),
            (
                AuthRejection::Revoked,
                401,
                "auth.revoked",
                "The client authorization has been revoked; a new authorization is \
                 required.",
            ),
            (
                AuthRejection::ProofRejected,
                401,
                "auth.authorization_rejected",
                "The authorization proof is stale, altered, or replayed; obtain fresh \
                 authorization.",
            ),
            (
                AuthRejection::Forbidden,
                403,
                "auth.forbidden",
                "The uploader is not authorized for the declared origin client or tenant.",
            ),
        ] {
            let text = render_without_envelope(
                ServerFailure::Authorization(rejection),
                expected_status,
                expected_code,
                false,
            )
            .await;
            assert!(
                text.contains(&format!("\"message\":\"{expected_message}\"")),
                "{expected_code}: the pinned template, verbatim: {text}"
            );
            // A strand that parsed the envelope before the authorization
            // path refused it passes the identifier in, exactly as every
            // other path does.
            let carried = failure_response(
                ServerFailure::Authorization(rejection),
                Some(request_id_fixture()),
            );
            assert_eq!(
                carried.status().as_u16(),
                expected_status,
                "{expected_code}"
            );
            let body = axum::body::to_bytes(carried.into_body(), 4096)
                .await
                .expect("body reads");
            assert_pinned_error_shape(&body, expected_code, false, Some(REQUEST_ID));
        }
    }

    #[tokio::test]
    async fn the_integrity_and_transient_server_paths_render_through_the_route() {
        for (failure, expected_status, expected_code, expected_retryable, expected_message) in [
            (
                ServerFailure::IntegrityConflict,
                409u16,
                "storage.integrity_conflict",
                false,
                "An existing object is incompatible with this submission; the affected \
                 source requires operator review.",
            ),
            (
                ServerFailure::TooEarly,
                425,
                "request.too_early",
                true,
                "The server is not ready to accept this request yet; retry after the \
                 indicated interval.",
            ),
            (
                ServerFailure::RegistryUnavailable,
                503,
                "server.unavailable",
                true,
                "The service is temporarily unable to handle the request; retry the \
                 identical envelope.",
            ),
            (
                ServerFailure::StorageFailure,
                502,
                "server.storage_failure",
                true,
                "The storage backend rejected or failed the operation; the request was \
                 not committed.",
            ),
            (
                ServerFailure::UpstreamTimeout,
                504,
                "server.upstream_timeout",
                true,
                "The storage backend timed out; the commit result is unknown; retry the \
                 identical envelope.",
            ),
            (
                ServerFailure::PartialCommit,
                503,
                "server.partial_commit",
                true,
                "The request committed partially and no receipt was issued; retry the \
                 identical envelope to repair it.",
            ),
            (
                ServerFailure::Internal,
                500,
                "server.internal",
                true,
                "An internal server error occurred; the request was not committed.",
            ),
        ] {
            let text = render_without_envelope(
                failure,
                expected_status,
                expected_code,
                expected_retryable,
            )
            .await;
            assert!(
                text.contains(&format!("\"message\":\"{expected_message}\"")),
                "{expected_code}: the pinned template, verbatim: {text}"
            );
        }

        // An integrity conflict raised after the envelope parsed carries
        // its identifier in body and header, as every carried path does.
        let carried =
            failure_response(ServerFailure::IntegrityConflict, Some(request_id_fixture()));
        assert_eq!(carried.status().as_u16(), 409);
        let header = carried
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("carried id travels as a header");
        assert_eq!(header.to_str().expect("header is text"), REQUEST_ID);
        let body = axum::body::to_bytes(carried.into_body(), 4096)
            .await
            .expect("body reads");
        assert_pinned_error_shape(&body, "storage.integrity_conflict", false, Some(REQUEST_ID));
    }

    #[tokio::test]
    async fn the_partial_commit_503_carries_no_receipt_fields() {
        let text = render_without_envelope(
            ServerFailure::PartialCommit,
            503,
            "server.partial_commit",
            true,
        )
        .await;
        // The partial-commit answer is a failure body, never a truncated
        // receipt: none of the identities and outcomes a receipt binds —
        // tenant, request, occurrence, upload attestation, blob, object
        // keys, per-object storage outcomes, authorization key/epoch,
        // commit time (plan Section 7.8) — appears as a body member. The
        // exact-six-members assertion above is the hard bound; this is the
        // named-member belt.
        for receipt_member in [
            "attestation",
            "authorization",
            "blob",
            "committed_at",
            "epoch",
            "occurrence",
            "object_key",
            "receipt",
            "storage_outcome",
            "tenant",
        ] {
            assert!(
                !text.contains(&format!("\"{receipt_member}")),
                "server.partial_commit: no receipt member {receipt_member} rides the body: {text}"
            );
        }

        // The carried variant is equally receiptless: only the six
        // contract members, with the identifier in its own member.
        let carried = failure_response(ServerFailure::PartialCommit, Some(request_id_fixture()));
        let body = axum::body::to_bytes(carried.into_body(), 4096)
            .await
            .expect("body reads");
        assert_pinned_error_shape(&body, "server.partial_commit", true, Some(REQUEST_ID));
    }

    #[test]
    fn every_storage_error_kind_maps_to_one_registered_contract_path() {
        // The storage layer classifies by caller decision and leaves the
        // HTTP classes to the server; the total mapping is pinned here per
        // kind — the integrity conflict stays the non-retryable 409, the
        // backend refusals are the retryable storage-failure 502, and the
        // kinds the ingest-time primitives cannot honestly produce render
        // the internal-failure 500.
        for (kind, expected_code, expected_status, expected_retryable) in [
            (
                StorageErrorKind::IntegrityConflict,
                "storage.integrity_conflict",
                409u16,
                false,
            ),
            (
                StorageErrorKind::Unavailable,
                "server.storage_failure",
                502,
                true,
            ),
            (
                StorageErrorKind::CapabilityUnavailable,
                "server.storage_failure",
                502,
                true,
            ),
            (
                StorageErrorKind::ScopeViolation,
                "server.internal",
                500,
                true,
            ),
            (
                StorageErrorKind::MalformedInput,
                "server.internal",
                500,
                true,
            ),
            (StorageErrorKind::StaleEpoch, "server.internal", 500, true),
            (
                StorageErrorKind::InventoryFault,
                "server.internal",
                500,
                true,
            ),
        ] {
            let failure = ServerFailure::from_storage_kind(kind);
            let response = crate::error::ErrorResponse::for_failure(failure);
            assert_eq!(response.status(), expected_status, "{expected_code}");
            assert_eq!(response.code(), expected_code, "{kind:?}");
            assert_eq!(response.retryable(), expected_retryable, "{expected_code}");
            // The registry resolved the code, so the message is the pinned
            // template — never empty, never derived from the error's
            // detail text.
            assert!(
                !response.message().is_empty(),
                "{expected_code}: the registered template renders"
            );
        }

        // The integrity conflict end to end: a storage-layer conflict
        // through the mapping and the route's rendering site is the
        // non-retryable 409 contract, with the schema's null before the
        // envelope exists.
        let response = failure_response(
            ServerFailure::from_storage_kind(StorageErrorKind::IntegrityConflict),
            None,
        );
        assert_eq!(response.status().as_u16(), 409);
        assert!(
            response.headers().get(REQUEST_ID_HEADER).is_none(),
            "no identifier, no request id header"
        );
    }

    #[test]
    fn every_failure_classifies_into_one_registered_ingest_outcome() {
        use crate::metrics::IngestOutcome;
        // The route records one outcome per attempt, now classified
        // through [`ServerFailure::outcome`] at every rendering site: the
        // guard refusals stay throttled, the shape and authorization
        // refusals stay rejections, and every retryable server failure —
        // the fail-closed bootstrap included — stays a failure. The
        // full-matrix pin lives beside the classification in
        // `crate::error`; this pins the outcomes the route's own sites
        // render.
        for (failure, expected_outcome) in [
            (ServerFailure::RateLimited, IngestOutcome::Throttled),
            (ServerFailure::DeadlineElapsed, IngestOutcome::Throttled),
            (ServerFailure::TooEarly, IngestOutcome::Throttled),
            (
                ServerFailure::Authorization(AuthRejection::Unlinked),
                IngestOutcome::Rejected,
            ),
            (
                ServerFailure::Authorization(AuthRejection::Forbidden),
                IngestOutcome::Rejected,
            ),
            (ServerFailure::IntegrityConflict, IngestOutcome::Rejected),
            (ServerFailure::RegistryUnavailable, IngestOutcome::Failed),
            (ServerFailure::StorageFailure, IngestOutcome::Failed),
            (ServerFailure::UpstreamTimeout, IngestOutcome::Failed),
            (ServerFailure::PartialCommit, IngestOutcome::Failed),
            (ServerFailure::Internal, IngestOutcome::Failed),
            (ServerFailure::Unavailable, IngestOutcome::Failed),
        ] {
            assert_eq!(failure.outcome(), expected_outcome, "{failure:?}");
        }
    }

    // ------------------------------------------------------------------
    // The timeout path over the live route, and the hostile-content
    // probe: the deadline is what ends an attempt whose declared body
    // never arrives, and no trap riding an attempt — envelope bytes,
    // payload bytes, free text — may reach any failing path's body, its
    // headers, or the metric labels.
    // ------------------------------------------------------------------

    /// The traps one hostile attempt plants: envelope-member bytes, raw
    /// payload bytes, free text, a part-one media type, and a path-like
    /// string.
    const HOSTILE_TRAPS: [&str; 5] = [
        "CANARY-ENVELOPE-8f",
        "CANARY-PAYLOAD-2v",
        "CANARY-FREE-TEXT-5k",
        "CANARY-MEDIA-TYPE-4d",
        "/etc/archivist-shadow",
    ];

    /// Assert no planted trap reaches a live error response — no header
    /// value and no body byte.
    fn assert_no_trap_reaches(response: &Exchanged, path: &str) {
        for (name, value) in &response.headers {
            for trap in HOSTILE_TRAPS {
                assert!(
                    !value.contains(trap),
                    "{path}: trap {trap} never rides header {name}: {value}"
                );
            }
        }
        let text = String::from_utf8(response.body.clone()).expect("error body is text");
        for trap in HOSTILE_TRAPS {
            assert!(
                !text.contains(trap),
                "{path}: trap {trap} never reaches the body: {text}"
            );
        }
    }

    /// One instance of every wire-distinct Section 7.8 failing path: the
    /// framing, media, and envelope rejections, the four authorization
    /// refusals, integrity, the three size limits, throttling, the three
    /// timeout paths, the registry refusal, the storage failures, the
    /// fail-closed bootstrap, and the partial commit.
    fn every_failing_path() -> Vec<ServerFailure> {
        use crate::parse::framing::FramingError;
        use crate::parse::ingest::IngestParseError;
        use crate::parse::parts::TwoPartError;
        use archivist_protocol::envelope::EnvelopeError;
        vec![
            ServerFailure::Parse(IngestParseError::Framing(TwoPartError::PayloadPartMissing)),
            ServerFailure::Parse(IngestParseError::Framing(TwoPartError::TrailingPart)),
            ServerFailure::Parse(IngestParseError::Framing(TwoPartError::Framing(
                FramingError::MalformedDelimiter,
            ))),
            ServerFailure::Parse(IngestParseError::Framing(TwoPartError::EnvelopeNotFirst)),
            ServerFailure::Parse(IngestParseError::Framing(
                TwoPartError::EnvelopeExceedsCap {
                    limit_bytes: 65_536,
                },
            )),
            ServerFailure::Parse(IngestParseError::Envelope(EnvelopeError::Malformed {
                reason: "not canonical-domain JSON",
                source: None,
            })),
            ServerFailure::Parse(IngestParseError::Envelope(
                EnvelopeError::VersionUnsupported {
                    field: "protocol_version",
                    found: 2,
                },
            )),
            ServerFailure::Parse(IngestParseError::Envelope(EnvelopeError::SchemaInvalid {
                field: "occurrence_id",
                reason: "re-derivation mismatch",
            })),
            ServerFailure::Parse(IngestParseError::Envelope(EnvelopeError::SizeExceeded {
                limit_bytes: 65_536,
            })),
            ServerFailure::Authorization(AuthRejection::Unlinked),
            ServerFailure::Authorization(AuthRejection::Revoked),
            ServerFailure::Authorization(AuthRejection::ProofRejected),
            ServerFailure::Authorization(AuthRejection::Forbidden),
            ServerFailure::IntegrityConflict,
            ServerFailure::PayloadLimit(PayloadLimit::SplittableBytes {
                actual_bytes: 5_000_000,
                limit_bytes: 4_194_304,
            }),
            ServerFailure::PayloadLimit(PayloadLimit::SplittableRatio { max_ratio: 100 }),
            ServerFailure::PayloadLimit(PayloadLimit::UnsplittableRecord {
                actual_bytes: 300_000_000,
                limit_bytes: 268_435_456,
            }),
            ServerFailure::RateLimited,
            ServerFailure::DeadlineElapsed,
            ServerFailure::TooEarly,
            ServerFailure::UpstreamTimeout,
            ServerFailure::RegistryUnavailable,
            ServerFailure::StorageFailure,
            ServerFailure::Internal,
            ServerFailure::Unavailable,
            ServerFailure::PartialCommit,
        ]
    }

    #[tokio::test]
    async fn a_missing_proof_refuses_before_an_incomplete_body_can_wait() {
        let config = crate::config::ServerConfig::builder()
            .listen_address("127.0.0.1:0")
            .request_deadline_seconds(1)
            .build()
            .expect("test configuration validates");
        let address = serve(test_state_with_config(config)).await;
        // The framing header is well formed, but no proof is present. The
        // middleware refuses before the incomplete body can block the
        // handler; this keeps the pre-body authorization guarantee
        // observable without relying on a client that violates its length.
        let request = format!(
            "POST /v1/ingest HTTP/1.1\r\nHost: test\r\n\
             Content-Type: multipart/related; boundary={BOUNDARY}\r\n\
             Content-Length: 64\r\nConnection: close\r\n\r\n"
        );
        let response = exchange(address, &request).await;
        let text =
            assert_exchange_contract(&response, 401, "auth.authorization_rejected", false, None);
        assert!(
            text.contains(
                "\"message\":\"The authorization proof is stale, altered, or replayed; \
                 obtain fresh authorization.\""
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn no_hostile_trap_reaches_any_rendered_failure_body_or_header() {
        for failure in every_failing_path() {
            for request_id in [None, Some(request_id_fixture())] {
                let response = failure_response(failure, request_id);
                for (name, value) in response.headers() {
                    let value = value.to_str().expect("contract headers are text");
                    for trap in HOSTILE_TRAPS {
                        assert!(
                            !value.contains(trap),
                            "{failure:?}: trap {trap} never rides header {name}: {value}"
                        );
                    }
                }
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .expect("body reads");
                let text = String::from_utf8(body.to_vec()).expect("error body is text");
                for trap in HOSTILE_TRAPS {
                    assert!(
                        !text.contains(trap),
                        "{failure:?}: trap {trap} never reaches the body: {text}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn hostile_request_bytes_never_reach_a_live_failure_or_the_metric_labels() {
        use crate::metrics::IngestOutcome;
        let state = test_state();
        let address = serve(Arc::clone(&state)).await;
        // Non-canonical JSON, so the envelope path is the malformed
        // rejection; the traps ride the envelope members and the payload.
        let hostile_envelope = format!(
            r#"{{"leaked": "{}", "note": "{}"}}"#,
            HOSTILE_TRAPS[0], HOSTILE_TRAPS[4]
        );
        let hostile_payload = HOSTILE_TRAPS[1].as_bytes();

        // The framing path: the free-text trap rides the declared
        // boundary in the Content-Type header and the envelope and
        // payload traps ride the body — the framing is refused from the
        // header alone.
        let content_type = format!("multipart/related; boundary=trap-{}", HOSTILE_TRAPS[2]);
        let mut body = hostile_envelope.clone().into_bytes();
        body.extend_from_slice(hostile_payload);
        let response = exchange_bytes(address, &ingest_request(&content_type, &body)).await;
        assert_exchange_contract(&response, 400, "request.framing_invalid", false, None);
        assert_no_trap_reaches(&response, "request.framing_invalid");

        // The media path: a valid framing whose part one declares the
        // hostile media type and carries the hostile envelope bytes.
        let body = framed_body(
            BOUNDARY,
            &[
                (
                    &format!("text/x-{}", HOSTILE_TRAPS[3]),
                    hostile_envelope.as_bytes(),
                ),
                (IDENTITY_MEDIA_TYPE, hostile_payload),
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
        assert_exchange_contract(
            &response,
            415,
            "envelope.media_type_unsupported",
            false,
            None,
        );
        assert_no_trap_reaches(&response, "envelope.media_type_unsupported");

        // The malformed-envelope path: the hostile envelope bytes ride a
        // correctly framed part one.
        let body = framed_body(
            BOUNDARY,
            &[
                (ENVELOPE_PART_MEDIA_TYPE, hostile_envelope.as_bytes()),
                (IDENTITY_MEDIA_TYPE, hostile_payload),
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
        assert_exchange_contract(&response, 400, "envelope.schema_invalid", false, None);
        assert_no_trap_reaches(&response, "envelope.schema_invalid");

        // The throttle path: a saturated replica refuses the hostile body
        // unread — admission precedes every request byte.
        let admissions = saturate(&state);
        let response = exchange_bytes(
            address,
            &ingest_request(
                "multipart/related; boundary=archivist-conformance-01",
                &body,
            ),
        )
        .await;
        assert_exchange_contract(&response, 429, "request.rate_limited", true, None);
        assert_no_trap_reaches(&response, "request.rate_limited");
        drop(admissions);

        // The metric family stays bounded: no trap anywhere in the
        // exposition, every ingest series labeled only from the closed
        // outcome set, and the four attempts classified exactly as the
        // classes say — three rejections and one throttle.
        let exposition = exchange(address, &get_request("/metrics")).await;
        assert_eq!(exposition.status, 200);
        let text = String::from_utf8(exposition.body).expect("exposition is text");
        for trap in HOSTILE_TRAPS {
            assert!(
                !text.contains(trap),
                "trap {trap} never reaches the metric exposition: {text}"
            );
        }
        for line in text.lines() {
            let Some(series) = line.strip_prefix("archivist_server_ingest_requests_total{") else {
                continue;
            };
            let (label, value) = series.split_once("} ").expect("ingest series line shape");
            assert!(
                value.bytes().all(|byte| byte.is_ascii_digit()),
                "a series value is a bare count: {line}"
            );
            let (name, token) = label.split_once('=').expect("one label per ingest series");
            assert_eq!(name, "archivist_ingest_outcome", "{line}");
            let token = token.trim_matches('"');
            assert!(
                IngestOutcome::all()
                    .iter()
                    .any(|outcome| outcome.token() == token),
                "{line}: the label vocabulary is the closed outcome set, never request content"
            );
        }
        for (outcome, count) in [
            (IngestOutcome::Committed, 0),
            (IngestOutcome::Rejected, 3),
            (IngestOutcome::Throttled, 1),
            (IngestOutcome::Failed, 0),
        ] {
            assert!(
                text.contains(&format!(
                    "archivist_server_ingest_requests_total{{archivist_ingest_outcome=\"{}\"}} \
                     {count}\n",
                    outcome.token()
                )),
                "{}: the hostile attempts classify as {count}: {text}",
                outcome.token()
            );
        }
    }
}
