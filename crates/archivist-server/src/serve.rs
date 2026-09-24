// SPDX-License-Identifier: Apache-2.0

//! Cancellation-aware startup: bind the validated configuration to a
//! socket, serve the registered routes, and shut down on command.
//!
//! The lifecycle is three steps, each fail-safe:
//!
//! 1. [`ArchivistServer::new`] composes the validated configuration, the
//!    trust anchors, and the two storage identities. It performs no I/O:
//!    an invalid combination is impossible here because every part
//!    already validated in its own module.
//! 2. [`ArchivistServer::bind`] opens the listening socket. Binding is
//!    the first syscall the replica makes and it allocates nothing
//!    durable — a replica that fails to bind leaves a world identical to
//!    the one it found.
//! 3. [`BoundServer::serve`] runs until the cancellation signal fires.
//!    Serving before the signal is unbounded — the window says nothing
//!    about uptime. When the signal fires it first stops acceptance,
//!    then in-flight work has the configured
//!    `server.shutdown_drain_seconds` window (plan Phase 4); the window
//!    starts at the signal and is a hard bound on the drain alone, so a
//!    stalled drain cannot hold the process past it. When the window
//!    elapses the drain ends in [`ShutdownOutcome::DrainTimedOut`] and
//!    the caller — the composition root — decides the exit.
//!
//!    The run's last step is the plan's multipart-abort step ("abort
//!    unfinished multipart uploads, and exit nonzero if an abort
//!    fails"): after the drain, on either verdict, the gauge moves to
//!    [`ShutdownPhase::Aborting`] and every session the run left
//!    registered as abandoned is aborted against the raw writer
//!    ([`archivist_storage::multipart::OpenUploads::abort_abandoned`]).
//!    A failed abort ends the run in [`ShutdownOutcome::AbortsFailed`]
//!    — the nonzero exit [`ShutdownOutcome::exit_code`] reports — and
//!    the failed sessions stay registered so a later drain retries
//!    them. What a forced termination orphans beyond this process's
//!    reach — a backend session whose identifier never reached the
//!    registry, one still owned by a writer finishing past the drain —
//!    is the deployment's 24-hour incomplete-multipart lifecycle rule's
//!    to reap (plan Section 7.7).
//!
//! Cancellation is a plain channel: [`shutdown_channel`] hands out one
//! trigger and one signal, the composition root wires the trigger to
//! [`shutdown_on_signal`] (SIGTERM/SIGINT) or its own supervision, and
//! tests fire it directly. There is no implicit signal handling — a
//! replica shuts down exactly when its operator says so.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::time::Duration;

use archivist_storage::commit::ConditionalCreateStore;
use archivist_storage::control::ControlReadStore;
use archivist_storage::ingest::IngestStorage;
use archivist_storage::raw_write::RawWriteStore;
use tokio::sync::watch;

use crate::config::ServerConfig;
use crate::metrics::ShutdownPhase;
use crate::routes;
use crate::state::ServerState;
use crate::trust::TrustConfig;

/// Why a replica failed to start: the one failure binding can produce.
///
/// The socket address is the replica's own deployment configuration —
/// echoing it names the failing resource, never a secret. The OS error
/// travels as the [`std::error::Error::source`], not as formatted text
/// this type owns.
#[derive(Debug)]
pub struct StartupError {
    address: SocketAddr,
    source: io::Error,
}

impl StartupError {
    /// The address the replica failed to bind.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to bind the ingest listener on {}", self.address)
    }
}

impl std::error::Error for StartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// How a serve run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShutdownOutcome {
    /// The cancellation fired and every in-flight request drained inside
    /// the configured window.
    Drained,
    /// The drain window elapsed with work still in flight; the process
    /// stopped waiting. Callers exiting the process treat this as the
    /// nonzero exit the plan reserves for an unfinished shutdown.
    DrainTimedOut,
    /// The multipart-abort step ran and at least one abandoned session
    /// could not be aborted — the nonzero exit the plan pins to a
    /// failed abort. The failed sessions stay registered, so a later
    /// drain retries them.
    AbortsFailed,
}

impl ShutdownOutcome {
    /// The exit code the plan pins to this outcome: a drained run exits
    /// zero, and a drain that outlived its window or an abort that
    /// failed exits nonzero ("stop accepting requests, drain for 30
    /// seconds, then abort unfinished multipart uploads and exit
    /// nonzero if an abort fails" — plan Phase 4).
    ///
    /// An abort failure outranks a timed-out drain in the reported
    /// outcome — the abort is the run's last step and the narrower fact
    /// — but both are nonzero, so a caller acting on the code alone
    /// acts identically.
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Drained => 0,
            Self::DrainTimedOut | Self::AbortsFailed => 1,
        }
    }
}

/// One replica ready to bind: the validated parts, held.
pub struct ArchivistServer<W, C> {
    config: ServerConfig,
    trust: TrustConfig,
    storage: IngestStorage<W, C>,
}

impl<W, C> ArchivistServer<W, C>
where
    W: RawWriteStore + ConditionalCreateStore + Send + Sync + 'static,
    C: ControlReadStore + Send + Sync + 'static,
{
    /// Compose a replica from validated parts. No I/O, no allocation of
    /// request-scale resources, nothing durable.
    #[must_use]
    pub fn new(config: ServerConfig, trust: TrustConfig, storage: IngestStorage<W, C>) -> Self {
        Self {
            config,
            trust,
            storage,
        }
    }

    /// The validated configuration this replica will serve under.
    #[must_use]
    pub const fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The trust anchor set this replica serves.
    #[must_use]
    pub const fn trust(&self) -> &TrustConfig {
        &self.trust
    }

    /// The two storage identities this replica was given.
    #[must_use]
    pub const fn storage(&self) -> &IngestStorage<W, C> {
        &self.storage
    }

    /// Open the listening socket.
    ///
    /// # Errors
    /// [`StartupError`] when the configured address cannot be bound —
    /// in use, denied, or unroutable. The failure is the caller's to
    /// report; nothing has been started and nothing must be cleaned up.
    pub fn bind(self) -> Result<BoundServer<W, C>, StartupError> {
        let address = self.config.listen_address();
        let listener =
            StdListener::bind(address).map_err(|source| StartupError { address, source })?;
        // Hand the socket to tokio inside `serve`; marking it
        // non-blocking here is the conversion tokio requires and cannot
        // fail for a freshly bound listener.
        listener
            .set_nonblocking(true)
            .map_err(|source| StartupError { address, source })?;
        let state = Arc::new(ServerState::new(self.config, self.trust, self.storage));
        Ok(BoundServer { listener, state })
    }
}

/// A bound replica: the socket, the shared state, and nothing else.
pub struct BoundServer<W, C> {
    listener: StdListener,
    state: Arc<ServerState<W, C>>,
}

impl<W, C> BoundServer<W, C>
where
    W: RawWriteStore + ConditionalCreateStore + Send + Sync + 'static,
    C: ControlReadStore + Send + Sync + 'static,
{
    /// The address the replica is listening on — the configured
    /// address, or the ephemeral one the OS chose when the configuration
    /// binds port 0 (as the test suite does).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .unwrap_or(self.state.config().listen_address())
    }

    /// The shared state: readiness evidence and metrics are driven
    /// through it by the tests and by the slices to come.
    #[must_use]
    pub fn state(&self) -> &Arc<ServerState<W, C>> {
        &self.state
    }

    /// Serve until the cancellation signal fires.
    ///
    /// The run has three steps. Before the signal there is no bound: the
    /// replica serves for as long as its operator says so, however many
    /// drain windows that spans. When the shutdown future resolves,
    /// acceptance stops, the gauge moves to `draining`, and the
    /// remaining in-flight work has the configured drain window — a hard
    /// bound on that phase alone. The run's last step, on either drain
    /// verdict, is the multipart-abort step: the gauge moves to
    /// `aborting`, every session registered as abandoned is aborted
    /// against the raw writer, and a failed abort ends the run in
    /// [`ShutdownOutcome::AbortsFailed`].
    ///
    /// # Errors
    /// An I/O failure handing the socket to the async runtime or in the
    /// accept loop itself — the socket died underneath the server. That
    /// failure ends the run before the shutdown sequence begins, and
    /// its I/O error is the outcome the caller reports; whatever the
    /// run leaves registered is abandoned with the process, and the
    /// backend sessions it names are the deployment's 24-hour
    /// incomplete-multipart lifecycle rule's to reap.
    pub async fn serve(
        self,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<ShutdownOutcome> {
        let state = self.state;
        let drain = state.config().shutdown_drain();
        state.metrics().set_shutdown_phase(ShutdownPhase::Running);

        // The cancellation future is observed twice: axum's graceful
        // machinery drains on its completion, and the fired channel
        // marks the instant the drain window starts.
        let (fired_tx, mut fired_rx) = watch::channel(false);
        let drain_state = Arc::clone(&state);
        let cancellation = async move {
            shutdown.await;
            let _ = fired_tx.send(true);
            drain_state
                .metrics()
                .set_shutdown_phase(ShutdownPhase::Draining);
        };

        // The serve future is held behind a stable heap address in its
        // awaitable form: axum's graceful-shutdown wrapper implements
        // `IntoFuture` rather than `Future`, so `into_future()` resolves
        // it to the pollable type once, up front, and `Box::pin` lets
        // both phases re-borrow the one future.
        let mut serving = Box::pin(
            axum::serve(
                tokio::net::TcpListener::from_std(self.listener)?,
                routes::router(Arc::clone(&state)),
            )
            .with_graceful_shutdown(cancellation)
            .into_future(),
        );

        // Phase 1 — serve. No bound: this ends only when the operator's
        // cancellation lands. The server future is polled here — the
        // accept loop only runs while this select is awaiting — so a
        // socket that dies underneath the server ends the run early with
        // that I/O failure instead of waiting for a cancellation that
        // can no longer matter.
        let early = tokio::select! {
            _ = fired_rx.wait_for(|fired| *fired) => None,
            result = serving.as_mut() => Some(result),
        };

        // Phase 2 — the bounded drain. A serve future that completes
        // ahead of the fired watch has already finished the shutdown
        // inside its own poll — a replica with no in-flight work at the
        // instant the cancellation landed drains in that poll — so its
        // `Ok` is the drained verdict and only its `Err`, the socket
        // dying underneath the server, ends the run before the shutdown
        // sequence begins.
        let drained = match early {
            Some(result) => result.map(|()| ShutdownOutcome::Drained)?,
            None => bounded_drain(serving.as_mut(), drain).await?,
        };

        // Phase 3 — the multipart-abort step, on either drain verdict:
        // every session the run left registered as abandoned is aborted
        // against the raw writer, and a failure is the run's outcome.
        // Sessions still live at this point belong to writers that may
        // still commit; the registry contract leaves them to their own
        // terminal operation, and one whose cleanup abort fails there
        // lands back here as abandoned — residue for a later drain and
        // for the deployment's 24-hour lifecycle rule.
        state.metrics().set_shutdown_phase(ShutdownPhase::Aborting);
        let failures = state.uploads().abort_abandoned(state.storage().raw()).await;
        if failures.is_empty() {
            Ok(drained)
        } else {
            Ok(ShutdownOutcome::AbortsFailed)
        }
    }
}

/// Bound one drain attempt.
///
/// The window is a hard bound, not a hint: whatever the drain still owes
/// when it elapses — a connection that never finishes its exchange, a
/// response still streaming — the caller learns as
/// [`ShutdownOutcome::DrainTimedOut`], and dropping the drain future
/// closes what is left. The outcome is the caller's to act on; nothing
/// here exits the process.
async fn bounded_drain(
    drain: impl Future<Output = io::Result<()>>,
    window: Duration,
) -> io::Result<ShutdownOutcome> {
    match tokio::time::timeout(window, drain).await {
        Ok(result) => result.map(|()| ShutdownOutcome::Drained),
        Err(_elapsed) => Ok(ShutdownOutcome::DrainTimedOut),
    }
}

/// The cancellation side of [`shutdown_channel`]: dropping it without
/// triggering means nothing can fire the signal, so a replica waits
/// forever — cancellation is explicit, never implied.
#[derive(Clone, Debug)]
pub struct ShutdownTrigger {
    tx: watch::Sender<bool>,
}

impl ShutdownTrigger {
    /// Fire the cancellation signal.
    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }
}

/// The waiting side of [`shutdown_channel`]: the future a serve run is
/// cancelled by.
#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    rx: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Resolve when the trigger fires. If every trigger was dropped
    /// without firing, this never resolves — there is no one left who
    /// could cancel.
    pub async fn wait(self) {
        let mut rx = self.rx;
        if rx.wait_for(|fired| *fired).await.is_err() {
            // Every trigger dropped without firing: cancellation is
            // impossible, so wait forever.
            std::future::pending::<()>().await;
        }
    }
}

/// A one-shot cancellation channel: `(trigger, signal)`.
#[must_use]
pub fn shutdown_channel() -> (ShutdownTrigger, ShutdownSignal) {
    let (tx, rx) = watch::channel(false);
    (ShutdownTrigger { tx }, ShutdownSignal { rx })
}

/// The shutdown future a service deployment wires in: resolve on
/// SIGTERM or SIGINT.
///
/// # Panics
/// Only if the OS signal handlers cannot be installed — on the
/// supported platforms that is file-descriptor exhaustion, which the
/// process cannot serve requests under anyway.
pub async fn shutdown_on_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate()).expect("SIGTERM handler installs");
    let mut interrupt = signal(SignalKind::interrupt()).expect("SIGINT handler installs");
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{ArchivistServer, ShutdownOutcome, StartupError, shutdown_channel};
    use crate::config::ServerConfig;
    use crate::metrics::ShutdownPhase;
    use crate::state::{ServerState, signed_test_control_record};
    use crate::trust::{TenantTrustRoot, TrustConfig};
    use archivist_auth::ed25519;
    use archivist_protocol::derivation::blob_digest;
    use archivist_protocol::object_key::BlobObjectKey;
    use archivist_protocol::vocabulary::{
        ClientId, Ed25519PublicKey, KeyId, StorageOutcome, StorageProfile, TenantId,
    };
    use archivist_storage::capability::StoreCapabilities;
    use archivist_storage::commit::ConditionalCreateStore;
    use archivist_storage::control::{AuthorizationEpoch, ControlReadStore, ControlRecord};
    use archivist_storage::error::{StorageError, StorageErrorKind};
    use archivist_storage::ingest::IngestStorage;
    use archivist_storage::metadata::ObjectTag;
    use archivist_storage::multipart::{MultipartWriter, PART_BYTES};
    use archivist_storage::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const TENANT_A: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const AUTHORITY_SEED: [u8; 32] = [0x01; 32];

    // ------------------------------------------------------------------
    // Mock stores: nothing in this surface calls them, so every method
    // reports the closed unavailable class. They exist to prove the
    // bootstrap composes real trait objects.
    // ------------------------------------------------------------------

    fn unavailable<T>() -> Result<T, StorageError> {
        Err(StorageError::of_kind(StorageErrorKind::Unavailable))
    }

    #[derive(Clone, Copy, Debug)]
    struct MockRawStore;

    impl RawWriteStore for MockRawStore {
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

    // The writer-only adoption: the trait's default answers every atomic
    // primitive request with capability-unavailable, matching the mock's
    // unprobed report.
    impl ConditionalCreateStore for MockRawStore {}

    #[derive(Clone, Copy, Debug)]
    struct MockControlStore;

    impl ControlReadStore for MockControlStore {
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

    fn test_trust() -> TrustConfig {
        let authority = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&AUTHORITY_SEED));
        TrustConfig::from_roots(vec![
            TenantTrustRoot::new(TENANT_A, &authority.to_hex()).unwrap(),
        ])
        .unwrap()
    }

    fn test_server(drain_seconds: u64) -> ArchivistServer<MockRawStore, MockControlStore> {
        let config = ServerConfig::builder()
            .listen_address("127.0.0.1:0")
            .shutdown_drain_seconds(drain_seconds)
            .build()
            .unwrap();
        ArchivistServer::new(
            config,
            test_trust(),
            IngestStorage::compose(MockRawStore, MockControlStore),
        )
    }

    /// One HTTP/1.1 request with `Connection: close`, answered to EOF.
    async fn request(address: std::net::SocketAddr, request_line: &str) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let raw =
            format!("{request_line} HTTP/1.1\r\nHost: archivist.test\r\nConnection: close\r\n\r\n");
        stream.write_all(raw.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    /// Bind a fresh replica on an ephemeral port and serve it in the
    /// background; returns the address and the trigger.
    async fn serving(
        drain_seconds: u64,
    ) -> (
        std::net::SocketAddr,
        super::ShutdownTrigger,
        tokio::task::JoinHandle<io::Result<ShutdownOutcome>>,
    ) {
        let (trigger, signal) = shutdown_channel();
        let bound = test_server(drain_seconds).bind().unwrap();
        let address = bound.local_addr();
        let handle = tokio::spawn(async move { bound.serve(signal.wait()).await });
        // The listener accepts as soon as bind returned; yield so the
        // spawned task starts before the first request arrives.
        tokio::task::yield_now().await;
        (address, trigger, handle)
    }

    #[tokio::test]
    async fn liveness_is_answered_by_the_process_alone() {
        let (address, _trigger, _handle) = serving(5).await;
        let response = request(address, "GET /health/live").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains("content-type: application/json\r\n"),
            "{response}"
        );
        assert!(response.ends_with("{\"live\":true}"), "{response}");
    }

    #[tokio::test]
    async fn readiness_fails_closed_until_trust_evidence_exists() {
        let (address, _trigger, _handle) = serving(5).await;
        let response = request(address, "GET /health/ready").await;
        assert!(
            response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
            "{response}"
        );
        assert!(
            response.contains(
                "{\"ready\":false,\"reason\":\"trust_evidence_absent\",\
                 \"tenants_configured\":1,\"tenants_ready\":0}"
            ),
            "{response}"
        );
    }

    #[tokio::test]
    async fn recorded_trust_evidence_turns_readiness_on() {
        let (_trigger, signal) = shutdown_channel();
        let bound = test_server(5).bind().unwrap();
        let address = bound.local_addr();
        // Drive evidence through a signed control-record read, exactly as
        // the trust refresh path does. The raw writer is never consulted.
        let tenant = TENANT_A.parse().unwrap();
        bound
            .state()
            .record_verified_control_read(
                &tenant,
                &signed_test_control_record(&tenant, &AUTHORITY_SEED),
                |_| None,
            )
            .expect("the signed control read verifies");
        let handle = tokio::spawn(async move { bound.serve(signal.wait()).await });
        tokio::task::yield_now().await;

        let response = request(address, "GET /health/ready").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains("{\"ready\":true,\"tenants_configured\":1,\"tenants_ready\":1}"),
            "{response}"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn the_ingest_route_refuses_with_the_stable_retryable_body() {
        let (address, _trigger, _handle) = serving(5).await;
        // No Content-Type: the framing rejection precedes everything
        // request-derived, rendered through the error contract with a
        // freshly minted correlation id.
        let response = request(address, "POST /v1/ingest").await;
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{response}"
        );
        assert!(
            response.contains("content-type: application/vnd.agent-archivist.error+json\r\n"),
            "{response}"
        );
        let body = response.rsplit("\r\n\r\n").next().unwrap();
        assert!(
            body.starts_with("{\"code\":\"request.framing_invalid\",\"correlation_id\":\""),
            "{body}"
        );
        assert!(
            body.contains(
                "\"message\":\"The request is not the pinned two-part multipart/related \
                 framing; send the identical bytes the signature covered.\""
            ),
            "{body}"
        );
        assert!(
            body.contains(
                ",\"request_id\":null,\"retryable\":false,\
                 \"schema\":\"archivist.error/v1\"}"
            ),
            "{body}"
        );
        // A GET on the ingest route is a method mismatch, not a route
        // miss: the router knows the path and refuses the method.
        let response = request(address, "GET /v1/ingest").await;
        assert!(
            response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{response}"
        );
    }

    #[tokio::test]
    async fn metrics_expose_the_registered_bootstrap_families() {
        let (address, _trigger, _handle) = serving(5).await;
        // One ingest attempt happened below; the rejected counter counts
        // the Content-Type-less framing refusal.
        let _ = request(address, "POST /v1/ingest").await;
        let response = request(address, "GET /metrics").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains("content-type: text/plain; version=0.0.4; charset=utf-8\r\n"),
            "{response}"
        );
        let body = response.rsplit("\r\n\r\n").next().unwrap();
        assert!(
            body.contains(
                "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"rejected\"} 1\n"
            ),
            "{body}"
        );
        assert!(
            body.contains("# TYPE archivist_server_shutdown gauge\n"),
            "{body}"
        );
        assert!(
            body.contains("archivist_server_shutdown{archivist_shutdown_phase=\"running\"} 1\n"),
            "{body}"
        );
        assert!(
            body.contains("# TYPE archivist_server_trust_refresh_attempts_total counter\n"),
            "{body}"
        );
        // No trust evidence exists yet, so the age family is absent —
        // not zero.
        assert!(!body.contains("trust_age"), "{body}");
    }

    #[tokio::test]
    async fn cancellation_drains_and_returns() {
        let (address, trigger, handle) = serving(5).await;
        // The route answers, proving the server is live before the
        // cancellation lands.
        let response = request(address, "GET /health/live").await;
        assert!(response.starts_with("HTTP/1.1 200"));
        trigger.trigger();
        let outcome = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serve ends after cancellation")
            .unwrap()
            .unwrap();
        assert_eq!(outcome, ShutdownOutcome::Drained);
    }

    #[tokio::test]
    async fn a_stalled_connection_does_not_hang_the_drain() {
        let (trigger, signal) = shutdown_channel();
        let bound = test_server(1).bind().unwrap();
        let address = bound.local_addr();
        let handle = tokio::spawn(async move { bound.serve(signal.wait()).await });
        tokio::task::yield_now().await;

        // Announce request headers that never terminate (no blank line,
        // so hyper never has a request to hand to a handler). hyper's
        // h1 state machine has the connection parked idle, and the
        // graceful shutdown closes idle connections at once — the run
        // ends `Drained`, not stuck. (A *timed-out* drain needs an
        // exchange in flight, which is the ingestion pipeline's arrival;
        // the window's bound itself is proven on `bounded_drain` below.)
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                b"POST /v1/ingest HTTP/1.1\r\nHost: archivist.test\r\n\
                  Content-Length: 4096\r\n",
            )
            .await
            .unwrap();

        trigger.trigger();
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("a stalled connection must not hang the drain")
            .unwrap()
            .unwrap();
        assert_eq!(outcome, ShutdownOutcome::Drained);
        // One configured drain window plus scheduling slack — never the
        // ten-second safety timeout above.
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_replica_serves_past_the_drain_window_without_a_cancellation() {
        // Regression: the drain window bounds the post-cancellation
        // drain only. A replica whose uptime crosses the window — one
        // configured second here — is still serving when it ends.
        let (address, trigger, handle) = serving(1).await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let response = request(address, "GET /health/live").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        trigger.trigger();
        let outcome = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serve ends after cancellation")
            .unwrap()
            .unwrap();
        assert_eq!(outcome, ShutdownOutcome::Drained);
    }

    #[tokio::test]
    async fn a_drain_that_outlives_the_window_ends_in_drain_timed_out() {
        let started = std::time::Instant::now();
        let outcome = super::bounded_drain(std::future::pending(), Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(outcome, ShutdownOutcome::DrainTimedOut);
        // The window elapsed before the outcome surfaced: it is a real
        // wait, not an immediate give-up.
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn a_drain_inside_the_window_ends_drained() {
        let outcome = super::bounded_drain(std::future::ready(Ok(())), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(outcome, ShutdownOutcome::Drained);
    }

    #[tokio::test]
    async fn a_bound_replica_reports_the_socket_it_serves() {
        let bound = test_server(5).bind().unwrap();
        let address = bound.local_addr();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
    }

    #[tokio::test]
    async fn binding_a_taken_address_fails_with_the_address_named() {
        let first = test_server(5).bind().unwrap();
        let taken = first.local_addr();
        // A second replica on the same configured address cannot start:
        // the failure names the address, carries the OS error as its
        // source, and the type stays `StartupError` — nothing broader.
        let config = ServerConfig::builder()
            .listen_address(taken.to_string())
            .build()
            .unwrap();
        let second: ArchivistServer<MockRawStore, MockControlStore> = ArchivistServer::new(
            config,
            test_trust(),
            IngestStorage::compose(MockRawStore, MockControlStore),
        );
        let error: StartupError = match second.bind() {
            Err(error) => error,
            Ok(_) => panic!("a taken address must refuse to bind"),
        };
        assert_eq!(error.address(), taken);
        assert_eq!(
            error.to_string(),
            format!("failed to bind the ingest listener on {taken}")
        );
        assert!(std::error::Error::source(&error).is_some());
    }

    /// The acceptance behind the bead: a replica starts, serves, and
    /// shuts down without producing one byte of durable local state.
    /// The process working directory is an empty temporary directory
    /// for the whole lifecycle — any relative-path write the bootstrap
    /// made would land there and fail this test.
    #[tokio::test]
    async fn a_replica_leaves_no_durable_local_state() {
        let workspace =
            std::env::temp_dir().join(format!("archivist-server-stateless-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(&workspace).unwrap();

        let (trigger, signal) = shutdown_channel();
        let bound = test_server(2).bind().unwrap();
        let address = bound.local_addr();
        let handle = tokio::spawn(async move { bound.serve(signal.wait()).await });
        tokio::task::yield_now().await;

        // The whole registered surface answers while nothing appears on
        // disk.
        assert!(
            request(address, "GET /health/live")
                .await
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            request(address, "GET /health/ready")
                .await
                .starts_with("HTTP/1.1 503")
        );
        assert!(
            request(address, "GET /metrics")
                .await
                .starts_with("HTTP/1.1 200")
        );
        // The Content-Type-less POST draws the framing rejection: the
        // refusal precedes everything request-derived, so it is the
        // contract's request_invalid 400, not the old fail-closed 503.
        assert!(
            request(address, "POST /v1/ingest")
                .await
                .starts_with("HTTP/1.1 400")
        );

        trigger.trigger();
        let outcome = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serve ends after cancellation")
            .unwrap()
            .unwrap();
        assert_eq!(outcome, ShutdownOutcome::Drained);

        std::env::set_current_dir(original).unwrap();
        let left: Vec<_> = std::fs::read_dir(&workspace)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        std::fs::remove_dir(&workspace).unwrap();
        assert!(
            left.is_empty(),
            "replica wrote durable local state: {left:?}"
        );
    }

    // ------------------------------------------------------------------
    // The multipart-abort step: the plan's third shutdown phase.
    // ------------------------------------------------------------------

    struct AbortProbeStore {
        state: std::sync::Mutex<ProbeState>,
        refuse_aborts: AtomicBool,
    }

    #[derive(Default)]
    struct ProbeState {
        begun: usize,
        part_bytes: usize,
        aborted: Vec<String>,
        abort_attempts: usize,
        committed: Vec<String>,
    }

    impl AbortProbeStore {
        fn new() -> Self {
            Self {
                state: std::sync::Mutex::new(ProbeState::default()),
                refuse_aborts: AtomicBool::new(false),
            }
        }

        fn part_bytes(&self) -> usize {
            self.state.lock().expect("probe store lock").part_bytes
        }

        fn aborted(&self) -> Vec<String> {
            self.state.lock().expect("probe store lock").aborted.clone()
        }

        fn committed(&self) -> Vec<String> {
            self.state
                .lock()
                .expect("probe store lock")
                .committed
                .clone()
        }

        fn abort_attempts(&self) -> usize {
            self.state.lock().expect("probe store lock").abort_attempts
        }
    }

    impl RawWriteStore for AbortProbeStore {
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
            let mut state = self.state.lock().expect("probe store lock");
            state.begun += 1;
            MultipartUploadId::parse(&format!("shutdown-probe-{}", state.begun))
                .map_err(|_| StorageError::of_kind(StorageErrorKind::MalformedInput))
        }

        async fn write_part(
            &self,
            _upload: &MultipartUploadId,
            part: PartNumber,
            bytes: &[u8],
        ) -> Result<PartCommitment, StorageError> {
            let mut state = self.state.lock().expect("probe store lock");
            state.part_bytes += bytes.len();
            let tag = ObjectTag::parse("serve-shutdown-probe").expect("tag grammar");
            Ok(PartCommitment::new(part, tag))
        }

        async fn commit_multipart(
            &self,
            upload: &MultipartUploadId,
            _parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            let mut state = self.state.lock().expect("probe store lock");
            state.committed.push(upload.to_string());
            state.part_bytes = 0;
            Ok(StorageOutcome::Created)
        }

        async fn abort_multipart(&self, upload: &MultipartUploadId) -> Result<(), StorageError> {
            let mut state = self.state.lock().expect("probe store lock");
            state.abort_attempts += 1;
            if self.refuse_aborts.load(Ordering::SeqCst) {
                return unavailable();
            }
            state.aborted.push(upload.to_string());
            state.part_bytes = 0;
            Ok(())
        }
    }

    // The writer-only adoption, matching the other mocks: the trait's
    // defaults answer every atomic primitive with capability-unavailable.
    impl ConditionalCreateStore for AbortProbeStore {}

    fn probe_server(drain_seconds: u64) -> ArchivistServer<AbortProbeStore, MockControlStore> {
        let config = ServerConfig::builder()
            .listen_address("127.0.0.1:0")
            .shutdown_drain_seconds(drain_seconds)
            .build()
            .unwrap();
        ArchivistServer::new(
            config,
            test_trust(),
            IngestStorage::compose(AbortProbeStore::new(), MockControlStore),
        )
    }

    /// Open one streaming session against the replica's own registry and
    /// store, exactly the way the ingest route does.
    async fn open_session<'a>(
        state: &'a Arc<ServerState<AbortProbeStore, MockControlStore>>,
        payload: &[u8],
    ) -> MultipartWriter<'a, AbortProbeStore> {
        let tenant = TenantId::parse(TENANT_A).expect("tenant grammar");
        let blob = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &blob_digest(payload));
        MultipartWriter::begin(state.storage().raw(), &blob, state.uploads())
            .await
            .expect("session begins")
    }

    #[tokio::test]
    async fn shutdown_aborts_what_forced_termination_orphaned() {
        let (trigger, signal) = shutdown_channel();
        let bound = probe_server(5).bind().unwrap();
        let state = bound.state().clone();
        let handle = tokio::spawn(async move { bound.serve(signal.wait()).await });
        tokio::task::yield_now().await;

        // A writer mid-stream dies the forced-termination death: the
        // writer goes away with no terminal operation, and the registry
        // holds the session as abandoned. The payload crosses one part
        // boundary, so the backend holds a real uploaded part — the
        // orphan parts the cleanup has to cover; the tail sits in the
        // writer's buffer and never reaches the backend.
        let payload = vec![0xAB_u8; PART_BYTES + 1024];
        {
            let mut writer = open_session(&state, &payload).await;
            writer
                .write_chunk(&payload)
                .await
                .expect("the probe store never refuses a part");
            // The scope ends the writer's life: registered abandoned,
            // no I/O performed.
        }
        let store = state.storage().raw();
        assert_eq!(state.uploads().abandoned_count(), 1);
        assert_eq!(store.part_bytes(), PART_BYTES, "orphan parts standing");

        trigger.trigger();
        let outcome = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serve ends after cancellation")
            .unwrap()
            .unwrap();
        assert_eq!(outcome, ShutdownOutcome::Drained);

        // The abort step covered the residual orphan parts: the session
        // was aborted against the backend, its bytes are gone, and
        // nothing committed — no invalid committed object exists.
        assert_eq!(store.aborted().len(), 1);
        assert_eq!(store.part_bytes(), 0);
        assert!(store.committed().is_empty());
        assert_eq!(state.uploads().live_count(), 0);
        assert_eq!(state.uploads().abandoned_count(), 0);
        // The gauge ends in the phase the step moved it to.
        assert_eq!(state.metrics().shutdown_phase(), ShutdownPhase::Aborting);
    }

    #[tokio::test]
    async fn a_failed_abort_ends_the_run_in_aborts_failed() {
        let (trigger, signal) = shutdown_channel();
        let bound = probe_server(5).bind().unwrap();
        let state = bound.state().clone();
        let handle = tokio::spawn(async move { bound.serve(signal.wait()).await });
        tokio::task::yield_now().await;

        let payload = vec![0xCD_u8; 512];
        {
            let mut writer = open_session(&state, &payload).await;
            writer
                .write_chunk(&payload)
                .await
                .expect("the probe store never refuses a part");
        }
        // Every abort the step attempts is refused: the unavailable
        // class the closed mapping reserves for a backend that cannot
        // answer.
        state
            .storage()
            .raw()
            .refuse_aborts
            .store(true, Ordering::SeqCst);

        trigger.trigger();
        let outcome = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serve ends after cancellation")
            .unwrap()
            .unwrap();
        assert_eq!(outcome, ShutdownOutcome::AbortsFailed);

        let store = state.storage().raw();
        assert_eq!(store.abort_attempts(), 1, "the step attempted the abort");
        assert!(store.aborted().is_empty(), "no abort succeeded");
        assert!(store.committed().is_empty(), "nothing committed");
        // The failed session stays registered, so a later drain retries
        // it — the nonzero exit is the report, not a silent give-up.
        assert_eq!(state.uploads().abandoned_count(), 1);
        assert_eq!(state.metrics().shutdown_phase(), ShutdownPhase::Aborting);
    }

    #[tokio::test]
    async fn the_abort_step_leaves_live_sessions_to_their_writers() {
        let (trigger, signal) = shutdown_channel();
        let bound = probe_server(5).bind().unwrap();
        let state = bound.state().clone();
        let handle = tokio::spawn(async move { bound.serve(signal.wait()).await });
        tokio::task::yield_now().await;

        // A writer still streaming when the cancellation lands: the
        // registry contract leaves its live session alone, because the
        // writer may still lawfully commit it.
        let payload = vec![0x11_u8; 256];
        let mut writer = open_session(&state, &payload).await;
        writer
            .write_chunk(&payload)
            .await
            .expect("the probe store never refuses a part");

        trigger.trigger();
        let outcome = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("serve ends after cancellation")
            .unwrap()
            .unwrap();
        assert_eq!(outcome, ShutdownOutcome::Drained);

        let store = state.storage().raw();
        assert_eq!(store.abort_attempts(), 0, "live sessions are not touched");
        assert_eq!(state.uploads().live_count(), 1);
        // The writer still ends its own session lawfully.
        writer.finish().await.expect("the tail part flushes");
        writer.commit().await.expect("the attempt commits");
        assert_eq!(store.committed().len(), 1);
        assert_eq!(state.uploads().live_count(), 0);
    }

    #[test]
    fn the_outcome_carries_the_exit_code_the_plan_pins() {
        assert_eq!(ShutdownOutcome::Drained.exit_code(), 0);
        assert_ne!(ShutdownOutcome::DrainTimedOut.exit_code(), 0);
        assert_ne!(ShutdownOutcome::AbortsFailed.exit_code(), 0);
    }
}
