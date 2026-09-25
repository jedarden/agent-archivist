// SPDX-License-Identifier: Apache-2.0

//! The replica's metrics snapshot and its `/metrics` exposition.
//!
//! Every exported family is a signal already registered in
//! `tools/metrics.toml` (surface `server`, Phase 4); nothing here invents
//! a name. The exported family name is derived by exactly the pinned
//! translation of the metrics conventions (MET-011): dots become
//! underscores, a unit other than `1` appends its exported suffix, and a
//! counter appends `_total`; label keys render as `archivist.<key>` with
//! dots replaced. A unit test pins the translation against the literal
//! strings below, so a registry rename that lands without this module
//! fails here first.
//!
//! This bootstrap surface exports the families it owns and no others:
//!
//! - `archivist.server.ingest` — ingest requests by terminal outcome;
//!   the bootstrap route admits no pipeline yet, so the fail-closed
//!   refusals land in the `failed` outcome and every guard refusal in
//!   the `throttled` outcome;
//! - `archivist.server.ingest.inflight` — requests currently inside
//!   admission, against the 16-per-process concurrency bound (plan
//!   Section 7.6); the admission gate moves it and nothing else does,
//!   and the series is one unlabeled gauge — overload is visible only
//!   as a process total, never per client or per request (SEC-004);
//! - `archivist.server.shutdown` — the graceful-shutdown phase gauge;
//! - `archivist.server.trust.age` — the age of the newest successful
//!   tenant trust-record read; the series is *omitted* until evidence
//!   exists, because an invented age is a fabricated fact (plan Phase 4:
//!   readiness expires at 60 seconds);
//! - `archivist.server.trust.refresh` — refresh attempts by outcome,
//!   pre-emitted at zero for every registered outcome so a dashboard can
//!   join on the series before the first attempt.
//!
//! The pipeline slice adds the families the ingest pipeline owns, each
//! recorded only where its event actually happens:
//!
//! - `archivist.server.ingest.received` — accepted transport-encoded
//!   payload bytes (compressed on the wire);
//! - `archivist.server.ingest.canonical` — accepted canonical
//!   uncompressed payload bytes after streaming validation (OPS-005);
//! - `archivist.server.ingest.duration` — end-to-end ingest duration
//!   over the registered boundaries;
//! - `archivist.server.ingest.failures` — authorization and validation
//!   failures by [`FailureCode`], the closed mirror of the registry's
//!   `error_code` values this replica can reach (ERR-032, OPS-005) — the
//!   only error-derived label the surface exports, and never the
//!   rendered message text (MET-020, SEC-004);
//! - `archivist.server.commit` — blob, occurrence, and attestation
//!   commits by object kind and by what the backend could establish
//!   (RCPT-003, RCPT-004); receipt success is not a separate family —
//!   `ingest` reports `committed` exactly when all three objects stand
//!   and the receipt issued (RCPT-005 keeps partial commits in
//!   `failed`).
//!
//! Every failure code and commit outcome here is a closed enum whose
//! exhaustive mapping the tests pin; a new [`crate::error::ServerFailure`]
//! variant or protocol outcome fails to map by compile error or misses
//! its series visibly in the same commit, never renders an unregistered
//! label value (MET-026).
//!
//! The `archivist.storage.*` families are the storage surface's own
//! ([`archivist_storage::telemetry`]), rendered by the same scrape from
//! the shared snapshot; this module exports only what `server` owns.
//!
//! Values are process-local counters and gauges backed by atomics — no
//! metric ever carries content, an identifier, or a bounded-enum value
//! outside its registered set (MET-016, MET-020, SEC-004).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use archivist_protocol::vocabulary::StorageOutcome;
use archivist_storage::telemetry::{SpanSink, bucket_for, render_seconds};

use crate::error::{AuthRejection, PayloadLimit, ServerFailure};

/// The graceful-shutdown phase (`shutdown_phase` label values, in
/// registry order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShutdownPhase {
    /// Serving requests.
    Running,
    /// Stop-accepting received; draining in-flight work.
    Draining,
    /// Drain window elapsed; aborting unfinished multipart uploads.
    Aborting,
}

impl ShutdownPhase {
    /// Every phase, in registry order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Running, Self::Draining, Self::Aborting]
    }

    /// The registered label value.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Draining => "draining",
            Self::Aborting => "aborting",
        }
    }

    fn index(self) -> u8 {
        match self {
            Self::Running => 0,
            Self::Draining => 1,
            Self::Aborting => 2,
        }
    }

    fn from_index(index: u8) -> Self {
        Self::all()[usize::from(index).min(Self::all().len() - 1)]
    }
}

/// The terminal outcome of an ingest request attempt
/// (`ingest_outcome` label values, in registry order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IngestOutcome {
    /// Committed durably and receipted.
    Committed,
    /// Rejected as invalid or unauthorized.
    Rejected,
    /// Refused by a resource guard.
    Throttled,
    /// Failed after acceptance; nothing committed.
    Failed,
}

impl IngestOutcome {
    /// Every outcome, in registry order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Committed,
            Self::Rejected,
            Self::Throttled,
            Self::Failed,
        ]
    }

    /// The registered label value.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Rejected => "rejected",
            Self::Throttled => "throttled",
            Self::Failed => "failed",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Committed => 0,
            Self::Rejected => 1,
            Self::Throttled => 2,
            Self::Failed => 3,
        }
    }
}

/// The outcome of one trust-registry refresh attempt
/// (`trust_outcome` label values, in registry order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrustRefreshOutcome {
    /// Fresh evidence was read from the control plane.
    Refreshed,
    /// The bounded cache answered within its 60-second window (EC-09).
    CacheHit,
    /// The control plane was unreachable; readiness expires with the
    /// cache.
    Unavailable,
}

impl TrustRefreshOutcome {
    /// Every outcome, in registry order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Refreshed, Self::CacheHit, Self::Unavailable]
    }

    /// The registered label value.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Refreshed => "refreshed",
            Self::CacheHit => "cache_hit",
            Self::Unavailable => "unavailable",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Refreshed => 0,
            Self::CacheHit => 1,
            Self::Unavailable => 2,
        }
    }
}

/// The registered `error_code` values this replica's ingest path can
/// reach, as a closed enum (`ingest.failures` label values, in registry
/// order).
///
/// [`ServerFailure`] maps onto this set exhaustively — there is no
/// wildcard arm — so a future failure variant without a mapping is a
/// compile error here, and no unregistered code can ever render as a
/// label value (MET-016, MET-026). The client-side and transport registry
/// codes are deliberately absent: this replica never reports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureCode {
    /// `envelope.malformed` — part one was not canonical-domain JSON.
    EnvelopeMalformed,
    /// `envelope.version_unsupported` — an unsupported version axis.
    EnvelopeVersionUnsupported,
    /// `envelope.media_type_unsupported` — part one was not the pinned
    /// media type.
    EnvelopeMediaTypeUnsupported,
    /// `envelope.schema_invalid` — a member outside its grammar.
    EnvelopeSchemaInvalid,
    /// `envelope.size_exceeded` — part one or the envelope over its cap.
    EnvelopeSizeExceeded,
    /// `auth.unlinked` — the uploader presents no tenant link.
    AuthUnlinked,
    /// `auth.revoked` — the presented authorization was revoked.
    AuthRevoked,
    /// `auth.authorization_rejected` — the proof is stale, altered, or
    /// replayed.
    AuthAuthorizationRejected,
    /// `auth.forbidden` — not authorized for the declared origin client
    /// or tenant.
    AuthForbidden,
    /// `storage.integrity_conflict` — stored state is incompatible.
    StorageIntegrityConflict,
    /// `request.payload_too_large` — the whole payload over a limit
    /// smaller chunks could satisfy.
    RequestPayloadTooLarge,
    /// `request.expansion_ratio_exceeded` — the decompression expansion
    /// over its cap.
    RequestExpansionRatioExceeded,
    /// `request.record_too_large` — one record alone over an unsplittable
    /// limit.
    RequestRecordTooLarge,
    /// `request.deadline_exceeded` — the request deadline elapsed.
    RequestDeadlineExceeded,
    /// `request.rate_limited` — the admission inventory is exhausted.
    RequestRateLimited,
    /// `request.too_early` — the replica is not ready yet.
    RequestTooEarly,
    /// `request.framing_invalid` — the multipart body itself is not a
    /// valid two-part framing.
    RequestFramingInvalid,
    /// `server.internal` — an internal fault that committed nothing.
    ServerInternal,
    /// `server.storage_failure` — the backend rejected or failed.
    ServerStorageFailure,
    /// `server.unavailable` — not ready, or the trust registry is
    /// unreachable with no valid cache.
    ServerUnavailable,
    /// `server.partial_commit` — fewer than all three objects stand.
    ServerPartialCommit,
    /// `server.upstream_timeout` — the backend timed out with an unknown
    /// physical outcome.
    ServerUpstreamTimeout,
}

/// The registered failure-code count.
const FAILURE_CODE_COUNT: usize = 22;

impl FailureCode {
    /// Every code this replica can reach, in registry order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::EnvelopeMalformed,
            Self::EnvelopeVersionUnsupported,
            Self::EnvelopeMediaTypeUnsupported,
            Self::EnvelopeSchemaInvalid,
            Self::EnvelopeSizeExceeded,
            Self::AuthUnlinked,
            Self::AuthRevoked,
            Self::AuthAuthorizationRejected,
            Self::AuthForbidden,
            Self::StorageIntegrityConflict,
            Self::RequestPayloadTooLarge,
            Self::RequestExpansionRatioExceeded,
            Self::RequestRecordTooLarge,
            Self::RequestDeadlineExceeded,
            Self::RequestRateLimited,
            Self::RequestTooEarly,
            Self::RequestFramingInvalid,
            Self::ServerInternal,
            Self::ServerStorageFailure,
            Self::ServerUnavailable,
            Self::ServerPartialCommit,
            Self::ServerUpstreamTimeout,
        ]
    }

    /// The registered label value.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::EnvelopeMalformed => "envelope.malformed",
            Self::EnvelopeVersionUnsupported => "envelope.version_unsupported",
            Self::EnvelopeMediaTypeUnsupported => "envelope.media_type_unsupported",
            Self::EnvelopeSchemaInvalid => "envelope.schema_invalid",
            Self::EnvelopeSizeExceeded => "envelope.size_exceeded",
            Self::AuthUnlinked => "auth.unlinked",
            Self::AuthRevoked => "auth.revoked",
            Self::AuthAuthorizationRejected => "auth.authorization_rejected",
            Self::AuthForbidden => "auth.forbidden",
            Self::StorageIntegrityConflict => "storage.integrity_conflict",
            Self::RequestPayloadTooLarge => "request.payload_too_large",
            Self::RequestExpansionRatioExceeded => "request.expansion_ratio_exceeded",
            Self::RequestRecordTooLarge => "request.record_too_large",
            Self::RequestDeadlineExceeded => "request.deadline_exceeded",
            Self::RequestRateLimited => "request.rate_limited",
            Self::RequestTooEarly => "request.too_early",
            Self::RequestFramingInvalid => "request.framing_invalid",
            Self::ServerInternal => "server.internal",
            Self::ServerStorageFailure => "server.storage_failure",
            Self::ServerUnavailable => "server.unavailable",
            Self::ServerPartialCommit => "server.partial_commit",
            Self::ServerUpstreamTimeout => "server.upstream_timeout",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::EnvelopeMalformed => 0,
            Self::EnvelopeVersionUnsupported => 1,
            Self::EnvelopeMediaTypeUnsupported => 2,
            Self::EnvelopeSchemaInvalid => 3,
            Self::EnvelopeSizeExceeded => 4,
            Self::AuthUnlinked => 5,
            Self::AuthRevoked => 6,
            Self::AuthAuthorizationRejected => 7,
            Self::AuthForbidden => 8,
            Self::StorageIntegrityConflict => 9,
            Self::RequestPayloadTooLarge => 10,
            Self::RequestExpansionRatioExceeded => 11,
            Self::RequestRecordTooLarge => 12,
            Self::RequestDeadlineExceeded => 13,
            Self::RequestRateLimited => 14,
            Self::RequestTooEarly => 15,
            Self::RequestFramingInvalid => 16,
            Self::ServerInternal => 17,
            Self::ServerStorageFailure => 18,
            Self::ServerUnavailable => 19,
            Self::ServerPartialCommit => 20,
            Self::ServerUpstreamTimeout => 21,
        }
    }

    /// The code one ingest failure is reported under, or `None` when the
    /// failure's code is outside the set this replica's metrics know —
    /// which the exhaustive mapping below makes a compile-time
    /// impossibility for every variant that exists today, and a visible
    /// test failure for any variant added without extending this enum.
    #[must_use]
    pub fn of_failure(failure: &ServerFailure) -> Option<Self> {
        match failure {
            ServerFailure::Parse(parse) => Self::of_code(parse.code().as_str()),
            ServerFailure::Authorization(rejection) => Some(match rejection {
                AuthRejection::Unlinked => Self::AuthUnlinked,
                AuthRejection::Revoked => Self::AuthRevoked,
                AuthRejection::ProofRejected => Self::AuthAuthorizationRejected,
                AuthRejection::Forbidden => Self::AuthForbidden,
            }),
            ServerFailure::IntegrityConflict => Some(Self::StorageIntegrityConflict),
            ServerFailure::PayloadLimit(limit) => Some(match limit {
                PayloadLimit::SplittableBytes { .. } => Self::RequestPayloadTooLarge,
                PayloadLimit::SplittableRatio { .. } => Self::RequestExpansionRatioExceeded,
                PayloadLimit::UnsplittableRecord { .. } => Self::RequestRecordTooLarge,
            }),
            ServerFailure::RateLimited => Some(Self::RequestRateLimited),
            ServerFailure::DeadlineElapsed => Some(Self::RequestDeadlineExceeded),
            ServerFailure::TooEarly => Some(Self::RequestTooEarly),
            ServerFailure::RegistryUnavailable | ServerFailure::Unavailable => {
                Some(Self::ServerUnavailable)
            }
            ServerFailure::StorageFailure => Some(Self::ServerStorageFailure),
            ServerFailure::UpstreamTimeout => Some(Self::ServerUpstreamTimeout),
            ServerFailure::PartialCommit => Some(Self::ServerPartialCommit),
            ServerFailure::Internal => Some(Self::ServerInternal),
        }
    }

    /// The registered code token, resolved through the pinned mapping.
    /// The parse arm is the one place a variant's code arrives as text:
    /// it is matched against the exact registered tokens and anything
    /// else is `None` — a miss under-counts one series in a test, it
    /// never invents a label value.
    fn of_code(code: &str) -> Option<Self> {
        Self::all().iter().copied().find(|known| known.token() == code)
    }
}

/// The kind of raw object a commit signal counts (`object_kind` label
/// values, in registry order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    /// The canonical content-addressed blob.
    Blob,
    /// The occurrence manifest.
    Occurrence,
    /// The upload attestation.
    Attestation,
}

impl ObjectKind {
    /// Every object kind, in registry order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Blob, Self::Occurrence, Self::Attestation]
    }

    /// The registered label value.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Occurrence => "occurrence",
            Self::Attestation => "attestation",
        }
    }
}

/// The registry-order index of one object kind.
fn kind_index(kind: ObjectKind) -> usize {
    match kind {
        ObjectKind::Blob => 0,
        ObjectKind::Occurrence => 1,
        ObjectKind::Attestation => 2,
    }
}

/// The registered ingest-duration histogram boundaries, in seconds
/// (MET-027); the last boundary brackets the 15-minute deadline.
pub const INGEST_DURATION_BOUNDARIES_SECONDS: [f64; 8] = [0.05, 0.25, 1.0, 5.0, 25.0, 60.0, 300.0, 900.0];

/// Eight registered boundaries plus the implicit infinite one.
const INGEST_DURATION_BUCKETS: usize = INGEST_DURATION_BOUNDARIES_SECONDS.len() + 1;

/// The process-local metrics snapshot.
///
/// Every field is an atomic; the snapshot is shared behind the server
/// state and rendered on scrape, so no request path ever blocks on
/// another.
#[derive(Debug, Default)]
pub struct ServerMetrics {
    ingest: [AtomicU64; 4],
    inflight: AtomicU64,
    refresh: [AtomicU64; 3],
    phase: AtomicU8,
    received_bytes: AtomicU64,
    canonical_bytes: AtomicU64,
    duration_buckets: [AtomicU64; INGEST_DURATION_BUCKETS],
    duration_sum_nanos: AtomicU64,
    duration_count: AtomicU64,
    failures: [AtomicU64; FAILURE_CODE_COUNT],
    commits: [[AtomicU64; COMMIT_OUTCOME_COUNT]; OBJECT_KIND_COUNT],
    /// The bounded span ring, shared with the pipeline's span recording.
    spans: SpanSink,
}

/// The registered object-kind count.
const OBJECT_KIND_COUNT: usize = 3;
/// The registered commit-outcome count.
const COMMIT_OUTCOME_COUNT: usize = 4;
/// The registered commit-outcome label tokens, in registry order; the
/// module tests pin them against the protocol's [`StorageOutcome`]
/// tokens.
const COMMIT_OUTCOME_TOKENS: [&str; COMMIT_OUTCOME_COUNT] = [
    "created",
    "already_present",
    "replaced_equivalent",
    "logically_committed_unknown_physical_result",
];

impl ServerMetrics {
    /// A fresh snapshot: every counter at zero, phase
    /// [`ShutdownPhase::Running`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one ingest request reaching its terminal outcome.
    pub fn record_ingest(&self, outcome: IngestOutcome) {
        self.ingest[outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// The bounded span ring: the pipeline records its registered spans
    /// here, newest [`archivist_storage::telemetry`] ring capacity
    /// retained.
    #[must_use]
    pub const fn spans(&self) -> &SpanSink {
        &self.spans
    }

    /// Add `bytes` accepted transport-encoded payload bytes — counted
    /// only for attempts whose validation completed, never per raw read
    /// (a rejected attempt accepts nothing).
    pub fn record_received_bytes(&self, bytes: u64) {
        self.received_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add `bytes` accepted canonical uncompressed payload bytes.
    pub fn record_canonical_bytes(&self, bytes: u64) {
        self.canonical_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record one ingest attempt's end-to-end duration into the
    /// registered histogram.
    pub fn record_ingest_duration(&self, duration: std::time::Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        let bucket = bucket_for(nanos, &INGEST_DURATION_BOUNDARIES_SECONDS);
        self.duration_buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.duration_sum_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.duration_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one validation or authorization failure by its bounded
    /// code. The `Option` comes from the exhaustive
    /// [`FailureCode::of_failure`] mapping; a code outside the registered
    /// set is never rendered.
    pub fn record_failure(&self, code: FailureCode) {
        self.failures[code.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Record one object commit: what kind of raw object, and exactly
    /// what the backend could establish.
    pub fn record_commit(&self, kind: ObjectKind, outcome: StorageOutcome) {
        let outcome_index = match outcome {
            StorageOutcome::Created => 0,
            StorageOutcome::AlreadyPresent => 1,
            StorageOutcome::ReplacedEquivalent => 2,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult => 3,
        };
        self.commits[kind_index(kind)][outcome_index].fetch_add(1, Ordering::Relaxed);
    }

    /// Count `count` ingest requests entering admission, moving the
    /// `archivist.server.ingest.inflight` gauge up.
    pub fn ingest_inflight_add(&self, count: u64) {
        self.inflight.fetch_add(count, Ordering::Relaxed);
    }

    /// Count `count` ingest requests leaving admission, moving the
    /// `archivist.server.ingest.inflight` gauge down.
    ///
    /// The subtraction saturates at zero: the gauge is a snapshot of a
    /// live count, and an unbalanced release would otherwise render a
    /// negative inventory of requests that never existed.
    pub fn ingest_inflight_sub(&self, count: u64) {
        let _ = self
            .inflight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(count))
            });
    }

    /// The in-flight ingest count the gauge currently renders.
    #[must_use]
    pub fn ingest_inflight(&self) -> u64 {
        self.inflight.load(Ordering::Relaxed)
    }

    /// Record one trust-registry refresh attempt.
    pub fn record_trust_refresh(&self, outcome: TrustRefreshOutcome) {
        self.refresh[outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Move the replica into a shutdown phase.
    pub fn set_shutdown_phase(&self, phase: ShutdownPhase) {
        self.phase.store(phase.index(), Ordering::Relaxed);
    }

    /// The current shutdown phase.
    #[must_use]
    pub fn shutdown_phase(&self) -> ShutdownPhase {
        ShutdownPhase::from_index(self.phase.load(Ordering::Relaxed))
    }

    /// Render the Prometheus text exposition (format 0.0.4) for this
    /// snapshot.
    ///
    /// `newest_trust_age_seconds` is the age of the newest successful
    /// tenant trust-record read, or `None` while no read has ever
    /// succeeded — in which case the `archivist.server.trust.age` family
    /// is omitted entirely.
    #[must_use]
    pub fn exposition(&self, newest_trust_age_seconds: Option<u64>) -> String {
        let mut out = String::new();

        family(
            &mut out,
            "archivist_server_ingest_requests_total",
            "counter",
        );
        for outcome in IngestOutcome::all() {
            series(
                &mut out,
                "archivist_server_ingest_requests_total",
                &[("archivist_ingest_outcome", outcome.token())],
                self.ingest[outcome.index()].load(Ordering::Relaxed),
            );
        }

        family(
            &mut out,
            "archivist_server_ingest_inflight_requests",
            "gauge",
        );
        series(
            &mut out,
            "archivist_server_ingest_inflight_requests",
            &[],
            self.ingest_inflight(),
        );

        family(&mut out, "archivist_server_shutdown", "gauge");
        let current = self.shutdown_phase();
        for phase in ShutdownPhase::all() {
            series(
                &mut out,
                "archivist_server_shutdown",
                &[("archivist_shutdown_phase", phase.token())],
                u64::from(*phase == current),
            );
        }

        if let Some(age) = newest_trust_age_seconds {
            family(&mut out, "archivist_server_trust_age_seconds", "gauge");
            series(&mut out, "archivist_server_trust_age_seconds", &[], age);
        }

        family(
            &mut out,
            "archivist_server_trust_refresh_attempts_total",
            "counter",
        );
        for outcome in TrustRefreshOutcome::all() {
            series(
                &mut out,
                "archivist_server_trust_refresh_attempts_total",
                &[("archivist_trust_outcome", outcome.token())],
                self.refresh[outcome.index()].load(Ordering::Relaxed),
            );
        }

        family(
            &mut out,
            "archivist_server_ingest_received_bytes_total",
            "counter",
        );
        series(
            &mut out,
            "archivist_server_ingest_received_bytes_total",
            &[],
            self.received_bytes.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "archivist_server_ingest_canonical_bytes_total",
            "counter",
        );
        series(
            &mut out,
            "archivist_server_ingest_canonical_bytes_total",
            &[],
            self.canonical_bytes.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "archivist_server_ingest_duration_seconds",
            "histogram",
        );
        render_histogram(
            &mut out,
            "archivist_server_ingest_duration_seconds",
            &INGEST_DURATION_BOUNDARIES_SECONDS,
            &self.duration_buckets,
            self.duration_sum_nanos.load(Ordering::Relaxed),
            self.duration_count.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "archivist_server_ingest_failures_errors_total",
            "counter",
        );
        for code in FailureCode::all() {
            series(
                &mut out,
                "archivist_server_ingest_failures_errors_total",
                &[("archivist_error_code", code.token())],
                self.failures[code.index()].load(Ordering::Relaxed),
            );
        }

        family(&mut out, "archivist_server_commit_objects_total", "counter");
        for kind in ObjectKind::all() {
            for (outcome_index, outcome) in COMMIT_OUTCOME_TOKENS.iter().enumerate() {
                series(
                    &mut out,
                    "archivist_server_commit_objects_total",
                    &[
                        ("archivist_object_kind", kind.token()),
                        ("archivist_commit_outcome", outcome),
                    ],
                    self.commits[kind_index(*kind)][outcome_index].load(Ordering::Relaxed),
                );
            }
        }

        out
    }
}

fn family(out: &mut String, name: &str, kind: &str) {
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Render one explicit-bucket histogram family: cumulative bucket lines
/// under each registered boundary plus the infinite one, then `_sum` and
/// `_count`. The same convention the storage surface's renderer uses.
fn render_histogram(
    out: &mut String,
    name: &str,
    boundaries_seconds: &[f64],
    buckets: &[AtomicU64],
    sum_nanos: u64,
    count: u64,
) {
    let mut cumulative = 0u64;
    for (bound, bucket) in boundaries_seconds.iter().zip(buckets.iter()) {
        cumulative += bucket.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{name}_bucket{{le=\"{}\"}} {cumulative}",
            archivist_storage::telemetry::bucket_le_text(*bound)
        );
    }
    cumulative += buckets[boundaries_seconds.len()].load(Ordering::Relaxed);
    let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {cumulative}");
    let _ = writeln!(out, "{name}_sum {}", render_seconds(sum_nanos));
    let _ = writeln!(out, "{name}_count {count}");
}

fn series(out: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (index, (key, value)) in labels.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let _ = write!(out, "{key}=\"{}\"", escape_label_value(value));
        }
        out.push('}');
    }
    let _ = writeln!(out, " {value}");
}

/// Escape a label value per the exposition format. Registered enum
/// tokens never need it; the helper exists so the rendering cannot be
/// the place an unescaped value escapes from.
fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::{
        IngestOutcome, ServerMetrics, ShutdownPhase, TrustRefreshOutcome, escape_label_value,
    };

    #[test]
    fn label_values_match_the_registry() {
        assert_eq!(
            IngestOutcome::all().len()
                + ShutdownPhase::all().len()
                + TrustRefreshOutcome::all().len(),
            4 + 3 + 3
        );
        for outcome in IngestOutcome::all() {
            assert!(["committed", "rejected", "throttled", "failed"].contains(&outcome.token()));
        }
        for phase in ShutdownPhase::all() {
            assert!(["running", "draining", "aborting"].contains(&phase.token()));
        }
        for outcome in TrustRefreshOutcome::all() {
            assert!(["refreshed", "cache_hit", "unavailable"].contains(&outcome.token()));
        }
    }

    /// The exported names are the pinned MET-011 translation of the
    /// registry entries, spelled out byte for byte: a registry edit that
    /// moves a name without moving this module fails here.
    #[test]
    fn a_fresh_snapshot_exposes_the_registered_families() {
        let metrics = ServerMetrics::new();
        assert_eq!(
            metrics.exposition(None),
            "# TYPE archivist_server_ingest_requests_total counter\n\
             archivist_server_ingest_requests_total{archivist_ingest_outcome=\"committed\"} 0\n\
             archivist_server_ingest_requests_total{archivist_ingest_outcome=\"rejected\"} 0\n\
             archivist_server_ingest_requests_total{archivist_ingest_outcome=\"throttled\"} 0\n\
             archivist_server_ingest_requests_total{archivist_ingest_outcome=\"failed\"} 0\n\
             # TYPE archivist_server_ingest_inflight_requests gauge\n\
             archivist_server_ingest_inflight_requests 0\n\
             # TYPE archivist_server_shutdown gauge\n\
             archivist_server_shutdown{archivist_shutdown_phase=\"running\"} 1\n\
             archivist_server_shutdown{archivist_shutdown_phase=\"draining\"} 0\n\
             archivist_server_shutdown{archivist_shutdown_phase=\"aborting\"} 0\n\
             # TYPE archivist_server_trust_refresh_attempts_total counter\n\
             archivist_server_trust_refresh_attempts_total{archivist_trust_outcome=\"refreshed\"} 0\n\
             archivist_server_trust_refresh_attempts_total{archivist_trust_outcome=\"cache_hit\"} 0\n\
             archivist_server_trust_refresh_attempts_total{archivist_trust_outcome=\"unavailable\"} 0\n\
             # TYPE archivist_server_ingest_received_bytes_total counter\n\
             archivist_server_ingest_received_bytes_total 0\n\
             # TYPE archivist_server_ingest_canonical_bytes_total counter\n\
             archivist_server_ingest_canonical_bytes_total 0\n\
             # TYPE archivist_server_ingest_duration_seconds histogram\n\
             archivist_server_ingest_duration_seconds_bucket{le=\"0.05\"} 0\n\
             archivist_server_ingest_duration_seconds_bucket{le=\"0.25\"} 0\n\
             archivist_server_ingest_duration_seconds_bucket{le=\"1\"} 0\n\
             archivist_server_ingest_duration_seconds_bucket{le=\"5\"} 0\n\
             archivist_server_ingest_duration_seconds_bucket{le=\"25\"} 0\n\
             archivist_server_ingest_duration_seconds_bucket{le=\"60\"} 0\n\
             archivist_server_ingest_duration_seconds_bucket{le=\"300\"} 0\n\
             archivist_server_ingest_duration_seconds_bucket{le=\"900\"} 0\n\
             archivist_server_ingest_duration_seconds_bucket{le=\"+Inf\"} 0\n\
             archivist_server_ingest_duration_seconds_sum 0\n\
             archivist_server_ingest_duration_seconds_count 0\n\
             # TYPE archivist_server_ingest_failures_errors_total counter\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"envelope.malformed\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"envelope.version_unsupported\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"envelope.media_type_unsupported\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"envelope.schema_invalid\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"envelope.size_exceeded\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"auth.unlinked\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"auth.revoked\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"auth.authorization_rejected\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"auth.forbidden\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"storage.integrity_conflict\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"request.payload_too_large\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"request.expansion_ratio_exceeded\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"request.record_too_large\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"request.deadline_exceeded\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"request.rate_limited\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"request.too_early\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"request.framing_invalid\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"server.internal\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"server.storage_failure\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"server.unavailable\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"server.partial_commit\"} 0\n\
             archivist_server_ingest_failures_errors_total{archivist_error_code=\"server.upstream_timeout\"} 0\n\
             # TYPE archivist_server_commit_objects_total counter\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"blob\",archivist_commit_outcome=\"created\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"blob\",archivist_commit_outcome=\"already_present\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"blob\",archivist_commit_outcome=\"replaced_equivalent\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"blob\",archivist_commit_outcome=\"logically_committed_unknown_physical_result\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"occurrence\",archivist_commit_outcome=\"created\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"occurrence\",archivist_commit_outcome=\"already_present\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"occurrence\",archivist_commit_outcome=\"replaced_equivalent\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"occurrence\",archivist_commit_outcome=\"logically_committed_unknown_physical_result\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"attestation\",archivist_commit_outcome=\"created\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"attestation\",archivist_commit_outcome=\"already_present\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"attestation\",archivist_commit_outcome=\"replaced_equivalent\"} 0\n\
             archivist_server_commit_objects_total{archivist_object_kind=\"attestation\",archivist_commit_outcome=\"logically_committed_unknown_physical_result\"} 0\n"
        );
    }

    #[test]
    fn counters_count_and_the_gauge_tracks_one_phase() {
        let metrics = ServerMetrics::new();
        metrics.record_ingest(IngestOutcome::Failed);
        metrics.record_ingest(IngestOutcome::Failed);
        metrics.record_ingest(IngestOutcome::Committed);
        metrics.record_trust_refresh(TrustRefreshOutcome::Unavailable);
        metrics.set_shutdown_phase(ShutdownPhase::Draining);
        let text = metrics.exposition(Some(12));
        assert!(text.contains(
            "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"failed\"} 2\n"
        ));
        assert!(text.contains(
            "archivist_server_ingest_requests_total{archivist_ingest_outcome=\"committed\"} 1\n"
        ));
        assert!(text.contains(
            "archivist_server_trust_refresh_attempts_total{archivist_trust_outcome=\"unavailable\"} 1\n"
        ));
        assert!(
            text.contains("archivist_server_shutdown{archivist_shutdown_phase=\"draining\"} 1\n")
        );
        assert!(
            text.contains("archivist_server_shutdown{archivist_shutdown_phase=\"running\"} 0\n")
        );
        assert!(text.contains("# TYPE archivist_server_trust_age_seconds gauge\n"));
        assert!(text.contains("archivist_server_trust_age_seconds 12\n"));
        assert_eq!(metrics.shutdown_phase().token(), "draining");
        assert_eq!(metrics.shutdown_phase(), ShutdownPhase::Draining);
    }

    #[test]
    fn the_inflight_gauge_tracks_admission_and_release() {
        let metrics = ServerMetrics::new();
        assert_eq!(metrics.ingest_inflight(), 0);
        metrics.ingest_inflight_add(1);
        metrics.ingest_inflight_add(2);
        assert_eq!(metrics.ingest_inflight(), 3);
        metrics.ingest_inflight_sub(1);
        assert_eq!(metrics.ingest_inflight(), 2);
        metrics.ingest_inflight_sub(2);
        assert_eq!(metrics.ingest_inflight(), 0);
    }

    #[test]
    fn the_inflight_gauge_saturates_instead_of_going_negative() {
        let metrics = ServerMetrics::new();
        metrics.ingest_inflight_add(1);
        // A defensive floor: a sub past zero must clamp, never wrap negative.
        metrics.ingest_inflight_sub(5);
        assert_eq!(
            metrics.ingest_inflight(),
            0,
            "no inventory of ghost requests"
        );
        metrics.ingest_inflight_sub(1);
        assert_eq!(metrics.ingest_inflight(), 0);
    }

    #[test]
    fn the_inflight_gauge_renders_one_unlabeled_series() {
        let metrics = ServerMetrics::new();
        metrics.ingest_inflight_add(2);
        let text = metrics.exposition(None);
        assert!(text.contains(
            "# TYPE archivist_server_ingest_inflight_requests gauge\n\
             archivist_server_ingest_inflight_requests 2\n"
        ));
    }

    #[test]
    fn the_trust_age_family_is_omitted_until_evidence_exists() {
        let metrics = ServerMetrics::new();
        let text = metrics.exposition(None);
        assert!(!text.contains("trust_age"));
        // And `Some(0)` is a real, fresh observation — not omitted.
        assert!(
            metrics
                .exposition(Some(0))
                .contains("archivist_server_trust_age_seconds 0\n")
        );
    }

    #[test]
    fn phase_reads_survive_round_trip() {
        let metrics = ServerMetrics::new();
        assert_eq!(metrics.shutdown_phase(), ShutdownPhase::Running);
        metrics.set_shutdown_phase(ShutdownPhase::Aborting);
        assert_eq!(metrics.shutdown_phase(), ShutdownPhase::Aborting);
    }

    #[test]
    fn label_values_escape_per_the_exposition_rules() {
        assert_eq!(escape_label_value("plain"), "plain");
        assert_eq!(escape_label_value("a\"b"), "a\\\"b");
        assert_eq!(escape_label_value("a\\b"), "a\\\\b");
        assert_eq!(escape_label_value("a\nb"), "a\\nb");
    }
}
