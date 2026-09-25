// SPDX-License-Identifier: Apache-2.0

//! The storage surface's telemetry: operation latency and failures,
//! multipart-abort failures, and the operation spans, all behind the
//! [`MeasuredRawStore`] seam.
//!
//! Every exported family and span name here is a signal already registered
//! in `tools/metrics.toml` (surface `storage`, Phase 2); nothing here
//! invents a name. The exported family names are derived by exactly the
//! pinned translation of the metrics conventions (MET-011): dots become
//! underscores, the unit appends its exported suffix, and a counter appends
//! `_total`; label keys render as `archivist.<key>` with dots replaced.
//!
//! - `archivist.storage.operation.duration` — latency per operation class
//!   over the registered boundaries, as an explicit-bucket histogram;
//! - `archivist.storage.operation.failures` — failures per operation class
//!   and bounded error class;
//! - `archivist.storage.multipart.abort.failures` — failed aborts, the
//!   nonzero-rate page of plan Section 7.7;
//! - `archivist.storage.operation` — one span per backend operation with
//!   its bounded classification (MET-030, MET-033).
//!
//! The label values are closed enums translated one-to-one from the
//! registry's value sets: no runtime string ever becomes a label, so a
//! backend's error text, a key, or a tenant identifier cannot reach the
//! exposition (SEC-004; MET-016, MET-022).
//!
//! [`MeasuredRawStore`] wraps any [`crate::raw_write::RawWriteStore`] and is where the
//! replica's raw-write identity is measured: the wrapper composes once at
//! startup around the concrete backend, and every operation the ingest path
//! drives — including the shutdown drain's abandoned-session aborts, which
//! go through the same wrapped store — lands in the same process-local
//! snapshot. The snapshot is atomics and a bounded span ring; rendering
//! happens on scrape, so no write path ever blocks on another.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use archivist_protocol::object_key::BlobObjectKey;
use archivist_protocol::vocabulary::StorageOutcome;

use crate::commit::{ConditionalCreateStore, CreateIfAbsent};
use crate::error::{StorageError, StorageErrorKind};
use crate::raw_write::{ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore};

/// Capacity of the bounded span ring: the newest 128 operation spans are
/// retained for inspection, and older ones fall off. A sink that grew with
/// traffic would be an unbounded memory surface on the write path.
const SPAN_RING_CAPACITY: usize = 128;

/// The OpenTelemetry span status a recorded span carries (MET-033): the
/// operation either failed — with the bounded error class naming why — or
/// it produced no error. There is no third state and no description text:
/// a status description could only carry free text, and no free text
/// belongs in telemetry (SEC-004).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpanStatus {
    /// The operation completed without an error.
    Unset,
    /// The operation failed.
    Error,
}

/// One recorded span: a registered name, a status, its registered
/// attributes, and how long the operation took.
///
/// Every field is closed by construction — the name and the attribute
/// keys and values are `'static` strings from the registry's sets, and
/// there is no field a message, a key, or an identifier could ride
/// (MET-032, SEC-004).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanRecord {
    /// The registered span name.
    pub name: &'static str,
    /// The OpenTelemetry status.
    pub status: SpanStatus,
    /// The registered attributes, at most three (MET-018).
    pub attributes: Vec<(&'static str, &'static str)>,
    /// How long the operation took.
    pub duration: Duration,
}

impl SpanRecord {
    /// A successful span with one registered attribute.
    #[must_use]
    pub fn unset(name: &'static str, attributes: &[(&'static str, &'static str)]) -> Self {
        Self {
            name,
            status: SpanStatus::Unset,
            attributes: attributes.to_vec(),
            duration: Duration::ZERO,
        }
    }

    /// A failed span naming its bounded error class.
    #[must_use]
    pub fn error(name: &'static str, attributes: &[(&'static str, &'static str)]) -> Self {
        Self {
            name,
            status: SpanStatus::Error,
            attributes: attributes.to_vec(),
            duration: Duration::ZERO,
        }
    }
}

/// The bounded span ring: the newest [`SPAN_RING_CAPACITY`] records.
///
/// Recording never blocks on a reader and a full ring drops its oldest
/// record — the sink is a diagnostic window, not a queue, and it can
/// never grow with traffic.
#[derive(Debug, Default)]
pub struct SpanSink {
    ring: Mutex<VecDeque<SpanRecord>>,
}

impl SpanSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one completed span, dropping the oldest when full.
    pub fn record(&self, record: SpanRecord) {
        let mut ring = match self.ring.lock() {
            Ok(ring) => ring,
            // A poisoned lock means a reader panicked while holding the
            // ring; the records are still a valid VecDeque, so recovery
            // is the honest move.
            Err(poisoned) => poisoned.into_inner(),
        };
        if ring.len() >= SPAN_RING_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(record);
    }

    /// A snapshot of the retained records, oldest first.
    #[must_use]
    pub fn snapshot(&self) -> Vec<SpanRecord> {
        match self.ring.lock() {
            Ok(ring) => ring.iter().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().iter().cloned().collect(),
        }
    }

    /// How many records the ring currently holds.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.ring.lock() {
            Ok(ring) => ring.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Whether the ring holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The storage operation label (`storage_operation` values, in registry
/// order). The value set is the registry's; the seam's operations map
/// onto it one-to-one and never extend it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StorageOperation {
    /// One complete object written by its exact final bytes: the single
    /// `PUT` the manifest writer and the conditional primitive both are.
    PutObject,
    /// One multipart session opened for a content-addressed blob key.
    BeginMultipart,
    /// One part streamed into an uncommitted session.
    UploadPart,
    /// One session committed after every size and digest verified.
    CompleteMultipart,
    /// One uncommitted session aborted, releasing its parts.
    AbortMultipart,
}

impl StorageOperation {
    /// Every operation, in registry order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::PutObject,
            Self::BeginMultipart,
            Self::UploadPart,
            Self::CompleteMultipart,
            Self::AbortMultipart,
        ]
    }

    /// The registered label value.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::PutObject => "put_object",
            Self::BeginMultipart => "begin_multipart",
            Self::UploadPart => "upload_part",
            Self::CompleteMultipart => "complete_multipart",
            Self::AbortMultipart => "abort_multipart",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::PutObject => 0,
            Self::BeginMultipart => 1,
            Self::UploadPart => 2,
            Self::CompleteMultipart => 3,
            Self::AbortMultipart => 4,
        }
    }
}

/// The storage failure classification (`error_class` values, in registry
/// order): the bounded class a failed operation is reported under — never
/// the backend's own error text (MET-023, SEC-004).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StorageErrorClass {
    /// The identity lacks authority for the requested object.
    Auth,
    /// The backend refused the operation by policy.
    Throttling,
    /// The backend or network is down, or refused a primitive.
    Unavailable,
    /// The operation ran past its time budget.
    Timeout,
    /// Stored state contradicts its derived identity.
    Corruption,
    /// Anything the closed kinds above do not name.
    Unknown,
}

impl StorageErrorClass {
    /// Every class, in registry order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Auth,
            Self::Throttling,
            Self::Unavailable,
            Self::Timeout,
            Self::Corruption,
            Self::Unknown,
        ]
    }

    /// The registered label value.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Throttling => "throttling",
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Corruption => "corruption",
            Self::Unknown => "unknown",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Auth => 0,
            Self::Throttling => 1,
            Self::Unavailable => 2,
            Self::Timeout => 3,
            Self::Corruption => 4,
            Self::Unknown => 5,
        }
    }

    /// The class one storage error kind is reported under: the decision
    /// the caller must make next, translated onto the registry's closed
    /// value set. A scope violation or a stale epoch is the identity's
    /// authority refusing; an integrity conflict is corruption of the
    /// derived identity; a malformed ingest-time request is nothing the
    /// closed classes above name.
    #[must_use]
    pub fn classify(kind: StorageErrorKind) -> Self {
        match kind {
            StorageErrorKind::Unavailable | StorageErrorKind::CapabilityUnavailable => {
                Self::Unavailable
            }
            StorageErrorKind::ScopeViolation | StorageErrorKind::StaleEpoch => Self::Auth,
            StorageErrorKind::IntegrityConflict => Self::Corruption,
            StorageErrorKind::MalformedInput | StorageErrorKind::InventoryFault => Self::Unknown,
        }
    }
}

/// The registered histogram boundaries for
/// `archivist.storage.operation.duration`, in seconds (MET-027): the
/// latency brackets of the storage operation budget, from a fast local
/// object write to a stalled backend the deadline guard ends.
pub const OPERATION_BOUNDARIES_SECONDS: [f64; 7] = [0.005, 0.025, 0.1, 0.5, 2.5, 10.0, 60.0];

/// The number of registered storage operations.
const OPERATION_COUNT: usize = 5;
/// The number of registered storage error classes.
const ERROR_CLASS_COUNT: usize = 6;
/// Seven registered boundaries plus the implicit infinite one.
const OPERATION_BUCKETS: usize = OPERATION_BOUNDARIES_SECONDS.len() + 1;

/// The process-local storage telemetry snapshot: latency buckets, failure
/// counts, multipart-abort failures, and the operation span ring.
///
/// Every field is an atomic or a bounded ring; the snapshot is shared
/// behind the replica state and rendered on scrape, so no write path ever
/// blocks on another.
#[derive(Debug, Default)]
pub struct StorageTelemetry {
    /// Per-operation bucket counts, last bucket the overflow.
    buckets: [[AtomicU64; OPERATION_BUCKETS]; OPERATION_COUNT],
    /// Per-operation accumulated duration, in nanoseconds.
    sum_nanos: [AtomicU64; OPERATION_COUNT],
    /// Per-operation attempt counts.
    counts: [AtomicU64; OPERATION_COUNT],
    /// Per-operation, per-class failure counts.
    failures: [[AtomicU64; ERROR_CLASS_COUNT]; OPERATION_COUNT],
    /// Failed multipart aborts, wherever the abort ran.
    abort_failures: AtomicU64,
    /// The operation span ring.
    spans: SpanSink,
}

/// The registered name of the per-operation span.
pub const OPERATION_SPAN_NAME: &str = "archivist.storage.operation";

impl StorageTelemetry {
    /// A fresh snapshot: every counter and bucket at zero, no spans.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The operation span ring, shared with the snapshot.
    #[must_use]
    pub const fn spans(&self) -> &SpanSink {
        &self.spans
    }

    /// Record one backend operation attempt: its duration lands in the
    /// operation's histogram, a failure lands in its class's counter —
    /// and a failed abort also lands in the multipart-abort failure
    /// counter, the signal a nonzero rate pages (plan Section 7.7) — and
    /// one operation span closes with the bounded classification.
    pub fn record(
        &self,
        operation: StorageOperation,
        duration: Duration,
        outcome: Result<(), StorageError>,
    ) {
        let op = operation.index();
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        let bucket = bucket_for(nanos, &OPERATION_BOUNDARIES_SECONDS);
        self.buckets[op][bucket].fetch_add(1, Ordering::Relaxed);
        self.sum_nanos[op].fetch_add(nanos, Ordering::Relaxed);
        self.counts[op].fetch_add(1, Ordering::Relaxed);

        let class = outcome.err().map(|error| {
            let class = StorageErrorClass::classify(error.kind());
            self.failures[op][class.index()].fetch_add(1, Ordering::Relaxed);
            if operation == StorageOperation::AbortMultipart {
                self.abort_failures.fetch_add(1, Ordering::Relaxed);
            }
            class
        });

        let mut attributes = vec![("archivist.storage_operation", operation.token())];
        let span = match class {
            Some(class) => {
                attributes.push(("archivist.error_class", class.token()));
                SpanRecord::error(OPERATION_SPAN_NAME, &attributes)
            }
            None => SpanRecord::unset(OPERATION_SPAN_NAME, &attributes),
        };
        self.spans.record(SpanRecord { duration, ..span });
    }

    /// Render the Prometheus text exposition (format 0.0.4) for this
    /// snapshot: the three registered storage families, every registered
    /// label value pre-emitted at zero so a dashboard can join on the
    /// series before the first backend call.
    #[must_use]
    pub fn exposition(&self) -> String {
        let mut out = String::new();

        out.push_str("# TYPE archivist_storage_operation_duration_seconds histogram\n");
        for operation in StorageOperation::all() {
            let op = operation.index();
            let label = format!("archivist_storage_operation=\"{}\"", operation.token());
            let mut cumulative = 0u64;
            for (bound, bucket) in OPERATION_BOUNDARIES_SECONDS.iter().zip(
                self.buckets[op]
                    .iter()
                    .take(OPERATION_BOUNDARIES_SECONDS.len()),
            ) {
                cumulative += bucket.load(Ordering::Relaxed);
                let _ = writeln!(
                    out,
                    "archivist_storage_operation_duration_seconds_bucket{{{label},le=\"{bound}\"}} {cumulative}"
                );
            }
            cumulative += self.buckets[op][OPERATION_BUCKETS - 1].load(Ordering::Relaxed);
            out.push_str(
                "archivist_storage_operation_duration_seconds_bucket{\
                 archivist_storage_operation=\"",
            );
            out.push_str(operation.token());
            out.push_str("\",le=\"+Inf\"} ");
            let _ = writeln!(out, "{cumulative}");
            let _ = writeln!(
                out,
                "archivist_storage_operation_duration_seconds_sum{{archivist_storage_operation=\"{}\"}} {}",
                operation.token(),
                render_seconds(self.sum_nanos[op].load(Ordering::Relaxed))
            );
            let _ = writeln!(
                out,
                "archivist_storage_operation_duration_seconds_count{{archivist_storage_operation=\"{}\"}} {}",
                operation.token(),
                self.counts[op].load(Ordering::Relaxed)
            );
        }

        out.push_str("# TYPE archivist_storage_operation_failures_errors counter\n");
        for operation in StorageOperation::all() {
            let op = operation.index();
            for class in StorageErrorClass::all() {
                let _ = writeln!(
                    out,
                    "archivist_storage_operation_failures_errors_total{{archivist_storage_operation=\"{}\",archivist_error_class=\"{}\"}} {}",
                    operation.token(),
                    class.token(),
                    self.failures[op][class.index()].load(Ordering::Relaxed)
                );
            }
        }

        out.push_str("# TYPE archivist_storage_multipart_abort_failures_errors counter\n");
        let _ = writeln!(
            out,
            "archivist_storage_multipart_abort_failures_errors_total {}",
            self.abort_failures.load(Ordering::Relaxed)
        );

        out
    }
}

/// The bucket index one duration lands in: the first boundary strictly
/// above the duration, or the overflow bucket. The nanosecond count only
/// ever compares against the registered boundaries, so the conversion's
/// rounding above 2^53 nanoseconds (104 days, far past any operation
/// budget) is irrelevant to the bucket chosen. Shared with the server
/// surface, whose registered histograms follow the identical convention.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn bucket_for(nanos: u64, boundaries_seconds: &[f64]) -> usize {
    let seconds = nanos as f64 / 1_000_000_000.0;
    for (index, bound) in boundaries_seconds.iter().enumerate() {
        if seconds < *bound {
            return index;
        }
    }
    boundaries_seconds.len()
}

/// Render nanoseconds as the seconds value a `_sum` series carries. The
/// conversion's rounding above 2^53 nanoseconds is far below exposition
/// significance for operation durations. Shared with the server surface,
/// whose registered histograms follow the identical convention.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn render_seconds(nanos: u64) -> String {
    let seconds = nanos as f64 / 1_000_000_000.0;
    let mut text = String::new();
    let _ = write!(text, "{seconds}");
    text
}

/// Render one histogram boundary as its `le` label text. Rust's shortest
/// float rendering is exactly the exposition convention for these
/// registered boundaries (`0.005`, `2.5`, `60`).
#[must_use]
pub fn bucket_le_text(bound: f64) -> String {
    let mut text = String::new();
    let _ = write!(text, "{bound}");
    text
}

/// The measured raw-write identity: every [`RawWriteStore`] operation the
/// replica drives is timed and classified against the shared
/// [`StorageTelemetry`] before the backend's own answer travels through
/// untouched.
///
/// The wrapper is transparent by contract: answers, errors, and outcomes
/// pass through byte-for-byte, and a failed abort is both the wrapped
/// error and a multipart-abort failure recorded — the shutdown drain
/// aborts through this same store, so its failures land in the same
/// process-local snapshot.
#[derive(Debug)]
pub struct MeasuredRawStore<S> {
    inner: S,
    telemetry: Arc<StorageTelemetry>,
}

impl<S> MeasuredRawStore<S> {
    /// Wrap one raw-write identity in measurement.
    #[must_use]
    pub fn new(inner: S, telemetry: Arc<StorageTelemetry>) -> Self {
        Self { inner, telemetry }
    }

    /// The wrapped identity: the seam only times and classifies the
    /// backend's own answers, so an observer that inspects the backend —
    /// a probe, a test double's recording handle — reaches it here,
    /// unchanged.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    async fn measure<F, T>(&self, operation: StorageOperation, call: F) -> Result<T, StorageError>
    where
        F: std::future::Future<Output = Result<T, StorageError>> + Send,
        T: Send,
    {
        let start = std::time::Instant::now();
        let result = call.await;
        self.telemetry.record(
            operation,
            start.elapsed(),
            result.as_ref().map_err(|error| *error).map(|_| ()),
        );
        result
    }
}

// The wrapper's futures hold `&S` across their await points, so sharing
// the wrapped store by reference — the trait's concurrency contract —
// requires the wrapped store to be `Sync`, exactly as any direct
// implementation sharing `&self` across awaits is.
impl<S: RawWriteStore + Sync> RawWriteStore for MeasuredRawStore<S> {
    fn capabilities(&self) -> crate::capability::StoreCapabilities {
        // A report, not an operation: the trait contract keeps I/O off
        // this call, so there is no latency to measure and nothing to
        // classify.
        self.inner.capabilities()
    }

    async fn write_manifest(
        &self,
        key: &ManifestKey,
        bytes: &[u8],
    ) -> Result<StorageOutcome, StorageError> {
        self.measure(
            StorageOperation::PutObject,
            self.inner.write_manifest(key, bytes),
        )
        .await
    }

    async fn begin_multipart(
        &self,
        blob: &BlobObjectKey,
    ) -> Result<MultipartUploadId, StorageError> {
        self.measure(
            StorageOperation::BeginMultipart,
            self.inner.begin_multipart(blob),
        )
        .await
    }

    async fn write_part(
        &self,
        upload: &MultipartUploadId,
        part: PartNumber,
        bytes: &[u8],
    ) -> Result<PartCommitment, StorageError> {
        self.measure(
            StorageOperation::UploadPart,
            self.inner.write_part(upload, part, bytes),
        )
        .await
    }

    async fn commit_multipart(
        &self,
        upload: &MultipartUploadId,
        parts: &[PartCommitment],
    ) -> Result<StorageOutcome, StorageError> {
        self.measure(
            StorageOperation::CompleteMultipart,
            self.inner.commit_multipart(upload, parts),
        )
        .await
    }

    async fn abort_multipart(&self, upload: &MultipartUploadId) -> Result<(), StorageError> {
        self.measure(
            StorageOperation::AbortMultipart,
            self.inner.abort_multipart(upload),
        )
        .await
    }
}

impl<S: ConditionalCreateStore + Sync> ConditionalCreateStore for MeasuredRawStore<S> {
    async fn create_manifest_if_absent(
        &self,
        key: &ManifestKey,
        bytes: &[u8],
    ) -> Result<CreateIfAbsent, StorageError> {
        // The atomic conditional create is the backend's own `PUT`-shaped
        // primitive: one write operation, whichever answer resolves.
        self.measure(
            StorageOperation::PutObject,
            self.inner.create_manifest_if_absent(key, bytes),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        OPERATION_BOUNDARIES_SECONDS, OPERATION_SPAN_NAME, SpanRecord, SpanSink, SpanStatus,
        StorageErrorClass, StorageOperation, StorageTelemetry, bucket_for, bucket_le_text,
    };
    use crate::error::{StorageError, StorageErrorKind};

    /// The registered boundaries in whole nanoseconds.
    const BOUNDARY_NANOS: [u64; 7] = [
        5_000_000,
        25_000_000,
        100_000_000,
        500_000_000,
        2_500_000_000,
        10_000_000_000,
        60_000_000_000,
    ];

    #[test]
    fn the_registered_sets_have_their_registry_cardinalities() {
        assert_eq!(StorageOperation::all().len(), 5);
        assert_eq!(StorageErrorClass::all().len(), 6);
    }

    #[test]
    fn label_tokens_match_the_registered_sets() {
        assert!(
            StorageOperation::all()
                .iter()
                .copied()
                .map(StorageOperation::token)
                .eq([
                    "put_object",
                    "begin_multipart",
                    "upload_part",
                    "complete_multipart",
                    "abort_multipart",
                ])
        );
        assert!(
            StorageErrorClass::all()
                .iter()
                .copied()
                .map(StorageErrorClass::token)
                .eq([
                    "auth",
                    "throttling",
                    "unavailable",
                    "timeout",
                    "corruption",
                    "unknown"
                ])
        );
    }

    #[test]
    fn every_error_kind_classifies_into_the_closed_set() {
        assert_eq!(
            StorageErrorClass::classify(StorageErrorKind::Unavailable),
            StorageErrorClass::Unavailable
        );
        assert_eq!(
            StorageErrorClass::classify(StorageErrorKind::CapabilityUnavailable),
            StorageErrorClass::Unavailable
        );
        assert_eq!(
            StorageErrorClass::classify(StorageErrorKind::ScopeViolation),
            StorageErrorClass::Auth
        );
        assert_eq!(
            StorageErrorClass::classify(StorageErrorKind::StaleEpoch),
            StorageErrorClass::Auth
        );
        assert_eq!(
            StorageErrorClass::classify(StorageErrorKind::IntegrityConflict),
            StorageErrorClass::Corruption
        );
        assert_eq!(
            StorageErrorClass::classify(StorageErrorKind::MalformedInput),
            StorageErrorClass::Unknown
        );
        assert_eq!(
            StorageErrorClass::classify(StorageErrorKind::InventoryFault),
            StorageErrorClass::Unknown
        );
    }

    #[test]
    fn durations_land_in_the_registered_buckets() {
        // Strictly below the first boundary is bucket zero.
        assert_eq!(
            bucket_for(BOUNDARY_NANOS[0] - 1, &OPERATION_BOUNDARIES_SECONDS),
            0
        );
        // Each boundary's own value lands in the bucket it opens.
        for (index, bound_nanos) in BOUNDARY_NANOS.iter().enumerate() {
            assert_eq!(
                bucket_for(*bound_nanos, &OPERATION_BOUNDARIES_SECONDS),
                index + 1
            );
        }
        // Past the last boundary is the overflow bucket.
        assert_eq!(
            bucket_for(BOUNDARY_NANOS[6] + 1, &OPERATION_BOUNDARIES_SECONDS),
            OPERATION_BOUNDARIES_SECONDS.len()
        );
        assert_eq!(
            bucket_for(u64::MAX, &OPERATION_BOUNDARIES_SECONDS),
            OPERATION_BOUNDARIES_SECONDS.len()
        );
    }

    #[test]
    fn a_success_records_latency_and_one_unset_span() {
        let telemetry = StorageTelemetry::new();
        telemetry.record(
            StorageOperation::PutObject,
            Duration::from_millis(3),
            Ok(()),
        );
        let text = telemetry.exposition();
        assert!(
            text.contains(
                "archivist_storage_operation_duration_seconds_bucket{\
                 archivist_storage_operation=\"put_object\",le=\"0.005\"} 1\n"
            ),
            "{text}"
        );
        assert!(text.contains(
            "archivist_storage_operation_duration_seconds_count{\
                 archivist_storage_operation=\"put_object\"} 1\n"
        ));
        assert!(text.contains("_sum{archivist_storage_operation=\"put_object\"} 0.003"));
        // No failure series moved anywhere.
        assert!(!text.contains(
            "archivist_storage_operation_failures_errors_total{\
                             archivist_storage_operation=\"put_object\",\
                             archivist_error_class=\"unavailable\"} 1"
        ));
        // One span, unset status, the operation attribute only.
        let spans = telemetry.spans().snapshot();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].name, OPERATION_SPAN_NAME);
        assert_eq!(spans[0].status, SpanStatus::Unset);
        assert_eq!(
            spans[0].attributes,
            vec![("archivist.storage_operation", "put_object")]
        );
    }

    #[test]
    fn a_failure_records_its_class_and_an_error_span() {
        let telemetry = StorageTelemetry::new();
        telemetry.record(
            StorageOperation::CompleteMultipart,
            Duration::from_millis(12),
            Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
        );
        let text = telemetry.exposition();
        assert!(
            text.contains(
                "archivist_storage_operation_failures_errors_total{\
                 archivist_storage_operation=\"complete_multipart\",\
                 archivist_error_class=\"unavailable\"} 1\n"
            ),
            "{text}"
        );
        let spans = telemetry.spans().snapshot();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].status, SpanStatus::Error);
        assert_eq!(
            spans[0].attributes,
            vec![
                ("archivist.storage_operation", "complete_multipart"),
                ("archivist.error_class", "unavailable"),
            ]
        );
    }

    #[test]
    fn a_failed_abort_also_lands_in_the_abort_failure_family() {
        let telemetry = StorageTelemetry::new();
        telemetry.record(
            StorageOperation::AbortMultipart,
            Duration::from_millis(1),
            Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
        );
        let text = telemetry.exposition();
        assert!(
            text.contains("archivist_storage_multipart_abort_failures_errors_total 1\n"),
            "{text}"
        );
        // A successful abort never moves the page signal.
        telemetry.record(
            StorageOperation::AbortMultipart,
            Duration::from_millis(1),
            Ok(()),
        );
        assert!(
            telemetry
                .exposition()
                .contains("archivist_storage_multipart_abort_failures_errors_total 1\n")
        );
    }

    #[test]
    fn a_fresh_snapshot_pre_emits_every_registered_series() {
        let text = StorageTelemetry::new().exposition();
        // Eight buckets plus the infinite one, the sum, and the count, per
        // operation.
        assert_eq!(text.matches("_bucket{").count(), 5 * 8);
        assert_eq!(text.matches("le=\"+Inf\"").count(), 5);
        assert_eq!(text.matches("_seconds_sum{").count(), 5);
        assert_eq!(text.matches("_seconds_count{").count(), 5);
        // Five operations times six classes of failures.
        assert_eq!(
            text.matches("archivist_storage_operation_failures_errors_total{")
                .count(),
            30
        );
        // And the abort family, pre-emitted at zero.
        assert!(
            text.contains("archivist_storage_multipart_abort_failures_errors_total 0\n"),
            "{text}"
        );
    }

    #[test]
    fn the_exposition_names_are_the_pinned_translation() {
        let text = StorageTelemetry::new().exposition();
        // MET-011, spelled out: unit suffix then the counter total.
        assert!(text.contains("# TYPE archivist_storage_operation_duration_seconds histogram"));
        assert!(text.contains("# TYPE archivist_storage_operation_failures_errors counter"));
        assert!(
            text.contains("# TYPE archivist_storage_multipart_abort_failures_errors counter"),
            "{text}"
        );
    }

    #[test]
    fn bucket_boundaries_render_without_trailing_zeros() {
        assert_eq!(bucket_le_text(0.005), "0.005");
        assert_eq!(bucket_le_text(2.5), "2.5");
        assert_eq!(bucket_le_text(60.0), "60");
    }

    #[test]
    fn the_span_ring_is_bounded_and_drops_its_oldest() {
        let sink = SpanSink::new();
        for _ in 0..200 {
            sink.record(SpanRecord::unset("archivist.storage.operation", &[]));
        }
        assert_eq!(sink.len(), 128);
        // The oldest records fell off; the ring holds the newest.
        assert_eq!(sink.snapshot().len(), 128);
    }

    #[test]
    fn span_records_carry_only_their_registered_fields() {
        let record = SpanRecord::error(
            OPERATION_SPAN_NAME,
            &[("archivist.storage_operation", "abort_multipart")],
        );
        // The debug rendering is the whole record: nothing beyond the
        // name, the status, the registered attributes, and the duration
        // exists to leak.
        let rendered = format!("{record:?}");
        assert!(rendered.contains("archivist.storage.operation"));
        assert!(rendered.contains("Error"));
    }
}
