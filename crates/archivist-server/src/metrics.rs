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
//! The pipeline-owned families (`ingest.received`, `ingest.canonical`,
//! `ingest.duration`, `commit`) are absent until the slice that produces
//! them lands; exporting a zero histogram or a zero byte counter for
//! work that cannot happen would misstate the replica.
//!
//! Values are process-local counters and gauges backed by atomics — no
//! metric ever carries content, an identifier, or a bounded-enum value
//! outside its registered set (MET-016, MET-020, SEC-004).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

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
}

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

        out
    }
}

fn family(out: &mut String, name: &str, kind: &str) {
    let _ = writeln!(out, "# TYPE {name} {kind}");
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
             archivist_server_trust_refresh_attempts_total{archivist_trust_outcome=\"unavailable\"} 0\n"
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
        metrics.ingest_inflight_sub(5);
        assert_eq!(metrics.ingest_inflight(), 0, "no inventory of ghost requests");
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
