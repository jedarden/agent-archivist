// SPDX-License-Identifier: Apache-2.0

//! The shared per-replica state: the validated configuration, the trust
//! anchor set, the two storage identities, and the readiness evidence —
//! one value, composed once at startup, shared by reference across every
//! request handler.
//!
//! The state holds **no durable local state**: nothing here names a file,
//! a socket, or a disk path, and nothing here outlives the process. That
//! is the bootstrap half of the statelessness contract (plan Sections 4
//! and 5): a replica's entire world is what was handed to
//! [`ServerState::new`] — S3-compatible storage remains the only durable
//! server-side truth.
//!
//! # Readiness evidence
//!
//! Plan Phase 4: readiness requires a successful signed control-record
//! read for each configured tenant within the last 60 seconds, and a
//! replica stops advertising readiness immediately when that evidence
//! expires. [`ReadinessTracker`] is the evidence ledger: it starts with
//! none, accepts evidence per configured tenant, and evaluates readiness
//! on demand — the freshness check runs at request time, so expiry is
//! immediate and does not wait for a refresh tick (EC-09: the cache
//! bounds trust, it never extends it).
//!
//! The tracker never touches storage: readiness is derived from evidence
//! the control-record refresh records, never probed — a readiness check
//! that wrote a probe object would be a durable server-side write with
//! no caller, and there is no such thing here. The producer of the
//! evidence — the control-record refresh that verifies records through
//! the tenant authority keys of [`crate::trust::TrustConfig`] — arrives
//! with the trust verification slice; until then a replica starts
//! not-ready and fails closed, which is the honest state for a replica
//! that has proven nothing yet.
//!
//! # Admission
//!
//! The state also holds the replica's one [`AdmissionGate`] (plan
//! Section 7.6): the process-wide in-flight cap, the per-client share,
//! and the per-client new-request bucket, built from the validated
//! configuration at composition and enforced before anything
//! request-derived happens — the route-level half (deadline, process
//! cap) on the bootstrap surface, the per-client half wherever the
//! uploader identity is first known. The gate shares the state's
//! metrics snapshot, so its refusals land in the registered
//! `archivist.server.ingest` family and its admissions move the
//! registered `archivist.server.ingest.inflight` gauge — both
//! content-free (SEC-004).

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use archivist_protocol::vocabulary::TenantId;
use archivist_storage::ingest::IngestStorage;

use crate::config::ServerConfig;
use crate::guard::AdmissionGate;
use crate::metrics::ServerMetrics;
use crate::trust::TrustConfig;

/// How long one successful tenant trust-record read stays fresh
/// (plan Phase 4; the 60-second trust cache of EC-09).
pub const TRUST_EVIDENCE_WINDOW: Duration = Duration::from_mins(1);

/// Why a replica is not ready: a closed, content-free class carried in
/// the readiness body. There is no reason to report when ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NotReadyReason {
    /// No trust evidence exists for at least one configured tenant —
    /// including the state of a replica that has proven nothing yet.
    TrustEvidenceAbsent,
    /// Every tenant had evidence once, but at least one has expired
    /// past the 60-second window.
    TrustEvidenceStale,
}

impl NotReadyReason {
    /// Every reason, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::TrustEvidenceAbsent, Self::TrustEvidenceStale]
    }

    /// The content-free token the readiness body carries.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::TrustEvidenceAbsent => "trust_evidence_absent",
            Self::TrustEvidenceStale => "trust_evidence_stale",
        }
    }
}

/// The readiness of one replica at one instant, reduced to content-free
/// facts: a boolean, two counts, and — when not ready — one closed
/// reason class. No tenant identifier ever appears (SEC-004).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessSnapshot {
    /// Whether every configured tenant has fresh trust evidence.
    pub ready: bool,
    /// How many configured tenants currently hold fresh evidence.
    pub tenants_ready: usize,
    /// How many tenants the replica is configured to serve.
    pub tenants_configured: usize,
    /// The closed reason class, when not ready.
    pub reason: Option<NotReadyReason>,
}

/// The per-tenant trust-evidence ledger: which configured tenants hold
/// evidence, and how old their newest successful read is.
#[derive(Debug)]
pub struct ReadinessTracker {
    tenants: RwLock<Vec<(TenantId, Option<Instant>)>>,
}

impl ReadinessTracker {
    /// Open a ledger for the configured tenants: every tenant starts
    /// with no evidence.
    #[must_use]
    pub fn new(trust: &TrustConfig) -> Self {
        Self {
            tenants: RwLock::new(
                trust
                    .roots()
                    .iter()
                    .map(|root| (root.tenant().clone(), None))
                    .collect(),
            ),
        }
    }

    /// Record one successful trust-record read for a configured tenant.
    ///
    /// Returns `false` — and records nothing — for a tenant outside the
    /// configuration: evidence can only ever exist for a tenant the
    /// replica serves, and an unknown tenant is a caller bug to surface,
    /// not a state to grow.
    ///
    /// # Panics
    /// Only if the readiness ledger is poisoned — a concurrent panic
    /// while holding it, which is itself a bug.
    pub fn record_trust_evidence(&self, tenant: &TenantId) -> bool {
        let mut tenants = self.tenants.write().expect("readiness ledger poisoned");
        match tenants.iter_mut().find(|(known, _)| known == tenant) {
            Some((_, evidence)) => {
                *evidence = Some(Instant::now());
                true
            }
            None => false,
        }
    }

    /// Whether one configured tenant currently holds fresh evidence.
    ///
    /// # Panics
    /// Only if the readiness ledger is poisoned — a concurrent panic
    /// while holding it, which is itself a bug.
    #[must_use]
    pub fn has_fresh_evidence(&self, tenant: &TenantId, now: Instant) -> bool {
        let tenants = self.tenants.read().expect("readiness ledger poisoned");
        tenants.iter().any(|(known, evidence)| {
            known == tenant
                && evidence.is_some_and(|at| now.duration_since(at) <= TRUST_EVIDENCE_WINDOW)
        })
    }

    /// The age of the newest successful trust-record read across all
    /// configured tenants, or `None` while no read has ever succeeded.
    ///
    /// # Panics
    /// Only if the readiness ledger is poisoned — a concurrent panic
    /// while holding it, which is itself a bug.
    #[must_use]
    pub fn newest_evidence_age(&self, now: Instant) -> Option<Duration> {
        let tenants = self.tenants.read().expect("readiness ledger poisoned");
        tenants
            .iter()
            .filter_map(|(_, evidence)| evidence.as_ref())
            .map(|at| now.duration_since(*at))
            .min()
    }

    /// Evaluate readiness at `now`: every configured tenant must hold
    /// evidence inside [`TRUST_EVIDENCE_WINDOW`].
    ///
    /// # Panics
    /// Only if the readiness ledger is poisoned — a concurrent panic
    /// while holding it, which is itself a bug.
    #[must_use]
    pub fn evaluate(&self, now: Instant) -> ReadinessSnapshot {
        let tenants = self.tenants.read().expect("readiness ledger poisoned");
        let tenants_configured = tenants.len();
        let mut tenants_ready = 0usize;
        let mut any_absent = false;
        for (_, evidence) in tenants.iter() {
            match evidence {
                Some(at) if now.duration_since(*at) <= TRUST_EVIDENCE_WINDOW => tenants_ready += 1,
                // Stale evidence is only distinguishable from absent when
                // some tenant is not ready at all; the reason class below
                // derives staleness by elimination, so it is not recorded.
                Some(_) => {}
                None => any_absent = true,
            }
        }
        let ready = tenants_ready == tenants_configured;
        let reason = if ready {
            None
        } else if any_absent {
            Some(NotReadyReason::TrustEvidenceAbsent)
        } else {
            Some(NotReadyReason::TrustEvidenceStale)
        };
        ReadinessSnapshot {
            ready,
            tenants_ready,
            tenants_configured,
            reason,
        }
    }
}

/// The shared per-replica state, composed once at startup.
pub struct ServerState<W, C> {
    config: ServerConfig,
    trust: TrustConfig,
    storage: IngestStorage<W, C>,
    readiness: ReadinessTracker,
    gate: AdmissionGate,
    metrics: Arc<ServerMetrics>,
}

impl<W, C> ServerState<W, C> {
    /// Compose the state of one replica from validated parts.
    ///
    /// Construction performs no I/O and writes nothing: this is the
    /// property the no-durable-local-state acceptance names.
    #[must_use]
    pub fn new(config: ServerConfig, trust: TrustConfig, storage: IngestStorage<W, C>) -> Self {
        let metrics = Arc::new(ServerMetrics::new());
        Self {
            readiness: ReadinessTracker::new(&trust),
            gate: AdmissionGate::new(&config, Arc::clone(&metrics)),
            metrics,
            config,
            trust,
            storage,
        }
    }

    /// The validated configuration.
    #[must_use]
    pub const fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The trust anchor set.
    #[must_use]
    pub const fn trust(&self) -> &TrustConfig {
        &self.trust
    }

    /// The two storage identities.
    #[must_use]
    pub const fn storage(&self) -> &IngestStorage<W, C> {
        &self.storage
    }

    /// Evaluate readiness now.
    #[must_use]
    pub fn readiness(&self) -> ReadinessSnapshot {
        self.readiness.evaluate(Instant::now())
    }

    /// The replica's admission gate: the resource guards every ingest
    /// request meets before anything request-derived happens.
    #[must_use]
    pub const fn gate(&self) -> &AdmissionGate {
        &self.gate
    }

    /// The process-local metrics snapshot: handlers record into it,
    /// the `/metrics` exposition renders from it, and the admission
    /// gate shares it.
    #[must_use]
    pub fn metrics(&self) -> &ServerMetrics {
        &self.metrics
    }

    /// Record one successful trust-record read for a configured tenant.
    ///
    /// Returns `false` for a tenant outside the trust configuration.
    pub fn record_trust_evidence(&self, tenant: &TenantId) -> bool {
        self.readiness.record_trust_evidence(tenant)
    }

    /// The age of the newest successful trust-record read, in whole
    /// seconds, or `None` while no read has ever succeeded.
    #[must_use]
    pub fn newest_trust_age_seconds(&self) -> Option<u64> {
        self.readiness
            .newest_evidence_age(Instant::now())
            .map(|age| age.as_secs())
    }
}

impl<W, C> fmt::Debug for ServerState<W, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerState")
            .field("config", &self.config)
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{NotReadyReason, ReadinessTracker, TRUST_EVIDENCE_WINDOW};
    use crate::trust::{TenantTrustRoot, TrustConfig};
    use archivist_protocol::vocabulary::TenantId;
    use std::time::{Duration, Instant};

    const TENANT_A: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const TENANT_B: &str = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d";
    const KEY_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const KEY_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn two_tenant_config() -> TrustConfig {
        TrustConfig::from_roots(vec![
            TenantTrustRoot::new(TENANT_A, KEY_A).unwrap(),
            TenantTrustRoot::new(TENANT_B, KEY_B).unwrap(),
        ])
        .unwrap()
    }

    #[test]
    fn the_evidence_window_is_the_plan_sixty_seconds() {
        assert_eq!(TRUST_EVIDENCE_WINDOW.as_secs(), 60);
    }

    #[test]
    fn a_fresh_ledger_is_not_ready() {
        let tracker = ReadinessTracker::new(&two_tenant_config());
        let snapshot = tracker.evaluate(Instant::now());
        assert!(!snapshot.ready);
        assert_eq!(snapshot.tenants_configured, 2);
        assert_eq!(snapshot.tenants_ready, 0);
        assert_eq!(snapshot.reason, Some(NotReadyReason::TrustEvidenceAbsent));
        assert!(tracker.newest_evidence_age(Instant::now()).is_none());
    }

    #[test]
    fn evidence_makes_one_tenant_ready_not_both() {
        let tracker = ReadinessTracker::new(&two_tenant_config());
        let tenant_a: TenantId = TENANT_A.parse().unwrap();
        assert!(tracker.record_trust_evidence(&tenant_a));
        let snapshot = tracker.evaluate(Instant::now());
        assert!(!snapshot.ready);
        assert_eq!(snapshot.tenants_ready, 1);
        assert_eq!(snapshot.tenants_configured, 2);
        // One absent tenant dominates the reason class.
        assert_eq!(snapshot.reason, Some(NotReadyReason::TrustEvidenceAbsent));
    }

    #[test]
    fn all_fresh_evidence_is_ready() {
        let tracker = ReadinessTracker::new(&two_tenant_config());
        tracker.record_trust_evidence(&TENANT_A.parse().unwrap());
        tracker.record_trust_evidence(&TENANT_B.parse().unwrap());
        let snapshot = tracker.evaluate(Instant::now());
        assert!(snapshot.ready);
        assert_eq!(snapshot.tenants_ready, 2);
        assert_eq!(snapshot.reason, None);
    }

    #[test]
    fn evidence_expires_immediately_past_the_window() {
        let tracker = ReadinessTracker::new(&two_tenant_config());
        // The provable freshness interval is anchored to instants captured
        // around the recording: every evidence instant lies in
        // `[before, after]`, so `before + WINDOW` proves fresh (`<=`) and
        // `after + WINDOW + 1ns` proves expired — expiry lands "immediately
        // past the window" within that capture gap.
        let before = Instant::now();
        tracker.record_trust_evidence(&TENANT_A.parse().unwrap());
        tracker.record_trust_evidence(&TENANT_B.parse().unwrap());
        let after = Instant::now();

        assert!(tracker.evaluate(before + TRUST_EVIDENCE_WINDOW).ready);

        let snapshot = tracker.evaluate(after + TRUST_EVIDENCE_WINDOW + Duration::from_nanos(1));
        assert!(!snapshot.ready);
        assert_eq!(snapshot.tenants_ready, 0);
        assert_eq!(snapshot.reason, Some(NotReadyReason::TrustEvidenceStale));
    }

    #[test]
    fn one_stale_tenant_is_not_ready_but_counted() {
        let tracker = ReadinessTracker::new(&two_tenant_config());
        tracker.record_trust_evidence(&TENANT_A.parse().unwrap());
        // A real gap between the two recordings (coarse clocks can return
        // the same instant for adjacent calls) so the evaluation instant
        // below is unambiguously past B's boundary while inside A's.
        std::thread::sleep(Duration::from_millis(2));
        tracker.record_trust_evidence(&TENANT_B.parse().unwrap());
        std::thread::sleep(Duration::from_millis(2));
        let a_rerecorded = Instant::now();
        tracker.record_trust_evidence(&TENANT_A.parse().unwrap());

        // Evaluate exactly one window after A's re-recording: A's evidence
        // is at most one window old (fresh — `<=`), and B's is a whole
        // recording gap older than A's, so it is past its window (stale).
        // Both facts follow from the captured instant, with no assumption
        // about scheduling delay.
        let snapshot = tracker.evaluate(a_rerecorded + TRUST_EVIDENCE_WINDOW);
        assert!(!snapshot.ready);
        assert_eq!(snapshot.tenants_ready, 1);
        assert_eq!(snapshot.reason, Some(NotReadyReason::TrustEvidenceStale));
    }

    #[test]
    fn unknown_tenants_cannot_grow_the_ledger() {
        let tracker = ReadinessTracker::new(&two_tenant_config());
        let stranger: TenantId = "99999999-9999-4999-8999-999999999999".parse().unwrap();
        assert!(!tracker.record_trust_evidence(&stranger));
        assert!(!tracker.has_fresh_evidence(&stranger, Instant::now()));
        assert_eq!(tracker.evaluate(Instant::now()).tenants_configured, 2);
    }

    #[test]
    fn the_newest_evidence_age_is_the_minimum_across_tenants() {
        let tracker = ReadinessTracker::new(&two_tenant_config());
        assert!(tracker.newest_evidence_age(Instant::now()).is_none());
        tracker.record_trust_evidence(&TENANT_A.parse().unwrap());
        tracker.record_trust_evidence(&TENANT_B.parse().unwrap());
        tracker.record_trust_evidence(&TENANT_A.parse().unwrap());
        let age = tracker.newest_evidence_age(Instant::now()).unwrap();
        // The newest read (tenant A's second one) is within test-execution
        // noise of now.
        assert!(age < Duration::from_secs(1));
    }

    #[test]
    fn not_ready_reasons_stay_content_free() {
        for reason in NotReadyReason::all() {
            assert!(
                reason
                    .token()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
            );
        }
    }
}
