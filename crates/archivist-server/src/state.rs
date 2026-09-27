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
//! evidence is [`ServerState::record_verified_control_read`]: it accepts
//! only bytes returned by the control-read boundary after the
//! tenant-authority signature has been verified — through the bounded
//! 60-second trust cache composed at the resolution seam (EC-09), so a
//! registry outage serves cached trust for at most the lease and then
//! fails closed with the retryable unavailable class while the ledger's
//! own window lets the evidence lapse. Until anything is verified a
//! replica starts not-ready and fails closed, which is the honest state
//! for a replica that has proven nothing yet.
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

use std::cell::Cell;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use archivist_auth::authority::{
    AuthorityChainError, PinnedAuthorityRoot, resolve_authority, verify_control_record_resolved,
};
#[cfg(test)]
use archivist_auth::trust_cache::TrustCacheClock;
use archivist_auth::trust_cache::{BoundedTrustCache, SystemClock};
use archivist_protocol::vocabulary::{Ed25519PublicKey, KeyId, TenantId};
use archivist_storage::control::{ControlReadStore, ControlRecord};
use archivist_storage::ingest::IngestStorage;
use archivist_storage::multipart::OpenUploads;
use archivist_storage::raw_write::RawWriteStore;
use archivist_storage::telemetry::{MeasuredRawStore, StorageTelemetry};

use crate::config::ServerConfig;
use crate::guard::AdmissionGate;
use crate::metrics::{ServerMetrics, TrustRefreshOutcome};
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
    fn record_evidence(&self, tenant: &TenantId) -> bool {
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
                && evidence
                    .is_some_and(|at| now.saturating_duration_since(at) < TRUST_EVIDENCE_WINDOW)
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
            .map(|at| now.saturating_duration_since(*at))
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
                Some(at) if now.saturating_duration_since(*at) < TRUST_EVIDENCE_WINDOW => {
                    tenants_ready += 1;
                }
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
    /// The composed storage identities behind the measurement seam: every
    /// raw-write operation any handler or the shutdown drain drives is
    /// timed and classified into the storage telemetry snapshot before
    /// the backend's own answer travels through untouched.
    storage: IngestStorage<MeasuredRawStore<W>, C>,
    /// The process-local storage telemetry snapshot the measurement seam
    /// records into and the `/metrics` scrape renders from.
    telemetry: Arc<StorageTelemetry>,
    /// The per-tenant receipt signing schedules: the keys a fully
    /// committed attempt's receipt is signed with (plan Section 7.8;
    /// RCPT-002, RCPT-006). Composed once at startup from certified
    /// keys loaded through protected references; a tenant without a
    /// schedule commits without issuing evidence.
    receipts: crate::receipts::ReceiptSigners,
    /// The process-wide multipart-session registry: every blob commit any
    /// handler opens registers here, so a failed attempt's abort and the
    /// shutdown path's abandoned-session drain see one shared set
    /// (`OpenUploads` is an `Arc` — writers clone the handle, the state
    /// owns the original).
    uploads: Arc<OpenUploads>,
    /// The bounded 60-second trust cache (EC-09): the reader-side cache
    /// every refresh's chain walk composes at the resolution seam, shared
    /// across refreshes so a trust-registry outage degrades to at most
    /// sixty seconds of cached trust before the walk re-runs and the
    /// registry's failure surfaces. It holds public material only and is
    /// never consulted by any other surface.
    trust_cache: BoundedTrustCache,
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
    pub fn new(
        config: ServerConfig,
        trust: TrustConfig,
        storage: IngestStorage<W, C>,
        receipts: crate::receipts::ReceiptSigners,
    ) -> Self
    where
        W: RawWriteStore + Sync,
        C: ControlReadStore,
    {
        Self::compose_state(
            config,
            trust,
            storage,
            receipts,
            BoundedTrustCache::new(SystemClock),
        )
    }

    /// The test composition: identical to [`ServerState::new`], with the
    /// trust cache's clock injected so the 60-second TTL boundaries are
    /// deterministic on the test path — the cache never reads the wall
    /// clock itself, `TrustCacheClock` is the seam.
    #[cfg(test)]
    pub(crate) fn with_trust_cache_clock(
        config: ServerConfig,
        trust: TrustConfig,
        storage: IngestStorage<W, C>,
        receipts: crate::receipts::ReceiptSigners,
        clock: impl TrustCacheClock + 'static,
    ) -> Self
    where
        W: RawWriteStore + Sync,
        C: ControlReadStore,
    {
        Self::compose_state(
            config,
            trust,
            storage,
            receipts,
            BoundedTrustCache::new(clock),
        )
    }

    /// The one composition body behind both constructors.
    fn compose_state(
        config: ServerConfig,
        trust: TrustConfig,
        storage: IngestStorage<W, C>,
        receipts: crate::receipts::ReceiptSigners,
        trust_cache: BoundedTrustCache,
    ) -> Self
    where
        W: RawWriteStore + Sync,
        C: ControlReadStore,
    {
        let metrics = Arc::new(ServerMetrics::new());
        let telemetry = Arc::new(StorageTelemetry::new());
        let (raw, control) = storage.into_parts();
        Self {
            readiness: ReadinessTracker::new(&trust),
            gate: AdmissionGate::new(&config, Arc::clone(&metrics)),
            metrics,
            telemetry: Arc::clone(&telemetry),
            uploads: Arc::new(OpenUploads::new()),
            config,
            trust,
            trust_cache,
            storage: IngestStorage::compose(MeasuredRawStore::new(raw, telemetry), control),
            receipts,
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

    /// The two storage identities, the raw writer behind the measurement
    /// seam.
    #[must_use]
    pub const fn storage(&self) -> &IngestStorage<MeasuredRawStore<W>, C> {
        &self.storage
    }

    /// The process-local storage telemetry snapshot: the measurement seam
    /// records into it, the `/metrics` scrape renders from it.
    #[must_use]
    pub fn storage_telemetry(&self) -> &StorageTelemetry {
        &self.telemetry
    }

    /// The per-tenant receipt signing schedules: the lookup a complete
    /// three-object commit issues its receipt through, and the reason a
    /// schedule-less tenant's commits answer without one.
    #[must_use]
    pub const fn receipts(&self) -> &crate::receipts::ReceiptSigners {
        &self.receipts
    }

    /// The process-wide multipart-session registry every blob commit
    /// registers its session in — the handle the route's commit phase
    /// hands to `commit_blob`, and the one place a shutdown drain can
    /// enumerate and abort whatever a crash interrupted.
    #[must_use]
    pub const fn uploads(&self) -> &Arc<OpenUploads> {
        &self.uploads
    }

    /// Evaluate readiness now.
    #[must_use]
    pub fn readiness(&self) -> ReadinessSnapshot {
        self.readiness.evaluate(Instant::now())
    }

    /// Evaluate readiness at an explicit instant — the test surface for
    /// the withdrawal half of EC-09: expiry is evaluated on demand, so a
    /// test pins the instant instead of waiting out the window.
    #[cfg(test)]
    pub(crate) fn readiness_at(&self, now: Instant) -> ReadinessSnapshot {
        self.readiness.evaluate(now)
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

    /// Record one successful, signed control-record read for a configured
    /// tenant.
    ///
    /// The record must be the byte-exact value returned by the control-read
    /// store. Its tenant-authority signature is checked against this
    /// replica's pinned root before the freshness lease is updated — the
    /// resolution running through the replica's [`BoundedTrustCache`] at
    /// the [`verify_control_record_resolved`] seam (EC-09): a cached
    /// resolution inside its 60-second lease answers without touching the
    /// registry, an expired lease re-walks, and a walk that fails is never
    /// cached. The optional fetch resolves authority-rotation links by
    /// their derived key, allowing the same verifier to accept a successor
    /// authority during its valid chain window. A failed verification
    /// never changes readiness: the evidence simply ages out of the ledger
    /// at its own window, and a replica whose registry stays unreachable
    /// past both the cache lease and that window answers not-ready — the
    /// retryable 503 of EC-09 — until a verification succeeds again.
    ///
    /// The fetch closure is deliberately synchronous and storage-agnostic:
    /// callers perform any asynchronous control reads before passing the
    /// immutable bytes here. No raw-writer capability is consulted, and no
    /// probe object is written.
    ///
    /// # Errors
    /// [`AuthorityChainError::RecordDisagreement`] when `tenant` is not
    /// configured, or the corresponding closed authority-verification
    /// error for an invalid record, signer, or chain.
    pub fn record_verified_control_read(
        &self,
        tenant: &TenantId,
        record: &ControlRecord,
        fetch_authority_rotation: impl FnMut(&KeyId) -> Option<Vec<u8>>,
    ) -> Result<(), AuthorityChainError> {
        // Whether the walk ran at all is the refreshed/cache-hit line: a
        // resolution the cache served inside its lease never reaches the
        // registry, and the metrics family reports exactly that.
        let walked = Cell::new(false);
        let outcome = self.record_verified_control_read_inner(
            tenant,
            record,
            fetch_authority_rotation,
            &walked,
        );
        // The refresh family counts the attempt: a walk that reached the
        // signer and refreshed the freshness lease is `refreshed`; a
        // resolution the bounded cache served inside its lease is
        // `cache_hit`; and every refusal — unconfigured tenant, malformed
        // record, broken chain, a registry unreachable past the lease, or
        // a verification the pinned root rejects — is `unavailable`, the
        // class the error registry renders as the retryable 503 (EC-09).
        self.metrics.record_trust_refresh(match &outcome {
            Ok(()) if walked.get() => TrustRefreshOutcome::Refreshed,
            Ok(()) => TrustRefreshOutcome::CacheHit,
            Err(_) => TrustRefreshOutcome::Unavailable,
        });
        outcome
    }

    fn record_verified_control_read_inner(
        &self,
        tenant: &TenantId,
        record: &ControlRecord,
        mut fetch_authority_rotation: impl FnMut(&KeyId) -> Option<Vec<u8>>,
        walked: &Cell<bool>,
    ) -> Result<(), AuthorityChainError> {
        let root = self
            .trust
            .root_for(tenant)
            .ok_or(AuthorityChainError::RecordDisagreement)?;
        let public_key = Ed25519PublicKey::parse(root.authority().as_str())
            .map_err(|_| AuthorityChainError::MalformedRecord)?;
        let pinned = PinnedAuthorityRoot::new(tenant.clone(), public_key);
        verify_control_record_resolved(record.envelope(), |record_tenant, signer, signed_at| {
            // The chain has no force outside the configured tenant — the
            // same closed refusal `verify_control_record` renders before
            // its walk.
            if *record_tenant != *tenant {
                return Err(AuthorityChainError::RecordDisagreement);
            }
            // The bounded trust cache in front of the walk: a hit skips
            // the registry entirely, an expired entry re-walks, and only
            // a resolution the walk actually reached is cached (EC-09).
            self.trust_cache
                .resolve(record_tenant, signer, signed_at, |_, signer| {
                    walked.set(true);
                    resolve_authority(&pinned, signer, &mut fetch_authority_rotation)
                })
        })?;
        if self.readiness.record_evidence(tenant) {
            Ok(())
        } else {
            Err(AuthorityChainError::RecordDisagreement)
        }
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
/// Build the smallest signed control record accepted by the authority
/// verifier for server unit tests. It models the byte-exact object a
/// control-read store returns; the readiness path still performs the real
/// signature check.
pub(crate) fn signed_test_control_record(tenant: &TenantId, seed: &[u8; 32]) -> ControlRecord {
    use archivist_auth::ed25519;
    use archivist_protocol::json::{Object, Value};
    use archivist_protocol::vocabulary::{Ed25519Signature, Timestamp};
    use archivist_storage::metadata::Observation;

    let public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(seed));
    let authority_key_id = KeyId::from_public_key(&public);
    let mut object = Object::new();
    object.set("schema", Value::Text("archivist.control/v1".to_owned()));
    object.set("record_type", Value::Text("receipt-key".to_owned()));
    object.set("record_kind", Value::Text("immutable".to_owned()));
    object.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    object.set("signed_at", Value::Text("2026-09-23T00:00:00Z".to_owned()));
    object.set("authority_key_id", Value::Text(authority_key_id.to_hex()));
    let signature = ed25519::sign(seed, &Value::Object(object.clone()).canonical_bytes());
    object.set(
        "authority_signature",
        Value::Text(Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
    );
    ControlRecord::new(
        Value::Object(object).canonical_bytes(),
        Observation::new(
            None,
            None,
            Timestamp::parse("2026-09-23T00:00:00Z").expect("test timestamp is valid"),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        NotReadyReason, ReadinessTracker, ServerState, TRUST_EVIDENCE_WINDOW,
        signed_test_control_record,
    };
    use crate::config::ServerConfig;
    use crate::receipts::ReceiptSigners;
    use crate::trust::{TenantTrustRoot, TrustConfig};
    use archivist_auth::authority::{AuthorityChainError, AuthorityRotationLink};
    use archivist_auth::ed25519;
    use archivist_auth::trust_cache::{TRUST_CACHE_TTL_SECONDS, TrustCacheClock};
    use archivist_protocol::json::{Object, Value};
    use archivist_protocol::object_key::BlobObjectKey;
    use archivist_protocol::vocabulary::{
        ClientId, Ed25519PublicKey, Ed25519Signature, KeyId, StorageOutcome, TenantId,
    };
    use archivist_storage::capability::StoreCapabilities;
    use archivist_storage::commit::ConditionalCreateStore;
    use archivist_storage::control::{AuthorizationEpoch, ControlReadStore, ControlRecord};
    use archivist_storage::error::{StorageError, StorageErrorKind};
    use archivist_storage::ingest::IngestStorage;
    use archivist_storage::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
        assert!(tracker.record_evidence(&tenant_a));
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
        tracker.record_evidence(&TENANT_A.parse().unwrap());
        tracker.record_evidence(&TENANT_B.parse().unwrap());
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
        // `[before, after]`, so `before + WINDOW` proves fresh and
        // `after + WINDOW + 1ns` proves expired — expiry lands
        // immediately at the 60-second boundary.
        let before = Instant::now();
        tracker.record_evidence(&TENANT_A.parse().unwrap());
        tracker.record_evidence(&TENANT_B.parse().unwrap());
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
        tracker.record_evidence(&TENANT_A.parse().unwrap());
        // A real gap between the two recordings (coarse clocks can return
        // the same instant for adjacent calls) so the evaluation instant
        // below is unambiguously past B's boundary while inside A's.
        std::thread::sleep(Duration::from_millis(2));
        tracker.record_evidence(&TENANT_B.parse().unwrap());
        std::thread::sleep(Duration::from_millis(2));
        let a_rerecorded = Instant::now();
        tracker.record_evidence(&TENANT_A.parse().unwrap());

        // Evaluate just inside one window after A's re-recording: A's
        // evidence is fresh, and B's is a whole recording gap older than
        // A's, so it is past its window (stale).
        // Both facts follow from the captured instant, with no assumption
        // about scheduling delay.
        let snapshot = tracker.evaluate(
            (a_rerecorded + TRUST_EVIDENCE_WINDOW)
                .checked_sub(Duration::from_nanos(1))
                .expect("the test window is longer than one nanosecond"),
        );
        assert!(!snapshot.ready);
        assert_eq!(snapshot.tenants_ready, 1);
        assert_eq!(snapshot.reason, Some(NotReadyReason::TrustEvidenceStale));
    }

    #[test]
    fn unknown_tenants_cannot_grow_the_ledger() {
        let tracker = ReadinessTracker::new(&two_tenant_config());
        let stranger: TenantId = "99999999-9999-4999-8999-999999999999".parse().unwrap();
        assert!(!tracker.record_evidence(&stranger));
        assert!(!tracker.has_fresh_evidence(&stranger, Instant::now()));
        assert_eq!(tracker.evaluate(Instant::now()).tenants_configured, 2);
    }

    #[test]
    fn the_newest_evidence_age_is_the_minimum_across_tenants() {
        let tracker = ReadinessTracker::new(&two_tenant_config());
        assert!(tracker.newest_evidence_age(Instant::now()).is_none());
        tracker.record_evidence(&TENANT_A.parse().unwrap());
        tracker.record_evidence(&TENANT_B.parse().unwrap());
        tracker.record_evidence(&TENANT_A.parse().unwrap());
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

    // ------------------------------------------------------------------
    // The refresh path end to end: verification through the bounded
    // trust cache at the resolution seam, evidence in the ledger,
    // readiness derived from it — the EC-09 integration, driven with
    // keys the archivist-auth ed25519 module generates.
    // ------------------------------------------------------------------

    /// The pinned tenant authority's seed, and the successor its first
    /// rotation link establishes: two halves of one chain, both derived
    /// by the ed25519 module, never asserted.
    const ROOT_SEED: [u8; 32] = [0x2A; 32];
    const SUCCESSOR_SEED: [u8; 32] = [0x2B; 32];
    /// The rotation link's instant: before every record below, so the
    /// successor is established material at each record's own `signed_at`.
    const LINK_SIGNED_AT: &str = "2026-09-10T00:00:00Z";

    /// A fixed cache clock: the only time source the refresh path's trust
    /// cache reads here, advanced by hand so the 60-second TTL boundary
    /// is deterministic.
    #[derive(Clone)]
    struct FixedCacheClock {
        now: Arc<AtomicU64>,
    }

    impl FixedCacheClock {
        fn at(seconds: u64) -> Self {
            Self {
                now: Arc::new(AtomicU64::new(seconds)),
            }
        }

        fn advance_by(&self, seconds: u64) {
            self.now.fetch_add(seconds, Ordering::SeqCst);
        }
    }

    impl TrustCacheClock for FixedCacheClock {
        fn now_seconds(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
    }

    /// A raw writer that only counts: the refresh path owns no raw-write
    /// capability, so the counter standing at zero after every refresh
    /// exchange is the no-storage-writes half of EC-09, observed rather
    /// than asserted in prose.
    #[derive(Clone, Debug)]
    struct CountingRawStore {
        writes: Arc<AtomicUsize>,
    }

    impl CountingRawStore {
        fn new() -> Self {
            Self {
                writes: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    fn unavailable<T>() -> Result<T, StorageError> {
        Err(StorageError::of_kind(StorageErrorKind::Unavailable))
    }

    impl RawWriteStore for CountingRawStore {
        fn capabilities(&self) -> StoreCapabilities {
            StoreCapabilities::unprobed()
        }

        async fn write_manifest(
            &self,
            _key: &ManifestKey,
            _bytes: &[u8],
        ) -> Result<StorageOutcome, StorageError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            unavailable()
        }

        async fn begin_multipart(
            &self,
            _blob: &BlobObjectKey,
        ) -> Result<MultipartUploadId, StorageError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            unavailable()
        }

        async fn write_part(
            &self,
            _upload: &MultipartUploadId,
            _part: PartNumber,
            _bytes: &[u8],
        ) -> Result<PartCommitment, StorageError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            unavailable()
        }

        async fn commit_multipart(
            &self,
            _upload: &MultipartUploadId,
            _parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            unavailable()
        }

        async fn abort_multipart(&self, _upload: &MultipartUploadId) -> Result<(), StorageError> {
            unavailable()
        }
    }

    // The writer-only adoption: the trait's default answers every atomic
    // primitive request with capability-unavailable, matching the mock's
    // unprobed report.
    impl ConditionalCreateStore for CountingRawStore {}

    /// A control store that never answers: the refresh path reads no
    /// control records itself — the caller's fetch closure is the
    /// registry — so nothing here is ever consulted.
    #[derive(Clone, Copy, Debug)]
    struct UnavailableControlStore;

    impl ControlReadStore for UnavailableControlStore {
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

    /// A replica composed for the refresh path: one tenant whose pinned
    /// authority half derives from [`ROOT_SEED`], the trust cache reading
    /// the fixed clock, every durable write counted.
    fn verified_read_state(
        clock: FixedCacheClock,
        raw: CountingRawStore,
    ) -> ServerState<CountingRawStore, UnavailableControlStore> {
        let authority = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&ROOT_SEED));
        let config = ServerConfig::builder()
            .listen_address("127.0.0.1:0")
            .shutdown_drain_seconds(5)
            .build()
            .expect("the test configuration validates");
        let trust = TrustConfig::from_roots(vec![
            TenantTrustRoot::new(TENANT_A, &authority.to_hex())
                .expect("the generated authority half parses"),
        ])
        .expect("the one-tenant anchor set validates");
        ServerState::with_trust_cache_clock(
            config,
            trust,
            IngestStorage::compose(raw, UnavailableControlStore),
            ReceiptSigners::new(),
            clock,
        )
    }

    /// The signed link retiring `predecessor_seed` and establishing
    /// `successor_seed` — the rotation record a registry serves at the
    /// predecessor's address.
    fn signed_rotation_link(signed_at: &str, tenant: &TenantId) -> Vec<u8> {
        let previous_public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&ROOT_SEED));
        let public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&SUCCESSOR_SEED));
        let previous_key_id = KeyId::from_public_key(&previous_public);
        let mut members = Object::new();
        members.set("schema", Value::Text("archivist.control/v1".to_owned()));
        members.set("record_type", Value::Text("authority-rotation".to_owned()));
        members.set("record_kind", Value::Text("immutable".to_owned()));
        members.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
        members.set("previous_public_key", Value::Text(previous_public.to_hex()));
        members.set("previous_key_id", Value::Text(previous_key_id.to_hex()));
        members.set("key_algorithm", Value::Text("ed25519".to_owned()));
        members.set("public_key", Value::Text(public.to_hex()));
        members.set(
            "key_id",
            Value::Text(KeyId::from_public_key(&public).to_hex()),
        );
        members.set("signed_at", Value::Text(signed_at.to_owned()));
        members.set("authority_key_id", Value::Text(previous_key_id.to_hex()));
        let signature = ed25519::sign(
            &ROOT_SEED,
            &Value::Object(members.clone()).canonical_bytes(),
        );
        members.set(
            "authority_signature",
            Value::Text(Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        Value::Object(members).canonical_bytes()
    }

    /// The registry fetch: a link-free tenant registry — every rotation
    /// address answers nothing — that counts how often the walks touch it.
    fn link_free_registry(
        counter: &Arc<AtomicUsize>,
    ) -> impl FnMut(&KeyId) -> Option<Vec<u8>> + '_ {
        |_: &KeyId| {
            counter.fetch_add(1, Ordering::SeqCst);
            None
        }
    }

    /// EC-09's two bounds are one bound: the freshness window readiness
    /// evaluates against is exactly the lease the trust cache serves
    /// under — readiness expires with the cache, never before or after.
    #[test]
    fn the_evidence_window_is_the_trust_cache_ttl() {
        assert_eq!(TRUST_EVIDENCE_WINDOW.as_secs(), TRUST_CACHE_TTL_SECONDS);
    }

    /// The ready side, end to end: a signed control record verifies
    /// through the cached seam — first refresh walks the link-free
    /// registry once, second refresh inside the lease is served by the
    /// cache with the registry untouched — and both land evidence the
    /// readiness ledger answers with. Nothing is written to storage.
    #[test]
    fn a_signed_control_read_verifies_through_the_cached_seam_and_records_evidence() {
        let raw = CountingRawStore::new();
        let state = verified_read_state(FixedCacheClock::at(1_000), raw.clone());
        let tenant: TenantId = TENANT_A.parse().expect("test tenant parses");
        let record = signed_test_control_record(&tenant, &ROOT_SEED);

        // First refresh: the cache is empty, so the resolution walks once
        // (the signer is the pinned root; one retirement probe), the
        // signature verifies under the resolved half, and the evidence
        // lands — the tenant is ready.
        let walks = Arc::new(AtomicUsize::new(0));
        state
            .record_verified_control_read(&tenant, &record, link_free_registry(&walks))
            .expect("the signed control read verifies against the generated root");
        assert_eq!(walks.load(Ordering::SeqCst), 1, "an empty cache walks once");
        let recorded = Instant::now();
        assert!(state.readiness_at(recorded).ready);

        // Second refresh inside the lease: the cached resolution answers,
        // the registry is never touched, and the evidence is refreshed —
        // the availability half of EC-09.
        state
            .record_verified_control_read(&tenant, &record, link_free_registry(&walks))
            .expect("a fresh cache entry serves the resolution without the walk");
        assert_eq!(
            walks.load(Ordering::SeqCst),
            1,
            "a cache hit skips the walk"
        );
        assert!(
            state.readiness_at(recorded).ready,
            "a served hit keeps the evidence fresh"
        );

        // The refresh family tells the two producers apart.
        let text = state.metrics().exposition(state.newest_trust_age_seconds());
        assert!(
            text.contains(
                "archivist_server_trust_refresh_attempts_total\
                 {archivist_trust_outcome=\"refreshed\"} 1\n"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "archivist_server_trust_refresh_attempts_total\
                 {archivist_trust_outcome=\"cache_hit\"} 1\n"
            ),
            "{text}"
        );
        // And the whole exchange wrote nothing to storage.
        assert_eq!(
            raw.writes.load(Ordering::SeqCst),
            0,
            "the refresh path never writes"
        );
    }

    /// The failure side, end to end: a rotated signer's verified read
    /// makes the tenant ready; with the registry then unreachable and the
    /// cache lease exhausted, the next refresh re-walks, finds the chain
    /// unresolvable, and fails closed the retryable unavailable class —
    /// while readiness lapses at the evidence window, evaluated on
    /// demand, never revoked and never awaited. Nothing is written to
    /// storage.
    #[test]
    fn a_registry_unreachable_past_the_lease_fails_closed_and_readiness_lapses() {
        let clock = FixedCacheClock::at(1_000);
        let raw = CountingRawStore::new();
        let state = verified_read_state(clock.clone(), raw.clone());
        let tenant: TenantId = TENANT_A.parse().expect("test tenant parses");

        // The successor-signed record verifies through the rotation link
        // the registry serves at the root's address: the walk adopts the
        // successor, the signature verifies under the successor half, and
        // the evidence lands.
        let successor_record = signed_test_control_record(&tenant, &SUCCESSOR_SEED);
        let link = signed_rotation_link(LINK_SIGNED_AT, &tenant);
        let mut registry = HashMap::new();
        let parsed = AuthorityRotationLink::parse(&link).expect("the test link is well-formed");
        registry.insert(*parsed.previous_key_id(), link);
        let walks = Arc::new(AtomicUsize::new(0));
        let before = Instant::now();
        state
            .record_verified_control_read(&tenant, &successor_record, |key: &KeyId| {
                walks.fetch_add(1, Ordering::SeqCst);
                registry.get(key).cloned()
            })
            .expect("the successor-signed read verifies through the chain");
        let after = Instant::now();
        assert!(state.readiness_at(before).ready);
        assert_eq!(
            walks.load(Ordering::SeqCst),
            2,
            "the chain walk reads two addresses"
        );

        // The registry goes unreachable and the lease runs out: the next
        // refresh re-walks, the registry answers nothing at the root's
        // address, and the read fails the closed unreachable class — the
        // retryable unavailability of EC-09 — instead of serving stale
        // trust.
        clock.advance_by(TRUST_CACHE_TTL_SECONDS);
        let failure = state
            .record_verified_control_read(&tenant, &successor_record, link_free_registry(&walks))
            .expect_err("an unreachable registry past the lease fails closed");
        assert_eq!(failure, AuthorityChainError::Unreachable);
        assert_eq!(
            walks.load(Ordering::SeqCst),
            3,
            "the exhausted lease re-walked"
        );
        let text = state.metrics().exposition(state.newest_trust_age_seconds());
        assert!(
            text.contains(
                "archivist_server_trust_refresh_attempts_total\
                 {archivist_trust_outcome=\"unavailable\"} 1\n"
            ),
            "{text}"
        );

        // Readiness is never revoked by the failed read — it lapses at
        // the evidence window, evaluated on demand: provably fresh one
        // nanosecond inside the window, provably withdrawn one nanosecond
        // past it, with the stale class naming the reason the 503 body
        // carries.
        assert!(
            state
                .readiness_at(
                    before
                        + TRUST_EVIDENCE_WINDOW
                            .checked_sub(Duration::from_nanos(1))
                            .expect("the window exceeds a nanosecond"),
                )
                .ready
        );
        let withdrawn = state.readiness_at(after + TRUST_EVIDENCE_WINDOW + Duration::from_nanos(1));
        assert!(!withdrawn.ready);
        assert_eq!(withdrawn.reason, Some(NotReadyReason::TrustEvidenceStale));
        assert_eq!(withdrawn.tenants_ready, 0);
        // And the whole exchange — verified, cache-served, and failed —
        // wrote nothing to storage.
        assert_eq!(
            raw.writes.load(Ordering::SeqCst),
            0,
            "the refresh path never writes"
        );
    }
}
