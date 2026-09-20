// SPDX-License-Identifier: Apache-2.0

//! The admission-time resource guards: the process-wide in-flight cap, the
//! per-client in-flight share, the per-client new-request token bucket, and
//! the per-request deadline (plan Section 7.6).
//!
//! Every guard runs **before** anything request-derived is read: the
//! process-wide cap is a `try_acquire` against a semaphore built from
//! `server.max_inflight_upload_count`, and the per-client guards are keyed
//! by the authenticated uploader identity the pipeline supplies — so an
//! overloaded replica refuses with a content-free throttle body while the
//! request's bytes are still sitting unread in the socket. No payload-scale
//! resource (a body buffer, a decompression window, a multipart upload) can
//! be allocated ahead of admission.
//!
//! # The four guards
//!
//! | Guard | Version 1 value | Refusal |
//! |---|---|---|
//! | Request deadline | 15 minutes (configurable) | 408 `request.deadline_exceeded` |
//! | In-flight per process | 16 | 429 `request.rate_limited` |
//! | In-flight per client | 4 of the process total | 429 `request.rate_limited` |
//! | New requests per client | 60/minute per replica, burst 8 | 429 `request.rate_limited` |
//!
//! All four refusals are in the `throttle` class: retryable, bounded to the
//! two registered codes above, and low-cardinality — the only metric they
//! touch is the registered `archivist.server.ingest` counter's `throttled`
//! outcome and the `archivist.server.ingest.inflight` gauge. Neither the
//! refusal nor the gauge ever carries a client, tenant, or request
//! identifier (SEC-004): the per-client guard state is keyed by client but
//! never exported by client.
//!
//! # Client-level admission timing
//!
//! The plan's server data flow orders the guards: bounds and the
//! process-wide cap first (step 1), authentication second (step 2). The
//! per-client share and the token bucket therefore admit through
//! [`AdmissionGate::admit_client`] at the point the uploader identity is
//! known — the authorization middleware calls it between its steps and the
//! pipeline's first payload-scale allocation. [`AdmissionGate::
//! try_admit_process`] is the route-level half that runs before any of
//! that. The deadline wrapper ([`within_deadline`]) bounds the whole
//! attempt, admission included.
//!
//! # Bucket arithmetic
//!
//! The token bucket is integer-exact: credit is accumulated in
//! micro-seconds times the configured per-minute rate, and one admission
//! costs `CREDIT_PER_REQUEST` of those units — so `rate_per_minute`
//! credits are earned per minute regardless of how the minute is divided,
//! with no floating point and no drift. A client's first observation starts
//! the bucket full (`ServerConfig::rate_burst_count` tokens); entries
//! persist for the process lifetime so a client cannot re-arm its burst by
//! going idle. The table footprint is bounded by the authenticated client
//! population — a trust boundary the authorization middleware holds — and
//! each entry is two counters and an instant, never payload-scale.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use archivist_protocol::vocabulary::ClientId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::ServerConfig;
use crate::metrics::ServerMetrics;

/// Credit units consumed by one admitted new request: a bucket refilling at
/// `rate_per_minute` accumulates `elapsed_micros * rate_per_minute` credit,
/// so one minute at rate 1 — one admission — is exactly 60,000,000 units.
/// Every admitted request costs the same, and integer arithmetic stays
/// exact for every configured rate (plan Section 7.6: 60/minute, burst 8).
const CREDIT_PER_REQUEST: u128 = 60_000_000;

/// Why admission refused a request: a closed, content-free class of
/// resource-guard refusal. Every variant is retryable and carries the one
/// registered throttle code the wire body renders.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuardRejection {
    /// The process-wide in-flight cap is exhausted — the replica is at its
    /// configured concurrency and admits nothing further until one lands.
    ProcessAtCapacity,
    /// The client's in-flight share of the process is exhausted: this
    /// uploader already holds the configured per-client maximum.
    ClientAtCapacity,
    /// The client's new-request bucket has no credit: the uploader's rate
    /// past the configured burst is refused until the bucket refills.
    ClientRateExhausted,
}

impl GuardRejection {
    /// Every rejection, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::ProcessAtCapacity,
            Self::ClientAtCapacity,
            Self::ClientRateExhausted,
        ]
    }

    /// The content-free rejection token — for structured logs and tests,
    /// never for the wire body (the body carries only the registered code).
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::ProcessAtCapacity => "process_at_capacity",
            Self::ClientAtCapacity => "client_at_capacity",
            Self::ClientRateExhausted => "client_rate_exhausted",
        }
    }

    /// The registered error code the wire body carries. Every guard
    /// rejection is admission overload, and the registry pins one
    /// retryable 429 code for that condition.
    #[must_use]
    pub const fn error_code(self) -> &'static str {
        let _ = self;
        "request.rate_limited"
    }

    /// Whether the client should retry: always, for every guard rejection
    /// (the `throttle` class is retryable by registry fiat).
    #[must_use]
    pub const fn retryable(self) -> bool {
        let _ = self;
        true
    }
}

/// A process-wide in-flight slot. Dropping it releases the slot and
/// decrements the `archivist.server.ingest.inflight` gauge.
#[derive(Debug)]
pub struct ProcessAdmission {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<ServerMetrics>,
}

impl Drop for ProcessAdmission {
    fn drop(&mut self) {
        self.metrics.ingest_inflight_sub(1);
    }
}

/// One client's admitted in-flight slot. Dropping it releases the client's
/// per-process share; nothing is exported anywhere on either event.
#[derive(Debug)]
pub struct ClientAdmission {
    _permit: OwnedSemaphorePermit,
}

/// The per-client new-request bucket: integer-exact credit, refilled by
/// elapsed time against the configured rate, capped at the burst.
#[derive(Debug)]
struct TokenBucket {
    credit: u128,
    last: Instant,
}

impl TokenBucket {
    /// Try to consume one admission, crediting the bucket for the time
    /// since its last observation first. A bucket configured with neither
    /// refill nor burst is the disabled guard and admits everything.
    fn try_consume(&mut self, rate_per_minute: u32, burst: u32, now: Instant) -> bool {
        if rate_per_minute == 0 && burst == 0 {
            return true;
        }
        let elapsed_micros = now
            .checked_duration_since(self.last)
            .unwrap_or_default()
            .as_micros();
        self.last = now;
        self.credit = self
            .credit
            .saturating_add(elapsed_micros.saturating_mul(u128::from(rate_per_minute)));
        self.credit = self.credit.min(u128::from(burst) * CREDIT_PER_REQUEST);
        if self.credit >= CREDIT_PER_REQUEST {
            self.credit -= CREDIT_PER_REQUEST;
            true
        } else {
            false
        }
    }
}

/// One identified client's guard state: its in-flight share and its
/// new-request bucket. Entries persist for the process lifetime —
/// re-entering must not re-arm a burst — and stay keyed by client and
/// never exported (SEC-004).
#[derive(Debug)]
struct ClientEntry {
    inflight: Arc<Semaphore>,
    bucket: TokenBucket,
}

/// The admission gate: the process-wide semaphore, the per-client ledger,
/// and the configured limits. One gate per replica, composed into the
/// shared server state at startup; every method is non-blocking.
pub struct AdmissionGate {
    process: Arc<Semaphore>,
    clients: Mutex<HashMap<ClientId, ClientEntry>>,
    max_inflight_per_client: u32,
    rate_per_minute: u32,
    burst: u32,
    metrics: Arc<ServerMetrics>,
}

impl std::fmt::Debug for AdmissionGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The client ledger is deliberately absent from the rendering: a
        // debug dump is one place a client identifier must never surface.
        f.debug_struct("AdmissionGate")
            .field("process_capacity", &self.process.available_permits())
            .field("max_inflight_per_client", &self.max_inflight_per_client)
            .field("rate_per_minute", &self.rate_per_minute)
            .field("burst", &self.burst)
            .finish_non_exhaustive()
    }
}

impl AdmissionGate {
    /// Build the gate for one replica from the validated configuration.
    ///
    /// # Panics
    /// Only if the configured process cap does not fit a `usize` —
    /// impossible for a `u32` on every supported target.
    #[must_use]
    pub fn new(config: &ServerConfig, metrics: Arc<ServerMetrics>) -> Self {
        let capacity = usize::try_from(config.max_inflight_upload_count())
            .expect("process in-flight cap fits usize");
        Self {
            process: Arc::new(Semaphore::new(capacity)),
            clients: Mutex::new(HashMap::new()),
            max_inflight_per_client: config.max_inflight_per_client_count(),
            rate_per_minute: config.rate_per_minute_count(),
            burst: config.rate_burst_count(),
            metrics,
        }
    }

    /// Try to admit one request against the process-wide in-flight cap.
    ///
    /// This is the first guard a request meets, ahead of everything
    /// request-derived: on success the replica has reserved it a slot and
    /// the `archivist.server.ingest.inflight` gauge counts it; on failure
    /// the replica is at capacity and nothing was read, allocated, or
    /// recorded but the refusal.
    ///
    /// # Errors
    /// [`GuardRejection::ProcessAtCapacity`] when every slot is in
    /// flight; the refusal is content-free and nothing is consumed.
    ///
    /// # Panics
    /// Only if the process semaphore is closed — which nothing here ever
    /// does.
    pub fn try_admit_process(&self) -> Result<ProcessAdmission, GuardRejection> {
        match Arc::clone(&self.process).try_acquire_owned() {
            Ok(permit) => {
                self.metrics.ingest_inflight_add(1);
                Ok(ProcessAdmission {
                    _permit: permit,
                    metrics: Arc::clone(&self.metrics),
                })
            }
            Err(_closed_or_exhausted) => Err(GuardRejection::ProcessAtCapacity),
        }
    }

    /// Try to admit one new request from an identified uploader: the
    /// per-client in-flight share first, then the new-request bucket.
    ///
    /// `now` anchors the bucket refill; the caller passes its observation
    /// instant so the guard stays deterministic under test. A consumed
    /// token is consumed by admission, not by success — the bucket is a
    /// resource guard, not a billing quota (plan Section 7.6).
    ///
    /// # Errors
    /// [`GuardRejection::ClientAtCapacity`] when the client already holds
    /// its full in-flight share, or [`GuardRejection::ClientRateExhausted`]
    /// when its new-request bucket has no credit — in which case the
    /// in-flight share is handed back before refusing.
    ///
    /// # Panics
    /// Only if the client ledger is poisoned — a concurrent panic while
    /// holding it, which is itself a bug.
    pub fn admit_client(
        &self,
        client: &ClientId,
        now: Instant,
    ) -> Result<ClientAdmission, GuardRejection> {
        let mut clients = self.clients.lock().expect("client guard ledger poisoned");
        let entry = clients
            .entry(client.clone())
            .or_insert_with(|| ClientEntry {
                inflight: Arc::new(Semaphore::new(
                    usize::try_from(self.max_inflight_per_client)
                        .expect("per-client in-flight cap fits usize"),
                )),
                bucket: TokenBucket {
                    credit: u128::from(self.burst) * CREDIT_PER_REQUEST,
                    last: now,
                },
            });
        let permit = match Arc::clone(&entry.inflight).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_closed_or_exhausted) => return Err(GuardRejection::ClientAtCapacity),
        };
        if !entry
            .bucket
            .try_consume(self.rate_per_minute, self.burst, now)
        {
            // Hand the in-flight share back before refusing: a rate
            // refusal must not also occupy the client's concurrency slot.
            drop(permit);
            return Err(GuardRejection::ClientRateExhausted);
        }
        Ok(ClientAdmission { _permit: permit })
    }
}

/// Why a deadline-bound attempt ended early: the configured request
/// deadline elapsed. The throttle class owns this condition — the attempt
/// is retryable exactly as every other guard refusal is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeadlineElapsed;

/// Bound one request attempt by its configured deadline.
///
/// The deadline wraps the whole attempt — admission included — so a
/// request can never outlive the bound by waiting for a guard or a
/// storage call inside it. Elapsing yields [`DeadlineElapsed`]; the
/// attempt's future is dropped, which is what releases its admission and
/// every payload-scale resource it held.
///
/// # Errors
/// [`DeadlineElapsed`] when the attempt does not complete within the
/// configured deadline; the attempt is dropped, never abandoned running.
pub async fn within_deadline<F: Future>(
    deadline: Duration,
    attempt: F,
) -> Result<F::Output, DeadlineElapsed> {
    tokio::time::timeout(deadline, attempt)
        .await
        .map_err(|_elapsed| DeadlineElapsed)
}

#[cfg(test)]
mod tests {
    use super::{
        AdmissionGate, ClientAdmission, DeadlineElapsed, GuardRejection, ProcessAdmission,
        within_deadline,
    };
    use crate::config::ServerConfig;
    use crate::metrics::ServerMetrics;
    use archivist_protocol::vocabulary::ClientId;
    use std::future::pending;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const CLIENT_A: &str = "aaaaaaaa-bbbb-4ccc-8ddd-111111111111";
    const CLIENT_B: &str = "bbbbbbbb-cccc-4ddd-8eee-222222222222";

    fn client(text: &str) -> ClientId {
        text.parse().expect("test client id validates")
    }

    fn gate(
        total: u32,
        per_client: u32,
        rate_per_minute: u32,
        burst: u32,
    ) -> (AdmissionGate, Arc<ServerMetrics>) {
        let config = ServerConfig::builder()
            .listen_address("127.0.0.1:0")
            .max_inflight_upload_count(total)
            .max_inflight_per_client_count(per_client)
            .rate_per_minute_count(rate_per_minute)
            .rate_burst_count(burst)
            .build()
            .expect("guard configuration validates");
        let metrics = Arc::new(ServerMetrics::new());
        (AdmissionGate::new(&config, Arc::clone(&metrics)), metrics)
    }

    /// The plan's version 1 defaults, admitted against directly.
    #[test]
    fn the_plan_defaults_cap_the_process_at_sixteen_in_flight() {
        let (gate, _metrics) = gate(16, 4, 60, 8);
        let mut admissions: Vec<ProcessAdmission> = Vec::new();
        for _ in 0..16 {
            admissions.push(gate.try_admit_process().expect("slot 16 admits"));
        }
        assert_eq!(
            gate.try_admit_process().map(|_| ()),
            Err(GuardRejection::ProcessAtCapacity),
            "the seventeenth in-flight request is refused"
        );
        // Releasing one slot makes room for exactly one more admission.
        admissions.remove(0);
        assert!(gate.try_admit_process().is_ok());
    }

    #[test]
    fn a_client_is_capped_at_its_share_and_others_keep_their_own() {
        let (gate, _metrics) = gate(16, 4, 60, 8);
        let a = client(CLIENT_A);
        let b = client(CLIENT_B);
        let now = Instant::now();
        let mut admissions: Vec<ClientAdmission> = Vec::new();
        for _ in 0..4 {
            admissions.push(gate.admit_client(&a, now).expect("share admits"));
        }
        assert_eq!(
            gate.admit_client(&a, now).map(|_| ()),
            Err(GuardRejection::ClientAtCapacity),
            "the fifth in-flight request of one client is refused"
        );
        // The refusal is the client's alone: another client admits, and
        // the process still has twelve slots free.
        assert!(gate.admit_client(&b, now).is_ok());
        assert!(gate.try_admit_process().is_ok());
    }

    #[test]
    fn releasing_a_client_slot_and_a_process_slot_re_admits() {
        let (gate, _metrics) = gate(1, 1, 60, 8);
        let a = client(CLIENT_A);
        let now = Instant::now();
        let admission = gate.admit_client(&a, now).expect("first admits");
        drop(admission);
        // Hold the re-admission: an in-line `is_ok()` would drop the slot
        // before the next assertion could observe it held.
        let re_admitted = gate.admit_client(&a, now).expect("release re-admits");
        assert_eq!(
            gate.admit_client(&a, now).map(|_| ()),
            Err(GuardRejection::ClientAtCapacity),
            "the held re-admission occupies the single slot again"
        );
        drop(re_admitted);
        assert!(
            gate.admit_client(&a, now).is_ok(),
            "releasing the held slot re-admits once more"
        );
    }

    #[test]
    fn the_bucket_admits_the_burst_then_makes_rate_wait() {
        let (gate, _metrics) = gate(64, 64, 60, 8);
        let a = client(CLIENT_A);
        let t0 = Instant::now();
        for _ in 0..8 {
            assert!(
                gate.admit_client(&a, t0).is_ok(),
                "the burst depth of eight admits"
            );
        }
        assert_eq!(
            gate.admit_client(&a, t0).map(|_| ()),
            Err(GuardRejection::ClientRateExhausted),
            "the ninth new request is refused inside the same instant"
        );
        // Refill at 60/minute is one token per second: 999 ms is not yet
        // one, 1000 ms is exactly one (the boundary is inclusive).
        assert_eq!(
            gate.admit_client(&a, t0 + Duration::from_millis(999))
                .map(|_| ()),
            Err(GuardRejection::ClientRateExhausted),
        );
        assert!(
            gate.admit_client(&a, t0 + Duration::from_secs(1)).is_ok(),
            "a full second of refill admits exactly one more"
        );
        // The bucket is empty again until another second passes.
        assert_eq!(
            gate.admit_client(&a, t0 + Duration::from_secs(1))
                .map(|_| ()),
            Err(GuardRejection::ClientRateExhausted),
        );
    }

    #[test]
    fn idle_time_never_arms_more_than_the_burst() {
        let (gate, _metrics) = gate(64, 64, 60, 8);
        let a = client(CLIENT_A);
        let t0 = Instant::now();
        // An hour idle: the bucket is still capped at the burst of eight,
        // never at the 3600 tokens the raw 60-per-minute rate would have
        // minted over that hour.
        for _ in 0..8 {
            assert!(gate.admit_client(&a, t0 + Duration::from_hours(1)).is_ok());
        }
        assert_eq!(
            gate.admit_client(&a, t0 + Duration::from_hours(1))
                .map(|_| ()),
            Err(GuardRejection::ClientRateExhausted),
        );
    }

    #[test]
    fn a_disabled_bucket_admits_without_ever_consuming() {
        let (gate, _metrics) = gate(64, 64, 0, 0);
        let a = client(CLIENT_A);
        let now = Instant::now();
        for _ in 0..64 {
            assert!(
                gate.admit_client(&a, now).is_ok(),
                "no refill and no burst is the documented disabled guard"
            );
        }
    }

    #[test]
    fn a_burst_without_refill_admits_only_the_burst_forever() {
        let (gate, _metrics) = gate(64, 64, 0, 2);
        let a = client(CLIENT_A);
        let t0 = Instant::now();
        assert!(gate.admit_client(&a, t0).is_ok());
        assert!(gate.admit_client(&a, t0).is_ok());
        assert_eq!(
            gate.admit_client(&a, t0 + Duration::from_hours(1))
                .map(|_| ()),
            Err(GuardRejection::ClientRateExhausted),
            "zero refill never mints another token, however long the wait"
        );
    }

    #[test]
    fn every_rejection_is_the_one_retryable_rate_limit_code() {
        for rejection in GuardRejection::all() {
            assert_eq!(rejection.error_code(), "request.rate_limited");
            assert!(rejection.retryable());
            assert!(
                rejection
                    .token()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
            );
        }
    }

    #[tokio::test]
    async fn the_deadline_bounds_a_pending_attempt() {
        let started = Instant::now();
        let outcome = within_deadline(Duration::from_millis(50), pending::<()>()).await;
        assert_eq!(outcome, Err(DeadlineElapsed));
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "the deadline is a real wait, not an immediate give-up"
        );
    }

    #[tokio::test]
    async fn an_attempt_inside_the_deadline_yields_its_output() {
        let outcome = within_deadline(Duration::from_secs(5), std::future::ready(7u8)).await;
        assert_eq!(outcome, Ok(7));
    }

    #[tokio::test]
    async fn a_dropped_deadline_releases_its_process_admission() {
        let (gate, metrics) = gate(1, 1, 60, 8);
        let attempt = async {
            let admission = gate.try_admit_process().expect("the slot admits");
            pending::<()>().await;
            drop(admission);
        };
        let outcome = within_deadline(Duration::from_millis(50), attempt).await;
        assert_eq!(outcome, Err(DeadlineElapsed));
        // The dropped attempt released both the slot and the gauge.
        assert!(gate.try_admit_process().is_ok(), "the slot was released");
        assert_eq!(metrics.ingest_inflight(), 0);
    }

    #[test]
    fn the_inflight_gauge_tracks_admissions_and_releases() {
        let (gate, metrics) = gate(2, 2, 60, 8);
        assert_eq!(metrics.ingest_inflight(), 0);
        let first = gate.try_admit_process().expect("first admits");
        assert_eq!(metrics.ingest_inflight(), 1);
        let second = gate.try_admit_process().expect("second admits");
        assert_eq!(metrics.ingest_inflight(), 2);
        drop(first);
        assert_eq!(metrics.ingest_inflight(), 1);
        drop(second);
        assert_eq!(metrics.ingest_inflight(), 0);
    }

    #[test]
    fn a_client_rate_refusal_does_not_hold_the_client_slot() {
        let (gate, _metrics) = gate(64, 64, 60, 1);
        let a = client(CLIENT_A);
        let t0 = Instant::now();
        assert!(gate.admit_client(&a, t0).is_ok());
        assert_eq!(
            gate.admit_client(&a, t0).map(|_| ()),
            Err(GuardRejection::ClientRateExhausted),
        );
        // The refusal handed back the concurrency share it had briefly
        // taken: a full second later one refill admits despite the burst
        // of one.
        assert!(gate.admit_client(&a, t0 + Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn distinct_clients_keep_distinct_buckets() {
        let (gate, _metrics) = gate(64, 64, 60, 1);
        let a = client(CLIENT_A);
        let b = client(CLIENT_B);
        let t0 = Instant::now();
        assert!(gate.admit_client(&a, t0).is_ok());
        assert_eq!(
            gate.admit_client(&a, t0).map(|_| ()),
            Err(GuardRejection::ClientRateExhausted),
        );
        assert!(
            gate.admit_client(&b, t0).is_ok(),
            "one client's exhausted bucket says nothing about another's"
        );
    }

    #[test]
    fn the_gate_debug_rendering_never_names_a_client() {
        let (gate, _metrics) = gate(16, 4, 60, 8);
        let a = client(CLIENT_A);
        let _ = gate.admit_client(&a, Instant::now()).expect("admits");
        let rendered = format!("{gate:?}");
        assert!(!rendered.contains(CLIENT_A), "{rendered}");
        assert!(!rendered.contains("clients:"), "{rendered}");
        assert!(!rendered.contains("ledger"), "{rendered}");
    }
}
