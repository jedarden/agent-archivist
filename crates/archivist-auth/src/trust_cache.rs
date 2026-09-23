// SPDX-License-Identifier: Apache-2.0

//! The bounded 60-second trust cache (EC-09): the reader-side cache a
//! client or ingestion replica composes in front of the authority-chain
//! walk, so a trust-registry outage degrades to at most sixty seconds of
//! staleness and then fails closed.
//!
//! The plan's own words (Section 5): "Trust records cache for at most 60
//! seconds. If S3 is unavailable, an unexpired record may be used;
//! otherwise the server fails closed with retryable 503" — the same
//! bound the configuration registry pins as `trustRecordCacheTtlSeconds`.
//! The composition point is the resolution seam
//! [`crate::authority::verify_control_record_resolved`] ships: a cached
//! verifier is that function with this cache in front of the walk, and
//! [`BoundedTrustCache::resolve`] is shaped exactly as the seam's
//! resolver, so wiring is one closure and nothing else.
//!
//! Three rules are the whole contract:
//!
//! - **A hit skips the walk.** An entry younger than
//!   [`TRUST_CACHE_TTL_SECONDS`] serves its cached [`ResolvedAuthority`]
//!   without touching the registry. That is itself the availability
//!   story: while the registry is down, every request inside the lease
//!   is served from the cache, and the first request past it re-walks
//!   and surfaces the registry's error — a valid cached record for at
//!   most 60 seconds, then fail closed.
//! - **Acceptance stays at the record's own `signed_at`.** A hit applies
//!   the same dual-key rule a fresh walk would
//!   ([`ResolvedAuthority::verify_signing_at`]), evaluated at the
//!   record's own instant and never at read time — the property
//!   [`crate::authority`] pins for a stale view. Caching therefore
//!   cannot retroactively revoke a record the chain accepted, and cannot
//!   extend a retired signer's window past the 24 hours its own
//!   retirement link set: a retired half whose resolution was cached
//!   inside the TTL is still rejected once the record's own instant
//!   falls past the window.
//! - **Only successes are cached.** A walk that fails — a broken chain,
//!   an unreachable signer, an unavailable registry — is never
//!   remembered. The error propagates now and the next record re-walks:
//!   the TTL bounds staleness, never pins a rejection, and a registry
//!   failure stays retryable rather than cached-closed.
//!
//! An entry is refused at exactly its TTL age (the plan's "at most"),
//! and the refused entry is evicted on the spot, so nothing stale can
//! serve again whatever the walk that follows reports. Time is injected
//! ([`TrustCacheClock`]): production wires [`SystemClock`], tests pin a
//! fixed clock, and every boundary is deterministic — nothing here reads
//! the wall clock itself.
//!
//! The cache holds public material only — key IDs, public halves, and
//! the window instants a walk already served — and renders none of it
//! anywhere; there is no `Debug` and no diagnostic surface to leak
//! through (SEC-004).

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use archivist_protocol::vocabulary::{KeyId, TenantId, Timestamp};

use crate::authority::{AuthorityChainError, ResolvedAuthority};

/// `trustRecordCacheTtlSeconds` — 60 (plan Section 5: "Trust records
/// cache for at most 60 seconds"): how long a cached [`ResolvedAuthority`]
/// may serve in place of a fresh chain walk, counted from the moment the
/// entry was cached. At the boundary age an entry is refused, not
/// served — the bound is "at most", and the first request past it
/// re-walks.
pub const TRUST_CACHE_TTL_SECONDS: u64 = 60;

/// The cache's time source: whole seconds since the Unix epoch.
///
/// Injection is the determinism contract — the cache never reads the
/// wall clock itself, so a test pins a fixed clock and every TTL
/// boundary is reproducible. `Send + Sync` because a replica shares one
/// cache across connections.
pub trait TrustCacheClock: Send + Sync {
    /// The current instant, in whole seconds since the Unix epoch.
    fn now_seconds(&self) -> u64;
}

/// The production clock: the system wall clock.
///
/// A clock misread as pre-epoch returns `0`, which ages every entry past
/// its lease — a broken wall clock fails closed toward re-walking, never
/// toward serving stale trust.
pub struct SystemClock;

impl TrustCacheClock for SystemClock {
    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since_epoch| since_epoch.as_secs())
    }
}

/// One cached resolution and the instant it was cached — the anchor of
/// its lease.
struct CacheEntry {
    resolved: ResolvedAuthority,
    cached_at: u64,
}

/// The bounded 60-second trust cache: one [`ResolvedAuthority`] per
/// (tenant, signer key id), each entry living at most
/// [`TRUST_CACHE_TTL_SECONDS`] from the request that cached it.
///
/// The map holds exactly the (tenant, signer) pairs this reader has
/// actually resolved and nothing else — no prewarming, no negative
/// entries — and expired entries are evicted on refusal, so the cache
/// carries no dead weight and no remembered failure.
///
/// Shared use across connections is safe: the map is a [`Mutex`], and
/// the lock is never held across a walk, so a slow registry cannot
/// serialize every resolver behind one request.
pub struct BoundedTrustCache {
    clock: Box<dyn TrustCacheClock>,
    entries: Mutex<HashMap<(TenantId, KeyId), CacheEntry>>,
}

impl BoundedTrustCache {
    /// A cache reading its leases from `clock`.
    pub fn new(clock: impl TrustCacheClock + 'static) -> Self {
        Self {
            clock: Box::new(clock),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `signer` for `tenant`'s chain — from the cache when a
    /// fresh entry exists, through `walk` otherwise — then apply the
    /// acceptance rule at the record's own `signed_at`.
    ///
    /// Shaped exactly as the resolver
    /// [`crate::authority::verify_control_record_resolved`] hands the
    /// record's parsed `(tenant, signer, signed_at)` to, with `walk` —
    /// the caller's registry access, everything this cache must not own
    /// — as the last argument:
    ///
    /// ```text
    /// verify_control_record_resolved(&envelope, |tenant, signer, at| {
    ///     cache.resolve(tenant, signer, at, |tenant, signer| {
    ///         resolve_authority(&root, signer, |key| store.fetch(key))
    ///     })
    /// })
    /// ```
    ///
    /// A hit returns the cached resolution without invoking `walk`. A
    /// miss — or an entry refused at its TTL — invokes `walk` once, and
    /// only a resolution the walk actually reached is cached, stamped
    /// with the instant this call began: a slow walk shortens what it
    /// later serves and never extends the sixty seconds.
    ///
    /// # Errors
    /// The acceptance classes of [`ResolvedAuthority::verify_signing_at`]
    /// ([`AuthorityChainError::MalformedRecord`] for an impossible
    /// instant, [`AuthorityChainError::NotEstablished`] before the
    /// signer's establishment, [`AuthorityChainError::Retired`] past the
    /// dual-key window) from hit and miss alike, plus whatever `walk`
    /// reports for a resolution the cache could not serve — a failed
    /// walk is propagated uncached and retried on the next record.
    pub fn resolve(
        &self,
        tenant: &TenantId,
        signer: &KeyId,
        signed_at: &Timestamp,
        walk: impl FnOnce(&TenantId, &KeyId) -> Result<ResolvedAuthority, AuthorityChainError>,
    ) -> Result<ResolvedAuthority, AuthorityChainError> {
        let now = self.clock.now_seconds();
        if let Some(resolved) = self.fresh_resolution(tenant, signer, now) {
            // The lease answers only "which half and which window" — the
            // acceptance decision is still this record's own instant's.
            resolved.verify_signing_at(signed_at)?;
            return Ok(resolved);
        }
        let resolved = walk(tenant, signer)?;
        self.insert(tenant, signer, resolved.clone(), now);
        resolved.verify_signing_at(signed_at)?;
        Ok(resolved)
    }

    /// The cached resolution for `(tenant, signer)` while it is inside
    /// its lease, evicting it the moment it is not.
    fn fresh_resolution(
        &self,
        tenant: &TenantId,
        signer: &KeyId,
        now: u64,
    ) -> Option<ResolvedAuthority> {
        let key = (tenant.clone(), *signer);
        let mut entries = self.entries_locked();
        let fresh = entries
            .get(&key)
            .filter(|entry| now.saturating_sub(entry.cached_at) < TRUST_CACHE_TTL_SECONDS)
            .map(|entry| entry.resolved.clone());
        if fresh.is_none() {
            // Whatever is at this key is gone now: an expired resolution
            // can never serve again, whatever the walk that follows
            // reports. (`saturating_sub` makes a clock stepped backwards
            // read as age zero — bounded by the same lease either way.)
            entries.remove(&key);
        }
        fresh
    }

    /// Cache a resolution the walk reached, replacing whatever was there.
    fn insert(
        &self,
        tenant: &TenantId,
        signer: &KeyId,
        resolved: ResolvedAuthority,
        cached_at: u64,
    ) {
        let key = (tenant.clone(), *signer);
        self.entries_locked().insert(
            key,
            CacheEntry {
                resolved,
                cached_at,
            },
        );
    }

    /// Lock the entry map, a poisoned lock included: an entry is always
    /// structurally valid public material, so a panic while holding the
    /// lock leaves nothing worth guarding against — recover the guard.
    fn entries_locked(&self) -> MutexGuard<'_, HashMap<(TenantId, KeyId), CacheEntry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{
        AuthorityRotationLink, PinnedAuthorityRoot, resolve_authority,
        verify_control_record_resolved,
    };
    use crate::ed25519;
    use archivist_protocol::json::{self, Object, Value};
    use archivist_protocol::vocabulary::{Ed25519PublicKey, Ed25519Signature};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// Insert a text member.
    fn text(value: &str) -> Value {
        Value::Text(value.to_owned())
    }

    /// A deterministic predecessor/successor pair: seeds fixed, so every
    /// signature below is reproducible byte for byte.
    const ROOT_SEED: [u8; 32] = [0x01; 32];
    const SUCCESSOR_SEED: [u8; 32] = [0x02; 32];
    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
    const LINK_INSTANT: &str = "2026-09-10T00:00:00Z";

    fn tenant() -> TenantId {
        TENANT.parse().expect("tenant grammar")
    }

    fn other_tenant() -> TenantId {
        OTHER_TENANT.parse().expect("tenant grammar")
    }

    fn pinned_root() -> PinnedAuthorityRoot {
        PinnedAuthorityRoot::new(tenant(), public_half(&ROOT_SEED))
    }

    fn public_half(seed: &[u8; 32]) -> Ed25519PublicKey {
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(seed))
    }

    fn instant(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("test instants are grammatical")
    }

    /// A fixed clock: the only time source on the test path, advanced by
    /// hand so every TTL boundary is deterministic.
    #[derive(Clone)]
    struct FixedClock {
        now: Arc<AtomicU64>,
    }

    impl FixedClock {
        fn at(seconds: u64) -> Self {
            Self {
                now: Arc::new(AtomicU64::new(seconds)),
            }
        }

        fn set(&self, seconds: u64) {
            self.now.store(seconds, Ordering::SeqCst);
        }
    }

    impl TrustCacheClock for FixedClock {
        fn now_seconds(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
    }

    /// How many times the cache fell through to the walk.
    #[derive(Clone, Default)]
    struct WalkCounter(Arc<AtomicUsize>);

    impl WalkCounter {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// Build the signed link that retires `predecessor_seed` and
    /// establishes `successor_seed` at `signed_at` for `tenant`.
    fn signed_link(
        predecessor_seed: &[u8; 32],
        successor_seed: &[u8; 32],
        signed_at: &str,
        tenant: &TenantId,
    ) -> Vec<u8> {
        let previous_public = public_half(predecessor_seed);
        let public = public_half(successor_seed);
        let previous_key_id = KeyId::from_public_key(&previous_public);
        let mut members = Object::new();
        members.set("schema", text("archivist.control/v1"));
        members.set("record_type", text("authority-rotation"));
        members.set("record_kind", text("immutable"));
        members.set("tenant_id", text(tenant.as_str()));
        members.set("previous_public_key", text(&previous_public.to_hex()));
        members.set("previous_key_id", text(&previous_key_id.to_hex()));
        members.set("key_algorithm", text("ed25519"));
        members.set("public_key", text(&public.to_hex()));
        members.set("key_id", text(&KeyId::from_public_key(&public).to_hex()));
        members.set("signed_at", text(signed_at));
        members.set("authority_key_id", text(&previous_key_id.to_hex()));
        let signature = ed25519::sign(
            predecessor_seed,
            &Value::Object(members.clone()).canonical_bytes(),
        );
        members.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        Value::Object(members).canonical_bytes()
    }

    /// A chain store: the bytes at each predecessor address, exactly as a
    /// `ControlReadStore` would serve them.
    fn chain_store(links: Vec<Vec<u8>>) -> HashMap<KeyId, Vec<u8>> {
        let mut store = HashMap::new();
        for bytes in links {
            let link = AuthorityRotationLink::parse(&bytes).expect("test links are well-formed");
            store.insert(*link.previous_key_id(), bytes);
        }
        store
    }

    /// A synthetic tenant-authority-signed control record, modeled on the
    /// receipt-key record, signed by `signer_seed` at `signed_at` under
    /// the control-record-v1 construction.
    fn signed_control_record(
        signer_seed: &[u8; 32],
        signed_at: &str,
        tenant: &TenantId,
    ) -> Vec<u8> {
        let signer_public = public_half(signer_seed);
        let signer_key_id = KeyId::from_public_key(&signer_public);
        let payload_key = KeyId::from_public_key(&public_half(&[0x5c; 32]));
        let mut members = Object::new();
        members.set("schema", text("archivist.control/v1"));
        members.set("record_type", text("receipt-key"));
        members.set("record_kind", text("immutable"));
        members.set("tenant_id", text(tenant.as_str()));
        members.set("key_algorithm", text("ed25519"));
        members.set("key_id", text(&payload_key.to_hex()));
        members.set("signed_at", text(signed_at));
        members.set("authority_key_id", text(&signer_key_id.to_hex()));
        let signature = ed25519::sign(
            signer_seed,
            &Value::Object(members.clone()).canonical_bytes(),
        );
        members.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        Value::Object(members).canonical_bytes()
    }

    #[test]
    fn the_ttl_constant_is_the_pinned_window() {
        assert_eq!(TRUST_CACHE_TTL_SECONDS, 60);
    }

    #[test]
    fn a_hit_within_the_ttl_serves_the_cache_without_walking() {
        let root = pinned_root();
        let store = chain_store(vec![]);
        let clock = FixedClock::at(1_000);
        let cache = BoundedTrustCache::new(clock.clone());
        let walks = WalkCounter::default();
        let signer = *root.key_id();
        let at = instant("2030-01-01T00:00:00Z");
        let walk = |_tenant: &TenantId, key: &KeyId| {
            walks.0.fetch_add(1, Ordering::SeqCst);
            resolve_authority(&root, key, |k| store.get(k).cloned())
        };

        let first = cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("the pinned root resolves with no links at all");
        assert_eq!(walks.count(), 1);

        // Every age short of the TTL is a hit: the same resolution comes
        // back and the walk is never invoked again.
        for age in [0u64, 1, 30, 59] {
            clock.set(1_000 + age);
            let served = cache
                .resolve(&tenant(), &signer, &at, walk)
                .expect("a fresh entry serves");
            assert_eq!(served, first, "age {age} serves the cached resolution");
            assert_eq!(walks.count(), 1, "age {age} must be a hit, not a walk");
        }
    }

    #[test]
    fn an_entry_is_served_one_second_before_its_ttl_and_refused_at_it() {
        let root = pinned_root();
        let store = chain_store(vec![]);
        let clock = FixedClock::at(1_000);
        let cache = BoundedTrustCache::new(clock.clone());
        let walks = WalkCounter::default();
        let signer = *root.key_id();
        let at = instant("2030-01-01T00:00:00Z");
        let walk = |_tenant: &TenantId, key: &KeyId| {
            walks.0.fetch_add(1, Ordering::SeqCst);
            resolve_authority(&root, key, |k| store.get(k).cloned())
        };

        cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("first walk");
        assert_eq!(walks.count(), 1);

        // Age 59: the lease's last serving instant.
        clock.set(1_059);
        cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("age 59 serves");
        assert_eq!(walks.count(), 1, "age 59 is still a hit");

        // Age 60 — the boundary itself: refused, and the walk resumes.
        clock.set(1_060);
        cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("the re-walk succeeds");
        assert_eq!(
            walks.count(),
            2,
            "age 60 is the first request past the lease"
        );

        // The re-walk cached a fresh lease anchored at this call: age 59
        // of the new lease serves, age 60 of it refuses again.
        clock.set(1_119);
        cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("the new lease serves");
        assert_eq!(walks.count(), 2);
        clock.set(1_120);
        cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("walk again");
        assert_eq!(
            walks.count(),
            3,
            "the new lease expires 60 seconds after its walk"
        );
    }

    #[test]
    fn past_the_ttl_a_dead_registry_fails_closed_not_stale() {
        // The successor's resolution caches against a healthy registry;
        // the registry then dies and the lease expires. The next request
        // must re-walk and report the registry's own failure class —
        // never the expired resolution.
        let root = pinned_root();
        let successor = KeyId::from_public_key(&public_half(&SUCCESSOR_SEED));
        let healthy = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);
        let dead: HashMap<KeyId, Vec<u8>> = chain_store(vec![]);
        let clock = FixedClock::at(2_000);
        let cache = BoundedTrustCache::new(clock.clone());
        let walks = WalkCounter::default();
        let at = instant("2026-09-10T00:00:00Z");
        let walk = |_tenant: &TenantId, key: &KeyId| {
            walks.0.fetch_add(1, Ordering::SeqCst);
            // The registry dies the moment the lease does: before 2_060
            // it serves the healthy view, at and past it nothing.
            let store: &HashMap<KeyId, Vec<u8>> = if clock.now_seconds() >= 2_060 {
                &dead
            } else {
                &healthy
            };
            resolve_authority(&root, key, |k| store.get(k).cloned())
        };

        let resolved = cache
            .resolve(&tenant(), &successor, &at, walk)
            .expect("the successor resolves while the registry is up");
        assert!(resolved.retired_at().is_none());
        assert_eq!(walks.count(), 1);

        // Inside the lease the dead registry is never consulted.
        clock.set(2_030);
        let served = cache
            .resolve(&tenant(), &successor, &at, walk)
            .expect("the lease outlives the outage this long");
        assert_eq!(served, resolved);
        assert_eq!(walks.count(), 1);

        // Past the lease: re-walk, registry still down, fail closed.
        clock.set(2_060);
        assert_eq!(
            cache.resolve(&tenant(), &successor, &at, walk).unwrap_err(),
            AuthorityChainError::Unreachable,
            "an expired entry is refused; the outage's own error surfaces"
        );
        assert_eq!(walks.count(), 2);

        // And the refusal evicted the entry: nothing stale remains to
        // serve on any later request.
        clock.set(2_061);
        assert_eq!(
            cache.resolve(&tenant(), &successor, &at, walk).unwrap_err(),
            AuthorityChainError::Unreachable
        );
        assert_eq!(walks.count(), 3, "each past-lease request re-walks");
    }

    #[test]
    fn a_failed_walk_is_never_cached() {
        // An unreachable signer while the registry is empty fails closed
        // twice, then resolves the moment the registry recovers — a
        // failure is never remembered, so the outage stays retryable.
        let root = pinned_root();
        let successor = KeyId::from_public_key(&public_half(&SUCCESSOR_SEED));
        let empty = chain_store(vec![]);
        let recovered = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);
        let clock = FixedClock::at(5_000);
        let cache = BoundedTrustCache::new(clock.clone());
        let walks = WalkCounter::default();
        let at = instant(LINK_INSTANT);
        let recovers_at = 5_005;
        let walk = |_tenant: &TenantId, key: &KeyId| {
            walks.0.fetch_add(1, Ordering::SeqCst);
            let store = if clock.now_seconds() >= recovers_at {
                &recovered
            } else {
                &empty
            };
            resolve_authority(&root, key, |k| store.get(k).cloned())
        };

        assert_eq!(
            cache.resolve(&tenant(), &successor, &at, walk).unwrap_err(),
            AuthorityChainError::Unreachable
        );
        clock.set(5_001);
        assert_eq!(
            cache.resolve(&tenant(), &successor, &at, walk).unwrap_err(),
            AuthorityChainError::Unreachable
        );
        assert_eq!(walks.count(), 2, "a failed walk must not be remembered");

        // The registry recovers; the very next record walks and succeeds.
        clock.set(5_005);
        let resolved = cache
            .resolve(&tenant(), &successor, &at, walk)
            .expect("the recovered registry resolves the successor");
        assert_eq!(
            resolved.established_at().map(Timestamp::as_str),
            Some(LINK_INSTANT)
        );
        assert_eq!(walks.count(), 3);

        // And the success is cached: the next record inside the lease is
        // a hit.
        clock.set(5_030);
        cache
            .resolve(&tenant(), &successor, &at, walk)
            .expect("the fresh lease serves");
        assert_eq!(walks.count(), 3);
    }

    #[test]
    fn a_retired_signers_cached_resolution_still_enforces_its_own_window() {
        // The root's resolution — retired at LINK_INSTANT — caches while
        // the record flow is inside the 24-hour dual-key window. Cached
        // or not, acceptance is the record's own signed_at: mid-window
        // records verify, the window's last instant verifies, and a
        // record signed past the window is rejected off the very same
        // cached entry.
        let root = pinned_root();
        let store = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);
        let clock = FixedClock::at(10_000);
        let cache = BoundedTrustCache::new(clock.clone());
        let walks = WalkCounter::default();
        let signer = *root.key_id();
        let walk = |_tenant: &TenantId, key: &KeyId| {
            walks.0.fetch_add(1, Ordering::SeqCst);
            resolve_authority(&root, key, |k| store.get(k).cloned())
        };

        // Cache the resolution mid-window (the walk sees the retirement).
        let mid_window = instant("2026-09-10T12:00:00Z");
        let cached = cache
            .resolve(&tenant(), &signer, &mid_window, walk)
            .expect("the root is mid-overlap");
        assert_eq!(
            cached.retired_at().map(Timestamp::as_str),
            Some(LINK_INSTANT),
            "the cached resolution carries the retirement anchor"
        );
        assert_eq!(walks.count(), 1);

        // Still inside the lease: the acceptance rule decides at each
        // record's own instant, the walk never resumed.
        clock.set(10_030);
        assert!(
            cache.resolve(&tenant(), &signer, &mid_window, walk).is_ok(),
            "a mid-window record verifies off the cache"
        );
        let boundary = instant("2026-09-11T00:00:00Z");
        assert!(
            cache.resolve(&tenant(), &signer, &boundary, walk).is_ok(),
            "the overlap includes its last instant, cached or not"
        );
        assert_eq!(
            cache
                .resolve(&tenant(), &signer, &instant("2026-09-12T00:00:00Z"), walk)
                .unwrap_err(),
            AuthorityChainError::Retired,
            "a record past the 24-hour window is rejected off the cached entry"
        );
        assert_eq!(walks.count(), 1, "every decision above was a cache hit");
    }

    #[test]
    fn entries_are_per_tenant_even_for_the_same_key_id() {
        // One key half pinned by two tenants: the chain has no force
        // outside its tenant, and neither does a cached entry. The same
        // key id resolves unretired for one tenant and retired for the
        // other, each through its own walk.
        let root_a = PinnedAuthorityRoot::new(tenant(), public_half(&ROOT_SEED));
        let root_b = PinnedAuthorityRoot::new(other_tenant(), public_half(&ROOT_SEED));
        let store_a = chain_store(vec![]);
        let store_b = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &other_tenant(),
        )]);
        let clock = FixedClock::at(20_000);
        let cache = BoundedTrustCache::new(clock.clone());
        let walks = WalkCounter::default();
        let signer = *root_a.key_id();
        let at = instant("2030-01-01T00:00:00Z");
        let walk = |record_tenant: &TenantId, key: &KeyId| {
            walks.0.fetch_add(1, Ordering::SeqCst);
            let (pinned, store) = if *record_tenant == tenant() {
                (&root_a, &store_a)
            } else {
                (&root_b, &store_b)
            };
            resolve_authority(pinned, key, |k| store.get(k).cloned())
        };

        let for_a = cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("tenant A's root resolves unretired");
        assert!(for_a.retired_at().is_none());
        assert_eq!(walks.count(), 1);

        // B's root is retired, so B's record carries an instant inside
        // the dual-key window — the resolution resolves retired and the
        // acceptance at that instant still holds.
        let b_record_at = instant(LINK_INSTANT);
        let for_b = cache
            .resolve(&other_tenant(), &signer, &b_record_at, walk)
            .expect("tenant B's root resolves retired");
        assert_eq!(
            for_b.retired_at().map(Timestamp::as_str),
            Some(LINK_INSTANT),
            "tenant B must not be served tenant A's entry"
        );
        assert_eq!(walks.count(), 2);

        // And back to A: still its own cached entry, no third walk.
        clock.set(20_030);
        let again = cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("tenant A's own lease serves");
        assert_eq!(again, for_a);
        assert_eq!(walks.count(), 2);
    }

    #[test]
    fn the_cache_is_a_drop_in_resolver_for_the_seam() {
        // The wiring the module exists for: verify_control_record_
        // resolved with the cache in front of the walk. The first record
        // walks, the second is served from the cache, and the seam's own
        // signature and acceptance checks hold identically on both.
        let root = pinned_root();
        let store = chain_store(vec![signed_link(
            &ROOT_SEED,
            &SUCCESSOR_SEED,
            LINK_INSTANT,
            &tenant(),
        )]);
        let clock = FixedClock::at(30_000);
        let cache = BoundedTrustCache::new(clock.clone());
        let walks = WalkCounter::default();
        let walk = |record_tenant: &TenantId, key: &KeyId| {
            walks.0.fetch_add(1, Ordering::SeqCst);
            if *record_tenant != *root.tenant_id() {
                return Err(AuthorityChainError::RecordDisagreement);
            }
            resolve_authority(&root, key, |k| store.get(k).cloned())
        };

        let mid_overlap = "2026-09-10T12:00:00Z";
        let record = signed_control_record(&SUCCESSOR_SEED, mid_overlap, &tenant());
        let resolve =
            |tenant: &TenantId, key: &KeyId, at: &Timestamp| cache.resolve(tenant, key, at, walk);

        let first = verify_control_record_resolved(&record, resolve)
            .expect("the first record walks the chain and verifies");
        assert_eq!(walks.count(), 1);

        // The second record, seconds later: the same resolution served
        // from the cache, and the record verifies against it.
        clock.set(30_010);
        let second = {
            let resolve = |tenant: &TenantId, key: &KeyId, at: &Timestamp| {
                cache.resolve(tenant, key, at, walk)
            };
            verify_control_record_resolved(&record, resolve)
                .expect("the cached resolution verifies the second record")
        };
        assert_eq!(first, second);
        assert_eq!(walks.count(), 1, "the second verification was a hit");

        // The seam's own forgery check is untouched by the cache: a
        // tampered payload fails the signature over the cached
        // resolution exactly as over a fresh walk.
        let Value::Object(mut forged) = json::parse(&record).expect("json") else {
            panic!("object");
        };
        forged.set(
            "key_id",
            Value::Text(KeyId::from_public_key(&public_half(&[0x5d; 32])).to_hex()),
        );
        let resolve =
            |tenant: &TenantId, key: &KeyId, at: &Timestamp| cache.resolve(tenant, key, at, walk);
        assert_eq!(
            verify_control_record_resolved(&Value::Object(forged).canonical_bytes(), resolve)
                .unwrap_err(),
            AuthorityChainError::Signature,
            "a payload the signature does not cover is a forgery off the cache too"
        );

        // And the predecessor signing past its window is refused —
        // acceptance at the record's own instant, seam-side. The late
        // record names the ROOT signer, whose resolution this cache had
        // never been asked for: it walks once (caching the root's
        // resolution) and the acceptance rule refuses at the record's
        // own instant, so the walk happened but the refusal is the
        // acceptance class, not the walk's.
        let late = signed_control_record(&ROOT_SEED, "2026-09-12T00:00:00Z", &tenant());
        let resolve =
            |tenant: &TenantId, key: &KeyId, at: &Timestamp| cache.resolve(tenant, key, at, walk);
        assert_eq!(
            verify_control_record_resolved(&late, resolve).unwrap_err(),
            AuthorityChainError::Retired
        );
        assert_eq!(
            walks.count(),
            2,
            "only the never-cached root signer walked; every successor call was a hit"
        );
    }

    #[test]
    fn a_clock_stepped_backwards_cannot_extend_a_lease() {
        // The lease is anchored at the instant the entry was cached: a
        // clock stepped backwards reads as age zero (saturating), and
        // the entry still expires at cached_at + TTL regardless of the
        // dip — bounded staleness under clock movement in both
        // directions.
        let root = pinned_root();
        let store = chain_store(vec![]);
        let clock = FixedClock::at(40_000);
        let cache = BoundedTrustCache::new(clock.clone());
        let walks = WalkCounter::default();
        let signer = *root.key_id();
        let at = instant("2030-01-01T00:00:00Z");
        let walk = |_tenant: &TenantId, key: &KeyId| {
            walks.0.fetch_add(1, Ordering::SeqCst);
            resolve_authority(&root, key, |k| store.get(k).cloned())
        };

        cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("first walk");
        assert_eq!(walks.count(), 1);

        clock.set(39_999);
        cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("a backwards step reads as age zero");
        assert_eq!(walks.count(), 1);

        clock.set(40_060);
        cache
            .resolve(&tenant(), &signer, &at, walk)
            .expect("the walk after expiry");
        assert_eq!(
            walks.count(),
            2,
            "the dip never moved the expiry: age 60 from the anchor refuses"
        );
    }
}
