// SPDX-License-Identifier: Apache-2.0

//! The noncurrent-version lifecycle audit: a versions-aware enumeration
//! over the audit/restore identity's scopes, and the STO-009 measurement
//! it reduces to — how many redundant noncurrent physical versions a
//! versioned backend is retaining at the derived keys, and how many bytes
//! they hold.
//!
//! Versioning enabled plus deterministic overwrite (STO-006) means every
//! replayed duplicate, equivalent overwrite, and concurrent writer lands
//! one more physical version *behind* the current one. Requirements
//! STO-009 makes the remedy a deployment action — configure lifecycle
//! expiration for redundant noncurrent versions, subject to retention
//! policy — and the qualification notes make the rule's scope
//! noncurrent-only: the current version at a derived key is the archive's
//! content address and is never a lifecycle target. What no qualification
//! artifact could do is *observe* the accumulation: the write path cannot
//! list (the raw-writer credential has no read, list, or delete method),
//! and the disclosure was words. This module makes it measurable.
//!
//! # The same identity, one more listing
//!
//! The audit rides the offline audit/restore identity — the only authority
//! with list grants across the tenant prefixes (plan Section 7.7) — and
//! reuses its closed scopes, key grammar, continuation tokens, and
//! observation metadata wholesale. It is deliberately **not** reachable
//! from ingestion: `ListObjectVersions` is the same rejected design the
//! `ListObjectsV2` rejection covers, and the ingest composition
//! ([`crate::ingest::IngestStorage`]) has no path to this trait either.
//! The audit is an operator and offline-tooling surface, like the restore
//! it sits beside.
//!
//! # The freeze contract, versions-shaped
//!
//! A versions listing returns *many records per key* — one per physical
//! version — so the `inventory-v1` freeze contract's duplicate-key fault
//! does not transfer directly. [`FrozenVersionListing::from_pages`] is the
//! one implementation of the versions-shaped contract, and it fails closed
//! on exactly the analogs: a page error, a repeated continuation token, a
//! repeated *(key, version)* pair, an out-of-prefix key, a key with zero
//! or several `latest` records, or a sequence that never reaches
//! exhaustion. Versions of one key may split across pages — grouping is
//! the validator's job, not the paginator's — and the canonical form is
//! sorted by key bytes and then by version bytes, so the digest is
//! independent of page boundaries and listing order.
//!
//! # What the audit cannot see
//!
//! The lifecycle rules themselves are invisible to every archivist
//! identity by construction — ARMOR authorizes reading the configuration
//! by an effect no archivist credential holds — so the audit never claims
//! a rule is present, absent, or drifted. It measures the residue the
//! rule exists to cap: noncurrent counts and retained bytes per scope,
//! cited against the documented guidance
//! ([`NONCURRENT_VERSION_GUIDANCE`]). A deployment that wants the concern
//! bounded compares consecutive audits; the numbers are the evidence the
//! disclosure could not offer.

use std::collections::BTreeMap;
use std::fmt;

use archivist_protocol::derivation::FrameBuilder;

use crate::audit_restore::{
    ContinuationToken, InventoryDigest, InventoryKey, InventoryScope, MAX_FREEZE_PAGES,
};
use crate::error::{StorageError, StorageErrorKind};
use crate::metadata::{ObjectTag, Observation, StorageVersionId};

/// The documented lifecycle guidance the audit's numbers are cited
/// against: requirements STO-009 — deployments using deterministic
/// overwrite on a versioned backend SHOULD configure lifecycle expiration
/// for redundant noncurrent versions, subject to retention policy — with
/// the qualification notes' scope rule (noncurrent copies only; the
/// current version at a derived key is the archive's content address).
pub const NONCURRENT_VERSION_GUIDANCE: &str = "sto-009-noncurrent-version-expiration";

/// One physical version as a versions listing observed it: the key it
/// lives at, its stored size, the backend's version identity, whether it
/// is that key's current version, and the observation evidence.
///
/// The version is mandatory here, by contrast with
/// [`Observation::storage_version`]'s optionality: an entry without a
/// backend-reported version identity cannot support the noncurrent/current
/// distinction the audit exists to make, so a versions listing that cannot
/// attribute versions is not a versions listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedEntry {
    key: InventoryKey,
    size: u64,
    version: StorageVersionId,
    is_latest: bool,
    observation: Observation,
}

impl VersionedEntry {
    /// Pair one observed physical version with its listing facts.
    #[must_use]
    pub fn new(
        key: InventoryKey,
        size: u64,
        version: StorageVersionId,
        is_latest: bool,
        observation: Observation,
    ) -> Self {
        Self {
            key,
            size,
            version,
            is_latest,
            observation,
        }
    }

    /// The key this version lives at.
    #[must_use]
    pub fn key(&self) -> &InventoryKey {
        &self.key
    }

    /// The stored size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The backend's version identity for this physical version.
    #[must_use]
    pub const fn version(&self) -> &StorageVersionId {
        &self.version
    }

    /// Whether this version is the key's current version.
    #[must_use]
    pub const fn is_latest(&self) -> bool {
        self.is_latest
    }

    /// The observation evidence.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }
}

/// One page of a versions listing: the versions the page observed and the
/// paginator's continuation, if any.
///
/// Like [`crate::audit_restore::InventoryPage`], a lone page is purely
/// advisory — the contract holds only across a whole sequence assembled by
/// [`FrozenVersionListing::from_pages`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedPage {
    entries: Vec<VersionedEntry>,
    next: Option<ContinuationToken>,
}

impl VersionedPage {
    /// Assemble one page from its entries and continuation.
    #[must_use]
    pub fn new(entries: Vec<VersionedEntry>, next: Option<ContinuationToken>) -> Self {
        Self { entries, next }
    }

    /// The version records this page observed.
    #[must_use]
    pub fn entries(&self) -> &[VersionedEntry] {
        &self.entries
    }

    /// The continuation token, when the listing has more pages.
    #[must_use]
    pub fn next(&self) -> Option<&ContinuationToken> {
        self.next.as_ref()
    }
}

/// One key's full physical version set: the current version plus every
/// noncurrent version the frozen listing observed behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyVersions {
    key: InventoryKey,
    versions: Vec<VersionedEntry>,
}

impl KeyVersions {
    /// The key these versions belong to.
    #[must_use]
    pub fn key(&self) -> &InventoryKey {
        &self.key
    }

    /// Every observed version, current and noncurrent, in canonical
    /// version-byte order.
    #[must_use]
    pub fn versions(&self) -> &[VersionedEntry] {
        &self.versions
    }

    /// The number of physical versions at this key.
    #[must_use]
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Whether the listing observed no versions (never true for a
    /// validated listing: a key exists because a version carried it).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// The key's current version.
    #[must_use]
    pub fn latest(&self) -> Option<&VersionedEntry> {
        self.versions.iter().find(|entry| entry.is_latest)
    }

    /// The noncurrent versions: the redundant physical copies STO-009's
    /// lifecycle guidance targets. Exactly the versions a noncurrent-only
    /// expiration rule may age out — the current version at a derived key
    /// is the archive's content address and is never a lifecycle target.
    pub fn noncurrent(&self) -> impl Iterator<Item = &VersionedEntry> {
        self.versions.iter().filter(|entry| !entry.is_latest)
    }

    /// The bytes the noncurrent versions retain.
    #[must_use]
    pub fn noncurrent_bytes(&self) -> u64 {
        self.noncurrent().map(VersionedEntry::size).sum()
    }
}

/// The frozen exhaustive versions enumeration of one scope: the
/// `version-audit-v1` contract, the versions-shaped analog of the
/// `inventory-v1` freeze.
///
/// The freeze is **not** assumed to be a transactionally consistent
/// snapshot of the moment it started — exactly why it is evidence. A
/// consumer that needs a fresher answer re-freezes; a consumer comparing
/// two audits cites both digests.
#[derive(Clone, Debug)]
pub struct FrozenVersionListing {
    scope: InventoryScope,
    keys: Vec<KeyVersions>,
    digest: InventoryDigest,
}

impl FrozenVersionListing {
    /// Validate a complete page sequence and freeze it.
    ///
    /// The one implementation of the versions freeze contract:
    ///
    /// - the sequence reaches exhaustion — the last page continues
    ///   nothing, and no page follows one that continued nothing;
    /// - no continuation token repeats within the sequence (a repeated
    ///   token is a loop, and a loop is a fault even if the pages happen
    ///   to agree);
    /// - every key is inside the scope's prefix (a list that leaks across
    ///   a prefix boundary is not this scope's listing);
    /// - no *(key, version)* pair repeats (a repeated version identity is
    ///   a loop or a broken paginator — the versions analog of the
    ///   duplicate-key fault);
    /// - every key carries exactly one `latest` record (zero means the
    ///   listing cannot say which version is current; several means it
    ///   said so twice);
    /// - the page count is within [`MAX_FREEZE_PAGES`].
    ///
    /// Versions of one key may split across pages; grouping is the
    /// validator's job. The frozen form is sorted by key bytes and then by
    /// version bytes, so page boundaries and listing order are invisible
    /// to the digest. Any violation, and any page error the caller
    /// surfaces in `pages`' place, fails the whole freeze closed.
    ///
    /// # Errors
    /// [`StorageError::InventoryFault`](crate::error::StorageError) for
    /// every contract violation above — never a partial listing.
    pub fn from_pages(
        scope: &InventoryScope,
        pages: Vec<Result<VersionedPage, StorageError>>,
    ) -> Result<Self, StorageError> {
        if pages.len() > MAX_FREEZE_PAGES {
            return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
        }
        let prefix = scope.prefix();
        let mut seen_tokens: Vec<ContinuationToken> = Vec::new();
        let mut seen_versions: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        let mut grouped: BTreeMap<String, (InventoryKey, Vec<VersionedEntry>)> = BTreeMap::new();
        let mut exhausted = false;
        for page in pages {
            // A page after exhaustion means the paginator kept going past
            // its own end — not a sequence that reaches exhaustion.
            if exhausted {
                return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
            }
            let page = page.map_err(|_| StorageError::of_kind(StorageErrorKind::InventoryFault))?;
            if let Some(token) = page.next() {
                if seen_tokens.contains(token) {
                    return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
                }
                seen_tokens.push(token.clone());
            } else {
                exhausted = true;
            }
            for entry in page.entries {
                if !entry.key().as_str().starts_with(&prefix) {
                    return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
                }
                if !seen_versions.insert((
                    entry.key().as_str().to_owned(),
                    entry.version().as_str().to_owned(),
                )) {
                    return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
                }
                grouped
                    .entry(entry.key().as_str().to_owned())
                    .or_insert_with(|| (entry.key().clone(), Vec::new()))
                    .1
                    .push(entry);
            }
        }
        if !exhausted {
            return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
        }
        let mut keys: Vec<KeyVersions> = grouped
            .into_values()
            .map(|(key, mut versions)| {
                // Canonical order within a key is version-byte order, so
                // the digest is independent of listing order.
                versions.sort_unstable_by(|a, b| {
                    a.version()
                        .as_str()
                        .as_bytes()
                        .cmp(b.version().as_str().as_bytes())
                });
                KeyVersions { key, versions }
            })
            .collect();
        // The keys arrived grouped from a byte-ordered map; re-sorting by
        // the parsed key's bytes keeps the invariant local to this type
        // instead of leaning on the grouping's iteration order.
        keys.sort_unstable_by(|a, b| a.key().as_str().as_bytes().cmp(b.key().as_str().as_bytes()));
        for group in &keys {
            let latest = group
                .versions
                .iter()
                .filter(|entry| entry.is_latest)
                .count();
            if latest != 1 {
                return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
            }
        }
        let digest = Self::compute_digest(scope, &keys);
        Ok(Self {
            scope: scope.clone(),
            keys,
            digest,
        })
    }

    /// The digest framing (`version-audit-v1`): the domain-separated,
    /// length-prefixed construction the protocol's identity derivations
    /// use, mirroring the `inventory-v1` framing.
    ///
    /// `label "version-audit-v1" || 0x00`, then the scope prefix as a
    /// `text` field, the key count as a `u63` field, then, per key in
    /// canonical key-byte order: the key (`text`), the version count
    /// (`u63`), and, per version in canonical version-byte order: the
    /// version identity (`text`), the size (`u63`), the currency flag
    /// (`text`, `latest` or `noncurrent`), the tag (`text`, empty when
    /// absent — a real tag is never empty), and the observation time
    /// (`text`, the wire timestamp).
    #[must_use]
    pub fn compute_digest(scope: &InventoryScope, keys: &[KeyVersions]) -> InventoryDigest {
        let mut frame = FrameBuilder::new("version-audit-v1");
        frame.push_text(&scope.prefix());
        frame.push_u63(keys.len() as u64);
        for group in keys {
            frame.push_text(group.key().as_str());
            frame.push_u63(group.len() as u64);
            for entry in group.versions() {
                frame.push_text(entry.version().as_str());
                frame.push_u63(entry.size());
                frame.push_text(if entry.is_latest {
                    "latest"
                } else {
                    "noncurrent"
                });
                frame.push_text(entry.observation().etag().map_or("", ObjectTag::as_str));
                frame.push_text(entry.observation().observed_at().as_str());
            }
        }
        InventoryDigest::from_raw(frame.finish())
    }

    /// The scope the listing froze.
    #[must_use]
    pub const fn scope(&self) -> &InventoryScope {
        &self.scope
    }

    /// The keys, in canonical key-byte order, each with its full version
    /// set.
    #[must_use]
    pub fn keys(&self) -> &[KeyVersions] {
        &self.keys
    }

    /// The number of distinct keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the listing observed no keys at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The pinned listing digest.
    #[must_use]
    pub const fn digest(&self) -> &InventoryDigest {
        &self.digest
    }

    /// The total number of physical versions across every key.
    #[must_use]
    pub fn total_versions(&self) -> usize {
        self.keys.iter().map(KeyVersions::len).sum()
    }
}

/// The STO-009 measurement of one frozen scope: how much redundant
/// noncurrent physical material the versioned backend is retaining, and
/// where it concentrates.
///
/// Every number is a measurement of the residue, never a claim about the
/// lifecycle rule: the rules are operator-managed and invisible to every
/// archivist identity, so "the count grew since the last audit" is the
/// sound the missing or drifted rule makes. The guidance citation
/// ([`NONCURRENT_VERSION_GUIDANCE`]) is part of the rendered line so a
/// report quoted out of context still names the duty it measures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoncurrentVersionReport {
    scope: InventoryScope,
    distinct_keys: usize,
    total_versions: usize,
    noncurrent_versions: usize,
    noncurrent_bytes: u64,
    total_bytes: u64,
    fullest_key: Option<String>,
    fullest_noncurrent: usize,
}

impl NoncurrentVersionReport {
    /// Reduce a frozen listing to the lifecycle measurement.
    #[must_use]
    pub fn from_listing(listing: &FrozenVersionListing) -> Self {
        let distinct_keys = listing.len();
        let total_versions = listing.total_versions();
        let noncurrent_versions = listing
            .keys()
            .iter()
            .map(|group| group.len().saturating_sub(1))
            .sum();
        let noncurrent_bytes: u64 = listing
            .keys()
            .iter()
            .map(KeyVersions::noncurrent_bytes)
            .sum();
        let total_bytes: u64 = listing
            .keys()
            .iter()
            .flat_map(|group| group.versions().iter().map(VersionedEntry::size))
            .sum();
        // The key where accumulation concentrates, and how deep it runs.
        // The keys arrive in canonical order and the scan keeps only
        // strictly deeper accumulations, so ties resolve to the first key
        // in canonical order — a deterministic choice.
        let mut fullest: Option<&KeyVersions> = None;
        for group in listing.keys() {
            if group.len() > 1 && fullest.is_none_or(|deepest| group.len() > deepest.len()) {
                fullest = Some(group);
            }
        }
        let fullest_noncurrent = fullest.map_or(0, |group| group.len() - 1);
        Self {
            scope: listing.scope().clone(),
            distinct_keys,
            total_versions,
            noncurrent_versions,
            noncurrent_bytes,
            total_bytes,
            fullest_key: fullest.map(|group| group.key().as_str().to_owned()),
            fullest_noncurrent,
        }
    }

    /// The scope the measurement covers.
    #[must_use]
    pub const fn scope(&self) -> &InventoryScope {
        &self.scope
    }

    /// Distinct keys (logical objects) in the scope.
    #[must_use]
    pub const fn distinct_keys(&self) -> usize {
        self.distinct_keys
    }

    /// Every physical version, current and noncurrent.
    #[must_use]
    pub const fn total_versions(&self) -> usize {
        self.total_versions
    }

    /// The noncurrent (redundant) physical versions — the count STO-009's
    /// lifecycle rule exists to bound.
    #[must_use]
    pub const fn noncurrent_versions(&self) -> usize {
        self.noncurrent_versions
    }

    /// The bytes the noncurrent versions retain — the storage a
    /// noncurrent-only expiration rule would reclaim.
    #[must_use]
    pub const fn noncurrent_bytes(&self) -> u64 {
        self.noncurrent_bytes
    }

    /// Every version's bytes, current included.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// The key where accumulation runs deepest, when any accumulation
    /// exists.
    #[must_use]
    pub fn fullest_key(&self) -> Option<&str> {
        self.fullest_key.as_deref()
    }

    /// The noncurrent depth at [`Self::fullest_key`].
    #[must_use]
    pub const fn fullest_noncurrent(&self) -> usize {
        self.fullest_noncurrent
    }

    /// The report line: one deterministic, content-free sentence with the
    /// counts, the retained bytes, and the guidance citation. The exact
    /// grammar the storage compatibility suite renders and the
    /// qualification kit's report grammar pins.
    #[must_use]
    pub fn render(&self) -> String {
        let mut line = format!(
            "noncurrent-version-audit scope={} keys={} versions={} noncurrent={} retained_bytes={} guidance={}",
            self.scope.prefix(),
            self.distinct_keys,
            self.total_versions,
            self.noncurrent_versions,
            self.noncurrent_bytes,
            NONCURRENT_VERSION_GUIDANCE,
        );
        if let Some(key) = &self.fullest_key {
            use std::fmt::Write as _;
            let _ = write!(
                line,
                " fullest_key={key} fullest_noncurrent={}",
                self.fullest_noncurrent
            );
        }
        line
    }
}

impl fmt::Display for NoncurrentVersionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// The audit identity's listing authority: exhaustive version-aware
/// enumeration over the closed [`InventoryScope`]s.
///
/// This is the versions-shaped sibling of
/// [`crate::audit_restore::AuditRestoreStore`]'s enumeration half, held by
/// the same offline identity — the only authority with list grants across
/// the tenant prefixes — and deliberately unreachable from ingestion. The
/// trait has no read, write, or delete method: an audit that needs object
/// bodies uses the identity's read authority
/// ([`crate::audit_restore::AuditRestoreStore::read_object`]), and nothing
/// here can mutate or destroy anything.
pub trait LifecycleAuditStore {
    /// Fetch one page of the scope's versions listing.
    ///
    /// Implementations follow the backend's versions pagination from
    /// `after` and enforce the identity's prefix scope before any request
    /// exists. A lone page is advisory; only a whole frozen sequence
    /// ([`freeze_version_listing`]) is evidence.
    ///
    /// # Errors
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down,
    /// [`StorageError::ScopeViolation`](crate::error::StorageError) when
    /// the scope is outside this identity's provisioning.
    fn list_versions_page(
        &self,
        scope: &InventoryScope,
        after: Option<&ContinuationToken>,
    ) -> impl Future<Output = Result<VersionedPage, StorageError>> + Send;
}

/// Freeze a scope's versions listing: page
/// [`LifecycleAuditStore::list_versions_page`] to exhaustion and validate
/// the whole sequence through [`FrozenVersionListing::from_pages`] — the
/// one contract implementation — so duplicate version identities,
/// repeated tokens, out-of-prefix keys, ill-currencied keys, page errors,
/// and non-exhaustion all fail the freeze closed.
///
/// A frozen listing is never assumed to be a transactionally consistent
/// snapshot of the moment the freeze started; consumers re-freeze for a
/// fresher answer and cite digests when comparing.
///
/// # Errors
/// [`StorageError::InventoryFault`](crate::error::StorageError) for any
/// freeze-contract violation,
/// [`StorageError::Unavailable`](crate::error::StorageError) when the
/// backend or network is down,
/// [`StorageError::ScopeViolation`](crate::error::StorageError) when the
/// scope is outside the identity's provisioning.
pub async fn freeze_version_listing<S: LifecycleAuditStore + Sync>(
    store: &S,
    scope: &InventoryScope,
) -> Result<FrozenVersionListing, StorageError> {
    let mut pages: Vec<Result<VersionedPage, StorageError>> = Vec::new();
    let mut after: Option<ContinuationToken> = None;
    let mut exhausted = false;
    while !exhausted {
        // The same bound the validator enforces, checked on the way in so
        // a looping paginator cannot grow the sequence unboundedly before
        // the validator ever sees it.
        if pages.len() == MAX_FREEZE_PAGES {
            return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
        }
        let page = store.list_versions_page(scope, after.as_ref()).await?;
        exhausted = page.next().is_none();
        after = page.next().cloned();
        pages.push(Ok(page));
    }
    FrozenVersionListing::from_pages(scope, pages)
}

#[cfg(test)]
mod tests {
    use super::{
        FrozenVersionListing, KeyVersions, LifecycleAuditStore, NONCURRENT_VERSION_GUIDANCE,
        NoncurrentVersionReport, VersionedEntry, VersionedPage, freeze_version_listing,
    };
    use crate::audit_restore::{ContinuationToken, InventoryDigest, InventoryKey, InventoryScope};
    use crate::error::{StorageError, StorageErrorKind};
    use crate::metadata::{ObjectTag, Observation, StorageVersionId};

    use archivist_protocol::vocabulary::Timestamp;

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const OBSERVED: &str = "2026-09-27T12:00:00Z";

    fn scope() -> InventoryScope {
        InventoryScope::TenantRaw(TENANT.parse().unwrap())
    }

    fn observed_at() -> Timestamp {
        Timestamp::parse(OBSERVED).unwrap()
    }

    fn key(tail: &str) -> InventoryKey {
        InventoryKey::parse(&format!("tenants/{TENANT}/v1/raw/{tail}")).unwrap()
    }

    fn version_id(text: &str) -> StorageVersionId {
        StorageVersionId::parse(text).unwrap()
    }

    fn entry(tail: &str, size: u64, version: &str, latest: bool) -> VersionedEntry {
        VersionedEntry::new(
            key(tail),
            size,
            version_id(version),
            latest,
            Observation::new(
                Some(ObjectTag::parse("\"tag\"").unwrap()),
                None,
                observed_at(),
            ),
        )
    }

    // Deliberately Option-shaped: every call site passes the token
    // straight into an `Option<ContinuationToken>` field.
    #[allow(clippy::unnecessary_wraps)]
    fn token(text: &str) -> Option<ContinuationToken> {
        Some(ContinuationToken::parse(text).unwrap())
    }

    /// A deterministic backend the freeze loop can drive: the token
    /// `p<N>` names page index `N`, exactly a paginator would mint them.
    #[derive(Clone, Debug)]
    struct PageSource {
        scope: InventoryScope,
        pages: Vec<Result<VersionedPage, StorageError>>,
    }

    impl LifecycleAuditStore for PageSource {
        async fn list_versions_page(
            &self,
            scope: &InventoryScope,
            after: Option<&ContinuationToken>,
        ) -> Result<VersionedPage, StorageError> {
            if *scope != self.scope {
                return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
            }
            let index = match after {
                None => 0,
                Some(token) => match token.as_str().strip_prefix('p') {
                    // An unknown token would be a loop; refuse here so the
                    // loop terminates regardless of what the validator
                    // would say one step later.
                    Some(number) => match number.parse::<usize>() {
                        Ok(found) if found < self.pages.len() => found,
                        _ => return Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
                    },
                    None => return Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
                },
            };
            self.pages
                .get(index)
                .cloned()
                .unwrap_or_else(|| Ok(VersionedPage::new(vec![], None)))
        }
    }

    // Deliberately Result-shaped: every call site embeds the page in the
    // `Result` sequence the freeze validator consumes.
    #[allow(clippy::unnecessary_wraps)]
    fn ok_page(
        entries: Vec<VersionedEntry>,
        next: Option<ContinuationToken>,
    ) -> Result<VersionedPage, StorageError> {
        Ok(VersionedPage::new(entries, next))
    }

    fn fault_kind(result: &Result<FrozenVersionListing, StorageError>) -> StorageErrorKind {
        match result {
            Ok(_) => panic!("the freeze must fail closed"),
            Err(error) => error.kind(),
        }
    }

    #[test]
    fn freeze_groups_versions_split_across_pages_and_digest_is_page_independent() {
        let pages = vec![
            ok_page(
                vec![entry("a", 10, "v2", true), entry("a", 10, "v1", false)],
                token("p1"),
            ),
            ok_page(vec![entry("b", 20, "v1", true)], None),
        ];
        let frozen = FrozenVersionListing::from_pages(&scope(), pages).unwrap();
        assert_eq!(frozen.len(), 2);
        assert_eq!(frozen.total_versions(), 3);
        assert_eq!(frozen.keys()[0].len(), 2);
        assert_eq!(
            frozen.keys()[0]
                .versions()
                .iter()
                .map(|entry| entry.version().as_str())
                .collect::<Vec<_>>(),
            vec!["v1", "v2"],
            "canonical order within a key is version-byte order"
        );
        assert!(frozen.keys()[0].latest().unwrap().is_latest());
        assert_eq!(frozen.keys()[0].noncurrent_bytes(), 10);

        // The same versions, one page, reversed within the page: identical
        // digest, because page boundaries and listing order are invisible.
        let single = FrozenVersionListing::from_pages(
            &scope(),
            vec![ok_page(
                vec![
                    entry("b", 20, "v1", true),
                    entry("a", 10, "v1", false),
                    entry("a", 10, "v2", true),
                ],
                None,
            )],
        )
        .unwrap();
        assert_eq!(frozen.digest(), single.digest());
        assert_ne!(frozen.digest(), &InventoryDigest::from_raw([0u8; 32]));
    }

    #[test]
    fn freeze_fails_closed_on_every_contract_violation() {
        let fault = FrozenVersionListing::from_pages(
            &scope(),
            vec![ok_page(
                vec![entry("a", 1, "v1", false), entry("a", 1, "v2", false)],
                None,
            )],
        );
        assert_eq!(
            fault_kind(&fault),
            StorageErrorKind::InventoryFault,
            "zero latest"
        );

        let two_latest = FrozenVersionListing::from_pages(
            &scope(),
            vec![ok_page(
                vec![entry("a", 1, "v1", true), entry("a", 1, "v2", true)],
                None,
            )],
        );
        assert_eq!(
            fault_kind(&two_latest),
            StorageErrorKind::InventoryFault,
            "two latest"
        );

        let repeated_version = FrozenVersionListing::from_pages(
            &scope(),
            vec![ok_page(
                vec![entry("a", 1, "v1", true), entry("a", 1, "v1", false)],
                None,
            )],
        );
        assert_eq!(
            fault_kind(&repeated_version),
            StorageErrorKind::InventoryFault,
            "a repeated version identity is the duplicate-key analog"
        );

        let out_of_prefix = FrozenVersionListing::from_pages(
            &scope(),
            vec![ok_page(
                vec![VersionedEntry::new(
                    InventoryKey::parse("tenants/ffffffff-0000-4000-8000-000000000000/v1/raw/a")
                        .unwrap(),
                    1,
                    version_id("v1"),
                    true,
                    Observation::new(None, None, observed_at()),
                )],
                None,
            )],
        );
        assert_eq!(fault_kind(&out_of_prefix), StorageErrorKind::InventoryFault);

        let repeated_token = FrozenVersionListing::from_pages(
            &scope(),
            vec![
                ok_page(vec![entry("a", 1, "v1", true)], token("loop")),
                ok_page(vec![entry("a", 1, "v2", false)], token("loop")),
            ],
        );
        assert_eq!(
            fault_kind(&repeated_token),
            StorageErrorKind::InventoryFault
        );

        let never_exhausts = FrozenVersionListing::from_pages(
            &scope(),
            vec![ok_page(vec![entry("a", 1, "v1", true)], token("next"))],
        );
        assert_eq!(
            fault_kind(&never_exhausts),
            StorageErrorKind::InventoryFault
        );

        let page_after_exhaustion = FrozenVersionListing::from_pages(
            &scope(),
            vec![
                ok_page(vec![entry("a", 1, "v1", true)], None),
                ok_page(vec![entry("a", 1, "v2", false)], None),
            ],
        );
        assert_eq!(
            fault_kind(&page_after_exhaustion),
            StorageErrorKind::InventoryFault
        );

        let page_error = FrozenVersionListing::from_pages(
            &scope(),
            vec![
                ok_page(vec![entry("a", 1, "v1", true)], token("p1")),
                Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
            ],
        );
        assert_eq!(fault_kind(&page_error), StorageErrorKind::InventoryFault);
    }

    #[test]
    fn empty_scope_freezes_empty_and_the_report_states_zero_without_a_fullest_key() {
        let frozen =
            FrozenVersionListing::from_pages(&scope(), vec![ok_page(vec![], None)]).unwrap();
        assert!(frozen.is_empty());
        let report = NoncurrentVersionReport::from_listing(&frozen);
        assert_eq!(report.distinct_keys(), 0);
        assert_eq!(report.noncurrent_versions(), 0);
        assert_eq!(report.noncurrent_bytes(), 0);
        assert_eq!(report.fullest_key(), None);
        assert_eq!(
            report.render(),
            format!(
                "noncurrent-version-audit scope=tenants/{TENANT}/v1/raw/ keys=0 versions=0 noncurrent=0 retained_bytes=0 guidance={NONCURRENT_VERSION_GUIDANCE}"
            )
        );
    }

    #[test]
    fn report_measures_counts_retained_bytes_and_the_fullest_key() {
        let frozen = FrozenVersionListing::from_pages(
            &scope(),
            vec![ok_page(
                vec![
                    entry("blob/aa", 100, "v1", true),
                    entry("manifest/occ/b", 10, "v1", false),
                    entry("manifest/occ/b", 11, "v2", false),
                    entry("manifest/occ/b", 12, "v3", true),
                    entry("manifest/occ/c", 5, "v1", false),
                    entry("manifest/occ/c", 6, "v2", true),
                ],
                None,
            )],
        )
        .unwrap();
        let report = NoncurrentVersionReport::from_listing(&frozen);
        assert_eq!(report.distinct_keys(), 3);
        assert_eq!(report.total_versions(), 6);
        assert_eq!(report.noncurrent_versions(), 3);
        assert_eq!(report.noncurrent_bytes(), 10 + 11 + 5);
        assert_eq!(report.total_bytes(), 100 + 10 + 11 + 12 + 5 + 6);
        assert_eq!(
            report.fullest_key(),
            Some("tenants/0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b/v1/raw/manifest/occ/b")
        );
        assert_eq!(report.fullest_noncurrent(), 2);
        let rendered = report.render();
        assert!(rendered.contains("keys=3 versions=6 noncurrent=3 retained_bytes=26"));
        assert!(rendered.contains(&format!("guidance={NONCURRENT_VERSION_GUIDANCE}")));
        assert!(rendered.contains("fullest_noncurrent=2"));
        // The group accessors agree with the aggregates.
        let deepest = frozen
            .keys()
            .iter()
            .find(|group| group.key().as_str().ends_with("/manifest/occ/b"))
            .unwrap();
        assert_eq!(deepest.noncurrent().count(), 2);
        assert_eq!(deepest.noncurrent_bytes(), 21);
        assert_eq!(deepest.latest().map(VersionedEntry::size), Some(12));
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn freeze_loop_pages_to_exhaustion_through_the_trait() {
        let source = PageSource {
            scope: scope(),
            pages: vec![
                ok_page(vec![entry("a", 10, "v1", false)], token("p1")),
                ok_page(
                    vec![entry("a", 10, "v2", true), entry("b", 3, "v1", true)],
                    token("p2"),
                ),
                ok_page(vec![], None),
            ],
        };
        let frozen = block_on(freeze_version_listing(&source, &scope())).unwrap();
        assert_eq!(frozen.len(), 2);
        assert_eq!(frozen.total_versions(), 3);
        assert_eq!(
            NoncurrentVersionReport::from_listing(&frozen).noncurrent_versions(),
            1
        );
    }

    #[test]
    fn freeze_loop_refuses_a_scope_outside_the_identity() {
        let source = PageSource {
            scope: scope(),
            pages: vec![ok_page(vec![], None)],
        };
        let foreign =
            InventoryScope::TenantRaw("ffffffff-0000-4000-8000-000000000000".parse().unwrap());
        let error = block_on(freeze_version_listing(&source, &foreign)).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
    }

    #[test]
    fn key_versions_group_is_never_empty_and_latest_is_findable() {
        let frozen = FrozenVersionListing::from_pages(
            &scope(),
            vec![ok_page(vec![entry("a", 7, "v9", true)], None)],
        )
        .unwrap();
        let group: &KeyVersions = &frozen.keys()[0];
        assert!(!group.is_empty());
        assert_eq!(group.latest().unwrap().version().as_str(), "v9");
        assert_eq!(group.noncurrent().count(), 0);
        assert_eq!(group.noncurrent_bytes(), 0);
    }
}
