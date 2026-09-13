// SPDX-License-Identifier: Apache-2.0

//! The offline audit/restore identity: paginated enumeration, the frozen
//! `inventory-v1` contract, and bounded object reads (plan Section 7.7,
//! Section 7.10).
//!
//! S3 is the durable source of truth, so deterministic catalog rebuild and
//! safe collection need an explicit exhaustive enumeration contract rather
//! than an implied database index. The contract is **fail closed**:
//! consumers never assume a portable S3 list is a transactionally consistent
//! snapshot, so a page error, a repeated continuation token, a duplicate
//! key, an out-of-prefix key, or a mutation detected while freezing fails
//! the whole operation with [`StorageErrorKind::InventoryFault`]
//! and the consumer re-freezes. The shared validator
//! ([`FrozenInventory::from_pages`]) enforces this for every backend, so an
//! implementation cannot pass the contract partially.
//!
//! This identity is deliberately not available to ingestion: making
//! `ListObjectsV2` available to ingestion is a rejected design (plan Section
//! 7.7), and the ingest composition ([`crate::ingest::IngestStorage`]) has
//! no path to this trait.

use std::fmt;
use std::str::FromStr;

use archivist_protocol::derivation::FrameBuilder;
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{GrammarError, TenantId};

use crate::error::{StorageError, StorageErrorKind};
use crate::metadata::{ObjectTag, Observation, StorageVersionId};

/// Why a candidate enumeration value is not valid.
pub type EnumerationError = GrammarError;

/// The most pages one freeze may consume before it is declared a fault.
///
/// A bound, not a semantic cap: a freeze that has not reached exhaustion
/// after this many pages is either a token loop the repeated-token detector
/// missed (an ever-changing token) or a deployment far beyond any planned
/// archive size, and either way continuing would make the freeze unbounded
/// in memory and time. The bound only has to exceed every real freeze; at
/// the portable page sizes this admits far more keys than any tenant raw
/// prefix can hold.
pub const MAX_FREEZE_PAGES: usize = 1_048_576;

/// A scope an audit/restore identity may enumerate.
///
/// Scopes are closed rather than arbitrary prefixes so an implementation's
/// provisioning can be checked against a value the contract understands:
/// catalog rebuild and reference scans consume the raw prefix, and the
/// `inventory-copy-v1` backup profile freezes raw and control objects
/// (plan Section 7.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InventoryScope {
    /// `tenants/<tenant>/v1/raw/` — blobs, occurrences, attestations.
    TenantRaw(TenantId),
    /// `tenants/<tenant>/v1/control/` — the signed control records.
    TenantControl(TenantId),
}

impl InventoryScope {
    /// The prefix every key in this scope must start with, with the
    /// trailing slash the membership check keys off.
    #[must_use]
    pub fn prefix(&self) -> String {
        match self {
            Self::TenantRaw(tenant) => format!("tenants/{tenant}/v1/raw/"),
            Self::TenantControl(tenant) => format!("tenants/{tenant}/v1/control/"),
        }
    }
}

/// An opaque object key as an enumeration observed it.
///
/// The inventory treats keys as **opaque key bytes** (plan Section 7.7):
/// listings record and sort them, but never interpret them — the typed raw
/// and control key grammars live where keys are *derived*
/// ([`archivist_protocol::object_key`], [`crate::control`]). The grammar
/// here is deliberately conservative — printable, non-space ASCII, no empty
/// or `.`/`..` segments, no doubled or edge slashes — because a key that
/// cannot satisfy it is either not a key this contract derived or a listing
/// artifact, and both fail the freeze.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InventoryKey(String);

impl InventoryKey {
    /// Adopt `text` after verifying its grammar.
    ///
    /// # Errors
    /// [`EnumerationError::NotCanonical`] for an empty or oversized key,
    /// non-printable or space bytes, an empty/`.`/`..` segment, or a doubled,
    /// leading, or trailing slash.
    pub fn parse(text: &str) -> Result<Self, EnumerationError> {
        if text.is_empty() || text.len() > 1024 {
            return Err(EnumerationError::NotCanonical);
        }
        if !text.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(EnumerationError::NotCanonical);
        }
        if text.starts_with('/') || text.ends_with('/') || text.contains("//") {
            return Err(EnumerationError::NotCanonical);
        }
        if text
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        {
            return Err(EnumerationError::NotCanonical);
        }
        Ok(Self(text.to_owned()))
    }

    /// The key bytes exactly as observed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InventoryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for InventoryKey {
    type Err = EnumerationError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// An opaque continuation token minted by an implementation's paginator:
/// 1–1024 printable, non-space ASCII characters, carried without
/// interpretation. Equality is byte equality — the repeated-token detector
/// compares exactly this.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContinuationToken(String);

impl ContinuationToken {
    /// Adopt `text` after verifying its grammar.
    ///
    /// # Errors
    /// [`EnumerationError::NotCanonical`] for anything but 1–1024 printable,
    /// non-space ASCII characters.
    pub fn parse(text: &str) -> Result<Self, EnumerationError> {
        if text.is_empty() || text.len() > 1024 || !text.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(EnumerationError::NotCanonical);
        }
        Ok(Self(text.to_owned()))
    }

    /// The token exactly as the paginator issued it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContinuationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ContinuationToken {
    type Err = EnumerationError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// One object as one enumeration page observed it: its key, stored size,
/// and the observation evidence ([`Observation`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryEntry {
    key: InventoryKey,
    size: u64,
    observation: Observation,
}

impl InventoryEntry {
    /// Record one enumerated object.
    #[must_use]
    pub const fn new(key: InventoryKey, size: u64, observation: Observation) -> Self {
        Self {
            key,
            size,
            observation,
        }
    }

    /// The observed key bytes.
    #[must_use]
    pub fn key(&self) -> &InventoryKey {
        &self.key
    }

    /// The stored size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The observation evidence (tag, version, observation time).
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }
}

/// One page of an exhaustive enumeration.
///
/// `next` is `Some` while the enumeration has more to fetch; a page with
/// `next: None` ends the sequence. The canonical sequence ends exactly once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryPage {
    entries: Vec<InventoryEntry>,
    next: Option<ContinuationToken>,
}

impl InventoryPage {
    /// Assemble one page from its entries and continuation, if any.
    #[must_use]
    pub const fn new(entries: Vec<InventoryEntry>, next: Option<ContinuationToken>) -> Self {
        Self { entries, next }
    }

    /// The page's entries, in the order the backend returned them.
    #[must_use]
    pub fn entries(&self) -> &[InventoryEntry] {
        &self.entries
    }

    /// The continuation to follow, if the enumeration continues.
    #[must_use]
    pub const fn next(&self) -> Option<&ContinuationToken> {
        self.next.as_ref()
    }
}

/// The SHA-256 digest over one frozen inventory.
///
/// Computed by [`FrozenInventory::from_pages`] over the canonical framing
/// documented there; two freezes of the same objects under the same scope
/// produce the same digest, which is what makes rebuild reproducibility and
/// backup evidence checkable (plan Section 7.7, Section 7.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InventoryDigest([u8; 32]);

impl InventoryDigest {
    /// Adopt 32 raw digest bytes.
    #[must_use]
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 raw digest bytes.
    #[must_use]
    pub const fn as_raw(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        sha256::encode_hex(&self.0)
    }
}

impl fmt::Display for InventoryDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// An immutable, exhaustive, self-verifying enumeration of one scope: the
/// `inventory-v1` freeze.
///
/// Construct only through [`FrozenInventory::from_pages`] — the type
/// guarantees canonical key-byte order, scope membership, absence of
/// duplicates, and the pinned digest, so every consumer (catalog rebuild,
/// backup, reference scan) can rely on those without re-checking. The
/// digest is computed at construction and carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenInventory {
    scope: InventoryScope,
    entries: Vec<InventoryEntry>,
    digest: InventoryDigest,
}

impl FrozenInventory {
    /// Validate a complete page sequence and freeze it.
    ///
    /// The one implementation of the freeze contract (plan Section 7.7):
    ///
    /// - the sequence reaches exhaustion — the last page continues nothing,
    ///   and no page follows one that continued nothing;
    /// - no continuation token repeats within the sequence (a repeated
    ///   token is a loop, and a loop is a fault even if the pages happen to
    ///   agree);
    /// - no key repeats (a duplicate is a mutation or a broken paginator,
    ///   and either way the inventory is not a clean snapshot);
    /// - every key is inside the scope's prefix (a list that leaks across a
    ///   prefix boundary is not this scope's inventory);
    /// - the page count is within [`MAX_FREEZE_PAGES`].
    ///
    /// Entries are then sorted by opaque key bytes and hashed (framing
    /// documented on [`FrozenInventory::digest`]). Any violation, and any
    /// page error the caller surfaces in `pages`' place, fails the whole
    /// freeze closed.
    ///
    /// # Errors
    /// [`StorageError::InventoryFault`](crate::error::StorageError) for
    /// every contract violation above — never a partial inventory.
    pub fn from_pages(
        scope: &InventoryScope,
        pages: Vec<Result<InventoryPage, StorageError>>,
    ) -> Result<Self, StorageError> {
        if pages.len() > MAX_FREEZE_PAGES {
            return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
        }
        let prefix = scope.prefix();
        let mut seen_tokens: Vec<ContinuationToken> = Vec::new();
        let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut entries: Vec<InventoryEntry> = Vec::new();
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
                if !seen_keys.insert(entry.key().as_str().to_owned()) {
                    return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
                }
                entries.push(entry);
            }
        }
        if !exhausted {
            return Err(StorageError::of_kind(StorageErrorKind::InventoryFault));
        }
        // Canonical order is opaque key-byte order (plan Section 7.7).
        entries
            .sort_unstable_by(|a, b| a.key().as_str().as_bytes().cmp(b.key().as_str().as_bytes()));
        let digest = Self::compute_digest(scope, &entries);
        Ok(Self {
            scope: scope.clone(),
            entries,
            digest,
        })
    }

    /// The digest framing (`inventory-v1`): the domain-separated,
    /// length-prefixed construction the protocol's identity derivations use.
    ///
    /// `label "inventory-v1" || 0x00`, then the scope prefix as a `text`
    /// field, the entry count as a `u63` field, then, per entry in
    /// canonical order: the key (`text`), the size (`u63`), the tag
    /// (`text`, empty when absent — a real tag is never empty), the storage
    /// version (`text`, empty when absent), and the observation time
    /// (`text`, the wire timestamp). Sorting before hashing is what makes
    /// the digest independent of page boundaries and listing order.
    #[must_use]
    pub fn compute_digest(scope: &InventoryScope, entries: &[InventoryEntry]) -> InventoryDigest {
        let mut frame = FrameBuilder::new("inventory-v1");
        frame.push_text(&scope.prefix());
        frame.push_u63(entries.len() as u64);
        for entry in entries {
            frame.push_text(entry.key().as_str());
            frame.push_u63(entry.size());
            let observation = entry.observation();
            frame.push_text(observation.etag().map_or("", ObjectTag::as_str));
            frame.push_text(
                observation
                    .storage_version()
                    .map_or("", StorageVersionId::as_str),
            );
            frame.push_text(observation.observed_at().as_str());
        }
        InventoryDigest::from_raw(frame.finish())
    }

    /// The scope the inventory froze.
    #[must_use]
    pub const fn scope(&self) -> &InventoryScope {
        &self.scope
    }

    /// The entries, in canonical key-byte order.
    #[must_use]
    pub fn entries(&self) -> &[InventoryEntry] {
        &self.entries
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the inventory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The pinned inventory digest.
    #[must_use]
    pub const fn digest(&self) -> &InventoryDigest {
        &self.digest
    }
}

/// The metadata a HEAD-style inspection establishes about one object:
/// stored size and the observation evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectMetadata {
    size: u64,
    observation: Observation,
}

impl ObjectMetadata {
    /// Pair a stored size with how it was observed.
    #[must_use]
    pub const fn new(size: u64, observation: Observation) -> Self {
        Self { size, observation }
    }

    /// The stored size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The observation evidence.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }
}

/// A bounded object body read for restore or verification: the exact stored
/// bytes and how they were observed.
///
/// The owned-byte shape serves the artifacts offline restore actually reads
/// whole today — control records, occurrence and attestation manifests, and
/// verify samples — under the deployment's own size bounds. A streaming
/// restore of multi-gigabyte blobs arrives with the restore implementation
/// and will extend, not replace, this contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectBody {
    bytes: Vec<u8>,
    observation: Observation,
}

impl ObjectBody {
    /// Pair the stored bytes with how they were observed.
    #[must_use]
    pub const fn new(bytes: Vec<u8>, observation: Observation) -> Self {
        Self { bytes, observation }
    }

    /// The exact stored bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The observation evidence.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }
}

/// The offline audit/restore authority: exhaustive enumeration, frozen
/// inventories, and bounded reads.
///
/// This is the third storage identity of plan Section 5 — offline verify and
/// restore use its reads, offline catalog and governance use its
/// enumeration — and it is deliberately unreachable from an ingestion
/// replica's storage configuration. It has no write or delete method:
/// collection deletes through a separately administered workflow after
/// two-pass revalidation (plan Section 7.10), never through the identity
/// that audits.
pub trait AuditRestoreStore {
    /// Fetch one page of the scope's enumeration.
    ///
    /// A purely advisory page: the contract holds only across a whole
    /// sequence assembled by [`AuditRestoreStore::freeze_inventory`], so a
    /// lone page proves nothing and is not a snapshot.
    ///
    /// # Errors
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down,
    /// [`StorageError::ScopeViolation`](crate::error::StorageError) when the
    /// scope is outside this identity's provisioning.
    fn list_page(
        &self,
        scope: &InventoryScope,
        after: Option<&ContinuationToken>,
    ) -> impl Future<Output = Result<InventoryPage, StorageError>> + Send;

    /// Freeze the scope: enumerate to exhaustion and assemble the immutable
    /// [`FrozenInventory`].
    ///
    /// Implementations follow continuation tokens to exhaustion and validate
    /// the sequence through [`FrozenInventory::from_pages`] — the shared
    /// contract validator — so duplicate keys, out-of-prefix keys, repeated
    /// tokens, page errors, and non-exhaustion all fail the freeze closed.
    /// Consumers re-freeze after any fault; a frozen inventory is never
    /// assumed to be a transactionally consistent snapshot of the moment a
    /// rebuild started, which is exactly why it is evidence.
    ///
    /// # Errors
    /// [`StorageError::InventoryFault`](crate::error::StorageError) for any
    /// freeze-contract violation,
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down,
    /// [`StorageError::ScopeViolation`](crate::error::StorageError) when the
    /// scope is outside this identity's provisioning.
    fn freeze_inventory(
        &self,
        scope: &InventoryScope,
    ) -> impl Future<Output = Result<FrozenInventory, StorageError>> + Send;

    /// Inspect one object without reading its body (the offline `HEAD`):
    /// stored size and observation evidence.
    ///
    /// Garbage collection's pre-delete revalidation is one consumer: "any
    /// changed or unreadable candidate survives the pass" (plan Section
    /// 7.10) — an error here is information, not a reason to retry.
    ///
    /// # Errors
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down or the object is unreadable,
    /// [`StorageError::ScopeViolation`](crate::error::StorageError) when the
    /// key is outside this identity's provisioning.
    fn inspect_object(
        &self,
        key: &InventoryKey,
    ) -> impl Future<Output = Result<ObjectMetadata, StorageError>> + Send;

    /// Read one object's exact stored bytes (the offline `GET`).
    ///
    /// # Errors
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down or the object is unreadable,
    /// [`StorageError::ScopeViolation`](crate::error::StorageError) when the
    /// key is outside this identity's provisioning.
    fn read_object(
        &self,
        key: &InventoryKey,
    ) -> impl Future<Output = Result<ObjectBody, StorageError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::{
        ContinuationToken, FrozenInventory, InventoryDigest, InventoryEntry, InventoryKey,
        InventoryPage, InventoryScope, MAX_FREEZE_PAGES,
    };
    use crate::error::{StorageError, StorageErrorKind};
    use crate::metadata::{ObjectTag, StorageVersionId};

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const OBSERVED: &str = "2026-09-13T12:00:00Z";

    fn scope() -> InventoryScope {
        InventoryScope::TenantRaw(TENANT.parse().unwrap())
    }

    fn observed_at() -> archivist_protocol::vocabulary::Timestamp {
        archivist_protocol::vocabulary::Timestamp::parse(OBSERVED).unwrap()
    }

    fn entry(key: &str, size: u64) -> InventoryEntry {
        InventoryEntry::new(
            InventoryKey::parse(key).unwrap(),
            size,
            crate::metadata::Observation::new(None, None, observed_at()),
        )
    }

    fn tagged_entry(key: &str, size: u64, tag: &str, version: &str) -> InventoryEntry {
        InventoryEntry::new(
            InventoryKey::parse(key).unwrap(),
            size,
            crate::metadata::Observation::new(
                ObjectTag::parse(tag).ok(),
                StorageVersionId::parse(version).ok(),
                observed_at(),
            ),
        )
    }

    fn key_in_scope(suffix: &str) -> String {
        format!("tenants/{TENANT}/v1/raw/{suffix}")
    }

    #[test]
    fn scope_prefixes() {
        assert_eq!(scope().prefix(), format!("tenants/{TENANT}/v1/raw/"));
        let control = InventoryScope::TenantControl(TENANT.parse().unwrap());
        assert_eq!(control.prefix(), format!("tenants/{TENANT}/v1/control/"));
    }

    #[test]
    fn inventory_key_grammar() {
        assert!(InventoryKey::parse(&key_in_scope("blobs/zstd-v1/sha256/01/x.zst")).is_ok());
        assert!(InventoryKey::parse("").is_err());
        assert!(InventoryKey::parse("/leading").is_err());
        assert!(InventoryKey::parse("trailing/").is_err());
        assert!(InventoryKey::parse("doubled//slash").is_err());
        assert!(InventoryKey::parse("./dot").is_err());
        assert!(InventoryKey::parse("a/../b").is_err());
        assert!(InventoryKey::parse("has space").is_err());
        assert!(InventoryKey::parse(&"k".repeat(1025)).is_err());
        assert!(InventoryKey::parse(&"k".repeat(1024)).is_ok());
    }

    #[test]
    fn continuation_token_grammar() {
        assert!(ContinuationToken::parse("eyJlbGVtZW50cyI6").is_ok());
        assert!(ContinuationToken::parse("").is_err());
        assert!(ContinuationToken::parse("with space").is_err());
        assert!(ContinuationToken::parse(&"t".repeat(1025)).is_err());
    }

    #[test]
    fn freeze_sorts_dedups_and_hashes() {
        let a = entry(&key_in_scope("a/first"), 10);
        let b = tagged_entry(&key_in_scope("b/second"), 20, "\"tag-b\"", "ver-1");
        let inventory = FrozenInventory::from_pages(
            &scope(),
            vec![Ok(InventoryPage::new(vec![b.clone(), a.clone()], None))],
        )
        .unwrap();
        // Canonical key-byte order, regardless of listing order.
        assert_eq!(inventory.entries()[0].key().as_str(), a.key().as_str());
        assert_eq!(inventory.entries()[1].key().as_str(), b.key().as_str());
        assert_eq!(inventory.len(), 2);
        assert!(!inventory.is_empty());
        assert_eq!(inventory.scope(), &scope());
        assert_eq!(
            inventory.entries()[1]
                .observation()
                .etag()
                .unwrap()
                .as_str(),
            "\"tag-b\""
        );
        assert_eq!(
            inventory.entries()[1]
                .observation()
                .storage_version()
                .unwrap()
                .as_str(),
            "ver-1"
        );
    }

    #[test]
    fn digest_is_independent_of_page_boundaries_and_order() {
        let a = entry(&key_in_scope("a/first"), 10);
        let b = entry(&key_in_scope("b/second"), 20);
        let one_page = FrozenInventory::from_pages(
            &scope(),
            vec![Ok(InventoryPage::new(vec![a.clone(), b.clone()], None))],
        )
        .unwrap();
        let two_pages = FrozenInventory::from_pages(
            &scope(),
            vec![
                Ok(InventoryPage::new(
                    vec![b.clone()],
                    Some(ContinuationToken::parse("next-1").unwrap()),
                )),
                Ok(InventoryPage::new(vec![a.clone()], None)),
            ],
        )
        .unwrap();
        let reordered =
            FrozenInventory::from_pages(&scope(), vec![Ok(InventoryPage::new(vec![b, a], None))])
                .unwrap();
        assert_eq!(one_page.digest(), two_pages.digest());
        assert_eq!(one_page.digest(), reordered.digest());
    }

    /// Independent digest implementation over the documented framing, so
    /// the golden vector does not trust the code under test's own builder.
    fn reference_digest(scope_prefix: &str, entries: &[(&str, u64, &str, &str, &str)]) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"inventory-v1\0");
        let push_text = |bytes: &mut Vec<u8>, text: &str| {
            bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
            bytes.extend_from_slice(text.as_bytes());
        };
        push_text(&mut bytes, scope_prefix);
        bytes.extend_from_slice(&8u64.to_be_bytes());
        bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
        for (key, size, tag, version, observed) in entries {
            push_text(&mut bytes, key);
            bytes.extend_from_slice(&8u64.to_be_bytes());
            bytes.extend_from_slice(&size.to_be_bytes());
            push_text(&mut bytes, tag);
            push_text(&mut bytes, version);
            push_text(&mut bytes, observed);
        }
        hex::encode(&archivist_protocol::sha256::digest(&bytes))
    }

    /// Minimal lowercase-hex encoder, independent of the protocol's codec.
    mod hex {
        pub fn encode(bytes: &[u8]) -> String {
            use std::fmt::Write as _;
            let mut text = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                let _ = write!(text, "{byte:02x}");
            }
            text
        }
    }

    #[test]
    fn digest_matches_independent_reference_framing() {
        let prefix = scope().prefix();
        let inventory = FrozenInventory::from_pages(
            &scope(),
            vec![Ok(InventoryPage::new(
                vec![
                    tagged_entry(&key_in_scope("a/first"), 10, "\"t\"", "v1"),
                    entry(&key_in_scope("b/second"), 20),
                ],
                None,
            ))],
        )
        .unwrap();
        let expected = reference_digest(
            &prefix,
            &[
                (&key_in_scope("a/first"), 10, "\"t\"", "v1", OBSERVED),
                (&key_in_scope("b/second"), 20, "", "", OBSERVED),
            ],
        );
        assert_eq!(inventory.digest().to_hex(), expected);
        // And the empty inventory has its own stable digest.
        let empty =
            FrozenInventory::from_pages(&scope(), vec![Ok(InventoryPage::new(vec![], None))])
                .unwrap();
        let empty_expected = reference_digest(&prefix, &[]);
        assert_eq!(empty.digest().to_hex(), empty_expected);
        assert_ne!(empty.digest(), inventory.digest());
        let _ = InventoryDigest::from_raw([0u8; 32]).to_hex();
    }

    #[test]
    fn freeze_rejects_duplicate_keys() {
        let key = key_in_scope("a/first");
        let pages = vec![Ok(InventoryPage::new(
            vec![entry(&key, 10), entry(&key, 10)],
            None,
        ))];
        let error = FrozenInventory::from_pages(&scope(), pages).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::InventoryFault);
    }

    #[test]
    fn freeze_rejects_out_of_prefix_keys() {
        let pages = vec![Ok(InventoryPage::new(
            vec![entry("tenants/other-tenant/v1/raw/blob", 10)],
            None,
        ))];
        let error = FrozenInventory::from_pages(&scope(), pages).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::InventoryFault);
    }

    #[test]
    fn freeze_rejects_repeated_tokens() {
        let token = || Some(ContinuationToken::parse("loop-token").unwrap());
        let pages = vec![
            Ok(InventoryPage::new(
                vec![entry(&key_in_scope("a"), 1)],
                token(),
            )),
            Ok(InventoryPage::new(
                vec![entry(&key_in_scope("b"), 2)],
                token(),
            )),
        ];
        let error = FrozenInventory::from_pages(&scope(), pages).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::InventoryFault);
    }

    #[test]
    fn freeze_rejects_page_error() {
        let pages = vec![
            Ok(InventoryPage::new(
                vec![entry(&key_in_scope("a"), 1)],
                Some(ContinuationToken::parse("next").unwrap()),
            )),
            Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
        ];
        let error = FrozenInventory::from_pages(&scope(), pages).unwrap_err();
        // The page error is subsumed: the freeze fails as a freeze.
        assert_eq!(error.kind(), StorageErrorKind::InventoryFault);
    }

    #[test]
    fn freeze_rejects_non_exhaustion_and_post_exhaustion_pages() {
        let unterminated = vec![Ok(InventoryPage::new(
            vec![entry(&key_in_scope("a"), 1)],
            Some(ContinuationToken::parse("next").unwrap()),
        ))];
        assert_eq!(
            FrozenInventory::from_pages(&scope(), unterminated)
                .unwrap_err()
                .kind(),
            StorageErrorKind::InventoryFault
        );
        let trailing = vec![
            Ok(InventoryPage::new(vec![entry(&key_in_scope("a"), 1)], None)),
            Ok(InventoryPage::new(vec![], None)),
        ];
        assert_eq!(
            FrozenInventory::from_pages(&scope(), trailing)
                .unwrap_err()
                .kind(),
            StorageErrorKind::InventoryFault
        );
    }

    #[test]
    fn freeze_rejects_page_bound_exceeded() {
        let pages: Vec<_> = (0..=MAX_FREEZE_PAGES)
            .map(|_| Ok(InventoryPage::new(vec![], None)))
            .collect();
        assert_eq!(
            FrozenInventory::from_pages(&scope(), pages)
                .unwrap_err()
                .kind(),
            StorageErrorKind::InventoryFault
        );
    }

    #[test]
    fn empty_scope_freezes_to_empty_inventory() {
        let inventory =
            FrozenInventory::from_pages(&scope(), vec![Ok(InventoryPage::new(vec![], None))])
                .unwrap();
        assert!(inventory.is_empty());
        assert_eq!(inventory.entries().len(), 0);
    }
}
