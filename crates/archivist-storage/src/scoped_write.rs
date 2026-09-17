// SPDX-License-Identifier: Apache-2.0

//! The scoped writer authorities: append and enumerate one derived
//! namespace each — catalog checkpoints and derived projections — and
//! nothing else.
//!
//! The two Phase 10 write identities repeat the control-administrator's
//! shape one namespace over: `put` and `list` below one prefix, no read,
//! no delete, no abort (the ARMOR provisioning grants exactly
//! `put+list` per writer, so a writer can append checkpoints or
//! projections and list what is there, but never reads object bodies
//! back through the write identity and holds no destroy capability).
//! Like [`crate::raw_write`], each trait here is deliberately missing
//! every method its credential cannot exercise: the action boundary is
//! the trait's own shape, not a runtime check a caller could bypass.
//!
//! # One namespace per writer, and never the ingest namespaces
//!
//! [`CatalogWriteStore`] writes only below
//! `tenants/<tenant>/v1/catalog/`, and [`DerivedWriteStore`] only below
//! `tenants/<tenant>/v1/derived/` (plan Section 7.5). Raw blobs,
//! occurrences, attestations, and control records — and every other
//! tenant's prefix — are outside both authorities; the key types carry
//! their namespace in their grammar, so a key from the wrong namespace
//! does not parse and a store cannot be handed one. Every method derives
//! or validates its key against that grammar before any request exists:
//! client-chosen paths are a design anti-pattern (plan Section 7.11),
//! and an implementation whose provisioning does not cover the key's
//! tenant or namespace fails the call with
//! [`StorageErrorKind::ScopeViolation`](crate::error::StorageErrorKind::ScopeViolation).

use std::future::Future;

use archivist_protocol::vocabulary::{BlobDigest, GrammarError, TenantId};

use crate::error::StorageError;

/// The prefix every catalog checkpoint key lives below, for one tenant.
fn catalog_prefix(tenant: &TenantId) -> String {
    format!("tenants/{tenant}/v1/catalog/checkpoints/")
}

/// The prefix every derived-projection key lives below, for one tenant.
fn derived_prefix(tenant: &TenantId) -> String {
    format!("tenants/{tenant}/v1/derived/")
}

/// Why a candidate scoped-writer key or list prefix is not valid.
///
/// A thin alias over the protocol grammar error: these types are newtypes
/// over the same fail-closed grammar discipline as the wire vocabulary.
pub type ScopedWriterError = GrammarError;

/// A validated catalog-checkpoint object key:
/// `tenants/<tenant>/v1/catalog/checkpoints/<checkpoint>.json`
/// (plan Section 7.5).
///
/// The checkpoint identifier is the checkpoint document's own SHA-256
/// digest — the rebuild is deterministic, so the key is a pure function
/// of the bytes beneath it, and two rebuilds of one raw prefix converge
/// on one checkpoint object. Parse accepts exactly the canonical form;
/// anything else — another namespace, another tenant's prefix, traversal,
/// a non-canonical digest — is refused rather than normalized.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CatalogCheckpointKey {
    text: String,
    tenant: TenantId,
    checkpoint: BlobDigest,
}

impl CatalogCheckpointKey {
    /// The canonical key prefix shared by every checkpoint of `tenant`.
    #[must_use]
    pub fn prefix(tenant: &TenantId) -> String {
        catalog_prefix(tenant)
    }

    /// Assemble the checkpoint key for `tenant` and `checkpoint`.
    #[must_use]
    pub fn new(tenant: &TenantId, checkpoint: &BlobDigest) -> Self {
        Self {
            text: format!("{}{checkpoint}.json", catalog_prefix(tenant)),
            tenant: tenant.clone(),
            checkpoint: *checkpoint,
        }
    }

    /// The assembled key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The canonical tenant segment of the key.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The checkpoint digest the key addresses.
    #[must_use]
    pub const fn checkpoint(&self) -> &BlobDigest {
        &self.checkpoint
    }

    /// Parse and cross-check: tenant grammar, the catalog-checkpoint
    /// layout, and a digest grammar whose shard-free position agrees.
    ///
    /// # Errors
    /// [`ScopedWriterError::NotCanonical`] for anything outside the one
    /// canonical form.
    pub fn parse(text: &str) -> Result<Self, ScopedWriterError> {
        let bad = || GrammarError::NotCanonical;
        let rest = text.strip_prefix("tenants/").ok_or_else(bad)?;
        let Some((tenant, rest)) = rest.split_once('/') else {
            return Err(bad());
        };
        let tenant = TenantId::parse(tenant)?;
        // `rest` began life after `tenants/<tenant>/`, so the namespace
        // member is stripped from there — never from the assembled
        // prefix, which `rest` no longer starts with.
        let member = rest
            .strip_prefix("v1/catalog/checkpoints/")
            .ok_or_else(bad)?;
        let digest = BlobDigest::parse(member.strip_suffix(".json").ok_or_else(bad)?)?;
        debug_assert_eq!(
            format!("{}{digest}.json", catalog_prefix(&tenant)),
            text,
            "parse accepts exactly its own canonical form"
        );
        Ok(Self {
            text: text.to_owned(),
            tenant,
            checkpoint: digest,
        })
    }
}

impl std::fmt::Display for CatalogCheckpointKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::str::FromStr for CatalogCheckpointKey {
    type Err = ScopedWriterError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// A validated derived-projection object key:
/// `tenants/<tenant>/v1/<pipeline>/<version>/<partition/object>`
/// (plan Section 7.5), e.g. the usage-summary producer's
/// `tenants/<tenant>/v1/derived/usage/1/usage-summaries/<shard>/<digest>
/// .json`.
///
/// The pipeline names the projection family (`usage`, a redacted-episode
/// pipeline, an inventory), the version its immutable pipeline version,
/// and the remainder the projection's own partitioned layout — bounded,
/// lowercase, opaque segments; raw upstream identifiers never become key
/// components. Parse accepts exactly the canonical grammar; another
/// namespace, another tenant's prefix, traversal, or an empty segment is
/// refused rather than normalized.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DerivedObjectKey {
    text: String,
    tenant: TenantId,
}

/// The longest pipeline segment (a short registry token).
const PIPELINE_MAX: usize = 64;
/// The longest version segment (a version token, e.g. `1`).
const VERSION_MAX: usize = 32;
/// The most partition/object segments below `<pipeline>/<version>/`.
const TAIL_SEGMENTS_MAX: usize = 16;
/// The longest one tail segment. The pinned usage-summary layout's
/// object member is `<64-hex digest>.json` — 69 characters — so the
/// bound sits above that with room for a double extension, and still
/// far below the whole-key bound.
const TAIL_SEGMENT_MAX: usize = 96;
/// The longest assembled key.
const KEY_MAX: usize = 512;

/// Whether `segment` is one bounded lowercase key segment: non-empty,
/// `[a-z0-9._-]`, and never a `.` or `..` relative marker.
fn is_tail_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= TAIL_SEGMENT_MAX
        && segment != "."
        && segment != ".."
        && segment.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Whether `pipeline` is a short registry token: lowercase start,
/// `[a-z0-9._-]` after.
fn is_pipeline_token(pipeline: &str) -> bool {
    let raw = pipeline.as_bytes();
    !raw.is_empty()
        && raw.len() <= PIPELINE_MAX
        && (raw[0].is_ascii_lowercase() || raw[0].is_ascii_digit())
        && raw[1..].iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// Whether `version` is a bounded version token: alphanumerics and the
/// version punctuation `._+-`.
fn is_version_token(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= VERSION_MAX
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

impl DerivedObjectKey {
    /// The canonical key prefix shared by every derived object of
    /// `tenant`.
    #[must_use]
    pub fn prefix(tenant: &TenantId) -> String {
        derived_prefix(tenant)
    }

    /// Assemble the derived key for `tenant` from its validated members:
    /// the projection family `pipeline`, its immutable `version`, and the
    /// partition/object `tail` below them.
    ///
    /// # Errors
    /// [`ScopedWriterError::NotCanonical`] for a pipeline outside the
    /// short-token grammar, a version outside the version-token grammar,
    /// or a tail with an empty, oversized, or relative (`.`/`..`)
    /// segment.
    pub fn new(
        tenant: &TenantId,
        pipeline: &str,
        version: &str,
        tail: &str,
    ) -> Result<Self, ScopedWriterError> {
        let bad = || GrammarError::NotCanonical;
        if !is_pipeline_token(pipeline) || !is_version_token(version) {
            return Err(bad());
        }
        let trimmed = tail.strip_suffix('/').unwrap_or(tail);
        let segments: Vec<&str> = trimmed.split('/').collect();
        if segments.is_empty() || segments.len() > TAIL_SEGMENTS_MAX {
            return Err(bad());
        }
        if !segments.iter().all(|segment| is_tail_segment(segment)) {
            return Err(bad());
        }
        let text = format!("{}{pipeline}/{version}/{trimmed}", derived_prefix(tenant));
        if text.len() > KEY_MAX {
            return Err(bad());
        }
        Ok(Self {
            text,
            tenant: tenant.clone(),
        })
    }

    /// The assembled key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The canonical tenant segment of the key.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Parse and cross-check: tenant grammar and the bounded derived
    /// layout with at least one partition/object segment below
    /// `<pipeline>/<version>/`.
    ///
    /// # Errors
    /// [`ScopedWriterError::NotCanonical`] for anything outside the
    /// canonical grammar.
    pub fn parse(text: &str) -> Result<Self, ScopedWriterError> {
        let bad = || GrammarError::NotCanonical;
        if text.len() > KEY_MAX {
            return Err(bad());
        }
        let rest = text.strip_prefix("tenants/").ok_or_else(bad)?;
        let Some((tenant, rest)) = rest.split_once('/') else {
            return Err(bad());
        };
        let tenant = TenantId::parse(tenant)?;
        // Same split as the checkpoint key: the namespace member starts
        // after `tenants/<tenant>/`, not at the assembled prefix.
        let rest = rest.strip_prefix("v1/derived/").ok_or_else(bad)?;
        let Some((pipeline, rest)) = rest.split_once('/') else {
            return Err(bad());
        };
        let Some((version, tail)) = rest.split_once('/') else {
            return Err(bad());
        };
        if !is_pipeline_token(pipeline) || !is_version_token(version) || tail.is_empty() {
            return Err(bad());
        }
        let trimmed = tail.strip_suffix('/').unwrap_or(tail);
        let segments: Vec<&str> = trimmed.split('/').collect();
        if segments.len() > TAIL_SEGMENTS_MAX || !segments.iter().all(|s| is_tail_segment(s)) {
            return Err(bad());
        }
        Ok(Self {
            text: text.to_owned(),
            tenant,
        })
    }
}

impl std::fmt::Display for DerivedObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::str::FromStr for DerivedObjectKey {
    type Err = ScopedWriterError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// A validated catalog list prefix: the checkpoint namespace root, or a
/// canonical partial path below it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CatalogListPrefix(String);

impl CatalogListPrefix {
    /// The whole checkpoint namespace of `tenant`.
    #[must_use]
    pub fn root(tenant: &TenantId) -> Self {
        Self(catalog_prefix(tenant))
    }

    /// The prefix text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Adopt `text` as a list prefix for `tenant`'s checkpoint
    /// namespace: the root itself, or the root plus a canonical partial
    /// path.
    ///
    /// # Errors
    /// [`ScopedWriterError::NotCanonical`] for anything outside the
    /// namespace, or for a remainder carrying an empty, relative, or
    /// oversized segment.
    pub fn parse(tenant: &TenantId, text: &str) -> Result<Self, ScopedWriterError> {
        validate_list_prefix(&catalog_prefix(tenant), text)?;
        Ok(Self(text.to_owned()))
    }
}

/// A validated derived list prefix: the derived namespace root, or a
/// canonical partial path below it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DerivedListPrefix(String);

impl DerivedListPrefix {
    /// The whole derived namespace of `tenant`.
    #[must_use]
    pub fn root(tenant: &TenantId) -> Self {
        Self(derived_prefix(tenant))
    }

    /// The prefix text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Adopt `text` as a list prefix for `tenant`'s derived namespace:
    /// the root itself, or the root plus a canonical partial path.
    ///
    /// # Errors
    /// [`ScopedWriterError::NotCanonical`] for anything outside the
    /// namespace, or for a remainder carrying an empty, relative, or
    /// oversized segment.
    pub fn parse(tenant: &TenantId, text: &str) -> Result<Self, ScopedWriterError> {
        validate_list_prefix(&derived_prefix(tenant), text)?;
        Ok(Self(text.to_owned()))
    }
}

/// Refuse any list prefix that is not `root` itself or `root` plus a
/// canonical partial path: no other namespace, no other tenant, no
/// traversal, no empty segment beyond one optional trailing slash.
fn validate_list_prefix(root: &str, text: &str) -> Result<(), ScopedWriterError> {
    let bad = || GrammarError::NotCanonical;
    if text.len() > KEY_MAX {
        return Err(bad());
    }
    if text == root {
        return Ok(());
    }
    let Some(remainder) = text.strip_prefix(root) else {
        return Err(bad());
    };
    if remainder.is_empty() || remainder.contains("//") {
        return Err(bad());
    }
    let trimmed = remainder.strip_suffix('/').unwrap_or(remainder);
    let segments: Vec<&str> = trimmed.split('/').collect();
    if segments.len() > TAIL_SEGMENTS_MAX || !segments.iter().all(|s| is_tail_segment(s)) {
        return Err(bad());
    }
    Ok(())
}

/// The catalog writer's authority: append one checkpoint object at its
/// derived key, and enumerate the checkpoint namespace.
///
/// The provisioned identity holds `put+list` on the catalog prefix and
/// nothing else, so the trait has no read, delete, or abort method: a
/// caller that needs object bodies uses the backup/restore identity,
/// never the writer. The bytes are written unconditionally — the rebuild
/// is deterministic, so a replay of the same checkpoint bytes at the
/// same derived key converges on the same object.
pub trait CatalogWriteStore {
    /// Write `bytes` at the derived checkpoint key `key`.
    ///
    /// # Errors
    /// [`StorageErrorKind::ScopeViolation`](crate::error::StorageErrorKind::ScopeViolation)
    /// when the key is outside this identity's provisioned prefix;
    /// [`StorageErrorKind::Unavailable`](crate::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down.
    fn put_checkpoint(
        &self,
        key: &CatalogCheckpointKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Enumerate the keys below `prefix`, which must sit inside this
    /// identity's provisioned namespace.
    ///
    /// # Errors
    /// [`StorageErrorKind::ScopeViolation`](crate::error::StorageErrorKind::ScopeViolation)
    /// when the prefix is outside the provisioned namespace;
    /// [`StorageErrorKind::Unavailable`](crate::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down.
    fn list_checkpoints(
        &self,
        prefix: &CatalogListPrefix,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send;
}

/// The derived writer's authority: append one projection object at its
/// derived key, and enumerate the derived namespace.
///
/// The provisioned identity holds `put+list` on the derived prefix and
/// nothing else, so the trait has no read, delete, or abort method. The
/// bytes are written unconditionally: a projection producer (the
/// usage-summary derivation, a redacted-episode pipeline) emits complete
/// canonical bytes whose digest its own key carries.
pub trait DerivedWriteStore {
    /// Write `bytes` at the derived object key `key`.
    ///
    /// # Errors
    /// [`StorageErrorKind::ScopeViolation`](crate::error::StorageErrorKind::ScopeViolation)
    /// when the key is outside this identity's provisioned prefix;
    /// [`StorageErrorKind::Unavailable`](crate::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down.
    fn put_object(
        &self,
        key: &DerivedObjectKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Enumerate the keys below `prefix`, which must sit inside this
    /// identity's provisioned namespace.
    ///
    /// # Errors
    /// [`StorageErrorKind::ScopeViolation`](crate::error::StorageErrorKind::ScopeViolation)
    /// when the prefix is outside the provisioned namespace;
    /// [`StorageErrorKind::Unavailable`](crate::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down.
    fn list_objects(
        &self,
        prefix: &DerivedListPrefix,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send;
}
