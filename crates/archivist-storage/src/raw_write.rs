// SPDX-License-Identifier: Apache-2.0

//! The raw writer authority: create, multipart-write, and abort — scoped to
//! the tenant raw prefix, and nothing else.
//!
//! `RawWriteStore` is the only trait in this crate with begin/write/commit/
//! abort semantics, and it deliberately has no read, delete, list, or
//! existence method: the ingestion replica's raw credential "can create,
//! multipart-write, and abort only the tenant raw prefix but cannot read or
//! delete objects or access control/catalog/derived prefixes" (plan Section
//! 5). A preflight `HEAD` is an optimization for deployments that
//! deliberately grant raw read — it is never part of this trait and never
//! the correctness guard (STO-007).
//!
//! # Keys are derived, never supplied
//!
//! Every method takes a key the *server* derived from validated identifiers
//! ([`BlobObjectKey`], [`ManifestKey`]): client-chosen paths are a design
//! anti-pattern (plan Section 7.11), and an implementation that accepted an
//! arbitrary key string would break the authority boundary this trait
//! exists to draw. An implementation whose provisioning does not cover the
//! key's tenant or prefix fails the call with
//! [`StorageErrorKind::ScopeViolation`](crate::error::StorageErrorKind::ScopeViolation).
//!
//! # Honest outcomes
//!
//! Every write reports exactly what the backend could establish — one of
//! the protocol's [`StorageOutcome`] values — and a writer-only profile
//! reports the weaker physical result
//! ([`StorageOutcome::LogicallyCommittedUnknownPhysicalResult`]) rather
//! than claiming deduplication it cannot observe (RCPT-003, RCPT-004,
//! plan Section 7.7). Replays of the same content at the same derived key
//! converge on the same logical object (STO-004); where conditional create
//! is available it is used (STO-005), otherwise deterministic overwrite is
//! the idempotency mechanism (STO-006) and the deployment owns lifecycle
//! expiration of redundant noncurrent versions (STO-009).
//!
//! # Multipart sessions
//!
//! A multipart upload is a session between one caller and one store: it
//! begins with [`RawWriteStore::begin_multipart`], advances by
//! [`RawWriteStore::write_part`], and ends exactly once with
//! [`RawWriteStore::commit_multipart`] (only after the caller has validated
//! every size and digest — validate-before-complete, plan Section 7.7) or
//! [`RawWriteStore::abort_multipart`]. Aborting an abandoned session is
//! writer-prefix work by definition; a 24-hour incomplete-multipart
//! lifecycle rule remains the deployment's cleanup backstop (plan Section 8,
//! Phase 2). Using a session handle a store does not recognize — or one
//! whose key no longer matches — fails with
//! [`StorageErrorKind::MalformedInput`](crate::error::StorageErrorKind::MalformedInput).

use std::future::Future;

use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::vocabulary::{GrammarError, StorageOutcome};

use crate::capability::StoreCapabilities;
use crate::error::StorageError;
use crate::metadata::ObjectTag;

/// Why a candidate identifier is not a value of the target type.
///
/// A thin alias over the protocol grammar error: these types are newtypes
/// over the same fail-closed grammar discipline as the wire vocabulary.
pub type IdentifierError = GrammarError;

/// An opaque multipart-upload session handle minted by an implementation.
///
/// 1–1024 printable, non-space ASCII characters — whatever the backend uses
/// to name the session, carried without interpretation. The handle means
/// nothing outside the store instance that issued it and the raw prefix key
/// it was opened for.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MultipartUploadId(String);

impl MultipartUploadId {
    /// Adopt `text` after verifying its grammar.
    ///
    /// # Errors
    /// [`IdentifierError::NotCanonical`] for anything but 1–1024 printable,
    /// non-space ASCII characters.
    pub fn parse(text: &str) -> Result<Self, IdentifierError> {
        if text.is_empty() || text.len() > 1024 || !text.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(IdentifierError::NotCanonical);
        }
        Ok(Self(text.to_owned()))
    }

    /// The handle exactly as the implementation issued it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MultipartUploadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A one-based part ordinal inside one multipart session (1–10,000, the
/// portable S3-family bound).
///
/// At the pinned 8 MiB part size (plan Section 7.6) the bound admits
/// 80 GiB per blob — far above the 256 MiB single-record cap — so the bound
/// is a backend portability fact, not a payload limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartNumber(u16);

impl PartNumber {
    /// The largest part ordinal a portable backend accepts.
    pub const MAX: u16 = 10_000;

    /// Adopt `n` as a part ordinal.
    ///
    /// # Errors
    /// [`IdentifierError::NotCanonical`] for 0 or anything above
    /// [`PartNumber::MAX`].
    pub fn new(n: u16) -> Result<Self, IdentifierError> {
        if n == 0 || n > Self::MAX {
            return Err(IdentifierError::NotCanonical);
        }
        Ok(Self(n))
    }

    /// The ordinal value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for PartNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The backend's per-part commitment, returned by
/// [`RawWriteStore::write_part`].
///
/// Committing requires passing back exactly the commitments a session
/// produced, in part order; the implementation rejects a set that skips,
/// repeats, or reorders parts with
/// [`StorageErrorKind::MalformedInput`](crate::error::StorageErrorKind::MalformedInput).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartCommitment {
    number: PartNumber,
    tag: ObjectTag,
}

impl PartCommitment {
    /// Pair a part ordinal with the tag the backend returned for it.
    #[must_use]
    pub const fn new(number: PartNumber, tag: ObjectTag) -> Self {
        Self { number, tag }
    }

    /// The part ordinal.
    #[must_use]
    pub const fn number(&self) -> PartNumber {
        self.number
    }

    /// The backend's commitment tag for the part.
    #[must_use]
    pub const fn tag(&self) -> &ObjectTag {
        &self.tag
    }
}

/// A deterministic raw-prefix manifest key: the occurrence manifest or the
/// upload attestation — the two small JSON objects an ingest commit writes
/// after the blob is durable (RCPT-001, plan Section 7.7).
///
/// Constructed only from the protocol's typed keys, so the enum cannot name
/// anything outside the tenant raw prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestKey {
    /// `tenants/<tenant>/v1/raw/occurrences/...` (STO-002).
    Occurrence(OccurrenceObjectKey),
    /// `tenants/<tenant>/v1/raw/attestations/...` (STO-013).
    Attestation(AttestationObjectKey),
}

impl ManifestKey {
    /// The derived key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Occurrence(key) => key.as_str(),
            Self::Attestation(key) => key.as_str(),
        }
    }
}

impl std::fmt::Display for ManifestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The raw-write identity: deterministic writes into the tenant raw prefix,
/// with multipart commit/abort and nothing else.
///
/// Implementations are shared by reference (`&self`) across concurrent
/// uploads; the ingest server runs 16 in-flight uploads per process (plan
/// Section 7.6). Every method's future is [`Send`] so a `tokio` worker can
/// drive it; implementations must not hold a non-`Send` guard across an
/// await.
///
/// The trait carries no method that reads, lists, deletes, or tests
/// existence — an ingestion replica configured with only this trait and
/// [`crate::control::ControlReadStore`] cannot obtain raw read, delete,
/// audit, catalog, derived, or control-write authority through its storage
/// configuration (plan Section 5).
pub trait RawWriteStore {
    /// The observed capability report.
    ///
    /// Advisory by contract (see [`crate::capability`]); a store may return
    /// a freshly probed report or a cached one. This call never performs
    /// I/O against tenant data.
    fn capabilities(&self) -> StoreCapabilities;

    /// Write one deterministic manifest object with its exact final bytes.
    ///
    /// The canonical write for occurrence manifests and upload attestations:
    /// the bytes are complete before the call (these objects are bounded
    /// JSON documents, not streams), and a replay of the same bytes at the
    /// same derived key converges on one logical object (STO-004). Where
    /// conditional create is supported the backend's atomic primitive is
    /// used and "already exists" resolves after compatible-metadata
    /// validation (STO-005); otherwise deterministic overwrite is the
    /// idempotency mechanism (STO-006).
    ///
    /// # Errors
    /// [`StorageError::ScopeViolation`](crate::error::StorageError) when the
    /// key's tenant or prefix is outside this identity's provisioning,
    /// [`StorageError::MalformedInput`](crate::error::StorageError) for
    /// bounds violations,
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down.
    fn write_manifest(
        &self,
        key: &ManifestKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<StorageOutcome, StorageError>> + Send;

    /// Begin a multipart session for one content-addressed blob key.
    ///
    /// The session is uncommitted by construction: nothing it writes is
    /// visible at the key until [`RawWriteStore::commit_multipart`] — the
    /// property the validate-before-complete contract depends on (plan
    /// Section 7.7).
    ///
    /// # Errors
    /// [`StorageError::ScopeViolation`](crate::error::StorageError) when the
    /// key is outside this identity's provisioning,
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down.
    fn begin_multipart(
        &self,
        blob: &BlobObjectKey,
    ) -> impl Future<Output = Result<MultipartUploadId, StorageError>> + Send;

    /// Stream one part into an uncommitted session.
    ///
    /// Parts arrive in ordinal order without gaps (plan Section 7.6 pins
    /// the 8 MiB part size); an implementation may enforce order and reject
    /// replays or overlaps with
    /// [`StorageError::MalformedInput`](crate::error::StorageError).
    ///
    /// # Errors
    /// [`StorageError::MalformedInput`](crate::error::StorageError) for an
    /// unknown session or out-of-bounds part,
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down.
    fn write_part(
        &self,
        upload: &MultipartUploadId,
        part: PartNumber,
        bytes: &[u8],
    ) -> impl Future<Output = Result<PartCommitment, StorageError>> + Send;

    /// Commit a completed session after the caller validated every size and
    /// digest.
    ///
    /// Only the caller can make this judgment — the store never saw the
    /// canonical bytes' digest — which is why commit is an explicit,
    /// caller-gated step and not something the store does on part count or
    /// size alone (plan Section 7.7: complete only after all sizes, digests,
    /// and the request signature verify).
    ///
    /// # Errors
    /// [`StorageError::MalformedInput`](crate::error::StorageError) for an
    /// unknown session or an inconsistent commitment set,
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down. A commit lost in flight is repaired by
    /// retrying the whole immutable request, never by reusing the dead
    /// session (`EC-10`).
    fn commit_multipart(
        &self,
        upload: &MultipartUploadId,
        parts: &[PartCommitment],
    ) -> impl Future<Output = Result<StorageOutcome, StorageError>> + Send;

    /// Abort an uncommitted session, releasing its parts.
    ///
    /// The one destructive-looking call a writer identity legitimately has:
    /// it only ever releases parts this session itself wrote into the raw
    /// prefix. Aborting an already-committed or already-aborted session is
    /// reported as success — abort is cleanup, and cleanup must be
    /// idempotent (plan Section 7.7's 24-hour incomplete-multipart cleanup).
    ///
    /// # Errors
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down.
    fn abort_multipart(
        &self,
        upload: &MultipartUploadId,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::{ManifestKey, MultipartUploadId, PartCommitment, PartNumber};
    use crate::metadata::ObjectTag;

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn upload_id_grammar() {
        assert!(MultipartUploadId::parse("abc123").is_ok());
        assert!(MultipartUploadId::parse("").is_err());
        assert!(MultipartUploadId::parse(&"x".repeat(1025)).is_err());
        assert!(MultipartUploadId::parse(&"x".repeat(1024)).is_ok());
        assert!(MultipartUploadId::parse("with space").is_err());
    }

    #[test]
    fn part_number_bounds() {
        assert!(PartNumber::new(1).is_ok());
        assert!(PartNumber::new(10_000).is_ok());
        assert_eq!(
            PartNumber::new(0).unwrap_err().to_string(),
            "value does not match the canonical grammar"
        );
        assert!(PartNumber::new(10_001).is_err());
        assert_eq!(PartNumber::new(7).unwrap().get(), 7);
        assert_eq!(PartNumber::MAX, 10_000);
    }

    #[test]
    fn part_commitment_pairs_number_and_tag() {
        let commitment = PartCommitment::new(
            PartNumber::new(2).unwrap(),
            ObjectTag::parse("\"etag-2\"").unwrap(),
        );
        assert_eq!(commitment.number().get(), 2);
        assert_eq!(commitment.tag().as_str(), "\"etag-2\"");
    }

    #[test]
    fn manifest_key_dispatches_by_record() {
        let tenant = archivist_protocol::vocabulary::TenantId::parse(TENANT).unwrap();
        let occurrence = archivist_protocol::vocabulary::OccurrenceId::parse(DIGEST).unwrap();
        let attestation =
            archivist_protocol::vocabulary::AttestationId::parse(&"ab".repeat(32)).unwrap();
        let occurrence_key = archivist_protocol::object_key::OccurrenceObjectKey::new(
            &tenant,
            &archivist_protocol::vocabulary::ClientId::parse(
                "aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f",
            )
            .unwrap(),
            &archivist_protocol::vocabulary::HarnessId::parse("claude-code").unwrap(),
            &archivist_protocol::vocabulary::SessionHash::parse(DIGEST).unwrap(),
            &occurrence,
        );
        let attestation_key = archivist_protocol::object_key::AttestationObjectKey::new(
            &tenant,
            &occurrence,
            &attestation,
        );
        let occurrence_manifest = ManifestKey::Occurrence(occurrence_key.clone());
        let attestation_manifest = ManifestKey::Attestation(attestation_key.clone());
        assert!(
            occurrence_manifest
                .as_str()
                .contains("/v1/raw/occurrences/")
        );
        assert!(
            attestation_manifest
                .as_str()
                .contains("/v1/raw/attestations/")
        );
        assert_eq!(ManifestKey::Occurrence(occurrence_key), occurrence_manifest);
        assert_eq!(
            ManifestKey::Attestation(attestation_key),
            attestation_manifest
        );
    }
}
