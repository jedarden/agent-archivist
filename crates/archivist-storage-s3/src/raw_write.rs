// SPDX-License-Identifier: Apache-2.0

//! The S3 raw writer: bounded manifest `PUT`s and multipart sessions over
//! the raw-writer credential, using the strongest primitive the observed
//! capability report establishes.
//!
//! [`S3RawWriteStore`] implements [`RawWriteStore`] for one pinned tenant
//! of one [`S3StorageConfig`](crate::config::S3StorageConfig): the
//! `storage.raw_write_credentials_ref` identity the configuration
//! validates (plan Section 5), the raw bucket it addresses, and the
//! [`StoreCapabilities`] a probe observed. The report decides the write
//! path — manifest writes go through the storage crate's atomic
//! conditional-create decision layer when
//! [`ConditionalCreate::Supported`] is established, and through bounded
//! deterministic overwrite otherwise — and neither path ever reports more
//! than the backend could establish (RCPT-003).
//!
//! # The strongest reported primitive
//!
//! The reference profile and B2 differ on exactly this point: a
//! conditional `PUT` (`IfNoneMatch: *`) resolves the create-or-exists race
//! in one backend operation, and a backend without it converges on the
//! same logical object by rewriting the same deterministic bytes at the
//! same derived key (STO-006). The store never guesses which backend it
//! faces: the capability report is the only input, and
//! [`ConditionalCreateStore::create_manifest_if_absent`] — the trait this
//! store implements *in addition* to [`RawWriteStore`] — refuses with
//! [`StorageErrorKind::CapabilityUnavailable`] unless the report
//! established the primitive. `commit_multipart` reports
//! [`StorageOutcome::LogicallyCommittedUnknownPhysicalResult`] on every
//! profile: a complete response proves the write happened, but nothing a
//! writer identity can carry distinguishes creation from byte-equivalent
//! replacement, and there is no portable conditional complete.
//!
//! # Sessions and cancellation safety
//!
//! A multipart session is a table entry: `begin_multipart` registers the
//! handle the backend minted together with its derived key, `write_part`
//! appends one [`PartCommitment`] per part in strict ordinal order, and
//! the terminal operations leave a tombstone so a late `abort_multipart`
//! stays idempotent (abort is cleanup, and cleanup must be idempotent).
//! Presenting an unknown handle fails with
//! [`StorageErrorKind::MalformedInput`]; presenting a commitment set that
//! is not exactly the session's own parts, in order, fails the same way
//! and never reaches the backend's complete. A commit that fails in
//! flight leaves the session open for the caller's abort — a dead session
//! is never retried (`EC-10`) — and the deployment's 24-hour
//! incomplete-multipart lifecycle rule remains the backstop for sessions
//! orphaned by a dropped process. The table is guarded by a lock that is
//! never held across an await, so every future the trait returns is
//! [`Send`] and one store instance serves the ingest server's 16
//! in-flight uploads by shared reference (plan Section 7.6).
//!
//! # The seam
//!
//! [`RawWriteBackend`] is the S3 request seam: plain `PUT`, conditional
//! `PUT`, create, part, complete, and abort — keyed by the derived
//! [`RawObjectKey`] only, with no read, list, delete, arbitrary-key, or
//! bucket-level method, because the raw-writer credential "can create,
//! multipart-write, and abort only the tenant raw prefix but cannot read
//! or delete objects or access control/catalog/derived prefixes" (plan
//! Section 5). The concrete binding over the raw-writer credential
//! enforces that prefix scope; the mock in this module's tests mirrors
//! the denial so the store's requests are proven to stay inside it.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use archivist_protocol::envelope::CANONICAL_MAX_BYTES;
use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::vocabulary::{GrammarError, StorageOutcome, TenantId};

use archivist_storage::capability::{ConditionalCreate, StoreCapabilities};
use archivist_storage::commit::{
    ConditionalCreateStore, CreateIfAbsent, commit_by_conditional_create,
};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::metadata::ObjectTag;
use archivist_storage::multipart::PART_BYTES;
use archivist_storage::raw_write::{
    IdentifierError, ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
};

use crate::config::{CredentialReference, S3StorageConfig};

const DETAIL_SCOPE: &str = "object key is outside this raw-write identity";
const DETAIL_UNKNOWN_SESSION: &str = "multipart session is not known to this store";
const DETAIL_ENDED_SESSION: &str = "multipart session has already ended";
const DETAIL_PART_SEQUENCE: &str = "part ordinal is out of sequence";
const DETAIL_PART_BOUNDS: &str = "part size is outside the pinned part bounds";
const DETAIL_EMPTY_COMMITMENTS: &str = "commitment set is empty";
const DETAIL_MISMATCHED_COMMITMENTS: &str = "commitment set does not match the session parts";
const DETAIL_EMPTY_MANIFEST: &str = "manifest bytes are empty";
const DETAIL_OVERSIZED_MANIFEST: &str = "manifest exceeds the canonical document bound";
const DETAIL_MALFORMED_HANDLE: &str = "backend session handle is outside the grammar";
const DETAIL_DUPLICATE_HANDLE: &str = "backend session handle is not unique";
const DETAIL_MALFORMED_TAG: &str = "backend part commitment is outside the tag grammar";
const DETAIL_CONDITIONAL: &str = "conditional create is not a reported capability of this store";

/// A derived raw-prefix object key: one of the three raw layouts the
/// protocol defines (plan Section 7.5), carried as typed text with its
/// tenant pinned.
///
/// Constructed only from the protocol's typed keys, so it cannot name
/// anything outside the tenant raw prefix; [`RawObjectKey::parse`] adopts
/// arbitrary text only after one of the layout parsers accepted it,
/// cross-checked shard couplings included.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RawObjectKey {
    text: Box<str>,
    tenant: Box<str>,
}

impl RawObjectKey {
    /// Adopt the text of a layout the protocol's own parser already
    /// accepted, splitting out the tenant segment it guarantees.
    fn from_validated(text: &str) -> Self {
        // Unreachable for a validated layout: every raw key is
        // `tenants/<tenant>/v1/raw/<family>/...`, and the family parser
        // cross-checked the tenant segment before returning.
        let tenant = text
            .split('/')
            .nth(1)
            .expect("a raw layout always carries its tenant segment");
        Self {
            text: text.into(),
            tenant: tenant.into(),
        }
    }

    /// The blob key: `tenants/<tenant>/v1/raw/blobs/...`.
    #[must_use]
    pub fn blob(key: &BlobObjectKey) -> Self {
        Self::from_validated(key.as_str())
    }

    /// The occurrence-manifest key:
    /// `tenants/<tenant>/v1/raw/occurrences/...`.
    #[must_use]
    pub fn occurrence(key: &OccurrenceObjectKey) -> Self {
        Self::from_validated(key.as_str())
    }

    /// The upload-attestation key:
    /// `tenants/<tenant>/v1/raw/attestations/...`.
    #[must_use]
    pub fn attestation(key: &AttestationObjectKey) -> Self {
        Self::from_validated(key.as_str())
    }

    /// Either manifest family's key, whichever one the manifest names.
    #[must_use]
    pub fn manifest(key: &ManifestKey) -> Self {
        match key {
            ManifestKey::Occurrence(occurrence) => Self::occurrence(occurrence),
            ManifestKey::Attestation(attestation) => Self::attestation(attestation),
        }
    }

    /// Parse and cross-check against every raw layout: the text is a
    /// [`RawObjectKey`] exactly when one of the protocol's family parsers
    /// accepts it, shard couplings included.
    ///
    /// # Errors
    /// [`IdentifierError::NotCanonical`] for anything but the three
    /// canonical raw layouts.
    pub fn parse(text: &str) -> Result<Self, IdentifierError> {
        let canonical = BlobObjectKey::parse(text).is_ok()
            || OccurrenceObjectKey::parse(text).is_ok()
            || AttestationObjectKey::parse(text).is_ok();
        if !canonical {
            return Err(IdentifierError::NotCanonical);
        }
        Ok(Self::from_validated(text))
    }

    /// The derived key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The canonical tenant segment of the key.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
}

impl std::fmt::Display for RawObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::str::FromStr for RawObjectKey {
    type Err = GrammarError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// The S3 request seam of the raw-writer identity: the six object
/// primitives the credential needs, keyed by the derived
/// [`RawObjectKey`] only.
///
/// The trait is deliberately narrower than an S3 client: there is no
/// read, no delete, no list, no arbitrary-key method, and no bucket-level
/// call — the raw-writer credential can create, multipart-write, and
/// abort only the tenant raw prefix (plan Section 5), so this is the
/// entire surface that authority has. A concrete binding (the reference
/// profile's HTTP client over the raw-writer credential, the
/// compatibility suite's fault-injecting backend) implements these
/// operations over `PutObject`, a conditional `PutObject`
/// (`IfNoneMatch: *`), `CreateMultipartUpload`, `UploadPart`,
/// `CompleteMultipartUpload`, and `AbortMultipartUpload`, and enforces
/// the same prefix scope the deployment's backend policy states:
/// create-and-multipart below `tenants/<tenant>/v1/raw/`, deny every
/// other prefix. The mock in this module's tests mirrors that denial so
/// the store's requests are proven to stay inside it.
pub trait RawWriteBackend {
    /// Write `bytes` at one derived raw key unconditionally — the
    /// deterministic-overwrite primitive (STO-006).
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the key is outside
    /// this credential's provisioned prefix.
    fn put_raw_object(
        &self,
        key: &RawObjectKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Create the object at one derived raw key if — and only if — the
    /// key is absent, atomically, reporting whatever readable evidence
    /// the backend can attach to an existing object.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the key is outside
    /// this credential's provisioned prefix.
    fn create_raw_object_if_absent(
        &self,
        key: &RawObjectKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<CreateIfAbsent, StorageError>> + Send;

    /// Open a multipart session at one derived raw key, returning the
    /// backend's opaque session handle.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the key is outside
    /// this credential's provisioned prefix.
    fn create_multipart(
        &self,
        key: &RawObjectKey,
    ) -> impl Future<Output = Result<String, StorageError>> + Send;

    /// Upload one part into an open session, returning the backend's
    /// commitment tag for it.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down, or the session is not open at the backend.
    fn upload_part(
        &self,
        key: &RawObjectKey,
        session: &str,
        part: PartNumber,
        bytes: &[u8],
    ) -> impl Future<Output = Result<String, StorageError>> + Send;

    /// Complete one open session with exactly the commitments it
    /// produced, making the concatenated parts the object at the key.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down, or the presented set does not match the session the backend
    /// holds.
    fn complete_multipart(
        &self,
        key: &RawObjectKey,
        session: &str,
        parts: &[PartCommitment],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Abort one open session, releasing its parts.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down.
    fn abort_multipart(
        &self,
        key: &RawObjectKey,
        session: &str,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// Where one session stands in this store's table.
#[derive(Debug)]
enum SessionState {
    /// Open at its derived key with the commitments its parts produced.
    Open(OpenSession),
    /// Completed; the tombstone keeps a late abort idempotent.
    Committed,
    /// Aborted; the tombstone keeps a repeated abort idempotent.
    Aborted,
}

/// One open multipart session: the derived key its parts belong to and
/// the commitments they produced, in ordinal order.
#[derive(Debug)]
struct OpenSession {
    key: RawObjectKey,
    commitments: Vec<PartCommitment>,
}

/// The portable S3 [`RawWriteStore`]: one ingest configuration, one
/// pinned tenant, one observed capability report, one backend seam, and
/// the session table that makes commit and abort honest.
///
/// The ingest replica (the composition root) composes this store over
/// the [`RawWriteBackend`] binding for its raw-writer credential and
/// hands it the capability report its probe observed;
/// [`S3RawWriteStore::with_capabilities`] is the only way a report
/// arrives, and an unprobed store behaves as the weakest model — plain
/// bounded `PUT`s reporting
/// [`StorageOutcome::LogicallyCommittedUnknownPhysicalResult`]. A replica
/// serving several tenants composes one store per tenant over a shared
/// backend handle, so each identity's scope check stays exact.
pub struct S3RawWriteStore<B> {
    config: S3StorageConfig,
    tenant: TenantId,
    capabilities: StoreCapabilities,
    backend: B,
    sessions: Mutex<HashMap<Box<str>, SessionState>>,
}

impl<B> S3RawWriteStore<B> {
    /// Compose the raw-write authority: the validated ingest
    /// configuration (its raw-writer credential reference and raw
    /// bucket), the one tenant whose raw prefix this store provisions,
    /// and the backend seam. The capability report starts unprobed.
    #[must_use]
    pub fn new(config: S3StorageConfig, tenant: TenantId, backend: B) -> Self {
        Self {
            config,
            tenant,
            capabilities: StoreCapabilities::unprobed(),
            backend,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Adopt the capability report a probe observed for this store's
    /// backend. The report is the only input to the write-path decision,
    /// so this is the single place a deployment's probe result enters.
    #[must_use]
    pub fn with_capabilities(mut self, report: StoreCapabilities) -> Self {
        self.capabilities = report;
        self
    }

    /// The ingest configuration this store was composed with.
    #[must_use]
    pub const fn config(&self) -> &S3StorageConfig {
        &self.config
    }

    /// The one tenant whose raw prefix this store provisions. Every key
    /// the store writes lives under this tenant's prefix, and every other
    /// tenant's key fails the scope check before any request is issued.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The raw-writer credential reference this store's requests ride on
    /// — the `storage.raw_write_credentials_ref` identity the
    /// configuration validated ([`StorageRole::RawWriter`]'s reference).
    ///
    /// [`StorageRole::RawWriter`]: crate::config::StorageRole::RawWriter
    #[must_use]
    pub const fn raw_write_credentials(&self) -> &CredentialReference {
        self.config.identities().raw_write()
    }

    /// Whether a raw object key is inside this identity's provisioned
    /// scope: one of the three canonical raw layouts under this tenant's
    /// raw prefix (plan Section 7.5), and nothing else.
    ///
    /// This is the Rust-side model of the deployment's backend policy for
    /// the raw-writer credential — create and multipart below
    /// `tenants/<tenant>/v1/raw/`, deny every other prefix. Control,
    /// catalog, and derived prefixes, every other tenant's prefix, and a
    /// raw-layout key with a non-canonical identifier or shard segment
    /// are denied rather than normalized. The compatibility-suite
    /// profiles prove the live policy agrees.
    #[must_use]
    pub fn permits_key(&self, key: &str) -> bool {
        RawObjectKey::parse(key).is_ok_and(|derived| derived.tenant() == self.tenant.as_str())
    }

    /// Fail closed unless the key is inside this identity's provisioning:
    /// the pinned tenant, and the prefix policy's own shape. Unreachable
    /// while the key derivation and the scope model agree — which is
    /// exactly the agreement a drift between the two must fail closed
    /// on, before any request is issued against the raw-writer
    /// credential.
    fn authorize(&self, key: RawObjectKey) -> Result<RawObjectKey, StorageError> {
        if key.tenant() != self.tenant.as_str() || !self.permits_key(key.as_str()) {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        Ok(key)
    }
}

/// The manifest payload bound this module enforces locally — non-empty
/// and within the pinned canonical-document maximum — with the same
/// detail literals the storage crate's own manifest write paths use, so
/// behavior does not depend on which layer refused first.
fn bounded_manifest(bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.is_empty() {
        return Err(StorageError::new(
            StorageErrorKind::MalformedInput,
            DETAIL_EMPTY_MANIFEST,
        ));
    }
    if bytes.len() > CANONICAL_MAX_BYTES {
        return Err(StorageError::new(
            StorageErrorKind::MalformedInput,
            DETAIL_OVERSIZED_MANIFEST,
        ));
    }
    Ok(())
}

fn unknown_session() -> StorageError {
    StorageError::new(StorageErrorKind::MalformedInput, DETAIL_UNKNOWN_SESSION)
}

fn ended_session() -> StorageError {
    StorageError::new(StorageErrorKind::MalformedInput, DETAIL_ENDED_SESSION)
}

fn out_of_sequence() -> StorageError {
    StorageError::new(StorageErrorKind::MalformedInput, DETAIL_PART_SEQUENCE)
}

fn part_bounds() -> StorageError {
    StorageError::new(StorageErrorKind::MalformedInput, DETAIL_PART_BOUNDS)
}

// `Sync` on the backend is what lets `&self` ride across the awaits of
// the trait's `Send` futures; every real backend (an HTTP client handle
// over the raw-writer credential) is sync in exactly this sense. The
// session lock is never held across an await: each method snapshots or
// updates under the lock and awaits between critical sections.
impl<B: RawWriteBackend + Sync> RawWriteStore for S3RawWriteStore<B> {
    fn capabilities(&self) -> StoreCapabilities {
        self.capabilities
    }

    async fn write_manifest(
        &self,
        key: &ManifestKey,
        bytes: &[u8],
    ) -> Result<StorageOutcome, StorageError> {
        bounded_manifest(bytes)?;
        match self.capabilities.conditional_create {
            // The strongest primitive: the storage crate's own decision
            // layer runs the atomic create and classifies any existing
            // object's readable evidence. This store is the bottom of the
            // call stack, so the writer-only arm below performs its PUT
            // directly against the seam rather than routing through the
            // helpers that call back into this method.
            ConditionalCreate::Supported => commit_by_conditional_create(self, key, bytes).await,
            ConditionalCreate::Unavailable => {
                let raw = self.authorize(RawObjectKey::manifest(key))?;
                self.backend.put_raw_object(&raw, bytes).await?;
                // A writer-only identity cannot establish creation,
                // presence, or replacement — no deduplication is claimed
                // (RCPT-003, RCPT-004), and any noncurrent physical
                // version is the deployment's lifecycle concern (STO-009).
                Ok(StorageOutcome::LogicallyCommittedUnknownPhysicalResult)
            }
        }
    }

    async fn begin_multipart(
        &self,
        blob: &BlobObjectKey,
    ) -> Result<MultipartUploadId, StorageError> {
        let raw = self.authorize(RawObjectKey::blob(blob))?;
        let handle = self.backend.create_multipart(&raw).await?;
        let id = MultipartUploadId::parse(&handle).map_err(|_| {
            StorageError::new(StorageErrorKind::Unavailable, DETAIL_MALFORMED_HANDLE)
        })?;
        {
            let mut sessions = self.sessions.lock().expect("raw-write session lock");
            if sessions.contains_key(id.as_str()) {
                // A backend that reuses a live handle would corrupt the
                // bookkeeping of both sessions; refusing costs one
                // session orphaned at the backend, which the 24-hour
                // lifecycle rule reaps.
                return Err(StorageError::new(
                    StorageErrorKind::Unavailable,
                    DETAIL_DUPLICATE_HANDLE,
                ));
            }
            sessions.insert(
                Box::from(id.as_str()),
                SessionState::Open(OpenSession {
                    key: raw,
                    commitments: Vec::new(),
                }),
            );
        }
        Ok(id)
    }

    async fn write_part(
        &self,
        upload: &MultipartUploadId,
        part: PartNumber,
        bytes: &[u8],
    ) -> Result<PartCommitment, StorageError> {
        let key = {
            let mut sessions = self.sessions.lock().expect("raw-write session lock");
            let Some(state) = sessions.get_mut(upload.as_str()) else {
                return Err(unknown_session());
            };
            let SessionState::Open(open) = state else {
                return Err(ended_session());
            };
            // Strict ordinal order, no gaps, no replays — the sequence the
            // streaming writer emits (plan Section 7.6) — enforced before
            // the part travels, so a refused part costs no request.
            if usize::from(part.get()) != open.commitments.len() + 1 {
                return Err(out_of_sequence());
            }
            if bytes.is_empty() || bytes.len() > PART_BYTES {
                return Err(part_bounds());
            }
            open.key.clone()
        };
        let tag_text = self
            .backend
            .upload_part(&key, upload.as_str(), part, bytes)
            .await?;
        let tag = ObjectTag::parse(&tag_text)
            .map_err(|_| StorageError::new(StorageErrorKind::Unavailable, DETAIL_MALFORMED_TAG))?;
        let commitment = PartCommitment::new(part, tag);
        {
            // The re-check under the record lock closes the same-session
            // race a shared `&self` admits: two concurrent writers that
            // both passed the ordinal snapshot cannot both record.
            let mut sessions = self.sessions.lock().expect("raw-write session lock");
            let Some(state) = sessions.get_mut(upload.as_str()) else {
                return Err(unknown_session());
            };
            match state {
                SessionState::Open(open)
                    if open.commitments.len() + 1 == usize::from(part.get()) =>
                {
                    open.commitments.push(commitment.clone());
                }
                SessionState::Open(_) => return Err(out_of_sequence()),
                SessionState::Committed | SessionState::Aborted => {
                    return Err(ended_session());
                }
            }
        }
        Ok(commitment)
    }

    async fn commit_multipart(
        &self,
        upload: &MultipartUploadId,
        parts: &[PartCommitment],
    ) -> Result<StorageOutcome, StorageError> {
        let key = {
            let sessions = self.sessions.lock().expect("raw-write session lock");
            let Some(state) = sessions.get(upload.as_str()) else {
                return Err(unknown_session());
            };
            let SessionState::Open(open) = state else {
                return Err(ended_session());
            };
            if parts.is_empty() {
                return Err(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    DETAIL_EMPTY_COMMITMENTS,
                ));
            }
            // Exactly the session's own parts, in order: a set that
            // skips, repeats, reorders, or substitutes tags never reaches
            // the backend's complete.
            if parts != open.commitments.as_slice() {
                return Err(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    DETAIL_MISMATCHED_COMMITMENTS,
                ));
            }
            open.key.clone()
        };
        self.backend
            .complete_multipart(&key, upload.as_str(), parts)
            .await?;
        // A failure above leaves the session open — the caller aborts it;
        // a dead session is never retried (EC-10).
        if let Some(state) = self
            .sessions
            .lock()
            .expect("raw-write session lock")
            .get_mut(upload.as_str())
        {
            *state = SessionState::Committed;
        }
        // The complete response proves the write happened and nothing
        // more: a writer identity cannot distinguish creation from
        // byte-equivalent replacement, so every profile reports the
        // weaker physical result (RCPT-003, RCPT-004).
        Ok(StorageOutcome::LogicallyCommittedUnknownPhysicalResult)
    }

    async fn abort_multipart(&self, upload: &MultipartUploadId) -> Result<(), StorageError> {
        let key = {
            let sessions = self.sessions.lock().expect("raw-write session lock");
            let Some(state) = sessions.get(upload.as_str()) else {
                return Err(unknown_session());
            };
            match state {
                SessionState::Open(open) => open.key.clone(),
                // Abort is idempotent cleanup: a session that already
                // ended has nothing to release, so the repeat succeeds
                // without issuing a request.
                SessionState::Committed | SessionState::Aborted => return Ok(()),
            }
        };
        self.backend.abort_multipart(&key, upload.as_str()).await?;
        if let Some(state) = self
            .sessions
            .lock()
            .expect("raw-write session lock")
            .get_mut(upload.as_str())
        {
            *state = SessionState::Aborted;
        }
        Ok(())
    }
}

impl<B: RawWriteBackend + Sync> ConditionalCreateStore for S3RawWriteStore<B> {
    async fn create_manifest_if_absent(
        &self,
        key: &ManifestKey,
        bytes: &[u8],
    ) -> Result<CreateIfAbsent, StorageError> {
        bounded_manifest(bytes)?;
        // The primitive exists only when the observed report established
        // it — the same refusal the decision layer makes, kept here so a
        // direct caller cannot route around the honest-mode contract.
        if self.capabilities.conditional_create != ConditionalCreate::Supported {
            return Err(StorageError::new(
                StorageErrorKind::CapabilityUnavailable,
                DETAIL_CONDITIONAL,
            ));
        }
        let raw = self.authorize(RawObjectKey::manifest(key))?;
        self.backend.create_raw_object_if_absent(&raw, bytes).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use archivist_protocol::envelope::CANONICAL_MAX_BYTES;
    use archivist_protocol::object_key::{
        AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey,
    };
    use archivist_protocol::sha256;
    use archivist_protocol::vocabulary::{
        AttestationId, BlobDigest, ClientId, HarnessId, OccurrenceId, SafeMessage, SessionHash,
        StorageOutcome, TenantId,
    };
    use archivist_storage::capability::{ConditionalCreate, StoreCapabilities};
    use archivist_storage::commit::{ConditionalCreateStore, CreateIfAbsent, ExistingObject};
    use archivist_storage::error::{StorageError, StorageErrorKind};
    use archivist_storage::metadata::ObjectTag;
    use archivist_storage::multipart::{MultipartWriter, OpenUploads, PART_BYTES};
    use archivist_storage::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber,
    };

    use super::{RawObjectKey, RawWriteBackend, RawWriteStore, S3RawWriteStore};
    use crate::config::{EncryptionPolicy, S3StorageConfig};

    // The golden identifiers the protocol's object-key tests pin, plus
    // the control adapter's client UUID: one story for tenant, client,
    // harness, and digests across every derivation this module checks.
    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
    const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";
    const HARNESS: &str = "claude-code";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SESSION: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const OCCURRENCE: &str = "0011223344556677001122334455667700112233445566770011223344556677";
    const ATTESTATION: &str = "9988776655443322110088776655443322110088776655443322110088776655";
    const RAW_WRITE_REF: &str = "file:/etc/archivist/storage/raw-write-credentials";
    const CONTROL_READ_REF: &str = "file:/etc/archivist/storage/control-read-credentials";

    /// A no-dependency executor for futures that complete without pending
    /// (the same helper the storage crate's ingest tests use).
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            match future.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).unwrap()
    }

    fn other_tenant() -> TenantId {
        TenantId::parse(OTHER_TENANT).unwrap()
    }

    fn ingest_config() -> S3StorageConfig {
        S3StorageConfig::builder()
            .endpoint_url("https://s3.example.com")
            .region("us-east-1")
            .encryption(EncryptionPolicy::S3Sse)
            .raw_bucket("archivist-raw-example")
            .control_bucket("archivist-control-example")
            .raw_write_credentials(RAW_WRITE_REF)
            .control_read_credentials(CONTROL_READ_REF)
            .build()
            .expect("golden ingest configuration validates")
    }

    fn blob_key(tenant: &TenantId) -> BlobObjectKey {
        BlobObjectKey::new(
            tenant,
            archivist_protocol::vocabulary::StorageProfile::ZstdV1,
            &BlobDigest::parse(DIGEST).unwrap(),
        )
    }

    fn occurrence_manifest(tenant: &TenantId) -> ManifestKey {
        ManifestKey::Occurrence(OccurrenceObjectKey::new(
            tenant,
            &ClientId::parse(CLIENT).unwrap(),
            &HarnessId::parse(HARNESS).unwrap(),
            &SessionHash::parse(SESSION).unwrap(),
            &OccurrenceId::parse(OCCURRENCE).unwrap(),
        ))
    }

    fn attestation_manifest(tenant: &TenantId) -> ManifestKey {
        ManifestKey::Attestation(AttestationObjectKey::new(
            tenant,
            &OccurrenceId::parse(OCCURRENCE).unwrap(),
            &AttestationId::parse(ATTESTATION).unwrap(),
        ))
    }

    fn part_number(n: u16) -> PartNumber {
        PartNumber::new(n).unwrap()
    }

    fn part_bytes(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from(index % 251).expect("the remainder is below 251"))
            .collect()
    }

    /// A report that establishes conditional create and nothing else.
    fn supported() -> StoreCapabilities {
        StoreCapabilities {
            conditional_create: ConditionalCreate::Supported,
            ..StoreCapabilities::unprobed()
        }
    }

    fn writer(backend: MapBackend) -> S3RawWriteStore<MapBackend> {
        S3RawWriteStore::new(ingest_config(), tenant(), backend)
    }

    fn conditional_writer(backend: MapBackend) -> S3RawWriteStore<MapBackend> {
        writer(backend).with_capabilities(supported())
    }

    fn kind_of<T>(result: &Result<T, StorageError>) -> StorageErrorKind {
        match result {
            Ok(_) => panic!("this call must fail"),
            Err(error) => error.kind(),
        }
    }

    fn detail_of<T>(result: &Result<T, StorageError>) -> &'static str {
        match result {
            Ok(_) => panic!("this call must fail"),
            Err(error) => error.detail(),
        }
    }

    /// What the fault knobs can break, one operation at a time.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fault {
        None,
        Put,
        ConditionalPut,
        Begin,
        Part,
        Complete,
        Abort,
    }

    /// What an existing object's conditional refusal reports.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Evidence {
        /// Stored length and the backend-maintained SHA-256.
        Digest,
        /// Stored length only.
        SizeOnly,
        /// Presence without readable evidence.
        None,
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct Counters {
        requests: u32,
        puts: u32,
        conditional_puts: u32,
        begins: u32,
        parts: u32,
        completes: u32,
        aborts: u32,
        next_session: u32,
    }

    /// One mock session's uploaded parts, in push order.
    type MockParts = Vec<(u16, Vec<u8>)>;

    #[derive(Clone, Copy, Debug)]
    struct Knobs {
        fault: Fault,
        malformed_handle: bool,
        malformed_tag: bool,
    }

    /// The in-memory backend: an object map, an open-session map, and the
    /// prefix denial the deployment's raw-writer credential policy
    /// states. The check is the policy's own shape — a literal
    /// string-prefix rule over the key, create-and-multipart below
    /// `tenants/<tenant>/v1/raw/` and deny everything else — not a
    /// structural tenant compare, so the store's requests are proven to
    /// stay inside the prefix exactly as a live backend would grant or
    /// refuse them. Every request that reaches any verb is counted, so a
    /// test can prove a refused call never issued one.
    #[derive(Clone)]
    struct MapBackend {
        raw_prefix: String,
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        uploads: Arc<Mutex<HashMap<String, MockParts>>>,
        counters: Arc<Mutex<Counters>>,
        knobs: Arc<Mutex<Knobs>>,
        evidence: Evidence,
    }

    impl MapBackend {
        fn new(tenant: &TenantId) -> Self {
            Self {
                raw_prefix: format!("tenants/{tenant}/v1/raw/"),
                objects: Arc::new(Mutex::new(HashMap::new())),
                uploads: Arc::new(Mutex::new(HashMap::new())),
                counters: Arc::new(Mutex::new(Counters::default())),
                knobs: Arc::new(Mutex::new(Knobs {
                    fault: Fault::None,
                    malformed_handle: false,
                    malformed_tag: false,
                })),
                evidence: Evidence::Digest,
            }
        }

        fn with_evidence(mut self, evidence: Evidence) -> Self {
            self.evidence = evidence;
            self
        }

        /// The deployment policy for the raw-writer credential, as a
        /// grant predicate over one object key.
        fn policy_permits(&self, key: &str) -> bool {
            key.starts_with(&self.raw_prefix)
        }

        fn counters(&self) -> Counters {
            *self.counters.lock().expect("test backend lock")
        }

        fn stored(&self, key: &str) -> Option<Vec<u8>> {
            self.objects
                .lock()
                .expect("test backend lock")
                .get(key)
                .cloned()
        }

        fn open_sessions(&self) -> usize {
            self.uploads.lock().expect("test backend lock").len()
        }

        fn preload(&self, key: &str, bytes: &[u8]) {
            self.objects
                .lock()
                .expect("test backend lock")
                .insert(key.to_owned(), bytes.to_vec());
        }

        fn set_fault(&self, fault: Fault) {
            self.knobs.lock().expect("test backend lock").fault = fault;
        }

        fn set_malformed_handle(&self) {
            self.knobs
                .lock()
                .expect("test backend lock")
                .malformed_handle = true;
        }

        fn set_malformed_tag(&self) {
            self.knobs.lock().expect("test backend lock").malformed_tag = true;
        }

        /// Both malformation knobs are one-shot: a backend that mints one
        /// unusable handle or tag recovers on the next call, so a test
        /// can prove the session itself survives the malformed response.
        fn take_malformed_handle(&self) -> bool {
            let mut knobs = self.knobs.lock().expect("test backend lock");
            let armed = knobs.malformed_handle;
            knobs.malformed_handle = false;
            armed
        }

        fn take_malformed_tag(&self) -> bool {
            let mut knobs = self.knobs.lock().expect("test backend lock");
            let armed = knobs.malformed_tag;
            knobs.malformed_tag = false;
            armed
        }

        fn count_request(&self) {
            self.counters.lock().expect("test backend lock").requests += 1;
        }

        fn fails(&self, operation: Fault) -> bool {
            self.knobs.lock().expect("test backend lock").fault == operation
        }

        fn unavailable() -> StorageError {
            StorageError::of_kind(StorageErrorKind::Unavailable)
        }

        fn scope_violation() -> StorageError {
            StorageError::of_kind(StorageErrorKind::ScopeViolation)
        }
    }

    /// The mock's commitment tag for one part ordinal.
    fn etag_of(number: u16) -> String {
        format!("etag-{number}")
    }

    impl RawWriteBackend for MapBackend {
        async fn put_raw_object(
            &self,
            key: &RawObjectKey,
            bytes: &[u8],
        ) -> Result<(), StorageError> {
            self.count_request();
            if self.fails(Fault::Put) {
                return Err(Self::unavailable());
            }
            if !self.policy_permits(key.as_str()) {
                return Err(Self::scope_violation());
            }
            self.counters.lock().expect("test backend lock").puts += 1;
            self.objects
                .lock()
                .expect("test backend lock")
                .insert(key.as_str().to_owned(), bytes.to_vec());
            Ok(())
        }

        async fn create_raw_object_if_absent(
            &self,
            key: &RawObjectKey,
            bytes: &[u8],
        ) -> Result<CreateIfAbsent, StorageError> {
            self.count_request();
            if self.fails(Fault::ConditionalPut) {
                return Err(Self::unavailable());
            }
            if !self.policy_permits(key.as_str()) {
                return Err(Self::scope_violation());
            }
            self.counters
                .lock()
                .expect("test backend lock")
                .conditional_puts += 1;
            let existing = self
                .objects
                .lock()
                .expect("test backend lock")
                .get(key.as_str())
                .cloned();
            match existing {
                None => {
                    self.objects
                        .lock()
                        .expect("test backend lock")
                        .insert(key.as_str().to_owned(), bytes.to_vec());
                    Ok(CreateIfAbsent::Created)
                }
                Some(stored) => {
                    // Whatever readable evidence the deployment's backend
                    // could attach — the knob each classification case
                    // turns.
                    let size = u64::try_from(stored.len()).expect("a test length is a u64");
                    let evidence = match self.evidence {
                        Evidence::Digest => ExistingObject::new()
                            .with_size(size)
                            .with_stored_sha256(sha256::digest(&stored)),
                        Evidence::SizeOnly => ExistingObject::new().with_size(size),
                        Evidence::None => ExistingObject::new(),
                    };
                    Ok(CreateIfAbsent::AlreadyExists(evidence))
                }
            }
        }

        async fn create_multipart(&self, key: &RawObjectKey) -> Result<String, StorageError> {
            self.count_request();
            if self.fails(Fault::Begin) {
                return Err(Self::unavailable());
            }
            if !self.policy_permits(key.as_str()) {
                return Err(Self::scope_violation());
            }
            if self.take_malformed_handle() {
                // Contains a space, so no store can adopt it as a handle.
                return Ok("not a valid handle".to_owned());
            }
            let handle = {
                let mut counters = self.counters.lock().expect("test backend lock");
                counters.begins += 1;
                counters.next_session += 1;
                format!("mock-session-{}", counters.next_session)
            };
            self.uploads
                .lock()
                .expect("test backend lock")
                .insert(handle.clone(), Vec::new());
            Ok(handle)
        }

        async fn upload_part(
            &self,
            key: &RawObjectKey,
            session: &str,
            part: PartNumber,
            bytes: &[u8],
        ) -> Result<String, StorageError> {
            self.count_request();
            if self.fails(Fault::Part) {
                return Err(Self::unavailable());
            }
            if !self.policy_permits(key.as_str()) {
                return Err(Self::scope_violation());
            }
            if self.take_malformed_tag() {
                // Contains a space, so no store can adopt it as a tag.
                return Ok("not a valid tag".to_owned());
            }
            let mut uploads = self.uploads.lock().expect("test backend lock");
            let Some(parts) = uploads.get_mut(session) else {
                return Err(Self::unavailable());
            };
            parts.push((part.get(), bytes.to_vec()));
            drop(uploads);
            self.counters.lock().expect("test backend lock").parts += 1;
            Ok(etag_of(part.get()))
        }

        async fn complete_multipart(
            &self,
            key: &RawObjectKey,
            session: &str,
            parts: &[PartCommitment],
        ) -> Result<(), StorageError> {
            self.count_request();
            if self.fails(Fault::Complete) {
                return Err(Self::unavailable());
            }
            if !self.policy_permits(key.as_str()) {
                return Err(Self::scope_violation());
            }
            let Some(mut uploaded) = self
                .uploads
                .lock()
                .expect("test backend lock")
                .remove(session)
            else {
                return Err(Self::unavailable());
            };
            // The complete must present exactly the parts the session
            // holds, ordinal and tag alike — the same rule a live S3
            // complete enforces against its own session.
            uploaded.sort_by_key(|(number, _)| *number);
            let expected: Vec<(u16, String)> = uploaded
                .iter()
                .map(|(number, _)| (*number, etag_of(*number)))
                .collect();
            let presented: Vec<(u16, String)> = parts
                .iter()
                .map(|commitment| {
                    (
                        commitment.number().get(),
                        commitment.tag().as_str().to_owned(),
                    )
                })
                .collect();
            if presented != expected {
                return Err(Self::unavailable());
            }
            let mut assembled = Vec::new();
            for (_, bytes) in uploaded {
                assembled.extend_from_slice(&bytes);
            }
            self.objects
                .lock()
                .expect("test backend lock")
                .insert(key.as_str().to_owned(), assembled);
            self.counters.lock().expect("test backend lock").completes += 1;
            Ok(())
        }

        async fn abort_multipart(
            &self,
            key: &RawObjectKey,
            session: &str,
        ) -> Result<(), StorageError> {
            self.count_request();
            if self.fails(Fault::Abort) {
                return Err(Self::unavailable());
            }
            if !self.policy_permits(key.as_str()) {
                return Err(Self::scope_violation());
            }
            self.uploads
                .lock()
                .expect("test backend lock")
                .remove(session);
            self.counters.lock().expect("test backend lock").aborts += 1;
            Ok(())
        }
    }

    #[test]
    fn the_store_reports_the_capability_report_it_was_given() {
        let plain = writer(MapBackend::new(&tenant()));
        assert_eq!(plain.capabilities(), StoreCapabilities::unprobed());
        let conditional = conditional_writer(MapBackend::new(&tenant()));
        assert_eq!(conditional.capabilities(), supported());
    }

    #[test]
    fn the_raw_writer_role_is_the_configured_credential() {
        let store = writer(MapBackend::new(&tenant()));
        assert_eq!(
            store.raw_write_credentials(),
            ingest_config().identities().raw_write()
        );
        // The reference display is content-free by design; what the store
        // wires is the identity itself, not an echo of its text.
        assert_eq!(
            store.raw_write_credentials().to_string(),
            "credential-reference(file)"
        );
        assert_eq!(store.config().raw_bucket(), "archivist-raw-example");
        assert_eq!(store.tenant(), &tenant());
    }

    #[test]
    fn writer_only_manifests_commit_by_deterministic_overwrite() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());
        let key = occurrence_manifest(&tenant());

        let outcome = block_on(store.write_manifest(&key, b"occurrence-manifest")).unwrap();
        assert_eq!(
            outcome,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        let counters = backend.counters();
        assert_eq!(counters.puts, 1);
        assert_eq!(counters.conditional_puts, 0);
        assert_eq!(
            backend.stored(RawObjectKey::manifest(&key).as_str()),
            Some(b"occurrence-manifest".to_vec())
        );

        // The replay converges the only way a writer-only identity can
        // claim: same logical object, weaker physical result, and the
        // deterministic bytes stand at the key.
        let replay = block_on(store.write_manifest(&key, b"occurrence-manifest")).unwrap();
        assert_eq!(
            replay,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        assert_eq!(backend.counters().puts, 2);
        assert_eq!(
            backend.stored(RawObjectKey::manifest(&key).as_str()),
            Some(b"occurrence-manifest".to_vec())
        );
    }

    #[test]
    fn manifest_bounds_are_refused_before_any_request() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());
        let key = occurrence_manifest(&tenant());
        let oversized = vec![0u8; CANONICAL_MAX_BYTES + 1];

        let empty = block_on(store.write_manifest(&key, b""));
        assert_eq!(kind_of(&empty), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&empty), super::DETAIL_EMPTY_MANIFEST);
        let too_big = block_on(store.write_manifest(&key, &oversized));
        assert_eq!(kind_of(&too_big), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&too_big), super::DETAIL_OVERSIZED_MANIFEST);
        assert_eq!(backend.counters().requests, 0);

        // The conditional profile enforces the same bound before its
        // atomic primitive is ever attempted.
        let conditional = conditional_writer(backend.clone());
        let direct = block_on(ConditionalCreateStore::create_manifest_if_absent(
            &conditional,
            &key,
            b"",
        ));
        assert_eq!(kind_of(&direct), StorageErrorKind::MalformedInput);
        assert_eq!(backend.counters().requests, 0);
    }

    #[test]
    fn conditional_profiles_use_the_atomic_primitive() {
        let backend = MapBackend::new(&tenant());
        let store = conditional_writer(backend.clone());

        let outcome =
            block_on(store.write_manifest(&occurrence_manifest(&tenant()), b"occurrence-manifest"))
                .unwrap();
        assert_eq!(outcome, StorageOutcome::Created);
        let outcome = block_on(
            store.write_manifest(&attestation_manifest(&tenant()), b"attestation-manifest"),
        )
        .unwrap();
        assert_eq!(outcome, StorageOutcome::Created);

        let counters = backend.counters();
        assert_eq!(counters.conditional_puts, 2);
        assert_eq!(counters.puts, 0);
    }

    #[test]
    fn conditional_replays_classify_readable_evidence() {
        let key = occurrence_manifest(&tenant());
        let raw = RawObjectKey::manifest(&key);

        // Readable digest evidence proving equality converges on the
        // existing object: already present, no overwrite issued.
        let backend = MapBackend::new(&tenant()).with_evidence(Evidence::Digest);
        backend.preload(raw.as_str(), b"occurrence-manifest");
        let store = conditional_writer(backend.clone());
        let outcome = block_on(store.write_manifest(&key, b"occurrence-manifest")).unwrap();
        assert_eq!(outcome, StorageOutcome::AlreadyPresent);
        assert_eq!(backend.counters().puts, 0);
        assert_eq!(
            backend.stored(raw.as_str()),
            Some(b"occurrence-manifest".to_vec())
        );

        // Digest evidence contradicting the bytes is an integrity
        // conflict, and whatever was there keeps standing.
        let backend = MapBackend::new(&tenant()).with_evidence(Evidence::Digest);
        backend.preload(raw.as_str(), b"different-manifest");
        let store = conditional_writer(backend.clone());
        let conflict = block_on(store.write_manifest(&key, b"occurrence-manifest"));
        assert_eq!(kind_of(&conflict), StorageErrorKind::IntegrityConflict);
        assert_eq!(
            backend.stored(raw.as_str()),
            Some(b"different-manifest".to_vec())
        );

        // A length that matches proves nothing about content: the weaker
        // physical result, never deduplication.
        let backend = MapBackend::new(&tenant()).with_evidence(Evidence::SizeOnly);
        backend.preload(raw.as_str(), b"MANIFEST-occurrence");
        let store = conditional_writer(backend.clone());
        let outcome = block_on(store.write_manifest(&key, b"occurrence-manifest")).unwrap();
        assert_eq!(
            outcome,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );

        // A length that contradicts is a conflict, evidence or not.
        let backend = MapBackend::new(&tenant()).with_evidence(Evidence::SizeOnly);
        backend.preload(raw.as_str(), b"other-length");
        let store = conditional_writer(backend.clone());
        let conflict = block_on(store.write_manifest(&key, b"occurrence-manifest"));
        assert_eq!(kind_of(&conflict), StorageErrorKind::IntegrityConflict);

        // Presence without readable evidence resolves the same honest way.
        let backend = MapBackend::new(&tenant()).with_evidence(Evidence::None);
        backend.preload(raw.as_str(), b"different-manifest");
        let store = conditional_writer(backend.clone());
        let outcome = block_on(store.write_manifest(&key, b"occurrence-manifest")).unwrap();
        assert_eq!(
            outcome,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
    }

    #[test]
    fn the_conditional_primitive_refuses_an_unreported_capability() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());
        let key = occurrence_manifest(&tenant());

        let refused = block_on(store.create_manifest_if_absent(&key, b"occurrence-manifest"));
        assert_eq!(kind_of(&refused), StorageErrorKind::CapabilityUnavailable);
        assert_eq!(detail_of(&refused), super::DETAIL_CONDITIONAL);
        assert_eq!(backend.counters().requests, 0);
    }

    #[test]
    fn foreign_keys_are_refused_before_any_request() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());
        let other = other_tenant();

        for key in [occurrence_manifest(&other), attestation_manifest(&other)] {
            let refused = block_on(store.write_manifest(&key, b"manifest"));
            assert_eq!(kind_of(&refused), StorageErrorKind::ScopeViolation);
            assert_eq!(detail_of(&refused), super::DETAIL_SCOPE);
        }
        let refused = block_on(store.begin_multipart(&blob_key(&other)));
        assert_eq!(kind_of(&refused), StorageErrorKind::ScopeViolation);
        assert_eq!(backend.counters().requests, 0);
    }

    #[test]
    fn the_scope_model_admits_only_the_pinned_raw_layouts() {
        let store = writer(MapBackend::new(&tenant()));
        let tenant = tenant();

        for admitted in [
            blob_key(&tenant).as_str().to_owned(),
            RawObjectKey::manifest(&occurrence_manifest(&tenant))
                .as_str()
                .to_owned(),
            RawObjectKey::manifest(&attestation_manifest(&tenant))
                .as_str()
                .to_owned(),
        ] {
            assert!(store.permits_key(&admitted), "{admitted} must be admitted");
            assert_eq!(RawObjectKey::parse(&admitted).unwrap().as_str(), admitted);
            assert_eq!(
                RawObjectKey::parse(&admitted).unwrap().tenant(),
                TENANT,
                "the pinned tenant is the key's own tenant segment"
            );
        }

        // Every other tenant, every other prefix, and a raw layout whose
        // shard coupling disagrees: denied rather than normalized.
        let blob = blob_key(&tenant).as_str().to_owned();
        let bad_shard = blob.replacen("/01/", "/99/", 1);
        for denied in [
            blob_key(&other_tenant()).as_str().to_owned(),
            format!("tenants/{tenant}/v1/control/linked-clients/{CLIENT}.json"),
            format!("tenants/{tenant}/v1/catalog/checkpoints/latest.json"),
            format!("tenants/{tenant}/v1/derived/indexes/main.bin"),
            bad_shard,
            String::new(),
            "tenants".to_owned(),
        ] {
            assert!(!store.permits_key(&denied), "{denied} must be denied");
        }
    }

    #[test]
    fn multipart_commits_exactly_the_session_commitments() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());
        let blob = blob_key(&tenant());

        let upload = block_on(store.begin_multipart(&blob)).unwrap();
        let first =
            block_on(store.write_part(&upload, part_number(1), &part_bytes(PART_BYTES))).unwrap();
        let second =
            block_on(store.write_part(&upload, part_number(2), &part_bytes(PART_BYTES))).unwrap();
        let tail = block_on(store.write_part(&upload, part_number(3), &part_bytes(9))).unwrap();
        let recorded = [first, second, tail];

        let outcome = block_on(store.commit_multipart(&upload, &recorded)).unwrap();
        assert_eq!(
            outcome,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );

        let mut expected = part_bytes(PART_BYTES);
        expected.extend(part_bytes(PART_BYTES));
        expected.extend(part_bytes(9));
        assert_eq!(backend.stored(blob.as_str()), Some(expected));
        assert_eq!(backend.counters().completes, 1);
        assert_eq!(backend.open_sessions(), 0);
    }

    #[test]
    fn commit_reports_the_weaker_physical_result_on_every_profile() {
        // Even the profile that just proved conditional create cannot
        // learn from a complete response what it wrote over.
        let backend = MapBackend::new(&tenant());
        let store = conditional_writer(backend.clone());
        let upload = block_on(store.begin_multipart(&blob_key(&tenant()))).unwrap();
        let part = block_on(store.write_part(&upload, part_number(1), &part_bytes(9))).unwrap();
        let outcome = block_on(store.commit_multipart(&upload, &[part])).unwrap();
        assert_eq!(
            outcome,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
    }

    #[test]
    fn parts_arrive_in_order_within_bounds_or_not_at_all() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());
        let upload = block_on(store.begin_multipart(&blob_key(&tenant()))).unwrap();

        // A gap first: part 2 cannot precede part 1.
        let gap = block_on(store.write_part(&upload, part_number(2), &part_bytes(9)));
        assert_eq!(kind_of(&gap), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&gap), super::DETAIL_PART_SEQUENCE);
        assert_eq!(backend.counters().parts, 0);

        block_on(store.write_part(&upload, part_number(1), &part_bytes(PART_BYTES))).unwrap();

        // A replay of part 1 is out of sequence, not idempotent.
        let replay = block_on(store.write_part(&upload, part_number(1), &part_bytes(9)));
        assert_eq!(kind_of(&replay), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&replay), super::DETAIL_PART_SEQUENCE);
        assert_eq!(backend.counters().parts, 1);

        let empty = block_on(store.write_part(&upload, part_number(2), b""));
        assert_eq!(kind_of(&empty), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&empty), super::DETAIL_PART_BOUNDS);
        let oversized =
            block_on(store.write_part(&upload, part_number(2), &part_bytes(PART_BYTES + 1)));
        assert_eq!(kind_of(&oversized), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&oversized), super::DETAIL_PART_BOUNDS);
        assert_eq!(backend.counters().parts, 1);

        block_on(store.write_part(&upload, part_number(2), &part_bytes(9))).unwrap();
        assert_eq!(backend.counters().parts, 2);
    }

    #[test]
    fn unknown_and_ended_sessions_are_malformed_input() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());
        let stranger = MultipartUploadId::parse("never-begun").unwrap();

        let part = block_on(store.write_part(&stranger, part_number(1), b"part"));
        assert_eq!(kind_of(&part), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&part), super::DETAIL_UNKNOWN_SESSION);
        let commit = block_on(store.commit_multipart(&stranger, &[]));
        assert_eq!(kind_of(&commit), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&commit), super::DETAIL_UNKNOWN_SESSION);

        let upload = block_on(store.begin_multipart(&blob_key(&tenant()))).unwrap();
        let part = block_on(store.write_part(&upload, part_number(1), b"part")).unwrap();
        block_on(store.commit_multipart(&upload, &[part])).unwrap();

        let ended = block_on(store.write_part(&upload, part_number(2), b"part"));
        assert_eq!(kind_of(&ended), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&ended), super::DETAIL_ENDED_SESSION);
        let ended = block_on(store.commit_multipart(&upload, &[]));
        assert_eq!(kind_of(&ended), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&ended), super::DETAIL_ENDED_SESSION);
    }

    #[test]
    fn inconsistent_commitment_sets_never_reach_the_backend_complete() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());
        let upload = block_on(store.begin_multipart(&blob_key(&tenant()))).unwrap();
        let first = block_on(store.write_part(&upload, part_number(1), b"first")).unwrap();
        let second = block_on(store.write_part(&upload, part_number(2), b"second")).unwrap();

        let empty = block_on(store.commit_multipart(&upload, &[]));
        assert_eq!(kind_of(&empty), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&empty), super::DETAIL_EMPTY_COMMITMENTS);

        let subset = block_on(store.commit_multipart(&upload, std::slice::from_ref(&first)));
        assert_eq!(kind_of(&subset), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&subset), super::DETAIL_MISMATCHED_COMMITMENTS);

        let substituted = block_on(store.commit_multipart(
            &upload,
            &[
                first.clone(),
                PartCommitment::new(part_number(2), ObjectTag::parse("etag-999").unwrap()),
            ],
        ));
        assert_eq!(kind_of(&substituted), StorageErrorKind::MalformedInput);
        assert_eq!(
            detail_of(&substituted),
            super::DETAIL_MISMATCHED_COMMITMENTS
        );

        let reordered = block_on(store.commit_multipart(&upload, &[second, first]));
        assert_eq!(kind_of(&reordered), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&reordered), super::DETAIL_MISMATCHED_COMMITMENTS);

        assert_eq!(backend.counters().completes, 0);
        // The session is still open, so the caller's abort still works —
        // the only honest exit from a session that cannot commit.
        block_on(store.abort_multipart(&upload)).unwrap();
        assert_eq!(backend.counters().aborts, 1);
    }

    #[test]
    fn abort_is_idempotent_cleanup() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());

        let upload = block_on(store.begin_multipart(&blob_key(&tenant()))).unwrap();
        block_on(store.write_part(&upload, part_number(1), b"part")).unwrap();
        block_on(store.abort_multipart(&upload)).unwrap();
        assert_eq!(backend.counters().aborts, 1);
        assert_eq!(backend.open_sessions(), 0);

        // The repeat succeeds and issues nothing: the session ended, and
        // cleanup must be idempotent.
        block_on(store.abort_multipart(&upload)).unwrap();
        assert_eq!(backend.counters().aborts, 1);

        // A committed session is just as ended.
        let upload = block_on(store.begin_multipart(&blob_key(&tenant()))).unwrap();
        let part = block_on(store.write_part(&upload, part_number(1), b"part")).unwrap();
        block_on(store.commit_multipart(&upload, &[part])).unwrap();
        block_on(store.abort_multipart(&upload)).unwrap();
        assert_eq!(backend.counters().aborts, 1);

        // A handle this store never minted is not cleanup; it is not
        // anything, and it fails as malformed input.
        let stranger = MultipartUploadId::parse("never-begun").unwrap();
        let refused = block_on(store.abort_multipart(&stranger));
        assert_eq!(kind_of(&refused), StorageErrorKind::MalformedInput);
        assert_eq!(detail_of(&refused), super::DETAIL_UNKNOWN_SESSION);
    }

    #[test]
    fn backend_faults_surface_as_unavailable_and_leave_cleanup_open() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());

        backend.set_fault(Fault::Put);
        let failed = block_on(store.write_manifest(&occurrence_manifest(&tenant()), b"manifest"));
        assert_eq!(kind_of(&failed), StorageErrorKind::Unavailable);

        backend.set_fault(Fault::ConditionalPut);
        let conditional = conditional_writer(backend.clone());
        let failed = block_on(conditional.write_manifest(&occurrence_manifest(&tenant()), b"m"));
        assert_eq!(kind_of(&failed), StorageErrorKind::Unavailable);

        backend.set_fault(Fault::Begin);
        let failed = block_on(store.begin_multipart(&blob_key(&tenant())));
        assert_eq!(kind_of(&failed), StorageErrorKind::Unavailable);

        backend.set_fault(Fault::None);
        let upload = block_on(store.begin_multipart(&blob_key(&tenant()))).unwrap();

        // A part lost in flight leaves the session open: the caller
        // aborts, and that abort still reaches the backend.
        backend.set_fault(Fault::Part);
        let failed = block_on(store.write_part(&upload, part_number(1), b"part"));
        assert_eq!(kind_of(&failed), StorageErrorKind::Unavailable);
        backend.set_fault(Fault::None);
        block_on(store.abort_multipart(&upload)).unwrap();
        assert_eq!(backend.counters().aborts, 1);

        // A commit lost in flight does the same — the session is never
        // retried (EC-10), only aborted.
        let upload = block_on(store.begin_multipart(&blob_key(&tenant()))).unwrap();
        let part = block_on(store.write_part(&upload, part_number(1), b"part")).unwrap();
        backend.set_fault(Fault::Complete);
        let failed = block_on(store.commit_multipart(&upload, &[part]));
        assert_eq!(kind_of(&failed), StorageErrorKind::Unavailable);
        assert_eq!(backend.counters().completes, 0);
        backend.set_fault(Fault::None);
        block_on(store.abort_multipart(&upload)).unwrap();
        assert_eq!(backend.counters().aborts, 2);

        // A failed abort stays registered for a later drain to retry.
        let upload = block_on(store.begin_multipart(&blob_key(&tenant()))).unwrap();
        backend.set_fault(Fault::Abort);
        let failed = block_on(store.abort_multipart(&upload));
        assert_eq!(kind_of(&failed), StorageErrorKind::Unavailable);
        backend.set_fault(Fault::None);
        block_on(store.abort_multipart(&upload)).unwrap();
        assert_eq!(backend.counters().aborts, 3);
    }

    #[test]
    fn malformed_backend_handles_and_tags_fail_closed() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());

        // A handle outside the grammar is never a session, even though
        // the backend minted it: nothing opens at the backend and nothing
        // is registered here.
        backend.set_malformed_handle();
        let failed = block_on(store.begin_multipart(&blob_key(&tenant())));
        assert_eq!(kind_of(&failed), StorageErrorKind::Unavailable);
        assert_eq!(detail_of(&failed), super::DETAIL_MALFORMED_HANDLE);
        assert_eq!(backend.open_sessions(), 0);
        let stranger = MultipartUploadId::parse("mock-session-1").unwrap();
        let orphan = block_on(store.write_part(&stranger, part_number(1), b"part"));
        assert_eq!(kind_of(&orphan), StorageErrorKind::MalformedInput);

        // A tag outside the grammar is never a commitment; the session
        // itself stays usable.
        backend.set_malformed_tag();
        let upload = block_on(store.begin_multipart(&blob_key(&tenant()))).unwrap();
        let failed = block_on(store.write_part(&upload, part_number(1), b"part"));
        assert_eq!(kind_of(&failed), StorageErrorKind::Unavailable);
        assert_eq!(detail_of(&failed), super::DETAIL_MALFORMED_TAG);
        backend.set_fault(Fault::None);
        let recovered = block_on(store.write_part(&upload, part_number(1), b"part"));
        assert!(recovered.is_ok());
    }

    #[test]
    fn the_streaming_writer_drives_this_store() {
        let backend = MapBackend::new(&tenant());
        let store = writer(backend.clone());
        let open = OpenUploads::new();
        let blob = blob_key(&tenant());

        // One blob over the part boundary: two parts, one small tail,
        // committed through the streaming writer's own sequencing.
        let payload = part_bytes(PART_BYTES + 5);
        let mut session = block_on(MultipartWriter::begin(&store, &blob, &open)).unwrap();
        block_on(session.write_chunk(&payload)).unwrap();
        block_on(session.finish()).unwrap();
        let outcome = block_on(session.commit()).unwrap();
        assert_eq!(
            outcome,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        assert_eq!(backend.stored(blob.as_str()), Some(payload));
        assert_eq!(backend.counters().completes, 1);

        // Cancellation safety end to end: a writer dropped mid-stream
        // leaves its session registered as abandoned, and the drain
        // aborts exactly that session at this store.
        let mut abandoned = block_on(MultipartWriter::begin(&store, &blob, &open)).unwrap();
        block_on(abandoned.write_chunk(&part_bytes(64))).unwrap();
        drop(abandoned);
        assert_eq!(open.abandoned_count(), 1);
        let failures = block_on(open.abort_abandoned(&store));
        assert!(failures.is_empty());
        assert_eq!(backend.counters().aborts, 1);
        assert_eq!(backend.open_sessions(), 0);
    }

    #[test]
    fn every_error_detail_is_a_safe_message() {
        // Every static detail this module can emit stays inside the
        // project's safe-message grammar.
        for detail in [
            super::DETAIL_SCOPE,
            super::DETAIL_UNKNOWN_SESSION,
            super::DETAIL_ENDED_SESSION,
            super::DETAIL_PART_SEQUENCE,
            super::DETAIL_PART_BOUNDS,
            super::DETAIL_EMPTY_COMMITMENTS,
            super::DETAIL_MISMATCHED_COMMITMENTS,
            super::DETAIL_EMPTY_MANIFEST,
            super::DETAIL_OVERSIZED_MANIFEST,
            super::DETAIL_MALFORMED_HANDLE,
            super::DETAIL_DUPLICATE_HANDLE,
            super::DETAIL_MALFORMED_TAG,
            super::DETAIL_CONDITIONAL,
        ] {
            assert_eq!(
                SafeMessage::parse(detail)
                    .unwrap_or_else(|_| panic!("detail is not safe: {detail}"))
                    .as_str(),
                detail
            );
        }
    }
}
