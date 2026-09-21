// SPDX-License-Identifier: Apache-2.0

//! The content-addressed blob commit path: drive one canonical payload
//! through the pinned storage encoder and a streaming multipart session,
//! and complete the session only after the payload's identity verifies —
//! the write half of plan Section 7.7 on top of
//! [`crate::multipart::MultipartWriter`].
//!
//! [`commit_blob`] is the whole path in one call. It opens an uncommitted
//! multipart session under the blob key derived from the *declared*
//! content digest (the claimed address), streams the canonical chunks
//! through the caller-supplied [`BlobEncoder`] and the writer while
//! accumulating the computed identity, and reaches
//! [`crate::multipart::MultipartWriter::commit`] only after every check
//! the caller's declaration makes possible has passed:
//!
//! - **Digest (VAL-004, VAL-005)** — the SHA-256 accumulated over the
//!   canonical stream must equal the declared [`BlobDigest`]. The key was
//!   derived from the declared value, so this check is what makes the
//!   content-addressed claim true: a mismatch aborts the session, and
//!   nothing ever lands under an address its content does not hash to
//!   (STO-001; protocol Section 3.1 — the declared digest is evidence,
//!   and the commit is what promotes a verified computation into the
//!   address).
//! - **Size (VAL-003, VAL-005)** — the decoded canonical byte count must
//!   equal the declared uncompressed size.
//! - **Part discipline (VAL-008)** — the writer enforces the pinned part
//!   bounds on the stored stream: every part except the last is exactly
//!   [`crate::multipart::PART_BYTES`], so a body whose stored form is
//!   below the part threshold is simply a single-part session — the
//!   simplest shape of the same machinery. The raw-write trait
//!   deliberately has no plain `PUT` for blob keys (blob writes are
//!   sessions, so an invalid stream is always abortable before anything
//!   is visible), and this layer does not widen that surface.
//!
//! An interrupted or invalid stream never completes a content-addressed
//! object: every validation and encoder failure aborts the live session,
//! writer-originated failures carry the abort the writer already
//! attempted, and an abort that itself fails rides along in
//! [`BlobCommitError::cleanup`] while the session stays registered in
//! [`crate::multipart::OpenUploads`] for a later drain — never swallowed.
//!
//! # Retry convergence (STO-004)
//!
//! A replay of the same canonical body computes the same digest, derives
//! the same key, and produces the same stored bytes (the profile's
//! deterministic encoder, VAL-006), so both attempts converge on one
//! logical blob object with no duplicate visible at the key. Which
//! physical story the backend can tell about the replay is exactly the
//! [`StorageOutcome`] the store's `commit_multipart` reports — the
//! honest profile truth (RCPT-003, RCPT-004; protocol Section 4.4),
//! passed through untouched: this layer adds validation and sequencing,
//! never a stronger claim than the store made.
//!
//! # The encoder seam
//!
//! [`BlobEncoder`] is the pinned storage transform the caller supplies.
//! Version 1 has exactly one profile, `zstd-v1` (protocol Section 3.2),
//! and the commit layer pins it in every key it derives — but the
//! encoder implementation itself arrives with the streaming-pipeline
//! deliverable, so the trait carries only the streaming contract:
//! `update` compresses canonical chunks, `finish` emits the frame
//! epilogue, and the two together must produce the deterministic
//! canonical form VAL-006 requires. The commit layer cannot verify
//! determinism; it reports the stored form's length and SHA-256 in
//! [`BlobCommit`] so callers, conformance vectors, and backends that
//! maintain stored-content checksums (STO-001) can pin it.

use std::fmt;

use archivist_protocol::object_key::BlobObjectKey;
use archivist_protocol::sha256::Sha256;
use archivist_protocol::vocabulary::{BlobDigest, StorageOutcome, StorageProfile, TenantId};

use crate::error::{StorageError, StorageErrorKind};
use crate::multipart::{MultipartWriter, MultipartWriterError, OpenUploads};
use crate::raw_write::RawWriteStore;

/// The static detail for a canonical stream whose computed digest does not
/// match the declared content address.
const DIGEST_MISMATCH_DETAIL: &str =
    "computed canonical digest does not match the declared blob digest";
/// The static detail for a canonical stream whose decoded length does not
/// match the declared uncompressed size.
const SIZE_MISMATCH_DETAIL: &str = "decoded canonical size does not match the declared size";

/// The declared identity a streamed blob body must verify against before
/// the session may complete.
///
/// Both members come from the request envelope (protocol Section 3.1):
/// the digest names the content address the write claims, and the size is
/// the declared uncompressed extent. Neither is trusted as truth — they
/// are the standard the computed stream is held to, and a mismatch aborts
/// the uncommitted write (VAL-005).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobExpectation {
    content: BlobDigest,
    uncompressed_bytes: u64,
}

impl BlobExpectation {
    /// Declare the content address and uncompressed extent of one blob.
    #[must_use]
    pub const fn new(content: BlobDigest, uncompressed_bytes: u64) -> Self {
        Self {
            content,
            uncompressed_bytes,
        }
    }

    /// The declared content digest — the blob key's authority (STO-001).
    #[must_use]
    pub const fn content(&self) -> &BlobDigest {
        &self.content
    }

    /// The declared uncompressed payload extent.
    #[must_use]
    pub const fn uncompressed_bytes(&self) -> u64 {
        self.uncompressed_bytes
    }
}

/// The pinned storage transform the caller supplies: canonical bytes in,
/// stored-form bytes out (protocol Section 3.2).
///
/// The `zstd-v1` implementation is [`crate::zstd_v1::ZstdV1Encoder`]; this
/// trait is the seam the commit path drives, so the pipeline stays codec-
/// agnostic at the type level. The two
/// calls compose one stream: `update` per canonical chunk, then `finish`
/// exactly once to emit the frame epilogue. Implementations must produce
/// the deterministic canonical form VAL-006 pins — identical canonical
/// bytes, identical stored bytes, on every platform and retry — and must
/// be [`Send`], because one commit future may run on any worker thread.
pub trait BlobEncoder: Send {
    /// Compress one canonical chunk, appending stored output to `out`.
    ///
    /// `out` is caller-owned scratch the commit layer drains after every
    /// call, so an implementation never holds payload scale beyond its
    /// own encoder state.
    ///
    /// # Errors
    /// The encoder's own failure class (a malformed stream it rejects);
    /// the commit aborts the session and never completes.
    fn update(&mut self, canonical: &[u8], out: &mut Vec<u8>) -> Result<(), StorageError>;

    /// End the canonical stream, appending any final stored output.
    ///
    /// # Errors
    /// The encoder's own failure class; the commit aborts the session and
    /// never completes.
    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), StorageError>;
}

/// What one successful blob commit established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobCommit {
    key: BlobObjectKey,
    outcome: StorageOutcome,
    uncompressed_bytes: u64,
    stored_bytes: u64,
    stored_sha256: [u8; 32],
    parts: usize,
}

impl BlobCommit {
    /// The content-addressed key the object is visible at.
    #[must_use]
    pub const fn key(&self) -> &BlobObjectKey {
        &self.key
    }

    /// The outcome the store reported — the profile physical truth, never
    /// strengthened here (RCPT-003).
    #[must_use]
    pub const fn outcome(&self) -> StorageOutcome {
        self.outcome
    }

    /// The verified canonical byte count.
    #[must_use]
    pub const fn uncompressed_bytes(&self) -> u64 {
        self.uncompressed_bytes
    }

    /// The stored form's byte count, as streamed to the backend.
    #[must_use]
    pub const fn stored_bytes(&self) -> u64 {
        self.stored_bytes
    }

    /// The stored form's SHA-256, accumulated over the bytes streamed —
    /// the pin callers and stored-checksum backends can check (STO-001).
    #[must_use]
    pub const fn stored_sha256(&self) -> &[u8; 32] {
        &self.stored_sha256
    }

    /// Parts the session committed.
    #[must_use]
    pub const fn parts(&self) -> usize {
        self.parts
    }
}

/// Why a blob commit failed: the primary failure, plus the cleanup abort
/// failure when that abort was attempted and did not succeed.
///
/// The same content-safe composite as the multipart writer's error: the
/// cleanup half is the visibility contract (the VAL-008 abort must not be
/// lost), and neither half can echo keys or payload content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlobCommitError {
    failure: StorageError,
    cleanup: Option<StorageError>,
}

impl BlobCommitError {
    /// Build an error with no cleanup failure (no abort was attempted, or
    /// the abort succeeded).
    #[must_use]
    pub const fn new(failure: StorageError) -> Self {
        Self {
            failure,
            cleanup: None,
        }
    }

    /// Build an error whose cleanup abort also failed.
    #[must_use]
    pub const fn with_cleanup(failure: StorageError, cleanup: StorageError) -> Self {
        Self {
            failure,
            cleanup: Some(cleanup),
        }
    }

    /// The primary failure class.
    #[must_use]
    pub const fn kind(&self) -> StorageErrorKind {
        self.failure.kind()
    }

    /// What went wrong.
    #[must_use]
    pub const fn failure(&self) -> StorageError {
        self.failure
    }

    /// The cleanup abort failure, when the abort was attempted and did
    /// not succeed.
    #[must_use]
    pub const fn cleanup(&self) -> Option<StorageError> {
        self.cleanup
    }
}

impl fmt::Display for BlobCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.cleanup {
            None => write!(f, "blob commit failed: {}", self.failure),
            Some(cleanup) => write!(
                f,
                "blob commit failed: {}; cleanup abort failed: {cleanup}",
                self.failure
            ),
        }
    }
}

impl std::error::Error for BlobCommitError {}

/// Commit one canonical payload as a content-addressed blob.
///
/// Streams `canonical` through `encoder` and one uncommitted multipart
/// session under the key derived from `expectation`'s declared digest,
/// validates the computed identity against the declaration, and completes
/// the session only then — the validate-before-complete contract of plan
/// Section 7.7. A validation failure, an encoder failure, or any store
/// failure leaves the key without a committed object: validation and
/// encoder failures abort the live session, writer failures carry the
/// abort the writer already attempted.
///
/// The canonical iterable is consumed synchronously; the async streaming
/// adaptation (transport decode, expansion checks, request deadlines) is
/// the server pipeline's, which feeds this path chunk by chunk at the
/// plan's 16 MiB target chunk size.
///
/// # Errors
/// [`BlobCommitError::failure`] with
/// [`StorageErrorKind::IntegrityConflict`] when the computed digest does
/// not match the declared content address,
/// [`StorageErrorKind::MalformedInput`] when the decoded size does not
/// match the declared extent or the encoder rejects the stream, or the
/// store's own failure otherwise; a failed cleanup abort rides along in
/// [`BlobCommitError::cleanup`], and the session stays registered in
/// `open` for a later drain in that case.
pub async fn commit_blob<S, E, I>(
    store: &S,
    open: &OpenUploads,
    tenant: &TenantId,
    expectation: BlobExpectation,
    encoder: &mut E,
    canonical: I,
) -> Result<BlobCommit, BlobCommitError>
where
    S: RawWriteStore + ?Sized,
    E: BlobEncoder,
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    // The claimed address: derived from the declared digest, exactly as
    // the protocol's server-side derivation pins it (STO-003; protocol
    // Section 3.1). The digest validation below is what makes the claim
    // true before anything completes under it.
    let key = BlobObjectKey::new(tenant, StorageProfile::ZstdV1, expectation.content());
    let mut writer = MultipartWriter::begin(store, &key, open).await.map_err(
        |error: MultipartWriterError| BlobCommitError {
            failure: error.failure(),
            cleanup: error.cleanup(),
        },
    )?;

    let mut canonical_hasher = Sha256::new();
    let mut canonical_bytes: u64 = 0;
    let mut stored_hasher = Sha256::new();
    let mut stored_bytes: u64 = 0;
    let mut stored = Vec::new();

    for chunk in canonical {
        let chunk = chunk.as_ref();
        canonical_hasher.update(chunk);
        canonical_bytes = canonical_bytes.saturating_add(chunk.len() as u64);
        stored.clear();
        // An encoder failure leaves the session live; a writer failure
        // cleaned up after itself. Either way nothing is committed.
        if let Err(failure) = encoder.update(chunk, &mut stored) {
            return Err(abort_writer(writer, failure).await);
        }
        drain_encoded(
            &mut writer,
            &mut stored,
            &mut stored_hasher,
            &mut stored_bytes,
        )
        .await?;
    }
    stored.clear();
    if let Err(failure) = encoder.finish(&mut stored) {
        return Err(abort_writer(writer, failure).await);
    }
    drain_encoded(
        &mut writer,
        &mut stored,
        &mut stored_hasher,
        &mut stored_bytes,
    )
    .await?;
    if let Err(error) = writer.finish().await {
        return Err(BlobCommitError {
            failure: error.failure(),
            cleanup: error.cleanup(),
        });
    }

    // Validate-before-complete: the session is finished and uncommitted;
    // these are the last checks between the stream and the address. Each
    // mismatch aborts the live session so the claimed address stays
    // empty (VAL-005).
    if canonical_hasher.finalize() != *expectation.content().as_raw() {
        let failure =
            StorageError::new(StorageErrorKind::IntegrityConflict, DIGEST_MISMATCH_DETAIL);
        return Err(abort_writer(writer, failure).await);
    }
    if canonical_bytes != expectation.uncompressed_bytes() {
        let failure = StorageError::new(StorageErrorKind::MalformedInput, SIZE_MISMATCH_DETAIL);
        return Err(abort_writer(writer, failure).await);
    }

    let stored_sha256 = stored_hasher.finalize();
    let parts = writer.part_count();
    match writer.commit().await {
        Ok(outcome) => Ok(BlobCommit {
            key,
            outcome,
            uncompressed_bytes: canonical_bytes,
            stored_bytes,
            stored_sha256,
            parts,
        }),
        Err(error) => Err(BlobCommitError {
            failure: error.failure(),
            cleanup: error.cleanup(),
        }),
    }
}

/// Drain one batch of encoded output through the writer, accumulating the
/// stored form's evidence. A writer failure needs no further abort — the
/// writer already attempted one and reported it in the error.
async fn drain_encoded<S: RawWriteStore + ?Sized>(
    writer: &mut MultipartWriter<'_, S>,
    encoded: &mut [u8],
    stored_hasher: &mut Sha256,
    stored_bytes: &mut u64,
) -> Result<(), BlobCommitError> {
    if encoded.is_empty() {
        return Ok(());
    }
    stored_hasher.update(encoded);
    *stored_bytes = stored_bytes.saturating_add(encoded.len() as u64);
    writer
        .write_chunk(encoded)
        .await
        .map_err(|error| BlobCommitError {
            failure: error.failure(),
            cleanup: error.cleanup(),
        })
}

/// Abort `writer` because `failure` ended the commit, surfacing a failed
/// cleanup abort alongside it.
async fn abort_writer<S: RawWriteStore + ?Sized>(
    writer: MultipartWriter<'_, S>,
    failure: StorageError,
) -> BlobCommitError {
    match writer.abort().await {
        Ok(()) => BlobCommitError::new(failure),
        Err(cleanup) => BlobCommitError::with_cleanup(failure, cleanup),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use archivist_protocol::object_key::BlobObjectKey;
    use archivist_protocol::sha256;
    use archivist_protocol::vocabulary::{
        BlobDigest, SafeMessage, StorageOutcome, StorageProfile, TenantId,
    };

    use super::{BlobCommit, BlobCommitError, BlobEncoder, BlobExpectation, commit_blob};
    use crate::capability::{
        ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
    };
    use crate::error::{StorageError, StorageErrorKind};
    use crate::metadata::ObjectTag;
    use crate::multipart::{OpenUploads, PART_BYTES};
    use crate::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const BODY: &[u8] = b"archivist zstd-v1 canonical payload";

    /// A no-dependency executor for the mock futures, following the
    /// multipart-module pattern: every mock future completes without
    /// pending, so first-poll-until-ready terminates.
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
        TenantId::parse(TENANT).expect("grammatical mock tenant")
    }

    fn digest_of(bytes: &[u8]) -> BlobDigest {
        BlobDigest::parse(&sha256::encode_hex(&sha256::digest(bytes)))
            .expect("grammatical mock digest")
    }

    /// The honest declaration for `bytes`: computed digest and exact size.
    fn expectation_for(bytes: &[u8]) -> BlobExpectation {
        BlobExpectation::new(digest_of(bytes), bytes.len() as u64)
    }

    fn derived_key(digest: &BlobDigest) -> BlobObjectKey {
        BlobObjectKey::new(&tenant(), StorageProfile::ZstdV1, digest)
    }

    /// The passthrough transform: the stored form is the canonical form.
    struct IdentityEncoder;

    impl BlobEncoder for IdentityEncoder {
        fn update(&mut self, canonical: &[u8], out: &mut Vec<u8>) -> Result<(), StorageError> {
            out.extend_from_slice(canonical);
            Ok(())
        }

        fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), StorageError> {
            Ok(())
        }
    }

    /// An encoder whose `update` fails on a chosen call number — the
    /// encoder's own rejection of the stream.
    struct FailingEncoder {
        fail_on_update: usize,
        updates: AtomicUsize,
    }

    impl FailingEncoder {
        fn on_update(number: usize) -> Self {
            Self {
                fail_on_update: number,
                updates: AtomicUsize::new(0),
            }
        }
    }

    impl BlobEncoder for FailingEncoder {
        fn update(&mut self, _canonical: &[u8], _out: &mut Vec<u8>) -> Result<(), StorageError> {
            if self.updates.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_on_update {
                return Err(StorageError::of_kind(StorageErrorKind::MalformedInput));
            }
            Ok(())
        }

        fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), StorageError> {
            Ok(())
        }
    }

    /// The recorded behavior and fault knobs of one mock backend.
    #[derive(Default)]
    struct MockState {
        uploads: BTreeMap<String, String>,
        parts: Vec<(String, u16, usize)>,
        /// The stored bytes streamed to each upload, in part order — the
        /// content a commit would persist at the key.
        streamed: BTreeMap<String, Vec<u8>>,
        completes: Vec<String>,
        committed: Vec<String>,
        /// The readable evidence at each committed key: how many commits
        /// physically persisted content there, and the stored form the
        /// store holds. A replay the store dedupes (`AlreadyPresent`)
        /// never touches it.
        evidence: BTreeMap<String, (u32, [u8; 32])>,
        aborts: Vec<String>,
        outcomes: VecDeque<StorageOutcome>,
        content_addressed: bool,
        fail_part_at: Option<u16>,
        fail_abort: bool,
        next_upload: u32,
    }

    /// A raw writer that models a content-addressed object store: one
    /// visible object per committed key, replay reported as
    /// `AlreadyPresent`, and faults available on demand.
    #[derive(Default)]
    struct MockStore {
        state: Mutex<MockState>,
    }

    impl MockStore {
        fn replay_reports_already_present(&self) {
            self.state.lock().unwrap().content_addressed = true;
        }

        fn script_commit_outcomes(&self, outcomes: &[StorageOutcome]) {
            self.state.lock().unwrap().outcomes = outcomes.iter().copied().collect();
        }

        fn fail_part_at(&self, ordinal: u16) {
            self.state.lock().unwrap().fail_part_at = Some(ordinal);
        }

        fn fail_abort(&self) {
            self.state.lock().unwrap().fail_abort = true;
        }

        fn recover_abort(&self) {
            self.state.lock().unwrap().fail_abort = false;
        }

        fn committed_keys(&self) -> Vec<String> {
            self.state.lock().unwrap().committed.clone()
        }

        /// The readable evidence at `key` — (physical writes, stored-form
        /// SHA-256) — or `None` when the store never persisted the key.
        fn evidence_of(&self, key: &str) -> Option<(u32, [u8; 32])> {
            self.state.lock().unwrap().evidence.get(key).copied()
        }

        fn completes(&self) -> Vec<String> {
            self.state.lock().unwrap().completes.clone()
        }

        fn aborts(&self) -> Vec<String> {
            self.state.lock().unwrap().aborts.clone()
        }

        fn parts_of(&self, upload: &str) -> Vec<(u16, usize)> {
            self.state
                .lock()
                .unwrap()
                .parts
                .iter()
                .filter(|(id, _, _)| id == upload)
                .map(|(_, number, size)| (*number, *size))
                .collect()
        }
    }

    impl RawWriteStore for MockStore {
        fn capabilities(&self) -> StoreCapabilities {
            StoreCapabilities {
                conditional_create: ConditionalCreate::Unavailable,
                stored_checksum: StoredChecksum::Sha256,
                versioning: VersioningState::Unknown,
                server_side_encryption: EncryptionState::Unavailable,
            }
        }

        async fn write_manifest(
            &self,
            _key: &ManifestKey,
            _bytes: &[u8],
        ) -> Result<StorageOutcome, StorageError> {
            unreachable!("the blob commit path never writes manifests")
        }

        async fn begin_multipart(
            &self,
            blob: &BlobObjectKey,
        ) -> Result<MultipartUploadId, StorageError> {
            let mut state = self.state.lock().unwrap();
            state.next_upload += 1;
            let id = MultipartUploadId::parse(&format!("mock-upload-{}", state.next_upload))
                .expect("grammatical mock id");
            state
                .uploads
                .insert(id.as_str().to_owned(), blob.as_str().to_owned());
            Ok(id)
        }

        async fn write_part(
            &self,
            upload: &MultipartUploadId,
            part: PartNumber,
            bytes: &[u8],
        ) -> Result<PartCommitment, StorageError> {
            let mut state = self.state.lock().unwrap();
            if state.fail_part_at == Some(part.get()) {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            state
                .parts
                .push((upload.as_str().to_owned(), part.get(), bytes.len()));
            state
                .streamed
                .entry(upload.as_str().to_owned())
                .or_default()
                .extend_from_slice(bytes);
            let tag = ObjectTag::parse(&format!("\"tag-{}\"", part.get())).expect("tag grammar");
            Ok(PartCommitment::new(part, tag))
        }

        async fn commit_multipart(
            &self,
            upload: &MultipartUploadId,
            _parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            let mut state = self.state.lock().unwrap();
            state.completes.push(upload.as_str().to_owned());
            let key = state.uploads[upload.as_str()].clone();
            let outcome = if let Some(scripted) = state.outcomes.pop_front() {
                scripted
            } else if state.content_addressed && state.committed.contains(&key) {
                // The dedupe verdict: readable compatible metadata
                // established prior presence, so the object the store
                // already holds stays exactly as the first commit wrote
                // it — no rewrite, no second object (vocabulary:
                // `AlreadyPresent`, never `ReplacedEquivalent`).
                StorageOutcome::AlreadyPresent
            } else {
                let content = state.streamed.remove(upload.as_str()).unwrap_or_default();
                let stored = sha256::digest(&content);
                let entry = state.evidence.entry(key.clone()).or_insert((0, stored));
                entry.0 += 1;
                entry.1 = stored;
                StorageOutcome::Created
            };
            if !state.committed.contains(&key) {
                state.committed.push(key);
            }
            Ok(outcome)
        }

        async fn abort_multipart(&self, upload: &MultipartUploadId) -> Result<(), StorageError> {
            let mut state = self.state.lock().unwrap();
            if state.fail_abort {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            state.aborts.push(upload.as_str().to_owned());
            Ok(())
        }
    }

    /// Run one commit of `chunks` declared as `expectation`.
    fn commit_chunks(
        store: &MockStore,
        open: &OpenUploads,
        expectation: BlobExpectation,
        encoder: &mut impl BlobEncoder,
        chunks: &[&[u8]],
    ) -> Result<BlobCommit, BlobCommitError> {
        block_on(commit_blob(
            store,
            open,
            &tenant(),
            expectation,
            encoder,
            chunks.iter().copied(),
        ))
    }

    fn commit_body(body: &[u8]) -> (MockStore, Result<BlobCommit, BlobCommitError>) {
        let store = MockStore::default();
        let result = commit_chunks(
            &store,
            &OpenUploads::new(),
            expectation_for(body),
            &mut IdentityEncoder,
            &[body],
        );
        (store, result)
    }

    #[test]
    fn identical_retry_converges_on_one_blob_identity() {
        let store = MockStore::default();
        store.replay_reports_already_present();
        let digest = digest_of(BODY);

        let first = commit_chunks(
            &store,
            &OpenUploads::new(),
            BlobExpectation::new(digest, BODY.len() as u64),
            &mut IdentityEncoder,
            &[BODY],
        )
        .expect("the first commit lands the blob");
        let second = commit_chunks(
            &store,
            &OpenUploads::new(),
            BlobExpectation::new(digest, BODY.len() as u64),
            &mut IdentityEncoder,
            &[BODY],
        )
        .expect("the retry converges");

        assert_eq!(first.outcome(), StorageOutcome::Created);
        assert_eq!(
            second.outcome(),
            StorageOutcome::AlreadyPresent,
            "the replay reports the object was already there"
        );
        assert_eq!(
            first.key().as_str(),
            second.key().as_str(),
            "both attempts address the same derived key"
        );
        assert_eq!(
            first.key().as_str(),
            derived_key(&digest).as_str(),
            "the key is the server-derived zstd-v1 blob key"
        );
        assert_eq!(
            store.committed_keys(),
            vec![first.key().as_str().to_owned()],
            "no duplicate visible object at the key"
        );
        assert_eq!(
            (
                second.stored_bytes(),
                second.stored_sha256(),
                second.parts()
            ),
            (first.stored_bytes(), first.stored_sha256(), first.parts()),
            "the deterministic body produces the identical stored form"
        );
        assert_eq!(store.aborts(), Vec::<String>::new(), "nothing was aborted");
    }

    #[test]
    fn equivalent_retry_does_not_overwrite_readable_evidence() {
        // The physical half of convergence: the retry must converge *on*
        // the object the first commit established, never rewrite it. The
        // mock's per-key evidence — how many commits physically persisted
        // content at the key, and the stored form the store holds — pins
        // that a deduped replay leaves the readable evidence exactly as
        // the first commit wrote it.
        let store = MockStore::default();
        store.replay_reports_already_present();
        let expectation = BlobExpectation::new(digest_of(BODY), BODY.len() as u64);

        let first = commit_chunks(
            &store,
            &OpenUploads::new(),
            expectation,
            &mut IdentityEncoder,
            &[BODY],
        )
        .expect("the first commit establishes the readable evidence");
        let retry = commit_chunks(
            &store,
            &OpenUploads::new(),
            expectation,
            &mut IdentityEncoder,
            &[BODY],
        )
        .expect("the equivalent retry converges");

        assert_eq!(
            retry.key().as_str(),
            first.key().as_str(),
            "both attempts address the one derived key"
        );
        assert_eq!(
            retry.outcome(),
            StorageOutcome::AlreadyPresent,
            "the store deduped the replay instead of rewriting it"
        );
        let (writes, stored) = store
            .evidence_of(first.key().as_str())
            .expect("the derived key holds readable evidence");
        assert_eq!(
            writes, 1,
            "the retry never persisted content over the readable evidence"
        );
        assert_eq!(
            stored,
            sha256::digest(BODY),
            "the readable evidence is the canonical stored form, untouched"
        );
        assert_eq!(
            retry.stored_sha256(),
            &stored,
            "the retry's own report matches the evidence the store holds"
        );
        assert_eq!(store.aborts(), Vec::<String>::new());
    }

    #[test]
    fn writer_only_replay_reports_created_not_verified() {
        // The blob family's weaker-truth pin (RCPT-003, RCPT-004): the
        // mock store reports no conditional-create capability and no
        // readable dedupe evidence, so the identical retry is a second
        // physical write whose verdict is `Created` again — created, not
        // verified. The layer never promotes deterministic convergence
        // (STO-004, at the derived key STO-002) into the `AlreadyPresent`
        // presence claim only the store's readable metadata can
        // establish.
        let store = MockStore::default();
        let expectation = BlobExpectation::new(digest_of(BODY), BODY.len() as u64);

        let first = commit_chunks(
            &store,
            &OpenUploads::new(),
            expectation,
            &mut IdentityEncoder,
            &[BODY],
        )
        .expect("the first commit lands the blob");
        let replay = commit_chunks(
            &store,
            &OpenUploads::new(),
            expectation,
            &mut IdentityEncoder,
            &[BODY],
        )
        .expect("the retry lands the blob");

        assert_eq!(
            first.outcome(),
            StorageOutcome::Created,
            "the first write reports exactly what the writer-only store reported"
        );
        assert_eq!(
            replay.outcome(),
            StorageOutcome::Created,
            "without readable dedupe evidence the retry reports the weaker truth again — created, not verified"
        );
        assert_eq!(
            replay.key().as_str(),
            first.key().as_str(),
            "both attempts address the one derived key"
        );
        let (writes, _) = store
            .evidence_of(first.key().as_str())
            .expect("the derived key holds readable evidence");
        assert_eq!(
            writes, 2,
            "the store really wrote twice: the verdict is the store's report, never the layer's"
        );
        assert_eq!(store.aborts(), Vec::<String>::new());
    }

    #[test]
    fn digest_mismatch_never_completes_and_aborts_the_session() {
        let other = b"a different canonical body";
        let (store, result) = {
            let store = MockStore::default();
            let error = commit_chunks(
                &store,
                &OpenUploads::new(),
                BlobExpectation::new(digest_of(other), BODY.len() as u64),
                &mut IdentityEncoder,
                &[BODY],
            )
            .expect_err("the declared digest contradicts the stream");
            (store, error)
        };
        assert_eq!(result.kind(), StorageErrorKind::IntegrityConflict);
        assert_eq!(
            result.failure().detail(),
            "computed canonical digest does not match the declared blob digest"
        );
        assert_eq!(result.cleanup(), None, "the cleanup abort succeeded");
        assert!(
            store.completes().is_empty(),
            "a digest mismatch never completes the content-addressed object"
        );
        assert_eq!(store.committed_keys(), Vec::<String>::new());
        assert_eq!(store.aborts().len(), 1, "the live session was aborted");
    }

    #[test]
    fn size_mismatch_never_completes_and_aborts_the_session() {
        let store = MockStore::default();
        let error = commit_chunks(
            &store,
            &OpenUploads::new(),
            BlobExpectation::new(digest_of(BODY), BODY.len() as u64 + 1),
            &mut IdentityEncoder,
            &[BODY],
        )
        .expect_err("the declared size contradicts the stream");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(
            error.failure().detail(),
            "decoded canonical size does not match the declared size"
        );
        assert!(
            store.completes().is_empty(),
            "a size mismatch never completes the content-addressed object"
        );
        assert_eq!(store.aborts().len(), 1, "the live session was aborted");
    }

    #[test]
    fn validation_failure_surfaces_a_failed_cleanup_abort() {
        // The digest flavor: the mismatch abort itself fails, and both
        // facts surface while the session stays registered for a drain.
        let store = MockStore::default();
        store.fail_abort();
        let open = OpenUploads::new();
        let error = commit_chunks(
            &store,
            &open,
            BlobExpectation::new(digest_of(b"not this body"), BODY.len() as u64),
            &mut IdentityEncoder,
            &[BODY],
        )
        .expect_err("digest mismatch aborts");
        assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
        assert_eq!(
            error.cleanup(),
            Some(StorageError::of_kind(StorageErrorKind::Unavailable)),
            "the failed abort is carried, not swallowed"
        );
        assert!(store.completes().is_empty());
        assert_eq!(open.abandoned_count(), 1, "the drain can still reach it");

        // The size flavor behaves identically once the backend recovers.
        store.recover_abort();
        assert!(block_on(open.abort_abandoned(&store)).is_empty());
        store.fail_abort();
        let error = commit_chunks(
            &store,
            &open,
            BlobExpectation::new(digest_of(BODY), BODY.len() as u64 + 7),
            &mut IdentityEncoder,
            &[BODY],
        )
        .expect_err("size mismatch aborts");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(
            error.cleanup(),
            Some(StorageError::of_kind(StorageErrorKind::Unavailable)),
            "the failed size-mismatch abort is carried too"
        );
        assert!(store.completes().is_empty(), "still nothing completed");
        assert_eq!(open.abandoned_count(), 1);
        store.recover_abort();
        assert!(block_on(open.abort_abandoned(&store)).is_empty());
    }

    #[test]
    fn encoder_failure_never_completes_and_aborts_the_session() {
        let store = MockStore::default();
        let error = commit_chunks(
            &store,
            &OpenUploads::new(),
            expectation_for(BODY),
            &mut FailingEncoder::on_update(1),
            &[BODY],
        )
        .expect_err("the encoder rejected the stream");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert!(
            store.completes().is_empty(),
            "an encoder failure never completes the object"
        );
        assert_eq!(store.committed_keys(), Vec::<String>::new());
        assert_eq!(store.aborts().len(), 1, "the live session was aborted");
    }

    #[test]
    fn writer_part_failure_interrupts_the_stream_without_a_commit() {
        let store = MockStore::default();
        store.fail_part_at(1);
        let body = vec![9u8; PART_BYTES + 1];
        let error = commit_chunks(
            &store,
            &OpenUploads::new(),
            expectation_for(&body),
            &mut IdentityEncoder,
            &[&body],
        )
        .expect_err("the store rejected the part");
        assert_eq!(error.kind(), StorageErrorKind::Unavailable);
        assert_eq!(error.cleanup(), None, "the writer already aborted cleanly");
        assert!(
            store.completes().is_empty(),
            "an interrupted stream never completes"
        );
        assert_eq!(store.aborts().len(), 1);
    }

    #[test]
    fn commit_outcome_is_the_store_report_passed_through_untouched() {
        let store = MockStore::default();
        store.script_commit_outcomes(&[
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult,
            StorageOutcome::AlreadyPresent,
            StorageOutcome::ReplacedEquivalent,
        ]);
        for expected in [
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult,
            StorageOutcome::AlreadyPresent,
            StorageOutcome::ReplacedEquivalent,
        ] {
            let commit = commit_chunks(
                &store,
                &OpenUploads::new(),
                expectation_for(BODY),
                &mut IdentityEncoder,
                &[BODY],
            )
            .expect("each commit succeeds");
            assert_eq!(
                commit.outcome(),
                expected,
                "the layer reports exactly the store's physical truth"
            );
        }
    }

    #[test]
    fn small_body_is_a_single_part_session() {
        let (store, result) = commit_body(BODY);
        let commit = result.expect("the small body commits");
        assert_eq!(commit.parts(), 1);
        assert_eq!(commit.uncompressed_bytes(), BODY.len() as u64);
        assert_eq!(commit.stored_bytes(), BODY.len() as u64);
        assert_eq!(commit.stored_sha256(), &sha256::digest(BODY));
        assert_eq!(commit.outcome(), StorageOutcome::Created);
        let id = store.completes()[0].clone();
        assert_eq!(
            store.parts_of(&id),
            vec![(1, BODY.len())],
            "below the part threshold the session is one bounded part"
        );
        assert_eq!(store.aborts(), Vec::<String>::new());
    }

    #[test]
    fn part_discipline_holds_across_a_multi_part_body() {
        let body = vec![7u8; 2 * PART_BYTES + 3];
        let (store, result) = commit_body(&body);
        let commit = result.expect("the multi-part body commits");
        assert_eq!(commit.parts(), 3);
        let id = store.completes()[0].clone();
        assert_eq!(
            store.parts_of(&id),
            vec![(1, PART_BYTES), (2, PART_BYTES), (3, 3)],
            "every part except the last is exactly the pinned part size"
        );
        assert_eq!(commit.stored_bytes(), body.len() as u64);
        assert_eq!(commit.stored_sha256(), &sha256::digest(&body));
    }

    #[test]
    fn declared_empty_body_never_completes() {
        let store = MockStore::default();
        let error = commit_chunks(
            &store,
            &OpenUploads::new(),
            expectation_for(b""),
            &mut IdentityEncoder,
            &[b""],
        )
        .expect_err("an empty stored stream cannot complete");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(
            error.failure().detail(),
            "an empty stream cannot complete a content-addressed object"
        );
        assert!(store.completes().is_empty());
        assert_eq!(store.aborts().len(), 1, "the empty session is aborted");
    }

    #[test]
    fn multi_chunk_stream_commits_the_whole_body() {
        let (first, second) = BODY.split_at(10);
        let (store, result) = {
            let store = MockStore::default();
            let commit = commit_chunks(
                &store,
                &OpenUploads::new(),
                expectation_for(BODY),
                &mut IdentityEncoder,
                &[first, second],
            )
            .expect("the chunked stream commits");
            (store, commit)
        };
        assert_eq!(result.uncompressed_bytes(), BODY.len() as u64);
        assert_eq!(result.stored_sha256(), &sha256::digest(BODY));
        let id = store.completes()[0].clone();
        assert_eq!(store.parts_of(&id), vec![(1, BODY.len())]);
    }

    #[test]
    fn details_stay_inside_the_safe_message_grammar() {
        for detail in [super::DIGEST_MISMATCH_DETAIL, super::SIZE_MISMATCH_DETAIL] {
            assert_eq!(
                SafeMessage::parse(detail)
                    .unwrap_or_else(|_| panic!("detail is not safe: {detail}"))
                    .as_str(),
                detail
            );
        }
    }
}
