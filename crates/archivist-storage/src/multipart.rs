// SPDX-License-Identifier: Apache-2.0

//! The streaming multipart writer: bounded create, part upload, complete,
//! abort, and simple `PUT` — the five write operations of
//! [`crate::raw_write::RawWriteStore`] composed into one cancellation-safe
//! session
//! (plan Sections 7.6 and 7.7; VAL-008).
//!
//! A session begins with [`MultipartWriter::begin`], accepts bytes through
//! [`MultipartWriter::write_chunk`] in chunks of any size, ends with
//! [`MultipartWriter::finish`], and terminates exactly once with
//! [`MultipartWriter::commit`] — only after the caller has validated every
//! size and digest — or [`MultipartWriter::abort`]. The bounded manifest
//! `PUT` for occurrence manifests and upload attestations is
//! [`put_manifest`]. Every operation maps onto exactly one
//! [`RawWriteStore`] call: the writer adds orchestration and safety, never
//! a second protocol.
//!
//! # Bounded means bounded
//!
//! The writer holds at most one part buffer of [`PART_BYTES`] (the pinned
//! 8 MiB part size, plan Section 7.6) at a time. A chunk larger than a
//! part is consumed in part-sized slices, never buffered whole; a chunk of
//! one byte costs one byte of buffering. Every part except the last is
//! exactly [`PART_BYTES`], and the portable part-count bound
//! ([`PartNumber::MAX`]) is enforced before the ordinal is ever minted —
//! at 8 MiB parts it admits tens of GiB per blob, far above the 256 MiB
//! single-record cap, so the bound is a backend portability fact rather
//! than a payload limit.
//!
//! # Validate-before-complete (plan Section 7.7)
//!
//! Nothing the writer does can complete a content-addressed object: parts
//! land in an uncommitted multipart session, and [`MultipartWriter::commit`]
//! is a separate, explicit step the caller reaches only after the stream
//! ended and its own size and digest checks passed. The writer refuses to
//! commit an empty stream, a stream that was never finished, or a session
//! a store call already failed in — each refusal aborts the session so no
//! half-written object survives. The commitment set handed to the store is
//! exactly the parts the session produced, in ordinal order, and a backend
//! commitment naming a different part number than the one requested fails
//! the session closed.
//!
//! # Cancellation safety
//!
//! Dropping a writer future at any await point is always safe: the session
//! is uncommitted by construction, so an interrupted stream never completes
//! an object. Because `Drop` cannot perform I/O, a dropped writer leaves
//! its upload registered as *abandoned* in the [`OpenUploads`] registry the
//! session was opened against; the owner drains that registry later with
//! [`OpenUploads::abort_abandoned`], which is the same primitive the
//! graceful-shutdown path uses ("abort unfinished multipart uploads, and
//! exit nonzero if an abort fails" — plan Section 8, Phase 4). The one
//! window `Drop` cannot cover is a future dropped *during*
//! [`MultipartWriter::begin`] itself: the backend may have created an
//! upload whose identifier never reached this side. That orphan is
//! unobservable from here and is exactly what the deployment's 24-hour
//! incomplete-multipart lifecycle rule exists to reap (plan Section 7.7).
//!
//! # Abort failures stay visible
//!
//! Every failure path attempts an immediate abort, and when that abort
//! itself fails the result carries both facts:
//! [`MultipartWriterError::failure`] is what went wrong, and
//! [`MultipartWriterError::cleanup`] is the abort that did not succeed —
//! neither swallows the other, and the session stays in the registry so a
//! later drain can retry. A commit that failed in flight is never retried
//! on the same session (`EC-10`): the writer aborts it and the caller
//! retries the whole immutable request.
//!
//! # Keys stay derived
//!
//! The writer accepts only the store's own typed keys
//! ([`BlobObjectKey`] for sessions, [`ManifestKey`] for the simple `PUT`);
//! it never assembles or rewrites key text, so the authority boundary of
//! [`crate::raw_write`] is the boundary of this module too.

use std::fmt;
use std::sync::Arc;

use archivist_protocol::envelope::CANONICAL_MAX_BYTES;
use archivist_protocol::object_key::BlobObjectKey;
use archivist_protocol::vocabulary::StorageOutcome;

use crate::error::{StorageError, StorageErrorKind};
use crate::raw_write::{ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore};

/// The pinned multipart part size: 8 MiB (plan Section 7.6, "Multipart
/// part | 8 MiB").
///
/// Every part except the last is exactly this many bytes; the last part is
/// 1..=[`PART_BYTES`]. The value is a policy constant, not a tunable: the
/// stored layout a backend sees (part count, boundaries) is part of the
/// deterministic shape of a commit, so a per-session part size would make
/// object shape caller-dependent.
pub const PART_BYTES: usize = 8 * 1024 * 1024;

/// The static detail for an exhausted part ordinal.
const PART_BOUND_DETAIL: &str = "part count exceeds the portable multipart bound";
/// The static detail for operating on a session a store call already failed in.
const DEAD_SESSION_DETAIL: &str = "multipart session is no longer usable";
/// The static detail for writing after the stream was finished.
const STREAM_FINISHED_DETAIL: &str = "multipart stream already finished";
/// The static detail for committing with buffered bytes.
const UNFINISHED_DETAIL: &str = "finish the stream before committing";
/// The static detail for committing a stream with no parts.
const EMPTY_STREAM_DETAIL: &str = "an empty stream cannot complete a content-addressed object";
/// The static detail for a backend commitment naming a different part.
const WRONG_COMMITMENT_DETAIL: &str = "backend returned a commitment for a different part";
/// The static detail for an empty manifest payload.
const EMPTY_MANIFEST_DETAIL: &str = "manifest bytes are empty";
/// The static detail for an oversized manifest payload.
const OVERSIZED_MANIFEST_DETAIL: &str = "manifest exceeds the canonical document bound";

/// Why a streaming multipart session operation failed: the primary
/// failure, plus the cleanup abort failure when that abort was attempted
/// and did not succeed.
///
/// Both halves are content-safe by construction ([`StorageError`] carries
/// only closed kinds and static details), so the composite can never echo
/// keys or payload content. The cleanup half is the visibility contract:
/// an abort that failed is reported, not absorbed into the primary error
/// and not lost — the session also remains registered in [`OpenUploads`]
/// for a later drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MultipartWriterError {
    failure: StorageError,
    cleanup: Option<StorageError>,
}

impl MultipartWriterError {
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

    /// The cleanup abort failure, when the abort was attempted and did not
    /// succeed.
    #[must_use]
    pub const fn cleanup(&self) -> Option<StorageError> {
        self.cleanup
    }
}

impl fmt::Display for MultipartWriterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.cleanup {
            None => write!(f, "multipart session failed: {}", self.failure),
            Some(cleanup) => write!(
                f,
                "multipart session failed: {}; cleanup abort failed: {cleanup}",
                self.failure
            ),
        }
    }
}

impl std::error::Error for MultipartWriterError {}

/// A failed cleanup recorded by [`OpenUploads::abort_abandoned`]: which
/// abandoned session could not be aborted, and why.
///
/// The upload stays registered after a failure so the next drain retries
/// it — abort is cleanup, and cleanup must converge (the trait contract
/// makes aborting an already-aborted or already-committed session a
/// success).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupFailure {
    upload: MultipartUploadId,
    error: StorageError,
}

impl CleanupFailure {
    /// Pair the abandoned session with the abort failure.
    #[must_use]
    pub const fn new(upload: MultipartUploadId, error: StorageError) -> Self {
        Self { upload, error }
    }

    /// The session whose abort failed.
    #[must_use]
    pub const fn upload(&self) -> &MultipartUploadId {
        &self.upload
    }

    /// Why the abort failed.
    #[must_use]
    pub const fn error(&self) -> StorageError {
        self.error
    }
}

/// The process-local registry of multipart sessions opened through this
/// module: what cancellation safety is built on.
///
/// [`MultipartWriter::begin`] registers the session as live; a successful
/// [`MultipartWriter::commit`] or [`MultipartWriter::abort`] releases it;
/// anything else — a dropped writer, a failure whose cleanup abort also
/// failed — leaves the session registered as *abandoned*. Because `Drop`
/// cannot perform I/O, the registry is how an interrupted stream's session
/// stays reachable for cleanup instead of relying solely on the
/// deployment's 24-hour lifecycle backstop.
///
/// The handle is a cheap cloneable reference to one shared set; pass the
/// same [`OpenUploads`] to every writer a process owns, and drain it at
/// shutdown with [`OpenUploads::abort_abandoned`].
#[derive(Clone, Debug, Default)]
pub struct OpenUploads {
    inner: Arc<RegistryInner>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    entries: std::sync::Mutex<Vec<RegistryEntry>>,
}

#[derive(Clone, Debug)]
struct RegistryEntry {
    upload: MultipartUploadId,
    abandoned: bool,
}

impl OpenUploads {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sessions currently owned by live writers.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.with_entries(|entries| entries.iter().filter(|entry| !entry.abandoned).count())
    }

    /// Sessions whose writer went away without a terminal operation —
    /// interrupted streams awaiting cleanup.
    #[must_use]
    pub fn abandoned_count(&self) -> usize {
        self.with_entries(|entries| entries.iter().filter(|entry| entry.abandoned).count())
    }

    /// Abort every abandoned session against `store`, removing the ones
    /// whose abort succeeded and reporting the ones whose abort failed.
    ///
    /// This is the drain half of cancellation safety: the shutdown path
    /// calls it after live writers finished, and a non-empty return is the
    /// "exit nonzero if an abort fails" signal (plan Section 8, Phase 4).
    /// Sessions whose abort failed stay registered, so a later drain
    /// retries them. Live sessions are never touched — they belong to
    /// writers that may still commit. The call itself cannot fail; each
    /// failed abort is a returned [`CleanupFailure`] instead.
    #[must_use]
    pub async fn abort_abandoned<S: RawWriteStore + ?Sized>(
        &self,
        store: &S,
    ) -> Vec<CleanupFailure> {
        let targets: Vec<MultipartUploadId> = self.with_entries(|entries| {
            entries
                .iter()
                .filter(|entry| entry.abandoned)
                .map(|entry| entry.upload.clone())
                .collect()
        });
        let mut failures = Vec::new();
        for upload in targets {
            match store.abort_multipart(&upload).await {
                Ok(()) => self.release(&upload),
                Err(error) => failures.push(CleanupFailure::new(upload, error)),
            }
        }
        failures
    }

    fn register(&self, upload: MultipartUploadId) {
        self.with_entries(|entries| {
            entries.push(RegistryEntry {
                upload,
                abandoned: false,
            });
        });
    }

    fn release(&self, upload: &MultipartUploadId) {
        self.with_entries(|entries| entries.retain(|entry| &entry.upload != upload));
    }

    fn abandon(&self, upload: &MultipartUploadId) {
        self.with_entries(|entries| {
            if let Some(entry) = entries.iter_mut().find(|entry| &entry.upload == upload) {
                entry.abandoned = true;
            }
        });
    }

    fn with_entries<T>(&self, body: impl FnOnce(&mut Vec<RegistryEntry>) -> T) -> T {
        // The lock is never held across an await: every body is
        // synchronous, and the one async method (abort_abandoned) only
        // snapshots under the lock and awaits between critical sections.
        let mut entries = self
            .inner
            .entries
            .lock()
            .expect("open-uploads registry lock");
        body(&mut entries)
    }
}

/// Where one streaming session stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Session {
    /// Accepting chunks.
    Open,
    /// The stream ended; awaiting caller validation and commit.
    Flushed,
    /// A store call failed and cleanup was attempted; unusable.
    Failed,
}

/// One streaming multipart session against a raw writer: create, part
/// upload, complete, and abort for one content-addressed blob key.
///
/// Built only by [`MultipartWriter::begin`]; see the module docs for the
/// bounded-memory, validate-before-complete, and cancellation-safety
/// contracts. The writer borrows the store, so it cannot outlive the
/// identity that opened it.
pub struct MultipartWriter<'store, S: RawWriteStore + ?Sized> {
    store: &'store S,
    open: OpenUploads,
    upload: MultipartUploadId,
    blob: BlobObjectKey,
    buffer: Vec<u8>,
    next_ordinal: u32,
    parts: Vec<PartCommitment>,
    uploaded_bytes: u64,
    session: Session,
    terminal: bool,
}

impl<'store, S: RawWriteStore + ?Sized> MultipartWriter<'store, S> {
    /// Begin one multipart session for `blob` — the bounded *create*
    /// operation.
    ///
    /// The session is registered in `open` as live and stays reachable
    /// until it terminates. The buffer is allocated lazily on the first
    /// byte, so opening sessions costs no part-scale memory.
    ///
    /// # Errors
    /// [`MultipartWriterError::failure`] with the store's reason when the
    /// backend cannot create the session; there is no cleanup half,
    /// because a session that was never created has nothing to abort. A
    /// future dropped while this call is in flight may leave a backend
    /// orphan the 24-hour lifecycle rule reaps (see the module docs).
    pub async fn begin(
        store: &'store S,
        blob: &BlobObjectKey,
        open: &OpenUploads,
    ) -> Result<Self, MultipartWriterError> {
        let upload = store
            .begin_multipart(blob)
            .await
            .map_err(MultipartWriterError::new)?;
        open.register(upload.clone());
        Ok(Self {
            store,
            open: open.clone(),
            upload,
            blob: blob.clone(),
            buffer: Vec::new(),
            next_ordinal: 1,
            parts: Vec::new(),
            uploaded_bytes: 0,
            session: Session::Open,
            terminal: false,
        })
    }

    /// The opaque session handle the store minted.
    #[must_use]
    pub fn session_id(&self) -> &MultipartUploadId {
        &self.upload
    }

    /// The content-addressed key this session writes toward.
    #[must_use]
    pub fn blob_key(&self) -> &BlobObjectKey {
        &self.blob
    }

    /// Bytes already handed to the backend as complete parts — the number
    /// the caller's stored-bytes validation compares against.
    #[must_use]
    pub fn uploaded_bytes(&self) -> u64 {
        self.uploaded_bytes
    }

    /// Bytes buffered for the next part (always below [`PART_BYTES`]).
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Parts this session committed to the backend so far.
    #[must_use]
    pub fn part_count(&self) -> usize {
        self.parts.len()
    }

    /// Append one chunk of any size — the bounded *part upload* operation.
    ///
    /// Chunks larger than [`PART_BYTES`] are consumed in part-sized
    /// slices; buffering never exceeds one part. When a store call fails,
    /// the session is aborted (the abort failure, if any, rides along in
    /// the error) and every later operation on this writer fails closed.
    ///
    /// # Errors
    /// [`MultipartWriterError`] with [`StorageErrorKind::MalformedInput`]
    /// when the stream was already finished or the session already failed,
    /// or the store's failure otherwise; see also
    /// [`MultipartWriterError::cleanup`].
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), MultipartWriterError> {
        match self.session {
            Session::Failed => return Err(MultipartWriterError::new(dead_session())),
            Session::Flushed => return Err(MultipartWriterError::new(finished_stream())),
            Session::Open => {}
        }
        let mut offset = 0;
        while offset < chunk.len() {
            let take = (PART_BYTES - self.buffer.len()).min(chunk.len() - offset);
            let end = offset + take;
            self.buffer.extend_from_slice(&chunk[offset..end]);
            offset = end;
            if self.buffer.len() == PART_BYTES {
                self.upload_part(PART_BYTES).await?;
            }
        }
        Ok(())
    }

    /// End the stream: flush the final partial part, if any.
    ///
    /// After this the caller validates sizes and digests and then — only
    /// then — calls [`MultipartWriter::commit`]. `finish` is idempotent
    /// for a live session; it never uploads an empty tail part.
    ///
    /// # Errors
    /// [`MultipartWriterError`] when the tail upload fails or the session
    /// already failed; a failed session stays aborted and unusable.
    pub async fn finish(&mut self) -> Result<(), MultipartWriterError> {
        match self.session {
            Session::Open => {
                let tail = self.buffer.len();
                if tail > 0 {
                    self.upload_part(tail).await?;
                }
                self.session = Session::Flushed;
                Ok(())
            }
            Session::Flushed => Ok(()),
            Session::Failed => Err(MultipartWriterError::new(dead_session())),
        }
    }

    /// Complete the session — the caller-gated *complete* operation.
    ///
    /// Only the caller can decide this: the store never saw the canonical
    /// bytes' digest, so the writer refuses to commit a stream that was
    /// not finished, an empty stream, or a failed session — each refusal
    /// aborts so nothing half-written survives. On success the session is
    /// released from the registry. On a store failure the session is
    /// aborted rather than retried: a commit lost in flight is repaired by
    /// retrying the whole immutable request, never by reusing the dead
    /// session (`EC-10`).
    ///
    /// # Errors
    /// [`MultipartWriterError`] with [`StorageErrorKind::MalformedInput`]
    /// for the refusals above, or the store's commit failure; a failed
    /// cleanup abort rides along in
    /// [`MultipartWriterError::cleanup`].
    pub async fn commit(mut self) -> Result<StorageOutcome, MultipartWriterError> {
        if matches!(self.session, Session::Failed) {
            return Err(MultipartWriterError::new(dead_session()));
        }
        if !self.buffer.is_empty() {
            return Err(self.fail(unfinished_stream()).await);
        }
        if self.parts.is_empty() {
            return Err(self.fail(empty_stream()).await);
        }
        match self.store.commit_multipart(&self.upload, &self.parts).await {
            Ok(outcome) => {
                self.terminal = true;
                self.open.release(&self.upload);
                Ok(outcome)
            }
            Err(failure) => Err(self.fail(failure).await),
        }
    }

    /// Abort the session and release its parts — the *abort* operation.
    ///
    /// Cleanup, and cleanup converges: aborting an already-aborted or
    /// already-committed session is a backend success by the trait
    /// contract, and a successful abort (explicit or internal) releases
    /// the registry entry. A failed abort leaves the session registered
    /// and returns the failure — never swallowed.
    ///
    /// # Errors
    /// [`StorageError`] when the backend abort fails; the session stays
    /// registered as abandoned for a later drain.
    pub async fn abort(mut self) -> Result<(), StorageError> {
        self.terminate_by_abort().await
    }

    /// Send `len` bytes from the front of the buffer as the next part.
    ///
    /// The one place a part crosses the store boundary: mints the ordinal
    /// (enforcing the portable bound first), uploads, verifies the backend
    /// commitment names the part it was asked to write, and only then
    /// records the commitment and drains the buffer. Any failure routes
    /// through [`MultipartWriter::fail`], which aborts the session.
    async fn upload_part(&mut self, len: usize) -> Result<(), MultipartWriterError> {
        let Some(number) = part_ordinal(self.next_ordinal) else {
            return Err(self
                .fail(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    PART_BOUND_DETAIL,
                ))
                .await);
        };
        let commitment = match self
            .store
            .write_part(&self.upload, number, &self.buffer[..len])
            .await
        {
            Ok(commitment) => commitment,
            Err(failure) => return Err(self.fail(failure).await),
        };
        if commitment.number() != number {
            return Err(self
                .fail(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    WRONG_COMMITMENT_DETAIL,
                ))
                .await);
        }
        self.next_ordinal += 1;
        self.uploaded_bytes += len as u64;
        self.parts.push(commitment);
        self.buffer.drain(..len);
        Ok(())
    }

    /// Mark the session failed, attempt the cleanup abort, and report
    /// both halves.
    async fn fail(&mut self, failure: StorageError) -> MultipartWriterError {
        self.session = Session::Failed;
        match self.terminate_by_abort().await {
            Ok(()) => MultipartWriterError::new(failure),
            Err(cleanup) => MultipartWriterError::with_cleanup(failure, cleanup),
        }
    }

    /// Run the store abort; on success the session is terminal and
    /// released. On failure the registry entry stays — flagged abandoned,
    /// because no live writer path remains that could terminate it — for a
    /// later drain to retry.
    async fn terminate_by_abort(&mut self) -> Result<(), StorageError> {
        match self.store.abort_multipart(&self.upload).await {
            Ok(()) => {
                self.terminal = true;
                self.open.release(&self.upload);
                Ok(())
            }
            Err(error) => {
                self.open.abandon(&self.upload);
                Err(error)
            }
        }
    }
}

impl<S: RawWriteStore + ?Sized> Drop for MultipartWriter<'_, S> {
    fn drop(&mut self) {
        // A writer that never reached a terminal operation was
        // interrupted at some await point (or simply went out of scope):
        // nothing is committed, and the session stays registered as
        // abandoned so the drain can abort it. `Drop` cannot perform the
        // abort itself — that is the registry's job, not a limitation to
        // route around.
        if !self.terminal {
            self.open.abandon(&self.upload);
        }
    }
}

/// The bounded simple `PUT`: write one manifest object with its exact
/// final bytes.
///
/// The canonical write for occurrence manifests and upload attestations —
/// bounded JSON documents whose bytes are complete before the call, in
/// contrast with the streaming blob session. The bound is the protocol's
/// pinned canonical-document maximum
/// ([`CANONICAL_MAX_BYTES`], the same 64 KiB class as the canonical
/// envelope): the `PUT` path must never become a way to stream payload
/// scale through a manifest key, so it refuses empty and oversized input
/// before touching the store.
///
/// # Errors
/// [`StorageErrorKind::MalformedInput`] for empty or oversized input
/// (rejected without a store call), or the store's own failure otherwise.
pub async fn put_manifest<S: RawWriteStore + ?Sized>(
    store: &S,
    key: &ManifestKey,
    bytes: &[u8],
) -> Result<StorageOutcome, StorageError> {
    if bytes.is_empty() {
        return Err(StorageError::new(
            StorageErrorKind::MalformedInput,
            EMPTY_MANIFEST_DETAIL,
        ));
    }
    if bytes.len() > CANONICAL_MAX_BYTES {
        return Err(StorageError::new(
            StorageErrorKind::MalformedInput,
            OVERSIZED_MANIFEST_DETAIL,
        ));
    }
    store.write_manifest(key, bytes).await
}

/// Mint the next part ordinal, enforcing the portable bound before the
/// part is ever named. `None` means the session has exhausted
/// [`PartNumber::MAX`].
fn part_ordinal(next: u32) -> Option<PartNumber> {
    u16::try_from(next)
        .ok()
        .and_then(|number| PartNumber::new(number).ok())
}

fn dead_session() -> StorageError {
    StorageError::new(StorageErrorKind::MalformedInput, DEAD_SESSION_DETAIL)
}

fn finished_stream() -> StorageError {
    StorageError::new(StorageErrorKind::MalformedInput, STREAM_FINISHED_DETAIL)
}

fn unfinished_stream() -> StorageError {
    StorageError::new(StorageErrorKind::MalformedInput, UNFINISHED_DETAIL)
}

fn empty_stream() -> StorageError {
    StorageError::new(StorageErrorKind::MalformedInput, EMPTY_STREAM_DETAIL)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use archivist_protocol::object_key::{BlobObjectKey, OccurrenceObjectKey};
    use archivist_protocol::vocabulary::{
        BlobDigest, ClientId, HarnessId, OccurrenceId, SafeMessage, SessionHash, StorageOutcome,
        StorageProfile, TenantId,
    };

    use super::{
        CleanupFailure, MultipartWriter, MultipartWriterError, OpenUploads, PART_BYTES,
        part_ordinal, put_manifest,
    };
    use crate::capability::{
        ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
    };
    use crate::error::{StorageError, StorageErrorKind};
    use crate::metadata::ObjectTag;
    use crate::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A no-dependency executor for the mock futures, following the
    /// ingest-module pattern: every mock future completes without pending,
    /// so first-poll-until-ready terminates.
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

    /// The recorded behavior and fault knobs of one mock backend.
    #[derive(Default)]
    struct MockState {
        begun: Vec<String>,
        parts: Vec<(String, u16, usize)>,
        completes: Vec<(String, Vec<u16>)>,
        aborts: Vec<String>,
        manifests: Vec<(String, usize)>,
        fail_part_at: Option<u16>,
        fail_commit: bool,
        fail_abort: bool,
        wrong_commitment: bool,
        next_upload: u32,
    }

    /// A raw writer that records every call and can fail each operation on
    /// demand. `Mutex` (not `RefCell`) so the trait's `Send` futures hold.
    #[derive(Default)]
    struct MockStore {
        state: Mutex<MockState>,
    }

    impl MockStore {
        fn fail_part_at(&self, ordinal: u16) {
            self.state.lock().unwrap().fail_part_at = Some(ordinal);
        }

        fn fail_commit(&self) {
            self.state.lock().unwrap().fail_commit = true;
        }

        fn fail_abort(&self) {
            self.state.lock().unwrap().fail_abort = true;
        }

        fn recover_abort(&self) {
            self.state.lock().unwrap().fail_abort = false;
        }

        fn wrong_commitment(&self) {
            self.state.lock().unwrap().wrong_commitment = true;
        }

        fn began(&self) -> Vec<String> {
            self.state.lock().unwrap().begun.clone()
        }

        /// (ordinal, size) for one session's parts, in upload order.
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

        fn completes(&self) -> Vec<(String, Vec<u16>)> {
            self.state.lock().unwrap().completes.clone()
        }

        fn aborts(&self) -> Vec<String> {
            self.state.lock().unwrap().aborts.clone()
        }

        fn manifests(&self) -> Vec<(String, usize)> {
            self.state.lock().unwrap().manifests.clone()
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
            key: &ManifestKey,
            bytes: &[u8],
        ) -> Result<StorageOutcome, StorageError> {
            self.state
                .lock()
                .unwrap()
                .manifests
                .push((key.as_str().to_owned(), bytes.len()));
            Ok(StorageOutcome::Created)
        }

        async fn begin_multipart(
            &self,
            _blob: &BlobObjectKey,
        ) -> Result<MultipartUploadId, StorageError> {
            let mut state = self.state.lock().unwrap();
            state.next_upload += 1;
            let id = MultipartUploadId::parse(&format!("mock-upload-{}", state.next_upload))
                .expect("grammatical mock id");
            state.begun.push(id.as_str().to_owned());
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
            // The wrong-commitment fault shifts the ordinal by one; test
            // ordinals stay far below the portable bound.
            let number = if state.wrong_commitment {
                PartNumber::new(part.get() + 1).expect("shifted ordinal stays in bounds")
            } else {
                part
            };
            let tag = ObjectTag::parse(&format!("\"tag-{}\"", part.get())).expect("tag grammar");
            Ok(PartCommitment::new(number, tag))
        }

        async fn commit_multipart(
            &self,
            upload: &MultipartUploadId,
            parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            let mut state = self.state.lock().unwrap();
            state.completes.push((
                upload.as_str().to_owned(),
                parts.iter().map(|part| part.number().get()).collect(),
            ));
            if state.fail_commit {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            Ok(StorageOutcome::Created)
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

    fn blob_key() -> BlobObjectKey {
        BlobObjectKey::new(
            &TenantId::parse(TENANT).unwrap(),
            StorageProfile::ZstdV1,
            &BlobDigest::parse(DIGEST).unwrap(),
        )
    }

    fn occurrence_manifest_key() -> ManifestKey {
        ManifestKey::Occurrence(OccurrenceObjectKey::new(
            &TenantId::parse(TENANT).unwrap(),
            &ClientId::parse("aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f").unwrap(),
            &HarnessId::parse("claude-code").unwrap(),
            &SessionHash::parse(DIGEST).unwrap(),
            &OccurrenceId::parse(DIGEST).unwrap(),
        ))
    }

    fn begin(store: &MockStore) -> MultipartWriter<'_, MockStore> {
        block_on(MultipartWriter::begin(
            store,
            &blob_key(),
            &OpenUploads::new(),
        ))
        .expect("mock begin succeeds")
    }

    #[test]
    fn validated_stream_commits_in_order() {
        let store = MockStore::default();
        let open = OpenUploads::new();
        let mut writer = block_on(MultipartWriter::begin(&store, &blob_key(), &open))
            .expect("mock begin succeeds");

        let chunk = vec![7u8; 2 * PART_BYTES + 3];
        block_on(writer.write_chunk(&chunk)).expect("chunks upload");
        // Sliced into two full parts plus a buffered tail.
        assert_eq!(writer.part_count(), 2);
        assert_eq!(writer.uploaded_bytes(), (2 * PART_BYTES) as u64);
        assert_eq!(writer.buffered_bytes(), 3);
        assert_eq!(open.live_count(), 1);

        block_on(writer.finish()).expect("finish flushes the tail");
        assert_eq!(writer.part_count(), 3);
        assert_eq!(writer.buffered_bytes(), 0);

        let outcome = block_on(writer.commit()).expect("commit after validation");
        assert_eq!(outcome, StorageOutcome::Created);

        let id = store.began()[0].clone();
        assert_eq!(
            store.parts_of(&id),
            vec![(1, PART_BYTES), (2, PART_BYTES), (3, 3)],
            "non-final parts are exactly the pinned part size"
        );
        assert_eq!(
            store.completes(),
            vec![(id, vec![1, 2, 3])],
            "commit passes back exactly the produced parts in order"
        );
        assert!(store.aborts().is_empty());
        assert_eq!(
            open.live_count() + open.abandoned_count(),
            0,
            "a committed session is released"
        );
    }

    #[test]
    fn exact_part_multiple_has_no_empty_tail() {
        let store = MockStore::default();
        let mut writer = begin(&store);
        block_on(writer.write_chunk(&vec![0u8; 2 * PART_BYTES])).expect("chunks upload");
        block_on(writer.finish()).expect("finish");
        let id = store.began()[0].clone();
        assert_eq!(
            store.parts_of(&id),
            vec![(1, PART_BYTES), (2, PART_BYTES)],
            "no zero-byte third part"
        );
        block_on(writer.commit()).expect("commit");
    }

    #[test]
    fn small_blob_is_one_part() {
        let store = MockStore::default();
        let mut writer = begin(&store);
        block_on(writer.write_chunk(b"canonical bytes")).expect("chunk");
        block_on(writer.finish()).expect("finish");
        block_on(writer.commit()).expect("commit");
        let id = store.began()[0].clone();
        assert_eq!(store.parts_of(&id), vec![(1, 15)]);
    }

    #[test]
    fn interrupted_stream_never_completes_and_drains() {
        let store = MockStore::default();
        let open = OpenUploads::new();
        let mut writer = block_on(MultipartWriter::begin(&store, &blob_key(), &open))
            .expect("mock begin succeeds");
        block_on(writer.write_chunk(&vec![1u8; PART_BYTES])).expect("one full part");
        drop(writer);

        assert!(
            store.completes().is_empty(),
            "an interrupted stream never completes an object"
        );
        assert_eq!(open.abandoned_count(), 1);
        assert_eq!(open.live_count(), 0);

        let failures = block_on(open.abort_abandoned(&store));
        assert!(failures.is_empty());
        assert_eq!(
            store.aborts(),
            store.began(),
            "the abandoned session is aborted"
        );
        assert_eq!(open.abandoned_count(), 0, "released after a clean abort");
    }

    #[test]
    fn dropped_after_finish_still_never_completes() {
        // The validation window between finish and commit: dropping there
        // must be as safe as dropping mid-stream.
        let store = MockStore::default();
        let open = OpenUploads::new();
        let mut writer = block_on(MultipartWriter::begin(&store, &blob_key(), &open))
            .expect("mock begin succeeds");
        block_on(writer.write_chunk(b"tail candidate")).expect("chunk");
        block_on(writer.finish()).expect("finish");
        drop(writer);
        assert!(store.completes().is_empty());
        assert!(block_on(open.abort_abandoned(&store)).is_empty());
    }

    #[test]
    fn part_failure_aborts_and_never_completes() {
        let store = MockStore::default();
        store.fail_part_at(1);
        let mut writer = begin(&store);
        let error = block_on(writer.write_chunk(&vec![2u8; PART_BYTES]))
            .expect_err("the store rejected the part");
        assert_eq!(error.kind(), StorageErrorKind::Unavailable);
        assert_eq!(error.cleanup(), None, "the cleanup abort succeeded");
        assert!(store.completes().is_empty());
        assert_eq!(store.aborts().len(), 1, "the dead session is aborted");

        // The session is unusable afterwards, with no further store I/O.
        let again = block_on(writer.write_chunk(b"more")).expect_err("session is dead");
        assert_eq!(again.kind(), StorageErrorKind::MalformedInput);
        let finish = block_on(writer.finish()).expect_err("finish on a dead session");
        assert_eq!(finish.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(store.aborts().len(), 1, "no second abort attempt");
    }

    #[test]
    fn abort_failure_stays_visible_in_error_and_registry() {
        let store = MockStore::default();
        store.fail_part_at(1);
        store.fail_abort();
        let open = OpenUploads::new();
        let mut writer = block_on(MultipartWriter::begin(&store, &blob_key(), &open))
            .expect("mock begin succeeds");
        let error =
            block_on(writer.write_chunk(&vec![3u8; PART_BYTES])).expect_err("part upload fails");
        assert_eq!(error.kind(), StorageErrorKind::Unavailable);
        assert_eq!(
            error.cleanup(),
            Some(StorageError::of_kind(StorageErrorKind::Unavailable)),
            "the failed abort is carried, not swallowed"
        );
        assert!(store.completes().is_empty());
        assert_eq!(
            open.abandoned_count(),
            1,
            "the session stays registered for a retry"
        );

        // Once the backend recovers, the drain converges.
        store.recover_abort();
        assert!(block_on(open.abort_abandoned(&store)).is_empty());
        assert_eq!(open.abandoned_count(), 0);
    }

    #[test]
    fn commit_failure_aborts_the_dead_session() {
        let store = MockStore::default();
        store.fail_commit();
        let mut writer = begin(&store);
        block_on(writer.write_chunk(b"canonical")).expect("chunk");
        block_on(writer.finish()).expect("finish");
        let error = block_on(writer.commit()).expect_err("the store rejected the commit");
        assert_eq!(error.kind(), StorageErrorKind::Unavailable);
        assert_eq!(error.cleanup(), None, "the cleanup abort succeeded");
        assert_eq!(store.completes().len(), 1, "the commit was attempted");
        assert_eq!(store.aborts().len(), 1, "the dead session is not reused");
    }

    #[test]
    fn empty_stream_never_completes() {
        let store = MockStore::default();
        let mut writer = begin(&store);
        block_on(writer.finish()).expect("an empty stream still finishes");
        let error = block_on(writer.commit()).expect_err("an empty stream cannot complete");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(
            error.failure().detail(),
            "an empty stream cannot complete a content-addressed object"
        );
        assert!(store.completes().is_empty());
        assert_eq!(store.aborts().len(), 1, "the empty session is aborted");
    }

    #[test]
    fn commit_before_finish_never_completes() {
        let store = MockStore::default();
        let mut writer = begin(&store);
        block_on(writer.write_chunk(b"still buffered")).expect("chunk");
        let error = block_on(writer.commit()).expect_err("buffered bytes are unaccounted");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(
            error.failure().detail(),
            "finish the stream before committing"
        );
        assert!(store.completes().is_empty());
        assert_eq!(store.aborts().len(), 1);
    }

    #[test]
    fn write_after_finish_is_rejected() {
        let store = MockStore::default();
        let mut writer = begin(&store);
        block_on(writer.write_chunk(b"one")).expect("chunk");
        block_on(writer.finish()).expect("finish");
        block_on(writer.finish()).expect("finish is idempotent");
        let error = block_on(writer.write_chunk(b"late")).expect_err("stream is closed");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(
            error.failure().detail(),
            "multipart stream already finished"
        );
        let id = store.began()[0].clone();
        assert_eq!(store.parts_of(&id).len(), 1, "no further part I/O");
        // The writer is still committable: rejection is not failure.
        block_on(writer.commit()).expect("commit still allowed after validation");
    }

    #[test]
    fn wrong_part_commitment_fails_closed() {
        let store = MockStore::default();
        store.wrong_commitment();
        let mut writer = begin(&store);
        let error = block_on(writer.write_chunk(&vec![4u8; PART_BYTES]))
            .expect_err("commitment names the wrong part");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(
            error.failure().detail(),
            "backend returned a commitment for a different part"
        );
        assert!(store.completes().is_empty());
        assert_eq!(store.aborts().len(), 1);
    }

    #[test]
    fn explicit_abort_releases_the_session() {
        let store = MockStore::default();
        let open = OpenUploads::new();
        let mut writer = block_on(MultipartWriter::begin(&store, &blob_key(), &open))
            .expect("mock begin succeeds");
        block_on(writer.write_chunk(b"partial")).expect("chunk");
        block_on(writer.abort()).expect("explicit abort");
        assert!(store.completes().is_empty());
        assert_eq!(store.aborts().len(), 1);
        assert_eq!(open.live_count() + open.abandoned_count(), 0);
        assert!(
            block_on(open.abort_abandoned(&store)).is_empty(),
            "nothing left to drain"
        );
    }

    #[test]
    fn registry_tracks_writers_independently() {
        let store = MockStore::default();
        let open = OpenUploads::new();
        let first = block_on(MultipartWriter::begin(&store, &blob_key(), &open))
            .expect("mock begin succeeds");
        let mut second = block_on(MultipartWriter::begin(&store, &blob_key(), &open))
            .expect("mock begin succeeds");
        block_on(second.write_chunk(b"live")).expect("chunk");
        assert_eq!(open.live_count(), 2);
        drop(first);
        assert_eq!(open.live_count(), 1);
        assert_eq!(open.abandoned_count(), 1);

        // The drain aborts only the abandoned session, never the live one.
        assert!(block_on(open.abort_abandoned(&store)).is_empty());
        assert_eq!(store.aborts().len(), 1);
        assert_ne!(
            store.aborts()[0],
            store.began()[1],
            "the live session survives"
        );
        assert_eq!(open.live_count(), 1);
        block_on(second.commit()).expect_err("cannot commit without finish");
    }

    #[test]
    fn oversize_chunk_never_buffers_whole() {
        // A payload-scale single chunk is consumed in part-sized slices:
        // buffering stays at one part regardless of chunk size.
        let store = MockStore::default();
        let mut writer = begin(&store);
        let chunk = vec![5u8; 2 * PART_BYTES + 1];
        block_on(writer.write_chunk(&chunk)).expect("chunk");
        assert_eq!(writer.part_count(), 2);
        assert_eq!(writer.buffered_bytes(), 1);
        assert!(writer.buffered_bytes() < PART_BYTES);
        block_on(writer.finish()).expect("finish");
        block_on(writer.commit()).expect("commit");
        let id = store.began()[0].clone();
        assert_eq!(
            store.parts_of(&id),
            vec![(1, PART_BYTES), (2, PART_BYTES), (3, 1)]
        );
    }

    #[test]
    fn part_ordinal_enforces_the_portable_bound() {
        assert_eq!(part_ordinal(1).map(PartNumber::get), Some(1));
        assert_eq!(part_ordinal(10_000).map(PartNumber::get), Some(10_000));
        assert_eq!(part_ordinal(10_001), None);
        assert_eq!(part_ordinal(u32::MAX), None);
        assert_eq!(PART_BYTES, 8 * 1024 * 1024, "the pinned part size");
    }

    #[test]
    fn put_manifest_delegates_within_the_bound() {
        let store = MockStore::default();
        let key = occurrence_manifest_key();
        let outcome = block_on(put_manifest(&store, &key, b"{\"canonical\":true}")).expect("put");
        assert_eq!(outcome, StorageOutcome::Created);
        assert_eq!(store.manifests(), vec![(key.as_str().to_owned(), 18)]);

        let empty = block_on(put_manifest(&store, &key, b"")).expect_err("empty is malformed");
        assert_eq!(empty.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(empty.detail(), "manifest bytes are empty");

        let oversized = vec![b'x'; archivist_protocol::envelope::CANONICAL_MAX_BYTES + 1];
        let rejected =
            block_on(put_manifest(&store, &key, &oversized)).expect_err("oversize is malformed");
        assert_eq!(rejected.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(
            rejected.detail(),
            "manifest exceeds the canonical document bound"
        );
        assert_eq!(
            store.manifests().len(),
            1,
            "the two refusals never reached the store"
        );

        // The bound itself is inclusive: a maximal document is a store call.
        let maximal = vec![b'x'; archivist_protocol::envelope::CANONICAL_MAX_BYTES];
        block_on(put_manifest(&store, &key, &maximal)).expect("exactly at the bound");
        assert_eq!(store.manifests().len(), 2);
    }

    #[test]
    fn cleanup_failures_carry_the_session_and_reason() {
        let upload = MultipartUploadId::parse("mock-upload-9").unwrap();
        let failure = CleanupFailure::new(
            upload.clone(),
            StorageError::of_kind(StorageErrorKind::Unavailable),
        );
        assert_eq!(failure.upload(), &upload);
        assert_eq!(failure.error().kind(), StorageErrorKind::Unavailable);
    }

    #[test]
    fn error_display_and_details_are_safe_messages() {
        let plain =
            MultipartWriterError::new(StorageError::of_kind(StorageErrorKind::MalformedInput));
        assert_eq!(
            plain.to_string(),
            "multipart session failed: storage malformed-input: \
             request input is malformed or out of bounds"
        );
        let with_cleanup = MultipartWriterError::with_cleanup(
            StorageError::of_kind(StorageErrorKind::Unavailable),
            StorageError::of_kind(StorageErrorKind::Unavailable),
        );
        assert_eq!(
            with_cleanup.to_string(),
            "multipart session failed: storage unavailable: storage backend unavailable; \
             cleanup abort failed: storage unavailable: storage backend unavailable"
        );
        // Every static detail this module can emit stays inside the
        // project's safe-message grammar.
        for detail in [
            super::PART_BOUND_DETAIL,
            super::DEAD_SESSION_DETAIL,
            super::STREAM_FINISHED_DETAIL,
            super::UNFINISHED_DETAIL,
            super::EMPTY_STREAM_DETAIL,
            super::WRONG_COMMITMENT_DETAIL,
            super::EMPTY_MANIFEST_DETAIL,
            super::OVERSIZED_MANIFEST_DETAIL,
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
