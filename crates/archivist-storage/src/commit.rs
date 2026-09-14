// SPDX-License-Identifier: Apache-2.0

//! The deterministic commit decision layer: how one manifest object reaches
//! the tenant raw prefix honestly, on top of
//! [`crate::raw_write::RawWriteStore`].
//!
//! Given a derived key, the exact final bytes, and the store's own
//! [`StoreCapabilities`](crate::capability::StoreCapabilities) report,
//! [`commit_manifest`] selects the strongest
//! backend primitive the report establishes and carries the write through:
//!
//! - **Atomic conditional create when established (STO-005).** When the
//!   report says [`ConditionalCreate::Supported`], the commit goes through
//!   [`ConditionalCreateStore::create_manifest_if_absent`] — the backend's
//!   create-if-absent primitive. `Created` proves creation from the write
//!   response itself; an already-exists result is resolved by validating
//!   the readable metadata the backend reported about the existing object:
//!   evidence equivalent to the committed bytes converges on the existing
//!   logical object ([`StorageOutcome::AlreadyPresent`], STO-004), evidence
//!   that contradicts them raises
//!   [`StorageErrorKind::IntegrityConflict`]
//!   and writes nothing (EC-06, VAL-005), and existence without readable
//!   evidence either way is reported as
//!   [`StorageOutcome::LogicallyCommittedUnknownPhysicalResult`] — presence
//!   without readable compatible metadata is never reported as
//!   deduplication (RCPT-004; protocol Section 4.4).
//! - **Deterministic overwrite when the profile is writer-only (STO-006).**
//!   When conditional create is not established, the same bytes rewritten at
//!   the same derived key *is* the idempotency mechanism: the commit
//!   reports [`StorageOutcome::LogicallyCommittedUnknownPhysicalResult`],
//!   the weaker physical truth, whatever the raw write claimed — a
//!   writer-only identity cannot establish creation, presence, or
//!   replacement, and must not claim deduplication it cannot observe
//!   (RCPT-003, RCPT-004).
//!
//! Either mode converges: a replay of identical bytes at the same derived
//! key lands on one logical object, because the key is derived (STO-003)
//! and the bytes are a pure function of frozen inputs (STO-010) — the
//! primitive only decides which physical story the outcome may tell.
//!
//! # The atomic primitive is an opt-in implementation, never an assumption
//!
//! [`ConditionalCreateStore`] is the seam an adapter implements when its
//! backend has a real create-if-absent operation. Its provided default
//! fails closed with
//! [`StorageErrorKind::CapabilityUnavailable`]:
//! a store whose capability report claims conditional create while
//! implementing no primitive is a misconfiguration, and the commit refuses
//! loudly rather than silently degrading to overwrite (the same honest-mode
//! doctrine as [`crate::capability`]).

use std::future::Future;

use archivist_protocol::vocabulary::StorageOutcome;

use crate::capability::ConditionalCreate;
use crate::error::{StorageError, StorageErrorKind};
use crate::multipart::{bounded_manifest_bytes, put_manifest};
use crate::raw_write::{ManifestKey, RawWriteStore};

/// The static detail for acting on a capability the store did not report.
const CONDITIONAL_NOT_REPORTED_DETAIL: &str =
    "conditional create is not a reported capability of this store";
/// The static detail for a store whose report claims the atomic capability
/// while implementing no primitive.
const NO_ATOMIC_PRIMITIVE_DETAIL: &str =
    "this store does not implement an atomic create-if-absent primitive";
/// The static detail for readable evidence contradicting the committed
/// bytes at a derived key.
const INCOMPATIBLE_EXISTING_DETAIL: &str =
    "existing object at the derived key is incompatible with the committed bytes";

/// What the backend can state about an object that already occupies a
/// derived key, as reported by
/// [`ConditionalCreateStore::create_manifest_if_absent`].
///
/// Every field is optional because every field is an observation: a backend
/// that can only report existence constructs the empty value, and presence
/// without readable evidence is resolved as
/// [`StorageOutcome::LogicallyCommittedUnknownPhysicalResult`], never as
/// deduplication (RCPT-004).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExistingObject {
    size: Option<u64>,
    stored_sha256: Option<[u8; 32]>,
}

impl ExistingObject {
    /// The report of an object whose presence carries no readable evidence.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Report the stored content's length.
    #[must_use]
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Report the SHA-256 the backend maintains over the stored content —
    /// the project's content identity (STO-001), never a provider tag.
    #[must_use]
    pub fn with_stored_sha256(mut self, digest: [u8; 32]) -> Self {
        self.stored_sha256 = Some(digest);
        self
    }

    /// The stored content's length, when the backend exposed it.
    #[must_use]
    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    /// The stored content's SHA-256, when the backend exposed it.
    #[must_use]
    pub const fn stored_sha256(&self) -> Option<&[u8; 32]> {
        self.stored_sha256.as_ref()
    }
}

/// The result of one atomic create-if-absent attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateIfAbsent {
    /// The write created the object — the write response itself proves
    /// creation (STO-005).
    Created,
    /// The key already held an object, reported with whatever readable
    /// evidence the backend could attach.
    AlreadyExists(ExistingObject),
}

/// The atomic create-if-absent primitive over a raw manifest key, available
/// on stores whose backend established conditional create (STO-005).
///
/// An adapter implements this *in addition to* [`RawWriteStore`] when its
/// backend offers the operation (for the portable S3 family, a conditional
/// `PUT`). The atomicity is the point: the backend resolves the
/// create-or-exists race, so the commit decision layer can turn an
/// already-exists result into convergence or an integrity conflict without
/// ever reading, listing, or deleting.
///
/// The provided default is the honest absence of the primitive: it fails
/// with
/// [`StorageErrorKind::CapabilityUnavailable`].
/// A writer-only store adopts it with an empty impl; a store must not
/// report [`ConditionalCreate::Supported`] while keeping the default.
pub trait ConditionalCreateStore: RawWriteStore {
    /// Create `key` with exactly `bytes` if — and only if — the key is
    /// absent, atomically.
    ///
    /// # Errors
    /// [`StorageError::ScopeViolation`](crate::error::StorageError) when the
    /// key is outside this identity's provisioning,
    /// [`StorageErrorKind::CapabilityUnavailable`]
    /// from the provided default when this store implements no atomic
    /// primitive, [`StorageError::Unavailable`](crate::error::StorageError)
    /// when the backend or network is down.
    fn create_manifest_if_absent(
        &self,
        key: &ManifestKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<CreateIfAbsent, StorageError>> + Send {
        // The default body never looks at the request: its only answer is
        // that this store has no atomic primitive to run it on.
        let _ = (key, bytes);
        std::future::ready(Err(StorageError::new(
            StorageErrorKind::CapabilityUnavailable,
            NO_ATOMIC_PRIMITIVE_DETAIL,
        )))
    }
}

/// Commit one manifest object by the strongest primitive the store reports.
///
/// The single entry point the ingest path binds: it reads the store's own
/// [`StoreCapabilities`](crate::capability::StoreCapabilities) once and dispatches — atomic conditional create
/// ([`commit_by_conditional_create`]) when the report establishes it,
/// deterministic overwrite ([`commit_by_deterministic_overwrite`]) when the
/// profile is writer-only. Either way the payload bounds are enforced
/// before the store is touched, and the returned
/// [`StorageOutcome`] names exactly what the backend could establish —
/// never stronger (RCPT-003).
///
/// # Errors
/// [`StorageErrorKind::MalformedInput`](crate::error::StorageErrorKind)
/// for empty or oversized manifest bytes (rejected without a store call),
/// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
/// when readable evidence at the derived key contradicts the committed
/// bytes, [`StorageErrorKind::CapabilityUnavailable`](crate::error::StorageErrorKind)
/// when the report claims conditional create but the store implements no
/// atomic primitive, or the store's own failure otherwise.
pub async fn commit_manifest<S: RawWriteStore + ConditionalCreateStore + ?Sized>(
    store: &S,
    key: &ManifestKey,
    bytes: &[u8],
) -> Result<StorageOutcome, StorageError> {
    match store.capabilities().conditional_create {
        ConditionalCreate::Supported => commit_by_conditional_create(store, key, bytes).await,
        ConditionalCreate::Unavailable => {
            commit_by_deterministic_overwrite(store, key, bytes).await
        }
    }
}

/// Commit one manifest object by atomic conditional create (STO-005).
///
/// Runs the store's create-if-absent primitive and resolves the result:
/// `Created` is reported as [`StorageOutcome::Created`]; an already-exists
/// result is classified against the committed bytes —
/// - readable evidence proving the stored content equals these bytes
///   (a reported stored-content SHA-256, STO-001) converges on the existing
///   logical object as [`StorageOutcome::AlreadyPresent`] (STO-004);
/// - readable evidence contradicting them — a different stored digest, or a
///   different stored length — fails the call with
///   [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
///   and leaves whatever was there standing, never an overwrite (EC-06,
///   VAL-005);
/// - existence without evidence either way — nothing readable, or a length
///   match that cannot prove content equality — is reported as
///   [`StorageOutcome::LogicallyCommittedUnknownPhysicalResult`] (RCPT-004;
///   protocol Section 4.4: presence without readable compatible metadata is
///   never deduplication).
///
/// The call refuses a store that does not report conditional create:
/// treating an unreported capability as available would route around the
/// honest-mode contract ([`crate::capability`]).
///
/// # Errors
/// [`StorageErrorKind::MalformedInput`](crate::error::StorageErrorKind)
/// for empty or oversized manifest bytes,
/// [`StorageErrorKind::CapabilityUnavailable`](crate::error::StorageErrorKind)
/// when the store does not report conditional create or implements no
/// atomic primitive,
/// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
/// on contradicting readable evidence, or the store's own failure
/// otherwise.
pub async fn commit_by_conditional_create<S: RawWriteStore + ConditionalCreateStore + ?Sized>(
    store: &S,
    key: &ManifestKey,
    bytes: &[u8],
) -> Result<StorageOutcome, StorageError> {
    bounded_manifest_bytes(bytes)?;
    if store.capabilities().conditional_create != ConditionalCreate::Supported {
        return Err(StorageError::new(
            StorageErrorKind::CapabilityUnavailable,
            CONDITIONAL_NOT_REPORTED_DETAIL,
        ));
    }
    match store.create_manifest_if_absent(key, bytes).await? {
        CreateIfAbsent::Created => Ok(StorageOutcome::Created),
        CreateIfAbsent::AlreadyExists(existing) => match classify_existing(&existing, bytes) {
            ExistingCompatibility::Equivalent => Ok(StorageOutcome::AlreadyPresent),
            ExistingCompatibility::Contradicts => Err(StorageError::new(
                StorageErrorKind::IntegrityConflict,
                INCOMPATIBLE_EXISTING_DETAIL,
            )),
            ExistingCompatibility::Unproven => {
                Ok(StorageOutcome::LogicallyCommittedUnknownPhysicalResult)
            }
        },
    }
}

/// Commit one manifest object by deterministic overwrite (STO-006).
///
/// The writer-only profile's idempotency mechanism: the exact final bytes
/// rewritten at the derived key through the bounded simple `PUT`
/// ([`put_manifest`]). The commit always reports
/// [`StorageOutcome::LogicallyCommittedUnknownPhysicalResult`] — a
/// writer-only identity cannot establish creation, presence, or
/// replacement, so no raw-write report may be promoted into a stronger
/// outcome and no deduplication is claimed (RCPT-003, RCPT-004). Logical
/// convergence holds because the key is derived (STO-003) and the bytes are
/// deterministic (STO-010); on a versioned backend the deployment owns the
/// lifecycle expiration of redundant noncurrent versions (STO-009).
///
/// # Errors
/// [`StorageErrorKind::MalformedInput`](crate::error::StorageErrorKind)
/// for empty or oversized manifest bytes (rejected without a store call),
/// or the store's own failure otherwise.
pub async fn commit_by_deterministic_overwrite<S: RawWriteStore + ?Sized>(
    store: &S,
    key: &ManifestKey,
    bytes: &[u8],
) -> Result<StorageOutcome, StorageError> {
    put_manifest(store, key, bytes).await?;
    Ok(StorageOutcome::LogicallyCommittedUnknownPhysicalResult)
}

/// How the readable evidence about an existing object relates to the bytes
/// being committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExistingCompatibility {
    /// The backend's evidence proves the stored content is these bytes.
    Equivalent,
    /// The backend's evidence contradicts the committed identity.
    Contradicts,
    /// Existence without readable evidence proving either way.
    Unproven,
}

/// Classify the reported evidence for an existing object against `bytes`.
///
/// A reported stored-content SHA-256 decides: equality proves equivalence,
/// inequality contradicts. Without a digest a reported length can only
/// contradict (a different length is impossible for the same bytes) —
/// agreement proves nothing about content, so it stays unproven. Nothing
/// readable at all is unproven by definition (RCPT-004).
fn classify_existing(existing: &ExistingObject, bytes: &[u8]) -> ExistingCompatibility {
    if let Some(digest) = existing.stored_sha256() {
        if digest == &archivist_protocol::sha256::digest(bytes) {
            return ExistingCompatibility::Equivalent;
        }
        return ExistingCompatibility::Contradicts;
    }
    match existing.size() {
        Some(size) if size == bytes.len() as u64 => ExistingCompatibility::Unproven,
        Some(_) => ExistingCompatibility::Contradicts,
        None => ExistingCompatibility::Unproven,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use archivist_protocol::envelope::CANONICAL_MAX_BYTES;
    use archivist_protocol::object_key::{BlobObjectKey, OccurrenceObjectKey};
    use archivist_protocol::sha256;
    use archivist_protocol::vocabulary::{
        ClientId, HarnessId, OccurrenceId, SessionHash, StorageOutcome, TenantId,
    };

    use super::{
        ConditionalCreateStore, CreateIfAbsent, ExistingObject, commit_by_conditional_create,
        commit_by_deterministic_overwrite, commit_manifest,
    };
    use crate::capability::{
        ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
    };
    use crate::error::{StorageError, StorageErrorKind};
    use crate::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// The out-of-bounds empty manifest: refused before any store call.
    const EMPTY_BYTES: &[u8] = b"";

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

    fn occurrence_manifest_key() -> ManifestKey {
        ManifestKey::Occurrence(OccurrenceObjectKey::new(
            &TenantId::parse(TENANT).unwrap(),
            &ClientId::parse("aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f").unwrap(),
            &HarnessId::parse("claude-code").unwrap(),
            &SessionHash::parse(DIGEST).unwrap(),
            &OccurrenceId::parse(DIGEST).unwrap(),
        ))
    }

    /// The canonical manifest payload under test: bounded, non-empty, and
    /// distinct from its deliberately incompatible counterpart below.
    const COMMITTED_BYTES: &[u8] = b"{\"occurrence\":\"canonical-bytes\"}";
    /// Same length as `COMMITTED_BYTES`, different content: the sharpest
    /// unproven case, because size alone cannot tell them apart.
    const EQUAL_LENGTH_OTHER_BYTES: &[u8] = b"{\"occurrence\":\"cAnonical-bytes\"}";
    /// Different length: a size-only report can reject this outright.
    const OTHER_LENGTH_BYTES: &[u8] = b"{\"occurrence\":\"canonical-bytes\"}\n";

    /// What the atomic mock reports about an existing object.
    #[derive(Clone, Copy, Default)]
    struct Report {
        size: bool,
        digest: bool,
    }

    /// Shared recorded state behind both mocks (`Mutex`, not `RefCell`, so
    /// the trait's `Send` futures hold).
    #[derive(Default)]
    struct FakeState {
        objects: HashMap<String, Vec<u8>>,
        report: Report,
        primitive_calls: u32,
        overwrite_calls: u32,
        overwrite_outcome: Option<StorageOutcome>,
    }

    impl FakeState {
        fn seed(&mut self, key: &ManifestKey, bytes: &[u8]) {
            self.objects.insert(key.as_str().to_owned(), bytes.to_vec());
        }

        fn stored_bytes(&self, key: &ManifestKey) -> Option<&Vec<u8>> {
            self.objects.get(key.as_str())
        }

        fn evidence(&self, stored: &[u8]) -> ExistingObject {
            let mut existing = ExistingObject::new();
            if self.report.size {
                existing = existing.with_size(stored.len() as u64);
            }
            if self.report.digest {
                existing = existing.with_stored_sha256(sha256::digest(stored));
            }
            existing
        }
    }

    /// A store that reports conditional create `Supported` and implements
    /// the atomic primitive for real (mocked atomically: the `HashMap`
    /// check-and-insert is one locked step).
    struct FakeAtomicStore {
        state: Mutex<FakeState>,
    }

    impl FakeAtomicStore {
        fn new(report: Report) -> Self {
            Self {
                state: Mutex::new(FakeState {
                    report,
                    ..FakeState::default()
                }),
            }
        }

        fn seed(&self, key: &ManifestKey, bytes: &[u8]) {
            self.state.lock().unwrap().seed(key, bytes);
        }
    }

    impl RawWriteStore for FakeAtomicStore {
        fn capabilities(&self) -> StoreCapabilities {
            StoreCapabilities {
                conditional_create: ConditionalCreate::Supported,
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
            self.state.lock().unwrap().overwrite_calls += 1;
            panic!("the atomic path never falls back to overwrite");
        }

        async fn begin_multipart(
            &self,
            _blob: &BlobObjectKey,
        ) -> Result<MultipartUploadId, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::MalformedInput))
        }

        async fn write_part(
            &self,
            _upload: &MultipartUploadId,
            _part: PartNumber,
            _bytes: &[u8],
        ) -> Result<PartCommitment, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::MalformedInput))
        }

        async fn commit_multipart(
            &self,
            _upload: &MultipartUploadId,
            _parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::MalformedInput))
        }

        async fn abort_multipart(&self, _upload: &MultipartUploadId) -> Result<(), StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::MalformedInput))
        }
    }

    impl ConditionalCreateStore for FakeAtomicStore {
        async fn create_manifest_if_absent(
            &self,
            key: &ManifestKey,
            bytes: &[u8],
        ) -> Result<CreateIfAbsent, StorageError> {
            let mut state = self.state.lock().unwrap();
            state.primitive_calls += 1;
            if let Some(stored) = state.objects.get(key.as_str()) {
                return Ok(CreateIfAbsent::AlreadyExists(state.evidence(stored)));
            }
            state
                .objects
                .insert(key.as_str().to_owned(), bytes.to_vec());
            Ok(CreateIfAbsent::Created)
        }
    }

    /// A store with no atomic primitive (empty [`ConditionalCreateStore`]
    /// impl). `reports_supported` true is the misconfiguration under test:
    /// the report claims the capability while the default primitive is
    /// inherited.
    struct FakeWriterStore {
        reports_supported: bool,
        state: Mutex<FakeState>,
    }

    impl FakeWriterStore {
        fn writer_only() -> Self {
            Self {
                reports_supported: false,
                state: Mutex::new(FakeState::default()),
            }
        }

        fn lying_overwrite(outcome: StorageOutcome) -> Self {
            Self {
                reports_supported: false,
                state: Mutex::new(FakeState {
                    overwrite_outcome: Some(outcome),
                    ..FakeState::default()
                }),
            }
        }

        fn misconfigured() -> Self {
            Self {
                reports_supported: true,
                state: Mutex::new(FakeState::default()),
            }
        }
    }

    impl RawWriteStore for FakeWriterStore {
        fn capabilities(&self) -> StoreCapabilities {
            StoreCapabilities {
                conditional_create: if self.reports_supported {
                    ConditionalCreate::Supported
                } else {
                    ConditionalCreate::Unavailable
                },
                stored_checksum: StoredChecksum::Unavailable,
                versioning: VersioningState::Unknown,
                server_side_encryption: EncryptionState::Unavailable,
            }
        }

        async fn write_manifest(
            &self,
            key: &ManifestKey,
            bytes: &[u8],
        ) -> Result<StorageOutcome, StorageError> {
            let mut state = self.state.lock().unwrap();
            state.overwrite_calls += 1;
            state
                .objects
                .insert(key.as_str().to_owned(), bytes.to_vec());
            Ok(state.overwrite_outcome.unwrap_or(StorageOutcome::Created))
        }

        async fn begin_multipart(
            &self,
            _blob: &BlobObjectKey,
        ) -> Result<MultipartUploadId, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::MalformedInput))
        }

        async fn write_part(
            &self,
            _upload: &MultipartUploadId,
            _part: PartNumber,
            _bytes: &[u8],
        ) -> Result<PartCommitment, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::MalformedInput))
        }

        async fn commit_multipart(
            &self,
            _upload: &MultipartUploadId,
            _parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::MalformedInput))
        }

        async fn abort_multipart(&self, _upload: &MultipartUploadId) -> Result<(), StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::MalformedInput))
        }
    }

    impl ConditionalCreateStore for FakeWriterStore {}

    #[test]
    fn conditional_commit_creates_then_replays_as_already_present() {
        let store = FakeAtomicStore::new(Report {
            size: true,
            digest: true,
        });
        let key = occurrence_manifest_key();

        let first =
            block_on(commit_manifest(&store, &key, COMMITTED_BYTES)).expect("first commit creates");
        assert_eq!(first, StorageOutcome::Created);

        let replay = block_on(commit_manifest(&store, &key, COMMITTED_BYTES))
            .expect("identical replay converges");
        assert_eq!(replay, StorageOutcome::AlreadyPresent);

        let state = store.state.lock().unwrap();
        assert_eq!(
            state.objects.len(),
            1,
            "replay converges on one logical object"
        );
        assert_eq!(
            state.primitive_calls, 2,
            "both commits used the atomic primitive"
        );
        assert_eq!(state.overwrite_calls, 0, "overwrite is never touched");
    }

    #[test]
    fn digest_mismatch_conflicts_and_never_overwrites() {
        let store = FakeAtomicStore::new(Report {
            size: true,
            digest: true,
        });
        let key = occurrence_manifest_key();
        store.seed(&key, EQUAL_LENGTH_OTHER_BYTES);

        let failure = block_on(commit_manifest(&store, &key, COMMITTED_BYTES))
            .expect_err("contradicting digest is a conflict");
        assert_eq!(failure.kind(), StorageErrorKind::IntegrityConflict);

        let state = store.state.lock().unwrap();
        assert_eq!(
            state.stored_bytes(&key).map(Vec::as_slice),
            Some(EQUAL_LENGTH_OTHER_BYTES),
            "whatever was there stays; nothing is written over it"
        );
        assert_eq!(state.overwrite_calls, 0, "no silent overwrite");
    }

    #[test]
    fn size_mismatch_conflicts_without_digest() {
        let store = FakeAtomicStore::new(Report {
            size: true,
            digest: false,
        });
        let key = occurrence_manifest_key();
        store.seed(&key, OTHER_LENGTH_BYTES);

        let failure = block_on(commit_manifest(&store, &key, COMMITTED_BYTES))
            .expect_err("a different stored length cannot be the same bytes");
        assert_eq!(failure.kind(), StorageErrorKind::IntegrityConflict);
        let state = store.state.lock().unwrap();
        assert_eq!(state.overwrite_calls, 0);
    }

    #[test]
    fn equal_size_without_digest_is_not_deduplication() {
        let store = FakeAtomicStore::new(Report {
            size: true,
            digest: false,
        });
        let key = occurrence_manifest_key();
        store.seed(&key, EQUAL_LENGTH_OTHER_BYTES);

        let outcome = block_on(commit_manifest(&store, &key, COMMITTED_BYTES))
            .expect("length agreement is no contradiction");
        assert_eq!(
            outcome,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult,
            "size alone never proves equivalence, so presence is not reported as dedup"
        );

        let state = store.state.lock().unwrap();
        assert_eq!(
            state.stored_bytes(&key).map(Vec::as_slice),
            Some(EQUAL_LENGTH_OTHER_BYTES),
            "the unproven replay rewrote nothing"
        );
        assert_eq!(state.overwrite_calls, 0);
    }

    #[test]
    fn existence_without_readable_metadata_reports_unknown_physical() {
        let store = FakeAtomicStore::new(Report::default());
        let key = occurrence_manifest_key();
        store.seed(&key, EQUAL_LENGTH_OTHER_BYTES);

        let outcome = block_on(commit_manifest(&store, &key, COMMITTED_BYTES))
            .expect("bare existence is no contradiction");
        assert_eq!(
            outcome,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
    }

    #[test]
    fn reported_digest_match_converges_without_size() {
        let store = FakeAtomicStore::new(Report {
            size: false,
            digest: true,
        });
        let key = occurrence_manifest_key();
        store.seed(&key, COMMITTED_BYTES);

        let outcome =
            block_on(commit_manifest(&store, &key, COMMITTED_BYTES)).expect("digest matches");
        assert_eq!(outcome, StorageOutcome::AlreadyPresent);
    }

    #[test]
    fn writer_only_replays_report_unknown_physical_result() {
        let store = FakeWriterStore::writer_only();
        let key = occurrence_manifest_key();

        let first = block_on(commit_manifest(&store, &key, COMMITTED_BYTES))
            .expect("writer-only commit succeeds");
        assert_eq!(
            first,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );

        let replay = block_on(commit_manifest(&store, &key, COMMITTED_BYTES))
            .expect("identical replay converges the same way");
        assert_eq!(
            replay,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );

        let state = store.state.lock().unwrap();
        assert_eq!(
            state.objects.len(),
            1,
            "deterministic overwrite keeps one logical object at the key"
        );
        assert_eq!(
            state.overwrite_calls, 2,
            "both commits went through the raw deterministic write"
        );
        assert_eq!(
            state.primitive_calls, 0,
            "a writer-only profile never reaches for an atomic primitive"
        );
    }

    #[test]
    fn writer_only_never_reports_a_stronger_outcome_than_the_truth() {
        // A naive raw write that overclaims — `Created`, `AlreadyPresent`,
        // or `ReplacedEquivalent` from an identity that can observe none of
        // those — is downgraded to the weaker physical truth.
        for fabricated in [
            StorageOutcome::Created,
            StorageOutcome::AlreadyPresent,
            StorageOutcome::ReplacedEquivalent,
        ] {
            let store = FakeWriterStore::lying_overwrite(fabricated);
            let outcome = block_on(commit_manifest(
                &store,
                &occurrence_manifest_key(),
                COMMITTED_BYTES,
            ))
            .expect("the commit itself succeeds");
            assert_eq!(
                outcome,
                StorageOutcome::LogicallyCommittedUnknownPhysicalResult,
                "no fabricated dedup evidence survives the layer"
            );
        }
    }

    #[test]
    fn claimed_but_unimplemented_primitive_fails_closed() {
        let store = FakeWriterStore::misconfigured();
        let key = occurrence_manifest_key();

        let failure = block_on(commit_manifest(&store, &key, COMMITTED_BYTES))
            .expect_err("a claimed capability without a primitive is a misconfiguration");
        assert_eq!(failure.kind(), StorageErrorKind::CapabilityUnavailable);

        let state = store.state.lock().unwrap();
        assert_eq!(
            state.overwrite_calls, 0,
            "the commit refuses loudly instead of silently degrading to overwrite"
        );
    }

    #[test]
    fn conditional_mode_refuses_an_unreported_capability() {
        let store = FakeWriterStore::writer_only();
        let failure = block_on(commit_by_conditional_create(
            &store,
            &occurrence_manifest_key(),
            COMMITTED_BYTES,
        ))
        .expect_err("an unreported capability is final, not something to route around");
        assert_eq!(failure.kind(), StorageErrorKind::CapabilityUnavailable);
    }

    #[test]
    fn manifest_bounds_fail_before_any_store_call() {
        let oversized = vec![0u8; CANONICAL_MAX_BYTES + 1];
        let atomic = FakeAtomicStore::new(Report {
            size: true,
            digest: true,
        });
        let writer = FakeWriterStore::writer_only();
        let key = occurrence_manifest_key();

        for bytes in [EMPTY_BYTES, oversized.as_slice()] {
            for failure in [
                block_on(commit_manifest(&atomic, &key, bytes)),
                block_on(commit_by_conditional_create(&atomic, &key, bytes)),
                block_on(commit_by_deterministic_overwrite(&writer, &key, bytes)),
            ] {
                let failure = failure.expect_err("out-of-bounds manifests are refused");
                assert_eq!(failure.kind(), StorageErrorKind::MalformedInput);
            }
        }

        assert_eq!(atomic.state.lock().unwrap().primitive_calls, 0);
        assert_eq!(atomic.state.lock().unwrap().overwrite_calls, 0);
        assert_eq!(writer.state.lock().unwrap().overwrite_calls, 0);
    }

    #[test]
    fn deterministic_overwrite_commits_through_the_bounded_put() {
        let store = FakeWriterStore::writer_only();
        let key = occurrence_manifest_key();
        let outcome = block_on(commit_by_deterministic_overwrite(
            &store,
            &key,
            COMMITTED_BYTES,
        ))
        .expect("the bounded put succeeds");
        assert_eq!(
            outcome,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        let state = store.state.lock().unwrap();
        assert_eq!(
            state.stored_bytes(&key).map(Vec::as_slice),
            Some(COMMITTED_BYTES),
            "the exact final bytes are what reached the key"
        );
        assert_eq!(state.overwrite_calls, 1);
    }
}
