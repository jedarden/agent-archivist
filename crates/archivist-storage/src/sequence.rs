// SPDX-License-Identifier: Apache-2.0

//! The three-object commit sequence: one validated attempt reaching a
//! durable blob, occurrence manifest, and upload attestation in the
//! protocol's normative order, and what a failed or interrupted attempt
//! leaves standing (protocol Section 4.1; plan Section 5, server flow
//! steps 7–9).
//!
//! One successful ingest writes exactly three objects, in this order:
//! the raw blob (multipart upload → complete, only after every size,
//! digest, and the request signature verified against the bytes actually
//! produced), the occurrence manifest (only after the blob is durable at
//! its key), and the upload attestation (only after the bound occurrence
//! manifest is durable at its key). [`commit_sequence`] is that contract
//! as one call: it derives the blob expectation from the envelope the
//! way the ingest path does, drives the payload through
//! [`commit_blob`], and — only once that
//! commit reports the blob durable — lands the two manifests through
//! [`commit_provenance`]. A request is successful only after all three
//! are durably accepted (RCPT-001): [`SequenceCommit`] exists only on
//! that condition, and carries each object's key and the store's own
//! physical outcome for the receipt to bind (RCPT-003).
//!
//! # The reachable partial states are exactly three
//!
//! The write order is normative (RCPT-001), so a failed attempt stands
//! in one of exactly three durable states — nothing, blob-only, or
//! blob-plus-occurrence (protocol Section 4.1). An occurrence without
//! its blob or an attestation without its occurrence is unreachable by
//! construction, which [`DurableState`] names and [`SequenceError`]
//! reports: whatever failed, the error says how far the sequence got so
//! the caller can render the honest `server.partial_commit` class
//! (RCPT-005) without inventing state the sequence never reached.
//!
//! # Repair by identical retry is convergence, not surgery
//!
//! No server-side recovery queue exists because none is needed
//! (protocol Section 4.5; plan Section 5): the retry re-authorizes
//! freshly over the *identical* frozen envelope, re-derives the
//! identical keys, and re-runs this sequence. The already-durable
//! objects converge per protocol Section 4.4 — a replay of the same
//! deterministic bytes at the same derived key is deduplication
//! ([`StorageOutcome::AlreadyPresent`](archivist_protocol::vocabulary::StorageOutcome)
//! when readable evidence proves it, the weaker logical truth when the
//! profile cannot prove anything), and the missing objects are written
//! for the first time. Because every identity input is frozen in the
//! envelope, the sequence holds no per-replica state a retry could miss:
//! terminating at any boundary and retrying through any other replica —
//! or this one — converges on the same three logical objects without
//! multiplying logical provenance (STO-004, STO-013): uploader and
//! request never enter the occurrence, so two uploaders of one source
//! event converge on one occurrence (EC-05A), and a retry of one frozen
//! request folds the same `attestation_id` and rewrites its one
//! attestation.
//!
//! # Repair never fixes by overwriting
//!
//! An incompatible object at any of the three keys propagates
//! [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind::IntegrityConflict)
//! with the stored object left
//! exactly as it was (EC-06, PI-08): the conflict is an operator-visible
//! stop, never a transient retry and never a silent overwrite. The
//! sequence reports it with the durable state it had reached, so the
//! caller's wire class stays honest about what stands.
//!
//! Identity is re-derived, never trusted (SID-005): each manifest layer
//! re-derives its own identity before its own write, and the blob
//! address is the validated digest of the bytes the stream produced —
//! this layer adds ordering, never a second opinion on identity.

use std::fmt;

use archivist_protocol::envelope::Envelope;

use crate::blob::{BlobCommit, BlobCommitError, BlobEncoder, BlobExpectation, commit_blob};
use crate::commit::ConditionalCreateStore;
use crate::error::StorageError;
use crate::manifests::{
    Delegation, ManifestCommit, commit_attestation_manifest, commit_occurrence_manifest,
};
use crate::multipart::OpenUploads;
use crate::raw_write::RawWriteStore;

/// The durable state one attempt of the sequence reached — the exactly
/// three partial states a failed attempt can stand in (protocol Section
/// 4.1: the write order is normative, so an occurrence without its blob
/// or an attestation without its occurrence is unreachable by
/// construction). Success is not a variant: it is
/// [`SequenceCommit`], which exists only once all three objects are
/// durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DurableState {
    /// No object is durable: the attempt ended at or before the blob
    /// commit, so nothing visible stands at any derived key.
    Nothing,
    /// The blob is durable at its content-addressed key; the occurrence
    /// manifest and attestation are not.
    BlobOnly,
    /// The blob and the occurrence manifest are durable; only the
    /// upload attestation is missing.
    BlobAndOccurrence,
}

impl fmt::Display for DurableState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nothing => write!(f, "nothing durable"),
            Self::BlobOnly => write!(f, "only the blob is durable"),
            Self::BlobAndOccurrence => write!(f, "the blob and occurrence manifest are durable"),
        }
    }
}

/// Why the sequence ended short of all three objects: the durable state
/// the attempt reached, the failure that stopped it, and — when the
/// failure was a blob-commit validation whose cleanup abort itself
/// failed — that abort failure carried alongside, never swallowed (the
/// same content-safe composite as [`BlobCommitError`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SequenceError {
    durable: DurableState,
    failure: StorageError,
    cleanup: Option<StorageError>,
}

impl SequenceError {
    /// The durable state the attempt had reached when it failed — what
    /// an identical retry will converge on rather than rewrite.
    #[must_use]
    pub const fn durable(&self) -> DurableState {
        self.durable
    }

    /// The failure class that stopped the sequence.
    #[must_use]
    pub const fn kind(&self) -> crate::error::StorageErrorKind {
        self.failure.kind()
    }

    /// The failure that stopped the sequence.
    #[must_use]
    pub const fn failure(&self) -> StorageError {
        self.failure
    }

    /// The cleanup abort failure, when a blob-commit validation
    /// attempted its abort and the abort did not succeed — the session
    /// stays registered in the caller's [`OpenUploads`] for a later
    /// drain.
    #[must_use]
    pub const fn cleanup(&self) -> Option<StorageError> {
        self.cleanup
    }
}

impl fmt::Display for SequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.cleanup {
            None => write!(
                f,
                "commit sequence failed with {}: {}",
                self.durable, self.failure
            ),
            Some(cleanup) => write!(
                f,
                "commit sequence failed with {}: {}; cleanup abort failed: {cleanup}",
                self.durable, self.failure
            ),
        }
    }
}

impl std::error::Error for SequenceError {}

/// What one successful provenance tail established: the occurrence
/// manifest and the upload attestation, each with its derived key and
/// the store's own physical outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceCommit {
    occurrence: ManifestCommit,
    attestation: ManifestCommit,
}

impl ProvenanceCommit {
    /// The occurrence manifest's commit — the derived key and the
    /// store's physical truth for the source-stable record.
    #[must_use]
    pub const fn occurrence(&self) -> &ManifestCommit {
        &self.occurrence
    }

    /// The upload attestation's commit — the derived key and the
    /// store's physical truth for the uploader's own record.
    #[must_use]
    pub const fn attestation(&self) -> &ManifestCommit {
        &self.attestation
    }
}

/// What one successful sequence established: all three objects durable,
/// each with its server-derived key and the store's own physical
/// outcome — never strengthened, exactly the per-object results the
/// receipt binds (RCPT-001, RCPT-003).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequenceCommit {
    blob: BlobCommit,
    provenance: ProvenanceCommit,
}

impl SequenceCommit {
    /// The content-addressed blob's commit — key and physical outcome.
    #[must_use]
    pub const fn blob(&self) -> &BlobCommit {
        &self.blob
    }

    /// The occurrence manifest's commit — key and physical outcome.
    #[must_use]
    pub const fn occurrence(&self) -> &ManifestCommit {
        &self.provenance.occurrence
    }

    /// The upload attestation's commit — key and physical outcome.
    #[must_use]
    pub const fn attestation(&self) -> &ManifestCommit {
        &self.provenance.attestation
    }
}

/// Drive the full three-object sequence for one validated envelope:
/// blob, occurrence, then attestation, each only after the previous is
/// durable (protocol Section 4.1; plan Section 5, steps 7–9).
///
/// The blob expectation is the envelope's own declaration — the content
/// digest that names the address and the declared uncompressed extent —
/// exactly as the ingest path derives it, and [`commit_blob`] holds the
/// stream to it before anything completes. The canonical iterable is
/// consumed synchronously; the async streaming adaptation is the server
/// pipeline's. On success every object's key and physical outcome
/// travel out untouched (RCPT-003).
///
/// A failure reports [`SequenceError::durable`] — how far the attempt
/// got — with the store's own failure class, so an identical retry
/// converges on what stands instead of rewriting it (protocol Section
/// 4.5). A blob-commit failure aborts the live session itself (its
/// cleanup abort rides along in [`SequenceError::cleanup`]); a manifest
/// failure leaves the earlier objects durable and writes nothing later
/// in the order.
///
/// # Errors
/// [`SequenceError`] whose `durable` state is exactly what the attempt
/// reached: nothing (the blob never completed), blob-only (the
/// occurrence write failed), or blob-plus-occurrence (the attestation
/// write failed).
pub async fn commit_sequence<S, E, I>(
    store: &S,
    open: &OpenUploads,
    envelope: &Envelope,
    delegation: Delegation,
    encoder: &mut E,
    canonical: I,
) -> Result<SequenceCommit, SequenceError>
where
    S: RawWriteStore + ConditionalCreateStore + ?Sized,
    E: BlobEncoder,
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let expectation = BlobExpectation::new(envelope.blob_digest, envelope.uncompressed_size);
    let blob = commit_blob(
        store,
        open,
        &envelope.tenant_id,
        expectation,
        encoder,
        canonical,
    )
    .await
    .map_err(|error: BlobCommitError| SequenceError {
        durable: DurableState::Nothing,
        failure: error.failure(),
        cleanup: error.cleanup(),
    })?;
    let provenance = commit_provenance(store, envelope, delegation).await?;
    Ok(SequenceCommit { blob, provenance })
}

/// Land the occurrence manifest and then the upload attestation —
/// protocol Section 4.1's steps 8 and 9, the tail the ingest path runs
/// once its streaming pass holds a durable blob.
///
/// The precondition is the sequence's own ordering contract: call this
/// only after the envelope's blob is durable at its key, because the
/// [`DurableState`] an error reports counts that blob. Each manifest is
/// committed through its own layer with its own identity re-derivation
/// (SID-005), and the attestation is written only after the occurrence
/// commit reported durable — an attestation without its occurrence is
/// unreachable by construction.
///
/// # Errors
/// [`SequenceError`] with [`DurableState::BlobOnly`] when the
/// occurrence write failed, or [`DurableState::BlobAndOccurrence`] when
/// the attestation write failed; an incompatible object at either key
/// is [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
/// with the stored object left as it was.
pub async fn commit_provenance<S>(
    store: &S,
    envelope: &Envelope,
    delegation: Delegation,
) -> Result<ProvenanceCommit, SequenceError>
where
    S: RawWriteStore + ConditionalCreateStore + ?Sized,
{
    let occurrence = commit_occurrence_manifest(store, envelope)
        .await
        .map_err(|failure| SequenceError {
            durable: DurableState::BlobOnly,
            failure,
            cleanup: None,
        })?;
    let attestation = commit_attestation_manifest(store, envelope, delegation)
        .await
        .map_err(|failure| SequenceError {
            durable: DurableState::BlobAndOccurrence,
            failure,
            cleanup: None,
        })?;
    Ok(ProvenanceCommit {
        occurrence,
        attestation,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};

    use archivist_protocol::derivation;
    use archivist_protocol::envelope::Envelope;
    use archivist_protocol::object_key::{
        AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey,
    };
    use archivist_protocol::sha256::{self, Sha256};
    use archivist_protocol::vocabulary::{
        AdapterId, ArtifactKind, BlobDigest, ChecksumAlgorithm, ClientId, GenerationId, HarnessId,
        IdSource, IncomingChecksum, OpaqueId, RangeKind, RequestId, StorageOutcome, StorageProfile,
        TenantId, Timestamp, TransportEncoding, VersionToken,
    };

    use super::{DurableState, commit_provenance, commit_sequence};
    use crate::blob::{BlobEncoder, BlobExpectation, commit_blob};
    use crate::capability::{
        ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
    };
    use crate::commit::{ConditionalCreateStore, CreateIfAbsent, ExistingObject};
    use crate::error::{StorageError, StorageErrorKind};
    use crate::manifests::{Delegation, commit_occurrence_manifest};
    use crate::metadata::ObjectTag;
    use crate::multipart::OpenUploads;
    use crate::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };
    use crate::zstd_v1::ZstdV1Encoder;

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const ORIGIN: &str = "11111111-2222-4333-8444-555555555555";
    const RELAY: &str = "aaaaaaa1-bbbb-4ccc-9ddd-1e2f3f4f5f6f";
    /// The canonical payload one attempt presents: arbitrary bytes whose
    /// digest the envelope declares and the stream must reproduce.
    const BODY: &[u8] = b"agent-archivist three-object sequence canonical payload";

    /// A no-dependency executor for the mock futures, following the
    /// blob-module pattern: every mock future completes without pending,
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

    /// The passthrough transform: the stored form is the canonical form.
    /// The deterministic-encoder contract (VAL-006) is the real profile's;
    /// the sequence under test never inspects the stored bytes.
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

    /// A validated envelope whose identity inputs derive the declared
    /// ids and whose blob declaration is the honest one for `body`.
    fn envelope_for(body: &[u8], uploader: &str, request: &str) -> Envelope {
        let tenant = TenantId::parse(TENANT).expect("test tenant");
        let origin = ClientId::parse(ORIGIN).expect("test origin");
        let uploader = ClientId::parse(uploader).expect("test uploader");
        let harness = HarnessId::parse("claude-code").expect("test harness");
        let upstream = OpaqueId::parse("4f9c2f1e-8a3d-4b67-9c2f-1e8a3d4b679c").expect("session");
        let adapter = AdapterId::parse("claude-jsonl").expect("adapter");
        let projection = VersionToken::parse("1").expect("projection");
        let artifact_id = OpaqueId::parse("session-file-4f9c2f1e").expect("artifact");
        let generation = GenerationId::parse("1a079d80-7000-7000-8000-000000000051").expect("gen");
        let request_id = RequestId::parse(request).expect("request");

        let session = derivation::session_hash(&tenant, &origin, &harness, upstream.as_str());
        let artifact = derivation::artifact_hash(
            &session,
            ArtifactKind::FileSlice,
            &adapter,
            &projection,
            artifact_id.as_str(),
        );
        let blob = derivation::blob_digest(body);
        let occurrence = derivation::occurrence_id(
            &session,
            &artifact,
            &generation,
            RangeKind::Byte,
            0,
            body.len().saturating_sub(1) as u64,
            &blob,
        );
        let attestation = derivation::attestation_id(&occurrence, &uploader, &request_id);
        Envelope {
            tenant_id: tenant,
            origin_client_id: origin,
            uploader_client_id: uploader,
            harness,
            upstream_session_id: upstream,
            id_source: IdSource::Upstream,
            artifact_kind: ArtifactKind::FileSlice,
            adapter_id: adapter,
            adapter_projection_version: projection,
            adapter_artifact_id: artifact_id,
            generation,
            range_kind: RangeKind::Byte,
            range_start: 0,
            range_end: body.len().saturating_sub(1) as u64,
            blob_digest: blob,
            incoming_checksum: IncomingChecksum::parse(&sha256::encode_hex(&sha256::digest(body)))
                .expect("checksum grammar"),
            incoming_checksum_algorithm: ChecksumAlgorithm::Sha256,
            storage_profile: StorageProfile::ZstdV1,
            transport_encoding: TransportEncoding::Identity,
            compressed_size: body.len() as u64,
            uncompressed_size: body.len() as u64,
            occurrence_id: occurrence,
            attestation_id: attestation,
            request_id,
            capture_time: Timestamp::parse("2026-09-11T16:44:10Z").expect("capture time"),
            envelope_creation_time: Timestamp::parse("2026-09-11T16:44:11Z").expect("creation"),
            source_time: Some(Timestamp::parse("2026-09-11T16:44:02Z").expect("source")),
            parent_session_id: None,
            orchestrator_attempt_id: None,
            trace_id: None,
            inference_request_id: None,
            unknown_fields: archivist_protocol::json::Object::new(),
        }
    }

    fn direct_envelope() -> Envelope {
        envelope_for(BODY, ORIGIN, "1a079e10-7000-7000-8000-000000000001")
    }

    /// The same source event presented by an authorized relay: a
    /// distinct uploader whose frozen request folds its own
    /// `attestation_id` (STO-013) while every occurrence input — and so
    /// the occurrence itself — is unchanged.
    fn relayed_envelope() -> Envelope {
        envelope_for(BODY, RELAY, "1a079e10-7000-7000-8000-000000000002")
    }

    fn direct_delegation() -> Delegation {
        Delegation::Direct
    }

    /// The derived keys the three objects must land at — computed here
    /// from the envelope the way each layer derives them, so the tests
    /// assert against the derivation, not a copy of it.
    fn derived_keys(envelope: &Envelope) -> (String, String, String) {
        let session = envelope.rederive_session_hash();
        let blob = BlobObjectKey::new(
            &envelope.tenant_id,
            StorageProfile::ZstdV1,
            &envelope.blob_digest,
        )
        .as_str()
        .to_owned();
        let occurrence = OccurrenceObjectKey::new(
            &envelope.tenant_id,
            &envelope.origin_client_id,
            &envelope.harness,
            &session,
            &envelope.rederive_occurrence_id(),
        )
        .as_str()
        .to_owned();
        let attestation = AttestationObjectKey::new(
            &envelope.tenant_id,
            &envelope.rederive_occurrence_id(),
            &envelope.rederive_attestation_id(),
        )
        .as_str()
        .to_owned();
        (blob, occurrence, attestation)
    }

    /// One backend operation, in order: the ordered log the sequencing
    /// assertions read.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Operation {
        /// A multipart session opened under a blob key.
        Begin(String),
        /// A multipart session completed under a blob key.
        Complete(String),
        /// A session aborted.
        Abort(String),
        /// A manifest write attempted at a key.
        Manifest(String),
    }

    /// Where a scripted fault stops the next matching store call: the
    /// three boundaries a partial state stands at, plus the blob
    /// completion itself.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fault {
        /// The next multipart completion fails.
        BlobComplete,
        /// The next occurrence-manifest write fails.
        OccurrenceWrite,
        /// The next attestation-manifest write fails.
        AttestationWrite,
    }

    /// The honest-dedup profile the backend runs: a content-addressed
    /// object store (conditional create plus stored digests, replay
    /// reported as already present) or a writer-only one (deterministic
    /// overwrite, weaker physical truth).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Profile {
        /// Conditional create supported, stored SHA-256 evidence — the
        /// strongest portable profile.
        ContentAddressed,
        /// No conditional create, no readable evidence: idempotency by
        /// deterministic overwrite alone (RCPT-004).
        WriterOnly,
    }

    /// The durable object state two replicas share — the standalone
    /// backend a retry converges through. Everything a replica holds
    /// privately (its open sessions, its fault script) lives on the
    /// replica handles, so dropping one models the process going away.
    #[derive(Default)]
    struct Backend {
        objects: HashMap<String, Vec<u8>>,
        sessions: BTreeMap<String, (String, Vec<u8>)>,
        operations: Vec<Operation>,
        /// Physical manifest writes that reached the key — the
        /// multiplication probe: convergence writes no second one.
        manifest_puts: u32,
        /// Physical multipart completions that persisted content — the
        /// physical half of blob convergence.
        blob_puts: u32,
        next_session: u32,
    }

    impl Backend {
        /// The one object standing at `key`, when any does.
        fn object(&self, key: &str) -> Option<&Vec<u8>> {
            self.objects.get(key)
        }

        /// How many of the standing objects are occurrence manifests —
        /// the logical-occurrence count.
        fn occurrence_count(&self) -> usize {
            self.objects
                .keys()
                .filter(|key| key.contains("/v1/raw/occurrences/"))
                .count()
        }

        /// How many are attestations — the logical-attestation count.
        fn attestation_count(&self) -> usize {
            self.objects
                .keys()
                .filter(|key| key.contains("/v1/raw/attestations/"))
                .count()
        }

        /// The position of the first manifest write at `key` in the
        /// operation order.
        fn first_manifest_at(&self, key: &str) -> Option<usize> {
            self.operations
                .iter()
                .position(|operation| *operation == Operation::Manifest(key.to_owned()))
        }
    }

    /// One replica's independently scoped handle over the shared
    /// backend: its own capabilities, its own fault script, its own
    /// open-session view. Dropping it discards exactly what a replica
    /// process holds in memory.
    struct ReplicaStore {
        backend: Arc<Mutex<Backend>>,
        profile: Profile,
        faults: Mutex<Vec<Fault>>,
    }

    impl ReplicaStore {
        /// A replica over `backend` running `profile`.
        fn over(backend: &Arc<Mutex<Backend>>, profile: Profile) -> Self {
            Self {
                backend: Arc::clone(backend),
                profile,
                faults: Mutex::new(Vec::new()),
            }
        }

        /// Script one fault for the next matching call.
        fn fault(&self, fault: Fault) {
            self.faults.lock().expect("fault lock").push(fault);
        }

        /// Whether a scripted fault consumes this call.
        fn trip(&self, fault: Fault) -> bool {
            let mut faults = self.faults.lock().expect("fault lock");
            if let Some(at) = faults.iter().position(|scripted| *scripted == fault) {
                faults.remove(at);
                return true;
            }
            false
        }

        /// The manifest write the writer-only overwrite primitive
        /// funnels through: fault-checked, logged, and counted when it
        /// reaches the key.
        fn put_manifest(
            &self,
            key: &ManifestKey,
            bytes: &[u8],
            fault: Fault,
        ) -> Result<StorageOutcome, StorageError> {
            if self.trip(fault) {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            let mut backend = self.backend.lock().expect("backend lock");
            backend
                .operations
                .push(Operation::Manifest(key.as_str().to_owned()));
            backend
                .objects
                .insert(key.as_str().to_owned(), bytes.to_vec());
            backend.manifest_puts += 1;
            Ok(StorageOutcome::Created)
        }
    }

    impl RawWriteStore for ReplicaStore {
        fn capabilities(&self) -> StoreCapabilities {
            match self.profile {
                Profile::ContentAddressed => StoreCapabilities {
                    conditional_create: ConditionalCreate::Supported,
                    stored_checksum: StoredChecksum::Sha256,
                    versioning: VersioningState::Unknown,
                    server_side_encryption: EncryptionState::Unavailable,
                },
                Profile::WriterOnly => StoreCapabilities {
                    conditional_create: ConditionalCreate::Unavailable,
                    stored_checksum: StoredChecksum::Unavailable,
                    versioning: VersioningState::Unknown,
                    server_side_encryption: EncryptionState::Unavailable,
                },
            }
        }

        async fn write_manifest(
            &self,
            key: &ManifestKey,
            bytes: &[u8],
        ) -> Result<StorageOutcome, StorageError> {
            let fault = match key {
                ManifestKey::Occurrence(_) => Fault::OccurrenceWrite,
                ManifestKey::Attestation(_) => Fault::AttestationWrite,
            };
            self.put_manifest(key, bytes, fault)
        }

        async fn begin_multipart(
            &self,
            blob: &BlobObjectKey,
        ) -> Result<MultipartUploadId, StorageError> {
            let mut backend = self.backend.lock().expect("backend lock");
            backend.next_session += 1;
            let id = MultipartUploadId::parse(&format!("replica-session-{}", backend.next_session))
                .expect("session grammar");
            backend.sessions.insert(
                id.as_str().to_owned(),
                (blob.as_str().to_owned(), Vec::new()),
            );
            backend
                .operations
                .push(Operation::Begin(blob.as_str().to_owned()));
            Ok(id)
        }

        async fn write_part(
            &self,
            upload: &MultipartUploadId,
            part: PartNumber,
            bytes: &[u8],
        ) -> Result<PartCommitment, StorageError> {
            let mut backend = self.backend.lock().expect("backend lock");
            backend
                .sessions
                .get_mut(upload.as_str())
                .expect("live session")
                .1
                .extend_from_slice(bytes);
            let tag =
                ObjectTag::parse(&format!("\"replica-part-{}\"", part.get())).expect("tag grammar");
            Ok(PartCommitment::new(part, tag))
        }

        async fn commit_multipart(
            &self,
            upload: &MultipartUploadId,
            _parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            if self.trip(Fault::BlobComplete) {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            let mut backend = self.backend.lock().expect("backend lock");
            let (key, content) = backend
                .sessions
                .remove(upload.as_str())
                .expect("live session");
            backend.operations.push(Operation::Complete(key.clone()));
            if self.profile == Profile::ContentAddressed && backend.objects.contains_key(&key) {
                // The dedupe verdict: readable compatible evidence
                // established prior presence (vocabulary:
                // `AlreadyPresent`, never a rewrite).
                return Ok(StorageOutcome::AlreadyPresent);
            }
            backend.objects.insert(key.clone(), content);
            backend.blob_puts += 1;
            Ok(StorageOutcome::Created)
        }

        async fn abort_multipart(&self, upload: &MultipartUploadId) -> Result<(), StorageError> {
            let mut backend = self.backend.lock().expect("backend lock");
            backend.sessions.remove(upload.as_str());
            backend
                .operations
                .push(Operation::Abort(upload.as_str().to_owned()));
            Ok(())
        }
    }

    impl ConditionalCreateStore for ReplicaStore {
        async fn create_manifest_if_absent(
            &self,
            key: &ManifestKey,
            bytes: &[u8],
        ) -> Result<CreateIfAbsent, StorageError> {
            let fault = match key {
                ManifestKey::Occurrence(_) => Fault::OccurrenceWrite,
                ManifestKey::Attestation(_) => Fault::AttestationWrite,
            };
            if self.trip(fault) {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            let mut backend = self.backend.lock().expect("backend lock");
            backend
                .operations
                .push(Operation::Manifest(key.as_str().to_owned()));
            if let Some(stored) = backend.objects.get(key.as_str()) {
                let evidence = ExistingObject::new()
                    .with_size(stored.len() as u64)
                    .with_stored_sha256(sha256::digest(stored));
                Ok(CreateIfAbsent::AlreadyExists(evidence))
            } else {
                backend
                    .objects
                    .insert(key.as_str().to_owned(), bytes.to_vec());
                backend.manifest_puts += 1;
                Ok(CreateIfAbsent::Created)
            }
        }
    }

    /// One shared backend with nothing standing in it.
    fn shared_backend() -> Arc<Mutex<Backend>> {
        Arc::new(Mutex::new(Backend::default()))
    }

    /// The full sequence over one replica, as one blocking-free call.
    fn run_sequence(
        store: &ReplicaStore,
        envelope: &Envelope,
    ) -> Result<super::SequenceCommit, super::SequenceError> {
        block_on(commit_sequence(
            store,
            &OpenUploads::new(),
            envelope,
            direct_delegation(),
            &mut IdentityEncoder,
            [BODY],
        ))
    }

    /// The blob step alone — the first boundary a terminated attempt
    /// can stop at.
    fn run_blob(
        store: &ReplicaStore,
        envelope: &Envelope,
    ) -> Result<crate::blob::BlobCommit, crate::blob::BlobCommitError> {
        block_on(commit_blob(
            store,
            &OpenUploads::new(),
            &envelope.tenant_id,
            BlobExpectation::new(envelope.blob_digest, envelope.uncompressed_size),
            &mut IdentityEncoder,
            [BODY],
        ))
    }

    #[test]
    fn full_sequence_lands_three_objects_in_the_normative_order() {
        let backend = shared_backend();
        let replica = ReplicaStore::over(&backend, Profile::ContentAddressed);
        let envelope = direct_envelope();
        let (blob_key, occurrence_key, attestation_key) = derived_keys(&envelope);

        let commit = run_sequence(&replica, &envelope).expect("the sequence completes");
        assert_eq!(commit.blob().key().as_str(), blob_key);
        assert_eq!(commit.occurrence().key().as_str(), occurrence_key);
        assert_eq!(commit.attestation().key().as_str(), attestation_key);
        assert_eq!(commit.blob().outcome(), StorageOutcome::Created);
        assert_eq!(commit.occurrence().outcome(), StorageOutcome::Created);
        assert_eq!(commit.attestation().outcome(), StorageOutcome::Created);

        let backend = backend.lock().expect("backend lock");
        assert_eq!(backend.objects.len(), 3, "exactly three logical objects");
        assert_eq!(backend.object(&blob_key).map(Vec::as_slice), Some(BODY));
        assert!(backend.object(&occurrence_key).is_some());
        assert!(backend.object(&attestation_key).is_some());

        // The order is normative (RCPT-001): every blob-session operation
        // precedes the occurrence write, which precedes the attestation
        // write, and nothing else happened.
        let complete = backend
            .operations
            .iter()
            .position(|operation| *operation == Operation::Complete(blob_key.clone()))
            .expect("the blob completed");
        let occurrence_at = backend
            .first_manifest_at(&occurrence_key)
            .expect("occurrence");
        let attestation_at = backend
            .first_manifest_at(&attestation_key)
            .expect("attestation");
        assert!(
            complete < occurrence_at,
            "the occurrence follows a durable blob"
        );
        assert!(
            occurrence_at < attestation_at,
            "the attestation follows a durable occurrence"
        );
        assert_eq!(backend.manifest_puts, 2);
        assert_eq!(backend.blob_puts, 1);
        assert!(
            !backend
                .operations
                .iter()
                .any(|operation| matches!(operation, Operation::Abort(_))),
            "nothing was aborted"
        );
    }

    /// The three boundaries a scripted later-write failure can stop at,
    /// paired with the durable state each leaves and the objects that
    /// stand after it.
    #[test]
    fn failure_at_each_boundary_reports_its_durable_state_and_writes_nothing_later() {
        for (fault, durable, standing, later_key_absent) in [
            (
                Fault::BlobComplete,
                DurableState::Nothing,
                0,
                "/v1/raw/occurrences/",
            ),
            (
                Fault::OccurrenceWrite,
                DurableState::BlobOnly,
                1,
                "/v1/raw/attestations/",
            ),
            (
                Fault::AttestationWrite,
                DurableState::BlobAndOccurrence,
                2,
                "no-third-key",
            ),
        ] {
            let backend = shared_backend();
            let replica = ReplicaStore::over(&backend, Profile::ContentAddressed);
            replica.fault(fault);
            let envelope = direct_envelope();

            let error = run_sequence(&replica, &envelope).unwrap_err();
            assert_eq!(
                error.durable(),
                durable,
                "the {fault:?} boundary reports exactly what stood"
            );
            assert_eq!(error.kind(), StorageErrorKind::Unavailable);
            assert_eq!(error.cleanup(), None);

            let backend = backend.lock().expect("backend lock");
            assert_eq!(
                backend.objects.len(),
                standing,
                "the {fault:?} boundary leaves exactly the earlier objects"
            );
            if later_key_absent != "no-third-key" {
                assert!(
                    backend
                        .objects
                        .keys()
                        .all(|key| !key.contains(later_key_absent)),
                    "an object later in the normative order never exists at the {fault:?} boundary"
                );
            }
        }
    }

    #[test]
    fn no_success_precedes_all_three_objects() {
        // The attestation boundary is the deepest partial state: the
        // sequence's success type must not exist for it.
        let backend = shared_backend();
        let replica = ReplicaStore::over(&backend, Profile::ContentAddressed);
        replica.fault(Fault::AttestationWrite);
        let error = run_sequence(&replica, &direct_envelope())
            .expect_err("success requires the attestation too");
        assert_eq!(error.durable(), DurableState::BlobAndOccurrence);
        let (_, occurrence_key, attestation_key) = derived_keys(&direct_envelope());
        let backend = backend.lock().expect("backend lock");
        assert!(backend.object(&occurrence_key).is_some());
        assert!(
            backend.object(&attestation_key).is_none(),
            "the deepest partial state still stands one object short"
        );
    }

    /// The retry half every convergence test shares: an identical
    /// attempt through a fresh replica over the same backend, which is
    /// the protocol's "another replica" word for word — no shared
    /// process state, no sticky routing (ARCH-003).
    fn retry_through_another_replica(
        backend: &Arc<Mutex<Backend>>,
        profile: Profile,
    ) -> super::SequenceCommit {
        let other = ReplicaStore::over(backend, profile);
        run_sequence(&other, &direct_envelope())
            .expect("the identical retry through another replica completes")
    }

    #[test]
    fn termination_after_the_blob_converges_through_another_replica() {
        let backend = shared_backend();
        let first = ReplicaStore::over(&backend, Profile::ContentAddressed);
        let envelope = direct_envelope();

        // The first process dies right after its blob commit: the step
        // completed, then everything the replica held in memory — its
        // store handle, its open-upload registry — is gone.
        let blob = run_blob(&first, &envelope).expect("the blob is durable");
        drop(first);
        let (_, occurrence_key, attestation_key) = derived_keys(&envelope);

        let repair = retry_through_another_replica(&backend, Profile::ContentAddressed);
        assert_eq!(
            repair.blob().outcome(),
            StorageOutcome::AlreadyPresent,
            "the converged blob is reported as already present"
        );
        assert_eq!(repair.occurrence().outcome(), StorageOutcome::Created);
        assert_eq!(repair.attestation().outcome(), StorageOutcome::Created);
        assert_eq!(repair.blob().key().as_str(), blob.key().as_str());

        let backend = backend.lock().expect("backend lock");
        assert_eq!(backend.objects.len(), 3, "one logical triple, no more");
        assert!(backend.object(&occurrence_key).is_some());
        assert!(backend.object(&attestation_key).is_some());
        assert_eq!(
            backend.blob_puts, 1,
            "the repair converged on the standing blob instead of writing a second"
        );
        assert_eq!(backend.manifest_puts, 2);
    }

    #[test]
    fn termination_after_the_occurrence_converges_through_another_replica() {
        let backend = shared_backend();
        let first = ReplicaStore::over(&backend, Profile::ContentAddressed);
        let envelope = direct_envelope();

        // The first process dies after its occurrence commit: two of the
        // three objects stand, the attestation was never attempted.
        run_blob(&first, &envelope).expect("the blob is durable");
        block_on(commit_occurrence_manifest(&first, &envelope)).expect("the occurrence is durable");
        drop(first);

        // The blob-plus-occurrence repair: both converged objects report
        // already-present and only the attestation is new — the outcome
        // triple the protocol's corpus pins for exactly this repair.
        let repair = retry_through_another_replica(&backend, Profile::ContentAddressed);
        assert_eq!(repair.blob().outcome(), StorageOutcome::AlreadyPresent);
        assert_eq!(
            repair.occurrence().outcome(),
            StorageOutcome::AlreadyPresent
        );
        assert_eq!(repair.attestation().outcome(), StorageOutcome::Created);

        let backend = backend.lock().expect("backend lock");
        assert_eq!(backend.objects.len(), 3);
        assert_eq!(backend.occurrence_count(), 1, "one logical occurrence");
        assert_eq!(backend.blob_puts, 1);
        assert_eq!(backend.manifest_puts, 2);
    }

    #[test]
    fn retry_of_a_complete_sequence_converges_without_multiplying_provenance() {
        let backend = shared_backend();
        let first = ReplicaStore::over(&backend, Profile::ContentAddressed);
        let envelope = direct_envelope();
        let original = run_sequence(&first, &envelope).expect("the first attempt completes");
        drop(first);

        // The identical retry — a different replica, the same frozen
        // envelope: every object converges, nothing is multiplied, and
        // no byte moves (the dedupe paths write nothing).
        let retry = retry_through_another_replica(&backend, Profile::ContentAddressed);
        assert_eq!(retry.blob().outcome(), StorageOutcome::AlreadyPresent);
        assert_eq!(retry.occurrence().outcome(), StorageOutcome::AlreadyPresent);
        assert_eq!(
            retry.attestation().outcome(),
            StorageOutcome::AlreadyPresent
        );
        assert_eq!(
            retry.occurrence().key().as_str(),
            original.occurrence().key().as_str()
        );
        assert_eq!(
            retry.attestation().key().as_str(),
            original.attestation().key().as_str()
        );

        let backend = backend.lock().expect("backend lock");
        assert_eq!(
            backend.objects.len(),
            3,
            "still exactly three logical objects"
        );
        assert_eq!(backend.occurrence_count(), 1);
        assert_eq!(backend.attestation_count(), 1);
        assert_eq!(backend.blob_puts, 1, "the blob was never rewritten");
        assert_eq!(backend.manifest_puts, 2, "neither manifest was rewritten");
    }

    #[test]
    fn writer_only_profiles_converge_on_one_logical_object_each() {
        // The weaker profile converges the same way logically: the retry
        // rewrites deterministic bytes at the same derived keys and
        // reports the weaker physical truth, never a fabricated dedup
        // (RCPT-004) and never a second logical object.
        let backend = shared_backend();
        let first = ReplicaStore::over(&backend, Profile::WriterOnly);
        let envelope = direct_envelope();
        let (blob_key, occurrence_key, attestation_key) = derived_keys(&envelope);

        let commit = run_sequence(&first, &envelope).expect("the writer-only sequence completes");
        assert_eq!(commit.blob().outcome(), StorageOutcome::Created);
        assert_eq!(
            commit.occurrence().outcome(),
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        assert_eq!(
            commit.attestation().outcome(),
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        drop(first);

        let retry = retry_through_another_replica(&backend, Profile::WriterOnly);
        assert_eq!(
            retry.occurrence().outcome(),
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult,
            "the weaker truth again, never a presence claim the profile cannot make"
        );
        assert_eq!(
            retry.attestation().outcome(),
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );

        let backend = backend.lock().expect("backend lock");
        assert_eq!(
            backend.objects.len(),
            3,
            "one logical object per derived key"
        );
        assert_eq!(backend.occurrence_count(), 1);
        assert_eq!(backend.attestation_count(), 1);
        // The physical rewrites carried identical deterministic bytes:
        // every object still stands at its one derived key.
        for key in [blob_key, occurrence_key, attestation_key] {
            assert!(
                backend.object(&key).is_some(),
                "the deterministic rewrite kept the object at {key}"
            );
        }
    }

    #[test]
    fn repair_never_fixes_by_overwriting() {
        // An incompatible object at the occurrence key: the conflict
        // propagates with the stored object untouched and nothing later
        // in the order attempted (EC-06, PI-08).
        let envelope = direct_envelope();
        let (_, occurrence_key, attestation_key) = derived_keys(&envelope);

        let backend = shared_backend();
        let replica = ReplicaStore::over(&backend, Profile::ContentAddressed);
        backend.lock().expect("backend lock").objects.insert(
            occurrence_key.clone(),
            b"{\"incompatible\":\"object at the key\"}".to_vec(),
        );
        let error = run_sequence(&replica, &envelope)
            .expect_err("an incompatible occurrence is a conflict, never an overwrite");
        assert_eq!(error.durable(), DurableState::BlobOnly);
        assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
        let backend = backend.lock().expect("backend lock");
        assert_eq!(
            backend.object(&occurrence_key).map(Vec::as_slice),
            Some(b"{\"incompatible\":\"object at the key\"}".as_slice()),
            "whatever was there stays"
        );
        assert!(
            backend.object(&attestation_key).is_none(),
            "the attestation behind a conflicted occurrence is never attempted"
        );

        // The same refusal at the attestation key, one boundary deeper.
        let backend = shared_backend();
        let replica = ReplicaStore::over(&backend, Profile::ContentAddressed);
        let (_, _, attestation_key) = derived_keys(&envelope);
        backend.lock().expect("backend lock").objects.insert(
            attestation_key.clone(),
            b"{\"forged\":\"attestation at the key\"}".to_vec(),
        );
        let error = run_sequence(&replica, &envelope)
            .expect_err("an incompatible attestation is a conflict, never an overwrite");
        assert_eq!(error.durable(), DurableState::BlobAndOccurrence);
        assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
        let backend = backend.lock().expect("backend lock");
        assert_eq!(
            backend.object(&attestation_key).map(Vec::as_slice),
            Some(b"{\"forged\":\"attestation at the key\"}".as_slice())
        );
    }

    #[test]
    fn a_relay_presentation_adds_its_attestation_without_multiplying_the_occurrence() {
        // Two authorized uploaders of one source event: the relay's
        // frozen request folds its own attestation id, so the fourth
        // object is the relay's attestation — never a second occurrence
        // (EC-05A, STO-013).
        let backend = shared_backend();
        let origin = ReplicaStore::over(&backend, Profile::ContentAddressed);
        run_sequence(&origin, &direct_envelope()).expect("the origin's sequence completes");
        drop(origin);

        let relay = ReplicaStore::over(&backend, Profile::ContentAddressed);
        let relayed = relayed_envelope();
        let commit = block_on(commit_sequence(
            &relay,
            &OpenUploads::new(),
            &relayed,
            Delegation::Relay,
            &mut IdentityEncoder,
            [BODY],
        ))
        .expect("the relay's sequence completes");
        assert_eq!(commit.blob().outcome(), StorageOutcome::AlreadyPresent);
        assert_eq!(
            commit.occurrence().outcome(),
            StorageOutcome::AlreadyPresent,
            "the occurrence is the origin's, converged on"
        );
        assert_eq!(commit.attestation().outcome(), StorageOutcome::Created);

        let backend = backend.lock().expect("backend lock");
        assert_eq!(
            backend.objects.len(),
            4,
            "blob, occurrence, two attestations"
        );
        assert_eq!(backend.occurrence_count(), 1, "one logical occurrence");
        assert_eq!(
            backend.attestation_count(),
            2,
            "one attestation per uploader"
        );
        assert_eq!(
            backend.blob_puts, 1,
            "the source bytes were never re-persisted"
        );
    }

    #[test]
    fn the_provenance_tail_reports_how_far_it_got_on_its_own() {
        // The server's streaming path calls the tail directly after its
        // own durable blob; the tail's errors count that blob.
        let backend = shared_backend();
        let replica = ReplicaStore::over(&backend, Profile::ContentAddressed);
        replica.fault(Fault::OccurrenceWrite);
        let error = block_on(commit_provenance(
            &replica,
            &direct_envelope(),
            direct_delegation(),
        ))
        .expect_err("the occurrence write fails");
        assert_eq!(error.durable(), DurableState::BlobOnly);

        replica.fault(Fault::AttestationWrite);
        let error = block_on(commit_provenance(
            &replica,
            &direct_envelope(),
            direct_delegation(),
        ))
        .expect_err("the attestation write fails");
        assert_eq!(error.durable(), DurableState::BlobAndOccurrence);

        let repaired = block_on(commit_provenance(
            &replica,
            &direct_envelope(),
            direct_delegation(),
        ))
        .expect("the recovered tail completes");
        // The recovery converges, never rewrites: the occurrence from the
        // second attempt stands at the key, so the conditional create
        // dedupes it (protocol Section 4.4); the attestation's earlier
        // fault fired before any write, so it lands created.
        assert_eq!(repaired.occurrence().outcome(), StorageOutcome::AlreadyPresent);
        assert_eq!(repaired.attestation().outcome(), StorageOutcome::Created);
    }

    #[test]
    fn a_failing_blob_commit_reports_nothing_durable_with_its_cleanup_carried() {
        // A blob-stream digest mismatch aborts the session and nothing
        // durable stands; the sequence's error carries the blob layer's
        // failure with no cleanup failure, and no manifest was touched.
        let backend = shared_backend();
        let replica = ReplicaStore::over(&backend, Profile::ContentAddressed);
        let mut envelope = direct_envelope();
        envelope.blob_digest =
            BlobDigest::parse(&sha256::encode_hex(&sha256::digest(b"not this body")))
                .expect("digest grammar");

        let error = run_sequence(&replica, &envelope)
            .expect_err("the declared digest contradicts the stream");
        assert_eq!(error.durable(), DurableState::Nothing);
        assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
        assert_eq!(error.cleanup(), None);
        let backend = backend.lock().expect("backend lock");
        assert!(
            backend.objects.is_empty(),
            "nothing stands at any derived key"
        );
        assert!(
            !backend
                .operations
                .iter()
                .any(|operation| matches!(operation, Operation::Manifest(_))),
            "no manifest write was ever attempted"
        );
    }

    #[test]
    fn the_real_profile_encoder_streams_through_the_sequence() {
        // The same sequence over the pinned zstd-v1 encoder: the stored
        // blob is the canonical frame, not the passthrough bytes, and
        // the manifest objects are the deterministic documents — the
        // composition the ingest route drives.
        let backend = shared_backend();
        let replica = ReplicaStore::over(&backend, Profile::ContentAddressed);
        let envelope = direct_envelope();
        let (blob_key, _, _) = derived_keys(&envelope);

        let mut encoder =
            ZstdV1Encoder::new(envelope.uncompressed_size).expect("the pinned encoder builds");
        let commit = block_on(commit_sequence(
            &replica,
            &OpenUploads::new(),
            &envelope,
            direct_delegation(),
            &mut encoder,
            [BODY],
        ))
        .expect("the sequence completes over the real encoder");

        let backend = backend.lock().expect("backend lock");
        let stored = backend.object(&blob_key).expect("the blob stands");
        assert_ne!(stored, BODY, "the stored form is the encoded frame");
        // The stored-form digest the commit reports is over the bytes
        // that reached the backend (STO-001).
        let mut hasher = Sha256::new();
        hasher.update(stored);
        assert_eq!(commit.blob().stored_sha256(), &hasher.finalize());
        assert!(commit.blob().stored_bytes() > 0);
    }

    #[test]
    fn display_names_the_durable_state_and_the_failure() {
        let error = super::SequenceError {
            durable: DurableState::BlobAndOccurrence,
            failure: StorageError::of_kind(StorageErrorKind::Unavailable),
            cleanup: None,
        };
        let text = error.to_string();
        assert!(
            text.contains("the blob and occurrence manifest are durable"),
            "{text}"
        );
        assert!(text.contains("storage unavailable"), "{text}");
    }
}
