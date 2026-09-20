// SPDX-License-Identifier: Apache-2.0

//! The manifest commit path: the occurrence manifest and the upload
//! attestation built from one validated envelope and landed at their
//! server-derived keys through [`crate::commit::commit_manifest`] — steps
//! 8 and 9 of the server flow (plan Section 5), on top of the decision
//! layer.
//!
//! The two durable records split the envelope by *what the record is
//! about* (SID-006; schemas/v1/occurrence-manifest.json,
//! schemas/v1/upload-attestation.json). Every field is an identity input
//! or a deterministic derivation of one, so the canonical bytes are a pure
//! function of frozen inputs (STO-010) and a replay reproduces them
//! exactly:
//!
//! - **The occurrence manifest** carries the source-stable provenance
//!   only — session, artifact tuple, generation, range, blob digest, and
//!   the derived `session_hash`, `artifact_hash`, and `occurrence_id`.
//!   Uploader, request, transport, per-attempt, and server material stay
//!   out by construction, which is why two uploaders of one source event
//!   produce byte-identical manifests at one key (STO-002, EC-05A).
//! - **The upload attestation** carries who presented which frozen
//!   request for which occurrence: uploader, request, the delegation
//!   relation, and the folded `attestation_id` (STO-013). A relay's
//!   attestation lands beside the origin's under its own key; neither
//!   ever rewrites the occurrence.
//!
//! # Identity is re-derived, never trusted (SID-005)
//!
//! Before anything is written, the server re-derives the identity the
//! object is named by from the envelope's identity inputs and refuses a
//! mismatch with [`StorageErrorKind::IntegrityConflict`] — the commit-side
//! check of SID-005 (occurrence) and STO-013 (attestation). A hand-built
//! or tampered [`Envelope`] whose declared ids disagree with its inputs is
//! a payload whose re-derived identity differs from the key it would
//! occupy; it never reaches the store.
//!
//! # Deduplication, not conflict (STO-002)
//!
//! Writes are immutable and write-once at the derived keys: the commit
//! primitive resolves a replay of identical bytes at the same key as
//! convergence on one logical object — [`StorageOutcome::AlreadyPresent`]
//! when readable evidence proves it, the weaker
//! [`StorageOutcome::LogicallyCommittedUnknownPhysicalResult`] when the
//! profile cannot prove anything (RCPT-003, RCPT-004) — and readable
//! evidence that *contradicts* the committed bytes as
//! [`StorageErrorKind::IntegrityConflict`] with nothing overwritten
//! (EC-06, VAL-005). Identical replay is deduplication working, never an
//! error.

use archivist_protocol::envelope::Envelope;
use archivist_protocol::json::{Object, Value};
use archivist_protocol::object_key::{AttestationObjectKey, OccurrenceObjectKey};
use archivist_protocol::vocabulary::{AttestationId, OccurrenceId, SessionHash, StorageOutcome};

use crate::commit::{ConditionalCreateStore, commit_manifest};
use crate::error::{StorageError, StorageErrorKind};
use crate::raw_write::{ManifestKey, RawWriteStore};

/// The occurrence-manifest schema major version
/// (`occurrence-manifest.json` `occurrence_version`; plan Section 7.1).
const OCCURRENCE_VERSION: i64 = 1;
/// The upload-attestation schema major version
/// (`upload-attestation.json` `attestation_version`; plan Section 7.1).
const ATTESTATION_VERSION: i64 = 1;
/// The static detail for a declared occurrence id that disagrees with the
/// server-side re-derivation.
const OCCURRENCE_ID_MISMATCH_DETAIL: &str =
    "declared occurrence_id does not match the server-side re-derivation";
/// The static detail for a declared attestation id that disagrees with the
/// server-side re-derivation.
const ATTESTATION_ID_MISMATCH_DETAIL: &str =
    "declared attestation_id does not match the server-side re-derivation";
/// The static detail for a declared delegation relation that contradicts
/// the envelope's uploader and origin clients.
const DELEGATION_INCONSISTENT_DETAIL: &str =
    "delegation relation contradicts the envelope's uploader and origin clients";

/// The delegation relation an attestation records
/// (`upload-attestation.json` `delegation`; STO-013): how the uploader
/// stands to the origin for the frozen request.
///
/// The caller derives it from the verified authorization — the storage
/// layer cannot see the linked-client record, and `relay` means a
/// delegation was actually verified, so the relation is durably recorded
/// rather than inferred from the two client ids alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delegation {
    /// The uploader is the origin client.
    Direct,
    /// An authorized uploader presented the origin's frozen occurrence on
    /// its behalf (ID-005: the origin identity is preserved, never
    /// replaced).
    Relay,
}

impl Delegation {
    /// The wire token (`upload-attestation.json` `delegation-relation`).
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

/// What one successful manifest commit established: the derived key the
/// object is visible at, and the store's own physical-truth outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestCommit {
    key: ManifestKey,
    outcome: StorageOutcome,
}

impl ManifestCommit {
    /// The derived key the object landed at.
    #[must_use]
    pub const fn key(&self) -> &ManifestKey {
        &self.key
    }

    /// The outcome the store reported — the profile physical truth, never
    /// strengthened here (RCPT-003).
    #[must_use]
    pub const fn outcome(&self) -> StorageOutcome {
        self.outcome
    }
}

/// Commit the occurrence manifest of one validated envelope at its derived
/// key.
///
/// Re-derives the occurrence identity server-side (SID-005) and refuses a
/// declared mismatch, assembles the source-stable manifest document's
/// canonical bytes, and commits them at
/// `OccurrenceObjectKey::new(tenant, origin, harness, session, occurrence)`
/// — uploader and request never enter the document or the key, so two
/// uploaders of one source event converge on one object (STO-002, STO-004,
/// EC-05A). Replay is deduplication, never a conflict (see the module
/// docs).
///
/// Only the occurrence identity gates this path: the manifest document and
/// its key are independent of attestation identity, so an envelope whose
/// attestation id alone disagrees is not this object's integrity problem.
///
/// # Errors
/// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
/// when the declared `occurrence_id` differs from the re-derived one,
/// [`StorageErrorKind::MalformedInput`](crate::error::StorageErrorKind)
/// for out-of-bounds canonical bytes, or the store's own failure
/// otherwise.
pub async fn commit_occurrence_manifest<S>(
    store: &S,
    envelope: &Envelope,
) -> Result<ManifestCommit, StorageError>
where
    S: RawWriteStore + ConditionalCreateStore + ?Sized,
{
    let occurrence = verified_occurrence_id(envelope)?;
    let session = envelope.rederive_session_hash();
    let key = OccurrenceObjectKey::new(
        &envelope.tenant_id,
        &envelope.origin_client_id,
        &envelope.harness,
        &session,
        &occurrence,
    );
    let bytes = occurrence_manifest_value(envelope, &occurrence, &session).canonical_bytes();
    commit_at_key(store, ManifestKey::Occurrence(key), &bytes).await
}

/// Commit the upload attestation of one validated envelope at its derived
/// key.
///
/// Re-derives both identities server-side — the attestation folds the
/// occurrence, the uploader, and the frozen request (STO-013) — checks the
/// declared [`Delegation`] against the two client ids (the schema's
/// consistency rule: `direct` requires uploader equal to origin, `relay`
/// requires them to differ; the delegation's verification itself is the
/// authorization path's, not this crate's), and commits the canonical
/// bytes at
/// `AttestationObjectKey::new(tenant, occurrence, attestation)`. A relay's
/// attestation coexists with the origin's under its own key; a replay of
/// one frozen request rewrites its identical object (STO-004, EC-05A).
///
/// # Errors
/// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
/// when the declared `occurrence_id` or `attestation_id` differs from the
/// re-derived one,
/// [`StorageErrorKind::MalformedInput`](crate::error::StorageErrorKind)
/// when the delegation relation contradicts the two client ids or the
/// canonical bytes are out of bounds, or the store's own failure
/// otherwise.
pub async fn commit_attestation_manifest<S>(
    store: &S,
    envelope: &Envelope,
    delegation: Delegation,
) -> Result<ManifestCommit, StorageError>
where
    S: RawWriteStore + ConditionalCreateStore + ?Sized,
{
    let (occurrence, attestation) = verified_attestation_identity(envelope)?;
    let consistent = match delegation {
        Delegation::Direct => envelope.uploader_client_id == envelope.origin_client_id,
        Delegation::Relay => envelope.uploader_client_id != envelope.origin_client_id,
    };
    if !consistent {
        return Err(StorageError::new(
            StorageErrorKind::MalformedInput,
            DELEGATION_INCONSISTENT_DETAIL,
        ));
    }
    let key = AttestationObjectKey::new(&envelope.tenant_id, &occurrence, &attestation);
    let bytes = attestation_manifest_value(envelope, delegation, &occurrence, &attestation)
        .canonical_bytes();
    commit_at_key(store, ManifestKey::Attestation(key), &bytes).await
}

/// Commit canonical `bytes` at the derived `key` through the decision
/// layer, reporting the derived key and the store's physical truth.
async fn commit_at_key<S>(
    store: &S,
    key: ManifestKey,
    bytes: &[u8],
) -> Result<ManifestCommit, StorageError>
where
    S: RawWriteStore + ConditionalCreateStore + ?Sized,
{
    let outcome = commit_manifest(store, &key, bytes).await?;
    Ok(ManifestCommit { key, outcome })
}

/// The occurrence identity re-derived from the envelope's identity inputs,
/// refused when the declared value disagrees (SID-005).
fn verified_occurrence_id(envelope: &Envelope) -> Result<OccurrenceId, StorageError> {
    let occurrence = envelope.rederive_occurrence_id();
    if envelope.occurrence_id.as_raw() != occurrence.as_raw() {
        return Err(StorageError::new(
            StorageErrorKind::IntegrityConflict,
            OCCURRENCE_ID_MISMATCH_DETAIL,
        ));
    }
    Ok(occurrence)
}

/// Both identities re-derived from the envelope's inputs, refused when the
/// declared values disagree (SID-005; STO-013's fold covers the
/// occurrence, the uploader, and the frozen request).
fn verified_attestation_identity(
    envelope: &Envelope,
) -> Result<(OccurrenceId, AttestationId), StorageError> {
    let occurrence = verified_occurrence_id(envelope)?;
    let attestation = envelope.rederive_attestation_id();
    if envelope.attestation_id.as_raw() != attestation.as_raw() {
        return Err(StorageError::new(
            StorageErrorKind::IntegrityConflict,
            ATTESTATION_ID_MISMATCH_DETAIL,
        ));
    }
    Ok((occurrence, attestation))
}

/// The occurrence manifest document (`occurrence-manifest.json`,
/// `occurrence_version` 1): source-stable provenance only. Every member is
/// an identity input or a derived identity; uploader, request, transport,
/// per-attempt, and server members never appear (SID-006).
fn occurrence_manifest_value(
    envelope: &Envelope,
    occurrence: &OccurrenceId,
    session: &SessionHash,
) -> Value {
    let mut object = Object::new();
    let mut set = |name: &str, value: Value| object.set(name, value);
    set(
        "adapter_artifact_id",
        Value::Text(envelope.adapter_artifact_id.as_str().to_owned()),
    );
    set("adapter_id", text(&envelope.adapter_id));
    set(
        "adapter_projection_version",
        text(&envelope.adapter_projection_version),
    );
    set(
        "artifact_hash",
        Value::Text(envelope.rederive_artifact_hash().to_hex()),
    );
    set(
        "artifact_kind",
        Value::Text(envelope.artifact_kind.token().to_owned()),
    );
    set("blob_digest", Value::Text(envelope.blob_digest.to_hex()));
    set("generation", text(&envelope.generation));
    set("harness", text(&envelope.harness));
    set(
        "id_source",
        Value::Text(envelope.id_source.token().to_owned()),
    );
    set("occurrence_id", Value::Text(occurrence.to_hex()));
    set("occurrence_version", Value::Int(OCCURRENCE_VERSION));
    set("origin_client_id", text(&envelope.origin_client_id));
    set("range_end", u63(envelope.range_end));
    set(
        "range_kind",
        Value::Text(envelope.range_kind.token().to_owned()),
    );
    set("range_start", u63(envelope.range_start));
    set("session_hash", Value::Text(session.to_hex()));
    if let Some(source_time) = &envelope.source_time {
        set("source_time", text(source_time));
    }
    set(
        "storage_profile",
        Value::Text(envelope.storage_profile.token().to_owned()),
    );
    set("tenant_id", text(&envelope.tenant_id));
    set(
        "upstream_session_id",
        Value::Text(envelope.upstream_session_id.as_str().to_owned()),
    );
    Value::Object(object)
}

/// The upload-attestation document (`upload-attestation.json`,
/// `attestation_version` 1): who presented which frozen request for which
/// occurrence. Per-attempt authorization material stays in the receipt
/// (plan Section 7.5) — only the frozen request's identity is recorded.
fn attestation_manifest_value(
    envelope: &Envelope,
    delegation: Delegation,
    occurrence: &OccurrenceId,
    attestation: &AttestationId,
) -> Value {
    let mut object = Object::new();
    let mut set = |name: &str, value: Value| object.set(name, value);
    set("attestation_id", Value::Text(attestation.to_hex()));
    set("attestation_version", Value::Int(ATTESTATION_VERSION));
    set("capture_time", text(&envelope.capture_time));
    set("delegation", Value::Text(delegation.token().to_owned()));
    set(
        "envelope_creation_time",
        text(&envelope.envelope_creation_time),
    );
    set("occurrence_id", Value::Text(occurrence.to_hex()));
    set("origin_client_id", text(&envelope.origin_client_id));
    set("request_id", text(&envelope.request_id));
    set("tenant_id", text(&envelope.tenant_id));
    set("uploader_client_id", text(&envelope.uploader_client_id));
    Value::Object(object)
}

/// Render a text newtype as a JSON string value.
fn text<T: std::fmt::Display>(value: &T) -> Value {
    Value::Text(value.to_string())
}

/// Render a `u63` field: the envelope's parse guarantees the bound, so a
/// value that no longer fits is a programmatic-construction bug, not a
/// wire condition.
fn u63(value: u64) -> Value {
    Value::Int(i64::try_from(value).expect("u63 fields stay below 2^63"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use archivist_protocol::envelope::Envelope;
    use archivist_protocol::json::{Object, Value};
    use archivist_protocol::object_key::{
        AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey,
    };
    use archivist_protocol::sha256;
    use archivist_protocol::vocabulary::{
        AdapterId, ArtifactKind, AttestationId, BlobDigest, ChecksumAlgorithm, ClientId,
        GenerationId, HarnessId, IdSource, IncomingChecksum, OccurrenceId, OpaqueId, RangeKind,
        RequestId, StorageOutcome, StorageProfile, TenantId, Timestamp, TransportEncoding,
        VersionToken,
    };

    use super::{
        Delegation, ManifestCommit, ManifestKey, commit_attestation_manifest,
        commit_occurrence_manifest,
    };
    use crate::capability::{
        ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
    };
    use crate::commit::{ConditionalCreateStore, CreateIfAbsent, ExistingObject};
    use crate::error::{StorageError, StorageErrorKind};
    use crate::raw_write::{MultipartUploadId, PartCommitment, PartNumber, RawWriteStore};

    /// The conformance corpus's `valid-direct-baseline` tenant.
    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    /// The origin client of the pinned provenance bundle's shared source
    /// event.
    const ORIGIN: &str = "11111111-2222-4333-8444-555555555555";
    /// The pinned provenance bundle's shared canonical payload digest
    /// (`schemas/v1/examples/provenance/manifest.json`).
    const BLOB: &str = "33cb5534930ffe41c245b1f4b5c42872abbe668edb9da835314b414da5a690a6";

    /// The pinned canonical occurrence manifest of the bundle's
    /// `direct-upload-and-relay-source.json` (`schemas/v1/examples/
    /// provenance/occurrences/`, minus the file's one trailing LF): the
    /// byte-exact target the occurrence path must reproduce.
    const PINNED_OCCURRENCE_BYTES: &[u8] = b"{\"adapter_artifact_id\":\"session-file-4f9c2f1e\",\"adapter_id\":\"claude-jsonl\",\"adapter_projection_version\":\"1\",\"artifact_hash\":\"0438d5c38d1b36b289ecc4f0fcb707e3661408b8973b6d50764a2cf2b163ac7a\",\"artifact_kind\":\"file-slice\",\"blob_digest\":\"33cb5534930ffe41c245b1f4b5c42872abbe668edb9da835314b414da5a690a6\",\"generation\":\"1a079d80-7000-7000-8000-000000000051\",\"harness\":\"claude-code\",\"id_source\":\"upstream\",\"occurrence_id\":\"e107d1532d571127e2bf8bb1f4b02ec8057b074e527ef8d550975011e1399cde\",\"occurrence_version\":1,\"origin_client_id\":\"11111111-2222-4333-8444-555555555555\",\"range_end\":169,\"range_kind\":\"byte\",\"range_start\":0,\"session_hash\":\"b1be7353c6aae5eb945802a690ab0269120bcb292599d849bcb7e298867755a0\",\"source_time\":\"2026-09-11T16:44:02Z\",\"storage_profile\":\"zstd-v1\",\"tenant_id\":\"0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b\",\"upstream_session_id\":\"4f9c2f1e-8a3d-4b67-9c2f-1e8a3d4b679c\"}";

    /// The pinned canonical attestation of the bundle's
    /// `origin-direct-first-request.json` (`schemas/v1/examples/
    /// provenance/attestations/`, minus the file's one trailing LF).
    const PINNED_ATTESTATION_BYTES: &[u8] = b"{\"attestation_id\":\"aee6b0ac31db9e79503e652aa76c3e3f9b8257b8ca53213c1ab3c96d89972ee7\",\"attestation_version\":1,\"capture_time\":\"2026-09-11T16:44:10Z\",\"delegation\":\"direct\",\"envelope_creation_time\":\"2026-09-11T16:44:11Z\",\"occurrence_id\":\"e107d1532d571127e2bf8bb1f4b02ec8057b074e527ef8d550975011e1399cde\",\"origin_client_id\":\"11111111-2222-4333-8444-555555555555\",\"request_id\":\"1a079e10-7000-7000-8000-000000000001\",\"tenant_id\":\"0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b\",\"uploader_client_id\":\"11111111-2222-4333-8444-555555555555\"}";

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

    fn uuid(text: &str) -> ClientId {
        ClientId::parse(text).expect("grammatical mock client")
    }

    /// The pinned bundle's shared source event as a validated envelope:
    /// the direct origin upload whose manifest and attestation bytes the
    /// bundle pins. Identity inputs reproduce the pinned
    /// `session_hash`/`artifact_hash`/`occurrence_id`/`attestation_id`
    /// derivations, which the byte-equality tests below prove end to end.
    fn direct_envelope() -> Envelope {
        Envelope {
            tenant_id: TenantId::parse(TENANT).unwrap(),
            origin_client_id: uuid(ORIGIN),
            uploader_client_id: uuid(ORIGIN),
            harness: HarnessId::parse("claude-code").unwrap(),
            upstream_session_id: OpaqueId::parse("4f9c2f1e-8a3d-4b67-9c2f-1e8a3d4b679c").unwrap(),
            id_source: IdSource::Upstream,
            artifact_kind: ArtifactKind::FileSlice,
            adapter_id: AdapterId::parse("claude-jsonl").unwrap(),
            adapter_projection_version: VersionToken::parse("1").unwrap(),
            adapter_artifact_id: OpaqueId::parse("session-file-4f9c2f1e").unwrap(),
            generation: GenerationId::parse("1a079d80-7000-7000-8000-000000000051").unwrap(),
            range_kind: RangeKind::Byte,
            range_start: 0,
            range_end: 169,
            blob_digest: BlobDigest::parse(BLOB).unwrap(),
            incoming_checksum: IncomingChecksum::parse(BLOB).unwrap(),
            incoming_checksum_algorithm: ChecksumAlgorithm::Sha256,
            storage_profile: StorageProfile::ZstdV1,
            transport_encoding: TransportEncoding::Identity,
            compressed_size: 170,
            uncompressed_size: 170,
            occurrence_id: OccurrenceId::parse(
                "e107d1532d571127e2bf8bb1f4b02ec8057b074e527ef8d550975011e1399cde",
            )
            .unwrap(),
            attestation_id: AttestationId::parse(
                "aee6b0ac31db9e79503e652aa76c3e3f9b8257b8ca53213c1ab3c96d89972ee7",
            )
            .unwrap(),
            request_id: RequestId::parse("1a079e10-7000-7000-8000-000000000001").unwrap(),
            capture_time: Timestamp::parse("2026-09-11T16:44:10Z").unwrap(),
            envelope_creation_time: Timestamp::parse("2026-09-11T16:44:11Z").unwrap(),
            source_time: Some(Timestamp::parse("2026-09-11T16:44:02Z").unwrap()),
            parent_session_id: None,
            orchestrator_attempt_id: None,
            trace_id: None,
            inference_request_id: None,
            unknown_fields: Object::new(),
        }
    }

    /// Shared recorded state behind the mocks (`Mutex`, not `RefCell`, so
    /// the trait's `Send` futures hold).
    #[derive(Default)]
    struct FakeState {
        objects: HashMap<String, Vec<u8>>,
        primitive_calls: u32,
        overwrite_calls: u32,
        overwrite_outcome: Option<StorageOutcome>,
    }

    /// A raw writer in one of the two profiles the decision layer
    /// dispatches on: atomic conditional create with stored-content digest
    /// evidence, or writer-only deterministic overwrite.
    struct FakeStore {
        atomic: bool,
        state: Mutex<FakeState>,
    }

    impl FakeStore {
        fn atomic() -> Self {
            Self {
                atomic: true,
                state: Mutex::new(FakeState::default()),
            }
        }

        fn writer_only() -> Self {
            Self {
                atomic: false,
                state: Mutex::new(FakeState::default()),
            }
        }

        /// A writer-only store whose raw write overclaims `outcome` — the
        /// downgrade-to-weaker-truth under test.
        fn lying_overwrite(outcome: StorageOutcome) -> Self {
            Self {
                atomic: false,
                state: Mutex::new(FakeState {
                    overwrite_outcome: Some(outcome),
                    ..FakeState::default()
                }),
            }
        }

        fn seed(&self, key: &ManifestKey, bytes: &[u8]) {
            self.state
                .lock()
                .unwrap()
                .objects
                .insert(key.as_str().to_owned(), bytes.to_vec());
        }
    }

    impl RawWriteStore for FakeStore {
        fn capabilities(&self) -> StoreCapabilities {
            StoreCapabilities {
                conditional_create: if self.atomic {
                    ConditionalCreate::Supported
                } else {
                    ConditionalCreate::Unavailable
                },
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
            let mut state = self.state.lock().unwrap();
            state.overwrite_calls += 1;
            assert!(
                !self.atomic,
                "the atomic path never falls back to overwrite"
            );
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

    impl ConditionalCreateStore for FakeStore {
        async fn create_manifest_if_absent(
            &self,
            key: &ManifestKey,
            bytes: &[u8],
        ) -> Result<CreateIfAbsent, StorageError> {
            let mut state = self.state.lock().unwrap();
            state.primitive_calls += 1;
            if let Some(stored) = state.objects.get(key.as_str()) {
                let evidence = ExistingObject::new()
                    .with_size(stored.len() as u64)
                    .with_stored_sha256(sha256::digest(stored));
                return Ok(CreateIfAbsent::AlreadyExists(evidence));
            }
            state
                .objects
                .insert(key.as_str().to_owned(), bytes.to_vec());
            Ok(CreateIfAbsent::Created)
        }
    }

    #[test]
    fn occurrence_bytes_are_the_pinned_canonical_document() {
        let store = FakeStore::atomic();
        let commit = block_on(commit_occurrence_manifest(&store, &direct_envelope()))
            .expect("the occurrence manifest commits");

        let ManifestKey::Occurrence(key) = commit.key() else {
            panic!("the occurrence path names an occurrence key");
        };
        assert_eq!(
            key.as_str(),
            "tenants/0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b/v1/raw/occurrences/11111111-2222-4333-8444-555555555555/claude-code/b1/b1be7353c6aae5eb945802a690ab0269120bcb292599d849bcb7e298867755a0/e107d1532d571127e2bf8bb1f4b02ec8057b074e527ef8d550975011e1399cde.json",
            "the key is the pinned occurrence object key"
        );

        let state = store.state.lock().unwrap();
        assert_eq!(
            state.objects.get(key.as_str()).map(Vec::as_slice),
            Some(PINNED_OCCURRENCE_BYTES),
            "the stored bytes are the pinned canonical document"
        );
        assert_eq!(commit.outcome(), StorageOutcome::Created);
    }

    #[test]
    fn attestation_bytes_are_the_pinned_canonical_document() {
        let store = FakeStore::atomic();
        let commit = block_on(commit_attestation_manifest(
            &store,
            &direct_envelope(),
            Delegation::Direct,
        ))
        .expect("the attestation commits");

        let ManifestKey::Attestation(key) = commit.key() else {
            panic!("the attestation path names an attestation key");
        };
        assert_eq!(
            key.as_str(),
            "tenants/0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b/v1/raw/attestations/e1/e107d1532d571127e2bf8bb1f4b02ec8057b074e527ef8d550975011e1399cde/aee6b0ac31db9e79503e652aa76c3e3f9b8257b8ca53213c1ab3c96d89972ee7.json",
            "the key is the pinned attestation object key"
        );

        let state = store.state.lock().unwrap();
        assert_eq!(
            state.objects.get(key.as_str()).map(Vec::as_slice),
            Some(PINNED_ATTESTATION_BYTES),
            "the stored bytes are the pinned canonical document"
        );
        assert_eq!(commit.outcome(), StorageOutcome::Created);
    }

    #[test]
    fn identical_occurrence_replay_dedupes_without_a_conflict() {
        let store = FakeStore::atomic();

        let first = block_on(commit_occurrence_manifest(&store, &direct_envelope()))
            .expect("the first commit creates");
        let replay = block_on(commit_occurrence_manifest(&store, &direct_envelope()))
            .expect("an identical replay is deduplication, not a conflict");

        assert_eq!(first.outcome(), StorageOutcome::Created);
        assert_eq!(
            replay.outcome(),
            StorageOutcome::AlreadyPresent,
            "readable evidence proves the replay found the same object"
        );
        assert_eq!(
            first.key().as_str(),
            replay.key().as_str(),
            "both attempts address one derived key"
        );
        let state = store.state.lock().unwrap();
        assert_eq!(
            state.objects.len(),
            1,
            "the replay converged on one logical object"
        );
        assert_eq!(state.primitive_calls, 2, "both commits used the primitive");
        assert_eq!(state.overwrite_calls, 0);
    }

    #[test]
    fn identical_attestation_replay_dedupes_without_a_conflict() {
        let store = FakeStore::atomic();

        let first = block_on(commit_attestation_manifest(
            &store,
            &direct_envelope(),
            Delegation::Direct,
        ))
        .expect("the first commit creates");
        let replay = block_on(commit_attestation_manifest(
            &store,
            &direct_envelope(),
            Delegation::Direct,
        ))
        .expect("an identical replay is deduplication, not a conflict");

        assert_eq!(first.outcome(), StorageOutcome::Created);
        assert_eq!(replay.outcome(), StorageOutcome::AlreadyPresent);
        let state = store.state.lock().unwrap();
        assert_eq!(state.objects.len(), 1);
    }

    #[test]
    fn contradictory_evidence_at_the_key_conflicts_and_never_overwrites() {
        let store = FakeStore::atomic();
        let key = {
            let envelope = direct_envelope();
            let occurrence = envelope.rederive_occurrence_id();
            ManifestKey::Occurrence(OccurrenceObjectKey::new(
                &envelope.tenant_id,
                &envelope.origin_client_id,
                &envelope.harness,
                &envelope.rederive_session_hash(),
                &occurrence,
            ))
        };
        store.seed(&key, b"{\"something\":\"else at the key\"}");

        let failure = block_on(commit_occurrence_manifest(&store, &direct_envelope()))
            .expect_err("a different stored object is an integrity conflict, not an overwrite");
        assert_eq!(failure.kind(), StorageErrorKind::IntegrityConflict);

        let state = store.state.lock().unwrap();
        assert_eq!(
            state.objects.get(key.as_str()).map(Vec::as_slice),
            Some(b"{\"something\":\"else at the key\"}".as_slice()),
            "whatever was there stays; writes are write-once at the derived key"
        );
        assert_eq!(state.overwrite_calls, 0);
    }

    #[test]
    fn contradictory_evidence_at_the_attestation_key_conflicts_and_never_overwrites() {
        let store = FakeStore::atomic();
        let key = {
            let envelope = direct_envelope();
            let occurrence = envelope.rederive_occurrence_id();
            let attestation = envelope.rederive_attestation_id();
            ManifestKey::Attestation(AttestationObjectKey::new(
                &envelope.tenant_id,
                &occurrence,
                &attestation,
            ))
        };
        store.seed(&key, b"{\"forged\":\"attestation at the key\"}");

        let failure = block_on(commit_attestation_manifest(
            &store,
            &direct_envelope(),
            Delegation::Direct,
        ))
        .expect_err("a different stored object is an integrity conflict, not an overwrite");
        assert_eq!(failure.kind(), StorageErrorKind::IntegrityConflict);

        let state = store.state.lock().unwrap();
        assert_eq!(
            state.objects.get(key.as_str()).map(Vec::as_slice),
            Some(b"{\"forged\":\"attestation at the key\"}".as_slice()),
            "whatever was there stays; writes are write-once at the derived key"
        );
        assert_eq!(state.overwrite_calls, 0);
    }

    #[test]
    fn mismatched_occurrence_id_is_refused_before_any_store_call() {
        let store = FakeStore::atomic();
        let mut envelope = direct_envelope();
        envelope.occurrence_id = OccurrenceId::parse(&"ab".repeat(32)).unwrap();

        let failure = block_on(commit_occurrence_manifest(&store, &envelope)).expect_err(
            "a payload whose re-derived occurrence_id differs is an integrity conflict",
        );
        assert_eq!(failure.kind(), StorageErrorKind::IntegrityConflict);
        assert_eq!(
            failure.detail(),
            "declared occurrence_id does not match the server-side re-derivation"
        );
        let state = store.state.lock().unwrap();
        assert!(
            state.objects.is_empty(),
            "the refused payload never reached the store"
        );
        assert_eq!(state.primitive_calls, 0);
        assert_eq!(state.overwrite_calls, 0);
    }

    #[test]
    fn mismatched_attestation_id_is_refused_before_any_store_call() {
        let store = FakeStore::atomic();
        let mut envelope = direct_envelope();
        envelope.attestation_id = AttestationId::parse(&"cd".repeat(32)).unwrap();

        let failure = block_on(commit_attestation_manifest(
            &store,
            &envelope,
            Delegation::Direct,
        ))
        .expect_err("a payload whose re-derived attestation_id differs is an integrity conflict");
        assert_eq!(failure.kind(), StorageErrorKind::IntegrityConflict);
        assert_eq!(
            failure.detail(),
            "declared attestation_id does not match the server-side re-derivation"
        );
        let state = store.state.lock().unwrap();
        assert!(state.objects.is_empty());
        assert_eq!(state.primitive_calls, 0);
        assert_eq!(state.overwrite_calls, 0);
    }

    #[test]
    fn a_tampered_occurrence_id_also_refuses_the_attestation() {
        // The attestation folds the occurrence (STO-013) and its key is
        // sharded by it, so the occurrence identity gates this path too.
        let store = FakeStore::atomic();
        let mut envelope = direct_envelope();
        envelope.occurrence_id = OccurrenceId::parse(&"ab".repeat(32)).unwrap();

        let failure = block_on(commit_attestation_manifest(
            &store,
            &envelope,
            Delegation::Direct,
        ))
        .expect_err("the folded identity disagrees with the declared one");
        assert_eq!(failure.kind(), StorageErrorKind::IntegrityConflict);
        let state = store.state.lock().unwrap();
        assert!(state.objects.is_empty());
    }

    /// The same source event presented by an authorized relay: a distinct
    /// uploader whose frozen envelope folds its own `attestation_id`
    /// (STO-013 — the id names the uploader, so a relayed request carries
    /// a different one than the origin's).
    fn relayed_envelope() -> Envelope {
        let mut envelope = direct_envelope();
        envelope.uploader_client_id = uuid("aaaaaaa1-bbbb-4ccc-9ddd-1e2f3f4f5f6f");
        envelope.attestation_id = archivist_protocol::derivation::attestation_id(
            &envelope.occurrence_id,
            &envelope.uploader_client_id,
            &envelope.request_id,
        );
        envelope
    }

    #[test]
    fn delegation_contradicting_the_client_ids_is_refused() {
        let store = FakeStore::atomic();

        // `direct` requires the uploader to be the origin.
        let failure = block_on(commit_attestation_manifest(
            &store,
            &relayed_envelope(),
            Delegation::Direct,
        ))
        .expect_err("a direct relation with a distinct uploader contradicts the ids");
        assert_eq!(failure.kind(), StorageErrorKind::MalformedInput);

        // `relay` requires the uploader to differ from the origin.
        let failure = block_on(commit_attestation_manifest(
            &store,
            &direct_envelope(),
            Delegation::Relay,
        ))
        .expect_err("a relay relation with uploader equal to origin contradicts the ids");
        assert_eq!(failure.kind(), StorageErrorKind::MalformedInput);

        let state = store.state.lock().unwrap();
        assert!(
            state.objects.is_empty(),
            "an inconsistent attestation never reaches the store"
        );
    }

    #[test]
    fn a_relay_attestation_lands_beside_the_origin_at_its_own_key() {
        let store = FakeStore::atomic();

        let origin = block_on(commit_attestation_manifest(
            &store,
            &direct_envelope(),
            Delegation::Direct,
        ))
        .expect("the origin's attestation lands");
        let relay = block_on(commit_attestation_manifest(
            &store,
            &relayed_envelope(),
            Delegation::Relay,
        ))
        .expect("the relay's attestation lands beside it");

        assert_ne!(
            origin.key().as_str(),
            relay.key().as_str(),
            "uploader_client_id is an attestation-identity input (STO-013)"
        );
        assert_eq!(relay.outcome(), StorageOutcome::Created);
        let state = store.state.lock().unwrap();
        assert_eq!(
            state.objects.len(),
            2,
            "two attestations coexist for one occurrence (EC-05A)"
        );
        assert!(
            state
                .objects
                .keys()
                .all(|key| key.contains("/v1/raw/attestations/")),
            "neither attestation touched the occurrence or the blob"
        );
    }

    #[test]
    fn writer_only_profiles_report_the_weaker_physical_outcome() {
        writer_only_profile_reports_weaker_outcome(commit_of_occurrence, "the occurrence path");
        writer_only_profile_reports_weaker_outcome(commit_of_attestation, "the attestation path");
    }

    /// One manifest commit through the writer-only profile, as a function
    /// of the store, so both paths share the weaker-truth assertions.
    fn commit_of_occurrence(store: &FakeStore) -> Result<ManifestCommit, StorageError> {
        block_on(commit_occurrence_manifest(store, &direct_envelope()))
    }

    fn commit_of_attestation(store: &FakeStore) -> Result<ManifestCommit, StorageError> {
        block_on(commit_attestation_manifest(
            store,
            &direct_envelope(),
            Delegation::Direct,
        ))
    }

    /// The shared weaker-truth assertions: first write and identical
    /// replay both report the weaker physical outcome, one logical object
    /// stays at the key, and the atomic primitive is never reached.
    fn writer_only_profile_reports_weaker_outcome(
        commit_of: fn(&FakeStore) -> Result<ManifestCommit, StorageError>,
        path: &str,
    ) {
        let store = FakeStore::writer_only();
        let first =
            commit_of(&store).unwrap_or_else(|e| panic!("{path}: the commit succeeds: {e}"));
        assert_eq!(
            first.outcome(),
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult,
            "a writer-only identity cannot establish creation or presence"
        );
        let replay =
            commit_of(&store).unwrap_or_else(|e| panic!("{path}: the replay converges: {e}"));
        assert_eq!(
            replay.outcome(),
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult,
            "the replay reports the same weaker physical truth, never a fabricated dedup"
        );
        assert_eq!(first.key().as_str(), replay.key().as_str());
        let state = store.state.lock().unwrap();
        assert_eq!(
            state.objects.len(),
            1,
            "deterministic overwrite keeps one logical object at the key"
        );
        assert_eq!(state.primitive_calls, 0);
    }

    #[test]
    fn a_writer_only_raw_write_cannot_overclaim_through_the_path() {
        for fabricated in [
            StorageOutcome::Created,
            StorageOutcome::AlreadyPresent,
            StorageOutcome::ReplacedEquivalent,
        ] {
            let store = FakeStore::lying_overwrite(fabricated);
            let commit = block_on(commit_occurrence_manifest(&store, &direct_envelope()))
                .expect("the commit itself succeeds");
            assert_eq!(
                commit.outcome(),
                StorageOutcome::LogicallyCommittedUnknownPhysicalResult,
                "no fabricated dedup evidence survives the wiring"
            );
        }
    }

    #[test]
    fn a_source_without_time_omits_the_member() {
        let mut envelope = direct_envelope();
        envelope.source_time = None;
        let session = envelope.rederive_session_hash();
        let occurrence = envelope.rederive_occurrence_id();
        let Value::Object(object) =
            super::occurrence_manifest_value(&envelope, &occurrence, &session)
        else {
            panic!("the manifest document is an object");
        };
        assert!(!object.contains("source_time"));
        assert_eq!(object.len(), 19, "every other v1 member is present");
    }

    #[test]
    fn delegation_tokens_are_the_schema_values() {
        assert_eq!(Delegation::Direct.token(), "direct");
        assert_eq!(Delegation::Relay.token(), "relay");
    }

    #[test]
    fn details_stay_inside_the_safe_message_grammar() {
        for detail in [
            super::OCCURRENCE_ID_MISMATCH_DETAIL,
            super::ATTESTATION_ID_MISMATCH_DETAIL,
            super::DELEGATION_INCONSISTENT_DETAIL,
        ] {
            assert_eq!(
                archivist_protocol::vocabulary::SafeMessage::parse(detail)
                    .unwrap_or_else(|_| panic!("detail is not safe: {detail}"))
                    .as_str(),
                detail
            );
        }
    }
}
