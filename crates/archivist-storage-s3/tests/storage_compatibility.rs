// SPDX-License-Identifier: Apache-2.0

//! Black-box storage compatibility tests.
//!
//! The suite deliberately talks to the public raw-writer and commit traits.
//! `SyntheticBackend` is an S3-shaped test double, not an implementation
//! shortcut: each profile changes only its reported capabilities and backend
//! behavior, while [`run_suite`] stays identical.  The report retains the
//! physical history for every key so logical convergence is never mistaken
//! for physical deduplication.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{
    AttestationId, BlobDigest, ClientId, HarnessId, OccurrenceId, SessionHash, StorageOutcome,
    StorageProfile, TenantId,
};
use archivist_storage::capability::{
    ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
};
use archivist_storage::commit::{CreateIfAbsent, ExistingObject, commit_manifest};
use archivist_storage::error::StorageErrorKind;
use archivist_storage::raw_write::{ManifestKey, PartCommitment, PartNumber, RawWriteStore};
use archivist_storage_s3::config::{EncryptionPolicy, S3StorageConfig};
use archivist_storage_s3::raw_write::{RawObjectKey, RawWriteBackend, S3RawWriteStore};

const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
const CLIENT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f";
const HARNESS: &str = "synthetic";
const SESSION: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const OCCURRENCE: &str = "0011223344556677001122334455667700112233445566770011223344556677";
const ATTESTATION_ORIGIN: &str = "9988776655443322110088776655443322110088776655443322110088776655";
const ATTESTATION_RELAY: &str = "8877665544332211008877665544332211008877665544332211008877665544";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OCCURRENCE_DUPLICATE: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const OCCURRENCE_OVERWRITE: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const OCCURRENCE_CONCURRENT: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const OCCURRENCE_CONFLICT: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";

/// The five profiles named by the storage registry.  These are synthetic
/// lanes: a real qualification run supplies the same profile description to a
/// live S3 request seam, while this credential-free gate checks the portable
/// contract and its honest capability branches.
#[derive(Clone, Copy, Debug)]
struct Profile {
    name: &'static str,
    capabilities: StoreCapabilities,
    read_capable: bool,
}

const PROFILES: &[Profile] = &[
    Profile {
        name: "minio",
        capabilities: StoreCapabilities {
            conditional_create: ConditionalCreate::Supported,
            stored_checksum: StoredChecksum::Sha256,
            versioning: VersioningState::Enabled,
            server_side_encryption: EncryptionState::Verified,
        },
        read_capable: true,
    },
    Profile {
        name: "backblaze-b2",
        capabilities: StoreCapabilities {
            conditional_create: ConditionalCreate::Unavailable,
            stored_checksum: StoredChecksum::ProviderSpecific,
            versioning: VersioningState::Enabled,
            server_side_encryption: EncryptionState::Verified,
        },
        read_capable: true,
    },
    Profile {
        name: "armor",
        capabilities: StoreCapabilities {
            conditional_create: ConditionalCreate::Unavailable,
            stored_checksum: StoredChecksum::ProviderSpecific,
            versioning: VersioningState::Enabled,
            server_side_encryption: EncryptionState::Verified,
        },
        read_capable: true,
    },
    Profile {
        name: "aws-s3",
        capabilities: StoreCapabilities {
            conditional_create: ConditionalCreate::Supported,
            stored_checksum: StoredChecksum::Sha256,
            versioning: VersioningState::Enabled,
            server_side_encryption: EncryptionState::Verified,
        },
        read_capable: true,
    },
    Profile {
        name: "garage",
        capabilities: StoreCapabilities {
            conditional_create: ConditionalCreate::Unavailable,
            stored_checksum: StoredChecksum::Md5,
            versioning: VersioningState::Unknown,
            server_side_encryption: EncryptionState::Unavailable,
        },
        read_capable: false,
    },
];

#[derive(Clone, Debug)]
struct PhysicalObject {
    bytes: Vec<u8>,
    checksum: Option<String>,
    version: Option<String>,
}

#[derive(Clone, Debug)]
struct MultipartState {
    key: String,
    parts: Vec<(PartNumber, Vec<u8>, String)>,
}

#[derive(Debug, Default)]
struct BackendState {
    objects: HashMap<String, Vec<PhysicalObject>>,
    uploads: HashMap<String, MultipartState>,
    next_upload: u64,
    next_version: u64,
    aborts: u64,
}

/// A deterministic, thread-safe S3 request seam used by every profile lane.
/// The adapter can only call the six methods in `RawWriteBackend`; the helper
/// observations below are test-side audit evidence for the physical report.
#[derive(Clone, Debug)]
struct SyntheticBackend {
    profile: Profile,
    state: Arc<Mutex<BackendState>>,
}

impl SyntheticBackend {
    fn new(profile: Profile) -> Self {
        Self {
            profile,
            state: Arc::new(Mutex::new(BackendState::default())),
        }
    }

    fn physical_count(&self, key: &str) -> usize {
        self.state
            .lock()
            .expect("synthetic backend lock")
            .objects
            .get(key)
            .map_or(0, Vec::len)
    }

    fn physical_versions(&self, key: &str) -> Vec<String> {
        self.state
            .lock()
            .expect("synthetic backend lock")
            .objects
            .get(key)
            .into_iter()
            .flatten()
            .filter_map(|object| object.version.clone())
            .collect()
    }

    fn latest_checksum(&self, key: &str) -> Option<String> {
        self.state
            .lock()
            .expect("synthetic backend lock")
            .objects
            .get(key)
            .and_then(|objects| objects.last())
            .and_then(|object| object.checksum.clone())
    }

    fn latest_bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.state
            .lock()
            .expect("synthetic backend lock")
            .objects
            .get(key)
            .and_then(|objects| objects.last())
            .map(|object| object.bytes.clone())
    }

    fn open_uploads(&self) -> usize {
        self.state
            .lock()
            .expect("synthetic backend lock")
            .uploads
            .len()
    }

    fn abort_count(&self) -> u64 {
        self.state.lock().expect("synthetic backend lock").aborts
    }

    fn preload(&self, key: &str, bytes: &[u8]) {
        let mut state = self.state.lock().expect("synthetic backend lock");
        let object = PhysicalObject {
            bytes: bytes.to_vec(),
            checksum: self.checksum(bytes),
            version: self.version(&mut state),
        };
        state.objects.insert(key.to_owned(), vec![object]);
    }

    fn checksum(&self, bytes: &[u8]) -> Option<String> {
        let hex = sha256::encode_hex(&sha256::digest(bytes));
        match self.profile.capabilities.stored_checksum {
            StoredChecksum::Sha256 => Some(hex),
            StoredChecksum::Md5 => Some(format!("md5-{hex}")),
            StoredChecksum::ProviderSpecific => Some(format!("provider-{hex}")),
            StoredChecksum::Unavailable => None,
        }
    }

    fn version(&self, state: &mut BackendState) -> Option<String> {
        match self.profile.capabilities.versioning {
            VersioningState::Enabled => {
                state.next_version += 1;
                Some(format!("v{}", state.next_version))
            }
            VersioningState::Disabled | VersioningState::Unknown => None,
        }
    }

    fn store_object(&self, state: &mut BackendState, key: &str, bytes: &[u8]) {
        let object = PhysicalObject {
            bytes: bytes.to_vec(),
            checksum: self.checksum(bytes),
            version: self.version(state),
        };
        match self.profile.capabilities.versioning {
            VersioningState::Disabled => {
                state.objects.insert(key.to_owned(), vec![object]);
            }
            VersioningState::Enabled | VersioningState::Unknown => {
                state
                    .objects
                    .entry(key.to_owned())
                    .or_default()
                    .push(object);
            }
        }
    }

    fn existing_evidence(&self, object: &PhysicalObject) -> ExistingObject {
        if !self.profile.read_capable {
            return ExistingObject::new();
        }
        let mut evidence = ExistingObject::new().with_size(object.bytes.len() as u64);
        if self.profile.capabilities.stored_checksum == StoredChecksum::Sha256 {
            evidence = evidence.with_stored_sha256(sha256::digest(&object.bytes));
        }
        evidence
    }

    fn tag(upload: &str, part: PartNumber) -> String {
        format!("\"{upload}-{}\"", part.get())
    }
}

impl RawWriteBackend for SyntheticBackend {
    async fn put_raw_object(
        &self,
        key: &RawObjectKey,
        bytes: &[u8],
    ) -> Result<(), archivist_storage::error::StorageError> {
        let mut state = self.state.lock().expect("synthetic backend lock");
        self.store_object(&mut state, key.as_str(), bytes);
        Ok(())
    }

    async fn create_raw_object_if_absent(
        &self,
        key: &RawObjectKey,
        bytes: &[u8],
    ) -> Result<CreateIfAbsent, archivist_storage::error::StorageError> {
        let mut state = self.state.lock().expect("synthetic backend lock");
        let Some(existing) = state
            .objects
            .get(key.as_str())
            .and_then(|objects| objects.last())
        else {
            self.store_object(&mut state, key.as_str(), bytes);
            return Ok(CreateIfAbsent::Created);
        };
        Ok(CreateIfAbsent::AlreadyExists(
            self.existing_evidence(existing),
        ))
    }

    async fn create_multipart(
        &self,
        key: &RawObjectKey,
    ) -> Result<String, archivist_storage::error::StorageError> {
        let mut state = self.state.lock().expect("synthetic backend lock");
        state.next_upload += 1;
        let id = format!("upload-{}", state.next_upload);
        state.uploads.insert(
            id.clone(),
            MultipartState {
                key: key.as_str().to_owned(),
                parts: Vec::new(),
            },
        );
        Ok(id)
    }

    async fn upload_part(
        &self,
        _key: &RawObjectKey,
        session: &str,
        part: PartNumber,
        bytes: &[u8],
    ) -> Result<String, archivist_storage::error::StorageError> {
        let mut state = self.state.lock().expect("synthetic backend lock");
        let upload = state
            .uploads
            .get_mut(session)
            .expect("adapter validates the upload handle");
        let tag = Self::tag(session, part);
        upload.parts.push((part, bytes.to_vec(), tag.clone()));
        Ok(tag)
    }

    async fn complete_multipart(
        &self,
        _key: &RawObjectKey,
        session: &str,
        parts: &[PartCommitment],
    ) -> Result<(), archivist_storage::error::StorageError> {
        let mut state = self.state.lock().expect("synthetic backend lock");
        let upload = state
            .uploads
            .remove(session)
            .expect("adapter validates the upload handle");
        assert_eq!(parts.len(), upload.parts.len());
        for (commitment, (number, _, tag)) in parts.iter().zip(&upload.parts) {
            assert_eq!(commitment.number(), *number);
            assert_eq!(commitment.tag().as_str(), tag);
        }
        let mut bytes = Vec::new();
        for (_, part, _) in upload.parts {
            bytes.extend(part);
        }
        self.store_object(&mut state, &upload.key, &bytes);
        Ok(())
    }

    async fn abort_multipart(
        &self,
        _key: &RawObjectKey,
        session: &str,
    ) -> Result<(), archivist_storage::error::StorageError> {
        let mut state = self.state.lock().expect("synthetic backend lock");
        state.uploads.remove(session);
        state.aborts += 1;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct PhysicalHistory {
    count: usize,
    version_ids: Vec<String>,
}

#[derive(Debug)]
struct CompatibilityReport {
    profile: &'static str,
    capabilities: StoreCapabilities,
    physical_versions: BTreeMap<String, PhysicalHistory>,
}

impl CompatibilityReport {
    fn observe(&mut self, label: &str, backend: &SyntheticBackend, key: &str) {
        let history = PhysicalHistory {
            count: backend.physical_count(key),
            version_ids: backend.physical_versions(key),
        };
        match self.capabilities.versioning {
            VersioningState::Enabled => {
                assert_eq!(
                    history.count,
                    history.version_ids.len(),
                    "enabled versioning must expose every physical version"
                );
                let mut unique = history.version_ids.clone();
                unique.sort_unstable();
                unique.dedup();
                assert_eq!(unique.len(), history.version_ids.len());
            }
            VersioningState::Disabled | VersioningState::Unknown => {
                assert!(
                    history.version_ids.is_empty(),
                    "a profile without observed versioning cannot report version ids"
                );
            }
        }
        self.physical_versions.insert(label.to_owned(), history);
    }

    fn render(&self) -> String {
        let histories = self
            .physical_versions
            .iter()
            .map(|(label, history)| format!("{label}:{}:{:?}", history.count, history.version_ids))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "storage-compatibility profile={} conditional_create={} stored_checksum={} versioning={} server_side_encryption={} physical_versions=[{}]",
            self.profile,
            self.capabilities.conditional_create.token(),
            self.capabilities.stored_checksum.token(),
            self.capabilities.versioning.token(),
            self.capabilities.server_side_encryption.token(),
            histories,
        )
    }
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

fn tenant() -> TenantId {
    TenantId::parse(TENANT).expect("synthetic tenant")
}

fn config(profile: Profile) -> S3StorageConfig {
    let encryption = if profile.name == "armor" {
        EncryptionPolicy::Armor
    } else {
        EncryptionPolicy::S3Sse
    };
    S3StorageConfig::builder()
        .endpoint_url("https://synthetic.example.test")
        .region("synthetic")
        .encryption(encryption)
        .raw_bucket("archivist-raw-synthetic")
        .control_bucket("archivist-control-synthetic")
        .raw_write_credentials(format!("file:/synthetic/{}/raw-writer", profile.name))
        .control_read_credentials(format!("file:/synthetic/{}/control-reader", profile.name))
        .build()
        .expect("synthetic profile configuration")
}

fn occurrence_key(scenario: &str) -> ManifestKey {
    let occurrence = match scenario {
        "duplicate" => OCCURRENCE_DUPLICATE,
        "overwrite" => OCCURRENCE_OVERWRITE,
        "concurrent" => OCCURRENCE_CONCURRENT,
        "conflict" => OCCURRENCE_CONFLICT,
        _ => panic!("unknown synthetic scenario"),
    };
    ManifestKey::Occurrence(OccurrenceObjectKey::new(
        &tenant(),
        &ClientId::parse(CLIENT).expect("synthetic client"),
        &HarnessId::parse(HARNESS).expect("synthetic harness"),
        &SessionHash::parse(SESSION).expect("synthetic session"),
        &OccurrenceId::parse(occurrence).expect("synthetic occurrence"),
    ))
}

fn attestation_key(id: &str) -> ManifestKey {
    ManifestKey::Attestation(AttestationObjectKey::new(
        &tenant(),
        &OccurrenceId::parse(OCCURRENCE).expect("synthetic occurrence"),
        &AttestationId::parse(id).expect("synthetic attestation"),
    ))
}

fn blob_key() -> BlobObjectKey {
    BlobObjectKey::new(
        &tenant(),
        StorageProfile::ZstdV1,
        &BlobDigest::parse(DIGEST).expect("synthetic blob digest"),
    )
}

fn expected_versions(profile: Profile, writes: usize) -> usize {
    match profile.capabilities.versioning {
        VersioningState::Disabled => usize::from(writes > 0),
        VersioningState::Enabled | VersioningState::Unknown => writes,
    }
}

fn assert_checksum(profile: Profile, backend: &SyntheticBackend, key: &str, bytes: &[u8]) {
    let checksum = backend.latest_checksum(key);
    match profile.capabilities.stored_checksum {
        StoredChecksum::Sha256 => {
            let expected = sha256::encode_hex(&sha256::digest(bytes));
            assert_eq!(checksum.as_deref(), Some(expected.as_str()));
        }
        StoredChecksum::Md5 => assert!(checksum.is_some_and(|value| value.starts_with("md5-"))),
        StoredChecksum::ProviderSpecific => {
            assert!(checksum.is_some_and(|value| value.starts_with("provider-")));
        }
        StoredChecksum::Unavailable => assert!(checksum.is_none()),
    }
}

fn run_suite(profile: Profile) -> CompatibilityReport {
    let backend = SyntheticBackend::new(profile);
    let store = Arc::new(
        S3RawWriteStore::new(config(profile), tenant(), backend.clone())
            .with_capabilities(profile.capabilities),
    );
    let mut report = CompatibilityReport {
        profile: profile.name,
        capabilities: profile.capabilities,
        physical_versions: BTreeMap::new(),
    };

    // Duplicate requests converge on one logical key.  The physical count is
    // intentionally profile-dependent: atomic create never overwrites, while
    // deterministic overwrite may leave noncurrent versions.
    let duplicate_key = occurrence_key("duplicate");
    let duplicate_bytes = b"duplicate-request";
    let first = block_on(commit_manifest(
        store.as_ref(),
        &duplicate_key,
        duplicate_bytes,
    ))
    .expect("first duplicate request");
    let second = block_on(commit_manifest(
        store.as_ref(),
        &duplicate_key,
        duplicate_bytes,
    ))
    .expect("replayed duplicate request");
    match profile.capabilities.conditional_create {
        ConditionalCreate::Supported if profile.read_capable => {
            assert_eq!(first, StorageOutcome::Created);
            assert_eq!(second, StorageOutcome::AlreadyPresent);
        }
        ConditionalCreate::Supported => {
            assert_eq!(first, StorageOutcome::Created);
            assert_eq!(
                second,
                StorageOutcome::LogicallyCommittedUnknownPhysicalResult
            );
        }
        ConditionalCreate::Unavailable => {
            assert_eq!(
                first,
                StorageOutcome::LogicallyCommittedUnknownPhysicalResult
            );
            assert_eq!(
                second,
                StorageOutcome::LogicallyCommittedUnknownPhysicalResult
            );
        }
    }
    let duplicate_count = backend.physical_count(duplicate_key.as_str());
    assert_eq!(
        duplicate_count,
        expected_versions(
            profile,
            if profile.capabilities.conditional_create == ConditionalCreate::Supported {
                1
            } else {
                2
            }
        )
    );
    assert_checksum(profile, &backend, duplicate_key.as_str(), duplicate_bytes);
    report.observe("duplicate-request", &backend, duplicate_key.as_str());

    // Equivalent overwrite uses the same deterministic key and bytes.  It is
    // a successful logical replay, never an integrity conflict.
    let overwrite_key = occurrence_key("overwrite");
    let overwrite_bytes = b"equivalent-overwrite";
    let overwrite_first = block_on(store.write_manifest(&overwrite_key, overwrite_bytes))
        .expect("first equivalent overwrite");
    let overwrite_second = block_on(store.write_manifest(&overwrite_key, overwrite_bytes))
        .expect("second equivalent overwrite");
    if profile.capabilities.conditional_create == ConditionalCreate::Supported {
        assert_eq!(overwrite_first, StorageOutcome::Created);
        if profile.read_capable {
            assert_eq!(overwrite_second, StorageOutcome::AlreadyPresent);
        } else {
            assert_eq!(
                overwrite_second,
                StorageOutcome::LogicallyCommittedUnknownPhysicalResult
            );
        }
    } else {
        assert_eq!(
            overwrite_first,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        assert_eq!(
            overwrite_second,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
    }
    assert_eq!(
        backend.physical_count(overwrite_key.as_str()),
        expected_versions(
            profile,
            if profile.capabilities.conditional_create == ConditionalCreate::Supported {
                1
            } else {
                2
            },
        )
    );
    report.observe("equivalent-overwrite", &backend, overwrite_key.as_str());

    // Two writers race on one immutable manifest.  The backend's mutex is the
    // atomicity boundary, so this exercises the same store instance from two
    // independent threads rather than serializing calls in the test.
    let concurrent_key = occurrence_key("concurrent");
    let concurrent_bytes = b"concurrent-writers";
    let left_store = Arc::clone(&store);
    let right_store = Arc::clone(&store);
    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            block_on(commit_manifest(
                left_store.as_ref(),
                &concurrent_key,
                concurrent_bytes,
            ))
        });
        let right = scope.spawn(|| {
            block_on(commit_manifest(
                right_store.as_ref(),
                &concurrent_key,
                concurrent_bytes,
            ))
        });
        (
            left.join()
                .expect("left concurrent writer")
                .expect("left commit"),
            right
                .join()
                .expect("right concurrent writer")
                .expect("right commit"),
        )
    });
    let outcomes = [left, right];
    if profile.capabilities.conditional_create == ConditionalCreate::Supported
        && profile.read_capable
    {
        assert!(outcomes.contains(&StorageOutcome::Created));
        assert!(outcomes.contains(&StorageOutcome::AlreadyPresent));
    } else if profile.capabilities.conditional_create == ConditionalCreate::Supported {
        assert!(outcomes.contains(&StorageOutcome::Created));
        assert!(outcomes.contains(&StorageOutcome::LogicallyCommittedUnknownPhysicalResult));
    } else {
        assert!(outcomes.iter().all(|outcome| {
            *outcome == StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        }));
    }
    let concurrent_writes =
        if profile.capabilities.conditional_create == ConditionalCreate::Supported {
            1
        } else {
            2
        };
    assert_eq!(
        backend.physical_count(concurrent_key.as_str()),
        expected_versions(profile, concurrent_writes)
    );
    report.observe("concurrent-writers", &backend, concurrent_key.as_str());

    // Read-capable conditional profiles must reject incompatible existing
    // bytes.  Writer-only profiles cannot claim that evidence and therefore
    // take the honest unknown/overwrite branch.
    let conflict_key = occurrence_key("conflict");
    let conflict_bytes = b"new-compatible-length";
    backend.preload(conflict_key.as_str(), b"old-incompatible");
    let conflict = block_on(commit_manifest(
        store.as_ref(),
        &conflict_key,
        conflict_bytes,
    ));
    if profile.capabilities.conditional_create == ConditionalCreate::Supported
        && profile.read_capable
    {
        assert_eq!(
            conflict
                .expect_err("incompatible readable object must fail")
                .kind(),
            StorageErrorKind::IntegrityConflict
        );
        assert_eq!(backend.physical_count(conflict_key.as_str()), 1);
        assert_eq!(
            backend.latest_bytes(conflict_key.as_str()).as_deref(),
            Some(&b"old-incompatible"[..])
        );
    } else if profile.capabilities.conditional_create == ConditionalCreate::Supported {
        assert_eq!(
            conflict.expect("unreadable existing object remains logically committed"),
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        assert_eq!(backend.physical_count(conflict_key.as_str()), 1);
    } else {
        assert_eq!(
            conflict.expect("overwrite profile commits without readable preflight"),
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        assert_eq!(
            backend.physical_count(conflict_key.as_str()),
            expected_versions(profile, 2)
        );
    }
    report.observe("read-capable-conflict", &backend, conflict_key.as_str());

    // A multipart abort releases all temporary state and remains idempotent.
    let blob = blob_key();
    let upload = block_on(store.begin_multipart(&blob)).expect("begin multipart");
    let part = PartNumber::new(1).expect("part number");
    let _commitment =
        block_on(store.write_part(&upload, part, b"abandoned-part")).expect("write abandoned part");
    assert_eq!(backend.open_uploads(), 1);
    block_on(store.abort_multipart(&upload)).expect("abort multipart");
    block_on(store.abort_multipart(&upload)).expect("repeat abort multipart");
    assert_eq!(backend.open_uploads(), 0);
    assert_eq!(backend.physical_count(blob.as_str()), 0);
    assert_eq!(backend.abort_count(), 1);

    // A successful multipart commit records the object and its physical
    // version, proving version/checksum observations are attached to writes.
    let committed_upload =
        block_on(store.begin_multipart(&blob)).expect("begin committed multipart");
    let committed_part = block_on(store.write_part(&committed_upload, part, b"committed-part"))
        .expect("write committed part");
    let committed = block_on(store.commit_multipart(&committed_upload, &[committed_part]))
        .expect("commit multipart");
    assert_eq!(
        committed,
        StorageOutcome::LogicallyCommittedUnknownPhysicalResult
    );
    assert_eq!(
        backend.latest_bytes(blob.as_str()).as_deref(),
        Some(&b"committed-part"[..])
    );
    assert_checksum(profile, &backend, blob.as_str(), b"committed-part");
    report.observe("multipart-commit", &backend, blob.as_str());

    // One occurrence can have independent attestations for two uploaders.
    // The source occurrence is a different logical object from each request /
    // uploader attestation, so neither attestation may overwrite the other.
    let origin_key = attestation_key(ATTESTATION_ORIGIN);
    let relay_key = attestation_key(ATTESTATION_RELAY);
    let origin_bytes = b"uploader=origin;request=request-origin";
    let relay_bytes = b"uploader=relay;request=request-relay";
    let origin = block_on(commit_manifest(store.as_ref(), &origin_key, origin_bytes))
        .expect("origin attestation");
    let relay = block_on(commit_manifest(store.as_ref(), &relay_key, relay_bytes))
        .expect("relay attestation");
    if profile.capabilities.conditional_create == ConditionalCreate::Supported {
        assert_eq!(origin, StorageOutcome::Created);
        assert_eq!(relay, StorageOutcome::Created);
    } else {
        assert_eq!(
            origin,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        assert_eq!(
            relay,
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
    }
    assert_ne!(origin_key.as_str(), relay_key.as_str());
    assert_eq!(backend.physical_count(origin_key.as_str()), 1);
    assert_eq!(backend.physical_count(relay_key.as_str()), 1);
    report.observe("origin-attestation", &backend, origin_key.as_str());
    report.observe("relay-attestation", &backend, relay_key.as_str());

    report
}

#[test]
fn the_same_suite_passes_for_every_supported_profile_and_records_versions() {
    let reports = PROFILES.iter().copied().map(run_suite).collect::<Vec<_>>();
    assert_eq!(reports.len(), PROFILES.len());
    for report in reports {
        assert!(
            report
                .physical_versions
                .values()
                .any(|history| history.count > 1)
                || report.capabilities.conditional_create == ConditionalCreate::Supported,
            "{} did not record a physical-version observation",
            report.profile
        );
        println!("{}", report.render());
    }
}
