// SPDX-License-Identifier: Apache-2.0

//! Black-box coverage for the community qualification driver.
//!
//! This deliberately composes the same public probe, raw-write, and
//! lifecycle-audit seams as the executable driver.  The backend double keeps
//! the test credential-free while retaining physical object histories, so the
//! assertions cover the probe reduction, every write-path scenario, the
//! injected enumeration faults, and the honest negative paths as one run.

#![allow(clippy::manual_async_fn, clippy::too_many_lines)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{TenantId, Timestamp};
use archivist_storage::audit_restore::{ContinuationToken, InventoryKey, InventoryScope};
use archivist_storage::capability::{
    ConditionalCreate, EncryptionState, StoredChecksum, VersioningState,
};
use archivist_storage::commit::{CreateIfAbsent, ExistingObject};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::lifecycle_audit::{VersionedEntry, VersionedPage};
use archivist_storage::metadata::{ObjectTag, Observation, StorageVersionId};
use archivist_storage::probe::{ProbeKey, VersioningObservation};
use archivist_storage::raw_write::{PartCommitment, PartNumber};
use archivist_storage_s3::config::{EncryptionPolicy, S3StorageConfig};
use archivist_storage_s3::lifecycle_audit::{S3LifecycleAuditStore, VersionAuditBackend};
use archivist_storage_s3::probe::{
    ProbeObjectObservation, ProbeReceipt, ProbeWriteBackend, S3ProbeSource,
};
use archivist_storage_s3::qualify::{
    self, FIXTURE_TENANT, LegExit, LegId, RunTranscript, RunVerdict, ScenarioOutcome,
};
use archivist_storage_s3::raw_write::{RawObjectKey, RawWriteBackend, S3RawWriteStore};

const OBSERVED_AT: &str = "2026-09-28T12:00:00Z";
const PROFILE: &str = "community-fixture";
const SUITE_REVISION: &str = "qualification-test-revision";

// These values model operator configuration.  They are intentionally
// distinctive so a transcript that accidentally carries deployment or
// credential data cannot pass by coincidence.
const ENDPOINT: &str = "https://community-storage.example.invalid";
const RAW_BUCKET: &str = "community-raw-private-bucket";
const CONTROL_BUCKET: &str = "community-control-private-bucket";
const RAW_CREDENTIAL: &str = "file:/run/secrets/community-raw-writer";
const CONTROL_CREDENTIAL: &str = "env:COMMUNITY_CONTROL_READER_SECRET";
const RESTORE_CREDENTIAL: &str = "file:/run/secrets/community-offline-restore";

const SCENARIOS: [&str; 8] = [
    "duplicate-request",
    "equivalent-overwrite",
    "concurrent-writers",
    "read-capable-conflict",
    "multipart-abort",
    "multipart-commit",
    "origin-attestation",
    "relay-attestation",
];

type UploadSession = (String, Vec<(PartNumber, Vec<u8>, String)>);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum VersioningAnswer {
    #[default]
    Enabled,
    NoSurface,
}

#[derive(Clone, Debug)]
struct Physical {
    bytes: Vec<u8>,
    checksum: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Default)]
struct State {
    objects: HashMap<String, Vec<Physical>>,
    uploads: HashMap<String, UploadSession>,
    probe_objects: HashMap<String, Vec<Physical>>,
    probe_uploads: HashMap<String, UploadSession>,
    next_id: u64,
    versioning_answer: VersioningAnswer,
    fail_raw_writes: bool,
    fail_probe_multipart: bool,
    fail_control_enumeration: bool,
}

#[derive(Clone, Debug, Default)]
struct Fake {
    state: Arc<Mutex<State>>,
    versioned: bool,
}

impl Fake {
    fn honest() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            versioned: true,
        }
    }

    fn version(&self, state: &mut State) -> String {
        state.next_id += 1;
        if self.versioned {
            format!("v{}", state.next_id)
        } else {
            String::from("null")
        }
    }

    fn store(map: &mut HashMap<String, Vec<Physical>>, key: &str, object: Physical) {
        map.entry(key.to_owned()).or_default().push(object);
    }
}

fn checksum(bytes: &[u8]) -> String {
    sha256::encode_hex(&sha256::digest(bytes))
}

fn tenant() -> TenantId {
    TenantId::parse(FIXTURE_TENANT).expect("fixture tenant")
}

fn observed_at() -> Timestamp {
    Timestamp::parse(OBSERVED_AT).expect("static timestamp")
}

fn config() -> S3StorageConfig {
    S3StorageConfig::builder()
        .endpoint_url(ENDPOINT)
        .region("community-test-region")
        .encryption(EncryptionPolicy::S3Sse)
        .raw_bucket(RAW_BUCKET)
        .control_bucket(CONTROL_BUCKET)
        .raw_write_credentials(RAW_CREDENTIAL)
        .control_read_credentials(CONTROL_CREDENTIAL)
        .offline_restore_credentials(RESTORE_CREDENTIAL)
        .build()
        .expect("synthetic configuration")
}

impl ProbeWriteBackend for Fake {
    async fn write_probe_if_absent(
        &self,
        key: &ProbeKey,
        bytes: &[u8],
    ) -> Result<ProbeReceipt, StorageError> {
        let mut state = self.state.lock().expect("fake lock");
        if let Some(existing) = state
            .probe_objects
            .get(key.as_str())
            .and_then(|objects| objects.last())
        {
            return Ok(ProbeReceipt::new(
                false,
                existing.version.clone(),
                existing.checksum.clone(),
                true,
            ));
        }
        let object = Physical {
            bytes: bytes.to_vec(),
            checksum: Some(checksum(bytes)),
            version: Some(self.version(&mut state)),
        };
        Self::store(&mut state.probe_objects, key.as_str(), object);
        let stored = state.probe_objects[key.as_str()]
            .last()
            .expect("just stored");
        Ok(ProbeReceipt::new(
            true,
            stored.version.clone(),
            stored.checksum.clone(),
            true,
        ))
    }

    async fn read_probe_object(
        &self,
        key: &ProbeKey,
    ) -> Result<Option<ProbeObjectObservation>, StorageError> {
        let state = self.state.lock().expect("fake lock");
        Ok(state
            .probe_objects
            .get(key.as_str())
            .and_then(|objects| objects.last())
            .map(|object| {
                ProbeObjectObservation::new(
                    object.bytes.len() as u64,
                    object.version.clone(),
                    object.checksum.clone(),
                    true,
                )
            }))
    }

    async fn bucket_versioning(&self) -> Result<Option<VersioningObservation>, StorageError> {
        match self.state.lock().expect("fake lock").versioning_answer {
            VersioningAnswer::Enabled => Ok(Some(VersioningObservation::Enabled)),
            VersioningAnswer::NoSurface => Ok(None),
        }
    }

    async fn bucket_encryption(&self) -> Result<bool, StorageError> {
        Ok(true)
    }

    async fn create_probe_multipart(&self, key: &ProbeKey) -> Result<String, StorageError> {
        let mut state = self.state.lock().expect("fake lock");
        if state.fail_probe_multipart {
            return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
        }
        state.next_id += 1;
        let id = format!("probe-upload-{}", state.next_id);
        state
            .probe_uploads
            .insert(id.clone(), (key.as_str().to_owned(), Vec::new()));
        Ok(id)
    }

    async fn upload_probe_part(
        &self,
        _key: &ProbeKey,
        session: &str,
        part: PartNumber,
        bytes: &[u8],
    ) -> Result<String, StorageError> {
        let mut state = self.state.lock().expect("fake lock");
        let upload = state
            .probe_uploads
            .get_mut(session)
            .expect("probe session is open");
        let tag = checksum(bytes);
        upload.1.push((part, bytes.to_vec(), tag.clone()));
        Ok(tag)
    }

    async fn complete_probe_multipart(
        &self,
        _key: &ProbeKey,
        session: &str,
        _parts: &[PartCommitment],
    ) -> Result<(), StorageError> {
        let mut state = self.state.lock().expect("fake lock");
        let (key, parts) = state
            .probe_uploads
            .remove(session)
            .expect("probe session is open");
        let mut bytes = Vec::new();
        for (_, part, _) in parts {
            bytes.extend(part);
        }
        let object = Physical {
            checksum: Some(checksum(&bytes)),
            version: Some(self.version(&mut state)),
            bytes,
        };
        Self::store(&mut state.probe_objects, &key, object);
        Ok(())
    }

    async fn abort_probe_multipart(
        &self,
        _key: &ProbeKey,
        session: &str,
    ) -> Result<(), StorageError> {
        self.state
            .lock()
            .expect("fake lock")
            .probe_uploads
            .remove(session);
        Ok(())
    }
}

impl RawWriteBackend for Fake {
    async fn put_raw_object(&self, key: &RawObjectKey, bytes: &[u8]) -> Result<(), StorageError> {
        let mut state = self.state.lock().expect("fake lock");
        if state.fail_raw_writes {
            return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
        }
        let object = Physical {
            bytes: bytes.to_vec(),
            checksum: Some(checksum(bytes)),
            version: Some(self.version(&mut state)),
        };
        Self::store(&mut state.objects, key.as_str(), object);
        Ok(())
    }

    async fn create_raw_object_if_absent(
        &self,
        key: &RawObjectKey,
        bytes: &[u8],
    ) -> Result<CreateIfAbsent, StorageError> {
        let mut state = self.state.lock().expect("fake lock");
        if state.fail_raw_writes {
            return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
        }
        if let Some(existing) = state
            .objects
            .get(key.as_str())
            .and_then(|objects| objects.last())
        {
            let mut evidence = ExistingObject::new().with_size(existing.bytes.len() as u64);
            if existing.checksum.is_some() {
                evidence = evidence
                    .with_stored_sha256(archivist_protocol::sha256::digest(&existing.bytes));
            }
            return Ok(CreateIfAbsent::AlreadyExists(evidence));
        }
        let object = Physical {
            bytes: bytes.to_vec(),
            checksum: Some(checksum(bytes)),
            version: Some(self.version(&mut state)),
        };
        Self::store(&mut state.objects, key.as_str(), object);
        Ok(CreateIfAbsent::Created)
    }

    async fn create_multipart(&self, key: &RawObjectKey) -> Result<String, StorageError> {
        let mut state = self.state.lock().expect("fake lock");
        state.next_id += 1;
        let id = format!("upload-{}", state.next_id);
        state
            .uploads
            .insert(id.clone(), (key.as_str().to_owned(), Vec::new()));
        Ok(id)
    }

    async fn upload_part(
        &self,
        _key: &RawObjectKey,
        session: &str,
        part: PartNumber,
        bytes: &[u8],
    ) -> Result<String, StorageError> {
        let mut state = self.state.lock().expect("fake lock");
        let upload = state.uploads.get_mut(session).expect("upload is open");
        let tag = checksum(bytes);
        upload.1.push((part, bytes.to_vec(), tag.clone()));
        Ok(tag)
    }

    async fn complete_multipart(
        &self,
        _key: &RawObjectKey,
        session: &str,
        _parts: &[PartCommitment],
    ) -> Result<(), StorageError> {
        let mut state = self.state.lock().expect("fake lock");
        let (key, parts) = state.uploads.remove(session).expect("upload is open");
        let mut bytes = Vec::new();
        for (_, part, _) in parts {
            bytes.extend(part);
        }
        let object = Physical {
            checksum: Some(checksum(&bytes)),
            version: Some(self.version(&mut state)),
            bytes,
        };
        Self::store(&mut state.objects, &key, object);
        Ok(())
    }

    async fn abort_multipart(
        &self,
        _key: &RawObjectKey,
        session: &str,
    ) -> Result<(), StorageError> {
        self.state
            .lock()
            .expect("fake lock")
            .uploads
            .remove(session);
        Ok(())
    }
}

impl VersionAuditBackend for Fake {
    async fn list_object_versions(
        &self,
        scope: &InventoryScope,
        after: Option<&ContinuationToken>,
    ) -> Result<VersionedPage, StorageError> {
        let state = self.state.lock().expect("fake lock");
        if state.fail_control_enumeration && matches!(scope, InventoryScope::TenantControl(_)) {
            return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
        }
        let prefix = scope.prefix();
        let mut records = state
            .objects
            .iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .flat_map(|(key, objects)| {
                let last = objects.len().saturating_sub(1);
                objects
                    .iter()
                    .enumerate()
                    .filter_map(move |(index, object)| {
                        Some((
                            key.clone(),
                            object.bytes.len() as u64,
                            object.version.as_ref()?.clone(),
                            index == last,
                            object.checksum.clone(),
                        ))
                    })
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.0
                .as_bytes()
                .cmp(right.0.as_bytes())
                .then(left.2.as_bytes().cmp(right.2.as_bytes()))
        });
        let entries = records
            .into_iter()
            .map(|(key, size, version, latest, checksum)| {
                VersionedEntry::new(
                    InventoryKey::parse(&key).expect("synthetic inventory key"),
                    size,
                    StorageVersionId::parse(&version).expect("synthetic version"),
                    latest,
                    Observation::new(
                        checksum
                            .as_deref()
                            .map(ObjectTag::parse)
                            .transpose()
                            .expect("synthetic checksum"),
                        None,
                        observed_at(),
                    ),
                )
            })
            .collect::<Vec<_>>();
        let page_size = 2;
        let page_number = match after {
            None => 0,
            Some(token) => token
                .as_str()
                .strip_prefix('p')
                .and_then(|number| number.parse::<usize>().ok())
                .ok_or_else(|| StorageError::of_kind(StorageErrorKind::Unavailable))?,
        };
        let start = page_number * page_size;
        if start > entries.len() {
            return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
        }
        let end = (start + page_size).min(entries.len());
        let next = (end < entries.len()).then(|| {
            ContinuationToken::parse(&format!("p{}", end / page_size))
                .expect("synthetic continuation")
        });
        Ok(VersionedPage::new(entries[start..end].to_vec(), next))
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

fn run_over(fake: &Fake) -> qualify::QualificationReport {
    let tenant = tenant();
    let probe = S3ProbeSource::new(fake.clone(), tenant.clone());
    let store = Arc::new(S3RawWriteStore::new(config(), tenant.clone(), fake.clone()));
    let audit = S3LifecycleAuditStore::new(config(), tenant.clone(), fake.clone())
        .expect("the synthetic configuration grants offline restore");
    let plan = qualify::RunPlan {
        profile_key: PROFILE,
        suite_revision: SUITE_REVISION,
        read_capable: true,
        observed_at: observed_at(),
    };
    block_on(qualify::run(&plan, &tenant, &probe, &store, &audit))
}

#[test]
fn public_driver_runs_every_leg_and_redacts_deployment_data() {
    let report = run_over(&Fake::honest());

    assert_eq!(report.verdict(), &RunVerdict::Qualified);
    assert!(report.profile_supported());
    assert_eq!(
        report.capabilities().conditional_create,
        ConditionalCreate::Supported
    );
    assert_eq!(
        report.capabilities().stored_checksum,
        StoredChecksum::Sha256
    );
    assert_eq!(report.capabilities().versioning, VersioningState::Enabled);
    assert_eq!(
        report.capabilities().server_side_encryption,
        EncryptionState::Verified
    );
    assert_eq!(report.capability_report_bytes()[0], b'{');
    assert!(report.capability_report_digest().starts_with("sha256:"));

    for leg in report.legs() {
        assert_eq!(leg.exit, LegExit::Complete, "leg {:?}", leg.leg);
    }
    assert_eq!(
        report
            .scenarios()
            .iter()
            .map(|scenario| (scenario.label, scenario.outcome))
            .collect::<Vec<_>>(),
        SCENARIOS
            .into_iter()
            .map(|label| (label, ScenarioOutcome::Matched))
            .collect::<Vec<_>>(),
        "the report retains every write-path and enumeration scenario",
    );
    assert_eq!(report.physical_versions().len(), 7);
    assert!(report.noncurrent().is_some());
    assert!(report.render_line().contains("noncurrent-version-audit"));
    assert!(report.render_line().contains("scope=tenant-raw"));

    // The transcript is the only printable run record.  Supplying every
    // operator value to the public redaction boundary proves that none of
    // them was serialized into the report or capability evidence.
    let configured = [
        ENDPOINT,
        RAW_BUCKET,
        CONTROL_BUCKET,
        RAW_CREDENTIAL,
        CONTROL_CREDENTIAL,
        RESTORE_CREDENTIAL,
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();
    let transcript = RunTranscript::from_report(&report, SUITE_REVISION)
        .render(&configured)
        .expect("the committed record contains no deployment material");
    for prohibited in configured {
        assert!(
            !transcript.contains(&prohibited),
            "prohibited deployment or credential data leaked: {prohibited}"
        );
    }
    assert!(!transcript.contains(FIXTURE_TENANT));
    assert!(qualify::redaction_violations(&transcript, &[]).is_empty());
    assert!(transcript.contains("leg=enumeration exit=complete"));
    assert!(
        !qualify::redaction_violations("bucket=raw", &[String::from("raw")]).is_empty(),
        "short configured bucket names are still sensitive"
    );
    assert!(
        !qualify::redaction_violations("tenant=0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b", &[])
            .is_empty(),
        "identity-shaped UUIDs are refused"
    );
}

#[test]
fn report_and_transcript_have_the_documented_complete_shape() {
    let report = run_over(&Fake::honest());
    let line = report.render_line();
    for field in [
        "storage-compatibility profile=community-fixture",
        "conditional_create=supported",
        "stored_checksum=sha256",
        "versioning=enabled",
        "server_side_encryption=verified",
        "physical_versions=[",
        "noncurrent_audit=[noncurrent-version-audit",
    ] {
        assert!(line.contains(field), "report omitted {field}: {line}");
    }
    for scenario in [
        "duplicate-request",
        "equivalent-overwrite",
        "concurrent-writers",
        "read-capable-conflict",
        "multipart-commit",
        "origin-attestation",
        "relay-attestation",
    ] {
        assert!(
            line.contains(&format!("{scenario}:")),
            "report omitted physical history for {scenario}: {line}"
        );
    }

    let transcript = RunTranscript::from_report(&report, SUITE_REVISION)
        .render(&[])
        .expect("the complete transcript is safe to render");
    assert!(transcript.contains("capability-report-digest=sha256:"));
    assert!(transcript.contains("profile_supported=true"));
    assert!(transcript.contains("verdict=qualified"));
    for leg in ["probe", "write-path", "enumeration"] {
        assert!(transcript.contains(&format!("leg={leg} exit=complete")));
    }
    for scenario in SCENARIOS {
        assert!(transcript.contains(&format!("scenario={scenario} outcome=matched")));
    }
}

#[test]
fn capability_reduction_stays_weak_and_probe_failure_is_unqualified() {
    let unknown = Fake {
        state: Arc::new(Mutex::new(State {
            versioning_answer: VersioningAnswer::NoSurface,
            ..State::default()
        })),
        versioned: false,
    };
    let report = run_over(&unknown);
    assert_eq!(report.verdict(), &RunVerdict::Qualified);
    assert_eq!(report.capabilities().versioning, VersioningState::Unknown);
    assert!(report.noncurrent().is_none());
    assert!(
        report
            .physical_versions()
            .values()
            .all(|history| { history.version_ids.is_empty() })
    );
    assert!(report.render_line().contains("versioning=unknown"));
    assert!(report.render_line().contains("noncurrent_audit=refused"));

    let unsupported = Fake::honest();
    unsupported
        .state
        .lock()
        .expect("fake lock")
        .fail_probe_multipart = true;
    let report = run_over(&unsupported);
    assert!(matches!(report.verdict(), RunVerdict::Unqualified(_)));
    assert!(!report.profile_supported());
    assert_eq!(report.leg(LegId::Probe).exit, LegExit::Complete);
    assert_eq!(report.leg(LegId::WritePath).exit, LegExit::NotReached);
    assert_eq!(report.leg(LegId::Enumeration).exit, LegExit::NotReached);
    assert!(
        report
            .scenarios()
            .iter()
            .all(|scenario| scenario.outcome == ScenarioOutcome::NotReached)
    );
}

#[test]
fn write_failure_is_recorded_as_unqualified_without_claiming_completion() {
    let failed = Fake::honest();
    failed.state.lock().expect("fake lock").fail_raw_writes = true;
    let report = run_over(&failed);

    assert!(matches!(report.verdict(), RunVerdict::Unqualified(_)));
    assert_eq!(report.leg(LegId::Probe).exit, LegExit::Complete);
    assert_ne!(report.leg(LegId::WritePath).exit, LegExit::Complete);
    assert_eq!(report.leg(LegId::Enumeration).exit, LegExit::NotReached);
    assert!(
        report
            .scenarios()
            .iter()
            .any(|scenario| scenario.outcome == ScenarioOutcome::Errored)
    );
    assert!(
        report
            .scenarios()
            .iter()
            .all(|scenario| scenario.outcome != ScenarioOutcome::Matched)
    );
}

#[test]
fn enumeration_failure_is_recorded_as_unqualified_after_write_completion() {
    let failed = Fake::honest();
    failed
        .state
        .lock()
        .expect("fake lock")
        .fail_control_enumeration = true;
    let report = run_over(&failed);

    assert!(matches!(report.verdict(), RunVerdict::Unqualified(_)));
    assert_eq!(report.leg(LegId::Probe).exit, LegExit::Complete);
    assert_eq!(report.leg(LegId::WritePath).exit, LegExit::Complete);
    assert_eq!(report.leg(LegId::Enumeration).exit, LegExit::Unknown);
    assert!(
        report
            .scenarios()
            .iter()
            .all(|scenario| scenario.outcome == ScenarioOutcome::Matched)
    );
}
