// SPDX-License-Identifier: Apache-2.0

//! The Phase 10 catalog rebuild's end-to-end command contract.
//!
//! The test binary re-executes itself once per scenario so the parent can
//! observe the real router streams and exit status. Successful scenarios use
//! the command's generic rebuild seam with three independent, role-named
//! stores: the audit reader can read raw objects and checkpoints, the catalog
//! writer can only put/list checkpoints, and the derived writer can only
//! put/list derived rows. Refusal scenarios register the production handler,
//! proving configuration is resolved before any backend work is attempted.

#![allow(clippy::manual_async_fn, clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use archivist_client_core::cli::{CliError, Invocation, Router};
use archivist_protocol::derivation::{
    artifact_hash, attestation_id, blob_digest, occurrence_id, session_hash,
};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::vocabulary::{
    AdapterId, ArtifactKind, ClientId, GenerationId, HarnessId, RangeKind, RequestId,
    StorageProfile, TenantId, Timestamp, VersionToken,
};
use archivist_storage::audit_restore::{
    AuditRestoreStore, ContinuationToken, FrozenInventory, InventoryEntry, InventoryKey,
    InventoryPage, InventoryScope, ObjectBody, ObjectMetadata,
};
use archivist_storage::blob::BlobEncoder;
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::metadata::Observation;
use archivist_storage::scoped_write::{
    CatalogCheckpointKey, CatalogListPrefix, CatalogWriteStore, DerivedListPrefix,
    DerivedObjectKey, DerivedWriteStore,
};
use archivist_storage::zstd_v1::ZstdV1Encoder;

const SCENARIO_ENV: &str = "CATALOG_REBUILD_E2E_SCENARIO";
const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
const OBSERVED_AT: &str = "2026-09-28T12:00:00Z";
const WITNESS: &str = "catalog-rebuild-e2e-transcript-witness";
#[derive(Clone, Copy, Debug)]
enum Scenario {
    GoldenBare,
    GoldenJson,
    Retry,
    MissingConfiguration,
    MissingCredential,
    SharedWriterIdentity,
    IngestIdentityReuse,
}

const SCENARIOS: &[Scenario] = &[
    Scenario::GoldenBare,
    Scenario::GoldenJson,
    Scenario::Retry,
    Scenario::MissingConfiguration,
    Scenario::MissingCredential,
    Scenario::SharedWriterIdentity,
    Scenario::IngestIdentityReuse,
];

impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Self::GoldenBare => "golden-bare",
            Self::GoldenJson => "golden-json",
            Self::Retry => "retry",
            Self::MissingConfiguration => "missing-configuration",
            Self::MissingCredential => "missing-credential",
            Self::SharedWriterIdentity => "shared-writer-identity",
            Self::IngestIdentityReuse => "ingest-identity-reuse",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        SCENARIOS
            .iter()
            .copied()
            .find(|scenario| scenario.name() == name)
    }

    fn is_success(self) -> bool {
        matches!(self, Self::GoldenBare | Self::GoldenJson | Self::Retry)
    }

    fn is_json(self) -> bool {
        matches!(self, Self::GoldenJson)
    }

    fn expected_exit(self) -> i32 {
        if self.is_success() { 0 } else { 64 }
    }

    fn expected_diagnostic(self) -> Option<&'static str> {
        match self {
            Self::GoldenBare | Self::GoldenJson | Self::Retry => None,
            Self::MissingConfiguration => Some("cli.decision_missing"),
            Self::MissingCredential => Some("client.secret_ref_refused"),
            Self::SharedWriterIdentity | Self::IngestIdentityReuse => Some("cli.usage_error"),
        }
    }

    fn argv(self) -> Vec<OsString> {
        let mut args = vec![OsString::from("--non-interactive")];
        if self.is_json() {
            args.push(OsString::from("--json"));
        }
        args.extend([
            OsString::from("catalog"),
            OsString::from("rebuild"),
            OsString::from("--from-occurrences"),
        ]);
        args
    }
}

fn main() {
    match std::env::var(SCENARIO_ENV) {
        Ok(name) => run_child(Scenario::from_name(&name).expect("parent selected a scenario")),
        Err(_) => run_parent(),
    }
}

fn run_parent() {
    for scenario in SCENARIOS {
        let binary = std::env::current_exe().expect("test binary path");
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env(SCENARIO_ENV, scenario.name())
            .env("HOME", "/tmp/archivist-catalog-rebuild-e2e-home")
            .stdin(std::process::Stdio::null());
        if matches!(
            scenario,
            Scenario::MissingCredential
                | Scenario::SharedWriterIdentity
                | Scenario::IngestIdentityReuse
        ) {
            for (name, value) in composition_environment(*scenario) {
                command.env(name, value);
            }
        }
        let output = command.output().expect("scenario child spawns");
        let story = scenario.name();
        assert_eq!(
            output.status.code(),
            Some(scenario.expected_exit()),
            "{story}: exit class (stderr: {})",
            String::from_utf8_lossy(&output.stderr),
        );
        if let Some(code) = scenario.expected_diagnostic() {
            assert!(output.stdout.is_empty(), "{story}: refusal has no stdout");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.starts_with(&format!("archivist {code}:")),
                "{story}: diagnostic code (stderr: {stderr})",
            );
        } else {
            assert!(
                output.stderr.is_empty(),
                "{story}: success has no stderr (stderr: {})",
                String::from_utf8_lossy(&output.stderr),
            );
            assert_success_output(*scenario, &output.stdout);
        }
    }
}

fn run_child(scenario: Scenario) {
    let mut router = Router::new();
    if scenario.is_success() {
        router
            .register_handler("catalog rebuild", e2e_handler)
            .expect("the catalog result schema accepts the seam handler");
    } else {
        for (path, handler) in archivist_cli::catalog::handlers() {
            router
                .register_handler(path, handler)
                .expect("the production catalog handler is schema-bound");
        }
    }
    let exit = router.run(&scenario.argv());
    if scenario.is_success() && exit == 0 {
        verify_landed_state(scenario);
    }
    std::process::exit(exit);
}

fn e2e_handler(invocation: &Invocation) -> Result<Value, CliError> {
    let store = store();
    let tenant = tenant();
    let first = archivist_cli::catalog::rebuild_over(
        invocation,
        &tenant,
        &store.audit,
        &store.catalog,
        &store.derived,
    )?;
    if matches!(current_scenario(), Scenario::Retry) {
        let second = archivist_cli::catalog::rebuild_over(
            invocation,
            &tenant,
            &store.audit,
            &store.catalog,
            &store.derived,
        )?;
        assert_eq!(
            first.canonical_bytes(),
            second.canonical_bytes(),
            "a retry converges on byte-identical result state",
        );
        Ok(second)
    } else {
        Ok(first)
    }
}

fn current_scenario() -> Scenario {
    Scenario::from_name(&std::env::var(SCENARIO_ENV).expect("child scenario environment"))
        .expect("known child scenario")
}

fn tenant() -> TenantId {
    TenantId::parse(TENANT).expect("fixture tenant grammar")
}

fn assert_success_output(scenario: Scenario, stdout: &[u8]) {
    let story = scenario.name();
    let framed = stdout
        .strip_suffix(b"\n")
        .unwrap_or_else(|| panic!("{story}: stdout has one trailing newline"));
    let document = json::parse(framed).unwrap_or_else(|error| panic!("{story}: JSON: {error}"));
    assert_eq!(
        framed,
        document.canonical_bytes().as_slice(),
        "{story}: output is canonical JSON",
    );
    assert!(
        !String::from_utf8_lossy(framed).contains(WITNESS),
        "{story}: raw transcript text stays out of result output",
    );
    let result = if scenario.is_json() {
        let Value::Object(envelope) = &document else {
            panic!("{story}: --json output is an object");
        };
        assert_eq!(envelope.len(), 4, "{story}: output envelope is closed");
        assert_eq!(
            envelope.get("schema"),
            Some(&Value::Text("archivist.cli-output/v1".to_owned()))
        );
        assert_eq!(
            envelope.get("command"),
            Some(&Value::Text("catalog-rebuild".to_owned()))
        );
        envelope.get("result").expect("envelope result")
    } else {
        &document
    };
    assert_catalog_result(story, result);
}

fn assert_catalog_result(story: &str, result: &Value) {
    let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/v1/cli-catalog-rebuild.json");
    let Value::Object(schema) = json::parse(&std::fs::read(schema_path).expect("result schema"))
        .expect("result schema JSON")
    else {
        panic!("{story}: result schema is an object");
    };
    let Value::Array(required) = schema.get("required").expect("schema required") else {
        panic!("{story}: schema required is an array");
    };
    let Value::Object(record) = result else {
        panic!("{story}: result is an object");
    };
    assert_eq!(record.len(), required.len(), "{story}: result is closed");
    for member in required {
        let Value::Text(member) = member else {
            panic!("{story}: required member name is text");
        };
        assert!(
            record.get(member).is_some(),
            "{story}: result carries {member}"
        );
    }
    assert_eq!(
        record.get("schema"),
        Some(&Value::Text("archivist.cli-result/v1".to_owned()))
    );
    assert_eq!(
        record.get("tenant_id"),
        Some(&Value::Text(TENANT.to_owned()))
    );
    assert_eq!(record.get("occurrences_total"), Some(&Value::Int(1)));
    assert_eq!(record.get("complete"), Some(&Value::Bool(true)));
    let Value::Object(row_states) = record.get("row_states").expect("row states") else {
        panic!("{story}: row states is an object");
    };
    assert_eq!(row_states.get("measured"), Some(&Value::Int(1)));
    assert_eq!(row_states.get("absent"), Some(&Value::Int(0)));
    assert_eq!(row_states.get("malformed"), Some(&Value::Int(0)));
    assert_eq!(row_states.get("unsupported"), Some(&Value::Int(0)));
    let Some(Value::Text(checkpoint_key)) = record.get("checkpoint_key") else {
        panic!("{story}: checkpoint key is text");
    };
    assert!(checkpoint_key.starts_with(&format!("tenants/{TENANT}/v1/catalog/checkpoints/")));
}

fn verify_landed_state(scenario: Scenario) {
    let store = store();
    assert_eq!(
        store.catalog.put_count(),
        1,
        "one content-addressed checkpoint put"
    );
    assert_eq!(store.derived.put_count(), 1, "one derived row put");
    assert_eq!(
        store.audit.checkpoint_reads(),
        usize::from(matches!(scenario, Scenario::Retry)),
        "retry reads the prior checkpoint through the audit identity",
    );
    assert_eq!(
        store.catalog.list_count(),
        1 + usize::from(matches!(scenario, Scenario::Retry)),
        "each pass lists the checkpoint namespace through the catalog identity",
    );

    for key in store.catalog.keys() {
        let parsed = CatalogCheckpointKey::parse(&key).expect("catalog key grammar");
        let bytes = store.catalog.bytes(&key).expect("checkpoint bytes");
        assert_eq!(parsed.checkpoint(), &blob_digest(&bytes));
    }
    for key in store.derived.keys() {
        assert!(
            key.starts_with(&format!("tenants/{TENANT}/v1/derived/")),
            "derived writer stayed in its namespace: {key}",
        );
        let bytes = store.derived.bytes(&key).expect("derived row bytes");
        assert!(!String::from_utf8_lossy(&bytes).contains(WITNESS));
        let Value::Object(row) = json::parse(&bytes).expect("derived row JSON") else {
            panic!("derived row is an object");
        };
        assert_eq!(
            row.get("pipeline_id"),
            Some(&Value::Text("usage".to_owned()))
        );
        assert_eq!(
            row.get("pipeline_version"),
            Some(&Value::Text("1".to_owned()))
        );
    }
}

fn composition_environment(scenario: Scenario) -> Vec<(&'static str, String)> {
    let raw = "file:/tmp/archivist-e2e-raw-credentials".to_owned();
    let control = "file:/tmp/archivist-e2e-control-credentials".to_owned();
    let catalog = if matches!(scenario, Scenario::IngestIdentityReuse) {
        raw.clone()
    } else {
        "file:/tmp/archivist-e2e-catalog-credentials".to_owned()
    };
    let derived = if matches!(scenario, Scenario::SharedWriterIdentity) {
        catalog.clone()
    } else {
        "file:/tmp/archivist-e2e-derived-credentials".to_owned()
    };
    vec![
        (
            "ARCHIVIST_INGEST_ENDPOINT_URL",
            "https://ingest.example.invalid".to_owned(),
        ),
        (
            "ARCHIVIST_SERVER_LISTEN_ADDRESS",
            "127.0.0.1:8087".to_owned(),
        ),
        (
            "ARCHIVIST_STORAGE_ENDPOINT_URL",
            "https://s3.example.invalid".to_owned(),
        ),
        ("ARCHIVIST_STORAGE_REGION", "us-east-1".to_owned()),
        ("ARCHIVIST_STORAGE_ENCRYPTION", "s3_sse".to_owned()),
        ("ARCHIVIST_STORAGE_RAW_BUCKET", "raw-bucket".to_owned()),
        (
            "ARCHIVIST_STORAGE_CONTROL_BUCKET",
            "control-bucket".to_owned(),
        ),
        ("ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF", raw),
        ("ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF", control),
        ("ARCHIVIST_STORAGE_CATALOG_WRITE_CREDENTIALS_REF", catalog),
        ("ARCHIVIST_STORAGE_DERIVED_WRITE_CREDENTIALS_REF", derived),
        (
            "ARCHIVIST_STORAGE_TENANT_BUCKET",
            "tenant-bucket".to_owned(),
        ),
        ("ARCHIVIST_STORAGE_TENANT", TENANT.to_owned()),
    ]
}

// ---------------------------------------------------------------------------
// Role-separated rebuild seam.
// ---------------------------------------------------------------------------

struct FixtureStore {
    audit: FakeAudit,
    catalog: FakeCatalog,
    derived: FakeDerived,
}

impl FixtureStore {
    fn new(tenant: &TenantId) -> Self {
        let fixture = fixture(tenant);
        let mut raw = BTreeMap::new();
        raw.insert(
            fixture.occurrence_key.as_str().to_owned(),
            fixture.occurrence,
        );
        raw.insert(
            fixture.attestation_key.as_str().to_owned(),
            fixture.attestation,
        );
        raw.insert(fixture.blob_key.as_str().to_owned(), fixture.blob);
        let entries = raw
            .iter()
            .map(|(key, bytes)| {
                InventoryEntry::new(
                    InventoryKey::parse(key).expect("fixture inventory key"),
                    bytes.len() as u64,
                    Observation::new(None, None, observed_at()),
                )
            })
            .collect();
        let scope = InventoryScope::TenantRaw(tenant.clone());
        let inventory =
            FrozenInventory::from_pages(&scope, vec![Ok(InventoryPage::new(entries, None))])
                .expect("fixture inventory freezes");
        let checkpoints = Arc::new(Mutex::new(BTreeMap::new()));
        let derived = Arc::new(Mutex::new(BTreeMap::new()));
        Self {
            audit: FakeAudit {
                raw: Arc::new(Mutex::new(raw)),
                checkpoints: Arc::clone(&checkpoints),
                inventory,
                checkpoint_reads: Arc::new(AtomicUsize::new(0)),
            },
            catalog: FakeCatalog {
                objects: checkpoints,
                puts: Arc::new(AtomicUsize::new(0)),
                lists: Arc::new(AtomicUsize::new(0)),
            },
            derived: FakeDerived {
                objects: derived,
                puts: Arc::new(AtomicUsize::new(0)),
            },
        }
    }
}

struct FakeAudit {
    raw: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    checkpoints: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    inventory: FrozenInventory,
    checkpoint_reads: Arc<AtomicUsize>,
}

impl FakeAudit {
    fn object(&self, key: &InventoryKey) -> Option<Vec<u8>> {
        self.raw
            .lock()
            .expect("audit raw lock")
            .get(key.as_str())
            .cloned()
            .or_else(|| {
                self.checkpoints
                    .lock()
                    .expect("audit checkpoint lock")
                    .get(key.as_str())
                    .cloned()
            })
    }

    fn checkpoint_reads(&self) -> usize {
        self.checkpoint_reads.load(Ordering::Relaxed)
    }
}

impl AuditRestoreStore for FakeAudit {
    fn list_page(
        &self,
        _scope: &InventoryScope,
        _after: Option<&ContinuationToken>,
    ) -> impl Future<Output = Result<InventoryPage, StorageError>> + Send {
        async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
    }

    fn freeze_inventory(
        &self,
        _scope: &InventoryScope,
    ) -> impl Future<Output = Result<FrozenInventory, StorageError>> + Send {
        let inventory = self.inventory.clone();
        async move { Ok(inventory) }
    }

    fn inspect_object(
        &self,
        key: &InventoryKey,
    ) -> impl Future<Output = Result<ObjectMetadata, StorageError>> + Send {
        let object = self.object(key);
        async move {
            object
                .map(|bytes| {
                    ObjectMetadata::new(
                        bytes.len() as u64,
                        Observation::new(None, None, observed_at()),
                    )
                })
                .ok_or_else(|| StorageError::of_kind(StorageErrorKind::Unavailable))
        }
    }

    fn read_object(
        &self,
        key: &InventoryKey,
    ) -> impl Future<Output = Result<ObjectBody, StorageError>> + Send {
        let is_checkpoint = key.as_str().contains("/v1/catalog/");
        if is_checkpoint {
            self.checkpoint_reads.fetch_add(1, Ordering::Relaxed);
        }
        let object = self.object(key);
        async move {
            object
                .map(|bytes| ObjectBody::new(bytes, Observation::new(None, None, observed_at())))
                .ok_or_else(|| StorageError::of_kind(StorageErrorKind::Unavailable))
        }
    }
}

struct FakeCatalog {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    puts: Arc<AtomicUsize>,
    lists: Arc<AtomicUsize>,
}

impl FakeCatalog {
    fn put_count(&self) -> usize {
        self.puts.load(Ordering::Relaxed)
    }

    fn list_count(&self) -> usize {
        self.lists.load(Ordering::Relaxed)
    }

    fn keys(&self) -> Vec<String> {
        self.objects
            .lock()
            .expect("catalog lock")
            .keys()
            .cloned()
            .collect()
    }

    fn bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.lock().expect("catalog lock").get(key).cloned()
    }
}

impl CatalogWriteStore for FakeCatalog {
    fn put_checkpoint(
        &self,
        key: &CatalogCheckpointKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.puts.fetch_add(1, Ordering::Relaxed);
        self.objects
            .lock()
            .expect("catalog lock")
            .insert(key.as_str().to_owned(), bytes.to_vec());
        async { Ok(()) }
    }

    fn list_checkpoints(
        &self,
        _prefix: &CatalogListPrefix,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send {
        self.lists.fetch_add(1, Ordering::Relaxed);
        let keys = self.keys();
        async move { Ok(keys) }
    }
}

struct FakeDerived {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    puts: Arc<AtomicUsize>,
}

impl FakeDerived {
    fn put_count(&self) -> usize {
        self.puts.load(Ordering::Relaxed)
    }

    fn keys(&self) -> Vec<String> {
        self.objects
            .lock()
            .expect("derived lock")
            .keys()
            .cloned()
            .collect()
    }

    fn bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.lock().expect("derived lock").get(key).cloned()
    }
}

impl DerivedWriteStore for FakeDerived {
    fn put_object(
        &self,
        key: &DerivedObjectKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.puts.fetch_add(1, Ordering::Relaxed);
        self.objects
            .lock()
            .expect("derived lock")
            .insert(key.as_str().to_owned(), bytes.to_vec());
        async { Ok(()) }
    }

    fn list_objects(
        &self,
        _prefix: &DerivedListPrefix,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send {
        let keys = self.keys();
        async move { Ok(keys) }
    }
}

static STORE: OnceLock<Arc<FixtureStore>> = OnceLock::new();

fn store() -> Arc<FixtureStore> {
    STORE
        .get_or_init(|| Arc::new(FixtureStore::new(&tenant())))
        .clone()
}

// ---------------------------------------------------------------------------
// A real raw occurrence, attestation, and zstd-v1 blob.
// ---------------------------------------------------------------------------

struct Fixture {
    occurrence_key: OccurrenceObjectKey,
    occurrence: Vec<u8>,
    attestation_key: AttestationObjectKey,
    attestation: Vec<u8>,
    blob_key: BlobObjectKey,
    blob: Vec<u8>,
}

fn fixture(tenant: &TenantId) -> Fixture {
    let occurrence_template = bundle_doc("occurrences/direct-upload-and-relay-source.json");
    let attestation_template = bundle_doc("attestations/origin-direct-first-request.json");
    let plaintext = payload();
    let mut encoder = ZstdV1Encoder::new(plaintext.len() as u64).expect("zstd encoder");
    let mut blob = Vec::new();
    encoder.update(&plaintext, &mut blob).expect("zstd update");
    encoder.finish(&mut blob).expect("zstd finish");
    let digest = blob_digest(&plaintext);

    let client = ClientId::parse(text_member(&occurrence_template, "origin_client_id"))
        .expect("fixture client");
    let harness =
        HarnessId::parse(text_member(&occurrence_template, "harness")).expect("fixture harness");
    let session = session_hash(
        tenant,
        &client,
        &harness,
        text_member(&occurrence_template, "upstream_session_id"),
    );
    let artifact_kind = ArtifactKind::parse(text_member(&occurrence_template, "artifact_kind"))
        .expect("fixture artifact kind");
    let adapter =
        AdapterId::parse(text_member(&occurrence_template, "adapter_id")).expect("fixture adapter");
    let projection = VersionToken::parse(text_member(
        &occurrence_template,
        "adapter_projection_version",
    ))
    .expect("fixture projection");
    let artifact = artifact_hash(
        &session,
        artifact_kind,
        &adapter,
        &projection,
        text_member(&occurrence_template, "adapter_artifact_id"),
    );
    let generation = GenerationId::parse(text_member(&occurrence_template, "generation"))
        .expect("fixture generation");
    let range_kind = RangeKind::parse(text_member(&occurrence_template, "range_kind"))
        .expect("fixture range kind");
    let occurrence = occurrence_id(
        &session,
        &artifact,
        &generation,
        range_kind,
        0,
        plaintext.len() as u64,
        &digest,
    );
    let occurrence_key = OccurrenceObjectKey::new(tenant, &client, &harness, &session, &occurrence);
    let blob_key = BlobObjectKey::new(tenant, StorageProfile::ZstdV1, &digest);

    let mut occurrence_document = occurrence_template;
    occurrence_document.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    occurrence_document.set("session_hash", Value::Text(session.to_hex()));
    occurrence_document.set("artifact_hash", Value::Text(artifact.to_hex()));
    occurrence_document.set("blob_digest", Value::Text(digest.to_hex()));
    occurrence_document.set(
        "range_end",
        Value::Int(i64::try_from(plaintext.len()).expect("fixture payload fits i64")),
    );
    occurrence_document.set("occurrence_id", Value::Text(occurrence.to_hex()));

    let uploader = ClientId::parse(text_member(&attestation_template, "uploader_client_id"))
        .expect("fixture uploader");
    let request = RequestId::parse(text_member(&attestation_template, "request_id"))
        .expect("fixture request");
    let attestation = attestation_id(&occurrence, &uploader, &request);
    let mut attestation_document = attestation_template;
    attestation_document.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    attestation_document.set("occurrence_id", Value::Text(occurrence.to_hex()));
    attestation_document.set("attestation_id", Value::Text(attestation.to_hex()));

    Fixture {
        occurrence_key,
        occurrence: render(&occurrence_document),
        attestation_key: AttestationObjectKey::new(tenant, &occurrence, &attestation),
        attestation: render(&attestation_document),
        blob_key,
        blob,
    }
}

fn bundle_doc(relative: &str) -> Object {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/v1/examples/provenance");
    let bytes = std::fs::read(root.join(relative)).expect("committed provenance fixture");
    match json::parse(&bytes).expect("provenance JSON") {
        Value::Object(object) => object,
        _ => panic!("provenance fixture is an object"),
    }
}

fn text_member<'a>(object: &'a Object, name: &str) -> &'a str {
    match object.get(name) {
        Some(Value::Text(value)) => value,
        other => panic!("fixture member {name} is text, got {other:?}"),
    }
}

fn render(object: &Object) -> Vec<u8> {
    let mut bytes = Value::Object(object.clone()).canonical_bytes();
    bytes.push(b'\n');
    bytes
}

fn payload() -> Vec<u8> {
    let line = format!(
        r#"{{"type":"assistant","message":{{"model":"claude-sonnet-4","usage":{{"input_tokens":11,"output_tokens":7,"cache_read_input_tokens":3,"cache_creation":{{"ephemeral_5m_input_tokens":5,"ephemeral_1h_input_tokens":0}},"reasoning_tokens":0}},"content":[{{"text":""}}]}},"note":"{WITNESS}"}}"#
    );
    let mut bytes = line.into_bytes();
    bytes.push(b'\n');
    bytes
}

fn observed_at() -> Timestamp {
    Timestamp::parse(OBSERVED_AT).expect("observation timestamp")
}
