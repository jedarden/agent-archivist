// SPDX-License-Identifier: Apache-2.0

//! End-to-end guards for the Phase 10 scoped writers' permission scope
//! (plan Section 7.5; the ARMOR provisioning's catalog-writer and
//! derived-writer identities).
//!
//! The boundary is one statement made by three surfaces, and every test
//! here walks at least two of them together over the public API alone:
//!
//! - the **configuration surface** — [`CatalogWriterConfig`] and
//!   [`DerivedWriterConfig`], each validated fail-closed from its tier
//!   strings the way a deployment assembles them, each naming exactly
//!   one credential reference;
//! - the **store** — [`S3CatalogWriteStore`] and
//!   [`S3DerivedWriteStore`], which accept only validated keys of their
//!   own namespace and re-check the provisioned scope before any
//!   request is issued;
//! - the **permission scope** — the backend policy for each writer
//!   credential: put and list below its own namespace
//!   (`tenants/<tenant>/v1/catalog/` or `…/v1/derived/`), and every
//!   other prefix — raw, control, the other writer's namespace, every
//!   other tenant's prefix — denied.
//!
//! The action boundary is the traits' own shape and is therefore
//! compile-time: neither [`CatalogWriteBackend`] nor
//! [`DerivedWriteBackend`] offers a read, delete, abort, or
//! bucket-level method, so no test can exercise one and no caller can
//! reach around the store to something the credential never held. What
//! the tests here pin is the prefix half of the same statement: that
//! every request the write paths issue stays inside the provisioned
//! namespace, that the raw and control prefixes are unreachable through
//! these writers at every layer (the key grammars refuse to parse them,
//! the scope predicates refuse to admit them, the stores refuse them
//! without issuing a request, and the edge policy refuses them even if
//! handed one directly), and that the write paths land the real derived
//! artifacts — the usage-summary projection at the protocol's own
//! derived address, and a deterministic catalog checkpoint at its
//! digest-derived address.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use archivist_protocol::sha256::{digest, encode_hex};
use archivist_protocol::usage_summary::{
    MessageUsage, OccurrenceProvenance, SourceUsageCounts, UsageRegion, UsageSummary,
};
use archivist_protocol::vocabulary::{AdapterId, OccurrenceId, TenantId, VersionToken};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::scoped_write::{
    CatalogCheckpointKey, CatalogListPrefix, CatalogWriteStore, DerivedListPrefix,
    DerivedObjectKey, DerivedWriteStore,
};
use archivist_storage_s3::config::{
    ControlAdminConfig, ControlAdminConfigBuilder, EncryptionPolicy, S3ConfigErrorKind,
    S3StorageConfigBuilder,
};
use archivist_storage_s3::scoped_write::{
    CatalogWriteBackend, CatalogWriterConfig, CatalogWriterConfigBuilder, DerivedWriteBackend,
    DerivedWriterConfig, DerivedWriterConfigBuilder, S3CatalogWriteStore, S3DerivedWriteStore,
};

// The golden identifiers shared with the sibling boundary suites, so
// every layer of this boundary tells one story.
const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";

const ENDPOINT: &str = "https://s3.example.invalid";
const REGION: &str = "us-east-1";
const TENANT_BUCKET: &str = "archivist-tenant-example";
const RAW_BUCKET: &str = "archivist-raw-example";
const CONTROL_BUCKET: &str = "archivist-control-example";

const CATALOG_REF: &str = "file:/etc/archivist/storage/catalog-writer-credentials";
const DERIVED_REF: &str = "file:/etc/archivist/storage/derived-writer-credentials";
const ADMIN_REF: &str = "file:/etc/archivist/storage/control-admin-credentials";
const RAW_WRITE_REF: &str = "file:/etc/archivist/storage/raw-write-credentials";
const CONTROL_READ_REF: &str = "file:/etc/archivist/storage/control-read-credentials";

fn tenant() -> TenantId {
    TENANT.parse().unwrap()
}

fn other_tenant() -> TenantId {
    OTHER_TENANT.parse().unwrap()
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    // A no-dependency executor for futures that complete without pending
    // (the same helper the store tests use).
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(output) => return output,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn catalog_config() -> CatalogWriterConfig {
    CatalogWriterConfigBuilder::default()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .tenant_bucket(TENANT_BUCKET)
        .tenant(TENANT)
        .catalog_write_credentials(CATALOG_REF)
        .build()
        .unwrap()
}

fn derived_config() -> DerivedWriterConfig {
    DerivedWriterConfigBuilder::default()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .tenant_bucket(TENANT_BUCKET)
        .tenant(TENANT)
        .derived_write_credentials(DERIVED_REF)
        .build()
        .unwrap()
}

fn ingest_config() -> archivist_storage_s3::config::S3StorageConfig {
    S3StorageConfigBuilder::default()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .encryption(EncryptionPolicy::S3Sse)
        .raw_bucket(RAW_BUCKET)
        .control_bucket(CONTROL_BUCKET)
        .raw_write_credentials(RAW_WRITE_REF)
        .control_read_credentials(CONTROL_READ_REF)
        .build()
        .unwrap()
}

fn admin_config() -> ControlAdminConfig {
    ControlAdminConfigBuilder::default()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .control_bucket(CONTROL_BUCKET)
        .tenant(TENANT)
        .control_admin_credentials(ADMIN_REF)
        .build()
        .unwrap()
}

/// The per-request counters, so a test can prove a refused call never
/// issued one and an exercised path issued exactly the two verbs the
/// provisioning grants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counters {
    puts: u32,
    lists: u32,
    refused_puts: u32,
    refused_lists: u32,
}

/// The in-memory backend: an object map and the two prefix grants the
/// deployment's writer credentials state — the ARMOR edge's own policy
/// shape, a literal string-prefix rule per credential, put and list
/// below the granted prefix and deny everything else.
#[derive(Clone)]
struct MapBackend {
    catalog_grant: String,
    derived_grant: String,
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    counters: Arc<Mutex<Counters>>,
}

impl MapBackend {
    fn new() -> Self {
        Self {
            catalog_grant: format!("tenants/{TENANT}/v1/catalog/"),
            derived_grant: format!("tenants/{TENANT}/v1/derived/"),
            objects: Arc::new(Mutex::new(BTreeMap::new())),
            counters: Arc::new(Mutex::new(Counters::default())),
        }
    }

    /// The deployment policy for the catalog-writer credential, as a
    /// grant predicate over one raw string.
    fn catalog_policy_permits(&self, text: &str) -> bool {
        text.starts_with(&self.catalog_grant)
    }

    /// The deployment policy for the derived-writer credential, as a
    /// grant predicate over one raw string.
    fn derived_policy_permits(&self, text: &str) -> bool {
        text.starts_with(&self.derived_grant)
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

    fn refuse(detail: &'static str) -> StorageError {
        StorageError::new(StorageErrorKind::ScopeViolation, detail)
    }

    fn put_under_grant(&self, grant_ok: bool, key: &str, bytes: &[u8]) -> Result<(), StorageError> {
        let mut counters = self.counters.lock().expect("test backend lock");
        if !grant_ok {
            counters.refused_puts += 1;
            return Err(Self::refuse("key is outside this writer identity"));
        }
        self.objects
            .lock()
            .expect("test backend lock")
            .insert(key.to_owned(), bytes.to_vec());
        counters.puts += 1;
        Ok(())
    }

    fn list_under_grant(&self, grant_ok: bool, prefix: &str) -> Result<Vec<String>, StorageError> {
        let mut counters = self.counters.lock().expect("test backend lock");
        if !grant_ok {
            counters.refused_lists += 1;
            return Err(Self::refuse("list prefix is outside this writer identity"));
        }
        let keys = self
            .objects
            .lock()
            .expect("test backend lock")
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        counters.lists += 1;
        Ok(keys)
    }
}

impl CatalogWriteBackend for MapBackend {
    async fn put_catalog_object(
        &self,
        key: &CatalogCheckpointKey,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let ok = self.catalog_policy_permits(key.as_str());
        self.put_under_grant(ok, key.as_str(), bytes)
    }

    async fn list_catalog_objects(
        &self,
        prefix: &CatalogListPrefix,
    ) -> Result<Vec<String>, StorageError> {
        let ok = self.catalog_policy_permits(prefix.as_str());
        self.list_under_grant(ok, prefix.as_str())
    }
}

impl DerivedWriteBackend for MapBackend {
    async fn put_derived_object(
        &self,
        key: &DerivedObjectKey,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let ok = self.derived_policy_permits(key.as_str());
        self.put_under_grant(ok, key.as_str(), bytes)
    }

    async fn list_derived_objects(
        &self,
        prefix: &DerivedListPrefix,
    ) -> Result<Vec<String>, StorageError> {
        let ok = self.derived_policy_permits(prefix.as_str());
        self.list_under_grant(ok, prefix.as_str())
    }
}

/// Canonical checkpoint bytes: the deterministic rebuild's output for
/// one raw prefix, whatever document shape a later catalog slice pins.
fn checkpoint_bytes(seed: u8) -> Vec<u8> {
    format!("{{\"checkpoints\":[\"occurrence-{seed:03}\"],\"seed\":{seed}}}\n").into_bytes()
}

fn checkpoint_key(bytes: &[u8]) -> CatalogCheckpointKey {
    let digest =
        archivist_protocol::vocabulary::BlobDigest::parse(&encode_hex(&digest(bytes))).unwrap();
    CatalogCheckpointKey::new(&tenant(), &digest)
}

fn usage_summary() -> UsageSummary {
    let provenance = OccurrenceProvenance {
        tenant_id: tenant(),
        adapter_id: AdapterId::parse("claude-code").unwrap(),
        adapter_projection_version: VersionToken::parse("1").unwrap(),
        occurrence_id: OccurrenceId::parse(&encode_hex(&digest(b"occurrence"))).unwrap(),
    };
    let messages = [MessageUsage {
        model_id: Some("glm-5.3".to_owned()),
        service_tier: None,
        region: UsageRegion::Measured(SourceUsageCounts {
            input_tokens: 1200,
            output_tokens: 340,
            cache_read_tokens: 56_000,
            cache_creation_5m: 0,
            cache_creation_1h: 0,
            reasoning_tokens: 90,
        }),
    }];
    UsageSummary::derive(&provenance, &messages)
}

/// The boundary's strongest form: a raw or control key does not parse
/// as a scoped-writer key at all, so no store method can accept one —
/// the namespace lives in the key grammar, not in a runtime check a
/// caller could bypass.
#[test]
fn raw_and_control_keys_do_not_parse_as_scoped_writer_keys() {
    let tenant = tenant();
    let raw_blob = format!(
        "tenants/{tenant}/v1/raw/blobs/01/{}.zst",
        encode_hex(&digest(b"blob"))
    );
    let occurrence = format!(
        "tenants/{tenant}/v1/raw/occurrences/{}.json",
        encode_hex(&digest(b"occ"))
    );
    let attestation = format!(
        "tenants/{tenant}/v1/raw/attestations/{}.json",
        encode_hex(&digest(b"att"))
    );
    let control_key = format!("tenants/{tenant}/v1/control/clients/{CLIENT}.json");

    for foreign in [&raw_blob, &occurrence, &attestation, &control_key] {
        assert!(
            CatalogCheckpointKey::parse(foreign).is_err(),
            "a checkpoint key must not parse: {foreign}"
        );
        assert!(
            DerivedObjectKey::parse(foreign).is_err(),
            "a derived key must not parse: {foreign}"
        );
    }

    // And the reverse holds for the writers' own layouts: the protocol's
    // real usage-summary address parses as the derived key it is.
    let usage_key = usage_summary().object_key();
    assert_eq!(
        DerivedObjectKey::parse(&usage_key).unwrap().as_str(),
        usage_key
    );
    let checkpoint = checkpoint_key(&checkpoint_bytes(1));
    assert_eq!(
        CatalogCheckpointKey::parse(checkpoint.as_str())
            .unwrap()
            .as_str(),
        checkpoint.as_str()
    );
}

/// The write path integration: the deterministic catalog rebuild's
/// checkpoint lands at its digest-derived address, replays converge,
/// and the namespace enumerates back exactly what was appended.
#[test]
fn catalog_write_path_appends_and_enumerates_checkpoints() {
    let backend = MapBackend::new();
    let store = S3CatalogWriteStore::new(catalog_config(), backend.clone());

    let first = checkpoint_key(&checkpoint_bytes(1));
    let second = checkpoint_key(&checkpoint_bytes(2));
    block_on(store.put_checkpoint(&first, &checkpoint_bytes(1))).unwrap();
    block_on(store.put_checkpoint(&second, &checkpoint_bytes(2))).unwrap();
    // The rebuild is deterministic: a replay of the same bytes at the
    // same derived key converges on the same object.
    block_on(store.put_checkpoint(&first, &checkpoint_bytes(1))).unwrap();

    assert_eq!(backend.stored(first.as_str()), Some(checkpoint_bytes(1)));
    assert_eq!(backend.stored(second.as_str()), Some(checkpoint_bytes(2)));

    let listed = block_on(store.list_checkpoints(&CatalogListPrefix::root(&tenant()))).unwrap();
    let mut expected = vec![first.as_str().to_owned(), second.as_str().to_owned()];
    expected.sort_unstable();
    assert_eq!(listed, expected);

    // The exercised verbs are exactly the two the credential grants:
    // three puts, one list, nothing refused.
    assert_eq!(
        backend.counters(),
        Counters {
            puts: 3,
            lists: 1,
            refused_puts: 0,
            refused_lists: 0,
        }
    );
}

/// The write path integration on the derived side: the usage-summary
/// producer's record lands at the protocol's own derived address — the
/// record's `object_key()` and the store's key derivation are the same
/// statement — and the namespace enumerates it back.
#[test]
fn derived_write_path_lands_the_usage_summary_projection() {
    let backend = MapBackend::new();
    let store = S3DerivedWriteStore::new(derived_config(), backend.clone());

    let summary = usage_summary();
    let key = DerivedObjectKey::parse(&summary.object_key()).unwrap();
    block_on(store.put_object(&key, &summary.serialized())).unwrap();

    assert_eq!(backend.stored(key.as_str()), Some(summary.serialized()));
    let listed = block_on(store.list_objects(&DerivedListPrefix::root(&tenant()))).unwrap();
    assert_eq!(listed, vec![key.as_str().to_owned()]);

    assert_eq!(
        backend.counters(),
        Counters {
            puts: 1,
            lists: 1,
            refused_puts: 0,
            refused_lists: 0,
        }
    );
}

/// The rejection half of the boundary, store layer: a key or prefix of
/// another tenant — valid under its own grammar — is refused with a
/// scope violation before any request is issued.
#[test]
fn stores_refuse_foreign_tenants_without_issuing_a_request() {
    let backend = MapBackend::new();
    let catalog = S3CatalogWriteStore::new(catalog_config(), backend.clone());
    let derived = S3DerivedWriteStore::new(derived_config(), backend.clone());
    let other = other_tenant();

    let foreign_checkpoint = CatalogCheckpointKey::new(
        &other,
        &checkpoint_key(&checkpoint_bytes(1)).checkpoint().clone(),
    );
    let error = block_on(catalog.put_checkpoint(&foreign_checkpoint, b"bytes")).unwrap_err();
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);

    let error = block_on(catalog.list_checkpoints(&CatalogListPrefix::root(&other))).unwrap_err();
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);

    let foreign_projection =
        DerivedObjectKey::new(&other, "usage", "1", "usage-summaries/ab/x.json").unwrap();
    let error = block_on(derived.put_object(&foreign_projection, b"bytes")).unwrap_err();
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);

    let error = block_on(derived.list_objects(&DerivedListPrefix::root(&other))).unwrap_err();
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);

    // Nothing was issued — not even a request the edge would refuse.
    assert_eq!(backend.counters(), Counters::default());
}

/// The rejection half, edge layer: the deployment's own grant shape —
/// the literal string-prefix rule an ACL evaluates — refuses the raw
/// and control prefixes for both writer credentials, and each writer's
/// grant excludes the other writer's namespace.
#[test]
fn the_edge_policy_denies_the_raw_and_control_prefixes() {
    let backend = MapBackend::new();
    let tenant = tenant();

    let raw_blob = format!(
        "tenants/{tenant}/v1/raw/blobs/01/{}.zst",
        encode_hex(&digest(b"blob"))
    );
    let control_key = format!("tenants/{tenant}/v1/control/clients/{CLIENT}.json");
    let raw_root = format!("tenants/{tenant}/v1/raw/");
    let control_root = format!("tenants/{tenant}/v1/control/");
    let foreign_catalog_root = CatalogCheckpointKey::prefix(&other_tenant());
    let checkpoint = checkpoint_key(&checkpoint_bytes(3)).as_str().to_owned();
    let usage_key = usage_summary().object_key();

    for out_of_scope in [
        raw_blob.as_str(),
        control_key.as_str(),
        raw_root.as_str(),
        control_root.as_str(),
        foreign_catalog_root.as_str(),
        "",
    ] {
        assert!(
            !backend.catalog_policy_permits(out_of_scope),
            "catalog grant must refuse: {out_of_scope}"
        );
        assert!(
            !backend.derived_policy_permits(out_of_scope),
            "derived grant must refuse: {out_of_scope}"
        );
    }
    // Each grant admits its own namespace and not the other's.
    assert!(backend.catalog_policy_permits(&checkpoint));
    assert!(!backend.catalog_policy_permits(&usage_key));
    assert!(backend.derived_policy_permits(&usage_key));
    assert!(!backend.derived_policy_permits(&checkpoint));
}

/// The configuration's own scope predicates — the raw-string model of
/// each credential's provisioned prefix — admit exactly the namespace
/// the edge grants and deny the raw and control prefixes, the other
/// writer's namespace, and every other tenant.
#[test]
fn scope_predicates_admit_exactly_the_provisioned_namespaces() {
    let catalog = catalog_config();
    let derived = derived_config();
    let tenant = tenant();

    let checkpoint = checkpoint_key(&checkpoint_bytes(5));
    let usage_key = usage_summary().object_key();
    assert!(catalog.permits_key(checkpoint.as_str()));
    assert!(derived.permits_key(&usage_key));
    assert!(catalog.permits_list_prefix(&CatalogCheckpointKey::prefix(&tenant)));
    assert!(derived.permits_list_prefix(&DerivedObjectKey::prefix(&tenant)));

    let raw_blob = format!(
        "tenants/{tenant}/v1/raw/blobs/01/{}.zst",
        encode_hex(&digest(b"blob"))
    );
    let control_key = format!("tenants/{tenant}/v1/control/clients/{CLIENT}.json");
    let raw_root = format!("tenants/{tenant}/v1/raw/");
    let control_root = format!("tenants/{tenant}/v1/control/");
    for denied in [
        raw_blob.as_str(),
        control_key.as_str(),
        raw_root.as_str(),
        control_root.as_str(),
    ] {
        assert!(!catalog.permits_key(denied), "catalog: {denied}");
        assert!(!derived.permits_key(denied), "derived: {denied}");
        assert!(!catalog.permits_list_prefix(denied), "catalog: {denied}");
        assert!(!derived.permits_list_prefix(denied), "derived: {denied}");
    }
    assert!(!catalog.permits_key(&usage_key));
    assert!(!derived.permits_key(checkpoint.as_str()));
}

/// The identity split, configuration layer: the writer credentials are
/// never an ingest role, never the offline control-administration
/// credential, and never each other — the joint checks refuse every
/// reuse shape, and the honest deployment passes both.
#[test]
fn writer_credentials_stay_disjoint_from_every_other_identity() {
    let ingest = ingest_config();
    let admin = admin_config();
    let catalog = catalog_config();
    let derived = derived_config();

    catalog
        .reject_shared_credential(&ingest, &admin, &derived)
        .unwrap();
    derived
        .reject_shared_credential(&ingest, &admin, &catalog)
        .unwrap();

    let catalog_as_ingest = CatalogWriterConfigBuilder::default()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .tenant_bucket(TENANT_BUCKET)
        .tenant(TENANT)
        .catalog_write_credentials(RAW_WRITE_REF)
        .build()
        .unwrap();
    let error = catalog_as_ingest
        .reject_shared_credential(&ingest, &admin, &derived)
        .unwrap_err();
    assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);

    let derived_as_catalog = DerivedWriterConfigBuilder::default()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .tenant_bucket(TENANT_BUCKET)
        .tenant(TENANT)
        .derived_write_credentials(CATALOG_REF)
        .build()
        .unwrap();
    let error = catalog
        .reject_shared_credential(&ingest, &admin, &derived_as_catalog)
        .unwrap_err();
    assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
}

/// The configuration gate: a missing setting, a malformed setting, and
/// a transport contradiction each fail closed with their own decision,
/// never echoing the offending value.
#[test]
fn writer_configuration_validates_fail_closed() {
    let error = CatalogWriterConfigBuilder::default().build().unwrap_err();
    assert_eq!(error.kind(), S3ConfigErrorKind::MissingSetting);

    let error = CatalogWriterConfigBuilder::default()
        .endpoint_url("http://s3.example.invalid")
        .region(REGION)
        .tenant_bucket(TENANT_BUCKET)
        .tenant(TENANT)
        .catalog_write_credentials(CATALOG_REF)
        .build()
        .unwrap_err();
    assert_eq!(error.kind(), S3ConfigErrorKind::TransportMismatch);

    let error = DerivedWriterConfigBuilder::default()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .tenant_bucket(TENANT_BUCKET)
        .tenant("not-a-uuid")
        .derived_write_credentials(DERIVED_REF)
        .build()
        .unwrap_err();
    assert_eq!(error.kind(), S3ConfigErrorKind::MalformedSetting);
}
