// SPDX-License-Identifier: Apache-2.0

//! The versioned Parquet inventory's end-to-end build proofs (plan Phase
//! 10: "Produce versioned Parquet inventories"): the public
//! [`inventory_build`] API driven over the same mock identities the
//! catalog rebuild engine's own tests use — real committed occurrences
//! with real `zstd-v1` blobs, frozen through the real freeze contract,
//! read back through the real raw catalog source.
//!
//! The suite is the bead's acceptance criteria, one test each:
//!
//! - **reproducible** — two builds of one frozen prefix emit the same
//!   keys with byte-identical objects, and a retry over a store that
//!   already carries the objects converges on the identical files
//!   instead of diverging from them;
//! - **one view with the rebuild** — the inventory's chain digest and
//!   denominator tally equal the catalog rebuild's own for the same
//!   prefix and projection, and every partition shard is the digest
//!   prefix of a row the rebuild itself wrote — the two pipelines
//!   cannot disagree because the inventory is a projection of the
//!   derived rows, never a second reading of the raw bytes;
//! - **tenant-isolated** — every emitted key sits inside the building
//!   tenant's own derived namespace, and two tenants' builds share no
//!   key even through one shared writer;
//! - **never overwriting another version** — a later source version
//!   writes its own source-digest directory and leaves the earlier
//!   build's files byte-identical where they stand;
//! - **`unknown`, never zero** — the manifest's denominator tally
//!   carries absent and malformed sources as their bounded states (the
//!   cell-level proof — no count column beside an `unknown` state — is
//!   the module's own unit suite);
//! - **content-free** — no transcript text reaches any emitted byte,
//!   while the model identity the projection is allowed to carry does;
//! - **the manifest is the completeness statement** — an empty prefix
//!   still emits one, and a build whose manifest put fails leaves an
//!   incomplete directory behind, never an authoritative partition set.

#![allow(clippy::manual_async_fn, clippy::type_complexity)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;

use archivist_protocol::derivation::{
    artifact_hash, attestation_id, blob_digest, occurrence_id, session_hash,
};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::usage_summary::{MessageUsage, SourceUsageCounts, UsageRegion};
use archivist_protocol::vocabulary::{
    AdapterId, ArtifactKind, ClientId, GenerationId, HarnessId, RangeKind, RequestId,
    StorageProfile, TenantId, Timestamp, VersionToken,
};

use archivist_storage::audit_restore::{
    AuditRestoreStore, ContinuationToken, FrozenInventory, InventoryEntry, InventoryKey,
    InventoryPage, InventoryScope, ObjectBody, ObjectMetadata,
};
use archivist_storage::blob::BlobEncoder;
use archivist_storage::catalog_inventory::{
    INVENTORY_PIPELINE_ID, INVENTORY_PIPELINE_VERSION, inventory_build,
};
use archivist_storage::catalog_rebuild::{RebuildPolicy, UsageProjection, rebuild_pass};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::metadata::Observation;
use archivist_storage::scoped_write::{
    CatalogCheckpointKey, CatalogListPrefix, CatalogWriteStore, DerivedListPrefix,
    DerivedObjectKey, DerivedWriteStore,
};
use archivist_storage::zstd_v1::ZstdV1Encoder;

/// When the fixtures were observed (arbitrary, fixture-only).
const OBSERVED: &str = "2026-09-13T12:00:00Z";
/// The test projection's immutable reader version.
const PROJECTION_VERSION: &str = "usage-fixture-1";
/// The conformance corpus's tenant (the provenance bundle's own).
const TENANT_A: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
/// A second tenant, grammatical and distinct, for the isolation proof.
const TENANT_B: &str = "12345678-1234-4781-8234-123456789abc";

fn tenant_a() -> TenantId {
    TenantId::parse(TENANT_A).unwrap()
}

fn tenant_b() -> TenantId {
    TenantId::parse(TENANT_B).unwrap()
}

fn observed_at() -> Timestamp {
    Timestamp::parse(OBSERVED).unwrap()
}

// ---- The synthetic corpus: real occurrences with real payloads ----

/// A committed bundle document as a member map: the occurrence (or
/// attestation) template every synthetic fixture patches. The
/// provenance members are used as-is — they already validate — while
/// the payload- and tenant-derived members are re-derived per fixture.
fn bundle_doc(rel: &str) -> Object {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/v1/examples/provenance");
    let bytes = std::fs::read(root.join(rel))
        .unwrap_or_else(|e| panic!("committed bundle document {rel}: {e}"));
    match json::parse(&bytes).expect("bundle document parses") {
        Value::Object(object) => object,
        _ => panic!("bundle document is an object"),
    }
}

fn text_member<'a>(object: &'a Object, name: &str) -> &'a str {
    match object.get(name) {
        Some(Value::Text(text)) => text.as_str(),
        other => panic!("template member {name} is a string, got {other:?}"),
    }
}

fn int_member(object: &Object, name: &str) -> i64 {
    match object.get(name) {
        Some(Value::Int(value)) => *value,
        other => panic!("template member {name} is an integer, got {other:?}"),
    }
}

/// Render a document map in canonical form plus exactly one trailing
/// LF — the stored form of every raw object.
fn render(document: &Object) -> Vec<u8> {
    let mut bytes = Value::Object(document.clone()).canonical_bytes();
    bytes.push(b'\n');
    bytes
}

/// One synthetic occurrence's transcript payload: one JSONL line
/// naming its model and (optionally) a usage region, exactly the shape
/// the test projection reads. The `note` marker is the transcript
/// witness the content-free proof searches for: distinctive text that
/// exists only in the raw payload, never in any projection column.
fn payload(note: &str, model: Option<&str>, usage: Option<&str>) -> Vec<u8> {
    let mut line = format!("{{\"note\":\"{note}\",\"role\":\"assistant\"");
    if let Some(model) = model {
        let _ = write!(line, ",\"model_id\":\"{model}\"");
    }
    if let Some(usage) = usage {
        let _ = write!(line, ",\"usage\":{usage}");
    }
    line.push('}');
    let mut bytes = line.into_bytes();
    bytes.push(b'\n');
    bytes
}

/// The test projection's one measured usage shape.
const MEASURED: &str = "{\"input_tokens\":11,\"output_tokens\":7,\
     \"cache_read_input_tokens\":3,\"cache_creation\":{\"\
     ephemeral_5m_input_tokens\":5,\"ephemeral_1h_input_tokens\":0},\
     \"reasoning_tokens\":0}";

/// The corpus's three payload shapes: one measured, one absent, one
/// malformed — the denominator states the manifest must carry.
const NOTE_MEASURED: &str = "transcript-witness-measured";
const NOTE_ABSENT: &str = "transcript-witness-absent";
const NOTE_MALFORMED: &str = "transcript-witness-malformed";

/// A real `zstd-v1` frame over a payload, produced by the codec the
/// stored form is pinned to.
fn stored_frame(plaintext: &[u8]) -> Vec<u8> {
    let mut encoder =
        ZstdV1Encoder::new(u64::try_from(plaintext.len()).expect("fixture under u64"))
            .expect("fixture encoder");
    let mut stored = Vec::new();
    encoder
        .update(plaintext, &mut stored)
        .expect("fixture encode");
    encoder.finish(&mut stored).expect("fixture encode finish");
    stored
}

/// One occurrence's three derived keys and stored documents, with all
/// self-verifying identities re-derived exactly the way the ingest
/// derivations define them — including the tenant-derived session
/// namespace, so a fixture built for any grammatical tenant validates
/// as that tenant's own provenance.
struct Fixture {
    occurrence_key: OccurrenceObjectKey,
    occurrence: Vec<u8>,
    attestation_key: AttestationObjectKey,
    attestation: Vec<u8>,
    blob_key: BlobObjectKey,
    blob: Vec<u8>,
}

/// Build one occurrence fixture over `plaintext` for `tenant`: the
/// payload- and tenant-derived identity members are re-derived from the
/// real bytes and patched into the committed templates; everything else
/// is the bundle's own validated provenance.
fn fixture_from(tenant: &TenantId, note: &str, plaintext: &[u8]) -> Fixture {
    let template = bundle_doc("occurrences/direct-upload-and-relay-source.json");
    let blob = stored_frame(plaintext);
    let digest = blob_digest(plaintext);

    let client = ClientId::parse(text_member(&template, "origin_client_id")).unwrap();
    let harness = HarnessId::parse(text_member(&template, "harness")).unwrap();
    let upstream = text_member(&template, "upstream_session_id");
    let session = session_hash(tenant, &client, &harness, upstream);
    // The artifact identity names the session namespace, so a tenant's
    // own session re-derives its artifact hash — the template's own
    // value holds only for the conformance tenant it was committed for.
    let artifact_kind = ArtifactKind::parse(text_member(&template, "artifact_kind")).unwrap();
    let adapter_id = AdapterId::parse(text_member(&template, "adapter_id")).unwrap();
    let adapter_projection =
        VersionToken::parse(text_member(&template, "adapter_projection_version")).unwrap();
    let adapter_artifact_id = text_member(&template, "adapter_artifact_id");
    let artifact = artifact_hash(
        &session,
        artifact_kind,
        &adapter_id,
        &adapter_projection,
        adapter_artifact_id,
    );
    let generation = GenerationId::parse(text_member(&template, "generation")).unwrap();
    let range_kind = RangeKind::parse(text_member(&template, "range_kind")).unwrap();
    let range_start = u64::try_from(int_member(&template, "range_start")).unwrap();
    let range_end = u64::try_from(plaintext.len()).expect("fixture under u64");

    let occurrence = occurrence_id(
        &session,
        &artifact,
        &generation,
        range_kind,
        range_start,
        range_end,
        &digest,
    );
    let occurrence_key = OccurrenceObjectKey::new(tenant, &client, &harness, &session, &occurrence);
    let blob_key = BlobObjectKey::new(tenant, StorageProfile::ZstdV1, &digest);

    let mut document = template.clone();
    document.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    document.set("session_hash", Value::Text(session.to_hex()));
    document.set("artifact_hash", Value::Text(artifact.to_hex()));
    document.set("blob_digest", Value::Text(digest.to_hex()));
    document.set(
        "range_end",
        Value::Int(i64::try_from(range_end).expect("fixture under i64")),
    );
    document.set("occurrence_id", Value::Text(occurrence.to_hex()));
    let occurrence_bytes = render(&document);

    // One upload attestation per occurrence, re-targeted and re-derived
    // the same way.
    let mut attestation = bundle_doc("attestations/origin-direct-first-request.json");
    let uploader = ClientId::parse(text_member(&attestation, "uploader_client_id")).unwrap();
    let request = RequestId::parse(text_member(&attestation, "request_id")).unwrap();
    let attestation_id = attestation_id(&occurrence, &uploader, &request);
    attestation.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    attestation.set("occurrence_id", Value::Text(occurrence.to_hex()));
    attestation.set("attestation_id", Value::Text(attestation_id.to_hex()));
    let attestation_bytes = render(&attestation);
    let attestation_key = AttestationObjectKey::new(tenant, &occurrence, &attestation_id);

    let _ = note; // the note rides inside the payload bytes only
    Fixture {
        occurrence_key,
        occurrence: occurrence_bytes,
        attestation_key,
        attestation: attestation_bytes,
        blob_key,
        blob,
    }
}

/// A fixture over the one measured payload shape.
fn fixture_measured(tenant: &TenantId) -> Fixture {
    fixture_from(
        tenant,
        NOTE_MEASURED,
        &payload(NOTE_MEASURED, Some("claude-sonnet-4"), Some(MEASURED)),
    )
}

/// A fixture whose payload carries no usage region at all.
fn fixture_absent(tenant: &TenantId) -> Fixture {
    fixture_from(
        tenant,
        NOTE_ABSENT,
        &payload(NOTE_ABSENT, Some("claude-sonnet-4"), None),
    )
}

/// A fixture whose payload carries a present-but-unparseable region.
fn fixture_malformed(tenant: &TenantId) -> Fixture {
    fixture_from(
        tenant,
        NOTE_MALFORMED,
        &payload(
            NOTE_MALFORMED,
            Some("claude-haiku-4"),
            Some("{\"input_tokens\":1}"),
        ),
    )
}

/// The corpus: three occurrences with mixed usage states — one
/// measured, one absent, one malformed.
fn corpus(tenant: &TenantId) -> Vec<Fixture> {
    vec![
        fixture_measured(tenant),
        fixture_absent(tenant),
        fixture_malformed(tenant),
    ]
}

/// The frozen prefix over `fixtures`, frozen through the real freeze
/// contract across two pages.
fn freeze(tenant: &TenantId, fixtures: &[Fixture]) -> FrozenInventory {
    let scope = InventoryScope::TenantRaw(tenant.clone());
    let mut entries: Vec<(&str, u64)> = Vec::new();
    for fixture in fixtures {
        entries.push((
            fixture.occurrence_key.as_str(),
            u64::try_from(fixture.occurrence.len()).unwrap(),
        ));
        entries.push((
            fixture.attestation_key.as_str(),
            u64::try_from(fixture.attestation.len()).unwrap(),
        ));
        entries.push((
            fixture.blob_key.as_str(),
            u64::try_from(fixture.blob.len()).unwrap(),
        ));
    }
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    if entries.is_empty() {
        return FrozenInventory::from_pages(&scope, vec![Ok(InventoryPage::new(Vec::new(), None))])
            .unwrap();
    }
    let page = |slice: &[(&str, u64)], token: Option<&str>| {
        InventoryPage::new(
            slice
                .iter()
                .map(|(key, size)| {
                    InventoryEntry::new(
                        InventoryKey::parse(key).expect("grammatical fixture key"),
                        *size,
                        Observation::new(None, None, observed_at()),
                    )
                })
                .collect(),
            token.map(ContinuationToken::parse).transpose().unwrap(),
        )
    };
    let mid = entries.len().div_ceil(2);
    FrozenInventory::from_pages(
        &scope,
        vec![
            Ok(page(&entries[..mid], Some("next-page"))),
            Ok(page(&entries[mid..], None)),
        ],
    )
    .unwrap()
}

// ---- The mock identities ----

/// A no-dependency in-memory audit/restore store carrying one tenant's
/// frozen inventory and objects — the catalog-rebuild-module mock
/// pattern.
struct MockStore {
    objects: Mutex<HashMap<String, Vec<u8>>>,
    tenant: TenantId,
    inventory: FrozenInventory,
}

impl MockStore {
    fn with(tenant: &TenantId, fixtures: &[Fixture]) -> Self {
        let inventory = freeze(tenant, fixtures);
        let mut objects = HashMap::new();
        for fixture in fixtures {
            objects.insert(
                fixture.occurrence_key.as_str().to_owned(),
                fixture.occurrence.clone(),
            );
            objects.insert(
                fixture.attestation_key.as_str().to_owned(),
                fixture.attestation.clone(),
            );
            objects.insert(fixture.blob_key.as_str().to_owned(), fixture.blob.clone());
        }
        Self {
            objects: Mutex::new(objects),
            tenant: tenant.clone(),
            inventory,
        }
    }

    /// Replace the frozen prefix with a later source version's — the
    /// never-overwrite proof's seam.
    fn refreeze(&mut self, fixtures: &[Fixture]) {
        self.inventory = freeze(&self.tenant, fixtures);
        let mut objects = self.objects.lock().expect("mock lock");
        for fixture in fixtures {
            objects.insert(
                fixture.occurrence_key.as_str().to_owned(),
                fixture.occurrence.clone(),
            );
            objects.insert(
                fixture.attestation_key.as_str().to_owned(),
                fixture.attestation.clone(),
            );
            objects.insert(fixture.blob_key.as_str().to_owned(), fixture.blob.clone());
        }
    }
}

impl AuditRestoreStore for MockStore {
    async fn list_page(
        &self,
        _scope: &InventoryScope,
        _after: Option<&ContinuationToken>,
    ) -> Result<InventoryPage, StorageError> {
        Err(StorageError::of_kind(StorageErrorKind::Unavailable))
    }

    async fn freeze_inventory(
        &self,
        scope: &InventoryScope,
    ) -> Result<FrozenInventory, StorageError> {
        if matches!(scope, InventoryScope::TenantRaw(t) if t == &self.tenant) {
            Ok(self.inventory.clone())
        } else {
            Err(StorageError::of_kind(StorageErrorKind::ScopeViolation))
        }
    }

    async fn inspect_object(&self, key: &InventoryKey) -> Result<ObjectMetadata, StorageError> {
        let objects = self.objects.lock().expect("mock lock");
        match objects.get(key.as_str()) {
            Some(bytes) => Ok(ObjectMetadata::new(
                u64::try_from(bytes.len()).expect("fixture under u64"),
                Observation::new(None, None, observed_at()),
            )),
            None => Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
        }
    }

    async fn read_object(&self, key: &InventoryKey) -> Result<ObjectBody, StorageError> {
        let objects = self.objects.lock().expect("mock lock");
        match objects.get(key.as_str()) {
            Some(bytes) => Ok(ObjectBody::new(
                bytes.clone(),
                Observation::new(None, None, observed_at()),
            )),
            None => Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
        }
    }
}

/// The derived writer's mock: records every put in order — the log the
/// reproducibility proofs compare — and can refuse the manifest put, so
/// a build can fail exactly where completeness would be declared.
#[derive(Default)]
struct MockDerived {
    puts: Mutex<Vec<(String, Vec<u8>)>>,
    refuse_manifest: bool,
}

impl MockDerived {
    fn new() -> Self {
        Self::default()
    }

    fn refusing_the_manifest() -> Self {
        Self {
            refuse_manifest: true,
            ..Self::default()
        }
    }

    fn log(&self) -> Vec<(String, Vec<u8>)> {
        self.puts.lock().expect("mock lock").clone()
    }

    fn bytes_at(&self, key: &str) -> Vec<u8> {
        self.puts
            .lock()
            .expect("mock lock")
            .iter()
            .find(|(put, _)| put == key)
            .map(|(_, bytes)| bytes.clone())
            .unwrap_or_default()
    }
}

impl DerivedWriteStore for MockDerived {
    fn put_object(
        &self,
        key: &DerivedObjectKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        let refused = self.refuse_manifest && key.as_str().ends_with("/manifest.json");
        if !refused {
            self.puts
                .lock()
                .expect("mock lock")
                .push((key.as_str().to_owned(), bytes.to_vec()));
        }
        async move {
            if refused {
                Err(StorageError::of_kind(StorageErrorKind::Unavailable))
            } else {
                Ok(())
            }
        }
    }

    fn list_objects(
        &self,
        _prefix: &DerivedListPrefix,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send {
        async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
    }
}

/// The catalog writer's mock for the agreement proof: records every
/// checkpoint put in order.
#[derive(Default)]
struct MockCatalog {
    puts: Mutex<Vec<(String, Vec<u8>)>>,
}

impl MockCatalog {
    fn log(&self) -> Vec<(String, Vec<u8>)> {
        self.puts.lock().expect("mock lock").clone()
    }

    /// The checkpoints the rebuild landed — the agreement proof's
    /// sanity check that the rebuild itself wrote.
    fn checkpoint_count(&self) -> usize {
        self.log().len()
    }
}

impl CatalogWriteStore for MockCatalog {
    fn put_checkpoint(
        &self,
        key: &CatalogCheckpointKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        self.puts
            .lock()
            .expect("mock lock")
            .push((key.as_str().to_owned(), bytes.to_vec()));
        async { Ok(()) }
    }

    fn list_checkpoints(
        &self,
        _prefix: &CatalogListPrefix,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send {
        let keys: Vec<String> = self
            .puts
            .lock()
            .expect("mock lock")
            .iter()
            .map(|(key, _)| key.clone())
            .collect();
        async { Ok(keys) }
    }
}

// ---- The test projection: a real bounded reader over the fixture shape ----

/// The fixture projection: parse each JSONL line's `usage` region into
/// the protocol's normalized reading. Present-but-unparseable regions
/// are `Malformed`; a line without a usage region is `Absent`. This
/// mirrors the adapter projections' contract at fixture scale.
fn read_usage(adapter: &AdapterId, plaintext: &[u8]) -> Vec<MessageUsage> {
    let _ = adapter;
    let mut messages = Vec::new();
    for line in plaintext.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let fields = match json::parse(line) {
            Ok(Value::Object(object)) => Some(object),
            _ => None,
        };
        let region = match &fields {
            Some(object) => match object.get("usage") {
                None => UsageRegion::Absent,
                Some(Value::Object(usage)) => match read_counts(usage) {
                    Some(counts) => UsageRegion::Measured(counts),
                    None => UsageRegion::Malformed,
                },
                Some(_) => UsageRegion::Malformed,
            },
            None => UsageRegion::Malformed,
        };
        let model = fields
            .as_ref()
            .and_then(|object| match object.get("model_id") {
                Some(Value::Text(model)) => Some(model.clone()),
                _ => None,
            });
        messages.push(MessageUsage {
            model_id: model,
            service_tier: None,
            region,
        });
    }
    messages
}

/// Read the fixture's four bounded axes; any missing or mistyped axis
/// refuses the region.
fn read_counts(usage: &Object) -> Option<SourceUsageCounts> {
    let int_of = |object: &Object, name: &str| -> Option<u64> {
        match object.get(name) {
            Some(Value::Int(value)) if *value >= 0 => u64::try_from(*value).ok(),
            _ => None,
        }
    };
    let Some(Value::Object(creation)) = usage.get("cache_creation") else {
        return None;
    };
    Some(SourceUsageCounts {
        input_tokens: int_of(usage, "input_tokens")?,
        output_tokens: int_of(usage, "output_tokens")?,
        cache_read_tokens: int_of(usage, "cache_read_input_tokens")?,
        cache_creation_5m: int_of(creation, "ephemeral_5m_input_tokens")?,
        cache_creation_1h: int_of(creation, "ephemeral_1h_input_tokens")?,
        reasoning_tokens: int_of(usage, "reasoning_tokens")?,
    })
}

fn projection() -> UsageProjection<fn(&AdapterId, &[u8]) -> Vec<MessageUsage>> {
    UsageProjection::new(
        VersionToken::parse(PROJECTION_VERSION).expect("grammar projection version"),
        read_usage,
    )
}

// ---- Driving ----

/// Complete first-poll-until-ready, the catalog-module pattern (every
/// mock future completes without pending).
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

/// The manifest document of one completed build, parsed back from the
/// exact bytes the build wrote.
fn manifest_of(bytes: &[u8]) -> Object {
    match json::parse(bytes) {
        Ok(Value::Object(object)) => object,
        other => panic!("the manifest parses back: {other:?}"),
    }
}

/// One member's integer, for manifest assertions.
fn manifest_int(object: &Object, name: &str) -> i64 {
    match object.get(name) {
        Some(Value::Int(value)) => *value,
        other => panic!("manifest member {name} is an integer, got {other:?}"),
    }
}

/// One member's text, for manifest assertions.
fn manifest_text<'a>(object: &'a Object, name: &str) -> &'a str {
    match object.get(name) {
        Some(Value::Text(text)) => text.as_str(),
        other => panic!("manifest member {name} is text, got {other:?}"),
    }
}

/// The manifest's `row_states` member as its four counts.
fn row_states_of(object: &Object) -> (i64, i64, i64, i64) {
    match object.get("row_states") {
        Some(Value::Object(states)) => (
            manifest_int(states, "measured"),
            manifest_int(states, "absent"),
            manifest_int(states, "malformed"),
            manifest_int(states, "unsupported"),
        ),
        other => panic!("manifest row_states is an object, got {other:?}"),
    }
}

/// Whether `needle`'s bytes appear anywhere in `haystack`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---- The proofs ----

/// **Reproducible:** two builds of one frozen prefix emit the same keys
/// with byte-identical objects, and a retry over the writer that
/// already carries the build converges on the identical files — the
/// rebuild gate (same raw prefix and pipeline version, byte-identical
/// partitions) holds for the inventory family too.
#[test]
fn two_builds_of_one_prefix_are_byte_identical() {
    let tenant = tenant_a();
    let store = MockStore::with(&tenant, &corpus(&tenant));

    let first = MockDerived::new();
    let outcome_a = block_on(inventory_build(&store, &first, &projection(), &tenant))
        .expect("the first build completes");

    let second = MockDerived::new();
    let outcome_b = block_on(inventory_build(&store, &second, &projection(), &tenant))
        .expect("the second build completes");

    assert_eq!(
        first.log(),
        second.log(),
        "two builds of one prefix put the same keys with the same bytes"
    );
    assert_eq!(
        outcome_a.manifest_digest(),
        outcome_b.manifest_digest(),
        "the manifest digest is a function of the prefix, not the run"
    );
    assert_eq!(
        outcome_a.result_document(),
        outcome_b.result_document(),
        "the content-free result document is run-independent"
    );

    // A retry over a writer that already carries the objects converges
    // on the identical files instead of diverging from them: the same
    // puts again, in the same order, with the same bytes.
    let again = block_on(inventory_build(&store, &first, &projection(), &tenant))
        .expect("the retry completes");
    let log = first.log();
    let half = log.len() / 2;
    assert_eq!(
        &log[..half],
        &log[half..],
        "a retry re-puts the identical files"
    );
    assert_eq!(again.manifest_digest(), outcome_a.manifest_digest());
    for (key, bytes) in &log[..half] {
        assert_eq!(
            &first.bytes_at(key),
            bytes,
            "the retry never rewrites a landed file's bytes"
        );
    }
}

/// **One view with the rebuild:** the inventory's chain digest and
/// denominator tally equal the catalog rebuild's own for the same
/// frozen prefix and projection, every partition shard is the digest
/// prefix of a row the rebuild itself wrote, and the manifest's
/// statements match the objects that actually landed.
#[test]
fn the_inventory_agrees_with_the_catalog_rebuild() {
    let tenant = tenant_a();
    let store = MockStore::with(&tenant, &corpus(&tenant));

    let rebuild_rows = MockDerived::new();
    let catalog = MockCatalog::default();
    let rebuild = block_on(rebuild_pass(
        &store,
        &rebuild_rows,
        &catalog,
        &projection(),
        &tenant,
        RebuildPolicy {
            checkpoint_every: 1,
            window: None,
        },
        None,
    ))
    .expect("the rebuild pass completes");
    assert!(
        catalog.checkpoint_count() > 0,
        "the comparison rebuild wrote its own checkpoints"
    );

    let derived = MockDerived::new();
    let outcome = block_on(inventory_build(&store, &derived, &projection(), &tenant))
        .expect("the inventory build completes");

    assert_eq!(
        outcome.chain_digest(),
        rebuild.chain_digest(),
        "the inventory and the rebuild fold one prefix to one chain"
    );
    let rebuild_document = rebuild.result_document(&tenant, projection().version());
    assert_eq!(
        Value::Object(outcome.row_states()),
        rebuild_document
            .get("row_states")
            .cloned()
            .unwrap_or(Value::Null),
        "the two pipelines tally the same denominators"
    );

    // Every partition shard is the digest prefix of a row the rebuild
    // wrote — the partitioning rides the derived family's own sharding,
    // never a second reading of the raw bytes.
    let row_digests: Vec<String> = rebuild_rows
        .log()
        .iter()
        .map(|(key, _)| key.rsplit('/').next().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(row_digests.len(), 3, "one derived row per occurrence");
    for partition in outcome.partitions() {
        let expected = row_digests
            .iter()
            .any(|digest| digest.starts_with(&partition.shard));
        assert!(
            expected,
            "shard {} carries rows the rebuild derived",
            partition.shard
        );
    }

    // The manifest's statements match the objects that landed: rows,
    // sizes, digests, and the partition count.
    let manifest = manifest_of(outcome.manifest_bytes());
    assert_eq!(
        manifest_int(&manifest, "partition_count"),
        i64::try_from(outcome.partitions().len()).unwrap(),
        "the manifest counts the partitions that landed"
    );
    let listed_rows: i64 = match manifest.get("partitions") {
        Some(Value::Array(entries)) => entries
            .iter()
            .map(|entry| match entry {
                Value::Object(object) => manifest_int(object, "rows"),
                other => panic!("a partition entry is an object, got {other:?}"),
            })
            .sum(),
        other => panic!("the manifest lists its partitions, got {other:?}"),
    };
    assert_eq!(
        listed_rows,
        manifest_int(&manifest, "occurrences_total"),
        "one inventory row per occurrence, all inside partitions"
    );
    for partition in outcome.partitions() {
        let bytes = derived.bytes_at(&partition.key);
        assert_eq!(
            bytes.len(),
            usize::try_from(partition.file_size).unwrap(),
            "the recorded size names the landed bytes"
        );
        assert_eq!(
            blob_digest(&bytes).to_hex(),
            partition.digest,
            "the recorded digest names the landed bytes"
        );
        assert!(partition.key.ends_with(&format!(
            "/{}/part-{}.parquet",
            outcome.source_inventory_digest(),
            partition.shard
        )));
    }

    // The manifest itself is the last put: a directory without it is
    // never an authoritative partition set.
    let log = derived.log();
    let (last_key, _) = log.last().expect("the build put a manifest");
    assert_eq!(*last_key, outcome.manifest_key(), "the manifest lands last");
}

/// **Tenant isolation:** every key a build emits sits inside the
/// building tenant's own derived namespace under the pinned pipeline
/// and version, and two tenants building through one shared writer
/// share no key.
#[test]
fn tenants_never_share_output_directories() {
    let a = tenant_a();
    let b = tenant_b();
    let store_a = MockStore::with(&a, &corpus(&a));
    let store_b = MockStore::with(&b, &corpus(&b));

    let shared = MockDerived::new();
    let outcome_a =
        block_on(inventory_build(&store_a, &shared, &projection(), &a)).expect("tenant A builds");
    let outcome_b =
        block_on(inventory_build(&store_b, &shared, &projection(), &b)).expect("tenant B builds");

    let prefix_a =
        format!("tenants/{a}/v1/derived/{INVENTORY_PIPELINE_ID}/{INVENTORY_PIPELINE_VERSION}/");
    let prefix_b =
        format!("tenants/{b}/v1/derived/{INVENTORY_PIPELINE_ID}/{INVENTORY_PIPELINE_VERSION}/");
    for (key, _) in shared.log() {
        let inside_a = key.starts_with(&prefix_a);
        let inside_b = key.starts_with(&prefix_b);
        assert!(
            inside_a ^ inside_b,
            "every put sits inside exactly one tenant's namespace: {key}"
        );
    }
    assert_eq!(
        outcome_a.manifest_key(),
        format!(
            "{prefix_a}{}/manifest.json",
            outcome_a.source_inventory_digest()
        ),
        "the manifest key is the pinned tenant-scoped layout"
    );
    assert_ne!(
        outcome_a.source_inventory_digest(),
        outcome_b.source_inventory_digest(),
        "the two tenants' prefixes are different sources"
    );

    // The frozen source digest names the source: the outcome's digest
    // equals the store's own frozen inventory digest.
    let frozen = block_on(store_a.freeze_inventory(&InventoryScope::TenantRaw(a.clone())))
        .expect("the store freezes");
    assert_eq!(
        outcome_a.source_inventory_digest(),
        frozen.digest().to_hex(),
        "the build commits to the prefix it read"
    );
}

/// **Never overwriting another version:** a later source version
/// writes its own source-digest directory and leaves the earlier
/// build's files byte-identical where they stand — a content-named
/// key set can never overwrite another pipeline version's outputs,
/// because a different source is a different directory and nothing
/// lands anywhere else.
#[test]
fn a_later_source_version_never_overwrites_an_earlier_one() {
    let tenant = tenant_a();
    let mut store = MockStore::with(&tenant, &corpus(&tenant));

    let derived = MockDerived::new();
    let v1 = block_on(inventory_build(&store, &derived, &projection(), &tenant))
        .expect("the first source version builds");
    let v1_files: Vec<(String, Vec<u8>)> = derived
        .log()
        .iter()
        .map(|(key, bytes)| (key.clone(), bytes.clone()))
        .collect();
    assert!(!v1_files.is_empty());

    // The prefix grows: a fourth occurrence makes a different frozen
    // source, so a different source digest directory.
    store.refreeze(&[
        fixture_measured(&tenant),
        fixture_absent(&tenant),
        fixture_malformed(&tenant),
        fixture_from(
            &tenant,
            "transcript-witness-fourth",
            &payload(
                "transcript-witness-fourth",
                Some("claude-sonnet-4"),
                Some(MEASURED),
            ),
        ),
    ]);
    let v2 = block_on(inventory_build(&store, &derived, &projection(), &tenant))
        .expect("the second source version builds");

    assert_ne!(
        v1.source_inventory_digest(),
        v2.source_inventory_digest(),
        "a grown prefix is a different source commitment"
    );
    assert_eq!(
        v2.occurrences_total(),
        4,
        "the later version covers the grown prefix"
    );

    // The two builds share no key: the second build's directory is the
    // new digest's, so the first version's files were never put over.
    let v1_keys: Vec<&String> = v1_files.iter().map(|(key, _)| key).collect();
    let v2_keys: Vec<String> = v2
        .partitions()
        .iter()
        .map(|partition| partition.key.clone())
        .chain([v2.manifest_key().to_owned()])
        .collect();
    assert!(
        v2_keys.iter().all(|key| !v1_keys.contains(&key)),
        "the later build never writes an earlier version's key"
    );

    // And the earlier files still stand byte-identical: the writer's
    // log carries the v1 bytes untouched after the v2 build.
    for (key, bytes) in &v1_files {
        let landed = derived
            .log()
            .iter()
            .find(|(put, _)| put == key)
            .map(|(_, landed)| landed.clone())
            .unwrap_or_default();
        assert_eq!(
            &landed, bytes,
            "the earlier version's file stands byte-identical: {key}"
        );
    }
}

/// **`unknown`, never zero:** the manifest's denominator tally carries
/// the corpus's absent and malformed sources as their bounded states —
/// an incomplete source reads as unaccounted, never as free. (The
/// cell-level rule — no count column beside an `unknown` state — is
/// the module unit suite's `unknown_rows_carry_the_reason_and_never_a_count`.)
#[test]
fn absent_and_malformed_usage_stay_unknown() {
    let tenant = tenant_a();
    let store = MockStore::with(&tenant, &corpus(&tenant));
    let derived = MockDerived::new();
    let outcome = block_on(inventory_build(&store, &derived, &projection(), &tenant))
        .expect("the build completes");

    let manifest = manifest_of(outcome.manifest_bytes());
    assert_eq!(manifest_int(&manifest, "occurrences_total"), 3);
    assert_eq!(
        row_states_of(&manifest),
        (1, 1, 1, 0),
        "measured, absent, and malformed each counted in their own state"
    );
    assert_eq!(
        manifest_text(&manifest, "usage_pipeline_id"),
        "usage",
        "the evidence names its source family"
    );
    assert_eq!(
        manifest_text(&manifest, "usage_projection_version"),
        PROJECTION_VERSION,
        "the projection version is part of the commitment"
    );
    // The state members are observations, not absences: all four are
    // present, the unsupported count honestly zero.
    let states = match manifest.get("row_states") {
        Some(Value::Object(states)) => states,
        other => panic!("row_states is an object, got {other:?}"),
    };
    for member in ["measured", "absent", "malformed", "unsupported"] {
        assert!(states.get(member).is_some(), "{member} is always present");
    }
}

/// **Content-free:** no transcript text reaches any emitted byte — not
/// the payload's note markers, not the role member — while the model
/// identity the projection is allowed to carry does, which is what
/// makes the absence a proof rather than an empty file.
#[test]
fn no_transcript_text_reaches_the_projection() {
    let tenant = tenant_a();
    let store = MockStore::with(&tenant, &corpus(&tenant));
    let derived = MockDerived::new();
    block_on(inventory_build(&store, &derived, &projection(), &tenant))
        .expect("the build completes");

    for (key, bytes) in derived.log() {
        for witness in [
            NOTE_MEASURED.as_bytes(),
            NOTE_ABSENT.as_bytes(),
            NOTE_MALFORMED.as_bytes(),
            // The role member is payload structure, not a projection
            // column; no column name or manifest member carries the
            // quoted form. (The bare token `usage` is deliberately not
            // a witness: it is the manifest's own pipeline identifier's
            // value, `usage_pipeline_id`.)
            b"\"role\"",
        ] {
            assert!(
                !contains_bytes(&bytes, witness),
                "transcript text reached {key}"
            );
        }
    }
    // The projection is not empty: the allowed identity text is there,
    // plain-encoded in the partition bytes.
    let partition_bytes: Vec<u8> = derived
        .log()
        .iter()
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect();
    assert!(
        contains_bytes(&partition_bytes, b"claude-sonnet-4"),
        "the model identity column carries its values"
    );
    assert!(
        contains_bytes(&partition_bytes, b"tenants/"),
        "the provenance columns carry the tenant"
    );
}

/// **The manifest is the completeness statement:** an empty prefix
/// still emits one — zero partitions, zero rows, every state honestly
/// zero — and a build whose manifest put fails leaves an incomplete
/// directory behind, never an authoritative partition set.
#[test]
fn the_manifest_is_the_completeness_statement() {
    let tenant = tenant_a();

    // The empty prefix: exactly one put, the manifest.
    let empty = MockStore::with(&tenant, &[]);
    let derived = MockDerived::new();
    let outcome = block_on(inventory_build(&empty, &derived, &projection(), &tenant))
        .expect("the empty prefix builds");
    assert!(outcome.partitions().is_empty());
    assert_eq!(outcome.occurrences_total(), 0);
    let log = derived.log();
    assert_eq!(log.len(), 1, "the manifest only");
    assert_eq!(log[0].0, outcome.manifest_key());
    let manifest = manifest_of(outcome.manifest_bytes());
    assert_eq!(manifest_int(&manifest, "occurrences_total"), 0);
    assert_eq!(manifest_int(&manifest, "partition_count"), 0);
    assert_eq!(row_states_of(&manifest), (0, 0, 0, 0));

    // The refused manifest put: the build fails, the partitions it
    // already landed stay, and no manifest exists — an incomplete
    // directory, by construction never authoritative.
    let store = MockStore::with(&tenant, &corpus(&tenant));
    let refusing = MockDerived::refusing_the_manifest();
    let failed = block_on(inventory_build(&store, &refusing, &projection(), &tenant));
    assert!(failed.is_err(), "the build fails closed on the refused put");
    let log = refusing.log();
    assert!(
        log.iter().all(|(key, _)| !key.ends_with("/manifest.json")),
        "no manifest landed"
    );
    assert!(!log.is_empty(), "the partitions it did land are recorded");
}
