// SPDX-License-Identifier: Apache-2.0

//! End-to-end guards for the administration credential's permission scope
//! (plan Section 5, control-plane boundary).
//!
//! The boundary is one statement made by three surfaces, and every test here
//! walks at least two of them together over the public API alone:
//!
//! - the **configuration surface** — `S3StorageConfig` for the ingest
//!   replica, `ControlAdminConfig` for the offline administrator — each
//!   validated fail-closed from its tier strings, the way a deployment
//!   assembles them;
//! - the **store** — `S3ControlAdminStore`, which accepts complete signed
//!   records and derives every object key from the record's own validated
//!   members;
//! - the **permission scope** — the backend policy for the administration
//!   credential: read-write below `tenants/<tenant>/v1/control/`, and every
//!   non-control prefix — raw, catalog, derived, tombstone, legal-hold, and
//!   every other tenant's prefix — denied.
//!
//! The read/write split the plan pins is guarded here as an outcome of that
//! boundary: the ingest surface has no role the administration credential
//! could fill, the joint check refuses the one composition mistake the type
//! split cannot see (a deployment reusing the reference string across both
//! surfaces), and the store refuses any record outside the pinned tenant
//! before a request is issued — proven family by family, through the write
//! method each family's own write class pins.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{Ed25519PublicKey, KeyId, TenantId};
use archivist_storage::control::{
    AdminControlRecord, ControlAdminStore, ControlRecordKind, ControlWriteClass,
};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage_s3::config::{
    ControlAdminConfig, EncryptionPolicy, S3ConfigErrorKind, S3StorageConfig,
    S3StorageConfigBuilder, StorageRole,
};
use archivist_storage_s3::control_admin::{
    ControlAdminBackend, ControlObjectKey, S3ControlAdminStore,
};

// The golden identifiers the control schema gate pins
// (tools/check-control-schemas.py), shared with the store's own unit tests
// so every layer of this boundary tells one story.
const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";
const RELAY: &str = "2b1a0f9e-8d7c-4e6b-9a5f-1e2d3c4b5a69";
const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
const SIGNED_AT: &str = "2026-09-13T00:00:00Z";

const ENDPOINT: &str = "https://s3.example.invalid";
const REGION: &str = "us-east-1";
const RAW_BUCKET: &str = "archivist-raw-example";
const CONTROL_BUCKET: &str = "archivist-control-example";

const RAW_WRITE_REF: &str = "file:/etc/archivist/storage/raw-write-credentials";
const CONTROL_READ_REF: &str = "file:/etc/archivist/storage/control-read-credentials";
const RAW_READ_REF: &str = "file:/etc/archivist/storage/raw-read-credentials";
const RESTORE_REF: &str = "env:RESTORE_CREDENTIALS_TARGET";
const ADMIN_REF: &str = "file:/etc/archivist/storage/control-admin-credentials";
// The dedicated administration reference through the grammar's other kind
// (CFG-029): a secret's env channel instead of its file channel.
const ENV_ADMIN_REF: &str = "env:CONTROL_ADMIN_CREDENTIAL_TARGET";

fn tenant_id() -> TenantId {
    TENANT.parse().expect("golden tenant parses")
}

fn signature_hex() -> String {
    "00".repeat(64)
}

fn authority_key_id() -> String {
    key_id_hex_of(&[0xab; 32])
}

fn key_id_hex_of(raw: &[u8; 32]) -> String {
    let public = Ed25519PublicKey::from_raw(*raw);
    KeyId::from_public_key(&public).to_hex()
}

/// Canonical envelope bytes from ordered members (canonical output sorts,
/// so call sites may name members in any order).
fn envelope(members: &[(&str, Value)]) -> Vec<u8> {
    let mut object = Object::new();
    for (name, value) in members {
        object.set(name, value.clone());
    }
    Value::Object(object).canonical_bytes()
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

/// The wrapper members every control record carries, signed under
/// `record_tenant`'s authority.
fn wrapper(
    record_tenant: &str,
    record_type: &str,
    record_kind: &str,
) -> Vec<(&'static str, Value)> {
    vec![
        ("schema", text("archivist.control/v1")),
        ("record_type", text(record_type)),
        ("record_kind", text(record_kind)),
        ("tenant_id", text(record_tenant)),
        ("signed_at", text(SIGNED_AT)),
        ("authority_key_id", text(&authority_key_id())),
        ("authority_signature", text(&signature_hex())),
    ]
}

fn linked_client_envelope(record_tenant: &str, epoch: i64) -> Vec<u8> {
    let mut members = wrapper(record_tenant, "linked-client", "current-pointer");
    members.extend([
        ("client_id", text(CLIENT)),
        ("key_id", text(&key_id_hex_of(&[0xcd; 32]))),
        ("key_algorithm", text("ed25519")),
        ("public_key", text(&"cd".repeat(32))),
        ("authorization_epoch", Value::Int(epoch)),
    ]);
    envelope(&members)
}

fn delegation_envelope(record_tenant: &str, epoch: i64) -> Vec<u8> {
    let mut members = wrapper(record_tenant, "delegation", "current-pointer");
    members.extend([
        ("relay_client_id", text(RELAY)),
        ("origin_client_id", text(CLIENT)),
        ("delegation_state", text("active")),
        ("authorization_epoch", Value::Int(epoch)),
    ]);
    envelope(&members)
}

fn revocation_envelope(record_tenant: &str, epoch: i64) -> Vec<u8> {
    let mut members = wrapper(record_tenant, "revocation", "immutable");
    members.extend([
        ("client_id", text(CLIENT)),
        ("revoked_key_id", text(&key_id_hex_of(&[0xcd; 32]))),
        ("authorization_epoch", Value::Int(epoch)),
    ]);
    envelope(&members)
}

fn rotation_envelope(record_tenant: &str, epoch: i64) -> Vec<u8> {
    let mut members = wrapper(record_tenant, "rotation", "immutable");
    members.extend([
        ("client_id", text(CLIENT)),
        ("previous_epoch", Value::Int(epoch - 1)),
        ("previous_public_key", text(&"ef".repeat(32))),
        ("previous_key_id", text(&key_id_hex_of(&[0xef; 32]))),
        ("key_algorithm", text("ed25519")),
        ("public_key", text(&"cd".repeat(32))),
        ("key_id", text(&key_id_hex_of(&[0xcd; 32]))),
        ("authorization_epoch", Value::Int(epoch)),
    ]);
    envelope(&members)
}

fn receipt_key_envelope(record_tenant: &str) -> Vec<u8> {
    let mut members = wrapper(record_tenant, "receipt-key", "immutable");
    members.extend([
        ("key_id", text(&key_id_hex_of(&[0x3c; 32]))),
        ("key_algorithm", text("ed25519")),
        ("public_key", text(&"3c".repeat(32))),
        ("valid_from", text("2026-09-04T00:00:00Z")),
        ("valid_until", text("2026-10-11T00:00:00Z")),
    ]);
    envelope(&members)
}

/// The validated ingest configuration of a deployment, assembled from its
/// tier strings.
fn ingest_builder() -> S3StorageConfigBuilder {
    S3StorageConfig::builder()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .encryption(EncryptionPolicy::S3Sse)
        .raw_bucket(RAW_BUCKET)
        .control_bucket(CONTROL_BUCKET)
        .raw_write_credentials(RAW_WRITE_REF)
        .control_read_credentials(CONTROL_READ_REF)
}

fn admin_config() -> ControlAdminConfig {
    ControlAdminConfig::builder()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .control_bucket(CONTROL_BUCKET)
        .tenant(TENANT)
        .control_admin_credentials(ADMIN_REF)
        .build()
        .expect("golden administration configuration validates")
}

/// Both validated configuration surfaces of one golden deployment, and the
/// proof that they compose: the ingest replica and the offline
/// administrator keep disjoint credentials.
fn deployment() -> (S3StorageConfig, ControlAdminConfig) {
    let ingest = ingest_builder().build().expect("golden ingest validates");
    let admin = admin_config();
    ingest
        .reject_administration_credential(&admin)
        .expect("the golden deployment keeps the credential split");
    (ingest, admin)
}

/// A no-dependency executor for futures that complete without pending (the
/// same helper the store's unit tests use).
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

/// The backend seam as the deployment's live backend behaves for the
/// administration credential: the policy is a literal string-prefix rule —
/// read-write below the pinned tenant's control prefix, deny everything
/// else — enforced on every request, with granted and refused keys
/// observable so the tests can prove the store's requests never leave the
/// provisioned scope.
#[derive(Clone, Debug)]
struct PolicyBackend {
    prefix: String,
    objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    granted: Arc<Mutex<Vec<String>>>,
    requests: Arc<Mutex<u32>>,
    denials: Arc<Mutex<u32>>,
    puts: Arc<Mutex<HashMap<String, u32>>>,
}

impl PolicyBackend {
    fn new(tenant: &TenantId) -> Self {
        Self {
            prefix: format!("tenants/{tenant}/v1/control/"),
            objects: Arc::new(Mutex::new(HashMap::new())),
            granted: Arc::new(Mutex::new(Vec::new())),
            requests: Arc::new(Mutex::new(0)),
            denials: Arc::new(Mutex::new(0)),
            puts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The deployment policy for the administration credential, as a grant
    /// predicate over one object key.
    fn policy_permits(&self, key: &str) -> bool {
        key.starts_with(&self.prefix)
    }

    /// Every key a request was granted for, in request order.
    fn granted_keys(&self) -> Vec<String> {
        self.granted.lock().expect("test backend lock").clone()
    }

    /// How many requests reached the backend at all.
    fn requests(&self) -> u32 {
        *self.requests.lock().expect("test backend lock")
    }

    /// How many requests the policy refused.
    fn denials(&self) -> u32 {
        *self.denials.lock().expect("test backend lock")
    }

    /// How many puts the policy actually granted at one key — the counter
    /// an idempotent replay or a refused write must not move.
    fn puts_at(&self, key: &str) -> u32 {
        self.puts
            .lock()
            .expect("test backend lock")
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    fn stored(&self, key: &str) -> Option<Vec<u8>> {
        self.objects
            .lock()
            .expect("test backend lock")
            .get(key)
            .cloned()
    }
}

impl ControlAdminBackend for PolicyBackend {
    async fn get_control_object(
        &self,
        key: &ControlObjectKey,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        *self.requests.lock().expect("test backend lock") += 1;
        if !self.policy_permits(key.as_str()) {
            *self.denials.lock().expect("test backend lock") += 1;
            return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
        }
        self.granted
            .lock()
            .expect("test backend lock")
            .push(key.as_str().to_owned());
        Ok(self
            .objects
            .lock()
            .expect("test backend lock")
            .get(key.as_str())
            .cloned())
    }

    async fn put_control_object(
        &self,
        key: &ControlObjectKey,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        *self.requests.lock().expect("test backend lock") += 1;
        if !self.policy_permits(key.as_str()) {
            *self.denials.lock().expect("test backend lock") += 1;
            return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
        }
        self.granted
            .lock()
            .expect("test backend lock")
            .push(key.as_str().to_owned());
        *self
            .puts
            .lock()
            .expect("test backend lock")
            .entry(key.as_str().to_owned())
            .or_insert(0) += 1;
        self.objects
            .lock()
            .expect("test backend lock")
            .insert(key.as_str().to_owned(), bytes.to_vec());
        Ok(())
    }
}

/// A store composed the way the offline administrator CLI composes it, over
/// the policy-enforcing backend. The backend handle stays with the caller:
/// the store does not lend it back, which is part of the point.
fn admin_store(backend: PolicyBackend) -> (ControlAdminConfig, S3ControlAdminStore<PolicyBackend>) {
    let config = admin_config();
    let store = S3ControlAdminStore::new(config.clone(), backend);
    (config, store)
}

/// Every object key the five canonical record layouts derive, one per
/// family, over the golden identifiers. Each fixture key is proven to parse
/// back to itself, so both directions of the derivation agree.
fn one_key_per_family() -> Vec<String> {
    let keys = [
        format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json"),
        format!("tenants/{TENANT}/v1/control/delegations/{RELAY}/{CLIENT}.json"),
        format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/3.json"),
        format!("tenants/{TENANT}/v1/control/rotations/{CLIENT}/3.json"),
        format!(
            "tenants/{TENANT}/v1/control/receipt-keys/{}.json",
            key_id_hex_of(&[0x3c; 32])
        ),
    ];
    for key in &keys {
        let parsed = ControlObjectKey::parse(key).expect("fixture key parses");
        assert_eq!(parsed.as_str(), key);
    }
    keys.to_vec()
}

fn record(kind: ControlRecordKind, bytes: Vec<u8>) -> AdminControlRecord {
    AdminControlRecord::new(kind, bytes)
}

fn error_kind(result: Result<(), StorageError>) -> StorageErrorKind {
    result.expect_err("this write must fail").kind()
}

/// Replace one top-level text/int member of an envelope (test helper:
/// re-parse, set, re-serialize canonically).
fn replace_member(bytes: &[u8], name: &str, value: Value) -> Vec<u8> {
    let Value::Object(mut object) = archivist_protocol::json::parse(bytes).unwrap() else {
        panic!("test envelopes are objects");
    };
    object.set(name, value);
    Value::Object(object).canonical_bytes()
}

/// Drop one top-level member of an envelope.
fn without_member(bytes: &[u8], name: &str) -> Vec<u8> {
    let Value::Object(mut object) = archivist_protocol::json::parse(bytes).unwrap() else {
        panic!("test envelopes are objects");
    };
    let _ = object.remove(name);
    Value::Object(object).canonical_bytes()
}

#[test]
fn the_ingest_surface_has_no_role_the_administration_credential_could_fill() {
    // The role table is closed and names exactly the four ingest
    // identities — there is no fifth "administration" role, so an ingest
    // replica cannot be configured with this credential as an identity.
    // Its only route in is a reused reference string, which the joint
    // check refuses.
    let tokens: Vec<_> = StorageRole::all()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    assert_eq!(
        tokens,
        vec![
            "raw-writer",
            "control-reader",
            "raw-reader",
            "offline-restore"
        ]
    );
}

#[test]
fn ingest_configuration_refuses_the_administration_credential_across_every_role() {
    let (_, admin) = deployment();

    // Every ingest role — required or optional — remapped onto the
    // administration reference builds as a structurally valid ingest
    // configuration and is still refused by the joint check, with no echo
    // of the reference anywhere in the refusal.
    for (role, builder) in [
        (
            "raw-writer",
            ingest_builder().raw_write_credentials(ADMIN_REF),
        ),
        (
            "control-reader",
            ingest_builder().control_read_credentials(ADMIN_REF),
        ),
        (
            "raw-reader",
            ingest_builder().raw_read_credentials(ADMIN_REF),
        ),
        (
            "offline-restore",
            ingest_builder().offline_restore_credentials(ADMIN_REF),
        ),
    ] {
        let ingest = builder.build().unwrap_or_else(|e| panic!("{role}: {e}"));
        let error = ingest
            .reject_administration_credential(&admin)
            .expect_err("{role} must be refused");
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
        assert_eq!(
            error.detail(),
            "an ingest identity is the control-administration credential"
        );
        assert!(
            !error.to_string().contains(ADMIN_REF),
            "the refusal echoed the reference"
        );
    }
}

#[test]
fn the_dedicated_reference_stays_dedicated_for_either_reference_kind() {
    // The reference grammar has exactly two kinds, and the administration
    // credential can arrive as either. The split holds for both: every
    // ingest role mapped onto an env-kind administration reference is
    // refused exactly as a file-kind one is, with no echo of the reference
    // or its variable name, and mixed-kind disjoint references compose.
    let env_admin = ControlAdminConfig::builder()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .control_bucket(CONTROL_BUCKET)
        .tenant(TENANT)
        .control_admin_credentials(ENV_ADMIN_REF)
        .build()
        .expect("env-kind administration configuration validates");

    for (role, builder) in [
        (
            "raw-writer",
            ingest_builder().raw_write_credentials(ENV_ADMIN_REF),
        ),
        (
            "control-reader",
            ingest_builder().control_read_credentials(ENV_ADMIN_REF),
        ),
        (
            "raw-reader",
            ingest_builder().raw_read_credentials(ENV_ADMIN_REF),
        ),
        (
            "offline-restore",
            ingest_builder().offline_restore_credentials(ENV_ADMIN_REF),
        ),
    ] {
        let ingest = builder.build().unwrap_or_else(|e| panic!("{role}: {e}"));
        let error = ingest
            .reject_administration_credential(&env_admin)
            .expect_err("this ingest role must be refused");
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
        assert_eq!(
            error.detail(),
            "an ingest identity is the control-administration credential"
        );
        for never_echoed in [ENV_ADMIN_REF, "CONTROL_ADMIN_CREDENTIAL_TARGET"] {
            assert!(
                !error.to_string().contains(never_echoed),
                "the refusal echoed the reference"
            );
            assert!(
                !format!("{error:?}").contains(never_echoed),
                "the refusal's debug rendering echoed the reference"
            );
        }
    }

    // Mixed kinds compose: the env-kind administration credential over the
    // file-kind golden ingest identities is a split deployment — different
    // kinds name different references by construction.
    ingest_builder()
        .build()
        .expect("golden ingest validates")
        .reject_administration_credential(&env_admin)
        .expect("mixed-kind disjoint references compose");

    // The dedicated reference keeps its own grammar either way: an env-kind
    // administration credential is a reference, never a value, and its
    // configuration renders without the variable name.
    let rendered = format!("{env_admin:?}");
    for never_rendered in [ENV_ADMIN_REF, "CONTROL_ADMIN_CREDENTIAL_TARGET"] {
        assert!(
            !rendered.contains(never_rendered),
            "admin debug rendering leaked the reference target"
        );
    }
}

#[test]
fn a_validated_replica_configuration_never_carries_the_administration_credential() {
    let (_, admin) = deployment();

    // The portable replica profile: exactly the two required roles. After
    // validation, no present role holds the administration reference — the
    // read/write split as a set statement over the replica's credentials.
    let replica = ingest_builder().build().expect("replica profile validates");
    replica
        .reject_administration_credential(&admin)
        .expect("the replica profile never carries the administration credential");
    for role in StorageRole::all() {
        if let Some(reference) = replica.identities().role(*role) {
            assert_ne!(
                reference,
                admin.control_admin_credentials(),
                "{role} holds the administration credential"
            );
        }
    }

    // The same holds with every optional role granted.
    let full = ingest_builder()
        .raw_read_credentials(RAW_READ_REF)
        .offline_restore_credentials(RESTORE_REF)
        .build()
        .expect("full ingest configuration validates");
    full.reject_administration_credential(&admin)
        .expect("the split holds with every optional role granted");
    for role in StorageRole::all() {
        let reference = full
            .identities()
            .role(*role)
            .unwrap_or_else(|| panic!("role {role} must be mapped"));
        assert_ne!(
            reference,
            admin.control_admin_credentials(),
            "{role} holds the administration credential"
        );
    }
}

#[test]
fn every_non_control_prefix_is_denied_and_unreachable_through_the_typed_seam() {
    let admin = admin_config();
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let denied = [
        // The five non-control namespaces the plan names for this
        // credential: raw, catalog, derived, tombstone, legal-hold.
        format!("tenants/{TENANT}/v1/raw/blobs/zstd-v1/sha256/0123/{digest}.zst"),
        format!("tenants/{TENANT}/v1/raw/occurrences/{CLIENT}/claude-code/sh/ab/{digest}.json"),
        format!("tenants/{TENANT}/v1/raw/attestations/ab/{digest}/{digest}.json"),
        format!("tenants/{TENANT}/v1/catalog/checkpoints/{digest}.json"),
        format!("tenants/{TENANT}/v1/derived/inference/v1/day/2026-09-13/{digest}.json"),
        format!("tenants/{TENANT}/v1/tombstones/{CLIENT}/{digest}.json"),
        format!("tenants/{TENANT}/v1/legal-hold/{CLIENT}.json"),
        // The control prefix itself with a non-canonical shape is denied
        // rather than normalized.
        format!("tenants/{TENANT}/v1/control/clients/not-a-uuid.json"),
        format!("tenants/{TENANT}/v1/control/anything-else"),
        "tenants//v1/control/clients/x.json".to_owned(),
        String::new(),
    ];
    for key in denied {
        // The scope model denies the key…
        assert!(!admin.permits_key(&key), "{key} must be denied");
        // …and the typed seam cannot even express it: derivation is the
        // only way a key enters the store, and these keys do not derive.
        assert!(
            ControlObjectKey::parse(&key).is_err(),
            "{key} must not parse as a control key"
        );
    }

    // Another tenant's control prefix is the one denied key the typed seam
    // *can* express — it is a well-formed control layout, of a tenant this
    // credential does not provision. The scope model denies it here, and
    // the store and backend tests below prove both refuse it in turn.
    let foreign = format!("tenants/{OTHER_TENANT}/v1/control/clients/{CLIENT}.json");
    assert!(!admin.permits_key(&foreign), "{foreign} must be denied");
    assert!(ControlObjectKey::parse(&foreign).is_ok());

    // Inside the prefix, the five canonical layouts are exactly the
    // granted set — and the two independent statements of the scope, the
    // configuration's predicate and the wire-side parser, agree on every
    // one.
    for key in one_key_per_family() {
        assert!(admin.permits_key(&key), "{key} must be permitted");
    }
}

#[test]
fn every_store_write_lands_inside_the_backend_permission_scope() {
    let backend = PolicyBackend::new(&tenant_id());
    let (admin, store) = admin_store(backend.clone());

    // All five families, through both write classes: two current pointers
    // and three immutable records. Each write must succeed *under
    // enforcement* — the policy is live on every request the store issues.
    block_on(store.put_current_pointer(&record(
        ControlRecordKind::LinkedClient,
        linked_client_envelope(TENANT, 1),
    )))
    .expect("linked-client pointer write stays in scope");
    block_on(store.put_current_pointer(&record(
        ControlRecordKind::Delegation,
        delegation_envelope(TENANT, 1),
    )))
    .expect("delegation pointer write stays in scope");
    for (kind, bytes) in [
        (
            ControlRecordKind::Revocation,
            revocation_envelope(TENANT, 3),
        ),
        (ControlRecordKind::Rotation, rotation_envelope(TENANT, 3)),
        (ControlRecordKind::ReceiptKey, receipt_key_envelope(TENANT)),
    ] {
        block_on(store.put_immutable_record(&record(kind, bytes)))
            .expect("immutable write stays in scope");
    }

    // The store's documented write rule is read-then-write, so five
    // families produced ten granted requests — one read and one write
    // each. Every granted key sits under the provisioned prefix, proven
    // twice: by the policy's own string rule and by the configuration's
    // scope model, two statements that must not drift.
    let granted = backend.granted_keys();
    assert_eq!(granted.len(), 10, "one read and one write per family");
    for key in &granted {
        assert!(
            backend.policy_permits(key),
            "{key} left the provisioned prefix"
        );
        assert!(admin.permits_key(key), "{key} is outside the scope model");
    }
    // The granted set is exactly the five derived layouts.
    let mut unique = granted.clone();
    unique.sort();
    unique.dedup();
    let mut expected = one_key_per_family();
    expected.sort();
    assert_eq!(unique, expected);
    assert_eq!(backend.denials(), 0, "no request was refused");

    // The policy is real, not vacuous: addressed directly with a
    // parseable control key of another tenant, it refuses both verbs.
    let foreign = ControlObjectKey::parse(&format!(
        "tenants/{OTHER_TENANT}/v1/control/clients/{CLIENT}.json"
    ))
    .expect("a foreign control key is still a control key");
    let error = block_on(backend.clone().get_control_object(&foreign))
        .expect_err("the policy denies another tenant's prefix");
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
    let error = block_on(backend.clone().put_control_object(&foreign, b"{}"))
        .expect_err("the policy denies another tenant's prefix");
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
    assert_eq!(backend.denials(), 2);
}

#[test]
fn a_foreign_tenant_record_is_refused_before_any_request_is_issued() {
    let backend = PolicyBackend::new(&tenant_id());
    let (_, store) = admin_store(backend.clone());

    // Every family, through the write method its own write class pins: a
    // record signed under another tenant's authority is outside this
    // administration identity — refused with the scope detail, and the
    // backend saw nothing at all: no read, no write, nothing stored.
    let foreign_records = [
        (
            ControlRecordKind::LinkedClient,
            linked_client_envelope(OTHER_TENANT, 1),
        ),
        (
            ControlRecordKind::Delegation,
            delegation_envelope(OTHER_TENANT, 1),
        ),
        (
            ControlRecordKind::Revocation,
            revocation_envelope(OTHER_TENANT, 1),
        ),
        (
            ControlRecordKind::Rotation,
            rotation_envelope(OTHER_TENANT, 3),
        ),
        (
            ControlRecordKind::ReceiptKey,
            receipt_key_envelope(OTHER_TENANT),
        ),
    ];
    for (kind, bytes) in foreign_records {
        let attempted = match kind.write_class() {
            ControlWriteClass::CurrentPointer => {
                block_on(store.put_current_pointer(&record(kind, bytes)))
            }
            ControlWriteClass::Immutable => {
                block_on(store.put_immutable_record(&record(kind, bytes)))
            }
        };
        let error = attempted.expect_err("a foreign-tenant record must be refused");
        assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
        assert_eq!(
            error.detail(),
            "record tenant is outside this administration identity"
        );
        // The counter is cumulative across the loop, so asserting zero
        // here — per family, not only once at the end — is what makes
        // this a per-family proof: any single family reaching the
        // backend would fail its own iteration, not just the total.
        assert_eq!(backend.requests(), 0, "no request may be issued");
    }
    assert!(backend.granted_keys().is_empty());
    for key in one_key_per_family() {
        assert!(backend.stored(&key).is_none(), "{key} stored");
    }

    // The backend seam itself denies a foreign-tenant control key even if
    // one were somehow derived — the permission profile's denial, both
    // verbs.
    let foreign = ControlObjectKey::parse(&format!(
        "tenants/{OTHER_TENANT}/v1/control/clients/{CLIENT}.json"
    ))
    .expect("a foreign control key is still a control key");
    let error = block_on(backend.clone().get_control_object(&foreign))
        .expect_err("foreign tenant must be denied");
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
    let error = block_on(backend.clone().put_control_object(&foreign, b"{}"))
        .expect_err("foreign tenant must be denied");
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
    assert_eq!(backend.requests(), 2, "only the direct probes asked");
    assert_eq!(backend.denials(), 2);
}

#[test]
fn the_split_holds_end_to_end_administrator_writes_inside_one_prefix() {
    let (ingest, admin) = deployment();
    let backend = PolicyBackend::new(&tenant_id());
    let (_, store) = admin_store(backend.clone());

    // The administrator writes the pointer at its derived key.
    block_on(store.put_current_pointer(&record(
        ControlRecordKind::LinkedClient,
        linked_client_envelope(TENANT, 1),
    )))
    .expect("the administrator writes the linked-client pointer");
    let pointer_key = format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json");
    assert_eq!(
        backend.stored(&pointer_key).as_deref(),
        Some(linked_client_envelope(TENANT, 1).as_slice())
    );

    // The read/write split, as a statement over the composed surfaces: no
    // ingest role holds the administration credential, and the store that
    // does carry it was composed from the administration configuration —
    // never from the replica's identity map.
    for role in StorageRole::all() {
        assert_ne!(
            ingest.identities().role(*role),
            Some(admin.control_admin_credentials()),
            "{role} would hand the replica the administration credential"
        );
    }
    assert_eq!(
        store.config().control_admin_credentials(),
        admin.control_admin_credentials(),
        "the store's credential is the administration configuration's"
    );

    // And every request the administration store issued stayed inside the
    // one provisioned prefix.
    assert_eq!(backend.denials(), 0);
    for key in backend.granted_keys() {
        assert!(admin.permits_key(&key), "{key} escaped the scope");
    }
}

// -------------------------------------------------------------------
// The write rules through the trait seam.
//
// Every test above names the concrete store. The generic functions below
// do not: their only bound is `ControlAdminStore`, so each assertion
// inside is a property of the trait's write contract — the two write
// classes and their refusal rules — that any implementing store must
// satisfy. The S3 store proves the contract from outside its own module,
// against a harness that never learns which store it is driving.
// -------------------------------------------------------------------

/// The immutable write class, as the trait contract states it: a fresh
/// record writes, the byte-identical replay of that write is an
/// idempotent success, and any other bytes at the occupied key — a
/// payload member or a wrapper member mutated, so a re-signed or
/// re-timestamped variant too — are an integrity conflict.
fn drive_immutable_write_rules<S: ControlAdminStore>(store: &S) {
    let cases = [
        (
            ControlRecordKind::Revocation,
            revocation_envelope(TENANT, 3),
            [
                replace_member(
                    &revocation_envelope(TENANT, 3),
                    "revoked_key_id",
                    text(&key_id_hex_of(&[0xef; 32])),
                ),
                replace_member(
                    &revocation_envelope(TENANT, 3),
                    "authority_signature",
                    text(&"11".repeat(64)),
                ),
            ],
        ),
        (
            ControlRecordKind::Rotation,
            rotation_envelope(TENANT, 3),
            [
                replace_member(
                    &rotation_envelope(TENANT, 3),
                    "public_key",
                    text(&"ef".repeat(32)),
                ),
                replace_member(
                    &rotation_envelope(TENANT, 3),
                    "signed_at",
                    text("2026-09-12T00:00:00Z"),
                ),
            ],
        ),
        (
            ControlRecordKind::ReceiptKey,
            receipt_key_envelope(TENANT),
            [
                replace_member(
                    &receipt_key_envelope(TENANT),
                    "valid_until",
                    text("2026-10-12T00:00:00Z"),
                ),
                replace_member(
                    &receipt_key_envelope(TENANT),
                    "authority_signature",
                    text(&"22".repeat(64)),
                ),
            ],
        ),
    ];
    for (kind, bytes, conflictings) in cases {
        block_on(store.put_immutable_record(&record(kind, bytes.clone())))
            .expect("a fresh immutable record writes");
        block_on(store.put_immutable_record(&record(kind, bytes.clone())))
            .expect("the byte-identical replay is an idempotent success, not an error");
        for conflicting in &conflictings {
            let error = block_on(store.put_immutable_record(&record(kind, conflicting.clone())))
                .expect_err("incompatible bytes at an occupied immutable key fail");
            assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
        }
    }
}

/// The current-pointer write class, as the trait contract states it: the
/// first pointer writes, a strictly higher *valid* signed epoch replaces,
/// and everything else fails closed — the byte-identical replay, novel
/// bytes carrying the stored epoch, a lower epoch, and an epoch that is
/// not a valid signed epoch at all even though it would be higher.
fn drive_current_pointer_write_rules<S: ControlAdminStore>(store: &S) {
    // linked-client: 1 writes, 2 replaces, then every non-increase is
    // stale — including different payload at the stored epoch, which the
    // epoch-2 signature never covered — and 3 replaces again.
    block_on(store.put_current_pointer(&record(
        ControlRecordKind::LinkedClient,
        linked_client_envelope(TENANT, 1),
    )))
    .expect("the first linked-client pointer writes");
    block_on(store.put_current_pointer(&record(
        ControlRecordKind::LinkedClient,
        linked_client_envelope(TENANT, 2),
    )))
    .expect("a strictly higher epoch replaces the pointer");
    let linked_stale = [
        linked_client_envelope(TENANT, 2),
        replace_member(
            &linked_client_envelope(TENANT, 2),
            "public_key",
            text(&"ef".repeat(32)),
        ),
        linked_client_envelope(TENANT, 1),
    ];
    for stale in linked_stale {
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::LinkedClient,
                stale,
            )))),
            StorageErrorKind::StaleEpoch
        );
    }
    block_on(store.put_current_pointer(&record(
        ControlRecordKind::LinkedClient,
        linked_client_envelope(TENANT, 3),
    )))
    .expect("the next strictly higher epoch replaces the pointer");

    // delegation: the same rule over the relation's own epoch sequence.
    block_on(store.put_current_pointer(&record(
        ControlRecordKind::Delegation,
        delegation_envelope(TENANT, 1),
    )))
    .expect("the first delegation pointer writes");
    assert_eq!(
        error_kind(block_on(store.put_current_pointer(&record(
            ControlRecordKind::Delegation,
            delegation_envelope(TENANT, 1),
        )))),
        StorageErrorKind::StaleEpoch
    );
    block_on(store.put_current_pointer(&record(
        ControlRecordKind::Delegation,
        delegation_envelope(TENANT, 2),
    )))
    .expect("a strictly higher epoch replaces the delegation pointer");
    let delegation_stale = [
        replace_member(
            &delegation_envelope(TENANT, 2),
            "signed_at",
            text("2026-09-12T00:00:00Z"),
        ),
        delegation_envelope(TENANT, 1),
    ];
    for stale in delegation_stale {
        assert_eq!(
            error_kind(block_on(store.put_current_pointer(&record(
                ControlRecordKind::Delegation,
                stale,
            )))),
            StorageErrorKind::StaleEpoch
        );
    }

    // Invalid epochs fail closed for both pointer families. The
    // candidates carry epochs *higher* than the stored pointers, so what
    // refuses them is invalidity, never staleness.
    let invalid_epoch_candidates = [
        (
            ControlRecordKind::LinkedClient,
            linked_client_envelope(TENANT, 4),
        ),
        (
            ControlRecordKind::Delegation,
            delegation_envelope(TENANT, 4),
        ),
    ];
    for (kind, candidate) in invalid_epoch_candidates {
        let broken_epochs = [
            without_member(&candidate, "authorization_epoch"),
            replace_member(&candidate, "authorization_epoch", text("4")),
            replace_member(&candidate, "authorization_epoch", Value::Int(0)),
            replace_member(&candidate, "authorization_epoch", Value::Int(-1)),
            replace_member(
                &candidate,
                "authorization_epoch",
                Value::Int(1_000_000_000_000_000_000),
            ),
        ];
        for broken in broken_epochs {
            let error = block_on(store.put_current_pointer(&record(kind, broken)))
                .expect_err("an invalid epoch fails closed");
            assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        }
    }
}

/// Both write classes in sequence: the whole write contract of the trait
/// over one store.
fn drive_write_rules<S: ControlAdminStore>(store: &S) {
    drive_immutable_write_rules(store);
    drive_current_pointer_write_rules(store);
}

#[test]
fn the_write_rules_hold_through_the_control_admin_store_trait_seam() {
    let backend = PolicyBackend::new(&tenant_id());
    let (admin, store) = admin_store(backend.clone());

    // The harness binds only the trait, so the rules it asserts are the
    // trait's; this composition proves the S3 store satisfies them. The
    // backend counters below are the evidence for what each rule did:
    // which writes landed, which refusals wrote nothing.
    drive_write_rules(&store);

    // The immutable families: exactly one accepted put each — the fresh
    // write; neither the idempotent replay nor either conflicting variant
    // wrote — and the stored bytes are that first record's.
    let accepted_immutable = [
        (
            format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/3.json"),
            revocation_envelope(TENANT, 3),
        ),
        (
            format!("tenants/{TENANT}/v1/control/rotations/{CLIENT}/3.json"),
            rotation_envelope(TENANT, 3),
        ),
        (
            format!(
                "tenants/{TENANT}/v1/control/receipt-keys/{}.json",
                key_id_hex_of(&[0x3c; 32])
            ),
            receipt_key_envelope(TENANT),
        ),
    ];
    for (key, bytes) in &accepted_immutable {
        assert_eq!(backend.puts_at(key), 1, "{key}: one accepted put");
        assert_eq!(backend.stored(key).as_deref(), Some(bytes.as_slice()));
    }

    // The linked-client pointer: epochs 1, 2, 3 accepted — three puts —
    // and neither the replay, the same-epoch rewrite, nor the lower epoch
    // added one. The delegation relation's own sequence: two.
    let pointer_key = format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json");
    assert_eq!(backend.puts_at(&pointer_key), 3);
    assert_eq!(
        backend.stored(&pointer_key).as_deref(),
        Some(linked_client_envelope(TENANT, 3).as_slice())
    );
    let delegation_key = format!("tenants/{TENANT}/v1/control/delegations/{RELAY}/{CLIENT}.json");
    assert_eq!(backend.puts_at(&delegation_key), 2);
    assert_eq!(
        backend.stored(&delegation_key).as_deref(),
        Some(delegation_envelope(TENANT, 2).as_slice())
    );

    // And the scope statement holds over the whole battery, accepted and
    // refused writes alike: every request the store issued was granted
    // inside the provisioned prefix by both statements of the scope, the
    // policy refused nothing, and the granted set is exactly the five
    // derived layouts.
    assert_eq!(backend.denials(), 0);
    for key in backend.granted_keys() {
        assert!(
            backend.policy_permits(&key),
            "{key} left the provisioned prefix"
        );
        assert!(admin.permits_key(&key), "{key} is outside the scope model");
    }
    let mut unique = backend.granted_keys();
    unique.sort();
    unique.dedup();
    let mut expected = one_key_per_family();
    expected.sort();
    assert_eq!(unique, expected);
}
