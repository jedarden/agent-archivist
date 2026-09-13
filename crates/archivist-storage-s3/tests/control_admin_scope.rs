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
//! before a request is issued.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{Ed25519PublicKey, KeyId, TenantId};
use archivist_storage::control::{AdminControlRecord, ControlAdminStore, ControlRecordKind};
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
}

impl PolicyBackend {
    fn new(tenant: &TenantId) -> Self {
        Self {
            prefix: format!("tenants/{tenant}/v1/control/"),
            objects: Arc::new(Mutex::new(HashMap::new())),
            granted: Arc::new(Mutex::new(Vec::new())),
            requests: Arc::new(Mutex::new(0)),
            denials: Arc::new(Mutex::new(0)),
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

    // A record signed under another tenant's authority is outside this
    // administration identity: refused with the scope detail, and the
    // backend saw nothing — no read, no write, nothing stored.
    let error = block_on(store.put_current_pointer(&record(
        ControlRecordKind::LinkedClient,
        linked_client_envelope(OTHER_TENANT, 1),
    )))
    .expect_err("a foreign-tenant record must be refused");
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
    assert_eq!(
        error.detail(),
        "record tenant is outside this administration identity"
    );
    assert_eq!(backend.requests(), 0, "no request may be issued");
    assert!(backend.granted_keys().is_empty());
    for key in one_key_per_family() {
        assert!(backend.stored(&key).is_none(), "{key} stored");
    }

    // The immutable method refuses the same way, before any request.
    let error = block_on(store.put_immutable_record(&record(
        ControlRecordKind::Revocation,
        revocation_envelope(OTHER_TENANT, 1),
    )))
    .expect_err("a foreign-tenant record must be refused");
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
    assert_eq!(backend.requests(), 0);
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
