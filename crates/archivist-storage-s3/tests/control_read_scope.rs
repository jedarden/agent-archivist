// SPDX-License-Identifier: Apache-2.0

//! End-to-end guards for the control-read identity's authority boundary
//! (plan Section 5, control-plane boundary — the read half).
//!
//! The administration credential's scope is guarded by
//! `control_admin_scope.rs` from the write side; every test here walks the
//! same boundary from the replica's side, over the public API alone and
//! across at least two of the three surfaces that state it:
//!
//! - the **configuration surface** — `ControlReadConfig`, the dedicated
//!   reader configuration whose one credential reference, one-tenant
//!   scope, and joint administration-credential refusal keep the read
//!   identity from collapsing into the write identity;
//! - the **store** — `S3ControlReadStore`, which derives every object key
//!   from validated identifiers and gates each one against the provisioned
//!   scope before any request is issued;
//! - the **permission scope** — the backend policy for the read-only
//!   credential: read below `tenants/<tenant>/v1/control/`, and every
//!   non-control prefix — raw, catalog, derived, tombstone, legal-hold,
//!   and every other tenant's prefix — denied.
//!
//! What the tests pin is the *absence* of authority: no write, delete, or
//! list path (the store compiles only against the read trait and the
//! seam's two verbs; `S3ControlReadStore`'s rustdoc carries the
//! `compile_fail` proofs), no reach outside the one control prefix even
//! when the backend visibly holds the objects, and no reach into another
//! tenant's records even at well-formed control keys. The positive control
//! that closes the suite is the split itself: the administrator writes a
//! record and the replica reads exactly that record back — the one thing
//! the read identity is for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{ClientId, Ed25519PublicKey, KeyId, TenantId};
use archivist_storage::audit_restore::{ObjectBody, ObjectMetadata};
use archivist_storage::control::{
    AdminControlRecord, AuthorizationEpoch, ControlAdminStore, ControlReadStore, ControlRecord,
    ControlRecordKind,
};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::metadata::{ObjectTag, Observation, StorageVersionId};
use archivist_storage_s3::config::{ControlAdminConfig, ControlReadConfig, S3ConfigErrorKind};
use archivist_storage_s3::control_admin::{
    ControlAdminBackend, ControlObjectKey, S3ControlAdminStore,
};
use archivist_storage_s3::control_read::{ControlReadBackend, S3ControlReadStore};

// The golden identifiers the control schema gate pins
// (tools/check-control-schemas.py), shared with the sibling boundary
// suites so every layer of this boundary tells one story.
const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";
const RELAY: &str = "2b1a0f9e-8d7c-4e6b-9a5f-1e2d3c4b5a69";

const ENDPOINT: &str = "https://s3.example.invalid";
const REGION: &str = "us-east-1";
const CONTROL_BUCKET: &str = "archivist-control-example";

const READ_REF: &str = "file:/etc/archivist/storage/control-read-credentials";
const ADMIN_REF: &str = "file:/etc/archivist/storage/control-admin-credentials";
// The dedicated administration reference through the grammar's other kind
// (CFG-029): a secret's env channel instead of its file channel.
const ENV_ADMIN_REF: &str = "env:CONTROL_ADMIN_CREDENTIAL_TARGET";

// The read scope's refusal detail: the store refuses an out-of-scope key
// with this exact safe message, before any request is issued.
const SCOPE_DETAIL: &str = "key tenant is outside this control-read identity";

// The observation evidence every stored object carries, so the read
// transport can hand over bodies with their metadata.
const OBSERVED: &str = "2026-09-20T12:00:00Z";
const ETAG: &str = "\"d41d8cd98f00b204e9800998ecf8427e\"";
const VERSION: &str = "3sL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUO";
const SIGNED_AT: &str = "2026-09-20T00:00:00Z";

fn tenant_id() -> TenantId {
    TENANT.parse().expect("golden tenant parses")
}

fn other_tenant_id() -> TenantId {
    OTHER_TENANT.parse().expect("foreign tenant parses")
}

fn client_id() -> ClientId {
    CLIENT.parse().expect("golden client parses")
}

fn relay_id() -> ClientId {
    RELAY.parse().expect("golden relay parses")
}

fn epoch() -> AuthorizationEpoch {
    AuthorizationEpoch::new(3).expect("golden epoch")
}

fn receipt_key() -> KeyId {
    key_id_of(&[0x3c; 32])
}

fn key_id_of(raw: &[u8; 32]) -> KeyId {
    let public = Ed25519PublicKey::from_raw(*raw);
    KeyId::from_public_key(&public)
}

fn observation() -> Observation {
    Observation::new(
        Some(ObjectTag::parse(ETAG).expect("golden etag parses")),
        Some(StorageVersionId::parse(VERSION).expect("golden version parses")),
        archivist_protocol::vocabulary::Timestamp::parse(OBSERVED).expect("golden time parses"),
    )
}

// -------------------------------------------------------------------
// Golden control envelopes — the same canonical shape the sibling
// boundary suites write with, so what the administration store proves
// addressable is exactly what this boundary accepts as a record.
// -------------------------------------------------------------------

fn signature_hex() -> String {
    "00".repeat(64)
}

fn authority_key_id() -> String {
    key_id_of(&[0xab; 32]).to_hex()
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

fn linked_client_envelope(record_tenant: &str, epoch_value: i64) -> Vec<u8> {
    let mut members = wrapper(record_tenant, "linked-client", "current-pointer");
    members.extend([
        ("client_id", text(CLIENT)),
        ("key_id", text(&key_id_of(&[0xcd; 32]).to_hex())),
        ("key_algorithm", text("ed25519")),
        ("public_key", text(&"cd".repeat(32))),
        ("authorization_epoch", Value::Int(epoch_value)),
    ]);
    envelope(&members)
}

fn delegation_envelope(record_tenant: &str, epoch_value: i64) -> Vec<u8> {
    let mut members = wrapper(record_tenant, "delegation", "current-pointer");
    members.extend([
        ("relay_client_id", text(RELAY)),
        ("origin_client_id", text(CLIENT)),
        ("delegation_state", text("active")),
        ("authorization_epoch", Value::Int(epoch_value)),
    ]);
    envelope(&members)
}

fn revocation_envelope(record_tenant: &str, epoch_value: i64) -> Vec<u8> {
    let mut members = wrapper(record_tenant, "revocation", "immutable");
    members.extend([
        ("client_id", text(CLIENT)),
        ("revoked_key_id", text(&key_id_of(&[0xcd; 32]).to_hex())),
        ("authorization_epoch", Value::Int(epoch_value)),
    ]);
    envelope(&members)
}

fn rotation_envelope(record_tenant: &str, epoch_value: i64) -> Vec<u8> {
    let mut members = wrapper(record_tenant, "rotation", "immutable");
    members.extend([
        ("client_id", text(CLIENT)),
        ("previous_epoch", Value::Int(epoch_value - 1)),
        ("previous_public_key", text(&"ef".repeat(32))),
        ("previous_key_id", text(&key_id_of(&[0xef; 32]).to_hex())),
        ("key_algorithm", text("ed25519")),
        ("public_key", text(&"cd".repeat(32))),
        ("key_id", text(&key_id_of(&[0xcd; 32]).to_hex())),
        ("authorization_epoch", Value::Int(epoch_value)),
    ]);
    envelope(&members)
}

fn receipt_key_envelope(record_tenant: &str) -> Vec<u8> {
    let mut members = wrapper(record_tenant, "receipt-key", "immutable");
    members.extend([
        ("key_id", text(&receipt_key().to_hex())),
        ("key_algorithm", text("ed25519")),
        ("public_key", text(&"3c".repeat(32))),
        ("valid_from", text("2026-09-04T00:00:00Z")),
        ("valid_until", text("2026-10-11T00:00:00Z")),
    ]);
    envelope(&members)
}

/// One structurally valid golden envelope per family, each deriving
/// exactly its family's canonical key under this identity's tenant.
fn family_records() -> Vec<(&'static str, String, Vec<u8>)> {
    vec![
        (
            "linked-client",
            format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json"),
            linked_client_envelope(TENANT, 3),
        ),
        (
            "delegation",
            format!("tenants/{TENANT}/v1/control/delegations/{RELAY}/{CLIENT}.json"),
            delegation_envelope(TENANT, 3),
        ),
        (
            "revocation",
            format!("tenants/{TENANT}/v1/control/revocations/{CLIENT}/3.json"),
            revocation_envelope(TENANT, 3),
        ),
        (
            "rotation",
            format!("tenants/{TENANT}/v1/control/rotations/{CLIENT}/3.json"),
            rotation_envelope(TENANT, 3),
        ),
        (
            "receipt-key",
            format!(
                "tenants/{TENANT}/v1/control/receipt-keys/{}.json",
                receipt_key().to_hex()
            ),
            receipt_key_envelope(TENANT),
        ),
    ]
}

/// The same five families derived under the foreign tenant: well-formed
/// control layouts — every one parses — of a tenant this identity does
/// not provision.
fn foreign_family_keys() -> Vec<(&'static str, String)> {
    vec![
        (
            "linked-client",
            format!("tenants/{OTHER_TENANT}/v1/control/clients/{CLIENT}.json"),
        ),
        (
            "delegation",
            format!("tenants/{OTHER_TENANT}/v1/control/delegations/{RELAY}/{CLIENT}.json"),
        ),
        (
            "revocation",
            format!("tenants/{OTHER_TENANT}/v1/control/revocations/{CLIENT}/3.json"),
        ),
        (
            "rotation",
            format!("tenants/{OTHER_TENANT}/v1/control/rotations/{CLIENT}/3.json"),
        ),
        (
            "receipt-key",
            format!(
                "tenants/{OTHER_TENANT}/v1/control/receipt-keys/{}.json",
                receipt_key().to_hex()
            ),
        ),
    ]
}

// -------------------------------------------------------------------
// The deployment, as both identities observe it: one bucket whose policy
// is a literal string-prefix rule enforced on every request, and one
// request log the proofs read back. The two transports are the two
// credentials — the administration transport carries the put verb, the
// read transport carries only the two read verbs, and neither can reach
// the other's surface except through the stores under test.
// -------------------------------------------------------------------

#[derive(Default)]
struct Bucket {
    prefix: String,
    objects: HashMap<String, (Vec<u8>, Observation)>,
    requests: u32,
    puts: u32,
    denials: u32,
    requested: Vec<String>,
    puts_at: HashMap<String, u32>,
}

impl Bucket {
    fn policy_permits(&self, key: &str) -> bool {
        key.starts_with(&self.prefix)
    }
}

/// One bucket under the prefix policy, as the administration credential
/// and the read-only credential each see it, plus the shared log handle.
fn deployment() -> (AdminTransport, ReadTransport, Arc<Mutex<Bucket>>) {
    let bucket = Arc::new(Mutex::new(Bucket {
        prefix: format!("tenants/{TENANT}/v1/control/"),
        ..Bucket::default()
    }));
    (
        AdminTransport(bucket.clone()),
        ReadTransport(bucket.clone()),
        bucket,
    )
}

#[derive(Clone)]
struct AdminTransport(Arc<Mutex<Bucket>>);

#[derive(Clone)]
struct ReadTransport(Arc<Mutex<Bucket>>);

impl AdminTransport {
    /// The stored bytes at one key, whatever wrote them.
    fn stored(&self, key: &str) -> Option<Vec<u8>> {
        self.0
            .lock()
            .expect("test bucket lock")
            .objects
            .get(key)
            .map(|(bytes, _)| bytes.clone())
    }

    /// How many puts the policy actually granted at one key — the counter
    /// a read-side overreach would have to move.
    fn puts_at(&self, key: &str) -> u32 {
        self.0
            .lock()
            .expect("test bucket lock")
            .puts_at
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    /// How many puts the policy granted in total.
    fn puts(&self) -> u32 {
        self.0.lock().expect("test bucket lock").puts
    }

    /// Test setup: place an object directly, without a store and without
    /// touching the request log.
    fn preload(&self, key: &str, bytes: &[u8]) {
        self.0
            .lock()
            .expect("test bucket lock")
            .objects
            .insert(key.to_owned(), (bytes.to_vec(), observation()));
    }
}

impl ControlAdminBackend for AdminTransport {
    async fn get_control_object(
        &self,
        key: &ControlObjectKey,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let mut bucket = self.0.lock().expect("test bucket lock");
        bucket.requests += 1;
        if !bucket.policy_permits(key.as_str()) {
            bucket.denials += 1;
            return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
        }
        bucket.requested.push(key.as_str().to_owned());
        Ok(bucket
            .objects
            .get(key.as_str())
            .map(|(bytes, _)| bytes.clone()))
    }

    async fn put_control_object(
        &self,
        key: &ControlObjectKey,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let mut bucket = self.0.lock().expect("test bucket lock");
        bucket.requests += 1;
        if !bucket.policy_permits(key.as_str()) {
            bucket.denials += 1;
            return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
        }
        bucket.puts += 1;
        *bucket.puts_at.entry(key.as_str().to_owned()).or_insert(0) += 1;
        bucket
            .objects
            .insert(key.as_str().to_owned(), (bytes.to_vec(), observation()));
        Ok(())
    }
}

impl ReadTransport {
    /// Every key a request asked about, in request order — the log the
    /// whole-surface proofs read.
    fn requested_keys(&self) -> Vec<String> {
        self.0.lock().expect("test bucket lock").requested.clone()
    }

    /// How many requests reached the transport at all — the counter a
    /// refused-before-any-request proof holds at zero.
    fn requests(&self) -> u32 {
        self.0.lock().expect("test bucket lock").requests
    }

    /// How many requests the policy refused.
    fn denials(&self) -> u32 {
        self.0.lock().expect("test bucket lock").denials
    }

    /// Test setup: place an object directly, without a store and without
    /// touching the request log.
    fn preload(&self, key: &str, bytes: &[u8]) {
        self.0
            .lock()
            .expect("test bucket lock")
            .objects
            .insert(key.to_owned(), (bytes.to_vec(), observation()));
    }
}

impl ControlReadBackend for ReadTransport {
    async fn get_control_object(
        &self,
        key: &ControlObjectKey,
    ) -> Result<Option<ObjectBody>, StorageError> {
        let mut bucket = self.0.lock().expect("test bucket lock");
        bucket.requests += 1;
        bucket.requested.push(key.as_str().to_owned());
        if !bucket.policy_permits(key.as_str()) {
            bucket.denials += 1;
            return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
        }
        Ok(bucket
            .objects
            .get(key.as_str())
            .map(|(bytes, observed)| ObjectBody::new(bytes.clone(), observed.clone())))
    }

    async fn head_control_object(
        &self,
        key: &ControlObjectKey,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        let mut bucket = self.0.lock().expect("test bucket lock");
        bucket.requests += 1;
        bucket.requested.push(key.as_str().to_owned());
        if !bucket.policy_permits(key.as_str()) {
            bucket.denials += 1;
            return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
        }
        Ok(bucket
            .objects
            .get(key.as_str())
            .map(|(bytes, observed)| ObjectMetadata::new(bytes.len() as u64, observed.clone())))
    }
}

// -------------------------------------------------------------------
// The read surface, written generically. This function is the review
// anchor for the read trait's authority: its only bound is
// `ControlReadStore`, so it compiles only while the trait exposes exactly
// the five record reads — if the bound trait ever grew a write, delete,
// list, raw, catalog, derived, tombstone, or legal-hold method, this
// file is where that diff lands, and such a diff must be rejected as the
// acceptance failure it is.
// -------------------------------------------------------------------

/// Drive all five record reads through the trait bound, whatever store
/// implements it. Each result keeps its family's name so a failure says
/// which read escaped.
fn drive_every_trait_read<C: ControlReadStore>(
    store: &C,
    tenant: &TenantId,
) -> Vec<(&'static str, Result<Option<ControlRecord>, StorageError>)> {
    let client = client_id();
    let relay = relay_id();
    let receipt = receipt_key();
    let epoch_value = epoch();
    vec![
        (
            "linked-client",
            block_on(store.read_linked_client(tenant, &client)),
        ),
        (
            "delegation",
            block_on(store.read_delegation(tenant, &relay, &client)),
        ),
        (
            "revocation",
            block_on(store.read_revocation(tenant, &client, epoch_value)),
        ),
        (
            "rotation",
            block_on(store.read_rotation(tenant, &client, epoch_value)),
        ),
        (
            "receipt-key",
            block_on(store.read_receipt_key(tenant, &receipt)),
        ),
    ]
}

/// A no-dependency executor for futures that complete without pending (the
/// same helper the sibling boundary suites use).
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

fn reader_config() -> ControlReadConfig {
    ControlReadConfig::builder()
        .endpoint_url(ENDPOINT)
        .region(REGION)
        .control_bucket(CONTROL_BUCKET)
        .tenant(TENANT)
        .control_read_credentials(READ_REF)
        .build()
        .expect("golden control-read configuration validates")
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

fn reader_store(transport: ReadTransport) -> S3ControlReadStore<ReadTransport> {
    S3ControlReadStore::new(reader_config(), transport)
}

#[test]
fn a_reader_on_the_administration_credential_is_refused() {
    // The one composition mistake the separate configuration types cannot
    // see — both surfaces naming one credential reference — is what the
    // joint check exists for. The reader configured with the
    // administration reference is refused with DuplicateIdentity, for
    // either reference kind, with no echo of the reference anywhere in
    // the refusal.
    for admin_ref in [ADMIN_REF, ENV_ADMIN_REF] {
        let admin = ControlAdminConfig::builder()
            .endpoint_url(ENDPOINT)
            .region(REGION)
            .control_bucket(CONTROL_BUCKET)
            .tenant(TENANT)
            .control_admin_credentials(admin_ref)
            .build()
            .expect("administration configuration validates");
        let reader = ControlReadConfig::builder()
            .endpoint_url(ENDPOINT)
            .region(REGION)
            .control_bucket(CONTROL_BUCKET)
            .tenant(TENANT)
            .control_read_credentials(admin_ref)
            .build()
            .expect("a structurally valid reader configuration is not enough");

        let error = reader
            .reject_administration_credential(&admin)
            .expect_err("a reader on the administration credential must be refused");
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
        assert_eq!(
            error.detail(),
            "the control-read identity is the control-administration credential"
        );
        for never_echoed in [admin_ref, "CONTROL_ADMIN_CREDENTIAL_TARGET"] {
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

    // The positive control: distinct references are the ordinary,
    // accepted deployment.
    reader_config()
        .reject_administration_credential(&admin_config())
        .expect("disjoint references compose");
}

#[test]
fn the_reader_scope_denies_every_non_control_prefix() {
    let config = reader_config();
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let denied = [
        // The five non-control namespaces the plan names for this
        // credential: raw, catalog, derived, tombstone, legal-hold.
        format!("tenants/{TENANT}/v1/raw/blobs/zstd-v1/sha256/0123/{digest}.zst"),
        format!("tenants/{TENANT}/v1/raw/occurrences/{CLIENT}/claude-code/sh/ab/{digest}.json"),
        format!("tenants/{TENANT}/v1/raw/attestations/ab/{digest}/{digest}.json"),
        format!("tenants/{TENANT}/v1/catalog/checkpoints/{digest}.json"),
        format!("tenants/{TENANT}/v1/derived/inference/v1/day/2026-09-20/{digest}.json"),
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
        assert!(!config.permits_key(&key), "{key} must be denied");
        // …and the typed seam cannot even express it: derivation is the
        // only way a key enters the reader, and these keys do not derive.
        assert!(
            ControlObjectKey::parse(&key).is_err(),
            "{key} must not parse as a control key"
        );
    }

    // Another tenant's control prefix is the one denied key the typed
    // seam *can* express — a well-formed control layout of a tenant this
    // identity does not provision. The scope model denies it; the store
    // tests below prove the denial holds before any request.
    let foreign = format!("tenants/{OTHER_TENANT}/v1/control/clients/{CLIENT}.json");
    assert!(
        ControlObjectKey::parse(&foreign).is_ok(),
        "the foreign layout is well formed"
    );
    assert!(!config.permits_key(&foreign), "{foreign} must be denied");
}

#[test]
fn the_reader_scope_admits_exactly_the_five_canonical_layouts() {
    let config = reader_config();

    // Inside the prefix, the five canonical layouts are exactly the
    // granted set — and the two independent statements of the scope, the
    // configuration's predicate and the wire-side parser, agree on every
    // one. This is the agreement the store-side gate leans on.
    for (family, key, _) in family_records() {
        let parsed = ControlObjectKey::parse(&key)
            .unwrap_or_else(|e| panic!("{family}: the canonical layout must parse: {e}"));
        assert_eq!(parsed.as_str(), key, "{family}: parse must round-trip");
        assert!(
            config.permits_key(&key),
            "{family}: {key} must be permitted"
        );
    }
}

#[test]
fn records_outside_the_prefix_are_unreachable_through_the_whole_read_surface() {
    let (admin, read, _) = deployment();
    let store = reader_store(read.clone());

    // The backend visibly holds an object in every denied namespace —
    // raw, catalog, derived, tombstone, legal-hold, a foreign tenant's
    // control prefix, and a non-canonical key inside this tenant's own
    // control prefix. None of them may be asked for.
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let off_limits = [
        format!("tenants/{TENANT}/v1/raw/blobs/zstd-v1/sha256/0123/{digest}.zst"),
        format!("tenants/{TENANT}/v1/catalog/checkpoints/{digest}.json"),
        format!("tenants/{TENANT}/v1/derived/inference/v1/day/2026-09-20/{digest}.json"),
        format!("tenants/{TENANT}/v1/tombstones/{CLIENT}/{digest}.json"),
        format!("tenants/{TENANT}/v1/legal-hold/{CLIENT}.json"),
        format!("tenants/{OTHER_TENANT}/v1/control/clients/{CLIENT}.json"),
        format!("tenants/{TENANT}/v1/control/anything-else"),
    ];
    for (index, key) in off_limits.iter().enumerate() {
        admin.preload(key, format!("off-limits marker {index}").as_bytes());
    }

    // Walk the whole read surface — all five trait reads and all five
    // head inspections, over this identity's own tenant. The own-tenant
    // records are absent, so every call answers Ok(None); what the test
    // pins is where the requests went.
    let tenant = tenant_id();
    for (family, result) in drive_every_trait_read(&store, &tenant) {
        let record = result
            .unwrap_or_else(|e| panic!("{family}: the absent record must read as Ok(None): {e}"));
        assert!(record.is_none(), "{family}: nothing is stored yet");
    }
    let heads = [
        block_on(store.head_linked_client(&tenant, &client_id())),
        block_on(store.head_delegation(&tenant, &relay_id(), &client_id())),
        block_on(store.head_revocation(&tenant, &client_id(), epoch())),
        block_on(store.head_rotation(&tenant, &client_id(), epoch())),
        block_on(store.head_receipt_key(&tenant, &receipt_key())),
    ];
    for metadata in heads {
        assert!(
            metadata
                .expect("the absent object must head as Ok(None)")
                .is_none(),
            "nothing is stored yet"
        );
    }

    // Every request stayed inside the provisioned prefix, and none of the
    // off-limits objects was ever asked for.
    let prefix = format!("tenants/{TENANT}/v1/control/");
    let requested = read.requested_keys();
    assert_eq!(requested.len(), 10, "one request per surface method");
    for key in &requested {
        assert!(
            key.starts_with(&prefix),
            "{key} left the provisioned prefix"
        );
        assert!(
            !off_limits.contains(key),
            "{key} is off limits and must never be requested"
        );
    }
}

#[test]
fn another_tenants_records_are_unreachable_even_at_well_formed_control_keys() {
    let (_, read, _) = deployment();
    let store = reader_store(read.clone());

    // The foreign records exist, at well-formed control keys — every one
    // parses as the canonical layout, of a tenant this identity does not
    // provision.
    for (family, key) in foreign_family_keys() {
        assert!(
            ControlObjectKey::parse(&key).is_ok(),
            "{family}: {key} is a well-formed control key"
        );
        read.preload(&key, &linked_client_envelope(OTHER_TENANT, 3));
    }

    // All five reads refuse before any request: the counter is cumulative
    // across the loop, so asserting zero here — per family, not only once
    // at the end — is what makes this a per-family proof: any single
    // family reaching the transport would fail its own iteration, not
    // just the total.
    let foreign = other_tenant_id();
    for (family, result) in drive_every_trait_read(&store, &foreign) {
        let error = result.expect_err("a foreign-tenant read must be refused");
        assert_eq!(error.kind(), StorageErrorKind::ScopeViolation, "{family}");
        assert_eq!(error.detail(), SCOPE_DETAIL, "{family}");
        assert_eq!(read.requests(), 0, "no request may be issued");
    }
    let foreign_heads = [
        block_on(store.head_linked_client(&foreign, &client_id())),
        block_on(store.head_delegation(&foreign, &relay_id(), &client_id())),
        block_on(store.head_revocation(&foreign, &client_id(), epoch())),
        block_on(store.head_rotation(&foreign, &client_id(), epoch())),
        block_on(store.head_receipt_key(&foreign, &receipt_key())),
    ];
    for error in foreign_heads {
        let error = error.expect_err("a foreign-tenant head must be refused");
        assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
        assert_eq!(error.detail(), SCOPE_DETAIL);
        assert_eq!(read.requests(), 0, "no request may be issued");
    }

    // The positive control: the same reads under this identity's own
    // tenant reach the transport and simply find absence.
    let own = tenant_id();
    for (family, result) in drive_every_trait_read(&store, &own) {
        let record = result.unwrap_or_else(|e| panic!("{family}: the read must reach: {e}"));
        assert!(record.is_none(), "{family}: nothing is stored here either");
    }
    assert!(read.requests() > 0, "own-tenant reads are issued");

    // And the read-only credential's own backend policy denies the
    // well-formed foreign key for both of its verbs — the scope is
    // enforced twice, store-side before any request and again at the
    // policy, the way a real deployment's IAM statement would.
    let foreign_key = ControlObjectKey::parse(&format!(
        "tenants/{OTHER_TENANT}/v1/control/clients/{CLIENT}.json"
    ))
    .expect("a foreign control key is still a control key");
    let error = block_on(read.clone().get_control_object(&foreign_key))
        .expect_err("the policy denies another tenant's prefix");
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
    let error = block_on(read.head_control_object(&foreign_key))
        .expect_err("the policy denies another tenant's prefix");
    assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
    assert_eq!(read.denials(), 2);
}

#[test]
fn the_split_holds_end_to_end_replica_reads_what_the_administrator_wrote() {
    let (admin, read, _) = deployment();
    let admin_store = S3ControlAdminStore::new(admin_config(), admin.clone());
    let store = reader_store(read.clone());

    // The administrator writes the linked-client pointer at its derived
    // key, inside the one provisioned prefix.
    let pointer_key = format!("tenants/{TENANT}/v1/control/clients/{CLIENT}.json");
    let written = linked_client_envelope(TENANT, 1);
    block_on(admin_store.put_current_pointer(&AdminControlRecord::new(
        ControlRecordKind::LinkedClient,
        written.clone(),
    )))
    .expect("the administrator writes the linked-client pointer");

    // The replica reads exactly that record, byte for byte, at the key
    // both surfaces derive the same way — the agreement the scope gate
    // leans on. This is the one thing the read identity is for.
    let record = block_on(store.read_linked_client(&tenant_id(), &client_id()))
        .expect("the written record must read")
        .expect("the administrator's pointer must be present");
    assert_eq!(record.envelope(), written.as_slice(), "byte-exact handover");

    // The head carries the observation evidence without the body.
    let metadata = block_on(store.head_linked_client(&tenant_id(), &client_id()))
        .expect("the head must succeed")
        .expect("the pointer must be present");
    assert_eq!(metadata.size(), written.len() as u64);

    // And nothing the replica did moved the stored record: one put in
    // total, the administrator's; the bytes unchanged after the reads.
    // The reader has no write verb — the compile-time pins on the store
    // say so — and this is the runtime half of that statement.
    assert_eq!(admin.puts(), 1, "only the administrator's write may land");
    assert_eq!(
        admin.puts_at(&pointer_key),
        1,
        "the administrator's write is the pointer write"
    );
    assert_eq!(
        admin.stored(&pointer_key).as_deref(),
        Some(written.as_slice())
    );

    // Every read-side request stayed inside the provisioned prefix, and
    // the reader's own scope model admits the key the administrator
    // wrote — the two surfaces' derivations cannot drift.
    let prefix = format!("tenants/{TENANT}/v1/control/");
    for key in read.requested_keys() {
        assert!(
            key.starts_with(&prefix),
            "{key} left the provisioned prefix"
        );
    }
    assert!(
        reader_config().permits_key(&pointer_key),
        "the reader scope must admit the written record's key"
    );
}
