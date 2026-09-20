// SPDX-License-Identifier: Apache-2.0

//! The ingestion replica's control-read authority of the S3 adapter (plan
//! Section 5): [`S3ControlReadStore`], the portable implementation of
//! [`ControlReadStore`] over a dedicated read-only credential.
//!
//! This is the read half of the control-plane boundary. The administrator
//! CLI writes the five signed record families through
//! [`crate::control_admin::S3ControlAdminStore`] and never shares its
//! credential; the replica reads them through this store and can neither
//! publish, retract, nor enumerate a record. Everything here is shaped
//! around that split:
//!
//! - **A reader composed from a reader configuration.** The store is
//!   configured from a [`ControlReadConfig`] — the surface
//!   [`crate::config`] validates with its own dedicated credential
//!   reference, its own one-tenant scope, and
//!   [`reject_administration_credential`](crate::config::ControlReadConfig::reject_administration_credential)
//!   refusing the one composition mistake that would collapse the split.
//!   The only credential this type can name is that read reference: there
//!   is no write, delete, or list method on the store, and no method takes
//!   a raw object key.
//! - **Derived keys, one method per family.** Each read and each head
//!   derives its object key from validated identifiers through
//!   [`ControlObjectKey`] — the same grammar the administration store
//!   derives its writes from, which is the property that makes a record
//!   the administrator wrote findable by the replica. The five
//!   [`ControlReadStore`] families are the whole read surface; there is no
//!   `read(key)` escape hatch, so the read authority cannot be pointed at
//!   an arbitrary object.
//! - **Bounded GETs, classified oversize.** A record larger than the
//!   pinned canonical-document maximum ([`CANONICAL_MAX_BYTES`], the same
//!   bound the wire envelope and the raw manifest paths pin) is a
//!   [`StorageErrorKind::MalformedInput`] classification — never a
//!   truncated acceptance. Absent records are `Ok(None)`: an unlinked
//!   client and a client with no delegation are ordinary states, not
//!   errors.
//! - **Structure at the boundary, trust at the consumer.** Every GET
//!   result is routed through the same structural validation the
//!   administration store writes with
//!   ([`validate_envelope`](crate::control_admin::validate_envelope)):
//!   the family token in the closed v1 registry, the declared write class,
//!   every member the key derivation leans on, and the presence and shape
//!   of the authority-signature members. A structurally invalid object
//!   never leaves this store as a record — truncated bytes, an unknown
//!   family token, a wrong schema version, or a record whose members
//!   derive another key is a [`StorageErrorKind::MalformedInput`], an
//!   envelope naming another tenant is a
//!   [`StorageErrorKind::ScopeViolation`], and no failure echoes record
//!   content. What the reader deliberately does not do is decide trust:
//!   the tenant-authority signature is never verified here, and failing
//!   closed on a bad signature, a stale epoch, or an expired cache entry
//!   stays the consumer's contract (`EC-09`), applied over the
//!   observation metadata this store surfaces.
//! - **Scope before the network.** Every request path checks the derived
//!   key against the provisioned tenant —
//!   [`permits_key`](crate::config::ControlReadConfig::permits_key) —
//!   before any call is issued, so a key outside this identity's one
//!   control prefix is refused locally as
//!   [`StorageErrorKind::ScopeViolation`]. Backend and network failures
//!   arrive as [`StorageErrorKind::Unavailable`] from the seam and pass
//!   through unchanged.
//! - **HEAD for the cache metadata.** Alongside the five reads, the store
//!   exposes the five per-family head inspections: stored size and the
//!   observation evidence (commitment tag, storage version, observation
//!   time) without the body — the metadata the read boundary's
//!   [`ControlRecord`] carries and cache-bounded consumers need, at the
//!   cost of no envelope transfer.

use std::future::Future;

use archivist_protocol::envelope::CANONICAL_MAX_BYTES;
use archivist_protocol::vocabulary::{ClientId, KeyId, TenantId};
use archivist_storage::audit_restore::{ObjectBody, ObjectMetadata};
use archivist_storage::control::{AuthorizationEpoch, ControlReadStore, ControlRecord};
use archivist_storage::error::{StorageError, StorageErrorKind};

use crate::config::ControlReadConfig;
use crate::control_admin::{validate_envelope, ControlObjectKey};

// Content-safe detail literals, one static sentence per failure site. A
// unit test pins them against the protocol's safe-message grammar, the
// same discipline the sibling stores keep.
const DETAIL_SCOPE: &str = "key tenant is outside this control-read identity";
const DETAIL_OVERSIZE: &str = "control record exceeds the canonical document bound";
const DETAIL_RECORD_TENANT: &str = "record tenant is outside this control-read identity";
const DETAIL_KEY_MISMATCH: &str = "stored record does not derive the requested key";

/// The S3 request seam of the control-read identity: the two object
/// primitives the read-only credential needs, keyed by the derived
/// [`ControlObjectKey`] only.
///
/// The trait is deliberately narrower than an S3 client: there is no put,
/// no delete, no list, no multipart, no arbitrary-key method, and no
/// bucket-level call — the provisioned credential holds read-only access
/// below the tenant control prefix and nothing else, so this is the
/// entire surface that authority has. A concrete binding (the reference
/// profile's HTTP client over the control-read credential) implements the
/// two operations over `GetObject` and `HeadObject` and enforces the same
/// prefix scope the deployment's backend policy states: read below
/// `tenants/<tenant>/v1/control/`, deny every other prefix. The mock in
/// this module's tests mirrors that denial so the store's requests are
/// proven to stay inside it.
pub trait ControlReadBackend {
    /// Read the stored bytes at one derived control key, with the
    /// observation evidence the body was read under.
    ///
    /// [`None`] is the absent object — a `404` from the real binding, an
    /// empty slot in a test double.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the key is outside
    /// this credential's provisioned prefix.
    fn get_control_object(
        &self,
        key: &ControlObjectKey,
    ) -> impl Future<Output = Result<Option<ObjectBody>, StorageError>> + Send;

    /// Inspect one derived control key without reading its body: stored
    /// size and the observation evidence, the HEAD pair of
    /// [`Self::get_control_object`].
    ///
    /// [`None`] is the absent object, as in [`Self::get_control_object`].
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the key is outside
    /// this credential's provisioned prefix.
    fn head_control_object(
        &self,
        key: &ControlObjectKey,
    ) -> impl Future<Output = Result<Option<ObjectMetadata>, StorageError>> + Send;
}

/// The portable S3 [`ControlReadStore`]: one control-read configuration,
/// one backend seam, and the scope gates that keep every request inside
/// the provisioned tenant's control prefix.
///
/// Composed once by the ingest replica's configuration root and handed to
/// [`archivist_storage::ingest::IngestStorage::compose`] as the control
/// half beside the raw writer. The store hands over structurally
/// validated bytes: an object that does not parse as a complete signed
/// record of the family its derived key names, inside this identity's one
/// tenant, never leaves the boundary as a record. Trust is not decided
/// here — failing closed on a bad signature, a stale epoch, or an expired
/// cache entry is the consumer's contract (`EC-09`), which applies its
/// 60-second trust-cache policy over the surfaced observation metadata.
pub struct S3ControlReadStore<B> {
    config: ControlReadConfig,
    backend: B,
}

impl<B> S3ControlReadStore<B> {
    /// Compose the control-read authority: the validated configuration
    /// (its credential reference and pinned tenant) over one backend seam.
    #[must_use]
    pub const fn new(config: ControlReadConfig, backend: B) -> Self {
        Self { config, backend }
    }

    /// The control-read configuration this store was composed with.
    #[must_use]
    pub const fn config(&self) -> &ControlReadConfig {
        &self.config
    }
}

impl<B: ControlReadBackend + Sync> S3ControlReadStore<B> {
    /// Inspect the linked-client record for one installation without
    /// reading its body: stored size and observation evidence.
    ///
    /// # Errors
    /// [`StorageErrorKind::ScopeViolation`] when `tenant` is outside this
    /// identity's provisioning (refused before any request);
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down.
    pub async fn head_linked_client(
        &self,
        tenant: &TenantId,
        client: &ClientId,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        self.inspect(ControlObjectKey::linked_client(tenant, client))
            .await
    }

    /// Inspect the delegation record granting `relay` authority over
    /// `origin` without reading its body.
    ///
    /// # Errors
    /// As [`S3ControlReadStore::head_linked_client`].
    pub async fn head_delegation(
        &self,
        tenant: &TenantId,
        relay: &ClientId,
        origin: &ClientId,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        self.inspect(ControlObjectKey::delegation(tenant, relay, origin))
            .await
    }

    /// Inspect one revocation record at an exact authorization epoch
    /// without reading its body.
    ///
    /// # Errors
    /// As [`S3ControlReadStore::head_linked_client`].
    pub async fn head_revocation(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        epoch: AuthorizationEpoch,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        self.inspect(ControlObjectKey::revocation(tenant, client, epoch))
            .await
    }

    /// Inspect one rotation record at an exact authorization epoch
    /// without reading its body.
    ///
    /// # Errors
    /// As [`S3ControlReadStore::head_linked_client`].
    pub async fn head_rotation(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        epoch: AuthorizationEpoch,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        self.inspect(ControlObjectKey::rotation(tenant, client, epoch))
            .await
    }

    /// Inspect the receipt-key record for one verification key without
    /// reading its body.
    ///
    /// # Errors
    /// As [`S3ControlReadStore::head_linked_client`].
    pub async fn head_receipt_key(
        &self,
        tenant: &TenantId,
        key: &KeyId,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        self.inspect(ControlObjectKey::receipt_key(tenant, key))
            .await
    }

    /// Gate one derived key against the provisioned scope, then head it.
    async fn inspect(&self, key: ControlObjectKey) -> Result<Option<ObjectMetadata>, StorageError> {
        self.authorize(&key)?;
        self.backend.head_control_object(&key).await
    }

    /// The backend permission model, enforced store-side before any
    /// request is issued: the derived key must name this configuration's
    /// one tenant and sit inside the control prefix
    /// [`ControlReadConfig::permits_key`] admits. Unreachable while the
    /// key derivation and the scope model agree — which is exactly the
    /// agreement a drift between the two must fail closed on, before the
    /// read-only credential is pointed anywhere.
    fn authorize(&self, key: &ControlObjectKey) -> Result<(), StorageError> {
        if key.tenant() != self.config.tenant() || !self.config.permits_key(key.as_str()) {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        Ok(())
    }
}

impl<B: ControlReadBackend + Sync> ControlReadStore for S3ControlReadStore<B> {
    async fn read_linked_client(
        &self,
        tenant: &TenantId,
        client: &ClientId,
    ) -> Result<Option<ControlRecord>, StorageError> {
        self.read(ControlObjectKey::linked_client(tenant, client))
            .await
    }

    async fn read_delegation(
        &self,
        tenant: &TenantId,
        relay: &ClientId,
        origin: &ClientId,
    ) -> Result<Option<ControlRecord>, StorageError> {
        self.read(ControlObjectKey::delegation(tenant, relay, origin))
            .await
    }

    async fn read_revocation(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        epoch: AuthorizationEpoch,
    ) -> Result<Option<ControlRecord>, StorageError> {
        self.read(ControlObjectKey::revocation(tenant, client, epoch))
            .await
    }

    async fn read_rotation(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        epoch: AuthorizationEpoch,
    ) -> Result<Option<ControlRecord>, StorageError> {
        self.read(ControlObjectKey::rotation(tenant, client, epoch))
            .await
    }

    async fn read_receipt_key(
        &self,
        tenant: &TenantId,
        key: &KeyId,
    ) -> Result<Option<ControlRecord>, StorageError> {
        self.read(ControlObjectKey::receipt_key(tenant, key)).await
    }
}

impl<B: ControlReadBackend + Sync> S3ControlReadStore<B> {
    /// Gate one derived key, GET it, and validate it at the boundary —
    /// absent is `Ok(None)`; oversize is a classification, never a
    /// truncated acceptance; a structurally invalid envelope never reaches
    /// the caller as a record. What is handed over is the byte-exact
    /// object with its observation: structurally sound (family, version,
    /// key derivation, tenant, signature members), with signature and
    /// trust verification still the consumer's contract (`EC-09`).
    async fn read(&self, key: ControlObjectKey) -> Result<Option<ControlRecord>, StorageError> {
        self.authorize(&key)?;
        let Some(body) = self.backend.get_control_object(&key).await? else {
            return Ok(None);
        };
        if body.bytes().len() > CANONICAL_MAX_BYTES {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_OVERSIZE,
            ));
        }
        let validated = validate_envelope(body.bytes())?;
        if validated.tenant() != self.config.tenant() {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_RECORD_TENANT,
            ));
        }
        if validated.key() != &key {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_KEY_MISMATCH,
            ));
        }
        Ok(Some(ControlRecord::new(
            body.bytes().to_vec(),
            body.observation().clone(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use archivist_protocol::json::{self, Object, Value};
    use archivist_protocol::vocabulary::{Ed25519PublicKey, KeyId as KeyIdType, SafeMessage};
    use archivist_storage::audit_restore::ObjectBody;
    use archivist_storage::metadata::{ObjectTag, Observation, StorageVersionId};

    use super::{
        AuthorizationEpoch, CANONICAL_MAX_BYTES, ClientId, ControlObjectKey, ControlReadBackend,
        ControlReadStore, DETAIL_KEY_MISMATCH, DETAIL_OVERSIZE, DETAIL_RECORD_TENANT,
        DETAIL_SCOPE, S3ControlReadStore, StorageError, StorageErrorKind, TenantId,
    };
    use crate::config::ControlReadConfig;

    // The golden identifiers shared with the sibling boundary suites, so
    // every layer of this boundary tells one story.
    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
    const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";
    const OTHER_CLIENT: &str = "99999999-8888-4777-8666-555555555555";
    const RELAY: &str = "2b1a0f9e-8d7c-4e6b-9a5f-1e2d3c4b5a69";
    const READ_REF: &str = "file:/etc/archivist/storage/control-read-credentials";
    const CONTROL_BUCKET: &str = "archivist-control-example";
    const OBSERVED: &str = "2026-09-19T12:00:00Z";
    const ETAG: &str = "\"d41d8cd98f00b204e9800998ecf8427e\"";
    const VERSION: &str = "3sL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo";
    const SIGNED_AT: &str = "2026-09-11T00:00:00Z";

    fn tenant() -> TenantId {
        TENANT.parse().unwrap()
    }

    fn other_tenant() -> TenantId {
        OTHER_TENANT.parse().unwrap()
    }

    fn client() -> ClientId {
        CLIENT.parse().unwrap()
    }

    fn relay() -> ClientId {
        RELAY.parse().unwrap()
    }

    fn epoch() -> AuthorizationEpoch {
        AuthorizationEpoch::new(3).unwrap()
    }

    fn receipt_key() -> KeyIdType {
        KeyIdType::parse(&key_id_of(&[0x3c; 32])).unwrap()
    }

    fn key_id_of(raw: &[u8; 32]) -> String {
        let public = Ed25519PublicKey::from_raw(*raw);
        KeyIdType::from_public_key(&public).to_hex()
    }

    // -------------------------------------------------------------------
    // Golden control envelopes — the same canonical shape the sibling
    // administration-store suite writes with, so what that store proves
    // addressable is exactly what this boundary accepts as a record.
    // -------------------------------------------------------------------

    fn signature_hex() -> String {
        "00".repeat(64)
    }

    fn authority_key_id() -> String {
        key_id_of(&[0xab; 32])
    }

    /// Canonical envelope bytes from ordered members (the builder upserts,
    /// and canonical output sorts, so call sites read in any order).
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

    /// The wrapper members every control record carries, with the family's
    /// own type and kind tokens.
    fn wrapper(record_type: &str, record_kind: &str, tenant: &str) -> Vec<(&'static str, Value)> {
        vec![
            ("schema", text("archivist.control/v1")),
            ("record_type", text(record_type)),
            ("record_kind", text(record_kind)),
            ("tenant_id", text(tenant)),
            ("signed_at", text(SIGNED_AT)),
            ("authority_key_id", text(&authority_key_id())),
            ("authority_signature", text(&signature_hex())),
        ]
    }

    fn linked_client_envelope(tenant: &str, client: &str, epoch: i64) -> Vec<u8> {
        let mut members = wrapper("linked-client", "current-pointer", tenant);
        members.extend([
            ("client_id", text(client)),
            ("key_id", text(&key_id_of(&[0xcd; 32]))),
            ("key_algorithm", text("ed25519")),
            ("public_key", text(&"cd".repeat(32))),
            ("authorization_epoch", Value::Int(epoch)),
        ]);
        envelope(&members)
    }

    fn delegation_envelope(tenant: &str, relay: &str, origin: &str, epoch: i64) -> Vec<u8> {
        let mut members = wrapper("delegation", "current-pointer", tenant);
        members.extend([
            ("relay_client_id", text(relay)),
            ("origin_client_id", text(origin)),
            ("delegation_state", text("active")),
            ("authorization_epoch", Value::Int(epoch)),
        ]);
        envelope(&members)
    }

    fn revocation_envelope(tenant: &str, client: &str, epoch: i64) -> Vec<u8> {
        let mut members = wrapper("revocation", "immutable", tenant);
        members.extend([
            ("client_id", text(client)),
            ("revoked_key_id", text(&key_id_of(&[0xcd; 32]))),
            ("authorization_epoch", Value::Int(epoch)),
        ]);
        envelope(&members)
    }

    fn rotation_envelope(tenant: &str, client: &str, epoch: i64) -> Vec<u8> {
        let mut members = wrapper("rotation", "immutable", tenant);
        members.extend([
            ("client_id", text(client)),
            ("previous_epoch", Value::Int(epoch - 1)),
            ("previous_public_key", text(&"ef".repeat(32))),
            ("previous_key_id", text(&key_id_of(&[0xef; 32]))),
            ("key_algorithm", text("ed25519")),
            ("public_key", text(&"cd".repeat(32))),
            ("key_id", text(&key_id_of(&[0xcd; 32]))),
            ("authorization_epoch", Value::Int(epoch)),
        ]);
        envelope(&members)
    }

    fn receipt_key_envelope(tenant: &str) -> Vec<u8> {
        let mut members = wrapper("receipt-key", "immutable", tenant);
        members.extend([
            ("key_id", text(&key_id_of(&[0x3c; 32]))),
            ("key_algorithm", text("ed25519")),
            ("public_key", text(&"3c".repeat(32))),
            ("valid_from", text("2026-09-04T00:00:00Z")),
            ("valid_until", text("2026-10-11T00:00:00Z")),
        ]);
        envelope(&members)
    }

    /// Replace one top-level text/int member of an envelope (test helper:
    /// re-parse, set, re-serialize canonically).
    fn replace_member(bytes: &[u8], name: &str, value: Value) -> Vec<u8> {
        let Value::Object(mut object) = json::parse(bytes).unwrap() else {
            panic!("test envelopes are objects");
        };
        object.set(name, value);
        Value::Object(object).canonical_bytes()
    }

    /// Drop one top-level member of an envelope.
    fn without_member(bytes: &[u8], name: &str) -> Vec<u8> {
        let Value::Object(mut object) = json::parse(bytes).unwrap() else {
            panic!("test envelopes are objects");
        };
        let _ = object.remove(name);
        Value::Object(object).canonical_bytes()
    }

    fn observation() -> Observation {
        Observation::new(
            Some(ObjectTag::parse(ETAG).unwrap()),
            Some(StorageVersionId::parse(VERSION).unwrap()),
            archivist_protocol::vocabulary::Timestamp::parse(OBSERVED).unwrap(),
        )
    }

    fn read_config() -> ControlReadConfig {
        ControlReadConfig::builder()
            .endpoint_url("https://s3.example.invalid")
            .region("us-east-1")
            .control_bucket(CONTROL_BUCKET)
            .tenant(TENANT)
            .control_read_credentials(READ_REF)
            .build()
            .expect("golden control-read configuration validates")
    }

    /// A no-dependency executor for futures that complete without pending
    /// (the same helper the sibling store tests use).
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

    /// The in-memory transport: an object map plus the prefix denial the
    /// deployment's control-read policy states — read below
    /// `tenants/<tenant>/v1/control/`, deny everything else — with the
    /// two verbs counted separately so a test can prove which primitive a
    /// read or a head actually issued, and that a refused key issued
    /// nothing at all.
    #[derive(Clone, Debug)]
    struct MapBackend {
        control_prefix: String,
        objects: Arc<Mutex<HashMap<String, ObjectBody>>>,
        requests: Arc<Mutex<u32>>,
        gets: Arc<Mutex<u32>>,
        heads: Arc<Mutex<u32>>,
        requested_keys: Arc<Mutex<Vec<String>>>,
        fault: Arc<Mutex<Option<StorageErrorKind>>>,
    }

    impl MapBackend {
        fn new(tenant: &TenantId) -> Self {
            Self {
                control_prefix: format!("tenants/{tenant}/v1/control/"),
                objects: Arc::new(Mutex::new(HashMap::new())),
                requests: Arc::new(Mutex::new(0)),
                gets: Arc::new(Mutex::new(0)),
                heads: Arc::new(Mutex::new(0)),
                requested_keys: Arc::new(Mutex::new(Vec::new())),
                fault: Arc::new(Mutex::new(None)),
            }
        }

        /// How many requests reached this transport at all, granted or
        /// refused — the counter a refused-before-any-request proof holds
        /// at zero.
        fn requests(&self) -> u32 {
            *self.requests.lock().expect("test transport lock")
        }

        /// How many GETs this transport issued.
        fn gets(&self) -> u32 {
            *self.gets.lock().expect("test transport lock")
        }

        /// How many HEADs this transport issued.
        fn heads(&self) -> u32 {
            *self.heads.lock().expect("test transport lock")
        }

        /// Every key this transport was asked about, in order.
        fn requested_keys(&self) -> Vec<String> {
            self.requested_keys
                .lock()
                .expect("test transport lock")
                .clone()
        }

        /// Make both verbs fail with `kind` until cleared — the injected
        /// backend or network outage.
        fn fail_with(&self, kind: StorageErrorKind) {
            *self.fault.lock().expect("test transport lock") = Some(kind);
        }

        /// The deployment policy for the control-read credential, as a
        /// grant predicate over one object key.
        fn policy_permits(&self, key: &str) -> bool {
            key.starts_with(&self.control_prefix)
        }

        fn preload(&self, key: &ControlObjectKey, bytes: &[u8]) {
            self.objects.lock().expect("test transport lock").insert(
                key.as_str().to_owned(),
                ObjectBody::new(bytes.to_vec(), observation()),
            );
        }
    }

    impl ControlReadBackend for MapBackend {
        async fn get_control_object(
            &self,
            key: &ControlObjectKey,
        ) -> Result<Option<ObjectBody>, StorageError> {
            *self.requests.lock().expect("test transport lock") += 1;
            *self.gets.lock().expect("test transport lock") += 1;
            self.requested_keys
                .lock()
                .expect("test transport lock")
                .push(key.as_str().to_owned());
            if let Some(kind) = *self.fault.lock().expect("test transport lock") {
                return Err(StorageError::of_kind(kind));
            }
            if !self.policy_permits(key.as_str()) {
                return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
            }
            Ok(self
                .objects
                .lock()
                .expect("test transport lock")
                .get(key.as_str())
                .cloned())
        }

        async fn head_control_object(
            &self,
            key: &ControlObjectKey,
        ) -> Result<Option<super::ObjectMetadata>, StorageError> {
            *self.requests.lock().expect("test transport lock") += 1;
            *self.heads.lock().expect("test transport lock") += 1;
            self.requested_keys
                .lock()
                .expect("test transport lock")
                .push(key.as_str().to_owned());
            if let Some(kind) = *self.fault.lock().expect("test transport lock") {
                return Err(StorageError::of_kind(kind));
            }
            if !self.policy_permits(key.as_str()) {
                return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
            }
            Ok(self
                .objects
                .lock()
                .expect("test transport lock")
                .get(key.as_str())
                .map(|body| {
                    super::ObjectMetadata::new(
                        body.bytes().len() as u64,
                        body.observation().clone(),
                    )
                }))
        }
    }

    fn store() -> S3ControlReadStore<MapBackend> {
        S3ControlReadStore::new(read_config(), MapBackend::new(&tenant()))
    }

    /// The five (identifiers, derived key, stored bytes) rows one story
    /// is told with: every read method, its family's key, and the
    /// structurally valid golden envelope of that family that derives
    /// exactly that key.
    fn families() -> Vec<(&'static str, ControlObjectKey, Vec<u8>)> {
        let tenant = tenant();
        let client_id = client();
        let relay_id = relay();
        let receipt = receipt_key();
        let epoch_value = epoch();
        vec![
            (
                "linked-client",
                ControlObjectKey::linked_client(&tenant, &client_id),
                linked_client_envelope(TENANT, CLIENT, 3),
            ),
            (
                "delegation",
                ControlObjectKey::delegation(&tenant, &relay_id, &client_id),
                delegation_envelope(TENANT, RELAY, CLIENT, 3),
            ),
            (
                "revocation",
                ControlObjectKey::revocation(&tenant, &client_id, epoch_value),
                revocation_envelope(TENANT, CLIENT, 3),
            ),
            (
                "rotation",
                ControlObjectKey::rotation(&tenant, &client_id, epoch_value),
                rotation_envelope(TENANT, CLIENT, 3),
            ),
            (
                "receipt-key",
                ControlObjectKey::receipt_key(&tenant, &receipt),
                receipt_key_envelope(TENANT),
            ),
        ]
    }

    #[test]
    fn reads_return_the_stored_envelope_with_its_observation() {
        let store = store();
        let (name, key, bytes) = &families()[0];
        store.backend.preload(key, bytes);

        let record = block_on(store.read_linked_client(&tenant(), &client()))
            .expect("the stored record must read")
            .unwrap_or_else(|| panic!("{name}: the preloaded record must be present"));
        assert_eq!(record.envelope(), bytes.as_slice(), "byte-exact handover");
        let observed = record.observation();
        assert_eq!(observed.etag().map(ObjectTag::as_str), Some(ETAG));
        assert_eq!(
            observed
                .storage_version()
                .map(archivist_storage::metadata::StorageVersionId::as_str),
            Some(VERSION)
        );
        assert_eq!(observed.observed_at().as_str(), OBSERVED);
        assert_eq!(store.backend.gets(), 1);
        assert_eq!(store.backend.heads(), 0, "a read never heads first");
    }

    #[test]
    fn every_family_reads_its_own_derived_key() {
        let store = store();
        for (_, key, bytes) in families() {
            store.backend.preload(&key, &bytes);
        }

        let receipt = receipt_key();
        let epoch_value = epoch();
        let mut requested = 0;
        for (name, expected_key, bytes) in families() {
            let record = match name {
                "linked-client" => block_on(store.read_linked_client(&tenant(), &client())),
                "delegation" => block_on(store.read_delegation(&tenant(), &relay(), &client())),
                "revocation" => block_on(store.read_revocation(&tenant(), &client(), epoch_value)),
                "rotation" => block_on(store.read_rotation(&tenant(), &client(), epoch_value)),
                "receipt-key" => block_on(store.read_receipt_key(&tenant(), &receipt)),
                other => panic!("unexpected family {other}"),
            }
            .unwrap_or_else(|e| panic!("{name}: the stored record must read: {e}"))
            .unwrap_or_else(|| panic!("{name}: the preloaded record must be present"));
            assert_eq!(record.envelope(), bytes.as_slice(), "{name}");
            assert_eq!(
                store.backend.requested_keys().get(requested),
                Some(expected_key.as_str().to_owned()).as_ref(),
                "{name}: the read must target the family's derived key"
            );
            requested += 1;
        }
        assert_eq!(requested, 5, "all five families read");
        assert_eq!(store.backend.gets(), 5, "one GET per family");
    }

    #[test]
    fn absent_records_read_as_ok_none() {
        let store = store();
        let receipt = receipt_key();
        let epoch_value = epoch();

        assert!(
            block_on(store.read_linked_client(&tenant(), &client()))
                .expect("absent must not error")
                .is_none()
        );
        assert!(
            block_on(store.read_delegation(&tenant(), &relay(), &client()))
                .expect("absent must not error")
                .is_none()
        );
        assert!(
            block_on(store.read_revocation(&tenant(), &client(), epoch_value))
                .expect("absent must not error")
                .is_none()
        );
        assert!(
            block_on(store.read_rotation(&tenant(), &client(), epoch_value))
                .expect("absent must not error")
                .is_none()
        );
        assert!(
            block_on(store.read_receipt_key(&tenant(), &receipt))
                .expect("absent must not error")
                .is_none()
        );
        assert_eq!(store.backend.gets(), 5, "absence is a decided GET");
    }

    #[test]
    fn out_of_tenant_reads_are_refused_before_any_request() {
        let store = store();
        let receipt = receipt_key();
        let epoch_value = epoch();

        let refused = [
            block_on(store.read_linked_client(&other_tenant(), &client())),
            block_on(store.read_delegation(&other_tenant(), &relay(), &client())),
            block_on(store.read_revocation(&other_tenant(), &client(), epoch_value)),
            block_on(store.read_rotation(&other_tenant(), &client(), epoch_value)),
            block_on(store.read_receipt_key(&other_tenant(), &receipt)),
        ];
        for result in refused {
            let error = result.expect_err("an out-of-tenant read must be refused");
            assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
            assert_eq!(error.detail(), DETAIL_SCOPE);
        }
        let refused_head = block_on(store.head_linked_client(&other_tenant(), &client()))
            .expect_err("an out-of-tenant head must be refused");
        assert_eq!(refused_head.kind(), StorageErrorKind::ScopeViolation);
        assert_eq!(refused_head.detail(), DETAIL_SCOPE);
        assert_eq!(
            store.backend.requests(),
            0,
            "the refusal happens before any request"
        );

        // The positive control: the same reads under this identity's own
        // tenant reach the transport and simply find absence.
        assert!(
            block_on(store.read_linked_client(&tenant(), &client()))
                .expect("in-scope read")
                .is_none()
        );
        assert!(store.backend.requests() > 0);
    }

    /// A structurally valid linked-client record of exactly the pinned
    /// canonical maximum: an extra payload member carries the filler, so
    /// the bound itself is proven to be acceptance of a whole record, not
    /// merely of a byte count.
    fn at_bound_envelope() -> Vec<u8> {
        let Value::Object(mut object) =
            json::parse(&linked_client_envelope(TENANT, CLIENT, 3)).unwrap()
        else {
            panic!("the golden envelope is an object");
        };
        // `"padding":""` costs 13 canonical bytes; each filler char adds one.
        let filler = CANONICAL_MAX_BYTES - linked_client_envelope(TENANT, CLIENT, 3).len() - 13;
        assert!(filler > 0, "the golden envelope leaves room to pad");
        object.set("padding", text(&"p".repeat(filler)));
        let bytes = Value::Object(object).canonical_bytes();
        assert_eq!(bytes.len(), CANONICAL_MAX_BYTES);
        bytes
    }

    #[test]
    fn oversize_records_are_classified_never_accepted() {
        let store = store();
        let (name, key, _) = &families()[0];

        let oversized = vec![b'x'; CANONICAL_MAX_BYTES + 1];
        store.backend.preload(key, &oversized);
        let error = block_on(store.read_linked_client(&tenant(), &client()))
            .expect_err("an oversize record must be refused, never truncated");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(error.detail(), DETAIL_OVERSIZE);

        // The bound itself is acceptance: a record of exactly the pinned
        // maximum — a valid one — is handed over whole.
        let at_bound = at_bound_envelope();
        store.backend.preload(key, &at_bound);
        let record = block_on(store.read_linked_client(&tenant(), &client()))
            .expect("a record at the bound must read")
            .unwrap_or_else(|| panic!("{name}: the preloaded record must be present"));
        assert_eq!(record.envelope().len(), CANONICAL_MAX_BYTES);
        assert_eq!(record.envelope(), at_bound.as_slice());
    }

    /// Every structural failure classifies, and no failure echoes record
    /// content: the detail is a safe message that names no identifier the
    /// stored bytes carried.
    fn assert_boundary_rejection(
        store: &S3ControlReadStore<MapBackend>,
        key: &ControlObjectKey,
        case: &str,
        bytes: &[u8],
        kind: StorageErrorKind,
    ) {
        store.backend.preload(key, bytes);
        let error = block_on(store.read_linked_client(&tenant(), &client()))
            .err()
            .unwrap_or_else(|| {
                panic!("linked-client/{case}: an invalid envelope must never read as a record")
            });
        assert_eq!(error.kind(), kind, "linked-client/{case}");
        assert_eq!(
            SafeMessage::parse(error.detail()).map(|_| ()).ok(),
            Some(()),
            "linked-client/{case}: the detail must be a safe message"
        );
        assert!(
            !error.detail().contains(CLIENT) && !error.detail().contains(TENANT),
            "linked-client/{case}: the detail must not echo record content"
        );
    }

    #[test]
    fn structurally_invalid_envelopes_never_read_as_records() {
        let store = store();
        let (_, key, _) = &families()[0];
        let linked = linked_client_envelope(TENANT, CLIENT, 3);

        // Truncated JSON, not JSON at all, not an object.
        assert_boundary_rejection(
            &store,
            key,
            "truncated json",
            b"{\"schema\":\"archivist.control/v1\"",
            StorageErrorKind::MalformedInput,
        );
        assert_boundary_rejection(
            &store,
            key,
            "not json",
            b"not json",
            StorageErrorKind::MalformedInput,
        );
        assert_boundary_rejection(
            &store,
            key,
            "not an object",
            b"[1,2,3]",
            StorageErrorKind::MalformedInput,
        );

        // A schema version outside the closed v1 registry.
        assert_boundary_rejection(
            &store,
            key,
            "wrong schema version",
            &replace_member(&linked, "schema", text("archivist.control/v2")),
            StorageErrorKind::MalformedInput,
        );

        // A family token with no variant in the closed registry — the
        // retention record is shipped in the registry but has not landed
        // as a family — and a declared kind its family disagrees with.
        assert_boundary_rejection(
            &store,
            key,
            "unknown family token",
            &replace_member(&linked, "record_type", text("retention")),
            StorageErrorKind::MalformedInput,
        );
        assert_boundary_rejection(
            &store,
            key,
            "kind disagrees with family",
            &replace_member(&linked, "record_kind", text("immutable")),
            StorageErrorKind::MalformedInput,
        );

        // A member the key derivation leans on, missing or off-grammar.
        assert_boundary_rejection(
            &store,
            key,
            "missing key member",
            &without_member(&linked, "client_id"),
            StorageErrorKind::MalformedInput,
        );
        assert_boundary_rejection(
            &store,
            key,
            "malformed key member",
            &replace_member(&linked, "client_id", text("not-a-uuid")),
            StorageErrorKind::MalformedInput,
        );

        // The authority-signature member must be present and well-formed
        // for the family — structure only; verification stays the
        // consumer's.
        assert_boundary_rejection(
            &store,
            key,
            "missing signature member",
            &without_member(&linked, "authority_signature"),
            StorageErrorKind::MalformedInput,
        );
        assert_boundary_rejection(
            &store,
            key,
            "malformed signature member",
            &replace_member(&linked, "authority_signature", text("00")),
            StorageErrorKind::MalformedInput,
        );
    }

    #[test]
    fn a_cross_tenant_envelope_is_a_scope_violation() {
        let store = store();

        // A structurally sound record whose signed tenant names another
        // tenant, stored inside this identity's prefix — the boundary
        // classifies it as a scope violation, not a malformed record.
        let (_, key, _) = &families()[0];
        store
            .backend
            .preload(key, &linked_client_envelope(OTHER_TENANT, CLIENT, 3));
        let error = block_on(store.read_linked_client(&tenant(), &client()))
            .err()
            .expect("a cross-tenant envelope must not read as a record");
        assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
        assert_eq!(error.detail(), DETAIL_RECORD_TENANT);

        // The same classification on an immutable family's read.
        let (_, revocation_key, _) = &families()[2];
        store
            .backend
            .preload(revocation_key, &revocation_envelope(OTHER_TENANT, CLIENT, 3));
        let error = block_on(store.read_revocation(&tenant(), &client(), epoch()))
            .err()
            .expect("a cross-tenant envelope must not read as a record");
        assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
        assert_eq!(error.detail(), DETAIL_RECORD_TENANT);
    }

    #[test]
    fn an_envelope_deriving_another_key_is_refused_at_the_boundary() {
        let store = store();
        let (_, key, _) = &families()[0];

        // A valid linked-client record for another client, stored at this
        // client's derived key: structurally sound, but its own members
        // derive a different key than the one it was found at.
        store
            .backend
            .preload(key, &linked_client_envelope(TENANT, OTHER_CLIENT, 3));
        let error = block_on(store.read_linked_client(&tenant(), &client()))
            .err()
            .expect("a non-deriving envelope must not read as a record");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(error.detail(), DETAIL_KEY_MISMATCH);

        // An epoch-addressed record for a different epoch at this epoch's
        // key: the derivation disagrees the same way.
        let (_, revocation_key, _) = &families()[2];
        store
            .backend
            .preload(revocation_key, &revocation_envelope(TENANT, CLIENT, 4));
        let error = block_on(store.read_revocation(&tenant(), &client(), epoch()))
            .err()
            .expect("a non-deriving envelope must not read as a record");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(error.detail(), DETAIL_KEY_MISMATCH);

        // A record of one family stored at another family's key.
        store
            .backend
            .preload(key, &revocation_envelope(TENANT, CLIENT, 3));
        let error = block_on(store.read_linked_client(&tenant(), &client()))
            .err()
            .expect("a cross-family envelope must not read as a record");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert_eq!(error.detail(), DETAIL_KEY_MISMATCH);

        // The positive control: the client's own record at its own key
        // reads, and issues exactly one GET per attempt.
        store
            .backend
            .preload(key, &linked_client_envelope(TENANT, CLIENT, 3));
        assert!(
            block_on(store.read_linked_client(&tenant(), &client()))
                .expect("the honest record must read")
                .is_some()
        );
    }

    #[test]
    fn backend_failures_classify_as_unavailable() {
        let store = store();
        let (_, key, bytes) = &families()[0];
        store.backend.preload(key, bytes);
        store.backend.fail_with(StorageErrorKind::Unavailable);

        let error = block_on(store.read_linked_client(&tenant(), &client()))
            .expect_err("an outage must surface");
        assert_eq!(error.kind(), StorageErrorKind::Unavailable);
        let error = block_on(store.head_linked_client(&tenant(), &client()))
            .expect_err("an outage must surface");
        assert_eq!(error.kind(), StorageErrorKind::Unavailable);
    }

    #[test]
    fn head_returns_size_and_version_without_a_get() {
        let store = store();
        let (_, key, bytes) = &families()[0];
        store.backend.preload(key, bytes);

        let metadata = block_on(store.head_linked_client(&tenant(), &client()))
            .expect("the head must succeed")
            .expect("the preloaded object must be present");
        assert_eq!(metadata.size(), bytes.len() as u64);
        assert_eq!(
            metadata.observation().etag().map(ObjectTag::as_str),
            Some(ETAG)
        );
        assert_eq!(
            metadata
                .observation()
                .storage_version()
                .map(archivist_storage::metadata::StorageVersionId::as_str),
            Some(VERSION)
        );
        assert_eq!(metadata.observation().observed_at().as_str(), OBSERVED);
        assert_eq!(store.backend.heads(), 1);
        assert_eq!(
            store.backend.gets(),
            0,
            "a head must never transfer the body"
        );

        // The absent object heads to Ok(None) too.
        assert!(
            block_on(store.head_receipt_key(&tenant(), &receipt_key()))
                .expect("absent head must not error")
                .is_none()
        );
        assert_eq!(store.backend.heads(), 2);
    }

    #[test]
    fn the_reader_names_only_the_read_identity() {
        let store = store();
        // The one credential reference the reader surface can name is the
        // control-read reference it was composed with; the tenant is the
        // one provisioned prefix holder.
        assert_eq!(store.config().tenant().as_str(), TENANT);
        assert_eq!(
            store.config().control_read_credentials().kind(),
            crate::config::CredentialKind::File
        );
        // And the scope model agrees with the key grammar the reads
        // derive through — the property the store-side gate leans on.
        for (_, key, _) in families() {
            assert!(
                store.config().permits_key(key.as_str()),
                "{}: every derived key must sit inside the provisioned prefix",
                key.as_str()
            );
        }
    }

    #[test]
    fn error_details_are_safe_messages() {
        for detail in [
            DETAIL_SCOPE,
            DETAIL_OVERSIZE,
            DETAIL_RECORD_TENANT,
            DETAIL_KEY_MISMATCH,
        ] {
            assert_eq!(
                SafeMessage::parse(detail)
                    .unwrap_or_else(|_| panic!("detail is not a safe message: {detail}"))
                    .as_str(),
                detail
            );
        }
    }
}
