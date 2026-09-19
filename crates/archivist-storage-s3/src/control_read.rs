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
//!   truncated acceptance. Absent records are [`Ok(None)`]: an unlinked
//!   client and a client with no delegation are ordinary states, not
//!   errors.
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
use crate::control_admin::ControlObjectKey;

// Content-safe detail literals, one static sentence per failure site. A
// unit test pins them against the protocol's safe-message grammar, the
// same discipline the sibling stores keep.
const DETAIL_SCOPE: &str = "key tenant is outside this control-read identity";
const DETAIL_OVERSIZE: &str = "control record exceeds the canonical document bound";

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
/// half beside the raw writer. The store hands over unverified bytes:
/// failing closed on a bad signature, a stale epoch, or an expired cache
/// entry is the consumer's contract (`EC-09`), not this store's.
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
    /// Gate one derived key, GET it, and hand over the byte-exact record
    /// with its observation — absent is [`Ok(None)`], oversize is a
    /// classification, never a truncated acceptance.
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

    use archivist_protocol::vocabulary::{Ed25519PublicKey, KeyId as KeyIdType, SafeMessage};
    use archivist_storage::audit_restore::ObjectBody;
    use archivist_storage::metadata::{ObjectTag, Observation, StorageVersionId};

    use super::{
        AuthorizationEpoch, CANONICAL_MAX_BYTES, ClientId, ControlObjectKey, ControlReadBackend,
        ControlReadStore, DETAIL_OVERSIZE, DETAIL_SCOPE, S3ControlReadStore, StorageError,
        StorageErrorKind, TenantId,
    };
    use crate::config::ControlReadConfig;

    // The golden identifiers shared with the sibling boundary suites, so
    // every layer of this boundary tells one story.
    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
    const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";
    const RELAY: &str = "2b1a0f9e-8d7c-4e6b-9a5f-1e2d3c4b5a69";
    const READ_REF: &str = "file:/etc/archivist/storage/control-read-credentials";
    const CONTROL_BUCKET: &str = "archivist-control-example";
    const OBSERVED: &str = "2026-09-19T12:00:00Z";
    const ETAG: &str = "\"d41d8cd98f00b204e9800998ecf8427e\"";
    const VERSION: &str = "3sL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo";

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

    fn error_kind(result: Result<Option<impl std::fmt::Debug>, StorageError>) -> StorageErrorKind {
        result.expect_err("this read must fail").kind()
    }

    /// The five (identifiers, derived key, stored bytes) rows one story
    /// is told with: every read method and its family's key.
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
                b"{\"record_type\":\"linked-client\"}".to_vec(),
            ),
            (
                "delegation",
                ControlObjectKey::delegation(&tenant, &relay_id, &client_id),
                b"{\"record_type\":\"delegation\"}".to_vec(),
            ),
            (
                "revocation",
                ControlObjectKey::revocation(&tenant, &client_id, epoch_value),
                b"{\"record_type\":\"revocation\"}".to_vec(),
            ),
            (
                "rotation",
                ControlObjectKey::rotation(&tenant, &client_id, epoch_value),
                b"{\"record_type\":\"rotation\"}".to_vec(),
            ),
            (
                "receipt-key",
                ControlObjectKey::receipt_key(&tenant, &receipt),
                b"{\"record_type\":\"receipt-key\"}".to_vec(),
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
        // maximum is handed over whole.
        let at_bound = vec![b'x'; CANONICAL_MAX_BYTES];
        store.backend.preload(key, &at_bound);
        let record = block_on(store.read_linked_client(&tenant(), &client()))
            .expect("a record at the bound must read")
            .unwrap_or_else(|| panic!("{name}: the preloaded record must be present"));
        assert_eq!(record.envelope().len(), CANONICAL_MAX_BYTES);
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
        for detail in [DETAIL_SCOPE, DETAIL_OVERSIZE] {
            assert_eq!(
                SafeMessage::parse(detail)
                    .unwrap_or_else(|_| panic!("detail is not a safe message: {detail}"))
                    .as_str(),
                detail
            );
        }
    }
}
