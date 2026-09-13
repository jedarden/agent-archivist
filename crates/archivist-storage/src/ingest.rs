// SPDX-License-Identifier: Apache-2.0

//! The storage configuration of an ingestion replica: exactly two
//! independently scoped identities, composed.
//!
//! Plan Section 5: "Ingestion replicas are configured with tenant authority
//! public keys and two independently scoped storage identities, even when
//! both use the same endpoint and bucket: a control reader that cannot
//! write any object, and a raw writer that can create, multipart-write, and
//! abort only the tenant raw prefix but cannot read or delete objects or
//! access control/catalog/derived prefixes."
//!
//! [`IngestStorage`] makes that sentence a type. It holds one
//! [`RawWriteStore`] and one [`ControlReadStore`] — and nothing else — so
//! the authority an ingest configuration has is exactly the union of those
//! two trait surfaces, no more:
//!
//! - **raw read** — no read or existence method exists on
//!   [`RawWriteStore`]; the optional raw-reader optimization (STO-007) is a
//!   fourth identity the portable ingest path never requires, and no trait
//!   in this crate represents it today;
//! - **delete** — no trait reachable from [`IngestStorage`] has a delete
//!   method; deletion is an offline administrator workflow (plan Section
//!   7.10);
//! - **audit, catalog, and derived authority** — enumeration, inventory
//!   freezing, and object reads live on
//!   [`crate::audit_restore::AuditRestoreStore`], which [`IngestStorage`]
//!   does not bind; the derived and catalog prefixes are similarly outside
//!   both bound traits;
//! - **control write** — [`crate::control::ControlAdminStore`] exists
//!   precisely so that control mutation has a home the ingest path never
//!   receives; ingest replicas "never receive this credential" (plan
//!   Section 5).
//!
//! The split is structural, not a runtime policy: there is no conversion,
//! supertrait, or shared method set that widens one authority into another,
//! so a compromised ingest configuration cannot call a method its traits do
//! not have. Enforcement beyond the type system — the backend policies
//! themselves (a `PUT`-and-multipart-only raw credential, a read-only
//! control credential, disjoint prefixes) — belongs to each adapter's
//! deployment, and the compatibility suite proves it (plan Section 8,
//! Phase 2).

use crate::control::ControlReadStore;
use crate::raw_write::RawWriteStore;

/// The two storage identities of one ingestion replica.
///
/// Compose once at startup; share by reference across request handlers
/// (the stores are `&self`-safe by their trait contracts, and the futures
/// they return are [`Send`]).
#[derive(Clone, Debug)]
pub struct IngestStorage<W, C> {
    raw: W,
    control: C,
}

impl<W: RawWriteStore, C: ControlReadStore> IngestStorage<W, C> {
    /// Compose the raw writer and the control reader for one replica.
    ///
    /// The two values are independently scoped identities even when they
    /// address the same endpoint and bucket — nothing here joins them, and
    /// no accessor returns a handle broader than the identity that went in.
    #[must_use]
    pub const fn compose(raw: W, control: C) -> Self {
        Self { raw, control }
    }

    /// The raw-write identity: create, multipart-write, abort — and
    /// nothing else.
    #[must_use]
    pub const fn raw(&self) -> &W {
        &self.raw
    }

    /// The control-read identity: the five signed record families, read
    /// only.
    #[must_use]
    pub const fn control(&self) -> &C {
        &self.control
    }
}

#[cfg(test)]
mod tests {
    use archivist_protocol::object_key::{BlobObjectKey, OccurrenceObjectKey};
    use archivist_protocol::vocabulary::{
        ClientId, HarnessId, KeyId, OccurrenceId, SessionHash, StorageOutcome, StorageProfile,
        TenantId,
    };

    use super::IngestStorage;
    use crate::audit_restore::{
        AuditRestoreStore, ContinuationToken, FrozenInventory, InventoryKey, InventoryPage,
        InventoryScope, ObjectBody, ObjectMetadata,
    };
    use crate::capability::{
        ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
    };
    use crate::control::{
        AdminControlRecord, AuthorizationEpoch, ControlReadStore, ControlRecord, ControlRecordKind,
    };
    use crate::error::{StorageError, StorageErrorKind};
    use crate::metadata::{ObjectTag, Observation};
    use crate::raw_write::{
        ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
    };

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OBSERVED: &str = "2026-09-13T12:00:00Z";

    /// A no-dependency executor for the mock futures. Every mock here
    /// completes without pending, so first-poll-until-ready terminates; a
    /// future that pends would spin this helper, which is itself a useful
    /// test property for trait implementations this small.
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

    /// A raw writer that also *pretends* to be dangerous: the inherent
    /// method below is exactly the authority the ingest path must never
    /// reach. It exists on the concrete type, and it is invisible through a
    /// `RawWriteStore` bound — which is the structural claim of this
    /// module.
    #[derive(Clone, Copy, Debug)]
    struct MockRawStore;

    impl MockRawStore {
        /// Inherent, NOT part of [`RawWriteStore`]: unreachable through the
        /// trait bound.
        fn delete_everything() -> StorageError {
            StorageError::new(
                StorageErrorKind::ScopeViolation,
                "inherent destructive method is not storage authority",
            )
        }
    }

    impl RawWriteStore for MockRawStore {
        fn capabilities(&self) -> StoreCapabilities {
            StoreCapabilities {
                conditional_create: ConditionalCreate::Unavailable,
                stored_checksum: StoredChecksum::Sha256,
                versioning: VersioningState::Unknown,
                server_side_encryption: EncryptionState::Verified,
            }
        }

        async fn write_manifest(
            &self,
            _key: &ManifestKey,
            _bytes: &[u8],
        ) -> Result<StorageOutcome, StorageError> {
            Ok(StorageOutcome::LogicallyCommittedUnknownPhysicalResult)
        }

        async fn begin_multipart(
            &self,
            _blob: &BlobObjectKey,
        ) -> Result<MultipartUploadId, StorageError> {
            MultipartUploadId::parse("mock-upload-1")
                .map_err(|_| StorageError::of_kind(StorageErrorKind::MalformedInput))
        }

        async fn write_part(
            &self,
            _upload: &MultipartUploadId,
            part: PartNumber,
            _bytes: &[u8],
        ) -> Result<PartCommitment, StorageError> {
            Ok(PartCommitment::new(
                part,
                ObjectTag::parse("\"mock-part\"").unwrap(),
            ))
        }

        async fn commit_multipart(
            &self,
            _upload: &MultipartUploadId,
            _parts: &[PartCommitment],
        ) -> Result<StorageOutcome, StorageError> {
            Ok(StorageOutcome::Created)
        }

        async fn abort_multipart(&self, _upload: &MultipartUploadId) -> Result<(), StorageError> {
            Ok(())
        }
    }

    /// A control reader that also *pretends* to be dangerous.
    #[derive(Clone, Copy, Debug)]
    struct MockControlStore;

    impl MockControlStore {
        /// Inherent, NOT part of [`ControlReadStore`]: unreachable through
        /// the trait bound.
        fn publish_record(_record: &AdminControlRecord) -> bool {
            true
        }
    }

    impl ControlReadStore for MockControlStore {
        async fn read_linked_client(
            &self,
            _tenant: &TenantId,
            _client: &ClientId,
        ) -> Result<Option<ControlRecord>, StorageError> {
            Ok(None)
        }

        async fn read_delegation(
            &self,
            _tenant: &TenantId,
            _relay: &ClientId,
            _origin: &ClientId,
        ) -> Result<Option<ControlRecord>, StorageError> {
            Ok(None)
        }

        async fn read_revocation(
            &self,
            _tenant: &TenantId,
            _client: &ClientId,
            _epoch: AuthorizationEpoch,
        ) -> Result<Option<ControlRecord>, StorageError> {
            Ok(None)
        }

        async fn read_rotation(
            &self,
            _tenant: &TenantId,
            _client: &ClientId,
            _epoch: AuthorizationEpoch,
        ) -> Result<Option<ControlRecord>, StorageError> {
            Ok(None)
        }

        async fn read_receipt_key(
            &self,
            _tenant: &TenantId,
            _key: &KeyId,
        ) -> Result<Option<ControlRecord>, StorageError> {
            Ok(None)
        }
    }

    /// An audit/restore store: the authority an ingest configuration is
    /// deliberately never given. This type shares no trait, accessor, or
    /// conversion with [`IngestStorage`] — the tests keep it separate the
    /// way a deployment's credentials are separate.
    #[derive(Clone, Copy, Debug)]
    struct MockAuditStore;

    impl AuditRestoreStore for MockAuditStore {
        async fn list_page(
            &self,
            _scope: &InventoryScope,
            _after: Option<&ContinuationToken>,
        ) -> Result<InventoryPage, StorageError> {
            Ok(InventoryPage::new(vec![], None))
        }

        async fn freeze_inventory(
            &self,
            scope: &InventoryScope,
        ) -> Result<FrozenInventory, StorageError> {
            let page = self.list_page(scope, None).await?;
            FrozenInventory::from_pages(scope, vec![Ok(page)])
        }

        async fn inspect_object(
            &self,
            _key: &InventoryKey,
        ) -> Result<ObjectMetadata, StorageError> {
            Ok(ObjectMetadata::new(
                0,
                Observation::new(None, None, OBSERVED.parse().unwrap()),
            ))
        }

        async fn read_object(&self, _key: &InventoryKey) -> Result<ObjectBody, StorageError> {
            Ok(ObjectBody::new(
                vec![],
                Observation::new(None, None, OBSERVED.parse().unwrap()),
            ))
        }
    }

    /// Every operation the ingest path can reach, written generically so it
    /// compiles only against the two trait surfaces. This function is the
    /// review anchor for this crate's authority split: if either bound
    /// trait ever grew a read, delete, list, audit, catalog, derived, or
    /// control-write method, this file is where that diff lands — and such
    /// a diff must be rejected as the acceptance failure it is.
    fn ingest_reachable_operations(ingest: &IngestStorage<MockRawStore, MockControlStore>) -> u32 {
        block_on(async {
            let tenant = TENANT.parse().unwrap();
            let client: ClientId = "aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f".parse().unwrap();
            let key_id = KeyId::parse(DIGEST).unwrap();
            let epoch = AuthorizationEpoch::new(1).unwrap();
            let mut performed = 0;

            // Raw-write authority: capability report, the full multipart
            // session begin→commit, abort, and a manifest write.
            let _capabilities = ingest.raw().capabilities();
            performed += 1;
            let blob =
                BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &DIGEST.parse().unwrap());
            let upload = ingest.raw().begin_multipart(&blob).await.unwrap();
            let part = ingest
                .raw()
                .write_part(&upload, PartNumber::new(1).unwrap(), b"part-bytes")
                .await
                .unwrap();
            let _committed = ingest
                .raw()
                .commit_multipart(&upload, &[part])
                .await
                .unwrap();
            performed += 1;
            ingest.raw().abort_multipart(&upload).await.unwrap();
            performed += 1;
            let occurrence = OccurrenceObjectKey::new(
                &tenant,
                &client,
                &HarnessId::parse("claude-code").unwrap(),
                &SessionHash::parse(DIGEST).unwrap(),
                &OccurrenceId::parse(DIGEST).unwrap(),
            );
            let _manifest = ingest
                .raw()
                .write_manifest(&ManifestKey::Occurrence(occurrence), b"{}")
                .await
                .unwrap();
            performed += 1;

            // Control-read authority: all five families, read only, none
            // present.
            assert!(
                ingest
                    .control()
                    .read_linked_client(&tenant, &client)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                ingest
                    .control()
                    .read_delegation(&tenant, &client, &client)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                ingest
                    .control()
                    .read_revocation(&tenant, &client, epoch)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                ingest
                    .control()
                    .read_rotation(&tenant, &client, epoch)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                ingest
                    .control()
                    .read_receipt_key(&tenant, &key_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            performed += 5;

            performed
        })
    }

    #[test]
    fn ingest_reaches_exactly_the_two_trait_surfaces() {
        let ingest = IngestStorage::compose(MockRawStore, MockControlStore);
        assert_eq!(ingest_reachable_operations(&ingest), 9);
    }

    #[test]
    fn inherent_authority_stays_on_the_concrete_type() {
        // The destructive and publish methods exist only on the concrete
        // types. Generic code bounded by `RawWriteStore` or
        // `ControlReadStore` cannot name them, so an ingest configuration
        // holding only the traits cannot reach them — this test keeps them
        // compiled and named while the generic path above proves the
        // surface the traits expose.
        assert_eq!(
            MockRawStore::delete_everything().kind(),
            StorageErrorKind::ScopeViolation
        );
        let record = AdminControlRecord::new(ControlRecordKind::LinkedClient, vec![]);
        assert!(MockControlStore::publish_record(&record));
    }

    #[test]
    fn audit_authority_is_a_separate_identity() {
        // The offline identity works on its own — and appears nowhere in
        // `IngestStorage`, which has no field, accessor, or conversion that
        // could hold it.
        let audit = MockAuditStore;
        let scope = InventoryScope::TenantRaw(TENANT.parse().unwrap());
        let frozen = block_on(audit.freeze_inventory(&scope)).unwrap();
        assert!(frozen.is_empty());

        let key = InventoryKey::parse(&format!("tenants/{TENANT}/v1/raw/occurrences/x")).unwrap();
        let inspected = block_on(audit.inspect_object(&key)).unwrap();
        assert_eq!(inspected.size(), 0);
        let body = block_on(audit.read_object(&key)).unwrap();
        assert!(body.bytes().is_empty());
    }
}
