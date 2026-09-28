// SPDX-License-Identifier: Apache-2.0

//! The S3 lifecycle-audit authority: [`S3LifecycleAuditStore`], the
//! portable [`LifecycleAuditStore`] over the offline-restore identity's
//! versions listing, and the STO-009 measurement the audit reduces to.
//!
//! On a versioned backend every deterministic overwrite (STO-006) lands a
//! new physical version behind the current one, and requirements STO-009
//! makes expiring those redundant noncurrent versions a deployment action.
//! The qualification artifacts could only disclose the accumulation — the
//! write identities cannot list, and the lifecycle rules themselves are
//! operator-managed and invisible to every archivist identity. This store
//! makes the residue observable: it enumerates the physical versions
//! under a tenant prefix through the one identity with list grants there —
//! the offline-restore identity, `get+list` and nothing else — and reports
//! noncurrent counts and retained bytes against the documented guidance.
//!
//! # Composed only where the identity exists
//!
//! The offline-restore credential is the configuration's optional role:
//! a deployment that omits it has no such identity, and this store refuses
//! to compose at all ([`S3LifecycleAuditStore::new`] fails with
//! [`StorageErrorKind::CapabilityUnavailable`]). The observed capability
//! report is the only input to the audit decision, exactly as it is for
//! the write path: an audit is meaningful only where versioning is
//! established ([`VersioningState::Enabled`]), so
//! [`S3LifecycleAuditStore::audit_noncurrent`] refuses with
//! [`StorageErrorKind::CapabilityUnavailable`] for an unprobed,
//! unknown-versioning, or versioning-disabled report — a report that
//! cannot attribute versions can never support the current/noncurrent
//! distinction, and unknown never strengthens.
//!
//! # The seam
//!
//! [`VersionAuditBackend`] is the S3 request seam: one versions-listing
//! operation over the closed [`InventoryScope`]s, with no read, write,
//! delete, multipart, arbitrary-prefix, or bucket-level method — the
//! provisioned credential holds list below the tenant prefixes and
//! nothing else, so this is the entire surface that authority has. The
//! concrete binding implements it over the backend's versions listing
//! (`ListObjectVersions`-shaped) and enforces the same prefix scope the
//! deployment's backend policy states; the mock in this module's tests
//! mirrors that denial so the store's requests are proven to stay inside
//! it.
//!
//! [`VersioningState::Enabled`]: archivist_storage::capability::VersioningState::Enabled

use std::fmt;
use std::future::Future;

use archivist_protocol::vocabulary::TenantId;

use archivist_storage::audit_restore::{ContinuationToken, InventoryScope};
use archivist_storage::capability::{StoreCapabilities, VersioningState};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::lifecycle_audit::{
    LifecycleAuditStore, NoncurrentVersionReport, VersionedPage, freeze_version_listing,
};

use crate::config::{CredentialReference, S3StorageConfig};

// Content-safe detail literals, one static sentence per failure site —
// the same discipline the sibling stores keep, pinned against the
// protocol's safe-message grammar by a unit test below.
const DETAIL_SCOPE: &str = "scope tenant is outside this audit identity";
const DETAIL_IDENTITY: &str = "the offline-restore identity is not configured";
const DETAIL_VERSIONING: &str = "the capability report does not establish versioning enabled";

/// The S3 request seam of the audit identity: the one listing primitive
/// the offline-restore credential needs, over the closed
/// [`InventoryScope`]s only.
///
/// Deliberately narrower than an S3 client: no get, no put, no delete, no
/// multipart, no arbitrary-prefix or bucket-level call exists to call. A
/// concrete binding enforces the deployment's backend policy — versions
/// listings below the named tenant prefix of the scope's bucket, deny
/// every other prefix — and the mock in this module's tests mirrors that
/// denial so the store's requests are proven to stay inside it.
pub trait VersionAuditBackend {
    /// Fetch one page of the scope's versions listing, continuing from
    /// `after` when the listing has a next page.
    ///
    /// # Errors
    /// [`StorageError::Unavailable`](archivist_storage::error::StorageError)
    /// when the backend or network is down,
    /// [`StorageError::ScopeViolation`](archivist_storage::error::StorageError)
    /// when the scope is outside this binding's provisioning.
    fn list_object_versions(
        &self,
        scope: &InventoryScope,
        after: Option<&ContinuationToken>,
    ) -> impl Future<Output = Result<VersionedPage, StorageError>> + Send;
}

/// The lifecycle-audit store of the S3 adapter: the portable
/// [`LifecycleAuditStore`] (and the STO-009 measurement on top of it) over
/// one pinned tenant of one [`S3StorageConfig`], riding the
/// offline-restore credential reference the configuration validated
/// ([`StorageRole::OfflineRestore`]'s reference).
///
/// [`StorageRole::OfflineRestore`]: crate::config::StorageRole::OfflineRestore
pub struct S3LifecycleAuditStore<B> {
    config: S3StorageConfig,
    tenant: TenantId,
    credential: CredentialReference,
    capabilities: StoreCapabilities,
    backend: B,
}

impl<B> fmt::Debug for S3LifecycleAuditStore<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The credential reference renders its kind alone (CFG-027), and
        // the backend seam is omitted: no diagnostic echoes a reference
        // string or a binding's internals.
        f.debug_struct("S3LifecycleAuditStore")
            .field("config", &self.config)
            .field("tenant", &self.tenant.as_str())
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl<B> S3LifecycleAuditStore<B> {
    /// Compose the audit authority: the validated configuration (its
    /// offline-restore credential reference and buckets), the one tenant
    /// whose prefixes this store audits, and the backend seam.
    ///
    /// The audit identity is the configuration's optional role, so
    /// composition itself is the fail-closed boundary: a configuration
    /// that never granted the offline-restore credential produces no
    /// audit store.
    ///
    /// # Errors
    /// [`StorageErrorKind::CapabilityUnavailable`] when the configuration
    /// did not grant the offline-restore identity.
    pub fn new(
        config: S3StorageConfig,
        tenant: TenantId,
        backend: B,
    ) -> Result<Self, StorageError> {
        let credential = config
            .identities()
            .offline_restore()
            .cloned()
            .ok_or_else(|| {
                StorageError::new(StorageErrorKind::CapabilityUnavailable, DETAIL_IDENTITY)
            })?;
        Ok(Self {
            config,
            tenant,
            credential,
            capabilities: StoreCapabilities::unprobed(),
            backend,
        })
    }

    /// Adopt the capability report a probe observed for this store's
    /// backend. The report is the only input to the audit decision, so
    /// this is the single place a deployment's probe result enters.
    #[must_use]
    pub fn with_capabilities(mut self, report: StoreCapabilities) -> Self {
        self.capabilities = report;
        self
    }

    /// The same composition — configuration, tenant, credential, backend
    /// — carrying the capability report one run's own probe observed: the
    /// qualification runner's binding step for the audit half, so the
    /// STO-009 measurement a run files is gated by exactly the versioning
    /// fact that run's single probe established.
    #[must_use]
    pub fn rebased(&self, capabilities: StoreCapabilities) -> Self
    where
        B: Clone,
    {
        Self {
            config: self.config.clone(),
            tenant: self.tenant.clone(),
            credential: self.credential.clone(),
            capabilities,
            backend: self.backend.clone(),
        }
    }

    /// The ingest configuration this store was composed with.
    #[must_use]
    pub const fn config(&self) -> &S3StorageConfig {
        &self.config
    }

    /// The one tenant whose prefixes this store audits. Every scope a
    /// caller names must carry this tenant, and every other tenant's
    /// scope fails the check before any request is issued.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The offline-restore credential reference this store's requests
    /// ride on — the optional restore identity the configuration
    /// validated ([`StorageRole::OfflineRestore`]'s reference).
    ///
    /// [`StorageRole::OfflineRestore`]: crate::config::StorageRole::OfflineRestore
    #[must_use]
    pub const fn offline_restore_credentials(&self) -> &CredentialReference {
        &self.credential
    }

    /// Whether `scope` names a prefix this identity audits: the scope's
    /// tenant is this store's one tenant, and nothing else. All four
    /// reserved namespaces are auditable — the offline-restore identity's
    /// list grants cover raw, control, catalog, and derived alike, and
    /// the derived writers' deterministic re-puts accumulate noncurrent
    /// versions under catalog and derived exactly as the ingest writes do
    /// under raw.
    fn check_scope(&self, scope: &InventoryScope) -> Result<(), StorageError> {
        let scope_tenant = match scope {
            InventoryScope::TenantRaw(tenant)
            | InventoryScope::TenantControl(tenant)
            | InventoryScope::TenantCatalog(tenant)
            | InventoryScope::TenantDerived(tenant) => tenant,
        };
        if scope_tenant != &self.tenant {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        Ok(())
    }
}

impl<B: VersionAuditBackend + Sync> S3LifecycleAuditStore<B> {
    /// Freeze the scope's versions listing and reduce it to the STO-009
    /// measurement: noncurrent counts and retained bytes against the
    /// documented lifecycle guidance.
    ///
    /// The audit refuses before any request when the observed capability
    /// report does not establish versioning enabled: an unprobed,
    /// unknown-versioning, or versioning-disabled report cannot support
    /// the current/noncurrent distinction the measurement exists to make.
    ///
    /// # Errors
    /// [`StorageErrorKind::CapabilityUnavailable`] when the capability
    /// report does not establish versioning enabled,
    /// [`StorageErrorKind::ScopeViolation`] when the scope names another
    /// tenant, [`StorageErrorKind::InventoryFault`] for any freeze-contract
    /// violation, [`StorageErrorKind::Unavailable`] when the backend or
    /// network is down.
    pub async fn audit_noncurrent(
        &self,
        scope: &InventoryScope,
    ) -> Result<NoncurrentVersionReport, StorageError> {
        if self.capabilities.versioning != VersioningState::Enabled {
            return Err(StorageError::new(
                StorageErrorKind::CapabilityUnavailable,
                DETAIL_VERSIONING,
            ));
        }
        self.check_scope(scope)?;
        let listing = freeze_version_listing(self, scope).await?;
        Ok(NoncurrentVersionReport::from_listing(&listing))
    }
}

impl<B: VersionAuditBackend + Sync> LifecycleAuditStore for S3LifecycleAuditStore<B> {
    async fn list_versions_page(
        &self,
        scope: &InventoryScope,
        after: Option<&ContinuationToken>,
    ) -> Result<VersionedPage, StorageError> {
        self.check_scope(scope)?;
        self.backend.list_object_versions(scope, after).await
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DETAIL_IDENTITY, DETAIL_SCOPE, DETAIL_VERSIONING, S3LifecycleAuditStore,
        VersionAuditBackend,
    };
    use archivist_protocol::vocabulary::{TenantId, Timestamp};
    use archivist_storage::audit_restore::{ContinuationToken, InventoryKey, InventoryScope};
    use archivist_storage::capability::{
        ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
    };
    use archivist_storage::error::{StorageError, StorageErrorKind};
    use archivist_storage::lifecycle_audit::{VersionedEntry, VersionedPage};
    use archivist_storage::metadata::{ObjectTag, Observation, StorageVersionId};

    use crate::config::{CredentialReference, EncryptionPolicy, S3StorageConfig};

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const FOREIGN: &str = "ffffffff-0000-4000-8000-000000000000";
    const RESTORE_REF: &str = "file:/synthetic/offline-restore";
    const RAW_WRITE_REF: &str = "file:/synthetic/raw-writer";
    const CONTROL_READ_REF: &str = "file:/synthetic/control-reader";
    const OBSERVED: &str = "2026-09-27T12:00:00Z";
    const RAW_PREFIX: &str = "tenants/0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b/v1/raw/";

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

    fn tenant() -> TenantId {
        TENANT.parse().unwrap()
    }

    fn scope() -> InventoryScope {
        InventoryScope::TenantRaw(tenant())
    }

    fn config_with_restore() -> S3StorageConfig {
        S3StorageConfig::builder()
            .endpoint_url("https://s3.example.com")
            .region("us-east-1")
            .encryption(EncryptionPolicy::S3Sse)
            .raw_bucket("archivist-raw-example")
            .control_bucket("archivist-control-example")
            .raw_write_credentials(RAW_WRITE_REF)
            .control_read_credentials(CONTROL_READ_REF)
            .offline_restore_credentials(RESTORE_REF)
            .build()
            .expect("audit configuration validates")
    }

    fn config_without_restore() -> S3StorageConfig {
        S3StorageConfig::builder()
            .endpoint_url("https://s3.example.com")
            .region("us-east-1")
            .encryption(EncryptionPolicy::S3Sse)
            .raw_bucket("archivist-raw-example")
            .control_bucket("archivist-control-example")
            .raw_write_credentials(RAW_WRITE_REF)
            .control_read_credentials(CONTROL_READ_REF)
            .build()
            .expect("ingest configuration validates")
    }

    fn versioned_capabilities() -> StoreCapabilities {
        StoreCapabilities {
            conditional_create: ConditionalCreate::Unavailable,
            stored_checksum: StoredChecksum::ProviderSpecific,
            versioning: VersioningState::Enabled,
            server_side_encryption: EncryptionState::Verified,
        }
    }

    fn observed_at() -> Timestamp {
        Timestamp::parse(OBSERVED).unwrap()
    }

    fn key(tail: &str) -> InventoryKey {
        InventoryKey::parse(&format!("{RAW_PREFIX}{tail}")).unwrap()
    }

    /// One versioned record under an explicit tenant namespace prefix,
    /// for the reserved-namespace tests.
    fn keyed_entry(key_text: &str, size: u64, version: &str, latest: bool) -> VersionedEntry {
        VersionedEntry::new(
            InventoryKey::parse(key_text).unwrap(),
            size,
            StorageVersionId::parse(version).unwrap(),
            latest,
            Observation::new(
                Some(ObjectTag::parse("etag-1").unwrap()),
                None,
                observed_at(),
            ),
        )
    }

    fn entry(tail: &str, size: u64, version: &str, latest: bool) -> VersionedEntry {
        VersionedEntry::new(
            key(tail),
            size,
            StorageVersionId::parse(version).unwrap(),
            latest,
            Observation::new(
                Some(ObjectTag::parse("etag-1").unwrap()),
                None,
                observed_at(),
            ),
        )
    }

    /// The mock mirrors the restore identity's provisioning exactly — a
    /// literal string-prefix grant per scope arm (this tenant's four
    /// reserved prefixes: raw, control, catalog, derived), every other
    /// prefix refused — and paginates the records it holds two per page,
    /// so the store's freeze is proven to drive a real paginator.
    #[derive(Debug, Default)]
    struct MockBackend {
        records: Vec<VersionedEntry>,
        pages_served: std::sync::atomic::AtomicUsize,
    }

    /// The continuation token `p<N>` names page index `N` of the mock's
    /// canonical sequence: records sorted by key bytes, then version
    /// bytes, two per page.
    const MOCK_PAGE_SIZE: usize = 2;

    impl MockBackend {
        fn holding(records: Vec<VersionedEntry>) -> Self {
            Self {
                records,
                pages_served: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl VersionAuditBackend for MockBackend {
        async fn list_object_versions(
            &self,
            scope: &InventoryScope,
            after: Option<&ContinuationToken>,
        ) -> Result<VersionedPage, StorageError> {
            let granted = match scope {
                InventoryScope::TenantRaw(tenant)
                | InventoryScope::TenantControl(tenant)
                | InventoryScope::TenantCatalog(tenant)
                | InventoryScope::TenantDerived(tenant) => tenant.as_str() == TENANT,
            };
            if !granted {
                return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
            }
            let prefix = scope.prefix();
            let mut matching: Vec<&VersionedEntry> = self
                .records
                .iter()
                .filter(|entry| entry.key().as_str().starts_with(&prefix))
                .collect();
            matching.sort_by(|a, b| {
                a.key()
                    .as_str()
                    .as_bytes()
                    .cmp(b.key().as_str().as_bytes())
                    .then_with(|| {
                        a.version()
                            .as_str()
                            .as_bytes()
                            .cmp(b.version().as_str().as_bytes())
                    })
            });
            let index = match after {
                None => 0,
                Some(token) => token
                    .as_str()
                    .strip_prefix('p')
                    .and_then(|number| number.parse::<usize>().ok())
                    .ok_or_else(|| StorageError::of_kind(StorageErrorKind::Unavailable))?,
            };
            let start = index * MOCK_PAGE_SIZE;
            if start > matching.len() {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            let end = (start + MOCK_PAGE_SIZE).min(matching.len());
            let entries: Vec<VersionedEntry> = matching[start..end]
                .iter()
                .map(|entry| (*entry).clone())
                .collect();
            self.pages_served
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let next = if end < matching.len() {
                Some(ContinuationToken::parse(&format!("p{}", end / MOCK_PAGE_SIZE)).unwrap())
            } else {
                None
            };
            Ok(VersionedPage::new(entries, next))
        }
    }

    fn audit_store(backend: MockBackend) -> S3LifecycleAuditStore<MockBackend> {
        S3LifecycleAuditStore::new(config_with_restore(), tenant(), backend)
            .expect("the restore identity is granted")
            .with_capabilities(versioned_capabilities())
    }

    fn detail_of<T>(result: &Result<T, StorageError>) -> &'static str {
        match result {
            Ok(_) => panic!("this call must fail"),
            Err(error) => error.detail(),
        }
    }

    #[test]
    fn composition_requires_the_offline_restore_identity() {
        let error =
            S3LifecycleAuditStore::new(config_without_restore(), tenant(), MockBackend::default())
                .expect_err("a configuration without the restore identity produces no audit store");
        assert_eq!(error.kind(), StorageErrorKind::CapabilityUnavailable);
        assert_eq!(error.detail(), DETAIL_IDENTITY);
    }

    #[test]
    fn the_composed_store_rides_the_restore_credential() {
        let store =
            S3LifecycleAuditStore::new(config_with_restore(), tenant(), MockBackend::default())
                .expect("the restore identity is granted");
        assert_eq!(
            store.offline_restore_credentials(),
            &CredentialReference::parse(RESTORE_REF).expect("the golden reference parses")
        );
        assert_eq!(store.tenant().as_str(), TENANT);
        assert!(store.config().identities().offline_restore().is_some());
    }

    #[test]
    fn audit_refuses_until_the_report_establishes_versioning() {
        let unprobed =
            S3LifecycleAuditStore::new(config_with_restore(), tenant(), MockBackend::default())
                .expect("the restore identity is granted");
        let error = block_on(unprobed.audit_noncurrent(&scope())).expect_err("unprobed refuses");
        assert_eq!(error.kind(), StorageErrorKind::CapabilityUnavailable);
        assert_eq!(error.detail(), DETAIL_VERSIONING);

        for state in [VersioningState::Unknown, VersioningState::Disabled] {
            let store = audit_store(MockBackend::default()).with_capabilities(StoreCapabilities {
                versioning: state,
                ..versioned_capabilities()
            });
            let result = block_on(store.audit_noncurrent(&scope()));
            assert_eq!(
                detail_of(&result),
                DETAIL_VERSIONING,
                "unknown never strengthens and disabled has nothing to audit"
            );
        }
    }

    #[test]
    fn audit_refuses_a_scope_outside_the_identity() {
        let store = audit_store(MockBackend::default());
        let foreign = InventoryScope::TenantRaw(FOREIGN.parse().unwrap());
        let error = block_on(store.audit_noncurrent(&foreign))
            .expect_err("another tenant's prefix is outside this identity");
        assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
        assert_eq!(error.detail(), DETAIL_SCOPE);
    }

    /// Every reserved namespace is auditable — the derived namespaces
    /// included, because the writers' deterministic re-puts accumulate
    /// noncurrent versions under catalog and derived exactly as the
    /// ingest writes do under raw — and each namespace's foreign-tenant
    /// scope is refused before any request.
    #[test]
    fn audit_covers_the_reserved_derived_namespaces_and_refuses_their_foreign_tenants() {
        let backend = MockBackend::holding(vec![
            // A checkpoint re-put twice at the same digest-derived key:
            // one current, one noncurrent copy.
            keyed_entry(
                &format!("tenants/{TENANT}/v1/catalog/checkpoints/x.json"),
                30,
                "v1",
                false,
            ),
            keyed_entry(
                &format!("tenants/{TENANT}/v1/catalog/checkpoints/x.json"),
                30,
                "v2",
                true,
            ),
            // A usage-summary projection superseded by a re-put of the
            // same content-addressed object: the older version is the
            // noncurrent residue the audit measures.
            keyed_entry(
                &format!("tenants/{TENANT}/v1/derived/usage/1/usage-summaries/ab/x.json"),
                20,
                "v1",
                false,
            ),
            keyed_entry(
                &format!("tenants/{TENANT}/v1/derived/usage/1/usage-summaries/ab/x.json"),
                25,
                "v2",
                true,
            ),
        ]);
        let store = audit_store(backend);

        let catalog = InventoryScope::TenantCatalog(TENANT.parse().unwrap());
        let report = block_on(store.audit_noncurrent(&catalog)).expect("the catalog scope audits");
        assert_eq!(report.distinct_keys(), 1);
        assert_eq!(report.noncurrent_versions(), 1);
        assert_eq!(report.noncurrent_bytes(), 30);

        let derived = InventoryScope::TenantDerived(TENANT.parse().unwrap());
        let report = block_on(store.audit_noncurrent(&derived)).expect("the derived scope audits");
        assert_eq!(report.distinct_keys(), 1);
        assert_eq!(report.noncurrent_versions(), 1);
        assert_eq!(report.noncurrent_bytes(), 20);

        for foreign_scope in [
            InventoryScope::TenantCatalog(FOREIGN.parse().unwrap()),
            InventoryScope::TenantDerived(FOREIGN.parse().unwrap()),
        ] {
            let error = block_on(store.audit_noncurrent(&foreign_scope))
                .expect_err("another tenant's reserved namespace is outside this identity");
            assert_eq!(error.kind(), StorageErrorKind::ScopeViolation);
            assert_eq!(error.detail(), DETAIL_SCOPE);
        }
    }

    #[test]
    fn audit_freezes_through_the_paginator_and_measures_the_accumulation() {
        // One current version per key plus redundant noncurrent copies:
        // exactly the physical shape the overwrite profile's lanes leave.
        let backend = MockBackend::holding(vec![
            entry("blob/aa", 100, "v1", true),
            entry("manifest/occ/b", 10, "v1", false),
            entry("manifest/occ/b", 11, "v2", false),
            entry("manifest/occ/b", 12, "v3", true),
            entry("manifest/occ/c", 5, "v1", false),
            entry("manifest/occ/c", 6, "v2", true),
        ]);
        let store = audit_store(backend);
        let report = block_on(store.audit_noncurrent(&scope())).expect("the audit freezes");
        assert_eq!(report.distinct_keys(), 3);
        assert_eq!(report.total_versions(), 6);
        assert_eq!(report.noncurrent_versions(), 3);
        assert_eq!(report.noncurrent_bytes(), 26);
        assert_eq!(report.fullest_noncurrent(), 2);
        assert!(
            report
                .fullest_key()
                .is_some_and(|key| key.ends_with("/manifest/occ/b"))
        );
        // The freeze drove a real paginator: three pages over six records
        // at the mock's page size.
        assert_eq!(
            store
                .backend
                .pages_served
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }

    #[test]
    fn audit_of_an_empty_scope_reports_zeros() {
        let store = audit_store(MockBackend::default());
        let report = block_on(store.audit_noncurrent(&scope())).expect("an empty listing freezes");
        assert_eq!(report.distinct_keys(), 0);
        assert_eq!(report.noncurrent_versions(), 0);
        assert_eq!(report.fullest_key(), None);
    }

    #[test]
    fn error_details_are_safe_messages() {
        // Every static detail this module can emit stays inside the
        // project's safe-message grammar.
        for detail in [DETAIL_SCOPE, DETAIL_IDENTITY, DETAIL_VERSIONING] {
            assert!(!detail.is_empty());
            assert!(detail.len() <= 200);
            assert!(
                detail
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            );
        }
    }
}
