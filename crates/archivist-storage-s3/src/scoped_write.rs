// SPDX-License-Identifier: Apache-2.0

//! The Phase 10 scoped writers of the S3 adapter (plan Section 7.5):
//! [`S3CatalogWriteStore`] and [`S3DerivedWriteStore`], the portable
//! implementations of [`CatalogWriteStore`] and [`DerivedWriteStore`]
//! over the two dedicated write identities the ARMOR provisioning
//! grants — the catalog writer and the derived writer, each `put+list`
//! below its own prefix and nothing else.
//!
//! Everything here is shaped around the provisioning those identities
//! carry (`docs/notes/armor-storage-provisioning.md`, identities table):
//!
//! - **One namespace per writer, and never the ingest namespaces.** The
//!   catalog writer provisions `tenants/<tenant>/v1/catalog/` — its
//!   checkpoint objects — and the derived writer
//!   `tenants/<tenant>/v1/derived/` — the usage-summary projection, a
//!   redacted-episode pipeline. Raw blobs, occurrence manifests,
//!   attestations, control records, and every other tenant's prefix are
//!   outside both authorities. The key types
//!   ([`CatalogCheckpointKey`], [`DerivedObjectKey`]) carry their
//!   namespace in their grammar, so a key from the wrong namespace does
//!   not parse and a store cannot be handed one; the configuration's
//!   `permits_key`/`permits_list_prefix` predicates are the raw-string
//!   model of the same scope; and the store re-checks both before any
//!   request exists, so a drift between the derivation and the scope
//!   model fails closed.
//! - **Dedicated protected credentials, never shared with another
//!   surface.** Each store is configured from its own configuration
//!   type — [`CatalogWriterConfig`] or [`DerivedWriterConfig`] — a
//!   separate surface with its own credential reference, never a field
//!   of the ingest [`S3StorageConfig`](crate::config::S3StorageConfig).
//!   [`CatalogWriterConfig::reject_shared_credential`] and its derived
//!   mirror refuse the composition mistakes the type split cannot see
//!   on its own: mapping an ingest role, the offline
//!   control-administration credential, or one Phase 10 writer onto the
//!   other writer's credential.
//! - **Append and enumerate, never read or destroy.** The provisioning
//!   grants exactly `put+list` per writer, so each backend seam —
//!   [`CatalogWriteBackend`], [`DerivedWriteBackend`] — exposes exactly
//!   two operations and the action boundary is the trait's own shape,
//!   not a runtime check a caller could bypass: no `get`, no `delete`,
//!   no `abort`, no bucket-level call exists to call. A writer that
//!   needs object bodies back uses the backup/restore identity, which
//!   is not resident on any writer.
//!
//! The concrete binding for each identity is the same composition the
//! other stores use: one HTTP client handle constructed over the
//! endpoint, the tenant bucket, and that writer's credential, enforcing
//! the same prefix scope the deployment's backend policy states. The
//! mock in this module's tests mirrors the ARMOR edge's policy exactly —
//! a literal string-prefix grant per credential, every other key refused
//! — so the stores' requests are proven to stay inside it.

use std::future::Future;

use archivist_protocol::vocabulary::TenantId;
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::scoped_write::{
    CatalogCheckpointKey, CatalogListPrefix, CatalogWriteStore, DerivedListPrefix,
    DerivedObjectKey, DerivedWriteStore,
};

use crate::config::{
    ControlAdminConfig, CredentialReference, EndpointUrl, PathStyle, S3ConfigError,
    S3ConfigErrorKind, S3StorageConfig, StorageRole, Tls,
};

// Content-safe detail literals, one static sentence per failure site —
// the same discipline `archivist-storage`'s error type keeps, pinned
// against the protocol's safe-message grammar by a unit test below.
const DETAIL_KEY_SCOPE: &str = "key is outside this writer identity";
const DETAIL_PREFIX_SCOPE: &str = "list prefix is outside this writer identity";
const DETAIL_ENDPOINT_MISSING: &str = "endpoint url is required";
const DETAIL_ENDPOINT_MALFORMED: &str = "endpoint url is outside the closed grammar";
const DETAIL_REGION_MISSING: &str = "region is required";
const DETAIL_REGION_MALFORMED: &str = "region is outside the closed grammar";
const DETAIL_BUCKET_MISSING: &str = "tenant bucket is required";
const DETAIL_BUCKET_MALFORMED: &str = "tenant bucket is outside the closed grammar";
const DETAIL_TENANT_MISSING: &str = "tenant is required";
const DETAIL_TENANT_MALFORMED: &str = "tenant is outside the closed grammar";
const DETAIL_CREDENTIALS_MISSING: &str = "scoped-writer credential is required";
const DETAIL_CREDENTIALS_MALFORMED: &str = "scoped-writer credential is outside the closed grammar";
const DETAIL_TLS_HTTPS: &str = "https endpoint requires tls enabled";
const DETAIL_TLS_PLAINTEXT: &str = "plaintext endpoint requires explicit tls disabled";
const DETAIL_INGEST_REUSE: &str = "an ingest identity is a scoped-writer credential";
const DETAIL_ADMIN_REUSE: &str = "a scoped writer is the control-administration credential";
const DETAIL_WRITER_SHARED: &str = "the two scoped writers share one credential";

/// The longest plain setting string (the registry string length the
/// other configuration surfaces pin, CFG-016).
const STRING_MAX: usize = 128;

/// The validated shape the two Phase 10 writer configurations share:
/// every provisioned writer identity carries exactly these settings and
/// differs only in the namespace its credential provisions. The public
/// types wrap this core so a catalog configuration and a derived
/// configuration remain distinct surfaces — a store constructor takes
/// one or the other, never a namespace-agnostic value.
#[derive(Clone, Debug)]
struct WriterCore {
    endpoint: EndpointUrl,
    tls: Tls,
    region: Box<str>,
    path_style: PathStyle,
    tenant_bucket: Box<str>,
    tenant: TenantId,
    credentials: CredentialReference,
}

impl WriterCore {
    /// Whether `text` is a bounded plain string: printable ASCII, no
    /// braces, at most [`STRING_MAX`] characters (CFG-016) — the same
    /// rule the ingest and administration surfaces pin.
    fn bounded(text: &str) -> bool {
        !text.is_empty()
            && text.len() <= STRING_MAX
            && text.bytes().all(|byte| (b' '..=b'~').contains(&byte))
            && !text.contains(['{', '}'])
    }
}

/// The unvalidated core under assembly; each public builder's `build` is
/// the single fail-closed gate over it.
#[derive(Clone, Debug, Default)]
struct WriterCoreBuilder {
    endpoint_url: Option<String>,
    tls: Option<Tls>,
    region: Option<String>,
    path_style: Option<PathStyle>,
    tenant_bucket: Option<String>,
    tenant: Option<String>,
    credentials: Option<String>,
}

impl WriterCoreBuilder {
    /// Validate everything assembled so far into one writer core, with
    /// the same rules the administration surface pins: a closed-grammar
    /// endpoint whose scheme agrees with the TLS setting (plaintext only
    /// ever reached affirmatively, SEC-001), bounded region and bucket
    /// strings, a grammar-correct tenant, and a CFG-029 credential
    /// reference. No error echoes the offending value.
    fn build(self) -> Result<WriterCore, S3ConfigError> {
        let endpoint_text = required(self.endpoint_url.as_ref(), DETAIL_ENDPOINT_MISSING)?;
        let endpoint =
            EndpointUrl::parse(&endpoint_text).map_err(|_| malformed(DETAIL_ENDPOINT_MALFORMED))?;
        let tls = self.tls.unwrap_or_default();
        if endpoint.tls() != tls {
            let detail = if endpoint.is_secure() {
                DETAIL_TLS_HTTPS
            } else {
                DETAIL_TLS_PLAINTEXT
            };
            return Err(S3ConfigError::new(
                S3ConfigErrorKind::TransportMismatch,
                detail,
            ));
        }

        let region_text = required(self.region.as_ref(), DETAIL_REGION_MISSING)?;
        if !WriterCore::bounded(&region_text) {
            return Err(malformed(DETAIL_REGION_MALFORMED));
        }

        let bucket_text = required(self.tenant_bucket.as_ref(), DETAIL_BUCKET_MISSING)?;
        if !WriterCore::bounded(&bucket_text) {
            return Err(malformed(DETAIL_BUCKET_MALFORMED));
        }

        let tenant_text = required(self.tenant.as_ref(), DETAIL_TENANT_MISSING)?;
        let tenant =
            TenantId::parse(&tenant_text).map_err(|_| malformed(DETAIL_TENANT_MALFORMED))?;

        let credentials_text = required(self.credentials.as_ref(), DETAIL_CREDENTIALS_MISSING)?;
        let credentials = CredentialReference::parse(&credentials_text)
            .map_err(|_| malformed(DETAIL_CREDENTIALS_MALFORMED))?;

        Ok(WriterCore {
            endpoint,
            tls,
            region: Box::from(region_text),
            path_style: self.path_style.unwrap_or_default(),
            tenant_bucket: Box::from(bucket_text),
            tenant,
            credentials,
        })
    }
}

/// The required-setting gate: `None` is the missing-setting failure.
fn required(value: Option<&String>, missing: &'static str) -> Result<String, S3ConfigError> {
    value.cloned().ok_or(S3ConfigError::new(
        S3ConfigErrorKind::MissingSetting,
        missing,
    ))
}

/// The malformed-setting failure for one detail literal.
fn malformed(detail: &'static str) -> S3ConfigError {
    S3ConfigError::new(S3ConfigErrorKind::MalformedSetting, detail)
}

/// The validated configuration of the catalog-writer identity (plan
/// Section 7.5; the ARMOR provisioning's `put+list` grant below the
/// catalog prefix): the dedicated credential that can append catalog
/// checkpoint objects below one tenant's catalog namespace — and do
/// nothing else.
///
/// This is a separate surface from
/// [`S3StorageConfig`](crate::config::S3StorageConfig) and from
/// [`ControlAdminConfig`](crate::config::ControlAdminConfig) by design:
/// one identity, one configuration, so the deterministic catalog
/// rebuild composes [`S3CatalogWriteStore`] from exactly this type and
/// no other store can. It carries no raw bucket, no encryption policy,
/// and no role mapping, because the writer identity has exactly one
/// capability and no optional companions.
#[derive(Clone, Debug)]
pub struct CatalogWriterConfig {
    core: WriterCore,
}

impl CatalogWriterConfig {
    /// Start assembling a catalog-writer configuration from its tier
    /// values.
    #[must_use]
    pub fn builder() -> CatalogWriterConfigBuilder {
        CatalogWriterConfigBuilder {
            core: WriterCoreBuilder::default(),
        }
    }

    /// The validated endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &EndpointUrl {
        &self.core.endpoint
    }

    /// The configured transport security.
    #[must_use]
    pub const fn tls(&self) -> Tls {
        self.core.tls
    }

    /// The region string the endpoint expects.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.core.region
    }

    /// The bucket addressing style.
    #[must_use]
    pub const fn path_style(&self) -> PathStyle {
        self.core.path_style
    }

    /// The tenant bucket: the bucket holding the tenant's namespace
    /// tree, whose `tenants/<tenant>/v1/catalog/` subtree this identity
    /// provisions.
    #[must_use]
    pub fn tenant_bucket(&self) -> &str {
        &self.core.tenant_bucket
    }

    /// The one tenant whose catalog prefix this identity provisions.
    /// Every checkpoint the store accepts belongs to this tenant, and
    /// every key it writes lives under this tenant's prefix.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.core.tenant
    }

    /// The dedicated catalog-writer credential reference. Distinct by
    /// construction from every ingest credential and the offline
    /// administration credential:
    /// [`CatalogWriterConfig::reject_shared_credential`] refuses a
    /// deployment that reuses any of them here.
    #[must_use]
    pub const fn catalog_write_credentials(&self) -> &CredentialReference {
        &self.core.credentials
    }

    /// Whether a raw object key is inside this identity's provisioned
    /// scope: one canonical catalog-checkpoint key under this tenant's
    /// catalog prefix (plan Section 7.5), and nothing else.
    ///
    /// This is the Rust-side model of the deployment's backend policy
    /// for the catalog-writer credential — put and list below
    /// `tenants/<tenant>/v1/catalog/`, deny every other prefix. Raw
    /// blobs, occurrences, attestations, control records, derived
    /// objects, and every other tenant's prefix are denied; a
    /// checkpoint key with a non-canonical digest segment is denied
    /// rather than normalized. The compatibility-suite profiles prove
    /// the live policy agrees.
    #[must_use]
    pub fn permits_key(&self, key: &str) -> bool {
        CatalogCheckpointKey::parse(key).is_ok_and(|parsed| parsed.tenant() == &self.core.tenant)
    }

    /// Whether a raw list prefix is inside this identity's provisioned
    /// scope: the checkpoint namespace root itself, or a canonical
    /// partial path below it.
    ///
    /// The list-half of [`CatalogWriterConfig::permits_key`]: the
    /// credential's `list` grant reaches exactly the namespace its
    /// `put` grant does, so an enumeration outside it — another
    /// namespace, another tenant, the bucket root — is refused before
    /// any request exists.
    #[must_use]
    pub fn permits_list_prefix(&self, prefix: &str) -> bool {
        prefix.starts_with(&CatalogCheckpointKey::prefix(&self.core.tenant))
    }

    /// Refuse the composition mistakes the type split cannot prevent on
    /// its own: an ingest role mapped onto this writer's credential, the
    /// offline control-administration credential reused here, or the two
    /// Phase 10 writers sharing one credential.
    ///
    /// Each configuration is valid on its own; only the pair (or the
    /// triple) states the violation. A deployment that made any of
    /// these mistakes would collapse the authority split this crate
    /// exists to keep — an ingest replica handed a writer credential,
    /// or one credential asked to serve two namespaces whose grants
    /// differ.
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::DuplicateIdentity`] for any of the three
    /// reuse shapes. The offending reference is not echoed.
    pub fn reject_shared_credential(
        &self,
        ingest: &S3StorageConfig,
        admin: &ControlAdminConfig,
        derived: &DerivedWriterConfig,
    ) -> Result<(), S3ConfigError> {
        for role in StorageRole::all() {
            if ingest.identities().role(*role) == Some(self.catalog_write_credentials()) {
                return Err(S3ConfigError::new(
                    S3ConfigErrorKind::DuplicateIdentity,
                    DETAIL_INGEST_REUSE,
                ));
            }
        }
        if admin.control_admin_credentials() == self.catalog_write_credentials() {
            return Err(S3ConfigError::new(
                S3ConfigErrorKind::DuplicateIdentity,
                DETAIL_ADMIN_REUSE,
            ));
        }
        if derived.derived_write_credentials() == self.catalog_write_credentials() {
            return Err(S3ConfigError::new(
                S3ConfigErrorKind::DuplicateIdentity,
                DETAIL_WRITER_SHARED,
            ));
        }
        Ok(())
    }
}

/// The unvalidated catalog-writer configuration under assembly;
/// [`CatalogWriterConfigBuilder::build`] is its single fail-closed gate,
/// with the same endpoint/TLS agreement rule the other surfaces pin.
#[derive(Clone, Debug, Default)]
pub struct CatalogWriterConfigBuilder {
    core: WriterCoreBuilder,
}

impl CatalogWriterConfigBuilder {
    /// Set the S3-compatible endpoint URL of the tenant bucket.
    #[must_use]
    pub fn endpoint_url(mut self, value: impl Into<String>) -> Self {
        self.core.endpoint_url = Some(value.into());
        self
    }

    /// Set the transport security. Defaults to [`Tls::Enabled`]; a
    /// plaintext endpoint is valid only with an explicit
    /// [`Tls::Disabled`].
    #[must_use]
    pub fn tls(mut self, value: Tls) -> Self {
        self.core.tls = Some(value);
        self
    }

    /// Set the region string.
    #[must_use]
    pub fn region(mut self, value: impl Into<String>) -> Self {
        self.core.region = Some(value.into());
        self
    }

    /// Set the bucket addressing style. Defaults to
    /// [`PathStyle::Path`].
    #[must_use]
    pub fn path_style(mut self, value: PathStyle) -> Self {
        self.core.path_style = Some(value);
        self
    }

    /// Set the tenant bucket.
    #[must_use]
    pub fn tenant_bucket(mut self, value: impl Into<String>) -> Self {
        self.core.tenant_bucket = Some(value.into());
        self
    }

    /// Set the tenant whose catalog prefix this identity provisions.
    /// Required: the writer identity is single-tenant by design.
    #[must_use]
    pub fn tenant(mut self, value: impl Into<String>) -> Self {
        self.core.tenant = Some(value.into());
        self
    }

    /// Set the dedicated catalog-writer credential reference (CFG-029
    /// grammar). Required.
    #[must_use]
    pub fn catalog_write_credentials(mut self, value: impl Into<String>) -> Self {
        self.core.credentials = Some(value.into());
        self
    }

    /// Validate everything assembled so far into a
    /// [`CatalogWriterConfig`].
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::MissingSetting`] when a required setting
    /// never arrived; [`S3ConfigErrorKind::MalformedSetting`] when a
    /// setting is outside its grammar;
    /// [`S3ConfigErrorKind::TransportMismatch`] when the endpoint scheme
    /// and the TLS setting disagree. No error echoes the offending
    /// value.
    pub fn build(self) -> Result<CatalogWriterConfig, S3ConfigError> {
        self.core.build().map(|core| CatalogWriterConfig { core })
    }
}

/// The validated configuration of the derived-writer identity (plan
/// Section 7.5; the ARMOR provisioning's `put+list` grant below the
/// derived prefix): the dedicated credential that can append derived
/// projection objects below one tenant's derived namespace — and do
/// nothing else.
///
/// The mirror of [`CatalogWriterConfig`] one namespace over, composed
/// by the derived-content pipelines (the usage-summary producer inside
/// the deterministic catalog rebuild, a redacted-episode pipeline) into
/// [`S3DerivedWriteStore`] and never by any other store.
#[derive(Clone, Debug)]
pub struct DerivedWriterConfig {
    core: WriterCore,
}

impl DerivedWriterConfig {
    /// Start assembling a derived-writer configuration from its tier
    /// values.
    #[must_use]
    pub fn builder() -> DerivedWriterConfigBuilder {
        DerivedWriterConfigBuilder {
            core: WriterCoreBuilder::default(),
        }
    }

    /// The validated endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &EndpointUrl {
        &self.core.endpoint
    }

    /// The configured transport security.
    #[must_use]
    pub const fn tls(&self) -> Tls {
        self.core.tls
    }

    /// The region string the endpoint expects.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.core.region
    }

    /// The bucket addressing style.
    #[must_use]
    pub const fn path_style(&self) -> PathStyle {
        self.core.path_style
    }

    /// The tenant bucket: the bucket holding the tenant's namespace
    /// tree, whose `tenants/<tenant>/v1/derived/` subtree this identity
    /// provisions.
    #[must_use]
    pub fn tenant_bucket(&self) -> &str {
        &self.core.tenant_bucket
    }

    /// The one tenant whose derived prefix this identity provisions.
    /// Every projection the store accepts belongs to this tenant, and
    /// every key it writes lives under this tenant's prefix.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.core.tenant
    }

    /// The dedicated derived-writer credential reference. Distinct by
    /// construction from every ingest credential, the offline
    /// administration credential, and the catalog writer's:
    /// [`DerivedWriterConfig::reject_shared_credential`] refuses a
    /// deployment that reuses any of them here.
    #[must_use]
    pub const fn derived_write_credentials(&self) -> &CredentialReference {
        &self.core.credentials
    }

    /// Whether a raw object key is inside this identity's provisioned
    /// scope: one canonical derived-projection key under this tenant's
    /// derived prefix (plan Section 7.5), and nothing else.
    ///
    /// This is the Rust-side model of the deployment's backend policy
    /// for the derived-writer credential — put and list below
    /// `tenants/<tenant>/v1/derived/`, deny every other prefix. Raw
    /// blobs, occurrences, attestations, control records, catalog
    /// checkpoints, and every other tenant's prefix are denied; a
    /// projection key with an empty, relative, or oversized segment is
    /// denied rather than normalized. The compatibility-suite profiles
    /// prove the live policy agrees.
    #[must_use]
    pub fn permits_key(&self, key: &str) -> bool {
        DerivedObjectKey::parse(key).is_ok_and(|parsed| parsed.tenant() == &self.core.tenant)
    }

    /// Whether a raw list prefix is inside this identity's provisioned
    /// scope: the derived namespace root itself, or a canonical partial
    /// path below it.
    ///
    /// The list-half of [`DerivedWriterConfig::permits_key`]: the
    /// credential's `list` grant reaches exactly the namespace its
    /// `put` grant does.
    #[must_use]
    pub fn permits_list_prefix(&self, prefix: &str) -> bool {
        prefix.starts_with(&DerivedObjectKey::prefix(&self.core.tenant))
    }

    /// Refuse the composition mistakes the type split cannot prevent on
    /// its own: an ingest role mapped onto this writer's credential, the
    /// offline control-administration credential reused here, or the two
    /// Phase 10 writers sharing one credential. The mirror of
    /// [`CatalogWriterConfig::reject_shared_credential`].
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::DuplicateIdentity`] for any of the three
    /// reuse shapes. The offending reference is not echoed.
    pub fn reject_shared_credential(
        &self,
        ingest: &S3StorageConfig,
        admin: &ControlAdminConfig,
        catalog: &CatalogWriterConfig,
    ) -> Result<(), S3ConfigError> {
        for role in StorageRole::all() {
            if ingest.identities().role(*role) == Some(self.derived_write_credentials()) {
                return Err(S3ConfigError::new(
                    S3ConfigErrorKind::DuplicateIdentity,
                    DETAIL_INGEST_REUSE,
                ));
            }
        }
        if admin.control_admin_credentials() == self.derived_write_credentials() {
            return Err(S3ConfigError::new(
                S3ConfigErrorKind::DuplicateIdentity,
                DETAIL_ADMIN_REUSE,
            ));
        }
        if catalog.catalog_write_credentials() == self.derived_write_credentials() {
            return Err(S3ConfigError::new(
                S3ConfigErrorKind::DuplicateIdentity,
                DETAIL_WRITER_SHARED,
            ));
        }
        Ok(())
    }
}

/// The unvalidated derived-writer configuration under assembly;
/// [`DerivedWriterConfigBuilder::build`] is its single fail-closed gate,
/// with the same endpoint/TLS agreement rule the other surfaces pin.
#[derive(Clone, Debug, Default)]
pub struct DerivedWriterConfigBuilder {
    core: WriterCoreBuilder,
}

impl DerivedWriterConfigBuilder {
    /// Set the S3-compatible endpoint URL of the tenant bucket.
    #[must_use]
    pub fn endpoint_url(mut self, value: impl Into<String>) -> Self {
        self.core.endpoint_url = Some(value.into());
        self
    }

    /// Set the transport security. Defaults to [`Tls::Enabled`]; a
    /// plaintext endpoint is valid only with an explicit
    /// [`Tls::Disabled`].
    #[must_use]
    pub fn tls(mut self, value: Tls) -> Self {
        self.core.tls = Some(value);
        self
    }

    /// Set the region string.
    #[must_use]
    pub fn region(mut self, value: impl Into<String>) -> Self {
        self.core.region = Some(value.into());
        self
    }

    /// Set the bucket addressing style. Defaults to
    /// [`PathStyle::Path`].
    #[must_use]
    pub fn path_style(mut self, value: PathStyle) -> Self {
        self.core.path_style = Some(value);
        self
    }

    /// Set the tenant bucket.
    #[must_use]
    pub fn tenant_bucket(mut self, value: impl Into<String>) -> Self {
        self.core.tenant_bucket = Some(value.into());
        self
    }

    /// Set the tenant whose derived prefix this identity provisions.
    /// Required: the writer identity is single-tenant by design.
    #[must_use]
    pub fn tenant(mut self, value: impl Into<String>) -> Self {
        self.core.tenant = Some(value.into());
        self
    }

    /// Set the dedicated derived-writer credential reference (CFG-029
    /// grammar). Required.
    #[must_use]
    pub fn derived_write_credentials(mut self, value: impl Into<String>) -> Self {
        self.core.credentials = Some(value.into());
        self
    }

    /// Validate everything assembled so far into a
    /// [`DerivedWriterConfig`].
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::MissingSetting`] when a required setting
    /// never arrived; [`S3ConfigErrorKind::MalformedSetting`] when a
    /// setting is outside its grammar;
    /// [`S3ConfigErrorKind::TransportMismatch`] when the endpoint scheme
    /// and the TLS setting disagree. No error echoes the offending
    /// value.
    pub fn build(self) -> Result<DerivedWriterConfig, S3ConfigError> {
        self.core.build().map(|core| DerivedWriterConfig { core })
    }
}

/// The S3 request seam of the catalog-writer identity: the two object
/// primitives the credential needs, keyed by the derived
/// [`CatalogCheckpointKey`] and [`CatalogListPrefix`] only.
///
/// The trait is deliberately narrower than an S3 client: there is no
/// get, no delete, no multipart, no arbitrary-key method, and no
/// bucket-level call — the provisioned credential holds `put+list`
/// below the tenant catalog prefix and nothing else, so this is the
/// entire surface that authority has. A concrete binding (the reference
/// profile's HTTP client over the catalog-writer credential) implements
/// these operations over `PutObject` and `ListObjectsV2` and enforces
/// the same prefix scope the deployment's backend policy states: put
/// and list below `tenants/<tenant>/v1/catalog/`, deny every other
/// prefix — and a scoped client always lists with an explicit in-scope
/// prefix, never a bare bucket request. The mock in this module's tests
/// mirrors that denial so the store's requests are proven to stay
/// inside it.
///
/// The verbs the provisioning withholds are pinned the same way the
/// control-read seam pins its own — `compile_fail` doc tests that
/// type-check only if this seam has grown an authority the catalog
/// writer was never granted:
///
/// ```compile_fail
/// // No destroy verb: the writer appends and enumerates; removal is
/// // not a primitive this identity holds.
/// use archivist_storage::scoped_write::CatalogCheckpointKey;
/// use archivist_storage_s3::scoped_write::CatalogWriteBackend;
///
/// fn prove<B: CatalogWriteBackend>(backend: &B, key: &CatalogCheckpointKey) {
///     backend.delete_catalog_object(key);
/// }
/// ```
///
/// ```compile_fail
/// // No read verb: object bodies come back only through the
/// // backup/restore identity, never through a writer.
/// use archivist_storage::scoped_write::CatalogCheckpointKey;
/// use archivist_storage_s3::scoped_write::CatalogWriteBackend;
///
/// fn prove<B: CatalogWriteBackend>(backend: &B, key: &CatalogCheckpointKey) {
///     backend.get_catalog_object(key);
/// }
/// ```
///
/// ```compile_fail
/// // No multipart session: a checkpoint lands as one PutObject, so
/// // there is no upload to initiate, part, or complete.
/// use archivist_storage::scoped_write::CatalogCheckpointKey;
/// use archivist_storage_s3::scoped_write::CatalogWriteBackend;
///
/// fn prove<B: CatalogWriteBackend>(backend: &B, key: &CatalogCheckpointKey) {
///     backend.create_multipart_upload(key);
/// }
/// ```
pub trait CatalogWriteBackend {
    /// Write `bytes` at one derived checkpoint key.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the key is
    /// outside this credential's provisioned prefix.
    fn put_catalog_object(
        &self,
        key: &CatalogCheckpointKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Enumerate the keys below one validated list prefix.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the prefix is
    /// outside this credential's provisioned namespace.
    fn list_catalog_objects(
        &self,
        prefix: &CatalogListPrefix,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send;
}

/// The S3 request seam of the derived-writer identity: the two object
/// primitives the credential needs, keyed by the derived
/// [`DerivedObjectKey`] and [`DerivedListPrefix`] only.
///
/// The same shape one namespace over: no get, no delete, no multipart,
/// no arbitrary-key method, no bucket-level call — `put+list` below the
/// tenant derived prefix is the entire surface this authority has. A
/// concrete binding implements these operations over `PutObject` and
/// `ListObjectsV2` (always with an explicit in-scope prefix) and
/// enforces the same prefix scope the deployment's backend policy
/// states. The mock in this module's tests mirrors that denial so the
/// store's requests are proven to stay inside it.
///
/// The withheld verbs are pinned exactly as on the catalog seam:
///
/// ```compile_fail
/// // No destroy verb: a projection is superseded by the next version's
/// // object, never removed by the writer that produced it.
/// use archivist_storage::scoped_write::DerivedObjectKey;
/// use archivist_storage_s3::scoped_write::DerivedWriteBackend;
///
/// fn prove<B: DerivedWriteBackend>(backend: &B, key: &DerivedObjectKey) {
///     backend.delete_derived_object(key);
/// }
/// ```
///
/// ```compile_fail
/// // No read verb: the producer's own bytes are the input, and object
/// // bodies come back only through the backup/restore identity.
/// use archivist_storage::scoped_write::DerivedObjectKey;
/// use archivist_storage_s3::scoped_write::DerivedWriteBackend;
///
/// fn prove<B: DerivedWriteBackend>(backend: &B, key: &DerivedObjectKey) {
///     backend.get_derived_object(key);
/// }
/// ```
///
/// ```compile_fail
/// // No multipart session: a projection lands as one PutObject.
/// use archivist_storage::scoped_write::DerivedObjectKey;
/// use archivist_storage_s3::scoped_write::DerivedWriteBackend;
///
/// fn prove<B: DerivedWriteBackend>(backend: &B, key: &DerivedObjectKey) {
///     backend.create_multipart_upload(key);
/// }
/// ```
pub trait DerivedWriteBackend {
    /// Write `bytes` at one derived object key.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the key is
    /// outside this credential's provisioned prefix.
    fn put_derived_object(
        &self,
        key: &DerivedObjectKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Enumerate the keys below one validated list prefix.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`] when the backend or network is
    /// down; [`StorageErrorKind::ScopeViolation`] when the prefix is
    /// outside this credential's provisioned namespace.
    fn list_derived_objects(
        &self,
        prefix: &DerivedListPrefix,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send;
}

/// The portable S3 [`CatalogWriteStore`]: one catalog-writer
/// configuration, one backend seam, and the prefix checks that keep
/// every request inside the provisioned namespace.
///
/// Composed by the deterministic catalog rebuild (the Phase 10
/// workflow the provisioning pins this identity for), never by an
/// ingest replica and never alongside the ingest configuration's
/// credentials:
/// [`CatalogWriterConfig::reject_shared_credential`] refuses a
/// deployment that tries either reuse.
///
/// The authorities this store must never grow are pinned at compile
/// time, so an erosion fails a build instead of a review:
///
/// ```compile_fail
/// // A writer is not an administrator: the offline control
/// // administration stays on the ControlAdminStore boundary.
/// use archivist_storage::control::ControlAdminStore;
/// use archivist_storage_s3::scoped_write::S3CatalogWriteStore;
///
/// struct ProbeBackend;
///
/// fn prove(store: &S3CatalogWriteStore<ProbeBackend>) {
///     fn admin_authority<T: ControlAdminStore>(_: &T) {}
///     admin_authority(store);
/// }
/// ```
///
/// ```compile_fail
/// // A writer is not the raw writer: the raw namespaces stay with
/// // archivist-storage's RawWriteStore boundary.
/// use archivist_storage::raw_write::RawWriteStore;
/// use archivist_storage_s3::scoped_write::S3CatalogWriteStore;
///
/// struct ProbeBackend;
///
/// fn prove(store: &S3CatalogWriteStore<ProbeBackend>) {
///     fn raw_write_authority<T: RawWriteStore>(_: &T) {}
///     raw_write_authority(store);
/// }
/// ```
///
/// ```compile_fail
/// // The catalog writer is not the derived writer: one namespace per
/// // identity, and the sibling's authority is the other identity's
/// // configuration and store.
/// use archivist_storage::scoped_write::DerivedWriteStore;
/// use archivist_storage_s3::scoped_write::S3CatalogWriteStore;
///
/// struct ProbeBackend;
///
/// fn prove(store: &S3CatalogWriteStore<ProbeBackend>) {
///     fn derived_authority<T: DerivedWriteStore>(_: &T) {}
///     derived_authority(store);
/// }
/// ```
pub struct S3CatalogWriteStore<B> {
    config: CatalogWriterConfig,
    backend: B,
}

impl<B> S3CatalogWriteStore<B> {
    /// Compose the catalog-writer authority: the validated
    /// configuration (its credential reference and pinned tenant) over
    /// one backend seam.
    #[must_use]
    pub const fn new(config: CatalogWriterConfig, backend: B) -> Self {
        Self { config, backend }
    }

    /// The catalog-writer configuration this store was composed with.
    #[must_use]
    pub const fn config(&self) -> &CatalogWriterConfig {
        &self.config
    }
}

impl<B: CatalogWriteBackend + Sync> CatalogWriteStore for S3CatalogWriteStore<B> {
    async fn put_checkpoint(
        &self,
        key: &CatalogCheckpointKey,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        // The backend permission model, enforced store-side as well: the
        // presented key must sit inside the one provisioned namespace
        // this configuration pins, tenant and layout both. Unreachable
        // while the key derivation and the scope model agree — which is
        // exactly the agreement a drift between the two must fail closed
        // on, before any request is issued against the writer
        // credential.
        if key.tenant() != self.config.tenant() || !self.config.permits_key(key.as_str()) {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_KEY_SCOPE,
            ));
        }
        self.backend.put_catalog_object(key, bytes).await
    }

    async fn list_checkpoints(
        &self,
        prefix: &CatalogListPrefix,
    ) -> Result<Vec<String>, StorageError> {
        if !self.config.permits_list_prefix(prefix.as_str()) {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_PREFIX_SCOPE,
            ));
        }
        self.backend.list_catalog_objects(prefix).await
    }
}

/// The portable S3 [`DerivedWriteStore`]: one derived-writer
/// configuration, one backend seam, and the prefix checks that keep
/// every request inside the provisioned namespace.
///
/// Composed by the derived-content pipelines (the usage-summary
/// producer, a redacted-episode pipeline) — the Phase 10 workflows the
/// provisioning pins this identity for — never by an ingest replica.
///
/// The same compile-time pins one namespace over:
///
/// ```compile_fail
/// // A writer is not an administrator.
/// use archivist_storage::control::ControlAdminStore;
/// use archivist_storage_s3::scoped_write::S3DerivedWriteStore;
///
/// struct ProbeBackend;
///
/// fn prove(store: &S3DerivedWriteStore<ProbeBackend>) {
///     fn admin_authority<T: ControlAdminStore>(_: &T) {}
///     admin_authority(store);
/// }
/// ```
///
/// ```compile_fail
/// // A writer is not the raw writer.
/// use archivist_storage::raw_write::RawWriteStore;
/// use archivist_storage_s3::scoped_write::S3DerivedWriteStore;
///
/// struct ProbeBackend;
///
/// fn prove(store: &S3DerivedWriteStore<ProbeBackend>) {
///     fn raw_write_authority<T: RawWriteStore>(_: &T) {}
///     raw_write_authority(store);
/// }
/// ```
///
/// ```compile_fail
/// // The derived writer is not the catalog writer: the checkpoint
/// // namespace is the sibling identity's authority.
/// use archivist_storage::scoped_write::CatalogWriteStore;
/// use archivist_storage_s3::scoped_write::S3DerivedWriteStore;
///
/// struct ProbeBackend;
///
/// fn prove(store: &S3DerivedWriteStore<ProbeBackend>) {
///     fn catalog_authority<T: CatalogWriteStore>(_: &T) {}
///     catalog_authority(store);
/// }
/// ```
pub struct S3DerivedWriteStore<B> {
    config: DerivedWriterConfig,
    backend: B,
}

impl<B> S3DerivedWriteStore<B> {
    /// Compose the derived-writer authority: the validated
    /// configuration (its credential reference and pinned tenant) over
    /// one backend seam.
    #[must_use]
    pub const fn new(config: DerivedWriterConfig, backend: B) -> Self {
        Self { config, backend }
    }

    /// The derived-writer configuration this store was composed with.
    #[must_use]
    pub const fn config(&self) -> &DerivedWriterConfig {
        &self.config
    }
}

impl<B: DerivedWriteBackend + Sync> DerivedWriteStore for S3DerivedWriteStore<B> {
    async fn put_object(&self, key: &DerivedObjectKey, bytes: &[u8]) -> Result<(), StorageError> {
        // The same store-side enforcement as the catalog writer: tenant
        // and layout must both sit inside the one provisioned namespace
        // before any request exists.
        if key.tenant() != self.config.tenant() || !self.config.permits_key(key.as_str()) {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_KEY_SCOPE,
            ));
        }
        self.backend.put_derived_object(key, bytes).await
    }

    async fn list_objects(&self, prefix: &DerivedListPrefix) -> Result<Vec<String>, StorageError> {
        if !self.config.permits_list_prefix(prefix.as_str()) {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_PREFIX_SCOPE,
            ));
        }
        self.backend.list_derived_objects(prefix).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use archivist_protocol::sha256::{digest, encode_hex};
    use archivist_protocol::usage_summary::{
        MessageUsage, OccurrenceProvenance, SourceUsageCounts, UsageRegion, UsageSummary,
    };
    use archivist_protocol::vocabulary::{AdapterId, OccurrenceId, SafeMessage, VersionToken};
    use archivist_storage::scoped_write::{
        CatalogCheckpointKey, CatalogListPrefix, CatalogWriteStore, DerivedListPrefix,
        DerivedObjectKey, DerivedWriteStore,
    };

    use super::{
        CatalogWriteBackend, CatalogWriterConfig, CatalogWriterConfigBuilder, DerivedWriteBackend,
        DerivedWriterConfig, DerivedWriterConfigBuilder, S3CatalogWriteStore, S3DerivedWriteStore,
    };
    use crate::config::{
        ControlAdminConfig, ControlAdminConfigBuilder, PathStyle, S3ConfigErrorKind,
        S3StorageConfigBuilder, Tls,
    };

    // The golden identifiers shared with the sibling boundary suites, so
    // every layer of this boundary tells one story.
    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
    const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";
    const ENDPOINT: &str = "https://s3.example.invalid";
    const REGION: &str = "us-east-1";
    const TENANT_BUCKET: &str = "archivist-tenant-example";
    const CONTROL_BUCKET: &str = "archivist-control-example";
    const RAW_BUCKET: &str = "archivist-raw-example";
    const CATALOG_REF: &str = "file:/etc/archivist/storage/catalog-writer-credentials";
    const DERIVED_REF: &str = "file:/etc/archivist/storage/derived-writer-credentials";
    const ADMIN_REF: &str = "file:/etc/archivist/storage/control-admin-credentials";
    const RAW_WRITE_REF: &str = "file:/etc/archivist/storage/raw-write-credentials";
    const CONTROL_READ_REF: &str = "file:/etc/archivist/storage/control-read-credentials";

    fn tenant() -> archivist_protocol::vocabulary::TenantId {
        TENANT.parse().unwrap()
    }

    fn other_tenant() -> archivist_protocol::vocabulary::TenantId {
        OTHER_TENANT.parse().unwrap()
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        // A no-dependency executor for futures that complete without
        // pending (the same helper the sibling store tests use).
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            match future.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    /// The complete unvalidated core every missing-setting strip starts
    /// from.
    fn complete_core() -> super::WriterCoreBuilder {
        super::WriterCoreBuilder {
            endpoint_url: Some(ENDPOINT.to_owned()),
            tls: None,
            region: Some(REGION.to_owned()),
            path_style: None,
            tenant_bucket: Some(TENANT_BUCKET.to_owned()),
            tenant: Some(TENANT.to_owned()),
            credentials: Some(CATALOG_REF.to_owned()),
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

    fn ingest_config() -> crate::config::S3StorageConfig {
        S3StorageConfigBuilder::default()
            .endpoint_url(ENDPOINT)
            .region(REGION)
            .encryption(crate::config::EncryptionPolicy::S3Sse)
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

    /// The per-request counters, so a test can prove a refused call
    /// never issued one and an exercised path issued exactly the verbs
    /// the provisioning grants.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct Counters {
        puts: u32,
        lists: u32,
        refused_puts: u32,
        refused_lists: u32,
    }

    /// The in-memory backend: an object map and the two prefix grants
    /// the deployment's writer credentials state. The check is the
    /// policy's own shape — a literal string-prefix rule per identity,
    /// put and list below the granted prefix and deny everything else —
    /// exactly how the ARMOR edge evaluates an ACL, so the stores'
    /// requests are proven to stay inside the grants the way a live
    /// backend would enforce them.
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

        fn put_under_grant(
            &self,
            grant_ok: bool,
            key: &str,
            bytes: &[u8],
        ) -> Result<(), archivist_storage::error::StorageError> {
            let mut counters = self.counters.lock().expect("test backend lock");
            if !grant_ok {
                counters.refused_puts += 1;
                return Err(archivist_storage::error::StorageError::new(
                    archivist_storage::error::StorageErrorKind::ScopeViolation,
                    "key is outside this writer identity",
                ));
            }
            self.objects
                .lock()
                .expect("test backend lock")
                .insert(key.to_owned(), bytes.to_vec());
            counters.puts += 1;
            Ok(())
        }

        fn list_under_grant(
            &self,
            grant_ok: bool,
            prefix: &str,
        ) -> Result<Vec<String>, archivist_storage::error::StorageError> {
            let mut counters = self.counters.lock().expect("test backend lock");
            if !grant_ok {
                counters.refused_lists += 1;
                return Err(archivist_storage::error::StorageError::new(
                    archivist_storage::error::StorageErrorKind::ScopeViolation,
                    "list prefix is outside this writer identity",
                ));
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
        ) -> Result<(), archivist_storage::error::StorageError> {
            let ok = self.catalog_policy_permits(key.as_str());
            self.put_under_grant(ok, key.as_str(), bytes)
        }

        async fn list_catalog_objects(
            &self,
            prefix: &CatalogListPrefix,
        ) -> Result<Vec<String>, archivist_storage::error::StorageError> {
            let ok = self.catalog_policy_permits(prefix.as_str());
            self.list_under_grant(ok, prefix.as_str())
        }
    }

    impl DerivedWriteBackend for MapBackend {
        async fn put_derived_object(
            &self,
            key: &DerivedObjectKey,
            bytes: &[u8],
        ) -> Result<(), archivist_storage::error::StorageError> {
            let ok = self.derived_policy_permits(key.as_str());
            self.put_under_grant(ok, key.as_str(), bytes)
        }

        async fn list_derived_objects(
            &self,
            prefix: &DerivedListPrefix,
        ) -> Result<Vec<String>, archivist_storage::error::StorageError> {
            let ok = self.derived_policy_permits(prefix.as_str());
            self.list_under_grant(ok, prefix.as_str())
        }
    }

    fn catalog_writer() -> S3CatalogWriteStore<MapBackend> {
        S3CatalogWriteStore::new(catalog_config(), MapBackend::new())
    }

    fn derived_writer() -> S3DerivedWriteStore<MapBackend> {
        S3DerivedWriteStore::new(derived_config(), MapBackend::new())
    }

    /// Canonical checkpoint bytes for the write-path story: the rebuild
    /// is deterministic, so the same raw prefix derives the same bytes.
    fn checkpoint_bytes(seed: u8) -> Vec<u8> {
        format!("{{\"checkpoints\":[\"occurrence-{seed:03}\"],\"seed\":{seed}}}\n").into_bytes()
    }

    fn checkpoint_key(bytes: &[u8]) -> CatalogCheckpointKey {
        CatalogCheckpointKey::new(&tenant(), &digest_of(bytes))
    }

    fn digest_of(bytes: &[u8]) -> archivist_protocol::vocabulary::BlobDigest {
        archivist_protocol::vocabulary::BlobDigest::parse(&encode_hex(&digest(bytes))).unwrap()
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

    #[test]
    fn every_error_detail_is_a_safe_message() {
        for detail in [
            super::DETAIL_KEY_SCOPE,
            super::DETAIL_PREFIX_SCOPE,
            super::DETAIL_ENDPOINT_MISSING,
            super::DETAIL_ENDPOINT_MALFORMED,
            super::DETAIL_REGION_MISSING,
            super::DETAIL_REGION_MALFORMED,
            super::DETAIL_BUCKET_MISSING,
            super::DETAIL_BUCKET_MALFORMED,
            super::DETAIL_TENANT_MISSING,
            super::DETAIL_TENANT_MALFORMED,
            super::DETAIL_CREDENTIALS_MISSING,
            super::DETAIL_CREDENTIALS_MALFORMED,
            super::DETAIL_TLS_HTTPS,
            super::DETAIL_TLS_PLAINTEXT,
            super::DETAIL_INGEST_REUSE,
            super::DETAIL_ADMIN_REUSE,
            super::DETAIL_WRITER_SHARED,
        ] {
            let parsed = SafeMessage::parse(detail)
                .unwrap_or_else(|_| panic!("detail is not a safe message: {detail}"));
            assert_eq!(parsed.as_str(), detail);
        }
    }

    #[test]
    fn builders_report_every_missing_setting() {
        // An otherwise complete assembly with exactly one required
        // setting stripped; the gate must name that setting's own
        // missing detail and nothing else.
        let stripped: [(CatalogWriterConfigBuilder, &str); 5] = [
            (
                CatalogWriterConfigBuilder {
                    core: super::WriterCoreBuilder {
                        endpoint_url: None,
                        ..complete_core()
                    },
                },
                super::DETAIL_ENDPOINT_MISSING,
            ),
            (
                CatalogWriterConfigBuilder {
                    core: super::WriterCoreBuilder {
                        region: None,
                        ..complete_core()
                    },
                },
                super::DETAIL_REGION_MISSING,
            ),
            (
                CatalogWriterConfigBuilder {
                    core: super::WriterCoreBuilder {
                        tenant_bucket: None,
                        ..complete_core()
                    },
                },
                super::DETAIL_BUCKET_MISSING,
            ),
            (
                CatalogWriterConfigBuilder {
                    core: super::WriterCoreBuilder {
                        tenant: None,
                        ..complete_core()
                    },
                },
                super::DETAIL_TENANT_MISSING,
            ),
            (
                CatalogWriterConfigBuilder {
                    core: super::WriterCoreBuilder {
                        credentials: None,
                        ..complete_core()
                    },
                },
                super::DETAIL_CREDENTIALS_MISSING,
            ),
        ];
        for (builder, missing) in stripped {
            let error = builder.build().unwrap_err();
            assert_eq!(error.kind(), S3ConfigErrorKind::MissingSetting, "{missing}");
            assert_eq!(error.detail(), missing);
        }

        // The derived builder runs the identical gate.
        let error = DerivedWriterConfigBuilder::default().build().unwrap_err();
        assert_eq!(error.kind(), S3ConfigErrorKind::MissingSetting);
        assert_eq!(error.detail(), super::DETAIL_ENDPOINT_MISSING);
    }

    #[test]
    fn builders_report_every_malformed_setting() {
        // A braced region, a braced bucket, a non-UUID tenant, a
        // credential without a CFG-029 kind, and an endpoint outside
        // the closed URL grammar.
        for (detail, build) in [
            (
                super::DETAIL_REGION_MALFORMED,
                CatalogWriterConfigBuilder::default()
                    .endpoint_url(ENDPOINT)
                    .region("not{a}region")
                    .tenant_bucket(TENANT_BUCKET)
                    .tenant(TENANT)
                    .catalog_write_credentials(CATALOG_REF),
            ),
            (
                super::DETAIL_BUCKET_MALFORMED,
                CatalogWriterConfigBuilder::default()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .tenant_bucket("bucket{brace}")
                    .tenant(TENANT)
                    .catalog_write_credentials(CATALOG_REF),
            ),
            (
                super::DETAIL_TENANT_MALFORMED,
                CatalogWriterConfigBuilder::default()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .tenant_bucket(TENANT_BUCKET)
                    .tenant("not-a-uuid")
                    .catalog_write_credentials(CATALOG_REF),
            ),
            (
                super::DETAIL_CREDENTIALS_MALFORMED,
                CatalogWriterConfigBuilder::default()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .tenant_bucket(TENANT_BUCKET)
                    .tenant(TENANT)
                    .catalog_write_credentials("not-a-reference"),
            ),
            (
                super::DETAIL_ENDPOINT_MALFORMED,
                CatalogWriterConfigBuilder::default()
                    .endpoint_url("ftp://s3.example.invalid")
                    .region(REGION)
                    .tenant_bucket(TENANT_BUCKET)
                    .tenant(TENANT)
                    .catalog_write_credentials(CATALOG_REF),
            ),
        ] {
            let error = build.build().unwrap_err();
            assert_eq!(
                error.kind(),
                S3ConfigErrorKind::MalformedSetting,
                "{detail}"
            );
            assert_eq!(error.detail(), detail);
        }
    }

    #[test]
    fn builders_refuse_transport_disagreement_both_ways() {
        // An https endpoint with TLS disabled, and a plaintext endpoint
        // left on the default: one decision stated twice, twice wrong.
        for (detail, build) in [
            (
                super::DETAIL_TLS_HTTPS,
                CatalogWriterConfigBuilder::default()
                    .endpoint_url(ENDPOINT)
                    .tls(Tls::Disabled)
                    .region(REGION)
                    .tenant_bucket(TENANT_BUCKET)
                    .tenant(TENANT)
                    .catalog_write_credentials(CATALOG_REF),
            ),
            (
                super::DETAIL_TLS_PLAINTEXT,
                CatalogWriterConfigBuilder::default()
                    .endpoint_url("http://s3.example.invalid")
                    .region(REGION)
                    .tenant_bucket(TENANT_BUCKET)
                    .tenant(TENANT)
                    .catalog_write_credentials(CATALOG_REF),
            ),
        ] {
            let error = build.build().unwrap_err();
            assert_eq!(
                error.kind(),
                S3ConfigErrorKind::TransportMismatch,
                "{detail}"
            );
            assert_eq!(error.detail(), detail);
        }
    }

    #[test]
    fn a_complete_assembly_carries_the_pinned_members() {
        let config = catalog_config();
        assert_eq!(config.endpoint().as_str(), ENDPOINT);
        assert_eq!(config.tls(), Tls::Enabled);
        assert_eq!(config.region(), REGION);
        assert_eq!(config.path_style(), PathStyle::Path);
        assert_eq!(config.tenant_bucket(), TENANT_BUCKET);
        assert_eq!(config.tenant(), &tenant());
        assert_eq!(
            *config.catalog_write_credentials(),
            crate::config::CredentialReference::parse(CATALOG_REF).unwrap()
        );

        let derived = derived_config();
        assert_eq!(derived.tenant(), &tenant());
        assert_eq!(derived.tenant_bucket(), TENANT_BUCKET);
        assert_eq!(
            *derived.derived_write_credentials(),
            crate::config::CredentialReference::parse(DERIVED_REF).unwrap()
        );
    }

    #[test]
    fn permits_key_admits_exactly_the_provisioned_namespace() {
        let catalog = catalog_config();
        let derived = derived_config();
        let tenant = tenant();
        let other = other_tenant();

        // The catalog writer admits exactly its own checkpoint keys.
        let checkpoint = checkpoint_key(&checkpoint_bytes(7));
        assert!(catalog.permits_key(checkpoint.as_str()));
        // The derived writer admits exactly its own projection keys,
        // including the usage summary's real derived layout.
        let usage_key = usage_summary().object_key();
        let projection =
            DerivedObjectKey::new(&tenant, "usage", "1", "usage-summaries/ab/abcd.json").unwrap();
        assert!(derived.permits_key(&usage_key));
        assert!(derived.permits_key(projection.as_str()));

        // Neither writer admits the other's namespace, the raw or
        // control prefixes, another tenant's prefix, or any malformed
        // shape — denied rather than normalized.
        let raw_blob = format!(
            "tenants/{tenant}/v1/raw/blobs/01/{}.zst",
            encode_hex(&digest(b"b"))
        );
        let control_key = format!("tenants/{tenant}/v1/control/clients/{CLIENT}.json");
        let other_checkpoint = CatalogCheckpointKey::new(&other, &digest_of(b"x"))
            .as_str()
            .to_owned();
        let other_projection =
            DerivedObjectKey::new(&other, "usage", "1", "usage-summaries/ab/abcd.json")
                .unwrap()
                .as_str()
                .to_owned();
        let tenant_root = format!("tenants/{tenant}/v1/");
        for denied in [
            raw_blob.as_str(),
            control_key.as_str(),
            other_checkpoint.as_str(),
            other_projection.as_str(),
            "",
            "tenants",
            tenant_root.as_str(),
        ] {
            assert!(!catalog.permits_key(denied), "catalog must deny: {denied}");
            assert!(!derived.permits_key(denied), "derived must deny: {denied}");
        }
        // Each writer's own namespace is the other writer's out-of-scope
        // prefix: the derived key is denied by the catalog identity and
        // the checkpoint key by the derived identity.
        assert!(!catalog.permits_key(&usage_key));
        assert!(!catalog.permits_key(projection.as_str()));
        assert!(!derived.permits_key(checkpoint.as_str()));
    }

    #[test]
    fn keys_from_other_namespaces_do_not_parse() {
        // The strongest form the prefix boundary takes: a raw or control
        // key is not merely denied by policy — it does not parse as a
        // scoped-writer key at all, so no store method can accept one.
        let tenant = tenant();
        let raw_blob = format!(
            "tenants/{tenant}/v1/raw/blobs/01/{}.zst",
            encode_hex(&digest(b"b"))
        );
        let control_key = format!("tenants/{tenant}/v1/control/clients/{CLIENT}.json");
        let attestation = format!(
            "tenants/{tenant}/v1/raw/attestations/{}.json",
            encode_hex(&digest(b"a"))
        );

        for foreign in [&raw_blob, &control_key, &attestation] {
            assert!(CatalogCheckpointKey::parse(foreign).is_err());
            assert!(DerivedObjectKey::parse(foreign).is_err());
        }

        // And the canonical round trip holds for the layouts each writer
        // owns: new-then-parse-then-new converges on the same key.
        let checkpoint = checkpoint_key(&checkpoint_bytes(1));
        let reparsed = CatalogCheckpointKey::parse(checkpoint.as_str()).unwrap();
        assert_eq!(reparsed.as_str(), checkpoint.as_str());
        assert_eq!(reparsed.checkpoint(), checkpoint.checkpoint());
        let usage_key = usage_summary().object_key();
        let reparsed = DerivedObjectKey::parse(&usage_key).unwrap();
        assert_eq!(reparsed.as_str(), usage_key);
        assert_eq!(reparsed.tenant(), &tenant);
    }

    #[test]
    fn permits_list_prefix_bounds_enumeration_to_the_namespace() {
        let catalog = catalog_config();
        let derived = derived_config();
        let tenant = tenant();

        // Each root and one canonical partial path below it: admitted.
        let catalog_root = CatalogCheckpointKey::prefix(&tenant);
        let derived_root = DerivedObjectKey::prefix(&tenant);
        assert!(catalog.permits_list_prefix(&catalog_root));
        assert!(derived.permits_list_prefix(&derived_root));
        assert!(derived.permits_list_prefix(&format!("{derived_root}usage/1/")));

        // The raw and control prefixes, the bare tenant tree root,
        // another tenant's namespace, and the empty prefix: denied by
        // both — and each writer's own list scope excludes the other
        // writer's namespace, the same exclusion `permits_key` pins.
        let raw_root = format!("tenants/{tenant}/v1/raw/");
        let control_root = format!("tenants/{tenant}/v1/control/");
        let other_root = DerivedObjectKey::prefix(&other_tenant());
        let tenant_root = format!("tenants/{tenant}/v1/");
        for denied in [
            raw_root.as_str(),
            control_root.as_str(),
            other_root.as_str(),
            tenant_root.as_str(),
            "",
        ] {
            assert!(!catalog.permits_list_prefix(denied), "catalog: {denied}");
            assert!(!derived.permits_list_prefix(denied), "derived: {denied}");
        }
        assert!(!catalog.permits_list_prefix(&derived_root));
        assert!(!derived.permits_list_prefix(&catalog_root));

        // The validated list-prefix types agree with the predicates.
        assert!(CatalogListPrefix::parse(&tenant, &catalog_root).is_ok());
        assert!(CatalogListPrefix::parse(&tenant, &raw_root).is_err());
        assert!(DerivedListPrefix::parse(&tenant, &derived_root).is_ok());
        assert!(DerivedListPrefix::parse(&tenant, &control_root).is_err());
    }

    #[test]
    fn catalog_write_path_appends_and_enumerates_checkpoints() {
        let writer = catalog_writer();
        let first = checkpoint_key(&checkpoint_bytes(1));
        let second = checkpoint_key(&checkpoint_bytes(2));

        block_on(writer.put_checkpoint(&first, &checkpoint_bytes(1))).unwrap();
        block_on(writer.put_checkpoint(&second, &checkpoint_bytes(2))).unwrap();
        // The bytes are written unconditionally: a replay of the same
        // deterministic rebuild at the same derived key converges.
        block_on(writer.put_checkpoint(&first, &checkpoint_bytes(1))).unwrap();

        assert_eq!(
            writer.backend.stored(first.as_str()),
            Some(checkpoint_bytes(1))
        );
        assert_eq!(
            writer.backend.stored(second.as_str()),
            Some(checkpoint_bytes(2))
        );

        let listed =
            block_on(writer.list_checkpoints(&CatalogListPrefix::root(&tenant()))).unwrap();
        // The backend returns the namespace in key order; the expected
        // set is sorted the same way.
        let mut expected = vec![first.as_str().to_owned(), second.as_str().to_owned()];
        expected.sort_unstable();
        assert_eq!(listed, expected);
        // The exercised verbs are exactly the two the credential
        // grants: three puts, one list, no refused request.
        assert_eq!(
            writer.backend.counters(),
            Counters {
                puts: 3,
                lists: 1,
                refused_puts: 0,
                refused_lists: 0,
            }
        );
    }

    #[test]
    fn derived_write_path_lands_the_usage_summary_projection() {
        let writer = derived_writer();
        let summary = usage_summary();
        let key = DerivedObjectKey::parse(&summary.object_key()).unwrap();

        block_on(writer.put_object(&key, &summary.serialized())).unwrap();

        assert_eq!(
            writer.backend.stored(key.as_str()),
            Some(summary.serialized())
        );
        let listed = block_on(writer.list_objects(&DerivedListPrefix::root(&tenant()))).unwrap();
        assert_eq!(listed, vec![key.as_str().to_owned()]);
        // The stored key is the projection's own pure function of its
        // bytes — the derivation and the writer agree on one address.
        assert_eq!(key.as_str(), summary.object_key());
        assert_eq!(
            writer.backend.counters(),
            Counters {
                puts: 1,
                lists: 1,
                refused_puts: 0,
                refused_lists: 0,
            }
        );
    }

    #[test]
    fn stores_refuse_foreign_tenants_without_issuing_a_request() {
        let catalog = catalog_writer();
        let derived = derived_writer();
        let other = other_tenant();

        // A valid key of another tenant parses, so the store's own scope
        // check is what refuses it — before any request exists.
        let foreign_checkpoint = CatalogCheckpointKey::new(&other, &digest_of(b"x"));
        let error = block_on(catalog.put_checkpoint(&foreign_checkpoint, b"bytes")).unwrap_err();
        assert_eq!(
            error.kind(),
            archivist_storage::error::StorageErrorKind::ScopeViolation
        );
        assert_eq!(error.detail(), super::DETAIL_KEY_SCOPE);

        // A list prefix validated for another tenant is refused the same
        // way.
        let foreign_root = CatalogListPrefix::root(&other);
        let error = block_on(catalog.list_checkpoints(&foreign_root)).unwrap_err();
        assert_eq!(
            error.kind(),
            archivist_storage::error::StorageErrorKind::ScopeViolation
        );
        assert_eq!(error.detail(), super::DETAIL_PREFIX_SCOPE);

        let foreign_projection =
            DerivedObjectKey::new(&other, "usage", "1", "usage-summaries/ab/abcd.json").unwrap();
        let error = block_on(derived.put_object(&foreign_projection, b"bytes")).unwrap_err();
        assert_eq!(
            error.kind(),
            archivist_storage::error::StorageErrorKind::ScopeViolation
        );
        assert_eq!(error.detail(), super::DETAIL_KEY_SCOPE);

        let foreign_derived_root = DerivedListPrefix::root(&other);
        let error = block_on(derived.list_objects(&foreign_derived_root)).unwrap_err();
        assert_eq!(
            error.kind(),
            archivist_storage::error::StorageErrorKind::ScopeViolation
        );
        assert_eq!(error.detail(), super::DETAIL_PREFIX_SCOPE);

        // Nothing was issued: no put, no list, and no request reached
        // the refusal path inside the backend either.
        assert_eq!(catalog.backend.counters(), Counters::default());
        assert_eq!(derived.backend.counters(), Counters::default());
    }

    #[test]
    fn the_edge_policy_denies_the_raw_and_control_prefixes() {
        // The deployment's own grant shape, evaluated the way a live
        // backend evaluates an ACL: a literal string-prefix rule. Even a
        // caller that bypassed the stores entirely could not put or
        // list outside the granted prefix — this is the policy the
        // compatibility-suite profiles prove live.
        let backend = MapBackend::new();
        let tenant = tenant();

        let raw_blob = format!(
            "tenants/{tenant}/v1/raw/blobs/01/{}.zst",
            encode_hex(&digest(b"b"))
        );
        let control_key = format!("tenants/{tenant}/v1/control/clients/{CLIENT}.json");
        let raw_root = format!("tenants/{tenant}/v1/raw/");
        let control_root = format!("tenants/{tenant}/v1/control/");
        let foreign_root = format!("tenants/{}/v1/catalog/", other_tenant());
        let catalog_key = checkpoint_key(&checkpoint_bytes(3)).as_str().to_owned();
        let derived_key = usage_summary().object_key();

        for out_of_scope in [
            raw_blob.as_str(),
            control_key.as_str(),
            raw_root.as_str(),
            control_root.as_str(),
            "",
            foreign_root.as_str(),
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

        // Each writer's own namespace is the one its grant admits — and
        // only its own: the catalog grant does not cover the derived
        // prefix, nor the derived grant the catalog prefix.
        assert!(backend.catalog_policy_permits(&catalog_key));
        assert!(!backend.catalog_policy_permits(&derived_key));
        assert!(backend.derived_policy_permits(&derived_key));
        assert!(!backend.derived_policy_permits(&catalog_key));
    }

    #[test]
    fn reject_shared_credential_refuses_every_reuse_shape() {
        let ingest = ingest_config();
        let admin = admin_config();
        let catalog = catalog_config();
        let derived = derived_config();

        // The honest deployment: every identity distinct.
        catalog
            .reject_shared_credential(&ingest, &admin, &derived)
            .unwrap();
        derived
            .reject_shared_credential(&ingest, &admin, &catalog)
            .unwrap();

        // An ingest role mapped onto the writer credential.
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
        assert_eq!(error.detail(), super::DETAIL_INGEST_REUSE);

        // The offline administration credential reused as a writer.
        let derived_as_admin = DerivedWriterConfigBuilder::default()
            .endpoint_url(ENDPOINT)
            .region(REGION)
            .tenant_bucket(TENANT_BUCKET)
            .tenant(TENANT)
            .derived_write_credentials(ADMIN_REF)
            .build()
            .unwrap();
        let error = derived_as_admin
            .reject_shared_credential(&ingest, &admin, &catalog)
            .unwrap_err();
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
        assert_eq!(error.detail(), super::DETAIL_ADMIN_REUSE);

        // The two Phase 10 writers sharing one credential.
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
        assert_eq!(error.detail(), super::DETAIL_WRITER_SHARED);
        let error = derived_as_catalog
            .reject_shared_credential(&ingest, &admin, &catalog)
            .unwrap_err();
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
        assert_eq!(error.detail(), super::DETAIL_WRITER_SHARED);
    }
}
