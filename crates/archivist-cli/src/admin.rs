// SPDX-License-Identifier: Apache-2.0

//! The offline administration control-plane composition (plan Section 5).
//!
//! Every `admin` command shares one composition, and this module is it:
//! resolve the registered `admin.*` configuration keys into a
//! [`ControlAdminConfig`] through its builder, assemble the
//! [`S3ControlAdminStore`] the commands hold from that administration
//! configuration alone — never from the ingest configuration — and carry the
//! authority-seed reference for the signing acts to resolve at use
//! (SEC-006), never at composition.
//!
//! The authority split is proven, not assumed. The ingest `storage.*` keys
//! are resolved into an [`S3StorageConfig`] solely so
//! [`S3StorageConfig::reject_administration_credential`] can refuse the one
//! composition mistake the type split cannot prevent on its own: a
//! deployment that mapped an ingest role onto the offline
//! control-administration credential. That ingest configuration is then
//! discarded — no store is ever assembled from it here.
//!
//! Transport security follows the endpoint scheme, and the v1 registry
//! declares no `tls` key for either surface, so composition is `https`-only:
//! the builders refuse a plaintext endpoint that is not affirmatively
//! marked (SEC-001), and no registered tier can supply that mark yet.
//!
//! The store is generic over the administration request seam
//! ([`archivist_storage_s3::control_admin::ControlAdminBackend`]): the live
//! backend arrives with its owning
//! deliverable, and the command handlers attach at the binary's composition
//! point in theirs. Composition owns the configuration halves and the
//! boundary proof; behavior over the seam is the store's own, already
//! landed and tested there.

use std::fmt;

use archivist_client_core::config::{ResolvedConfig, SecretRef};
use archivist_storage_s3::config::{
    ControlAdminConfig, EncryptionPolicy, PathStyle, S3ConfigError, S3ConfigErrorKind,
    S3StorageConfig, S3StorageConfigBuilder,
};
use archivist_storage_s3::control_admin::S3ControlAdminStore;

/// The administration control plane one `admin` command invocation holds:
/// the store assembled from the administration configuration and the
/// authority-seed reference that invocation's signing acts will resolve.
///
/// The seed is carried as the reference the registry resolved ([`SecretRef`])
/// — the pointer, never the value. Resolving it is the signing act's own
/// step and lives with the command behavior that needs it.
pub struct AdminControlPlane<B> {
    store: S3ControlAdminStore<B>,
    authority_seed_ref: SecretRef,
}

impl<B> AdminControlPlane<B> {
    /// The administration store, assembled from the administration
    /// configuration only.
    #[must_use]
    pub const fn store(&self) -> &S3ControlAdminStore<B> {
        &self.store
    }

    /// The unresolved authority-seed reference (`admin.authority_seed_ref`).
    ///
    /// Composition never resolves this: it hands the pointer to the signing
    /// act, which enforces the protected-material checks when it reads the
    /// seed (CFG-030, SEC-006).
    #[must_use]
    pub const fn authority_seed_ref(&self) -> &SecretRef {
        &self.authority_seed_ref
    }
}

/// The backend is rendered as a marker (it holds request machinery, not
/// configuration) and the seed reference renders through its own
/// redacting `Debug`.
impl<B> fmt::Debug for AdminControlPlane<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminControlPlane")
            .field("store", &"S3ControlAdminStore")
            .field("authority_seed_ref", &self.authority_seed_ref)
            .finish()
    }
}

/// Compose the administration control plane the `admin` commands share.
///
/// `resolved` is the invocation's fully-resolved configuration (every
/// registered key, whatever the owning crate); `backend` is the
/// administration request seam the store is assembled over. The
/// administration configuration is built from the `admin.*` keys, the
/// ingest configuration from the `storage.*` keys, and the pair is checked:
/// [`S3StorageConfig::reject_administration_credential`] refuses a
/// deployment that mapped any ingest role — required or optional — onto the
/// administration credential before any store exists to write with it.
///
/// The ingest configuration serves only that boundary proof and is
/// discarded; the returned store is assembled from the administration
/// configuration alone.
///
/// # Errors
/// [`S3ConfigErrorKind::MissingSetting`] when a composition-required key
/// did not resolve — unreachable while the registry marks those keys
/// required, because the load itself fails first, and the guard stands for
/// any future registry that makes them optional;
/// [`S3ConfigErrorKind::MalformedSetting`] when a resolved value is outside
/// its closed grammar (endpoint, bucket, region bounds, tenant UUID,
/// path-style or encryption token, credential-reference grammar);
/// [`S3ConfigErrorKind::TransportMismatch`] when an endpoint scheme
/// disagrees with the derived transport security;
/// [`S3ConfigErrorKind::DuplicateIdentity`] when two ingest roles share one
/// credential reference, or when an ingest role is mapped onto the
/// administration credential — the authority-split refusal this composition
/// exists to enforce. No error echoes a value or a reference target.
pub fn compose_admin_control_plane<B>(
    resolved: &ResolvedConfig,
    backend: B,
) -> Result<AdminControlPlane<B>, S3ConfigError> {
    let admin = admin_config(resolved)?;
    let ingest = ingest_config(resolved)?;
    // The joint check: each configuration is valid on its own, and only the
    // pair states the violation. Refused here, no store is assembled.
    ingest.reject_administration_credential(&admin)?;
    let authority_seed_ref = required_admin_reference(resolved, "admin.authority_seed_ref")?;
    Ok(AdminControlPlane {
        store: S3ControlAdminStore::new(admin, backend),
        authority_seed_ref: authority_seed_ref.clone(),
    })
}

/// Build the administration configuration from the registered `admin.*`
/// keys, through its builder — the single fail-closed gate that validates
/// the endpoint, region, bucket, tenant, and credential grammars.
fn admin_config(resolved: &ResolvedConfig) -> Result<ControlAdminConfig, S3ConfigError> {
    ControlAdminConfig::builder()
        .endpoint_url(required_admin_text(resolved, "admin.endpoint_url")?.to_owned())
        .region(required_admin_text(resolved, "admin.region")?.to_owned())
        .path_style(path_style_token(required_admin_text(
            resolved,
            "admin.path_style",
        )?)?)
        .control_bucket(required_admin_text(resolved, "admin.control_bucket")?.to_owned())
        .tenant(required_admin_text(resolved, "admin.tenant")?.to_owned())
        .control_admin_credentials(reference_text(required_admin_reference(
            resolved,
            "admin.credentials_ref",
        )?))
        .build()
}

/// Build the ingest configuration from the registered `storage.*` keys.
///
/// This configuration is never assembled into a store here; it exists so
/// [`S3StorageConfig::reject_administration_credential`] can state the
/// authority split over the pair, and it fails closed on its own grammars
/// first — a boundary proof over a malformed ingest configuration would
/// prove nothing.
fn ingest_config(resolved: &ResolvedConfig) -> Result<S3StorageConfig, S3ConfigError> {
    let mut builder = S3StorageConfigBuilder::default()
        .endpoint_url(required_ingest_text(resolved, "storage.endpoint_url")?.to_owned())
        .region(required_ingest_text(resolved, "storage.region")?.to_owned())
        .path_style(path_style_token(required_ingest_text(
            resolved,
            "storage.path_style",
        )?)?)
        .encryption(encryption_policy_token(required_ingest_text(
            resolved,
            "storage.encryption",
        )?)?)
        .raw_bucket(required_ingest_text(resolved, "storage.raw_bucket")?.to_owned())
        .control_bucket(required_ingest_text(resolved, "storage.control_bucket")?.to_owned())
        .raw_write_credentials(reference_text(required_ingest_reference(
            resolved,
            "storage.raw_write_credentials_ref",
        )?))
        .control_read_credentials(reference_text(required_ingest_reference(
            resolved,
            "storage.control_read_credentials_ref",
        )?));
    // The optional preflight and offline identities count in the boundary
    // check exactly like the required ones: a deployment that mapped the
    // administration credential onto either optional role has still
    // collapsed the split.
    if let Some(reference) = resolved.reference("storage.raw_read_credentials_ref") {
        builder = builder.raw_read_credentials(reference_text(reference));
    }
    if let Some(reference) = resolved.reference("storage.offline_restore_credentials_ref") {
        builder = builder.offline_restore_credentials(reference_text(reference));
    }
    builder.build()
}

/// A required administration setting's text. The registry resolves these as
/// required keys, so the load has already failed any host without them;
/// this refusal stands for a future registry that makes them optional.
fn required_admin_text<'a>(
    resolved: &'a ResolvedConfig,
    key: &str,
) -> Result<&'a str, S3ConfigError> {
    resolved
        .text(key)
        .ok_or_else(|| S3ConfigError::new(S3ConfigErrorKind::MissingSetting, MISSING_ADMIN))
}

/// A required ingest storage setting's text, with the same standing guard
/// as the administration half.
fn required_ingest_text<'a>(
    resolved: &'a ResolvedConfig,
    key: &str,
) -> Result<&'a str, S3ConfigError> {
    resolved
        .text(key)
        .ok_or_else(|| S3ConfigError::new(S3ConfigErrorKind::MissingSetting, MISSING_INGEST))
}

/// A required administration secret reference, carried unresolved.
fn required_admin_reference<'a>(
    resolved: &'a ResolvedConfig,
    key: &str,
) -> Result<&'a SecretRef, S3ConfigError> {
    resolved
        .reference(key)
        .ok_or_else(|| S3ConfigError::new(S3ConfigErrorKind::MissingSetting, MISSING_ADMIN))
}

/// A required ingest secret reference, carried unresolved.
fn required_ingest_reference<'a>(
    resolved: &'a ResolvedConfig,
    key: &str,
) -> Result<&'a SecretRef, S3ConfigError> {
    resolved
        .reference(key)
        .ok_or_else(|| S3ConfigError::new(S3ConfigErrorKind::MissingSetting, MISSING_INGEST))
}

/// Render one resolved reference back to its CFG-029 text so the storage
/// builders re-parse it through their own grammar. The loader validated the
/// reference into this shape, so the round trip is lossless, and the value
/// behind the reference never appears — only the pointer's canonical text.
fn reference_text(reference: &SecretRef) -> String {
    match reference {
        SecretRef::File { path } => format!("file:{}", path.display()),
        SecretRef::Env { name } => format!("env:{name}"),
    }
}

/// Parse a registry path-style token, failing closed on any drift between
/// the registry's closed value set and the model's tokens.
fn path_style_token(text: &str) -> Result<PathStyle, S3ConfigError> {
    PathStyle::parse(text)
        .map_err(|_| S3ConfigError::new(S3ConfigErrorKind::MalformedSetting, MALFORMED_PATH_STYLE))
}

/// Parse a registry encryption-policy token, failing closed on drift.
fn encryption_policy_token(text: &str) -> Result<EncryptionPolicy, S3ConfigError> {
    EncryptionPolicy::parse(text)
        .map_err(|_| S3ConfigError::new(S3ConfigErrorKind::MalformedSetting, MALFORMED_ENCRYPTION))
}

/// The content-free detail for an administration setting that resolved from
/// no tier: static literals only, per the configuration diagnostics
/// discipline (CFG-013).
const MISSING_ADMIN: &str = "an administration setting did not resolve from any tier";

/// The content-free detail for an ingest storage setting that resolved from
/// no tier.
const MISSING_INGEST: &str = "an ingest storage setting did not resolve from any tier";

/// The content-free detail for a non-canonical path-style token.
const MALFORMED_PATH_STYLE: &str = "path style token is not canonical";

/// The content-free detail for a non-canonical encryption-policy token.
const MALFORMED_ENCRYPTION: &str = "encryption policy token is not canonical";

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use archivist_client_core::config::{ConfigSources, SecretRef};
    use archivist_storage::error::StorageError;
    use archivist_storage_s3::config::{PathStyle, S3ConfigErrorKind};
    use archivist_storage_s3::control_admin::{ControlAdminBackend, ControlObjectKey};

    use super::compose_admin_control_plane;

    /// The tenant every fixture provisions (the registry's example value,
    /// canonical `uuid-v4` grammar).
    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";

    /// The administration endpoint, deliberately distinct from the ingest
    /// endpoint so a composition that drew the store's endpoint from the
    /// wrong surface cannot pass.
    const ADMIN_ENDPOINT: &str = "https://control.example.invalid";

    /// The synthetic environment of a fully-declared host: every
    /// required-without-default registered key through the environment
    /// tier, so one load resolves the whole registry. The secret
    /// references point at `env:` targets that are deliberately never set:
    /// nothing in this composition resolves secret material, and the
    /// fixtures prove it by carrying the references alone.
    fn base_sources() -> ConfigSources {
        ConfigSources::non_interactive()
            .env("HOME", "/home/operator")
            .env(
                "ARCHIVIST_INGEST_ENDPOINT_URL",
                "https://ingest.example.invalid",
            )
            .env(
                "ARCHIVIST_STORAGE_ENDPOINT_URL",
                "https://s3.example.invalid",
            )
            .env("ARCHIVIST_STORAGE_REGION", "us-east-1")
            .env("ARCHIVIST_STORAGE_ENCRYPTION", "s3_sse")
            .env("ARCHIVIST_STORAGE_RAW_BUCKET", "archivist-raw-example")
            .env(
                "ARCHIVIST_STORAGE_CONTROL_BUCKET",
                "archivist-control-example",
            )
            .env(
                "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
                "env:TEST_RAW_CREDENTIAL",
            )
            .env(
                "ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF",
                "env:TEST_CONTROL_CREDENTIAL",
            )
            .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "127.0.0.1:8087")
            .env("ARCHIVIST_ADMIN_ENDPOINT_URL", ADMIN_ENDPOINT)
            .env("ARCHIVIST_ADMIN_REGION", "us-east-1")
            .env(
                "ARCHIVIST_ADMIN_CONTROL_BUCKET",
                "archivist-control-example",
            )
            .env("ARCHIVIST_ADMIN_TENANT", TENANT)
            .env(
                "ARCHIVIST_ADMIN_CREDENTIALS_REF",
                "env:TEST_ADMIN_CREDENTIAL",
            )
            .env(
                "ARCHIVIST_ADMIN_AUTHORITY_SEED_REF",
                "env:TEST_AUTHORITY_SEED",
            )
    }

    /// The request seam the composition is proven over: a real
    /// [`ControlAdminBackend`] implementor, map-backed, so the composed
    /// plane holds the kind of store the commands will hold. The
    /// composition tests exercise assembly and refusal, not store behavior
    /// — that is the store's own, landed with it.
    #[derive(Debug, Default)]
    struct MapBackend {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl ControlAdminBackend for MapBackend {
        async fn get_control_object(
            &self,
            key: &ControlObjectKey,
        ) -> Result<Option<Vec<u8>>, StorageError> {
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
            envelope: &[u8],
        ) -> Result<(), StorageError> {
            self.objects
                .lock()
                .expect("test backend lock")
                .insert(key.as_str().to_owned(), envelope.to_vec());
            Ok(())
        }
    }

    #[test]
    fn composition_assembles_the_store_from_the_administration_configuration() {
        let resolved = base_sources().load().expect("fully declared host loads");
        let plane = compose_admin_control_plane(&resolved, MapBackend::default())
            .expect("the split configuration composes");
        let config = plane.store().config();
        assert_eq!(config.endpoint().as_str(), ADMIN_ENDPOINT);
        assert_eq!(config.region(), "us-east-1");
        // The registry's path-style default flows through the builder.
        assert_eq!(config.path_style(), PathStyle::Path);
        assert_eq!(config.control_bucket(), "archivist-control-example");
        assert_eq!(config.tenant().as_str(), TENANT);
        // The store's endpoint is the administration endpoint, not the
        // ingest surface's — the fixture keeps them distinct so a
        // composition fed from the wrong surface cannot pass.
        assert_ne!(config.endpoint().as_str(), "https://s3.example.invalid");
    }

    #[test]
    fn authority_seed_is_carried_as_an_unresolved_reference() {
        let resolved = base_sources().load().expect("fully declared host loads");
        let plane = compose_admin_control_plane(&resolved, MapBackend::default())
            .expect("the split configuration composes");
        // Carried, never resolved: the composition holds the pointer, and
        // the env: target it names is deliberately unset in this fixture.
        assert!(matches!(
            plane.authority_seed_ref(),
            SecretRef::Env { name } if name.as_ref() == "TEST_AUTHORITY_SEED"
        ));
    }

    #[test]
    fn required_ingest_role_on_the_administration_credential_is_refused() {
        let sources = base_sources().env(
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            "env:TEST_ADMIN_CREDENTIAL",
        );
        let resolved = sources.load().expect("fully declared host loads");
        let error = compose_admin_control_plane(&resolved, MapBackend::default())
            .expect_err("an ingest role mapped onto the administration credential");
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
    }

    #[test]
    fn optional_ingest_role_on_the_administration_credential_is_refused() {
        let sources = base_sources().env(
            "ARCHIVIST_STORAGE_RAW_READ_CREDENTIALS_REF",
            "env:TEST_ADMIN_CREDENTIAL",
        );
        let resolved = sources.load().expect("fully declared host loads");
        let error = compose_admin_control_plane(&resolved, MapBackend::default())
            .expect_err("an optional ingest role mapped onto the administration credential");
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
    }

    #[test]
    fn malformed_administration_tenant_is_refused_at_validation() {
        let sources = base_sources().env("ARCHIVIST_ADMIN_TENANT", "not-a-uuid");
        // The registry types the key as a plain string, so the load accepts
        // it; the composition's builder gate refuses the grammar.
        let resolved = sources.load().expect("the string grammar itself resolves");
        let error = compose_admin_control_plane(&resolved, MapBackend::default())
            .expect_err("a non-canonical tenant is refused at validation");
        assert_eq!(error.kind(), S3ConfigErrorKind::MalformedSetting);
    }

    #[test]
    fn plaintext_administration_endpoint_is_refused() {
        let sources = base_sources().env(
            "ARCHIVIST_ADMIN_ENDPOINT_URL",
            "http://control.example.invalid",
        );
        let resolved = sources.load().expect("the string grammar itself resolves");
        let error = compose_admin_control_plane(&resolved, MapBackend::default())
            .expect_err("a plaintext endpoint without an affirmative tls mark is refused");
        assert_eq!(error.kind(), S3ConfigErrorKind::TransportMismatch);
    }
}
