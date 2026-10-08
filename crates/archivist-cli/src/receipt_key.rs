// SPDX-License-Identifier: Apache-2.0

//! The `admin receipt-key` command: create a tenant-scoped receipt signing
//! key, protect its private seed locally, certify its public half with the
//! configured tenant authority, and publish the immutable control record.

use std::path::Path;

use archivist_auth::receipt::{
    AuthoritySigner, CertifiedReceiptKey, ReceiptKeyError, ReceiptSigningKey,
};
use archivist_auth::reference::ProtectedReference;
use archivist_client_core::cli::{CliError, CommandHandler, Invocation};
use archivist_client_core::config::{ConfigError, ResolvedConfig, SecretRef};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::Timestamp;
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage_s3::config::{S3ConfigError, S3ConfigErrorKind};
use archivist_storage_s3::control_admin::ControlAdminBackend;
use archivist_storage_s3::request::{S3RequestBackend, S3RequestErrorKind};

const SECRET_REF_REFUSED: &str = "client.secret_ref_refused";
const TRANSPORT_FAILED: &str = "transport.connection_failed";
const INTEGRITY_CONFLICT: &str = "storage.integrity_conflict";
const RECEIPT_SIGNING_KEY_PATH: &str = "admin.receipt_signing_key_path";

/// Attach `admin receipt-key` to the composition root.
#[must_use]
pub fn handlers() -> [(&'static str, CommandHandler); 1] {
    [("admin receipt-key", command as CommandHandler)]
}

/// Run `admin receipt-key` through the configured administration identity.
/// Configuration is resolved before constructing the concrete S3 request
/// backend, and the registered seed destination is checked as an absolute
/// path.
///
/// # Errors
/// Returns the registered configuration, protected-reference, or S3
/// publication refusal; diagnostics never include key material or paths.
pub fn command(invocation: &Invocation) -> Result<Value, CliError> {
    let sources = invocation
        .config_sources()
        .capture_environment()
        .map_err(|error| config_fault(&error))?;
    let resolved = sources.load().map_err(|error| config_fault(&error))?;
    let path = seed_path(&resolved)?;
    let config = crate::admin::admin_config(&resolved).map_err(composition_fault)?;
    let backend = S3RequestBackend::control_admin(&config).map_err(request_fault)?;
    issue_at(&resolved, path, backend)
}

/// Run the command over an administration request seam, allowing the
/// publication behavior to be checked without a live object store.
///
/// # Errors
/// Returns the registered configuration, protected-reference, or publication
/// refusal without exposing key material or paths.
pub fn run<B: ControlAdminBackend + Sync>(
    invocation: &Invocation,
    backend: B,
) -> Result<Value, CliError> {
    let sources = invocation
        .config_sources()
        .capture_environment()
        .map_err(|error| config_fault(&error))?;
    let resolved = sources.load().map_err(|error| config_fault(&error))?;
    let path = seed_path(&resolved)?;
    issue_at(&resolved, path, backend)
}

/// Generate, certify, persist, and publish one receipt signing key against
/// already-resolved configuration. Only the signed public control record is
/// returned; neither the seed nor its destination appears in the result.
///
/// # Errors
/// Returns the registered configuration, protected-reference, or publication
/// refusal without exposing key material or paths.
pub fn issue_at<B: ControlAdminBackend + Sync>(
    resolved: &ResolvedConfig,
    seed_path: &Path,
    backend: B,
) -> Result<Value, CliError> {
    if !seed_path.is_absolute() {
        return Err(CliError::usage());
    }

    let plane =
        crate::admin::compose_admin_control_plane(resolved, backend).map_err(composition_fault)?;
    let tenant = plane.store().config().tenant().clone();

    // Recreate the auth crate's protected-reference type from the already
    // parsed config reference. This keeps path and seed material opaque in
    // diagnostics while letting its resolver enforce CFG-030 against the
    // file actually opened.
    let authority_reference = protected_reference(plane.authority_seed_ref());
    let authority = AuthoritySigner::from_secret_reference(tenant.clone(), &authority_reference)
        .map_err(|_error| CliError::registered(SECRET_REF_REFUSED))?;

    let certificate_path = certificate_path(seed_path);
    if certificate_path
        .try_exists()
        .map_err(|_| CliError::usage())?
    {
        return Err(CliError::usage());
    }
    let now = archivist_client_core::cli::now_rfc3339();
    let signed_at = Timestamp::parse(&now).map_err(|_| CliError::internal())?;
    let key = ReceiptSigningKey::generate(tenant).map_err(|_error| CliError::usage())?;
    key.write_new(seed_path)
        .map_err(|_error| CliError::usage())?;
    let certified = CertifiedReceiptKey::certify(key, &authority, signed_at.clone(), signed_at)
        .map_err(receipt_fault)?;
    let certificate_bytes = certified.certificate().canonical_bytes();
    write_public_certificate(&certificate_path, &certificate_bytes)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CliError::internal())?;
    runtime
        .block_on(plane.store().put_receipt_key(certified.record()))
        .map_err(storage_fault)?;

    let certificate = json::parse(&certified.certificate().canonical_bytes())
        .map_err(|_| CliError::internal())?;
    let record =
        json::parse(&certified.record().canonical_bytes()).map_err(|_| CliError::internal())?;
    let mut result = Object::new();
    result.set("schema", Value::Text("archivist.cli-result/v1".to_owned()));
    result.set("certificate", certificate);
    result.set("record", record);
    Ok(Value::Object(result))
}

fn certificate_path(seed_path: &Path) -> std::path::PathBuf {
    let mut path = seed_path.as_os_str().to_os_string();
    path.push(".certificate.json");
    path.into()
}

#[cfg(unix)]
fn write_public_certificate(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .map_err(|_| CliError::usage())?;
    file.set_permissions(std::fs::Permissions::from_mode(0o644))
        .map_err(|_| CliError::usage())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| CliError::usage())
}

#[cfg(not(unix))]
fn write_public_certificate(_path: &Path, _bytes: &[u8]) -> Result<(), CliError> {
    Err(CliError::usage())
}

fn seed_path(resolved: &ResolvedConfig) -> Result<&Path, CliError> {
    let path = resolved
        .path(RECEIPT_SIGNING_KEY_PATH)
        .ok_or_else(|| CliError::registered("cli.decision_missing"))?;
    if !path.is_absolute() {
        return Err(CliError::usage());
    }
    Ok(path)
}

fn protected_reference(reference: &SecretRef) -> ProtectedReference {
    match reference {
        SecretRef::File { path } => ProtectedReference::File {
            path: path.to_path_buf().into_boxed_path(),
        },
        SecretRef::Env { name } => ProtectedReference::Env { name: name.clone() },
    }
}

fn config_fault(error: &ConfigError) -> CliError {
    CliError::registered(error.code().token())
}

fn composition_fault(error: S3ConfigError) -> CliError {
    match error.kind() {
        S3ConfigErrorKind::MissingSetting => CliError::registered("cli.decision_missing"),
        S3ConfigErrorKind::MalformedSetting
        | S3ConfigErrorKind::TransportMismatch
        | S3ConfigErrorKind::DuplicateIdentity => CliError::usage(),
    }
}

fn request_fault(error: archivist_storage_s3::request::S3RequestError) -> CliError {
    match error.kind() {
        S3RequestErrorKind::CredentialUnavailable | S3RequestErrorKind::CredentialMalformed => {
            CliError::registered(SECRET_REF_REFUSED)
        }
        S3RequestErrorKind::EndpointMalformed => CliError::usage(),
    }
}

fn receipt_fault(error: ReceiptKeyError) -> CliError {
    match error {
        ReceiptKeyError::SecretReference(_) => CliError::registered(SECRET_REF_REFUSED),
        _ => CliError::internal(),
    }
}

fn storage_fault(error: StorageError) -> CliError {
    match error.kind() {
        StorageErrorKind::IntegrityConflict => CliError::registered(INTEGRITY_CONFLICT),
        StorageErrorKind::Unavailable | StorageErrorKind::CapabilityUnavailable => {
            CliError::registered(TRANSPORT_FAILED)
        }
        _ => CliError::internal(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Mutex};

    use archivist_auth::authority::PinnedAuthorityRoot;
    use archivist_auth::identity::TenantAuthority;
    use archivist_auth::receipt::{ReceiptKeyCertificate, ReceiptKeyRecord};
    use archivist_client_core::config::ConfigSources;
    use archivist_protocol::vocabulary::TenantId;
    use archivist_storage::error::StorageError;
    use archivist_storage_s3::control_admin::{ControlAdminBackend, ControlObjectKey};

    use super::*;

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";

    #[derive(Clone, Default)]
    struct MapBackend {
        objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
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

    fn scratch_dir(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "archivist-receipt-key-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ))
    }

    fn sources(authority_seed_path: &Path, seed_path: &Path) -> ConfigSources {
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
            .env(
                "ARCHIVIST_ADMIN_ENDPOINT_URL",
                "https://control.example.invalid",
            )
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
                "ARCHIVIST_ADMIN_RECEIPT_SIGNING_KEY_PATH",
                seed_path.to_string_lossy().into_owned(),
            )
            .env(
                "ARCHIVIST_ADMIN_AUTHORITY_SEED_REF",
                format!("file:{}", authority_seed_path.display()),
            )
    }

    #[test]
    fn issues_public_record_and_writes_private_seed_once_with_restricted_modes() {
        let authority_dir = scratch_dir("authority");
        let seed_dir = scratch_dir("seed");
        let authority_path = authority_dir.join("authority-seed");
        let seed_path = seed_dir.join("receipt-seed");
        let certificate_path = certificate_path(&seed_path);
        let authority = TenantAuthority::generate().expect("OS entropy");
        authority
            .write_new(&authority_path)
            .expect("authority seed");
        let resolved = sources(&authority_path, &seed_path)
            .load()
            .expect("configuration");
        let backend = MapBackend::default();

        let result = issue_at(&resolved, &seed_path, backend.clone()).expect("issue receipt key");
        let Value::Object(result) = result else {
            panic!("receipt-key result is an object");
        };
        assert_eq!(
            result.get("schema"),
            Some(&Value::Text("archivist.cli-result/v1".to_owned()))
        );
        let certificate_value = result.get("certificate").expect("public certificate");
        let certificate =
            ReceiptKeyCertificate::parse(certificate_value).expect("public certificate shape");
        let record_value = result.get("record").expect("public control record");
        let record_bytes = record_value.canonical_bytes();
        let record = ReceiptKeyRecord::parse(&record_bytes).expect("public record shape");

        let mode = std::fs::metadata(&seed_path)
            .expect("seed file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            std::fs::metadata(&certificate_path)
                .expect("certificate file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            std::fs::metadata(&seed_dir)
                .expect("seed parent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let seed_text = std::fs::read_to_string(&seed_path).expect("seed bytes");
        assert_eq!(seed_text.len(), 64);
        let result_bytes = Value::Object(result.clone()).canonical_bytes();
        assert!(
            !result_bytes
                .windows(seed_text.len())
                .any(|window| window == seed_text.as_bytes())
        );
        assert!(
            !result_bytes
                .windows(seed_path.as_os_str().len())
                .any(|window| window == seed_path.as_os_str().as_encoded_bytes())
        );

        let root = PinnedAuthorityRoot::new(
            TENANT.parse::<TenantId>().expect("tenant grammar"),
            authority.public_key(),
        );
        record.verify(&root, |_| None).expect("authority signature");
        certificate
            .verify(&root, |_| None)
            .expect("certificate authority signature");
        assert_eq!(
            std::fs::read(&certificate_path).expect("certificate bytes"),
            certificate_value.canonical_bytes()
        );
        assert_eq!(certificate.tenant_id(), record.tenant_id());
        assert_eq!(certificate.key_id(), record.key_id());
        assert_eq!(certificate.public_key(), record.public_key());

        let key = ControlObjectKey::receipt_key(record.tenant_id(), record.key_id());
        let stored = backend
            .objects
            .lock()
            .expect("test backend lock")
            .get(key.as_str())
            .cloned()
            .expect("published record");
        assert_eq!(stored, record_bytes);

        let error = issue_at(&resolved, &seed_path, MapBackend::default())
            .expect_err("existing seed destination is never overwritten");
        assert_eq!(error.code(), "cli.usage_error");

        std::fs::remove_dir_all(authority_dir).expect("remove authority fixture");
        std::fs::remove_dir_all(seed_dir).expect("remove seed fixture");
    }
}
