// SPDX-License-Identifier: Apache-2.0

//! The `serve` command: the composition that turns the server and storage
//! libraries into a running ingestion replica (plan Phase 4).
//!
//! The binary is the workspace's composition root, and this module is the
//! `serve` half of that duty: it resolves the registered `server.*` and
//! `storage.*` keys through the ordinary configuration precedence, builds
//! the validated [`ServerConfig`], the pinned [`TrustConfig`], and the
//! concrete S3 storage identities, and hands the whole replica to the
//! server crate's three-step lifecycle — compose, bind, serve — with
//! SIGTERM/SIGINT as the cancellation. The server crate stays backend-
//! agnostic ([`archivist_server`]'s dependency boundary): the concrete
//! backend is selected here and nowhere else.
//!
//! The control-plane boundary is two credentials, not one (plan Section
//! 5): the raw writer and the control reader are two separately-resolved
//! request bindings, each over its own registered credential reference.
//! The configuration builder refuses a deployment that mapped both roles
//! onto one reference ([`S3ConfigErrorKind::DuplicateIdentity`]), and the
//! two stores that reach the replica each hold only their own identity's
//! reference — the same split the offline administration composition
//! proves for the third identity.
//!
//! Every refusal is fail-closed before the listening socket exists:
//! missing composition-required settings, malformed values, and an
//! unresolvable credential reference all end the startup with a
//! registered error code and an empty stdout, so no partially-started
//! process is possible. The composition-required trust and tenant keys
//! (`server.authority_key`, `storage.tenant`) are deliberately
//! registry-optional — requiredness there is universal across commands,
//! and the offline administration surfaces must load without the
//! replica's verification material — so this composition refuses their
//! absence itself, as a missing decision, before any socket exists.
//!
//! The command is always non-interactive (CLI-021) and stdout kind `none`
//! (CLI-016): it emits nothing on any path, and the process exit carries
//! the outcome — 0 for a signal-drained shutdown, the registered
//! `server.unavailable` class when the drain window elapsed with work in
//! flight or the socket died underneath the server (the supervisor's
//! restart is the retry), and the usage class for every startup refusal.

use archivist_client_core::cli::{CliError, CommandHandler, Invocation};
use archivist_client_core::config::{ConfigSources, ResolvedConfig};
use archivist_protocol::json::Value;
use archivist_protocol::vocabulary::TenantId;
use archivist_server::config::{ServerConfig, ServerConfigError, ServerConfigErrorKind};
use archivist_server::receipts::ReceiptSigners;
use archivist_server::serve::{ArchivistServer, ShutdownOutcome, shutdown_on_signal};
use archivist_server::trust::{TenantTrustRoot, TrustConfig};
use archivist_storage::ingest::IngestStorage;
use archivist_storage_s3::config::{
    ControlReadConfig, S3ConfigError, S3ConfigErrorKind, S3StorageConfig,
};
use archivist_storage_s3::control_read::S3ControlReadStore;
use archivist_storage_s3::raw_write::S3RawWriteStore;
use archivist_storage_s3::request::S3RequestBackend;

/// The registered code for a composition-required setting that resolved
/// from no tier (`tools/error-codes.toml`, class `usage`).
const DECISION_MISSING: &str = "cli.decision_missing";

/// The registered code for a serve run that did not end in a clean
/// drained shutdown (`tools/error-codes.toml`, class `server_failure`):
/// the drain window elapsed with work in flight, or the socket died
/// underneath the accept loop. The supervisor's restart is the retry.
const SERVE_UNAVAILABLE: &str = "server.unavailable";

/// The composition's attached surface: the registered command path and
/// its handler. The binary attaches every entry; the attachability test
/// proves the path still names a registered command with a shipped
/// output kind.
#[must_use]
pub fn handlers() -> [(&'static str, CommandHandler); 1] {
    [("serve", serve as CommandHandler)]
}

/// Run the `serve` command: resolve the configuration the invocation
/// names — always non-interactive (CLI-021), whether or not the flag was
/// passed — and run the replica until SIGTERM/SIGINT.
///
/// # Errors
/// The registered refusal of the first failing act: configuration
/// acquisition, replica composition, the bind, or the serve run itself.
pub fn serve(invocation: &Invocation) -> Result<Value, CliError> {
    let resolved = resolve(invocation)?;
    serve_over(&resolved)
}

/// Run the replica over an already-resolved configuration: compose the
/// validated parts, bind, and serve until the signal. Split from
/// [`serve`] so the composition is provable over a synthetic
/// configuration without touching the process environment.
///
/// # Errors
/// The registered refusal of the first failing act — composition, the
/// bind, or the serve run. Composition failures precede the bind, so no
/// socket ever exists for a refused configuration.
///
/// # Panics
/// Only if the process cannot host an async runtime or install its
/// signal handlers — the same structural guarantee the server's own
/// signal composition and the daemon's runtime composition restate.
pub fn serve_over(resolved: &ResolvedConfig) -> Result<Value, CliError> {
    let (server_config, trust, storage) = compose_replica(resolved)?;
    let bound = ArchivistServer::new(server_config, trust, storage, ReceiptSigners::new())
        .bind()
        .map_err(|_| CliError::usage())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CliError::internal())?;
    match runtime.block_on(bound.serve(shutdown_on_signal())) {
        Ok(ShutdownOutcome::Drained) => Ok(Value::Null),
        Ok(ShutdownOutcome::DrainTimedOut | ShutdownOutcome::AbortsFailed) | Err(_) => {
            Err(CliError::registered(SERVE_UNAVAILABLE))
        }
    }
}

/// The concrete replica the composition hands to the server crate: the
/// validated server configuration, the pinned trust anchor set, and the
/// two S3 storage identities over their separately-resolved request
/// bindings. Internal to this module's composition; the trio is a tuple
/// because [`ArchivistServer::new`] takes the three parts as parameters.
type Replica = (
    ServerConfig,
    TrustConfig,
    IngestStorage<S3RawWriteStore<S3RequestBackend>, S3ControlReadStore<S3RequestBackend>>,
);

/// Compose the replica's validated parts from the resolved
/// configuration, before any I/O: the server configuration from the
/// registered `server.*` keys, the trust anchor set from the pinned
/// tenant and authority key, and the two storage identities from the
/// `storage.*` keys over their two credential references.
///
/// # Errors
/// [`CliError::registered`](`CliError::registered`) with
/// `cli.decision_missing` for a composition-required setting that
/// resolved from no tier, and the usage class for every malformed
/// setting, refused configuration pair, or credential reference that did
/// not resolve to protected material.
fn compose_replica(resolved: &ResolvedConfig) -> Result<Replica, CliError> {
    let server_config = server_config(resolved)?;
    let trust = trust_config(resolved)?;
    let storage = ingest_storage(resolved)?;
    Ok((server_config, trust, storage))
}

/// Build the validated server configuration from the registered
/// `server.*` keys through the server crate's own fail-closed builder —
/// the single gate that bounds-checks every limit and the listen
/// address.
///
/// # Errors
/// The registered refusal of the builder's verdict: a missing decision
/// for the required listen address, the usage class for any value
/// outside its registry bounds. The defaulted limits always resolve on a
/// successful load; one that does not resolve is the same missing
/// decision a required key reports.
fn server_config(resolved: &ResolvedConfig) -> Result<ServerConfig, CliError> {
    let builder = ServerConfig::builder()
        .listen_address(required_text(resolved, "server.listen_address")?.to_owned())
        .request_deadline_seconds(count(resolved, "server.request_deadline_seconds")?)
        .envelope_max_bytes(count(resolved, "server.envelope_max_bytes")?)
        .record_max_bytes(count(resolved, "server.record_max_bytes")?)
        .max_expansion_ratio(narrow_count(resolved, "server.max_expansion_ratio")?)
        .multipart_part_bytes(count(resolved, "server.multipart_part_bytes")?)
        .max_inflight_upload_count(narrow_count(resolved, "server.max_inflight_upload_count")?)
        .max_inflight_per_client_count(narrow_count(
            resolved,
            "server.max_inflight_per_client_count",
        )?)
        .rate_per_minute_count(narrow_count(resolved, "server.rate_per_minute_count")?)
        .rate_burst_count(narrow_count(resolved, "server.rate_burst_count")?)
        .shutdown_drain_seconds(count(resolved, "server.shutdown_drain_seconds")?);
    builder.build().map_err(server_config_fault)
}

/// Build the trust anchor set from the pinned tenant and authority key.
///
/// The v1 composition serves the one tenant the storage identities
/// provision: [`ControlReadConfig`] and [`S3RawWriteStore`] each pin
/// exactly one tenant, so an anchor set of exactly that tenant is the
/// only configuration a replica can serve. The anchor is the public half
/// the offline administration surface certifies and exports; here it is
/// verification material, pinned at startup and never re-derived.
///
/// # Errors
/// The missing decision for either key that resolved from no tier, and
/// the usage class for a tenant or key outside its pinned grammar.
fn trust_config(resolved: &ResolvedConfig) -> Result<TrustConfig, CliError> {
    let tenant = required_text(resolved, "storage.tenant")?;
    let authority = required_text(resolved, "server.authority_key")?;
    let root = TenantTrustRoot::new(tenant, authority).map_err(|_| CliError::usage())?;
    TrustConfig::from_roots(vec![root]).map_err(|_| CliError::usage())
}

/// Build the two storage identities from the registered `storage.*`
/// keys: the ingest configuration (both roles' references, the buckets,
/// and the transport and encryption policy) and the control-read
/// configuration over the same endpoint and control bucket.
///
/// The ingest configuration is assembled through
/// [`crate::admin::ingest_config`] — the same resolved keys the
/// administration composition assembles for its boundary proof — and
/// here it is not discarded: it is the raw writer's configuration. The
/// builder's identity checks are the two-credentials rule's first gate;
/// the second is that each request binding below resolves only its own
/// role's reference.
///
/// # Errors
/// The registered refusal of either builder's verdict.
fn storage_identities(
    resolved: &ResolvedConfig,
) -> Result<(S3StorageConfig, ControlReadConfig), CliError> {
    let ingest = crate::admin::ingest_config(resolved).map_err(composition_fault)?;
    let control = ControlReadConfig::builder()
        .endpoint_url(
            crate::admin::required_ingest_text(resolved, "storage.endpoint_url")
                .map_err(composition_fault)?
                .to_owned(),
        )
        .region(
            crate::admin::required_ingest_text(resolved, "storage.region")
                .map_err(composition_fault)?
                .to_owned(),
        )
        .path_style(
            crate::admin::path_style_token(
                crate::admin::required_ingest_text(resolved, "storage.path_style")
                    .map_err(composition_fault)?,
            )
            .map_err(composition_fault)?,
        )
        .control_bucket(
            crate::admin::required_ingest_text(resolved, "storage.control_bucket")
                .map_err(composition_fault)?
                .to_owned(),
        )
        .tenant(required_text(resolved, "storage.tenant")?.to_owned())
        .control_read_credentials(crate::admin::reference_text(
            crate::admin::required_ingest_reference(
                resolved,
                "storage.control_read_credentials_ref",
            )
            .map_err(composition_fault)?,
        ))
        .build()
        .map_err(composition_fault)?;
    Ok((ingest, control))
}

/// Assemble the concrete ingest storage: two request bindings, each
/// resolving only its own role's credential reference, under the two
/// stores the replica holds.
///
/// Credential resolution happens here, at startup, and its refusal ends
/// the startup before the bind: a reference whose target cannot be read
/// or whose document is not a credential document is a deployment fault,
/// and the constructors' diagnostics are content-free by construction.
///
/// # Errors
/// The usage class for every composition and resolution refusal.
fn ingest_storage(
    resolved: &ResolvedConfig,
) -> Result<
    IngestStorage<S3RawWriteStore<S3RequestBackend>, S3ControlReadStore<S3RequestBackend>>,
    CliError,
> {
    let (ingest_config, control_config) = storage_identities(resolved)?;
    let tenant_text = required_text(resolved, "storage.tenant")?;
    let tenant: TenantId = tenant_text.parse().map_err(|_| CliError::usage())?;
    let raw_backend =
        S3RequestBackend::raw_write(&ingest_config, &tenant).map_err(|_| CliError::usage())?;
    let control_backend =
        S3RequestBackend::control_read(&control_config).map_err(|_| CliError::usage())?;
    Ok(IngestStorage::compose(
        S3RawWriteStore::new(ingest_config, tenant, raw_backend),
        S3ControlReadStore::new(control_config, control_backend),
    ))
}

/// A composition-required setting's text — the tenant and the authority
/// key the replica pins its trust anchor to. Both are required in the
/// registry and listed by this command alone; the missing-decision arm
/// is the fail-closed restatement for a load path that bypassed the
/// registry's requiredness.
///
/// # Errors
/// The missing decision when the key resolved from no tier.
fn required_text<'a>(resolved: &'a ResolvedConfig, key: &str) -> Result<&'a str, CliError> {
    resolved
        .text(key)
        .ok_or_else(|| CliError::registered(DECISION_MISSING))
}

/// A defaulted or required count from the resolved configuration. The
/// registry bounds already guarantee a non-negative in-range integer;
/// the conversion refusal is the fail-closed restatement, not a guard
/// against reachable input.
///
/// # Errors
/// The missing decision for a key that resolved from no tier, the usage
/// class for an out-of-range value.
fn count(resolved: &ResolvedConfig, key: &str) -> Result<u64, CliError> {
    let value = resolved
        .integer(key)
        .ok_or_else(|| CliError::registered(DECISION_MISSING))?;
    u64::try_from(value).map_err(|_| CliError::usage())
}

/// A count the server builder narrows to `u32`.
///
/// # Errors
/// As [`count`], with the narrower range.
fn narrow_count(resolved: &ResolvedConfig, key: &str) -> Result<u32, CliError> {
    let value = resolved
        .integer(key)
        .ok_or_else(|| CliError::registered(DECISION_MISSING))?;
    u32::try_from(value).map_err(|_| CliError::usage())
}

/// Map a server configuration refusal onto its registered code.
fn server_config_fault(error: ServerConfigError) -> CliError {
    match error.kind() {
        ServerConfigErrorKind::MissingSetting => CliError::registered(DECISION_MISSING),
        ServerConfigErrorKind::MalformedSetting | ServerConfigErrorKind::ContradictorySetting => {
            CliError::usage()
        }
    }
}

/// Map a storage configuration refusal onto its registered code: a
/// missing setting is a missing decision, every other kind — malformed
/// grammar, transport mismatch, or the duplicated-identity refusal the
/// two-credentials rule rides on — is the usage class.
fn composition_fault(error: S3ConfigError) -> CliError {
    match error.kind() {
        S3ConfigErrorKind::MissingSetting => CliError::registered(DECISION_MISSING),
        S3ConfigErrorKind::MalformedSetting
        | S3ConfigErrorKind::TransportMismatch
        | S3ConfigErrorKind::DuplicateIdentity => CliError::usage(),
    }
}

/// Resolve the serve configuration: always non-interactive (CLI-021)
/// whether or not the flag was passed, with the invocation's `--config`
/// and key flags applied over the captured environment. The `probe`
/// command resolves through this same composition, so the address it
/// probes is exactly the address the replica bound.
///
/// # Errors
/// The registered code of the first configuration fault.
pub(crate) fn resolve(invocation: &Invocation) -> Result<ResolvedConfig, CliError> {
    let mut sources = ConfigSources::daemon().map_err(|error| config_fault(&error))?;
    if let Some(path) = invocation.config_path() {
        sources = sources.config_path(path.to_path_buf());
    }
    for (name, value) in invocation.key_flags() {
        sources = sources.flag(name, value.to_owned());
    }
    sources.load().map_err(|error| config_fault(&error))
}

/// Map a configuration refusal onto its registered code.
fn config_fault(error: &archivist_client_core::config::ConfigError) -> CliError {
    CliError::registered(error.code().token())
}

#[cfg(test)]
mod tests {
    use archivist_client_core::cli::Router;
    use archivist_client_core::config::ConfigSources;

    use super::{handlers, ingest_storage, serve_over, storage_identities};

    /// The tenant every fixture provisions (the registry's example value,
    /// canonical `uuid-v4` grammar).
    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";

    /// The authority key every fixture pins: the registry example's
    /// canonical `ed25519-public-key-hex` form (64 lowercase hex
    /// characters), synthetic by construction.
    const AUTHORITY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// The synthetic environment of an ingest replica: every required
    /// registered key through the environment tier, plus the two
    /// composition-optional keys exactly when their flags say so. The
    /// credential references point at `env:` targets that are
    /// deliberately never set, so any act that resolves one refuses.
    fn replica_sources(tenant: bool, authority: bool) -> ConfigSources {
        let sources = ConfigSources::non_interactive()
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
            .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "127.0.0.1:8087");
        let sources = if tenant {
            sources.env("ARCHIVIST_STORAGE_TENANT", TENANT)
        } else {
            sources
        };
        if authority {
            sources.env("ARCHIVIST_SERVER_AUTHORITY_KEY", AUTHORITY)
        } else {
            sources
        }
    }

    /// The fully-declared replica: both composition-optional keys
    /// present.
    fn base_sources() -> ConfigSources {
        replica_sources(true, true)
    }

    #[test]
    fn handlers_attach_to_the_pinned_registry() {
        let mut router = Router::new();
        for (path, handler) in handlers() {
            router
                .register_handler(path, handler)
                .unwrap_or_else(|_| panic!("{path} attaches to the pinned registry"));
        }
    }

    #[test]
    fn composition_builds_both_storage_identities_over_the_ingest_keys() {
        let resolved = base_sources().load().expect("fully declared host loads");
        let (ingest, control) = storage_identities(&resolved).expect("the pair composes");
        // Both identities ride the ingest endpoint, not the administration
        // or client surfaces.
        assert_eq!(ingest.endpoint().as_str(), "https://s3.example.invalid");
        assert_eq!(control.endpoint().as_str(), "https://s3.example.invalid");
        assert_eq!(control.tenant().as_str(), TENANT);
        // The two credentials are two references: distinct identities,
        // each its own role's.
        assert_ne!(
            ingest.identities().raw_write(),
            ingest.identities().control_read()
        );
        assert!(matches!(
            control.control_read_credentials(),
            archivist_storage_s3::config::CredentialReference::Env { name }
                if name.as_ref() == "TEST_CONTROL_CREDENTIAL"
        ));
    }

    #[test]
    fn one_credential_for_both_roles_is_refused() {
        let sources = base_sources()
            .env(
                "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
                "env:TEST_SHARED_CREDENTIAL",
            )
            .env(
                "ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF",
                "env:TEST_SHARED_CREDENTIAL",
            );
        let resolved = sources.load().expect("fully declared host loads");
        let error =
            storage_identities(&resolved).expect_err("one reference mapped onto both ingest roles");
        assert_eq!(error.code(), "cli.usage_error");
    }

    #[test]
    fn missing_tenant_is_a_missing_decision() {
        let resolved = replica_sources(false, true)
            .load()
            .expect("the load resolves without the composition-optional keys");
        let error = serve_over(&resolved).expect_err("no tenant pinned");
        assert_eq!(error.code(), "cli.decision_missing");
    }

    #[test]
    fn missing_authority_key_is_a_missing_decision() {
        let resolved = replica_sources(true, false)
            .load()
            .expect("the load resolves without the composition-optional keys");
        let error = serve_over(&resolved).expect_err("no authority key pinned");
        assert_eq!(error.code(), "cli.decision_missing");
    }

    #[test]
    fn malformed_authority_key_is_a_usage_error() {
        let resolved = base_sources()
            .env("ARCHIVIST_SERVER_AUTHORITY_KEY", "not-hex")
            .load()
            .expect("the string grammar itself resolves");
        let error = serve_over(&resolved).expect_err("the key is outside the hex grammar");
        assert_eq!(error.code(), "cli.usage_error");
    }

    #[test]
    fn malformed_tenant_is_a_usage_error() {
        let resolved = base_sources()
            .env("ARCHIVIST_STORAGE_TENANT", "not-a-uuid")
            .load()
            .expect("the string grammar itself resolves");
        let error = serve_over(&resolved).expect_err("the tenant is outside the uuid grammar");
        assert_eq!(error.code(), "cli.usage_error");
    }

    #[test]
    fn malformed_listen_address_is_a_usage_error() {
        let resolved = base_sources()
            .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "not-a-socket-address")
            .load()
            .expect("the string grammar itself resolves");
        let error = serve_over(&resolved).expect_err("the address is outside the grammar");
        assert_eq!(error.code(), "cli.usage_error");
    }

    #[test]
    fn an_unresolvable_credential_reference_refuses_startup() {
        // The fixture's `env:` targets are deliberately unset in the
        // process environment, so the first credential resolution refuses
        // before any socket exists. The store assembly is the unit under
        // test here — the refusal is the credential act's, not the
        // lifecycle's.
        let resolved = base_sources().load().expect("fully declared host loads");
        // `expect_err` needs `Debug` on the store pair; a `let...else`
        // states the same refusal without that bound.
        let Err(error) = ingest_storage(&resolved) else {
            panic!("the reference resolves to nothing, yet startup composed");
        };
        assert_eq!(error.code(), "cli.usage_error");
    }
}
