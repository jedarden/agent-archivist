// SPDX-License-Identifier: Apache-2.0

//! Composition for `archivist catalog rebuild --from-occurrences`.
//!
//! The storage engine owns the deterministic fold; this module supplies the
//! shipped adapter projection and the operational shells around it. The
//! recurring cluster shape is a long-running Deployment calling
//! [`rebuild_loop`], which sleeps between internal passes. An operator's
//! one-shot shape is an Argo `WorkflowTemplate` calling [`rebuild_over`].
//! Neither shape is a Kubernetes `Job` or `CronJob`.

use std::future::Future;

use archivist_client_core::cli::{CliError, CommandHandler, Invocation};
use archivist_client_core::config::{ConfigError, ResolvedConfig};
use archivist_client_core::daemon::{self, Cancel, LoopReport, LoopStop, ScheduleConfig, Sleeper};
use archivist_client_core::upload::Jitter;
use archivist_protocol::json::Value;
use archivist_protocol::vocabulary::{AdapterId, TenantId, VersionToken};
use archivist_storage::audit_restore::{
    AuditRestoreStore, ContinuationToken, FrozenInventory, InventoryKey, InventoryPage,
    InventoryScope, ObjectBody, ObjectMetadata,
};
use archivist_storage::catalog_rebuild::{
    RebuildPolicy, UsageProjection, latest_checkpoint, rebuild_pass,
};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::scoped_write::{CatalogWriteStore, DerivedWriteStore};
use archivist_storage_s3::config::{S3ConfigError, S3ConfigErrorKind, ScopedWritersConfig};
use archivist_storage_s3::request::{S3RequestBackend, S3RequestErrorKind};
use archivist_storage_s3::scoped_write::{S3CatalogWriteStore, S3DerivedWriteStore};

const INTEGRITY_CONFLICT: &str = "storage.integrity_conflict";
const TRANSPORT_FAILED: &str = "transport.connection_failed";
const SECRET_REF_REFUSED: &str = "client.secret_ref_refused";
const INTERNAL: &str = "client.internal_error";

/// The stable catalog checkpoint cadence. It is an operational bound, not a
/// member of derived rows; changing the rebuild mapping itself still requires
/// a new pipeline version in the protocol crate.
pub const CHECKPOINT_EVERY: u64 = 128;

/// The production composition surface: the binary attaches this handler only
/// after the registry pins the result schema and all storage decisions.
#[must_use]
pub fn handlers() -> [(&'static str, CommandHandler); 1] {
    [("catalog rebuild", rebuild as CommandHandler)]
}

/// Bind the Phase 10 command to the offline audit identity and the two
/// dedicated scoped writers. Configuration is resolved before any request
/// backend is constructed, and each credential reference is handed to only
/// the authority whose typed constructor accepts it.
///
/// # Errors
///
/// Returns a usage, configuration, storage, or protocol error when the
/// command cannot compose its required identities or complete the rebuild.
pub fn rebuild(invocation: &Invocation) -> Result<Value, CliError> {
    if !invocation.has_operational_flag("from-occurrences") {
        return Err(CliError::usage());
    }
    let resolved = resolve(invocation)?;
    let tenant = tenant(&resolved)?;
    let ingest = crate::admin::ingest_config(&resolved).map_err(composition_fault)?;
    let writers = scoped_writers(&resolved).map_err(composition_fault)?;
    reject_ingest_reuse(&ingest, &writers)?;
    let audit =
        AuditBinding(S3RequestBackend::audit_restore(&ingest, &tenant).map_err(request_fault)?);
    let catalog = S3CatalogWriteStore::new(
        writers.catalog().clone(),
        S3RequestBackend::catalog_write(writers.catalog()).map_err(request_fault)?,
    );
    let derived = S3DerivedWriteStore::new(
        writers.derived().clone(),
        S3RequestBackend::derived_write(writers.derived()).map_err(request_fault)?,
    );
    rebuild_over(invocation, &tenant, &audit, &catalog, &derived)
}

/// The concrete audit/restore adapter is deliberately a thin wrapper around
/// the request authority. It exposes the storage crate's four-method trait
/// and nothing else to the rebuild engine.
struct AuditBinding(S3RequestBackend);

impl AuditRestoreStore for AuditBinding {
    fn list_page(
        &self,
        scope: &InventoryScope,
        after: Option<&ContinuationToken>,
    ) -> impl Future<Output = Result<InventoryPage, StorageError>> + Send {
        self.0.audit_list_page(scope, after)
    }

    #[allow(clippy::manual_async_fn)]
    fn freeze_inventory(
        &self,
        scope: &InventoryScope,
    ) -> impl Future<Output = Result<FrozenInventory, StorageError>> + Send {
        async move {
            let mut pages = Vec::new();
            let mut after = None;
            loop {
                let page = self.list_page(scope, after.as_ref()).await?;
                after = page.next().cloned();
                let exhausted = after.is_none();
                pages.push(Ok(page));
                if exhausted {
                    break;
                }
            }
            FrozenInventory::from_pages(scope, pages)
        }
    }

    fn inspect_object(
        &self,
        key: &InventoryKey,
    ) -> impl Future<Output = Result<ObjectMetadata, StorageError>> + Send {
        self.0.audit_inspect_object(key)
    }

    fn read_object(
        &self,
        key: &InventoryKey,
    ) -> impl Future<Output = Result<ObjectBody, StorageError>> + Send {
        self.0.audit_read_object(key)
    }
}

fn resolve(invocation: &Invocation) -> Result<ResolvedConfig, CliError> {
    invocation
        .config_sources()
        .capture_environment()
        .map_err(|error| config_fault(&error))?
        .load()
        .map_err(|error| config_fault(&error))
}

fn tenant(resolved: &ResolvedConfig) -> Result<TenantId, CliError> {
    let text = resolved
        .text("storage.tenant")
        .ok_or_else(|| CliError::registered(DECISION_MISSING))?;
    TenantId::parse(text).map_err(|_| CliError::usage())
}

fn scoped_writers(resolved: &ResolvedConfig) -> Result<ScopedWritersConfig, S3ConfigError> {
    ScopedWritersConfig::builder()
        .endpoint_url(required_text(resolved, "storage.endpoint_url")?.to_owned())
        .region(required_text(resolved, "storage.region")?.to_owned())
        .path_style(crate::admin::path_style_token(required_text(
            resolved,
            "storage.path_style",
        )?)?)
        .tenant_bucket(required_text(resolved, "storage.tenant_bucket")?.to_owned())
        .tenant(required_text(resolved, "storage.tenant")?.to_owned())
        .catalog_write_credentials(crate::admin::reference_text(
            crate::admin::required_ingest_reference(
                resolved,
                "storage.catalog_write_credentials_ref",
            )?,
        ))
        .derived_write_credentials(crate::admin::reference_text(
            crate::admin::required_ingest_reference(
                resolved,
                "storage.derived_write_credentials_ref",
            )?,
        ))
        .build()
}

fn required_text<'a>(resolved: &'a ResolvedConfig, key: &str) -> Result<&'a str, S3ConfigError> {
    resolved.text(key).ok_or_else(|| {
        S3ConfigError::new(
            S3ConfigErrorKind::MissingSetting,
            "a catalog rebuild setting did not resolve from any tier",
        )
    })
}

fn config_fault(error: &ConfigError) -> CliError {
    CliError::registered(error.code().token())
}

fn composition_fault(error: S3ConfigError) -> CliError {
    match error.kind() {
        S3ConfigErrorKind::MissingSetting => CliError::registered(DECISION_MISSING),
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

fn reject_ingest_reuse(
    ingest: &archivist_storage_s3::config::S3StorageConfig,
    writers: &ScopedWritersConfig,
) -> Result<(), CliError> {
    for role in archivist_storage_s3::config::StorageRole::all() {
        let Some(identity) = ingest.identities().role(*role) else {
            continue;
        };
        if identity == writers.catalog().catalog_write_credentials()
            || identity == writers.derived().derived_write_credentials()
        {
            return Err(CliError::usage());
        }
    }
    Ok(())
}

const DECISION_MISSING: &str = "cli.decision_missing";

type ProjectionReader =
    fn(&AdapterId, &[u8]) -> Vec<archivist_protocol::usage_summary::MessageUsage>;

fn projection() -> UsageProjection<ProjectionReader> {
    UsageProjection::new(
        VersionToken::parse(archivist_adapter_claude::PROJECTION_VERSION)
            .expect("the shipped projection version has valid grammar"),
        archivist_adapter_claude::usage_projection::read_usage,
    )
}

/// Run one deterministic catalog rebuild over the provisioned storage
/// identities. The command resumes from the furthest verified checkpoint
/// when one exists, and otherwise starts from the frozen raw prefix.
///
/// This generic composition point is what a production S3 transport binds;
/// the CLI module does not own credentials or an alternate storage client.
///
/// # Errors
/// Returns a usage error when the source flag is absent, a registered client
/// error when the runtime cannot start, or the mapped storage refusal from
/// the freeze, checkpoint, read, or derived-write path.
pub fn rebuild_over<R, C, D>(
    invocation: &Invocation,
    tenant: &TenantId,
    audit: &R,
    catalog: &C,
    derived: &D,
) -> Result<Value, CliError>
where
    R: AuditRestoreStore + Sync + ?Sized,
    C: CatalogWriteStore + Sync + ?Sized,
    D: DerivedWriteStore + Sync + ?Sized,
{
    if !invocation.has_operational_flag("from-occurrences") {
        return Err(CliError::usage());
    }
    let projection = projection();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CliError::registered(INTERNAL))?;
    let outcome = runtime
        .block_on(rebuild_once(audit, catalog, derived, tenant, &projection))
        .map_err(storage_fault)?;
    Ok(Value::Object(
        outcome
            .result_document(tenant, projection.version())
            .clone(),
    ))
}

/// Run the recurring internal-loop form used by the long-running
/// Deployment. Each cycle is sequential and each pass resumes through the
/// verified checkpoint seam, so a cancelled or restarted process cannot
/// reorder occurrences or create a second logical row.
///
/// # Errors
/// Returns a usage error when the source flag is absent, a registered client
/// error when the runtime or loop entropy fails, or the mapped storage refusal
/// from the cycle that stopped the loop.
#[allow(clippy::too_many_arguments)]
pub fn rebuild_loop<R, C, D, J, S>(
    invocation: &Invocation,
    tenant: &TenantId,
    audit: &R,
    catalog: &C,
    derived: &D,
    schedule: &ScheduleConfig,
    cancel: &Cancel,
    jitter: &mut J,
    sleeper: &mut S,
) -> Result<LoopReport, CliError>
where
    R: AuditRestoreStore + Sync + ?Sized,
    C: CatalogWriteStore + Sync + ?Sized,
    D: DerivedWriteStore + Sync + ?Sized,
    J: Jitter,
    S: Sleeper,
{
    if !invocation.has_operational_flag("from-occurrences") {
        return Err(CliError::usage());
    }
    let projection = projection();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CliError::registered(INTERNAL))?;
    let mut failure = None;
    let report = daemon::run(schedule, cancel, jitter, sleeper, |cycle_cancel| {
        if failure.is_some() {
            return;
        }
        if let Err(error) =
            runtime.block_on(rebuild_once(audit, catalog, derived, tenant, &projection))
        {
            failure = Some(storage_fault(error));
            cycle_cancel.cancel();
        }
    });
    match failure {
        Some(error) => Err(error),
        None if report.stop == LoopStop::EntropyUnavailable => Err(CliError::registered(INTERNAL)),
        None => Ok(report),
    }
}

async fn rebuild_once<R, C, D, F>(
    audit: &R,
    catalog: &C,
    derived: &D,
    tenant: &TenantId,
    projection: &UsageProjection<F>,
) -> Result<archivist_storage::catalog_rebuild::RebuildOutcome, StorageError>
where
    R: AuditRestoreStore + Sync + ?Sized,
    C: CatalogWriteStore + Sync + ?Sized,
    D: DerivedWriteStore + Sync + ?Sized,
    F: Fn(&AdapterId, &[u8]) -> Vec<archivist_protocol::usage_summary::MessageUsage>,
{
    let resume = latest_checkpoint(audit, catalog, projection, tenant).await?;
    rebuild_pass(
        audit,
        derived,
        catalog,
        projection,
        tenant,
        RebuildPolicy {
            checkpoint_every: CHECKPOINT_EVERY,
            window: None,
        },
        resume.as_deref(),
    )
    .await
}

fn storage_fault(error: StorageError) -> CliError {
    match error.kind() {
        StorageErrorKind::IntegrityConflict | StorageErrorKind::InventoryFault => {
            CliError::registered(INTEGRITY_CONFLICT)
        }
        StorageErrorKind::Unavailable | StorageErrorKind::CapabilityUnavailable => {
            CliError::registered(TRANSPORT_FAILED)
        }
        _ => CliError::registered(INTERNAL),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::manual_async_fn)]

    use std::ffi::OsString;
    use std::future::Future;

    use archivist_client_core::cli::registry::Registry;
    use archivist_client_core::cli::{CliError, Invocation, OutputEnvelope, Router, parse};
    use archivist_protocol::json::{self, Value};
    use archivist_storage::audit_restore::{
        AuditRestoreStore, ContinuationToken, FrozenInventory, InventoryKey, InventoryPage,
        InventoryScope, ObjectBody, ObjectMetadata,
    };
    use archivist_storage::error::{StorageError, StorageErrorKind};
    use archivist_storage::scoped_write::{
        CatalogCheckpointKey, CatalogListPrefix, CatalogWriteStore, DerivedListPrefix,
        DerivedObjectKey, DerivedWriteStore,
    };

    use super::{
        INTEGRITY_CONFLICT, INTERNAL, SECRET_REF_REFUSED, TRANSPORT_FAILED, handlers, rebuild_over,
        request_fault,
    };
    use archivist_storage_s3::request::{S3RequestError, S3RequestErrorKind};

    #[allow(clippy::unnecessary_wraps)]
    fn empty_result(_: &Invocation) -> Result<Value, CliError> {
        Ok(Value::Object(json::Object::new()))
    }

    struct EmptyAudit {
        inventory: FrozenInventory,
    }

    impl AuditRestoreStore for EmptyAudit {
        fn list_page(
            &self,
            _scope: &InventoryScope,
            _after: Option<&ContinuationToken>,
        ) -> impl Future<Output = Result<InventoryPage, StorageError>> + Send {
            async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
        }

        fn freeze_inventory(
            &self,
            _scope: &InventoryScope,
        ) -> impl Future<Output = Result<FrozenInventory, StorageError>> + Send {
            let inventory = self.inventory.clone();
            async move { Ok(inventory) }
        }

        fn inspect_object(
            &self,
            _key: &InventoryKey,
        ) -> impl Future<Output = Result<ObjectMetadata, StorageError>> + Send {
            async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
        }

        fn read_object(
            &self,
            _key: &InventoryKey,
        ) -> impl Future<Output = Result<ObjectBody, StorageError>> + Send {
            async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
        }
    }

    struct EmptyCatalog;

    impl CatalogWriteStore for EmptyCatalog {
        fn put_checkpoint(
            &self,
            _key: &CatalogCheckpointKey,
            _bytes: &[u8],
        ) -> impl Future<Output = Result<(), StorageError>> + Send {
            async { Ok(()) }
        }

        fn list_checkpoints(
            &self,
            _prefix: &CatalogListPrefix,
        ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send {
            async { Ok(Vec::new()) }
        }
    }

    struct EmptyDerived;

    impl DerivedWriteStore for EmptyDerived {
        fn put_object(
            &self,
            _key: &DerivedObjectKey,
            _bytes: &[u8],
        ) -> impl Future<Output = Result<(), StorageError>> + Send {
            async { Ok(()) }
        }

        fn list_objects(
            &self,
            _prefix: &DerivedListPrefix,
        ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send {
            async { Ok(Vec::new()) }
        }
    }

    struct FailingAudit {
        kind: StorageErrorKind,
    }

    impl AuditRestoreStore for FailingAudit {
        fn list_page(
            &self,
            _scope: &InventoryScope,
            _after: Option<&ContinuationToken>,
        ) -> impl Future<Output = Result<InventoryPage, StorageError>> + Send {
            async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
        }

        fn freeze_inventory(
            &self,
            _scope: &InventoryScope,
        ) -> impl Future<Output = Result<FrozenInventory, StorageError>> + Send {
            let error = StorageError::of_kind(self.kind);
            async move { Err(error) }
        }

        fn inspect_object(
            &self,
            _key: &InventoryKey,
        ) -> impl Future<Output = Result<ObjectMetadata, StorageError>> + Send {
            async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
        }

        fn read_object(
            &self,
            _key: &InventoryKey,
        ) -> impl Future<Output = Result<ObjectBody, StorageError>> + Send {
            async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
        }
    }

    fn empty_invocation() -> Invocation {
        let args = [
            OsString::from("--non-interactive"),
            OsString::from("catalog"),
            OsString::from("rebuild"),
            OsString::from("--from-occurrences"),
        ];
        match parse::parse(&args, Registry::pinned()).expect("catalog invocation parses") {
            parse::Parsed::Command(invocation) => invocation,
            other => panic!("expected a command invocation, got {other:?}"),
        }
    }

    #[test]
    fn production_handler_attaches_to_the_schema_pinned_registry() {
        let mut router = Router::new();
        for (path, handler) in handlers() {
            router
                .register_handler(path, handler)
                .expect("catalog rebuild is result-schema bound");
        }
    }

    #[test]
    fn catalog_refusal_is_removed_only_by_handler_attachment() {
        let args = [
            OsString::from("catalog"),
            OsString::from("rebuild"),
            OsString::from("--from-occurrences"),
        ];
        let gated = Router::new();
        assert_eq!(gated.run(&args), 64);

        let mut attached = Router::new();
        attached
            .register_handler("catalog rebuild", empty_result)
            .expect("the result schema permits attachment");
        assert_eq!(attached.run(&args), 0);
    }

    #[test]
    fn emitted_result_and_cli_envelope_conform_to_the_registered_schema() {
        let tenant = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b"
            .parse::<archivist_protocol::vocabulary::TenantId>()
            .expect("tenant grammar");
        let scope = InventoryScope::TenantRaw(tenant.clone());
        let inventory =
            FrozenInventory::from_pages(&scope, vec![Ok(InventoryPage::new(Vec::new(), None))])
                .expect("empty inventory freezes");
        let document = rebuild_over(
            &empty_invocation(),
            &tenant,
            &EmptyAudit { inventory },
            &EmptyCatalog,
            &EmptyDerived,
        )
        .expect("empty catalog rebuild emits a result");

        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/v1/cli-catalog-rebuild.json");
        let Value::Object(schema) =
            json::parse(&std::fs::read(schema_path).expect("catalog schema is committed"))
                .expect("catalog schema parses")
        else {
            panic!("catalog schema is an object");
        };
        let Value::Array(required) = schema.get("required").expect("required members") else {
            panic!("required members are an array");
        };
        let Value::Object(properties) = schema.get("properties").expect("schema properties") else {
            panic!("schema properties are an object");
        };
        let Value::Object(record) = document else {
            panic!("rebuild result is an object");
        };
        assert_eq!(record.len(), required.len());
        for member in required {
            let Value::Text(member) = member else {
                panic!("schema member name is text");
            };
            assert!(record.get(member).is_some(), "result carries {member}");
            assert!(properties.get(member).is_some(), "schema pins {member}");
        }
        assert_eq!(
            record.get("schema"),
            Some(&Value::Text("archivist.cli-result/v1".to_owned()))
        );

        let envelope = OutputEnvelope::with_timestamp(
            "catalog-rebuild",
            "2026-09-28T12:00:00Z",
            Value::Object(record.clone()),
        )
        .expect("result object fits the CLI envelope");
        let Value::Object(envelope_record) =
            json::parse(&envelope.canonical_bytes()).expect("envelope is canonical JSON")
        else {
            panic!("envelope is an object");
        };
        assert_eq!(
            envelope_record.get("schema"),
            Some(&Value::Text("archivist.cli-output/v1".to_owned()))
        );
        assert_eq!(
            envelope_record.get("command"),
            Some(&Value::Text("catalog-rebuild".to_owned()))
        );
        assert_eq!(envelope_record.get("result"), Some(&Value::Object(record)));
    }

    #[test]
    fn rebuild_maps_storage_failures_to_registered_cli_codes() {
        let tenant = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b"
            .parse::<archivist_protocol::vocabulary::TenantId>()
            .expect("tenant grammar");
        let cases = [
            (StorageErrorKind::IntegrityConflict, INTEGRITY_CONFLICT),
            (StorageErrorKind::InventoryFault, INTEGRITY_CONFLICT),
            (StorageErrorKind::Unavailable, TRANSPORT_FAILED),
            (StorageErrorKind::CapabilityUnavailable, TRANSPORT_FAILED),
            (StorageErrorKind::ScopeViolation, INTERNAL),
            (StorageErrorKind::MalformedInput, INTERNAL),
            (StorageErrorKind::StaleEpoch, INTERNAL),
        ];

        for (kind, expected) in cases {
            let error = rebuild_over(
                &empty_invocation(),
                &tenant,
                &FailingAudit { kind },
                &EmptyCatalog,
                &EmptyDerived,
            )
            .expect_err("the injected storage failure is rejected");
            assert_eq!(error.code(), expected, "mapping for {kind:?}");
            assert!(error.exit_code() > 0, "{expected} is registered");
        }
    }

    #[test]
    fn rebuild_maps_request_credential_failures_to_the_secret_reference_code() {
        for kind in [
            S3RequestErrorKind::CredentialUnavailable,
            S3RequestErrorKind::CredentialMalformed,
        ] {
            let error = request_fault(S3RequestError::new(kind, "content-free test detail"));
            assert_eq!(error.code(), SECRET_REF_REFUSED);
            assert!(error.exit_code() > 0);
        }
        assert_eq!(
            request_fault(S3RequestError::new(
                S3RequestErrorKind::EndpointMalformed,
                "content-free test detail",
            ))
            .code(),
            "cli.usage_error"
        );
    }
}
