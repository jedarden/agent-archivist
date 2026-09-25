// SPDX-License-Identifier: Apache-2.0

//! Composition for `archivist catalog rebuild --from-occurrences`.
//!
//! The storage engine owns the deterministic fold; this module supplies the
//! shipped adapter projection and the operational shells around it. The
//! recurring cluster shape is a long-running Deployment calling
//! [`rebuild_loop`], which sleeps between internal passes. An operator's
//! one-shot shape is an Argo WorkflowTemplate calling [`rebuild_over`].
//! Neither shape is a Kubernetes Job or CronJob.

use archivist_client_core::cli::{CliError, Invocation};
use archivist_client_core::daemon::{self, Cancel, LoopReport, LoopStop, ScheduleConfig, Sleeper};
use archivist_client_core::upload::Jitter;
use archivist_protocol::json::Value;
use archivist_protocol::vocabulary::{AdapterId, TenantId, VersionToken};
use archivist_storage::audit_restore::AuditRestoreStore;
use archivist_storage::catalog_rebuild::{
    RebuildPolicy, UsageProjection, latest_checkpoint, rebuild_pass,
};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::scoped_write::{CatalogWriteStore, DerivedWriteStore};

const INTEGRITY_CONFLICT: &str = "storage.integrity_conflict";
const TRANSPORT_FAILED: &str = "transport.connection_failed";
const INTERNAL: &str = "client.internal_error";

/// The stable catalog checkpoint cadence. It is an operational bound, not a
/// member of derived rows; changing the rebuild mapping itself still requires
/// a new pipeline version in the protocol crate.
pub const CHECKPOINT_EVERY: u64 = 128;

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
