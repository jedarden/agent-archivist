// SPDX-License-Identifier: Apache-2.0

//! The zero-state tenant-authority bootstrap command.
//!
//! `admin create-authority` is intentionally local. A tenant root is not a
//! control record: its public half is pinned by each ingest replica and its
//! private half is the only material the offline administrator needs to sign
//! the first control record. The command therefore has no storage backend to
//! compose and no credential to resolve.

use archivist_auth::identity::TenantAuthority;
use archivist_client_core::cli::{CliError, CommandHandler, Invocation};
use archivist_client_core::config::{ConfigError, ResolvedConfig};
use archivist_protocol::json::{self, Value};
use archivist_protocol::vocabulary::TenantId;

const TENANT_KEY: &str = "admin.tenant";
const DECISION_MISSING: &str = "cli.decision_missing";

/// Attach the local tenant-authority bootstrap command to the composition
/// root.
#[must_use]
pub fn handlers() -> [(&'static str, CommandHandler); 1] {
    [("admin create-authority", command as CommandHandler)]
}

/// Generate a fresh tenant root and write its private seed to the operand
/// path. Only the public root is returned.
///
/// # Errors
/// Returns the registered usage or configuration refusal when the tenant,
/// operand, entropy source, or protected destination is unusable.
pub fn command(invocation: &Invocation) -> Result<Value, CliError> {
    let sources = invocation
        .config_sources()
        .capture_environment()
        .map_err(|error| config_fault(&error))?;
    let resolved = sources.load().map_err(|error| config_fault(&error))?;
    create_over(&resolved, invocation)
}

/// Execute the bootstrap over already-resolved configuration.
///
/// # Errors
/// Returns the registered usage or decision-missing refusal when the tenant
/// or protected destination is unusable.
pub fn create_over(resolved: &ResolvedConfig, invocation: &Invocation) -> Result<Value, CliError> {
    let tenant_text = resolved
        .text(TENANT_KEY)
        .ok_or_else(|| CliError::registered(DECISION_MISSING))?;
    let tenant = tenant_text
        .parse::<TenantId>()
        .map_err(|_| CliError::usage())?;
    let path = invocation.operands().first().ok_or_else(CliError::usage)?;
    let path = std::path::Path::new(path);
    if !path.is_absolute() {
        return Err(CliError::usage());
    }

    let authority = TenantAuthority::generate().map_err(|_| CliError::usage())?;
    authority.write_new(path).map_err(|_| CliError::usage())?;

    let mut result = json::Object::new();
    result.set("schema", Value::Text("archivist.cli-result/v1".to_owned()));
    result.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    result.set(
        "authority_key",
        Value::Text(authority.public_key().to_hex()),
    );
    result.set("authority_key_id", Value::Text(authority.key_id().to_hex()));
    Ok(Value::Object(result))
}

fn config_fault(error: &ConfigError) -> CliError {
    CliError::registered(error.code().token())
}
