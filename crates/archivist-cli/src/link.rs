// SPDX-License-Identifier: Apache-2.0

//! The public client-side link request command.
//!
//! A new client has no local identity yet, so this command mints one into the
//! mode-restricted client state directory and emits the public request an
//! administrator approves. Re-running it discovers the existing identity;
//! the private seed never enters the request, result, diagnostics, or an
//! argument.

use archivist_auth::identity::InstallationIdentity;
use archivist_auth::link::{LinkRequest, RequestedScopes, ScopeOperation};
use archivist_auth::reference::ProtectedReference;
use archivist_client_core::cli::{CliError, CommandHandler, Invocation};
use archivist_client_core::config::{ConfigError, ResolvedConfig};
use archivist_protocol::json::{self, Value};
use archivist_protocol::vocabulary::{HarnessId, TenantId};

const STATE_DIR_KEY: &str = "client.state_dir";
const TENANT_KEY: &str = "client.tenant";
const HARNESS_KEY: &str = "client.harness";
const DECISION_MISSING: &str = "cli.decision_missing";

/// Attach the public link-request command to the composition root.
#[must_use]
pub fn handlers() -> [(&'static str, CommandHandler); 1] {
    [("link request", command as CommandHandler)]
}

/// Mint or discover the local installation identity and emit its public link
/// request.
///
/// # Errors
/// Returns the registered configuration, usage, or protected-state refusal
/// when the tenant, harness, or local identity is unusable.
pub fn command(invocation: &Invocation) -> Result<Value, CliError> {
    let sources = invocation
        .config_sources()
        .capture_environment()
        .map_err(|error| config_fault(&error))?;
    let resolved = sources.load().map_err(|error| config_fault(&error))?;
    request_over(&resolved)
}

/// Execute the link request over already-resolved configuration.
///
/// # Errors
/// Returns the registered decision-missing, usage, or protected-state refusal
/// when the tenant, harness, or local identity is unusable.
pub fn request_over(resolved: &ResolvedConfig) -> Result<Value, CliError> {
    let tenant_text = resolved
        .text(TENANT_KEY)
        .ok_or_else(|| CliError::registered(DECISION_MISSING))?;
    let tenant = tenant_text
        .parse::<TenantId>()
        .map_err(|_| CliError::usage())?;
    let harness_text = resolved
        .text(HARNESS_KEY)
        .ok_or_else(|| CliError::registered(DECISION_MISSING))?;
    let harness = harness_text
        .parse::<HarnessId>()
        .map_err(|_| CliError::usage())?;

    let state_dir = resolved
        .path(STATE_DIR_KEY)
        .ok_or_else(|| CliError::registered(DECISION_MISSING))?;
    let identity_path = state_dir.join(["identity", "json"].join("."));
    let identity = if identity_path.exists() {
        let reference = ProtectedReference::parse(&format!("file:{}", identity_path.display()))
            .map_err(|_| CliError::usage())?;
        InstallationIdentity::discover(&reference).map_err(|_| CliError::usage())?
    } else {
        let identity = InstallationIdentity::generate().map_err(|_| CliError::usage())?;
        identity
            .write_new(&identity_path)
            .map_err(|_| CliError::usage())?;
        identity
    };

    let scopes = RequestedScopes::new(vec![harness], vec![ScopeOperation::Ingest])
        .map_err(|_| CliError::usage())?;
    let request = LinkRequest::new(identity.public_identity(), tenant, scopes);
    json::parse(&request.canonical_bytes()).map_err(|_| CliError::internal())
}

fn config_fault(error: &ConfigError) -> CliError {
    CliError::registered(error.code().token())
}
