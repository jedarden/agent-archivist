// SPDX-License-Identifier: Apache-2.0

//! The `probe` command: one bounded liveness probe against the served
//! process-only liveness route (plan Phase 4; release-container RC-020).
//!
//! The release image's `HEALTHCHECK` invokes the binary itself — the
//! runtime base ships neither `curl` nor `wget` and the runtime stage
//! installs no packages, so a fetched probe tool is exactly what the
//! baseline forbids — which makes this command the image's probe
//! mechanism. The command resolves the configuration exactly as `serve`
//! does (through that module's shared `resolve`, so the address it probes
//! is exactly the address the replica bound), hands the registered
//! `server.listen_address` to [`archivist_server::probe::probe_live`],
//! and lets the process exit carry the verdict: 0 when the route answered
//! `200 OK` within the probe bound, the registered `server.unavailable`
//! class when a replica did not answer in health — the HEALTHCHECK's own
//! interval and retries are the retry — and the ordinary configuration
//! and usage refusals a resolution that never reached a replica reports.
//! stdout stays empty on every path (CLI-016).

use archivist_client_core::cli::{CliError, CommandHandler, Invocation};
use archivist_client_core::config::ResolvedConfig;
use archivist_protocol::json::Value;
use archivist_server::probe::{ProbeFault, probe_live};

/// The registered code for a composition-required setting that resolved
/// from no tier (`tools/error-codes.toml`, class `usage`).
const DECISION_MISSING: &str = "cli.decision_missing";

/// The registered code for a replica that did not answer the liveness
/// route in health (`tools/error-codes.toml`, class `server_failure`):
/// the retryable condition the HEALTHCHECK's own scheduling retries.
const UNAVAILABLE: &str = "server.unavailable";

/// The composition's attached surface: the registered command path and
/// its handler. The binary attaches every entry; the attachability test
/// proves the path still names a registered command with a shipped
/// output kind.
#[must_use]
pub fn handlers() -> [(&'static str, CommandHandler); 1] {
    [("probe", probe as CommandHandler)]
}

/// Run the `probe` command: resolve the configuration the invocation
/// names — always non-interactive (CLI-021) — and probe the listen
/// address it resolves.
///
/// # Errors
/// The registered refusal of the first failing act: configuration
/// acquisition, the missing listen address, or the probe verdict itself.
pub fn probe(invocation: &Invocation) -> Result<Value, CliError> {
    let resolved = crate::serve::resolve(invocation)?;
    probe_over(&resolved)
}

/// Probe over an already-resolved configuration: read the registered
/// listen address and map the probe's verdict onto the registered codes.
/// Split from [`probe`] so the mapping is provable over a synthetic
/// configuration without touching the process environment.
///
/// # Errors
/// `cli.decision_missing` when no listen address resolved, the usage
/// class when the address is outside the socket-address grammar, and the
/// registered `server.unavailable` class when the replica did not answer
/// the liveness route in health.
pub fn probe_over(resolved: &ResolvedConfig) -> Result<Value, CliError> {
    let address = resolved
        .text("server.listen_address")
        .ok_or_else(|| CliError::registered(DECISION_MISSING))?;
    match probe_live(address) {
        Ok(()) => Ok(Value::Null),
        Err(ProbeFault::MalformedAddress) => Err(CliError::usage()),
        Err(ProbeFault::Unreachable | ProbeFault::Unhealthy) => {
            Err(CliError::registered(UNAVAILABLE))
        }
    }
}

#[cfg(test)]
mod tests {
    use archivist_client_core::cli::Router;
    use archivist_client_core::config::ConfigSources;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::{handlers, probe_over};

    /// The environment tier every load resolves over: the required
    /// registered keys (the same fixture the serve composition tests
    /// use), with the listen address supplied per test. The credential
    /// references point at `env:` targets that are deliberately never
    /// set — the probe consumes none of them, so nothing resolves them.
    fn probe_sources() -> ConfigSources {
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
    }

    /// Bind an ephemeral listener whose first connection is answered with
    /// the liveness route's success response and then closed.
    fn serving_liveness_route() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral listener binds");
        let address = listener
            .local_addr()
            .expect("the listener names an address");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 512];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                      content-length: 13\r\nconnection: close\r\n\r\n{\"live\":true}",
                );
            }
        });
        address
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
    fn a_live_replica_confirms_the_verdict() {
        let address = serving_liveness_route();
        let resolved = probe_sources()
            .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", &address.to_string())
            .load()
            .expect("the address resolves");
        assert_eq!(
            probe_over(&resolved),
            Ok(archivist_protocol::json::Value::Null)
        );
    }

    #[test]
    fn a_replica_that_is_not_there_is_the_registered_unavailable_class() {
        // Bind, take the address, and drop the listener: localhost
        // refuses the probe's connect outright.
        let address = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral listener binds");
            listener
                .local_addr()
                .expect("the listener names an address")
        };
        let resolved = probe_sources()
            .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", &address.to_string())
            .load()
            .expect("the address resolves");
        let error = probe_over(&resolved).expect_err("nothing serves on the dropped address");
        assert_eq!(error.code(), "server.unavailable");
        assert_eq!(error.exit_code(), 75, "the server_failure class exit");
    }

    #[test]
    fn a_malformed_address_is_a_usage_error() {
        let resolved = probe_sources()
            .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "not-a-socket-address")
            .load()
            .expect("the string grammar itself resolves");
        let error = probe_over(&resolved).expect_err("the address is outside the grammar");
        assert_eq!(error.code(), "cli.usage_error");
    }

    #[test]
    fn a_missing_listen_address_is_a_missing_decision() {
        // `server.listen_address` is required in the registry, so the
        // load refuses — and that registered refusal is exactly what the
        // command surfaces through `resolve`. [`probe_over`]'s own
        // missing-decision arm is the fail-closed restatement for a load
        // path that bypassed the registry's requiredness.
        let error = probe_sources()
            .load()
            .expect_err("no listen address resolved from any tier");
        assert_eq!(error.code().token(), "cli.decision_missing");
    }
}
