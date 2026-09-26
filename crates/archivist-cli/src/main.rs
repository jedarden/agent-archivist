// SPDX-License-Identifier: Apache-2.0

//! `archivist` command-line entry point.
//!
//! The single portable binary behind the `collect`, `serve`, `link`, `admin`,
//! and `status` command families (implementation plan, Section 6). This crate
//! is the workspace's composition root: it selects the concrete storage
//! backend and the set of enabled source adapters and hands them to the
//! library crates. Command behavior, configuration precedence, JSON output,
//! exit codes, and secret-reference handling live in the library crates, not
//! here.
//!
//! The binary owns no command behavior. It composes the registry-driven
//! parser and router from [`archivist_client_core::cli`] and attaches the
//! implemented phases' handlers at this composition point. The Phase 5
//! operator surface is attached: the `daemon`, `run --once`, `inventory`,
//! `status`, `verify-state`, and `doctor` commands the operator module
//! composes. The Phase 4 ingestion server is attached with it: the
//! `serve` command the serve module composes — the concrete S3 storage
//! backend is selected here, at the composition root — and the `probe`
//! command the probe module composes, the release image's HEALTHCHECK
//! mechanism (release-container RC-020).
//! A registered command whose phase has not attached a handler is
//! rejected as not shipped when invoked, rather than being represented
//! by placeholder behavior.
//!
//! The composition surfaces those handlers share live in this crate's
//! library target (`archivist_cli::admin` carries the offline
//! administration control plane: the store assembled from the registered
//! `admin.*` configuration keys, with the ingest-credential boundary
//! enforced at composition), so each surface is reachable and unit-tested
//! in the window before the handler that calls it attaches.
//!
//! # Dependency boundary
//!
//! May depend on every workspace crate: it exists to compose them. Business
//! logic that would need one of the library crates as a peer belongs in that
//! library crate instead.

/// Compose the command router, attach the implemented handlers, and run
/// one invocation.
fn main() {
    let mut router = archivist_client_core::cli::router::Router::new();
    let operator = archivist_cli::operator::handlers();
    let serve = archivist_cli::serve::handlers();
    let probe = archivist_cli::probe::handlers();
    for (path, handler) in operator
        .iter()
        .copied()
        .chain(serve.iter().copied())
        .chain(probe.iter().copied())
    {
        // Every entry names a registered path whose phase shipped its
        // output kind; the registry gate checked the pair, and a refusal
        // here is a composition bug, not runtime behavior.
        router
            .register_handler(path, handler)
            .expect("an attached handler names a registered command");
    }
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    std::process::exit(router.run(&args));
}
