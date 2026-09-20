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
//! parser and router from [`archivist_client_core::cli`]; later phases attach
//! their library-owned handlers at this composition point. A registered
//! command without a result schema or handler is rejected as not shipped,
//! rather than being represented by placeholder behavior.
//!
//! # Dependency boundary
//!
//! May depend on every workspace crate: it exists to compose them. Business
//! logic that would need one of the library crates as a peer belongs in that
//! library crate instead.

/// Compose the command router and run one invocation.
fn main() {
    let router = archivist_client_core::cli::router::Router::new();
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    std::process::exit(router.run(&args));
}
