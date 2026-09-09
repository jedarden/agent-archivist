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
//! # Status
//!
//! Skeleton scaffold (Phase 0). Commands arrive across Phases 3, 5, 6, and 7;
//! `main` deliberately does nothing yet. There is no placeholder production
//! behavior here and no stub pretending to work.
//!
//! # Dependency boundary
//!
//! May depend on every workspace crate: it exists to compose them. Business
//! logic that would need one of the library crates as a peer belongs in that
//! library crate instead.

fn main() {}
