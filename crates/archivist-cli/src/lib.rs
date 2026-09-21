// SPDX-License-Identifier: Apache-2.0

//! Library surface of the `archivist` composition root.
//!
//! The `archivist` binary (`src/main.rs`) stays a thin entry point: it
//! composes the registry-driven parser and router from
//! `archivist_client_core::cli` and attaches the library-owned handlers a
//! command's implementing phase registers. The composition surfaces those
//! handlers share live in this library target instead of the binary so they
//! are reachable, documented, and unit-tested from the moment they land —
//! including in the window before the handler that calls them attaches,
//! where the same code compiled inside the binary alone would be
//! unreachable. The first of these is the offline administration control
//! plane ([`admin`]): the shared assembly of the
//! `S3ControlAdminStore` from the registered `admin.*` configuration keys.
//! The second is the `admin approve` command behavior ([`approve`]): the
//! link-request draft read, validated, and signed at the current instant,
//! published through that store, and emitted as the linked-client record
//! document its registry entry's `result_schema` names — every refusal a
//! registered code of `tools/error-codes.toml`, with stdout empty. The
//! third is the `admin revoke` command's revocation-draft parsing
//! ([`revoke`]): the operand document read and grammar-checked into the
//! draft the command's signing and persistence acts consume, refusing on
//! the same registered-code discipline.
//!
//! # Dependency boundary
//!
//! May depend on every workspace crate: it exists to compose them. Business
//! logic that would need one of the library crates as a peer belongs in that
//! library crate instead — the same rule the binary itself follows, so this
//! target adds no privilege, only a testable home for composition.

pub mod admin;
pub mod approve;
pub mod revoke;
