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
//! third is the `admin revoke` command ([`revoke`]): the operand document
//! read and grammar-checked into the draft, and the signing-and-persistence
//! act that verifies the client's standing pointer, signs the revocation
//! with the tenant authority, and publishes it through that store — every
//! refusal a registered code of `tools/error-codes.toml`, with stdout
//! empty. The fourth is the Phase 5 operator command surface
//! ([`operator`]): the `status`, `verify-state`, and `inventory`
//! read-only reports over a state snapshot, and the `run --once` and
//! `daemon` mutators that lock the state directory, migrate, reconcile
//! the spool, evaluate pressure, and plan the round — every document
//! pinned to its registry entry's `result_schema`, every refusal a
//! registered code, and the binary attaches the five handlers at its
//! own composition point. The fifth is the Phase 4 ingestion replica
//! ([`serve`]): the composition that selects the concrete S3 storage
//! backend, pins the trust anchor set, and hands the validated parts to
//! the server crate's bind/serve lifecycle — the composition root's
//! whole reason for the storage-s3 dependency edge.
//!
//! # Dependency boundary
//!
//! May depend on every workspace crate: it exists to compose them. Business
//! logic that would need one of the library crates as a peer belongs in that
//! library crate instead — the same rule the binary itself follows, so this
//! target adds no privilege, only a testable home for composition.

pub mod admin;
pub mod approve;
pub mod catalog;
pub mod operator;
pub mod revoke;
pub mod serve;
