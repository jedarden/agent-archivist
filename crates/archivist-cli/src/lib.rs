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
//! whole reason for the storage-s3 dependency edge. The sixth is the
//! liveness probe ([`probe`]): one bounded GET on a served replica's
//! process-only liveness route, the image's own HEALTHCHECK mechanism
//! (release-container note RC-020) on the one binary the image carries.
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
pub mod probe;
pub mod revoke;
pub mod serve;

use archivist_client_core::cli::CommandHandler;

/// All handlers shipped by the composition root.
///
/// This is the one command-to-handler list used by the binary and by the
/// command-level coherence test. Keeping the aggregation here makes a new
/// production handler impossible to wire into only one of those surfaces.
#[must_use]
pub fn handlers() -> Vec<(&'static str, CommandHandler)> {
    operator::handlers()
        .into_iter()
        .chain(serve::handlers())
        .chain(probe::handlers())
        .chain(approve::handlers())
        .chain(revoke::handlers())
        .chain(catalog::handlers())
        .collect()
}

/// Compose every shipped command against the registry and the two embedded
/// supporting registries. These assertions are intentionally command-level:
/// a local registry parser can pass while a handler list, consumed key, error
/// code, or error class has drifted at the composition boundary.
///
/// # Panics
/// Panics when the committed command surface contains a duplicate handler,
/// an unregistered or unavailable handler, an available document without a
/// result schema, an unregistered key, an unconsumed key, or an error code
/// without a registered exit class.
pub fn assert_registry_coherence() {
    let registry = archivist_client_core::cli::registry::Registry::pinned();
    let attached = handlers();
    let mut attached_paths = std::collections::BTreeSet::new();
    for (path, _handler) in &attached {
        assert!(attached_paths.insert(*path), "duplicate handler for {path}");
        let segments = path.split(' ').map(str::to_owned).collect::<Vec<_>>();
        let command = registry
            .command(&segments)
            .unwrap_or_else(|| panic!("handler {path} is not a registered command"));
        assert!(
            command.is_available(),
            "handler {path} is not an available command"
        );
        if command.stdout_kind() == "document" {
            assert!(
                command.result_schema().is_some(),
                "document command {path} has no result schema"
            );
        }
    }

    let available = registry
        .commands()
        .filter(|command| command.is_available())
        .map(archivist_client_core::cli::registry::Command::path_text)
        .collect::<std::collections::BTreeSet<_>>();
    let attached_text = attached_paths
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        attached_text, available,
        "every available command must have exactly one production handler"
    );

    let config = archivist_client_core::config::registry::config_registry();
    let mut consumed = std::collections::BTreeSet::new();
    for command in registry.commands() {
        for key in command.keys() {
            assert!(
                config.key(key).is_some(),
                "command {} consumes unregistered key {key}",
                command.path_text()
            );
            consumed.insert(key.as_str());
        }
    }
    for key in config.keys() {
        assert!(
            consumed.contains(key.name()),
            "registered key {} is consumed by no command",
            key.name()
        );
    }

    let errors = archivist_client_core::config::registry::error_registry();
    for class in errors.classes() {
        assert_ne!(
            class.exit_code(),
            0,
            "error class {} must not claim the success exit",
            class.name()
        );
        assert!(
            class.exit_code() < 128,
            "error class {} must not claim a signal exit",
            class.name()
        );
    }
    for code in errors.codes() {
        let class = errors
            .class(code.class())
            .unwrap_or_else(|| panic!("error code {} names no class", code.code()));
        assert_eq!(
            archivist_client_core::cli::CliError::registered(code.code()).exit_code(),
            class.exit_code(),
            "emitted code {} must use its registered exit class",
            code.code()
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn command_surface_joins_handlers_keys_codes_and_exit_classes() {
        super::assert_registry_coherence();
    }
}
