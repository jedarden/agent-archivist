// SPDX-License-Identifier: Apache-2.0

//! The manifest-level adapter dependency boundary (implementation plan
//! Section 6; docs/notes/crate-ownership.md rules 1 and 3): adapter
//! dependencies cannot leak into the protocol or server crates, source
//! adapters depend on the SDK alone, and pre-1.0 adapters ship with the
//! core version.
//!
//! The test reads the committed manifests from the checkout — no cargo
//! metadata, no third-party parser — so it runs wherever `cargo test`
//! runs and fails on the working tree the moment a boundary-unsafe edge
//! is added. This pins the manifest half of the boundary; the
//! source-surface half (no replaceable SDK types in protocol's public
//! signatures, crate-ownership rule 6) is the protocol boundary's own
//! gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The workspace root, resolved from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("the SDK lives at crates/archivist-adapter-sdk")
}

/// The workspace's crate names and manifest paths, discovered from the
/// `crates/*` member glob on disk.
fn workspace_members(root: &Path) -> BTreeMap<String, PathBuf> {
    let mut members = BTreeMap::new();
    let crates_dir = root.join("crates");
    for entry in fs::read_dir(&crates_dir).expect("crates/ directory exists") {
        let path = entry.expect("readable crates/ entry").path();
        let manifest = path.join("Cargo.toml");
        if !path.is_dir() || !manifest.exists() {
            continue;
        }
        let text = fs::read_to_string(&manifest)
            .unwrap_or_else(|error| panic!("{} is readable: {error}", manifest.display()));
        let name = package_name(&text)
            .unwrap_or_else(|| panic!("{} declares a package name", manifest.display()));
        members.insert(name, manifest);
    }
    assert!(!members.is_empty(), "the workspace has members");
    members
}

/// The `[package].name` of a manifest.
fn package_name(manifest: &str) -> Option<String> {
    let section = manifest_section(manifest, "package")?;
    section
        .lines()
        .find_map(|line| exact_key(line, "name").map(|value| value.trim_matches('"').to_owned()))
}

/// The text of one top-level `[section]` of a manifest, to the next
/// top-level header. Header names match in full, so `[package]` and
/// `[workspace.package]` are distinct sections.
fn manifest_section(manifest: &str, wanted: &str) -> Option<String> {
    let mut current: Option<&str> = None;
    let mut section = Vec::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if current == Some(wanted) {
                break;
            }
            current = Some(trimmed.trim_start_matches('[').trim_end_matches(']'));
            section.clear();
            continue;
        }
        if current.is_some() {
            section.push(trimmed);
        }
    }
    if current == Some(wanted) {
        Some(section.join("\n"))
    } else {
        None
    }
}

/// The value of `key = "value"` (or any bare value) on one line, with no
/// prefix — `version.workspace = true` matches `version.workspace`, and
/// `x_version = "1"` does not match `version`.
fn exact_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let line = line.trim();
    let (name, value) = line.split_once('=')?;
    let name = name.trim();
    if name == key {
        Some(value.trim())
    } else {
        None
    }
}

/// Every internal dependency name a manifest declares, across the plain,
/// dev, build, and target-qualified dependency sections. The dependency
/// *name* is what pins the edge — target sections and inline tables are
/// handled by section tracking plus a first-line name match, so a
/// multi-line `{ ... }` value still records its dependency.
fn internal_dependencies(manifest: &str) -> BTreeSet<String> {
    const DEPENDENCY_SECTIONS: [&str; 3] =
        ["dependencies", "dev-dependencies", "build-dependencies"];

    let mut dependencies = BTreeSet::new();
    let mut in_dependency_section = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            let leaf = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .rsplit('.')
                .next()
                .unwrap_or("")
                .trim_matches('\'')
                .trim_matches('"');
            in_dependency_section = DEPENDENCY_SECTIONS.contains(&leaf);
            continue;
        }
        if !in_dependency_section || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = line.split_once('=') {
            let name = name.trim();
            if name.starts_with("archivist-") {
                dependencies.insert(name.to_owned());
            }
        }
    }
    dependencies
}

/// The concrete source adapters (the SDK itself is not one).
fn is_concrete_adapter(crate_name: &str) -> bool {
    [
        "archivist-adapter-claude",
        "archivist-adapter-codex",
        "archivist-adapter-opencode",
        "archivist-adapter-pi",
    ]
    .contains(&crate_name)
}

#[test]
fn protocol_declares_no_internal_dependency_at_all() {
    let root = workspace_root();
    let members = workspace_members(&root);
    let protocol = internal_dependencies(
        &fs::read_to_string(members["archivist-protocol"].clone()).expect("manifest"),
    );
    assert!(
        protocol.is_empty(),
        "archivist-protocol is sealed (crate-ownership rule 1); found internal \
         dependencies {protocol:?} — adapter dependencies cannot reach the wire contract"
    );
}

#[test]
fn server_and_protocol_declare_no_adapter_dependency() {
    let root = workspace_root();
    let members = workspace_members(&root);
    for sealed in ["archivist-protocol", "archivist-server"] {
        let manifest = fs::read_to_string(members[sealed].clone()).expect("manifest");
        let dependencies = internal_dependencies(&manifest);
        let adapter_edges: Vec<_> = dependencies
            .iter()
            .filter(|name| name.as_str() == "archivist-adapter-sdk" || is_concrete_adapter(name))
            .collect();
        assert!(
            adapter_edges.is_empty(),
            "{sealed} must not depend on the adapter SDK or any source adapter \
             (crate-ownership rules 1 and 3); found {adapter_edges:?}"
        );
    }
}

#[test]
fn only_the_cli_composes_concrete_adapters() {
    let root = workspace_root();
    let members = workspace_members(&root);
    for (name, manifest_path) in &members {
        if name == "archivist-cli" {
            continue;
        }
        let manifest = fs::read_to_string(manifest_path).expect("manifest");
        let dependencies = internal_dependencies(&manifest);
        let adapter_edges: Vec<_> = dependencies
            .iter()
            .filter(|dep| is_concrete_adapter(dep))
            .collect();
        assert!(
            adapter_edges.is_empty(),
            "only archivist-cli may depend on a concrete source adapter \
             (crate-ownership rule 3); {name} declares {adapter_edges:?}"
        );
    }
}

#[test]
fn source_adapters_depend_on_the_sdk_alone() {
    let root = workspace_root();
    let members = workspace_members(&root);
    for (name, manifest_path) in &members {
        if !is_concrete_adapter(name) {
            continue;
        }
        let manifest = fs::read_to_string(manifest_path).expect("manifest");
        let dependencies = internal_dependencies(&manifest);
        let outside: Vec<_> = dependencies
            .iter()
            .filter(|dep| dep.as_str() != "archivist-adapter-sdk")
            .collect();
        assert!(
            outside.is_empty(),
            "source adapters depend on archivist-adapter-sdk only \
             (crate-ownership rule 3); {name} also declares {outside:?}"
        );
    }
}

#[test]
fn the_sdk_depends_on_protocol_alone() {
    let root = workspace_root();
    let members = workspace_members(&root);
    let manifest = fs::read_to_string(members["archivist-adapter-sdk"].clone()).expect("manifest");
    let dependencies = internal_dependencies(&manifest);
    let outside: Vec<_> = dependencies
        .iter()
        .filter(|dep| dep.as_str() != "archivist-protocol")
        .collect();
    assert!(
        outside.is_empty(),
        "archivist-adapter-sdk depends on archivist-protocol only; found {outside:?}"
    );
}

#[test]
fn pre_1_0_adapters_inherit_the_core_version() {
    let root = workspace_root();
    let root_manifest = fs::read_to_string(root.join("Cargo.toml")).expect("root manifest");
    let workspace_package =
        manifest_section(&root_manifest, "workspace.package").expect("workspace package");
    let core_version = workspace_package
        .lines()
        .find_map(|line| exact_key(line, "version"))
        .expect("the workspace pins a core version")
        .trim_matches('"')
        .to_owned();

    // The lockstep rule governs the pre-1.0 regime (plan Phase 6D:
    // "version adapters independently from the core only after 1.0").
    // When the core reaches 1.0 this assertion is deliberately replaced,
    // in the commit that publishes 1.0, by the compatibility-boundary
    // rule.
    assert!(
        core_version.starts_with('0'),
        "this test pins the pre-1.0 version lockstep; the core version is now \
         {core_version}, so adapter versioning follows the post-1.0 rule instead"
    );

    let members = workspace_members(&root);
    for (name, manifest_path) in &members {
        if !is_concrete_adapter(name) && name != "archivist-adapter-sdk" {
            continue;
        }
        let manifest = fs::read_to_string(manifest_path).expect("manifest");
        let package = manifest_section(&manifest, "package").expect("package section");
        let inherits = package
            .lines()
            .any(|line| exact_key(line, "version.workspace") == Some("true"));
        let pinned = package
            .lines()
            .any(|line| exact_key(line, "version").is_some());
        assert!(
            inherits && !pinned,
            "{name} must ship with the core version while the core is pre-1.0: \
             declare `version.workspace = true` and no standalone `version` \
             (plan Phase 6D; core version is {core_version})"
        );
    }
}
