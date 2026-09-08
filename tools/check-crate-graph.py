#!/usr/bin/env python3
"""Dependency-cycle check for the Agent Archivist workspace.

Reads the committed manifests alone and verifies that:

1. every workspace member declares a name and a non-empty description
   (the documented purpose the Phase 0 exit gate requires);
2. every member has a doc-commented entry point (``lib.rs`` or ``main.rs``);
3. every internal ``path`` dependency resolves to a workspace member whose
   package name matches; and
4. the internal dependency graph — normal, dev, and build dependencies alike —
   is acyclic.

On success it prints the crate layers implied by the graph and exits 0. Any
failure prints a report on stderr and exits 2.

Usage::

    tools/check-crate-graph.py

The script is standard-library only so a clean checkout can run it before any
dependency is fetched.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_FIELD_RE = re.compile(r'^(?P<key>name|description)\s*=\s*"(?P<value>[^"]*)"', re.M)
_PATH_DEP_RE = re.compile(
    r'^(?P<name>[A-Za-z0-9_.-]+)\s*=\s*\{\s*path\s*=\s*"(?P<path>[^"]+)"', re.M
)
_MEMBERS_RE = re.compile(r'^members\s*=\s*\[(?P<items>[^\]]*)\]', re.M | re.S)
_ITEM_RE = re.compile(r'"(?P<pattern>[^"]+)"')
_SECTION_RE = re.compile(r"^\[{1,2}(?P<section>[A-Za-z0-9._-]+)\]{1,2}\s*$", re.M)

# A crate-level doc comment may be preceded by ordinary comment lines (the
# license header) and blank lines, but must come before any item.
DOC_COMMENT_RE = re.compile(r"\A(?:[ \t]*(?://[^\n]*)?\n)*[ \t]*//!")

DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def section(manifest: str, name: str) -> str:
    """Return the body of a TOML section, or ``""`` when absent.

    Section boundaries are line-anchored so a ``[[bin]]`` block never bleeds
    into ``[package]`` parsing.
    """
    matches = list(_SECTION_RE.finditer(manifest))
    for index, match in enumerate(matches):
        if match.group("section").split(".", 1)[0] != name:
            continue
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(manifest)
        return manifest[start:end]
    return ""


def workspace_members() -> list[Path]:
    """Expand the root manifest's ``members`` globs into member directories."""
    root_manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = _MEMBERS_RE.search(section(root_manifest, "workspace"))
    if not match:
        fail("root Cargo.toml has no [workspace] members list")
        return []

    members: list[Path] = []
    for pattern in _ITEM_RE.findall(match.group("items")):
        found = sorted(p for p in ROOT.glob(pattern) if (p / "Cargo.toml").is_file())
        if not found:
            fail(f"member pattern {pattern!r} matched no crate directories")
        members.extend(found)
    return members


def package_fields(directory: Path) -> dict[str, str]:
    return dict(_FIELD_RE.findall(section((directory / "Cargo.toml").read_text(
        encoding="utf-8"), "package")))


def load_crate(directory: Path) -> tuple[str, str, list[str]] | None:
    """Return ``(name, description, internal dependency names)`` for a crate."""
    manifest_path = directory / "Cargo.toml"
    manifest = manifest_path.read_text(encoding="utf-8")

    fields = package_fields(directory)
    name = fields.get("name")
    if not name:
        fail(f"{manifest_path} does not declare a package name")
        return None
    description = fields.get("description", "").strip()
    if not description:
        fail(f"{name} ({manifest_path}) has no description; every planned crate "
             "must document its purpose")
        return None

    entry_point = next(
        (source for source in ("src/lib.rs", "src/main.rs") if (directory / source).is_file()),
        None,
    )
    if entry_point is None:
        fail(f"{name} has no src/lib.rs or src/main.rs")
        return None
    if not DOC_COMMENT_RE.match((directory / entry_point).read_text(encoding="utf-8")):
        fail(f"{name} entry point {entry_point} has no crate-level documentation")
        return None

    dependencies: list[str] = []
    for dep_section in DEPENDENCY_SECTIONS:
        for dep_name, dep_path in _PATH_DEP_RE.findall(section(manifest, dep_section)):
            target = (directory / dep_path).resolve()
            if not (target / "Cargo.toml").is_file():
                fail(f"{name} depends on {dep_name} at missing path {dep_path!r}")
                return None
            target_name = package_fields(target).get("name", dep_name)
            if target_name != dep_name:
                fail(f"{name} declares path dependency {dep_name!r} but that crate "
                     f"is named {target_name!r}")
                return None
            dependencies.append(target_name)

    return name, description, dependencies


def check_acyclic(
    graph: dict[str, list[str]], descriptions: dict[str, str]
) -> list[list[str]] | None:
    """Kahn topological layering; returns ``None`` (after reporting) on a cycle."""
    remaining = {node: set(deps) for node, deps in graph.items()}
    ordered: list[list[str]] = []
    while remaining:
        layer = sorted(node for node, deps in remaining.items() if not deps)
        if not layer:
            fail("dependency cycle detected among: " + ", ".join(sorted(remaining)))
            return None
        ordered.append(layer)
        for node in layer:
            del remaining[node]
        for deps in remaining.values():
            deps -= set(layer)

    for depth, members in enumerate(ordered):
        named = ", ".join(f"{node} — {descriptions[node]}" for node in members)
        print(f"layer {depth}: {named}")
    return ordered


def main() -> int:
    directories = workspace_members()
    if not directories:
        return 2

    graph: dict[str, list[str]] = {}
    descriptions: dict[str, str] = {}
    for directory in directories:
        loaded = load_crate(directory)
        if loaded is None:
            return 2
        name, description, dependencies = loaded
        if name in graph:
            fail(f"duplicate crate name {name!r}")
            return 2
        graph[name] = dependencies
        descriptions[name] = description

    unknown = sorted(
        dep for deps in graph.values() for dep in deps if dep not in graph
    )
    if unknown:
        fail(f"internal dependencies outside the workspace: {', '.join(unknown)}")
        return 2

    print(f"agent-archivist crate graph: {len(graph)} members")
    if check_acyclic(graph, descriptions) is None:
        return 2
    print(f"OK: acyclic ({sum(len(deps) for deps in graph.values())} internal edges)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
