#!/usr/bin/env python3
"""License gate for the Agent Archivist workspace.

Every workspace member carries the project license, and every third-party
package in ``Cargo.lock`` has had its license reviewed and recorded in
``tools/license-allowlist.toml``. The check reads committed files only, so it
runs on a clean checkout with no network access and no external credentials,
and its output names packages and SPDX identifiers only.

Policy:

1. the root manifest's ``[workspace.package] license`` is the project license
   (Apache-2.0, the license of [LICENSE] and of every contribution);
2. every workspace member either inherits it (``license.workspace = true``)
   or declares exactly the same string; and
3. every ``Cargo.lock`` package that is not a workspace member appears in the
   ``[approved]`` table of the allowlist with the SPDX expression published
   for that crate, recorded in the same commit that adds the dependency.

A dependency that reaches the lockfile without an allowlist entry fails this
check, so adopting a dependency is always a deliberate license review. A stale
allowlist entry (the dependency is gone) also fails, keeping the file an
honest record rather than an accreting dump.

On success it prints the verified counts and exits 0. Any failure prints a
report on stderr and exits 2.

Usage::

    tools/check-licenses.py

The script is standard-library only and shares its manifest-parsing approach
with ``tools/check-crate-graph.py``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PROJECT_LICENSE = "Apache-2.0"
ALLOWLIST_PATH = ROOT / "tools" / "license-allowlist.toml"

_SECTION_RE = re.compile(r"^\[{1,2}(?P<section>[A-Za-z0-9._-]+)\]{1,2}\s*$", re.M)
_MEMBERS_RE = re.compile(r"^members\s*=\s*\[(?P<items>[^\]]*)\]", re.M | re.S)
_ITEM_RE = re.compile(r'"(?P<pattern>[^"]+)"')
_LICENSE_RE = re.compile(r'^license\s*=\s*"(?P<value>[^"]*)"', re.M)
_LICENSE_INHERIT_RE = re.compile(r"^license\.workspace\s*=\s*true", re.M)
_NAME_RE = re.compile(r'^name\s*=\s*"(?P<value>[^"]*)"', re.M)
_ALLOWLIST_ENTRY_RE = re.compile(
    r'^(?P<name>[A-Za-z0-9_.-]+)\s*=\s*"(?P<spdx>[^"]*)"', re.M
)


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def section(manifest: str, name: str) -> str:
    """Return the body of the exactly-named TOML section, or ``""``."""
    matches = list(_SECTION_RE.finditer(manifest))
    for index, match in enumerate(matches):
        if match.group("section") != name:
            continue
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(manifest)
        return manifest[start:end]
    return ""


def workspace_member_names() -> list[str] | None:
    """Expand the root manifest's ``members`` globs into package names."""
    root_manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    workspace_body = ""
    for name in ("workspace", "workspace.package"):
        workspace_body += section(root_manifest, name)
    match = _MEMBERS_RE.search(workspace_body)
    if not match:
        fail("root Cargo.toml has no [workspace] members list")
        return None

    names: list[str] = []
    for pattern in _ITEM_RE.findall(match.group("items")):
        for directory in sorted(ROOT.glob(pattern)):
            manifest = directory / "Cargo.toml"
            if not manifest.is_file():
                continue
            name_match = _NAME_RE.search(section(manifest.read_text(
                encoding="utf-8"), "package"))
            if not name_match:
                fail(f"{manifest} does not declare a package name")
                return None
            names.append(name_match.group("value"))
    if not names:
        fail("root Cargo.toml members list matched no crate directories")
        return None
    return names


def check_workspace_license() -> bool:
    """Verify the project license is declared and inherited by every member."""
    root_manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    workspace_license = _LICENSE_RE.search(section(root_manifest, "workspace.package"))
    if not workspace_license:
        fail("root Cargo.toml [workspace.package] declares no license; the "
             "project license must be stated once there")
        return False
    if workspace_license.group("value") != PROJECT_LICENSE:
        fail(f"[workspace.package] license is {workspace_license.group('value')!r}, "
             f"expected {PROJECT_LICENSE!r} (the license of LICENSE and of "
             "every contribution); update this check in the same commit if "
             "the project license ever changes")
        return False

    members = workspace_member_names()
    if members is None:
        return False
    for directory in sorted(ROOT.glob("crates/*")):
        manifest_path = directory / "Cargo.toml"
        if not manifest_path.is_file():
            continue
        package_body = section(manifest_path.read_text(encoding="utf-8"), "package")
        name_match = _NAME_RE.search(package_body)
        name = name_match.group("value") if name_match else str(manifest_path)
        if _LICENSE_INHERIT_RE.search(package_body):
            continue
        own = _LICENSE_RE.search(package_body)
        if not own:
            fail(f"{name} ({manifest_path}) declares no license; set "
                 "`license.workspace = true` to inherit the project license")
            return False
        if own.group("value") != PROJECT_LICENSE:
            fail(f"{name} ({manifest_path}) licenses itself as "
                 f"{own.group('value')!r} instead of the project license "
                 f"{PROJECT_LICENSE!r}")
            return False
    return True


def lockfile_packages() -> list[str] | None:
    """Return every package name recorded in ``Cargo.lock``."""
    lock_body = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
    names = [match.group("value") for match in _NAME_RE.finditer(lock_body)]
    if not names:
        fail("Cargo.lock records no packages; run `cargo build` to generate it")
        return None
    return names


def check_third_party(member_names: list[str]) -> bool:
    """Verify every lockfile package outside the workspace is allowlisted."""
    members = set(member_names)
    packages = lockfile_packages()
    if packages is None:
        return False
    unreviewed = sorted({p for p in packages if p not in members})

    allowlist_body = section(
        ALLOWLIST_PATH.read_text(encoding="utf-8"), "approved"
    )
    reviewed = dict(
        (match.group("name"), match.group("spdx"))
        for match in _ALLOWLIST_ENTRY_RE.finditer(allowlist_body)
    )

    missing = [name for name in unreviewed if name not in reviewed]
    if missing:
        for name in missing:
            fail(f"third-party dependency {name!r} has no license review; "
                 f"record its SPDX identifier in {ALLOWLIST_PATH.relative_to(ROOT)} "
                 "in the same commit that adds the dependency")
        return False

    stale = sorted(set(reviewed) - set(unreviewed))
    if stale:
        for name in stale:
            fail(f"allowlist entry for {name!r} is stale (not in Cargo.lock); "
                 "remove it so the file stays an honest review record")
        return False

    print(f"license gate: {len(members)} workspace members under {PROJECT_LICENSE}, "
          f"{len(unreviewed)} third-party packages reviewed")
    for name in unreviewed:
        print(f"  {name} — {reviewed[name]}")
    return True


def main() -> int:
    if not check_workspace_license():
        return 2
    members = workspace_member_names()
    if members is None:
        return 2
    if not check_third_party(members):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
