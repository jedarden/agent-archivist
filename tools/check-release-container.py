#!/usr/bin/env python3
"""Release container baseline gate for Agent Archivist.

Validates ``containers/agent-archivist/VERSION`` and
``containers/agent-archivist/Dockerfile`` against the conventions in
``docs/notes/release-container.md``:

1. the version record grammar: one line, strict core SemVer ``X.Y.Z``, a
   single trailing newline (RC-004);
2. version equality: the ``VERSION`` file, the workspace
   ``[workspace.package] version``, and every member crate's inherited
   version are one fact (RC-005);
3. Dockerfile structure (RC-011 through RC-018): exactly two stages
   (``builder``, ``runtime``), every base digest-pinned with a
   version-exact tag, the builder tag matching the pinned
   ``rust-toolchain.toml`` channel, the runtime tag a pinned
   ``debian:<major.minor>-slim``, the exact
   ``cargo build --release --frozen --offline --bin archivist``
   invocation, ``COPY``-only file transfer (no ``ADD``, no
   ``COPY --from=builder`` — the known-broken crossing — no
   ``rust-toolchain.toml`` in the build context, no ``cargo install`` or
   ``rustup``), the release binary installed by exactly one ``RUN``
   bind-mounting it read-only from the builder stage, with the ``cp``
   destination equal to the exec-form ``ENTRYPOINT`` and the mtime pin
   covering the binary, its parent directory, ``/etc``, and ``/tmp``,
   package installs cleaned in the same ``RUN``, every ``RUN`` pinning
   its output mtimes to ``SOURCE_DATE_EPOCH`` (declared as a build
   argument in every stage that runs one), the
   ``AGENT_ARCHIVIST_VERSION`` label wiring, and a fixed numeric
   non-root final ``USER``;
4. the same-commit rule (RC-008 through RC-010): walking the commit
   history of both version records from the commit that introduced the
   ``VERSION`` file, no commit diverges and the file never disappears;
   and every ``vX.Y.Z`` release tag resolves to a commit whose ``VERSION``
   is exactly ``X.Y.Z`` (RC-006).

On success it prints a content-free summary and exits 0. Any failure
prints a report on stderr and exits 2.

``--self-test`` first validates the committed tree, then runs the tree
validators against mutated copies and the history and tag validators
against synthetic sequences, failing unless every bad sample is rejected
and every good sample accepted — proving the rejection paths (a version
record that moved alone, a floating base tag, a dropped build flag)
rather than only the accept path. When the ambient directory is a bare
tree with no repository history (a ``git archive`` extraction), the
ambient history/tag walk is skipped for the base case and those
validators are proven by the synthetic cases alone; plain check mode
still fails without a walkable HEAD.

Usage::

    tools/check-release-container.py [--self-test]

Standard-library only (``tomllib``), so a clean checkout runs it before
any dependency is fetched. Its output names paths, versions, digests, and
commit counts only.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_REL = "containers/agent-archivist/VERSION"
DOCKERFILE_REL = "containers/agent-archivist/Dockerfile"

# RC-004: strict core SemVer — three numeric components, no leading zeros,
# no pre-release or build metadata. Widening this grammar is a contract
# change that updates docs/notes/release-container.md in the same commit.
SEMVER_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
RELEASE_TAG_RE = re.compile(r"^v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$")

# RC-012/RC-013: the only permitted base images. The builder tag embeds the
# pinned toolchain channel (cross-checked against rust-toolchain.toml);
# the runtime tag pins both debian version components.
BUILDER_REPO = "rust"
BUILDER_TAG_SUFFIX = "-slim-bookworm"
RUNTIME_REPO = "debian"
RUNTIME_TAG_RE = re.compile(r"^[0-9]+\.[0-9]+-slim$")

# RC-014: the one compilation command the build stage may run. The binary
# name is pinned by archivist-cli's [[bin]] table.
BIN_NAME = "archivist"
BUILD_FLAGS = ("--release", "--frozen", "--offline")

IMAGE_REF_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9./_-]*)"
    r"(?::(?P<tag>[^\s@]+))?"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?$"
)
# Matches the FROM *value* (keyword already stripped by directives()).
FROM_RE = re.compile(r"^(\S+)(?:\s+[Aa][Ss]\s+([A-Za-z0-9_.-]+))?\s*$")

# A tree snapshot: every validator below is a pure function of this state,
# so --self-test can mutate it without touching the working tree.
#
#   version_text     raw VERSION file content (None: file absent)
#   cargo_version    [workspace.package] version (None: unreadable)
#   member_versions  crate name -> declared [package] version (None: inherits)
#   toolchain        rust-toolchain.toml channel (None: unreadable)
#   dockerfile       raw Dockerfile text (None: file absent)
#   history          oldest-first (commit, cargo version, VERSION content)
#   tags             (tag, VERSION content at the tagged commit or None)
TREE_KEYS = ("version_text", "cargo_version", "member_versions", "toolchain",
             "dockerfile")

# Appended by load_state() when the ambient directory is a bare tree (for
# example a `git archive` extraction) rather than a repository. Plain check
# mode fails on it; --self-test treats it as a property of the context and
# skips only the ambient history/tag walk, because the synthetic cases
# still prove those validators reject every bad sample.
NO_HISTORY_ERROR = ("history check: no committed HEAD to walk (the "
                    "same-commit rule needs at least the introduction "
                    "commit)")


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)


# ---------------------------------------------------------------- tree

def validate_version_record(state: dict) -> list[str]:
    """RC-004 and RC-005: grammar, then equality across the three records."""
    violations: list[str] = []
    text = state["version_text"]

    version = None
    if text is None:
        violations.append("RC-004: containers/agent-archivist/VERSION is missing")
    elif not text.endswith("\n") or "\n" in text[:-1] or "\r" in text:
        violations.append(
            f"RC-004: VERSION must be exactly one line with one trailing "
            f"newline (found {text!r})")
    else:
        version = text[:-1]
        if not SEMVER_RE.match(version):
            violations.append(
                f"RC-004: VERSION {version!r} is not strict core SemVer "
                f"(X.Y.Z, ASCII digits, no leading zeros, no pre-release)")

    cargo = state["cargo_version"]
    if cargo is None:
        violations.append("RC-005: the workspace Cargo.toml carries no "
                          "[workspace.package] version to compare against")
    elif not SEMVER_RE.match(cargo):
        violations.append(f"RC-005: workspace version {cargo!r} is not "
                          "strict core SemVer")
    elif version is not None and cargo != version:
        violations.append(
            f"RC-005: the version records diverge — Cargo.toml says {cargo!r}, "
            f"VERSION says {version!r}; they must move in the same commit")

    for crate, declared in sorted(state["member_versions"].items()):
        # `version.workspace = true` parses as {"workspace": True} — the
        # sanctioned inheritance form. Only a string literal is a pin.
        if isinstance(declared, str):
            violations.append(
                f"RC-005: member crate {crate} pins its own [package] "
                f"version {declared!r}; member crates must inherit "
                f"version.workspace = true")
    return violations


def logical_lines(text: str) -> list[str]:
    """Dockerfile directives as logical lines: continuations joined,
    full-line comments and blanks dropped."""
    joined: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if buf:
            line = buf + " " + line.lstrip()
            buf = ""
        if line.rstrip().endswith("\\"):
            buf = line.rstrip()[:-1].rstrip()
            continue
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            joined.append(line.rstrip())
    if buf:
        joined.append(buf)
    return joined


def directives(lines: list[str]) -> list[tuple[str, str]]:
    """(keyword, value) pairs; keywords upper-cased, values verbatim."""
    out: list[tuple[str, str]] = []
    for line in lines:
        parts = line.split(None, 1)
        out.append((parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return out


def validate_dockerfile(state: dict) -> list[str]:
    """RC-011 through RC-017: structural reproducibility rules."""
    violations: list[str] = []
    text = state["dockerfile"]
    if text is None:
        return [f"RC-001: {DOCKERFILE_REL} is missing"]
    dirs = directives(logical_lines(text))
    values = {kw: [v for k, v in dirs if k == kw] for kw in
              ("FROM", "ARG", "LABEL", "RUN", "COPY", "ADD", "USER",
               "ENTRYPOINT")}

    # RC-017: exactly two named stages.
    stages = []
    for value in values["FROM"]:
        m = FROM_RE.match(value)
        if m is None:
            violations.append(f"RC-011: unparsable FROM reference {value!r}")
            continue
        stages.append((m.group(1), m.group(2)))
    if len(stages) != 2:
        violations.append(f"RC-017: the image must have exactly two stages, "
                          f"found {len(stages)}")
    if [s[1] for s in stages] != ["builder", "runtime"]:
        violations.append("RC-017: the two stages must be named builder and "
                          "runtime, in that order")

    for ref, _stage in stages:
        m = IMAGE_REF_RE.match(ref)
        if m is None:
            violations.append(f"RC-011: unparsable base reference {ref!r}")
            continue
        if m.group("tag") is None:
            violations.append(f"RC-011: base {ref!r} carries no tag")
        elif m.group("tag").lower() == "latest":
            violations.append(f"RC-011: base {ref!r} uses a mutable "
                              "convenience tag")
        if m.group("digest") is None:
            violations.append(f"RC-011: base {ref!r} is not digest-pinned "
                              "(name:tag@sha256:<64 hex>)")

    # RC-012: the builder tag embeds the pinned toolchain channel.
    channel = state["toolchain"]
    if channel is None:
        violations.append("RC-012: rust-toolchain.toml carries no pinned "
                          "channel to cross-check the builder tag against")
    elif stages and stages[0][1] == "builder":
        m = IMAGE_REF_RE.match(stages[0][0])
        expected_tag = f"{channel}{BUILDER_TAG_SUFFIX}"
        if m and (m.group("name") != BUILDER_REPO or m.group("tag") != expected_tag):
            violations.append(
                f"RC-012: the builder base must be {BUILDER_REPO}:{expected_tag}"
                f"@sha256:… to match the pinned toolchain, found "
                f"{stages[0][0]!r}")

    # RC-013: the runtime base pins both debian version components.
    if len(stages) == 2 and stages[1][1] == "runtime":
        m = IMAGE_REF_RE.match(stages[1][0])
        if m and (m.group("name") != RUNTIME_REPO
                  or not RUNTIME_TAG_RE.match(m.group("tag") or "")):
            violations.append(
                f"RC-013: the runtime base must be {RUNTIME_REPO}:"
                f"<major.minor>-slim with both components pinned, found "
                f"{stages[1][0]!r}")

    # RC-014: exactly the sanctioned compilation command, and nothing that
    # fetches a toolchain or crate at build time.
    builds = [v for v in values["RUN"] if "cargo build" in v]
    if len(builds) != 1:
        violations.append(f"RC-014: the build stage must run exactly one "
                          f"'cargo build' invocation, found {len(builds)}")
    for build in builds:
        tokens = build.split()
        for flag in BUILD_FLAGS:
            if flag not in tokens:
                violations.append(f"RC-014: the cargo build invocation is "
                                  f"missing {flag} (found {build.strip()!r})")
        if tokens[:1] == ["cargo"] and "--bin" in tokens:
            name = tokens[tokens.index("--bin") + 1] if tokens[-1] != "--bin" else ""
            if name != BIN_NAME:
                violations.append(f"RC-014: the build must produce the "
                                  f"{BIN_NAME!r} binary, found --bin {name!r}")
        else:
            violations.append(f"RC-014: the build invocation must select "
                              f"--bin {BIN_NAME} (found {build.strip()!r})")
    for kw in ("RUN", "ENV", "ARG", "LABEL"):
        for value in values.get(kw, []):
            if "cargo install" in value or "rustup" in value:
                violations.append(f"RC-014: {kw} must not fetch toolchains "
                                  f"or crates ({value.strip()!r})")

    # RC-015: COPY is the only file-transfer directive; the context is the
    # repository paths COPY names, and never the toolchain pin.
    if values["ADD"]:
        violations.append("RC-015: ADD must not appear; COPY is the only "
                          "file-transfer directive")
    for value in values["COPY"]:
        if "rust-toolchain.toml" in value:
            violations.append(
                "RC-012/RC-015: rust-toolchain.toml must not enter the "
                "build — the builder image is the toolchain pin, and "
                "copying the file invites a rustup download")

    # RC-017: package installs clean up in the same RUN.
    for value in values["RUN"]:
        if "apt-get" in value and "rm -rf /var/lib/apt/lists" not in value:
            violations.append("RC-017: a package-install RUN must remove "
                              "/var/lib/apt/lists in the same RUN")

    # RC-018: every RUN pins the mtimes of what it produces to
    # SOURCE_DATE_EPOCH, so layer digests are functions of content, not of
    # when the build ran — and every stage that runs one declares the
    # argument (build args do not cross stages).
    for value in values["RUN"]:
        if "SOURCE_DATE_EPOCH" not in value:
            violations.append("RC-018: every RUN must normalize the mtimes "
                              "of the files it creates or modifies to "
                              "SOURCE_DATE_EPOCH")
    stage_args: dict[str, set[str]] = {}
    stage_runs: dict[str, int] = {}
    current: str | None = None
    for kw, value in dirs:
        if kw == "FROM":
            m = FROM_RE.match(value)
            current = m.group(2) if m else None
        elif current is not None:
            if kw == "ARG":
                stage_args.setdefault(current, set()).add(
                    value.split()[0] if value.split() else "")
            elif kw == "RUN":
                stage_runs[current] = stage_runs.get(current, 0) + 1
    for stage, count in sorted(stage_runs.items()):
        if "SOURCE_DATE_EPOCH" not in stage_args.get(stage, set()):
            violations.append(f"RC-018: stage {stage} runs {count} RUN "
                              f"step(s) but does not declare "
                              f"ARG SOURCE_DATE_EPOCH for the mtime pin")

    # RC-016: the version label is injected from the VERSION file content
    # through exactly one build argument.
    if "AGENT_ARCHIVIST_VERSION" not in [v.split()[0] if v.split() else ""
                                         for v in values["ARG"]]:
        violations.append("RC-016: the final stage must declare "
                          "ARG AGENT_ARCHIVIST_VERSION")
    label_ok = any("org.opencontainers.image.version" in v
                   and "${AGENT_ARCHIVIST_VERSION}" in v
                   for v in values["LABEL"])
    if not label_ok:
        violations.append("RC-016: org.opencontainers.image.version must "
                          "reference ${AGENT_ARCHIVIST_VERSION}")

    # RC-017: fixed numeric non-root final user, exec-form entrypoint naming
    # the installed binary.
    user = values["USER"][-1].strip() if values["USER"] else ""
    if not user:
        violations.append("RC-017: the final stage must set USER")
    elif not re.match(r"^[1-9][0-9]*(:[1-9][0-9]*)?$", user):
        violations.append(f"RC-017: USER must be a fixed numeric non-root "
                          f"UID[:GID] (no /etc mutation), found {user!r}")
    entry = values["ENTRYPOINT"][-1].strip() if values["ENTRYPOINT"] else ""
    entry_path = None
    if not entry:
        violations.append("RC-017: the final stage must declare an "
                          "exec-form ENTRYPOINT")
    elif not (entry.startswith("[") and entry.endswith("]")):
        violations.append(f"RC-017: ENTRYPOINT must be exec-form, found "
                          f"{entry!r}")
    else:
        try:
            parsed = json.loads(entry)
            if isinstance(parsed, list) and len(parsed) == 1 \
                    and isinstance(parsed[0], str):
                entry_path = parsed[0]
            else:
                violations.append("RC-017: ENTRYPOINT must name exactly one "
                                  "executable path")
        except ValueError:
            violations.append(f"RC-017: ENTRYPOINT is not valid JSON: {entry!r}")

    # RC-015: the binary must not cross stages by COPY — a COPY layer
    # records the destination directory's wall-clock mtime, so two builds
    # of identical content ship two digests (proven by experiment; see
    # docs/notes/release-container.md RC-015).
    for value in values["COPY"]:
        if value.split()[:1] == ["--from=builder"]:
            violations.append(
                "RC-015: COPY --from=builder cannot produce a reproducible "
                "layer (the destination directory's mtime lands in the "
                "layer tar as wall-clock); the binary crosses stages via "
                "the install RUN's read-only bind mount")

    # RC-017: the install RUN — exactly one RUN bind-mounts the builder's
    # release binary read-only and cp's it to its destination.
    installs = [v for v in values["RUN"]
                if "--mount=type=bind,from=builder" in v]
    if len(installs) != 1:
        violations.append(f"RC-017: the runtime stage must install the "
                          f"release binary in exactly one RUN bind-mounting "
                          f"it read-only from the builder stage, found "
                          f"{len(installs)}")
        return violations
    install = installs[0]
    mount = re.search(r"--mount=(\S+)", install)
    if mount is None or ",ro" not in mount.group(1):
        violations.append("RC-015: the install RUN's bind mount must be "
                          "read-only (ro)")
    cp = re.search(r"\bcp\s+(\S+)\s+(\S+)", install)
    if cp is None:
        violations.append("RC-017: the install RUN must cp the mounted "
                          "binary to its destination")
        return violations
    if entry_path is not None and cp.group(2) != entry_path:
        violations.append(
            f"RC-017: ENTRYPOINT {entry_path!r} does not name the "
            f"installed binary destination {cp.group(2)!r}")

    # RC-018: the install RUN's pin set — the cp destination, its parent
    # directory, /etc, and /tmp (the mount creates its target under /tmp
    # and stamps /etc; every one of them lands in the layer diff).
    touch = re.search(
        r'touch\s+--date="@\$\{SOURCE_DATE_EPOCH[^}]*\}"\s+(.+)$', install)
    if touch is None:
        violations.append("RC-018: the install RUN must pin mtimes with "
                          'touch --date="@${SOURCE_DATE_EPOCH…}" covering '
                          "the binary, its parent directory, /etc, and /tmp")
    else:
        pinned = set(touch.group(1).split())
        parent = cp.group(2).rsplit("/", 1)[0] or "/"
        for required in (cp.group(2), parent, "/etc", "/tmp"):
            if required not in pinned:
                violations.append(
                    f"RC-018: the install RUN's mtime pin must cover "
                    f"{required!r} — the cp destination, its parent "
                    f"directory, and the two directories the mount "
                    f"machinery stamps")
    return violations


# ------------------------------------------------------------- history

def validate_history(entries: list[tuple[str, str | None, str | None]]) -> list[str]:
    """RC-008 through RC-010 over oldest-first (commit, cargo, VERSION)."""
    violations: list[str] = []
    introduced = next((i for i, e in enumerate(entries) if e[2] is not None), None)
    if introduced is None:
        return ["RC-008: the VERSION record has never been committed; the "
                "version contract starts at its introduction commit"]

    commit, cargo, version = entries[introduced]
    if cargo != version:
        violations.append(
            f"RC-005/RC-008: the introduction commit {commit[:12]} carries "
            f"Cargo.toml {cargo!r} against VERSION {version!r}")

    for i in range(introduced + 1, len(entries)):
        commit, cargo, version = entries[i]
        _, prev_cargo, prev_version = entries[i - 1]
        if version is None:
            violations.append(
                f"RC-009: the VERSION record disappears at commit "
                f"{commit[:12]}")
            continue
        if cargo != version:
            if cargo != prev_cargo and version == prev_version:
                detail = "the workspace version moved without VERSION"
            elif version != prev_version and cargo == prev_cargo:
                detail = "VERSION moved without the workspace version"
            else:
                detail = "the two version records diverged"
            violations.append(
                f"RC-008: {detail} at commit {commit[:12]} "
                f"({cargo!r} vs {version!r}) — both records must move in "
                f"the same commit")
    return violations


def validate_tags(tags: list[tuple[str, str | None]]) -> list[str]:
    """RC-006: every vX.Y.Z tag matches the VERSION content at its commit."""
    violations: list[str] = []
    for tag, version_at in tags:
        m = RELEASE_TAG_RE.match(tag)
        if m is None:
            continue
        if version_at is None:
            violations.append(
                f"RC-006: release tag {tag} points at a commit without a "
                f"VERSION record")
        elif version_at != m.group(1):
            violations.append(
                f"RC-006: release tag {tag} does not match VERSION "
                f"{version_at!r} at its commit")
    return violations


def validate_tree(state: dict) -> list[str]:
    return validate_version_record(state) + validate_dockerfile(state)


# -------------------------------------------------------------- loading

def run_git(args: list[str]) -> str | None:
    try:
        proc = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                              text=True, check=False)
    except OSError:
        return None
    return proc.stdout if proc.returncode == 0 else None


def git_version_at(rev: str, rel_path: str) -> str | None:
    """The SemVer recorded in a file at a commit, or None if absent."""
    blob = run_git(["show", f"{rev}:{rel_path}"])
    if blob is None:
        return None
    if rel_path == "Cargo.toml":
        try:
            cargo = tomllib.loads(blob)
            return cargo["workspace"]["package"]["version"]
        except (tomllib.TOMLDecodeError, KeyError, TypeError):
            return None
    match = SEMVER_RE.match(blob.strip())
    return match.group(0) if match else None


def load_state() -> tuple[dict, list[str]]:
    errors: list[str] = []
    state: dict = {key: None for key in TREE_KEYS}
    state["member_versions"] = {}

    version_path = ROOT / VERSION_REL
    if version_path.is_file():
        raw = version_path.read_bytes()
        try:
            state["version_text"] = raw.decode("ascii")
        except UnicodeDecodeError:
            errors.append("RC-004: VERSION is not ASCII")
    else:
        errors.append(f"RC-004: {VERSION_REL} is missing")

    try:
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
        state["cargo_version"] = cargo["workspace"]["package"]["version"]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError):
        errors.append("RC-005: the workspace Cargo.toml has no readable "
                      "[workspace.package] version")

    crates = ROOT / "crates"
    if crates.is_dir():
        for manifest in sorted(crates.glob("*/Cargo.toml")):
            try:
                package = tomllib.loads(manifest.read_text())["package"]
            except (OSError, tomllib.TOMLDecodeError, KeyError):
                errors.append(f"RC-005: unreadable member manifest "
                              f"{manifest.relative_to(ROOT)}")
                continue
            state["member_versions"][manifest.parent.name] = \
                package.get("version")

    try:
        state["toolchain"] = tomllib.loads(
            (ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError):
        errors.append("RC-012: rust-toolchain.toml has no pinned channel")

    dockerfile = ROOT / DOCKERFILE_REL
    if dockerfile.is_file():
        state["dockerfile"] = dockerfile.read_text()
    else:
        errors.append(f"RC-001: {DOCKERFILE_REL} is missing")

    state["history"] = []
    state["tags"] = []
    if run_git(["rev-parse", "--verify", "HEAD"]) is None:
        errors.append(NO_HISTORY_ERROR)
    else:
        hashes = run_git(["log", "--format=%H", "--", "Cargo.toml",
                          VERSION_REL]) or ""
        for commit in reversed(hashes.splitlines()):
            state["history"].append(
                (commit, git_version_at(commit, "Cargo.toml"),
                 git_version_at(commit, VERSION_REL)))
        for tag in (run_git(["tag", "--list", "v*"]) or "").splitlines():
            state["tags"].append((tag, git_version_at(tag, VERSION_REL)))
    return state, errors


# ------------------------------------------------------------ self-test

def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise AssertionError(f"self-test mutation anchor is not unique: {old!r}")
    return text.replace(old, new)


def mutate(state: dict, **changes: object) -> dict:
    mutated = copy.deepcopy(state)
    mutated.update(changes)
    return mutated


def with_dockerfile(state: dict, old: str, new: str) -> dict:
    return mutate(state, dockerfile=replace_once(state["dockerfile"], old, new))


TREE_CASES: list[tuple[str, bool, dict]] = []
HISTORY_CASES: list[tuple[str, bool, list]] = []
TAG_CASES: list[tuple[str, bool, list]] = []


def build_cases(state: dict) -> None:
    """Mutation cases over the committed tree, mirroring the other gates."""
    digest = "@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3"
    runtime_ref = "debian:12.15-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
    install_run = (
        "RUN --mount=type=bind,from=builder,"
        "source=/build/target/release/archivist,ro,target=/tmp/archivist \\\n"
        "    cp /tmp/archivist /usr/local/bin/archivist \\\n"
        " && chmod 0555 /usr/local/bin/archivist \\\n"
        " && touch --date=\"@${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must "
        "be set}\" \\\n"
        "      /usr/local/bin/archivist /usr/local/bin /etc /tmp")
    cases = [
        ("the committed tree (unmutated)", False, dict(state)),
        ("VERSION file removed",
         True, mutate(state, version_text=None)),
        ("VERSION carries a pre-release suffix",
         True, mutate(state, version_text="0.1.0-rc.1\n")),
        ("VERSION component has a leading zero",
         True, mutate(state, version_text="0.01.0\n")),
        ("VERSION lost its trailing newline",
         True, mutate(state, version_text="0.1.0")),
        ("VERSION is a second line of commentary",
         True, mutate(state, version_text="0.1.0\n0.1.0\n")),
        ("VERSION moved without the workspace version",
         True, mutate(state, version_text="0.2.0\n")),
        ("the workspace version moved without VERSION",
         True, mutate(state, cargo_version="0.2.0")),
        ("a member crate pins its own version",
         True, mutate(state, member_versions={
             **state["member_versions"], "archivist-protocol": "0.1.0"})),
        ("the builder base lost its digest pin",
         True, with_dockerfile(state, digest, "")),
        ("the runtime base tag is a floating suite alias",
         True, with_dockerfile(state, runtime_ref,
                               "debian:bookworm-slim@sha256:88200866dfff7ea7"
                               "f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07"
                               "ea4171")),
        ("the builder tag lags the pinned toolchain",
         True, with_dockerfile(state, "rust:1.97.1-slim-bookworm",
                               "rust:1.97.0-slim-bookworm")),
        ("the build dropped --offline",
         True, with_dockerfile(state,
                               "cargo build --release --frozen --offline "
                               "--bin archivist",
                               "cargo build --release --frozen "
                               "--bin archivist")),
        ("the build dropped --frozen",
         True, with_dockerfile(state,
                               "cargo build --release --frozen --offline "
                               "--bin archivist",
                               "cargo build --release --offline "
                               "--bin archivist")),
        ("the build selects the wrong binary",
         True, with_dockerfile(state, "--bin archivist", "--bin other")),
        ("the Dockerfile uses ADD instead of COPY",
         True, with_dockerfile(state, "COPY crates ./crates",
                               "ADD crates ./crates")),
        ("the toolchain pin leaked into the build context",
         True, with_dockerfile(state, "COPY Cargo.toml Cargo.lock ./",
                               "COPY Cargo.toml Cargo.lock "
                               "rust-toolchain.toml ./")),
        ("a stage installs a package without cleaning lists",
         True, with_dockerfile(state,
                               " AS runtime\n",
                               " AS runtime\nRUN apt-get update && "
                               "apt-get install -y curl\n")),
        ("the install RUN skipped the mtime pin",
         True, with_dockerfile(state,
                               '--date="@${SOURCE_DATE_EPOCH:?SOURCE_DATE'
                               '_EPOCH must be set}" \\\n'
                               '      /usr/local/bin/archivist'
                               ' /usr/local/bin /etc /tmp',
                               '--date="@0" \\\n'
                               '      /usr/local/bin/archivist'
                               ' /usr/local/bin /etc /tmp')),
        ("the install RUN's pin set lost /tmp",
         True, with_dockerfile(state,
                               " /usr/local/bin/archivist /usr/local/bin"
                               " /etc /tmp",
                               " /usr/local/bin/archivist /usr/local/bin"
                               " /etc")),
        ("the install RUN's pin set lost the parent directory",
         True, with_dockerfile(state,
                               " /usr/local/bin/archivist /usr/local/bin"
                               " /etc /tmp",
                               " /usr/local/bin/archivist /etc /tmp")),
        ("the mtime build argument was dropped from the runtime stage",
         True, with_dockerfile(state,
                               "ARG AGENT_ARCHIVIST_VERSION\n"
                               "ARG SOURCE_DATE_EPOCH\n",
                               "ARG AGENT_ARCHIVIST_VERSION\n")),
        ("the version build argument was dropped",
         True, with_dockerfile(state, "ARG AGENT_ARCHIVIST_VERSION\n", "")),
        ("the version label stopped referencing the build argument",
         True, with_dockerfile(state,
                               'org.opencontainers.image.version='
                               '"${AGENT_ARCHIVIST_VERSION}"',
                               'org.opencontainers.image.version="0.1.0"')),
        ("the final stage runs as root",
         True, with_dockerfile(state, "USER 65532:65532", "USER root")),
        ("USER is a name instead of a fixed numeric UID",
         True, with_dockerfile(state, "USER 65532:65532", "USER archivist")),
        ("the final stage lost its USER",
         True, with_dockerfile(state, "USER 65532:65532\n", "")),
        ("ENTRYPOINT is shell-form",
         True, with_dockerfile(state,
                               'ENTRYPOINT ["/usr/local/bin/archivist"]',
                               "ENTRYPOINT /usr/local/bin/archivist")),
        ("ENTRYPOINT diverges from the installed binary path",
         True, with_dockerfile(state,
                               'ENTRYPOINT ["/usr/local/bin/archivist"]',
                               'ENTRYPOINT ["/usr/bin/archivist"]')),
        ("the binary was COPYied from the builder stage",
         True, with_dockerfile(state, install_run,
                               "COPY --from=builder /build/target/release/"
                               "archivist /usr/local/bin/archivist")),
        ("the runtime stage lost its install RUN",
         True, with_dockerfile(state, install_run, "RUN true")),
        ("the install mount lost its read-only flag",
         True, with_dockerfile(state, ",ro,target=/tmp/archivist",
                               ",target=/tmp/archivist")),
        ("a third stage appeared",
         True, with_dockerfile(state,
                               "USER 65532:65532\n",
                               "USER 65532:65532\nFROM " + runtime_ref +
                               " AS extra\nUSER 65532:65532\n")),
        ("the stages were renamed",
         True, with_dockerfile(state, " AS builder", " AS build")),
    ]
    TREE_CASES.extend(cases)

    HISTORY_CASES.extend([
        ("introduction then a paired bump", False, [
            ("aaaa00000000", "0.1.0", None),
            ("aaaa00000001", "0.1.0", "0.1.0"),
            ("aaaa00000002", "0.2.0", "0.2.0"),
            ("aaaa00000003", "0.3.0", "0.3.0")]),
        ("introduction alone", False, [
            ("aaaa00000000", "0.1.0", None),
            ("aaaa00000001", "0.1.0", "0.1.0")]),
        ("VERSION was never committed", True, [
            ("aaaa00000000", "0.1.0", None)]),
        ("the workspace version moved without VERSION", True, [
            ("aaaa00000000", "0.1.0", "0.1.0"),
            ("aaaa00000001", "0.2.0", "0.1.0")]),
        ("VERSION moved without the workspace version", True, [
            ("aaaa00000000", "0.1.0", "0.1.0"),
            ("aaaa00000001", "0.1.0", "0.2.0")]),
        ("both moved to different versions", True, [
            ("aaaa00000000", "0.1.0", "0.1.0"),
            ("aaaa00000001", "0.2.0", "0.3.0")]),
        ("VERSION disappeared after its introduction", True, [
            ("aaaa00000000", "0.1.0", None),
            ("aaaa00000001", "0.1.0", "0.1.0"),
            ("aaaa00000002", "0.2.0", None)]),
        ("the introduction commit itself diverged", True, [
            ("aaaa00000000", "0.1.0", None),
            ("aaaa00000001", "0.1.0", "0.2.0")]),
        ("a divergence followed by repair", True, [
            ("aaaa00000000", "0.1.0", "0.1.0"),
            ("aaaa00000001", "0.2.0", "0.1.0"),
            ("aaaa00000002", "0.2.0", "0.2.0")]),
    ])

    TAG_CASES.extend([
        ("a release tag matches its VERSION content", False, [
            ("v0.1.0", "0.1.0")]),
        ("a release tag names a different version", True, [
            ("v0.2.0", "0.1.0")]),
        ("a release tag points before VERSION existed", True, [
            ("v0.1.0", None)]),
        ("a non-release tag is out of scope", False, [
            ("notes-2026", None)]),
    ])


def run_self_test() -> int:
    state, errors = load_state()
    # A bare tree (a `git archive` extraction) has no history to walk:
    # a property of the context, not of the tree. Skip only the ambient
    # history/tag walk for the base case; the synthetic cases below still
    # prove those validators reject every bad sample.
    unwalked = NO_HISTORY_ERROR in errors
    errors = [error for error in errors if error != NO_HISTORY_ERROR]
    if errors:
        for error in errors:
            fail(f"self-test base: {error}")
        return 2
    if unwalked:
        print("  note: no repository history in this context; the ambient "
              "history/tag base check is skipped (synthetic cases still "
              "prove the rules)")
    violations = validate_tree(state)
    if not unwalked:
        violations += validate_history(state["history"])
        violations += validate_tags(state["tags"])
    if violations:
        fail("self-test base: the committed tree itself is invalid:")
        for violation in violations:
            fail(f"  {violation}")
        return 2

    build_cases(state)
    passed = 0
    failed = 0

    def report(label: str, must_reject: bool, violations: list[str]) -> None:
        nonlocal passed, failed
        rejected = bool(violations)
        if rejected == must_reject:
            passed += 1
            print(f"  ok  {'rejects' if rejected else 'accepts'}: {label}")
        else:
            failed += 1
            print(f"  FAIL should "
                  f"{'reject' if must_reject else 'accept'}: {label}")
            for violation in violations:
                print(f"       violation: {violation}")

    for label, must_reject, mutated in TREE_CASES:
        report(label, must_reject, validate_tree(mutated))
    for label, must_reject, entries in HISTORY_CASES:
        report(label, must_reject, validate_history(entries))
    for label, must_reject, tags in TAG_CASES:
        report(label, must_reject, validate_tags(tags))

    print(f"self-test: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 2


def main(argv: list[str]) -> int:
    if "--self-test" in argv[1:]:
        return run_self_test()
    if argv[1:]:
        fail(f"unknown arguments: {' '.join(argv[1:])}")
        return 2

    state, errors = load_state()
    violations = (errors + validate_tree(state)
                  + validate_history(state["history"])
                  + validate_tags(state["tags"]))
    for violation in violations:
        fail(violation)
    if violations:
        return 2

    version = state["version_text"] and state["version_text"].strip()
    print("agent-archivist release container baseline")
    print(f"version: {version} (VERSION == Cargo.toml workspace == "
          f"{len(state['member_versions'])} inheriting member crates)")
    dirs = directives(logical_lines(state["dockerfile"] or ""))
    for _, value in (d for d in dirs if d[0] == "FROM"):
        ref = value.split()[0]
        digest_at = ref.find("@sha256:")
        if digest_at != -1:
            ref = f"{ref[:digest_at + 15]}…{ref[-4:]}"
        print(f"base: {ref}")
    user = next((v for k, v in reversed(dirs) if k == "USER"), "?")
    entrypoint = next((v for k, v in reversed(dirs) if k == "ENTRYPOINT"), "?")
    print(f"entrypoint: {entrypoint} as user '{user.split()[0]}'")
    history = state["history"]
    introduced = next(i for i, e in enumerate(history) if e[2] is not None)
    print(f"history: {len(history) - introduced} commits carry the version "
          f"records since introduction {history[introduced][0][:12]}; "
          f"no divergence")
    print(f"release tags checked: {len(state['tags'])}")
    print("OK: baseline satisfies docs/notes/release-container.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
