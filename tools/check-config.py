#!/usr/bin/env python3
"""Configuration-key registry gate for Agent Archivist.

Validates ``tools/config-keys.toml`` against the conventions in
``docs/notes/configuration.md``, then scans the committed tree:

1. the registry declares schema ``archivist.config-registry/v1`` and nothing
   else at the top level;
2. key names are two lowercase dot-separated segments; derived environment
   names (``ARCHIVIST_*``) and flag names are unique across the registry, so
   the derivation is injective by construction;
3. every key is owned by a workspace crate, carries a closed type, a
   non-empty tier list that includes the file tier, and a bounded
   description and example; exactly one of a default or ``required`` is
   declared;
4. integer keys carry a unit suffix (``_bytes``, ``_seconds``,
   ``_percent``, ``_count``, ``_ratio``) and defaults/examples respect the
   suffix bounds — there are no float values anywhere;
5. secrets are exactly the conjunction of type ``reference``, a ``_ref``
   name suffix, and ``secret = true``; secret keys never expose a flag
   tier; reference values match the closed ``file:``/``env:`` grammar
   (literal absolute paths; environment targets outside the reserved
   ``ARCHIVIST_`` namespace);
6. the working-tree scan rejects any configuration-bearing committed file
   (TOML, YAML, env/INI shapes, and documentation) that assigns a literal
   value to a ``*_ref`` setting — examples and fixtures carry references,
   never secret values (CFG-032, SEC-006, SEC-010).

On success it prints a summary and exits 0. Any failure prints a report on
stderr and exits 2. Scan findings name the file, line, and key only; the
matched value is never reproduced.

``--self-test`` runs the same validators against mutated copies of the
committed registry (proving every rejection path above) and against sandbox
files carrying literal and well-formed ``*_ref`` assignments. The base
registry and the committed tree must both be clean.

Usage::

    tools/check-config.py [--self-test]

Standard-library only (``tomllib``), so a clean checkout runs it before any
dependency is fetched.
"""

from __future__ import annotations

import os
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = Path("tools/config-keys.toml")

REGISTRY_SCHEMA = "archivist.config-registry/v1"

# The closed v1 type set (docs/notes/configuration.md CFG-014).
TYPES = frozenset({"boolean", "integer", "string", "path", "enum", "reference"})

# Workspace crates (docs/notes/crate-ownership.md). A key's owner must be a
# public crate; a new crate extends this set in the same commit as its keys.
CRATES = frozenset({
    "archivist-protocol", "archivist-auth", "archivist-storage",
    "archivist-adapter-sdk", "archivist-storage-s3", "archivist-client-core",
    "archivist-adapter-claude", "archivist-adapter-codex",
    "archivist-adapter-opencode", "archivist-adapter-pi", "archivist-server",
    "archivist-cli",
})

TIERS = ("flag", "env", "file")

# The frozen integer unit-suffix contract (CFG-015). Every integer key name
# ends in one of these; the suffix fixes the value bounds.
INT_SUFFIX_BOUNDS: dict[str, tuple[int, int]] = {
    "bytes": (1, 2**48),
    "seconds": (1, 31_536_000),
    "percent": (0, 100),
    "count": (0, 2**31 - 1),
    "ratio": (1, 10_000),
}

KEY_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}\.[a-z][a-z0-9_]{0,63}$")
ENUM_VALUE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
ENV_TARGET_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
# Printable ASCII without braces, quotes already excluded by TOML quoting.
STRING_RE = re.compile(r"^[ -~]+$")

# Path values: an optional leading XDG/HOME template variable, then absolute
# POSIX segments of a bounded charset with no `.`/`..` segment (CFG-018).
PATH_TEMPLATE_VARS = (
    "${XDG_CONFIG_HOME}", "${XDG_STATE_HOME}", "${XDG_DATA_HOME}",
    "${XDG_CACHE_HOME}", "${HOME}",
)
PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._+-]*$")
REF_PATH_MAX = 4096
STRING_MAX = 128
PROSE_MAX = 200

KEYS_REQUIRED = frozenset({"owner", "type", "tiers", "secret", "description",
                           "example"})
KEYS_OPTIONAL = frozenset({"default", "required", "values", "deprecated"})

# --- working-tree scan (CFG-032) ---------------------------------------------
#
# Any assignment to a *_ref setting (TOML/YAML/JSON/env shapes, case-
# insensitive to cover environment names) whose value is not a well-formed
# reference is a violation. Findings name file, line, and key only.

ASSIGN_RE = re.compile(
    r"(?P<key>[A-Za-z0-9_.-]+_ref)[\"']?\s*[=:]\s*[\"']?"
    r"(?P<val>[^\"'\r\n#]*)",
    re.IGNORECASE,
)

# Configuration-bearing files: the TOML config itself, YAML/INI/env shapes a
# deployment or example might use, and the documentation that shows them.
# Data interchange (JSON/JSONL/TXT) is deliberately out of scope — `_ref`
# fields there are ordinary cross-references (the bead store's own metadata,
# for example), and secret-shaped content in data files is the gitleaks
# lanes' jurisdiction, not this grammar check.
SCAN_EXTENSIONS = frozenset({
    ".toml", ".yaml", ".yml", ".md", ".example", ".env", ".cfg", ".ini",
    ".conf",
})
PRUNE_DIRS = frozenset({".git", "target", "__pycache__"})


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def prose_errors(value: object, what: str) -> list[str]:
    """Bound and charset-check a descriptive string (no braces, one line)."""
    if not isinstance(value, str):
        return [f"{what} must be a string"]
    errors: list[str] = []
    if STRING_RE.match(value) is None or "{" in value or "}" in value:
        errors.append(f"{what} contains a brace or non-printable-ASCII "
                      "character")
    if len(value) > PROSE_MAX:
        errors.append(f"{what} exceeds the {PROSE_MAX}-character bound")
    return errors


def string_errors(value: object, what: str) -> list[str]:
    """Validate a bounded string value (CFG-016)."""
    if not isinstance(value, str):
        return [f"{what} must be a string"]
    errors: list[str] = []
    if STRING_RE.match(value) is None or "{" in value or "}" in value:
        errors.append(f"{what} contains a brace or non-printable-ASCII "
                      "character")
    if len(value) > STRING_MAX:
        errors.append(f"{what} exceeds the {STRING_MAX}-character bound")
    return errors


def path_suffix_errors(value: str, what: str) -> list[str]:
    """Validate the absolute suffix of a path or file reference (CFG-018)."""
    if len(value) > REF_PATH_MAX:
        return [f"{what} exceeds the {REF_PATH_MAX}-character bound"]
    segments = value.split("/")
    if any(seg not in ("",) and PATH_SEGMENT_RE.match(seg) is None
           for seg in segments):
        return [f"{what} contains a character outside [A-Za-z0-9._+-] or a "
                "tilde"]
    if any(seg in (".", "..") for seg in segments):
        return [f"{what} contains a '.' or '..' segment"]
    return []


def path_errors(value: object, what: str) -> list[str]:
    """Validate a path value: literal absolute, or XDG/HOME + suffix."""
    if not isinstance(value, str):
        return [f"{what} must be a string"]
    for var in PATH_TEMPLATE_VARS:
        if value.startswith(var):
            return path_suffix_errors(value[len(var):], what)
    if not value.startswith("/"):
        return [f"{what} is not an absolute path or a leading XDG/HOME "
                "template"]
    return path_suffix_errors(value, what)


def reference_errors(value: object, what: str) -> list[str]:
    """Validate a secret reference against the closed grammar (CFG-029)."""
    if not isinstance(value, str):
        return [f"{what} must be a string"]
    if value.startswith("file:"):
        target = value[len("file:"):]
        if not target.startswith("/"):
            return [f"{what} is a file reference without an absolute path"]
        errors = path_suffix_errors(target, what)
        if "${" in target:
            errors.append(f"{what} is a file reference containing a template "
                          "variable; references are literal")
        return errors
    if value.startswith("env:"):
        target = value[len("env:"):]
        if ENV_TARGET_RE.match(target) is None:
            return [f"{what} is an env reference whose target is not "
                    "[A-Z][A-Z0-9_]{0,63}"]
        if target.startswith("ARCHIVIST_"):
            return [f"{what} targets the reserved ARCHIVIST_ namespace; "
                    "secrets never ride the configuration environment tier"]
        return []
    return [f"{what} is not a file: or env: reference"]


def int_bounds(name: str) -> tuple[int, int] | None:
    """The bounds a key's unit suffix fixes, or None if there is none."""
    for suffix, bounds in INT_SUFFIX_BOUNDS.items():
        if name.endswith(f"_{suffix}"):
            return bounds
    return None


def value_errors(name: str, declared: dict, what: str,
                 field: str) -> list[str]:
    """Type- and range-check a default or example against its key."""
    vtype = declared.get("type")
    value = declared.get(field)
    errors: list[str] = []
    if vtype == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return [f"{what} must be an integer; floats and booleans are "
                    "not configuration values"]
        bounds = int_bounds(name)
        if bounds is None:
            return [f"{what} belongs to an integer key without a unit "
                    f"suffix from {sorted(INT_SUFFIX_BOUNDS)}"]
        lo, hi = bounds
        if not lo <= value <= hi:
            errors.append(f"{what} is outside the {lo}..{hi} bounds its "
                          "unit suffix fixes")
        return errors
    if vtype == "boolean":
        if not isinstance(value, bool):
            errors.append(f"{what} must be a boolean")
        return errors
    if vtype == "string":
        return string_errors(value, what)
    if vtype == "path":
        return path_errors(value, what)
    if vtype == "enum":
        values = declared.get("values")
        if isinstance(value, str) and isinstance(values, list) \
                and value not in values:
            errors.append(f"{what} is not one of the key's declared values "
                          f"{values}")
        elif not isinstance(value, str):
            errors.append(f"{what} must be a string")
        return errors
    if vtype == "reference":
        return reference_errors(value, what)
    return errors  # an unknown type is reported where the type is checked.


def validate_registry(registry: dict) -> list[str]:
    """Return every convention violation in a parsed registry."""
    errors: list[str] = []

    extra_top = set(registry) - {"schema", "keys"}
    missing_top = {"schema", "keys"} - set(registry)
    if extra_top:
        errors.append(f"unknown top-level keys: {sorted(extra_top)}")
    if missing_top:
        errors.append(f"missing top-level keys: {sorted(missing_top)}")
    if registry.get("schema") != REGISTRY_SCHEMA:
        errors.append(f"schema must be {REGISTRY_SCHEMA!r}, "
                      f"found {registry.get('schema')!r}")
    if errors:
        return errors

    keys: dict = registry["keys"]
    if not isinstance(keys, dict) or not keys:
        return ["registry declares no keys"]

    env_names: dict[str, str] = {}
    flag_names: dict[str, str] = {}
    for name, declared in keys.items():
        what = f"key {name!r}"
        if not isinstance(name, str) or KEY_NAME_RE.match(name) is None:
            errors.append(f"{what} does not match the two-segment "
                          "lowercase name grammar")
        if not isinstance(declared, dict):
            errors.append(f"{what} must be a table")
            continue

        unknown = set(declared) - KEYS_REQUIRED - KEYS_OPTIONAL
        if unknown:
            errors.append(f"{what} has unknown keys {sorted(unknown)}; the "
                          "registry schema is closed")
        missing = KEYS_REQUIRED - set(declared)
        if missing:
            errors.append(f"{what} is missing keys {sorted(missing)}")

        has_default = "default" in declared
        has_required = declared.get("required") is True
        if has_default and has_required:
            errors.append(f"{what} declares both a default and required")
        if not has_default and not has_required:
            errors.append(f"{what} declares neither a default nor "
                          "required = true")
        if "required" in declared and declared["required"] is not True:
            errors.append(f"{what} declares required = "
                          f"{declared['required']!r}; the key is either "
                          "required = true or carries a default")
        if has_default:
            errors.extend(value_errors(name, declared,
                                       f"{what} default", "default"))

        owner = declared.get("owner")
        if owner not in CRATES:
            errors.append(f"{what} names owner {owner!r}, which is not a "
                          "workspace crate")

        vtype = declared.get("type")
        if vtype not in TYPES:
            errors.append(f"{what} declares type {vtype!r}, which is not in "
                          f"the closed set {sorted(TYPES)}")
        if vtype == "enum":
            values = declared.get("values")
            if not isinstance(values, list) or not values:
                errors.append(f"{what} is an enum without a non-empty "
                              "closed value set")
            else:
                for v in values:
                    if not isinstance(v, str) or ENUM_VALUE_RE.match(v) is None:
                        errors.append(f"{what} enum value {v!r} does not "
                                      "match [a-z][a-z0-9_]{0,31}")
                if len(set(map(str, values))) != len(values):
                    errors.append(f"{what} enum values contain duplicates")
        elif "values" in declared:
            errors.append(f"{what} declares values but is not an enum")

        secret = declared.get("secret")
        if not isinstance(secret, bool):
            errors.append(f"{what} must declare secret as a boolean")
        else:
            ends_ref = isinstance(name, str) and \
                name.split(".")[-1].endswith("_ref")
            if secret and not (vtype == "reference" and ends_ref):
                errors.append(f"{what} is secret, so it must be type "
                              "reference with a name ending in _ref")
            if vtype == "reference" and not secret:
                errors.append(f"{what} is type reference, so it must "
                              "declare secret = true")
            if ends_ref and vtype != "reference":
                errors.append(f"{what} ends in _ref but is not type "
                              "reference; the suffix means reference")
            if secret and has_default:
                errors.append(f"{what} is secret with a default; secrets "
                              "are required, never defaulted")

        tiers = declared.get("tiers")
        if not isinstance(tiers, list) or not tiers:
            errors.append(f"{what} must declare a non-empty tier list")
        elif not all(isinstance(t, str) for t in tiers):
            errors.append(f"{what} tier list must contain strings")
        else:
            unknown = [t for t in tiers if t not in TIERS]
            if unknown:
                errors.append(f"{what} declares unknown tiers {unknown}")
            if len(set(tiers)) != len(tiers):
                errors.append(f"{what} tier list contains duplicates")
            if "file" not in tiers:
                errors.append(f"{what} does not include the file tier; the "
                              "TOML file is the substrate every key supports")
            if secret is True and "flag" in tiers:
                errors.append(f"{what} is secret and exposes a flag tier; "
                              "references never ride command lines")

        if "deprecated" in declared and not isinstance(
                declared["deprecated"], bool):
            errors.append(f"{what} flag 'deprecated' must be a boolean")

        errors.extend(value_errors(name, declared, f"{what} example",
                                   "example"))
        errors.extend(prose_errors(declared.get("description"),
                                   f"{what} description"))

        if isinstance(name, str) and KEY_NAME_RE.match(name) is not None:
            env = "ARCHIVIST_" + name.replace(".", "_").upper()
            flag = "--" + name.replace(".", "-").replace("_", "-")
            if "env" in (tiers or []):
                if env in env_names:
                    errors.append(f"{what} derives environment name {env}, "
                                  f"already derived by {env_names[env]!r}")
                else:
                    env_names[env] = name
            if "flag" in (tiers or []):
                if flag in flag_names:
                    errors.append(f"{what} derives flag name {flag}, "
                                  f"already derived by {flag_names[flag]!r}")
                else:
                    flag_names[flag] = name

    return errors


def load_registry(path: Path) -> dict | None:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        fail(f"{path} is not valid TOML: {exc}")
    except OSError as exc:
        fail(f"{path} cannot be read: {exc}")
    return None


def scan_text(text: str, where: str) -> list[str]:
    """Flag *_ref assignments whose value is not a well-formed reference."""
    violations: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in ASSIGN_RE.finditer(line):
            value = match.group("val").strip()
            if reference_errors(value, "value"):
                violations.append(
                    f"{where}:{lineno}: '{match.group('key')}' is assigned a "
                    "value that is not a file:/env: reference (CFG-032)")
    return violations


def scan_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [f"{path} cannot be read: {exc}"]
    return scan_text(text, str(path))


def scan_tree() -> list[str]:
    """Scan every committed-shape file in the tree for literal *_ref values."""
    violations: list[str] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in PRUNE_DIRS)
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            rel = path.relative_to(ROOT)
            parts = rel.parts
            if parts[:1] == (".beads",) and ("traces" in parts
                                             or filename == "beads.db"):
                continue
            if path.suffix.lower() in SCAN_EXTENSIONS:
                violations.extend(scan_file(path))
    return violations


# --- self-test ---------------------------------------------------------------
#
# Every registry case is a mutation of the committed registry, which must
# itself be valid, and the committed tree must itself be clean. ``reject``
# cases must introduce at least one violation. The scan cases run against
# sandbox files under a temporary directory.

SELF_TEST_CASES: list[tuple[str, bool, object]] = [
    ("unmodified registry", False, None),
    ("secret key without the _ref suffix",
     True, ("key", "spool.max_bytes", "secret", True)),
    ("_ref name that is not secret",
     True, ("key", "storage.raw_write_credentials_ref", "secret", False)),
    ("_ref name with a non-reference type",
     True, ("key", "storage.raw_write_credentials_ref", "type", "string")),
    ("secret key exposing a flag tier",
     True, ("key", "storage.raw_write_credentials_ref", "tiers",
            ["flag", "file"])),
    ("secret key carrying a default",
     True, ("key", "storage.raw_write_credentials_ref", "default",
            "file:/etc/archivist/storage/raw-write-credentials")),
    ("literal-looking example for a secret key",
     True, ("key", "storage.raw_write_credentials_ref", "example",
            "not-a-reference-value")),
    ("env reference into the reserved namespace",
     True, ("key", "storage.raw_write_credentials_ref", "example",
            "env:ARCHIVIST_STORAGE_SECRET")),
    ("file reference that is not absolute",
     True, ("key", "storage.raw_write_credentials_ref", "example",
            "file:archivist/credentials")),
    ("file reference with traversal",
     True, ("key", "storage.raw_write_credentials_ref", "example",
            "file:/etc/../credentials")),
    ("file reference with a template variable",
     True, ("key", "storage.raw_write_credentials_ref", "example",
            "file:${HOME}/credentials")),
    ("percent default out of bounds",
     True, ("key", "schedule.jitter_percent", "default", 150)),
    ("float default",
     True, ("key", "schedule.jitter_percent", "default", 1.5)),
    ("byte default below its bound",
     True, ("key", "spool.max_bytes", "default", 0)),
    ("integer key without a unit suffix",
     True, ("rename", "spool.max_bytes", "spool.maximum")),
    ("key name is not two lowercase segments",
     True, ("rename", "client.state_dir", "Spool.State")),
    ("key name has three segments",
     True, ("rename", "client.state_dir", "a.b.c")),
    ("key declares neither default nor required",
     True, ("key", "ingest.endpoint_url", "required", False)),
    ("key declares both default and required",
     True, ("key", "ingest.endpoint_url", "default",
            "https://ingest.example.invalid")),
    ("key declares an unknown type",
     True, ("key", "storage.path_style", "type", "colour")),
    ("key names a non-workspace owner",
     True, ("key", "storage.path_style", "owner", "archivist-teapot")),
    ("enum without a value set",
     True, ("drop", ("storage.path_style", "values"))),
    ("enum default outside its value set",
     True, ("key", "storage.path_style", "default", "virtual-hosted")),
    ("enum value outside the value grammar",
     True, ("key", "storage.path_style", "values",
            ["path", "virtual_hosted", "Path"])),
    ("enum example outside its value set",
     True, ("key", "storage.encryption", "values",
            ["armor", "client_envelope"])),
    ("key drops the file tier",
     True, ("key", "client.state_dir", "tiers", ["flag", "env"])),
    ("key loses its example",
     True, ("drop", ("client.state_dir", "example"))),
    ("key loses its description",
     True, ("drop", ("client.state_dir", "description"))),
    ("path default that is relative",
     True, ("key", "client.state_dir", "default", "archivist/state")),
    ("path default with a tilde",
     True, ("key", "client.state_dir", "default", "~/archivist")),
    ("string example over its bound",
     True, ("key", "ingest.endpoint_url", "example", "x" * 129)),
    ("registry adds a colliding environment name",
     True, ("new", "spool_max.bytes", {
         "owner": "archivist-client-core", "type": "integer",
         "tiers": ["env", "file"], "secret": False, "default": 1,
         "description": "Collides with spool.max_bytes.",
         "example": 1})),
    ("registry declares the wrong schema",
     True, ("top", "schema", "archivist.config-registry/v2")),
    ("registry adds an unknown top-level key",
     True, ("top", "labels", ["free-form"])),
    ("key loses its tiers",
     True, ("drop", ("server.rate_burst_count", "tiers"))),
]

SCAN_CASES: list[tuple[str, bool, str]] = [
    ("literal value in a TOML example", True,
     'api_credentials_ref = "not-a-reference-value"\n'),
    ("reference in a TOML example", False,
     "api_credentials_ref = 'file:/etc/archivist/api-credentials'\n"),
    ("literal value in a JSON-shaped line", True,
     '{"storage": {"credentials_ref": "env:archivist_secret"}}\n'),
    ("environment reference in an env file", False,
     "CREDENTIALS_REF=env:S3_CREDENTIALS\n"),
    ("literal value in an env file", True,
     "STORE_CREDENTIALS_REF=not-a-reference-value\n"),
    ("block scalar for a reference key", True,
     "credentials_ref: |\n  multi-line-secret\n"),
    ("reference in a YAML example", False,
     "credentials_ref: file:/etc/archivist/credentials\n"),
]


def apply_mutation(registry: dict, mutation: object) -> dict:
    """Return a copy of ``registry`` with one mutation applied."""
    import copy

    mutated = copy.deepcopy(registry)
    if mutation is None:
        return mutated
    kind = mutation[0]
    if kind == "key":
        _, key, field, value = mutation
        if value is None:
            mutated["keys"][key].pop(field, None)
        else:
            mutated["keys"][key][field] = value
    elif kind == "rename":
        _, old, new = mutation
        mutated["keys"][new] = mutated["keys"].pop(old)
    elif kind == "drop":
        mutated["keys"][mutation[1][0]].pop(mutation[1][1], None)
    elif kind == "new":
        _, name, entry = mutation
        mutated["keys"][name] = entry
    elif kind == "top":
        _, key, value = mutation
        mutated[key] = value
    else:  # pragma: no cover - the case list is closed
        raise AssertionError(kind)
    return mutated


def run_self_test() -> int:
    base = load_registry(ROOT / REGISTRY_PATH)
    if base is None:
        return 2
    problems = validate_registry(base)
    if problems:
        fail("self-test base: the committed registry itself is invalid")
        for problem in problems:
            fail(f"  {problem}")
        return 2
    tree = scan_tree()
    if tree:
        fail("self-test base: the committed tree itself has violations")
        for violation in tree:
            fail(f"  {violation}")
        return 2

    import tempfile

    passed = 0
    failed = 0
    for label, must_reject, mutation in SELF_TEST_CASES:
        registry = apply_mutation(base, mutation)
        violations = validate_registry(registry)
        rejected = bool(violations)
        if rejected == must_reject:
            passed += 1
            print(f"  ok  {'rejects' if rejected else 'accepts'}: {label}")
        else:
            failed += 1
            outcome = "should reject" if must_reject else "should accept"
            print(f"  FAIL {outcome}: {label}")
            for violation in violations:
                print(f"       violation: {violation}")

    with tempfile.TemporaryDirectory() as sandbox:
        for index, (label, must_flag, content) in enumerate(SCAN_CASES):
            path = Path(sandbox) / f"case-{index}.txt"
            path.write_text(content, encoding="utf-8")
            violations = scan_file(path)
            flagged = bool(violations)
            if flagged == must_flag:
                passed += 1
                print(f"  ok  {'flags' if flagged else 'passes'}: {label}")
            else:
                failed += 1
                outcome = "should flag" if must_flag else "should pass"
                print(f"  FAIL {outcome}: {label}")
                for violation in violations:
                    print(f"       violation: {violation}")

    print(f"self-test: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 2


def main(argv: list[str]) -> int:
    if "--self-test" in argv[1:]:
        return run_self_test()
    if argv[1:]:
        fail(f"unknown arguments: {' '.join(argv[1:])}")
        return 2

    registry = load_registry(ROOT / REGISTRY_PATH)
    if registry is None:
        return 2

    violations = validate_registry(registry)
    for violation in violations:
        fail(violation)
    tree = scan_tree()
    for violation in tree:
        fail(violation)
    if violations or tree:
        return 2

    keys = registry["keys"]
    secrets = sum(1 for k in keys.values() if k.get("secret") is True)
    required = sum(1 for k in keys.values()
                   if k.get("required") is True)
    print(f"agent-archivist configuration registry: {REGISTRY_SCHEMA}")
    print(f"keys: {len(keys)} ({secrets} secret references, "
          f"{required} required)")
    print("OK: registry and working tree satisfy docs/notes/configuration.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
