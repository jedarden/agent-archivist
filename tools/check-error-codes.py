#!/usr/bin/env python3
"""Error-code registry gate for Agent Archivist.

Validates ``tools/error-codes.toml`` against the conventions in
``docs/notes/error-codes.md``:

1. the registry declares schema ``archivist.error-registry/v1`` and nothing
   else at the top level;
2. the class table matches the v1-frozen taxonomy exactly — the same class
   names, HTTP statuses, retryability, client action, and exit code pinned
   below, so a registry edit cannot silently redefine a class;
3. code names are two lowercase dot-separated segments and unique;
4. each code references a known class, carries an HTTP status only when its
   class is server-facing (and then one the class allows), and documents a
   bounded description;
5. message templates use printable ASCII without raw braces, stay within the
   template length bound, and reference only allowlisted placeholder fields —
   the allowlist contains bounded structural values (identifiers, versions,
   byte counts), never anything derived from source or transcript content;
6. every class has at least one code.

On success it prints a summary and exits 0. Any failure prints a report on
stderr and exits 2.

``--self-test`` runs the same validators against embedded good and bad
samples and fails unless every bad sample is rejected, proving the rejection
paths (source-derived placeholders, unbounded labels, class drift) rather
than only the accept path.

Usage::

    tools/check-error-codes.py [--self-test]

Standard-library only (``tomllib``), so a clean checkout runs it before any
dependency is fetched. Its output names codes, classes, and rules only.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = Path("tools/error-codes.toml")

REGISTRY_SCHEMA = "archivist.error-registry/v1"

# The v1-frozen class taxonomy (docs/notes/error-codes.md Section 2). The
# registry declares these; the gate pins them. Changing this table is a v2
# namespace event, not a registry edit.
FROZEN_CLASSES: dict[str, dict] = {
    "request_invalid": {
        "http": [400, 415], "retryable": False,
        "client_action": "quarantine_artifact", "exit": 65,
    },
    "authorization": {
        "http": [401, 403], "retryable": False,
        "client_action": "pause_for_linking", "exit": 78,
    },
    "integrity_conflict": {
        "http": [409], "retryable": False,
        "client_action": "stop_and_page_operator", "exit": 80,
    },
    "payload_limit_splittable": {
        "http": [413], "retryable": False,
        "client_action": "rechunk_and_resubmit", "exit": 65,
    },
    "payload_limit_unsplittable": {
        "http": [413], "retryable": False,
        "client_action": "quarantine_and_report_gap", "exit": 65,
    },
    "throttle": {
        "http": [408, 425, 429], "retryable": True,
        "client_action": "backoff_and_retry", "exit": 75,
    },
    "server_failure": {
        "http": [500, 502, 503, 504], "retryable": True,
        "client_action": "backoff_and_retry", "exit": 75,
    },
    "network": {
        "http": [], "retryable": True,
        "client_action": "retry_identical_envelope", "exit": 75,
    },
    "usage": {
        "http": [], "retryable": False,
        "client_action": "fix_invocation", "exit": 64,
    },
    "lock_contention": {
        "http": [], "retryable": False,
        "client_action": "await_mutator_exit", "exit": 75,
    },
    "resource_exhausted": {
        "http": [], "retryable": False,
        "client_action": "restore_disk_floor", "exit": 75,
    },
    "local_state": {
        "http": [], "retryable": False,
        "client_action": "run_doctor", "exit": 74,
    },
    "internal": {
        "http": [], "retryable": False,
        "client_action": "report_bug", "exit": 70,
    },
}

CLASS_KEYS = frozenset({"http", "retryable", "client_action", "exit", "description"})
CODE_KEYS_REQUIRED = frozenset({"class", "message", "description"})
CODE_KEYS_OPTIONAL = frozenset({"http", "deprecated"})

CLASS_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
CODE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,23}\.[a-z][a-z0-9_]{0,23}$")

# Placeholder allowlist (docs/notes/error-codes.md Section 4). Kind "token"
# renders only values matching PATTERN; kind "integer" renders only decimal
# integers below 2**63. No other field may ever be interpolated into a
# message: paths, payload excerpts, provider strings, and identifiers not
# listed here are all out of bounds by construction.
PLACEHOLDERS: dict[str, tuple[str, re.Pattern]] = {
    "version": ("token", re.compile(r"^[0-9A-Za-z._+-]{1,32}$")),
    "media_type": ("token", re.compile(r"^[0-9A-Za-z.+/-]{1,64}$")),
    "expected_media_type": ("token", re.compile(r"^[0-9A-Za-z.+/-]{1,64}$")),
    "field": ("identifier", re.compile(r"^[a-z0-9_.-]{1,64}$")),
    "actual_bytes": ("integer", re.compile(r"^[0-9]{1,19}$")),
    "limit_bytes": ("integer", re.compile(r"^[0-9]{1,19}$")),
    "free_bytes": ("integer", re.compile(r"^[0-9]{1,19}$")),
    "count": ("integer", re.compile(r"^[0-9]{1,19}$")),
    "max_ratio": ("integer", re.compile(r"^[0-9]{1,19}$")),
}

PLACEHOLDER_RE = re.compile(r"\{(?P<name>[a-z_][a-z0-9_]*)\}")
# Anything outside printable ASCII is invalid anywhere in a template.
NON_PRINTABLE_RE = re.compile(r"[^ -~]")
# Any brace is invalid in literal text; a brace surviving removal of
# well-formed placeholders marks a malformed placeholder.
STRAY_BRACE_RE = re.compile(r"[{}]")

TEMPLATE_MAX = 160   # template length bound
RENDERED_MAX = 200   # rendered-message bound the renderer truncates to
PROSE_MAX = 200      # bound for class and code descriptions


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def prose_errors(value: object, what: str) -> list[str]:
    """Bound and charset-check a descriptive string (no braces, one line)."""
    if not isinstance(value, str):
        return [f"{what} must be a string"]
    errors: list[str] = []
    if NON_PRINTABLE_RE.search(value) or STRAY_BRACE_RE.search(value):
        errors.append(f"{what} contains a brace or non-printable-ASCII character")
    if len(value) > PROSE_MAX:
        errors.append(f"{what} exceeds the {PROSE_MAX}-character bound")
    return errors


def message_errors(template: object, what: str) -> list[str]:
    """Validate a bounded, content-free message template."""
    if not isinstance(template, str):
        return [f"{what} must be a string"]
    errors: list[str] = []
    if len(template) > TEMPLATE_MAX:
        errors.append(f"{what} exceeds the {TEMPLATE_MAX}-character template bound")
    if NON_PRINTABLE_RE.search(template):
        errors.append(f"{what} contains a non-printable-ASCII character")
    residue = PLACEHOLDER_RE.sub("", template)
    if STRAY_BRACE_RE.search(residue):
        # An unmatched `{`, `}`, or format suffix survived placeholder removal.
        errors.append(f"{what} contains a brace in literal text or a malformed "
                      "placeholder")
    for match in PLACEHOLDER_RE.finditer(template):
        name = match.group("name")
        if name not in PLACEHOLDERS:
            errors.append(f"{what} interpolates '{'{' + name + '}'}', which is not "
                          "an allowlisted placeholder; messages never carry "
                          "source-derived content")
    return errors


def validate_registry(registry: dict) -> list[str]:
    """Return every convention violation in a parsed registry."""
    errors: list[str] = []

    extra_top = set(registry) - {"schema", "classes", "codes"}
    missing_top = {"schema", "classes", "codes"} - set(registry)
    if extra_top:
        errors.append(f"unknown top-level keys: {sorted(extra_top)}")
    if missing_top:
        errors.append(f"missing top-level keys: {sorted(missing_top)}")
    if registry.get("schema") != REGISTRY_SCHEMA:
        errors.append(f"schema must be {REGISTRY_SCHEMA!r}, "
                      f"found {registry.get('schema')!r}")
    if errors:
        return errors

    classes: dict = registry["classes"]
    codes: dict = registry["codes"]

    # --- frozen class table -------------------------------------------------
    for name in sorted(set(classes) - set(FROZEN_CLASSES)):
        errors.append(f"class {name!r} is not part of the frozen v1 taxonomy")
    for name in sorted(set(FROZEN_CLASSES) - set(classes)):
        errors.append(f"frozen v1 class {name!r} is missing from the registry")
    for name, declared in classes.items():
        if not isinstance(declared, dict):
            errors.append(f"class {name!r} must be a table")
            continue
        if not CLASS_NAME_RE.match(name):
            errors.append(f"class name {name!r} does not match [a-z][a-z0-9_]{{0,31}}")
        unknown = set(declared) - CLASS_KEYS
        if unknown:
            errors.append(f"class {name!r} has unknown keys {sorted(unknown)}")
        frozen = FROZEN_CLASSES.get(name)
        if frozen is None:
            continue
        for key in ("http", "retryable", "client_action", "exit"):
            if key in declared and declared[key] != frozen[key]:
                errors.append(
                    f"class {name!r} declares {key}={declared[key]!r} but v1 pins "
                    f"{key}={frozen[key]!r}; changing a frozen attribute is a "
                    "registry v2 event")
        errors.extend(prose_errors(declared.get("description"),
                                   f"class {name!r} description"))

    # --- codes --------------------------------------------------------------
    if not isinstance(codes, dict) or not codes:
        errors.append("registry declares no codes")
        return errors

    used_classes: set[str] = set()
    for name, declared in codes.items():
        what = f"code {name!r}"
        if not CODE_NAME_RE.match(name):
            errors.append(f"{what} does not match the two-segment "
                          "lowercase name grammar")
        if not isinstance(declared, dict):
            errors.append(f"{what} must be a table")
            continue
        unknown = set(declared) - CODE_KEYS_REQUIRED - CODE_KEYS_OPTIONAL
        if unknown:
            errors.append(f"{what} has unknown keys {sorted(unknown)}; free-form "
                          "labels are not part of the registry schema")
        missing = CODE_KEYS_REQUIRED - set(declared)
        if missing:
            errors.append(f"{what} is missing keys {sorted(missing)}")

        klass = declared.get("class")
        if klass not in FROZEN_CLASSES:
            errors.append(f"{what} references unknown class {klass!r}")
        else:
            used_classes.add(klass)
            allowed = FROZEN_CLASSES[klass]["http"]
            http = declared.get("http")
            if allowed:
                if "http" not in declared:
                    errors.append(f"{what} must declare an HTTP status "
                                  f"(class {klass!r} is server-facing)")
                elif not isinstance(http, int) or http not in allowed:
                    errors.append(f"{what} declares http={http!r}, which is not "
                                  f"one of {allowed} allowed for class {klass!r}")
            elif "http" in declared:
                errors.append(f"{what} declares http={declared['http']!r} but "
                              f"class {klass!r} never reaches HTTP")

        if "deprecated" in declared and not isinstance(declared["deprecated"], bool):
            errors.append(f"{what} flag 'deprecated' must be a boolean")

        errors.extend(message_errors(declared.get("message"), f"{what} message"))
        errors.extend(prose_errors(declared.get("description"),
                                   f"{what} description"))

    for name in sorted(set(FROZEN_CLASSES) - used_classes):
        errors.append(f"class {name!r} has no codes")

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


# --- self-test ---------------------------------------------------------------
#
# Every case is a mutation of the committed registry, which must itself be
# valid. ``reject`` cases must introduce at least one violation; the
# unmodified base must stay clean.

SELF_TEST_CASES: list[tuple[str, bool, object]] = [
    ("unmodified registry", False, None),
    ("message interpolates a source path",
     True, ("code", "envelope.schema_invalid", "message",
            "Cannot read source at {path}.")),
    ("message interpolates a provider string",
     True, ("code", "envelope.schema_invalid", "message",
            "Rejected: {provider_message}")),
    ("message contains a transcript excerpt field",
     True, ("code", "envelope.schema_invalid", "message",
            "Invalid after {transcript_excerpt}")),
    ("message contains a newline",
     True, ("code", "envelope.schema_invalid", "message",
            "Two\nlines")),
    ("message exceeds the template bound",
     True, ("code", "envelope.schema_invalid", "message", "x" * 161)),
    ("message has an unbalanced brace",
     True, ("code", "envelope.schema_invalid", "message",
            "Version {version is unsupported.")),
    ("message has a format-specifier placeholder",
     True, ("code", "envelope.schema_invalid", "message",
            "Limit is {limit_bytes:.2} bytes.")),
    ("message has an empty placeholder",
     True, ("code", "envelope.schema_invalid", "message", "Limit is {} bytes.")),
    ("message uses a brace in literal text",
     True, ("code", "envelope.schema_invalid", "message",
            "Use braces { like this.")),
    ("code carries a free-form metric label",
     True, ("code", "envelope.schema_invalid", "metric_label", "tenant-1234")),
    ("code name is not two lowercase segments",
     True, ("rename", "envelope.schema_invalid", "Envelope.Malformed")),
    ("code name has three segments",
     True, ("rename", "envelope.schema_invalid", "a.b.c")),
    ("code claims an HTTP status outside its class",
     True, ("code", "envelope.schema_invalid", "http", 418)),
    ("client-only code claims an HTTP status",
     True, ("code", "transport.response_lost", "http", 503)),
    ("server-facing code omits its HTTP status",
     True, ("drop", ("code", "envelope.schema_invalid", "http"))),
    ("code description is missing",
     True, ("drop", ("code", "envelope.schema_invalid", "description"))),
    ("code description exceeds the prose bound",
     True, ("code", "envelope.schema_invalid", "description", "y" * 201)),
    ("class attribute drifts from the frozen table",
     True, ("class", "throttle", "retryable", False)),
    ("registry adds an unknown class",
     True, ("new-class", "teapot")),
    ("registry declares the wrong schema",
     True, ("top", "schema", "archivist.error-registry/v2")),
    ("registry adds an unknown top-level key",
     True, ("top", "labels", ["free-form"])),
    ("class loses its last code",
     True, ("drop-code", "network")),
    ("code references an unknown class",
     True, ("code", "transport.response_lost", "class", "teapot")),
]


def apply_mutation(registry: dict, mutation: object) -> dict:
    """Return a copy of ``registry`` with one mutation applied."""
    import copy

    mutated = copy.deepcopy(registry)
    if mutation is None:
        return mutated
    kind = mutation[0]
    if kind == "code":
        _, code, key, value = mutation
        if value is None:
            mutated["codes"][code].pop(key, None)
        else:
            mutated["codes"][code][key] = value
    elif kind == "class":
        _, klass, key, value = mutation
        mutated["classes"][klass][key] = value
    elif kind == "rename":
        _, old, new = mutation
        mutated["codes"][new] = mutated["codes"].pop(old)
    elif kind == "drop":
        mutated["codes"][mutation[1][1]].pop(mutation[1][2], None)
    elif kind == "drop-code":
        for name, code in list(mutated["codes"].items()):
            if code["class"] == mutation[1]:
                del mutated["codes"][name]
    elif kind == "new-class":
        mutated["classes"][mutation[1]] = {
            "http": [418], "retryable": False,
            "client_action": "quarantine_artifact", "exit": 65,
            "description": "Unregistered class.",
        }
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
    if validate_registry(base):
        fail("self-test base: the committed registry itself is invalid")
        return 2

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
            print(f"  FAIL {'should reject' if must_reject else 'should accept'}: "
                  f"{label}")
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
    if violations:
        return 2

    classes = registry["classes"]
    codes = registry["codes"]
    server_codes = sum(1 for c in codes.values() if c.get("http") is not None)
    print(f"agent-archivist error registry: {REGISTRY_SCHEMA}")
    print(f"classes: {len(classes)} (frozen v1 taxonomy), "
          f"codes: {len(codes)} ({server_codes} server-facing)")
    used = sorted({p for c in codes.values() for p in PLACEHOLDER_RE.findall(
        c.get("message", ""))})
    print(f"placeholders in use: {', '.join(used) if used else 'none'}")
    print("OK: registry satisfies docs/notes/error-codes.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
