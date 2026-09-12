#!/usr/bin/env python3
"""CLI command-surface registry gate for Agent Archivist.

Validates the command contract of ``docs/notes/cli.md`` across the three
artifacts that pin it:

1. ``tools/cli-commands.toml`` (``archivist.cli-registry/v1``) — command
   grammar (one or two lowercase segments), the closed per-command shape,
   bounded summaries, phase and owner sanity, joined-form uniqueness
   (CLI-005), and boolean, globally unique operational flags (CLI-011);
2. cross-registry coherence with ``tools/config-keys.toml`` — a command's
   key list references registered keys only, every registered key is
   consumed by at least one command, and no secret key exposes a flag tier
   (CLI-010, CLI-024), so the argument surface is secret-free by
   construction;
3. ``schemas/v1/cli-output.json`` (``archivist.cli-output/v1``) — the $id,
   the namespace const, the closed four-member envelope, the command-token
   pattern the registry's joined forms must satisfy, the resolvable
   ``generated_at`` reference, and the no-float discipline (CLI-014).

The three flag namespaces (mode, key-derived, operational) are proven
pairwise disjoint, and the mode-flag set is pinned here so neither registry
can grow it (CFG-003, CLI-009).

On success it prints a summary and exits 0. Any failure prints a report on
stderr and exits 2. Findings name commands, flags, keys, and rules only.

``--self-test`` runs the same validators against mutated copies of the
committed trio (registry shape defects, each collision direction, coverage
and secret/flag separation, schema drift) and fails unless every one is
rejected. The committed trio must itself be clean.

Usage::

    tools/check-cli.py [--self-test]

Standard-library only (``tomllib``), so a clean checkout runs it before any
dependency is fetched.
"""

from __future__ import annotations

import copy
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI_PATH = Path("tools/cli-commands.toml")
CONFIG_PATH = Path("tools/config-keys.toml")
SCHEMA_PATH = Path("schemas/v1/cli-output.json")

REGISTRY_SCHEMA = "archivist.cli-registry/v1"
OUTPUT_NAMESPACE = "archivist.cli-output/v1"
SCHEMA_ID = "urn:agent-archivist:schema:v1:cli-output"
DRAFT = "https://json-schema.org/draft/2020-12/schema"
TIMESTAMP_REF = ("urn:agent-archivist:schema:v1:common"
                 "#/$defs/rfc3339-utc-timestamp")

# Workspace crates (docs/notes/crate-ownership.md), as in check-config.py.
CRATES = frozenset({
    "archivist-protocol", "archivist-auth", "archivist-storage",
    "archivist-adapter-sdk", "archivist-storage-s3", "archivist-client-core",
    "archivist-adapter-claude", "archivist-adapter-codex",
    "archivist-adapter-opencode", "archivist-adapter-pi", "archivist-server",
    "archivist-cli",
})

# The closed mode-flag set (CFG-003, CLI-009). Pinned here so neither
# registry can grow it; the value kind is pinned too, and exactly one mode
# flag takes a value — a path, never a secret.
MODE_FLAGS: dict[str, str] = {
    "non-interactive": "boolean",
    "json": "boolean",
    "config": "path",
    "help": "boolean",
    "version": "boolean",
}

# Closed per-command attribute sets (CLI-027). `flags` may be omitted when a
# command has none; `result_schema` attaches when the implementing phase
# pins the command's result document (CLI-015).
COMMAND_REQUIRED = frozenset({
    "summary", "phase", "owner", "state_lock", "stdout", "operand", "stdin",
    "keys",
})
COMMAND_OPTIONAL = frozenset({"flags", "result_schema", "deprecated"})
FLAG_REQUIRED = frozenset({"summary"})
FLAG_OPTIONAL = frozenset({"required"})

STATE_LOCKS = frozenset({"exclusive", "read_only", "none"})
STDOUT_KINDS = frozenset({"document", "none"})
OPERAND_KINDS = frozenset({"none", "path", "identifier"})
STDIN_KINDS = frozenset({"none", "payload"})
PHASE_BOUNDS = (2, 11)

COMMAND_SEGMENT_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
FLAG_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
# The envelope's command token, pinned by schemas/v1/cli-output.json; the
# registry's joined forms must all satisfy it (the gate cross-checks both
# directions so neither can drift alone).
COMMAND_TOKEN_RE = re.compile(r"^[a-z][a-z0-9-]{0,64}$")
COMMAND_TOKEN_MAX = 65
STRING_RE = re.compile(r"^[ -~]+$")
SUMMARY_MAX = 160

ENVELOPE_MEMBERS = frozenset({"schema", "command", "generated_at", "result"})


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def prose_errors(value: object, what: str) -> list[str]:
    """Bound and charset-check a one-line summary (no braces)."""
    if not isinstance(value, str):
        return [f"{what} must be a string"]
    errors: list[str] = []
    if STRING_RE.match(value) is None or "{" in value or "}" in value:
        errors.append(f"{what} contains a brace or non-printable-ASCII "
                      "character")
    if len(value) > SUMMARY_MAX:
        errors.append(f"{what} exceeds the {SUMMARY_MAX}-character bound")
    return errors


def key_flag_name(key: str) -> str:
    """The CFG-007 derivation: dots and underscores become hyphens."""
    return key.replace(".", "-").replace("_", "-")


def load_trio() -> tuple[dict, dict, dict] | None:
    """Load the committed registry pair and the envelope schema."""
    trio: list[dict] = []
    for path, kind in ((CLI_PATH, "cli"), (CONFIG_PATH, "config"),
                       (SCHEMA_PATH, "schema")):
        try:
            raw = (ROOT / path).read_bytes()
        except OSError as exc:
            fail(f"{path}: unreadable ({exc})")
            return None
        try:
            if kind == "schema":
                trio.append(json.loads(raw))
            else:
                trio.append(tomllib.loads(raw.decode("utf-8")))
        except (tomllib.TOMLDecodeError, json.JSONDecodeError,
                UnicodeDecodeError) as exc:
            fail(f"{path}: unparsable ({exc})")
            return None
    cli, config, schema = trio
    if not all(isinstance(doc, dict) for doc in trio):
        fail("a pinned artifact is not a top-level table/object")
        return None
    return cli, config, schema


def validate(cli: dict, config: dict, schema: dict) -> list[str]:
    """Return every CLI-contract violation in the trio."""
    errors: list[str] = []

    # --- registry shape ----------------------------------------------------
    extra_top = set(cli) - {"schema", "commands"}
    missing_top = {"schema", "commands"} - set(cli)
    if extra_top:
        errors.append(f"cli registry: unknown top-level keys {sorted(extra_top)}")
    if missing_top:
        errors.append(f"cli registry: missing top-level keys {sorted(missing_top)}")
    if cli.get("schema") != REGISTRY_SCHEMA:
        errors.append(f"cli registry: schema must be {REGISTRY_SCHEMA!r}, "
                       f"found {cli.get('schema')!r}")
    commands = cli.get("commands")
    if not isinstance(commands, dict) or not commands:
        return errors + ["cli registry declares no commands"]

    # --- config registry inputs --------------------------------------------
    config_keys = config.get("keys")
    if not isinstance(config_keys, dict):
        return errors + ["config registry declares no keys (run check-config)"]
    key_tiers = {name: (declared.get("tiers") if isinstance(declared, dict)
                        else None)
                 for name, declared in config_keys.items()}
    key_flags = {key_flag_name(name) for name, tiers in key_tiers.items()
                 if isinstance(tiers, list) and "flag" in tiers}
    secret_flagged = sorted(name for name, tiers in key_tiers.items()
                            if isinstance(tiers, list) and "flag" in tiers
                            and isinstance(config_keys[name], dict)
                            and config_keys[name].get("secret") is True)
    if secret_flagged:
        errors.append(f"secret keys exposing a flag tier (CFG-031, CLI-024): "
                      f"{secret_flagged}")

    # --- per command --------------------------------------------------------
    joined: dict[str, str] = {}
    operational: dict[str, str] = {}
    consumed: set[str] = set()
    for name, declared in commands.items():
        what = f"command {name!r}"
        if not isinstance(name, str):
            errors.append(f"{what}: command path must be a string")
            continue
        parts = name.split(" ")
        if not 1 <= len(parts) <= 2 or any(
                COMMAND_SEGMENT_RE.match(part) is None for part in parts):
            errors.append(f"{what} is not one or two segments matching "
                          "[a-z][a-z0-9-]{0,31}")
        token = "-".join(parts)
        if COMMAND_TOKEN_RE.match(token) is None or len(token) > COMMAND_TOKEN_MAX:
            errors.append(f"{what}: joined form {token!r} violates the "
                          "envelope command-token grammar")
        if token in joined:
            errors.append(f"{what}: joined form {token!r} collides with "
                          f"{joined[token]!r} (CLI-005)")
        else:
            joined[token] = name
        if not isinstance(declared, dict):
            errors.append(f"{what} must be a table")
            continue

        unknown = set(declared) - COMMAND_REQUIRED - COMMAND_OPTIONAL
        if unknown:
            errors.append(f"{what} has unknown keys {sorted(unknown)}; the "
                          "registry schema is closed")
        missing = COMMAND_REQUIRED - set(declared)
        if missing:
            errors.append(f"{what} is missing keys {sorted(missing)}")
            continue

        errors.extend(prose_errors(declared.get("summary"), f"{what} summary"))
        phase = declared.get("phase")
        if isinstance(phase, bool) or not isinstance(phase, int) \
                or not PHASE_BOUNDS[0] <= phase <= PHASE_BOUNDS[1]:
            errors.append(f"{what} phase must be an integer in "
                          f"{PHASE_BOUNDS[0]}..{PHASE_BOUNDS[1]}")
        if declared.get("owner") not in CRATES:
            errors.append(f"{what} owner must be a workspace crate")
        for field, allowed in (("state_lock", STATE_LOCKS),
                               ("stdout", STDOUT_KINDS),
                               ("operand", OPERAND_KINDS),
                               ("stdin", STDIN_KINDS)):
            if declared.get(field) not in allowed:
                errors.append(f"{what} {field} must be one of "
                              f"{sorted(allowed)}, found {declared.get(field)!r}")
        keys = declared.get("keys")
        if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            errors.append(f"{what} keys must be a list of key names")
        else:
            if len(keys) != len(set(keys)):
                errors.append(f"{what} keys contains duplicates")
            for key in keys:
                if key not in config_keys:
                    errors.append(f"{what} consumes unregistered key {key!r} "
                                  "(CFG-001, CLI-010)")
            consumed.update(keys)

        flags = declared.get("flags", {})
        if not isinstance(flags, dict):
            errors.append(f"{what} flags must be a table")
        else:
            for flag, entry in flags.items():
                fwhat = f"{what} flag {flag!r}"
                if not isinstance(flag, str) or FLAG_NAME_RE.match(flag) is None:
                    errors.append(f"{fwhat} does not match "
                                  "[a-z][a-z0-9-]{0,63}")
                if not isinstance(entry, dict):
                    errors.append(f"{fwhat} must be a table")
                    continue
                unknown = set(entry) - FLAG_REQUIRED - FLAG_OPTIONAL
                if unknown:
                    errors.append(f"{fwhat} has unknown keys {sorted(unknown)}; "
                                  "operational flags are boolean in v1 (CLI-011)")
                missing = FLAG_REQUIRED - set(entry)
                if missing:
                    errors.append(f"{fwhat} is missing keys {sorted(missing)}")
                errors.extend(prose_errors(entry.get("summary"),
                                           f"{fwhat} summary"))
                if "required" in entry and not isinstance(entry["required"], bool):
                    errors.append(f"{fwhat} required must be a boolean")
                if flag in MODE_FLAGS:
                    errors.append(f"{fwhat} collides with the mode-flag "
                                  "namespace (CLI-009)")
                elif flag in key_flags:
                    errors.append(f"{fwhat} collides with key-flag "
                                  f"--{flag} (CFG-007, CLI-011)")
                if flag in operational:
                    errors.append(f"{fwhat} duplicates the flag of "
                                  f"{operational[flag]!r} (CLI-011)")
                else:
                    operational[flag] = name

        result_schema = declared.get("result_schema")
        if result_schema is not None:
            if not isinstance(result_schema, str) \
                    or not result_schema.startswith("schemas/v1/") \
                    or not result_schema.endswith(".json"):
                errors.append(f"{what} result_schema must name a JSON schema "
                              "under schemas/v1/")
            elif not (ROOT / result_schema).is_file():
                errors.append(f"{what} result_schema {result_schema!r} does "
                              "not exist in this tree")

    # --- coverage: the two registries close over each other -----------------
    unconsumed = sorted(set(config_keys) - consumed)
    if unconsumed:
        errors.append("registered keys no command consumes (CLI-010): "
                      f"{unconsumed}")

    # --- output envelope -----------------------------------------------------
    errors.extend(schema_errors(schema, set(joined)))
    return errors


def schema_errors(schema: dict, command_tokens: set[str]) -> list[str]:
    """Validate the envelope against CLI-014 (shape) and CLI-005 (tokens)."""
    errors: list[str] = []
    what = "cli-output schema"
    if schema.get("$schema") != DRAFT:
        errors.append(f"{what}: $schema must be {DRAFT}")
    if schema.get("$id") != SCHEMA_ID:
        errors.append(f"{what}: $id must be {SCHEMA_ID}")
    if schema.get("type") != "object":
        errors.append(f"{what}: the envelope must be an object")
    if schema.get("additionalProperties") is not False:
        errors.append(f"{what}: the envelope must be closed "
                      "(additionalProperties false)")
    required = schema.get("required")
    if not isinstance(required, list) \
            or frozenset(required) != ENVELOPE_MEMBERS \
            or len(required) != len(set(required)):
        errors.append(f"{what}: required members must be exactly "
                      f"{sorted(ENVELOPE_MEMBERS)}")
    properties = schema.get("properties")
    if not isinstance(properties, dict) \
            or frozenset(properties) != ENVELOPE_MEMBERS:
        errors.append(f"{what}: properties must be exactly "
                      f"{sorted(ENVELOPE_MEMBERS)}")
        return errors

    ns = properties.get("schema", {})
    if ns.get("const") != OUTPUT_NAMESPACE:
        errors.append(f"{what}: the schema member must be const "
                      f"{OUTPUT_NAMESPACE!r}")
    elif ns.get("x-archivist", {}).get("failClosed") is not True:
        errors.append(f"{what}: the schema member must carry failClosed: true")

    command = properties.get("command", {})
    if command.get("pattern") != COMMAND_TOKEN_RE.pattern:
        errors.append(f"{what}: command pattern must be "
                      f"{COMMAND_TOKEN_RE.pattern!r}")
    if command.get("maxLength") != COMMAND_TOKEN_MAX:
        errors.append(f"{what}: command maxLength must be "
                      f"{COMMAND_TOKEN_MAX}")
    for token in sorted(command_tokens):
        if COMMAND_TOKEN_RE.match(token) is None:
            errors.append(f"{what}: registry command token {token!r} "
                          "violates the schema pattern (drift between the two)")

    generated = properties.get("generated_at", {})
    if generated.get("$ref") != TIMESTAMP_REF:
        errors.append(f"{what}: generated_at must reference the shared "
                      f"RFC 3339 UTC shape ({TIMESTAMP_REF})")

    result = properties.get("result", {})
    if result.get("type") != "object":
        errors.append(f"{what}: result must be an object")

    meta = schema.get("x-archivist", {})
    if meta.get("namespace") != OUTPUT_NAMESPACE \
            or meta.get("namespaceField") != "schema":
        errors.append(f"{what}: x-archivist namespace metadata must pin "
                      f"{OUTPUT_NAMESPACE!r} on the schema member")
    if meta.get("floats") is not False:
        errors.append(f"{what}: x-archivist.floats must be false")

    for node in walk(schema):
        if node.get("type") == "number":
            errors.append(f"{what}: type number at "
                          f"{node.get('description', 'a member')!r} "
                          "(floats are forbidden)")
            break
    return errors


def walk(node):
    """Yield every dict below `node`."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def set_key_flag(cli: dict, command: str, flag: str) -> None:
    """Attach a minimal operational flag to a command (self-test helper)."""
    cli["commands"][command].setdefault("flags", {})[flag] = {
        "summary": "self-test flag.",
    }


# Self-test mutations: (label, target, mutation) — each must be rejected.
# target is which pinned artifact the mutation touches.
SELF_TEST_CASES: list[tuple[str, str, object]] = [
    ("unknown top-level registry key", "cli",
     lambda c, k, s: c.__setitem__("teapot", True)),
    ("unknown per-command key", "cli",
     lambda c, k, s: c["commands"]["status"].__setitem__("colour", "red")),
    ("command path not lowercase", "cli",
     lambda c, k, s: c["commands"].__setitem__("Status", dict(
         c["commands"]["status"]))),
    ("command path with three segments", "cli",
     lambda c, k, s: c["commands"].__setitem__("a b c", dict(
         c["commands"]["status"]))),
    ("joined-form collision", "cli",
     lambda c, k, s: c["commands"].__setitem__("catalog-rebuild", {
         k2: v for k2, v in c["commands"]["catalog rebuild"].items()
         if k2 != "flags"})),
    ("summary over the bound", "cli",
     lambda c, k, s: c["commands"]["status"].__setitem__(
         "summary", "x" * 200)),
    ("phase outside the plan range", "cli",
     lambda c, k, s: c["commands"]["status"].__setitem__("phase", 1)),
    ("owner is not a workspace crate", "cli",
     lambda c, k, s: c["commands"]["status"].__setitem__(
         "owner", "archivist-teapot")),
    ("unknown state-lock kind", "cli",
     lambda c, k, s: c["commands"]["status"].__setitem__(
         "state_lock", "greedy")),
    ("operand of an unbounded kind", "cli",
     lambda c, k, s: c["commands"]["admin approve"].__setitem__(
         "operand", "value")),
    ("stdin kind outside the closed set", "cli",
     lambda c, k, s: c["commands"]["status"].__setitem__("stdin", "tty")),
    ("consumption of an unregistered key", "cli",
     lambda c, k, s: c["commands"]["status"]["keys"].append("teapot.mode")),
    ("duplicate key in one command's list", "cli",
     lambda c, k, s: c["commands"]["status"]["keys"].append(
         "client.state_dir")),
    ("missing required command attribute", "cli",
     lambda c, k, s: c["commands"]["status"].pop("state_lock")),
    ("operational flag colliding with a mode flag", "cli",
     lambda c, k, s: set_key_flag(c, "status", "config")),
    ("operational flag colliding with a key flag", "cli",
     lambda c, k, s: set_key_flag(c, "status", "spool-max-bytes")),
    ("operational flag reused across commands", "cli",
     lambda c, k, s: set_key_flag(c, "daemon", "once")),
    ("value-taking operational flag", "cli",
     lambda c, k, s: c["commands"]["run"]["flags"]["once"].__setitem__(
         "argument", True)),
    ("operational flag outside the name grammar", "cli",
     lambda c, k, s: set_key_flag(c, "run", "Verbose")),
    ("result_schema naming a missing file", "cli",
     lambda c, k, s: c["commands"]["status"].__setitem__(
         "result_schema", "schemas/v1/no-such.json")),
    ("flag-tier key no command consumes", "config",
     lambda c, k, s: k["keys"].__setitem__("teapot.mode", {
         "owner": "archivist-cli", "type": "boolean",
         "tiers": ["flag", "env", "file"], "secret": False,
         "default": False,
         "description": "self-test key.",
         "example": True})),
    ("secret key granted a flag tier", "config",
     lambda c, k, s: k["keys"]["storage.raw_write_credentials_ref"].__setitem__(
         "tiers", ["flag", "env", "file"])),
    ("envelope $id drift", "schema",
     lambda c, k, s: s.__setitem__("$id", SCHEMA_ID + "-x")),
    ("namespace const drift", "schema",
     lambda c, k, s: s["properties"]["schema"].__setitem__(
         "const", "archivist.cli-output/v2")),
    ("envelope opened to unknown members", "schema",
     lambda c, k, s: s.__setitem__("additionalProperties", True)),
    ("envelope member dropped", "schema",
     lambda c, k, s: s["required"].remove("result")),
    ("float leak in the envelope", "schema",
     lambda c, k, s: s["properties"]["result"].__setitem__(
         "type", "number")),
    ("dangling generated_at reference", "schema",
     lambda c, k, s: s["properties"]["generated_at"].__setitem__(
         "$ref", TIMESTAMP_REF.replace("rfc3339-utc-timestamp",
                                       "no-such-timestamp"))),
    ("command-token pattern relaxation", "schema",
     lambda c, k, s: s["properties"]["command"].__setitem__("pattern", "^.+$")),
]


def run_self_test(trio: tuple[dict, dict, dict]) -> int:
    if validate(*trio):
        fail("self-test base: the committed trio itself is invalid")
        return 2

    passed = 0
    failed = 0
    for label, target, mutation in SELF_TEST_CASES:
        copies = copy.deepcopy(trio)
        cli, config, schema = copies
        mutation(cli, config, schema)
        artifacts = {"cli": cli, "config": config, "schema": schema}
        violations = validate(artifacts["cli"], artifacts["config"],
                              artifacts["schema"])
        if violations:
            passed += 1
            print(f"  ok  rejects: {label}")
        else:
            failed += 1
            print(f"  FAIL should reject: {label}")
    print(f"self-test: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 2


def main(argv: list[str]) -> int:
    if "--self-test" in argv[1:]:
        trio = load_trio()
        return 2 if trio is None else run_self_test(trio)
    if argv[1:]:
        fail(f"unknown arguments: {' '.join(argv[1:])}")
        return 2

    trio = load_trio()
    if trio is None:
        return 2
    violations = validate(*trio)
    for violation in violations:
        fail(violation)
    if violations:
        return 2

    cli, config, _ = trio
    commands = cli["commands"]
    operational = sum(
        len(c.get("flags", {})) for c in commands.values()
        if isinstance(c, dict))
    key_flags = sum(
        1 for declared in config["keys"].values()
        if isinstance(declared, dict)
        and "flag" in (declared.get("tiers") or []))
    print(f"agent-archivist CLI registry: {len(commands)} commands, "
          f"{operational} operational flags, {len(MODE_FLAGS)} mode flags, "
          f"{key_flags} key flags")
    print("OK: tools/cli-commands.toml, tools/config-keys.toml, and "
          "schemas/v1/cli-output.json satisfy docs/notes/cli.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
