#!/usr/bin/env python3
"""CLI implementation-coherence gate for Agent Archivist.

The registry side of CLI-002 is ``tools/check-cli.py``'s: it proves the
command, configuration-key, and error-code registries and the output-envelope
schema agree with each other. This tool proves the implementation half — the
end-to-end join between the committed Rust command surface and those same
artifacts, which no other gate scans:

1. **Attachment** (CLI-003, CLI-015) — every ``("path", f as
   CommandHandler)`` tuple and literal ``register_handler("path", ...)`` site
   in the composition sources names a registered command path, no path
   attaches twice, and an attached ``document`` command pins its
   ``result_schema`` (a ``none``-stdout command ships behavior instead).
   Today these rules are enforced only by a composition-time ``expect``; here
   a violation is a gate failure before anything can start.
2. **Vocabulary** (CLI-002, ERR-008, CFG-001) — every ``domain.condition``-
   shaped string literal in the production sources is either a registered
   error code or a registered configuration key. An emitted code the error
   registry does not name, or a key reference outside the configuration
   registry, fails: the runtime's unregistered-code fallback (exit 70, generic
   message) must stay unreachable through a typo.
3. **Key consumption** (CLI-010) — a behavior module's configuration-key
   literals sit within the union of its commands' registry key lists; a shared
   composition module's keys must each be consumed by at least one command
   row. A handler that reads a key its command row does not name is a
   registry lie this gate catches.
4. **Mode flags** (CLI-009) — the runtime parser's mode match arms equal the
   closed CFG-003 set. A mode flag the parser accepts but the registries do
   not pin (or one they pin that the parser dropped) cannot ship.
5. **Operand kinds** (CLI-025) — the runtime operand-kind match arms equal the
   closed registry vocabulary and fall through to ``_ => false``, so an
   unknown kind is a parse refusal, never an acceptance.
6. **Success envelope** (CLI-014) — the runtime namespace constant, the
   members ``canonical_bytes`` serializes, and the command-token length bound
   and lowercase grammar agree with ``schemas/v1/cli-output.json``.
7. **Error body** (ERR-029) — the runtime ``archivist.error/v1`` namespace and
   the members the stderr body serializes agree with
   ``schemas/v1/ingest-error.json``.

Module classification is fail-closed: a Rust file under a scan root that is
neither a listed behavior module, a listed composition module, nor a
``tests.rs`` test module is a gate failure, so a new source file joins the
coherence proof in the commit that adds it.

``--self-test`` runs the validators against mutated copies of the committed
sources (an unregistered attachment, a duplicate, a schema-less document
command, an unregistered code, an off-row key, mode-flag and operand-kind
drift, a lost refusal arm, envelope and error-body drift, an unclassified
module) and fails unless every one is rejected. The committed tree is the
base case and must itself be clean.

The script is standard-library only (``tomllib``), so a clean checkout runs
it before any dependency is fetched.

Usage::

    tools/check-cli-implementation.py [--self-test]
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CLI_REGISTRY = "tools/cli-commands.toml"
CONFIG_REGISTRY = "tools/config-keys.toml"
ERROR_REGISTRY = "tools/error-codes.toml"
ENVELOPE_SCHEMA = "schemas/v1/cli-output.json"
ERROR_BODY_SCHEMA = "schemas/v1/ingest-error.json"
ARTIFACTS = (CLI_REGISTRY, CONFIG_REGISTRY, ERROR_REGISTRY,
             ENVELOPE_SCHEMA, ERROR_BODY_SCHEMA)

# The two scan roots: the composition crate and the CLI engine module. Every
# Rust file under either must be classified (or be a test module).
CLI_SRC = "crates/archivist-cli/src"
ENGINE_SRC = "crates/archivist-client-core/src/cli"

# Behavior modules are bound to the command paths whose registry key lists
# their configuration-key literals must sit within. The binding is the
# module's own documentation: each carries its command's behavior.
BEHAVIOR_MODULES: dict[str, tuple[str, ...]] = {
    f"{CLI_SRC}/operator.rs": ("daemon", "run", "inventory", "status",
                               "verify-state", "doctor"),
    f"{CLI_SRC}/serve.rs": ("serve",),
    f"{CLI_SRC}/probe.rs": ("probe",),
    f"{CLI_SRC}/link.rs": ("link request",),
    f"{CLI_SRC}/authority.rs": ("admin create-authority",),
    f"{CLI_SRC}/approve.rs": ("admin approve",),
    f"{CLI_SRC}/receipt_key.rs": ("admin receipt-key",),
    f"{CLI_SRC}/revoke.rs": ("admin revoke",),
    f"{CLI_SRC}/catalog.rs": ("catalog rebuild",),
}

# Composition modules serve several commands or none: the shared admin
# composition, the binary's entry points, and the registry-driven engine.
# Their key literals must each be consumed by at least one command row.
COMPOSITION_MODULES: tuple[str, ...] = (
    f"{CLI_SRC}/admin.rs",
    f"{CLI_SRC}/lib.rs",
    f"{CLI_SRC}/main.rs",
    f"{ENGINE_SRC}/error.rs",
    f"{ENGINE_SRC}/mod.rs",
    f"{ENGINE_SRC}/output.rs",
    f"{ENGINE_SRC}/parse.rs",
    f"{ENGINE_SRC}/registry.rs",
    f"{ENGINE_SRC}/router.rs",
)

# The closed mode-flag set (CFG-003, CLI-009) — the same pin as
# tools/check-cli.py's MODE_FLAGS; the parser's match arms must equal it.
MODE_FLAGS = frozenset({"json", "non-interactive", "config", "help", "version"})
# The closed operand-kind vocabulary (CLI-025).
OPERAND_KINDS = frozenset({"none", "path", "identifier"})

# `domain.condition` — two lowercase snake segments. Anything else is not
# treated as registry vocabulary.
DOTTED_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
CHAR_LITERAL_RE = re.compile(r"'(?:\\.|[^'\\])'")
TEST_MODULE_RE = re.compile(r"^#\[cfg\(test\)\]", re.MULTILINE)
# A command path: one or two segments, each matching the registry's segment
# grammar (CLI-004), so `verify-state` and `admin approve` both extract.
COMMAND_PATH = r"([a-z][a-z0-9-]{0,31}(?: [a-z][a-z0-9-]{0,31})?)"
HANDLER_TUPLE_RE = re.compile(
    rf'\(\s*"{COMMAND_PATH}"\s*,'
    r"\s*[a-z_][a-z0-9_]*\s+as\s+CommandHandler\s*\)")
REGISTER_HANDLER_RE = re.compile(rf'register_handler\(\s*"{COMMAND_PATH}"')
ARM_RE = re.compile(
    r'((?:"[a-z][a-z0-9-]+"\s*\|\s*)*"[a-z][a-z0-9-]+")\s*=>')
REFUSAL_ARM_RE = re.compile(r"_\s*=>\s*false")
NAMESPACE_DECL_RE = re.compile(
    r'const\s+OUTPUT_NAMESPACE:\s*&str\s*=\s*"([^"]+)"')
TOKEN_BOUND_RE = re.compile(r"text\.len\(\)\s*<=\s*(\d+)")
MEMBER_SET_RE = re.compile(r'object\.set\(\s*"([a-z_]+)"')
LOWERCASE_GRAMMAR_TOKEN = "is_ascii_lowercase"
OPERAND_VALIDATOR = "fn valid_operand_count"


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def is_module_path(path: str) -> bool:
    """Whether `path` is a Rust file under a scan root (test modules are
    classified too, as exempt, so a new test file cannot smuggle a
    production module past the classification check)."""
    if not path.endswith(".rs"):
        return False
    return (path.startswith(CLI_SRC + "/") or path.startswith(ENGINE_SRC + "/"))


def is_test_module(path: str) -> bool:
    return Path(path).name == "tests.rs"


def production_code(text: str) -> str:
    """Comment-stripped code of a module's production prefix: everything
    before its `#[cfg(test)]` test module. Test modules carry synthetic
    fixtures and unregistered shapes by design and stay out of the
    vocabulary scan."""
    stripped = rust_code(text)
    marker = TEST_MODULE_RE.search(stripped)
    return stripped[:marker.start()] if marker else stripped


def rust_code(text: str) -> str:
    """Strip line and (nested) block comments while preserving string and
    character literal contents, so literal scans see code and string
    contents but never doc prose. Unrecognized shapes fail toward
    visibility: an unterminated literal or comment surfaces as a scan
    miss, and every scan miss the validators depend on is an error."""
    out: list[str] = []
    index = 0
    length = len(text)
    in_string = False
    in_line_comment = False
    block_depth = 0
    while index < length:
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < length:
                out.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                out.append(char)
            index += 1
            continue
        if block_depth:
            if text.startswith("/*", index):
                block_depth += 1
                index += 2
                continue
            if text.startswith("*/", index):
                block_depth -= 1
                index += 2
                continue
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            in_line_comment = True
            index += 2
            continue
        if text.startswith("/*", index):
            block_depth = 1
            index += 2
            continue
        if char == "'":
            literal = CHAR_LITERAL_RE.match(text, index)
            if literal:
                out.append(literal.group(0))
                index = literal.end()
                continue
            # A lifetime tick, not a literal.
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def dotted_tokens(code: str) -> set[str]:
    """The `domain.condition`-shaped string literals in comment-stripped
    code."""
    return {match for match in re.findall(r'"((?:\\.|[^"\\])*)"', code)
            if DOTTED_RE.match(match)}


def match_arm_names(region: str) -> set[str]:
    """The string-literal match arms in a code region, including or-pattern
    groups."""
    names: set[str] = set()
    for match in ARM_RE.finditer(region):
        names.update(re.findall(r'"([a-z][a-z0-9-]+)"', match.group(1)))
    return names


def schema_properties(schema: object, what: str, errors: list[str]) -> dict:
    if not isinstance(schema, dict) or not isinstance(schema.get("properties"), dict):
        errors.append(f"{what}: the schema has no properties table")
        return {}
    return schema["properties"]


def validate(texts: dict[str, str]) -> list[str]:
    """Return every implementation-coherence violation in the scanned
    tree. `texts` maps repository-relative paths to file contents."""
    errors: list[str] = []
    missing = [path for path in (*ARTIFACTS, *BEHAVIOR_MODULES,
                                 *COMPOSITION_MODULES) if path not in texts]
    if missing:
        return [f"scan inputs missing: {sorted(missing)}"]

    try:
        cli_registry = tomllib.loads(texts[CLI_REGISTRY])
        config_registry = tomllib.loads(texts[CONFIG_REGISTRY])
        error_registry = tomllib.loads(texts[ERROR_REGISTRY])
        envelope_schema = json.loads(texts[ENVELOPE_SCHEMA])
        error_body_schema = json.loads(texts[ERROR_BODY_SCHEMA])
    except (tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
        return [f"a pinned artifact is unparsable: {exc}"]

    commands = cli_registry.get("commands")
    if not isinstance(commands, dict) or not commands:
        return ["the cli registry declares no commands"]
    config_keys = config_registry.get("keys")
    if not isinstance(config_keys, dict):
        return ["the config registry declares no keys"]
    codes_table = error_registry.get("codes")
    registered_codes = (set(codes_table)
                        if isinstance(codes_table, dict) else set())

    # --- module classification (fail-closed) ---------------------------------
    production: dict[str, str] = {}
    for path in sorted(texts):
        if not is_module_path(path):
            continue
        if is_test_module(path):
            continue
        if path not in BEHAVIOR_MODULES and path not in COMPOSITION_MODULES:
            errors.append(f"{path}: a Rust module under a CLI scan root is "
                          "not classified; it must join the coherence proof "
                          "in the commit that adds it")
            continue
        production[path] = production_code(texts[path])

    # --- vocabulary: every emitted token is registered -----------------------
    for path, code in production.items():
        for token in sorted(dotted_tokens(code)):
            if token not in registered_codes and token not in config_keys:
                errors.append(f"{path}: {token!r} is neither a registered "
                              "error code nor a registered configuration key "
                              "(CLI-002, ERR-008, CFG-001)")

    # --- key consumption against the registry rows ---------------------------
    row_keys = {name: set(row.get("keys") or []) if isinstance(row, dict) else set()
                for name, row in commands.items()}
    consumed_anywhere: set[str] = set()
    for keys in row_keys.values():
        consumed_anywhere |= keys
    for path, command_names in BEHAVIOR_MODULES.items():
        code = production.get(path)
        if code is None:
            continue
        for token in sorted(dotted_tokens(code)):
            if token in config_keys and not any(
                    token in row_keys[name] for name in command_names):
                errors.append(f"{path}: consumes key {token!r}, which no "
                              f"registry row of {sorted(command_names)} "
                              "lists (CLI-010)")
    for path in COMPOSITION_MODULES:
        code = production.get(path)
        if code is None:
            continue
        for token in sorted(dotted_tokens(code)):
            if token in config_keys and token not in consumed_anywhere:
                errors.append(f"{path}: composition key {token!r} is listed "
                              "by no command's registry row (CLI-002)")

    # --- attachment -----------------------------------------------------------
    attached: dict[str, str] = {}
    for path, code in production.items():
        sites = [match.group(1) for match in HANDLER_TUPLE_RE.finditer(code)]
        sites += [match.group(1) for match in REGISTER_HANDLER_RE.finditer(code)]
        for command_name in sites:
            if command_name in attached and attached[command_name] != path:
                errors.append(f"{path}: command {command_name!r} is attached "
                              f"again after {attached[command_name]!r}; a "
                              "command ships one handler (CLI-003)")
            elif command_name in attached:
                errors.append(f"{path}: command {command_name!r} is attached "
                              "twice in one module; a command ships one "
                              "handler (CLI-003)")
            else:
                attached[command_name] = path
    for command_name in sorted(attached):
        if command_name not in commands:
            errors.append(f"{attached[command_name]}: attached command "
                          f"{command_name!r} is not in the registry (CLI-003)")
            continue
        row = commands[command_name]
        if not isinstance(row, dict):
            continue
        if row.get("stdout") == "document" and not row.get("result_schema"):
            errors.append(f"{attached[command_name]}: attached command "
                          f"{command_name!r} has stdout=document but pins no "
                          "result_schema; a command with no result schema has "
                          "not shipped (CLI-015)")

    # A row is available once it has either shipped a result document or
    # explicitly declares that it emits no stdout. Those are the commands the
    # binary advertises as runnable; document rows without a result schema are
    # phase reservations and remain intentionally unbound. Check the reverse
    # direction as well as the attachment direction above: a handler can name
    # a valid row while a newly shipped row silently lacks a production
    # handler (CLI-002, CLI-003, CLI-015).
    for command_name, row in commands.items():
        if not isinstance(row, dict):
            continue
        available = row.get("stdout") == "none" or bool(row.get("result_schema"))
        if available and command_name not in attached:
            errors.append(f"registry command {command_name!r} is available but "
                          "has no attached handler (CLI-003, CLI-032)")
        if available and row.get("stdout") == "document" \
                and not row.get("result_schema"):
            errors.append(f"registry command {command_name!r} is available as "
                          "a document but has no result_schema (CLI-015)")

    # --- mode flags and operand kinds in the runtime parser -------------------
    parse_code = production.get(f"{ENGINE_SRC}/parse.rs")
    if parse_code is not None:
        split = parse_code.find(OPERAND_VALIDATOR)
        if split < 0:
            errors.append(f"parse.rs: the operand-kind validator "
                          f"({OPERAND_VALIDATOR}) is missing; the gate cannot "
                          "pin the operand vocabulary (CLI-025)")
        else:
            mode_arms = match_arm_names(parse_code[:split])
            if mode_arms != set(MODE_FLAGS):
                errors.append(f"parse.rs: mode-flag match arms "
                              f"{sorted(mode_arms)} are not the closed "
                              f"CFG-003 set {sorted(MODE_FLAGS)} (CLI-009)")
            operand_arms = match_arm_names(parse_code[split:])
            if operand_arms != set(OPERAND_KINDS):
                errors.append(f"parse.rs: operand-kind match arms "
                              f"{sorted(operand_arms)} are not the closed "
                              f"vocabulary {sorted(OPERAND_KINDS)} (CLI-025)")
            if not REFUSAL_ARM_RE.search(parse_code[split:]):
                errors.append("parse.rs: the operand-kind match lost its "
                              "`_ => false` refusal; an unknown kind must "
                              "fail parsing, never be accepted (CLI-025)")

    # --- the success envelope (CLI-014) ---------------------------------------
    envelope = schema_properties(envelope_schema, "cli-output schema", errors)
    output_code = production.get(f"{ENGINE_SRC}/output.rs")
    if envelope and output_code is not None:
        members = (set(envelope_schema.get("required") or [])
                   if isinstance(envelope_schema, dict) else set())
        declared = NAMESPACE_DECL_RE.search(output_code)
        schema_member = envelope.get("schema")
        ns_const = (schema_member.get("const")
                    if isinstance(schema_member, dict) else None)
        if declared is None:
            errors.append("output.rs: the OUTPUT_NAMESPACE constant is "
                          "missing; the gate cannot pin the envelope "
                          "namespace (CLI-014)")
        elif declared.group(1) != ns_const:
            errors.append(f"output.rs: envelope namespace "
                          f"{declared.group(1)!r} drifts from the schema "
                          f"const {ns_const!r} (CLI-014)")
        written = set(MEMBER_SET_RE.findall(output_code))
        if not written:
            errors.append("output.rs: no envelope members are serialized "
                          "where the gate expects them (CLI-014)")
        elif written != members:
            errors.append(f"output.rs: serialized members {sorted(written)} "
                          f"are not the closed envelope {sorted(members)} "
                          "(CLI-014)")
        command_member = envelope.get("command")
        max_length = (command_member.get("maxLength")
                      if isinstance(command_member, dict) else None)
        bound = TOKEN_BOUND_RE.search(output_code)
        if bound is None:
            errors.append("output.rs: the command-token length bound is "
                          "missing; the gate cannot pin the token grammar "
                          "(CLI-014, CLI-005)")
        elif max_length is None or int(bound.group(1)) != max_length:
            errors.append(f"output.rs: command-token bound "
                          f"{bound.group(1) if bound else None} drifts from "
                          f"the schema maxLength {max_length!r} (CLI-014)")
        if output_code.count(LOWERCASE_GRAMMAR_TOKEN) < 2:
            errors.append("output.rs: the command-token validator no longer "
                          "pins the lowercase token grammar the schema's "
                          "pattern declares (CLI-014)")

    # --- the error body (ERR-029) ---------------------------------------------
    body = schema_properties(error_body_schema, "error-body schema", errors)
    error_code = production.get(f"{ENGINE_SRC}/error.rs")
    if body and error_code is not None:
        members = (set(error_body_schema.get("required") or [])
                   if isinstance(error_body_schema, dict) else set())
        written = set(MEMBER_SET_RE.findall(error_code))
        if not written:
            errors.append("error.rs: no diagnostic members are serialized "
                          "where the gate expects them (ERR-029)")
        elif written != members:
            errors.append(f"error.rs: diagnostic members {sorted(written)} "
                          f"are not the closed error body {sorted(members)}")
        schema_member = body.get("schema")
        ns_const = (schema_member.get("const")
                    if isinstance(schema_member, dict) else None)
        if ns_const is None or f'"{ns_const}"' not in error_code:
            errors.append(f"error.rs: the {ns_const!r} namespace literal is "
                          "missing or has drifted from the error-body schema")

    return errors


def load_texts() -> dict[str, str] | None:
    """Load every scanned artifact and module from the committed tree."""
    paths = [ROOT / path for path in ARTIFACTS]
    for root in (CLI_SRC, ENGINE_SRC):
        paths.extend(sorted((ROOT / root).rglob("*.rs")))
    texts: dict[str, str] = {}
    for path in paths:
        relative = path.relative_to(ROOT).as_posix()
        try:
            texts[relative] = path.read_text(encoding="utf-8")
        except OSError as exc:
            fail(f"{relative}: unreadable ({exc})")
            return None
    return texts


def insert_production(text: str, snippet: str) -> str:
    """Insert a fixture before the test module so it lands in the scanned
    production prefix."""
    marker = TEST_MODULE_RE.search(text)
    if marker is None:
        return text + snippet
    return text[:marker.start()] + snippet + "\n" + text[marker.start():]


OPERATOR = f"{CLI_SRC}/operator.rs"
SERVE = f"{CLI_SRC}/serve.rs"
PROBE = f"{CLI_SRC}/probe.rs"
PARSE = f"{ENGINE_SRC}/parse.rs"
OUTPUT = f"{ENGINE_SRC}/output.rs"
ERROR_SRC = f"{ENGINE_SRC}/error.rs"

# Self-test mutations: (label, target, mutation) — each must be rejected.
SELF_TEST_CASES: list[tuple[str, str, object]] = [
    ("attached command outside the registry", OPERATOR,
     lambda t: t.replace('("daemon", daemon as CommandHandler)',
                         '("daemn", daemon as CommandHandler)', 1)),
    ("a command attached twice", SERVE,
     lambda t: t.replace(
         '[("serve", serve as CommandHandler)]',
         '[("serve", serve as CommandHandler),\n'
         '         ("serve", serve as CommandHandler)]', 1)),
    ("an available command without a handler", OPERATOR,
     lambda t: t.replace(
         '        ("status", status as CommandHandler),\n', "", 1)),
    ("attached document command with no result schema", CLI_REGISTRY,
     lambda t: t.replace('result_schema = "schemas/v1/cli-status.json"\n',
                         "", 1)),
    ("an emitted code the error registry does not name", OPERATOR,
     lambda t: insert_production(
         t, '\nconst TEAPOT: &str = "teapot.not_registered";\n')),
    ("a consumed key no command row of the module lists", PROBE,
     lambda t: insert_production(
         t, '\nconst TEAPOT_KEY: &str = "admin.credentials_ref";\n')),
    ("a mode flag outside the closed set", PARSE,
     lambda t: t.replace(
         '"json" | "non-interactive" | "help" | "version" =>',
         '"json" | "non-interactive" | "help" | "version" | "trace" =>', 1)),
    ("a mode flag renamed in the parser", PARSE,
     lambda t: t.replace(
         '"json" | "non-interactive" | "help" | "version" =>',
         '"json" | "non-interactive" | "halp" | "version" =>', 1)),
    ("an operand kind outside the closed vocabulary", PARSE,
     lambda t: t.replace('"identifier" =>', '"id" =>', 1)),
    ("an operand kind with no refusal arm", PARSE,
     lambda t: t.replace("_ => false", "_ => true", 1)),
    ("the operand-kind validator renamed away", PARSE,
     lambda t: t.replace(OPERAND_VALIDATOR, "fn operand_count", 1)),
    ("an envelope member renamed", OUTPUT,
     lambda t: t.replace('"generated_at",', '"generated",', 1)),
    ("envelope namespace drift", OUTPUT,
     lambda t: t.replace(
         'const OUTPUT_NAMESPACE: &str = "archivist.cli-output/v1"',
         'const OUTPUT_NAMESPACE: &str = "archivist.cli-output/v2"', 1)),
    ("command-token bound drift", OUTPUT,
     lambda t: t.replace("text.len() <= 65", "text.len() <= 80", 1)),
    ("the lowercase token grammar dropped", OUTPUT,
     lambda t: t.replace("first.is_ascii_lowercase()", "first.is_ascii_hexdigit()", 1)),
    ("a diagnostic member renamed", ERROR_SRC,
     lambda t: t.replace('object.set("request_id"',
                         'object.set("req_id"', 1)),
    ("error-body namespace drift", ERROR_SRC,
     lambda t: t.replace('"archivist.error/v1".to_owned()',
                         '"archivist.error/v2".to_owned()', 1)),
    ("envelope schema bound drift", ENVELOPE_SCHEMA,
     lambda t: t.replace('"maxLength": 65,', '"maxLength": 80,', 1)),
    ("an unclassified module under a scan root",
     f"{CLI_SRC}/teapot.rs", lambda t: "//! unclassified\n"),
]


def run_self_test(texts: dict[str, str]) -> int:
    base = validate(texts)
    if base:
        fail("self-test base: the committed tree itself violates the "
             "implementation join")
        for violation in base:
            fail(violation)
        return 2

    passed = 0
    failed = 0
    for label, target, mutation in SELF_TEST_CASES:
        mutated = dict(texts)
        # A synthetic target (the unclassified-module case) has no source
        # text; the mutation fabricates it.
        mutated[target] = mutation(texts.get(target, ""))  # type: ignore[operator]
        if mutated[target] == texts.get(target, ""):
            failed += 1
            print(f"  FAIL mutation did not apply: {label}")
            continue
        if validate(mutated):
            passed += 1
            print(f"  ok  rejects: {label}")
        else:
            failed += 1
            print(f"  FAIL should reject: {label}")
    print(f"self-test: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 2


def main(argv: list[str]) -> int:
    texts = load_texts()
    if texts is None:
        return 2
    if "--self-test" in argv[1:]:
        return run_self_test(texts)
    if argv[1:]:
        fail(f"unknown arguments: {' '.join(argv[1:])}")
        return 2

    violations = validate(texts)
    for violation in violations:
        fail(violation)
    if violations:
        return 2

    behavior = sum(len(paths) for paths in BEHAVIOR_MODULES.values())
    print(f"agent-archivist CLI implementation coherence: "
          f"{len(attached_of(texts))} attached commands, {behavior} behavior "
          f"commands, {len(BEHAVIOR_MODULES) + len(COMPOSITION_MODULES)} "
          "modules scanned")
    print("OK: the archivist-cli and client-core::cli implementation agrees "
          f"with {CLI_REGISTRY}, {CONFIG_REGISTRY}, {ERROR_REGISTRY}, "
          f"{ENVELOPE_SCHEMA}, and {ERROR_BODY_SCHEMA}")
    return 0


def attached_of(texts: dict[str, str]) -> set[str]:
    """The attached command set, for the summary line."""
    attached: set[str] = set()
    for path in (*BEHAVIOR_MODULES, *COMPOSITION_MODULES):
        code = production_code(texts[path])
        attached.update(match.group(1)
                        for match in HANDLER_TUPLE_RE.finditer(code))
    return attached


if __name__ == "__main__":
    sys.exit(main(sys.argv))
