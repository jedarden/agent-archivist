#!/usr/bin/env python3
"""Schema-to-Rust bindings generator for ``archivist-protocol``.

Implements the generated-bindings half of the plan Phase 1 exit gate
(docs/plan/plan.md, Section 8, Phase 1): "the normative documents, schemas,
generated bindings, fixtures, and verifier are updated and pass together in
one commit". The schema-derived knowledge the protocol crate speaks — the
schema URN space, the closed enum token sets, the pinned version and plan
constants, and the reserved-field name lists — used to be re-typed by hand
in ``crates/archivist-protocol/src/vocabulary.rs`` and ``envelope.rs``,
with only ``tools/check-wire-schemas.py`` checking the schemas' internal
coherence. This generator closes that gap: it emits
``crates/archivist-protocol/src/bindings.rs`` — a crate-private module of
constants, clearly marked generated — from the checked-in ``schemas/v1``
family.

What is extracted, mechanically and fail-closed (an extraction rule the
generator does not model is a generation error, never a silent skip):

1. the schema URN space: one constant per top-level schema, read from the
   schema's own ``$id`` (the value ``tools/check-wire-schemas.py`` pins),
   plus the common prefix;
2. the const-valued top-level properties of every schema — the pinned
   version axes (``protocol_version``, ``receipt_version``, ...) and the
   fixed request members (``http_method``, ``route``, the error
   ``schema`` namespace);
3. the scalar top-level ``x-archivist`` metadata of every schema — the
   plan-pinned limits (``canonicalMaxBytes``,
   ``authorizationWindowSeconds``, ...) and the declared behaviours
   (``floats``, ``unknownFields``);
4. every ``x-archivist.reservedFields`` list, order-preserved;
5. every top-level property name list;
6. every closed ``enum`` in the family — ``$defs`` shapes, properties, and
   nested array items — as a token slice plus its ``bearing`` and
   ``failClosed`` metadata.

The module is crate-private (``pub(crate)`` constants inside a private
``mod bindings``), so the public surface of ``archivist-protocol`` does
not grow. The vocabulary's closed enums source their ``tokens()`` slices
from it and the envelope sources its pinned versions, byte cap,
reserved-field list, and field-name list; a hand-written test in each
module pins the remaining hand-written mapping against the generated
values, so a schema edit without regeneration fails the test suite and a
hand edit of the generated file fails the drift gate.

Determinism: schema iteration, extraction order, and emission are fully
sorted, so regeneration is byte-identical everywhere; there is no
timestamp, host, or tool-version input.

Modes::

    tools/bindingsgen.py --generate [OUTPUT]  # write the module
    tools/bindingsgen.py --verify             # byte-compare against committed
    tools/bindingsgen.py --self-test          # prove the rejection paths

Exit codes: 0 pass; 2 regeneration drift or a missing committed module
(``--verify``) or a failed proof (``--self-test``); 3 a fail-closed
generation error. Standard-library only, so a clean checkout runs it
before any dependency is fetched. Its output names schemas, paths, and
rules only.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas" / "v1"
DEFAULT_OUTPUT = REPO_ROOT / "crates" / "archivist-protocol" / "src" / "bindings.rs"

# Path segments that locate an enum but carry no naming weight: the const
# name is built from the remaining segments (stem, def name, property name).
STRUCTURAL_KEYS = ("$defs", "properties", "items")

# Line width the emitter wraps long token lists at. The generated module is
# rustfmt-skipped (the attribute lives on `mod bindings` in lib.rs), so this
# is a readability bound on the emitted text, not a formatter contract.
MAX_LINE = 96


class GenerationError(Exception):
    """A fail-closed extraction error: the family holds something the
    generator does not model, and emitting nothing is the only safe output."""


def load_family() -> dict[str, dict]:
    """Every top-level schema, keyed by filename stem, in sorted order."""
    schemas: dict[str, dict] = {}
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GenerationError(f"{path}: unreadable or invalid JSON ({exc})") from exc
        if not isinstance(doc, dict):
            raise GenerationError(f"{path}: top level must be an object")
        schemas[path.stem] = doc
    if not schemas:
        raise GenerationError(f"{SCHEMA_DIR}: no schemas found")
    return schemas


def const_name(*parts: str) -> str:
    """Join identifier fragments into a SCREAMING_SNAKE_CASE const name,
    splitting the camelCase metadata keys at their case boundaries."""
    words: list[str] = []
    for part in parts:
        part = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", part)
        words.extend(
            word for word in re.sub(r"[^0-9A-Za-z_]+", "_", part).split("_")
            if word
        )
    name = "_".join(words).upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
        raise GenerationError(f"fragments {parts!r} produce an invalid name {name!r}")
    return name


def rust_string(value: str) -> str:
    """A Rust string literal: backslash and quote escaped, everything else
    verbatim UTF-8."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def doc_text(text: str) -> str:
    """Doc-comment-safe prose: square brackets become parentheses so rustdoc
    never reads a bracketed fragment as an intra-doc link."""
    return text.replace("[", "(").replace("]", ")")


class Binding:
    """One emitted constant: name, type, value expression, and doc lines."""

    def __init__(self, name: str, rust_type: str, value: str, doc: list[str]):
        self.name = name
        self.rust_type = rust_type
        self.value = value
        self.doc = [doc_text(line) for line in doc]


def scalar_binding(name: str, value: object, doc: list[str],
                   integer_type: str = "i64") -> Binding:
    """A JSON scalar (bool, integer, or string) as a Rust constant; anything
    else is outside the model and fails generation. Integer metadata renders
    in the caller-chosen integer type; a negative value cannot.
    """
    if isinstance(value, bool):
        return Binding(name, "bool", "true" if value else "false", doc)
    if isinstance(value, int):
        if integer_type == "usize":
            if value < 0:
                raise GenerationError(
                    f"{name}: negative value {value} cannot be a usize"
                )
            return Binding(name, "usize", str(value), doc)
        return Binding(name, "i64", str(value), doc)
    if isinstance(value, str):
        return Binding(name, "&str", rust_string(value), doc)
    raise GenerationError(
        f"{name}: unsupported const value {type(value).__name__} (only bool, "
        "integer, and string constants are modelled)"
    )


def string_list_binding(name: str, values: list, doc: list[str],
                        rust_type: str) -> Binding:
    """A list of strings as a Rust array or slice (a slice type renders as a
    `&`-referenced value); a non-string member fails generation."""
    for value in values:
        if not isinstance(value, str):
            raise GenerationError(
                f"{name}: non-string member {value!r} in a string list"
            )
    rendered = [rust_string(value) for value in values]
    if len(f"pub(crate) const {name}: {rust_type} = [{', '.join(rendered)}];") <= MAX_LINE \
            or not rendered:
        value = f"[{', '.join(rendered)}]"
    else:
        inner = ",\n    ".join(rendered)
        value = f"[\n    {inner},\n]"
    if rust_type.startswith("&"):
        value = f"&{value}"
    return Binding(name, rust_type, value, doc)


def urn_prefix(ids: list[str]) -> str:
    """The common URN prefix, cut at its last colon; no shared prefix is a
    generation error."""
    common = ""
    for character_tuple in zip(*ids):
        chars = set(character_tuple)
        if len(chars) != 1:
            break
        common += chars.pop()
    cut = common.rfind(":")
    if cut <= 0:
        raise GenerationError(f"schema $ids share no URN prefix: {sorted(ids)[:3]}")
    return common[: cut + 1]


def collect_enum_bindings(stem: str, doc: dict) -> list[Binding]:
    """Every enum node in one schema, named by its path below the root."""
    found: list[tuple[list[str], dict]] = []

    def walk(node: object, parts: list[str]) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("enum"), list):
                found.append((parts, node))
            for key, value in node.items():
                if key == "enum":
                    continue
                child = parts if key in STRUCTURAL_KEYS else parts + [key]
                walk(value, child)
        elif isinstance(node, list):
            for value in node:
                walk(value, parts)

    walk(doc, [])
    bindings: list[Binding] = []
    seen: dict[str, list[str]] = {}
    for parts, node in sorted(found, key=lambda item: item[0]):
        name = const_name("ENUM", stem, *parts)
        if name in seen:
            raise GenerationError(
                f"{stem}: enum const name {name} collides between "
                f"{seen[name]} and {parts}"
            )
        seen[name] = parts
        tokens = node["enum"]
        for token in tokens:
            if not isinstance(token, str):
                raise GenerationError(
                    f"{stem}: enum at {'/'.join(parts)} holds non-string "
                    f"token {token!r} (only string tokens are modelled)"
                )
        meta = node.get("x-archivist", {})
        bearing = meta.get("bearing", "unspecified")
        fail_closed = meta.get("failClosed") is True
        location = "/".join(parts) if parts else "(root)"
        doc = [
            f"Closed enum tokens of `{location}` in `schemas/v1/{stem}.json`.",
            f"Bearing `{bearing}`; fail-closed: {str(fail_closed).lower()}.",
            "Schema order is wire order; unknown values fail closed on the",
            "wire (plan Section 7.1).",
        ]
        bindings.append(
            string_list_binding(f"{name}_TOKENS", tokens, doc, "&[&str]")
        )
        bindings.append(
            Binding(f"{name}_BEARING", "&str", rust_string(str(bearing)),
                    [f"Bearing of the `{location}` enum in "
                     f"`schemas/v1/{stem}.json`."])
        )
        bindings.append(
            Binding(f"{name}_FAIL_CLOSED", "bool",
                    "true" if fail_closed else "false",
                    [f"Whether the `{location}` enum in "
                     f"`schemas/v1/{stem}.json` is declared fail-closed."]
                    )
        )
    return bindings


def collect_schema_bindings(stem: str, doc: dict,
                            prefix: str) -> list[Binding]:
    """Every constant one schema contributes, in emission order."""
    bindings: list[Binding] = []

    schema_id = doc.get("$id")
    if not isinstance(schema_id, str):
        raise GenerationError(f"{stem}: missing string $id")
    if schema_id != prefix + stem:
        raise GenerationError(
            f"{stem}: $id {schema_id!r} does not match the URN space "
            f"(expected {prefix + stem!r})"
        )
    bindings.append(Binding(
        f"SCHEMA_URN_{const_name(stem)}", "&str", rust_string(schema_id),
        [f"The canonical schema URN of `schemas/v1/{stem}.json`, read from",
         "the schema's own `$id`."],
    ))

    properties = doc.get("properties", {})
    if not isinstance(properties, dict):
        raise GenerationError(f"{stem}: properties must be an object")
    for field in sorted(properties):
        node = properties[field]
        if isinstance(node, dict) and "const" in node:
            bindings.append(scalar_binding(
                const_name(stem, field), node["const"],
                [f"Pinned const of `{field}` in `schemas/v1/{stem}.json`;",
                 "an unknown value fails closed on the wire."],
            ))

    meta = doc.get("x-archivist", {})
    if not isinstance(meta, dict):
        raise GenerationError(f"{stem}: x-archivist metadata must be an object")
    for key in sorted(meta):
        value = meta[key]
        if isinstance(value, (dict, list)):
            continue  # structured metadata stays schema-only
        bindings.append(scalar_binding(
            # The META segment keeps metadata constants out of the property
            # constant's name space: some schemas carry an x-archivist key
            # and a same-named property (ingest-request `route`). Metadata
            # integers are limits and sizes, so they render as usize.
            const_name(stem, "META", key), value,
            [f"The `{key}` metadata of `schemas/v1/{stem}.json`."],
            integer_type="usize",
        ))

    if "reservedFields" in meta:
        reserved = meta["reservedFields"]
        if not isinstance(reserved, list):
            raise GenerationError(f"{stem}: reservedFields must be a list")
        bindings.append(string_list_binding(
            const_name(stem, "RESERVED_FIELDS"), reserved,
            [f"Reserved per-attempt, server, or foreign names of",
             f"`schemas/v1/{stem}.json` (x-archivist.reservedFields), in",
             "schema order: names the record rejects outright, so retries",
             "cannot fork identity on them."],
            f"[&str; {len(reserved)}]",
        ))

    if properties:
        bindings.append(string_list_binding(
            const_name(stem, "FIELD_NAMES"), sorted(properties),
            [f"Every top-level member name `schemas/v1/{stem}.json` defines,",
             "alphabetical: the known-name set against which unknown members",
             "are recognized."],
            f"[&str; {len(properties)}]",
        ))

    bindings.extend(collect_enum_bindings(stem, doc))
    return bindings


def render_module(schemas: dict[str, dict]) -> str:
    """The full generated module text for a loaded family."""
    prefix = urn_prefix([doc.get("$id", "") for doc in schemas.values()])
    header = f"""\
// SPDX-License-Identifier: Apache-2.0

//! GENERATED FILE - DO NOT EDIT.
//!
//! Schema-derived bindings for the `schemas/v1` wire family: the schema URN
//! space, the closed enum token sets with their bearing and fail-closed
//! metadata, the pinned version and plan constants, and the reserved-field
//! and member-name lists. Emitted from the checked-in JSON Schemas by
//! `tools/bindingsgen.py`.
//!
//! Regenerate with `python3 tools/bindingsgen.py` in the same commit as any
//! schema change. `tools/bindingsgen.py --verify` byte-compares this file
//! against a fresh regeneration in the definition-of-done fast lane, so a
//! hand edit or an unregenerated schema change fails the gate. The module
//! is crate-private: the public surface of `archivist-protocol` does not
//! grow. `vocabulary` sources its closed-enum token slices here, and
//! `envelope` sources its pinned versions, canonical byte cap, reserved-
//! field list, and member-name list; their tests pin the hand-written
//! mappings against these values.
//!
//! Formatting is rustfmt-skipped (the attribute lives on the module
//! declaration in lib.rs) so regeneration is byte-exact and independent of
//! any formatter version.

/// The URN prefix every schema of the family shares, derived from the
/// `$id` values themselves.
pub(crate) const SCHEMA_URN_PREFIX: &str = {rust_string(prefix)};
"""
    sections = [header.rstrip("\n")]
    seen_names: dict[str, str] = {}
    for stem in sorted(schemas):
        bindings = collect_schema_bindings(stem, schemas[stem], prefix)
        for binding in bindings:
            if binding.name in seen_names:
                raise GenerationError(
                    f"{stem}: const name {binding.name} collides with the "
                    f"one emitted for {seen_names[binding.name]}"
                )
            seen_names[binding.name] = stem
        block = "\n\n".join(
            "\n".join(f"/// {line}" for line in binding.doc)
            + f"\npub(crate) const {binding.name}: {binding.rust_type} = {binding.value};"
            for binding in bindings
        )
        sections.append(block)
    return "\n\n".join(sections) + "\n"


def first_difference(generated: bytes, committed: bytes) -> str | None:
    """The first textual difference, or None when byte-identical."""
    gen_lines = generated.decode("utf-8").split("\n")
    committed_lines = committed.decode("utf-8").split("\n")
    for index, (expected, found) in enumerate(
        zip(gen_lines, committed_lines), start=1
    ):
        if expected != found:
            return (
                f"line {index}: regenerated {expected!r} != committed {found!r}"
            )
    if len(gen_lines) != len(committed_lines):
        return (
            f"line count differs: regenerated {len(gen_lines)} vs committed "
            f"{len(committed_lines)}"
        )
    return None


def summarize(schemas: dict[str, dict], text: str) -> str:
    enums = sum(1 for line in text.split("\n") if "_TOKENS: &[&str]" in line)
    return (
        f"{len(schemas)} schemas, {enums} closed enums, "
        f"{text.count('pub(crate) const')} constants"
    )


def run_generate(argv: list[str]) -> int:
    output = Path(argv[0]) if argv else DEFAULT_OUTPUT
    try:
        schemas = load_family()
        text = render_module(schemas)
    except GenerationError as exc:
        fail(str(exc))
        return 3
    output.write_text(text, encoding="utf-8")
    print(f"generated {output}: {summarize(schemas, text)}")
    return 0


def run_verify() -> int:
    try:
        schemas = load_family()
        text = render_module(schemas)
    except GenerationError as exc:
        fail(str(exc))
        return 3
    if not DEFAULT_OUTPUT.is_file():
        fail(f"{DEFAULT_OUTPUT}: missing committed bindings module")
        return 2
    report = first_difference(text.encode("utf-8"), DEFAULT_OUTPUT.read_bytes())
    if report is not None:
        fail(f"{DEFAULT_OUTPUT}: committed bindings drifted from the schemas")
        fail(f"  {report}")
        fail("  regenerate with: python3 tools/bindingsgen.py --generate")
        return 2
    print(f"agent-archivist protocol bindings: {summarize(schemas, text)}")
    print(f"OK: {DEFAULT_OUTPUT} matches regeneration from {SCHEMA_DIR}")
    return 0


def run_self_test() -> int:
    try:
        base = load_family()
        generated = render_module(base).encode("utf-8")
    except GenerationError as exc:
        fail(f"self-test base: the committed family does not generate ({exc})")
        return 3

    def mutated_probe(label: str, mutate) -> tuple[str, bool]:
        try:
            family = copy.deepcopy(base)
            mutate(family)
            drifted = render_module(family).encode("utf-8") != generated
        except GenerationError as exc:
            # A fail-closed generation error is itself a detected change.
            drifted = True
            label = f"{label} (rejected: {exc})"
        return label, drifted

    checks: list[tuple[str, bool]] = []
    checks.append((
        "regeneration is deterministic",
        render_module(base).encode("utf-8") == generated,
    ))

    def add_enum_token(family: dict) -> None:
        family["common"]["$defs"]["storage-profile"]["enum"].append("zstd-v2")

    checks.append(mutated_probe("an added enum token changes the output",
                                add_enum_token))

    def flip_version_const(family: dict) -> None:
        family["ingest-envelope"]["properties"]["protocol_version"]["const"] = 2

    checks.append(mutated_probe("a changed version const changes the output",
                                flip_version_const))

    def add_reserved_field(family: dict) -> None:
        family["ingest-envelope"]["x-archivist"]["reservedFields"].append(
            "commit_time_of_day")

    checks.append(mutated_probe("a reserved-field edit changes the output",
                                add_reserved_field))

    def unsupported_const(family: dict) -> None:
        family["ingest-receipt"]["properties"]["receipt_version"]["const"] = [
            1, 2]

    checks.append(mutated_probe("an unmodellable const fails generation",
                                unsupported_const))

    hand_edited = generated.replace(b'"created"', b'"created_all"')
    checks.append(("the drift detector rejects a hand edit",
                   first_difference(generated, hand_edited) is not None))
    checks.append(("the drift detector accepts identical bytes",
                   first_difference(generated, generated) is None))

    passed = sum(1 for _, ok in checks if ok)
    for label, ok in checks:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    print(f"self-test: {passed} passed, {len(checks) - passed} failed")
    return 0 if passed == len(checks) else 2


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else ""
    rest = argv[2:]
    if mode == "--generate":
        if len(rest) > 1:
            fail("--generate takes at most one OUTPUT path")
            return 2
        return run_generate(rest)
    if mode == "--verify":
        if rest:
            fail(f"--verify takes no arguments: {rest}")
            return 2
        return run_verify()
    if mode == "--self-test":
        if rest:
            fail(f"--self-test takes no arguments: {rest}")
            return 2
        return run_self_test()
    fail("usage: tools/bindingsgen.py --generate [OUTPUT] | --verify | --self-test")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
