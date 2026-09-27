#!/usr/bin/env python3
"""Provider-capture route-registry release gate for Agent Archivist.

The published provider-capture route registry lives in
``archivist-adapter-sdk::compatibility`` (``PUBLISHED_REGISTRY``, plan
Phase 9; threat ``EC-04``): one row per exact-capture route the project
claims, naming its route fingerprint, artifact schema version and
provider-boundary artifact kinds, support state, qualifying conformance
suite, and known gap. This gate is the release check that keeps the four
records that carry the claim from drifting apart:

1. the registry rows in ``compatibility.rs`` — ``const`` data, so the
   registry cannot grow except in the same commit as this gate;
2. the published note's registry table
   (``docs/notes/compatibility-matrix.md``, "The published
   provider-capture route registry");
3. the conformance mint sites — the only producers of the evidence a
   ``supported`` row claims;
4. the closed vocabularies the rows are written in (route policies,
   artifact kinds, support states) and the pinned schema/lifecycle
   versions.

Policy, one rule per check below:

1. **registry rows** — ``PUBLISHED_REGISTRY`` parses to exactly one row
   per ``RoutePolicy`` variant, each integration and fingerprint used
   once and grammar-canonical, and every row's artifact schema and
   lifecycle version equal to the protocol's and observer's pinned
   constants;
2. **artifact kinds** — ``PROVIDER_CAPTURE_ARTIFACT_KINDS`` equals the
   closed ``InferenceArtifactKind`` vocabulary parsed from
   ``expected_inference.rs``, in order, and every row claims exactly
   that set (a subset would leave attempts the coverage ledger counts
   ``partial``, which no supported route may do);
3. **state vocabulary** — every row's support state resolves through the
   closed ``RouteSupportState`` vocabulary parsed from the same source;
4. **mint sites** — each row's ``evidence_suite`` module path names a
   real suite file whose ``QualifiedRoute`` mint call carries that row's
   integration and fingerprint constants plus both pinned versions, so
   a supported claim cannot point at evidence that does not mint it;
5. **note agreement** — the note's table carries one row per registry
   row, equal field for field (route token, integration, fingerprint,
   schema and lifecycle versions, state, evidence suite, known gap), and
   its kinds sentence names the closed kind set in order;
6. **phrase pins** — the note keeps its normative sentences: the two
   matrices stay separate, an absent fingerprint is a claim the project
   does not make, and a registry change lands in the same commit as its
   evidence.

``--self-test`` runs the same validators against the committed sources
and note with embedded mutations and requires every rejection path to
fire and the unmutated tree to pass. On success the plain run prints the
verified registry summary and exits 0; any failure prints a report on
stderr and exits 2.

Usage::

    tools/check-provider-capture-registry.py [--self-test]

The script is standard-library only.
"""

from __future__ import annotations

import copy
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTE_PATH = Path("docs/notes/compatibility-matrix.md")
COMPAT_SOURCE_PATH = Path("crates/archivist-adapter-sdk/src/compatibility.rs")
EXPECTED_SOURCE_PATH = Path("crates/archivist-adapter-sdk/src/expected_inference.rs")
OBSERVER_SOURCE_PATH = Path("crates/archivist-adapter-sdk/src/inference_observer.rs")
PROTOCOL_SOURCE_PATH = Path("crates/archivist-protocol/src/inference_artifact.rs")
SDK_SRC = Path("crates/archivist-adapter-sdk/src")

NOTE_SECTION = "The published provider-capture route registry"
NOTE_HEADER = [
    "Route", "Integration", "Route fingerprint", "Schema", "Lifecycle",
    "State", "Evidence suite", "Known gap",
]

# The route -> mint constructor each conformance suite must call, and the
# two pinned versions the mint must carry alongside the row's identity
# constants.
MINT_CONSTRUCTORS = {"SdkHook": "new_sdk_hook", "Proxy": "new_proxy"}
ARTIFACT_VERSION_CONST = "INFERENCE_ARTIFACT_VERSION"
OBSERVER_VERSION_CONST = "INFERENCE_OBSERVER_VERSION"
KINDS_CONST = "PROVIDER_CAPTURE_ARTIFACT_KINDS"

# Rule 6: sentences whose retraction is itself a compatibility change.
# Matched whitespace-normalized so a reflow cannot break a pin.
REQUIRED_PHRASES = (
    "The provider-capture route registry is a separate matrix with "
    "separate evidence",
    "A route fingerprint absent from this registry is a claim the "
    "project does not make",
    "only in the same commit as the conformance evidence that qualifies it",
)

FIELD_RES = {
    "route": re.compile(r"route:\s*RoutePolicy::(\w+)"),
    "integration": re.compile(r"integration:\s*(\"[^\"]+\"|\w+)"),
    "fingerprint": re.compile(r"fingerprint:\s*(\"[^\"]+\"|\w+)"),
    "artifact_schema_version": re.compile(
        r"artifact_schema_version:\s*(\w+)"),
    "lifecycle_version": re.compile(r"lifecycle_version:\s*(\w+)"),
    "artifact_kinds": re.compile(r"artifact_kinds:\s*(\w+)"),
    "state": re.compile(r"state:\s*RouteSupportState::(\w+)"),
    "evidence_suite": re.compile(r'evidence_suite:\s*"([^"]+)"'),
}
KNOWN_GAP_RE = re.compile(r'known_gap:\s*"((?:[^"\\]|\\.)*)"', re.S)
STRING_CONST_RE = re.compile(r'pub const (\w+): &str = "([^"]+)";')
INT_CONST_RE = re.compile(r"pub const (\w+): i64 = (\d+);")


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def read_text(path: Path) -> str | None:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")
        return None


def enum_position(text: str, enum_name: str) -> int | None:
    match = re.search(rf"pub enum {enum_name} \{{", text)
    if match is None:
        fail(f"no `pub enum {enum_name}` found")
        return None
    return match.start()


def enum_all_variants(text: str, enum_name: str) -> list[str] | None:
    """The variants of ``enum_name``'s ``all()``, in declared order."""
    start = enum_position(text, enum_name)
    if start is None:
        return None
    match = re.search(
        r"pub const fn all\(\) -> \[Self; \d+\] \{\s*\[([^\]]+)\]",
        text[start:], re.S)
    if match is None:
        fail(f"no `all()` constructor after `pub enum {enum_name}`")
        return None
    return re.findall(r"Self::(\w+)", match.group(1))


def enum_tokens(text: str, enum_name: str) -> dict[str, str] | None:
    """Variant -> token from ``enum_name``'s ``token()`` match."""
    start = enum_position(text, enum_name)
    if start is None:
        return None
    match = re.search(
        r"pub const fn token\(self\) -> &'static str \{\s*match self \{"
        r"(.*?)\n        \}", text[start:], re.S)
    if match is None:
        fail(f"no `token()` constructor after `pub enum {enum_name}`")
        return None
    return dict(re.findall(r'Self::(\w+) => "([a-z_-]+)",', match.group(1)))


def string_consts(text: str) -> dict[str, str]:
    return dict(STRING_CONST_RE.findall(text))


def resolve_token(value: str, consts: dict[str, str], what: str) -> str | None:
    """A field value that is either a string literal or a const name."""
    if value.startswith('"'):
        return value.strip('"')
    resolved = consts.get(value)
    if resolved is None:
        fail(f"{what}: cannot resolve constant {value!r}")
    return resolved


def resolve_int_const(sources: dict[str, str], name: str) -> int | None:
    """Resolve a version field naming a pinned ``i64`` const anywhere."""
    for text in sources.values():
        match = re.search(rf"pub const {name}: i64 = (\d+);", text)
        if match:
            return int(match.group(1))
    return None


def fingerprint_grammar(text: str) -> bool:
    """The source-fingerprint grammar route fingerprints share."""
    if not text or len(text) > 128 or not text[0].isascii() \
            or not text[0].isalnum():
        return False
    return all(c in "._:-" or (c.isascii() and c.isalnum()) for c in text[1:])


def registry_block(compat: str) -> str | None:
    match = re.search(
        r"pub const PUBLISHED_REGISTRY: \[ProviderCaptureRoute; \d+\] = \["
        r"(.*?)\n\];", compat, re.S)
    if match is None:
        fail(f"{COMPAT_SOURCE_PATH}: no PUBLISHED_REGISTRY const block")
        return None
    return match.group(1)


def parse_registry_rows(compat: str) -> list[dict] | None:
    block = registry_block(compat)
    if block is None:
        return None
    chunks = block.split("ProviderCaptureRoute {")[1:]
    if not chunks:
        fail("PUBLISHED_REGISTRY carries no ProviderCaptureRoute rows")
        return None
    rows: list[dict] = []
    ok = True
    for index, chunk in enumerate(chunks):
        record: dict = {}
        for field, pattern in FIELD_RES.items():
            match = pattern.search(chunk)
            if match is None:
                fail(f"registry row {index}: no {field} field")
                ok = False
                continue
            record[field] = match.group(1)
        gap = KNOWN_GAP_RE.search(chunk)
        if gap is None:
            fail(f"registry row {index}: no known_gap field")
            ok = False
        else:
            # A trailing `\` in a Rust string escapes the newline and the
            # next line's leading whitespace.
            record["known_gap"] = re.sub(r"\\\r?\n\s*", "", gap.group(1))
        rows.append(record)
    return rows if ok else None


def parse_kinds_const(compat: str) -> list[str] | None:
    match = re.search(
        rf"pub const {KINDS_CONST}: &\[&str\] = &?\[([^\]]*)\]", compat, re.S)
    if match is None:
        fail(f"{COMPAT_SOURCE_PATH}: no `pub const {KINDS_CONST}`")
        return None
    kinds = re.findall(r'"([^"]+)"', match.group(1))
    if not kinds:
        fail(f"{KINDS_CONST} names no artifact kinds")
        return None
    return kinds


def check_registry_rows(sources: dict[str, str], note: str) -> bool:
    """Rule 1: one canonical row per route, versions pinned to the consts."""
    compat = sources.get(str(COMPAT_SOURCE_PATH))
    protocol = sources.get(str(PROTOCOL_SOURCE_PATH))
    observer = sources.get(str(OBSERVER_SOURCE_PATH))
    expected_text = sources.get(str(EXPECTED_SOURCE_PATH))
    if any(text is None for text in (compat, protocol, observer,
                                     expected_text)):
        return False
    rows = parse_registry_rows(compat)
    if rows is None:
        return False

    # RoutePolicy lives in expected_inference.rs; the compatibility
    # module only imports it.
    variants = enum_all_variants(expected_text, "RoutePolicy")
    route_tokens = enum_tokens(expected_text, "RoutePolicy")
    if variants is None or route_tokens is None:
        return False

    artifact_version = next(
        (int(value) for name, value in INT_CONST_RE.findall(protocol)
         if name == ARTIFACT_VERSION_CONST), None)
    if artifact_version is None:
        fail(f"{PROTOCOL_SOURCE_PATH}: no `pub const "
             f"{ARTIFACT_VERSION_CONST}: i64`")
    observer_version = next(
        (int(value) for name, value in INT_CONST_RE.findall(observer)
         if name == OBSERVER_VERSION_CONST), None)
    if observer_version is None:
        fail(f"{OBSERVER_SOURCE_PATH}: no `pub const "
             f"{OBSERVER_VERSION_CONST}: i64`")

    ok = True
    seen_routes: set[str] = set()
    seen_integrations: set[str] = set()
    seen_fingerprints: set[str] = set()
    consts = string_consts(compat)
    for index, row in enumerate(rows):
        variant = row.get("route")
        if variant not in variants:
            fail(f"registry row {index}: route {variant!r} is not one of "
                 f"{variants}")
            ok = False
            continue
        if variant in seen_routes:
            fail(f"registry row {index}: route {variant!r} published twice")
            ok = False
        seen_routes.add(variant)

        integration = resolve_token(
            row.get("integration", ""), consts,
            f"registry row {index} integration")
        fingerprint = resolve_token(
            row.get("fingerprint", ""), consts,
            f"registry row {index} fingerprint")
        if integration is not None:
            if integration in seen_integrations:
                fail(f"registry row {index}: integration {integration!r} is "
                     "already published by another row")
                ok = False
            seen_integrations.add(integration)
        else:
            ok = False
        if fingerprint is not None:
            if fingerprint in seen_fingerprints:
                fail(f"registry row {index}: fingerprint {fingerprint!r} is "
                     "already published by another row")
                ok = False
            seen_fingerprints.add(fingerprint)
            if not fingerprint_grammar(fingerprint):
                fail(f"registry row {index}: fingerprint {fingerprint!r} is "
                     "not grammar-canonical")
                ok = False
        else:
            ok = False

        schema_value = resolve_version_field(sources, row,
                                             "artifact_schema_version")
        if artifact_version is not None and schema_value != artifact_version:
            fail(f"registry row {index}: artifact schema version "
                 f"{schema_value} != {ARTIFACT_VERSION_CONST} "
                 f"{artifact_version}")
            ok = False
        lifecycle_value = resolve_version_field(sources, row,
                                                "lifecycle_version")
        if observer_version is not None and lifecycle_value != (
                observer_version):
            fail(f"registry row {index}: lifecycle version "
                 f"{lifecycle_value} != {OBSERVER_VERSION_CONST} "
                 f"{observer_version}")
            ok = False

        if not row.get("known_gap", "").strip():
            fail(f"registry row {index}: known_gap is empty — a published "
                 "row must name the boundary its claim stops at")
            ok = False

    missing = [v for v in variants if v not in seen_routes]
    if missing:
        fail(f"registry publishes no row for route variant(s) {missing}: "
             "the registry is total over the route vocabulary or it is not "
             "a registry")
        ok = False
    return ok


def resolve_version_field(sources: dict[str, str], row: dict,
                          field: str) -> int | None:
    value = row.get(field, "")
    if value.isdigit():
        return int(value)
    if re.fullmatch(r"\w+", value):
        return resolve_int_const(sources, value)
    return None


def check_artifact_kinds(sources: dict[str, str], note: str) -> bool:
    """Rule 2: the kinds const is the closed vocabulary, and rows claim it."""
    compat = sources.get(str(COMPAT_SOURCE_PATH))
    expected = sources.get(str(EXPECTED_SOURCE_PATH))
    if compat is None or expected is None:
        return False
    kinds = parse_kinds_const(compat)
    variants = enum_all_variants(expected, "InferenceArtifactKind")
    tokens = enum_tokens(expected, "InferenceArtifactKind")
    rows = parse_registry_rows(compat)
    if kinds is None or variants is None or tokens is None or rows is None:
        return False

    ok = True
    vocabulary = [tokens[v] for v in variants if v in tokens]
    if len(vocabulary) != len(variants):
        fail(f"InferenceArtifactKind variants {variants} do not all resolve "
             f"to tokens (got {tokens})")
        ok = False
    elif kinds != vocabulary:
        fail(f"{KINDS_CONST} {kinds} != the closed InferenceArtifactKind "
             f"vocabulary {vocabulary} (order included)")
        ok = False
    for index, row in enumerate(rows):
        if row.get("artifact_kinds") != KINDS_CONST:
            fail(f"registry row {index}: artifact_kinds "
                 f"{row.get('artifact_kinds')!r} is not the shared "
                 f"{KINDS_CONST} set")
            ok = False
    return ok


def check_state_vocabulary(sources: dict[str, str], note: str) -> bool:
    """Rule 3: every row's state resolves through the closed vocabulary."""
    compat = sources.get(str(COMPAT_SOURCE_PATH))
    if compat is None:
        return False
    rows = parse_registry_rows(compat)
    variants = enum_all_variants(compat, "RouteSupportState")
    tokens = enum_tokens(compat, "RouteSupportState")
    if rows is None or variants is None or tokens is None:
        return False

    ok = True
    if sorted(variants) != sorted(tokens):
        fail(f"RouteSupportState variants {sorted(variants)} and tokens "
             f"{sorted(tokens)} disagree")
        ok = False
    for index, row in enumerate(rows):
        variant = row.get("state")
        if variant not in variants:
            fail(f"registry row {index}: support state {variant!r} is not "
                 f"one of {sorted(variants)}")
            ok = False
    return ok


def check_mint_sites(sources: dict[str, str], note: str) -> bool:
    """Rule 4: each row's suite file mints that row's qualification."""
    compat = sources.get(str(COMPAT_SOURCE_PATH))
    if compat is None:
        return False
    rows = parse_registry_rows(compat)
    if rows is None:
        return False

    ok = True
    for index, row in enumerate(rows):
        suite = row.get("evidence_suite", "")
        parts = suite.split("::")
        if len(parts) < 2 or parts[0] != "crate":
            fail(f"registry row {index}: evidence_suite {suite!r} is not a "
                 "`crate::<module>::<Suite>` path")
            ok = False
            continue
        suite_path = SDK_SRC / f"{parts[1]}.rs"
        text = sources.get(str(suite_path))
        if text is None:
            fail(f"registry row {index}: evidence_suite {suite!r} names "
                 f"{suite_path}, which does not exist")
            ok = False
            continue
        constructor = MINT_CONSTRUCTORS.get(row.get("route", ""))
        if constructor is None:
            fail(f"registry row {index}: no mint constructor for route "
                 f"{row.get('route')!r}")
            ok = False
            continue
        calls = re.findall(
            rf"QualifiedRoute::{constructor}\(([^)]*)\)", text, re.S)
        if not calls:
            fail(f"{suite_path}: no QualifiedRoute::{constructor} mint "
                 f"call, so {suite!r} cannot produce this row's evidence")
            ok = False
            continue
        for token in (row.get("integration", ""), row.get("fingerprint", ""),
                      ARTIFACT_VERSION_CONST, OBSERVER_VERSION_CONST):
            if not any(token in call for call in calls):
                fail(f"{suite_path}: the {constructor} mint does not carry "
                     f"{token} for registry row {index} ({suite!r})")
                ok = False
    return ok


def note_section(note: str, heading: str) -> str:
    match = re.search(
        rf"^## {re.escape(heading)}\s*$(.*?)(?=^## |\Z)", note, re.M | re.S)
    return match.group(1) if match else ""


def table_rows(section: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        if re.fullmatch(r"\|(?:\s*:?-+:?\s*\|)+", stripped):
            continue  # header separator
        rows.append([cell.strip() for cell in stripped.strip("|").split("|")])
    return rows


def cell_tokens(cell: str) -> list[str]:
    return re.findall(r"`([^`]+)`", cell)


def bare(cell: str) -> str:
    return cell.replace("`", "").strip()


def check_note_agreement(sources: dict[str, str], note: str) -> bool:
    """Rule 5: the note's table equals the registry, field for field."""
    compat = sources.get(str(COMPAT_SOURCE_PATH))
    if compat is None:
        return False
    rows = parse_registry_rows(compat)
    consts = string_consts(compat)
    state_variants = enum_all_variants(compat, "RouteSupportState")
    state_tokens = enum_tokens(compat, "RouteSupportState")
    expected_text = sources.get(str(EXPECTED_SOURCE_PATH))
    route_tokens = (None if expected_text is None
                    else enum_tokens(expected_text, "RoutePolicy"))
    if rows is None or state_variants is None or state_tokens is None \
            or route_tokens is None:
        return False

    section = note_section(note, NOTE_SECTION)
    if not section:
        fail(f"note has no '## {NOTE_SECTION}' section")
        return False
    table = table_rows(section)
    if len(table) < 2:
        fail("note's provider-capture registry section contains no table")
        return False
    if table[0][:len(NOTE_HEADER)] != NOTE_HEADER:
        fail(f"registry table header is {table[0][:len(NOTE_HEADER)]}, "
             f"expected the {'/'.join(NOTE_HEADER)} columns")
        return False

    ok = True
    note_fingerprints: set[str] = set()
    for cells in table[1:]:
        if len(cells) < len(NOTE_HEADER):
            fail(f"registry note row {cells!r} does not have "
                 f"{len(NOTE_HEADER)} cells")
            ok = False
            continue
        route, integration, fingerprint, schema, lifecycle, state, \
            evidence, gap = cells[:len(NOTE_HEADER)]
        route, schema, lifecycle = (bare(route), bare(schema),
                                    bare(lifecycle))
        state, evidence = bare(state), bare(evidence)
        integration_tokens = cell_tokens(integration)
        fingerprint_tokens = cell_tokens(fingerprint)
        if len(integration_tokens) != 1 or len(fingerprint_tokens) != 1:
            fail(f"registry note row {fingerprint!r}: integration and "
                 "fingerprint cells must each carry exactly one token")
            ok = False
            continue
        fingerprint_value = fingerprint_tokens[0]
        note_fingerprints.add(fingerprint_value)

        registry_row = next(
            (r for r in rows
             if resolve_token(r.get("fingerprint", ""), consts,
                              "note cross-check fingerprint")
             == fingerprint_value), None)
        if registry_row is None:
            fail(f"note publishes fingerprint {fingerprint_value!r}, "
                 "which the registry does not")
            ok = False
            continue

        expected_integration = resolve_token(
            registry_row.get("integration", ""), consts,
            "note cross-check integration")
        if integration_tokens[0] != expected_integration:
            fail(f"note integration {integration_tokens[0]!r} != registry "
                 f"{expected_integration!r} for {fingerprint_value!r}")
            ok = False
        expected_route = route_tokens.get(registry_row.get("route", ""))
        if route != expected_route:
            fail(f"note route token {route!r} != registry route "
                 f"{registry_row.get('route')!r} ({expected_route!r}) for "
                 f"{fingerprint_value!r}")
            ok = False
        for cell_value, label, field in (
                (schema.strip(), "artifact schema version",
                 "artifact_schema_version"),
                (lifecycle, "lifecycle version",
                 "lifecycle_version")):
            registry_value = resolve_version_field(sources, registry_row,
                                                   field)
            if cell_value != str(registry_value):
                fail(f"note {label} {cell_value!r} != registry "
                     f"{registry_value} for {fingerprint_value!r}")
                ok = False
        expected_state = state_tokens.get(registry_row.get("state", ""), "")
        if state != expected_state:
            fail(f"note state {state!r} is not the registry row's "
                 f"state {expected_state!r} for {fingerprint_value!r}")
            ok = False
        if evidence != registry_row.get("evidence_suite", ""):
            fail(f"note evidence suite {evidence!r} != registry "
                 f"{registry_row.get('evidence_suite')!r} for "
                 f"{fingerprint_value!r}")
            ok = False
        if not gap.strip():
            fail(f"note row {fingerprint_value!r} carries no known gap")
            ok = False

    registry_fingerprints = {
        resolved
        for resolved in (
            resolve_token(r.get("fingerprint", ""), consts,
                          "registry fingerprint sweep") for r in rows)
        if resolved is not None
    }
    if note_fingerprints != registry_fingerprints:
        fail(f"note publishes {sorted(note_fingerprints)}; the registry "
             f"publishes {sorted(registry_fingerprints)}")
        ok = False

    kinds = parse_kinds_const(compat)
    if kinds is not None:
        kinds_lines = [line for line in section.splitlines()
                       if line.strip().startswith("Every row captures")]
        if len(kinds_lines) != 1:
            fail("note's registry section must carry exactly one 'Every row "
                 "captures' kinds sentence")
            ok = False
        else:
            named = cell_tokens(kinds_lines[0])
            if named != kinds:
                fail(f"note's kinds sentence names {named}, expected the "
                     f"closed set in order {kinds}")
                ok = False
    return ok


def normalize(text: str) -> str:
    return " ".join(text.split())


def check_phrases(sources: dict[str, str], note: str) -> bool:
    """Rule 6: the normative sentences stay."""
    normalized = normalize(note)
    ok = True
    for phrase in REQUIRED_PHRASES:
        if normalize(phrase) not in normalized:
            fail(f"note is missing the pinned phrase: {phrase!r}")
            ok = False
    return ok


CHECKS = (
    ("registry rows", check_registry_rows),
    ("artifact kinds", check_artifact_kinds),
    ("state vocabulary", check_state_vocabulary),
    ("mint sites", check_mint_sites),
    ("note agreement", check_note_agreement),
    ("phrase pins", check_phrases),
)


def load_sources() -> dict[str, str] | None:
    paths = [COMPAT_SOURCE_PATH, EXPECTED_SOURCE_PATH,
             OBSERVER_SOURCE_PATH, PROTOCOL_SOURCE_PATH, NOTE_PATH,
             SDK_SRC / "openai_conformance.rs",
             SDK_SRC / "openai_proxy_conformance.rs"]
    sources: dict[str, str] = {}
    ok = True
    for path in paths:
        text = read_text(path)
        if text is None:
            ok = False
            continue
        sources[str(path)] = text
    return sources if ok else None


def run_checks(sources: dict[str, str], note: str) -> bool:
    ok = True
    for name, check in CHECKS:
        if not check(sources, note):
            ok = False
    return ok


# (label, action, targeted check index). Every mutation rewrites text —
# source or note — in mutate() below and must fire exactly the check it
# targets.
MUTATIONS = (
    ("registry drift (dropped row)",
     "drop the proxy ProviderCaptureRoute row", 0),
    ("registry drift (duplicate integration)",
     "point the SDK-hook row's integration at the proxy integration", 0),
    ("registry drift (schema version)",
     "replace the SDK-hook row's schema version const with a literal", 0),
    ("artifact kind (out of vocabulary)",
     "drop the usage kind from the kinds const", 1),
    ("artifact kind (order)",
     "swap the first two kinds in the kinds const", 1),
    ("state vocabulary",
     "rename the SDK-hook row's state to an out-of-set variant", 2),
    ("mint site (wrong suite)",
     "point the SDK-hook row's evidence suite at the proxy suite", 3),
    ("mint site (wrong fingerprint)",
     "change the transport suite's mint fingerprint constant", 3),
    ("note drift (dropped row)",
     "drop the proxy row from the note's registry table", 4),
    ("note drift (schema version)",
     "change the note's proxy schema version cell", 4),
    ("note drift (state)",
     "rewrite the note's SDK-hook state cell to an out-of-set token", 4),
    ("note drift (kinds sentence)",
     "drop the usage kind from the note's kinds sentence", 4),
    ("phrase pins",
     "retract the absent-fingerprint sentence", 5),
)


def mutate(index: int, sources: dict[str, str], note: str
           ) -> tuple[dict[str, str], str]:
    """Apply mutation ``index``; returns the mutated (sources, note)."""
    compat_path = str(COMPAT_SOURCE_PATH)
    transport_path = str(SDK_SRC / "openai_conformance.rs")
    sources = copy.deepcopy(sources)
    if index == 0:
        sources[compat_path] = re.sub(
            r"    ProviderCaptureRoute \{\n"
            r"        route: RoutePolicy::Proxy,.*?\n    \},\n",
            "", sources[compat_path], count=1, flags=re.S)
    elif index == 1:
        sources[compat_path] = sources[compat_path].replace(
            "integration: FIRST_PARTY_OPENAI_HTTP1,",
            "integration: FIRST_PARTY_OPENAI_PROXY,", 1)
    elif index == 2:
        sources[compat_path] = sources[compat_path].replace(
            "artifact_schema_version: INFERENCE_ARTIFACT_VERSION,",
            "artifact_schema_version: 2,", 1)
    elif index == 3:
        sources[compat_path] = sources[compat_path].replace(
            '    "usage",\n', "", 1)
    elif index == 4:
        sources[compat_path] = sources[compat_path].replace(
            '    "provider-request",\n    "provider-response",',
            '    "provider-response",\n    "provider-request",', 1)
    elif index == 5:
        sources[compat_path] = sources[compat_path].replace(
            "state: RouteSupportState::Supported,",
            "state: RouteSupportState::Draft,", 1)
    elif index == 6:
        sources[compat_path] = sources[compat_path].replace(
            'evidence_suite: "crate::openai_conformance::'
            'TransportConformance"',
            'evidence_suite: "crate::openai_proxy_conformance::'
            'ProxyConformance"', 1)
    elif index == 7:
        sources[transport_path] = sources[transport_path].replace(
            "                ROUTE_FINGERPRINT_OPENAI_HTTP1,\n",
            "                ROUTE_FINGERPRINT_OPENAI_PROXY,\n", 1)
    elif index == 8:
        note = re.sub(r"^\| `proxy` \|[^\n]*\n", "", note, count=1,
                      flags=re.M)
    elif index == 9:
        note = note.replace(
            "| `openai-compat-capture-proxy-v1` | `1` |",
            "| `openai-compat-capture-proxy-v1` | `2` |", 1)
    elif index == 10:
        note = note.replace(
            "| `openai-compat-observer-hook-v1` | `1` | `1` | supported |",
            "| `openai-compat-observer-hook-v1` | `1` | `1` | beta |", 1)
    elif index == 11:
        note = note.replace("`, `usage`, `transport-error`",
                            "`, `transport-error`", 1)
    elif index == 12:
        note = note.replace(
            "A route fingerprint absent from this registry is a claim the "
            "project does not make.", "", 1)
    return sources, note


def self_test(sources: dict[str, str], note: str) -> bool:
    """Prove every rejection path fires and the committed tree passes."""
    if not run_checks(sources, note):
        fail("self-test: the committed sources and note already fail the "
             "gate; fix them before the mutation sweep can mean anything")
        return False

    ok = True
    for index, (label, action, expected_check) in enumerate(MUTATIONS):
        mutated_sources, mutated_note = mutate(index, sources, note)
        name, check = CHECKS[expected_check]
        if check(mutated_sources, mutated_note):
            fail(f"self-test: mutation {label!r} ({action}) did not fire "
                 f"the {name!r} rejection")
            ok = False
    if not ok:
        return False

    print(f"provider-capture-registry self-test: {len(MUTATIONS)} mutations, "
          "every rejection path fired; committed tree passes")
    return True


def main() -> int:
    sources = load_sources()
    if sources is None:
        return 2
    note = sources.pop(str(NOTE_PATH))

    if "--self-test" in sys.argv[1:]:
        if not self_test(sources, note):
            return 2
        return 0

    if not run_checks(sources, note):
        return 2

    compat = sources[str(COMPAT_SOURCE_PATH)]
    rows = parse_registry_rows(compat)
    consts = string_consts(compat)
    if rows is None:
        # run_checks just proved this parse passes; unreachable defence.
        return 2
    print(f"provider-capture registry gate: {len(rows)} published routes, "
          "every supported claim pinned to its minting conformance suite; "
          "registry, note, and mint sites agree")
    for row in rows:
        integration = resolve_token(row.get("integration", ""), consts,
                                    "summary integration")
        fingerprint = resolve_token(row.get("fingerprint", ""), consts,
                                    "summary fingerprint")
        print(f"  {row.get('route', '?'):8s} {integration or '?':26s} "
              f"{fingerprint or '?':32s} {row.get('state', '?')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
