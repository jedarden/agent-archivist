#!/usr/bin/env python3
"""Metrics and telemetry registry gate for Agent Archivist.

Validates ``tools/metrics.toml`` against the conventions in
``docs/notes/metrics.md``:

1. the registry declares schema ``archivist.metrics-registry/v1`` and
   nothing else at the top level;
2. labels are bounded by construction — closed kind set (enum, token,
   boolean), per-kind bounds, cardinality ceilings — and no label key is on
   the forbidden list of correlation-identifier, content, and location
   names (MET-016 through MET-020);
3. the pinned status sets (coverage, exact outcome, commit outcome,
   harness) match the plan vocabularies exactly, and the ``error_code``
   label equals the code set of ``tools/error-codes.toml`` in both
   directions, so neither registry can fork (MET-024, MET-025);
4. metric names satisfy the ``archivist.<surface>.<quantity>`` grammar,
   declare a frozen unit, never embed their unit or a reserved suffix as
   the final segment, and carry at most four labels whose cardinality
   product stays under the ceiling;
5. the pinned OpenTelemetry-to-Prometheus translation (dots to
   underscores, unit suffix, ``_total`` for counters) is injective over the
   registry: no two signals may surface under one exported family name
   (MET-011, MET-012);
6. histograms register explicit, monotonic, bounded boundary sets, and
   counters never measure time (MET-010, MET-027);
7. spans follow the internal or HTTP-template name grammar, declare a
   known surface consistent with their name, and reference registered
   labels only (MET-030 through MET-032).

On success it prints a summary and exits 0. Any failure prints a report on
stderr and exits 2. Findings name signals, labels, and rules only.

``--self-test`` runs the same validators against mutated copies of the
committed registry and fails unless every bad mutation is rejected,
proving the rejection paths (forbidden labels, free-form kinds, enum and
cross-registry drift, unit embedding, export collisions, boundary and
cardinality violations) rather than only the accept path. The committed
registry must itself be clean.

Usage::

    tools/check-metrics.py [--self-test]

Standard-library only (``tomllib``), so a clean checkout runs it before any
dependency is fetched.
"""

from __future__ import annotations

import copy
import math
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = Path("tools/metrics.toml")
ERROR_REGISTRY_PATH = Path("tools/error-codes.toml")

REGISTRY_SCHEMA = "archivist.metrics-registry/v1"

# Surface table (docs/notes/metrics.md Section 1): the emitting component,
# its owning crate (docs/notes/crate-ownership.md), and the base phase that
# implements it. Frozen: moving a surface is a same-commit change to the
# document, the plan, and this table.
SURFACES: dict[str, tuple[str, int]] = {
    "server": ("archivist-server", 4),
    "client": ("archivist-client-core", 5),
    "adapter": ("archivist-adapter-sdk", 6),
    "storage": ("archivist-storage", 2),
    "pilot": ("archivist-cli", 8),
    "exact": ("archivist-adapter-sdk", 9),
}
PHASE_BOUNDS = (2, 11)

# Frozen unit table (docs/notes/metrics.md Section 3). The value is the
# Prometheus suffix the pinned translation appends; changing an existing
# mapping would rename every exported family and is a v2 event.
FROZEN_UNITS: dict[str, str] = {
    "1": "",
    "s": "seconds",
    "By": "bytes",
    "{attempts}": "attempts",
    "{errors}": "errors",
    "{objects}": "objects",
    "{records}": "records",
    "{requests}": "requests",
    "{sources}": "sources",
}

# Final name segments the exposition format itself appends (MET-013).
RESERVED_FINAL_SEGMENTS = frozenset({
    "total", "sum", "count", "bucket", "info", "created",
})

# Forbidden label keys (MET-020): correlation identifiers, content-bearing
# names, locations, and credential material. Additions are compatible
# tightenings; removals are v2 events.
FORBIDDEN_LABELS = frozenset({
    "session_id", "upstream_session_id", "artifact_id", "generation_id",
    "occurrence_id", "attestation_id", "request_id", "correlation_id",
    "trace_id", "inference_request_id", "provider_attempt_id",
    "blob_digest", "digest", "tenant_id", "client_id", "origin_client_id",
    "uploader_client_id", "hostname", "host", "path", "source_path",
    "account", "username", "user", "user_agent", "url", "ip", "address",
    "key_id", "token", "secret", "credential", "password", "message",
    "body", "prompt", "response", "transcript", "content", "error_message",
    "exception",
})

# Status label sets pinned to their plan sources (MET-024). The error_code
# label is pinned to the error registry instead and is required to exist.
PINNED_ENUMS: dict[str, list[str]] = {
    "coverage_state": ["missing", "unsupported", "failed", "partial",
                       "current", "backfilled"],
    "exact_outcome": ["observed", "partial", "failed", "unobserved",
                      "unknown"],
    "commit_outcome": ["created", "already_present", "replaced_equivalent",
                       "logically_committed_unknown_physical_result"],
    "harness": ["claude", "codex", "opencode", "pi", "synthetic"],
}

KINDS = frozenset({"counter", "gauge", "histogram"})
LABEL_KINDS = frozenset({"enum", "token", "boolean"})

ENUM_MAX = 128            # values per enum label (MET-017)
TOKEN_BOUND_MAX = 32      # declared bound per token label (MET-017)
LABELS_PER_SIGNAL_MAX = 4
SIGNAL_CARDINALITY_MAX = 512
SPAN_ATTRIBUTES_MAX = 3
SPAN_CARDINALITY_MAX = 128
BOUNDARIES_MAX = 32
NAME_MAX = 100
SPAN_HTTP_MAX = 64

METRIC_NAME_RE = re.compile(
    r"^archivist\.(server|client|adapter|storage|pilot|exact)"
    r"(\.[a-z][a-z0-9]{0,23}){1,4}$")
SPAN_INTERNAL_RE = re.compile(
    r"^archivist\.(server|client|adapter|storage|pilot|exact)"
    r"(\.[a-z][a-z0-9]{0,23}){1,3}$")
SPAN_HTTP_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /[ -~]+$")
LABEL_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
ENUM_VALUE_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,63}$")
NON_PRINTABLE_RE = re.compile(r"[^ -~]")
STRAY_BRACE_RE = re.compile(r"[{}]")
PROSE_MAX = 200

LABEL_KEYS_COMMON = frozenset({"kind", "description", "deprecated"})
LABEL_KEYS_BY_KIND = {
    "enum": frozenset({"values"}),
    "token": frozenset({"bound"}),
    "boolean": frozenset(),
}
SIGNAL_KEYS_REQUIRED = frozenset({"kind", "unit", "phase", "description"})
SIGNAL_KEYS_OPTIONAL = frozenset({"labels", "boundaries", "deprecated"})
SPAN_KEYS_REQUIRED = frozenset({"surface", "description"})
SPAN_KEYS_OPTIONAL = frozenset({"attributes", "deprecated"})


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def prose_errors(value: object, what: str) -> list[str]:
    """Bound and charset-check a one-line description (no braces)."""
    if not isinstance(value, str):
        return [f"{what} must be a string"]
    errors: list[str] = []
    if NON_PRINTABLE_RE.search(value) or STRAY_BRACE_RE.search(value):
        errors.append(f"{what} contains a brace or non-printable-ASCII character")
    if len(value) > PROSE_MAX:
        errors.append(f"{what} exceeds the {PROSE_MAX}-character bound")
    return errors


def is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def label_cardinality(declared: dict) -> int | None:
    """Cardinality ceiling of a validated label entry, if computable."""
    kind = declared.get("kind")
    if kind == "enum":
        values = declared.get("values")
        return len(values) if isinstance(values, list) else None
    if kind == "token":
        bound = declared.get("bound")
        return bound if is_int(bound) else None
    if kind == "boolean":
        return 2
    return None


def exported_name(name: str, unit: str, kind: str) -> str:
    """The pinned OTel-to-Prometheus translation (MET-011)."""
    exported = name.replace(".", "_")
    suffix = FROZEN_UNITS[unit]
    if suffix:
        exported += f"_{suffix}"
    if kind == "counter":
        exported += "_total"
    return exported


def validate_labels(labels: dict, error_codes: set[str]) -> tuple[list[str], dict]:
    errors: list[str] = []
    for name, declared in labels.items():
        what = f"label {name!r}"
        if not isinstance(declared, dict):
            errors.append(f"{what} must be a table")
            continue
        if not LABEL_KEY_RE.match(name):
            errors.append(f"{what} does not match [a-z][a-z0-9_]{{0,31}}")
        if name in FORBIDDEN_LABELS:
            errors.append(f"{what} is a forbidden label: correlation, "
                          "content, location, and credential names never "
                          "label telemetry (MET-020)")
        kind = declared.get("kind")
        if kind not in LABEL_KINDS:
            errors.append(f"{what} kind {kind!r} is not one of the closed "
                          "kinds {sorted(LABEL_KINDS)}; there is no "
                          "free-form label (MET-016)")
            continue
        allowed = LABEL_KEYS_COMMON | LABEL_KEYS_BY_KIND[kind]
        unknown = set(declared) - allowed
        if unknown:
            errors.append(f"{what} has unknown keys {sorted(unknown)}")
        if "description" not in declared:
            errors.append(f"{what} is missing keys ['description']")
        if "deprecated" in declared and not isinstance(declared["deprecated"], bool):
            errors.append(f"{what} flag 'deprecated' must be a boolean")

        if kind == "enum":
            values = declared.get("values")
            if not isinstance(values, list) or not values:
                errors.append(f"{what} must declare a non-empty 'values' list")
            else:
                if len(values) > ENUM_MAX:
                    errors.append(f"{what} declares {len(values)} values, "
                                  f"over the {ENUM_MAX}-value enum ceiling")
                if len(set(values)) != len(values):
                    errors.append(f"{what} declares duplicate values")
                for value in values:
                    if not isinstance(value, str) or not ENUM_VALUE_RE.match(value):
                        errors.append(f"{what} value {value!r} does not match "
                                      "[a-z0-9][a-z0-9._+-]{0,63}")
                if name in PINNED_ENUMS and isinstance(values, list):
                    if set(values) != set(PINNED_ENUMS[name]):
                        differing = sorted(set(values) ^ set(PINNED_ENUMS[name]))
                        errors.append(
                            f"{what} values drift from the plan vocabulary "
                            f"pinned for it ({differing} differ); the set is "
                            "append-only, not editable (MET-024, MET-025)")
        elif kind == "token":
            bound = declared.get("bound")
            if not is_int(bound):
                errors.append(f"{what} must declare an integer 'bound'")
            elif not 1 <= bound <= TOKEN_BOUND_MAX:
                errors.append(f"{what} bound {bound} is outside "
                              f"1..{TOKEN_BOUND_MAX} (MET-017)")

        if name == "error_code":
            values = declared.get("values")
            emitted = set(map(str, values)) if isinstance(values, list) else set()
            if emitted != error_codes:
                errors.append(
                    "label 'error_code' must equal the error-code registry "
                    f"exactly: {sorted(emitted ^ error_codes)} differ "
                    "between tools/metrics.toml and tools/error-codes.toml "
                    "(MET-024; the registries cannot fork)")

        errors.extend(prose_errors(declared.get("description"),
                                   f"{what} description"))

    for name in sorted(set(PINNED_ENUMS) | {"error_code"}):
        if name not in labels:
            errors.append(f"required label {name!r} is missing from the "
                          "registry (MET-024)")
    return errors, labels


def validate_signals(signals: dict, labels: dict) -> tuple[list[str], dict[str, str]]:
    errors: list[str] = []
    exported: dict[str, str] = {}
    for name, declared in signals.items():
        what = f"signal {name!r}"
        if not isinstance(declared, dict):
            errors.append(f"{what} must be a table")
            continue
        if not METRIC_NAME_RE.match(name) or len(name) > NAME_MAX:
            errors.append(f"{what} does not match the "
                          "archivist.<surface>.<quantity> grammar "
                          "(lowercase dot segments, no underscores, at "
                          "most four quantity segments, 100 characters)")
            continue

        unknown = set(declared) - SIGNAL_KEYS_REQUIRED - SIGNAL_KEYS_OPTIONAL
        if unknown:
            errors.append(f"{what} has unknown keys {sorted(unknown)}; the "
                          "registry schema is closed (MET-038)")
        missing = SIGNAL_KEYS_REQUIRED - set(declared)
        if missing:
            errors.append(f"{what} is missing keys {sorted(missing)}")

        kind = declared.get("kind")
        if kind not in KINDS:
            errors.append(f"{what} kind {kind!r} is not one of "
                          f"{sorted(KINDS)} (MET-005)")
            kind = None
        unit = declared.get("unit")
        if unit not in FROZEN_UNITS:
            errors.append(f"{what} unit {unit!r} is not in the frozen unit "
                          f"table {sorted(FROZEN_UNITS)} (MET-008)")
            unit = None
        phase = declared.get("phase")
        if not is_int(phase):
            errors.append(f"{what} phase must be an integer")
        else:
            base = SURFACES[name.split(".")[1]][1]
            if not base <= phase <= PHASE_BOUNDS[1]:
                errors.append(f"{what} phase {phase} is outside "
                              f"{base}..{PHASE_BOUNDS[1]} for its surface")
        if "deprecated" in declared and not isinstance(declared["deprecated"], bool):
            errors.append(f"{what} flag 'deprecated' must be a boolean")

        final = name.rsplit(".", 1)[1]
        if final in RESERVED_FINAL_SEGMENTS:
            errors.append(f"{what} final segment {final!r} is a reserved "
                          "export suffix; the exposition format appends it "
                          "(MET-013)")
        if unit is not None and unit != "1" and final == FROZEN_UNITS[unit]:
            errors.append(f"{what} final segment {final!r} embeds its own "
                          "unit; the exporter appends it, so the series "
                          "would carry a doubled suffix (MET-009)")
        if kind == "counter" and unit in ("1", "s"):
            errors.append(f"{what} is a counter with unit {unit!r}; "
                          "counters count discrete things, never time or "
                          "ratio (MET-010)")

        signal_labels = declared.get("labels", [])
        if not isinstance(signal_labels, list) or not all(
                isinstance(item, str) for item in signal_labels):
            errors.append(f"{what} labels must be a list of label keys")
            signal_labels = []
        if len(set(signal_labels)) != len(signal_labels):
            errors.append(f"{what} repeats a label")
        if len(signal_labels) > LABELS_PER_SIGNAL_MAX:
            errors.append(f"{what} carries {len(signal_labels)} labels, over "
                          f"the {LABELS_PER_SIGNAL_MAX}-label ceiling "
                          "(MET-018)")
        cardinality = 1
        for key in signal_labels:
            if key not in labels:
                errors.append(f"{what} references unregistered label "
                              f"{key!r}; a producer cannot invent labels "
                              "mid-flight (MET-019)")
            else:
                bound = label_cardinality(labels[key])
                if bound is not None:
                    cardinality *= bound
        if cardinality > SIGNAL_CARDINALITY_MAX:
            errors.append(f"{what} label cardinality product {cardinality} "
                          f"exceeds {SIGNAL_CARDINALITY_MAX} (MET-018)")

        boundaries = declared.get("boundaries")
        if kind == "histogram":
            if not isinstance(boundaries, list) or not boundaries:
                errors.append(f"{what} is a histogram without registered "
                              "explicit boundaries (MET-027)")
            else:
                if len(boundaries) > BOUNDARIES_MAX:
                    errors.append(f"{what} declares {len(boundaries)} "
                                  f"boundaries, over the {BOUNDARIES_MAX} "
                                  "ceiling")
                numeric = [b for b in boundaries
                           if isinstance(b, (int, float))
                           and not isinstance(b, bool)]
                if len(numeric) != len(boundaries):
                    errors.append(f"{what} boundaries must all be numbers")
                elif not all(math.isfinite(b) and b > 0 for b in numeric):
                    errors.append(f"{what} boundaries must be positive and "
                                  "finite")
                elif numeric != sorted(numeric) or len(set(numeric)) != len(numeric):
                    errors.append(f"{what} boundaries must be strictly "
                                  "increasing")
        elif "boundaries" in declared:
            errors.append(f"{what} is not a histogram but declares "
                          "boundaries")

        errors.extend(prose_errors(declared.get("description"),
                                   f"{what} description"))

        if kind is not None and unit is not None:
            family = exported_name(name, unit, kind)
            if family in exported:
                errors.append(
                    f"{what} exports as {family!r}, already produced by "
                    f"signal {exported[family]!r}; the translation must be "
                    "injective so exporters retain consistent names "
                    "(MET-012)")
            else:
                exported[family] = name

    return errors, exported


def validate_spans(spans: dict, labels: dict) -> list[str]:
    errors: list[str] = []
    for name, declared in spans.items():
        what = f"span {name!r}"
        if not isinstance(declared, dict):
            errors.append(f"{what} must be a table")
            continue
        internal = bool(SPAN_INTERNAL_RE.match(name))
        http = bool(SPAN_HTTP_RE.match(name))
        if not internal and not http:
            errors.append(f"{what} matches neither the internal "
                          "archivist.<surface>.<operation> grammar nor the "
                          "'{METHOD} {route}' HTTP template (MET-030, "
                          "MET-031)")
        if http and (len(name) > SPAN_HTTP_MAX or STRAY_BRACE_RE.search(name)):
            errors.append(f"{what} violates the HTTP span-name bounds "
                          "(64 characters, no brace placeholders)")

        unknown = set(declared) - SPAN_KEYS_REQUIRED - SPAN_KEYS_OPTIONAL
        if unknown:
            errors.append(f"{what} has unknown keys {sorted(unknown)}")
        missing = SPAN_KEYS_REQUIRED - set(declared)
        if missing:
            errors.append(f"{what} is missing keys {sorted(missing)}")
        surface = declared.get("surface")
        if surface not in SURFACES:
            errors.append(f"{what} declares unknown surface {surface!r}")
        elif internal and name.split(".")[1] != surface:
            errors.append(f"{what} declares surface {surface!r} but its name "
                          f"names surface {name.split('.')[1]!r}")
        if "deprecated" in declared and not isinstance(declared["deprecated"], bool):
            errors.append(f"{what} flag 'deprecated' must be a boolean")

        attributes = declared.get("attributes", [])
        if not isinstance(attributes, list) or not all(
                isinstance(item, str) for item in attributes):
            errors.append(f"{what} attributes must be a list of label keys")
            attributes = []
        if len(set(attributes)) != len(attributes):
            errors.append(f"{what} repeats an attribute")
        if len(attributes) > SPAN_ATTRIBUTES_MAX:
            errors.append(f"{what} carries {len(attributes)} attributes, "
                          f"over the {SPAN_ATTRIBUTES_MAX}-attribute "
                          "ceiling (MET-018)")
        cardinality = 1
        for key in attributes:
            if key not in labels:
                errors.append(f"{what} references unregistered attribute "
                              f"{key!r} (MET-032)")
            else:
                bound = label_cardinality(labels[key])
                if bound is not None:
                    cardinality *= bound
        if cardinality > SPAN_CARDINALITY_MAX:
            errors.append(f"{what} attribute cardinality product "
                          f"{cardinality} exceeds "
                          f"{SPAN_CARDINALITY_MAX} (MET-018)")

        errors.extend(prose_errors(declared.get("description"),
                                   f"{what} description"))
    return errors


def validate_registry(registry: dict, error_codes: set[str]) -> list[str]:
    """Return every convention violation in a parsed registry."""
    errors: list[str] = []

    extra_top = set(registry) - {"schema", "labels", "signals", "spans"}
    missing_top = {"schema", "labels", "signals", "spans"} - set(registry)
    if extra_top:
        errors.append(f"unknown top-level keys: {sorted(extra_top)}")
    if missing_top:
        errors.append(f"missing top-level keys: {sorted(missing_top)}")
    if registry.get("schema") != REGISTRY_SCHEMA:
        errors.append(f"schema must be {REGISTRY_SCHEMA!r}, "
                      f"found {registry.get('schema')!r}")
    if errors:
        return errors

    labels: dict = registry["labels"]
    signals: dict = registry["signals"]
    spans: dict = registry["spans"]
    if not isinstance(labels, dict) or not labels:
        errors.append("registry declares no labels")
        return errors
    if not isinstance(signals, dict) or not signals:
        errors.append("registry declares no signals")
        return errors
    if not isinstance(spans, dict) or not spans:
        errors.append("registry declares no spans")
        return errors

    label_errors, labels = validate_labels(labels, error_codes)
    errors.extend(label_errors)
    signal_errors, exported = validate_signals(signals, labels)
    errors.extend(signal_errors)
    errors.extend(validate_spans(spans, labels))

    referenced = {key for declared in signals.values()
                  if isinstance(declared, dict)
                  for key in declared.get("labels", [])
                  if isinstance(key, str)}
    referenced |= {key for declared in spans.values()
                   if isinstance(declared, dict)
                   for key in declared.get("attributes", [])
                   if isinstance(key, str)}
    for name in sorted(set(labels) - referenced):
        errors.append(f"label {name!r} is referenced by no signal or span; "
                      "the registry carries no speculative taxonomy "
                      "(MET-019)")

    return errors


def load_toml(path: Path) -> dict | None:
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

_MANY_ENUM = [f"v{i}" for i in range(ENUM_MAX + 1)]
_MANY_BOUNDARIES = [float(i) for i in range(1, BOUNDARIES_MAX + 2)]

SELF_TEST_CASES: list[tuple[str, bool, object]] = [
    ("unmodified registry", False, None),
    ("label names a session identifier",
     True, ("new-label", "session_id", {
         "kind": "enum", "values": ["a", "b"],
         "description": "Session identifier."})),
    ("label names a hostname",
     True, ("new-label", "hostname", {
         "kind": "token", "bound": 8,
         "description": "Host name."})),
    ("label claims a free-form string kind",
     True, ("new-label", "region", {
         "kind": "string",
         "description": "Free-form region."})),
    ("error-code label loses a registry code",
     True, ("pop-label-value", "error_code")),
    ("error-code label gains an unregistered code",
     True, ("append-label-value", "error_code", "server.teapot")),
    ("coverage-state vocabulary drifts",
     True, ("label", "coverage_state", "values",
            ["missing", "unsupported", "failed", "partial", "current"])),
    ("exact-outcome vocabulary drifts",
     True, ("label", "exact_outcome", "values",
            ["observed", "partial", "failed", "unobserved", "unknown",
             "bypassed"])),
    ("commit-outcome vocabulary drifts",
     True, ("label", "commit_outcome", "values",
            ["created", "already_present", "replaced_equivalent"])),
    ("harness vocabulary drifts",
     True, ("label", "harness", "values",
            ["claude", "codex", "opencode", "pi"])),
    ("enum value uses uppercase",
     True, ("label", "object_kind", "values", ["Blob", "occurrence"])),
    ("enum exceeds the cardinality ceiling",
     True, ("new-label", "big", {
         "kind": "enum", "values": _MANY_ENUM,
         "description": "Too many values."})),
    ("token label loses its bound",
     True, ("label", "version", "bound", None)),
    ("token label bound exceeds the ceiling",
     True, ("label", "version", "bound", TOKEN_BOUND_MAX + 1)),
    ("signal name drops the archivist prefix",
     True, ("rename-signal", "archivist.client.active", "client.active")),
    ("signal name uses an underscore segment",
     True, ("rename-signal", "archivist.client.active",
            "archivist.client.active_sources")),
    ("signal name uses an unknown surface",
     True, ("rename-signal", "archivist.server.ingest",
            "archivist.gateway.ingest")),
    ("signal name embeds its own unit",
     True, ("rename-signal", "archivist.client.spool.usage",
            "archivist.client.spool.usage.bytes")),
    ("signal name ends in a reserved suffix",
     True, ("rename-signal", "archivist.server.trust.age",
            "archivist.server.trust.total")),
    ("signals collide on one exported family name",
     True, ("new-signal", "archivist.client.spool.usage.bytes", {
         "kind": "gauge", "unit": "1", "phase": 5,
         "description": "Collides with spool.usage under translation."})),
    ("signal references an unregistered label",
     True, ("signal", "archivist.client.coverage", "labels", ["region"])),
    ("signal repeats a label",
     True, ("signal", "archivist.client.coverage", "labels",
            ["harness", "harness"])),
    ("signal exceeds the label-count ceiling",
     True, ("signal", "archivist.client.coverage", "labels",
            ["harness", "coverage_state", "object_kind", "commit_outcome",
             "error_code"])),
    ("histogram loses its boundaries",
     True, ("signal", "archivist.client.cycle.duration", "boundaries", None)),
    ("histogram boundaries are not increasing",
     True, ("signal", "archivist.client.cycle.duration", "boundaries",
            [1.0, 0.5, 2.0])),
    ("histogram exceeds the boundary ceiling",
     True, ("signal", "archivist.client.cycle.duration", "boundaries",
            _MANY_BOUNDARIES)),
    ("gauge declares boundaries",
     True, ("signal", "archivist.client.spool.usage", "boundaries",
            [1.0, 2.0])),
    ("counter measures time",
     True, ("signal", "archivist.server.ingest", "unit", "s")),
    ("signal uses an unknown unit",
     True, ("signal", "archivist.server.ingest", "unit", "ms")),
    ("signal phase precedes its surface",
     True, ("signal", "archivist.server.ingest", "phase", 3)),
    ("signal phase exceeds the plan bound",
     True, ("signal", "archivist.server.ingest", "phase", 12)),
    ("span name matches no grammar",
     True, ("rename-span", "archivist.client.cycle", "client cycle")),
    ("HTTP span name carries a brace placeholder",
     True, ("rename-span", "GET /health/live", "GET /health/{probe}")),
    ("span surface contradicts its name",
     True, ("span", "archivist.storage.operation", "surface", "server")),
    ("span references an unregistered attribute",
     True, ("span", "archivist.client.cycle", "attributes", ["session_id"])),
    ("pinned status label is deleted",
     True, ("drop-label", "coverage_state")),
    ("registered label is referenced by nothing",
     True, ("new-label", "channel", {
         "kind": "enum", "values": ["stable", "beta"],
         "description": "Unused taxonomy."})),
    ("deprecated flag is not a boolean",
     True, ("signal", "archivist.server.ingest", "deprecated", "yes")),
    ("registry adds an unknown top-level key",
     True, ("top", "alerts", ["free-form"])),
    ("registry declares the wrong schema",
     True, ("top", "schema", "archivist.metrics-registry/v2")),
]


def apply_mutation(registry: dict, mutation: object) -> dict:
    """Return a copy of ``registry`` with one mutation applied."""
    mutated = copy.deepcopy(registry)
    if mutation is None:
        return mutated
    kind = mutation[0]
    if kind == "label":
        _, name, key, value = mutation
        if value is None:
            mutated["labels"][name].pop(key, None)
        else:
            mutated["labels"][name][key] = value
    elif kind == "pop-label-value":
        mutated["labels"][mutation[1]]["values"].pop()
    elif kind == "append-label-value":
        mutated["labels"][mutation[1]]["values"].append(mutation[2])
    elif kind == "new-label":
        mutated["labels"][mutation[1]] = mutation[2]
    elif kind == "drop-label":
        del mutated["labels"][mutation[1]]
    elif kind == "signal":
        _, name, key, value = mutation
        if value is None:
            mutated["signals"][name].pop(key, None)
        else:
            mutated["signals"][name][key] = value
    elif kind == "rename-signal":
        _, old, new = mutation
        mutated["signals"][new] = mutated["signals"].pop(old)
    elif kind == "new-signal":
        mutated["signals"][mutation[1]] = mutation[2]
    elif kind == "rename-span":
        _, old, new = mutation
        mutated["spans"][new] = mutated["spans"].pop(old)
    elif kind == "span":
        _, name, key, value = mutation
        if value is None:
            mutated["spans"][name].pop(key, None)
        else:
            mutated["spans"][name][key] = value
    elif kind == "top":
        _, key, value = mutation
        mutated[key] = value
    else:  # pragma: no cover - the case list is closed
        raise AssertionError(kind)
    return mutated


def run_self_test() -> int:
    base = load_toml(ROOT / REGISTRY_PATH)
    error_registry = load_toml(ROOT / ERROR_REGISTRY_PATH)
    if base is None or error_registry is None:
        return 2
    error_codes = set(error_registry.get("codes", {}))

    if validate_registry(base, error_codes):
        fail("self-test base: the committed registry itself is invalid")
        return 2

    passed = 0
    failed = 0
    for label, must_reject, mutation in SELF_TEST_CASES:
        registry = apply_mutation(base, mutation)
        violations = validate_registry(registry, error_codes)
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

    registry = load_toml(ROOT / REGISTRY_PATH)
    error_registry = load_toml(ROOT / ERROR_REGISTRY_PATH)
    if registry is None or error_registry is None:
        return 2
    error_codes = set(error_registry.get("codes", {}))

    violations = validate_registry(registry, error_codes)
    for violation in violations:
        fail(violation)
    if violations:
        return 2

    signals: dict = registry["signals"]
    labels: dict = registry["labels"]
    spans: dict = registry["spans"]
    by_kind = {kind: sum(1 for s in signals.values() if s.get("kind") == kind)
               for kind in sorted(KINDS)}
    exported = {exported_name(name, s["unit"], s["kind"])
                for name, s in signals.items()}
    print(f"agent-archivist metrics registry: {REGISTRY_SCHEMA}")
    print(f"surfaces: {len(SURFACES)}, signals: {len(signals)} "
          f"({by_kind['counter']} counters, {by_kind['gauge']} gauges, "
          f"{by_kind['histogram']} histograms), spans: {len(spans)}, "
          f"labels: {len(labels)}")
    print(f"exported families: {len(exported)} (unique under the pinned "
          "translation)")
    print(f"error-code label cross-checked: {len(error_codes)} codes")
    print("OK: registry satisfies docs/notes/metrics.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
