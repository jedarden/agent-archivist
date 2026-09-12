#!/usr/bin/env python3
"""Wire-schema coherence gate for Agent Archivist.

Validates the ``schemas/v1`` wire family against the internal contracts of
``docs/notes/wire-schemas.md`` (authority: plan Sections 7.1-7.8):

1. every top-level schema parses, declares draft 2020-12, and carries the
   ``urn:agent-archivist:schema:v1:<stem>`` id matching its filename;
2. every ``$ref`` resolves — URN refs across files and local ``#`` refs —
   so no schema dangles against the shared vocabulary;
3. every closed ``enum`` carries ``x-archivist.bearing`` metadata, and
   every security- or identity-bearing one carries ``failClosed: true``
   (the plan Section 7.1 acceptance: unknown security-bearing values fail
   closed, and the gate proves the metadata that says so exists);
4. no schema uses ``type: number`` anywhere and every instance schema
   declares ``x-archivist.floats: false`` — protocol structures contain
   no floating-point values;
5. the pinned v1 version consts are present with their pinned values and
   fail-closed metadata — an unknown major is a validation error, never a
   best-effort parse;
6. ``x-archivist.reservedFields`` metadata and the ``not`` block rejecting
   those names agree exactly (the envelope/manifest/attestation exclusion
   of per-attempt and server material);
7. the ``ingest-identifiers.json`` construction registry is coherent:
   derivation fields exist (and are required) in their source schema or
   are prior derivations, the one label-less derivation is the plain blob
   digest, the ingest-attempt-v1 covered list is exactly the request's
   required fields minus the signature pair, and the receipt signature
   constructions name members the receipt schema actually defines;
8. the error body keeps its closed six-field shape and the message
   pattern really enforces the printable-ASCII/no-braces charset it
   documents (checked behaviourally, not just syntactically).

On success it prints a summary and exits 0. Any failure prints a report on
stderr and exits 2.

``--self-test`` mutates a copy of the committed family and fails unless
every mutation is rejected, proving the rejection paths (missing
fail-closed metadata, dangling refs, reserved-name drift, construction
registry drift, signature-member drift, charset relaxation, float leak)
rather than only the accept path.

Usage::

    tools/check-wire-schemas.py [--self-test]

Standard-library only, so a clean checkout runs it before any dependency
is fetched. Its output names schemas, fields, and rules only.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = Path("schemas/v1")
URN_PREFIX = "urn:agent-archivist:schema:v1:"
DRAFT = "https://json-schema.org/draft/2020-12/schema"

# The ingest wire family this gate exists for (docs/notes/wire-schemas.md).
# Shared with the raw provenance family: common.json and the two durable
# records, which are scanned by the generic rules but owned by
# docs/notes/raw-provenance-schemas.md.
FAMILY_STEMS = (
    "common",
    "ingest-envelope",
    "ingest-request",
    "ingest-identifiers",
    "ingest-error",
    "ingest-receipt",
)

# Instance (per-record) schemas, as opposed to the two registries
# (common.json's $defs and ingest-identifiers.json's construction tables).
INSTANCE_STEMS = (
    "ingest-envelope",
    "ingest-request",
    "ingest-error",
    "ingest-receipt",
    "occurrence-manifest",
    "upload-attestation",
)

KNOWN_BEARINGS = {"security", "identity", "provenance", "structural",
                  "correlation"}
FAIL_CLOSED_BEARINGS = {"security", "identity"}

# Version-const pins: stem -> {field: pinned const value}. A value change
# here is a v1 contract change (a new major), not a schema edit the gate
# should silently tolerate.
VERSION_CONSTS = {
    "ingest-envelope": {"protocol_version": 1, "envelope_version": 1},
    "ingest-error": {"schema": "archivist.error/v1"},
    "ingest-receipt": {"receipt_version": 1},
    "occurrence-manifest": {"occurrence_version": 1},
    "upload-attestation": {"attestation_version": 1},
}

# The receipt-key certificate lives inside the receipt schema's $defs and
# carries its own axis.
CERT_PATH = ("$defs", "receipt-key-certificate")
CERT_VERSION_FIELD = "certificate_version"

# Plan-pinned v1 constants (Sections 5, 7.2, 7.6, and 7.8). Changing one is a
# contract change that must touch schema and gate in the same commit.
PINNED = {
    ("ingest-envelope", ("x-archivist", "canonicalMaxBytes")): 65536,
    ("ingest-request", ("x-archivist", "authorizationWindowSeconds")): 300,
    ("ingest-request", ("x-archivist", "clockSkewAllowanceSeconds")): 300,
    ("ingest-receipt", tuple(CERT_PATH) + ("x-archivist",
                                          "receiptKeyRotationDays")): 30,
    ("ingest-receipt", tuple(CERT_PATH) + ("x-archivist",
                                          "receiptKeySigningOverlapDays")): 7,
}

ERROR_BODY_FIELDS = {"schema", "code", "retryable", "message",
                     "request_id", "correlation_id"}

SIGNATURE_IDS = {"ingest-attempt-v1", "receipt-v1", "receipt-key-v1"}
ATTEMPT_UNCOVERED = {"signature", "signature_algorithm"}

# Self-test mutations: (label, stem, mutation) — each must be rejected.
SELF_TEST_CASES = [
    ("enum without failClosed metadata", "common",
     lambda s: s["$defs"]["storage-profile"]["x-archivist"].pop("failClosed")),
    ("dangling URN ref", "ingest-envelope",
     lambda s: s["properties"]["tenant_id"].__setitem__(
         "$ref", URN_PREFIX + "common#/$defs/no-such-shape")),
    ("reserved-name block drift", "ingest-envelope",
     lambda s: s["not"]["anyOf"].pop()),
    ("derivation field absent from source", "ingest-identifiers",
     lambda s: s["x-archivist"]["derivations"][0]["fields"].__setitem__(
         3, "hostname")),
    ("covered-list drift", "ingest-identifiers",
     lambda s: s["x-archivist"]["signatures"][0]["covered"].remove("route")),
    ("signature member drift", "ingest-receipt",
     lambda s: s[tuple(CERT_PATH)[0]][CERT_PATH[1]]["properties"].pop(
         "authority_signature")),
    ("message charset relaxation", "ingest-error",
     lambda s: s["properties"]["message"].__setitem__("pattern", "^.+$")),
    ("float leak", "ingest-envelope",
     lambda s: s["properties"].__setitem__(
         "ratio", {"type": "number", "description": "floats are forbidden"})),
]


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)


def load_schemas() -> dict[str, dict] | None:
    schemas: dict[str, dict] = {}
    ok = True
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(f"{path}: unreadable or invalid JSON ({exc})")
            ok = False
            continue
        if not isinstance(doc, dict):
            fail(f"{path}: top level must be an object")
            ok = False
            continue
        schemas[path.stem] = doc
    for stem in FAMILY_STEMS:
        if stem not in schemas:
            fail(f"{SCHEMA_DIR}/{stem}.json: missing from the wire family")
            ok = False
    return schemas if ok else None


def walk(node, meta=None):
    """Yield (node, nearest x-archivist metadata) for every dict below."""
    if isinstance(node, dict):
        current = node.get("x-archivist", meta)
        yield node, current
        for value in node.values():
            yield from walk(value, current)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value, meta)


def resolve_pointer(doc: dict, pointer: str) -> bool:
    node = doc
    for raw in pointer.strip("/").split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return False
    return True


def check_family(schemas: dict[str, dict]) -> list[str]:
    violations: list[str] = []

    # 1. ids and drafts.
    for stem, doc in schemas.items():
        if doc.get("$schema") != DRAFT:
            violations.append(f"{stem}: $schema must be {DRAFT}")
        if doc.get("$id") != URN_PREFIX + stem:
            violations.append(f"{stem}: $id must be {URN_PREFIX}{stem}")

    # 2. ref resolution (URN refs cross-file, '#' refs local).
    for stem, doc in schemas.items():
        for node, _ in walk(doc):
            ref = node.get("$ref")
            if not isinstance(ref, str):
                continue
            if ref.startswith("#/"):
                if not resolve_pointer(doc, ref[1:]):
                    violations.append(f"{stem}: dangling local ref {ref}")
            elif ref.startswith(URN_PREFIX):
                rest = ref[len(URN_PREFIX):]
                target_stem, _, pointer = rest.partition("#")
                target = schemas.get(target_stem)
                if target is None:
                    violations.append(f"{stem}: ref to unknown schema {ref}")
                elif pointer and not resolve_pointer(target, pointer):
                    violations.append(f"{stem}: dangling ref {ref}")

    # 3. closed enums carry fail-closed metadata where bearing demands it.
    for stem, doc in schemas.items():
        for node, meta in walk(doc):
            if "enum" not in node:
                continue
            if not isinstance(meta, dict) or "bearing" not in meta:
                violations.append(
                    f"{stem}: enum without x-archivist.bearing metadata")
                continue
            if meta["bearing"] not in KNOWN_BEARINGS:
                violations.append(
                    f"{stem}: enum with unknown bearing {meta['bearing']!r}")
            elif (meta["bearing"] in FAIL_CLOSED_BEARINGS
                  and meta.get("failClosed") is not True):
                violations.append(
                    f"{stem}: {meta['bearing']}-bearing enum missing "
                    "failClosed: true")

    # 4. no floats, anywhere, and instance schemas say so up front.
    for stem, doc in schemas.items():
        for node, _ in walk(doc):
            if node.get("type") == "number":
                violations.append(f"{stem}: type number (floats are forbidden)")
        if stem in INSTANCE_STEMS:
            floats = doc.get("x-archivist", {}).get("floats")
            if floats is not False:
                violations.append(f"{stem}: x-archivist.floats must be false")

    # 5. pinned version consts and plan constants.
    for stem, fields in VERSION_CONSTS.items():
        doc = schemas.get(stem)
        if doc is None:
            continue
        for field, value in fields.items():
            node = doc.get("properties", {}).get(field)
            if node is None:
                violations.append(f"{stem}: missing version field {field}")
            elif node.get("const") != value:
                violations.append(
                    f"{stem}: {field} must be const {value!r}")
            elif node.get("x-archivist", {}).get("failClosed") is not True:
                violations.append(
                    f"{stem}: {field} must carry failClosed: true")
    cert = schemas.get("ingest-receipt", {})
    for part in CERT_PATH:
        cert = cert.get(part, {}) if isinstance(cert, dict) else {}
    cert_version = cert.get("properties", {}).get(CERT_VERSION_FIELD)
    if cert_version is None:
        violations.append(
            f"ingest-receipt: missing {CERT_PATH[-1]}.{CERT_VERSION_FIELD}")
    elif (cert_version.get("const") != 1
          or cert_version.get("x-archivist", {}).get("failClosed") is not True):
        violations.append(
            f"ingest-receipt: {CERT_VERSION_FIELD} must be const 1 with "
            "failClosed: true")
    for (stem, path), value in PINNED.items():
        node: object = schemas.get(stem, {})
        for part in path:
            node = node.get(part, {}) if isinstance(node, dict) else {}
        if node != value:
            violations.append(
                f"{stem}: {'.'.join(path)} must be {value!r} (plan-pinned)")

    # Every instance schema fails closed on at least one const or enum.
    for stem in INSTANCE_STEMS:
        doc = schemas.get(stem)
        if doc is None:
            continue
        guarded = any(
            ("const" in node or "enum" in node)
            and isinstance(meta, dict)
            and meta.get("failClosed") is True
            for node, meta in walk(doc.get("properties", {})))
        if not guarded:
            violations.append(
                f"{stem}: no failClosed const or enum in any property")

    # 6. reservedFields metadata agrees with the not-block.
    for stem, doc in schemas.items():
        reserved = doc.get("x-archivist", {}).get("reservedFields")
        if reserved is None:
            continue
        block = doc.get("not", {}).get("anyOf", [])
        rejected = {name for entry in block
                    if isinstance(entry, dict) and set(entry) == {"required"}
                    for name in entry["required"]}
        if set(reserved) != rejected:
            violations.append(
                f"{stem}: reservedFields metadata and not-block disagree "
                f"(metadata-only: {sorted(set(reserved) - rejected)}, "
                f"block-only: {sorted(rejected - set(reserved))})")

    # 7. construction registry coherence.
    reg = schemas.get("ingest-identifiers", {}).get("x-archivist", {})
    derivations = reg.get("derivations", [])
    derived_ids = {d.get("id") for d in derivations}
    if len(derived_ids) != len(derivations):
        violations.append("ingest-identifiers: duplicate derivation ids")
    unlabeled = [d.get("id") for d in derivations if d.get("label") is None]
    if sorted(unlabeled) != ["blob_digest"]:
        violations.append(
            "ingest-identifiers: the only label-less derivation must be "
            f"blob_digest (found {sorted(unlabeled)})")
    for deriv in derivations:
        did = deriv.get("id", "<unnamed>")
        fields = deriv.get("fields", [])
        kinds = deriv.get("fieldKinds", [])
        if len(fields) != len(kinds):
            violations.append(
                f"ingest-identifiers: {did} fields/fieldKinds length drift")
        if any(k not in {"text", "u63", "digest", "bytes"} for k in kinds):
            violations.append(f"ingest-identifiers: {did} unknown field kind")
        source = schemas.get(Path(deriv.get("source", "")).stem)
        if source is None:
            if str(deriv.get("source", "")).startswith("schemas/"):
                violations.append(
                    f"ingest-identifiers: {did} source {deriv.get('source')!r} "
                    "is not a loaded schema")
                continue
            # A non-schema source (the payload part) names bytes, not fields;
            # there is nothing to cross-check against a schema.
            continue
        properties = source.get("properties", {})
        required = set(source.get("required", []))
        for field in fields:
            if field == "canonical_uncompressed_bytes" or field in derived_ids:
                continue
            if field not in properties:
                violations.append(
                    f"ingest-identifiers: {did} references {field!r}, "
                    f"absent from {deriv.get('source')}")
            elif field not in required:
                violations.append(
                    f"ingest-identifiers: {did} uses {field!r}, optional in "
                    f"{deriv.get('source')} (identity inputs must be required)")
    for entry in reg.get("objectKeys", []):
        pattern = entry.get("pattern", "")
        target = pattern.split("#", 1)
        if (len(target) != 2
                or Path(target[0]).stem not in schemas
                or not resolve_pointer(schemas[Path(target[0]).stem],
                                       target[1])):
            violations.append(
                f"ingest-identifiers: objectKey pattern {pattern!r} "
                "does not resolve")

    signatures = reg.get("signatures", [])
    if {s.get("id") for s in signatures} != SIGNATURE_IDS:
        violations.append(
            f"ingest-identifiers: signature set must be {sorted(SIGNATURE_IDS)}")
    by_id = {s.get("id"): s for s in signatures}
    request = schemas.get("ingest-request", {})
    attempt = by_id.get("ingest-attempt-v1", {})
    covered = set(attempt.get("covered", []))
    expected_covered = set(request.get("required", [])) - ATTEMPT_UNCOVERED
    if covered != expected_covered:
        violations.append(
            "ingest-identifiers: ingest-attempt-v1 covered list must be the "
            "request's required fields minus "
            f"{sorted(ATTEMPT_UNCOVERED)} (missing: "
            f"{sorted(expected_covered - covered)}, extra: "
            f"{sorted(covered - expected_covered)})")
    receipt = schemas.get("ingest-receipt", {})
    if "signature" not in receipt.get("properties", {}):
        violations.append(
            "ingest-receipt: receipt-v1 signs a `signature` member the "
            "schema does not define")
    receipt_key_covered = str(by_id.get("receipt-key-v1", {}).get("covered"))
    authority_member = cert.get("x-archivist", {}).get("authorityMember")
    if ("`authority_signature`" not in receipt_key_covered
            or "authority_signature" not in cert.get("properties", {})
            or authority_member != "authority_signature"):
        violations.append(
            "ingest-identifiers: receipt-key-v1 excluded member must be the "
            "certificate's authority_signature (registry, schema, and "
            "authorityMember metadata must agree)")

    # 8. error body shape and the message charset, checked behaviourally.
    error = schemas.get("ingest-error", {})
    if set(error.get("required", [])) != ERROR_BODY_FIELDS:
        violations.append(
            f"ingest-error: required fields must be {sorted(ERROR_BODY_FIELDS)}")
    if error.get("additionalProperties") is not False:
        violations.append("ingest-error: the error body must be closed")
    message = error.get("properties", {}).get("message", {})
    pattern = message.get("pattern")
    try:
        regex = re.compile(pattern) if isinstance(pattern, str) else None
    except re.error:
        regex = None
    if regex is None:
        violations.append("ingest-error: message pattern missing or invalid")
    else:
        accepted = "plain ASCII message text, ok"
        for sample, want in [
            (accepted, True),
            ("brace {placeholder} lookalike", False),
            ("closing } brace", False),
            ("control\x00byte", False),
            ("non-ascii café", False),
            ("line\nbreak", False),
        ]:
            if bool(regex.search(sample)) != want:
                violations.append(
                    "ingest-error: message pattern fails the charset "
                    f"contract on {sample!r}")

    return violations


def apply_mutation(schema: dict, mutation) -> None:
    mutation(schema)


def run_self_test() -> int:
    base = load_schemas()
    if base is None:
        return 2
    if check_family(base):
        fail("self-test base: the committed family itself is invalid")
        return 2

    passed = 0
    failed = 0
    for label, stem, mutation in SELF_TEST_CASES:
        mutated = copy.deepcopy(base)
        apply_mutation(mutated[stem], mutation)
        violations = check_family(mutated)
        rejected = bool(violations)
        if rejected:
            passed += 1
            print(f"  ok  rejects: {label}")
        else:
            failed += 1
            print(f"  FAIL should reject: {label}")
    print(f"self-test: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 2


def main(argv: list[str]) -> int:
    if "--self-test" in argv[1:]:
        return run_self_test()
    if argv[1:]:
        fail(f"unknown arguments: {' '.join(argv[1:])}")
        return 2

    schemas = load_schemas()
    if schemas is None:
        return 2

    violations = check_family(schemas)
    for violation in violations:
        fail(violation)
    if violations:
        return 2

    enums = sum(1 for doc in schemas.values()
                for node, _ in walk(doc) if "enum" in node)
    refs = sum(1 for doc in schemas.values()
               for node, _ in walk(doc)
               if isinstance(node.get("$ref"), str))
    print(f"agent-archivist wire schemas: {len(schemas)} top-level schemas")
    print(f"refs resolved: {refs}, closed enums guarded: {enums}")
    print("OK: schemas/v1 satisfies docs/notes/wire-schemas.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
