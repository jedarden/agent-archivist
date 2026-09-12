#!/usr/bin/env python3
"""Control-trust schema coherence gate for Agent Archivist.

Validates the ``archivist.control/v1`` family against the internal
contracts of ``docs/notes/control-trust-schemas.md`` (authority: plan
Sections 5, 7.1, and 7.5; requirements ID-003, ID-008, ID-009, SEC-006):

1. both family schemas parse, declare draft 2020-12, and carry the
   ``urn:agent-archivist:schema:v1:<stem>`` id matching the filename, and
   the envelope really is a conventions registry (shared defs plus metadata,
   no instance shape of its own);
2. the namespace is pinned: the envelope's ``namespace`` metadata, the
   ``schema-namespace`` const, and the record-schema references all agree on
   ``archivist.control/v1``, fail-closed;
3. the closed record-type, record-kind, and operation enums carry
   fail-closed security-bearing metadata, and the recordTypes registry is
   coherent: shipped types appear in the enum, the enum holds nothing
   unshipped, write classes are legal record-kind values, and every
   object-key pattern resolves inside the envelope;
4. every shipped record schema composes the wrapper flat: each member the
   wrapper registry requires for that record's kind is present, required,
   and references the registry's declared source (a narrowing ``const``
   beside the ``$ref`` is the one allowed difference), the signed epoch is
   required exactly for current-pointer records, and every object level
   that declares properties is closed (``additionalProperties: false``);
5. no private-key material in any field: member names matching the banned
   grammar (private, secret, seed) are rejected outright, and the public
   key members reference the common public shapes (SEC-006);
6. behaviourally (draft 2020-12, cross-file refs resolved through a
   referencing registry over ``schemas/v1``): a pinned synthetic
   linked-client record validates — with both key IDs computed by the
   pinned SHA-256-of-encoded-public-key derivation and the object key
   re-derived from the record's own identifiers, proving the
   computable-from-published-records property on the golden instance —
   and every mutation of it is rejected (unknown namespace, undeclared
   member, private-key member, zero and fractional epochs, empty and
   unknown scope values, unknown kind, not-yet-shipped record type,
   malformed key material, missing wrapper member). The receipt-key
   object-key pattern is cross-checked against the certificate's
   documented object key in ``schemas/v1/ingest-receipt.json``.

On success it prints a summary and exits 0. Any failure prints a report
on stderr and exits 2. A missing ``jsonschema`` module is a failure,
never a silent skip of the behavioural checks.

``--self-test`` mutates a copy of the committed family and fails unless
every mutation is rejected, proving the rejection paths (opened shape,
banned member name, dropped fail-closed metadata, registry/enum drift,
wrapper drift, epoch-bound drift, public-shape drift, key-pattern drift)
rather than only the accept path.

Usage::

    tools/check-control-schemas.py [--self-test]

Standard library plus ``jsonschema`` (already a baseline dependency of
the fixture gates). Its output names schemas, fields, and rules only.
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

ENVELOPE_STEM = "control-envelope"
RECORD_STEMS = ("control-client",)

NAMESPACE = "archivist.control/v1"
KINDS = ("immutable", "current-pointer")
ENVELOPE_DEFS = (
    "schema-namespace",
    "record-type",
    "record-kind",
    "authorization-epoch",
    "client-object-key",
    "revocation-object-key",
    "receipt-key-object-key",
)
RESERVED_KEY_DEFS = ("revocation-object-key", "receipt-key-object-key")
BANNED_MEMBER = re.compile(r"private|secret|seed", re.IGNORECASE)
PUBLIC_KEY_REF = URN_PREFIX + "common#/$defs/ed25519-public-key-hex"
SIGNATURE_ALGORITHM_REF = URN_PREFIX + "common#/$defs/signature-algorithm"

# Plan-pinned constants (Sections 5 and 7.5). Changing one is a contract
# change that must touch schema, note, and gate in the same commit.
PINNED = {
    ("control-client", ("x-archivist", "trustRecordCacheTtlSeconds")): 60,
    ("control-client", ("x-archivist", "rotationVerificationOverlapHours")): 24,
}
CERTIFICATE_KEY_TEMPLATE = (
    "tenants/<tenant_id>/v1/control/receipt-keys/<key_id>.json"
)

# Pinned synthetic constants (SEC-010: zero entropy, public material only).
# Constructed at runtime so no long hexadecimal literal — indistinguishable
# at a glance from secret material — ever sits in this file's source.
TENANT_ID = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d"
CLIENT_ID = "0f1e2d3c-4b5a-4968-8776-5544332211ff"
CLIENT_PUBLIC_KEY = "cd" * 32
AUTHORITY_PUBLIC_KEY = "ab" * 32
SYNTHETIC_SIGNATURE = "00" * 64
SIGNED_AT = "2026-09-11T00:00:00Z"


def key_id(public_key_hex: str) -> str:
    """The pinned key-ID derivation: SHA-256 of the encoded public key."""
    import hashlib

    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def golden_record() -> dict:
    return {
        "schema": NAMESPACE,
        "record_type": "linked-client",
        "record_kind": "current-pointer",
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "key_id": key_id(CLIENT_PUBLIC_KEY),
        "key_algorithm": "ed25519",
        "public_key": CLIENT_PUBLIC_KEY,
        "scopes": {
            "harnesses": ["claude-code", "codex"],
            "operations": ["ingest"],
        },
        "authorization_epoch": 3,
        "signed_at": SIGNED_AT,
        "authority_key_id": key_id(AUTHORITY_PUBLIC_KEY),
        "authority_signature": SYNTHETIC_SIGNATURE,
    }


# Behavioural mutations of the golden record: label -> must-be-rejected
# mutation. Each names the acceptance clause it proves.
INSTANCE_REJECTIONS = [
    ("unknown namespace", lambda r: r.__setitem__("schema", NAMESPACE + "2")),
    ("undeclared member", lambda r: r.__setitem__("display_name", "lab")),
    ("private-key member", lambda r: r.__setitem__("private_key", "ab" * 32)),
    ("zero epoch", lambda r: r.__setitem__("authorization_epoch", 0)),
    ("fractional epoch", lambda r: r.__setitem__("authorization_epoch", 1.5)),
    ("empty harness allowlist", lambda r: r["scopes"].__setitem__("harnesses", [])),
    ("unknown operation token", lambda r: r["scopes"].__setitem__("operations", ["export"])),
    ("undeclared scope member", lambda r: r["scopes"].__setitem__("origins", [])),
    ("unknown record kind", lambda r: r.__setitem__("record_kind", "pointer")),
    ("not-yet-shipped record type", lambda r: r.__setitem__("record_type", "revocation")),
    ("non-canonical public key", lambda r: r.__setitem__("public_key", "CD" * 32)),
    ("malformed authority signature", lambda r: r.__setitem__("authority_signature", "00" * 63)),
    ("missing wrapper member", lambda r: r.pop("signed_at")),
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
    for stem in (ENVELOPE_STEM, *RECORD_STEMS):
        if stem not in schemas:
            fail(f"{SCHEMA_DIR}/{stem}.json: missing from the control family")
            ok = False
    return schemas if ok else None


def resolve_pointer(doc: dict, pointer: str) -> bool:
    node: object = doc
    for raw in pointer.strip("/").split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return False
    return True


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


def expected_ref(source: str) -> str:
    """A wrapper source '#/$defs/x' resolves inside the envelope's URN."""
    if source.startswith("#/"):
        return URN_PREFIX + ENVELOPE_STEM + source
    return source


def check_envelope(schemas: dict[str, dict]) -> list[str]:
    violations: list[str] = []
    env = schemas[ENVELOPE_STEM]

    # 1. Registry shape: shared defs and metadata, no instance shape.
    if "type" in env or "properties" in env:
        violations.append(
            f"{ENVELOPE_STEM}: the envelope is a conventions registry, not an "
            "instance schema — record types own the instance shapes")
    if set(env.get("$defs", {})) != set(ENVELOPE_DEFS):
        violations.append(
            f"{ENVELOPE_STEM}: $defs must be exactly {sorted(ENVELOPE_DEFS)}")
    meta = env.get("x-archivist", {})

    # 2. Namespace pin.
    if meta.get("namespace") != NAMESPACE or meta.get("namespaceField") != "schema":
        violations.append(
            f"{ENVELOPE_STEM}: namespace metadata must be {NAMESPACE!r} on the "
            "`schema` field")
    ns = env.get("$defs", {}).get("schema-namespace", {})
    if ns.get("const") != NAMESPACE:
        violations.append(
            f"{ENVELOPE_STEM}: schema-namespace const must be {NAMESPACE!r}")
    elif ns.get("x-archivist", {}).get("failClosed") is not True:
        violations.append(
            f"{ENVELOPE_STEM}: schema-namespace must carry failClosed: true")
    if env.get("x-archivist", {}).get("floats") is not False:
        violations.append(f"{ENVELOPE_STEM}: x-archivist.floats must be false")

    # 3. Closed enums carry fail-closed security metadata; no floats.
    for name in ("record-type", "record-kind"):
        node = env.get("$defs", {}).get(name, {})
        enum = node.get("enum")
        if not isinstance(enum, list) or not enum:
            violations.append(f"{ENVELOPE_STEM}: {name} must be a closed enum")
            continue
        emeta = node.get("x-archivist", {})
        if emeta.get("bearing") != "security" or emeta.get("failClosed") is not True:
            violations.append(
                f"{ENVELOPE_STEM}: {name} must be security-bearing with "
                "failClosed: true")
    if list(env.get("$defs", {}).get("record-kind", {}).get("enum", [])) != list(KINDS):
        violations.append(
            f"{ENVELOPE_STEM}: record-kind enum must be {list(KINDS)}")

    # 4. recordTypes registry coherence.
    registry = meta.get("recordTypes", [])
    shipped = {e.get("type"): e for e in registry if e.get("status") == "shipped"}
    enum_types = set(env.get("$defs", {}).get("record-type", {}).get("enum", []))
    if set(shipped) != enum_types:
        violations.append(
            f"{ENVELOPE_STEM}: shipped recordTypes {sorted(shipped)} and the "
            f"record-type enum {sorted(enum_types)} disagree")
    for entry in registry:
        etype = entry.get("type", "<unnamed>")
        if entry.get("status") not in ("shipped", "pending"):
            violations.append(
                f"{ENVELOPE_STEM}: recordType {etype} has unknown status")
        if entry.get("writeClass") not in KINDS:
            violations.append(
                f"{ENVELOPE_STEM}: recordType {etype} writeClass must be one "
                f"of {list(KINDS)}")
        pattern = entry.get("objectKeyPattern", "")
        if not pattern.startswith("#/") or not resolve_pointer(env, pattern[1:]):
            violations.append(
                f"{ENVELOPE_STEM}: recordType {etype} objectKeyPattern "
                f"{pattern!r} does not resolve in the envelope")
        schema_path = entry.get("schema")
        if entry.get("status") == "shipped":
            if not schema_path or not (ROOT / schema_path).is_file():
                violations.append(
                    f"{ENVELOPE_STEM}: recordType {etype} is shipped but its "
                    f"schema {schema_path!r} is missing")
        elif schema_path:
            violations.append(
                f"{ENVELOPE_STEM}: recordType {etype} is pending and must not "
                "name a schema")
    for name in RESERVED_KEY_DEFS:
        if any(e.get("objectKeyPattern") == f"#/$defs/{name}" for e in registry):
            violations.append(
                f"{ENVELOPE_STEM}: {name} is reserved for a pending record "
                "type and must not be claimed by a shipped one")

    # 5. Wrapper registry: members resolve, kinds agree, epoch discipline.
    wrapper = meta.get("wrapper", {})
    members = wrapper.get("members", {})
    if not members:
        violations.append(f"{ENVELOPE_STEM}: wrapper.members registry is missing")
    for member, source in members.items():
        if not isinstance(source, str) or not (
            source.startswith("#/")
            and resolve_pointer(env, source[1:])
            or source.startswith(URN_PREFIX)
            and resolve_pointer(
                schemas.get(source[len(URN_PREFIX):].split("#", 1)[0], {}),
                source.split("#", 1)[1] if "#" in source else "")
        ):
            violations.append(
                f"{ENVELOPE_STEM}: wrapper member {member} source {source!r} "
                "does not resolve")
    required_by_kind = wrapper.get("requiredByKind", {})
    if set(required_by_kind) != set(KINDS):
        violations.append(
            f"{ENVELOPE_STEM}: requiredByKind must cover {list(KINDS)}")
    for kind, required in required_by_kind.items():
        if set(required) - set(members):
            violations.append(
                f"{ENVELOPE_STEM}: requiredByKind[{kind}] names members the "
                "wrapper does not define")
    if "authorization_epoch" not in required_by_kind.get("current-pointer", []):
        violations.append(
            f"{ENVELOPE_STEM}: current-pointer records must require the "
            "signed authorization epoch (plan Section 5)")
    if "authorization_epoch" in required_by_kind.get("immutable", []):
        violations.append(
            f"{ENVELOPE_STEM}: the epoch is not a wrapper requirement for "
            "immutable records — a type carries it only when it is part of "
            "the record's identity")

    # 6. The signing construction: control-record-v1, canonical-minus-member.
    signatures = meta.get("signatures", [])
    by_id = {s.get("id"): s for s in signatures}
    if set(by_id) != {"control-record-v1"}:
        violations.append(
            f"{ENVELOPE_STEM}: the signature registry must be exactly "
            "['control-record-v1']")
    attempt = by_id.get("control-record-v1", {})
    covered = str(attempt.get("covered"))
    if ("`authority_signature`" not in covered
            or attempt.get("authorityMember") != "authority_signature"
            or attempt.get("algorithm") != "ed25519"):
        violations.append(
            f"{ENVELOPE_STEM}: control-record-v1 must sign the RFC 8785 "
            "canonical record bytes minus `authority_signature`, under "
            "Ed25519, with the excluded member pinned in three places")

    # 7. Plan-pinned record constants.
    for (stem, path), value in PINNED.items():
        node: object = schemas.get(stem, {})
        for part in path:
            node = node.get(part, {}) if isinstance(node, dict) else {}
        if node != value:
            violations.append(
                f"{stem}: {'.'.join(path)} must be {value!r} (plan-pinned)")
    return violations


def check_record(schemas: dict[str, dict], stem: str) -> list[str]:
    violations: list[str] = []
    doc = schemas[stem]
    env = schemas[ENVELOPE_STEM]
    meta = env.get("x-archivist", {})
    wrapper_members = meta.get("wrapper", {}).get("members", {})
    required_by_kind = meta.get("wrapper", {}).get("requiredByKind", {})

    # 1. Instance shape, closed, namespace-pinned, no floats.
    if doc.get("type") != "object":
        violations.append(f"{stem}: must be an object instance schema")
    if doc.get("additionalProperties") is not False:
        violations.append(f"{stem}: the record shape must be closed")
    if doc.get("x-archivist", {}).get("floats") is not False:
        violations.append(f"{stem}: x-archivist.floats must be false")
    if doc.get("x-archivist", {}).get("namespace") != NAMESPACE:
        violations.append(f"{stem}: namespace metadata must be {NAMESPACE!r}")
    for node, _ in walk(doc):
        if node.get("type") == "number":
            violations.append(f"{stem}: type number (floats are forbidden)")
        props = node.get("properties")
        if isinstance(props, dict) and node.get("additionalProperties") is not False:
            violations.append(
                f"{stem}: every object level declaring properties must be "
                "closed")

    # 2. The record's own kind and type, narrowed by const.
    props = doc.get("properties", {})
    kind_node = props.get("record_kind", {})
    kind = kind_node.get("const")
    if kind not in KINDS:
        violations.append(
            f"{stem}: record_kind must narrow the envelope enum to one const")
    type_node = props.get("record_type", {})
    rtype = type_node.get("const")
    registry = {e.get("type"): e for e in meta.get("recordTypes", [])}
    entry = registry.get(rtype)
    if entry is None or entry.get("status") != "shipped":
        violations.append(
            f"{stem}: record_type const {rtype!r} is not a shipped record "
            "type in the envelope registry")
    elif entry.get("schema") != f"schemas/v1/{stem}.json":
        violations.append(
            f"{stem}: the envelope registry routes {rtype!r} to "
            f"{entry.get('schema')!r}, not this file")
    elif entry.get("writeClass") != kind:
        violations.append(
            f"{stem}: record_kind {kind!r} contradicts the registered write "
            f"class {entry.get('writeClass')!r} of {rtype!r}")

    # 3. Flat wrapper composition: every required wrapper member present,
    #    required, and referencing the registry's declared source.
    if kind in required_by_kind:
        for member in required_by_kind[kind]:
            node = props.get(member)
            if node is None:
                violations.append(
                    f"{stem}: wrapper member {member} missing "
                    f"(required for {kind} records)")
                continue
            if member not in doc.get("required", []):
                violations.append(
                    f"{stem}: wrapper member {member} must be required")
            source = wrapper_members.get(member)
            ref = node.get("$ref")
            if ref != expected_ref(source):
                violations.append(
                    f"{stem}: {member} must reference the wrapper source "
                    f"{expected_ref(source)!r} (found {ref!r})")
    for member in doc.get("required", []):
        if member not in props:
            violations.append(f"{stem}: required member {member} has no property")

    # 4. No private-key material in any field (SEC-006): banned member
    #    names, and key members keep the common public shapes.
    for name in list(props) + list(doc.get("$defs", {})):
        if BANNED_MEMBER.search(name):
            violations.append(
                f"{stem}: member name {name!r} matches the banned "
                "private/secret/seed grammar — control records carry public "
                "material only (SEC-006)")
    for node, _ in walk(doc):
        if isinstance(node.get("properties"), dict):
            for name, sub in node["properties"].items():
                if BANNED_MEMBER.search(name):
                    violations.append(
                        f"{stem}: member name {name!r} matches the banned "
                        "private/secret/seed grammar (SEC-006)")
    if props.get("public_key", {}).get("$ref") != PUBLIC_KEY_REF:
        violations.append(
            f"{stem}: public_key must reference the common "
            "ed25519-public-key-hex shape")
    if props.get("key_algorithm", {}).get("$ref") != SIGNATURE_ALGORITHM_REF:
        violations.append(
            f"{stem}: key_algorithm must reference the common closed "
            "signature-algorithm enum")
    return violations


def check_cross_family(schemas: dict[str, dict]) -> list[str]:
    """The reserved receipt-key pattern agrees with the receipt certificate."""
    violations: list[str] = []
    pattern = (
        schemas.get(ENVELOPE_STEM, {}).get("$defs", {})
        .get("receipt-key-object-key", {}).get("pattern"))
    cert = (
        schemas.get("ingest-receipt", {}).get("$defs", {})
        .get("receipt-key-certificate", {}))
    template = cert.get("x-archivist", {}).get("objectKey")
    if not isinstance(pattern, str) or not isinstance(template, str):
        violations.append(
            "cross-family: the receipt-key pattern or the certificate's "
            "objectKey metadata is missing")
        return violations
    concrete = template.replace("<tenant_id>", TENANT_ID).replace(
        "<key_id>", key_id(AUTHORITY_PUBLIC_KEY))
    if not re.match(pattern, concrete):
        violations.append(
            "cross-family: receipt-key-object-key does not match the "
            "certificate's documented object key — the receipt-key record "
            "type must consume the certificate definition, not fork it")
    return violations


def build_validator(schemas: dict[str, dict], stem: str):
    try:
        import jsonschema
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
    except ImportError:
        fail("jsonschema is not installed: behavioural validation cannot run "
             "(pip install jsonschema)")
        return None
    registry = Registry().with_resources([
        (doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012))
        for doc in schemas.values() if "$id" in doc
    ])
    return jsonschema.Draft202012Validator(schemas[stem], registry=registry)


def check_behaviour(schemas: dict[str, dict]) -> list[str]:
    violations: list[str] = []

    # Schema documents themselves validate as draft 2020-12.
    for stem in (ENVELOPE_STEM, *RECORD_STEMS):
        try:
            import jsonschema
            jsonschema.Draft202012Validator.check_schema(schemas[stem])
        except Exception as exc:  # noqa: BLE001 - report, don't crash
            violations.append(f"{stem}: not a valid draft 2020-12 schema ({exc})")
    if violations:
        return violations

    validator = build_validator(schemas, "control-client")
    if validator is None:
        return ["control-client: behavioural validator unavailable"]

    # The golden record: key IDs computed by the pinned derivation, and the
    # object key re-derived from the record's own identifiers.
    record = golden_record()
    if record["key_id"] != key_id(record["public_key"]):
        violations.append("golden record: key_id is not SHA-256(public_key)")
    pattern = (
        schemas[ENVELOPE_STEM].get("$defs", {})
        .get("client-object-key", {}).get("pattern"))
    derived_key = (
        f"tenants/{record['tenant_id']}/v1/control/clients/"
        f"{record['client_id']}.json")
    if not isinstance(pattern, str) or not re.match(pattern, derived_key):
        violations.append(
            "golden record: the object key derived from the record's own "
            "identifiers does not satisfy client-object-key")
    # The pattern must also reject near-miss keys, so a relaxed drift cannot
    # pass on the one positive example alone.
    near_misses = {
        "another record type's key": (
            f"tenants/{record['tenant_id']}/v1/control/revocations/"
            f"{record['client_id']}/3.json"),
        "non-canonical tenant segment": (
            f"tenants/{record['tenant_id'].upper()}/v1/control/clients/"
            f"{record['client_id']}.json"),
        "missing .json suffix": (
            f"tenants/{record['tenant_id']}/v1/control/clients/"
            f"{record['client_id']}"),
    }
    for label, key in near_misses.items():
        if isinstance(pattern, str) and re.match(pattern, key):
            violations.append(
                "client-object-key must not accept a near-miss key "
                f"({label})")
    errors = sorted(validator.iter_errors(record))
    for error in errors:
        violations.append(f"golden record rejected: {error.message}")
    if errors:
        return violations

    for label, mutation in INSTANCE_REJECTIONS:
        candidate = copy.deepcopy(record)
        mutation(candidate)
        if validator.is_valid(candidate):
            violations.append(
                f"behaviour: a record with {label} must be rejected")
    return violations


def check_family(schemas: dict[str, dict]) -> list[str]:
    violations: list[str] = []
    for stem, doc in schemas.items():
        if doc.get("$schema") != DRAFT:
            violations.append(f"{stem}: $schema must be {DRAFT}")
        if doc.get("$id") != URN_PREFIX + stem:
            violations.append(f"{stem}: $id must be {URN_PREFIX}{stem}")
    violations += check_envelope(schemas)
    for stem in RECORD_STEMS:
        if stem in schemas:
            violations += check_record(schemas, stem)
    violations += check_cross_family(schemas)
    violations += check_behaviour(schemas)
    return violations


# Self-test mutations: (label, stem, mutation) — each must be rejected.
SELF_TEST_CASES = [
    ("opened record shape", "control-client",
     lambda s: s.pop("additionalProperties")),
    ("banned member name", "control-client",
     lambda s: s["properties"].__setitem__(
         "secret_seed", {"type": "string"})),
    ("record-kind failClosed dropped", "control-envelope",
     lambda s: s["$defs"]["record-kind"]["x-archivist"].pop("failClosed")),
    ("enum/registry drift", "control-envelope",
     lambda s: s["$defs"]["record-type"]["enum"].append("delegation")),
    ("wrapper member dropped", "control-client",
     lambda s: (s["properties"].pop("authority_signature"),
                s["required"].remove("authority_signature"))),
    ("epoch bound drift", "control-envelope",
     lambda s: s["$defs"]["authorization-epoch"].__setitem__("minimum", 0)),
    ("public shape drift", "control-client",
     lambda s: s["properties"]["public_key"].__setitem__(
         "$ref", "urn:agent-archivist:schema:v1:common#/$defs/opaque-id")),
    ("object-key pattern drift", "control-envelope",
     lambda s: s["$defs"]["client-object-key"].__setitem__(
         "pattern", "^tenants/.+$")),
]


def run_self_test() -> int:
    base = load_schemas()
    if base is None:
        return 2
    if check_family(base):
        fail("self-test base: the committed family itself is invalid")
        for violation in check_family(base):
            fail(violation)
        return 2

    passed = 0
    failed = 0
    for label, stem, mutation in SELF_TEST_CASES:
        mutated = copy.deepcopy(base)
        mutation(mutated[stem])
        rejected = bool(check_family(mutated))
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

    enums = sum(
        1 for doc in (schemas[ENVELOPE_STEM], *(schemas[s] for s in RECORD_STEMS))
        for node, _ in walk(doc) if "enum" in node)
    print(f"agent-archivist control trust family: {len(RECORD_STEMS) + 1} schemas")
    print(f"closed enums guarded: {enums}, "
          f"behavioural rejections proven: {len(INSTANCE_REJECTIONS)}")
    print("OK: schemas/v1 control family satisfies "
          "docs/notes/control-trust-schemas.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
