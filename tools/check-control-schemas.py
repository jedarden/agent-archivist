#!/usr/bin/env python3
"""Control-trust schema coherence gate for Agent Archivist.

Validates the ``archivist.control/v1`` family against the internal
contracts of ``docs/notes/control-trust-schemas.md`` (authority: plan
Sections 5, 7.1, 7.2, and 7.5; requirements ID-003, ID-005, ID-006,
ID-008, ID-009, SEC-006):

1. all five family schemas parse, declare draft 2020-12, and carry the
   ``urn:agent-archivist:schema:v1:<stem>`` id matching the filename, and
   the envelope really is a conventions registry (shared defs plus metadata,
   no instance shape of its own);
2. the namespace is pinned: the envelope's ``namespace`` metadata, the
   ``schema-namespace`` const, and the record-schema references all agree on
   ``archivist.control/v1``, fail-closed;
3. the closed record-type, record-kind, and operation enums carry
   fail-closed security-bearing metadata, and the recordTypes registry is
   coherent: shipped types appear in the enum, the enum holds nothing
   unshipped, write classes are legal record-kind values, every
   object-key pattern resolves inside the envelope, and every
   ``keyMembers`` entry is a required property of the shipped record —
   the store derives object keys from exactly those validated fields, so
   the revocation and rotation records must require the epochs their
   keys name and the delegation record the relay and origin its key
   names;
4. every shipped record schema composes the wrapper flat: each member the
   wrapper registry requires for that record's kind is present, required,
   and references the registry's declared source (a narrowing ``const``
   beside the ``$ref`` is the one allowed difference) — and any other
   property that is a wrapper member references the declared source too,
   so the identity-carried epochs of the immutable revocation and
   rotation records cannot fork the shared definition — while every
   object level that declares properties is closed
   (``additionalProperties: false``);
5. no private-key material in any field: member names matching the banned
   grammar (private, secret, seed) are rejected outright, and key-bearing
   members, where a record type carries them, reference the common public
   shapes — the rotation record's previous and current halves alike
   (SEC-006);
6. the timing constants are named, not prose: the envelope's ``constants``
   registry carries the plan-pinned 60-second trust-record cache TTL
   (Section 5; EC-09), the 300-second authorization window, the
   300-second clock-skew allowance (Sections 5 and 7.2), and the 24-hour
   rotation verification overlap (Section 5), and each consuming schema
   pins the same number where it applies — the linked-client TTL and
   overlap, the delegation and rotation TTLs, the rotation overlap, the
   revocation propagation bound, and the two wire-family pins in
   ``ingest-request.json`` — with agreement proven mechanically, never
   assumed;
7. behaviourally (draft 2020-12, cross-file refs resolved through a
   referencing registry over ``schemas/v1``): pinned synthetic
   linked-client, revocation, delegation, and rotation records validate —
   one coherent authorization history: the client at epoch 3 whose key
   that epoch's golden rotation established, the relay grant presenting
   that client as origin, and the revocation of that epoch — with key IDs
   computed by the pinned SHA-256-of-encoded-public-key derivation and
   object keys re-derived from each record's own identifiers, proving the
   computable-from-published-records property on the golden instances,
   on the revocation and rotation keys at the epoch ceiling (the 18-digit
   lockstep between the epoch bound and both key grammars), and on the
   delegation record's withdrawn variant (the only withdrawal a
   current-pointer shape permits) — and every mutation of any of the
   four is rejected (unknown namespace, undeclared member, private-key
   member, zero, fractional, and above-bound epochs, empty, wildcard,
   and unknown scope values, unknown delegation state, unknown kind,
   wrong or unshipped record type, malformed key material, missing
   wrapper and identity members). The receipt-key object-key pattern is
   cross-checked against the certificate's documented object key in
   ``schemas/v1/ingest-receipt.json``.

On success it prints a summary and exits 0. Any failure prints a report
on stderr and exits 2. A missing ``jsonschema`` module is a failure,
never a silent skip of the behavioural checks.

``--self-test`` mutates a copy of the committed family and fails unless
every mutation is rejected, proving the rejection paths (opened shape,
banned member name, dropped fail-closed metadata, registry/enum drift,
wrapper drift, epoch-bound drift, public-shape drift, key-pattern drift,
dropped identity members, unshipped record types, constant drift, and
the cross-file constant fork) rather than only the accept path.

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
RECORD_STEMS = ("control-client", "control-revocation", "control-delegation",
                "control-rotation")

NAMESPACE = "archivist.control/v1"
KINDS = ("immutable", "current-pointer")
ENVELOPE_DEFS = (
    "schema-namespace",
    "record-type",
    "record-kind",
    "authorization-epoch",
    "client-object-key",
    "delegation-object-key",
    "revocation-object-key",
    "rotation-object-key",
    "receipt-key-object-key",
)
# Key patterns still awaiting their record type: no shipped type may claim
# one. The revocation, delegation, and rotation patterns left this set as
# their records shipped.
RESERVED_KEY_DEFS = ("receipt-key-object-key",)
BANNED_MEMBER = re.compile(r"private|secret|seed", re.IGNORECASE)
PUBLIC_KEY_REF = URN_PREFIX + "common#/$defs/ed25519-public-key-hex"
SIGNATURE_ALGORITHM_REF = URN_PREFIX + "common#/$defs/signature-algorithm"

# The envelope's named-constant registry: exactly these names, no more.
CONSTANT_NAMES = (
    "trustRecordCacheTtlSeconds",
    "authorizationWindowSeconds",
    "clockSkewAllowanceSeconds",
    "rotationVerificationOverlapHours",
)

# Plan-pinned constants (Sections 5, 7.2, 7.5, and EC-09). Changing one is
# a contract change that must touch schema, note, and gate in the same
# commit. The envelope registry is the cross-family home; the consuming
# schemas pin the same number where it applies.
PINNED = {
    ("control-envelope", ("x-archivist", "constants",
                          "trustRecordCacheTtlSeconds", "value")): 60,
    ("control-envelope", ("x-archivist", "constants",
                          "authorizationWindowSeconds", "value")): 300,
    ("control-envelope", ("x-archivist", "constants",
                          "clockSkewAllowanceSeconds", "value")): 300,
    ("control-envelope", ("x-archivist", "constants",
                          "rotationVerificationOverlapHours", "value")): 24,
    ("control-client", ("x-archivist", "trustRecordCacheTtlSeconds")): 60,
    ("control-client", ("x-archivist", "rotationVerificationOverlapHours")): 24,
    ("control-revocation",
     ("x-archivist", "revocationPropagationBoundSeconds")): 60,
    ("control-delegation", ("x-archivist", "trustRecordCacheTtlSeconds")): 60,
    ("control-rotation", ("x-archivist", "trustRecordCacheTtlSeconds")): 60,
    ("control-rotation", ("x-archivist",
                          "rotationVerificationOverlapHours")): 24,
    ("ingest-request", ("x-archivist", "authorizationWindowSeconds")): 300,
    ("ingest-request", ("x-archivist", "clockSkewAllowanceSeconds")): 300,
}

# Named-constant agreement: (left, right) paths whose values must be
# equal, so the consuming schemas and the envelope registry cannot fork.
# The revocation propagation bound is deliberately the same number as the
# cache TTL — propagation is bounded by the cache and by nothing else —
# and the rotation overlap is hours-valued everywhere it appears, so the
# agreement is plain equality, never a unit conversion.
CONSTANT_AGREEMENTS = (
    (("control-envelope", ("x-archivist", "constants",
                           "trustRecordCacheTtlSeconds", "value")),
     ("control-client", ("x-archivist", "trustRecordCacheTtlSeconds"))),
    (("control-envelope", ("x-archivist", "constants",
                           "trustRecordCacheTtlSeconds", "value")),
     ("control-revocation",
      ("x-archivist", "revocationPropagationBoundSeconds"))),
    (("control-envelope", ("x-archivist", "constants",
                           "trustRecordCacheTtlSeconds", "value")),
     ("control-delegation", ("x-archivist", "trustRecordCacheTtlSeconds"))),
    (("control-envelope", ("x-archivist", "constants",
                           "trustRecordCacheTtlSeconds", "value")),
     ("control-rotation", ("x-archivist", "trustRecordCacheTtlSeconds"))),
    (("control-envelope", ("x-archivist", "constants",
                           "authorizationWindowSeconds", "value")),
     ("ingest-request", ("x-archivist", "authorizationWindowSeconds"))),
    (("control-envelope", ("x-archivist", "constants",
                           "clockSkewAllowanceSeconds", "value")),
     ("ingest-request", ("x-archivist", "clockSkewAllowanceSeconds"))),
    (("control-envelope", ("x-archivist", "constants",
                           "rotationVerificationOverlapHours", "value")),
     ("control-client", ("x-archivist", "rotationVerificationOverlapHours"))),
    (("control-envelope", ("x-archivist", "constants",
                           "rotationVerificationOverlapHours", "value")),
     ("control-rotation",
      ("x-archivist", "rotationVerificationOverlapHours"))),
)
CERTIFICATE_KEY_TEMPLATE = (
    "tenants/<tenant_id>/v1/control/receipt-keys/<key_id>.json"
)

# Pinned synthetic constants (SEC-010: zero entropy, public material only).
# Constructed at runtime so no long hexadecimal literal — indistinguishable
# at a glance from secret material — ever sits in this file's source.
TENANT_ID = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d"
CLIENT_ID = "0f1e2d3c-4b5a-4968-8776-5544332211ff"
RELAY_CLIENT_ID = "2b1a0f9e-8d7c-4e6b-9a5f-1e2d3c4b5a69"
CLIENT_PUBLIC_KEY = "cd" * 32
PREVIOUS_PUBLIC_KEY = "ef" * 32
AUTHORITY_PUBLIC_KEY = "ab" * 32
SYNTHETIC_SIGNATURE = "00" * 64
SIGNED_AT = "2026-09-11T00:00:00Z"


def key_id(public_key_hex: str) -> str:
    """The pinned key-ID derivation: SHA-256 of the encoded public key."""
    import hashlib

    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def golden_client_record() -> dict:
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


def golden_revocation_record() -> dict:
    """The revocation of the golden client's epoch 3: the same tenant,
    client, and key the linked-client golden pins, so the goldens are
    one coherent control-plane story rather than unrelated objects."""
    return {
        "schema": NAMESPACE,
        "record_type": "revocation",
        "record_kind": "immutable",
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "revoked_key_id": key_id(CLIENT_PUBLIC_KEY),
        "authorization_epoch": 3,
        "signed_at": SIGNED_AT,
        "authority_key_id": key_id(AUTHORITY_PUBLIC_KEY),
        "authority_signature": SYNTHETIC_SIGNATURE,
    }


def golden_delegation_record() -> dict:
    """The current grant of the golden relay-for-origin relation: the
    relay may present the golden client's (the origin's) claude-code
    sessions. Epoch 2 — the grant was revised once (epoch 1 allowed
    claude-code and codex; epoch 2 narrowed the harness dimension to
    claude-code only), which exercises the relation's own epoch sequence
    rather than either client's."""
    return {
        "schema": NAMESPACE,
        "record_type": "delegation",
        "record_kind": "current-pointer",
        "tenant_id": TENANT_ID,
        "relay_client_id": RELAY_CLIENT_ID,
        "origin_client_id": CLIENT_ID,
        "delegation_state": "active",
        "scopes": {
            "harnesses": ["claude-code"],
            "operations": ["ingest"],
        },
        "authorization_epoch": 2,
        "signed_at": SIGNED_AT,
        "authority_key_id": key_id(AUTHORITY_PUBLIC_KEY),
        "authority_signature": SYNTHETIC_SIGNATURE,
    }


def golden_rotation_record() -> dict:
    """The rotation that established the golden client's epoch 3: the new
    half is the golden linked-client record's own key, the previous half
    is synthetic, so the rotation, client, and revocation goldens are one
    authorization history — key A at epoch 2, rotated to key B at
    epoch 3, and epoch 3 later revoked."""
    return {
        "schema": NAMESPACE,
        "record_type": "rotation",
        "record_kind": "immutable",
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "previous_epoch": 2,
        "previous_public_key": PREVIOUS_PUBLIC_KEY,
        "previous_key_id": key_id(PREVIOUS_PUBLIC_KEY),
        "key_algorithm": "ed25519",
        "public_key": CLIENT_PUBLIC_KEY,
        "key_id": key_id(CLIENT_PUBLIC_KEY),
        "authorization_epoch": 3,
        "signed_at": SIGNED_AT,
        "authority_key_id": key_id(AUTHORITY_PUBLIC_KEY),
        "authority_signature": SYNTHETIC_SIGNATURE,
    }


# Behavioural mutations of the golden records: label -> must-be-rejected
# mutation. Each names the acceptance clause it proves.
CLIENT_REJECTIONS = [
    ("unknown namespace", lambda r: r.__setitem__("schema", NAMESPACE + "2")),
    ("undeclared member", lambda r: r.__setitem__("display_name", "lab")),
    ("private-key member", lambda r: r.__setitem__("private_key", "ab" * 32)),
    ("zero epoch", lambda r: r.__setitem__("authorization_epoch", 0)),
    ("fractional epoch", lambda r: r.__setitem__("authorization_epoch", 1.5)),
    ("empty harness allowlist", lambda r: r["scopes"].__setitem__("harnesses", [])),
    ("unknown operation token", lambda r: r["scopes"].__setitem__("operations", ["export"])),
    ("undeclared scope member", lambda r: r["scopes"].__setitem__("origins", [])),
    ("unknown record kind", lambda r: r.__setitem__("record_kind", "pointer")),
    ("wrong record type token", lambda r: r.__setitem__("record_type", "revocation")),
    ("unshipped record type token", lambda r: r.__setitem__("record_type", "receipt-key")),
    ("non-canonical public key", lambda r: r.__setitem__("public_key", "CD" * 32)),
    ("malformed authority signature", lambda r: r.__setitem__("authority_signature", "00" * 63)),
    ("missing wrapper member", lambda r: r.pop("signed_at")),
]

REVOCATION_REJECTIONS = [
    ("unknown namespace", lambda r: r.__setitem__("schema", NAMESPACE + "2")),
    ("undeclared member", lambda r: r.__setitem__("reason", "compromised")),
    ("private-key member", lambda r: r.__setitem__("private_key", "ab" * 32)),
    ("zero epoch", lambda r: r.__setitem__("authorization_epoch", 0)),
    ("epoch above the 18-digit key-grammar bound",
     lambda r: r.__setitem__("authorization_epoch", 10 ** 18)),
    ("fractional epoch", lambda r: r.__setitem__("authorization_epoch", 1.5)),
    ("unknown record kind", lambda r: r.__setitem__("record_kind", "pointer")),
    ("wrong record type token", lambda r: r.__setitem__("record_type", "linked-client")),
    ("unshipped record type token", lambda r: r.__setitem__("record_type", "receipt-key")),
    ("non-canonical revoked key ID", lambda r: r.__setitem__("revoked_key_id", "AB" * 32)),
    ("short revoked key ID", lambda r: r.__setitem__("revoked_key_id", "ab" * 31)),
    ("malformed authority signature", lambda r: r.__setitem__("authority_signature", "00" * 63)),
    ("missing wrapper member", lambda r: r.pop("signed_at")),
    ("missing identity member", lambda r: r.pop("client_id")),
]

DELEGATION_REJECTIONS = [
    ("unknown namespace", lambda r: r.__setitem__("schema", NAMESPACE + "2")),
    ("undeclared member", lambda r: r.__setitem__("granted_by", "ops")),
    ("private-key member", lambda r: r.__setitem__("relay_private_key", "ab" * 32)),
    ("zero epoch", lambda r: r.__setitem__("authorization_epoch", 0)),
    ("fractional epoch", lambda r: r.__setitem__("authorization_epoch", 1.5)),
    ("empty harness allowlist", lambda r: r["scopes"].__setitem__("harnesses", [])),
    ("wildcard harness token", lambda r: r["scopes"].__setitem__("harnesses", ["*"])),
    ("unknown operation token", lambda r: r["scopes"].__setitem__("operations", ["export"])),
    ("undeclared scope member", lambda r: r["scopes"].__setitem__("tenants", [])),
    ("unknown delegation state", lambda r: r.__setitem__("delegation_state", "suspended")),
    ("unknown record kind", lambda r: r.__setitem__("record_kind", "pointer")),
    ("wrong record type token", lambda r: r.__setitem__("record_type", "revocation")),
    ("unshipped record type token", lambda r: r.__setitem__("record_type", "receipt-key")),
    ("malformed authority signature", lambda r: r.__setitem__("authority_signature", "00" * 63)),
    ("missing wrapper member", lambda r: r.pop("signed_at")),
    ("missing identity member", lambda r: r.pop("origin_client_id")),
    ("missing state member", lambda r: r.pop("delegation_state")),
]

ROTATION_REJECTIONS = [
    ("unknown namespace", lambda r: r.__setitem__("schema", NAMESPACE + "2")),
    ("undeclared member", lambda r: r.__setitem__("reason", "scheduled")),
    ("private-key member", lambda r: r.__setitem__("previous_private_key", "ab" * 32)),
    ("zero epoch", lambda r: r.__setitem__("authorization_epoch", 0)),
    ("epoch above the 18-digit key-grammar bound",
     lambda r: r.__setitem__("authorization_epoch", 10 ** 18)),
    ("fractional epoch", lambda r: r.__setitem__("authorization_epoch", 1.5)),
    ("zero previous epoch", lambda r: r.__setitem__("previous_epoch", 0)),
    ("unknown record kind", lambda r: r.__setitem__("record_kind", "pointer")),
    ("wrong record type token", lambda r: r.__setitem__("record_type", "linked-client")),
    ("unshipped record type token", lambda r: r.__setitem__("record_type", "receipt-key")),
    ("non-canonical previous public key",
     lambda r: r.__setitem__("previous_public_key", "EF" * 32)),
    ("non-canonical public key", lambda r: r.__setitem__("public_key", "CD" * 32)),
    ("short key ID", lambda r: r.__setitem__("key_id", "ab" * 31)),
    ("malformed authority signature", lambda r: r.__setitem__("authority_signature", "00" * 63)),
    ("missing wrapper member", lambda r: r.pop("signed_at")),
    ("missing identity member", lambda r: r.pop("client_id")),
    ("missing previous key material", lambda r: r.pop("previous_public_key")),
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


def dig(doc, path):
    """Follow a member path; None whenever any step is missing."""
    node = doc
    for part in path:
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


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
        key_members = entry.get("keyMembers", [])
        if (not isinstance(key_members, list) or not key_members
                or not all(isinstance(m, str) for m in key_members)
                or len(set(key_members)) != len(key_members)):
            violations.append(
                f"{ENVELOPE_STEM}: recordType {etype} keyMembers must be a "
                "non-empty list of unique member names — the fields the "
                "store derives the object key from (ID-008)")
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

    # 7. The named-constant registry: exactly the plan-pinned timing
    #    constants, each a structured entry with an integer value and a
    #    plan citation — named constants, not prose in a description.
    constants = meta.get("constants", {})
    if not isinstance(constants, dict) or set(constants) != set(CONSTANT_NAMES):
        violations.append(
            f"{ENVELOPE_STEM}: the constants registry must be exactly "
            f"{sorted(CONSTANT_NAMES)}")
    else:
        for name, entry in constants.items():
            if (not isinstance(entry, dict)
                    or isinstance(entry.get("value"), bool)
                    or not isinstance(entry.get("value"), int)
                    or not isinstance(entry.get("unit"), str)
                    or not isinstance(entry.get("plan"), list)
                    or not entry["plan"]
                    or not isinstance(entry.get("description"), str)):
                violations.append(
                    f"{ENVELOPE_STEM}: constant {name} must carry an "
                    "integer value, a unit, a non-empty plan citation "
                    "list, and a description")
        ttl = constants["trustRecordCacheTtlSeconds"].get("description", "")
        if "EC-09" not in ttl or "propagation" not in ttl:
            violations.append(
                f"{ENVELOPE_STEM}: the cache-TTL constant must cite EC-09 "
                "and name the revocation-propagation bound it is")

    # 8. Plan-pinned record constants, and cross-file agreement of every
    #    named constant with the schemas that pin it where it applies.
    for (stem, path), value in PINNED.items():
        node = dig(schemas.get(stem, {}), path)
        if node != value:
            violations.append(
                f"{stem}: {'.'.join(path)} must be {value!r} (plan-pinned)")
    for left, right in CONSTANT_AGREEMENTS:
        a = dig(schemas.get(left[0], {}), left[1])
        b = dig(schemas.get(right[0], {}), right[1])
        if a is None or b is None or a != b:
            violations.append(
                f"constants: {left[0]}:{'.'.join(left[1])} and "
                f"{right[0]}:{'.'.join(right[1])} must pin the same named "
                f"constant (found {a!r} and {b!r}) — a forked timing "
                "constant is a contract change, not a schema edit")
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
    else:
        # The members the store derives the object key from are required
        # properties of the record: the key segments must equal the
        # record's own validated identifiers (ID-008), and for the
        # revocation record that includes the epoch its key names.
        for member in entry.get("keyMembers", []):
            if member not in props or member not in doc.get("required", []):
                violations.append(
                    f"{stem}: keyMembers member {member!r} of {rtype!r} "
                    "must be a required property — the store derives the "
                    "object key from exactly these validated fields")

    # 3. Flat wrapper composition: every required wrapper member present,
    #    required, and referencing the registry's declared source; any
    #    other property that is a wrapper member references the declared
    #    source too, so an identity-carried epoch (immutable revocation)
    #    cannot fork the shared definition.
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
    for member, node in props.items():
        if member in wrapper_members:
            ref = node.get("$ref")
            if ref != expected_ref(wrapper_members[member]):
                violations.append(
                    f"{stem}: {member} must reference the wrapper source "
                    f"{expected_ref(wrapper_members[member])!r} "
                    f"(found {ref!r})")
    for member in doc.get("required", []):
        if member not in props:
            violations.append(f"{stem}: required member {member} has no property")

    # 4. No private-key material in any field (SEC-006): banned member
    #    names, and key members keep the common public shapes. The
    #    revocation record carries only a key identifier, so its shape
    #    checks are the key-id ref; key-bearing members are checked where
    #    the record type carries them.
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
    if "public_key" in props and props["public_key"].get("$ref") != PUBLIC_KEY_REF:
        violations.append(
            f"{stem}: public_key must reference the common "
            "ed25519-public-key-hex shape")
    if ("previous_public_key" in props
            and props["previous_public_key"].get("$ref") != PUBLIC_KEY_REF):
        violations.append(
            f"{stem}: previous_public_key must reference the common "
            "ed25519-public-key-hex shape — the overlap's old half is "
            "public material under the same shape, never a second "
            "convention")
    if ("key_algorithm" in props
            and props["key_algorithm"].get("$ref") != SIGNATURE_ALGORITHM_REF):
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

    # Key IDs on the golden instances hold under the pinned derivation:
    # computable from published public material, never asserted.
    client = golden_client_record()
    revocation = golden_revocation_record()
    delegation = golden_delegation_record()
    rotation = golden_rotation_record()
    if client["key_id"] != key_id(client["public_key"]):
        violations.append("golden client record: key_id is not SHA-256(public_key)")
    if revocation["revoked_key_id"] != key_id(client["public_key"]):
        violations.append(
            "golden revocation record: revoked_key_id is not the "
            "SHA-256(public_key) of the key the revoked epoch held")
    if rotation["key_id"] != key_id(rotation["public_key"]):
        violations.append(
            "golden rotation record: key_id is not SHA-256(public_key)")
    if rotation["previous_key_id"] != key_id(rotation["previous_public_key"]):
        violations.append(
            "golden rotation record: previous_key_id is not "
            "SHA-256(previous_public_key)")
    if rotation["public_key"] != client["public_key"]:
        violations.append(
            "golden rotation record: the established epoch's new half must "
            "be the golden linked-client record's own key — one coherent "
            "authorization history, not unrelated objects")

    # Per-type golden behaviour: factory, rejections, key pattern, key
    # derivation from the record's own identifiers, and the near-miss keys
    # the pattern must reject so a relaxed drift cannot pass on one
    # positive example alone.
    specs = (
        ("control-client", client, CLIENT_REJECTIONS, "client-object-key",
         lambda r: (f"tenants/{r['tenant_id']}/v1/control/clients/"
                    f"{r['client_id']}.json"),
         lambda r: {
             "another record type's key": (
                 f"tenants/{r['tenant_id']}/v1/control/revocations/"
                 f"{r['client_id']}/3.json"),
             "non-canonical tenant segment": (
                 f"tenants/{r['tenant_id'].upper()}/v1/control/clients/"
                 f"{r['client_id']}.json"),
             "missing .json suffix": (
                 f"tenants/{r['tenant_id']}/v1/control/clients/"
                 f"{r['client_id']}"),
         }),
        ("control-revocation", revocation, REVOCATION_REJECTIONS,
         "revocation-object-key",
         lambda r: (f"tenants/{r['tenant_id']}/v1/control/revocations/"
                    f"{r['client_id']}/{r['authorization_epoch']}.json"),
         lambda r: {
             "leading-zero epoch segment": (
                 f"tenants/{r['tenant_id']}/v1/control/revocations/"
                 f"{r['client_id']}/0{r['authorization_epoch']}.json"),
             "zero epoch segment": (
                 f"tenants/{r['tenant_id']}/v1/control/revocations/"
                 f"{r['client_id']}/0.json"),
             "19-digit epoch segment": (
                 f"tenants/{r['tenant_id']}/v1/control/revocations/"
                 f"{r['client_id']}/{10 ** 18}.json"),
             "another record type's key": (
                 f"tenants/{r['tenant_id']}/v1/control/clients/"
                 f"{r['client_id']}.json"),
             "missing .json suffix": (
                 f"tenants/{r['tenant_id']}/v1/control/revocations/"
                 f"{r['client_id']}/{r['authorization_epoch']}"),
             "non-canonical tenant segment": (
                 f"tenants/{r['tenant_id'].upper()}/v1/control/revocations/"
                 f"{r['client_id']}/{r['authorization_epoch']}.json"),
         }),
        ("control-delegation", delegation, DELEGATION_REJECTIONS,
         "delegation-object-key",
         lambda r: (f"tenants/{r['tenant_id']}/v1/control/delegations/"
                    f"{r['relay_client_id']}/{r['origin_client_id']}.json"),
         lambda r: {
             "another record type's key": (
                 f"tenants/{r['tenant_id']}/v1/control/clients/"
                 f"{r['relay_client_id']}.json"),
             "epoch-addressed delegation key": (
                 f"tenants/{r['tenant_id']}/v1/control/delegations/"
                 f"{r['relay_client_id']}/{r['origin_client_id']}/"
                 f"{r['authorization_epoch']}.json"),
             "non-canonical tenant segment": (
                 f"tenants/{r['tenant_id'].upper()}/v1/control/delegations/"
                 f"{r['relay_client_id']}/{r['origin_client_id']}.json"),
             "missing .json suffix": (
                 f"tenants/{r['tenant_id']}/v1/control/delegations/"
                 f"{r['relay_client_id']}/{r['origin_client_id']}"),
         }),
        ("control-rotation", rotation, ROTATION_REJECTIONS,
         "rotation-object-key",
         lambda r: (f"tenants/{r['tenant_id']}/v1/control/rotations/"
                    f"{r['client_id']}/{r['authorization_epoch']}.json"),
         lambda r: {
             "leading-zero epoch segment": (
                 f"tenants/{r['tenant_id']}/v1/control/rotations/"
                 f"{r['client_id']}/0{r['authorization_epoch']}.json"),
             "zero epoch segment": (
                 f"tenants/{r['tenant_id']}/v1/control/rotations/"
                 f"{r['client_id']}/0.json"),
             "19-digit epoch segment": (
                 f"tenants/{r['tenant_id']}/v1/control/rotations/"
                 f"{r['client_id']}/{10 ** 18}.json"),
             "revocation key at the same shape": (
                 f"tenants/{r['tenant_id']}/v1/control/revocations/"
                 f"{r['client_id']}/{r['authorization_epoch']}.json"),
             "missing .json suffix": (
                 f"tenants/{r['tenant_id']}/v1/control/rotations/"
                 f"{r['client_id']}/{r['authorization_epoch']}"),
             "non-canonical tenant segment": (
                 f"tenants/{r['tenant_id'].upper()}/v1/control/rotations/"
                 f"{r['client_id']}/{r['authorization_epoch']}.json"),
         }),
    )
    for stem, record, rejections, pattern_def, derive, near_misses in specs:
        validator = build_validator(schemas, stem)
        if validator is None:
            violations.append(f"{stem}: behavioural validator unavailable")
            continue
        pattern = (
            schemas[ENVELOPE_STEM].get("$defs", {})
            .get(pattern_def, {}).get("pattern"))
        derived_key = derive(record)
        if not isinstance(pattern, str) or not re.match(pattern, derived_key):
            violations.append(
                f"golden {stem}: the object key derived from the record's "
                f"own identifiers ({derived_key!r}) does not satisfy "
                f"{pattern_def}")
        for label, key in near_misses(record).items():
            if isinstance(pattern, str) and re.match(pattern, key):
                violations.append(
                    f"{pattern_def} must not accept a near-miss key "
                    f"({label})")
        errors = sorted(validator.iter_errors(record))
        for error in errors:
            violations.append(
                f"golden {stem} record rejected: {error.message}")
        if errors:
            continue
        for label, mutation in rejections:
            candidate = copy.deepcopy(record)
            mutation(candidate)
            if validator.is_valid(candidate):
                violations.append(
                    f"behaviour: a {stem} record with {label} must be "
                    "rejected")
        if stem == "control-revocation":
            # The epoch ceiling is schema-valid and its object key
            # satisfies the grammar: the authorization-epoch maximum and
            # the key's 18-digit decimal segment are in lockstep.
            ceiling = copy.deepcopy(record)
            ceiling["authorization_epoch"] = 999999999999999999
            if not validator.is_valid(ceiling):
                violations.append(
                    "golden revocation record: the epoch ceiling "
                    "999999999999999999 must be schema-valid — the epoch "
                    "bound and the key grammar are held in lockstep")
            if not (isinstance(pattern, str)
                    and re.match(pattern, derive(ceiling))):
                violations.append(
                    "revocation-object-key must accept the epoch-ceiling "
                    "key — 18 canonical digits, exactly the bound "
                    "authorization-epoch carries")
        if stem == "control-delegation":
            # Withdrawal is a valid shape: the current-pointer record has
            # no delete, so a withdrawn grant is a strictly higher-epoch
            # record at the same key carrying the state member. Its
            # scopes stay present and inert — that is the withdrawal
            # representation, and it must validate.
            withdrawn = copy.deepcopy(record)
            withdrawn["delegation_state"] = "withdrawn"
            if not validator.is_valid(withdrawn):
                violations.append(
                    "golden delegation record: the withdrawn variant must "
                    "be schema-valid — withdrawal is a higher-epoch record "
                    "at the same key, the only representation a "
                    "current-pointer shape permits")
        if stem == "control-rotation":
            # The epoch ceiling is schema-valid and its object key
            # satisfies the grammar: the same 18-digit lockstep the
            # revocation key keeps, proven on the rotation key too.
            ceiling = copy.deepcopy(record)
            ceiling["authorization_epoch"] = 999999999999999999
            ceiling["previous_epoch"] = 999999999999999998
            if not validator.is_valid(ceiling):
                violations.append(
                    "golden rotation record: the epoch ceiling "
                    "999999999999999999 (with the adjacent previous "
                    "epoch) must be schema-valid — the epoch bound and "
                    "the key grammar are held in lockstep")
            if not (isinstance(pattern, str)
                    and re.match(pattern, derive(ceiling))):
                violations.append(
                    "rotation-object-key must accept the epoch-ceiling "
                    "key — 18 canonical digits, exactly the bound "
                    "authorization-epoch carries")
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
     lambda s: s["$defs"]["record-type"]["enum"].append("receipt-key")),
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
    ("revocation identity epoch dropped", "control-revocation",
     lambda s: (s["properties"].pop("authorization_epoch"),
                s["required"].remove("authorization_epoch"))),
    ("identity epoch definition forked", "control-revocation",
     lambda s: s["properties"]["authorization_epoch"].__setitem__(
         "$ref", "urn:agent-archivist:schema:v1:common#/$defs/u63")),
    ("revocation unshipped drift", "control-envelope",
     lambda s: [e.update({"status": "pending", "schema": None})
                for e in s["x-archivist"]["recordTypes"]
                if e.get("type") == "revocation"]),
    ("delegation identity member dropped", "control-delegation",
     lambda s: (s["properties"].pop("origin_client_id"),
                s["required"].remove("origin_client_id"))),
    ("rotation overlap constant dropped", "control-rotation",
     lambda s: s["x-archivist"].pop("rotationVerificationOverlapHours")),
    ("rotation key-pattern drift", "control-envelope",
     lambda s: s["$defs"]["rotation-object-key"].__setitem__(
         "pattern", "^tenants/.+$")),
    ("constant registry drift", "control-envelope",
     lambda s: s["x-archivist"]["constants"]["trustRecordCacheTtlSeconds"]
     .__setitem__("value", 120)),
    ("cross-file constant fork", "ingest-request",
     lambda s: s["x-archivist"].__setitem__(
         "clockSkewAllowanceSeconds", 600)),
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
    rejections = (len(CLIENT_REJECTIONS) + len(REVOCATION_REJECTIONS)
                  + len(DELEGATION_REJECTIONS) + len(ROTATION_REJECTIONS))
    print(f"agent-archivist control trust family: {len(RECORD_STEMS) + 1} schemas")
    print(f"closed enums guarded: {enums}, "
          f"named constants pinned: {len(PINNED)}, "
          f"cross-file agreements proven: {len(CONSTANT_AGREEMENTS)}, "
          f"behavioural rejections proven: {rejections}")
    print("OK: schemas/v1 control family satisfies "
          "docs/notes/control-trust-schemas.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
