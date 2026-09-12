#!/usr/bin/env python3
"""Schema compatibility corpus generator for Agent Archivist.

Implements plan Section 7.1's closing sentence — "These compatibility
rules are enforced by old-reader/new-writer and new-reader/old-writer
fixtures" (bead ``aa-fe4cf4bd``) — by pinning, byte-exactly, a matrix of
writer documents read by two reader generations:

* the **old reader** (``v1.0``) is the shipped ``schemas/v1`` family
  itself, digest-pinned in the manifest so the corpus always names the
  schema generation it was verified against;
* the **new reader** (``v1.1``) is a mechanical projection of that family
  — one hypothetical optional field added to each retain-ignore durable
  record (envelope, occurrence manifest, upload attestation, receipt) —
  exactly the additive change plan Section 7.1 permits inside a major.

Around that matrix the corpus pins the negative compatibility cases:
unknown security- and identity-bearing enum values fail closed under
*both* reader generations; unknown majors (``envelope_version`` &
``protocol_version`` 2, ``occurrence_version`` 2,
``attestation_version`` 2, ``receipt_version`` 2) fail closed under
both; a float inside a would-be additive field has no canonical form and
so fails closed at the canonicalization layer even though an open-shape
schema alone would accept it; and the wire framing rejects a
``version=2`` envelope media type on ``/v1/ingest`` before any body
parse — the route-major rule.

It also pins the *policy* half: candidate "v1.2" schemas that add a
required field, redefine an existing field, weaken an identity input,
grow a fail-closed enum, or mutate the identity-derivation registry or
the object-key grammar are committed as fixtures together with the
finding codes the built-in policy checker must return for each —
``requires-v2`` / ``requires-new-prefix`` — plus the behavioural proof
of why (an old-writer document that the candidate rejects, or a
committed object whose key a repurposed grammar would move).

Storage-layout coverage: identical identity inputs derive byte-identical
``v1`` object keys across writer generations; an adapter-projection
version bump mints a fresh artifact hash, occurrence, and key while the
old ones stay valid (never overwritten); a hypothetical ``zstd-v2``
profile renders a *new* key segment rather than rewriting ``zstd-v1``
meaning; and a derived-pipeline key is rebuildable, versioned, and
prefix-disjoint from the raw namespace.

The old-writer documents are the committed golden baselines of the
sibling corpora (digest-pinned here): the conformance corpus's
``valid-direct-baseline`` envelope, attempt record, and receipt, and the
raw-provenance corpus's direct-upload occurrence manifest and
attestation. Nothing new is invented about v1; every v1.1 document is a
baseline plus one member.

Determinism model: no entropy source, no key material, no signatures —
this corpus proves the schema and canonical-bytes layers only, and
deliberately leaves signature-level proofs to the conformance corpus
(``tools/conformancegen.py``), whose ``*signed_bytes_sha256`` convention
this corpus reuses for "retained inside signed bytes" pins. Bundle
metadata files are RFC 8785 canonical JSON plus one trailing LF.
Regeneration is byte-identical everywhere.

Exit codes: 0 pass, 2 byte drift or non-canonical formatting, 3
verification, coverage, policy, or invariant failure (including a
remaining deferral under ``--require-complete``), 4 ``jsonschema`` is
unavailable.

Deferred verifications: scenarios listed in ``DEFERRED_VERIFICATION``
are generated and committed but not yet asserted — their outcome proofs
belong to later split-children of bead ``aa-fe4cf4bd``. Each owning
child deletes its entries; the DoD wiring runs ``--verify
--require-complete`` so a deferral can never silently outlive the
split.

Usage::

    tools/compatgen.py --generate [OUTPUT]  # default: the committed bundle
    tools/compatgen.py --verify             # regenerate and verify everything
    tools/compatgen.py --verify --require-complete  # ...and fail on deferrals
    tools/compatgen.py --self-test          # prove the rejection paths
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas" / "v1"
DEFAULT_OUTPUT = SCHEMA_DIR / "examples" / "compat"
CONFORMANCE_DIR = SCHEMA_DIR / "examples" / "conformance"
PROVENANCE_DIR = SCHEMA_DIR / "examples" / "provenance"
COMMON_SCHEMA = SCHEMA_DIR / "common.json"
IDENTIFIERS_SCHEMA = SCHEMA_DIR / "ingest-identifiers.json"

BUNDLE_SCHEMA = "archivist.compat-corpus/v1"

# The Section 7.1 rule inventory: the bead's acceptance criterion is that
# every one of these has at least one positive or negative case in the
# corpus, which --verify proves mechanically from the manifest's coverage
# map. Text is quoted or paraphrased from plan Section 7.1.
RULES = {
    "route-major": (
        "HTTP route /v1/ingest: breaking wire changes use a new route major "
        "(a version=2 envelope media type is rejected at framing; an "
        "unknown protocol_version fails closed)"
    ),
    "unknown-major-fails-closed": (
        "envelope/occurrence/attestation/receipt majors: an unknown major on "
        "any axis fails closed"
    ),
    "readers-retain-old-versions": (
        "occurrence and attestation axes: readers retain old-version support "
        "(a newer reader still accepts the older writer's documents)"
    ),
    "storage-layout-prefix-stable": (
        "storage layout: a v1 key prefix is never silently repurposed; a new "
        "encoder is a new named profile and key segment"
    ),
    "adapter-projection-preserved": (
        "adapter projection: the adapter + projection version is preserved "
        "in provenance and is an identity input, so a bump mints new "
        "occurrences instead of overwriting"
    ),
    "derived-pipeline-isolated": (
        "derived pipeline: name + version; rebuildable, versioned keys under "
        "a derived prefix that never overwrites raw data"
    ),
    "additive-optional-within-major": (
        "within a v1 schema, new optional fields are additive"
    ),
    "unknown-optional-retained-in-signed-bytes": (
        "old readers ignore the semantics of unknown optional data while "
        "retaining it inside signed bytes"
    ),
    "security-enums-fail-closed": (
        "unknown security- or identity-bearing enum values fail closed"
    ),
    "requires-new-major": (
        "new required fields, redefined fields, changed identity rules, or "
        "grown fail-closed enums require a new major"
    ),
    "no-floats": (
        "protocol structures contain no floating-point values"
    ),
}

KNOWN_BEARINGS = {"security", "identity", "provenance", "structural",
                  "correlation"}

# The durable retain-ignore records a v1.1 reader is projected for, and the
# single hypothetical optional field each projection adds. Field names are
# pinned synthetic stand-ins for plausible future additions (SEC-010); each
# carries the compat metadata an additive field must declare.
PROJECTED_STEMS = ("ingest-envelope", "occurrence-manifest",
                   "upload-attestation", "ingest-receipt")
ADDITIVE_FIELDS = {
    "ingest-envelope": {
        "client_build": {
            "$ref": "urn:agent-archivist:schema:v1:common#/$defs/short-token",
            "description": "Hypothetical v1.1 additive field pinned by the "
                           "compatibility corpus: the building client's "
                           "version token. Correlation only; never an "
                           "identity input, so old readers ignore its "
                           "semantics while retaining it inside the signed "
                           "canonical envelope bytes.",
            "x-archivist": {"bearing": "correlation",
                            "compat": "optional-additive-v1"},
        },
    },
    "occurrence-manifest": {
        "adapter_build_id": {
            "$ref": "urn:agent-archivist:schema:v1:common#/$defs/short-token",
            "description": "Hypothetical v1.1 additive field pinned by the "
                           "compatibility corpus: the adapter build that "
                           "produced this projection. Provenance only; the "
                           "artifact hash still binds exactly the v1 tuple.",
            "x-archivist": {"bearing": "provenance",
                            "compat": "optional-additive-v1"},
        },
    },
    "upload-attestation": {
        "uploader_agent_version": {
            "$ref": "urn:agent-archivist:schema:v1:common#/$defs/short-token",
            "description": "Hypothetical v1.1 additive field pinned by the "
                           "compatibility corpus: the uploading agent's "
                           "version token. Correlation only.",
            "x-archivist": {"bearing": "correlation",
                            "compat": "optional-additive-v1"},
        },
    },
    "ingest-receipt": {
        "server_build": {
            "$ref": "urn:agent-archivist:schema:v1:common#/$defs/short-token",
            "description": "Hypothetical v1.1 additive field pinned by the "
                           "compatibility corpus: the ingesting server's "
                           "build token, inside the receipt's signed "
                           "canonical bytes.",
            "x-archivist": {"bearing": "structural",
                            "compat": "optional-additive-v1"},
        },
    },
}

# Old-writer baselines consumed from the sibling corpora (digest-pinned in
# the manifest so drift there forces regeneration here).
BASELINES = {
    "envelope": (CONFORMANCE_DIR / "scenarios" / "valid-direct-baseline"
                 / "envelope.json", "schemas/v1/examples/conformance"),
    "payload": (CONFORMANCE_DIR / "scenarios" / "valid-direct-baseline"
                / "payload.jsonl", "schemas/v1/examples/conformance"),
    "attempt": (CONFORMANCE_DIR / "scenarios" / "valid-direct-baseline"
                / "attempt.json", "schemas/v1/examples/conformance"),
    "receipt": (CONFORMANCE_DIR / "scenarios" / "valid-direct-baseline"
                / "receipt.json", "schemas/v1/examples/conformance"),
    "occurrence": (PROVENANCE_DIR / "occurrences"
                   / "direct-upload-and-relay-source.json",
                   "schemas/v1/examples/provenance"),
    "attestation": (PROVENANCE_DIR / "attestations"
                    / "origin-direct-first-request.json",
                    "schemas/v1/examples/provenance"),
}

# Every reader stem the matrix may resolve, mapped to its schema file.
READER_STEMS = {
    "ingest-envelope": SCHEMA_DIR / "ingest-envelope.json",
    "ingest-request": SCHEMA_DIR / "ingest-request.json",
    "ingest-receipt": SCHEMA_DIR / "ingest-receipt.json",
    "occurrence-manifest": SCHEMA_DIR / "occurrence-manifest.json",
    "upload-attestation": SCHEMA_DIR / "upload-attestation.json",
}

# Scenarios whose fixtures this corpus commits but whose outcome proofs
# are still owned by a later split-child of aa-fe4cf4bd: the generator
# emits them and the bank carries them, while ``--verify`` does not yet
# assert them. Each owning child deletes its entries here once the
# scenario is green, and the child-5 DoD wiring runs ``--verify
# --require-complete`` so a deferral can never silently outlive the
# split. Everything not listed here is verified unconditionally.
DEFERRED_VERIFICATION = {
    "adapter-projection-bump":
        "split-child 3 (storage layouts): the bump doc must carry an "
        "additive member and mint a fresh occurrence identity and key",
    "derived-pipeline-isolation":
        "split-child 3 (storage layouts): the derived keys must stay "
        "prefix-disjoint from the raw namespace",
}

ENVELOPE_MEDIA_TYPE_PIN = "partOneMediaType"


# ---------------------------------------------------------------------------
# Canonical JSON (RFC 8785 over the protocol's no-float value domain) —
# the same profile tools/conformancegen.py pins.
# ---------------------------------------------------------------------------

def canonical_text(value: object) -> str:
    """RFC 8785 canonical text; floats (and any non-JSON-schema value
    type) are non-canonicalizable and raise, which is the no-float rule
    enforced at the canonical-bytes layer."""

    def check(node: object) -> None:
        if isinstance(node, dict):
            for key, item in node.items():
                if not key.isascii():
                    raise ValueError("non-ASCII member names are outside the "
                                     "canonical subset this corpus pins")
                check(item)
        elif isinstance(node, list):
            for item in node:
                check(item)
        elif isinstance(node, bool) or node is None:
            pass
        elif isinstance(node, int):
            pass
        elif isinstance(node, str):
            node.encode("utf-8")  # rejects lone surrogates
        else:
            raise ValueError(f"non-canonicalizable value type: {type(node)!r}")

    check(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True)


def canonical_bytes(value: object) -> bytes:
    return canonical_text(value).encode("utf-8")


def signed_bytes(stem: str, doc: dict) -> bytes:
    """The bytes a record's signature covers: the canonical record minus
    its signature member when the kind carries one (the receipt-v1
    convention the conformance corpus pins), the whole canonical record
    otherwise (the envelope has no per-record signature member)."""
    if stem == "ingest-receipt":
        return canonical_bytes(
            {k: v for k, v in doc.items() if k != "signature"})
    return canonical_bytes(doc)


def metadata_bytes(value: object) -> bytes:
    """Bundle files: canonical JSON plus one trailing LF."""
    return canonical_bytes(value) + b"\n"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Identity derivation, driven entirely by the construction registry in
# schemas/v1/ingest-identifiers.json (never a local copy of the fields).
# ---------------------------------------------------------------------------

def _field(raw: bytes) -> bytes:
    return len(raw).to_bytes(8, "big") + raw


def _encode(kind: str, value: object) -> bytes:
    if kind == "text":
        assert isinstance(value, str)
        return value.encode("utf-8")
    if kind == "digest":
        assert isinstance(value, str)
        return bytes.fromhex(value)
    if kind == "u63":
        assert isinstance(value, int)
        return value.to_bytes(8, "big")
    if kind == "bytes":
        assert isinstance(value, (bytes, bytearray))
        return bytes(value)
    raise ValueError(f"unknown field kind {kind!r}")


class Registry:
    """The pinned construction registry: derivations, signatures, keys."""

    def __init__(self, doc: dict):
        xa = doc.get("x-archivist", {})
        self.derivations = {d["id"]: d for d in xa.get("derivations", [])}
        self.order = [d["id"] for d in xa.get("derivations", [])]
        self.signatures = xa.get("signatures", [])
        self.object_keys = xa.get("objectKeys", [])

    def derive(self, did: str, values: dict) -> str:
        deriv = self.derivations[did]
        raw = b""
        for name, kind in zip(deriv["fields"], deriv["fieldKinds"]):
            # fieldEncoding: every member is 8-byte big-endian length +
            # exactly that many field bytes (plan Section 7.4) — the same
            # framing tools/conformancegen.py pins golden vectors for.
            raw += _field(_encode(kind, self.value_of(name, values)))
        label = deriv.get("label")
        if label is None:
            # The one label-less construction: plain SHA-256 over the bytes.
            return hashlib.sha256(raw).hexdigest()
        stream = label.encode("utf-8") + b"\x00" + raw
        return hashlib.sha256(stream).hexdigest()

    def value_of(self, name: str, values: dict) -> object:
        if name in values:
            return values[name]
        if name in self.derivations:
            return self.derive(name, values)
        raise KeyError(f"identity input {name!r} unavailable: the document "
                       "omits a field the construction registry requires")

    def derive_all(self, values: dict) -> dict:
        return {did: self.derive(did, values) for did in self.order}

    def identity_fields_of(self, stem: str) -> set[str]:
        """Envelope members the registry hashes for this schema's stem."""
        fields: set[str] = set()
        for deriv in self.derivations.values():
            source = str(deriv.get("source", ""))
            if Path(source).stem == stem:
                for name in deriv["fields"]:
                    if name not in self.derivations:
                        fields.add(name)
        return fields


_SEGMENT_RE = re.compile(r"^<([a-z_0-9]+)( first 2 hex)?(?:\.([a-z0-9.]+))?>$")


def render_segment(token: str, record: dict) -> str:
    match = _SEGMENT_RE.match(token)
    if match is None:
        # A literal grammar token (e.g. the 'sha256' algorithm segment) or a
        # bare field name (e.g. 'storage_profile').
        return str(record.get(token, token))
    name, shard, suffix = match.groups()
    value = str(record[name])
    if shard:
        return value[:2]
    return value + (f".{suffix}" if suffix else "")


def render_prefix(prefix: str, record: dict) -> str:
    rendered = prefix
    for name, value in record.items():
        rendered = rendered.replace(f"<{name}>", str(value))
    return rendered


def object_keys_for(record: dict, registry: Registry) -> dict[str, str]:
    """Render every registered object key for one validated record."""
    keys: dict[str, str] = {}
    for entry in registry.object_keys:
        purpose = entry["prefix"].split("/")[-1]
        keys[purpose] = "/".join(
            [render_prefix(entry["prefix"], record)]
            + [render_segment(t, record) for t in entry["segments"]])
    return keys


# ---------------------------------------------------------------------------
# The compatibility policy checker.
#
# classify_projection / classify_registry / classify_layout decide whether a
# candidate reader or grammar is a legal within-major evolution of the
# shipped one. Empty findings = legal additive change.
# ---------------------------------------------------------------------------

def _walk(node, path="#"):
    if isinstance(node, dict):
        yield path, node
        for key, value in node.items():
            yield from _walk(value, f"{path}/{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _walk(value, f"{path}/{i}")


def _contains_number_type(node) -> bool:
    return any(sub.get("type") == "number" for _, sub in _walk(node)
               if isinstance(sub, dict))


def classify_projection(old: dict, new: dict, stem: str,
                        registry: Registry) -> list[dict]:
    """Findings for a candidate evolution of one instance schema. Anything
    other than purely-additive optional members is a requires-v2 finding."""
    findings: list[dict] = []
    old_required = set(old.get("required", []))
    new_required = set(new.get("required", []))

    added = sorted(new_required - old_required)
    removed = sorted(old_required - new_required)
    if added:
        findings.append({"code": "required-field-added", "fields": added,
                         "verdict": "requires-v2"})
    if removed:
        findings.append({"code": "required-field-removed", "fields": removed,
                         "verdict": "requires-v2"})

    old_props = old.get("properties", {})
    new_props = new.get("properties", {})
    for name in sorted(set(old_props) - set(new_props)):
        findings.append({"code": "property-removed", "field": name,
                         "verdict": "requires-v2"})
    for name in sorted(set(old_props) & set(new_props)):
        if old_props[name] != new_props[name]:
            findings.append({"code": "property-redefined", "field": name,
                             "verdict": "requires-v2"})
    for name in sorted(set(new_props) - set(old_props)):
        prop = new_props[name]
        meta = prop.get("x-archivist", {})
        if name in added:
            continue  # already flagged as required-field-added
        if _contains_number_type(prop):
            findings.append({"code": "float-introduced", "field": name,
                             "verdict": "requires-v2"})
        elif meta.get("compat") != "optional-additive-v1":
            findings.append({"code": "additive-field-missing-compat-metadata",
                             "field": name, "verdict": "requires-v2"})
        elif meta.get("bearing") not in KNOWN_BEARINGS:
            findings.append({"code": "additive-field-unknown-bearing",
                             "field": name, "verdict": "requires-v2"})
        elif name in old.get("x-archivist", {}).get("reservedFields", []):
            findings.append({"code": "additive-field-uses-reserved-name",
                             "field": name, "verdict": "requires-v2"})

    # Identity rules: every registry-hashed member of this schema must stay
    # a defined, required property with an unchanged definition.
    for name in sorted(registry.identity_fields_of(stem)):
        if name in removed:
            findings.append({"code": "identity-input-weakened", "field": name,
                             "verdict": "requires-v2"})
        elif (name in old_props and name in new_props
              and old_props[name] != new_props[name]):
            pass  # already flagged as property-redefined

    # Fail-closed enums: growing one inside a major ships a value every
    # deployed old reader rejects (pinned by the enum scenarios below), so
    # it is a coordinated-major change, never a silent additive edit.
    old_enums = {path: node["enum"] for path, node in _walk(old)
                 if isinstance(node, dict) and "enum" in node}
    new_enums = {path: node["enum"] for path, node in _walk(new)
                 if isinstance(node, dict) and "enum" in node}
    for path in sorted(set(old_enums) | set(new_enums)):
        if old_enums.get(path) != new_enums.get(path):
            findings.append({"code": "fail-closed-enum-changed",
                             "pointer": path,
                             "old": old_enums.get(path),
                             "new": new_enums.get(path),
                             "verdict": "requires-v2"})

    # Semantic metadata (pinned limits, media type, reserved names) and the
    # reserved-name not-block must be untouched.
    if old.get("x-archivist", {}) != new.get("x-archivist", {}):
        findings.append({"code": "semantic-metadata-changed",
                         "verdict": "requires-v2"})
    if old.get("not", {}) != new.get("not", {}):
        findings.append({"code": "reserved-name-block-changed",
                         "verdict": "requires-v2"})
    if _contains_number_type(new):
        findings.append({"code": "float-introduced", "pointer": "#",
                         "verdict": "requires-v2"})
    return findings


def classify_registry(old: Registry, new: Registry) -> list[dict]:
    """Identity-rule findings for a candidate construction registry."""
    findings: list[dict] = []
    for did in sorted(set(old.derivations) | set(new.derivations)):
        a, b = old.derivations.get(did), new.derivations.get(did)
        if a != b:
            findings.append({"code": "identity-derivation-changed",
                             "derivation": did, "verdict": "requires-v2"})
    old_sigs = {s.get("id"): s for s in old.signatures}
    new_sigs = {s.get("id"): s for s in new.signatures}
    for sid in sorted(set(old_sigs) | set(new_sigs)):
        if old_sigs.get(sid) != new_sigs.get(sid):
            findings.append({"code": "signature-construction-changed",
                             "signature": sid, "verdict": "requires-v2"})
    return findings


def classify_layout(old_keys: list[dict], new_keys: list[dict]) -> list[dict]:
    """Storage-layout findings for a candidate object-key grammar. An
    existing prefix may never change meaning; a genuinely new prefix is
    the new-major/new-namespace path and is additive."""
    def index(entries):
        return {e["prefix"]: e["segments"] for e in entries}

    old_idx, new_idx = index(old_keys), index(new_keys)
    findings: list[dict] = []
    for prefix in sorted(set(old_idx) | set(new_idx)):
        if prefix not in old_idx:
            continue  # a genuinely new namespace prefix: legal addition
        if prefix not in new_idx:
            findings.append({"code": "layout-prefix-removed", "prefix": prefix,
                             "verdict": "requires-v2"})
        elif old_idx[prefix] != new_idx[prefix]:
            findings.append({"code": "existing-prefix-repurposed",
                             "prefix": prefix,
                             "old": old_idx[prefix], "new": new_idx[prefix],
                             "verdict": "requires-new-prefix"})
    return findings


# ---------------------------------------------------------------------------
# Reader generations.
# ---------------------------------------------------------------------------

def project_reader(old: dict, stem: str) -> dict:
    """The v1.1 reader: the shipped schema plus the corpus's one pinned
    additive optional field — nothing else changes."""
    new = copy.deepcopy(old)
    for name, prop in ADDITIVE_FIELDS[stem].items():
        new["properties"][name] = copy.deepcopy(prop)
    return new


def reader_schema(generation: str, stem: str) -> dict:
    doc = load_json(READER_STEMS[stem])
    if generation == "v1.1" and stem in PROJECTED_STEMS:
        return project_reader(doc, stem)
    return doc


# ---------------------------------------------------------------------------
# Scenario construction.
# ---------------------------------------------------------------------------

class Ctx:
    def __init__(self):
        self.registry = Registry(load_json(IDENTIFIERS_SCHEMA))
        self.baselines = {name: load_json(path)
                          for name, (path, _) in BASELINES.items()
                          if name != "payload"}
        # The one derivation whose source is not a document member: the
        # canonical payload bytes themselves (blob_digest's only input).
        # Every envelope-derived identity in this corpus is computed over
        # the baseline payload, whose digest the baseline envelope declares.
        self.payload_bytes = BASELINES["payload"][0].read_bytes()
        self.baseline_digests = {
            name: sha256_hex(path.read_bytes())
            for name, (path, _) in BASELINES.items()}

    def envelope_identities(self, envelope: dict) -> dict:
        values = dict(envelope)
        values.setdefault("canonical_uncompressed_bytes",
                          self.payload_bytes)
        return self.registry.derive_all(values)

    def envelope_record(self, envelope: dict) -> dict:
        """Identity-resolved view for object-key rendering."""
        record = dict(envelope)
        record.update(self.envelope_identities(envelope))
        return record

    def manifest_identities(self, manifest: dict) -> dict:
        # The stored manifest carries session_hash/artifact_hash and its
        # own occurrence_id; re-derive exactly those from its own fields.
        return {did: self.registry.derive(did, dict(manifest))
                for did in ("session_hash", "artifact_hash", "occurrence_id")}

    def attestation_identities(self, attestation: dict) -> dict:
        return {"attestation_id": self.registry.derive(
            "attestation_id", dict(attestation))}


def writer_envelope(ctx: Ctx, **overrides) -> dict:
    doc = copy.deepcopy(ctx.baselines["envelope"])
    doc.update(overrides)
    return doc


def scenario_entry(sid, kind, rules, reads, asserts, **extra) -> dict:
    entry = {"id": sid, "kind": kind, "rules": sorted(rules),
             "reads": reads, "asserts": asserts}
    entry.update(extra)
    return entry


def build_scenarios(ctx: Ctx) -> tuple[list[dict], dict[str, bytes]]:
    files: dict[str, bytes] = {}
    scenarios: list[dict] = []

    def put(path: str, doc: object) -> str:
        files[path] = metadata_bytes(doc)
        return path

    base_env = ctx.baselines["envelope"]
    base_attempt = ctx.baselines["attempt"]
    base_receipt = ctx.baselines["receipt"]
    base_occ = ctx.baselines["occurrence"]
    base_att = ctx.baselines["attestation"]

    additive_env = copy.deepcopy(base_env)
    additive_env["client_build"] = "9.9.1-compat"
    additive_occ = copy.deepcopy(base_occ)
    additive_occ["adapter_build_id"] = "claude-jsonl-b77"
    additive_att = copy.deepcopy(base_att)
    additive_att["uploader_agent_version"] = "1.0.0-archivist"
    additive_receipt = copy.deepcopy(base_receipt)
    additive_receipt["server_build"] = "archivist-0.4.2"

    # --- old-reader/new-writer: additive optional fields (positive) ------
    env_id = ctx.envelope_identities(additive_env)
    env_keys = object_keys_for(ctx.envelope_record(additive_env), ctx.registry)
    signed = canonical_bytes(additive_env)
    put("writers/orn-additive-envelope.json", additive_env)
    scenarios.append(scenario_entry(
        "orn-additive-envelope", "compatible",
        {"additive-optional-within-major",
         "unknown-optional-retained-in-signed-bytes"},
        [{"reader": "v1.0", "stem": "ingest-envelope", "outcome": "accepted"},
         {"reader": "v1.1", "stem": "ingest-envelope", "outcome": "accepted"}],
        ["the v1.0 reader accepts the v1.1 writer's envelope: the unknown "
         "optional member passes the open retain-ignore shape",
         "the member survives a parse -> canonicalize round trip byte-"
         "identically and the canonical envelope bytes (the material the "
         "ingest-attempt-v1 envelope_digest covers) are pinned including it",
         "every identity and object key equals the baseline's: the old "
         "reader ignores the member's semantics (VAL-002 re-derivation "
         "still matches the declared occurrence_id)"],
        writer={"generation": "v1.1",
                "file": "writers/orn-additive-envelope.json"},
        framing={"route": "/v1/ingest",
                 "part_one_media_type":
                     "application/vnd.agent-archivist.envelope+json;version=1",
                 "outcome": "accepted_at_framing"},
        signed_bytes_sha256=sha256_hex(signed),
        identity=env_id, keys=env_keys))

    put("writers/nro-envelope.json", base_env)
    scenarios.append(scenario_entry(
        "nro-envelope", "compatible", {"additive-optional-within-major"},
        [{"reader": "v1.1", "stem": "ingest-envelope", "outcome": "accepted"},
         {"reader": "v1.0", "stem": "ingest-envelope", "outcome": "accepted"}],
        ["the v1.1 reader accepts the untouched v1.0 writer envelope"],
        writer={"generation": "v1.0", "file": "writers/nro-envelope.json"}))

    put("writers/orn-additive-occurrence.json", additive_occ)
    scenarios.append(scenario_entry(
        "orn-additive-occurrence", "compatible",
        {"additive-optional-within-major",
         "unknown-optional-retained-in-signed-bytes"},
        [{"reader": "v1.0", "stem": "occurrence-manifest",
          "outcome": "accepted"},
         {"reader": "v1.1", "stem": "occurrence-manifest",
          "outcome": "accepted"}],
        ["the v1.0 reader accepts the manifest carrying the unknown "
         "optional member and retains it through canonical re-serialization",
         "session_hash, artifact_hash, and occurrence_id re-derive from the "
         "manifest's own fields exactly as the baseline's do (STO-011 "
         "self-verification is untouched)"],
        writer={"generation": "v1.1",
                "file": "writers/orn-additive-occurrence.json"},
        identity=ctx.manifest_identities(additive_occ)))

    put("writers/nro-occurrence.json", base_occ)
    scenarios.append(scenario_entry(
        "nro-occurrence", "compatible",
        {"readers-retain-old-versions", "additive-optional-within-major"},
        [{"reader": "v1.1", "stem": "occurrence-manifest",
          "outcome": "accepted"},
         {"reader": "v1.0", "stem": "occurrence-manifest",
          "outcome": "accepted"}],
        ["occurrence_version axis: the newer reader retains old-version "
         "support and accepts the stored v1.0 manifest unchanged"],
        writer={"generation": "v1.0", "file": "writers/nro-occurrence.json"}))

    put("writers/orn-additive-attestation.json", additive_att)
    scenarios.append(scenario_entry(
        "orn-additive-attestation", "compatible",
        {"additive-optional-within-major",
         "unknown-optional-retained-in-signed-bytes"},
        [{"reader": "v1.0", "stem": "upload-attestation",
          "outcome": "accepted"},
         {"reader": "v1.1", "stem": "upload-attestation",
          "outcome": "accepted"}],
        ["the v1.0 reader accepts the attestation carrying the unknown "
         "optional member; attestation_id re-derives unchanged"],
        writer={"generation": "v1.1",
                "file": "writers/orn-additive-attestation.json"},
        identity=ctx.attestation_identities(additive_att)))

    put("writers/nro-attestation.json", base_att)
    scenarios.append(scenario_entry(
        "nro-attestation", "compatible",
        {"readers-retain-old-versions", "additive-optional-within-major"},
        [{"reader": "v1.1", "stem": "upload-attestation",
          "outcome": "accepted"},
         {"reader": "v1.0", "stem": "upload-attestation",
          "outcome": "accepted"}],
        ["attestation_version axis: the newer reader retains old-version "
         "support and accepts the stored v1.0 attestation unchanged"],
        writer={"generation": "v1.0",
                "file": "writers/nro-attestation.json"}))

    receipt_signed = signed_bytes("ingest-receipt", additive_receipt)
    put("writers/orn-additive-receipt.json", additive_receipt)
    scenarios.append(scenario_entry(
        "orn-additive-receipt", "compatible",
        {"additive-optional-within-major",
         "unknown-optional-retained-in-signed-bytes"},
        [{"reader": "v1.0", "stem": "ingest-receipt", "outcome": "accepted"},
         {"reader": "v1.1", "stem": "ingest-receipt", "outcome": "accepted"}],
        ["the v1.0 reader accepts the receipt carrying the unknown optional "
         "member; the receipt-v1 signed canonical bytes (everything except "
         "the signature member) are pinned including it"],
        writer={"generation": "v1.1",
                "file": "writers/orn-additive-receipt.json"},
        signed_bytes_sha256=sha256_hex(receipt_signed)))

    put("writers/nro-receipt.json", base_receipt)
    scenarios.append(scenario_entry(
        "nro-receipt", "compatible",
        {"readers-retain-old-versions", "additive-optional-within-major"},
        [{"reader": "v1.1", "stem": "ingest-receipt", "outcome": "accepted"},
         {"reader": "v1.0", "stem": "ingest-receipt", "outcome": "accepted"}],
        ["receipt_version axis: the newer reader retains old-version "
         "support and accepts the v1.0 golden receipt unchanged"],
        writer={"generation": "v1.0", "file": "writers/nro-receipt.json"}))

    # --- rejected security- and identity-bearing enums (negative) --------
    enum_cases = [
        ("enum-storage-profile", "ingest-envelope", base_env,
         "storage_profile", "zstd-v2",
         "a new canonical encoder is a new named profile and key segment "
         "(plan Section 7.5); until readers know it, every reader fails "
         "closed on the value"),
        ("enum-transport-encoding", "ingest-envelope", base_env,
         "transport_encoding", "lz4",
         "the server decodes exactly one declared encoding; an unknown "
         "security-bearing value is a validation error, never a guess"),
        ("enum-checksum-algorithm", "ingest-envelope", base_env,
         "incoming_checksum_algorithm", "blake3",
         "an unknown checksum algorithm fails closed rather than being "
         "silently aliased to SHA-256"),
        ("enum-artifact-kind", "ingest-envelope", base_env,
         "artifact_kind", "container-image",
         "identity-bearing enum: the artifact tuple selects the artifact "
         "hash construction, so an unknown kind fails closed"),
        ("enum-delegation", "upload-attestation", base_att,
         "delegation", "mirror",
         "the attestation's security-bearing delegation relation fails "
         "closed on an unknown value"),
        ("enum-signature-algorithm", "ingest-request", base_attempt,
         "signature_algorithm", "ed448",
         "the per-attempt signature parameters fail closed on an unknown "
         "signature algorithm"),
        ("enum-storage-outcome", "ingest-receipt", base_receipt,
         "blob_outcome", "deduplicated",
         "receipt outcomes are security-bearing; an unknown outcome fails "
         "closed instead of being coerced to a near neighbour"),
    ]
    for sid, stem, base_doc, field, bogus, why in enum_cases:
        doc = copy.deepcopy(base_doc)
        doc[field] = bogus
        path = f"writers/{sid}.json"
        put(path, doc)
        scenarios.append(scenario_entry(
            sid, "rejected", {"security-enums-fail-closed"},
            [{"reader": gen, "stem": stem, "outcome": "rejected",
              "at": "schema", "reason_contains": bogus}
             for gen in ("v1.0", "v1.1")],
            [f"{field}: {bogus!r} is outside the closed v1 enum; both the "
             f"old and the new reader reject it — {why}"],
            writer={"generation": "v1.0", "file": path}))

    # --- unknown majors (negative) ---------------------------------------
    major_cases = [
        ("major-envelope-v2", "ingest-envelope", base_env,
         "envelope_version", 2, "unknown-major-fails-closed",
         {"route-major"}),
        ("major-protocol-v2", "ingest-envelope", base_env,
         "protocol_version", 2, "route-major", set()),
        ("major-occurrence-v2", "occurrence-manifest", base_occ,
         "occurrence_version", 2, "unknown-major-fails-closed", set()),
        ("major-attestation-v2", "upload-attestation", base_att,
         "attestation_version", 2, "unknown-major-fails-closed", set()),
        ("major-receipt-v2", "ingest-receipt", base_receipt,
         "receipt_version", 2, "unknown-major-fails-closed", set()),
    ]
    for sid, stem, base_doc, field, value, rule, extra in major_cases:
        doc = copy.deepcopy(base_doc)
        doc[field] = value
        path = f"writers/{sid}.json"
        put(path, doc)
        entry = scenario_entry(
            sid, "rejected", {rule} | extra,
            [{"reader": gen, "stem": stem, "outcome": "rejected",
              "at": "schema", "reason_contains": field}
             for gen in ("v1.0", "v1.1")],
            [f"{field}: {value} fails closed under both reader generations "
             "— the const pin makes an unknown major a validation error, "
             "never a best-effort parse"],
            writer={"generation": "v1.0", "file": path})
        if sid == "major-envelope-v2":
            entry["framing"] = {
                "route": "/v1/ingest",
                "part_one_media_type":
                    "application/vnd.agent-archivist.envelope+json;version=2",
                "outcome": "rejected_at_framing",
                "reason": "the media-type version parameter tracks "
                          "envelope_version, so a v2 envelope is refused at "
                          "framing time by a v1 server before any body "
                          "parse — breaking wire changes use a new route "
                          "major",
            }
        scenarios.append(entry)

    # --- no floats (negative, enforced at the canonicalization layer) ----
    # Pinned as raw text, not a bundle file: a document carrying a float has
    # no canonical serialization to commit (the sibling conformance corpus
    # stores its malformed texts the same way).
    float_doc = copy.deepcopy(base_env)
    float_doc["compression_ratio"] = 1.5
    float_text = json.dumps(float_doc, ensure_ascii=False,
                            separators=(",", ":"), sort_keys=True) + "\n"
    scenarios.append(scenario_entry(
        "float-in-unknown-field", "rejected", {"no-floats"},
        [{"reader": gen, "stem": "ingest-envelope", "outcome": "rejected",
          "at": "canonicalization"}
         for gen in ("v1.0", "v1.1")],
        ["an unknown optional field carrying 1.5 has no RFC 8785 "
         "representation in the protocol's no-float value domain: the "
         "canonicalizer rejects it even though an open-shape schema alone "
         "would accept the member — the no-float rule binds future "
         "additions, not just the pinned vocabulary"],
        writer={"generation": "v1.1", "text": float_text}))

    # --- storage layout: key stability across writer generations ---------
    base_keys = object_keys_for(ctx.envelope_record(base_env), ctx.registry)
    put("writers/layout-key-stability.json", additive_env)
    scenarios.append(scenario_entry(
        "layout-key-stability", "compatible",
        {"storage-layout-prefix-stable",
         "unknown-optional-retained-in-signed-bytes"},
        [],
        ["the v1.0 and v1.1 writers' envelopes share identical identity "
         "inputs, so all three object keys are byte-identical under the "
         "pinned v1 grammar — an additive envelope field never moves a key",
         "the additive writer's keys equal the pinned baseline keys"],
        writer={"generation": "v1.1",
                "file": "writers/layout-key-stability.json"},
        keys=env_keys, baseline_keys=base_keys))

    # --- adapter projection bump (positive, never overwrites) ------------
    bumped = writer_envelope(ctx, adapter_projection_version="2")
    bumped_id = ctx.envelope_identities(bumped)
    bumped_keys = object_keys_for(ctx.envelope_record(bumped), ctx.registry)
    put("writers/adapter-projection-bump.json", bumped)
    scenarios.append(scenario_entry(
        "adapter-projection-bump", "compatible",
        {"adapter-projection-preserved"},
        [{"reader": "v1.0", "stem": "ingest-envelope", "outcome": "accepted"},
         {"reader": "v1.1", "stem": "ingest-envelope", "outcome": "accepted"}],
        ["adapter_projection_version is a required provenance field and an "
         "artifact-hash input: bumping it (same source bytes) mints a fresh "
         "artifact hash, occurrence, and occurrence key while the blob key "
         "is unchanged",
         "the baseline occurrence and its key remain valid — the bump adds "
         "history, it never overwrites (EC-02)",
         "the bumped envelope's declared ids match their own re-derivation"],
        writer={"generation": "v1.1",
                "file": "writers/adapter-projection-bump.json"},
        identity=bumped_id, keys=bumped_keys, baseline_keys=base_keys))

    # --- a hypothetical new storage profile: new segment, not a rewrite --
    profile_doc = ctx.envelope_record(base_env)
    v1_key = object_keys_for(profile_doc, ctx.registry)["blobs"]
    profile_doc_v2 = dict(profile_doc, storage_profile="zstd-v2")
    v2_key = object_keys_for(profile_doc_v2, ctx.registry)["blobs"]
    scenarios.append(scenario_entry(
        "layout-new-profile-segment", "compatible",
        {"storage-layout-prefix-stable", "security-enums-fail-closed"},
        [],
        ["the same blob digest under a hypothetical zstd-v2 profile "
         "renders a distinct key segment (.../blobs/zstd-v2/...): a new "
         "canonical encoder is a new named profile, never a rewrite of "
         "zstd-v1's meaning (plan Section 7.5)",
         "the zstd-v1 key for the same digest is unchanged by the new "
         "profile's existence",
         "an envelope actually declaring storage_profile=zstd-v2 is "
         "rejected fail-closed by both readers (see enum-storage-profile): "
         "the new profile ships only with readers that know it"],
        keys={"blobs_zstd_v1": v1_key, "blobs_zstd_v2": v2_key}))

    # --- derived pipeline isolation (positive) ----------------------------
    occ = base_occ
    tenant = occ["tenant_id"]
    def derived_key(pipeline: str, version: str) -> str:
        digest = ctx.registry.derive(
            "occurrence_id", dict(occ))  # raw input binding, see asserts
        d = hashlib.sha256(
            b"derived-object-v1\x00"
            + _field(pipeline.encode()) + _field(version.encode())
            + _field(tenant.encode()) + _field(bytes.fromhex(digest))
        ).hexdigest()
        return (f"tenants/{tenant}/v1/derived/{pipeline}/{version}/"
                f"{d[:2]}/{d}.json")

    occ_keys = object_keys_for(dict(occ), ctx.registry)
    scenarios.append(scenario_entry(
        "derived-pipeline-isolation", "compatible",
        {"derived-pipeline-isolated"},
        [],
        ["the derived key lives under tenants/<t>/v1/derived/<pipeline>/"
         "<version>/... and shares no prefix with any raw namespace of the "
         "same occurrence — a pipeline can never overwrite raw data",
         "the derived key is a pure function of pipeline name, version, "
         "tenant, and the raw occurrence: recomputation is byte-identical "
         "(rebuildable; plan Section 10 'catalogs rebuild byte-identically')",
         "bumping the pipeline version or renaming the pipeline mints a new "
         "key while every raw key is untouched"],
        keys={"derived_session_index_v3": derived_key("session-index", "3"),
              "derived_session_index_v4": derived_key("session-index", "4"),
              "derived_other_pipeline": derived_key("coverage-map", "1"),
              "raw_occurrence": occ_keys["occurrences"]}))

    # --- illegal projections (negative policy fixtures) -------------------
    # Each candidate is committed together with the finding codes the
    # policy checker must return for it, and the behavioural reason.
    old_env_schema = load_json(READER_STEMS["ingest-envelope"])

    required_candidate = project_reader(old_env_schema, "ingest-envelope")
    required_candidate["required"] = sorted(
        required_candidate["required"] + ["client_build"])
    put("projections/required-field/ingest-envelope.json", required_candidate)
    scenarios.append(scenario_entry(
        "projection-required-field", "policy",
        {"requires-new-major", "additive-optional-within-major"},
        [{"reader": "candidate", "stem": "ingest-envelope",
          "outcome": "rejected", "at": "schema",
          "reason_contains": "client_build"},
         {"reader": "v1.0", "stem": "ingest-envelope",
          "outcome": "accepted"}],
        ["adding client_build to required is flagged "
         "required-field-added/requires-v2: the candidate then rejects the "
         "old writer's envelope (the behavioural proof that a new required "
         "field is breaking, not additive)"],
        writer={"generation": "v1.0",
                "file": "writers/nro-envelope.json"},
        candidate={"file": "projections/required-field/ingest-envelope.json",
                   "expect_findings": ["required-field-added"],
                   "expect_verdict": "requires-v2"}))

    redefined_candidate = copy.deepcopy(old_env_schema)
    redefined_candidate["properties"]["request_id"]["$ref"] = (
        "urn:agent-archivist:schema:v1:common#/$defs/uuid-v4")
    put("projections/redefined-field/ingest-envelope.json",
        redefined_candidate)
    scenarios.append(scenario_entry(
        "projection-redefined-field", "policy", {"requires-new-major"},
        [{"reader": "candidate", "stem": "ingest-envelope",
          "outcome": "rejected", "at": "schema",
          "reason_contains": "request_id"},
         {"reader": "v1.0", "stem": "ingest-envelope",
          "outcome": "accepted"}],
        ["redefining request_id from uuid-v7 to uuid-v4 is flagged "
         "property-redefined/requires-v2: the candidate rejects the old "
         "writer's still-valid v1.0 envelope"],
        writer={"generation": "v1.0",
                "file": "writers/nro-envelope.json"},
        candidate={"file": "projections/redefined-field/ingest-envelope.json",
                   "expect_findings": ["property-redefined"],
                   "expect_verdict": "requires-v2"}))

    weakened_candidate = copy.deepcopy(old_env_schema)
    weakened_candidate["required"] = sorted(
        f for f in weakened_candidate["required"]
        if f != "upstream_session_id")
    omitted = copy.deepcopy(base_env)
    del omitted["upstream_session_id"]
    put("projections/identity-input-weakened/ingest-envelope.json",
        weakened_candidate)
    put("writers/identity-input-omitted.json", omitted)
    scenarios.append(scenario_entry(
        "projection-identity-input-weakened", "policy",
        {"requires-new-major"},
        [{"reader": "candidate", "stem": "ingest-envelope",
          "outcome": "accepted"},
         {"reader": "v1.0", "stem": "ingest-envelope",
          "outcome": "rejected", "at": "schema",
          "reason_contains": "upstream_session_id"}],
        ["removing upstream_session_id from required is flagged "
         "required-field-removed + identity-input-weakened/requires-v2: it "
         "is a session-hash construction input, so the candidate accepts a "
         "document whose identity cannot be derived at all"],
        writer={"generation": "v1.0",
                "file": "writers/identity-input-omitted.json"},
        candidate={
            "file": "projections/identity-input-weakened/"
                    "ingest-envelope.json",
            "expect_findings": ["required-field-removed",
                                "identity-input-weakened"],
            "expect_verdict": "requires-v2"}))

    enum_candidate = copy.deepcopy(old_env_schema)
    # The enum lives in common.json's storage-profile def; the candidate
    # inlines a grown copy at the use site, which is exactly how a reader
    # would ship the wider set.
    enum_candidate["properties"]["storage_profile"] = {
        "type": "string",
        "enum": ["zstd-v1", "zstd-v2"],
        "description": "candidate: the closed set grown inside v1",
        "x-archivist": {"bearing": "security", "compat": "required-v1",
                        "failClosed": True},
    }
    put("projections/enum-grown/ingest-envelope.json", enum_candidate)
    scenarios.append(scenario_entry(
        "projection-enum-grown", "policy",
        {"requires-new-major", "security-enums-fail-closed"},
        [{"reader": "candidate", "stem": "ingest-envelope",
          "outcome": "accepted"},
         {"reader": "v1.0", "stem": "ingest-envelope",
          "outcome": "rejected", "at": "schema",
          "reason_contains": "zstd-v2"},
         {"reader": "v1.1", "stem": "ingest-envelope",
          "outcome": "rejected", "at": "schema",
          "reason_contains": "zstd-v2"}],
        ["growing the fail-closed storage-profile enum inside v1 is flagged "
         "fail-closed-enum-changed/requires-v2: the candidate accepts the "
         "zstd-v2 envelope that both pinned readers reject (the deployment "
         "hazard the fail-closed rule exists for); shipping it is a "
         "coordinated major change, never a silent additive edit"],
        writer={"generation": "v1.0",
                "file": "writers/enum-storage-profile.json"},
        candidate={"file": "projections/enum-grown/ingest-envelope.json",
                   "expect_findings": ["fail-closed-enum-changed",
                                       "property-redefined"],
                   "expect_verdict": "requires-v2"}))

    # --- illegal identity-registry drift (negative policy fixture) --------
    registry_doc = load_json(IDENTIFIERS_SCHEMA)
    drifted = copy.deepcopy(registry_doc)
    drifted["x-archivist"]["derivations"][0]["fields"].remove("tenant_id")
    drifted["x-archivist"]["derivations"][0]["fieldKinds"].remove("text")
    put("registry/identity-derivation-drift.json", drifted)
    scenarios.append(scenario_entry(
        "projection-identity-derivation-drift", "policy",
        {"requires-new-major"},
        [],
        ["dropping tenant_id from the session-v1 construction is flagged "
         "identity-derivation-changed/requires-v2: every committed session "
         "hash, occurrence id, and object key would silently change "
         "meaning — the re-derived baseline hash under the drifted "
         "registry differs from the committed one",
         "changed identity rules require a new major (plan Section 7.1)"],
        candidate={"file": "registry/identity-derivation-drift.json",
                   "expect_findings": ["identity-derivation-changed"],
                   "expect_verdict": "requires-v2"}))

    # --- illegal layout repurposing (negative policy fixture) -------------
    layout_doc = copy.deepcopy(registry_doc["x-archivist"]["objectKeys"])
    for entry in layout_doc:
        if entry["prefix"].endswith("/blobs"):
            entry["segments"] = ["storage_profile", "blake3",
                                 "<blob_digest first 2 hex>",
                                 "<blob_digest>.zst"]
    put("layouts/repurposed-prefix.json", layout_doc)
    scenarios.append(scenario_entry(
        "layout-repurposed-prefix", "policy",
        {"storage-layout-prefix-stable"},
        [],
        ["redefining the existing blobs-prefix grammar (here: the digest "
         "algorithm segment) is flagged existing-prefix-repurposed/"
         "requires-new-prefix: the committed blob would be addressed at a "
         "different key, orphaning every stored object",
         "a new digest algorithm or encoder is a new named profile and "
         "segment, never a rewrite of an existing prefix's meaning"],
        candidate={"file": "layouts/repurposed-prefix.json",
                   "expect_findings": ["existing-prefix-repurposed"],
                   "expect_verdict": "requires-new-prefix"}))

    return scenarios, files


# ---------------------------------------------------------------------------
# Manifest.
# ---------------------------------------------------------------------------

def build_manifest(ctx: Ctx, scenarios: list[dict],
                   files: dict[str, bytes]) -> dict:
    coverage: dict[str, list[str]] = {rule: [] for rule in RULES}
    for entry in scenarios:
        for rule in entry["rules"]:
            coverage[rule].append(entry["id"])

    file_records = [
        {"path": path, "bytes": len(data), "sha256": sha256_hex(data)}
        for path, data in sorted(files.items())
    ]

    return {
        "schema": BUNDLE_SCHEMA,
        "scan_version": 1,
        "authority": {
            "plan": "docs/plan/plan.md Section 7.1 (version axes and the "
                    "compatibility rules), enforced per its closing "
                    "sentence by this corpus",
            "bead": "aa-fe4cf4bd",
            "note": "docs/notes/schema-compatibility.md",
            "related": [
                "docs/notes/wire-schemas.md (the wire family's version "
                "axes and fail-closed behaviour)",
                "docs/notes/raw-provenance-schemas.md (the durable "
                "records' versioning section)",
            ],
        },
        "synthetic": "Every identifier, timestamp, and document byte in "
                     "this bundle is pinned synthetic data (SEC-010) "
                     "derived from the sibling corpora's committed golden "
                     "baselines; there is no entropy source and no key "
                     "material.",
        "readers": {
            "v1.0": {
                "description": "the shipped schemas/v1 family, digest-"
                               "pinned at generation time",
                "stems": {
                    stem: {"source": f"schemas/v1/{stem}.json",
                           "sha256": sha256_hex(
                               READER_STEMS[stem].read_bytes())}
                    for stem in sorted(READER_STEMS)
                },
            },
            "v1.1": {
                "description": "the same family plus exactly one pinned "
                               "additive optional field on each "
                               "retain-ignore durable record; every other "
                               "stem is shared with v1.0 unchanged",
                "projected": {
                    stem: {
                        "file": f"readers/v1.1/{stem}.json",
                        "additive_fields":
                            sorted(ADDITIVE_FIELDS[stem]),
                    }
                    for stem in PROJECTED_STEMS
                },
                "shared": sorted(set(READER_STEMS) - set(PROJECTED_STEMS)),
            },
        },
        "baselines": {
            name: {"source": str(path.relative_to(REPO_ROOT)),
                   "corpus": corpus,
                   "sha256": ctx.baseline_digests[name]}
            for name, (path, corpus) in BASELINES.items()
        },
        "rules": dict(sorted(RULES.items())),
        "coverage": {rule: sorted(ids) for rule, ids in sorted(
            coverage.items())},
        "invariants": {
            "coverage_complete": "every Section 7.1 rule id in rules has at "
                                 "least one scenario in coverage (the "
                                 "bead's acceptance criterion)",
            "enum_matrix": "for every failClosed enum reachable as a "
                           "top-level property of a reader document, a "
                           "synthesized unknown value is rejected by both "
                           "reader generations",
            "identity_untouched": "every envelope-based writer's declared "
                                  "ids match their re-derivation from the "
                                  "construction registry (VAL-002)",
            "determinism": "regeneration is byte-identical: no entropy, "
                           "no clocks, no key material",
        },
        "scenarios": scenarios,
        "files": file_records,
    }


def build_bundle() -> dict[str, bytes]:
    ctx = Ctx()
    scenarios, files = build_scenarios(ctx)

    for stem in PROJECTED_STEMS:
        path = f"readers/v1.1/{stem}.json"
        files[path] = metadata_bytes(project_reader(
            load_json(READER_STEMS[stem]), stem))

    files["manifest.json"] = metadata_bytes(
        build_manifest(ctx, scenarios, files))
    return files


def write_bundle(output: Path, files: dict[str, bytes]) -> None:
    marker = output / "manifest.json"
    if output.exists() and any(output.iterdir()) and not (
        marker.exists()
        and json.loads(marker.read_text(encoding="utf-8")).get("schema")
        == BUNDLE_SCHEMA
    ):
        raise SystemExit(
            f"refusing to write into {output}: not a {BUNDLE_SCHEMA} bundle "
            "(pass an empty or nonexistent directory)")
    for path, data in sorted(files.items()):
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    print(f"wrote {len(files)} files to {output}")


# ---------------------------------------------------------------------------
# Verification.
# ---------------------------------------------------------------------------

def load_jsonschema():
    try:
        import jsonschema
        from referencing import Registry as RefRegistry, Resource
        from referencing.jsonschema import DRAFT202012
    except ImportError:
        return None

    common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
    ref_registry = RefRegistry().with_resource(
        "urn:agent-archivist:schema:v1:common",
        Resource.from_contents(common, default_specification=DRAFT202012),
    )
    cache: dict[tuple[str, str], object] = {}

    def validator(generation: str, stem: str):
        key = (generation, stem)
        if key not in cache:
            schema = reader_schema(generation, stem)
            jsonschema.Draft202012Validator.check_schema(schema)
            cache[key] = jsonschema.Draft202012Validator(
                schema, registry=ref_registry)
        return cache[key]

    return validator


def outcome_matches(validator, doc: dict, want: str,
                    reason_contains: str | None) -> str | None:
    """Validate and compare with the expected outcome; returns a failure
    message or None."""
    errors = list(validator.iter_errors(doc))
    accepted = not errors
    if want == "accepted" and not accepted:
        return f"expected accepted, got rejection: {errors[0].message}"
    if want == "rejected" and accepted:
        return "expected rejected, got acceptance"
    if want == "rejected" and reason_contains:
        # The member path is part of the proof: a ``const`` pin on a
        # version field reports only "1 was expected", so pinning the
        # rejection to the member requires the JSON path, not just the
        # message.
        blob = json.dumps([[e.json_path, e.message] for e in errors])
        if reason_contains not in blob:
            return (f"rejection does not name {reason_contains!r}: "
                    f"{blob[:400]}")
    return None


def common_enum_defs() -> dict[str, list]:
    common = load_json(COMMON_SCHEMA)
    return {name: node.get("enum", [])
            for name, node in common.get("$defs", {}).items()
            if isinstance(node, dict) and "enum" in node}


def failclosed_fields(stem: str, generation: str) -> list[tuple[str, str]]:
    """Top-level properties whose common.json def is a closed enum."""
    schema = reader_schema(generation, stem)
    enums = common_enum_defs()
    fields = []
    for name, prop in sorted(schema.get("properties", {}).items()):
        ref = prop.get("$ref", "") if isinstance(prop, dict) else ""
        match = re.search(r"#/\$defs/([a-z0-9-]+)$", ref)
        if match and match.group(1) in enums:
            fields.append((name, match.group(1)))
    return fields


def scenario_writer_doc(entry: dict, files: dict[str, bytes]):
    writer = entry.get("writer")
    if not writer or "file" not in writer:
        return None
    return json.loads(files[writer["file"]])


def candidate_doc(entry: dict, files: dict[str, bytes]):
    candidate = entry.get("candidate")
    if not candidate:
        return None
    return json.loads(files[candidate["file"]])


def verify_bundle(require_complete: bool = False) -> int:
    expected = build_bundle()
    committed = DEFAULT_OUTPUT
    if not committed.is_dir():
        print(f"missing bundle directory {committed}", file=sys.stderr)
        return 2

    failures: list[str] = []
    on_disk = {str(p.relative_to(committed)) for p in committed.rglob("*")
               if p.is_file()}
    for path in sorted(set(expected) | on_disk):
        if path not in expected:
            failures.append(f"unexpected file in bundle: {path}")
        elif path not in on_disk:
            failures.append(f"missing file from bundle: {path}")
        else:
            actual = (committed / path).read_bytes()
            if actual != expected[path]:
                failures.append(f"byte drift in {path}")

    # Canonical-format guard: every bundle file is canonical JSON + LF.
    for path in sorted(expected):
        if path in on_disk and metadata_bytes(
                json.loads(expected[path])) != expected[path]:
            failures.append(f"non-canonical formatting in {path}")

    manifest = json.loads(expected["manifest.json"])
    ctx = Ctx()

    # Baseline digest pins: drift in the sibling corpora is regeneration
    # material, not silent tolerance.
    for name, (path, _) in BASELINES.items():
        pin = manifest["baselines"][name]["sha256"]
        if sha256_hex(path.read_bytes()) != pin:
            failures.append(f"baseline {name} drifted from its pinned "
                            "digest (regenerate the corpus)")

    make_validator = load_jsonschema()
    if make_validator is None:
        print("jsonschema is not installed: instance validation skipped "
              "(pip install jsonschema)", file=sys.stderr)
        return 4

    for entry in manifest["scenarios"]:
        sid = entry["id"]
        if sid in DEFERRED_VERIFICATION:
            continue
        doc = scenario_writer_doc(entry, expected)

        # Reader outcomes.
        for read in entry.get("reads", []):
            reader = read["reader"]
            if reader == "candidate":
                schema = json.loads(
                    expected[entry["candidate"]["file"]])
                import jsonschema
                from referencing import Registry as RefRegistry, Resource
                from referencing.jsonschema import DRAFT202012
                common = load_json(COMMON_SCHEMA)
                validator = jsonschema.Draft202012Validator(
                    schema, registry=RefRegistry().with_resource(
                        "urn:agent-archivist:schema:v1:common",
                        Resource.from_contents(
                            common, default_specification=DRAFT202012)))
            else:
                validator = make_validator(reader, read["stem"])
            problem = outcome_matches(
                validator, doc, read["outcome"],
                read.get("reason_contains"))
            if problem:
                failures.append(f"{sid}/{reader}: {problem}")

        # Canonicalization-layer outcomes.
        if any(r.get("at") == "canonicalization"
               for r in entry.get("reads", [])):
            text = entry.get("writer", {}).get("text")
            if text is None:
                failures.append(f"{sid}: canonicalization case pins no "
                                "writer text")
            else:
                try:
                    canonical_bytes(json.loads(text))
                    failures.append(
                        f"{sid}: expected canonicalization rejection")
                except ValueError:
                    pass

        # Framing-layer outcomes.
        framing = entry.get("framing")
        if framing is not None:
            request = load_json(READER_STEMS["ingest-request"])
            pinned = request["x-archivist"][ENVELOPE_MEDIA_TYPE_PIN]
            declared = framing["part_one_media_type"]
            if framing["outcome"] == "rejected_at_framing":
                if declared == pinned:
                    failures.append(
                        f"{sid}: framing expected rejection but the media "
                        "type matches the pinned v1 parameter")
            elif declared != pinned:
                failures.append(
                    f"{sid}: framing expected acceptance but the media "
                    "type disagrees with the pinned v1 parameter")

        # Retention: the additive member survives canonical re-serialization
        # and the signed-bytes digest is pinned over bytes including it.
        writer = entry.get("writer", {})
        if writer.get("generation") == "v1.1" and doc is not None:
            additive_names = sorted(
                name
                for stem, fields in ADDITIVE_FIELDS.items()
                for name in fields
                if name in doc
            ) or [k for k in doc if k == "compression_ratio"]
            if not additive_names:
                failures.append(f"{sid}: v1.1 writer carries no additive "
                                "member to retain")
            for name in additive_names:
                if name not in doc:
                    failures.append(f"{sid}: additive member {name} lost")
                roundtrip = json.loads(canonical_bytes(doc))
                if name not in roundtrip:
                    failures.append(
                        f"{sid}: additive member {name} not retained "
                        "through canonical re-serialization")
            if "signed_bytes_sha256" in entry:
                stem = (entry.get("reads") or [{}])[0].get("stem", "")
                if sha256_hex(signed_bytes(stem, doc)) != \
                        entry["signed_bytes_sha256"]:
                    failures.append(
                        f"{sid}: signed canonical bytes digest drift")

        # Identity re-derivation for writer documents that declare ids:
        # whatever a fixture claims must agree with a fresh derivation
        # from the document's own inputs (VAL-002), on every record kind
        # the matrix touches — not just the envelope.
        if doc is not None and "identity" in entry:
            stem = (entry.get("reads") or [{}])[0].get("stem", "")
            identity_of = {
                "ingest-envelope": (ctx.envelope_identities,
                                    ("occurrence_id", "attestation_id")),
                "occurrence-manifest": (ctx.manifest_identities,
                                        ("session_hash", "artifact_hash",
                                         "occurrence_id")),
                "upload-attestation": (ctx.attestation_identities,
                                       ("attestation_id",)),
            }.get(stem)
            if identity_of is not None:
                derive_ids, declared = identity_of
                ids = derive_ids(doc)
                if ids != entry["identity"]:
                    failures.append(f"{sid}: identity re-derivation drift")
                for field in declared:
                    if doc.get(field) != ids.get(field):
                        failures.append(
                            f"{sid}: declared {field} disagrees with its "
                            "re-derivation (VAL-002)")

        # Key assertions.
        if "keys" in entry and "writer" in entry:
            stem = (entry.get("reads") or [{}])[0].get("stem",
                                                       "ingest-envelope")
            if stem in ("ingest-envelope", ""):
                keys = object_keys_for(ctx.envelope_record(doc), ctx.registry)
                if keys != entry["keys"]:
                    failures.append(f"{sid}: object-key rendering drift")
                if "baseline_keys" in entry and \
                        keys != entry["baseline_keys"] and \
                        entry["id"] == "layout-key-stability":
                    failures.append(
                        f"{sid}: additive writer keys must equal baseline")

        # Policy candidates: finding codes and verdicts must match exactly.
        candidate = entry.get("candidate")
        if candidate:
            cdoc = json.loads(expected[candidate["file"]])
            if candidate["file"].startswith("projections/required-field") \
                    or candidate["file"].startswith(
                        "projections/redefined-field") \
                    or candidate["file"].startswith(
                        "projections/identity-input-weakened") \
                    or candidate["file"].startswith("projections/enum-grown"):
                findings = classify_projection(
                    load_json(READER_STEMS["ingest-envelope"]), cdoc,
                    "ingest-envelope", ctx.registry)
            elif candidate["file"].startswith("registry/"):
                findings = classify_registry(
                    ctx.registry, Registry(cdoc))
            else:
                old_keys = ctx.registry.object_keys
                new_keys = cdoc
                findings = classify_layout(old_keys, new_keys)
            codes = sorted({f["code"] for f in findings})
            if codes != sorted(candidate["expect_findings"]):
                failures.append(
                    f"{sid}: policy findings {codes} != expected "
                    f"{sorted(candidate['expect_findings'])}")
            verdicts = {f["verdict"] for f in findings}
            if verdicts != {candidate["expect_verdict"]}:
                failures.append(
                    f"{sid}: policy verdict {verdicts} != expected "
                    f"{{{candidate['expect_verdict']}}}")

    # Scenario-specific policy behavioural proofs.
    by_id = {e["id"]: e for e in manifest["scenarios"]}
    base_env = ctx.baselines["envelope"]

    # identity-derivation drift actually changes every committed identity.
    drifted = json.loads(
        expected["registry/identity-derivation-drift.json"])
    drifted_ids = Registry(drifted).derive_all(
        {**base_env, "canonical_uncompressed_bytes": ctx.payload_bytes})
    committed_ids = ctx.envelope_identities(base_env)
    if drifted_ids["session_hash"] == committed_ids["session_hash"]:
        failures.append("identity-derivation-drift: the drifted registry "
                        "must change the re-derived session hash")

    # repurposed layout actually moves the committed blob key.
    repurposed = json.loads(expected["layouts/repurposed-prefix.json"])
    moved = object_keys_for(ctx.envelope_record(base_env),
                            Registry({"x-archivist": {
                                "derivations": [],
                                "objectKeys": repurposed}}))
    stable = object_keys_for(ctx.envelope_record(base_env), ctx.registry)
    if moved["blobs"] == stable["blobs"]:
        failures.append("repurposed-prefix: the mutated grammar must move "
                        "the committed blob key")

    # derived-pipeline isolation.
    if "derived-pipeline-isolation" not in DEFERRED_VERIFICATION:
        iso = by_id["derived-pipeline-isolation"]["keys"]
        raw_prefix = f"tenants/{base_env['tenant_id']}/v1/raw/"
        for name, key in iso.items():
            if key.startswith(raw_prefix):
                failures.append(f"derived-pipeline-isolation: {name} "
                                "collides with the raw namespace")
        if iso["derived_session_index_v3"] == iso["derived_session_index_v4"]:
            failures.append("derived-pipeline-isolation: version bump must "
                            "mint a new key")
        if iso["derived_session_index_v3"] == iso["derived_other_pipeline"]:
            failures.append("derived-pipeline-isolation: pipeline rename "
                            "must mint a new key")

    # new-profile segment distinctness.
    prof = by_id["layout-new-profile-segment"]["keys"]
    if prof["blobs_zstd_v1"] == prof["blobs_zstd_v2"]:
        failures.append("layout-new-profile-segment: a new profile must "
                        "render a distinct key")

    # Shared baselines for the writer-generation proofs below (each block
    # is gated independently, so none may define these).
    base_occ = ctx.baselines["occurrence"]
    base_att = ctx.baselines["attestation"]
    base_keys = object_keys_for(ctx.envelope_record(base_env), ctx.registry)

    # adapter-projection bump: fresh identity, stable blob, old preserved.
    if "adapter-projection-bump" not in DEFERRED_VERIFICATION:
        bump = json.loads(expected["writers/adapter-projection-bump.json"])
        bump_id = ctx.envelope_identities(bump)
        if bump_id["artifact_hash"] == committed_ids["artifact_hash"]:
            failures.append("adapter-projection-bump: the bump must mint a "
                            "fresh artifact hash")
        bump_keys = object_keys_for(ctx.envelope_record(bump), ctx.registry)
        if bump_keys["blobs"] != base_keys["blobs"]:
            failures.append("adapter-projection-bump: same source bytes "
                            "must keep the blob key")
        if bump_keys["occurrences"] == base_keys["occurrences"]:
            failures.append("adapter-projection-bump: the bump must mint a "
                            "fresh occurrence key")

    # additive envelope: identity and keys equal the baseline's.
    if "orn-additive-envelope" not in DEFERRED_VERIFICATION:
        additive = json.loads(
            expected["writers/orn-additive-envelope.json"])
        if ctx.envelope_identities(additive) != committed_ids:
            failures.append("orn-additive-envelope: semantics of the "
                            "additive member must not touch identity")
        if object_keys_for(ctx.envelope_record(additive),
                           ctx.registry) != base_keys:
            failures.append("orn-additive-envelope: additive member must "
                            "not move object keys")

    # additive occurrence and attestation: adding a member must not
    # perturb the identity inputs there either.
    if "orn-additive-occurrence" not in DEFERRED_VERIFICATION:
        if ctx.manifest_identities(json.loads(
                expected["writers/orn-additive-occurrence.json"])) != \
                ctx.manifest_identities(base_occ):
            failures.append("orn-additive-occurrence: semantics of the "
                            "additive member must not touch identity")
    if "orn-additive-attestation" not in DEFERRED_VERIFICATION:
        if ctx.attestation_identities(json.loads(
                expected["writers/orn-additive-attestation.json"])) != \
                ctx.attestation_identities(base_att):
            failures.append("orn-additive-attestation: semantics of the "
                            "additive member must not touch identity")

    # Coverage: the acceptance criterion.
    for rule, ids in manifest["coverage"].items():
        if not ids:
            failures.append(f"coverage hole: rule {rule} has no scenario")
    for rule in RULES:
        if rule not in manifest["coverage"]:
            failures.append(f"coverage map is missing rule {rule}")
    for entry in manifest["scenarios"]:
        for rule in entry["rules"]:
            if rule not in RULES:
                failures.append(f"{entry['id']}: unknown rule id {rule}")

    # Exhaustive failClosed-enum matrix over both reader generations.
    matrix_stems = ("ingest-envelope", "ingest-request", "ingest-receipt",
                    "occurrence-manifest", "upload-attestation")
    base_docs = {
        "ingest-envelope": base_env,
        "ingest-request": ctx.baselines["attempt"],
        "ingest-receipt": ctx.baselines["receipt"],
        "occurrence-manifest": ctx.baselines["occurrence"],
        "upload-attestation": ctx.baselines["attestation"],
    }
    enums = common_enum_defs()
    checked = 0
    for stem in matrix_stems:
        for generation in ("v1.0", "v1.1"):
            validator = make_validator(generation, stem)
            doc = copy.deepcopy(base_docs[stem])
            for field, def_name in failclosed_fields(stem, generation):
                if field not in doc:
                    continue
                known = enums[def_name]
                doc[field] = f"{known[0]}-corpus-unknown"
                if validator.is_valid(doc):
                    failures.append(
                        f"enum matrix: {generation}/{stem}.{field} accepted "
                        "an unknown failClosed enum value")
                checked += 1
                doc[field] = base_docs[stem][field]
    if checked < 10:
        failures.append(f"enum matrix collapsed: only {checked} checks ran")

    if require_complete:
        failures.extend(
            f"{sid}: verification still deferred ({note})"
            for sid, note in sorted(DEFERRED_VERIFICATION.items()))

    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        return 3

    scenarios = len(manifest["scenarios"])
    print(f"agent-archivist schema compatibility corpus: "
          f"{scenarios} scenarios, {len(expected)} files")
    print(f"rules covered: {len(RULES)}/{len(RULES)}; enum matrix: "
          f"{checked} unknown-value rejections")
    if DEFERRED_VERIFICATION:
        print(f"note: {len(DEFERRED_VERIFICATION)} scenario verifications "
              "are deferred (fixtures committed, outcomes not yet "
              "asserted):", file=sys.stderr)
        for sid, note in sorted(DEFERRED_VERIFICATION.items()):
            print(f"  deferred {sid}: {note}", file=sys.stderr)
        print(f"OK (partial): every non-deferred scenario verified; "
              f"{len(DEFERRED_VERIFICATION)} deferral(s) remain")
    else:
        print("OK: every plan Section 7.1 rule has a pinned "
              "compatibility case")
    return 0


# ---------------------------------------------------------------------------
# Self-test: prove the rejection paths in memory.
# ---------------------------------------------------------------------------

def self_test() -> int:
    ctx = Ctx()
    failures: list[str] = []

    def check(name: str, condition: bool) -> None:
        if condition:
            print(f"  ok  {name}")
        else:
            failures.append(name)
            print(f"  FAIL {name}")

    old_env = load_json(READER_STEMS["ingest-envelope"])
    new_env = project_reader(old_env, "ingest-envelope")

    # Accept paths.
    check("identical schemas are a legal (empty) evolution",
          classify_projection(old_env, old_env, "ingest-envelope",
                              ctx.registry) == [])
    check("the pinned v1.1 projection is a legal additive evolution",
          classify_projection(old_env, new_env, "ingest-envelope",
                              ctx.registry) == [])

    # Rejection paths.
    def mutated(fn):
        doc = project_reader(old_env, "ingest-envelope")
        fn(doc)
        return doc

    def require_field(doc):
        doc["required"] = sorted(doc["required"] + ["client_build"])

    check("requiring the additive field is flagged",
          any(f["code"] == "required-field-added" for f in
              classify_projection(old_env, mutated(require_field),
                                  "ingest-envelope", ctx.registry)))

    def redefine(doc):
        doc["properties"]["harness"]["$ref"] = (
            "urn:agent-archivist:schema:v1:common#/$defs/uuid-v4")

    check("redefining an existing field is flagged",
          any(f["code"] == "property-redefined" for f in
              classify_projection(old_env, mutated(redefine),
                                  "ingest-envelope", ctx.registry)))

    def drop_meta(doc):
        del doc["properties"]["client_build"]["x-archivist"]

    check("an additive field without compat metadata is flagged",
          any(f["code"] == "additive-field-missing-compat-metadata" for f in
              classify_projection(old_env, mutated(drop_meta),
                                  "ingest-envelope", ctx.registry)))

    def grow_enum(doc):
        doc["properties"]["storage_profile"] = {
            "type": "string", "enum": ["zstd-v1", "zstd-v2"],
            "x-archivist": {"bearing": "security", "compat": "required-v1",
                            "failClosed": True}}

    check("growing a fail-closed enum is flagged",
          any(f["code"] == "fail-closed-enum-changed" for f in
              classify_projection(old_env, mutated(grow_enum),
                                  "ingest-envelope", ctx.registry)))

    def float_field(doc):
        doc["properties"]["ratio"] = {
            "type": "number",
            "x-archivist": {"bearing": "correlation",
                            "compat": "optional-additive-v1"}}

    check("a float-typed addition is flagged",
          any(f["code"] == "float-introduced" for f in
              classify_projection(old_env, mutated(float_field),
                                  "ingest-envelope", ctx.registry)))

    def weaken(doc):
        doc["required"] = sorted(
            f for f in doc["required"] if f != "upstream_session_id")

    codes = [f["code"] for f in
             classify_projection(old_env, mutated(weaken),
                                 "ingest-envelope", ctx.registry)]
    check("weakening an identity input is flagged",
          "required-field-removed" in codes and
          "identity-input-weakened" in codes)

    def move_limit(doc):
        doc.setdefault("x-archivist", {})["canonicalMaxBytes"] = 131072

    check("changing a pinned semantic limit is flagged",
          any(f["code"] == "semantic-metadata-changed" for f in
              classify_projection(old_env, mutated(move_limit),
                                  "ingest-envelope", ctx.registry)))

    def reserved_name(doc):
        doc["properties"]["commit_time"] = {
            "type": "string",
            "x-archivist": {"bearing": "correlation",
                            "compat": "optional-additive-v1"}}

    check("an additive field on a reserved name is flagged",
          any(f["code"] == "additive-field-uses-reserved-name" for f in
              classify_projection(old_env, mutated(reserved_name),
                                  "ingest-envelope", ctx.registry)))

    # Registry and layout rejection paths.
    drifted = copy.deepcopy(load_json(IDENTIFIERS_SCHEMA))
    drifted["x-archivist"]["derivations"][0]["fields"].remove("tenant_id")
    check("identity-registry drift is flagged",
          any(f["code"] == "identity-derivation-changed" for f in
              classify_registry(ctx.registry, Registry(drifted))))

    layout = copy.deepcopy(ctx.registry.object_keys)
    layout[0]["segments"] = ["storage_profile", "blake3",
                             "<blob_digest first 2 hex>",
                             "<blob_digest>.zst"]
    check("repurposing an existing prefix is flagged",
          any(f["code"] == "existing-prefix-repurposed" for f in
              classify_layout(ctx.registry.object_keys, layout)))

    added_prefix = copy.deepcopy(ctx.registry.object_keys) + [{
        "prefix": "tenants/<tenant_id>/v2/raw/blobs",
        "segments": ["storage_profile", "sha256",
                     "<blob_digest first 2 hex>", "<blob_digest>.zst"],
        "description": "a genuinely new namespace prefix",
    }]
    check("a genuinely new prefix is a legal addition",
          classify_layout(ctx.registry.object_keys, added_prefix) == [])

    # Canonicalizer rejection paths.
    for name, value in [("floats", {"x": 1.5}),
                        ("non-ASCII member names", {"héllo": 1})]:
        try:
            canonical_text(value)
            check(f"canonicalizer rejects {name}", False)
        except ValueError:
            check(f"canonicalizer rejects {name}", True)
    try:
        canonical_text({"x": "\ud800"})
        check("canonicalizer rejects lone surrogates", False)
    except ValueError:
        check("canonicalizer rejects lone surrogates", True)
    reorder = json.loads('{"b":1,"a":2}')
    check("canonical form is member-order independent",
          canonical_bytes(reorder) == canonical_bytes({"a": 2, "b": 1}))

    # Outcome comparator rejection paths.
    class FakeError:
        json_path = "$.synthetic"
        message = "synthetic rejection"

    class Vacuous:
        def iter_errors(self, doc):
            return iter([])

    class Always:
        def iter_errors(self, doc):
            yield FakeError()

    check("outcome comparator catches a flipped expectation",
          outcome_matches(Vacuous(), {}, "rejected", None) is not None
          and outcome_matches(Always(), {}, "accepted", None) is not None)
    check("outcome comparator enforces the reason token",
          outcome_matches(Always(), {}, "rejected", "zstd-v2") is not None
          and outcome_matches(Always(), {}, "rejected",
                              "synthetic") is None)

    # Coverage gate rejection path.
    manifest = json.loads(build_bundle()["manifest.json"])
    # Deferral gate: a deferred id that names no scenario verifies
    # nothing — it would mask the scenario's failures forever, so the
    # deferral set must stay a subset of the real scenario ids.
    check("deferred verifications name real scenarios",
          set(DEFERRED_VERIFICATION)
          <= {e["id"] for e in manifest["scenarios"]})
    del manifest["coverage"]["no-floats"]
    hole = [rule for rule, ids in manifest["coverage"].items() if not ids]
    check("a coverage hole is detectable",
          "no-floats" not in manifest["coverage"] and not hole)

    # Baseline digest pin rejection path.
    check("baseline digest pin detects tampering",
          sha256_hex(b"tampered") != ctx.baseline_digests["envelope"])

    if failures:
        print(f"self-test: {len(failures)} failed", file=sys.stderr)
        return 3
    print("self-test: all rejection paths proven")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify", action="store_true",
                       help="regenerate and verify the committed corpus")
    modes.add_argument("--generate", metavar="OUTPUT", nargs="?",
                       const=str(DEFAULT_OUTPUT),
                       help="write the corpus (default: the committed "
                            "location)")
    modes.add_argument("--self-test", action="store_true",
                       help="prove the rejection paths")
    parser.add_argument("--require-complete", action="store_true",
                        help="fail while any scenario verification is "
                             "still deferred to a later split-child")
    args = parser.parse_args(argv)

    if args.generate is not None:
        write_bundle(Path(args.generate), build_bundle())
        return 0
    if args.self_test:
        return self_test()
    return verify_bundle(args.require_complete)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
