#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Zero-entropy generator for the usage-summary example bundle.

The bundle under schemas/v1/examples/usage-summaries/ is the golden-vector
table for the usage-summary family (docs/notes/usage-summary-schema.md,
schemas/v1/usage-summary.json): every record digest is computed with the
byte-exact `usage-summary-v1` construction the schema pins, and the
occurrence IDs cited as provenance are the very IDs the raw-provenance
example bundle materializes — so the bundle demonstrates the plan Phase 10
traceability sentence on the usage projection: token questions answered by
a content-free row that traces to raw evidence by occurrence ID alone.

Every identifier and count is a pinned synthetic constant drawn from a
closed vocabulary (SEC-010); no real session, account, transcript, or
price appears. The counts are numbers the synthetic sources "reported";
no monetary amount exists anywhere in the generator or the bundle — cost
is a query-time computation outside the archive and has no encoding here.

--verify proves the family's acceptance, not just its bytes: each record
is re-digested from its own canonical bytes (self-verification), the
record whose source omitted usage validates as `unknown` and never as
zero (the bounded state is mandatory, the measured branch demands every
count, and no count may sit next to an `unknown`), the schema admits no
transcript content and no monetary field (the reserved-name matrix —
content carriers, monetary material, governance, raw paths, stability
breakers, and grand-total tokens — is injected one name at a time and
must be rejected), and the committed records collectively round-trip
every member the schema defines, optionals included, omitted-never-null.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import episodegen  # noqa: E402  (the provenance-payload digest helper)
import provenancegen  # noqa: E402  (pinned constructions + occurrence IDs)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "schemas" / "v1" / "examples" / "usage-summaries"
COMMON_SCHEMA = REPO_ROOT / "schemas" / "v1" / "common.json"
USAGE_SCHEMA = REPO_ROOT / "schemas" / "v1" / "usage-summary.json"

BUNDLE_SCHEMA = "archivist.usage-examples/v1"

# The pinned synthetic producer identity (plan Section 7.1 derived axis).
PIPELINE_ID = "usage"
PIPELINE_VERSION = "1"
USAGE_SUMMARY_VERSION = 1

# The pinned adapter projections, matched to the raw-provenance bundle: the
# same adapters that captured the materialized occurrences are the ones the
# usage rows name, so a row is auditable against its cited occurrence
# without leaving the two bundles.
ADAPTER_CLAUDE = provenancegen.ADAPTER_A  # "claude-jsonl"
ADAPTER_CODEX = provenancegen.ADAPTER_B  # "codex-rollout"
PROJECTION_VERSION = provenancegen.PROJECTION_A  # "1"

# Pinned synthetic model identities and service tiers (SEC-010). The model
# strings exercise the model-id grammar's two shapes — bare and
# provider-qualified — and are not claims about real product catalogs.
MODEL_A = "claude-opus-4-6"
MODEL_B = "openai/gpt-5.3-mini"
TIER_STANDARD = "standard"
TIER_PRIORITY = "priority"


def usage_digest(record_without_digest: dict) -> str:
    """Construction `usage-summary-v1` (schemas/v1/usage-summary.json,
    x-archivist.derivations): SHA-256 under the domain label
    `usage-summary-v1` over the RFC 8785 canonicalization of the complete
    record with the `usage_summary_digest` member removed — the same
    label/length framing every ingest identifier and the episode digest
    use, so one verifier core walks every family. The digest member is
    excluded from its own preimage, which is what makes the record
    self-verifying."""
    canonical = provenancegen.canonical_json(record_without_digest).encode("utf-8")
    return provenancegen.derive("usage-summary-v1", canonical)


def usage_object_key(digest_hex: str) -> str:
    return (f"tenants/{provenancegen.TENANT}/v1/derived/{PIPELINE_ID}/"
            f"{PIPELINE_VERSION}/usage-summaries/{digest_hex[:2]}/"
            f"{digest_hex}.json")


# The occurrence IDs every record cites, computed once from the pinned
# raw-provenance inputs (schemas/v1/examples/provenance/).
_BLOB = episodegen.blob_digest_of_provenance_payload()
_OCC_A, _ = provenancegen.build_occurrence_a(_BLOB)
_OCC_B, _ = provenancegen.build_occurrence_b(_BLOB)
OCCURRENCE_ID_A = _OCC_A["occurrence_id"]
OCCURRENCE_ID_B = _OCC_B["occurrence_id"]


# --- record assembly --------------------------------------------------------


def assemble_record(occurrence_id: str, adapter_id: str,
                    members: dict) -> tuple[dict, dict]:
    base = {
        "usage_summary_version": USAGE_SUMMARY_VERSION,
        "tenant_id": provenancegen.TENANT,
        "pipeline_id": PIPELINE_ID,
        "pipeline_version": PIPELINE_VERSION,
        "adapter_id": adapter_id,
        "adapter_projection_version": PROJECTION_VERSION,
        "occurrence_id": occurrence_id,
        **members,
    }
    record = dict(base)
    record["usage_summary_digest"] = usage_digest(base)
    identity = {
        "usage_summary_digest": record["usage_summary_digest"],
        "object_key": usage_object_key(record["usage_summary_digest"]),
        "usage_summary_version": USAGE_SUMMARY_VERSION,
        "pipeline_id": PIPELINE_ID,
        "pipeline_version": PIPELINE_VERSION,
        "occurrence_id": occurrence_id,
        "adapter_id": adapter_id,
        "adapter_projection_version": PROJECTION_VERSION,
        "harness_usage_state": members["harness_usage"]["state"],
    }
    return record, identity


def measured(input_tokens: int, output_tokens: int, cache_read: int,
             cache_5m: int, cache_1h: int, reasoning: int,
             messages: int) -> dict:
    return {
        "harness_usage": {
            "state": "measured",
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read,
            "cache_creation": {"ephemeral_5m": cache_5m,
                               "ephemeral_1h": cache_1h},
            "reasoning_tokens": reasoning,
            "assistant_message_count": messages,
        },
    }


def unknown(reason: str) -> dict:
    return {"harness_usage": {"state": "unknown", "reason": reason}}


def build_full_coverage() -> tuple[dict, dict]:
    """Every measured member at a nonzero value, plus model identity and
    service tier: the fixture that round-trips the full shape. Cites the
    raw-provenance bundle's direct-upload occurrence."""
    return assemble_record(
        OCCURRENCE_ID_A, ADAPTER_CLAUDE,
        {"model_id": MODEL_A, "service_tier": TIER_STANDARD,
         **measured(4127, 986, 15230, 152304, 40960, 512, 12)})


def build_observed_zero() -> tuple[dict, dict]:
    """A measured record whose cache and reasoning axes are explicit zeros:
    the source reported a complete, well-formed usage object that simply
    used no cache and reasoned nothing. Zero is an observation; only the
    `unknown` records below are absences — this record is the contrast that
    keeps 'never zero' from being misread as 'never zero values'."""
    return assemble_record(
        OCCURRENCE_ID_B, ADAPTER_CODEX,
        {"model_id": MODEL_B, "service_tier": TIER_PRIORITY,
         **measured(903, 221, 0, 0, 0, 0, 3)})


def build_usage_absent() -> tuple[dict, dict]:
    """The acceptance fixture: the source carried no usage region at all.
    The record validates with harness_usage = unknown/absent — and there is
    no all-zero measured encoding of this occurrence anywhere in the family,
    because the measured branch demands every count with at least one summed
    message. Model and tier are still present: absence of usage does not
    erase the identity the source did report."""
    return assemble_record(
        OCCURRENCE_ID_A, ADAPTER_CLAUDE,
        {"model_id": MODEL_A, "service_tier": TIER_STANDARD,
         **unknown("absent")})


def build_usage_malformed() -> tuple[dict, dict]:
    """A usage region was present but not parseable under the source's own
    declared shape (wrong types, negative counts) — the bounded refusal,
    not a partial sum. The service tier is absent here (omitted, never
    null): the source named no tier, and the record stays valid."""
    return assemble_record(
        OCCURRENCE_ID_B, ADAPTER_CODEX,
        {"model_id": MODEL_B, **unknown("malformed")})


def build_usage_unsupported() -> tuple[dict, dict]:
    """The usage region parses but the pinned projection does not support
    its shape (cache creation with no ephemeral-class split, counts spanning
    two model identities). Both identity members are omitted: an occurrence
    whose dialect the projection cannot read names no model it cannot
    vouch for, and the record stays valid without them."""
    return assemble_record(
        OCCURRENCE_ID_A, ADAPTER_CLAUDE, unknown("unsupported"))


# --- bundle construction ----------------------------------------------------


PATH_FULL = "usage-summaries/full-coverage.json"
PATH_ZERO = "usage-summaries/observed-zero.json"
PATH_ABSENT = "usage-summaries/usage-absent.json"
PATH_MALFORMED = "usage-summaries/usage-malformed.json"
PATH_UNSUPPORTED = "usage-summaries/usage-unsupported.json"
RECORD_PATHS = (PATH_FULL, PATH_ZERO, PATH_ABSENT, PATH_MALFORMED,
                PATH_UNSUPPORTED)


def schema_member_names() -> set[str]:
    """Every member name the schema defines: top-level properties and
    requireds, plus each $defs object's properties and requireds. This is
    the set the committed records must collectively exercise."""
    schema = json.loads(USAGE_SCHEMA.read_text(encoding="utf-8"))
    names: set[str] = set()
    for container in [schema] + list(schema["$defs"].values()):
        names |= set(container.get("properties", {}))
        names |= set(container.get("required", []))
    return names


def record_member_names(node: object) -> set[str]:
    """Every object key appearing anywhere inside a record (recursively)."""
    names: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            names.add(key)
            names |= record_member_names(value)
    elif isinstance(node, list):
        for item in node:
            names |= record_member_names(item)
    return names


def build_manifest(files: dict[str, bytes],
                   identities: dict[str, dict]) -> dict:
    schema = json.loads(USAGE_SCHEMA.read_text(encoding="utf-8"))
    reserved_count = len(schema["x-archivist"]["reservedFields"])
    members = schema_member_names()
    scenarios = [
        {
            "id": "full-coverage",
            "record": PATH_FULL,
            "asserts": [
                "every measured member is present at a nonzero value and the record validates — model identity, service tier, all five count groups, both ephemeral classes, and the assistant-message denominator",
                "the record digest is recomputable from the record's own canonical bytes with the digest member removed (VAL-005)",
                "occurrence provenance is the occurrence-v1 digest the raw-provenance bundle materializes — never a raw object path",
                "the adapter and projection version match the cited occurrence's raw provenance, so the row is auditable without consulting anything outside the two bundles",
            ],
        },
        {
            "id": "observed-zero",
            "record": PATH_ZERO,
            "asserts": [
                "explicit zeros are observations: the source reported a complete usage object with no cache use and no reasoning tokens, and the record states them as zeros",
                "zero-as-observation is the contrast that makes the unknown records meaningful: absence is a state, never a zero",
                "the provider-qualified model-id grammar shape is exercised (namespace separator, lowercase token)",
            ],
        },
        {
            "id": "usage-absent",
            "record": PATH_ABSENT,
            "asserts": [
                "a source that omitted usage validates as harness_usage = unknown/absent — and never as zeros: the measured branch demands every count with at least one summed message, so absence is inexpressible as numbers",
                "the bounded state is mandatory: removing the harness_usage member entirely is invalid, so absence cannot hide outside the state either",
                "model identity and service tier remain present: absent usage does not erase the identity the source did report",
            ],
        },
        {
            "id": "usage-malformed",
            "record": PATH_MALFORMED,
            "asserts": [
                "a present-but-unparseable usage region is the bounded refusal unknown/malformed, never a partial sum over whatever happened to parse",
                "an absent optional member is omitted, never null: no service_tier member, and no null anywhere in the record",
            ],
        },
        {
            "id": "usage-unsupported",
            "record": PATH_UNSUPPORTED,
            "asserts": [
                "a parseable usage region the pinned projection does not support (no ephemeral-class split, or counts across two model identities) is unknown/unsupported, never a guess distributed across classes",
                "both identity members are omitted rather than invented, and the record still validates — the closed shape carries exactly what the source vouched for",
            ],
        },
    ]
    return {
        "schema": BUNDLE_SCHEMA,
        "scan_version": 1,
        "authority": {
            "usage_summary": "schemas/v1/usage-summary.json",
            "vocabulary": "schemas/v1/common.json",
            "usage_summary_digest_construction":
                "schemas/v1/usage-summary.json#x-archivist.derivations",
            "identifier_constructions": "schemas/v1/ingest-identifiers.json",
            "raw_provenance_bundle":
                "schemas/v1/examples/provenance/ (the occurrence IDs cited here)",
        },
        "synthetic": (
            "Every identifier, model string, tier, and count in this bundle "
            "is pinned synthetic data (SEC-006, SEC-010); no real session, "
            "account, transcript, or price appears, and no monetary amount "
            "exists anywhere in the generator or the bundle — cost is a "
            "query-time computation outside the archive."
        ),
        "canonicalization": (
            "Each file is RFC 8785-style canonical JSON plus one trailing "
            "LF. usage_summary_digest is the usage-summary-v1 construction "
            "over the record's canonical bytes with the digest member "
            "removed, so every digest below is recomputable from this "
            "bundle alone."
        ),
        "content_boundary": (
            "No record file carries transcript text, a prompt, a tool "
            "argument, or a monetary amount: the reserved-name matrix in "
            "tools/usagegen.py --verify injects each reserved name — "
            "content carriers, monetary material, governance and redaction "
            "material, raw object paths, wall-clock and run identity, and "
            "the grand-total tokens — into a valid record and proves the "
            "schema rejects it. The identity and count grammars are bounded "
            "tokens and integers that cannot carry prose, so the "
            "content-freeness claim is mechanical, not aspirational."
        ),
        "scenarios": scenarios,
        "invariants": {
            "records": len(RECORD_PATHS),
            "distinct_usage_summary_digests": len(RECORD_PATHS),
            "forbidden_members_rejected": reserved_count,
            "members_exercised": len(members),
            "members_exercised_meaning": (
                "every member the schema defines — required and optional, "
                "measured and unknown, both ephemeral classes — appears in "
                "at least one committed record: the bundle round-trips the "
                "whole shape, and the optional members are exercised in "
                "both states, present and omitted-never-null"
            ),
            "unknown_is_never_zero": (
                "the three unknown records carry no count member at all, "
                "the one-row-per-occurrence catalog would hold exactly one "
                "of these alternative rebuild outcomes per cited occurrence"
            ),
        },
        "files": [
            {
                "path": path,
                "bytes": len(files[path]),
                "sha256": hashlib.sha256(files[path]).hexdigest(),
                "identity": identities[path],
            }
            for path in sorted(files)
        ],
    }


def build_bundle() -> dict[str, bytes]:
    full, identity_full = build_full_coverage()
    zero, identity_zero = build_observed_zero()
    absent, identity_absent = build_usage_absent()
    malformed, identity_malformed = build_usage_malformed()
    unsupported, identity_unsupported = build_usage_unsupported()
    identities = {
        PATH_FULL: identity_full,
        PATH_ZERO: identity_zero,
        PATH_ABSENT: identity_absent,
        PATH_MALFORMED: identity_malformed,
        PATH_UNSUPPORTED: identity_unsupported,
    }
    files = {
        path: provenancegen.file_bytes(record)
        for path, record in (
            (PATH_FULL, full),
            (PATH_ZERO, zero),
            (PATH_ABSENT, absent),
            (PATH_MALFORMED, malformed),
            (PATH_UNSUPPORTED, unsupported),
        )
    }
    files["manifest.json"] = provenancegen.file_bytes(
        build_manifest(files, identities))
    return files


# --- generate / verify ------------------------------------------------------


def write_bundle(output: Path, files: dict[str, bytes]) -> None:
    marker = output / "manifest.json"
    if output.exists() and not (
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


def load_jsonschema():
    try:
        import jsonschema  # noqa: F401
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
    except ImportError:
        return None
    import jsonschema as js

    def validator(schema_path: Path):
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        js.Draft202012Validator.check_schema(schema)
        common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
        registry = Registry().with_resource(
            "urn:agent-archivist:schema:v1:common",
            Resource.from_contents(common, default_specification=DRAFT202012),
        )
        return schema, js.Draft202012Validator(schema, registry=registry)

    return validator


def verify_record(path: str, record: dict, failures: list[str]) -> None:
    """Per-record invariants, recomputed from the record's own bytes — the
    self-verification an auditor performs with nothing but the stored
    object."""
    body = {k: v for k, v in record.items() if k != "usage_summary_digest"}
    if usage_digest(body) != record.get("usage_summary_digest"):
        failures.append(
            f"{path}: usage_summary_digest is not the usage-summary-v1 "
            f"digest of the record's own canonical bytes")

    def walk_nulls(node: object, at: str) -> None:
        if node is None:
            failures.append(f"{path}: null at {at} — members are omitted, "
                            f"never null")
        elif isinstance(node, dict):
            for key, value in node.items():
                walk_nulls(value, f"{at}.{key}")
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk_nulls(item, f"{at}[{index}]")

    walk_nulls(record, "$")

    usage = record["harness_usage"]
    if record["occurrence_id"] not in (OCCURRENCE_ID_A, OCCURRENCE_ID_B):
        failures.append(f"{path}: occurrence provenance must cite "
                        f"bundle-known occurrences")
    if record["pipeline_id"] != PIPELINE_ID or \
            record["pipeline_version"] != PIPELINE_VERSION:
        failures.append(f"{path}: pipeline identity must be the pinned "
                        f"usage/1")
    if record["adapter_projection_version"] != PROJECTION_VERSION:
        failures.append(f"{path}: adapter_projection_version must be the "
                        f"pinned projection generation")

    if usage["state"] == "measured":
        expected = {"state", "input_tokens", "output_tokens",
                    "cache_read_tokens", "cache_creation", "reasoning_tokens",
                    "assistant_message_count"}
        if set(usage) != expected:
            failures.append(f"{path}: measured usage must carry every count "
                            f"member exactly (has {sorted(usage)})")
        for member in ("input_tokens", "output_tokens", "cache_read_tokens",
                       "reasoning_tokens", "assistant_message_count"):
            value = usage[member]
            if not isinstance(value, int) or isinstance(value, bool) \
                    or value < 0:
                failures.append(f"{path}: {member} must be a non-negative "
                                f"integer")
        if usage["assistant_message_count"] < 1:
            failures.append(f"{path}: measured usage must sum at least one "
                            f"assistant message")
        for cls in ("ephemeral_5m", "ephemeral_1h"):
            value = usage["cache_creation"][cls]
            if not isinstance(value, int) or isinstance(value, bool) \
                    or value < 0:
                failures.append(f"{path}: cache_creation.{cls} must be a "
                                f"non-negative integer")
    elif usage["state"] == "unknown":
        if set(usage) != {"state", "reason"}:
            failures.append(f"{path}: an unknown usage carries no count "
                            f"member at all (has {sorted(usage)})")
        if usage.get("reason") not in ("absent", "malformed", "unsupported"):
            failures.append(f"{path}: unknown reason must be from the "
                            f"closed v1 set")
    else:
        failures.append(f"{path}: harness_usage must be measured or unknown, "
                        f"never {usage.get('state')!r}")

    key = usage_object_key(record["usage_summary_digest"])
    common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
    pattern = re.compile(
        common["$defs"]["usage-summary-object-key"]["pattern"])
    if not pattern.fullmatch(key):
        failures.append(f"{path}: object key does not match the "
                        f"usage-summary-object-key pattern")
    if key.rsplit("/", 2)[1] != record["usage_summary_digest"][:2]:
        failures.append(f"{path}: object key shard must be the digest's "
                        f"first two hex")


def negative_cases(valid: dict) -> list[tuple[str, dict, bool]]:
    """The negative matrix: (label, mutated record, must_be_rejected). The
    reserved list is read from the schema itself so the matrix can never
    drift from it; the acceptance anchors — transcript content, monetary
    field, absent-as-zero — are pinned structural cases on top."""
    schema = json.loads(USAGE_SCHEMA.read_text(encoding="utf-8"))
    reserved = schema["x-archivist"]["reservedFields"]
    cases: list[tuple[str, dict, bool]] = []
    payloads = {
        "cost": {"amount": 3, "currency": "synthetic"},
        "total_tokens": 12345,
        "prompt": "what did the user ask",
        "messages": [{"role": "user", "text": "hello"}],
        "transcript": "synthetic transcript bytes",
        "run_id": "rebuild-2026-09-14",
        "built_at": "2026-09-14T00:00:00Z",
        "raw_object_key": "tenants/x/v1/raw/blobs/zstd-v1/sha256/ab/ab.json",
        "price": 0.03,
        "text": "assistant prose",
    }
    for name in sorted(reserved):
        mutated = dict(valid)
        mutated[name] = payloads.get(name, "synthetic-" + name)
        cases.append((f"forbidden member: {name}", mutated, True))

    absent_record = build_usage_absent()[0]
    unknown_with_counts = json.loads(json.dumps(absent_record))
    unknown_with_counts["harness_usage"]["input_tokens"] = 0
    unknown_with_counts["harness_usage"]["cache_read_tokens"] = 0

    measured_record = build_full_coverage()[0]
    missing_count = json.loads(json.dumps(measured_record))
    del missing_count["harness_usage"]["reasoning_tokens"]
    zero_messages = json.loads(json.dumps(measured_record))
    zero_messages["harness_usage"]["assistant_message_count"] = 0
    negative_count = json.loads(json.dumps(measured_record))
    negative_count["harness_usage"]["input_tokens"] = -1
    float_count = json.loads(json.dumps(measured_record))
    float_count["harness_usage"]["input_tokens"] = 1.5
    extra_class = json.loads(json.dumps(measured_record))
    extra_class["harness_usage"]["cache_creation"]["ephemeral_15m"] = 5
    null_model = json.loads(json.dumps(measured_record))
    null_model["model_id"] = None
    no_usage_member = json.loads(json.dumps(absent_record))
    del no_usage_member["harness_usage"]

    cases.extend([
        ("unknown top-level member",
         dict(valid, extra_member=1), True),
        ("usage_summary_version 2",
         dict(valid, usage_summary_version=2), True),
        ("unknown pipeline_id",
         dict(valid, pipeline_id="not-a-pipeline"), True),
        ("unknown state value",
         dict(valid, harness_usage={"state": "unsettled"}), True),
        ("unknown reason outside the closed set",
         dict(absent_record,
              harness_usage={"state": "unknown", "reason": "nobody_knows"}),
         True),
        ("counts beside an unknown state", unknown_with_counts, True),
        ("measured missing a count member", missing_count, True),
        ("measured with zero summed messages", zero_messages, True),
        ("measured with a negative count", negative_count, True),
        ("measured with a fractional count", float_count, True),
        ("cache class outside the closed set", extra_class, True),
        ("null where a member is omitted", null_model, True),
        ("harness_usage member removed", no_usage_member, True),
        ("valid control (the matrix's negative control)",
         json.loads(json.dumps(valid)), False),
    ])
    return cases


def verify_bundle() -> int:
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

    for path in sorted(expected):
        if path.endswith(".json") and path in on_disk:
            raw = (committed / path).read_bytes()
            if provenancegen.file_bytes(json.loads(raw)) != raw:
                failures.append(f"non-canonical formatting in {path}")

    records = {p: json.loads(expected[p]) for p in expected
               if p.startswith("usage-summaries/")}
    for path, record in sorted(records.items()):
        verify_record(path, record, failures)

    if len({r["usage_summary_digest"] for r in records.values()}) \
            != len(records):
        failures.append("usage summary digests must be pairwise distinct")
    if len({usage_object_key(r["usage_summary_digest"])
            for r in records.values()}) != len(records):
        failures.append("usage summary object keys must be pairwise distinct")

    # Every member the schema defines must appear in at least one committed
    # record — the fixture suite round-trips the whole shape, optionals in
    # both states.
    defined = schema_member_names()
    observed: set[str] = set()
    for record in records.values():
        observed |= record_member_names(record)
    missing_members = sorted(defined - observed)
    if missing_members:
        failures.append(f"members never exercised by any fixture: "
                        f"{missing_members}")

    # Optional members must be exercised as absent somewhere, too —
    # omitted, never null.
    if "model_id" in records[PATH_UNSUPPORTED]:
        failures.append("usage-unsupported must omit model_id")
    if "service_tier" in records[PATH_MALFORMED] or \
            "service_tier" in records[PATH_UNSUPPORTED]:
        failures.append("usage-malformed and usage-unsupported must omit "
                        "service_tier")

    # Manifest identities must carry matching, pattern-valid object keys,
    # and the manifest's invariant counts must not drift.
    common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
    pattern = re.compile(
        common["$defs"]["usage-summary-object-key"]["pattern"])
    manifest = json.loads(expected["manifest.json"])
    for entry in manifest["files"]:
        key = entry["identity"].get("object_key")
        if key is None:
            failures.append(f"{entry['path']}: manifest must carry the "
                            f"object key")
        elif not pattern.fullmatch(key):
            failures.append(f"{entry['path']}: manifest object key misses "
                            f"the pattern")
    if manifest["invariants"]["records"] != len(records):
        failures.append("manifest record count drifted")
    if manifest["invariants"]["forbidden_members_rejected"] != len(
            json.loads(USAGE_SCHEMA.read_text(encoding="utf-8"))
            ["x-archivist"]["reservedFields"]):
        failures.append("manifest forbidden-members count drifted from "
                        "the schema")
    if manifest["invariants"]["members_exercised"] != len(defined):
        failures.append("manifest members-exercised count drifted from "
                        "the schema")

    # Schema validation: every committed record validates positively, and
    # the negative matrix is rejected one case at a time.
    make_validator = load_jsonschema()
    if make_validator is None:
        print(
            "jsonschema is not installed: instance validation skipped "
            "(pip install jsonschema)",
            file=sys.stderr,
        )
        return 4
    _, usage_validator = make_validator(USAGE_SCHEMA)
    for path in sorted(records):
        if path in on_disk:
            for error in sorted(usage_validator.iter_errors(
                    json.loads((committed / path).read_bytes()))):
                failures.append(
                    f"{path}: {error.message} at {list(error.absolute_path)}")

    control_ok = False
    for label, mutated, must_reject in negative_cases(records[PATH_FULL]):
        rejected = bool(list(usage_validator.iter_errors(mutated)))
        if must_reject and not rejected:
            failures.append(f"negative matrix: schema ACCEPTED {label}")
        elif not must_reject:
            if rejected:
                failures.append(
                    f"negative matrix: control case was rejected ({label})")
            else:
                control_ok = True
    if not control_ok:
        failures.append("negative matrix: the valid control case never ran")

    if failures:
        print(f"usage-summary bundle verification FAILED "
              f"({len(failures)}):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 3
    reserved_count = len(
        json.loads(USAGE_SCHEMA.read_text(encoding="utf-8"))
        ["x-archivist"]["reservedFields"])
    print(
        "usage-summary bundle verified: "
        f"{len(records)} records, {len(defined)} schema members exercised, "
        f"{reserved_count} forbidden members rejected by the schema, all "
        f"digests recomputed from bundle bytes"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify", action="store_true",
                       help="regenerate and byte-compare the committed "
                            "bundle, validate instances and the negative "
                            "matrix")
    modes.add_argument("--generate", metavar="OUTPUT", nargs="?",
                       const=str(DEFAULT_OUTPUT),
                       help="write the bundle (default: the committed "
                            "location)")
    args = parser.parse_args(argv)

    if args.generate is not None:
        write_bundle(Path(args.generate), build_bundle())
        return 0
    return verify_bundle()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
