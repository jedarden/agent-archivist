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
breakers, grand-total tokens, and the exact-inference artifact's own
usage-counter names — is injected one name at a time and must be
rejected), and the committed records collectively round-trip every
member the schema defines, optionals included, omitted-never-null. The
two usage denominators stay separate members with separate coverage
states: the reserved provider-observed member's shape is checked against
the exact-inference artifact schema's own `usage`-kind definition (read
from schemas/v1/inference-artifact.json, never restated here), the
negative matrix proves the provider counters cannot collapse into
`harness_usage`, the harness axes cannot ride `provider_usage`, and
neither denominator can be summed into one number, and the corpus pins
the both/either/neither coverage matrix by count.

--self-test proves the same rejection paths without the committed
bundle: the digest construction pins its domain label, its preimage
rule, and its object-key layout, the per-record invariants reject every
fault class — the provider denominator's included — the reconciliation
check catches drift on either side of the two schemas, the write guard
refuses a foreign directory, and the schema rejects the full negative
matrix while both valid controls (one denominator, both denominators)
stay valid.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import episodegen  # noqa: E402  (the provenance-payload digest helper)
import provenancegen  # noqa: E402  (pinned constructions + occurrence IDs)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "schemas" / "v1" / "examples" / "usage-summaries"
COMMON_SCHEMA = REPO_ROOT / "schemas" / "v1" / "common.json"
USAGE_SCHEMA = REPO_ROOT / "schemas" / "v1" / "usage-summary.json"
INFERENCE_SCHEMA = REPO_ROOT / "schemas" / "v1" / "inference-artifact.json"

# The shared u63 counter grammar both denominators' counts ref.
COMMON_U63 = "urn:agent-archivist:schema:v1:common#/$defs/u63"

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

# The closed refusal set of the provider-observed denominator's `unknown`
# state. Cross-checked against the schema by the reconciliation check, so
# neither side can drift.
PROVIDER_UNKNOWN_REASONS = ("unreconciled", "malformed")

# How the summary's provider-observed counter members map onto the
# exact-inference artifact schema's own `usage`-kind counter names — the
# reconciliation check walks this mapping in both directions.
ARTIFACT_COUNTER_MAP = {
    "input_tokens": "usage_input_tokens",
    "output_tokens": "usage_output_tokens",
    "total_tokens": "usage_total_tokens",
}


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
    if "provider_usage" in members:
        identity["provider_usage_state"] = members["provider_usage"]["state"]
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


def provider_measured(input_tokens: int, output_tokens: int, total_tokens: int,
                      reports: int) -> dict:
    """The provider-observed denominator in its `measured` state: the
    exact-inference `usage` artifact kind's bounded intersection, summed
    over the reconciled usage reports, with the report count as the
    aggregate's coverage denominator. `total_tokens` is the sum of the
    reports' own totals — retained as the providers reported them, never
    recomputed as input plus output."""
    return {"provider_usage": {
        "state": "measured",
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "usage_report_count": reports,
    }}


def provider_unknown(reason: str) -> dict:
    return {"provider_usage": {"state": "unknown", "reason": reason}}


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


def build_provider_observed() -> tuple[dict, dict]:
    """Both denominators measured on one row: the same harness reading as
    full-coverage (this is that sibling outcome for the same occurrence),
    with the provider boundary's exact counts standing in their own member.
    The provider counts deliberately differ from the harness counts — the
    two denominators account for the same traffic differently, and the
    record carries both without reconciling them. The provider's own total
    exceeds input plus output (cache-discounted arithmetic retained as
    reported); the counts sum three reconciled usage reports."""
    return assemble_record(
        OCCURRENCE_ID_A, ADAPTER_CLAUDE,
        {"model_id": MODEL_A, "service_tier": TIER_STANDARD,
         **measured(4127, 986, 15230, 152304, 40960, 512, 12),
         **provider_measured(4109, 986, 16420, 3)})


def build_provider_only() -> tuple[dict, dict]:
    """A row carrying only the provider denominator: the source wrote no
    usage region at all (harness_usage is the bounded unknown/absent
    refusal) while the routed traffic's provider boundary reported exact
    counts — the plan's 'either'. The exact denominator stands on its own:
    nothing in the record reconciles, rewrites, or averages it against the
    refused harness denominator. One reconciled report whose provider
    arithmetic is plain (total exactly input plus output)."""
    return assemble_record(
        OCCURRENCE_ID_B, ADAPTER_CODEX,
        {"model_id": MODEL_B, "service_tier": TIER_PRIORITY,
         **unknown("absent"),
         **provider_measured(903, 221, 1124, 1)})


def build_provider_unreconciled() -> tuple[dict, dict]:
    """Covered traffic without an exact count: the Phase 9 join reconciles
    exact-capture material to the occurrence but no `usage` artifact is
    among it, so the provider denominator is its own bounded
    unknown/unreconciled state — never zero, and never silence: the member
    is present precisely so the row does not read as uncovered. The only
    difference from provider-observed is the provider member's state, which
    is what makes the two denominators' independence visible in one
    bundle."""
    return assemble_record(
        OCCURRENCE_ID_A, ADAPTER_CLAUDE,
        {"model_id": MODEL_A, "service_tier": TIER_STANDARD,
         **measured(4127, 986, 15230, 152304, 40960, 512, 12),
         **provider_unknown("unreconciled")})


# --- bundle construction ----------------------------------------------------


PATH_FULL = "usage-summaries/full-coverage.json"
PATH_ZERO = "usage-summaries/observed-zero.json"
PATH_ABSENT = "usage-summaries/usage-absent.json"
PATH_MALFORMED = "usage-summaries/usage-malformed.json"
PATH_UNSUPPORTED = "usage-summaries/usage-unsupported.json"
PATH_PROVIDER_OBSERVED = "usage-summaries/provider-observed.json"
PATH_PROVIDER_ONLY = "usage-summaries/provider-only.json"
PATH_PROVIDER_UNRECONCILED = "usage-summaries/provider-unreconciled.json"
RECORD_PATHS = (PATH_FULL, PATH_ZERO, PATH_ABSENT, PATH_MALFORMED,
                PATH_UNSUPPORTED, PATH_PROVIDER_OBSERVED,
                PATH_PROVIDER_ONLY, PATH_PROVIDER_UNRECONCILED)


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


def artifact_usage_branch(artifact: dict) -> dict | None:
    """The exact-inference artifact schema's own definition of its `usage`
    kind: the allOf branch that fires when artifact_kind is `usage` — its
    `then` carries the required members and the closed metadata allowlist's
    required usage counters. None when the branch does not exist."""
    for branch in artifact.get("allOf", []):
        if not isinstance(branch, dict):
            continue
        kind = (branch.get("if", {}).get("properties", {})
                .get("artifact_kind", {}))
        if isinstance(kind, dict) and kind.get("const") == "usage":
            then = branch.get("then", {})
            return then if isinstance(then, dict) else None
    return None


def reconcile_provider_usage(usage_schema: dict | None = None,
                             artifact: dict | None = None) -> list[str]:
    """The reserved provider-observed denominator's contract with the
    exact-inference artifact schema (aa-b5cf6541), checked against both
    schemas' own definitions — never a restatement here, so neither schema
    can drift from the other without this check failing:

    - the artifact's `usage` kind requires `metadata` and `usage_source`,
      and its metadata allowlist requires exactly the three usage counters
      the summary's provider member carries, each on the shared u63;
    - the summary's `provider-usage-measured` requires exactly those three
      counters (under this family's member names) plus its `state` and the
      `usage_report_count` coverage denominator, each counter on the same
      shared u63, in a closed shape;
    - the artifact's per-report `usage_source` enum stays closed and does
      NOT appear in the summary member: a per-occurrence aggregate over
      several reports has no single source, so the member stays in the
      artifact where it is exact;
    - neither denominator can carry the other's axes: no harness axis in
      the provider object, no provider axis in the harness object, and no
      single member can express both;
    - the artifact's own counter names are reserved at the summary root,
      so an artifact-shaped usage payload cannot be hoisted into a
      collapsed top-level member.
    """
    failures: list[str] = []
    if usage_schema is None:
        usage_schema = json.loads(USAGE_SCHEMA.read_text(encoding="utf-8"))
    if artifact is None:
        artifact = json.loads(INFERENCE_SCHEMA.read_text(encoding="utf-8"))

    then = artifact_usage_branch(artifact)
    if then is None:
        return ["inference-artifact.json: the `usage` artifact-kind branch "
                "does not exist"]
    for member in ("metadata", "usage_source"):
        if member not in then.get("required", []):
            failures.append(f"inference-artifact.json: the usage kind must "
                            f"require {member}")

    metadata_shape = then.get("properties", {}).get("metadata", {})
    counters_required = metadata_shape.get("required", [])
    if sorted(counters_required) != sorted(ARTIFACT_COUNTER_MAP.values()):
        failures.append(
            f"inference-artifact.json: the usage kind's counter set drifted "
            f"from the bounded intersection ({counters_required})")
    allowlist = artifact.get("properties", {}).get("metadata", {}) \
        .get("properties", {})
    for theirs in ARTIFACT_COUNTER_MAP.values():
        if allowlist.get(theirs, {}).get("$ref") != COMMON_U63:
            failures.append(f"inference-artifact.json: {theirs} is not the "
                            f"shared u63 counter")

    source = artifact.get("properties", {}).get("usage_source", {})
    if not isinstance(source.get("enum"), list) or not source["enum"]:
        failures.append("inference-artifact.json: usage_source must stay a "
                        "closed enum")

    measured = usage_schema.get("$defs", {}).get("provider-usage-measured")
    if not isinstance(measured, dict):
        return failures + ["usage-summary.json: provider-usage-measured is "
                           "missing"]
    expected_members = sorted(list(ARTIFACT_COUNTER_MAP)
                              + ["state", "usage_report_count"])
    if sorted(measured.get("required", [])) != expected_members:
        failures.append("usage-summary.json: provider-usage-measured must "
                        f"require exactly {expected_members}")
    props = measured.get("properties", {})
    if sorted(props) != expected_members:
        failures.append("usage-summary.json: provider-usage-measured is not "
                        f"the closed shape over {expected_members}")
    for ours in ARTIFACT_COUNTER_MAP:
        if props.get(ours, {}).get("$ref") != COMMON_U63:
            failures.append(f"usage-summary.json: provider counter {ours} "
                            f"is not the shared u63")
    if "usage_source" in props:
        failures.append("usage-summary.json: the artifact's per-report "
                        "usage_source cannot ride the per-occurrence "
                        "aggregate")

    # Neither denominator can carry the other's axes. `input_tokens` and
    # `output_tokens` are deliberately shared axis names — the common
    # vocabulary of token accounting — living inside two different members;
    # the axes unique to one denominator are what must not leak into the
    # other's object.
    harness_props = set(usage_schema.get("$defs", {})
                        .get("harness-usage-measured", {})
                        .get("properties", {}))
    harness_only_axes = {"cache_read_tokens", "cache_creation",
                         "reasoning_tokens", "assistant_message_count"}
    provider_only_axes = {"total_tokens", "usage_report_count",
                          "usage_source"}
    if harness_props & provider_only_axes:
        failures.append("usage-summary.json: the harness denominator cannot "
                        "carry the provider's own axes "
                        f"{sorted(harness_props & provider_only_axes)}")
    if set(props) & harness_only_axes:
        failures.append("usage-summary.json: the provider denominator cannot "
                        "carry the harness's axes "
                        f"{sorted(set(props) & harness_only_axes)}")

    # The artifact's own counter names are reserved at the summary root.
    reserved = usage_schema.get("x-archivist", {}).get("reservedFields", [])
    for theirs in ARTIFACT_COUNTER_MAP.values():
        if theirs not in reserved:
            failures.append(f"usage-summary.json: the artifact counter name "
                            f"{theirs} must be reserved at the root")

    # The refusal side is a closed two-member object over a closed reason
    # set — its own coverage state, not the harness's.
    refusal = usage_schema.get("$defs", {}).get("provider-usage-unknown", {})
    if sorted(refusal.get("required", [])) != ["reason", "state"] \
            or refusal.get("properties", {}).get("reason", {}) \
            .get("enum") != list(PROVIDER_UNKNOWN_REASONS):
        failures.append("usage-summary.json: provider-usage-unknown must be "
                        "the closed refusal over "
                        f"{list(PROVIDER_UNKNOWN_REASONS)}")
    return failures


def build_manifest(files: dict[str, bytes],
                   identities: dict[str, dict],
                   records: dict[str, dict]) -> dict:
    schema = json.loads(USAGE_SCHEMA.read_text(encoding="utf-8"))
    reserved_count = len(schema["x-archivist"]["reservedFields"])
    members = schema_member_names()

    def state_of(path: str, member: str) -> str | None:
        usage = records[path].get(member)
        return usage["state"] if isinstance(usage, dict) else None

    harness_states = {path: state_of(path, "harness_usage")
                      for path in RECORD_PATHS}
    provider_states = {path: state_of(path, "provider_usage")
                       for path in RECORD_PATHS}
    denominators = {
        "both_measured_rows": sum(
            1 for path in RECORD_PATHS
            if harness_states[path] == "measured"
            and provider_states[path] == "measured"),
        "harness_only_rows": sum(
            1 for path in RECORD_PATHS
            if harness_states[path] == "measured"
            and provider_states[path] != "measured"),
        "provider_only_rows": sum(
            1 for path in RECORD_PATHS
            if harness_states[path] != "measured"
            and provider_states[path] == "measured"),
        "neither_measured_rows": sum(
            1 for path in RECORD_PATHS
            if harness_states[path] != "measured"
            and provider_states[path] != "measured"),
        "provider_unknown_rows": sum(
            1 for path in RECORD_PATHS
            if provider_states[path] == "unknown"),
        "provider_member_absent_rows": sum(
            1 for path in RECORD_PATHS if provider_states[path] is None),
    }
    denominators["meaning"] = (
        "the both/either/neither matrix of the plan's separate-columns "
        "rule, pinned by count over the committed records: the two "
        "denominators are separate members with separate coverage states, "
        "a row may carry both, either, or neither, and no member anywhere "
        "sums them into one number"
    )

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
        {
            "id": "provider-observed",
            "record": PATH_PROVIDER_OBSERVED,
            "asserts": [
                "both denominators measured on one row: the harness-reported counts and the provider-observed counts sit in two separate members with two separate coverage states, and neither is expressed inside the other",
                "the provider member carries the exact-inference artifact schema's bounded intersection — input, output, and the provider's own total retained as reported and summed over three reconciled usage reports, never recomputed and never summed with the harness counts",
                "the provider counts differ from the harness counts and nothing reconciles them: the two denominators account for the same traffic differently, and the record carries both numbers without picking one",
                "usage_report_count is the aggregate's coverage denominator, the provider-side analog of assistant_message_count — the artifact's per-report usage_source deliberately does not appear, because a per-occurrence aggregate has no single source",
            ],
        },
        {
            "id": "provider-only",
            "record": PATH_PROVIDER_ONLY,
            "asserts": [
                "a row carrying only the provider denominator validates: the source omitted usage entirely, so harness_usage is the bounded unknown/absent refusal while the routed traffic's exact counts stand in their own measured member — the 'either' of the plan's both/either/neither rule",
                "the exact denominator is complete on its own terms: one reconciled report, total exactly input plus output (plain provider arithmetic, still retained as reported rather than recomputed)",
                "the two denominators are never averaged, reconciled, or ranked: the refusal of one says nothing about the exactness of the other",
            ],
        },
        {
            "id": "provider-unreconciled",
            "record": PATH_PROVIDER_UNRECONCILED,
            "asserts": [
                "covered traffic without an exact count: capture material reconciles to the occurrence but contains no usage artifact, so the provider denominator is its own unknown/unreconciled state — never zero, and never silence",
                "the member's presence is load-bearing: an unknown provider denominator is distinct from the member's absence (outside capture coverage), so the row does not read as uncovered",
                "the only difference from provider-observed is the provider member's state — the two denominators vary independently, each with its own coverage state",
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
            "exact_inference_reconciliation":
                "schemas/v1/inference-artifact.json (the provider-observed "
                "counters' own definition; checked by usagegen --verify)",
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
            "material, raw object paths, wall-clock and run identity, the "
            "grand-total tokens, and the exact-inference artifact's own "
            "usage-counter names — into a valid record and proves the "
            "schema rejects it. The identity and count grammars are "
            "bounded tokens and integers that cannot carry prose, so the "
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
                "measured and unknown, both ephemeral classes, both "
                "denominators — appears in at least one committed record: "
                "the bundle round-trips the whole shape, and the optional "
                "members are exercised in both states, present and "
                "omitted-never-null"
            ),
            "unknown_is_never_zero": (
                "the records whose harness denominator is unknown carry no "
                "harness count member at all, the provider-unknown record "
                "carries no provider count either, and the one-row-per-"
                "occurrence catalog would hold exactly one of these "
                "alternative rebuild outcomes per cited occurrence"
            ),
            "denominators": denominators,
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
    provider_observed, identity_provider_observed = build_provider_observed()
    provider_only, identity_provider_only = build_provider_only()
    provider_unreconciled, identity_unreconciled = \
        build_provider_unreconciled()
    identities = {
        PATH_FULL: identity_full,
        PATH_ZERO: identity_zero,
        PATH_ABSENT: identity_absent,
        PATH_MALFORMED: identity_malformed,
        PATH_UNSUPPORTED: identity_unsupported,
        PATH_PROVIDER_OBSERVED: identity_provider_observed,
        PATH_PROVIDER_ONLY: identity_provider_only,
        PATH_PROVIDER_UNRECONCILED: identity_unreconciled,
    }
    records = {
        PATH_FULL: full,
        PATH_ZERO: zero,
        PATH_ABSENT: absent,
        PATH_MALFORMED: malformed,
        PATH_UNSUPPORTED: unsupported,
        PATH_PROVIDER_OBSERVED: provider_observed,
        PATH_PROVIDER_ONLY: provider_only,
        PATH_PROVIDER_UNRECONCILED: provider_unreconciled,
    }
    files = {
        path: provenancegen.file_bytes(record)
        for path, record in records.items()
    }
    files["manifest.json"] = provenancegen.file_bytes(
        build_manifest(files, identities, records))
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

    # The provider-observed denominator's own contract — never the
    # harness's: absent means outside capture coverage; present means its
    # own two-state discipline over its own members.
    provider = record.get("provider_usage")
    if provider is not None and not isinstance(provider, dict):
        failures.append(f"{path}: provider_usage must be an object when "
                        f"present, never a bare sum")
        provider = None
    if provider is not None:
        if provider.get("state") == "measured":
            expected = {"state", "input_tokens", "output_tokens",
                        "total_tokens", "usage_report_count"}
            if set(provider) != expected:
                failures.append(f"{path}: measured provider usage must "
                                f"carry every counter member exactly "
                                f"(has {sorted(provider)})")
            for member in ("input_tokens", "output_tokens", "total_tokens",
                           "usage_report_count"):
                value = provider.get(member)
                if not isinstance(value, int) or isinstance(value, bool) \
                        or value < 0:
                    failures.append(f"{path}: provider_usage.{member} must "
                                    f"be a non-negative integer")
            if provider.get("usage_report_count", 0) < 1:
                failures.append(f"{path}: measured provider usage must sum "
                                f"at least one usage report")
        elif provider.get("state") == "unknown":
            if set(provider) != {"state", "reason"}:
                failures.append(f"{path}: an unknown provider usage carries "
                                f"no count member at all "
                                f"(has {sorted(provider)})")
            if provider.get("reason") not in PROVIDER_UNKNOWN_REASONS:
                failures.append(f"{path}: provider unknown reason must be "
                                f"from the closed v1 set "
                                f"{list(PROVIDER_UNKNOWN_REASONS)}")
        else:
            failures.append(f"{path}: provider_usage must be measured or "
                            f"unknown, never {provider.get('state')!r}")

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

    # The two-denominator boundary: the provider counts cannot be expressed
    # inside the harness member, the harness axes cannot ride the provider
    # member, the artifact's own counter names cannot be hoisted to the
    # root (they are reserved there), and the two denominators cannot be
    # summed into one number or one member.
    both_record = build_provider_observed()[0]
    provider_in_harness = json.loads(json.dumps(measured_record))
    provider_in_harness["harness_usage"]["total_tokens"] = 5095
    provider_in_harness["harness_usage"]["usage_source"] = "response-body"
    harness_in_provider = json.loads(json.dumps(both_record))
    harness_in_provider["provider_usage"]["cache_read_tokens"] = 15230
    provider_missing_total = json.loads(json.dumps(both_record))
    del provider_missing_total["provider_usage"]["total_tokens"]
    provider_missing_count = json.loads(json.dumps(both_record))
    del provider_missing_count["provider_usage"]["usage_report_count"]
    provider_zero_reports = json.loads(json.dumps(both_record))
    provider_zero_reports["provider_usage"]["usage_report_count"] = 0
    provider_negative = json.loads(json.dumps(both_record))
    provider_negative["provider_usage"]["input_tokens"] = -1
    provider_source_riding = json.loads(json.dumps(both_record))
    provider_source_riding["provider_usage"]["usage_source"] = "response-body"
    provider_unknown_counts = json.loads(json.dumps(both_record))
    provider_unknown_counts["provider_usage"] = {
        "state": "unknown", "reason": "unreconciled", "input_tokens": 0}
    provider_bad_reason = json.loads(json.dumps(
        build_provider_unreconciled()[0]))
    provider_bad_reason["provider_usage"]["reason"] = "nobody_knows"
    provider_bad_state = json.loads(json.dumps(both_record))
    provider_bad_state["provider_usage"]["state"] = "unsettled"
    provider_as_one_number = json.loads(json.dumps(both_record))
    provider_as_one_number["provider_usage"] = 5095

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
        ("provider counters collapsed into harness_usage",
         provider_in_harness, True),
        ("harness axes collapsed into provider_usage",
         harness_in_provider, True),
        ("provider measured missing the provider total",
         provider_missing_total, True),
        ("provider measured missing the report count",
         provider_missing_count, True),
        ("provider measured with zero reconciled reports",
         provider_zero_reports, True),
        ("provider measured with a negative count", provider_negative, True),
        ("the artifact's per-report usage_source riding the aggregate",
         provider_source_riding, True),
        ("provider unknown carrying counts", provider_unknown_counts, True),
        ("provider reason outside the closed set", provider_bad_reason, True),
        ("provider state outside the two-state contract",
         provider_bad_state, True),
        ("both denominators summed into one number",
         provider_as_one_number, True),
        ("valid control (the matrix's negative control)",
         json.loads(json.dumps(valid)), False),
        ("valid control: both denominators measured on one row",
         json.loads(json.dumps(both_record)), False),
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

    control_ran = False
    for label, mutated, must_reject in negative_cases(records[PATH_FULL]):
        rejected = bool(list(usage_validator.iter_errors(mutated)))
        if must_reject and not rejected:
            failures.append(f"negative matrix: schema ACCEPTED {label}")
        elif not must_reject:
            control_ran = True
            if rejected:
                failures.append(
                    f"negative matrix: control case was rejected ({label})")
    if not control_ran:
        failures.append("negative matrix: no valid control case ever ran")

    # The two denominators' separation is checked against the exact-inference
    # artifact schema's own definition, not a restatement.
    failures.extend(reconcile_provider_usage())

    # The manifest's denominator matrix must match the committed records:
    # both, either-only, neither — every cell populated by count.
    committed_records = {
        p: json.loads((committed / p).read_bytes())
        for p in records if p in on_disk
    }
    def committed_state(record: dict, member: str) -> str | None:
        usage = record.get(member)
        return usage["state"] if isinstance(usage, dict) else None

    matrix = {
        "both_measured_rows": sum(
            1 for r in committed_records.values()
            if committed_state(r, "harness_usage") == "measured"
            and committed_state(r, "provider_usage") == "measured"),
        "harness_only_rows": sum(
            1 for r in committed_records.values()
            if committed_state(r, "harness_usage") == "measured"
            and committed_state(r, "provider_usage") != "measured"),
        "provider_only_rows": sum(
            1 for r in committed_records.values()
            if committed_state(r, "harness_usage") != "measured"
            and committed_state(r, "provider_usage") == "measured"),
        "neither_measured_rows": sum(
            1 for r in committed_records.values()
            if committed_state(r, "harness_usage") != "measured"
            and committed_state(r, "provider_usage") != "measured"),
        "provider_unknown_rows": sum(
            1 for r in committed_records.values()
            if committed_state(r, "provider_usage") == "unknown"),
        "provider_member_absent_rows": sum(
            1 for r in committed_records.values()
            if committed_state(r, "provider_usage") is None),
    }
    pinned = {key: value for key, value in
              manifest["invariants"]["denominators"].items()
              if key != "meaning"}
    if pinned != matrix:
        failures.append(f"denominator matrix drifted from the committed "
                        f"records (manifest {pinned}, records {matrix})")
    for cell in ("both_measured_rows", "harness_only_rows",
                 "provider_only_rows", "neither_measured_rows",
                 "provider_unknown_rows"):
        if matrix[cell] < 1:
            failures.append(f"denominator matrix cell {cell} is empty — "
                            f"the corpus must pin every coverage outcome")

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
        f"digests recomputed from bundle bytes, provider-observed "
        f"denominator reconciled with the exact-inference artifact schema"
    )
    return 0


def self_test() -> int:
    """Prove the rejection paths without the committed bundle: the digest
    construction pins its domain label, preimage rule, and object-key
    layout; the per-record invariants reject every fault class; the write
    guard refuses a foreign directory and rewrites its own bundle
    byte-identically; and the schema rejects the full negative matrix
    while the valid control stays valid."""
    checks: list[tuple[str, bool]] = []

    def check(name: str, condition: bool) -> None:
        checks.append((name, condition))

    # --- the digest construction ---------------------------------------
    full, _ = build_full_coverage()
    body = {k: v for k, v in full.items() if k != "usage_summary_digest"}
    stored = full["usage_summary_digest"]
    canonical = provenancegen.canonical_json(body).encode("utf-8")
    check("digest recomputes from the record's own canonical bytes",
          usage_digest(body) == stored)
    check("the digest member is excluded from its own preimage",
          usage_digest(full) != stored)
    tampered = json.loads(json.dumps(body))
    tampered["harness_usage"]["input_tokens"] += 1
    check("a tampered record digests differently",
          usage_digest(tampered) != stored)
    check("the domain label is pinned",
          provenancegen.derive("usage-summary-v0", canonical) != stored)

    # The derived object key: pinned prefix, the digest's own shard, the
    # digest as the object name — re-derivable from the stored record.
    key = usage_object_key(stored)
    common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
    pattern = re.compile(
        common["$defs"]["usage-summary-object-key"]["pattern"])
    check("object key matches the common.json pattern",
          bool(pattern.fullmatch(key)))
    check("the key shard is the digest's first two hex",
          key.rsplit("/", 2)[1] == stored[:2])
    check("a foreign pipeline misses the key pattern",
          not pattern.fullmatch(
              key.replace("/derived/usage/1/", "/derived/other/1/")))
    check("a non-hex shard misses the key pattern",
          not pattern.fullmatch(key.replace(f"/{stored[:2]}/", "/zz/", 1)))
    check("a digest change moves the object key",
          usage_object_key("ff" + stored[2:]) != key)

    # --- the per-record invariants -------------------------------------
    def record_failure(record: dict) -> str | None:
        found: list[str] = []
        verify_record("self-test", record, found)
        return found[0] if found else None

    check("a valid record passes the per-record invariants",
          record_failure(full) is None)
    absent = build_usage_absent()[0]
    unknown_counts = json.loads(json.dumps(absent))
    unknown_counts["harness_usage"]["input_tokens"] = 0
    unknown_reason = json.loads(json.dumps(absent))
    unknown_reason["harness_usage"]["reason"] = "nobody_knows"
    zero_messages = json.loads(json.dumps(full))
    zero_messages["harness_usage"]["assistant_message_count"] = 0
    negative_count = json.loads(json.dumps(full))
    negative_count["harness_usage"]["input_tokens"] = -1
    float_count = json.loads(json.dumps(full))
    float_count["harness_usage"]["input_tokens"] = 1.5
    extra_class = json.loads(json.dumps(full))
    extra_class["harness_usage"]["cache_creation"]["ephemeral_15m"] = 5
    faults = [
        ("tampered digest member", dict(full, usage_summary_digest="0" * 64)),
        ("null where a member is omitted", dict(full, model_id=None)),
        ("an unknown state carrying counts", unknown_counts),
        ("an unknown reason outside the closed set", unknown_reason),
        ("a wrong pipeline_id", dict(full, pipeline_id="not-a-pipeline")),
        ("a wrong adapter projection",
         dict(full, adapter_projection_version="2")),
        ("an occurrence the bundle cannot vouch for",
         dict(full, occurrence_id="0" * 64)),
        ("measured with zero summed messages", zero_messages),
        ("measured with a negative count", negative_count),
        ("measured with a fractional count", float_count),
        ("measured with an extra ephemeral class", extra_class),
    ]
    for name, mutated in faults:
        check(f"invariants reject: {name}",
              record_failure(mutated) is not None)

    # --- the provider-observed denominator's own contract --------------
    both, _ = build_provider_observed()
    provider_only, _ = build_provider_only()
    unreconciled, _ = build_provider_unreconciled()
    check("a row carrying both denominators passes the invariants",
          record_failure(both) is None)
    check("a row carrying only the provider denominator passes",
          record_failure(provider_only) is None)
    check("an unreconciled provider denominator passes",
          record_failure(unreconciled) is None)
    provider_zero_reports = json.loads(json.dumps(both))
    provider_zero_reports["provider_usage"]["usage_report_count"] = 0
    provider_unknown_with_counts = json.loads(json.dumps(unreconciled))
    provider_unknown_with_counts["provider_usage"]["input_tokens"] = 0
    provider_bad_reason = json.loads(json.dumps(unreconciled))
    provider_bad_reason["provider_usage"]["reason"] = "nobody_knows"
    provider_one_number = json.loads(json.dumps(both))
    provider_one_number["provider_usage"] = 5095
    provider_faults = [
        ("measured provider usage with zero reconciled reports",
         provider_zero_reports),
        ("an unknown provider state carrying counts",
         provider_unknown_with_counts),
        ("a provider reason outside the closed set", provider_bad_reason),
        ("the provider denominator summed into one number",
         provider_one_number),
    ]
    for name, mutated in provider_faults:
        check(f"invariants reject: {name}",
              record_failure(mutated) is not None)

    # --- reconciliation with the exact-inference artifact schema -------
    recon = reconcile_provider_usage()
    for failure in recon:
        print(f"  reconciliation: {failure}")
    check("provider_usage reconciles with the exact-inference usage kind",
          not recon)
    artifact_mutated = json.loads(
        INFERENCE_SCHEMA.read_text(encoding="utf-8"))
    artifact_usage_branch(artifact_mutated)["properties"]["metadata"][
        "required"].remove("usage_total_tokens")
    check("reconciliation catches artifact-side drift",
          reconcile_provider_usage(artifact=artifact_mutated) != [])
    summary_mutated = json.loads(USAGE_SCHEMA.read_text(encoding="utf-8"))
    summary_mutated["$defs"]["provider-usage-measured"]["properties"][
        "cache_read_tokens"] = {"$ref": COMMON_U63}
    check("reconciliation catches summary-side drift",
          reconcile_provider_usage(usage_schema=summary_mutated) != [])

    # --- the write guard -------------------------------------------------
    # write_bundle narrates each write; the self-test's scratch paths are
    # noise in the gate log, so the writes run quiet and only the proofs
    # speak.
    files = build_bundle()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "bundle"
        with contextlib.redirect_stdout(io.StringIO()):
            write_bundle(out, files)
            check("--generate writes every file byte-identically",
                  all((out / path).read_bytes() == data
                      for path, data in files.items()))
            try:
                write_bundle(out, files)
                rewritten = True
            except SystemExit:
                rewritten = False
        check("rewriting its own bundle is allowed", rewritten)
        foreign = Path(tmp) / "foreign"
        foreign.mkdir()
        (foreign / "unrelated.txt").write_bytes(b"not a bundle\n")
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                write_bundle(foreign, files)
            refused = False
        except SystemExit:
            refused = True
        check("the write guard refuses a foreign directory", refused)

    # --- the schema's rejection paths -----------------------------------
    make_validator = load_jsonschema()
    if make_validator is None:
        print("jsonschema is not installed: self-test cannot run",
              file=sys.stderr)
        return 4
    _, usage_validator = make_validator(USAGE_SCHEMA)
    reserved = json.loads(
        USAGE_SCHEMA.read_text(encoding="utf-8")
    )["x-archivist"]["reservedFields"]
    matrix = negative_cases(full)
    injected = [case for case in matrix
                if case[2] and case[0].startswith("forbidden member: ")]
    check("the matrix injects every reserved name",
          len(injected) == len(reserved))
    escaped = [case[0] for case in matrix
               if case[2]
               and not list(usage_validator.iter_errors(case[1]))]
    check("the schema rejects every negative case", not escaped)
    controls = [mutated for _, mutated, must_reject in matrix
                if not must_reject]
    check("every valid control stays valid (one member and both)",
          bool(controls) and all(
              not bool(list(usage_validator.iter_errors(control)))
              for control in controls))

    # The member-exercise helpers the manifest's invariant counts lean on.
    check("the schema scan covers the digest member",
          "usage_summary_digest" in schema_member_names())
    check("the record scan walks nested members",
          record_member_names({"a": {"b": [1]}}) == {"a", "b"})

    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if failed:
        print(f"self-test FAILED ({len(failed)})", file=sys.stderr)
        return 3
    print(f"self-test passed: {len(checks)} checks")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify", action="store_true",
                       help="regenerate and byte-compare the committed "
                            "bundle, validate instances and the negative "
                            "matrix, pin the two-denominator coverage "
                            "matrix, and reconcile the reserved provider "
                            "member with the exact-inference artifact "
                            "schema")
    modes.add_argument("--generate", metavar="OUTPUT", nargs="?",
                       const=str(DEFAULT_OUTPUT),
                       help="write the bundle (default: the committed "
                            "location)")
    modes.add_argument("--self-test", action="store_true",
                       help="prove the rejection paths")
    args = parser.parse_args(argv)

    if args.generate is not None:
        write_bundle(Path(args.generate), build_bundle())
        return 0
    if args.self_test:
        return self_test()
    return verify_bundle()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
