#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Zero-entropy generator for the exact-inference example bundle.

The bundle under schemas/v1/examples/inference/ is the golden-vector table
for the exact-inference artifact family (docs/notes/exact-inference-schemas.md,
schemas/v1/inference-artifact.json): one file per artifact record, covering
the plan Phase 9 artifact kinds — provider request, provider response,
streaming event, retry, usage, transport error — across three scenarios
(single attempt, retried attempt, streamed attempt).

Every identifier, timestamp, and payload byte is a pinned synthetic constant
(SEC-010); no real session, host, account, path, provider, or transcript data
appears. Payload digests are the plain SHA-256 of the pinned bytes — the one
label-less digest — so the bundle doubles as the correlation-rule proof: the
digest covers the captured bytes and nothing else, and no correlation
identifier (`trace_id`, `inference_request_id`, `provider_attempt_id`) is an
input to any digest in this family.

--verify proves the family's acceptance, not just its bytes: every committed
artifact re-validates against the schema, the reserved-name matrix (the
authorization, cookie, provider-credential, TLS/TCP-framing, and
storage-location names the schema rejects) is injected one name at a time and
must be rejected, the closed `metadata` allowlist must reject representative
unlisted names, the per-kind required-member rules must reject their missing
members, and the ordering invariants (dense stream ordinals reconstructing the
decoded body, strictly increasing retry chains, usage counters matching the
reporting bytes) are recomputed from the pinned bytes themselves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenancegen  # noqa: E402  (canonical bytes + plain blob digest)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "schemas" / "v1" / "examples" / "inference"
COMMON_SCHEMA = REPO_ROOT / "schemas" / "v1" / "common.json"
ARTIFACT_SCHEMA = REPO_ROOT / "schemas" / "v1" / "inference-artifact.json"

BUNDLE_SCHEMA = "archivist.inference-examples/v1"

# --- pinned synthetic identifiers (SEC-010: closed vocabulary, zero entropy) --

TENANT_ID = "00000000-0000-4000-8000-000000000001"
ORIGIN_CLIENT_ID = "00000000-0000-4000-8000-000000000002"

TRACE_SINGLE = "00000000-0000-7000-8000-000000000003"
TRACE_RETRIED = "00000000-0000-7000-8000-000000000004"
TRACE_STREAMED = "00000000-0000-7000-8000-000000000005"

INFERENCE_SINGLE = "00000000-0000-7000-8000-000000000010"
INFERENCE_RETRIED = "00000000-0000-7000-8000-000000000020"
INFERENCE_STREAMED = "00000000-0000-7000-8000-000000000030"

ATTEMPT_SINGLE = "00000000-0000-7000-8000-000000000101"
ATTEMPT_RETRIED_0 = "00000000-0000-7000-8000-000000000201"
ATTEMPT_RETRIED_1 = "00000000-0000-7000-8000-000000000202"
ATTEMPT_RETRIED_2 = "00000000-0000-7000-8000-000000000203"
ATTEMPT_STREAMED = "00000000-0000-7000-8000-000000000301"

CAPTURE_T0 = "2026-09-12T16:44:05Z"
CAPTURE_T1 = "2026-09-12T16:44:06Z"
CAPTURE_T2 = "2026-09-12T16:44:27Z"
CAPTURE_T3 = "2026-09-12T16:44:28Z"
CAPTURE_T4 = "2026-09-12T16:44:29Z"
CAPTURE_T5 = "2026-09-12T16:45:01Z"

# --- pinned synthetic payload bytes (the captured, transfer-decoded content) --

REQUEST_BODY = (
    b'{"model":"synthetic-model","messages":'
    b'[{"role":"user","content":"synthetic prompt text"}]}'
)
RESPONSE_BODY = (
    b'{"id":"synthetic-response-1","model":"synthetic-model",'
    b'"choices":[{"finish_reason":"stop","index":0}],'
    b'"usage":{"input_tokens":3,"output_tokens":5,"total_tokens":8}}'
)
RATE_LIMIT_BODY = (
    b'{"error":{"message":"synthetic rate limit reached",'
    b'"type":"rate_limit_error"}}'
)
# The streamed attempt's decoded body is exactly its three decoded events,
# concatenated in ordinal order — the reconstruction invariant --verify pins.
STREAM_EVENT_0 = b'{"choices":[{"delta":{"content":"synthetic "}}]}\n'
STREAM_EVENT_1 = b'{"choices":[{"delta":{"content":"response"}}]}\n'
STREAM_EVENT_2 = (
    b'{"choices":[{"delta":{},"finish_reason":"stop"}],'
    b'"usage":{"input_tokens":3,"output_tokens":5,"total_tokens":8}}\n'
)
STREAM_BODY = STREAM_EVENT_0 + STREAM_EVENT_1 + STREAM_EVENT_2

USAGE_INPUT, USAGE_OUTPUT, USAGE_TOTAL = 3, 5, 8

# --- bundle layout -----------------------------------------------------------

PATH_REQUEST = "single-attempt/request.json"
PATH_RESPONSE = "single-attempt/response.json"
PATH_USAGE = "single-attempt/usage.json"
PATH_RETRY_0_RESPONSE = "retried-attempt/attempt-0-response-429.json"
PATH_RETRY_0_RETRY = "retried-attempt/attempt-0-retry.json"
PATH_RETRY_1_ERROR = "retried-attempt/attempt-1-transport-error.json"
PATH_RETRY_1_RETRY = "retried-attempt/attempt-1-retry.json"
PATH_RETRY_2_REQUEST = "retried-attempt/attempt-2-request.json"
PATH_RETRY_2_RESPONSE = "retried-attempt/attempt-2-response.json"
PATH_STREAM_EVENT_0 = "streamed-attempt/event-0.json"
PATH_STREAM_EVENT_1 = "streamed-attempt/event-1.json"
PATH_STREAM_EVENT_2 = "streamed-attempt/event-2.json"
PATH_STREAM_USAGE = "streamed-attempt/usage.json"
PATH_MANIFEST = "manifest.json"

STREAM_PATHS = (PATH_STREAM_EVENT_0, PATH_STREAM_EVENT_1, PATH_STREAM_EVENT_2)
STREAM_PAYLOADS = (STREAM_EVENT_0, STREAM_EVENT_1, STREAM_EVENT_2)


def artifact(
    kind: str,
    trace_id: str,
    inference_request_id: str,
    provider_attempt_id: str,
    attempt_ordinal: int,
    *,
    capture_time: str | None = None,
    payload: bytes | None = None,
    metadata: dict | None = None,
    **kind_fields: object,
) -> dict:
    """Build one artifact record. Correlation fields are members only —
    nothing derived from them enters any digest."""
    record: dict = {
        "artifact_kind": kind,
        "attempt_ordinal": attempt_ordinal,
        "inference_artifact_version": 1,
        "inference_request_id": inference_request_id,
        "origin_client_id": ORIGIN_CLIENT_ID,
        "provider_attempt_id": provider_attempt_id,
        "tenant_id": TENANT_ID,
        "trace_id": trace_id,
    }
    if capture_time is not None:
        record["capture_time"] = capture_time
    if payload is not None:
        record["payload"] = {
            "payload_digest": provenancegen.blob_digest(payload),
            "payload_size": len(payload),
        }
    if metadata:
        record["metadata"] = dict(metadata)
    record.update(kind_fields)
    return record


def build_records() -> dict[str, dict]:
    """Every artifact record of the bundle, keyed by bundle path."""
    rate_limit_seen = {
        "rate_limit_limit": 60,
        "rate_limit_remaining": 59,
        "rate_limit_reset": 1,
    }
    records: dict[str, dict] = {}

    # Scenario 1 — single attempt: one request, one response, one usage
    # report extracted from the response body.
    records[PATH_REQUEST] = artifact(
        "provider-request", TRACE_SINGLE, INFERENCE_SINGLE, ATTEMPT_SINGLE, 0,
        capture_time=CAPTURE_T0, payload=REQUEST_BODY,
        metadata={"content_type": "application/json"},
    )
    records[PATH_RESPONSE] = artifact(
        "provider-response", TRACE_SINGLE, INFERENCE_SINGLE, ATTEMPT_SINGLE, 0,
        capture_time=CAPTURE_T1, payload=RESPONSE_BODY,
        metadata={
            "content_type": "application/json",
            "provider_request_id": "synthetic-provider-request-1",
            "http_status": 200,
            **rate_limit_seen,
        },
    )
    records[PATH_USAGE] = artifact(
        "usage", TRACE_SINGLE, INFERENCE_SINGLE, ATTEMPT_SINGLE, 0,
        capture_time=CAPTURE_T1, usage_source="response-body",
        metadata={
            "usage_input_tokens": USAGE_INPUT,
            "usage_output_tokens": USAGE_OUTPUT,
            "usage_total_tokens": USAGE_TOTAL,
        },
    )

    # Scenario 2 — retried inference: a rate-limited response, a retry, a
    # transport error, a second retry, then the succeeded attempt. The
    # retried request reuses the single attempt's exact bytes: identical
    # payload bytes carry one identical content digest.
    records[PATH_RETRY_0_RESPONSE] = artifact(
        "provider-response", TRACE_RETRIED, INFERENCE_RETRIED, ATTEMPT_RETRIED_0, 0,
        capture_time=CAPTURE_T0, payload=RATE_LIMIT_BODY,
        metadata={
            "content_type": "application/json",
            "provider_request_id": "synthetic-provider-request-2a",
            "http_status": 429,
            "rate_limit_limit": 60,
            "rate_limit_remaining": 0,
            "rate_limit_reset": 20,
        },
    )
    records[PATH_RETRY_0_RETRY] = artifact(
        "retry", TRACE_RETRIED, INFERENCE_RETRIED, ATTEMPT_RETRIED_1, 1,
        capture_time=CAPTURE_T2,
        retry_of_attempt_ordinal=0, retry_reason="rate-limit",
        backoff_ms=20000,
    )
    records[PATH_RETRY_1_ERROR] = artifact(
        "transport-error", TRACE_RETRIED, INFERENCE_RETRIED, ATTEMPT_RETRIED_1, 1,
        error_class="connect",
    )
    records[PATH_RETRY_1_RETRY] = artifact(
        "retry", TRACE_RETRIED, INFERENCE_RETRIED, ATTEMPT_RETRIED_2, 2,
        capture_time=CAPTURE_T3,
        retry_of_attempt_ordinal=1, retry_reason="transport-error",
        backoff_ms=250,
    )
    records[PATH_RETRY_2_REQUEST] = artifact(
        "provider-request", TRACE_RETRIED, INFERENCE_RETRIED, ATTEMPT_RETRIED_2, 2,
        capture_time=CAPTURE_T3, payload=REQUEST_BODY,
        metadata={"content_type": "application/json"},
    )
    records[PATH_RETRY_2_RESPONSE] = artifact(
        "provider-response", TRACE_RETRIED, INFERENCE_RETRIED, ATTEMPT_RETRIED_2, 2,
        capture_time=CAPTURE_T4, payload=RESPONSE_BODY,
        metadata={
            "content_type": "application/json",
            "provider_request_id": "synthetic-provider-request-2c",
            "http_status": 200,
            **rate_limit_seen,
        },
    )

    # Scenario 3 — streamed attempt: three ordered decoded events whose
    # concatenation is the attempt's decoded body, and the usage report
    # extracted from the terminal event (payload digest names the event).
    for ordinal, (path, event) in enumerate(zip(STREAM_PATHS, STREAM_PAYLOADS)):
        record = artifact(
            "streaming-event", TRACE_STREAMED, INFERENCE_STREAMED,
            ATTEMPT_STREAMED, 0,
            capture_time=CAPTURE_T5, payload=event, event_ordinal=ordinal,
        )
        if ordinal == 0:
            record["metadata"] = {"content_type": "text/event-stream"}
        records[path] = record
    records[PATH_STREAM_USAGE] = artifact(
        "usage", TRACE_STREAMED, INFERENCE_STREAMED, ATTEMPT_STREAMED, 0,
        capture_time=CAPTURE_T5, payload=STREAM_EVENT_2,
        usage_source="stream-event",
        metadata={
            "usage_input_tokens": USAGE_INPUT,
            "usage_output_tokens": USAGE_OUTPUT,
            "usage_total_tokens": USAGE_TOTAL,
        },
    )
    return records


def build_files() -> dict[str, bytes]:
    """The bundle's artifact files, canonical bytes plus one trailing LF."""
    return {
        path: provenancegen.file_bytes(record)
        for path, record in build_records().items()
    }


def build_manifest(files: dict[str, bytes]) -> bytes:
    schema = json.loads(ARTIFACT_SCHEMA.read_text(encoding="utf-8"))
    entries = []
    for path in sorted(files):
        record = json.loads(files[path])
        entries.append({
            "artifact_kind": record["artifact_kind"],
            "inference_request_id": record["inference_request_id"],
            "path": path,
            "provider_attempt_id": record["provider_attempt_id"],
            "sha256": hashlib.sha256(files[path]).hexdigest(),
        })
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "generated_by": "tools/inferencegen.py",
        "files": entries,
        "invariants": {
            "reserved_fields_rejected": len(schema["x-archivist"]["reservedFields"]),
            "metadata_allowlist_entries": len(
                schema["properties"]["metadata"]["properties"]),
            "payload_digest_reused": sorted({
                provenancegen.blob_digest(REQUEST_BODY),
            } & {
                record["payload"]["payload_digest"]
                for record in build_records().values()
                if "payload" in record
            }),
            "reconstruction": {
                "retried-attempt": (
                    "attempt ordinals 0,1,2 with two retry records; each "
                    "retry_of_attempt_ordinal names the attempt it follows"),
                "streamed-attempt": (
                    "events 0..2 by event_ordinal concatenate to the "
                    "attempt's decoded body"),
            },
        },
    }
    return provenancegen.file_bytes(manifest)


# --- generate / verify -------------------------------------------------------


def write_bundle(output: Path, files: dict[str, bytes]) -> None:
    marker = output / "manifest.json"
    if output.exists() and not (
        marker.exists()
        and json.loads(marker.read_text(encoding="utf-8")).get("schema") == BUNDLE_SCHEMA
    ):
        raise SystemExit(
            f"refusing to write into {output}: not a {BUNDLE_SCHEMA} bundle "
            "(pass an empty or nonexistent directory)"
        )
    for path, data in sorted(files.items()):
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (output / PATH_MANIFEST).write_bytes(build_manifest(files))
    print(f"wrote {len(files) + 1} files to {output}")


def load_validator():
    try:
        import jsonschema
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
    except ImportError:
        return None
    schema = json.loads(ARTIFACT_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
    registry = Registry().with_resource(
        "urn:agent-archivist:schema:v1:common",
        Resource.from_contents(common, default_specification=DRAFT202012),
    )
    return jsonschema.Draft202012Validator(schema, registry=registry), schema


def verify_payloads(records: dict[str, dict], failures: list[str]) -> None:
    """Content invariants, recomputed from the pinned bytes: digests are the
    plain content digest, stream order reconstructs the body, retry chains
    order, usage counters match the reporting bytes."""
    pinned = {
        PATH_REQUEST: REQUEST_BODY,
        PATH_RESPONSE: RESPONSE_BODY,
        PATH_RETRY_0_RESPONSE: RATE_LIMIT_BODY,
        PATH_RETRY_2_REQUEST: REQUEST_BODY,
        PATH_RETRY_2_RESPONSE: RESPONSE_BODY,
        PATH_STREAM_EVENT_0: STREAM_EVENT_0,
        PATH_STREAM_EVENT_1: STREAM_EVENT_1,
        PATH_STREAM_EVENT_2: STREAM_EVENT_2,
        PATH_STREAM_USAGE: STREAM_EVENT_2,
    }
    for path, payload in pinned.items():
        record = records[path]
        digest = record["payload"]["payload_digest"]
        if digest != hashlib.sha256(payload).hexdigest():
            failures.append(
                f"{path}: payload_digest is not the plain SHA-256 of the "
                f"pinned captured bytes — the digest must stay the one "
                f"label-less content digest, with no correlation field in it")
        if record["payload"]["payload_size"] != len(payload):
            failures.append(f"{path}: payload_size disagrees with the bytes")

    by_inference: dict[str, list[dict]] = {}
    for record in records.values():
        by_inference.setdefault(record["inference_request_id"], []).append(record)
    for inference_id, members in sorted(by_inference.items()):
        attempt_to_ordinal: dict[str, int] = {}
        for record in members:
            seen = attempt_to_ordinal.setdefault(
                record["provider_attempt_id"], record["attempt_ordinal"])
            if seen != record["attempt_ordinal"]:
                failures.append(
                    f"{inference_id}: attempt {record['provider_attempt_id']} "
                    f"carries two attempt ordinals ({seen}, "
                    f"{record['attempt_ordinal']})")
        ordinals = set(attempt_to_ordinal.values())
        for retry in (r for r in members if r["artifact_kind"] == "retry"):
            prior = retry["retry_of_attempt_ordinal"]
            if prior >= retry["attempt_ordinal"]:
                failures.append(
                    f"{inference_id}: retry_of_attempt_ordinal {prior} must "
                    f"be strictly below the retry's own attempt ordinal "
                    f"{retry['attempt_ordinal']}")
            if prior not in ordinals:
                failures.append(
                    f"{inference_id}: retry cites attempt ordinal {prior} "
                    f"with no artifacts in the inference")

    events = [records[path] for path in STREAM_PATHS]
    if [r["event_ordinal"] for r in events] != [0, 1, 2]:
        failures.append("streamed-attempt: event ordinals must be dense from zero")
    if b"".join(STREAM_PAYLOADS) != STREAM_BODY:
        failures.append(
            "streamed-attempt: event bytes in ordinal order must reconstruct "
            "the attempt's decoded body")
    usage = records[PATH_STREAM_USAGE]
    if usage["payload"]["payload_digest"] != events[-1]["payload"]["payload_digest"]:
        failures.append(
            "streamed-attempt: usage payload digest must name the reporting "
            "event's own digest")

    for path in (PATH_USAGE, PATH_STREAM_USAGE):
        got = records[path]["metadata"]
        if (got["usage_input_tokens"], got["usage_output_tokens"],
                got["usage_total_tokens"]) != (USAGE_INPUT, USAGE_OUTPUT,
                                               USAGE_TOTAL):
            failures.append(
                f"{path}: usage counters drifted from the pinned reporting "
                f"bytes")
        if (got["usage_input_tokens"] + got["usage_output_tokens"]
                != got["usage_total_tokens"]):
            failures.append(f"{path}: usage counters must satisfy the "
                            f"producer invariant total = input + output")


def negative_cases(valid: dict, schema: dict) -> list[tuple[str, dict, bool]]:
    """(label, mutated record, must_be_rejected). The reserved list is read
    from the schema itself so the matrix can never drift from it; the
    metadata closure cases prove unlisted names — innocuous ones included —
    are rejected outright by the closed allowlist."""
    cases: list[tuple[str, dict, bool]] = [
        ("valid control (the matrix's negative control)",
         json.loads(json.dumps(valid)), False),
    ]
    for name in sorted(schema["x-archivist"]["reservedFields"]):
        mutated = dict(valid)
        mutated[name] = "synthetic-" + name
        cases.append((f"reserved member: {name}", mutated, True))
    allowlisted = set(schema["properties"]["metadata"]["properties"])
    for name in ("authorization", "cookie", "set_cookie", "api_key",
                 "x_api_key", "bearer_token", "model", "url", "tls_version",
                 "blob_key", "user_agent", "date"):
        if name in allowlisted:
            cases.append((f"unlisted metadata member: {name} (in allowlist!)",
                          dict(valid), False))
            continue
        mutated = json.loads(json.dumps(valid))
        mutated.setdefault("metadata", {})[name] = "synthetic"
        cases.append((f"unlisted metadata member: {name}", mutated, True))
    cases.extend([
        ("unknown artifact_kind", dict(valid, artifact_kind="provider-headers"), True),
        ("inference_artifact_version 2",
         dict(valid, inference_artifact_version=2), True),
        ("missing correlation: trace_id",
         {k: v for k, v in valid.items() if k != "trace_id"}, True),
        ("provider-request without payload",
         {k: v for k, v in valid.items() if k != "payload"}, True),
        ("payload without digest",
         dict(valid, payload={"payload_size": 1}), True),
        ("payload with zero size",
         dict(valid, payload={"payload_digest": "0" * 64, "payload_size": 0}),
         True),
        ("kind-gated member on the wrong kind: usage_source on a request",
         dict(valid, usage_source="response-body"), True),
        ("kind-gated member on the wrong kind: error_class on a response",
         dict(valid, artifact_kind="provider-response", payload=valid["payload"],
              error_class="connect"), True),
        ("kind-gated member on the wrong kind: backoff_ms on a request",
         dict(valid, backoff_ms=250), True),
    ])
    return cases


def kind_negative_cases(valid_by_kind: dict[str, dict]) -> list[tuple[str, dict, bool]]:
    """Per-kind negatives: each kind's remaining required members and its
    closed enums, proven against that kind's own valid control."""

    def drop(record: dict, *names: str) -> dict:
        return {k: v for k, v in record.items() if k not in names}

    cases: list[tuple[str, dict, bool]] = []
    stream = valid_by_kind["streaming-event"]
    cases.append(("streaming-event without event_ordinal",
                  drop(stream, "event_ordinal"), True))
    retry = valid_by_kind["retry"]
    cases.append(("retry without retry_reason", drop(retry, "retry_reason"), True))
    cases.append(("retry with unknown reason",
                  dict(retry, retry_reason="vibes"), True))
    usage = valid_by_kind["usage"]
    cases.append(("usage without counters",
                  dict(usage, metadata={"content_type": "application/json"}), True))
    cases.append(("usage without usage_source", drop(usage, "usage_source"), True))
    cases.append(("usage with unknown source",
                  dict(usage, usage_source="telemetry"), True))
    error = valid_by_kind["transport-error"]
    cases.append(("transport-error without error_class",
                  drop(error, "error_class"), True))
    cases.append(("transport-error with unknown class",
                  dict(error, error_class="solar-flare"), True))
    return cases


def verify_bundle() -> int:
    records = build_records()
    expected = build_files()
    expected[PATH_MANIFEST] = build_manifest(expected)
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
        if path in on_disk:
            raw = (committed / path).read_bytes()
            if provenancegen.file_bytes(json.loads(raw)) != raw:
                failures.append(f"non-canonical formatting in {path}")

    verify_payloads(records, failures)

    made = load_validator()
    if made is None:
        print(
            "jsonschema is not installed: instance validation skipped "
            "(pip install jsonschema)",
            file=sys.stderr,
        )
        return 4
    validator, schema = made

    # Positive validation of every committed artifact.
    for path in sorted(records):
        if path not in on_disk:
            continue
        for error in sorted(validator.iter_errors(json.loads(
                (committed / path).read_bytes()))):
            failures.append(
                f"{path}: {error.message} at {list(error.absolute_path)}")

    # The negative matrix runs against one valid control per kind, so each
    # kind's rules are proven against its own well-formed record.
    valid_by_kind: dict[str, dict] = {}
    for record in records.values():
        valid_by_kind.setdefault(record["artifact_kind"], record)
    if set(valid_by_kind) != {"provider-request", "provider-response",
                              "streaming-event", "retry", "usage",
                              "transport-error"}:
        failures.append("bundle must carry a valid control of every kind")
    cases = negative_cases(valid_by_kind["provider-request"], schema) \
        + kind_negative_cases(valid_by_kind)
    control_seen = False
    for label, mutated, must_reject in cases:
        rejected = bool(list(validator.iter_errors(mutated)))
        if must_reject and not rejected:
            failures.append(f"negative matrix: schema ACCEPTED {label}")
        if not must_reject:
            control_seen = True
            if rejected:
                failures.append(f"negative matrix: control rejected ({label})")
    if not control_seen:
        failures.append("negative matrix: the valid control case never ran")

    manifest = json.loads(expected[PATH_MANIFEST])
    reserved_count = len(schema["x-archivist"]["reservedFields"])
    allowlist_count = len(schema["properties"]["metadata"]["properties"])
    invariants = manifest["invariants"]
    if invariants["reserved_fields_rejected"] != reserved_count:
        failures.append("manifest reserved-fields count drifted from the schema")
    if invariants["metadata_allowlist_entries"] != allowlist_count:
        failures.append("manifest allowlist count drifted from the schema")
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    if set(by_path) != set(records):
        failures.append("manifest file list drifted from the bundle")
    for path, entry in sorted(by_path.items()):
        record = records[path]
        if entry["artifact_kind"] != record["artifact_kind"]:
            failures.append(f"{path}: manifest kind drifted from the record")
        if entry["sha256"] != hashlib.sha256(expected[path]).hexdigest():
            failures.append(f"{path}: manifest digest drifted from the bytes")
        if entry["inference_request_id"] != record["inference_request_id"]:
            failures.append(f"{path}: manifest inference id drifted")
        if entry["provider_attempt_id"] != record["provider_attempt_id"]:
            failures.append(f"{path}: manifest attempt id drifted")

    if failures:
        print(f"inference bundle verification FAILED ({len(failures)}):",
              file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 3
    print(
        "inference bundle verified: "
        f"{len(records)} artifacts across 3 scenarios, "
        f"{reserved_count} reserved members and the closed "
        f"{allowlist_count}-entry metadata allowlist enforced, "
        f"ordering and reconstruction invariants recomputed from bytes"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify", action="store_true",
                       help="regenerate and byte-compare the committed bundle, "
                            "validate instances and the negative matrix")
    modes.add_argument("--generate", metavar="OUTPUT", nargs="?",
                       const=str(DEFAULT_OUTPUT),
                       help="write the bundle (default: the committed location)")
    args = parser.parse_args(argv)

    if args.generate is not None:
        write_bundle(Path(args.generate), build_files())
        return 0
    return verify_bundle()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
