#!/usr/bin/env python3
"""Deterministic raw-provenance example generator for Agent Archivist.

Implements the Phase 1 deliverable "versioned occurrence and
upload-attestation schemas" example half (docs/plan/plan.md, Section 8,
Phase 1: schemas plus examples under ``schemas/v1/``) and exercises the
acceptance scenarios of the raw provenance schema family: direct upload,
delegated relay, identical bytes with distinct occurrences, and multiple
attestations for one occurrence.

The two schemas are
``schemas/v1/occurrence-manifest.json`` (source-stable provenance) and
``schemas/v1/upload-attestation.json`` (uploader and request provenance).
Every derived value in the bundle — session hash, artifact hash, blob
digest, occurrence ID, attestation ID, and the three server-derived object
keys — is computed here with the byte-exact construction pinned by
``schemas/v1/ingest-identifiers.json`` (plan Section 7.4: SHA-256 over a
domain label, one 0x00 byte, then length-prefixed fields). Nothing is
hand-typed, so the bundle doubles as a golden-vector table for the
identity rules the conformance corpus will later pin.

Bundle layout under ``schemas/v1/examples/provenance``::

    payloads/       the synthetic canonical bytes; the file IS the payload
    occurrences/    one occurrence-manifest instance per distinct occurrence
    attestations/   one upload-attestation instance per frozen request
    manifest.json   scenarios, invariants, per-file digests, derived
                    identities and expected object keys

Scenario map (acceptance criteria):

1. ``direct-upload`` — origin A uploads its own captured chunk; the
   manifest carries no uploader/request field anywhere; one direct
   attestation.
2. ``delegated-relay`` — an authorized relay uploads the same frozen
   occurrence; the occurrence manifest bytes are unchanged and a second,
   relay attestation lands beside the origin's (EC-05A).
3. ``identical-bytes-distinct-occurrences`` — a second origin/session pair
   (different harness, adapter-minted synthetic session ID) submits the
   very same canonical bytes: one tenant-scoped blob, two distinct
   occurrence manifests, each with its own attestation (STO-002).
4. ``multiple-attestations-one-occurrence`` — the origin's spool entry was
   lost after its receipt window, so the chunk was re-spooled under a
   fresh frozen request: a third attestation for occurrence 1 that shares
   uploader and occurrence with attestation 1 and differs only in the
   frozen request (STO-013 separately-auditable axis).

Determinism model: there is no entropy source at all. Every identifier,
timestamp, and payload byte is a pinned synthetic constant below;
serialization is sorted-key compact JSON with one trailing LF, so
regeneration is byte-identical everywhere. ``--verify`` regenerates the
bundle and byte-compares every file against the working tree, validates
each instance against its schema (draft 2020-12, with the shared
``common`` vocabulary resolved from ``schemas/v1/common.json``), checks
each expected object key against the key patterns ``common.json`` pins,
and re-checks the scenario invariants. Exit codes: 0 pass, 2 byte drift
or non-canonical formatting, 3 schema or invariant failure, 4 the
``jsonschema`` module is unavailable (validation cannot run).

Content safety: every value is synthetic (SEC-010) — pinned UUID-shaped
identifiers, fixed UTC timestamps, and a three-record JSONL payload built
from a closed vocabulary; no real session, host, account, or path data.

Usage::

    tools/provenancegen.py --generate [OUTPUT]  # default: the committed bundle
    tools/provenancegen.py --verify             # regenerate, byte-compare, validate
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "schemas" / "v1" / "examples" / "provenance"
COMMON_SCHEMA = REPO_ROOT / "schemas" / "v1" / "common.json"
OCCURRENCE_SCHEMA = REPO_ROOT / "schemas" / "v1" / "occurrence-manifest.json"
ATTESTATION_SCHEMA = REPO_ROOT / "schemas" / "v1" / "upload-attestation.json"

BUNDLE_SCHEMA = "archivist.provenance-examples/v1"

# --- pinned synthetic identifiers (SEC-010: nothing here is real) ----------

TENANT = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b"
ORIGIN_A = "11111111-2222-4333-8444-555555555555"
ORIGIN_B = "66666666-7777-4888-a999-bbbbbbbbbbbb"
RELAY_UPLOADER = "aaaaaaa1-bbbb-4ccc-9ddd-1e2f3f4f5f6f"

GENERATION_A = "1a079d80-7000-7000-8000-000000000051"
GENERATION_B = "1a079d90-7000-7000-8000-000000000052"
REQUEST_1 = "1a079e10-7000-7000-8000-000000000001"
REQUEST_2 = "1a079e20-7000-7000-8000-000000000002"
REQUEST_3 = "1a079e30-7000-7000-8000-000000000003"
REQUEST_4 = "1a079e40-7000-7000-8000-000000000004"

# Scenario 1/2: a harness-issued upstream session ID (opaque, retained
# verbatim). Scenario 3: the harness had no session ID, so the adapter
# minted one (id_source=synthetic), never inferred from a path name.
SESSION_A_UPSTREAM = "4f9c2f1e-8a3d-4b67-9c2f-1e8a3d4b679c"
SESSION_B_SYNTHETIC = "d4811c22-93e4-4f30-8b17-a1c2d3e4f5a6"

HARNESS_A, ADAPTER_A, PROJECTION_A, ARTIFACT_A = (
    "claude-code", "claude-jsonl", "1", "session-file-4f9c2f1e",
)
HARNESS_B, ADAPTER_B, PROJECTION_B, ARTIFACT_B = (
    "codex", "codex-rollout", "1", "rollout-file-synthetic-001",
)

SOURCE_TIME_A = "2026-09-11T16:44:02Z"  # embedded in the source itself
ATT_1_CAPTURE, ATT_1_ENVELOPE = "2026-09-11T16:44:10Z", "2026-09-11T16:44:11Z"
ATT_2_CAPTURE, ATT_2_ENVELOPE = "2026-09-11T16:45:30Z", "2026-09-11T16:45:31Z"
ATT_3_CAPTURE, ATT_3_ENVELOPE = "2026-09-11T17:40:12Z", "2026-09-11T17:40:13Z"
ATT_4_CAPTURE, ATT_4_ENVELOPE = "2026-09-11T16:46:05Z", "2026-09-11T16:46:06Z"

PAYLOAD_RECORDS = [
    {"seq": 1, "text": "synthetic alpha one", "type": "user"},
    {"seq": 2, "text": "synthetic beta two", "type": "assistant"},
    {"seq": 3, "text": "synthetic gamma three", "type": "assistant"},
]

# --- canonical serialization and the pinned identity constructions --------


def canonical_json(value: object) -> str:
    """RFC 8785-style canonical text for this bundle's ASCII, integer-only
    values: sorted keys, no insignificant whitespace, no escaped ASCII."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def file_bytes(value: object) -> bytes:
    """Canonical object bytes plus the single trailing LF every bundle file
    carries; the canonical object is the file bytes minus that LF."""
    return (canonical_json(value) + "\n").encode("utf-8")


def _field(raw: bytes) -> bytes:
    return len(raw).to_bytes(8, "big") + raw


def text(value: str) -> bytes:
    return value.encode("utf-8")


def digest(value: str) -> bytes:
    return bytes.fromhex(value)


def u63(value: int) -> bytes:
    return value.to_bytes(8, "big")


def derive(label: str, *fields: bytes) -> str:
    """H(label, fields...) per schemas/v1/ingest-identifiers.json: SHA-256
    over the UTF-8 label, one 0x00 byte, then each field as an 8-byte
    big-endian length followed by exactly that many bytes."""
    stream = label.encode("utf-8") + b"\x00" + b"".join(_field(f) for f in fields)
    return hashlib.sha256(stream).hexdigest()


def blob_digest(payload: bytes) -> str:
    """The one digest that names a blob: plain SHA-256, no domain label."""
    return hashlib.sha256(payload).hexdigest()


def blob_object_key(tenant: str, digest_hex: str) -> str:
    return f"tenants/{tenant}/v1/raw/blobs/zstd-v1/sha256/{digest_hex[:2]}/{digest_hex}.zst"


def occurrence_object_key(tenant: str, origin: str, harness: str,
                          session_hash: str, occurrence_id: str) -> str:
    return (f"tenants/{tenant}/v1/raw/occurrences/{origin}/{harness}/"
            f"{session_hash[:2]}/{session_hash}/{occurrence_id}.json")


def attestation_object_key(tenant: str, occurrence_id: str, attestation_id: str) -> str:
    return (f"tenants/{tenant}/v1/raw/attestations/"
            f"{occurrence_id[:2]}/{occurrence_id}/{attestation_id}.json")


# --- bundle construction ---------------------------------------------------


def build_payload() -> tuple[bytes, dict]:
    payload = b"".join(file_bytes(record) for record in PAYLOAD_RECORDS)
    digest_hex = blob_digest(payload)
    return payload, {
        "blob_digest": digest_hex,
        "object_key": blob_object_key(TENANT, digest_hex),
    }


def build_occurrence_a(blob: str) -> tuple[dict, dict]:
    session_hash = derive("session-v1", text(TENANT), text(ORIGIN_A),
                          text(HARNESS_A), text(SESSION_A_UPSTREAM))
    artifact_hash = derive("artifact-v1", digest(session_hash), text("file-slice"),
                           text(ADAPTER_A), text(PROJECTION_A), text(ARTIFACT_A))
    end = sum(len(file_bytes(record)) for record in PAYLOAD_RECORDS) - 1
    occurrence_id = derive("occurrence-v1", digest(session_hash), digest(artifact_hash),
                           text(GENERATION_A), text("byte"), u63(0), u63(end),
                           digest(blob))
    manifest = {
        "occurrence_version": 1,
        "occurrence_id": occurrence_id,
        "tenant_id": TENANT,
        "origin_client_id": ORIGIN_A,
        "harness": HARNESS_A,
        "upstream_session_id": SESSION_A_UPSTREAM,
        "id_source": "upstream",
        "session_hash": session_hash,
        "artifact_kind": "file-slice",
        "adapter_id": ADAPTER_A,
        "adapter_projection_version": PROJECTION_A,
        "adapter_artifact_id": ARTIFACT_A,
        "artifact_hash": artifact_hash,
        "generation": GENERATION_A,
        "range_kind": "byte",
        "range_start": 0,
        "range_end": end,
        "blob_digest": blob,
        "storage_profile": "zstd-v1",
        "source_time": SOURCE_TIME_A,
    }
    identity = {
        "session_hash": session_hash,
        "artifact_hash": artifact_hash,
        "occurrence_id": occurrence_id,
        "blob_digest": blob,
        "object_key": occurrence_object_key(TENANT, ORIGIN_A, HARNESS_A,
                                            session_hash, occurrence_id),
    }
    return manifest, identity


def build_occurrence_b(blob: str) -> tuple[dict, dict]:
    session_hash = derive("session-v1", text(TENANT), text(ORIGIN_B),
                          text(HARNESS_B), text(SESSION_B_SYNTHETIC))
    artifact_hash = derive("artifact-v1", digest(session_hash), text("file-slice"),
                           text(ADAPTER_B), text(PROJECTION_B), text(ARTIFACT_B))
    end = sum(len(file_bytes(record)) for record in PAYLOAD_RECORDS) - 1
    occurrence_id = derive("occurrence-v1", digest(session_hash), digest(artifact_hash),
                           text(GENERATION_B), text("byte"), u63(0), u63(end),
                           digest(blob))
    manifest = {
        "occurrence_version": 1,
        "occurrence_id": occurrence_id,
        "tenant_id": TENANT,
        "origin_client_id": ORIGIN_B,
        "harness": HARNESS_B,
        "upstream_session_id": SESSION_B_SYNTHETIC,
        "id_source": "synthetic",
        "session_hash": session_hash,
        "artifact_kind": "file-slice",
        "adapter_id": ADAPTER_B,
        "adapter_projection_version": PROJECTION_B,
        "adapter_artifact_id": ARTIFACT_B,
        "artifact_hash": artifact_hash,
        "generation": GENERATION_B,
        "range_kind": "byte",
        "range_start": 0,
        "range_end": end,
        "blob_digest": blob,
        "storage_profile": "zstd-v1",
    }
    identity = {
        "session_hash": session_hash,
        "artifact_hash": artifact_hash,
        "occurrence_id": occurrence_id,
        "blob_digest": blob,
        "object_key": occurrence_object_key(TENANT, ORIGIN_B, HARNESS_B,
                                            session_hash, occurrence_id),
    }
    return manifest, identity


def build_attestation(occurrence_id: str, origin: str, uploader: str,
                      delegation: str, request: str,
                      capture: str, envelope: str) -> tuple[dict, dict]:
    attestation_id = derive("attestation-v1", digest(occurrence_id),
                            text(uploader), text(request))
    record = {
        "attestation_version": 1,
        "attestation_id": attestation_id,
        "tenant_id": TENANT,
        "occurrence_id": occurrence_id,
        "origin_client_id": origin,
        "uploader_client_id": uploader,
        "request_id": request,
        "delegation": delegation,
        "capture_time": capture,
        "envelope_creation_time": envelope,
    }
    identity = {
        "attestation_id": attestation_id,
        "occurrence_id": occurrence_id,
        "object_key": attestation_object_key(TENANT, occurrence_id, attestation_id),
    }
    return record, identity


PATH_PAYLOAD = "payloads/shared-session-chunk.jsonl"
PATH_OCC_A = "occurrences/direct-upload-and-relay-source.json"
PATH_OCC_B = "occurrences/identical-bytes-second-origin.json"
PATH_ATT_1 = "attestations/origin-direct-first-request.json"
PATH_ATT_2 = "attestations/relay-delegated-request.json"
PATH_ATT_3 = "attestations/origin-direct-refrozen-request.json"
PATH_ATT_4 = "attestations/second-origin-direct-request.json"


def build_bundle() -> dict[str, bytes]:
    payload, payload_identity = build_payload()
    blob = payload_identity["blob_digest"]
    occ_a, occ_a_identity = build_occurrence_a(blob)
    occ_b, occ_b_identity = build_occurrence_b(blob)
    att_1, att_1_identity = build_attestation(
        occ_a_identity["occurrence_id"], ORIGIN_A, ORIGIN_A, "direct",
        REQUEST_1, ATT_1_CAPTURE, ATT_1_ENVELOPE)
    att_2, att_2_identity = build_attestation(
        occ_a_identity["occurrence_id"], ORIGIN_A, RELAY_UPLOADER, "relay",
        REQUEST_2, ATT_2_CAPTURE, ATT_2_ENVELOPE)
    att_3, att_3_identity = build_attestation(
        occ_a_identity["occurrence_id"], ORIGIN_A, ORIGIN_A, "direct",
        REQUEST_4, ATT_3_CAPTURE, ATT_3_ENVELOPE)
    att_4, att_4_identity = build_attestation(
        occ_b_identity["occurrence_id"], ORIGIN_B, ORIGIN_B, "direct",
        REQUEST_3, ATT_4_CAPTURE, ATT_4_ENVELOPE)

    files: dict[str, bytes] = {
        PATH_PAYLOAD: payload,
        PATH_OCC_A: file_bytes(occ_a),
        PATH_OCC_B: file_bytes(occ_b),
        PATH_ATT_1: file_bytes(att_1),
        PATH_ATT_2: file_bytes(att_2),
        PATH_ATT_3: file_bytes(att_3),
        PATH_ATT_4: file_bytes(att_4),
    }
    identities = {
        PATH_PAYLOAD: payload_identity,
        PATH_OCC_A: occ_a_identity,
        PATH_OCC_B: occ_b_identity,
        PATH_ATT_1: att_1_identity,
        PATH_ATT_2: att_2_identity,
        PATH_ATT_3: att_3_identity,
        PATH_ATT_4: att_4_identity,
    }
    files["manifest.json"] = file_bytes(build_manifest(files, identities))
    return files


def build_manifest(files: dict[str, bytes], identities: dict) -> dict:
    occurrences = sorted(p for p in files if p.startswith("occurrences/"))
    attestations = sorted(p for p in files if p.startswith("attestations/"))
    blob_keys = sorted({identities[p]["object_key"] for p in files
                        if p.startswith(("payloads/",))})
    scenarios = [
        {
            "id": "direct-upload",
            "asserts": [
                "the occurrence manifest validates and names no uploader, request, transport, per-attempt, or server field",
                "every derived identity in the manifest is re-derivable from the manifest's own fields",
                "the attestation binds the occurrence with delegation=direct and uploader=origin",
                "the expected object keys match the key patterns pinned in schemas/v1/common.json",
            ],
            "occurrence": PATH_OCC_A,
            "attestations": [PATH_ATT_1],
        },
        {
            "id": "delegated-relay",
            "asserts": [
                "the relay attestation names the same occurrence_id and identical manifest bytes — uploader fields never touch the occurrence (EC-05A)",
                "delegation=relay with uploader != origin; the origin identity is preserved, never replaced (ID-005, SID-006)",
                "attestation identity differs from the origin's by uploader_client_id alone",
                "two attestations coexist under distinct keys for one occurrence",
            ],
            "occurrence": PATH_OCC_A,
            "attestations": [PATH_ATT_1, PATH_ATT_2],
        },
        {
            "id": "identical-bytes-distinct-occurrences",
            "asserts": [
                "both manifests carry the same blob_digest and the archive holds exactly one blob object key (STO-002)",
                "distinct session namespaces (origin, harness, synthetic session ID) derive distinct session_hash and occurrence_id values",
                "two occurrence manifests and two attestations exist, each pair under its own deterministic keys",
            ],
            "occurrence": PATH_OCC_B,
            "attestations": [PATH_ATT_4],
            "shares_payload_with": "direct-upload",
        },
        {
            "id": "multiple-attestations-one-occurrence",
            "asserts": [
                "three attestations name one occurrence: distinct relay uploader, and the same uploader under a re-frozen request (STO-013)",
                "the refrozen attestation differs from the first only in request_id, attestation_id, and its own capture/envelope times",
                "a retry of any single frozen request would rewrite its identical attestation object, not add a fourth (STO-004)",
            ],
            "occurrence": PATH_OCC_A,
            "attestations": [PATH_ATT_1, PATH_ATT_2, PATH_ATT_3],
        },
    ]
    return {
        "schema": BUNDLE_SCHEMA,
        "scan_version": 1,
        "authority": {
            "occurrence": "schemas/v1/occurrence-manifest.json",
            "attestation": "schemas/v1/upload-attestation.json",
            "vocabulary": "schemas/v1/common.json",
            "derivations": "schemas/v1/ingest-identifiers.json",
        },
        "synthetic": (
            "Every identifier, timestamp, and payload byte in this bundle is "
            "pinned synthetic data (SEC-010); nothing is copied from any real "
            "harness store."
        ),
        "canonicalization": (
            "Each file is RFC 8785-style canonical JSON plus one trailing LF; "
            "the payload file's exact bytes are the canonical payload, so "
            "every digest below is recomputable from this bundle alone."
        ),
        "scenarios": scenarios,
        "invariants": {
            "blob_object_keys": len(blob_keys),
            "occurrence_manifests": len(occurrences),
            "upload_attestations": len(attestations),
            "one_blob_two_occurrences": (
                "both occurrence manifests reference one tenant-scoped blob "
                "object key while remaining distinct occurrences (STO-002)"
            ),
        },
        "files": [
            {
                "path": path,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "identity": identities[path],
            }
            for path, data in sorted(files.items())
            if path != "manifest.json"
        ],
    }


# --- generate / verify -----------------------------------------------------


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


def verify_bundle() -> int:
    expected = build_bundle()
    committed = DEFAULT_OUTPUT
    if not committed.is_dir():
        print(f"missing bundle directory {committed}", file=sys.stderr)
        return 2

    failures: list[str] = []
    on_disk = {str(p.relative_to(committed)) for p in committed.rglob("*") if p.is_file()}
    for path in sorted(set(expected) | on_disk):
        if path not in expected:
            failures.append(f"unexpected file in bundle: {path}")
        elif path not in on_disk:
            failures.append(f"missing file from bundle: {path}")
        else:
            actual = (committed / path).read_bytes()
            if actual != expected[path]:
                failures.append(f"byte drift in {path}")

    # Canonical-format guard: every JSON file must be exactly its canonical
    # rendering plus one LF, so a hand edit cannot pass silently.
    for path in sorted(expected):
        if not path.endswith(".json"):
            continue
        if path in on_disk:
            raw = (committed / path).read_bytes()
            if file_bytes(json.loads(raw)) != raw:
                failures.append(f"non-canonical formatting in {path}")

    # Cross-file invariants, recomputed from the regenerated bundle.
    manifest = json.loads(expected["manifest.json"])
    occurrences = {p for p in expected if p.startswith("occurrences/")}
    attestations = {p for p in expected if p.startswith("attestations/")}
    occ_ids = {json.loads(expected[p])["occurrence_id"] for p in occurrences}
    blob_keys = {
        entry["identity"]["object_key"] for entry in manifest["files"]
        if entry["path"].startswith("payloads/")
    }
    att_keys = set()
    for p in attestations:
        record = json.loads(expected[p])
        if record["occurrence_id"] not in occ_ids:
            failures.append(f"{p} names an occurrence with no manifest in the bundle")
        if record["delegation"] == "direct" and record["uploader_client_id"] != record["origin_client_id"]:
            failures.append(f"{p}: delegation=direct but uploader != origin")
        if record["delegation"] == "relay" and record["uploader_client_id"] == record["origin_client_id"]:
            failures.append(f"{p}: delegation=relay but uploader == origin")
        att_keys.add(record["attestation_id"])
    if len(att_keys) != len(attestations):
        failures.append("attestation identities are not pairwise distinct")
    if len(occ_ids) != len(occurrences):
        failures.append("occurrence identities are not pairwise distinct")
    if len(blob_keys) != 1 or manifest["invariants"]["blob_object_keys"] != 1:
        failures.append("identical-bytes scenario must share exactly one blob key")

    # Expected object keys must satisfy the key patterns common.json pins.
    common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
    key_defs = {
        "payloads/": "blob-object-key",
        "occurrences/": "occurrence-object-key",
        "attestations/": "attestation-object-key",
    }
    for entry in manifest["files"]:
        role = next(r for r in key_defs if entry["path"].startswith(r))
        pattern = re.compile(common["$defs"][key_defs[role]]["pattern"])
        if not pattern.fullmatch(entry["identity"]["object_key"]):
            failures.append(
                f"{entry['path']}: object key does not match the {key_defs[role]} pattern"
            )

    # Schema validation of every instance against its versioned schema.
    make_validator = load_jsonschema()
    if make_validator is None:
        print(
            "jsonschema is not installed: instance validation skipped "
            "(pip install jsonschema)",
            file=sys.stderr,
        )
        return 4
    _, occ_validator = make_validator(OCCURRENCE_SCHEMA)
    _, att_validator = make_validator(ATTESTATION_SCHEMA)
    for p in sorted(occurrences):
        if p in on_disk:
            for error in sorted(occ_validator.iter_errors(json.loads((committed / p).read_bytes()))):
                failures.append(f"{p}: {error.message} at {list(error.absolute_path)}")
    for p in sorted(attestations):
        if p in on_disk:
            for error in sorted(att_validator.iter_errors(json.loads((committed / p).read_bytes()))):
                failures.append(f"{p}: {error.message} at {list(error.absolute_path)}")

    if failures:
        print(f"provenance bundle verification FAILED ({len(failures)}):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 3
    print(
        "provenance bundle verified: "
        f"{len(occurrences)} occurrences, {len(attestations)} attestations, "
        f"{len(blob_keys)} blob key, all files byte-identical and schema-valid"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify", action="store_true",
                       help="regenerate and byte-compare the committed bundle, "
                            "validate instances against the schemas")
    modes.add_argument("--generate", metavar="OUTPUT", nargs="?", const=str(DEFAULT_OUTPUT),
                       help="write the bundle (default: the committed location)")
    args = parser.parse_args(argv)

    if args.generate is not None:
        write_bundle(Path(args.generate), build_bundle())
        return 0
    return verify_bundle()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
