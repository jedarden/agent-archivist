#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Zero-entropy generator for the derived-episode example bundle.

The bundle under schemas/v1/examples/episodes/ is the golden-vector table
for the redacted episode family (docs/notes/derived-episode-schema.md,
schemas/v1/derived-episode.json): every episode digest is computed with the
byte-exact `episode-v1` construction the schema pins, every pseudonym and
key ID with the tenant-scoped HMAC the pipeline pins, and the occurrence IDs
cited as provenance are the very IDs the raw-provenance example bundle
materializes — so the bundle demonstrates, end to end, the plan Phase 10
traceability sentence: derived data traceable to raw occurrences without a
raw object path anywhere in the derived bytes.

Every identifier, timestamp, and content byte is a pinned synthetic
constant drawn from a closed vocabulary (SEC-010); no real session, host,
account, path, or transcript data appears. The redaction markers and
pseudonym texts are the *synthetic* rendering formats of the pinned
`redaction-v1` example corpus (`pipeline/redaction-v1-corpus.json`), not a
claim about the real producer's formats — the schema bounds the bytes, the
corpus digest pins what produced them.

--verify proves the family's acceptance, not just its bytes: each episode
is re-digested from its own canonical bytes (self-verification), each
census is re-counted from the content actually present, the forbidden
member matrix (risk assessment, trust decision, use approval, raw object
path, and the rest of the reserved list) is injected one name at a time
and must be rejected by the schema, and the closed shape must reject an
unknown member, an unknown role, and an unknown pipeline.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenancegen  # noqa: E402  (pinned constructions + occurrence IDs)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "schemas" / "v1" / "examples" / "episodes"
COMMON_SCHEMA = REPO_ROOT / "schemas" / "v1" / "common.json"
EPISODE_SCHEMA = REPO_ROOT / "schemas" / "v1" / "derived-episode.json"

BUNDLE_SCHEMA = "archivist.episode-examples/v1"

# The pinned synthetic pipeline identity (plan Section 7.1 derived axis).
PIPELINE_ID = "redaction"
PIPELINE_VERSION = "1"
EPISODE_VERSION = 1

# The synthetic tenant-scoped pseudonym key. Pinned patterned bytes, never a
# real key (SEC-006, SEC-010); it exists only inside this generator and never
# appears in any bundle file — only its HMAC self-ID does.
PSEUDONYM_KEY = bytes.fromhex(
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
PSEUDONYM_KEY_ID_LABEL = "pseudonym-key-id-v1"

# The synthetic rendering formats of the pinned example corpus: typed
# non-reversible markers and tenant-scoped HMAC pseudonyms. Part of the
# corpus below, not of the schema — the census classes are the schema's,
# the marker/pseudonym text is the pipeline version's.
MARKER_FORMAT = "[redacted:{class_token}]"
MARKER_CLASSES = {
    "pinned_credential": "pinned_credential",
    "authorization_header": "authorization_header",
    "private_key_block": "private_key_block",
    "environment_secret": "environment_secret",
    "high_entropy_token": "high_entropy_token",
}
PSEUDONYM_CLASSES = {
    "absolute_path": "path",
    "hostname": "hostname",
    "username": "user",
    "email_address": "email",
    "ip_address": "ip",
}
MARKER_RE = re.compile(r"\[redacted:(" + "|".join(MARKER_CLASSES) + r")\]")
PSEUDONYM_RE = re.compile(
    r"\bps_(?:" + "|".join(PSEUDONYM_CLASSES.values()) + r")_[0-9a-f]{12}\b")
PSEUDONYM_TOKEN_TO_CLASS = {v: k for k, v in PSEUDONYM_CLASSES.items()}

# Synthetic source identifiers the example pipeline pseudonymizes. Chosen
# from a closed vocabulary; nothing here names a real system.
SOURCE_HOSTNAME_SHARED = "build-runner.internal.example"  # cited by two episodes
SOURCE_HOSTNAME_C = "cache-node.internal.example"
SOURCE_PATH_A = "/build/work/session-chunk.jsonl"
SOURCE_USER_A = "agent-worker"
SOURCE_EMAIL_A = "worker@internal.example"
SOURCE_IP_A = "10.9.8.7"
SOURCE_IP_C = "10.9.8.8"

SOURCE_TIME_A0 = "2026-09-11T16:44:05Z"  # embedded in the source itself
SOURCE_TIME_A2 = "2026-09-11T16:44:19Z"
SOURCE_TIME_C0 = "2026-09-11T17:41:02Z"

PATH_EPISODE_A = "episodes/full-detector-sweep.json"
PATH_EPISODE_B = "episodes/clean-scan.json"
PATH_EPISODE_C = "episodes/shared-pseudonym-space.json"
PATH_CORPUS = "pipeline/redaction-v1-corpus.json"


# --- the pinned constructions ----------------------------------------------


def blob_digest_of_provenance_payload() -> str:
    """The blob digest of the raw-provenance bundle's shared payload —
    recomputed here from the same pinned records so the occurrence IDs this
    bundle cites are the exact IDs that bundle materializes."""
    payload, _identity = provenancegen.build_payload()
    return provenancegen.blob_digest(payload)


def pseudonym_key_id() -> str:
    """Lowercase hex of HMAC-SHA256(pseudonym key, label) — the keyed
    self-ID the schema pins for `pseudonym_key_id`: recomputable and
    verifiable only by key holders, disclosing nothing about the key."""
    return hmac.new(PSEUDONYM_KEY, PSEUDONYM_KEY_ID_LABEL.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def pseudonym(pseudonym_class: str, source_identifier: str) -> str:
    """Tenant-scoped HMAC pseudonym: the synthetic `redaction-v1` rendering
    `ps_<class>_<12 hex>` — stable within a tenant and key, irreversible
    without the key, and never carrying removed content."""
    body = hmac.new(PSEUDONYM_KEY,
                    f"{pseudonym_class}\x00{source_identifier}".encode("utf-8"),
                    hashlib.sha256).hexdigest()[:12]
    return f"ps_{PSEUDONYM_CLASSES[pseudonym_class]}_{body}"


def marker(marker_class: str) -> str:
    return MARKER_FORMAT.format(class_token=MARKER_CLASSES[marker_class])


def episode_digest(episode_without_digest: dict) -> str:
    """Construction `episode-v1` (schemas/v1/derived-episode.json,
    x-archivist.derivations): SHA-256 under the domain label `episode-v1`
    over the RFC 8785 canonicalization of the complete episode object with
    the `episode_digest` member removed — the same label/length framing
    every ingest identifier uses, so one verifier core walks both families.
    The digest member is excluded from its own preimage, which is what
    makes the record self-verifying and the assessment binding acyclic."""
    canonical = provenancegen.canonical_json(episode_without_digest).encode("utf-8")
    return provenancegen.derive("episode-v1", canonical)


def episode_object_key(digest_hex: str) -> str:
    return (f"tenants/{provenancegen.TENANT}/v1/derived/{PIPELINE_ID}/"
            f"{PIPELINE_VERSION}/episodes/{digest_hex[:2]}/{digest_hex}.json")


# --- the pinned corpus and raw provenance inputs ----------------------------
#
# Module-level so every builder and the verifier share one definition: the
# corpus digest every episode carries, and the occurrence IDs every episode
# cites, are computed once from pinned inputs.

CORPUS = {
    "corpus_version": PIPELINE_VERSION,
    "pipeline_id": PIPELINE_ID,
    "detectors": [
        {"order": 1, "detector": "pinned-credential-formats",
         "emits": "pinned_credential", "test_vectors": 12},
        {"order": 2, "detector": "authorization-headers",
         "emits": "authorization_header", "test_vectors": 8},
        {"order": 3, "detector": "private-key-blocks",
         "emits": "private_key_block", "test_vectors": 10},
        {"order": 4, "detector": "environment-secret-assignments",
         "emits": "environment_secret", "test_vectors": 14},
        {"order": 5, "detector": "high-entropy-token-candidates",
         "emits": "high_entropy_token", "test_vectors": 16},
        {"order": 6, "detector": "absolute-path-pseudonyms",
         "emits": "absolute_path", "test_vectors": 9},
        {"order": 7, "detector": "hostname-pseudonyms",
         "emits": "hostname", "test_vectors": 11},
        {"order": 8, "detector": "username-pseudonyms",
         "emits": "username", "test_vectors": 7},
        {"order": 9, "detector": "email-address-pseudonyms",
         "emits": "email_address", "test_vectors": 6},
        {"order": 10, "detector": "ip-address-pseudonyms",
         "emits": "ip_address", "test_vectors": 13},
    ],
    "marker_format": MARKER_FORMAT,
    "pseudonym_format": "ps_<class>_<12 lowercase hex of HMAC-SHA256>",
    "pseudonym_key_id_construction": (
        "HMAC-SHA256(pseudonym key, 'pseudonym-key-id-v1'), lowercase hex"),
    "structured_field_allowlist": ["role", "ordinal", "source_time",
                                   "parent_ordinals"],
    "test_suite_sha256": hashlib.sha256(
        b"agent-archivist synthetic redaction-v1 test corpus").hexdigest(),
}
# detector_corpus_digest names the corpus file's canonical bytes — the exact
# bytes the pipeline version freezes, LF excluded the way every canonical
# object here is its file bytes minus the one trailing LF.
CORPUS_DIGEST = hashlib.sha256(
    provenancegen.canonical_json(CORPUS).encode("utf-8")).hexdigest()

_BLOB = blob_digest_of_provenance_payload()
_OCC_A, _ = provenancegen.build_occurrence_a(_BLOB)
_OCC_B, _ = provenancegen.build_occurrence_b(_BLOB)
OCCURRENCE_ID_A = _OCC_A["occurrence_id"]
OCCURRENCE_ID_B = _OCC_B["occurrence_id"]

HOSTNAME_PSEUDONYM_SHARED = pseudonym("hostname", SOURCE_HOSTNAME_SHARED)


# --- episode assembly -------------------------------------------------------


def census(records: list[dict]) -> tuple[dict, dict]:
    """Re-count both censuses from the redacted content actually present,
    so the committed counts are provably a report of what fired, not a
    claim. Every class key is explicit, zero included — a detector that
    silently failed to run is a missing capability in the evidence."""
    markers = {k: 0 for k in MARKER_CLASSES}
    pseudonyms = {k: 0 for k in PSEUDONYM_CLASSES}
    for record in records:
        for match in MARKER_RE.findall(record["content"]):
            markers[match] += 1
        for match in PSEUDONYM_RE.findall(record["content"]):
            pseudonyms[PSEUDONYM_TOKEN_TO_CLASS[match.split("_")[1]]] += 1
    return markers, pseudonyms


def assemble_episode(occurrence_ids: list[str],
                     records: list[dict]) -> tuple[dict, dict]:
    marker_counts, pseudonym_counts = census(records)
    base = {
        "episode_version": EPISODE_VERSION,
        "tenant_id": provenancegen.TENANT,
        "pipeline_id": PIPELINE_ID,
        "pipeline_version": PIPELINE_VERSION,
        "detector_corpus_digest": CORPUS_DIGEST,
        "pseudonym_key_id": pseudonym_key_id(),
        "occurrence_ids": sorted(set(occurrence_ids)),
        "marker_counts": marker_counts,
        "pseudonym_counts": pseudonym_counts,
        "records": sorted(records, key=lambda r: r["ordinal"]),
    }
    episode = dict(base)
    episode["episode_digest"] = episode_digest(base)
    identity = {
        "episode_digest": episode["episode_digest"],
        "object_key": episode_object_key(episode["episode_digest"]),
        "episode_version": EPISODE_VERSION,
        "pipeline_id": PIPELINE_ID,
        "pipeline_version": PIPELINE_VERSION,
        "occurrence_ids": episode["occurrence_ids"],
    }
    return episode, identity


def build_episode_a() -> tuple[dict, dict]:
    """Every detector family fires at least once, and the record structure
    exercises the full allowlist: all four roles, contiguous ordinals,
    backward-only parent_ordinals, and source_time present on some records
    and absent on others (omitted, never null)."""
    records = [
        {"ordinal": 0, "role": "system",
         "content": "Session archive chunk accepted from " +
                    pseudonym("username", SOURCE_USER_A) +
                    " on host " + HOSTNAME_PSEUDONYM_SHARED + ".",
         "source_time": SOURCE_TIME_A0},
        {"ordinal": 1, "role": "user", "parent_ordinals": [0],
         "content": "Summarize the build log at " +
                    pseudonym("absolute_path", SOURCE_PATH_A) +
                    " and reply to " + pseudonym("email_address", SOURCE_EMAIL_A) +
                    " from " + pseudonym("ip_address", SOURCE_IP_A) + "."},
        {"ordinal": 2, "role": "assistant", "parent_ordinals": [1],
         "content": "Read the chunk; the upload presented " +
                    marker("authorization_header") +
                    " and the log cites " + marker("pinned_credential") + ".",
         "source_time": SOURCE_TIME_A2},
        {"ordinal": 3, "role": "tool", "parent_ordinals": [2],
         "content": "Tool output: key material " + marker("private_key_block") +
                    ", assigned secret " + marker("environment_secret") +
                    ", candidate token " + marker("high_entropy_token") + "."},
    ]
    return assemble_episode([OCCURRENCE_ID_A], records)


def build_episode_b() -> tuple[dict, dict]:
    """A clean scan: every census class explicitly zero. The census still
    names all ten classes, so a clean episode is distinguishable from one
    where a detector silently failed to run."""
    records = [
        {"ordinal": 0, "role": "user",
         "content": "Synthetic status question with no detector match."},
    ]
    return assemble_episode([OCCURRENCE_ID_B], records)


def build_episode_c() -> tuple[dict, dict]:
    """Two raw occurrences in one episode, and the same source hostname as
    episode A: the tenant-scoped pseudonym is byte-identical across the two
    episodes (analytic stability) while the episodes themselves stay
    distinct objects with distinct digests."""
    records = [
        {"ordinal": 0, "role": "user",
         "content": "Check connectivity to " + HOSTNAME_PSEUDONYM_SHARED +
                    " and then to " + pseudonym("hostname", SOURCE_HOSTNAME_C) +
                    " from " + pseudonym("ip_address", SOURCE_IP_C) + ".",
         "source_time": SOURCE_TIME_C0},
        {"ordinal": 1, "role": "assistant", "parent_ordinals": [0],
         "content": "First host reachable; second host rejected " +
                    marker("high_entropy_token") + " in its reply."},
    ]
    return assemble_episode([OCCURRENCE_ID_A, OCCURRENCE_ID_B], records)


# --- bundle construction ----------------------------------------------------


def build_manifest(files: dict[str, bytes], identities: dict) -> dict:
    scenarios = [
        {
            "id": "full-detector-sweep",
            "asserts": [
                "the episode validates and every census class is nonzero — the census reports what actually fired",
                "every marker and pseudonym visible in the redacted content is counted, and no removed byte appears anywhere",
                "the record allowlist is exercised: four roles, contiguous ordinals from zero, backward-only parent_ordinals, source_time present and absent",
                "the episode digest is recomputable from the record's own canonical bytes with the digest member removed (VAL-005)",
                "occurrence provenance is carried as occurrence IDs — the very IDs the raw-provenance example bundle materializes — with no raw object path in the episode",
            ],
            "episode": PATH_EPISODE_A,
        },
        {
            "id": "clean-scan",
            "asserts": [
                "every census class is an explicit zero, so a clean scan is distinguishable from a detector that silently failed to run",
                "a single-record episode with no source_time validates — optional members are omitted, never null",
            ],
            "episode": PATH_EPISODE_B,
        },
        {
            "id": "shared-pseudonym-space",
            "asserts": [
                "one episode derives from two raw occurrences (multi-occurrence provenance, ascending unique IDs)",
                "the same source hostname pseudonymizes to the identical pseudonym text as in full-detector-sweep — tenant-scoped analytic stability",
                "the two episodes remain distinct objects under distinct digests and distinct object keys",
            ],
            "episode": PATH_EPISODE_C,
            "shares_hostname_with": "full-detector-sweep",
        },
    ]
    schema = json.loads(EPISODE_SCHEMA.read_text(encoding="utf-8"))
    return {
        "schema": BUNDLE_SCHEMA,
        "scan_version": 1,
        "authority": {
            "episode": "schemas/v1/derived-episode.json",
            "vocabulary": "schemas/v1/common.json",
            "episode_digest_construction":
                "schemas/v1/derived-episode.json#x-archivist.derivations",
            "identifier_constructions": "schemas/v1/ingest-identifiers.json",
            "raw_provenance_bundle":
                "schemas/v1/examples/provenance/ (the occurrence IDs cited here)",
        },
        "synthetic": (
            "Every identifier, timestamp, key, and content byte in this "
            "bundle is pinned synthetic data (SEC-006, SEC-010); the "
            "pseudonym key exists only inside tools/episodegen.py and "
            "never appears in any file — only its HMAC self-ID does."
        ),
        "canonicalization": (
            "Each file is RFC 8785-style canonical JSON plus one trailing "
            "LF. detector_corpus_digest is SHA-256 over the corpus file's "
            "canonical bytes (the LF excluded); episode_digest is the "
            "episode-v1 construction over the episode's canonical bytes "
            "with the episode_digest member removed, so every digest below "
            "is recomputable from this bundle alone."
        ),
        "governance_boundary": (
            "Nothing in any episode file is an assessment, a trust "
            "decision, a use approval, a policy, or a route to raw bytes: "
            "the reserved-name matrix in tools/episodegen.py --verify "
            "injects each forbidden member into a valid episode and "
            "proves the schema rejects it. Later risk-assessment-v1 and "
            "use-approval-v1 records reference episode_digest and nothing "
            "else of the episode; no episode member references any of "
            "them, so neither record's serialization contains the other "
            "— binding by digest, without circular serialization."
        ),
        "scenarios": scenarios,
        "invariants": {
            "episodes": 3,
            "distinct_episode_digests": 3,
            "forbidden_members_rejected": len(
                schema["x-archivist"]["reservedFields"]),
            "shared_hostname_pseudonym": (
                "the hostname pseudonym in full-detector-sweep and "
                "shared-pseudonym-space is byte-identical for the same "
                "source hostname under the same tenant key"
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


def build_bundle() -> dict[str, bytes]:
    episode_a, identity_a = build_episode_a()
    episode_b, identity_b = build_episode_b()
    episode_c, identity_c = build_episode_c()
    files = {
        PATH_EPISODE_A: provenancegen.file_bytes(episode_a),
        PATH_EPISODE_B: provenancegen.file_bytes(episode_b),
        PATH_EPISODE_C: provenancegen.file_bytes(episode_c),
        PATH_CORPUS: provenancegen.file_bytes(CORPUS),
    }
    identities = {
        PATH_EPISODE_A: identity_a,
        PATH_EPISODE_B: identity_b,
        PATH_EPISODE_C: identity_c,
        PATH_CORPUS: {"detector_corpus_digest": CORPUS_DIGEST,
                      "corpus_version": PIPELINE_VERSION},
    }
    files["manifest.json"] = provenancegen.file_bytes(
        build_manifest(files, identities))
    return files


# --- generate / verify ------------------------------------------------------


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


def verify_episode(path: str, episode: dict, failures: list[str]) -> None:
    """Per-episode invariants, every one recomputed from the episode's own
    bytes — the self-verification an auditor performs with nothing but the
    stored object."""
    body = {k: v for k, v in episode.items() if k != "episode_digest"}
    if episode_digest(body) != episode.get("episode_digest"):
        failures.append(f"{path}: episode_digest is not the episode-v1 "
                        f"digest of the record's own canonical bytes")

    ids = episode["occurrence_ids"]
    if not ids or not set(ids) <= {OCCURRENCE_ID_A, OCCURRENCE_ID_B}:
        failures.append(f"{path}: occurrence provenance must cite "
                        f"bundle-known occurrences")
    if ids != sorted(set(ids)):
        failures.append(f"{path}: occurrence_ids must be unique and ascending")

    records = episode["records"]
    if [r["ordinal"] for r in records] != list(range(len(records))):
        failures.append(f"{path}: record ordinals must be contiguous from zero")
    for record in records:
        for parent in record.get("parent_ordinals", []):
            if parent >= record["ordinal"]:
                failures.append(
                    f"{path}: parent_ordinals must be strictly backward "
                    f"(record {record['ordinal']} cites {parent})")

    expected_markers, expected_pseudonyms = census(records)
    if episode["marker_counts"] != expected_markers:
        failures.append(f"{path}: marker_counts disagree with the content")
    if episode["pseudonym_counts"] != expected_pseudonyms:
        failures.append(f"{path}: pseudonym_counts disagree with the content")
    for census_name, classes in (("marker_counts", MARKER_CLASSES),
                                 ("pseudonym_counts", PSEUDONYM_CLASSES)):
        if set(episode[census_name]) != set(classes):
            failures.append(f"{path}: {census_name} must name every class "
                            f"explicitly, zero included")

    key = episode_object_key(episode["episode_digest"])
    common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
    pattern = re.compile(
        common["$defs"]["derived-episode-object-key"]["pattern"])
    if not pattern.fullmatch(key):
        failures.append(f"{path}: object key does not match the "
                        f"derived-episode-object-key pattern")
    if key.rsplit("/", 2)[1] != episode["episode_digest"][:2]:
        failures.append(f"{path}: object key shard must be the digest's "
                        f"first two hex")

    if episode["pseudonym_key_id"] != pseudonym_key_id():
        failures.append(f"{path}: pseudonym_key_id is not the pinned HMAC self-ID")
    if episode["detector_corpus_digest"] != CORPUS_DIGEST:
        failures.append(f"{path}: detector_corpus_digest does not name the "
                        f"pinned corpus")
    if (episode["pipeline_id"] != PIPELINE_ID
            or episode["pipeline_version"] != PIPELINE_VERSION):
        failures.append(f"{path}: pipeline identity must be the pinned redaction/1")


def forbidden_member_cases(valid_episode: dict) -> list[tuple[str, dict, bool]]:
    """The negative matrix: (label, mutated episode, must_be_rejected).
    The reserved list is read from the schema itself so the matrix can
    never drift from it; the category anchors named in the defining bead —
    risk assessment, trust decision, use approval, raw object path — are
    all members of that list."""
    schema = json.loads(EPISODE_SCHEMA.read_text(encoding="utf-8"))
    reserved = schema["x-archivist"]["reservedFields"]
    cases: list[tuple[str, dict, bool]] = []
    payloads = {
        "risk_assessment": {"labels": ["prompt_injection"], "severity": "high"},
        "trust_decision": "trusted",
        "use_approval": {"approved_by": "synthetic-approver"},
        "raw_object_key": "tenants/x/v1/raw/blobs/zstd-v1/sha256/ab/ab.json",
    }
    for name in sorted(reserved):
        mutated = dict(valid_episode)
        mutated[name] = payloads.get(name, "synthetic-" + name)
        cases.append((f"forbidden member: {name}", mutated, True))
    deep = json.loads(json.dumps(valid_episode))
    deep["records"][0]["role"] = "agent"
    unknown_role = deep
    deep2 = json.loads(json.dumps(valid_episode))
    deep2["records"][0]["plaintext"] = "never allowed"
    unknown_record_member = deep2
    deep3 = json.loads(json.dumps(valid_episode))
    deep3["occurrence_ids"] = [valid_episode["occurrence_ids"][0]] * 2
    duplicate_ids = deep3
    cases.extend([
        ("unknown top-level member", dict(valid_episode, extra_member=1), True),
        ("episode_version 2", dict(valid_episode, episode_version=2), True),
        ("unknown pipeline_id",
         dict(valid_episode, pipeline_id="not-a-pipeline"), True),
        ("unknown role", unknown_role, True),
        ("duplicate occurrence_ids", duplicate_ids, True),
        ("empty records", dict(valid_episode, records=[]), True),
        ("unknown record member", unknown_record_member, True),
        ("valid control (the matrix's negative control)",
         json.loads(json.dumps(valid_episode)), False),
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

    # The corpus digest names the corpus file's canonical bytes.
    canonical_corpus = expected[PATH_CORPUS][:-1]  # strip the one trailing LF
    if hashlib.sha256(canonical_corpus).hexdigest() != CORPUS_DIGEST:
        failures.append("detector_corpus_digest does not name the corpus file")

    # Per-episode invariants.
    episodes = {p: json.loads(expected[p]) for p in expected
                if p.startswith("episodes/")}
    for path, episode in sorted(episodes.items()):
        verify_episode(path, episode, failures)

    if len({e["episode_digest"] for e in episodes.values()}) != len(episodes):
        failures.append("episode digests must be pairwise distinct")
    if len({episode_object_key(e["episode_digest"])
            for e in episodes.values()}) != len(episodes):
        failures.append("episode object keys must be pairwise distinct")

    # Cross-episode pseudonym stability: the shared hostname renders to the
    # identical pseudonym text in episodes A and C.
    text_a = episodes[PATH_EPISODE_A]["records"][0]["content"]
    text_c = episodes[PATH_EPISODE_C]["records"][0]["content"]
    if (HOSTNAME_PSEUDONYM_SHARED not in text_a
            or HOSTNAME_PSEUDONYM_SHARED not in text_c):
        failures.append("the shared hostname pseudonym must appear "
                        "byte-identically in both episodes that cite it")

    # Manifest identities must carry matching, pattern-valid object keys.
    common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
    pattern = re.compile(
        common["$defs"]["derived-episode-object-key"]["pattern"])
    manifest = json.loads(expected["manifest.json"])
    for entry in manifest["files"]:
        key = entry["identity"].get("object_key")
        if entry["path"].startswith("episodes/"):
            if key is None:
                failures.append(f"{entry['path']}: manifest must carry "
                                f"the object key")
            elif not pattern.fullmatch(key):
                failures.append(f"{entry['path']}: manifest object key "
                                f"misses the pattern")

    # Schema validation: every committed episode validates positively, and
    # the forbidden-member matrix is rejected one name at a time.
    make_validator = load_jsonschema()
    if make_validator is None:
        print(
            "jsonschema is not installed: instance validation skipped "
            "(pip install jsonschema)",
            file=sys.stderr,
        )
        return 4
    _, episode_validator = make_validator(EPISODE_SCHEMA)
    for path in sorted(episodes):
        if path in on_disk:
            for error in sorted(episode_validator.iter_errors(
                    json.loads((committed / path).read_bytes()))):
                failures.append(
                    f"{path}: {error.message} at {list(error.absolute_path)}")

    control_ok = False
    for label, mutated, must_reject in forbidden_member_cases(
            episodes[PATH_EPISODE_A]):
        rejected = bool(list(episode_validator.iter_errors(mutated)))
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

    reserved_count = len(json.loads(EPISODE_SCHEMA.read_text(encoding="utf-8"))
                         ["x-archivist"]["reservedFields"])
    if manifest["invariants"]["forbidden_members_rejected"] != reserved_count:
        failures.append("manifest forbidden-members count drifted from the schema")

    if failures:
        print(f"episode bundle verification FAILED ({len(failures)}):",
              file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 3
    print(
        "episode bundle verified: "
        f"{len(episodes)} episodes, {reserved_count} forbidden members "
        f"rejected by the schema, all digests recomputed from bundle bytes"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify", action="store_true",
                       help="regenerate and byte-compare the committed bundle, "
                            "validate instances and the forbidden-member matrix")
    modes.add_argument("--generate", metavar="OUTPUT", nargs="?",
                       const=str(DEFAULT_OUTPUT),
                       help="write the bundle (default: the committed location)")
    args = parser.parse_args(argv)

    if args.generate is not None:
        write_bundle(Path(args.generate), build_bundle())
        return 0
    return verify_bundle()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
