#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Deterministic generator for the control-record verification corpus.

The bundle under schemas/v1/examples/control/ is the golden-vector table
for the ``archivist.control/v1`` trust family's current-pointer records
(docs/notes/control-trust.md items 1 and 5, docs/notes/
control-trust-schemas.md note 5): linked-client epoch progression and
delegations granted and withdrawn, every member a byte-pinned,
tenant-authority-signed record carrying the outcome a replay must
produce. A current-pointer replacement is accepted only when its signed
``authorization_epoch`` strictly increases over the standing pointer —
equal or lower is a stale write and is rejected — and that rule, not
signature mathematics, is what every ``stale-epoch`` member pins: its
signature verifies, and the decision procedure rejects it anyway.

Two scenario files share one keys.json:

- ``epoch-progression.json`` — the link is epoch 1 and every later
  administrative act on the same client publishes a strictly higher
  epoch of the same object; stale equal-epoch and stale lower-epoch
  members are rejected while their signatures verify. Two subjects
  (one origin client, one relay) pin that monotonicity is per subject.
- ``delegation-lifecycle.json`` — the (relay, origin) relation's own
  epoch sequence: grant, revision, withdrawal (the one move the
  current-pointer shape permits — the store has no delete), a stale
  re-grant rejected, a deliberate re-grant accepted, and a forged
  grant signed by the relay's own key rejected as ``untrusted-signer``
  — the epoch would strictly increase and the signature is a valid
  Ed25519 signature, but not by the authority key the record names.
  Verification precedes the epoch rule.

Every record validates against the archivist.control/v1 envelope
registry per the check-control-schemas.py conventions (draft 2020-12
validators over schemas/v1 with the family's ``$id``s resolvable, the
record schema named by tools/control-records.toml, the object key
re-derived from the record's own members and matched against the
envelope's key pattern), and every ``authority_signature`` is re-verified
by conformancegen's independent pure-Python Ed25519 verifier — the
signing path and the verifying path share no code.

--verify regenerates the bundle and proves it byte-identical to the
committed files (zero diff is the pinning contract), re-validates every
record, re-verifies every signature, and replays the decision procedure
over each history: every computed outcome must equal the pinned
``expected``/``reason``, and each fold must land on the file's
``final_state``.

--self-test proves the same machinery without the committed bundle:
build determinism (two builds byte-identical, signing deterministic),
the signature path (authority signatures verify, tampered bytes do
not), the forged member's trust property (valid Ed25519 by the wrong
key — accepted by mathematics, rejected by the authority check), the
decision procedure (agrees with every pinned outcome, and detects a
tampered outcome), the write guard, and the schema's rejection of a
small fault matrix around the valid control.

Every identifier is a pinned synthetic constant (SEC-010); every key
pair is derived at generation time from ``SHA-256("archivist.control/v1
<name>")`` and only the public half is ever emitted — no private key
material exists in this source, the bundle, or any argument.
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
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conformancegen  # noqa: E402  (pure-Python Ed25519 verifier)
import provenancegen  # noqa: E402  (canonical JSON + file bytes)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "schemas" / "v1" / "examples" / "control"
SCHEMA_DIR = REPO_ROOT / "schemas" / "v1"
REGISTRY_PATH = REPO_ROOT / "tools" / "control-records.toml"

NAMESPACE = "archivist.control/v1"
KEYS_SCHEMA = "archivist.control-keys/v1"
BUNDLE_SCHEMA = "archivist.control-examples/v1"
SCAN_VERSION = 1

PATH_KEYS = "keys.json"
PATH_EPOCH = "epoch-progression.json"
PATH_DELEGATION = "delegation-lifecycle.json"
URN_EPOCH = "urn:agent-archivist:corpus:control-epoch-progression"
URN_DELEGATION = "urn:agent-archivist:corpus:control-delegation-lifecycle"

# The outcome vocabulary the decision procedure produces. The reject
# reason ``stale-epoch`` is the storage family's own closed error-class
# token (crates/archivist-storage/src/error.rs); ``untrusted-signer`` is
# this corpus's name for the record whose authority signature does not
# verify against the key its own ``authority_key_id`` names.
OUTCOME_ACCEPTED = "accepted"
OUTCOME_REJECTED = "rejected"
REASON_STALE = "stale-epoch"
REASON_UNTRUSTED = "untrusted-signer"

CANONICALIZATION = (
    "RFC 8785: JSON objects with lexicographically sorted member names, "
    "no insignificant whitespace, minimal string escapes")
SIGNATURE_CONSTRUCTION = (
    "control-record-v1: Ed25519 by the tenant authority key named by "
    "authority_key_id, over the canonical bytes of the record with the "
    "authority_signature member removed")
KEY_ID_DERIVATION = (
    "lowercase-hex SHA-256 of the 32 raw public-key bytes")


# ---------------------------------------------------------------------------
# Pinned synthetic identities (SEC-010: nothing here is real) and keys.
#
# A separate synthetic deployment from every other corpus bundle: one
# tenant, two linked clients (an origin and the relay that may present
# its occurrences). Each key pair is derived from the SHA-256 of its
# namesake label under this corpus's own seed prefix, so the corpus is
# reproducible from the names alone; the private halves are never
# emitted anywhere.
# ---------------------------------------------------------------------------

KEY_SEED_PREFIX = "archivist.control/v1"

TENANT = "3e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30"
CLIENT_A = "9a4c2f18-6b37-4e59-8d20-1f3a5c7e9b42"  # the origin client
CLIENT_B = "c7d8e9f0-1a2b-4c3d-9e4f-5a6b7c8d9e0f"  # the relay client


class ControlSigningKey:
    """An Ed25519 key pair derived from a pinned label, public material only."""

    def __init__(self, name: str, role: str, extra: dict | None = None):
        self.name = name
        self.role = role
        self.extra = extra or {}
        seed = hashlib.sha256(f"{KEY_SEED_PREFIX} {name}".encode()).digest()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        private = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self.key_id = hashlib.sha256(bytes.fromhex(self.public_key)).hexdigest()
        self._private = private

    def sign(self, message: bytes) -> str:
        return self._private.sign(message).hex()

    def public_record(self) -> dict:
        record = {
            "name": self.name,
            "role": self.role,
            "public_key": self.public_key,
            "key_id": self.key_id,
        }
        record.update(self.extra)
        return record


AUTHORITY = ControlSigningKey("control-authority", "tenant-authority-root",
                              {"tenant_id": TENANT})
CLIENT_A_KEY = ControlSigningKey("control-client-a", "uploader",
                                 {"client_id": CLIENT_A,
                                  "linked_tenant": TENANT})
CLIENT_B_KEY = ControlSigningKey("control-client-b", "uploader",
                                 {"client_id": CLIENT_B,
                                  "linked_tenant": TENANT})

# The wall-clock context of the two stories. The epoch is the logical
# order of each subject's history; signed_at is its audit context only
# (no validity window is attached to a current-pointer record).
EPOCH_STORY_FROM = "2026-09-11T00:00:00Z"
DELEGATION_STORY_FROM = "2026-09-12T00:00:00Z"


def hours_after(start: str, hours: int) -> str:
    """A pinned signed_at: start plus a whole number of hours."""
    from datetime import datetime, timedelta, timezone

    moment = datetime.fromisoformat(start.replace("Z", "+00:00"))
    return (moment + timedelta(hours=hours)).astimezone(
        timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Record assembly
# ---------------------------------------------------------------------------


def canonical_bytes(record: dict) -> bytes:
    """The bytes the authority signs: the complete record object minus its
    ``authority_signature``, RFC 8785-canonicalized."""
    body = {k: v for k, v in record.items() if k != "authority_signature"}
    return provenancegen.canonical_json(body).encode("utf-8")


def sign_record(record: dict, signer: ControlSigningKey) -> dict:
    canonical = canonical_bytes(record)
    record["authority_signature"] = signer.sign(canonical)
    return record


def linked_client(client_id: str, key: ControlSigningKey, harnesses: list[str],
                  epoch: int, signed_at: str) -> dict:
    """One current-pointer record of the linked-client type: the client's
    identity, public half, base scopes, and current authorization epoch.
    Scope arrays are issued lexicographically sorted — the writer
    discipline that makes equivalent grants produce identical canonical
    bytes (control-client.json, scopes.harnesses)."""
    record = {
        "schema": NAMESPACE,
        "record_type": "linked-client",
        "record_kind": "current-pointer",
        "tenant_id": TENANT,
        "client_id": client_id,
        "key_id": key.key_id,
        "key_algorithm": "ed25519",
        "public_key": key.public_key,
        "scopes": {
            "harnesses": sorted(harnesses),
            "operations": ["ingest"],
        },
        "authorization_epoch": epoch,
        "signed_at": signed_at,
        "authority_key_id": AUTHORITY.key_id,
    }
    return sign_record(record, AUTHORITY)


def delegation(state: str, harnesses: list[str], epoch: int,
               signed_at: str, signer: ControlSigningKey | None = None) -> dict:
    """One current-pointer record of the delegation type: the relay grant
    over one origin client, as the conjunction of the harness and
    operation dimensions. The relation's epoch is its own sequence, not
    a client's. ``signer`` defaults to the tenant authority; the forged
    member passes the relay's key to pin the untrusted-signer outcome."""
    record = {
        "schema": NAMESPACE,
        "record_type": "delegation",
        "record_kind": "current-pointer",
        "tenant_id": TENANT,
        "relay_client_id": CLIENT_B,
        "origin_client_id": CLIENT_A,
        "delegation_state": state,
        "scopes": {
            "harnesses": sorted(harnesses),
            "operations": ["ingest"],
        },
        "authorization_epoch": epoch,
        "signed_at": signed_at,
        "authority_key_id": AUTHORITY.key_id,
    }
    return sign_record(record, signer or AUTHORITY)


# ---------------------------------------------------------------------------
# The two scenario histories
# ---------------------------------------------------------------------------


def epoch_progression_history() -> list[dict]:
    """Linked-client epoch progression, two subjects. The origin client's
    story: link at epoch 1, two revisions that strictly increase, then
    two stale writes — one equal to the standing epoch, one the
    byte-identical replay of the epoch-2 record — whose signatures
    verify and whose epochs do not. The relay links at its own epoch 1,
    pinning that monotonicity is per subject."""
    revision_two = linked_client(
        CLIENT_A, CLIENT_A_KEY, ["claude-code"], 2,
        hours_after(EPOCH_STORY_FROM, 6))
    return [
        {
            "name": "client-a-link-epoch-1",
            "record": linked_client(
                CLIENT_A, CLIENT_A_KEY, ["claude-code", "codex"], 1,
                EPOCH_STORY_FROM),
            "expected": OUTCOME_ACCEPTED,
            "note": "the link: first write at the subject's key, epoch 1 "
                    "(docs/notes/control-trust.md item 1)",
        },
        {
            "name": "client-b-link-epoch-1",
            "record": linked_client(
                CLIENT_B, CLIENT_B_KEY, ["codex"], 1,
                hours_after(EPOCH_STORY_FROM, 1)),
            "expected": OUTCOME_ACCEPTED,
            "note": "the relay's own link: monotonicity is per subject — "
                    "one client's epoch sequence never constrains another's",
        },
        {
            "name": "client-a-revision-epoch-2",
            "record": revision_two,
            "expected": OUTCOME_ACCEPTED,
            "note": "the harness allowlist narrows: a strictly higher epoch "
                    "replaces the standing pointer",
        },
        {
            "name": "client-a-revision-epoch-3",
            "record": linked_client(
                CLIENT_A, CLIENT_A_KEY, ["claude-code", "pi"], 3,
                hours_after(EPOCH_STORY_FROM, 12)),
            "expected": OUTCOME_ACCEPTED,
            "note": "re-granting a harness an earlier epoch held is a new "
                    "grant at a strictly higher epoch, never a repoint",
        },
        {
            "name": "client-a-stale-equal-epoch-3",
            "record": linked_client(
                CLIENT_A, CLIENT_A_KEY, ["codex"], 3,
                hours_after(EPOCH_STORY_FROM, 18)),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_STALE,
            "note": "equal to the standing epoch: an administrative act "
                    "that did not bump the epoch cannot replace the pointer",
        },
        {
            "name": "client-a-stale-lower-epoch-2",
            "record": dict(revision_two),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_STALE,
            "note": "the byte-identical replay of the epoch-2 record: the "
                    "signature still verifies, and the epoch rule alone "
                    "rejects — a captured pointer cannot roll the subject "
                    "back; rollback requires publishing another "
                    "higher-epoch record",
        },
    ]


def delegation_history() -> list[dict]:
    """The (relay, origin) relation's own epoch sequence: granted,
    revised, withdrawn, a stale re-grant rejected, a deliberate
    re-grant accepted, and a forged grant — signed by the relay's own
    key — rejected because verification precedes the epoch rule."""
    return [
        {
            "name": "delegation-grant-epoch-1",
            "record": delegation("active", ["claude-code"], 1,
                                 DELEGATION_STORY_FROM),
            "expected": OUTCOME_ACCEPTED,
            "note": "the grant: relay B may present origin A's "
                    "claude-code occurrences under the ingest operation",
        },
        {
            "name": "delegation-revision-epoch-2",
            "record": delegation("active", ["claude-code", "codex"], 2,
                                 hours_after(DELEGATION_STORY_FROM, 6)),
            "expected": OUTCOME_ACCEPTED,
            "note": "the harness dimension widens: a new epoch of the "
                    "relation, granted as deliberately as the first",
        },
        {
            "name": "delegation-withdrawal-epoch-3",
            "record": delegation("withdrawn", ["claude-code", "codex"], 3,
                                 hours_after(DELEGATION_STORY_FROM, 12)),
            "expected": OUTCOME_ACCEPTED,
            "note": "withdrawal — the one move the current-pointer shape "
                    "permits: the store has no delete, so a strictly "
                    "higher-epoch record at the same key carries the "
                    "withdrawn state, and it grants nothing regardless "
                    "of its scopes",
        },
        {
            "name": "delegation-stale-regrant-epoch-3",
            "record": delegation("active", ["claude-code"], 3,
                                 hours_after(DELEGATION_STORY_FROM, 13)),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_STALE,
            "note": "re-granting at the withdrawal's own epoch: equal is "
                    "stale, and the grant stays withdrawn",
        },
        {
            "name": "delegation-regrant-epoch-4",
            "record": delegation("active", ["claude-code"], 4,
                                 hours_after(DELEGATION_STORY_FROM, 18)),
            "expected": OUTCOME_ACCEPTED,
            "note": "withdrawal is a state, not a tombstone: repair "
                    "publishes a strictly higher epoch in the open",
        },
        {
            "name": "delegation-forged-epoch-5",
            "record": delegation("active", ["claude-code"], 5,
                                 hours_after(DELEGATION_STORY_FROM, 19),
                                 signer=CLIENT_B_KEY),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_UNTRUSTED,
            "note": "a relay cannot mint its own grant: the epoch would "
                    "strictly increase and the signature is a valid "
                    "Ed25519 signature — but by the relay's key, not the "
                    "authority key the record names. Verification "
                    "precedes the epoch rule",
        },
    ]


# ---------------------------------------------------------------------------
# Decision procedure — the replay any language performs
# ---------------------------------------------------------------------------


def decide(history: list[dict],
           keys_by_id: dict[str, str]) -> list[dict]:
    """Replay the corpus decision procedure over one history in order.

    1. the record's canonical bytes (authority_signature removed) are
       what the signature covers — already proven member-for-member by
       the canonical_bytes_sha256 pin;
    2. the signature must verify against the public half keys.json
       holds for the record's own authority_key_id — a key the table
       does not hold, or a signature that fails against it, is the
       untrusted-signer rejection, and the decision ends there;
    3. otherwise the current-pointer rule decides: accepted iff no
       pointer stands at the subject key yet, or the signed epoch
       strictly exceeds the standing one — otherwise stale-epoch;
    4. acceptance moves the standing epoch to this record's.
    """
    standing: dict[str, int] = {}
    outcomes = []
    for entry in history:
        record = entry["record"]
        public = keys_by_id.get(record["authority_key_id"])
        verified = public is not None and conformancegen.ed25519_verify(
            public, record["authority_signature"], canonical_bytes(record))
        if not verified:
            outcomes.append({"name": entry["name"],
                             "outcome": OUTCOME_REJECTED,
                             "reason": REASON_UNTRUSTED})
            continue
        key = record_object_key(record)
        epoch = record["authorization_epoch"]
        if key in standing and epoch <= standing[key]:
            outcomes.append({"name": entry["name"],
                             "outcome": OUTCOME_REJECTED,
                             "reason": REASON_STALE})
        else:
            standing[key] = epoch
            outcomes.append({"name": entry["name"],
                             "outcome": OUTCOME_ACCEPTED,
                             "reason": None})
    return outcomes


# ---------------------------------------------------------------------------
# Envelope-registry conventions (the check-control-schemas.py mold)
# ---------------------------------------------------------------------------


def load_registry() -> dict:
    return tomllib.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def record_object_key(record: dict, registry: dict | None = None) -> str:
    """The store-derived object key: the registry layout with the record's
    own key members substituted in key_members order (ID-008)."""
    registry = registry or load_registry()
    entry = registry["records"][record["record_type"]]
    key = entry["object_key"]
    for member in entry["key_members"]:
        key = key.replace(f"<{member}>", str(record[member]))
    return key


def family_schemas() -> dict[str, dict]:
    return {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(SCHEMA_DIR.glob("*.json"))
    }


def build_validator(schemas: dict[str, dict], stem: str):
    """A draft 2020-12 validator over one family schema, with every
    family ``$id`` resolvable through the referencing registry — the
    build_validator convention of tools/check-control-schemas.py."""
    import jsonschema
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    registry = Registry().with_resources([
        (doc["$id"], Resource.from_contents(doc,
                                            default_specification=DRAFT202012))
        for doc in schemas.values() if "$id" in doc
    ])
    return jsonschema.Draft202012Validator(schemas[stem], registry=registry)


def record_schema_stem(record_type: str, registry: dict) -> str:
    """The schema file the record registry names for this record type."""
    return Path(registry["records"][record_type]["schema"]).stem


# ---------------------------------------------------------------------------
# Bundle construction
# ---------------------------------------------------------------------------

EPOCH_TITLED = "Linked-client epoch progression conformance vectors"
DELEGATION_TITLED = "Delegation grant/withdrawal conformance vectors"

DECISION_PROCEDURE = [
    "recompute the record's canonical bytes: RFC 8785 over the complete "
    "record object with the authority_signature member removed; their "
    "SHA-256 must equal the entry's canonical_bytes_sha256",
    "look up the public half in keys.json by the record's own "
    "authority_key_id and verify the Ed25519 signature over those "
    "canonical bytes; failure is rejected/untrusted-signer and the "
    "decision ends there",
    "otherwise accept iff no pointer stands at the subject's object key "
    "yet, or the signed authorization_epoch strictly exceeds the "
    "standing epoch; any other epoch is rejected/stale-epoch",
    "acceptance moves the standing epoch to this record's; a full "
    "history's fold must land on this file's final_state",
]

OUTCOME_VOCABULARY = {
    OUTCOME_ACCEPTED: "the write lands; the standing epoch moves to this "
                      "record's",
    OUTCOME_REJECTED: "the store refuses the write",
    REASON_STALE: "the signed epoch does not strictly increase over the "
                  "standing pointer (the storage family's own closed "
                  "error-class token: crates/archivist-storage/src/"
                  "error.rs, StorageErrorKind::StaleEpoch)",
    REASON_UNTRUSTED: "the authority signature does not verify against "
                      "the key the record's own authority_key_id names",
}


def generation_block() -> dict:
    return {
        "note": (
            "Synthetic corpus keys only — never tenant material. Every "
            "private seed is SHA-256(\"archivist.control/v1 <name>\") for "
            "the key's name in keys.json; signatures are deterministic "
            "Ed25519 (RFC 8032), so any implementation reproduces the "
            "corpus from the names alone. No private half is emitted "
            "anywhere."),
        "canonicalization": CANONICALIZATION,
        "signature_construction": SIGNATURE_CONSTRUCTION,
        "key_id_derivation": KEY_ID_DERIVATION,
        "key_material": PATH_KEYS,
        "trust_record_cache_ttl_seconds": 60,
        "decision_procedure": DECISION_PROCEDURE,
        "outcome_vocabulary": OUTCOME_VOCABULARY,
    }


def history_entry(name: str, record: dict, expected: str, note: str,
                  reason: str | None = None) -> dict:
    entry = {
        "name": name,
        "record": record,
        "canonical_bytes_sha256": hashlib.sha256(
            canonical_bytes(record)).hexdigest(),
        "expected": expected,
    }
    if reason is not None:
        entry["reason"] = reason
    entry["note"] = note
    return entry


def build_epoch_progression() -> dict:
    history = [history_entry(**member)
               for member in epoch_progression_history()]
    client_key = record_object_key({
        "record_type": "linked-client", "tenant_id": TENANT,
        "client_id": CLIENT_A,
    })
    relay_key = record_object_key({
        "record_type": "linked-client", "tenant_id": TENANT,
        "client_id": CLIENT_B,
    })
    return {
        "$schema": URN_EPOCH,
        "title": EPOCH_TITLED,
        "description": (
            "Language-neutral, byte-pinned vectors for the linked-client "
            "current-pointer's epoch rule (docs/notes/control-trust.md "
            "item 1; docs/notes/control-trust-schemas.md note 5): a "
            "replacement is accepted only when its signed "
            "authorization_epoch strictly increases over the standing "
            "pointer — equal or lower is a stale write and is rejected, "
            "even though its authority signature verifies. Any "
            "implementation replays this offline with no server: read "
            "keys.json, walk history in order applying the generation "
            "block's decision procedure, and require every computed "
            "outcome to equal the entry's expected (and reason), with "
            "the fold landing on final_state. Two subjects pin that "
            "monotonicity is per subject."),
        "generation": generation_block(),
        "pinned": {
            "tenant_id": TENANT,
            "authority_key_id": AUTHORITY.key_id,
            "subjects": {
                client_key: {"client_id": CLIENT_A,
                             "key": "control-client-a"},
                relay_key: {"client_id": CLIENT_B,
                            "key": "control-client-b"},
            },
        },
        "history": history,
        "final_state": {
            client_key: {"authorization_epoch": 3,
                         "record": "client-a-revision-epoch-3"},
            relay_key: {"authorization_epoch": 1,
                        "record": "client-b-link-epoch-1"},
        },
    }


def build_delegation_lifecycle() -> dict:
    history = [history_entry(**member)
               for member in delegation_history()]
    object_key = record_object_key({
        "record_type": "delegation", "tenant_id": TENANT,
        "relay_client_id": CLIENT_B, "origin_client_id": CLIENT_A,
    })
    return {
        "$schema": URN_DELEGATION,
        "title": DELEGATION_TITLED,
        "description": (
            "Language-neutral, byte-pinned vectors for the delegation "
            "current-pointer's grant, revision, and withdrawal "
            "(docs/notes/control-trust.md item 5): the (relay, origin) "
            "relation's own epoch sequence, where withdrawal is the one "
            "move the current-pointer shape permits — the store has no "
            "delete — and a withdrawn record grants nothing regardless "
            "of its scopes. The forged member is signed by the relay's "
            "own key while naming the authority's: the epoch would "
            "strictly increase and the signature is a valid Ed25519 "
            "signature, so only the check against the named authority "
            "key rejects it — verification precedes the epoch rule. Any "
            "implementation replays this offline with no server: read "
            "keys.json, walk history in order applying the generation "
            "block's decision procedure, and require every computed "
            "outcome to equal the entry's expected (and reason), with "
            "the fold landing on final_state."),
        "generation": generation_block(),
        "pinned": {
            "tenant_id": TENANT,
            "authority_key_id": AUTHORITY.key_id,
            "relay_client_id": CLIENT_B,
            "origin_client_id": CLIENT_A,
            "object_key": object_key,
        },
        "history": history,
        "final_state": {
            object_key: {"authorization_epoch": 4,
                         "record": "delegation-regrant-epoch-4"},
        },
    }


def build_keys() -> dict:
    return {
        "key_id_derivation": KEY_ID_DERIVATION,
        "seed_derivation": (
            "Every corpus key's private seed is "
            "SHA-256(\"archivist.control/v1 <name>\") for the key's name "
            "below — documented, never emitted. Signatures are "
            "deterministic Ed25519 (RFC 8032), so the corpus is "
            "reproducible from the names alone."),
        "scope": (
            "The key material the epoch-progression and "
            "delegation-lifecycle bundles replay against. The "
            "authority-rotation-chain bundle pins its own root in-file "
            "(its seeds are one repeated byte, documented there)."),
        "keys": [
            AUTHORITY.public_record(),
            CLIENT_A_KEY.public_record(),
            CLIENT_B_KEY.public_record(),
        ],
    }


def build_manifest(files: dict[str, bytes], scenarios: list[dict]) -> dict:
    records = sum(s["records"] for s in scenarios)
    accepted = sum(s["accepted"] for s in scenarios)
    rejected = sum(s["rejected"] for s in scenarios)
    return {
        "schema": BUNDLE_SCHEMA,
        "scan_version": SCAN_VERSION,
        "authority": {
            "envelope_registry": "schemas/v1/control-envelope.json",
            "record_registry": "tools/control-records.toml",
            "record_schemas": "schemas/v1/control-*.json",
            "notes": [
                "docs/notes/control-trust.md",
                "docs/notes/control-trust-schemas.md",
                "docs/notes/conformance-corpus.md",
            ],
            "key_material": PATH_KEYS,
        },
        "synthetic": (
            "Every identifier, key, signature, and timestamp in this "
            "bundle is pinned synthetic data (SEC-006, SEC-010) for one "
            "synthetic deployment: one tenant, an origin client, and the "
            "relay that may present its occurrences. Nothing here is "
            "real, and only public halves are emitted."),
        "canonicalization": (
            "Each file is RFC 8785-style canonical JSON plus one trailing "
            "LF. Every authority_signature is deterministic Ed25519 over "
            "the canonical bytes of its record with the "
            "authority_signature member removed, so every record is "
            "verifiable from this bundle and keys.json alone."),
        "scenarios": scenarios,
        "invariants": {
            "records": records,
            "accepted": accepted,
            "rejected": rejected,
            "stale_epoch_rejections": 3,
            "untrusted_signer_rejections": 1,
            "invariant_meaning": (
                "every rejection is decided by the rule it pins: the "
                "stale-epoch members' authority signatures verify, and "
                "the forged member's epoch would strictly increase — "
                "no rejection rests on malformed input"),
        },
        "files": [
            {
                "path": path,
                "bytes": len(files[path]),
                "sha256": hashlib.sha256(files[path]).hexdigest(),
            }
            for path in sorted(files)
        ],
    }


def scenario_counts(history: list[dict], outcomes: list[dict]) -> dict:
    accepted = sum(1 for o in outcomes if o["outcome"] == OUTCOME_ACCEPTED)
    return {
        "records": len(history),
        "accepted": accepted,
        "rejected": len(history) - accepted,
    }


def build_bundle() -> dict[str, bytes]:
    epoch_doc = build_epoch_progression()
    delegation_doc = build_delegation_lifecycle()
    keys_doc = build_keys()
    files = {
        PATH_KEYS: provenancegen.file_bytes(keys_doc),
        PATH_EPOCH: provenancegen.file_bytes(epoch_doc),
        PATH_DELEGATION: provenancegen.file_bytes(delegation_doc),
    }
    keys_by_id = {k["key_id"]: k["public_key"] for k in keys_doc["keys"]}
    scenarios = [
        {
            "id": "epoch-progression",
            "file": PATH_EPOCH,
            "schema": URN_EPOCH,
            "subjects": ["linked-client"],
            "history_names": [e["name"] for e in epoch_doc["history"]],
            **scenario_counts(epoch_doc["history"],
                              decide(epoch_doc["history"], keys_by_id)),
        },
        {
            "id": "delegation-lifecycle",
            "file": PATH_DELEGATION,
            "schema": URN_DELEGATION,
            "subjects": ["delegation"],
            "history_names": [e["name"] for e in delegation_doc["history"]],
            **scenario_counts(delegation_doc["history"],
                              decide(delegation_doc["history"],
                                     keys_by_id)),
        },
    ]
    files["manifest.json"] = provenancegen.file_bytes(
        build_manifest(files, scenarios))
    return files


# ---------------------------------------------------------------------------
# generate / verify
# ---------------------------------------------------------------------------



# The control corpus directory is the family's shared home: the
# authority-rotation-chain bundle landed there first (aa-9d88f29c) and
# pins its own root in-file. This generator owns exactly its four files
# and must never touch, and never write beside an unrecognized,
# anything else.
SIBLING_FILES = ("authority-rotation-chain.json",)


def write_bundle(output: Path, files: dict[str, bytes]) -> None:
    marker = output / "manifest.json"
    unexpected: list[str] = []
    if output.exists():
        if marker.exists() and json.loads(
                marker.read_text(encoding="utf-8")).get("schema") \
                != BUNDLE_SCHEMA:
            raise SystemExit(
                f"refusing to write into {output}: not a {BUNDLE_SCHEMA} "
                "bundle (pass an empty or nonexistent directory)")
        unexpected = sorted(entry.name for entry in output.iterdir()
                            if entry.name not in files
                            and entry.name not in SIBLING_FILES)
        if unexpected:
            raise SystemExit(
                f"refusing to write into {output}: holds files this "
                f"generator does not own: {unexpected}")
    for path, data in sorted(files.items()):
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    print(f"wrote {len(files)} files to {output}")


def replay_history(doc: dict, keys_by_id: dict[str, str],
                   failures: list[str]) -> None:
    """The committed decision procedure, replayed from the file's own
    bytes: every outcome must equal the pinned expected/reason, and the
    fold must land on final_state."""
    history = doc["history"]
    outcomes = decide(history, keys_by_id)
    for entry, outcome in zip(history, outcomes):
        if outcome["outcome"] != entry["expected"]:
            failures.append(
                f"{doc['$schema']}: {entry['name']}: decision procedure "
                f"produced {outcome['outcome']}, pinned "
                f"{entry['expected']}")
        elif entry["expected"] == OUTCOME_REJECTED \
                and outcome["reason"] != entry.get("reason"):
            failures.append(
                f"{doc['$schema']}: {entry['name']}: decision procedure "
                f"produced reason {outcome['reason']}, pinned "
                f"{entry.get('reason')}")
    standing = {record_object_key(e["record"]):
                {"authorization_epoch": e["record"]["authorization_epoch"],
                 "record": e["name"]}
                for e, o in zip(history, outcomes)
                if o["outcome"] == OUTCOME_ACCEPTED}
    if standing != doc["final_state"]:
        failures.append(
            f"{doc['$schema']}: the fold landed on {standing}, pinned "
            f"{doc['final_state']}")


def verify_bundle() -> int:
    expected = build_bundle()
    committed = DEFAULT_OUTPUT
    if not committed.is_dir():
        print(f"missing bundle directory {committed}", file=sys.stderr)
        return 2

    failures: list[str] = []
    for path, data in sorted(expected.items()):
        target = committed / path
        if not target.is_file():
            failures.append(f"missing file from bundle: {path}")
        elif target.read_bytes() != data:
            failures.append(f"byte drift in {path}")

    for path in sorted(expected):
        target = committed / path
        if target.is_file():
            raw = target.read_bytes()
            if provenancegen.file_bytes(json.loads(raw)) != raw:
                failures.append(f"non-canonical formatting in {path}")

    if failures:
        # Everything below re-derives from the generated bytes; with the
        # pinning contract broken the report names the drift first.
        print(f"control corpus verification FAILED ({len(failures)}):",
              file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 3

    keys_doc = json.loads(expected[PATH_KEYS])
    keys_by_id = {k["key_id"]: k["public_key"] for k in keys_doc["keys"]}

    schemas = family_schemas()
    registry = load_registry()
    envelope = schemas["control-envelope"]
    validators: dict[str, object] = {}
    try:
        for record_type, entry in registry["records"].items():
            stem = Path(entry["schema"]).stem
            if stem not in validators:
                validators[stem] = build_validator(schemas, stem)
    except ImportError:
        print("jsonschema is not installed: instance validation skipped "
              "(pip install jsonschema)", file=sys.stderr)
        return 4

    key_pattern_refs = {
        "linked-client": "client-object-key",
        "delegation": "delegation-object-key",
    }

    checked = 0
    for path in (PATH_EPOCH, PATH_DELEGATION):
        doc = json.loads(expected[path])
        replay_history(doc, keys_by_id, failures)
        for entry in doc["history"]:
            record = entry["record"]
            name = f"{path}:{entry['name']}"
            checked += 1

            digest = hashlib.sha256(canonical_bytes(record)).hexdigest()
            if digest != entry["canonical_bytes_sha256"]:
                failures.append(
                    f"{name}: canonical_bytes_sha256 is not the SHA-256 of "
                    f"the record's canonical bytes")

            stem = record_schema_stem(record["record_type"], registry)
            for error in sorted(validators[stem].iter_errors(record)):
                failures.append(
                    f"{name}: fails {stem}: {error.message} at "
                    f"{list(error.absolute_path)}")

            key = record_object_key(record, registry)
            pattern = re.compile(
                envelope["$defs"][key_pattern_refs[record["record_type"]]]
                ["pattern"])
            if not pattern.fullmatch(key):
                failures.append(
                    f"{name}: derived object key {key} misses the "
                    f"envelope's {key_pattern_refs[record['record_type']]} "
                    f"pattern")
            if "subjects" in doc["pinned"] \
                    and key not in doc["pinned"]["subjects"]:
                failures.append(f"{name}: object key {key} is not one of "
                                f"the file's pinned subjects")

            verified = conformancegen.ed25519_verify(
                keys_by_id.get(record["authority_key_id"], ""),
                record["authority_signature"], canonical_bytes(record))
            expected_verified = entry.get("reason") != REASON_UNTRUSTED
            if verified != expected_verified:
                failures.append(
                    f"{name}: signature verifies={verified}, the pinned "
                    f"{entry.get('reason') or OUTCOME_ACCEPTED} outcome "
                    f"requires {expected_verified}")

    manifest = json.loads(expected["manifest.json"])
    if manifest["schema"] != BUNDLE_SCHEMA:
        failures.append("manifest.json is not a "
                        f"{BUNDLE_SCHEMA} manifest")
    if manifest["invariants"]["records"] != checked:
        failures.append("manifest record count drifted")
    if manifest["invariants"]["accepted"] \
            != sum(1 for p in (PATH_EPOCH, PATH_DELEGATION)
                   for e in json.loads(expected[p])["history"]
                   if e["expected"] == OUTCOME_ACCEPTED):
        failures.append("manifest accepted count drifted")
    if manifest["invariants"]["rejected"] \
            != manifest["invariants"]["records"] \
            - manifest["invariants"]["accepted"]:
        failures.append("manifest rejected count drifted")
    for entry in manifest["files"]:
        data = expected.get(entry["path"])
        if data is None or hashlib.sha256(data).hexdigest() \
                != entry["sha256"]:
            failures.append(f"manifest digest drifted for "
                            f"{entry['path']}")

    if failures:
        print(f"control corpus verification FAILED ({len(failures)}):",
              file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 3
    print(
        "control corpus verified: "
        f"{checked} records across 2 scenarios, every record valid "
        f"against the archivist.control/v1 envelope registry, every "
        f"signature re-verified independently, every pinned outcome "
        f"reproduced by the decision procedure, bundle byte-identical"
    )
    return 0


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------


def self_test() -> int:
    """Prove the machinery without the committed bundle: build
    determinism, the signature path, the forged member's trust property,
    the decision procedure's agreement with every pinned outcome, the
    write guard, and the schema's rejection of a small fault matrix
    around the valid control."""
    checks: list[tuple[str, bool]] = []

    def check(name: str, condition: bool) -> None:
        checks.append((name, condition))

    # --- determinism -----------------------------------------------------
    first = build_bundle()
    second = build_bundle()
    check("two builds are byte-identical", first == second)
    record_a = linked_client(CLIENT_A, CLIENT_A_KEY, ["claude-code"], 1,
                             EPOCH_STORY_FROM)
    record_b = linked_client(CLIENT_A, CLIENT_A_KEY, ["claude-code"], 1,
                             EPOCH_STORY_FROM)
    check("signing is deterministic (RFC 8032)",
          record_a["authority_signature"]
          == record_b["authority_signature"])

    # --- the signature path ----------------------------------------------
    authority_sig = record_a["authority_signature"]
    check("the authority signature verifies over the canonical bytes",
          conformancegen.ed25519_verify(
              AUTHORITY.public_key, authority_sig, canonical_bytes(record_a)))
    tampered = json.loads(json.dumps(record_a))
    tampered["scopes"]["harnesses"] = ["pi"]
    check("a tampered record fails signature verification",
          not conformancegen.ed25519_verify(
              AUTHORITY.public_key, authority_sig,
              canonical_bytes(tampered)))
    check("a foreign key fails signature verification",
          not conformancegen.ed25519_verify(
              CLIENT_A_KEY.public_key, authority_sig,
              canonical_bytes(record_a)))

    # --- the forged member's trust property ------------------------------
    forged = next(e for e in build_delegation_lifecycle()["history"]
                  if e["name"] == "delegation-forged-epoch-5")
    forged_record = forged["record"]
    check("the forged member's signature is a valid Ed25519 signature — "
          "by the relay's key",
          conformancegen.ed25519_verify(
              CLIENT_B_KEY.public_key,
              forged_record["authority_signature"],
              canonical_bytes(forged_record)))
    check("the forged member fails verification against the authority "
          "key its own authority_key_id names",
          not conformancegen.ed25519_verify(
              AUTHORITY.public_key,
              forged_record["authority_signature"],
              canonical_bytes(forged_record)))
    check("the forged member's epoch would strictly increase",
          forged_record["authorization_epoch"] == 5)

    # --- the decision procedure ------------------------------------------
    keys_by_id = {k.key_id: k.public_key
                  for k in (AUTHORITY, CLIENT_A_KEY, CLIENT_B_KEY)}
    for path, doc in (("epoch", build_epoch_progression()),
                      ("delegation", build_delegation_lifecycle())):
        outcomes = decide(doc["history"], keys_by_id)
        check(f"the {path} decision procedure agrees with every pinned "
              f"outcome",
              all(o["outcome"] == e["expected"]
                  and o["reason"] == e.get("reason")
                  for e, o in zip(doc["history"], outcomes)))
        standing = {record_object_key(e["record"]):
                    e["record"]["authorization_epoch"]
                    for e, o in zip(doc["history"], outcomes)
                    if o["outcome"] == OUTCOME_ACCEPTED}
        check(f"the {path} fold lands on final_state",
              standing == {k: v["authorization_epoch"]
                           for k, v in doc["final_state"].items()})
        flipped = json.loads(json.dumps(doc))
        for entry in flipped["history"]:
            entry["expected"] = (
                OUTCOME_REJECTED if entry["expected"] == OUTCOME_ACCEPTED
                else OUTCOME_ACCEPTED)
        flipped_outcomes = decide(flipped["history"], keys_by_id)
        check(f"the {path} decision procedure detects a flipped pin",
              any(o["outcome"] != e["expected"]
                  for e, o in zip(flipped["history"], flipped_outcomes)))

    stale = next(e for e in build_epoch_progression()["history"]
                 if e["name"] == "client-a-stale-lower-epoch-2")
    check("the stale member's signature verifies — the epoch rule is "
          "what rejects it",
          conformancegen.ed25519_verify(
              AUTHORITY.public_key, stale["record"]["authority_signature"],
              canonical_bytes(stale["record"])))

    # --- the write guard --------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "bundle"
        with contextlib.redirect_stdout(io.StringIO()):
            write_bundle(out, first)
            check("--generate writes every file byte-identically",
                  all((out / path).read_bytes() == data
                      for path, data in first.items()))
            try:
                write_bundle(out, first)
                rewritten = True
            except SystemExit:
                rewritten = False
        check("rewriting its own bundle is allowed", rewritten)
        sibling = Path(tmp) / "sibling"
        sibling.mkdir()
        (sibling / "authority-rotation-chain.json").write_bytes(
            b"the family's other bundle, sharing the home directory\n")
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                write_bundle(sibling, first)
            coexisted = True
        except SystemExit:
            coexisted = False
        check("writing beside the sibling bundle is allowed", coexisted)
        foreign = Path(tmp) / "foreign"
        foreign.mkdir()
        (foreign / "unrecognized.json").write_bytes(
            b"not this generator's, and not the sibling's\n")
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                write_bundle(foreign, first)
            refused = False
        except SystemExit:
            refused = True
        check("the write guard refuses unrecognized files", refused)

    # --- the schema's fault matrix ----------------------------------------
    schemas = family_schemas()
    registry = load_registry()
    try:
        client_validator = build_validator(
            schemas, record_schema_stem("linked-client", registry))
        delegation_validator = build_validator(
            schemas, record_schema_stem("delegation", registry))
    except ImportError:
        print("jsonschema is not installed: self-test cannot run",
              file=sys.stderr)
        return 4
    control = json.loads(json.dumps(
        build_epoch_progression()["history"][0]["record"]))
    check("the valid control validates",
          not list(client_validator.iter_errors(control)))
    faults = [
        ("zero epoch", dict(control, authorization_epoch=0),
         client_validator),
        ("fractional epoch", dict(control, authorization_epoch=1.5),
         client_validator),
        ("epoch above the 18-digit bound",
         dict(control, authorization_epoch=10 ** 18), client_validator),
        ("undeclared member", dict(control, display_name="lab"),
         client_validator),
        ("private-key member", dict(control, private_key="ab" * 32),
         client_validator),
    ]
    control_delegation = json.loads(json.dumps(
        build_delegation_lifecycle()["history"][0]["record"]))
    faults.extend([
        ("unknown delegation state",
         dict(control_delegation, delegation_state="suspended"),
         delegation_validator),
        ("wrong record type token",
         dict(control_delegation, record_type="linked-client"),
         delegation_validator),
    ])
    for name, mutated, validator in faults:
        check(f"the schema rejects: {name}",
              bool(list(validator.iter_errors(mutated))))

    # --- the registry conventions -----------------------------------------
    check("the registry maps linked-client to the client schema",
          record_schema_stem("linked-client", registry) == "control-client")
    check("the registry maps delegation to the delegation schema",
          record_schema_stem("delegation", registry)
          == "control-delegation")
    check("object keys derive from the record's own members",
          record_object_key(control, registry).endswith(
              f"/control/clients/{CLIENT_A}.json"))

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
                            "bundle, validate every record against the "
                            "archivist.control/v1 envelope registry, "
                            "re-verify every signature, and replay the "
                            "decision procedure")
    modes.add_argument("--generate", metavar="OUTPUT", nargs="?",
                       const=str(DEFAULT_OUTPUT),
                       help="write the bundle (default: the committed "
                            "location)")
    modes.add_argument("--self-test", action="store_true",
                       help="prove the machinery without the committed "
                            "bundle")
    args = parser.parse_args(argv)

    if args.generate is not None:
        write_bundle(Path(args.generate), build_bundle())
        return 0
    if args.self_test:
        return self_test()
    return verify_bundle()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
