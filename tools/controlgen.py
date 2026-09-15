#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Deterministic generator for the control-record verification corpus.

The bundle under schemas/v1/examples/control/ is the golden-vector table
for the ``archivist.control/v1`` trust family (docs/notes/control-trust.md
items 1, 3, 4, 5, and 7; docs/notes/control-trust-schemas.md notes 5
through 9), every member a byte-pinned, tenant-authority-signed record
carrying the outcome a replay must produce. A current-pointer
replacement is accepted only when its signed ``authorization_epoch``
strictly increases over the standing pointer — equal or lower is a
stale write and is rejected — and that rule, not signature mathematics,
is what every ``stale-epoch`` member pins: its signature verifies, and
the decision procedure rejects it anyway. Immutable records pin their
own write rules the same way: one object per derived key, written once,
a byte-identical retry an idempotent repair and an incompatible rewrite
an ``integrity-conflict`` (EC-06), with each type's cross-record checks
— no forward-dated revocation or rotation (``epoch-unreached``), the
standing half named exactly (``key-id-mismatch`` /
``pointer-key-mismatch``), receipt-key windows chained on the two named
constants (``window-discontinuity``) — rejected while their signatures
verify.

Five scenario files share one keys.json:

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
- ``revocation.json`` — the epoch-addressed revocation and the
  higher-epoch client pointer that completes it: revoke at the standing
  epoch, relink at a new key one epoch up (EC-12), then a replay of the
  revoked epoch's pointer rejected ``stale-epoch`` — the plan's Phase 3
  exit gate, an attempt presenting the revoked epoch is stale against
  the new pointer even when its envelope and signature verify — plus a
  forward-dated revocation rejected ``epoch-unreached`` (one cannot
  pre-revoke an epoch the client has not reached), a revocation naming
  a half the pointer does not hold rejected ``key-id-mismatch``, and an
  incompatible rewrite of the revocation's own key rejected
  ``integrity-conflict``.
- ``key-rotation.json`` — the rotation act's two halves: the pointer
  bump and the immutable evidence record (adjacent epochs, both public
  halves, key IDs recomputable from the record itself), an incompatible
  rotation rewrite rejected ``integrity-conflict``, a rotation whose
  new half is not the standing pointer's rejected
  ``pointer-key-mismatch``, a forward-dated rotation rejected
  ``epoch-unreached`` (it would arm its overlap window early), and the
  24-hour ``attempt_acceptance`` table: an attempt at the standing
  epoch signs with either half from ``signed_at`` through
  ``signed_at`` + ``rotationVerificationOverlapHours`` inclusive, and
  one second later the old half is ``outside-overlap`` — the pinned
  reject.
- ``receipt-key-cohort.json`` — the tenant authority's certification
  cohort: a fresh key every ``receiptKeyRotationDays`` (30), each
  signing ``receiptKeySigningOverlapDays`` (7) past its successor's
  first signing instant, so ``valid_until`` − ``valid_from`` is exactly
  the summed 37 days and a successor's ``valid_from`` sits exactly 30
  days after its predecessor's; a byte-identical retry accepted as an
  idempotent repair, a window that does not chain rejected
  ``window-discontinuity``, a key ID that is not the derivation of the
  record's own half rejected ``key-id-mismatch``, an incompatible
  rewrite rejected ``integrity-conflict``, and the ``signing_acceptance``
  table pinning the overlap: both halves sign through the shared
  window, and each is ``outside-signing-window`` on either side of its
  own.
- ``authority-rotation-chain.json`` — the tenant-authority rotation
  chain (subsumed from the bundle that landed first under closed
  aa-9d88f29c, byte-pinned with one generation-note correction: its
  fifth seed, the unreachable stranger's ``0x04``, is now documented),
  replayed by its own walk: predecessor-signed, predecessor-addressed
  links, fetch-verify-adopt from the pinned root, and the acceptance
  verdict for every (signer, ``signed_at``) pair —
  ``accepted``/``retired``/``not_established``/``unreachable`` against
  the same 24-hour window. The Rust replay
  (crates/archivist-auth/tests/authority_corpus.rs) applies the same
  walk to the committed bytes.

Every record validates against the archivist.control/v1 envelope
registry per the check-control-schemas.py conventions (draft 2020-12
validators over schemas/v1 with the family's ``$id``s resolvable, the
record schema named by tools/control-records.toml, the object key
re-derived from the record's own members and matched against the
envelope's key pattern), and every ``authority_signature`` is re-verified
by conformancegen's independent pure-Python Ed25519 verifier — the
signing path and the verifying path share no code. The
authority-rotation-chain vectors pin their canonical digests over the
complete record (the convention their Rust replay consumes); every
other file pins the pre-signature canonical bytes.

--verify regenerates the bundle and proves it byte-identical to the
committed files (zero diff is the pinning contract), re-validates every
record, re-verifies every signature, replays the store fold over each
history — every computed outcome must equal the pinned
``expected``/``reason``, and each fold must land on the file's
``final_state`` — and replays every acceptance table and the authority
chain walk.

--self-test proves the same machinery without the committed bundle:
build determinism (two builds byte-identical, signing deterministic),
the signature path (authority signatures verify, tampered bytes do
not), the forged member's trust property (valid Ed25519 by the wrong
key — accepted by mathematics, rejected by the authority check), the
decision procedure (agrees with every pinned outcome, and detects a
tampered outcome), the window arithmetic (the 24-hour rotation overlap,
the 37-day receipt-key span, the 30-day cadence), the chain walk, the
write guard, and the schema's rejection of a small fault matrix around
the valid controls.

Every identifier is a pinned synthetic constant (SEC-010); every main
bundle key pair is derived at generation time from
``SHA-256("archivist.control/v1 <name>")`` and only the public half is
ever emitted — no private key material exists in this source, the
bundle, or any argument. The authority-rotation-chain deployment pins
its own seeds in-file (one repeated byte each), reproduced here from
those documented bytes alone.
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
PATH_REVOCATION = "revocation.json"
PATH_ROTATION = "key-rotation.json"
PATH_RECEIPT_KEYS = "receipt-key-cohort.json"
PATH_CHAIN = "authority-rotation-chain.json"
URN_EPOCH = "urn:agent-archivist:corpus:control-epoch-progression"
URN_DELEGATION = "urn:agent-archivist:corpus:control-delegation-lifecycle"
URN_REVOCATION = "urn:agent-archivist:corpus:control-revocation"
URN_ROTATION = "urn:agent-archivist:corpus:control-key-rotation"
URN_RECEIPT_KEYS = "urn:agent-archivist:corpus:control-receipt-key-cohort"
URN_CHAIN = "urn:agent-archivist:corpus:control-authority-chain"

# The outcome vocabulary the decision procedure produces. ``stale-epoch``
# and ``integrity-conflict`` are the storage family's own closed
# error-class tokens (crates/archivist-storage/src/error.rs,
# StorageErrorKind::StaleEpoch / ::IntegrityConflict);
# ``untrusted-signer`` is this corpus's name for the record whose
# authority signature does not verify against the key its own
# ``authority_key_id`` names; the rest name the cross-record checks the
# schemas note pins per immutable type. The authority-rotation-chain
# file carries its own acceptance vocabulary
# (accepted/retired/not_established/unreachable), which its Rust replay
# consumes and which the store fold never produces.
OUTCOME_ACCEPTED = "accepted"
OUTCOME_REJECTED = "rejected"
REASON_STALE = "stale-epoch"
REASON_UNTRUSTED = "untrusted-signer"
REASON_INTEGRITY = "integrity-conflict"
REASON_UNREACHED = "epoch-unreached"
REASON_KEY_MISMATCH = "key-id-mismatch"
REASON_POINTER_MISMATCH = "pointer-key-mismatch"
REASON_WINDOW_DISCONTINUITY = "window-discontinuity"
REASON_OUTSIDE_OVERLAP = "outside-overlap"
REASON_OUTSIDE_SIGNING = "outside-signing-window"

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


def key_id_of(public_key_hex: str) -> str:
    """The pinned key-ID derivation: lowercase-hex SHA-256 of the 32 raw
    public-key bytes (VAL-002 — every verifier re-makes it)."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


class DerivedSigningKey:
    """An Ed25519 key pair derived from a pinned seed, public material
    only: the seed never survives this object, and only ``sign``'s
    output and the public half are ever emitted."""

    def __init__(self, seed: bytes, role: str, extra: dict | None = None):
        self.role = role
        self.extra = extra or {}
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        private = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self.key_id = key_id_of(self.public_key)
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


class ControlSigningKey(DerivedSigningKey):
    """A main-bundle key: derived from the SHA-256 of its pinned name
    under the corpus's seed prefix, so the corpus is reproducible from
    the names alone."""

    def __init__(self, name: str, role: str, extra: dict | None = None):
        self.name = name
        super().__init__(
            hashlib.sha256(f"{KEY_SEED_PREFIX} {name}".encode()).digest(),
            role, extra)


AUTHORITY = ControlSigningKey("control-authority", "tenant-authority-root",
                              {"tenant_id": TENANT})
CLIENT_A_KEY = ControlSigningKey("control-client-a", "uploader",
                                 {"client_id": CLIENT_A,
                                  "linked_tenant": TENANT})
CLIENT_B_KEY = ControlSigningKey("control-client-b", "uploader",
                                 {"client_id": CLIENT_B,
                                  "linked_tenant": TENANT})
# The rotation targets and the post-revocation relink half (EC-12: a
# relink is a new, higher epoch with a new key). Each is a distinct
# synthetic half of the same synthetic client.
CLIENT_A_KEY_R2 = ControlSigningKey("control-client-a-r2", "uploader",
                                    {"client_id": CLIENT_A,
                                     "linked_tenant": TENANT})
CLIENT_A_KEY_R3 = ControlSigningKey("control-client-a-r3", "uploader",
                                    {"client_id": CLIENT_A,
                                     "linked_tenant": TENANT})
CLIENT_A_KEY_R4 = ControlSigningKey("control-client-a-r4", "uploader",
                                    {"client_id": CLIENT_A,
                                     "linked_tenant": TENANT})
CLIENT_B_KEY_R2 = ControlSigningKey("control-client-b-r2", "uploader",
                                    {"client_id": CLIENT_B,
                                     "linked_tenant": TENANT})
# The server receipt-signing halves the cohort certifies. These are the
# certified keys, never signers of control records — the authority
# signs every certification.
RECEIPT_KEY_ONE = ControlSigningKey("control-receipt-key-one",
                                    "receipt-signer",
                                    {"tenant_id": TENANT})
RECEIPT_KEY_TWO = ControlSigningKey("control-receipt-key-two",
                                    "receipt-signer",
                                    {"tenant_id": TENANT})
# Material only for the cohort's reject members — a half whose
# certification is refused, so no receipt ever signs with it.
RECEIPT_KEY_THREE = ControlSigningKey("control-receipt-key-three",
                                      "receipt-signer",
                                      {"tenant_id": TENANT})

# The wall-clock context of the stories. The epoch is the logical
# order of each subject's history; signed_at is its audit context only
# (no validity window is attached to a current-pointer record). The
# receipt-key cohort's clock runs on its certifications' windows
# instead: valid_from anchors the signing window, signed_at never
# opens after it.
EPOCH_STORY_FROM = "2026-09-11T00:00:00Z"
DELEGATION_STORY_FROM = "2026-09-12T00:00:00Z"
REVOCATION_STORY_FROM = "2026-09-13T00:00:00Z"
ROTATION_STORY_FROM = "2026-09-14T00:00:00Z"
RECEIPT_COHORT_FROM = "2026-09-01T00:00:00Z"


def hours_after(start: str, hours: int) -> str:
    """A pinned signed_at: start plus a whole number of hours."""
    from datetime import datetime, timedelta, timezone

    moment = datetime.fromisoformat(start.replace("Z", "+00:00"))
    return (moment + timedelta(hours=hours)).astimezone(
        timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def days_after(start: str, days: int) -> str:
    """A pinned instant: start plus a whole number of days."""
    return hours_after(start, 24 * days)


def seconds_after(start: str, seconds: int) -> str:
    """A pinned instant: start plus a whole number of seconds — the
    one-second steps that pin a window's boundary from the outside."""
    from datetime import datetime, timedelta, timezone

    moment = datetime.fromisoformat(start.replace("Z", "+00:00"))
    return (moment + timedelta(seconds=seconds)).astimezone(
        timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def instant_nanos(text: str) -> int:
    """Nanoseconds since the epoch for an RFC 3339 UTC timestamp, at
    full nanosecond precision — datetime alone would truncate the
    sub-microsecond instants the acceptance tables pin (one nanosecond
    past a window's end must not compare equal to its end)."""
    from datetime import datetime, timezone

    # Strip the zone marker before partitioning: with a fractional
    # second the whole part carries no "Z", and a naive parse would
    # fall to the host's local zone instead of the pinned UTC.
    body = text[:-1] if text.endswith("Z") else text
    whole, _, fraction = body.partition(".")
    moment = datetime.fromisoformat(whole)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    nanos = int((fraction + "000000000")[:9]) if fraction else 0
    return int(moment.timestamp()) * 1_000_000_000 + nanos


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


def re_signed(record: dict, signer: ControlSigningKey,
              **changes) -> dict:
    """A record re-signed after the named members change: a fault
    member's fault is never its signature, so the signature must cover
    the faulty bytes — otherwise the decision would end at the
    untrusted-signer check and never reach the rule the member pins."""
    mutated = {k: v for k, v in record.items()
               if k != "authority_signature"}
    mutated.update(changes)
    return sign_record(mutated, signer)


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


def rotation(client_id: str, previous: ControlSigningKey,
             previous_epoch: int, new: ControlSigningKey, epoch: int,
             signed_at: str) -> dict:
    """One immutable rotation record: the durable evidence half of a key
    rotation. ``epoch`` is the epoch the rotation establishes — the
    object key's epoch segment — and must be adjacent to
    ``previous_epoch``; the record carries both public halves and their
    pinned-derivation IDs, so a replica verifies an old-half attempt
    inside the overlap from this record alone."""
    record = {
        "schema": NAMESPACE,
        "record_type": "rotation",
        "record_kind": "immutable",
        "tenant_id": TENANT,
        "client_id": client_id,
        "previous_epoch": previous_epoch,
        "previous_public_key": previous.public_key,
        "previous_key_id": previous.key_id,
        "key_algorithm": "ed25519",
        "public_key": new.public_key,
        "key_id": new.key_id,
        "authorization_epoch": epoch,
        "signed_at": signed_at,
        "authority_key_id": AUTHORITY.key_id,
    }
    return sign_record(record, AUTHORITY)


def revocation(client_id: str, revoked: ControlSigningKey, epoch: int,
               signed_at: str) -> dict:
    """One immutable revocation record: the append-only, epoch-addressed
    revocation of one client's authorization at one epoch.
    ``revoked_key_id`` is the half the client's pointer held at that
    epoch — the durable statement of which credential died, for readers
    after the pointer moves on and retains no history."""
    record = {
        "schema": NAMESPACE,
        "record_type": "revocation",
        "record_kind": "immutable",
        "tenant_id": TENANT,
        "client_id": client_id,
        "revoked_key_id": revoked.key_id,
        "authorization_epoch": epoch,
        "signed_at": signed_at,
        "authority_key_id": AUTHORITY.key_id,
    }
    return sign_record(record, AUTHORITY)


def receipt_key(key: ControlSigningKey, valid_from: str,
                valid_until: str, signed_at: str) -> dict:
    """One immutable receipt-key certification: the tenant authority's
    control-prefix original of the certificate every receipt from this
    key embeds. The signing window is anchored by ``valid_from`` inside
    the signed bytes — ``valid_until`` − ``valid_from`` is exactly
    ``receiptKeyRotationDays`` + ``receiptKeySigningOverlapDays`` (37
    days) — and ``signed_at`` never opens after the window does."""
    record = {
        "schema": NAMESPACE,
        "record_type": "receipt-key",
        "record_kind": "immutable",
        "tenant_id": TENANT,
        "key_id": key.key_id,
        "key_algorithm": "ed25519",
        "public_key": key.public_key,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "signed_at": signed_at,
        "authority_key_id": AUTHORITY.key_id,
    }
    return sign_record(record, AUTHORITY)


# ---------------------------------------------------------------------------
# The scenario histories
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


def revocation_history() -> list[dict]:
    """The epoch-addressed revocation and the pointer that completes it
    (docs/notes/control-trust-schemas.md, the revocation record): revoke
    at the standing epoch, relink at a new key one epoch up (EC-12),
    then the rejects — a replay of the revoked epoch's pointer
    (stale-epoch: the Phase 3 exit gate), a forward-dated revocation
    (epoch-unreached: one cannot pre-revoke an epoch the client has not
    reached), a revocation naming a half the pointer does not hold
    (key-id-mismatch), and an incompatible rewrite of the revocation's
    own derived key (integrity-conflict)."""
    return [
        {
            "name": "client-b-link-epoch-1",
            "record": linked_client(
                CLIENT_B, CLIENT_B_KEY, ["codex"], 1, REVOCATION_STORY_FROM),
            "expected": OUTCOME_ACCEPTED,
            "note": "the relay's link: the story's starting pointer, "
                    "epoch 1 at its own key",
        },
        {
            "name": "client-b-revocation-epoch-1",
            "record": revocation(
                CLIENT_B, CLIENT_B_KEY, 1, hours_after(REVOCATION_STORY_FROM, 2)),
            "expected": OUTCOME_ACCEPTED,
            "note": "the revocation: epoch-addressed and immutable, at "
                    "the standing epoch, naming the half the pointer "
                    "holds — the durable evidence half of the act",
        },
        {
            "name": "client-b-relink-epoch-2",
            "record": linked_client(
                CLIENT_B, CLIENT_B_KEY_R2, ["codex"], 2,
                hours_after(REVOCATION_STORY_FROM, 3)),
            "expected": OUTCOME_ACCEPTED,
            "note": "the pointer that completes the revocation: a "
                    "strictly higher epoch at a new key (EC-12) — after "
                    "this lands, an attempt presenting the revoked "
                    "epoch is stale whatever its signature does",
        },
        {
            "name": "client-b-stale-replay-epoch-1",
            "record": linked_client(
                CLIENT_B, CLIENT_B_KEY, ["codex"], 1, REVOCATION_STORY_FROM),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_STALE,
            "note": "the byte-identical replay of the revoked epoch's "
                    "pointer: the signature still verifies and the "
                    "epoch rule alone rejects — the plan's Phase 3 exit "
                    "gate, that a revoked epoch cannot be presented "
                    "back into standing",
        },
        {
            "name": "client-b-forward-dated-revocation-epoch-5",
            "record": revocation(
                CLIENT_B, CLIENT_B_KEY_R2, 5,
                hours_after(REVOCATION_STORY_FROM, 6)),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_UNREACHED,
            "note": "a revocation two epochs past the standing pointer: "
                    "one cannot pre-revoke an epoch the client has not "
                    "reached, because a forward-dated revocation would "
                    "arm itself against a legitimate later rotation",
        },
        {
            "name": "client-b-revocation-wrong-half-epoch-2",
            "record": revocation(
                CLIENT_B, CLIENT_B_KEY, 2,
                hours_after(REVOCATION_STORY_FROM, 7)),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_KEY_MISMATCH,
            "note": "revoking the current epoch while naming the "
                    "retired half: the pointer holds r2's key, the "
                    "record names the epoch-1 half — revoked_key_id is "
                    "the key_id the linked-client record held at that "
                    "epoch, and it is cross-checked",
        },
        {
            "name": "client-b-revocation-rewrite-epoch-1",
            "record": revocation(
                CLIENT_B, CLIENT_B_KEY_R2, 1,
                hours_after(REVOCATION_STORY_FROM, 8)),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_INTEGRITY,
            "note": "a different revocation at the first one's derived "
                    "key (same client, same epoch, a different "
                    "revoked_key_id): an immutable record is written "
                    "once, and an incompatible object at a derived key "
                    "is an integrity conflict, never an overwrite "
                    "(EC-06) — no operation removes or supersedes a "
                    "revocation",
        },
    ]


def rotation_history() -> list[dict]:
    """The client key-rotation act's two halves plus the rejects
    (docs/notes/control-trust-schemas.md, the key-rotation record): the
    pointer bump and the immutable evidence record are one
    administrative act, a byte-identical retry lands again as an
    idempotent repair, an incompatible rewrite is an integrity
    conflict, a rotation whose new half is not the standing pointer's
    is a pointer-key mismatch, a forward-dated rotation is rejected
    before it can arm its overlap window early — and the 24-hour
    ``attempt_acceptance`` table pins which half verifies when."""
    window_anchor = hours_after(ROTATION_STORY_FROM, 1)
    return [
        {
            "name": "client-a-link-epoch-1",
            "record": linked_client(
                CLIENT_A, CLIENT_A_KEY, ["claude-code"], 1,
                ROTATION_STORY_FROM),
            "expected": OUTCOME_ACCEPTED,
            "note": "the link at the epoch-1 key",
        },
        {
            "name": "client-a-pointer-epoch-2",
            "record": linked_client(
                CLIENT_A, CLIENT_A_KEY_R2, ["claude-code"], 2, window_anchor),
            "expected": OUTCOME_ACCEPTED,
            "note": "the pointer half of the rotation act: one "
                    "administrative act publishes the higher-epoch "
                    "pointer naming the new key and the evidence record "
                    "at the epoch it establishes",
        },
        {
            "name": "client-a-rotation-epoch-2",
            "record": rotation(
                CLIENT_A, CLIENT_A_KEY, 1, CLIENT_A_KEY_R2, 2, window_anchor),
            "expected": OUTCOME_ACCEPTED,
            "note": "the evidence half: adjacent epochs, both public "
                    "halves, both key IDs recomputable from the record "
                    "itself — the material a stateless replica needs to "
                    "verify an old-half attempt inside the overlap "
                    "without any server-local state",
        },
        {
            "name": "client-a-rotation-replay-epoch-2",
            "record": rotation(
                CLIENT_A, CLIENT_A_KEY, 1, CLIENT_A_KEY_R2, 2, window_anchor),
            "expected": OUTCOME_ACCEPTED,
            "note": "the byte-identical retry of the evidence record: a "
                    "lost response, not an overwrite — identical bytes "
                    "at a derived key are an idempotent repair",
        },
        {
            "name": "client-a-rotation-rewrite-epoch-2",
            "record": rotation(
                CLIENT_A, CLIENT_A_KEY, 1, CLIENT_A_KEY_R2, 2,
                hours_after(ROTATION_STORY_FROM, 2)),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_INTEGRITY,
            "note": "different bytes at the rotation's derived key "
                    "(same client, same established epoch, a re-dated "
                    "signed_at): an immutable record is written once "
                    "(EC-06), and re-dating a rotation after the fact "
                    "is exactly what immutability forbids",
        },
        {
            "name": "client-a-pointer-epoch-3",
            "record": linked_client(
                CLIENT_A, CLIENT_A_KEY_R3, ["claude-code", "codex"], 3,
                hours_after(ROTATION_STORY_FROM, 5)),
            "expected": OUTCOME_ACCEPTED,
            "note": "a scope revision, itself a pointer move: the "
                    "standing half is now r3's, which the next member "
                    "tests the rotation rule against",
        },
        {
            "name": "client-a-rotation-mismatch-epoch-3",
            "record": rotation(
                CLIENT_A, CLIENT_A_KEY_R2, 2, CLIENT_A_KEY, 3,
                hours_after(ROTATION_STORY_FROM, 5)),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_POINTER_MISMATCH,
            "note": "the evidence record names the wrong new half — the "
                    "epoch-1 key, not the half the standing pointer "
                    "carries: the record and the pointer bump that "
                    "activates it are one administrative act, so the "
                    "pointer at the established epoch must hold this "
                    "record's public_key",
        },
        {
            "name": "client-a-rotation-ahead-epoch-5",
            "record": rotation(
                CLIENT_A, CLIENT_A_KEY_R3, 4, CLIENT_A_KEY_R4, 5,
                hours_after(ROTATION_STORY_FROM, 7)),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_UNREACHED,
            "note": "a rotation for an epoch boundary the pointer never "
                    "reached: one cannot pre-date a rotation, because a "
                    "forward-dated rotation would arm its overlap "
                    "window early",
        },
    ]


def rotation_attempt_acceptance(rotation_record: dict,
                                anchor: str) -> list[dict]:
    """The 24-hour overlap table: which half may sign an attempt at the
    standing epoch, at pinned instants around the rotation. The window
    runs from the rotation record's signed_at through
    rotationVerificationOverlapHours (24) later, inclusive of its last
    instant — the widening covers retries of already-frozen envelopes
    and never widens which epoch is current."""
    old_key_id = rotation_record["previous_key_id"]
    new_key_id = rotation_record["key_id"]
    return [
        {
            "key_id": old_key_id,
            "signed_at": hours_after(anchor, 2),
            "expected": OUTCOME_ACCEPTED,
            "note": "inside the overlap: a retry of an already-frozen "
                    "envelope re-authorizes under the old half instead "
                    "of stranding in the spool (EC-12)",
        },
        {
            "key_id": new_key_id,
            "signed_at": anchor,
            "expected": OUTCOME_ACCEPTED,
            "note": "the new half verifies from the rotation instant "
                    "and never stops",
        },
        {
            "key_id": old_key_id,
            "signed_at": hours_after(anchor, 24),
            "expected": OUTCOME_ACCEPTED,
            "note": "the overlap includes its last instant",
        },
        {
            "key_id": old_key_id,
            "signed_at": seconds_after(hours_after(anchor, 24), 1),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_OUTSIDE_OVERLAP,
            "note": "one second past the overlap the old half no "
                    "longer verifies: the window bounds signing "
                    "acceptance at the record's own signed_at, never "
                    "what was already signed",
        },
        {
            "key_id": new_key_id,
            "signed_at": days_after(anchor, 30),
            "expected": OUTCOME_ACCEPTED,
            "note": "long after the window: the standing half is simply "
                    "the current key",
        },
    ]


def receipt_key_history() -> list[dict]:
    """The tenant authority's receipt-key certification cohort
    (docs/notes/control-trust-schemas.md, the receipt-key record): a
    fresh key every receiptKeyRotationDays (30), each valid exactly
    receiptKeyRotationDays + receiptKeySigningOverlapDays (37 days), the
    idempotent retry accepted, a window that does not chain rejected,
    a key ID that is not the derivation of the record's own half
    rejected, and an incompatible rewrite rejected."""
    return [
        {
            "name": "receipt-key-one-certified",
            "record": receipt_key(
                RECEIPT_KEY_ONE, RECEIPT_COHORT_FROM,
                days_after(RECEIPT_COHORT_FROM, 37), RECEIPT_COHORT_FROM),
            "expected": OUTCOME_ACCEPTED,
            "note": "the cohort's first certification: valid_from "
                    "anchors the signing window inside the signed "
                    "bytes, the span is exactly the summed 37 days, and "
                    "signed_at opens no later than the window does",
        },
        {
            "name": "receipt-key-one-retry-identical",
            "record": receipt_key(
                RECEIPT_KEY_ONE, RECEIPT_COHORT_FROM,
                days_after(RECEIPT_COHORT_FROM, 37), RECEIPT_COHORT_FROM),
            "expected": OUTCOME_ACCEPTED,
            "note": "the byte-identical retry of the certification: an "
                    "idempotent repair at the same key-addressed "
                    "object, never an overwrite",
        },
        {
            "name": "receipt-key-two-certified",
            "record": receipt_key(
                RECEIPT_KEY_TWO, days_after(RECEIPT_COHORT_FROM, 30),
                days_after(RECEIPT_COHORT_FROM, 67),
                days_after(RECEIPT_COHORT_FROM, 30)),
            "expected": OUTCOME_ACCEPTED,
            "note": "the successor: valid_from exactly 30 days after "
                    "its predecessor's (receiptKeyRotationDays), the "
                    "same 37-day span — for seven days "
                    "(receiptKeySigningOverlapDays) both halves sign "
                    "and the signer is never without a valid key across "
                    "the boundary",
        },
        {
            "name": "receipt-key-discontinuous-window",
            "record": receipt_key(
                RECEIPT_KEY_THREE, days_after(RECEIPT_COHORT_FROM, 31),
                days_after(RECEIPT_COHORT_FROM, 68),
                days_after(RECEIPT_COHORT_FROM, 31)),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_WINDOW_DISCONTINUITY,
            "note": "valid_from one day off the 30-day cadence: a "
                    "reader re-makes the chaining check from the two "
                    "records alone (VAL-002), and a window that does "
                    "not chain to the predecessor's is rejected",
        },
        {
            "name": "receipt-key-mismatched-id",
            "record": re_signed(
                receipt_key(
                    RECEIPT_KEY_THREE, RECEIPT_COHORT_FROM,
                    days_after(RECEIPT_COHORT_FROM, 37),
                    RECEIPT_COHORT_FROM),
                AUTHORITY, key_id="0" * 64),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_KEY_MISMATCH,
            "note": "the certified key ID is not the pinned derivation "
                    "of the record's own public_key — the check every "
                    "verifier re-makes from the record itself, "
                    "independent of the signature, which verifies and "
                    "is not the thing that rejects",
        },
        {
            "name": "receipt-key-one-rewrite",
            "record": receipt_key(
                RECEIPT_KEY_ONE, RECEIPT_COHORT_FROM,
                days_after(RECEIPT_COHORT_FROM, 36), RECEIPT_COHORT_FROM),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_INTEGRITY,
            "note": "different bytes at the certification's key-addressed "
                    "object (a shortened window): rotation is "
                    "non-invalidating precisely because nothing rewrites "
                    "a predecessor — every certificate ever issued keeps "
                    "verifying (ID-009)",
        },
    ]


def receipt_key_signing_acceptance() -> list[dict]:
    """The cohort's signing-acceptance table: whether a receipt key may
    sign at a pinned instant, decided against its own
    [valid_from, valid_until] window. The windows bound signing, never
    the verification of retained receipts, which never expires
    (ID-009)."""
    return [
        {
            "key_id": RECEIPT_KEY_ONE.key_id,
            "signed_at": days_after(RECEIPT_COHORT_FROM, 14),
            "expected": OUTCOME_ACCEPTED,
            "note": "mid-window under key one alone",
        },
        {
            "key_id": RECEIPT_KEY_ONE.key_id,
            "signed_at": days_after(RECEIPT_COHORT_FROM, -1),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_OUTSIDE_SIGNING,
            "note": "before the window opens: the certification does "
                    "not backdate signing",
        },
        {
            "key_id": RECEIPT_KEY_TWO.key_id,
            "signed_at": days_after(RECEIPT_COHORT_FROM, 30),
            "expected": OUTCOME_ACCEPTED,
            "note": "the successor's first signing instant",
        },
        {
            "key_id": RECEIPT_KEY_ONE.key_id,
            "signed_at": days_after(RECEIPT_COHORT_FROM, 33),
            "expected": OUTCOME_ACCEPTED,
            "note": "the overlap: key one signs seven days past key "
                    "two's first instant",
        },
        {
            "key_id": RECEIPT_KEY_TWO.key_id,
            "signed_at": days_after(RECEIPT_COHORT_FROM, 33),
            "expected": OUTCOME_ACCEPTED,
            "note": "the other half of the overlap: both sign",
        },
        {
            "key_id": RECEIPT_KEY_ONE.key_id,
            "signed_at": days_after(RECEIPT_COHORT_FROM, 37),
            "expected": OUTCOME_ACCEPTED,
            "note": "the window includes its last instant",
        },
        {
            "key_id": RECEIPT_KEY_ONE.key_id,
            "signed_at": seconds_after(days_after(RECEIPT_COHORT_FROM, 37), 1),
            "expected": OUTCOME_REJECTED,
            "reason": REASON_OUTSIDE_SIGNING,
            "note": "one second past valid_until the key no longer "
                    "signs; a receipt it already signed keeps verifying",
        },
    ]


# ---------------------------------------------------------------------------
# Decision procedure — the replay any language performs
# ---------------------------------------------------------------------------


def decide(history: list[dict],
           keys_by_id: dict[str, str]) -> list[dict]:
    """Replay the corpus decision procedure — the store fold — over one
    history in order.

    1. the record's canonical bytes (authority_signature removed) are
       what the signature covers — already proven member-for-member by
       the canonical_bytes_sha256 pin;
    2. the signature must verify against the public half keys.json
       holds for the record's own authority_key_id — a key the table
       does not hold, or a signature that fails against it, is the
       untrusted-signer rejection, and the decision ends there;
    3. a current-pointer record (linked-client, delegation) is accepted
       iff no pointer stands at the subject key yet, or the signed
       epoch strictly exceeds the standing one — otherwise stale-epoch;
    4. an immutable record (rotation, revocation, receipt-key) is
       written once at its derived key: a byte-identical retry lands
       again as an idempotent repair, and an incompatible object at the
       same derived key is integrity-conflict (EC-06). The type's own
       cross-record checks then decide (epoch-unreached,
       key-id-mismatch, pointer-key-mismatch, window-discontinuity);
    5. acceptance moves the state — a pointer to this record's epoch
       and half, an immutable object to these bytes.
    """
    pointers: dict[str, tuple[int, str | None]] = {}
    immutable: dict[str, str] = {}
    last_receipt: dict | None = None
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
        record_type = record["record_type"]
        if record_type in ("linked-client", "delegation"):
            epoch = record["authorization_epoch"]
            if key in pointers and epoch <= pointers[key][0]:
                outcomes.append({"name": entry["name"],
                                 "outcome": OUTCOME_REJECTED,
                                 "reason": REASON_STALE})
            else:
                pointers[key] = (epoch, record.get("key_id"))
                outcomes.append({"name": entry["name"],
                                 "outcome": OUTCOME_ACCEPTED,
                                 "reason": None})
            continue
        # Immutable write classes: one object per derived key, written
        # once. A byte-identical retry is an idempotent repair; any
        # other bytes at the same derived key are an integrity conflict.
        digest = hashlib.sha256(canonical_bytes(record)).hexdigest()
        if key in immutable:
            rejected = immutable[key] != digest
            outcomes.append({"name": entry["name"],
                             "outcome": OUTCOME_REJECTED
                             if rejected else OUTCOME_ACCEPTED,
                             "reason": REASON_INTEGRITY if rejected else None})
            continue
        # The revocation and rotation cross-record checks read the
        # subject client's standing pointer — the linked-client object
        # key — not the record's own derived key, which no pointer ever
        # occupies.
        standing = pointers.get(
            client_pointer_key(record)
            if record_type in ("revocation", "rotation") else key)
        if record_type == "revocation":
            epoch = record["authorization_epoch"]
            if standing is None or epoch > standing[0]:
                reason = REASON_UNREACHED
            elif standing[1] != record["revoked_key_id"]:
                reason = REASON_KEY_MISMATCH
            else:
                reason = None
        elif record_type == "rotation":
            epoch = record["authorization_epoch"]
            if standing is None or epoch > standing[0]:
                reason = REASON_UNREACHED
            elif standing[1] != record["key_id"]:
                reason = REASON_POINTER_MISMATCH
            else:
                reason = None
        else:  # receipt-key: key-addressed, no epoch, window chaining
            reason = None
            if record["key_id"] != key_id_of(record["public_key"]):
                reason = REASON_KEY_MISMATCH
            elif last_receipt is not None and (
                    record["valid_from"]
                    != days_after(last_receipt["valid_from"], 30)
                    or record["valid_until"]
                    != days_after(record["valid_from"], 37)):
                reason = REASON_WINDOW_DISCONTINUITY
        if reason is None:
            immutable[key] = digest
            if record_type == "receipt-key":
                last_receipt = record
            outcomes.append({"name": entry["name"],
                             "outcome": OUTCOME_ACCEPTED,
                             "reason": None})
        else:
            outcomes.append({"name": entry["name"],
                             "outcome": OUTCOME_REJECTED,
                             "reason": reason})
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


def client_pointer_key(record: dict) -> str:
    """The linked-client object key for the (tenant, client) a revocation
    or rotation record addresses — the standing pointer its cross-record
    checks read, distinct from the record's own derived key, which no
    pointer ever occupies."""
    return record_object_key({
        "record_type": "linked-client",
        "tenant_id": record["tenant_id"],
        "client_id": record["client_id"],
    })


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
REVOCATION_TITLED = "Revocation and relink conformance vectors"
ROTATION_TITLED = "Client key-rotation overlap conformance vectors"
RECEIPT_KEYS_TITLED = "Receipt-key certification cohort conformance vectors"

DECISION_PROCEDURE = [
    "recompute the record's canonical bytes: RFC 8785 over the complete "
    "record object with the authority_signature member removed; their "
    "SHA-256 must equal the entry's canonical_bytes_sha256",
    "look up the public half in keys.json by the record's own "
    "authority_key_id and verify the Ed25519 signature over those "
    "canonical bytes; failure is rejected/untrusted-signer and the "
    "decision ends there",
    "a current-pointer record (linked-client, delegation) is accepted "
    "iff no pointer stands at the subject's object key yet, or the "
    "signed authorization_epoch strictly exceeds the standing epoch; "
    "any other epoch is rejected/stale-epoch",
    "an immutable record (rotation, revocation, receipt-key) is written "
    "once at its derived key: a byte-identical retry lands again as an "
    "idempotent repair; an incompatible object at the same derived key "
    "is rejected/integrity-conflict (EC-06), and no operation removes "
    "or rewrites one",
    "a revocation is accepted only when its revoked epoch does not "
    "exceed the client pointer's current signed epoch — one cannot "
    "pre-revoke an epoch the client has not reached "
    "(rejected/epoch-unreached) — and names the half the pointer holds "
    "(rejected/key-id-mismatch); it completes by publishing a strictly "
    "higher-epoch linked-client record, after which a replay of the "
    "revoked epoch's pointer is rejected/stale-epoch",
    "a rotation is accepted only when the established epoch does not "
    "exceed the standing pointer's (rejected/epoch-unreached: a "
    "forward-dated rotation would arm its overlap window early) and the "
    "standing pointer's half is this record's new half "
    "(rejected/pointer-key-mismatch); previous_epoch is the adjacent "
    "epoch, and the record and the pointer bump that activates it are "
    "one administrative act",
    "a receipt-key certification's key_id must be the pinned derivation "
    "of the record's own public_key (rejected/key-id-mismatch), and its "
    "window must chain to the cohort's predecessor: valid_from exactly "
    "receiptKeyRotationDays (30 days) after the predecessor's and "
    "valid_until exactly receiptKeySigningOverlapDays (7 days) past "
    "valid_from (rejected/window-discontinuity); signed_at opens no "
    "later than the window does",
    "acceptance moves the state — a pointer to this record's epoch and "
    "half, an immutable object to these bytes — and a full history's "
    "fold must land on this file's final_state",
    "an acceptance table decides (key half, instant) pairs against the "
    "pinned window: the key-rotation file's attempt_acceptance against "
    "rotationVerificationOverlapHours (24 hours) from the rotation "
    "record's signed_at, inclusive of the window's last instant; the "
    "receipt-key cohort's signing_acceptance against each certified "
    "key's [valid_from, valid_until]. Outside its window a previous "
    "half is rejected/outside-overlap and a receipt key is "
    "rejected/outside-signing-window — the window bounds signing "
    "acceptance, never the validity of what was already signed",
]

OUTCOME_VOCABULARY = {
    OUTCOME_ACCEPTED: "the write lands; a pointer moves to this record's "
                      "epoch and half, an immutable object to these bytes",
    OUTCOME_REJECTED: "the store refuses the write",
    REASON_STALE: "the signed epoch does not strictly increase over the "
                  "standing pointer (the storage family's own closed "
                  "error-class token: crates/archivist-storage/src/"
                  "error.rs, StorageErrorKind::StaleEpoch)",
    REASON_UNTRUSTED: "the authority signature does not verify against "
                      "the key the record's own authority_key_id names",
    REASON_INTEGRITY: "an incompatible object at an immutable record's "
                      "derived key (the storage family's own closed "
                      "error-class token: StorageErrorKind::"
                      "IntegrityConflict); a byte-identical retry would "
                      "have been an idempotent repair",
    REASON_UNREACHED: "the record's epoch lies past the standing "
                      "pointer's: no forward-dated revocation or "
                      "rotation, because either would arm itself "
                      "against a legitimate later act",
    REASON_KEY_MISMATCH: "the record names a half the standing pointer "
                         "does not hold (a revocation's revoked_key_id) "
                         "or a key_id that is not the pinned derivation "
                         "of the record's own public_key (a receipt-key "
                         "certification)",
    REASON_POINTER_MISMATCH: "the rotation's new half is not the half "
                             "the standing pointer at the established "
                             "epoch carries — the record and the pointer "
                             "bump are one administrative act",
    REASON_WINDOW_DISCONTINUITY: "the certification window does not "
                                 "chain to the predecessor's: valid_from "
                                 "not exactly receiptKeyRotationDays (30 "
                                 "days) on, or valid_until not exactly "
                                 "valid_from + receiptKeySigningOverlapDays "
                                 "(7 days)",
    REASON_OUTSIDE_OVERLAP: "a previous-half attempt after "
                            "rotationVerificationOverlapHours (24) from "
                            "the rotation record's signed_at: the overlap "
                            "includes its last instant and nothing beyond",
    REASON_OUTSIDE_SIGNING: "an instant outside the certified key's own "
                            "[valid_from, valid_until] window: bounds "
                            "signing only — a receipt already signed "
                            "keeps verifying (ID-009)",
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
        "rotation_verification_overlap_hours": 24,
        "receipt_key_rotation_days": 30,
        "receipt_key_signing_overlap_days": 7,
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


CORPUS_KEYS: tuple = (
    AUTHORITY, CLIENT_A_KEY, CLIENT_B_KEY,
    CLIENT_A_KEY_R2, CLIENT_A_KEY_R3, CLIENT_A_KEY_R4,
    CLIENT_B_KEY_R2,
    RECEIPT_KEY_ONE, RECEIPT_KEY_TWO, RECEIPT_KEY_THREE,
)


def keys_by_id_map(keys: tuple | None = None) -> dict[str, str]:
    """The public-half table keys.json holds, keyed by key_id."""
    return {key.key_id: key.public_key
            for key in (keys if keys is not None else CORPUS_KEYS)}


def _story_outcomes(history: list[dict]) -> list[dict]:
    """The fold's outcomes for one scenario's story, against the full
    corpus key table."""
    return decide(history, keys_by_id_map())


def days_between(start: str, end: str) -> int:
    """Whole days between two pinned RFC 3339 UTC timestamps."""
    from datetime import datetime

    a = datetime.fromisoformat(start.replace("Z", "+00:00"))
    b = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return (b - a).days


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


def _subject_pins(history: list[dict], outcomes: list[dict]) -> dict:
    """The object keys the story touches, each pinned with the members
    that name it — derived from the history itself so the pins cannot
    drift from the records."""
    pins: dict[str, dict] = {}
    for entry, outcome in zip(history, outcomes):
        record = entry["record"]
        record_type = record["record_type"]
        pin: dict = {}
        if record_type in ("linked-client", "delegation", "rotation",
                           "revocation"):
            pin["authorization_epoch"] = record["authorization_epoch"]
        if record_type != "receipt-key" and "client_id" in record:
            pin["client_id"] = record["client_id"]
        if record_type == "receipt-key":
            pin["key_id"] = record["key_id"]
        pins[record_object_key(record)] = pin
    return pins


def build_revocation() -> dict:
    history = [history_entry(**member) for member in revocation_history()]
    outcomes = _story_outcomes(history)
    client_key = record_object_key({
        "record_type": "linked-client", "tenant_id": TENANT,
        "client_id": CLIENT_B,
    })
    return {
        "$schema": URN_REVOCATION,
        "title": REVOCATION_TITLED,
        "description": (
            "Language-neutral, byte-pinned vectors for the revocation "
            "record and the pointer that completes it (docs/notes/"
            "control-trust.md item 4; ID-006): epoch-addressed and "
            "immutable, one object per (client, revoked epoch), the "
            "store accepts it only at the standing epoch — one cannot "
            "pre-revoke an epoch the client has not reached — and the "
            "act completes by publishing a strictly higher-epoch "
            "linked-client record at a new key (EC-12). After the "
            "pointer moves, a replay of the revoked epoch's pointer is "
            "stale even though its authority signature verifies: the "
            "plan's Phase 3 exit gate. No operation removes or "
            "supersedes a revocation; an incompatible object at its "
            "derived key is an integrity conflict, and propagation is "
            "bounded by the reader's 60-second trust cache (EC-09), "
            "never by anything in the record. Any implementation "
            "replays this offline with no server: read keys.json, walk "
            "history in order applying the generation block's decision "
            "procedure, and require every computed outcome to equal "
            "the entry's expected (and reason), with the fold landing "
            "on final_state."),
        "generation": generation_block(),
        "pinned": {
            "tenant_id": TENANT,
            "authority_key_id": AUTHORITY.key_id,
            "client_id": CLIENT_B,
            "subjects": _subject_pins(history, outcomes),
        },
        "history": history,
        "final_state": {
            client_key: {"authorization_epoch": 2,
                         "record": "client-b-relink-epoch-2"},
            record_object_key({
                "record_type": "revocation", "tenant_id": TENANT,
                "client_id": CLIENT_B, "authorization_epoch": 1,
            }): {"authorization_epoch": 1,
                 "record": "client-b-revocation-epoch-1"},
        },
    }


def build_rotation() -> dict:
    history = [history_entry(**member) for member in rotation_history()]
    outcomes = _story_outcomes(history)
    rotation_entry = next(entry for entry in history
                          if entry["name"] == "client-a-rotation-epoch-2")
    anchor = rotation_entry["record"]["signed_at"]
    attempt_acceptance = rotation_attempt_acceptance(
        rotation_entry["record"], anchor)
    client_key = record_object_key({
        "record_type": "linked-client", "tenant_id": TENANT,
        "client_id": CLIENT_A,
    })
    return {
        "$schema": URN_ROTATION,
        "title": ROTATION_TITLED,
        "description": (
            "Language-neutral, byte-pinned vectors for the client "
            "key-rotation act (docs/notes/control-trust.md item 3; "
            "plan Section 5): the pointer bump and the immutable "
            "evidence record are one administrative act, the record "
            "carries both public halves at adjacent epochs so a "
            "stateless replica verifies an old-half attempt inside the "
            "overlap from the record alone, and enforcement rides the "
            "pointer — a forward-dated rotation is rejected before it "
            "can arm its window early, and a rotation whose new half "
            "is not the standing pointer's is rejected. The "
            "attempt_acceptance table pins the window itself: for "
            "rotationVerificationOverlapHours (24) from the record's "
            "signed_at an attempt at the current epoch may sign with "
            "either half, the overlap inclusive of its last instant, "
            "and one second later the old half is rejected/"
            "outside-overlap — the window bounds signing acceptance, "
            "never what was already signed. Any implementation "
            "replays this offline with no server: read keys.json, walk "
            "history in order applying the generation block's decision "
            "procedure, then evaluate attempt_acceptance against the "
            "window; every computed outcome must equal the pinned "
            "expected (and reason), with the fold landing on "
            "final_state."),
        "generation": generation_block(),
        "pinned": {
            "tenant_id": TENANT,
            "authority_key_id": AUTHORITY.key_id,
            "client_id": CLIENT_A,
            "rotation_record": "client-a-rotation-epoch-2",
            "subjects": _subject_pins(history, outcomes),
        },
        "history": history,
        "attempt_acceptance": attempt_acceptance,
        "final_state": {
            client_key: {"authorization_epoch": 3,
                         "record": "client-a-pointer-epoch-3"},
            record_object_key({
                "record_type": "rotation", "tenant_id": TENANT,
                "client_id": CLIENT_A, "authorization_epoch": 2,
            }): {"authorization_epoch": 2,
                 "record": "client-a-rotation-epoch-2"},
        },
    }


def build_receipt_keys() -> dict:
    history = [history_entry(**member) for member in receipt_key_history()]
    outcomes = _story_outcomes(history)
    # The accepted certifications, deduplicated by certified key in
    # first-seen order — the byte-identical retry is the same member of
    # the cohort, not a second one.
    certified: dict[str, dict] = {}
    for entry, outcome in zip(history, outcomes):
        record = entry["record"]
        if (record["record_type"] == "receipt-key"
                and outcome["reason"] is None
                and record["key_id"] not in certified):
            certified[record["key_id"]] = record
    cohort = list(certified.values())
    # The cohort's chaining arithmetic, stated on the accepted records:
    # every span is exactly the two named constants summed, and every
    # successor's valid_from sits exactly receiptKeyRotationDays after
    # its predecessor's.
    spans = {record["key_id"]:
             days_between(record["valid_from"], record["valid_until"])
             for record in cohort}
    gaps = [days_between(predecessor["valid_from"], record["valid_from"])
            for predecessor, record in zip(cohort, cohort[1:])]
    return {
        "$schema": URN_RECEIPT_KEYS,
        "title": RECEIPT_KEYS_TITLED,
        "description": (
            "Language-neutral, byte-pinned vectors for the receipt-key "
            "certification cohort (docs/notes/control-trust.md item 6; "
            "plan Section 7.8; ID-009): the tenant authority certifies "
            "a fresh receipt-signing key every receiptKeyRotationDays "
            "(30), each valid exactly receiptKeyRotationDays + "
            "receiptKeySigningOverlapDays (37 days), so successor and "
            "predecessor overlap for seven days of signing continuity "
            "and the signer is never without a valid key across a "
            "boundary. Certification is key-addressed and immutable — "
            "rotation is non-invalidating because nothing rewrites a "
            "predecessor, and verification of retained receipts never "
            "expires. The signing_acceptance table pins the windows "
            "themselves: each key signs from its valid_from through "
            "valid_until and not outside, which bounds signing, never "
            "the verification of what was already signed. Any "
            "implementation replays this offline with no server: read "
            "keys.json, walk history in order applying the generation "
            "block's decision procedure, then evaluate "
            "signing_acceptance against the records' windows; every "
            "computed outcome must equal the pinned expected (and "
            "reason), with the fold landing on final_state."),
        "generation": generation_block(),
        "pinned": {
            "tenant_id": TENANT,
            "authority_key_id": AUTHORITY.key_id,
            "subjects": _subject_pins(history, outcomes),
            "certified_cohort": [
                {"name": next(entry["name"] for entry, outcome
                              in zip(history, outcomes)
                              if entry["record"] is record),
                 "key_id": record["key_id"],
                 "valid_from": record["valid_from"],
                 "valid_until": record["valid_until"],
                 "span_days": spans[record["key_id"]]}
                for record in cohort
            ],
            "successor_gaps_days": gaps,
        },
        "history": history,
        "signing_acceptance": receipt_key_signing_acceptance(),
        "final_state": {
            record_object_key({
                "record_type": "receipt-key", "tenant_id": TENANT,
                "key_id": key_id,
            }): {"key_id": key_id,
                 "record": "receipt-key-two-certified"
                 if key_id == RECEIPT_KEY_TWO.key_id
                 else "receipt-key-one-certified"}
            for key_id in (RECEIPT_KEY_ONE.key_id, RECEIPT_KEY_TWO.key_id)
        },
    }


# ---------------------------------------------------------------------------
# The authority-rotation chain (subsumed sibling bundle)
#
# The chain deployment landed first (closed aa-9d88f29c) with its own
# synthetic tenant and its own seeds — one repeated byte each, pinned
# in its generation block. Subsuming it into this generator means the
# committed bytes are reproduced from those documented seeds alone; the
# one correction is documentation: the fifth seed (0x04, the stranger
# the unreachable sample names) was never listed, which made the
# committed bundle unreproducible from its own generation block.
# ---------------------------------------------------------------------------

CHAIN_TENANT = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d"
CHAIN_OVERLAP_NANOS = 24 * 3600 * 1_000_000_000


class ChainSeedKey(DerivedSigningKey):
    """An authority-chain deployment key: derived from its documented
    seed byte repeated 32 times."""

    def __init__(self, seed_byte: int, role: str):
        self.seed_note = f"0x{seed_byte:02x}"
        super().__init__(bytes([seed_byte]) * 32, role)


CHAIN_ROOT = ChainSeedKey(0x01, "tenant-authority-root")
CHAIN_SUCCESSOR_ONE = ChainSeedKey(0x02, "tenant-authority-successor")
CHAIN_SUCCESSOR_TWO = ChainSeedKey(0x03, "tenant-authority-successor")
CHAIN_STRANGER = ChainSeedKey(0x04, "unreachable-signer")
# The receipt-signing half every chain sample record certifies; the
# samples pin the acceptance decision around a mid-window rotation, so
# they carry the minimal shape that decision reads.
CHAIN_RECEIPT_HALF = ChainSeedKey(0x5C, "receipt-signer")


def chain_authority_rotation(previous: ChainSeedKey, new: ChainSeedKey,
                             signed_at: str) -> dict:
    """One chain link: the predecessor's signed witness to its own
    retirement, at the predecessor's own address."""
    record = {
        "schema": NAMESPACE,
        "record_type": "authority-rotation",
        "record_kind": "immutable",
        "tenant_id": CHAIN_TENANT,
        "previous_public_key": previous.public_key,
        "previous_key_id": previous.key_id,
        "key_algorithm": "ed25519",
        "public_key": new.public_key,
        "key_id": new.key_id,
        "signed_at": signed_at,
        "authority_key_id": previous.key_id,
    }
    return sign_record(record, previous)


def chain_receipt_sample(authority: ChainSeedKey, signed_at: str) -> dict:
    """One minimal receipt-key sample: the acceptance decision's input
    around the mid-window rotation, signed by whichever authority half
    held at that instant."""
    record = {
        "schema": NAMESPACE,
        "record_type": "receipt-key",
        "record_kind": "immutable",
        "tenant_id": CHAIN_TENANT,
        "key_algorithm": "ed25519",
        "key_id": CHAIN_RECEIPT_HALF.key_id,
        "signed_at": signed_at,
        "authority_key_id": authority.key_id,
    }
    return sign_record(record, authority)


CHAIN_LINKS = (
    {
        "name": "root-retires",
        "previous": CHAIN_ROOT,
        "new": CHAIN_SUCCESSOR_ONE,
        "signed_at": "2026-09-10T00:00:00Z",
    },
    {
        "name": "successor-retires",
        "previous": CHAIN_SUCCESSOR_ONE,
        "new": CHAIN_SUCCESSOR_TWO,
        "signed_at": "2026-09-12T00:00:00Z",
    },
)

CHAIN_SAMPLES = (
    {
        "name": "root-signed-before-rotation",
        "authority": CHAIN_ROOT,
        "signed_at": "2026-09-09T23:00:00Z",
        "expected": "accepted",
    },
    {
        "name": "root-signed-at-overlap-end",
        "authority": CHAIN_ROOT,
        "signed_at": "2026-09-11T00:00:00Z",
        "expected": "accepted",
    },
    {
        "name": "root-signed-past-overlap",
        "authority": CHAIN_ROOT,
        "signed_at": "2026-09-11T00:00:01Z",
        "expected": "retired",
    },
    {
        "name": "successor-signed-at-establishment",
        "authority": CHAIN_SUCCESSOR_ONE,
        "signed_at": "2026-09-10T00:00:00Z",
        "expected": "accepted",
    },
    {
        "name": "stranger-key-unreachable",
        "authority": CHAIN_STRANGER,
        "signed_at": "2026-09-20T00:00:00Z",
        "expected": "unreachable",
    },
)

# The pinned acceptance verdict for every (signer, signed_at) pair:
# accepted while the half holds, retired after its successor's window
# closes it, not_established before its own, unreachable for a signer
# no link reaches.
CHAIN_ACCEPTANCE = (
    {
        "signer": CHAIN_ROOT,
        "signed_at": "2026-09-09T23:00:00Z",
        "expected": "accepted",
    },
    {
        "signer": CHAIN_ROOT,
        "signed_at": "2026-09-10T00:00:00Z",
        "expected": "accepted",
    },
    {
        "signer": CHAIN_ROOT,
        "signed_at": "2026-09-10T12:00:00Z",
        "expected": "accepted",
        "note": "mid-window: either half signs",
    },
    {
        "signer": CHAIN_SUCCESSOR_ONE,
        "signed_at": "2026-09-10T12:00:00Z",
        "expected": "accepted",
        "note": "mid-window: the successor half",
    },
    {
        "signer": CHAIN_ROOT,
        "signed_at": "2026-09-11T00:00:00Z",
        "expected": "accepted",
        "note": "the overlap includes its last instant",
    },
    {
        "signer": CHAIN_ROOT,
        "signed_at": "2026-09-11T00:00:00.000000001Z",
        "expected": "retired",
        "note": "one nanosecond past the overlap fails closed",
    },
    {
        "signer": CHAIN_ROOT,
        "signed_at": "2026-09-12T00:00:00Z",
        "expected": "retired",
    },
    {
        "signer": CHAIN_SUCCESSOR_ONE,
        "signed_at": "2026-09-09T23:59:59.999999999Z",
        "expected": "not_established",
    },
    {
        "signer": CHAIN_SUCCESSOR_ONE,
        "signed_at": "2026-09-12T00:00:00Z",
        "expected": "accepted",
        "note": "the middle half at its own overlap's last instant (link 2)",
    },
    {
        "signer": CHAIN_SUCCESSOR_ONE,
        "signed_at": "2026-09-13T00:00:00.000000001Z",
        "expected": "retired",
        "note": "the second link closes the middle half's window",
    },
    {
        "signer": CHAIN_STRANGER,
        "signed_at": "2026-09-20T00:00:00Z",
        "expected": "unreachable",
    },
    {
        "signer": CHAIN_SUCCESSOR_TWO,
        "signed_at": "2026-09-20T00:00:00Z",
        "expected": "accepted",
        "note": "established by link 2, signing within its validity",
    },
)


def build_authority_chain() -> dict:
    """The subsumed chain bundle, byte-faithful to the committed file:
    same seeds, same records, same verdicts — regenerated from the
    documented seeds alone. The complete-record digest convention is
    the chain file's own (its Rust replay consumes it); every other
    file in this bundle pins pre-signature canonical bytes."""
    links = []
    for link in CHAIN_LINKS:
        record = chain_authority_rotation(
            link["previous"], link["new"], link["signed_at"])
        links.append({
            "name": link["name"],
            "address": (
                f"tenants/{CHAIN_TENANT}/v1/control/authority-rotations/"
                f"{record['previous_key_id']}.json"),
            "record": record,
            "canonical_bytes_sha256": hashlib.sha256(
                provenancegen.canonical_json(record).encode("utf-8")
            ).hexdigest(),
        })
    records = []
    for sample in CHAIN_SAMPLES:
        record = chain_receipt_sample(sample["authority"], sample["signed_at"])
        records.append({
            "name": sample["name"],
            "record": record,
            "canonical_bytes_sha256": hashlib.sha256(
                provenancegen.canonical_json(record).encode("utf-8")
            ).hexdigest(),
            "expected": sample["expected"],
        })
    return {
        "$schema": URN_CHAIN,
        "title": (
            "Authority-rotation chain conformance vectors "
            "(control-trust story item 7)"),
        "description": (
            "Language-neutral, byte-pinned vectors for the "
            "tenant-authority rotation chain: the predecessor-signed, "
            "predecessor-addressed links, control records signed "
            "around a mid-window rotation, and the acceptance decision "
            "for each (signer, signed_at) pair. Any implementation "
            "replays this offline with no server: recompute both key "
            "IDs as the lowercase-hex SHA-256 of the 32 raw public "
            "bytes, canonicalize each record per RFC 8785 "
            "(ASCII-sorted members, no insignificant whitespace), "
            "verify each link's Ed25519 signature against the "
            "previous_public_key it carries over the canonicalization "
            "with authority_signature removed, walk fetch-verify-adopt "
            "from the pinned root, and evaluate acceptance at each "
            "record's own signed_at against the 24-hour "
            "rotationVerificationOverlapHours window."),
        "generation": {
            "note": (
                "Synthetic corpus keys only — never tenant material. "
                "Every private seed is one byte repeated 32 times: "
                f"{CHAIN_ROOT.seed_note} (the pinned root), "
                f"{CHAIN_SUCCESSOR_ONE.seed_note} (the first successor), "
                f"{CHAIN_SUCCESSOR_TWO.seed_note} (the second successor), "
                f"{CHAIN_STRANGER.seed_note} (the stranger the "
                "unreachable sample names), "
                f"{CHAIN_RECEIPT_HALF.seed_note} (the receipt-key "
                "payload half the sample records carry). Regenerate any "
                "half as an Ed25519 key from its seed; signatures are "
                "deterministic Ed25519 (RFC 8032)."),
            "canonicalization": CANONICALIZATION,
            "signature_construction": (
                "control-record-v1: Ed25519 over the canonical bytes of "
                "the record with the authority_signature member removed"),
            "key_id_derivation": KEY_ID_DERIVATION,
            "rotation_verification_overlap_hours": 24,
            "trust_record_cache_ttl_seconds": 60,
        },
        "pinned": {
            "tenant_id": CHAIN_TENANT,
            "root_public_key": CHAIN_ROOT.public_key,
            "root_key_id": CHAIN_ROOT.key_id,
        },
        "links": links,
        "records": records,
        "acceptance": [
            ({"signer_key_id": case["signer"].key_id,
              "signed_at": case["signed_at"],
              "expected": case["expected"]}
             | ({"note": case["note"]} if "note" in case else {}))
            for case in CHAIN_ACCEPTANCE
        ],
    }


def chain_windows(doc: dict) -> dict[str, tuple[int | None, int | None]]:
    """Signer key_id -> (established, retired) as nanosecond instants:
    the pinned root is never established by a link; each successor is
    established by the link that names it and retired 24 hours after
    the next link's signed_at — the window inclusive of its last
    instant."""
    links = doc["links"]
    windows: dict[str, tuple[int | None, int | None]] = {}
    for index, link in enumerate(links):
        record = link["record"]
        windows[record["key_id"]] = (
            instant_nanos(record["signed_at"]),
            instant_nanos(links[index + 1]["record"]["signed_at"])
            + CHAIN_OVERLAP_NANOS
            if index + 1 < len(links) else None)
    root_id = doc["pinned"]["root_key_id"]
    windows[root_id] = (
        None,
        instant_nanos(links[0]["record"]["signed_at"]) + CHAIN_OVERLAP_NANOS
        if links else None)
    return windows


def chain_decision(windows: dict[str, tuple[int | None, int | None]],
                   signer_key_id: str, at_nanos: int) -> str:
    """The acceptance verdict for one (signer, instant) pair against the
    walked chain: unreachable, retired, not_established, or accepted."""
    if signer_key_id not in windows:
        return "unreachable"
    established, retired = windows[signer_key_id]
    if retired is not None and at_nanos > retired:
        return "retired"
    if established is not None and at_nanos < established:
        return "not_established"
    return "accepted"


def verify_authority_chain(doc: dict, failures: list[str]) -> None:
    """The chain bundle's own replay: walk fetch-verify-adopt from the
    pinned root — each link verified against the retiring half it
    carries and required to sit at that half's address — then replay
    every pinned acceptance verdict. This is the walk the Rust replay
    (crates/archivist-auth/tests/authority_corpus.rs) applies to the
    committed bytes."""
    urn = doc["$schema"]
    current = doc["pinned"]["root_key_id"]
    windows = chain_windows(doc)
    for link in doc["links"]:
        record = link["record"]
        name = f"{PATH_CHAIN}:{link['name']}"
        complete = provenancegen.canonical_json(record).encode("utf-8")
        if hashlib.sha256(complete).hexdigest() \
                != link["canonical_bytes_sha256"]:
            failures.append(
                f"{name}: canonical_bytes_sha256 is not the SHA-256 of "
                "the complete record's canonical bytes")
        if record["record_type"] != "authority-rotation" \
                or record["record_kind"] != "immutable":
            failures.append(
                f"{name}: not an immutable authority-rotation record")
        if record["previous_key_id"] != current:
            failures.append(
                f"{urn}: {name}: the link does not continue the walk "
                f"from {current}")
        if record["authority_key_id"] != record["previous_key_id"]:
            failures.append(
                f"{name}: the predecessor does not sign its own "
                "retirement")
        if not conformancegen.ed25519_verify(
                record["previous_public_key"],
                record["authority_signature"], canonical_bytes(record)):
            failures.append(
                f"{name}: the retiring half's signature does not verify")
        expected_address = (
            f"tenants/{record['tenant_id']}/v1/control/"
            f"authority-rotations/{record['previous_key_id']}.json")
        if link["address"] != expected_address:
            failures.append(
                f"{name}: the link does not sit at the retiring key's "
                "address")
        current = record["key_id"]
    for entry in doc["records"]:
        record = entry["record"]
        name = f"{PATH_CHAIN}:{entry['name']}"
        decision = chain_decision(
            windows, record["authority_key_id"],
            instant_nanos(record["signed_at"]))
        if decision != entry["expected"]:
            failures.append(
                f"{urn}: {name}: chain acceptance produced {decision}, "
                f"pinned {entry['expected']}")
    for case in doc["acceptance"]:
        decision = chain_decision(windows, case["signer_key_id"],
                                  instant_nanos(case["signed_at"]))
        if decision != case["expected"]:
            failures.append(
                f"{urn}: acceptance case {case['signer_key_id']} at "
                f"{case['signed_at']}: produced {decision}, pinned "
                f"{case['expected']}")


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
            "The key material every scenario bundle in this directory "
            "replays against. The authority-rotation-chain bundle pins "
            "its own deployment in-file: its seeds are one repeated "
            "byte each, documented there, and none of them appears "
            "here."),
        "keys": [key.public_record() for key in CORPUS_KEYS],
    }


def record_map(history: list[dict]) -> list[dict]:
    """The scenario-map manifest's enumeration of one history: every
    pinned record with its family (the record type) and expected
    outcome."""
    return [
        {"name": entry["name"],
         "record_type": entry["record"]["record_type"],
         "expected": entry["expected"]}
        | ({"reason": entry["reason"]} if "reason" in entry else {})
        for entry in history
    ]


def scenario_counts(history: list[dict], outcomes: list[dict]) -> dict:
    accepted = sum(1 for o in outcomes if o["outcome"] == OUTCOME_ACCEPTED)
    return {
        "accepted": accepted,
        "rejected": len(history) - accepted,
    }


def _fold_scenario(scenario_id: str, path: str, urn: str, family: str,
                   subject_types: list[str], doc: dict,
                   outcomes: list[dict]) -> dict:
    """The manifest's scenario-map entry for one store-fold scenario:
    the family it exercises and every pinned record with its expected
    outcome."""
    return {
        "id": scenario_id,
        "file": path,
        "schema": urn,
        "family": family,
        "subjects": subject_types,
        "history_names": [entry["name"] for entry in doc["history"]],
        "records": record_map(doc["history"]),
        "decision_vectors": len(doc.get("attempt_acceptance", []))
                            + len(doc.get("signing_acceptance", [])),
        **scenario_counts(doc["history"], outcomes),
    }


def build_manifest(files: dict[str, bytes], scenarios: list[dict]) -> dict:
    enumerated = [record for scenario in scenarios
                  for record in scenario["records"]]
    accepted = sum(1 for record in enumerated
                   if record["expected"] == OUTCOME_ACCEPTED)
    rejected = len(enumerated) - accepted
    by_reason: dict[str, int] = {}
    for record in enumerated:
        if "reason" in record:
            by_reason[record["reason"]] = \
                by_reason.get(record["reason"], 0) + 1
    decision_vectors = sum(scenario["decision_vectors"]
                           for scenario in scenarios)
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
            "bundle is pinned synthetic data (SEC-006, SEC-010) for "
            "two synthetic deployments: the main corpus's one tenant "
            "with its origin client and the relay that may present its "
            "occurrences, and the authority-rotation-chain "
            "deployment's own tenant and seed-derived authority keys. "
            "Nothing here is real, and only public halves are "
            "emitted."),
        "canonicalization": (
            "Each file is RFC 8785-style canonical JSON plus one "
            "trailing LF. Every authority_signature is deterministic "
            "Ed25519 over the canonical bytes of its record with the "
            "authority_signature member removed, so every record is "
            "verifiable from this bundle and keys.json alone. "
            "canonical_bytes_sha256 pins the pre-signature canonical "
            "bytes everywhere except the authority-rotation-chain "
            "file, whose digests cover the complete record — the "
            "convention its Rust replay consumes."),
        "scenarios": scenarios,
        "invariants": {
            "records": len(enumerated),
            "accepted": accepted,
            "rejected": rejected,
            "rejections_by_reason": dict(sorted(by_reason.items())),
            "decision_vectors": decision_vectors,
            "invariant_meaning": (
                "every rejection is decided by the rule it pins: every "
                "rejected record's authority signature verifies against "
                "the key it names (except the two untrusted-signer "
                "members, whose rejection is that check), no rejection "
                "rests on malformed input, and every acceptance-table "
                "verdict follows from the window its record pins"),
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


def build_bundle() -> dict[str, bytes]:
    epoch_doc = build_epoch_progression()
    delegation_doc = build_delegation_lifecycle()
    revocation_doc = build_revocation()
    rotation_doc = build_rotation()
    receipt_keys_doc = build_receipt_keys()
    chain_doc = build_authority_chain()
    keys_doc = build_keys()
    files = {
        PATH_KEYS: provenancegen.file_bytes(keys_doc),
        PATH_EPOCH: provenancegen.file_bytes(epoch_doc),
        PATH_DELEGATION: provenancegen.file_bytes(delegation_doc),
        PATH_REVOCATION: provenancegen.file_bytes(revocation_doc),
        PATH_ROTATION: provenancegen.file_bytes(rotation_doc),
        PATH_RECEIPT_KEYS: provenancegen.file_bytes(receipt_keys_doc),
        PATH_CHAIN: provenancegen.file_bytes(chain_doc),
    }
    keys_by_id = keys_by_id_map()
    chain_records = [
        {"name": link["name"], "record_type": "authority-rotation",
         "expected": OUTCOME_ACCEPTED}
        for link in chain_doc["links"]
    ] + [
        {"name": sample["name"],
         "record_type": sample["record"]["record_type"],
         "expected": sample["expected"]}
        for sample in chain_doc["records"]
    ]
    chain_accepted = sum(1 for record in chain_records
                         if record["expected"] == OUTCOME_ACCEPTED)
    scenarios = [
        _fold_scenario("epoch-progression", PATH_EPOCH, URN_EPOCH,
                       "linked-client", ["linked-client"], epoch_doc,
                       _story_outcomes(epoch_doc["history"])),
        _fold_scenario("delegation-lifecycle", PATH_DELEGATION,
                       URN_DELEGATION, "delegation", ["delegation"],
                       delegation_doc,
                       _story_outcomes(delegation_doc["history"])),
        _fold_scenario("revocation", PATH_REVOCATION, URN_REVOCATION,
                       "revocation", ["linked-client", "revocation"],
                       revocation_doc,
                       _story_outcomes(revocation_doc["history"])),
        _fold_scenario("key-rotation", PATH_ROTATION, URN_ROTATION,
                       "rotation", ["linked-client", "rotation"],
                       rotation_doc,
                       _story_outcomes(rotation_doc["history"])),
        _fold_scenario("receipt-key-cohort", PATH_RECEIPT_KEYS,
                       URN_RECEIPT_KEYS, "receipt-key", ["receipt-key"],
                       receipt_keys_doc,
                       _story_outcomes(receipt_keys_doc["history"])),
        {
            "id": "authority-rotation-chain",
            "file": PATH_CHAIN,
            "schema": URN_CHAIN,
            "family": "authority-rotation",
            "subjects": ["authority-rotation", "receipt-key"],
            "history_names": [link["name"] for link in chain_doc["links"]]
                             + [sample["name"]
                                for sample in chain_doc["records"]],
            "records": chain_records,
            "decision_vectors": len(chain_doc["acceptance"]),
            "accepted": chain_accepted,
            "rejected": len(chain_records) - chain_accepted,
        },
    ]
    files["manifest.json"] = provenancegen.file_bytes(
        build_manifest(files, scenarios))
    return files


# ---------------------------------------------------------------------------
# generate / verify
# ---------------------------------------------------------------------------


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
                            if entry.name not in files)
        if unexpected:
            raise SystemExit(
                f"refusing to write into {output}: holds files this "
                f"generator does not own: {unexpected}")
    for path, data in sorted(files.items()):
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    print(f"wrote {len(files)} files to {output}")


def standing_state(history: list[dict], outcomes: list[dict]) -> dict:
    """The store fold's end state: every accepted record's object key
    with the members that identify the standing object — a pointer's
    epoch, or an immutable object's own identity. A current-pointer
    replacement moves the pointer to the new record; a byte-identical
    retry of an immutable object re-lands the same bytes, and the
    standing object's identity stays with its first landing."""
    standing = {}
    for entry, outcome in zip(history, outcomes):
        if outcome["outcome"] != OUTCOME_ACCEPTED:
            continue
        record = entry["record"]
        if "authorization_epoch" in record:
            value = {"authorization_epoch": record["authorization_epoch"],
                     "record": entry["name"]}
        else:
            value = {"key_id": record["key_id"], "record": entry["name"]}
        key = record_object_key(record)
        if record["record_kind"] == "immutable":
            standing.setdefault(key, value)
        else:
            standing[key] = value
    return standing


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
    standing = standing_state(history, outcomes)
    if standing != doc["final_state"]:
        failures.append(
            f"{doc['$schema']}: the fold landed on {standing}, pinned "
            f"{doc['final_state']}")


def replay_window_table(doc: dict, failures: list[str], table: str,
                        window_of) -> None:
    """Replay an acceptance table: each row's (key, instant) decided
    against the window ``window_of`` derives from the file's own
    records, and must equal the pinned expected/reason. A window is
    ``(start_ns, end_ns)`` or ``(start_ns, None)`` for one whose
    present half never retires."""
    for entry in doc[table]:
        window = window_of(entry)
        if window is None:
            failures.append(
                f"{doc['$schema']}: {table} row {entry['key_id']} at "
                f"{entry['signed_at']}: the key is not one the file's "
                "records establish a window for")
            continue
        start, end = window
        at = instant_nanos(entry["signed_at"])
        accepted = start <= at and (end is None or at <= end)
        outcome = OUTCOME_ACCEPTED if accepted else OUTCOME_REJECTED
        reason = None if accepted else (
            REASON_OUTSIDE_OVERLAP if table == "attempt_acceptance"
            else REASON_OUTSIDE_SIGNING)
        if outcome != entry["expected"] or reason != entry.get("reason"):
            failures.append(
                f"{doc['$schema']}: {table} row {entry['key_id']} at "
                f"{entry['signed_at']}: produced {outcome}/{reason}, "
                f"pinned {entry['expected']}/{entry.get('reason')}")


def replay_attempt_acceptance(doc: dict, failures: list[str]) -> None:
    """The key-rotation file's attempt_acceptance: the window runs from
    the rotation record's signed_at through
    rotationVerificationOverlapHours later, inclusive, and covers both
    halves — the previous half only inside it, the new half from the
    rotation instant onward."""
    rotation_name = doc["pinned"]["rotation_record"]
    rotation_entry = next(entry for entry in doc["history"]
                          if entry["name"] == rotation_name)
    record = rotation_entry["record"]
    anchor = instant_nanos(record["signed_at"])
    overlap_end = anchor + doc["generation"][
        "rotation_verification_overlap_hours"] * 3600 * 1_000_000_000

    def window_of(entry: dict) -> tuple[int, int | None] | None:
        if entry["key_id"] == record["previous_key_id"]:
            return anchor, overlap_end
        if entry["key_id"] == record["key_id"]:
            return anchor, None  # the new half never retires
        return None

    replay_window_table(doc, failures, "attempt_acceptance", window_of)


def replay_signing_acceptance(doc: dict, failures: list[str]) -> None:
    """The receipt-key cohort's signing_acceptance: each certified key's
    own [valid_from, valid_until], anchored inside the signed bytes."""

    def window_of(entry: dict) -> tuple[int, int | None] | None:
        for member in doc["history"]:
            record = member["record"]
            if (record["record_type"] == "receipt-key"
                    and record["key_id"] == entry["key_id"]
                    and member["expected"] == OUTCOME_ACCEPTED):
                return (instant_nanos(record["valid_from"]),
                        instant_nanos(record["valid_until"]))
        return None

    replay_window_table(doc, failures, "signing_acceptance", window_of)


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
        "revocation": "revocation-object-key",
        "rotation": "rotation-object-key",
        "receipt-key": "receipt-key-object-key",
    }
    fold_paths = (PATH_EPOCH, PATH_DELEGATION, PATH_REVOCATION,
                  PATH_ROTATION, PATH_RECEIPT_KEYS)

    record_maps: dict[str, list[dict]] = {}
    checked = 0
    decision_vectors = 0
    for path in fold_paths:
        doc = json.loads(expected[path])
        replay_history(doc, keys_by_id, failures)
        tables = (("attempt_acceptance", replay_attempt_acceptance),
                  ("signing_acceptance", replay_signing_acceptance))
        for table, replay in tables:
            if table in doc:
                replay(doc, failures)
                decision_vectors += len(doc[table])
        records = []
        for entry in doc["history"]:
            record = entry["record"]
            name = f"{path}:{entry['name']}"
            checked += 1
            records.append({
                "name": entry["name"],
                "record_type": record["record_type"],
                "expected": entry["expected"],
            } | ({"reason": entry["reason"]} if "reason" in entry else {}))

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

        # The receipt-key cohort's pinned window arithmetic: every
        # certified key spans exactly 30+7 days and each successor's
        # certification starts exactly 30 days after its predecessor's.
        if "certified_cohort" in doc["pinned"]:
            for pin in doc["pinned"]["certified_cohort"]:
                record = next(entry["record"] for entry in doc["history"]
                              if entry["name"] == pin["name"])
                span = days_between(record["valid_from"],
                                    record["valid_until"])
                if span != pin["span_days"]:
                    failures.append(
                        f"{path}: {pin['name']} window spans {span} days, "
                        f"pinned {pin['span_days']}")
            gaps = [days_between(pin["valid_from"],
                                 doc["pinned"]["certified_cohort"][i + 1]
                                 ["valid_from"])
                    for i, pin
                    in enumerate(doc["pinned"]["certified_cohort"][:-1])]
            if gaps != doc["pinned"]["successor_gaps_days"]:
                failures.append(
                    f"{path}: successor certification gaps {gaps}, pinned "
                    f"{doc['pinned']['successor_gaps_days']}")
        record_maps[path] = records

    chain_doc = json.loads(expected[PATH_CHAIN])
    verify_authority_chain(chain_doc, failures)
    chain_records = (
        [{"name": link["name"], "record_type": "authority-rotation",
          "expected": OUTCOME_ACCEPTED} for link in chain_doc["links"]]
        + [{"name": sample["name"],
            "record_type": sample["record"]["record_type"],
            "expected": sample["expected"]}
           for sample in chain_doc["records"]])
    record_maps[PATH_CHAIN] = chain_records
    decision_vectors += len(chain_doc["acceptance"])
    checked += len(chain_records)

    manifest = json.loads(expected["manifest.json"])
    if manifest["schema"] != BUNDLE_SCHEMA:
        failures.append("manifest.json is not a "
                        f"{BUNDLE_SCHEMA} manifest")
    if len(manifest["scenarios"]) != len(record_maps):
        failures.append("manifest scenario count drifted")
    for scenario in manifest["scenarios"]:
        expected_map = record_maps.get(scenario["file"])
        if expected_map is None:
            failures.append(f"manifest names unknown file "
                            f"{scenario['file']}")
            continue
        if scenario["records"] != expected_map:
            failures.append(f"manifest scenario map drifted for "
                            f"{scenario['id']}")
        accepted = sum(1 for record in expected_map
                       if record["expected"] == OUTCOME_ACCEPTED)
        if scenario["accepted"] != accepted \
                or scenario["rejected"] != len(expected_map) - accepted:
            failures.append(f"manifest outcome counts drifted for "
                            f"{scenario['id']}")
        if scenario["file"] == PATH_CHAIN:
            expected_vectors = len(chain_doc["acceptance"])
        else:
            scenario_doc = json.loads(expected[scenario["file"]])
            expected_vectors = (
                len(scenario_doc.get("attempt_acceptance", []))
                + len(scenario_doc.get("signing_acceptance", [])))
        if scenario["decision_vectors"] != expected_vectors:
            failures.append(f"manifest decision-vector count drifted for "
                            f"{scenario['id']}")
    invariants = manifest["invariants"]
    enumerated = [record for scenario in manifest["scenarios"]
                  for record in scenario["records"]]
    if invariants["records"] != len(enumerated) or checked != len(enumerated):
        failures.append("manifest record count drifted")
    accepted = sum(1 for record in enumerated
                   if record["expected"] == OUTCOME_ACCEPTED)
    if invariants["accepted"] != accepted:
        failures.append("manifest accepted count drifted")
    if invariants["rejected"] != len(enumerated) - accepted:
        failures.append("manifest rejected count drifted")
    by_reason: dict[str, int] = {}
    for record in enumerated:
        if "reason" in record:
            by_reason[record["reason"]] = \
                by_reason.get(record["reason"], 0) + 1
    if invariants["rejections_by_reason"] != dict(sorted(by_reason.items())):
        failures.append("manifest rejection tally drifted")
    if invariants["decision_vectors"] != decision_vectors:
        failures.append("manifest decision-vector total drifted")
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
        f"{checked} records across {len(manifest['scenarios'])} scenarios, "
        f"{decision_vectors} acceptance-table verdicts, every record valid "
        f"against the archivist.control/v1 envelope registry, every "
        f"signature re-verified independently, every pinned outcome and "
        f"chain walk reproduced, bundle byte-identical"
    )
    return 0


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------


def self_test() -> int:
    """Prove the machinery without the committed bundle: build
    determinism, the signature path, the forged member's trust property,
    the decision procedure's agreement with every pinned outcome across
    all five scenario files, the chain replay, the pinned window
    arithmetic (the 24-hour rotation overlap, the 30+7-day receipt-key
    windows), the write guard, and the schema's rejection of a small
    fault matrix around one record of every family."""
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
    keys_by_id = keys_by_id_map()
    for path, doc in (("epoch", build_epoch_progression()),
                      ("delegation", build_delegation_lifecycle()),
                      ("revocation", build_revocation()),
                      ("rotation", build_rotation()),
                      ("receipt-key cohort", build_receipt_keys())):
        outcomes = decide(doc["history"], keys_by_id)
        check(f"the {path} decision procedure agrees with every pinned "
              f"outcome",
              all(o["outcome"] == e["expected"]
                  and o["reason"] == e.get("reason")
                  for e, o in zip(doc["history"], outcomes)))
        check(f"the {path} fold lands on final_state",
              standing_state(doc["history"], outcomes) == doc["final_state"])
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

    # --- the pinned window arithmetic -------------------------------------
    rotation_doc = build_rotation()
    rotation_record = next(e["record"] for e in rotation_doc["history"]
                           if e["name"]
                           == rotation_doc["pinned"]["rotation_record"])
    overlap_end = instant_nanos(rotation_record["signed_at"]) \
        + 24 * 3600 * 1_000_000_000
    previous_half = [instant_nanos(row["signed_at"])
                     for row in rotation_doc["attempt_acceptance"]
                     if row["key_id"] == rotation_record["previous_key_id"]]
    check("the rotation overlap keeps its last instant and rejects one "
          "second later",
          overlap_end in previous_half
          and min(t for t in previous_half if t > overlap_end)
          == overlap_end + 1_000_000_000)
    new_half = [instant_nanos(row["signed_at"])
                for row in rotation_doc["attempt_acceptance"]
                if row["key_id"] == rotation_record["key_id"]]
    check("the new half verifies from the rotation instant itself",
          min(new_half) == instant_nanos(rotation_record["signed_at"]))

    receipt_doc = build_receipt_keys()
    certified: dict[str, dict] = {}
    for entry in receipt_doc["history"]:
        record = entry["record"]
        if (entry["expected"] == OUTCOME_ACCEPTED
                and record["record_type"] == "receipt-key"):
            certified.setdefault(record["key_id"], record)
    cohort = list(certified.values())
    check("every certified receipt-key window spans exactly 30+7 days",
          all(days_between(record["valid_from"], record["valid_until"]) == 37
              for record in cohort))
    check("each successor receipt key certifies 30 days after its "
          "predecessor's window opens",
          [days_between(cohort[i]["valid_from"], cohort[i + 1]["valid_from"])
           for i in range(len(cohort) - 1)] == [30] * (len(cohort) - 1))
    window_end = instant_nanos(cohort[0]["valid_until"])
    boundary = {instant_nanos(row["signed_at"]): row["expected"]
                for row in receipt_doc["signing_acceptance"]
                if row["key_id"] == cohort[0]["key_id"]}
    check("a receipt key signs through its last valid instant and not one "
          "second later",
          boundary.get(window_end) == OUTCOME_ACCEPTED
          and boundary.get(window_end + 1_000_000_000) == OUTCOME_REJECTED)

    chain_failures: list[str] = []
    verify_authority_chain(build_authority_chain(), chain_failures)
    check("the chain file replays: contiguity from the pinned root, "
          "predecessor signatures, addressing, and every pinned verdict",
          not chain_failures)

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
        validators = {
            record_type: build_validator(
                schemas, record_schema_stem(record_type, registry))
            for record_type in ("linked-client", "delegation", "revocation",
                                "rotation", "receipt-key")
        }
    except ImportError:
        print("jsonschema is not installed: self-test cannot run",
              file=sys.stderr)
        return 4
    client_validator = validators["linked-client"]
    delegation_validator = validators["delegation"]
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
    control_rotation = json.loads(json.dumps(next(
        entry["record"] for entry in rotation_doc["history"]
        if entry["name"] == rotation_doc["pinned"]["rotation_record"])))
    rotation_without_previous = json.loads(json.dumps(control_rotation))
    del rotation_without_previous["previous_public_key"]
    faults.extend([
        ("rotation without its previous half",
         rotation_without_previous, validators["rotation"]),
        ("rotation typed as a linked-client",
         dict(control_rotation, record_type="linked-client"),
         validators["rotation"]),
        ("rotation at epoch zero",
         dict(control_rotation, authorization_epoch=0),
         validators["rotation"]),
    ])
    control_revocation = json.loads(json.dumps(next(
        entry["record"] for entry in build_revocation()["history"]
        if entry["record"]["record_type"] == "revocation")))
    revocation_without_key = json.loads(json.dumps(control_revocation))
    del revocation_without_key["revoked_key_id"]
    faults.extend([
        ("revocation without its revoked key",
         revocation_without_key, validators["revocation"]),
        ("revocation at epoch zero",
         dict(control_revocation, authorization_epoch=0),
         validators["revocation"]),
    ])
    control_receipt = json.loads(json.dumps(
        build_receipt_keys()["history"][0]["record"]))
    receipt_without_validity = json.loads(json.dumps(control_receipt))
    del receipt_without_validity["valid_until"]
    faults.extend([
        ("receipt key without its validity bound",
         receipt_without_validity, validators["receipt-key"]),
        ("receipt key with a non-hex key ID",
         dict(control_receipt, key_id="zz"), validators["receipt-key"]),
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
    check("the registry maps revocation to the revocation schema",
          record_schema_stem("revocation", registry)
          == "control-revocation")
    check("the registry maps rotation to the rotation schema",
          record_schema_stem("rotation", registry) == "control-rotation")
    check("the registry maps receipt-key to the receipt-key schema",
          record_schema_stem("receipt-key", registry)
          == "control-receipt-key")
    check("object keys derive from the record's own members",
          record_object_key(control, registry).endswith(
              f"/control/clients/{CLIENT_A}.json"))
    check("immutable families derive their keys the same way",
          record_object_key(control_revocation, registry).endswith(
              "/control/revocations/"
              f"{control_revocation['client_id']}/"
              f"{control_revocation['authorization_epoch']}.json")
          and record_object_key(control_rotation, registry).endswith(
              "/control/rotations/"
              f"{control_rotation['client_id']}/"
              f"{control_rotation['authorization_epoch']}.json")
          and record_object_key(control_receipt, registry).endswith(
              f"/control/receipt-keys/{control_receipt['key_id']}.json"))

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
