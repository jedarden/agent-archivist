#!/usr/bin/env python3
"""Language-neutral conformance corpus generator for Agent Archivist.

Implements the Phase 1 deliverable "a small language-neutral conformance
corpus containing expected signatures, digests, and object keys"
(docs/plan/plan.md, Section 8, Phase 1) and the golden-request half of the
Section 7.2 verification list: language-neutral golden requests, a
signature table, reordered/whitespace JSON cases, altered multipart cases,
retry-after-window cases, and incompatible-existing-object cases.

The corpus pins, byte-exactly, the constructions registered in
``schemas/v1/ingest-identifiers.json``:

* the four domain-separated identity hashes and the label-less blob
  digest, including their exact pre-image bytes;
* the three server-derived object keys;
* the ``ingest-attempt-v1`` Ed25519 request signature over the pinned
  covered-field order;
* the ``receipt-v1`` and ``receipt-key-v1`` Ed25519 constructions, so a
  receipt chain (tenant authority -> receipt-key certificate -> receipt)
  verifies offline with no server and no protocol-crate import.

Every scenario is a complete ``POST /v1/ingest`` attempt: the canonical
envelope part, the payload part, the exact ``multipart/related`` body, the
per-attempt signature-parameter record, and the expected outcome — a
golden signed receipt for valid vectors, a golden ``archivist.error/v1``
body for invalid ones. A standalone verifier in any language can replay
the corpus using only the pinned public keys in ``keys.json``.

Bundle layout under ``schemas/v1/examples/conformance``::

    keys.json               pinned public verification material and the
                            assumed client linkage it is evaluated against
    derivations.json        pure identity vectors: inputs -> session hash,
                            artifact hash, occurrence and attestation IDs,
                            object keys, plus full pre-image bytes
    canonicalization.json   RFC 8785 canonical-form vectors: Unicode
                            values, reordered/whitespace equivalence,
                            normalization lookalikes, and rejected inputs
    scenarios/<id>/envelope.json    the envelope part bytes as transmitted
    scenarios/<id>/payload.jsonl    the payload part bytes as transmitted
    scenarios/<id>/request.body     the whole multipart/related body
    scenarios/<id>/attempt.json     per-attempt signature parameters
    scenarios/<id>/receipt.json     golden signed receipt (valid vectors)
    scenarios/<id>/error.json       golden error body (invalid vectors)
    scenarios/<id>/existing-occurrence.json
                                    pre-existing incompatible store object
                                    (the integrity-conflict vector)
    manifest.json           scenarios, expectations, invariants, digests

Scenario map (bead aa-cfc9f227 acceptance criteria):

Valid — accepted with a golden receipt:

1. ``valid-direct-baseline`` — the reference direct upload: Unicode-free
   envelope, identity transport, byte range from zero, created x3.
2. ``valid-unicode-session`` — arbitrary-Unicode upstream session and
   artifact identifiers; canonical bytes carry them as literal UTF-8 with
   minimal escaping, and the hashes bind the exact bytes, never a
   normalized form.
3. ``valid-synthetic-session-id`` — adapter-minted session ID
   (``id_source=synthetic``), database-projection artifact with an event
   range, no ``source_time`` (omitted, never nulled).
4. ``valid-relay-upload`` — an authorized relay presents the origin's
   captured occurrence under its own key and request: same occurrence and
   blob objects, a distinct attestation (EC-05A, ID-005).
5. ``valid-reordered-envelope-framing`` — the envelope part is transmitted
   with non-canonical member order and whitespace; canonicalization is by
   parsed value, so every identity and digest is unchanged and a
   non-zero byte range lands as a fresh occurrence.
6. ``valid-cross-tenant-second`` — the minimal cross-tenant pair: the
   identical session inputs under a second tenant derive a distinct
   session hash and tenant-scoped keys around one shared blob digest.
7. ``valid-retry-after-window`` — the frozen baseline envelope re-presented
   after the authorization window and an epoch rotation: fresh
   authorization and signature, identical identity fields, and
   ``already_present`` outcomes (STO-004, RCPT-003).

Invalid — rejected with a golden error body and no receipt:

8.  ``invalid-reserved-field`` — the envelope freezes ``commit_time``, a
    reserved per-attempt/server name (VAL-001-adjacent fail-closed rule).
9.  ``invalid-unknown-enum-value`` — ``transport_encoding: "gzip"``, an
    unknown security-bearing enum value, fails closed.
10. ``invalid-occurrence-id-mismatch`` — the declared occurrence ID is not
    the derivation of its own inputs (VAL-002 consistency).
11. ``invalid-altered-payload-byte`` — one payload byte flipped after
    signing: the signature is valid but no longer covers these bytes
    (IA-02; altered request -> authorization rejected).
12. ``invalid-altered-framing-boundary`` — the multipart boundary swapped
    after signing while the covered content type still names the signed
    boundary (IA-02; altered framing).
13. ``invalid-stale-authorization`` — a proof twenty minutes old at
    evaluation time, far outside the 300-second window even with the full
    clock-skew allowance (ID-007).
14. ``invalid-cross-tenant-forbidden`` — a tenant-two envelope presented
    under a key linked only to tenant one (ID-005).
15. ``invalid-integrity-conflict`` — the derived occurrence key already
    holds an object with different canonical bytes: refused as
    ``storage.integrity_conflict``, never as deduplication, with no
    overwrite and no receipt.

Determinism model: there is no entropy source. Identifiers, timestamps,
payload bytes, and multipart boundaries are pinned constants; every
Ed25519 key pair is derived at generation time as
SHA-256("archivist.conformance/v1 <key-name>")-as-seed, so signatures are
RFC 8032-deterministic and regeneration is byte-identical everywhere.
Private halves exist only in generator memory and are never written to
any file; ``--verify`` proves no seed material leaked into the bundle.
Signing uses the installed ``cryptography`` wheel; every golden signature
is then re-verified by the independent pure-Python RFC 8032 verifier in
this file, which shares no code with the signing path — the corpus is
never asked to trust the same implementation on both sides.

``--verify`` regenerates the bundle, byte-compares every file against the
working tree, validates every schema-conformant instance against its
schema (draft 2020-12, ``common`` vocabulary resolved from
``schemas/v1/common.json``), re-derives every identity from the vectors'
own inputs, checks the golden error bodies against the error-code
registry in ``tools/error-codes.toml``, re-verifies every signature with
the pure-Python verifier plus bit-flip rejection cases, and re-checks the
cross-scenario invariants. Exit codes: 0 pass, 2 byte drift or
non-canonical formatting, 3 verification, schema, or invariant failure,
4 a required module (``jsonschema`` or ``cryptography``) is unavailable.

Content safety: every identifier, timestamp, key, and payload byte is
pinned synthetic data (SEC-010); nothing is copied from any real harness
store, and the payloads are drawn from a closed vocabulary.

Usage::

    tools/conformancegen.py --generate [OUTPUT]  # default: the committed bundle
    tools/conformancegen.py --verify             # regenerate and verify everything
    tools/conformancegen.py --self-test          # prove the rejection paths
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "schemas" / "v1" / "examples" / "conformance"
COMMON_SCHEMA = REPO_ROOT / "schemas" / "v1" / "common.json"
ENVELOPE_SCHEMA = REPO_ROOT / "schemas" / "v1" / "ingest-envelope.json"
REQUEST_SCHEMA = REPO_ROOT / "schemas" / "v1" / "ingest-request.json"
RECEIPT_SCHEMA = REPO_ROOT / "schemas" / "v1" / "ingest-receipt.json"
ERROR_SCHEMA = REPO_ROOT / "schemas" / "v1" / "ingest-error.json"
OCCURRENCE_SCHEMA = REPO_ROOT / "schemas" / "v1" / "occurrence-manifest.json"
ERROR_REGISTRY = REPO_ROOT / "tools" / "error-codes.toml"

BUNDLE_SCHEMA = "archivist.conformance-corpus/v1"
KEYS_SCHEMA = "archivist.conformance-keys/v1"
DERIVATIONS_SCHEMA = "archivist.conformance-derivations/v1"
CANONICALIZATION_SCHEMA = "archivist.conformance-canonicalization/v1"
ERROR_NAMESPACE = "archivist.error/v1"

ENVELOPE_MEDIA_TYPE = "application/vnd.agent-archivist.envelope+json;version=1"
IDENTITY_MEDIA_TYPE = "application/octet-stream"
AUTHORIZATION_WINDOW_SECONDS = 300
CLOCK_SKEW_SECONDS = 300
ENVELOPE_CANONICAL_MAX_BYTES = 65536

# ---------------------------------------------------------------------------
# Independent pure-Python Ed25519 verification (RFC 8032).
#
# Deliberately shares no code with the signing path (the `cryptography`
# wheel): a golden signature must verify under an implementation that did
# not produce it, which is the corpus's whole reason to exist.
# ---------------------------------------------------------------------------

_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int, sign: int) -> int | None:
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if x * x % _ED_P != x2:
        x = x * _ED_SQRT_M1 % _ED_P
    if x * x % _ED_P != x2:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _ED_P - x
    return x


_ED_BY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_BX = _ed_recover_x(_ED_BY, 0)
assert _ED_BX is not None
_ED_BASE = (_ED_BX, _ED_BY, 1, _ED_BX * _ED_BY % _ED_P)


def _ed_add(p1: tuple, p2: tuple) -> tuple:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = 2 * t1 * t2 * _ED_D % _ED_P
    d = 2 * z1 * z2 % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_mul(point: tuple, scalar: int) -> tuple:
    result = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return result


def _ed_decode(encoded: bytes) -> tuple | None:
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _ED_P:
        return None
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _ED_P)


def _ed_equal(p1: tuple, p2: tuple) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % _ED_P == 0 and (y1 * z2 - y2 * z1) % _ED_P == 0


def ed25519_verify(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    """RFC 8032 Ed25519 verification over raw public key and signature hex."""
    try:
        public = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _ed_decode(public)
    r = _ed_decode(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    k = int.from_bytes(
        hashlib.sha512(signature[:32] + public + message).digest(), "little"
    ) % _ED_L
    return _ed_equal(_ed_mul(_ED_BASE, s), _ed_add(r, _ed_mul(a, k)))


# ---------------------------------------------------------------------------
# Canonical JSON (RFC 8785 subset used by the protocol: objects with ASCII
# member names, integers, strings, arrays, booleans, null — no floats) and
# the pinned identity/signature framing.
# ---------------------------------------------------------------------------


def canonical_text(value: object) -> str:
    """RFC 8785 canonical text for the protocol's value domain.

    Member names are asserted ASCII so code-point sorting equals the JCS
    UTF-16 code-unit order (the two differ only for non-BMP names); string
    escaping is Python's ``ensure_ascii=False`` profile, which matches JCS
    (short escapes for \\b \\t \\n \\f \\r, \\u00xx for the remaining
    control characters, literal UTF-8 otherwise).
    """

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


def metadata_bytes(value: object) -> bytes:
    """Bundle metadata files: canonical JSON plus one trailing LF."""
    return canonical_bytes(value) + b"\n"


def noncanonical_text(value: object) -> str:
    """A deliberately non-canonical rendering: reverse-sorted member order
    and two-space indentation, parsing back to the identical value."""
    def render(node: object) -> str:
        if isinstance(node, dict):
            items = sorted(node.items(), reverse=True)
            body = ",\n".join(f"  {json.dumps(k)}: {render(v)}" for k, v in items)
            return "{\n" + body + "\n}" if body else "{}"
        if isinstance(node, list):
            return "[\n" + ",\n".join(f"  {render(v)}" for v in node) + "\n]" if node else "[]"
        return json.dumps(node, ensure_ascii=False)

    return render(value)


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
    """The one label-less construction: plain SHA-256 over canonical bytes."""
    return hashlib.sha256(payload).hexdigest()


def key_id_of(public_key_hex: str) -> str:
    """The pinned key-ID derivation, same as tools/check-control-schemas.py:
    SHA-256 over the 32 raw public-key bytes."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def blob_object_key(tenant: str, digest_hex: str) -> str:
    return f"tenants/{tenant}/v1/raw/blobs/zstd-v1/sha256/{digest_hex[:2]}/{digest_hex}.zst"


def occurrence_object_key(tenant: str, origin: str, harness: str,
                          session_hash: str, occurrence_id: str) -> str:
    return (f"tenants/{tenant}/v1/raw/occurrences/{origin}/{harness}/"
            f"{session_hash[:2]}/{session_hash}/{occurrence_id}.json")


def attestation_object_key(tenant: str, occurrence_id: str, attestation_id: str) -> str:
    return (f"tenants/{tenant}/v1/raw/attestations/"
            f"{occurrence_id[:2]}/{occurrence_id}/{attestation_id}.json")


# ---------------------------------------------------------------------------
# Pinned synthetic key material (SEC-010).
#
# Every key pair is derived at generation time from SHA-256 of its label;
# no hexadecimal literal sits in this source, private halves are never
# written anywhere, and the signatures are deterministic per RFC 8032.
# ---------------------------------------------------------------------------

KEY_SEED_PREFIX = "archivist.conformance/v1"


class SigningKey:
    """An Ed25519 key pair derived from a pinned label, public material only."""

    def __init__(self, name: str, role: str, extra: dict | None = None):
        self.name = name
        self.role = role
        self.extra = extra or {}
        seed = hashlib.sha256(f"{KEY_SEED_PREFIX} {name}".encode()).digest()
        self._seed_hex = seed.hex()
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

    def seed_hex(self) -> str:
        """The generation seed, for the leak check only — never emitted."""
        return self._seed_hex


# --- pinned synthetic identities (SEC-010: nothing here is real) ----------

# The same synthetic tenant, origin, relay, and upstream session the raw
# provenance bundle pins, so the two Phase 1 example families speak about
# one coherent synthetic deployment.
TENANT_1 = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b"
TENANT_2 = "5d9e2b64-8f7a-4c1d-b3e9-2a6f8d0c4e5b"
ORIGIN_A = "11111111-2222-4333-8444-555555555555"
RELAY_UPLOADER = "aaaaaaa1-bbbb-4ccc-9ddd-1e2f3f4f5f6f"
SESSION_ASCII = "4f9c2f1e-8a3d-4b67-9c2f-1e8a3d4b679c"
SESSION_SYNTHETIC = "d4811c22-93e4-4f30-8b17-a1c2d3e4f5a6"

# Arbitrary Unicode session identity (NFC), and its NFD lookalike: the
# protocol never Unicode-normalizes, so the two are distinct sessions.
SESSION_UNICODE_NFC = "対話-セッション-🤖-café-0001"
SESSION_UNICODE_NFD = "対話-セッション-🤖-café-0001"

# The integrity-conflict scenario's own session and artifact tuple.
SESSION_CONFLICT = "c0nf11ct-7e57-4be5-8f6a-1d2e3f4a5b6c"
ARTIFACT_CONFLICT = "conflicted-session-file-0001"

HARNESS_A, ADAPTER_A, PROJECTION_A = "claude-code", "claude-jsonl", "1"
HARNESS_UNI, ADAPTER_UNI, PROJECTION_UNI = "codex", "codex-rollout", "2.3.1"
HARNESS_SYNTH, ADAPTER_SYNTH, PROJECTION_SYNTH = "pi", "pi-store", "1.0.0-rc.2"

ARTIFACT_A_CHUNK_1 = "session-file-4f9c2f1e"
ARTIFACT_A_CHUNK_2 = "session-file-4f9c2f1e"  # same source file, next range
ARTIFACT_UNI = "ロールアウト-🄰-0001"
ARTIFACT_SYNTH = "store-projection-synthetic-0001"

GENERATION_ASCII = "1a07a111-7000-7000-8000-000000000001"
GENERATION_UNICODE = "1a07a112-7000-7000-8000-000000000002"
GENERATION_SYNTH = "1a07a113-7000-7000-8000-000000000003"
GENERATION_CONFLICT = "1a07a114-7000-7000-8000-000000000004"

REQUEST_BASELINE = "1a07b201-7000-7000-8000-000000000001"
REQUEST_UNICODE = "1a07b202-7000-7000-8000-000000000002"
REQUEST_SYNTH = "1a07b203-7000-7000-8000-000000000003"
REQUEST_RELAY = "1a07b204-7000-7000-8000-000000000004"
REQUEST_REORDERED = "1a07b205-7000-7000-8000-000000000005"
REQUEST_CROSS_TENANT = "1a07b206-7000-7000-8000-000000000006"
REQUEST_CONFLICT = "1a07b207-7000-7000-8000-000000000007"
REQUEST_INVALID_RESERVED = "1a07b208-7000-7000-8000-000000000008"
REQUEST_INVALID_ENUM = "1a07b209-7000-7000-8000-000000000009"
REQUEST_INVALID_OCC = "1a07b20a-7000-7000-8000-00000000000a"
REQUEST_STALE = REQUEST_BASELINE  # the stale attempt is the baseline retry
REQUEST_INVALID_TENANT = "1a07b20c-7000-7000-8000-00000000000c"

CORRELATION_INVALID = "1a07c201-7000-7000-8000-000000000001"

# --- pinned synthetic timeline (all UTC, all fixed) ------------------------
#
# Cohort A is committed 2026-09-11 under receipt key 1; cohort B is
# committed 2026-09-22 under receipt key 2 (tenant one) and receipt key 3
# (tenant two). Keys 1 and 2 overlap for the mandated seven days, and
# cohort A's receipts must still verify during cohort B — rotation never
# invalidates retained receipts (ID-009).

RECEIPT_WINDOW_1_FROM, RECEIPT_WINDOW_1_UNTIL = "2026-08-20T00:00:00Z", "2026-09-26T00:00:00Z"
RECEIPT_WINDOW_2_FROM, RECEIPT_WINDOW_2_UNTIL = "2026-09-19T00:00:00Z", "2026-10-25T00:00:00Z"
RECEIPT_WINDOW_3_FROM, RECEIPT_WINDOW_3_UNTIL = "2026-09-10T00:00:00Z", "2026-10-16T00:00:00Z"

T_BASELINE_ATTEMPT, T_BASELINE_COMMIT = "2026-09-11T17:59:57Z", "2026-09-11T17:59:59Z"
T_STALE_SERVER, T_STALE_ATTEMPT = "2026-09-11T18:12:01Z", "2026-09-11T17:52:01Z"
T_RETRY_SERVER, T_RETRY_ATTEMPT, T_RETRY_COMMIT = (
    "2026-09-11T18:12:03Z", "2026-09-11T18:12:02Z", "2026-09-11T18:12:04Z")
T_INVALID_ATTEMPT_A = "2026-09-11T18:19:59Z"
T_INVALID_ATTEMPT_B = "2026-09-11T18:21:59Z"
T_INVALID_ATTEMPT_C = "2026-09-11T18:23:59Z"
T_INVALID_ATTEMPT_D = "2026-09-11T18:25:59Z"
T_INVALID_ATTEMPT_E = "2026-09-11T18:29:59Z"
T_INVALID_ATTEMPT_F = "2026-09-11T18:31:59Z"

T_UNI_ATTEMPT, T_UNI_COMMIT = "2026-09-22T10:00:01Z", "2026-09-22T10:00:03Z"
T_SYNTH_ATTEMPT, T_SYNTH_COMMIT = "2026-09-22T10:02:01Z", "2026-09-22T10:02:03Z"
T_RELAY_ATTEMPT, T_RELAY_COMMIT = "2026-09-22T10:04:01Z", "2026-09-22T10:04:03Z"
T_REORDERED_ATTEMPT, T_REORDERED_COMMIT = "2026-09-22T10:06:01Z", "2026-09-22T10:06:03Z"
T_CROSS_TENANT_ATTEMPT, T_CROSS_TENANT_COMMIT = (
    "2026-09-22T10:08:01Z", "2026-09-22T10:08:03Z")
T_FORBIDDEN_SERVER, T_FORBIDDEN_ATTEMPT = "2026-09-22T10:10:00Z", "2026-09-22T10:09:59Z"

SOURCE_TIME_A = "2026-09-11T16:44:02Z"
SOURCE_TIME_UNI = "2026-09-22T09:58:44Z"
SOURCE_TIME_SYNTH = None  # the synthetic store carries no source time
SOURCE_TIME_CONFLICT_REQUEST = "2026-09-11T16:50:00Z"
SOURCE_TIME_CONFLICT_EXISTING = "2026-09-11T16:44:02Z"  # differs on purpose

CAPTURE_BASELINE, ENVELOPE_BASELINE = "2026-09-11T16:44:10Z", "2026-09-11T16:44:11Z"
CAPTURE_RETRY = CAPTURE_BASELINE  # the retry resubmits the frozen envelope
CAPTURE_UNICODE, ENVELOPE_UNICODE = "2026-09-22T09:59:10Z", "2026-09-22T09:59:11Z"
CAPTURE_SYNTH, ENVELOPE_SYNTH = "2026-09-22T10:01:10Z", "2026-09-22T10:01:11Z"
CAPTURE_RELAY, ENVELOPE_RELAY = "2026-09-22T10:03:10Z", "2026-09-22T10:03:11Z"
CAPTURE_REORDERED, ENVELOPE_REORDERED = "2026-09-22T10:05:10Z", "2026-09-22T10:05:11Z"
CAPTURE_CROSS, ENVELOPE_CROSS = "2026-09-22T10:07:10Z", "2026-09-22T10:07:11Z"
CAPTURE_CONFLICT, ENVELOPE_CONFLICT = "2026-09-11T16:49:10Z", "2026-09-11T16:49:11Z"
CAPTURE_INVALID, ENVELOPE_INVALID = "2026-09-11T18:18:10Z", "2026-09-11T18:18:11Z"

# --- pinned synthetic payloads (closed vocabulary; SEC-010) ----------------

PAYLOAD_BASELINE_RECORDS = [
    {"seq": 1, "text": "conformance alpha one", "type": "user"},
    {"seq": 2, "text": "conformance beta two", "type": "assistant"},
    {"seq": 3, "text": "conformance gamma three", "type": "assistant"},
]
PAYLOAD_CHUNK_2_RECORDS = [
    {"seq": 4, "text": "conformance delta four", "type": "user"},
    {"seq": 5, "text": "conformance epsilon five", "type": "assistant"},
]
PAYLOAD_UNICODE_RECORDS = [
    {"seq": 1, "text": "合成ログ一行目 🤖", "type": "user"},
    {"seq": 2, "text": "会話の記録・二行目", "type": "assistant"},
]
PAYLOAD_SYNTH_EVENTS = [
    {"event": "message", "ordinal": 1, "role": "user", "body": "synthetic pi one"},
    {"event": "message", "ordinal": 2, "role": "assistant", "body": "synthetic pi two"},
    {"event": "message", "ordinal": 3, "role": "assistant", "body": "synthetic pi three"},
]

PAYLOAD_CONFLICT_RECORDS = [
    {"seq": 1, "text": "conformance conflict one", "type": "user"},
    {"seq": 2, "text": "conformance conflict two", "type": "assistant"},
]

PAYLOAD_INVALID_RECORDS = [
    {"seq": 1, "text": "conformance invalid one", "type": "user"},
    {"seq": 2, "text": "conformance invalid two", "type": "assistant"},
]


def jsonl_bytes(records: list[dict]) -> bytes:
    """One canonical JSON object plus LF per record (plan Section 7.6)."""
    return b"".join(canonical_bytes(record) + b"\n" for record in records)


# ---------------------------------------------------------------------------
# Key set: one authority root per tenant, three tenant-scoped receipt keys,
# three uploader keys. The linkage assumptions document which tenant each
# uploader key is linked to — the precondition that makes the forbidden
# vector's 403 deterministic.
# ---------------------------------------------------------------------------

AUTHORITY_1 = SigningKey("tenant-authority-1", "tenant-authority-root",
                         {"tenant_id": TENANT_1})
AUTHORITY_2 = SigningKey("tenant-authority-2", "tenant-authority-root",
                         {"tenant_id": TENANT_2})
RECEIPT_KEY_1 = SigningKey("receipt-key-1", "receipt-signing", {
    "tenant_id": TENANT_1, "valid_from": RECEIPT_WINDOW_1_FROM,
    "valid_until": RECEIPT_WINDOW_1_UNTIL})
RECEIPT_KEY_2 = SigningKey("receipt-key-2", "receipt-signing", {
    "tenant_id": TENANT_1, "valid_from": RECEIPT_WINDOW_2_FROM,
    "valid_until": RECEIPT_WINDOW_2_UNTIL})
RECEIPT_KEY_3 = SigningKey("receipt-key-3", "receipt-signing", {
    "tenant_id": TENANT_2, "valid_from": RECEIPT_WINDOW_3_FROM,
    "valid_until": RECEIPT_WINDOW_3_UNTIL})
UPLOADER_ORIGIN_1 = SigningKey("uploader-origin-1", "uploader", {
    "client_id": ORIGIN_A, "linked_tenant": TENANT_1})
UPLOADER_RELAY_1 = SigningKey("uploader-relay-1", "uploader", {
    "client_id": RELAY_UPLOADER, "linked_tenant": TENANT_1})
UPLOADER_ORIGIN_2 = SigningKey("uploader-origin-2", "uploader", {
    "client_id": ORIGIN_A, "linked_tenant": TENANT_2})

ALL_SIGNING_KEYS = [AUTHORITY_1, AUTHORITY_2, RECEIPT_KEY_1, RECEIPT_KEY_2,
                    RECEIPT_KEY_3, UPLOADER_ORIGIN_1, UPLOADER_RELAY_1,
                    UPLOADER_ORIGIN_2]


# ---------------------------------------------------------------------------
# Builders.
# ---------------------------------------------------------------------------


class Scenario:
    """One pinned ingest attempt and its expected outcome."""

    def __init__(self, sid: str, kind: str, covers: list[str], story: str,
                 envelope: dict, payload: bytes, boundary: str,
                 uploader_key: SigningKey, epoch: int, authorization_time: str,
                 server_time: str, receipt_key: SigningKey | None,
                 outcomes: dict | None, commit_time: str | None,
                 error: dict | None, asserts: list[str],
                 envelope_wire_canonical: bool = True,
                 existing_occurrence: dict | None = None,
                 alteration: dict | None = None,
                 alter_boundary: str | None = None):
        self.id = sid
        self.kind = kind
        self.covers = covers
        self.story = story
        self.envelope = envelope
        self.payload = payload
        self.boundary = boundary
        self.uploader_key = uploader_key
        self.epoch = epoch
        self.authorization_time = authorization_time
        self.server_time = server_time
        self.receipt_key = receipt_key
        self.outcomes = outcomes
        self.commit_time = commit_time
        self.error = error
        self.asserts = asserts
        self.envelope_wire_canonical = envelope_wire_canonical
        self.existing_occurrence = existing_occurrence
        self.alteration = alteration
        self.alter_boundary = alter_boundary
        # Derived identity, recomputed here and pinned everywhere it appears.
        self.identity = derive_identity(envelope)
        if envelope["occurrence_id"] != self.identity["occurrence_id"]:
            # invalid-occurrence-id-mismatch is the one vector whose
            # declared ID intentionally disagrees; everyone else must agree.
            self.identity_declared_mismatch = True
        else:
            self.identity_declared_mismatch = False

    def envelope_wire_bytes(self) -> bytes:
        if self.envelope_wire_canonical:
            return canonical_bytes(self.envelope)
        return noncanonical_text(self.envelope).encode("utf-8")

    def content_type(self) -> str:
        return f"multipart/related; boundary={self.boundary}"

    def body_bytes(self, payload: bytes | None = None,
                   boundary: str | None = None) -> bytes:
        payload = self.payload if payload is None else payload
        boundary = self.boundary if boundary is None else boundary
        return multipart_body(boundary, self.envelope_wire_bytes(), payload)

    def covered_values(self, body: bytes) -> dict:
        envelope_digest = hashlib.sha256(
            canonical_bytes(self.envelope)).hexdigest()
        return {
            "http_method": "POST",
            "route": "/v1/ingest",
            "content_type": self.content_type(),
            "request_content_digest": hashlib.sha256(body).hexdigest(),
            "envelope_digest": envelope_digest,
            "payload_canonical_digest": blob_digest(self.payload),
            "payload_transport_digest": blob_digest(self.payload),
            "uploader_key_id": self.uploader_key.key_id,
            "authorization_epoch": self.epoch,
            "authorization_timestamp": self.authorization_time,
        }

    def attempt_input_bytes(self, covered: dict) -> bytes:
        return framing_bytes("ingest-attempt-v1", [
            text(covered["http_method"]),
            text(covered["route"]),
            text(covered["content_type"]),
            digest(covered["request_content_digest"]),
            digest(covered["envelope_digest"]),
            digest(covered["payload_canonical_digest"]),
            digest(covered["payload_transport_digest"]),
            digest(covered["uploader_key_id"]),
            u63(covered["authorization_epoch"]),
            text(covered["authorization_timestamp"]),
        ])

    def build(self) -> dict[str, bytes]:
        """Assemble this scenario's files, including the golden signature,
        receipt or error body, and optional pre-existing store object."""
        body = self.body_bytes()
        covered = self.covered_values(body)
        message = self.attempt_input_bytes(covered)
        signature = self.uploader_key.sign(message)
        attempt = {
            "http_method": covered["http_method"],
            "route": covered["route"],
            "content_type": covered["content_type"],
            "request_content_digest": covered["request_content_digest"],
            "envelope_digest": covered["envelope_digest"],
            "payload_canonical_digest": covered["payload_canonical_digest"],
            "payload_transport_digest": covered["payload_transport_digest"],
            "uploader_key_id": covered["uploader_key_id"],
            "authorization_epoch": covered["authorization_epoch"],
            "authorization_timestamp": covered["authorization_timestamp"],
            "signature_algorithm": "ed25519",
            "signature": signature,
        }
        files = {
            "envelope.json": self.envelope_wire_bytes(),
            "payload.jsonl": self.payload,
            "request.body": body,
            "attempt.json": metadata_bytes(attempt),
        }
        extras: dict[str, object] = {
            "signing": {
                "signing_key": self.uploader_key.name,
                "signing_key_id": self.uploader_key.key_id,
                "construction": "ingest-attempt-v1",
                "covered_order": [
                    "http_method", "route", "content_type",
                    "request_content_digest", "envelope_digest",
                    "payload_canonical_digest", "payload_transport_digest",
                    "uploader_key_id", "authorization_epoch",
                    "authorization_timestamp",
                ],
                "attempt_input_sha256": hashlib.sha256(message).hexdigest(),
                "attempt_input_hex": message.hex(),
                "attempt_signature": signature,
            },
        }
        if self.receipt_key is not None:
            receipt, receipt_signed, cert_signed = build_receipt(
                self, self.receipt_key)
            files["receipt.json"] = metadata_bytes(receipt)
            extras["signing"].update({
                "receipt_key": self.receipt_key.name,
                "receipt_construction": "receipt-v1",
                "receipt_signed_bytes_sha256": hashlib.sha256(
                    receipt_signed).hexdigest(),
                "certificate_construction": "receipt-key-v1",
                "certificate_signed_bytes_sha256": hashlib.sha256(
                    cert_signed).hexdigest(),
            })
        if self.error is not None:
            files["error.json"] = metadata_bytes(self.error)
        if self.existing_occurrence is not None:
            files["existing-occurrence.json"] = metadata_bytes(
                self.existing_occurrence)
        self.files = files
        self.extras = extras
        return files


def framing_bytes(label: str, fields: list[bytes]) -> bytes:
    """Label + 0x00 + length-prefixed fields, the framing every domain-
    separated construction in ingest-identifiers.json shares."""
    return label.encode("utf-8") + b"\x00" + b"".join(_field(f) for f in fields)


def multipart_body(boundary: str, envelope_bytes: bytes,
                   payload: bytes) -> bytes:
    """The exact multipart/related framing the corpus pins: dash-boundary,
    a lowercase content-type header per part, blank line, part bytes, and
    a closing boundary. Payload part media type is the identity transport
    (application/octet-stream) in every v1 corpus vector."""
    return (
        f"--{boundary}\r\n"
        f"content-type: {ENVELOPE_MEDIA_TYPE}\r\n"
        "\r\n"
    ).encode("utf-8") + envelope_bytes + (
        f"\r\n--{boundary}\r\n"
        f"content-type: {IDENTITY_MEDIA_TYPE}\r\n"
        "\r\n"
    ).encode("utf-8") + payload + f"\r\n--{boundary}--\r\n".encode("utf-8")


def derive_identity(envelope: dict) -> dict:
    """Re-derive every identity the envelope's inputs determine."""
    session_hash = derive("session-v1", text(envelope["tenant_id"]),
                          text(envelope["origin_client_id"]),
                          text(envelope["harness"]),
                          text(envelope["upstream_session_id"]))
    artifact_hash = derive("artifact-v1", digest(session_hash),
                           text(envelope["artifact_kind"]),
                           text(envelope["adapter_id"]),
                           text(envelope["adapter_projection_version"]),
                           text(envelope["adapter_artifact_id"]))
    blob = envelope["blob_digest"]
    occurrence_id = derive("occurrence-v1", digest(session_hash),
                           digest(artifact_hash), text(envelope["generation"]),
                           text(envelope["range_kind"]),
                           u63(envelope["range_start"]),
                           u63(envelope["range_end"]), digest(blob))
    attestation_id = derive("attestation-v1", digest(envelope["occurrence_id"]),
                            text(envelope["uploader_client_id"]),
                            text(envelope["request_id"]))
    tenant = envelope["tenant_id"]
    return {
        "session_hash": session_hash,
        "artifact_hash": artifact_hash,
        "occurrence_id": occurrence_id,
        "attestation_id": attestation_id,
        "blob_digest": blob,
        "blob_object_key": blob_object_key(tenant, blob),
        "occurrence_object_key": occurrence_object_key(
            tenant, envelope["origin_client_id"], envelope["harness"],
            session_hash, envelope["occurrence_id"]),
        "attestation_object_key": attestation_object_key(
            tenant, envelope["occurrence_id"], attestation_id),
    }


def make_envelope(**overrides) -> dict:
    """A schema-valid v1 envelope; every scenario customizes from here."""
    payload_len = overrides.pop("payload_len", 0)
    envelope = {
        "protocol_version": 1,
        "envelope_version": 1,
        "tenant_id": TENANT_1,
        "origin_client_id": ORIGIN_A,
        "uploader_client_id": ORIGIN_A,
        "harness": HARNESS_A,
        "upstream_session_id": SESSION_ASCII,
        "id_source": "upstream",
        "artifact_kind": "file-slice",
        "adapter_id": ADAPTER_A,
        "adapter_projection_version": PROJECTION_A,
        "adapter_artifact_id": ARTIFACT_A_CHUNK_1,
        "generation": GENERATION_ASCII,
        "range_kind": "byte",
        "range_start": 0,
        "range_end": payload_len - 1 if payload_len else 0,
        "blob_digest": "0" * 64,
        "incoming_checksum": "0" * 64,
        "incoming_checksum_algorithm": "sha256",
        "storage_profile": "zstd-v1",
        "transport_encoding": "identity",
        "compressed_size": payload_len,
        "uncompressed_size": payload_len,
        "capture_time": CAPTURE_BASELINE,
        "envelope_creation_time": ENVELOPE_BASELINE,
        "occurrence_id": "0" * 64,
        "attestation_id": "0" * 64,
        "request_id": REQUEST_BASELINE,
        "source_time": SOURCE_TIME_A,
    }
    envelope.update(overrides)
    # Optional members are omitted, never nulled, when the source carries
    # none (plan Section 7.3).
    if envelope.get("source_time") is None:
        envelope.pop("source_time", None)
    return envelope


def finalize_envelope(envelope: dict, payload: bytes) -> dict:
    """Fill the digest and identity fields every well-formed envelope
    carries, so callers declare only their scenario's story fields."""
    envelope = dict(envelope)
    blob = blob_digest(payload)
    envelope["blob_digest"] = blob
    envelope["incoming_checksum"] = blob  # identity transport: same bytes
    envelope["compressed_size"] = len(payload)
    envelope["uncompressed_size"] = len(payload)
    identity = derive_identity(envelope)
    envelope["occurrence_id"] = identity["occurrence_id"]
    envelope["attestation_id"] = identity["attestation_id"]
    return envelope


def build_certificate(receipt_key: SigningKey) -> tuple[dict, bytes]:
    """The tenant-authority-signed receipt-key certificate, embedded by
    value in every receipt the key signs (receipt-key-v1 over the record
    minus its authority_signature member)."""
    authority = AUTHORITY_1 if receipt_key.extra["tenant_id"] == TENANT_1 else AUTHORITY_2
    record = {
        "certificate_version": 1,
        "tenant_id": receipt_key.extra["tenant_id"],
        "key_id": receipt_key.key_id,
        "key_algorithm": "ed25519",
        "public_key": receipt_key.public_key,
        "valid_from": receipt_key.extra["valid_from"],
        "valid_until": receipt_key.extra["valid_until"],
        "authority_key_id": authority.key_id,
    }
    signed = canonical_bytes(record)
    record["authority_signature"] = authority.sign(signed)
    return record, signed


_CERTIFICATES: dict[str, tuple[dict, bytes]] = {}


def certificate_for(receipt_key: SigningKey) -> tuple[dict, bytes]:
    if receipt_key.name not in _CERTIFICATES:
        _CERTIFICATES[receipt_key.name] = build_certificate(receipt_key)
    return _CERTIFICATES[receipt_key.name]


def build_receipt(scenario: Scenario, receipt_key: SigningKey) -> tuple[dict, bytes, bytes]:
    """The golden receipt: identity fields from the frozen envelope, the
    successful authorization, per-object outcomes, the embedded signed
    certificate, and the receipt-v1 signature."""
    certificate, cert_signed = certificate_for(receipt_key)
    identity = scenario.identity
    receipt = {
        "receipt_version": 1,
        "tenant_id": scenario.envelope["tenant_id"],
        "request_id": scenario.envelope["request_id"],
        "occurrence_id": scenario.envelope["occurrence_id"],
        "attestation_id": identity["attestation_id"],
        "blob_digest": identity["blob_digest"],
        "blob_object_key": identity["blob_object_key"],
        "occurrence_object_key": identity["occurrence_object_key"],
        "attestation_object_key": identity["attestation_object_key"],
        "blob_outcome": scenario.outcomes["blob"],
        "occurrence_outcome": scenario.outcomes["occurrence"],
        "attestation_outcome": scenario.outcomes["attestation"],
        "authorization_epoch": scenario.epoch,
        "authorization_key_id": scenario.uploader_key.key_id,
        "receipt_key_id": receipt_key.key_id,
        "certificate": certificate,
        "commit_time": scenario.commit_time,
        "signature_algorithm": "ed25519",
    }
    signed = canonical_bytes(receipt)
    receipt["signature"] = receipt_key.sign(signed)
    return receipt, signed, cert_signed


def render_message(template: str, placeholders: dict) -> str:
    message = template
    for key, value in placeholders.items():
        message = message.replace("{" + key + "}", value)
    assert "{" not in message and "}" not in message
    return message


def error_body(code: str, template: str, retryable: bool,
               request_id: str | None, placeholders: dict) -> dict:
    return {
        "schema": ERROR_NAMESPACE,
        "code": code,
        "retryable": retryable,
        "message": render_message(template, placeholders),
        "request_id": request_id,
        "correlation_id": CORRELATION_INVALID,
    }


# ---------------------------------------------------------------------------
# The scenario table.
# ---------------------------------------------------------------------------


def build_scenarios() -> list[Scenario]:
    payload_baseline = jsonl_bytes(PAYLOAD_BASELINE_RECORDS)
    payload_chunk_2 = jsonl_bytes(PAYLOAD_CHUNK_2_RECORDS)
    payload_unicode = jsonl_bytes(PAYLOAD_UNICODE_RECORDS)
    payload_synth = jsonl_bytes(PAYLOAD_SYNTH_EVENTS)
    payload_conflict = jsonl_bytes(PAYLOAD_CONFLICT_RECORDS)
    payload_invalid = jsonl_bytes(PAYLOAD_INVALID_RECORDS)

    baseline_envelope = finalize_envelope(make_envelope(
        request_id=REQUEST_BASELINE), payload_baseline)

    scenarios: list[Scenario] = []

    # --- valid, cohort A (2026-09-11, tenant one, receipt key 1) ----------

    scenarios.append(Scenario(
        "valid-direct-baseline", "valid", ["baseline-direct-upload"],
        "The reference direct upload: the origin installation presents its "
        "own captured chunk under its linked key.",
        baseline_envelope, payload_baseline, "archivist-conformance-01",
        UPLOADER_ORIGIN_1, 1, T_BASELINE_ATTEMPT, T_BASELINE_ATTEMPT,
        RECEIPT_KEY_1,
        {"blob": "created", "occurrence": "created", "attestation": "created"},
        T_BASELINE_COMMIT,
        error=None,
        asserts=[
            "the envelope validates against schemas/v1/ingest-envelope.json "
            "and is exactly its RFC 8785 canonical bytes (no trailing LF)",
            "every derived identity in the manifest is re-derivable from the "
            "envelope's own fields (VAL-002)",
            "the attempt record validates against schemas/v1/ingest-request.json "
            "and its signature verifies under the pinned uploader public key",
            "the receipt chain verifies offline: pinned authority root signs "
            "the certificate, certificate key signs the receipt (RCPT-006, ID-009)",
            "all three storage outcomes are created for a first commit (RCPT-003)",
        ],
    ))

    scenarios.append(Scenario(
        "invalid-stale-authorization", "invalid",
        ["retry-after-window", "stale-authorization"],
        "The baseline retry's first presentation: the frozen envelope "
        "resubmitted with a proof minted twenty minutes earlier — far "
        "outside the 300-second window even with the full 300-second "
        "clock-skew allowance.",
        baseline_envelope, payload_baseline, "archivist-conformance-02",
        UPLOADER_ORIGIN_1, 1, T_STALE_ATTEMPT, T_STALE_SERVER,
        receipt_key=None, outcomes=None, commit_time=None,
        error=error_body(
            "auth.authorization_rejected",
            "The authorization proof is stale, altered, or replayed; obtain "
            "fresh authorization.", False, REQUEST_BASELINE, {}),
        asserts=[
            "the signature itself is valid — the covered authorization "
            "timestamp is simply too old at the pinned server time (ID-007)",
            "no receipt exists for a rejected attempt (RCPT-001)",
            "the identical envelope is retried with fresh authorization in "
            "valid-retry-after-window and converges (STO-004)",
        ],
    ))

    scenarios.append(Scenario(
        "valid-retry-after-window", "valid",
        ["retry-after-window", "authorization-epoch-change"],
        "The same frozen envelope bytes after the authorization window and "
        "an epoch rotation: fresh timestamp, epoch two, a new signature — "
        "and identical identity fields with already_present outcomes.",
        baseline_envelope, payload_baseline, "archivist-conformance-03",
        UPLOADER_ORIGIN_1, 2, T_RETRY_ATTEMPT, T_RETRY_SERVER,
        RECEIPT_KEY_1,
        {"blob": "already_present", "occurrence": "already_present",
         "attestation": "already_present"},
        T_RETRY_COMMIT,
        error=None,
        asserts=[
            "the envelope, payload, occurrence, attestation, and every object "
            "key are byte-identical to valid-direct-baseline (STO-004)",
            "the attempt signature differs from the baseline attempt only "
            "through the covered epoch and timestamp (ID-006, ID-007)",
            "the second receipt's identity fields are identical and its "
            "outcomes report already_present, honestly distinguishing repair "
            "from first commit (RCPT-003, RCPT-004)",
            "the envelope carries no per-attempt field — fresh authorization "
            "changes no frozen byte (plan Section 7.2)",
        ],
    ))

    # --- invalid envelope shape (cohort A; no receipt to sign) ------------

    scenarios.append(Scenario(
        "invalid-reserved-field", "invalid", ["reserved-envelope-field"],
        "A well-formed envelope that freezes commit_time — a server-only "
        "name the envelope rejects outright so retries cannot fork identity "
        "on per-attempt material.",
        {**finalize_envelope(make_envelope(
            request_id=REQUEST_INVALID_RESERVED,
            capture_time=CAPTURE_INVALID,
            envelope_creation_time=ENVELOPE_INVALID), payload_invalid),
         "commit_time": T_BASELINE_COMMIT},
        payload_invalid, "archivist-conformance-04",
        UPLOADER_ORIGIN_1, 1, T_INVALID_ATTEMPT_A, T_INVALID_ATTEMPT_A,
        receipt_key=None, outcomes=None, commit_time=None,
        error=error_body(
            "envelope.schema_invalid",
            "The envelope fails schema validation at field {field}.", False,
            REQUEST_INVALID_RESERVED, {"field": "commit_time"}),
        asserts=[
            "the reserved-name block in schemas/v1/ingest-envelope.json "
            "rejects commit_time, authorization_*, correlation_id, and "
            "signature outright (plan Section 7.3)",
            "the request signature is valid — rejection is the envelope's "
            "shape, not its authentication (VAL-002)",
        ],
    ))

    scenarios.append(Scenario(
        "invalid-unknown-enum-value", "invalid", ["fail-closed-enum"],
        "The payload part is framed identity but the envelope declares "
        "transport_encoding gzip — an unknown security-bearing enum value "
        "fails closed instead of being guessed.",
        finalize_envelope(make_envelope(
            request_id=REQUEST_INVALID_ENUM,
            capture_time=CAPTURE_INVALID,
            envelope_creation_time=ENVELOPE_INVALID,
            transport_encoding="gzip"), payload_invalid),
        payload_invalid, "archivist-conformance-05",
        UPLOADER_ORIGIN_1, 1, T_INVALID_ATTEMPT_B, T_INVALID_ATTEMPT_B,
        receipt_key=None, outcomes=None, commit_time=None,
        error=error_body(
            "envelope.schema_invalid",
            "The envelope fails schema validation at field {field}.", False,
            REQUEST_INVALID_ENUM, {"field": "transport_encoding"}),
        asserts=[
            "unknown security- and identity-bearing enum values fail closed "
            "(plan Section 7.1): gzip is not zstd and not identity, and the "
            "server must not decode a misdeclared encoding (PI-01)",
        ],
    ))

    scenarios.append(Scenario(
        "invalid-occurrence-id-mismatch", "invalid", ["identity-reconciliation"],
        "A declared occurrence ID that is not the derivation of its own "
        "inputs — the one field a lying envelope cannot make true.",
        (lambda env: {**env, "occurrence_id": env["occurrence_id"][:-1]
                      + ("0" if env["occurrence_id"][-1] != "0" else "1")})(
            finalize_envelope(make_envelope(
                request_id=REQUEST_INVALID_OCC,
                capture_time=CAPTURE_INVALID,
                envelope_creation_time=ENVELOPE_INVALID), payload_invalid)),
        payload_invalid, "archivist-conformance-06",
        UPLOADER_ORIGIN_1, 1, T_INVALID_ATTEMPT_C, T_INVALID_ATTEMPT_C,
        receipt_key=None, outcomes=None, commit_time=None,
        error=error_body(
            "envelope.schema_invalid",
            "The envelope fails schema validation at field {field}.", False,
            REQUEST_INVALID_OCC, {"field": "occurrence_id"}),
        asserts=[
            "the server re-derives occurrence_id from the envelope's own "
            "inputs and refuses the mismatch (VAL-002, SID-005)",
            "the attestation ID stays consistent with the declared (wrong) "
            "occurrence, so exactly one defect exists in the vector",
        ],
    ))

    conflict_envelope = finalize_envelope(make_envelope(
        upstream_session_id=SESSION_CONFLICT,
        adapter_artifact_id=ARTIFACT_CONFLICT,
        generation=GENERATION_CONFLICT,
        request_id=REQUEST_CONFLICT,
        capture_time=CAPTURE_CONFLICT,
        envelope_creation_time=ENVELOPE_CONFLICT,
        source_time=SOURCE_TIME_CONFLICT_REQUEST), payload_conflict)
    conflict_identity = derive_identity(conflict_envelope)
    existing_occurrence = {
        "occurrence_version": 1,
        "occurrence_id": conflict_identity["occurrence_id"],
        "tenant_id": TENANT_1,
        "origin_client_id": ORIGIN_A,
        "harness": HARNESS_A,
        "upstream_session_id": SESSION_CONFLICT,
        "id_source": "upstream",
        "session_hash": conflict_identity["session_hash"],
        "artifact_kind": "file-slice",
        "adapter_id": ADAPTER_A,
        "adapter_projection_version": PROJECTION_A,
        "adapter_artifact_id": ARTIFACT_CONFLICT,
        "artifact_hash": conflict_identity["artifact_hash"],
        "generation": GENERATION_CONFLICT,
        "range_kind": "byte",
        "range_start": conflict_envelope["range_start"],
        "range_end": conflict_envelope["range_end"],
        "blob_digest": conflict_identity["blob_digest"],
        "storage_profile": "zstd-v1",
        "source_time": SOURCE_TIME_CONFLICT_EXISTING,
    }

    scenarios.append(Scenario(
        "invalid-integrity-conflict", "invalid", ["incompatible-existing-object"],
        "Read-capable ingest finds a different canonical object already at "
        "the derived occurrence key: the conflict is reported, the existing "
        "bytes are never overwritten, and no receipt is issued.",
        conflict_envelope, payload_conflict, "archivist-conformance-07",
        UPLOADER_ORIGIN_1, 1, T_INVALID_ATTEMPT_D, T_INVALID_ATTEMPT_D,
        receipt_key=None, outcomes=None, commit_time=None,
        error=error_body(
            "storage.integrity_conflict",
            "An existing object is incompatible with this submission; the "
            "affected source requires operator review.", False,
            REQUEST_CONFLICT, {}),
        asserts=[
            "the pre-existing object validates as an occurrence manifest and "
            "sits at exactly the derived occurrence object key",
            "the two objects differ only in source_time, so both derivations "
            "agree and the conflict is canonical-content divergence at one "
            "immutable key (plan Section 7.4)",
            "the outcome is 409 with no receipt, never a silent overwrite "
            "and never deduplication (plan Section 7.8; RCPT-001)",
            "the client stops the affected source and pages an operator "
            "rather than retrying into a loop",
        ],
        existing_occurrence=existing_occurrence,
    ))

    # --- altered multipart bodies (cohort A) -------------------------------

    scenarios.append(Scenario(
        "invalid-altered-payload-byte", "invalid", ["altered-multipart-body"],
        "One payload byte flipped after signing: the attempt record and its "
        "signature are untouched and still verify, but they no longer cover "
        "the bytes actually submitted.",
        baseline_envelope, payload_baseline, "archivist-conformance-08",
        UPLOADER_ORIGIN_1, 1, T_INVALID_ATTEMPT_E, T_INVALID_ATTEMPT_E,
        receipt_key=None, outcomes=None, commit_time=None,
        error=error_body(
            "auth.authorization_rejected",
            "The authorization proof is stale, altered, or replayed; obtain "
            "fresh authorization.", False, REQUEST_BASELINE, {}),
        asserts=[
            "the signature verifies over the covered values; what fails is "
            "request_content_digest and payload_transport_digest against the "
            "actual body bytes (IA-02, ID-007)",
            "flipping the byte changed the payload digest, so the server "
            "cannot attribute the body to the authorized request",
        ],
        alteration={"kind": "payload-byte-flip", "offset_in_payload":
                    len(payload_baseline) - 9, "bit": 0x01},
    ))

    scenarios.append(Scenario(
        "invalid-altered-framing-boundary", "invalid", ["altered-multipart-body"],
        "The same parts reframed under a different multipart boundary while "
        "the covered, signed content type still names the original boundary.",
        baseline_envelope, payload_baseline, "archivist-conformance-09",
        UPLOADER_ORIGIN_1, 1, T_INVALID_ATTEMPT_F, T_INVALID_ATTEMPT_F,
        receipt_key=None, outcomes=None, commit_time=None,
        error=error_body(
            "auth.authorization_rejected",
            "The authorization proof is stale, altered, or replayed; obtain "
            "fresh authorization.", False, REQUEST_BASELINE, {}),
        asserts=[
            "the covered content_type is part of the signed material, so "
            "reframing the body under another boundary fails both the "
            "request content digest and the framing the signature names "
            "(IA-02)",
        ],
        alteration={"kind": "boundary-substitution"},
        alter_boundary="archivist-conformance-09b",
    ))

    # --- valid, cohort B (2026-09-22; receipt keys 2 and 3) ----------------

    scenarios.append(Scenario(
        "valid-unicode-session", "valid", ["arbitrary-unicode"],
        "An arbitrary-Unicode upstream session and artifact identifier: "
        "canonical bytes carry them as literal UTF-8, and every hash binds "
        "the exact bytes — never a normalized or case-folded form.",
        finalize_envelope(make_envelope(
            harness=HARNESS_UNI, adapter_id=ADAPTER_UNI,
            adapter_projection_version=PROJECTION_UNI,
            adapter_artifact_id=ARTIFACT_UNI,
            upstream_session_id=SESSION_UNICODE_NFC,
            generation=GENERATION_UNICODE,
            request_id=REQUEST_UNICODE,
            capture_time=CAPTURE_UNICODE,
            envelope_creation_time=ENVELOPE_UNICODE,
            source_time=SOURCE_TIME_UNI), payload_unicode),
        payload_unicode, "archivist-conformance-10",
        UPLOADER_ORIGIN_1, 1, T_UNI_ATTEMPT, T_UNI_ATTEMPT,
        RECEIPT_KEY_2,
        {"blob": "created", "occurrence": "created", "attestation": "created"},
        T_UNI_COMMIT,
        error=None,
        asserts=[
            "the canonical envelope bytes are multi-byte UTF-8 with minimal "
            "escaping and still far below the 64 KiB cap",
            "the NFC and NFD session forms hash to different session hashes "
            "and different object keys (pinned in derivations.json); neither "
            "is ever normalized to the other (plan Section 7.4)",
            "raw Unicode identifiers never appear in any object key — only "
            "their hashes do (ID-008)",
        ],
    ))

    scenarios.append(Scenario(
        "valid-synthetic-session-id", "valid", ["synthetic-session-id"],
        "A harness store with no session ID: the adapter minted a UUIDv4 "
        "stand-in (id_source synthetic, never inferred from a path), and a "
        "database projection with an event range carries no source_time.",
        finalize_envelope(make_envelope(
            harness=HARNESS_SYNTH, adapter_id=ADAPTER_SYNTH,
            adapter_projection_version=PROJECTION_SYNTH,
            adapter_artifact_id=ARTIFACT_SYNTH,
            upstream_session_id=SESSION_SYNTHETIC,
            id_source="synthetic",
            artifact_kind="database-projection",
            generation=GENERATION_SYNTH,
            range_kind="event",
            range_end=len(PAYLOAD_SYNTH_EVENTS) - 1,
            request_id=REQUEST_SYNTH,
            capture_time=CAPTURE_SYNTH,
            envelope_creation_time=ENVELOPE_SYNTH,
            source_time=None), payload_synth),
        payload_synth, "archivist-conformance-11",
        UPLOADER_ORIGIN_1, 1, T_SYNTH_ATTEMPT, T_SYNTH_ATTEMPT,
        RECEIPT_KEY_2,
        {"blob": "created", "occurrence": "created", "attestation": "created"},
        T_SYNTH_COMMIT,
        error=None,
        asserts=[
            "id_source=synthetic with a UUIDv4 upstream_session_id is the "
            "adapter-minted stand-in for a missing harness ID (plan Section "
            "7.4)",
            "database-projection artifacts use event ordinals for their "
            "range, one canonical JSON object plus LF per event (plan "
            "Section 7.6)",
            "source_time is omitted, never nulled, when the source carries "
            "none (plan Section 7.3)",
        ],
    ))

    relay_envelope = finalize_envelope(make_envelope(
        uploader_client_id=RELAY_UPLOADER,
        request_id=REQUEST_RELAY,
        capture_time=CAPTURE_RELAY,
        envelope_creation_time=ENVELOPE_RELAY,
        trace_id="conformance-trace-relay-0001"), payload_baseline)

    scenarios.append(Scenario(
        "valid-relay-upload", "valid", ["relay"],
        "An authorized relay presents the origin's already-captured "
        "occurrence under its own linked key and a fresh frozen request: "
        "the blob and occurrence objects are shared, the attestation is "
        "the relay's own.",
        relay_envelope, payload_baseline, "archivist-conformance-12",
        UPLOADER_RELAY_1, 1, T_RELAY_ATTEMPT, T_RELAY_ATTEMPT,
        RECEIPT_KEY_2,
        {"blob": "already_present", "occurrence": "already_present",
         "attestation": "created"},
        T_RELAY_COMMIT,
        error=None,
        asserts=[
            "the occurrence ID and both shared object keys equal "
            "valid-direct-baseline's — uploader and request never enter the "
            "occurrence (EC-05A, STO-004)",
            "the attestation ID differs by uploader and request alone and "
            "lands under its own key beside the origin's (STO-013)",
            "the optional trace_id rides inside the signed envelope bytes "
            "without touching any identity (plan Section 7.1 additive rule)",
            "the receipt names the relay's authorization key while the "
            "occurrence keeps the origin's identity (ID-005)",
        ],
    ))

    reordered_envelope = finalize_envelope(make_envelope(
        adapter_artifact_id=ARTIFACT_A_CHUNK_2,
        range_start=len(payload_baseline),
        range_end=len(payload_baseline) + len(payload_chunk_2) - 1,
        request_id=REQUEST_REORDERED,
        capture_time=CAPTURE_REORDERED,
        envelope_creation_time=ENVELOPE_REORDERED), payload_chunk_2)

    scenarios.append(Scenario(
        "valid-reordered-envelope-framing", "valid", ["reordered-json"],
        "The envelope part transmitted with reverse-sorted members and "
        "indentation whitespace: canonicalization is by parsed value, so "
        "the canonical digest, every identity, and the outcome are exactly "
        "what the canonical bytes would produce.",
        reordered_envelope, payload_chunk_2, "archivist-conformance-13",
        UPLOADER_ORIGIN_1, 1, T_REORDERED_ATTEMPT, T_REORDERED_ATTEMPT,
        RECEIPT_KEY_2,
        {"blob": "created", "occurrence": "created", "attestation": "created"},
        T_REORDERED_COMMIT,
        error=None,
        asserts=[
            "parsing the non-canonical part and re-serializing canonically "
            "reproduces the signed envelope_digest exactly (plan Section "
            "7.2 reordered/whitespace case)",
            "member order and whitespace enter no identity: the second chunk "
            "of the same session lands as its own occurrence through "
            "range_start alone (PI-05)",
            "a non-canonical serializer converges on the same object bytes "
            "— reordering cannot change canonical meaning silently (plan "
            "Section 10 property)",
        ],
        envelope_wire_canonical=False,
    ))

    cross_tenant_envelope = finalize_envelope(make_envelope(
        tenant_id=TENANT_2,
        request_id=REQUEST_CROSS_TENANT,
        capture_time=CAPTURE_CROSS,
        envelope_creation_time=ENVELOPE_CROSS), payload_baseline)

    scenarios.append(Scenario(
        "valid-cross-tenant-second", "valid", ["cross-tenant-separation"],
        "The minimal cross-tenant pair: the identical session inputs under "
        "a second tenant (mirrored bytes, enrolled origin) derive a wholly "
        "distinct namespace around one shared blob digest.",
        cross_tenant_envelope, payload_baseline, "archivist-conformance-14",
        UPLOADER_ORIGIN_2, 1, T_CROSS_TENANT_ATTEMPT, T_CROSS_TENANT_ATTEMPT,
        RECEIPT_KEY_3,
        {"blob": "created", "occurrence": "created", "attestation": "created"},
        T_CROSS_TENANT_COMMIT,
        error=None,
        asserts=[
            "only tenant_id differs from valid-direct-baseline's identity "
            "inputs, and the session hash, occurrence, attestation, and all "
            "three object keys differ with it (EC-03)",
            "the blob digest is identical — one canonical byte stream — "
            "while the blob object key is tenant-scoped, so no cross-tenant "
            "deduplication or read is implied (STO-002, plan Section 7.5)",
            "the receipt chain roots in tenant two's own authority and "
            "receipt key: trust never crosses tenants (ID-009)",
        ],
    ))

    forbidden_envelope = finalize_envelope(make_envelope(
        tenant_id=TENANT_2,
        request_id=REQUEST_INVALID_TENANT,
        capture_time=CAPTURE_CROSS,
        envelope_creation_time=ENVELOPE_CROSS), payload_baseline)

    scenarios.append(Scenario(
        "invalid-cross-tenant-forbidden", "invalid",
        ["cross-tenant-separation", "unauthorized-relay"],
        "A tenant-two envelope presented under a key linked only to tenant "
        "one: the proof is valid, the linkage is not.",
        forbidden_envelope, payload_baseline, "archivist-conformance-15",
        UPLOADER_ORIGIN_1, 1, T_FORBIDDEN_ATTEMPT, T_FORBIDDEN_SERVER,
        receipt_key=None, outcomes=None, commit_time=None,
        error=error_body(
            "auth.forbidden",
            "The uploader is not authorized for the declared origin client "
            "or tenant.", False, REQUEST_INVALID_TENANT, {}),
        asserts=[
            "the signature verifies under the pinned uploader key; rejection "
            "comes from the assumed linkage record (keys.json), which binds "
            "that key to tenant one only (ID-005)",
            "no write of tenant two's namespace happens under tenant one's "
            "authorization (EC-03)",
        ],
    ))

    return scenarios


# ---------------------------------------------------------------------------
# Standalone vector tables: derivations and canonicalization.
# ---------------------------------------------------------------------------


def derivation_case(case_id: str, note: str, envelope_inputs: dict,
                    payload: bytes) -> dict:
    """A pure identity vector: inputs, expected derivations, keys."""
    probe = make_envelope(**envelope_inputs)
    probe = finalize_envelope(probe, payload)
    identity = derive_identity(probe)
    return {
        "id": case_id,
        "note": note,
        "inputs": {
            "tenant_id": probe["tenant_id"],
            "origin_client_id": probe["origin_client_id"],
            "harness": probe["harness"],
            "upstream_session_id": probe["upstream_session_id"],
            "artifact_kind": probe["artifact_kind"],
            "adapter_id": probe["adapter_id"],
            "adapter_projection_version": probe["adapter_projection_version"],
            "adapter_artifact_id": probe["adapter_artifact_id"],
            "generation": probe["generation"],
            "range_kind": probe["range_kind"],
            "range_start": probe["range_start"],
            "range_end": probe["range_end"],
            "uploader_client_id": probe["uploader_client_id"],
            "request_id": probe["request_id"],
            "canonical_payload": payload.decode("utf-8"),
        },
        "expected": {
            "blob_digest": identity["blob_digest"],
            "session_hash": identity["session_hash"],
            "artifact_hash": identity["artifact_hash"],
            "occurrence_id": identity["occurrence_id"],
            "attestation_id": identity["attestation_id"],
            "blob_object_key": identity["blob_object_key"],
            "occurrence_object_key": identity["occurrence_object_key"],
            "attestation_object_key": identity["attestation_object_key"],
        },
    }


def build_derivations(scenarios: list[Scenario]) -> dict:
    payload_baseline = jsonl_bytes(PAYLOAD_BASELINE_RECORDS)
    payload_unicode = jsonl_bytes(PAYLOAD_UNICODE_RECORDS)
    payload_synth = jsonl_bytes(PAYLOAD_SYNTH_EVENTS)

    cases = [
        derivation_case(
            "ascii-baseline", "The reference session: UUID-shaped ASCII "
            "identifiers end to end.", {}, payload_baseline),
        derivation_case(
            "ascii-baseline-relay-pair", "Same occurrence under the relay "
            "uploader and a fresh request: only the attestation axis moves.",
            {"uploader_client_id": RELAY_UPLOADER,
             "request_id": REQUEST_RELAY}, payload_baseline),
        derivation_case(
            "ascii-baseline-retry-pair", "The frozen retry: identical "
            "uploader and request reproduce the attestation byte for byte.",
            {}, payload_baseline),
        derivation_case(
            "unicode-nfc", "Arbitrary Unicode, composed (NFC) form.",
            {"harness": HARNESS_UNI, "adapter_id": ADAPTER_UNI,
             "adapter_projection_version": PROJECTION_UNI,
             "adapter_artifact_id": ARTIFACT_UNI,
             "upstream_session_id": SESSION_UNICODE_NFC,
             "generation": GENERATION_UNICODE}, payload_unicode),
        derivation_case(
            "unicode-nfd", "The same visible string in decomposed (NFD) "
            "form: a different byte sequence, so a different session — "
            "identifiers are never Unicode-normalized.",
            {"harness": HARNESS_UNI, "adapter_id": ADAPTER_UNI,
             "adapter_projection_version": PROJECTION_UNI,
             "adapter_artifact_id": ARTIFACT_UNI,
             "upstream_session_id": SESSION_UNICODE_NFD,
             "generation": GENERATION_UNICODE}, payload_unicode),
        derivation_case(
            "synthetic-session-id", "Adapter-minted UUIDv4 stand-in for a "
            "missing harness session ID; event range over a projection.",
            {"harness": HARNESS_SYNTH, "adapter_id": ADAPTER_SYNTH,
             "adapter_projection_version": PROJECTION_SYNTH,
             "adapter_artifact_id": ARTIFACT_SYNTH,
             "upstream_session_id": SESSION_SYNTHETIC,
             "id_source": "synthetic",
             "artifact_kind": "database-projection",
             "generation": GENERATION_SYNTH,
             "range_kind": "event",
             "range_end": len(PAYLOAD_SYNTH_EVENTS) - 1,
             "source_time": None}, payload_synth),
        derivation_case(
            "cross-tenant-tenant-one", "Cross-tenant pair, tenant one "
            "member: the reference inputs under tenant one.",
            {}, payload_baseline),
        derivation_case(
            "cross-tenant-tenant-two", "Cross-tenant pair, tenant two "
            "member: only tenant_id differs, and every derived identity "
            "differs with it while the blob digest stays shared.",
            {"tenant_id": TENANT_2}, payload_baseline),
    ]

    # Full pre-image bytes, one golden framing per construction.
    baseline = cases[0]
    session_inputs = baseline["inputs"]
    session_preimage = framing_bytes("session-v1", [
        text(session_inputs["tenant_id"]),
        text(session_inputs["origin_client_id"]),
        text(session_inputs["harness"]),
        text(session_inputs["upstream_session_id"]),
    ])
    artifact_preimage = framing_bytes("artifact-v1", [
        digest(baseline["expected"]["session_hash"]),
        text(session_inputs["artifact_kind"]),
        text(session_inputs["adapter_id"]),
        text(session_inputs["adapter_projection_version"]),
        text(session_inputs["adapter_artifact_id"]),
    ])
    occurrence_preimage = framing_bytes("occurrence-v1", [
        digest(baseline["expected"]["session_hash"]),
        digest(baseline["expected"]["artifact_hash"]),
        text(session_inputs["generation"]),
        text(session_inputs["range_kind"]),
        u63(session_inputs["range_start"]),
        u63(session_inputs["range_end"]),
        digest(baseline["expected"]["blob_digest"]),
    ])
    attestation_preimage = framing_bytes("attestation-v1", [
        digest(baseline["expected"]["occurrence_id"]),
        text(session_inputs["uploader_client_id"]),
        text(session_inputs["request_id"]),
    ])
    baseline_scenario = next(s for s in scenarios
                             if s.id == "valid-direct-baseline")
    attempt_input = baseline_scenario.attempt_input_bytes(
        baseline_scenario.covered_values(baseline_scenario.body_bytes()))

    return {
        "schema": DERIVATIONS_SCHEMA,
        "synthetic": "Every input below is pinned synthetic data (SEC-010); "
                     "the constructions are normative in "
                     "schemas/v1/ingest-identifiers.json.",
        "construction": {
            "framing": "SHA-256 over the UTF-8 domain label, one 0x00 byte, "
                       "then each field as an 8-byte unsigned big-endian "
                       "length followed by exactly that many field bytes",
            "field_kinds": {
                "text": "UTF-8 bytes of the canonical wire text",
                "u63": "8-byte unsigned big-endian integer",
                "digest": "the 32 raw bytes a 64-character lowercase hex "
                          "digest names",
                "bytes": "the raw bytes themselves (the label-less blob "
                         "digest only)",
            },
        },
        "cases": cases,
        "preimages": {
            "note": "Exact pre-image bytes for the ascii-baseline case, so "
                    "an implementation tests its framing before its hashing",
            "session_hash": {
                "label": "session-v1", "hex": session_preimage.hex(),
                "sha256": baseline["expected"]["session_hash"]},
            "artifact_hash": {
                "label": "artifact-v1", "hex": artifact_preimage.hex(),
                "sha256": baseline["expected"]["artifact_hash"]},
            "occurrence_id": {
                "label": "occurrence-v1", "hex": occurrence_preimage.hex(),
                "sha256": baseline["expected"]["occurrence_id"]},
            "attestation_id": {
                "label": "attestation-v1", "hex": attestation_preimage.hex(),
                "sha256": baseline["expected"]["attestation_id"]},
            "ingest_attempt_v1": {
                "label": "ingest-attempt-v1", "hex": attempt_input.hex(),
                "note": "the Ed25519 message of scenarios/"
                        "valid-direct-baseline/attempt.json"},
        },
    }


def build_canonicalization() -> dict:
    value = {
        "adapter_artifact_id": "ロールアウト-🄰-0001",
        "empty_array": [],
        "escapes": "quote\" back\\slab\ttab\nlinectrl",
        "integers": [0, 1, 42, 4096],
        "nested": {"inner": {"flag": True, "nothing": None}},
        "unicode_session": SESSION_UNICODE_NFC,
    }
    canonical = canonical_bytes(value)
    nfc = canonical_bytes({"upstream_session_id": SESSION_UNICODE_NFC})
    nfd = canonical_bytes({"upstream_session_id": SESSION_UNICODE_NFD})
    return {
        "schema": CANONICALIZATION_SCHEMA,
        "synthetic": "Pinned synthetic values (SEC-010); the canonical form "
                     "is RFC 8785 as consumed by every digest in this "
                     "corpus.",
        "domain": "Objects with ASCII member names, integers, strings, "
                  "arrays, booleans, and null — the protocol's no-float "
                  "value domain. Member order is insignificant; string "
                  "escaping uses the short forms and literal UTF-8.",
        "cases": [
            {
                "id": "unicode-and-escapes",
                "object": value,
                "canonical_hex": canonical.hex(),
                "sha256": hashlib.sha256(canonical).hexdigest(),
            },
            {
                "id": "reordered-whitespace-equivalence",
                "note": "Non-canonical text that parses to the identical "
                        "object and canonicalizes to the identical bytes — "
                        "the property that makes reordering unable to "
                        "change canonical meaning silently.",
                "noncanonical_text": noncanonical_text(value),
                "same_canonical_as": "unicode-and-escapes",
                "sha256": hashlib.sha256(canonical).hexdigest(),
            },
            {
                "id": "nfc-nfd-lookalikes",
                "note": "Two canonically distinct encodings of one visible "
                        "string: distinct bytes, distinct digests, and "
                        "never normalized into each other.",
                "nfc": {"upstream_session_id": SESSION_UNICODE_NFC},
                "nfd": {"upstream_session_id": SESSION_UNICODE_NFD},
                "nfc_sha256": hashlib.sha256(nfc).hexdigest(),
                "nfd_sha256": hashlib.sha256(nfd).hexdigest(),
                "distinct": hashlib.sha256(nfc).hexdigest()
                            != hashlib.sha256(nfd).hexdigest(),
            },
        ],
        "rejections": [
            {
                "id": "duplicate-member-names",
                "text": '{"a":1,"a":2}',
                "reason": "Duplicate members have no RFC 8785 "
                          "canonicalization; parsers disagree on the value, "
                          "so the bytes are malformed for this protocol",
                "error_code": "envelope.malformed",
            },
            {
                "id": "lone-surrogate-escape",
                "text": '{"upstream_session_id":"\\ud800"}',
                "reason": "A lone surrogate is not valid Unicode and has no "
                          "UTF-8 canonical form",
                "error_code": "envelope.malformed",
            },
            {
                "id": "float-in-integer-field",
                "text": '{"uncompressed_size":1.5}',
                "reason": "Protocol structures contain no floating-point "
                          "values; the integer field fails schema validation",
                "error_code": "envelope.schema_invalid",
            },
        ],
    }


def build_keys_record() -> dict:
    return {
        "schema": KEYS_SCHEMA,
        "synthetic": "Every key below is pinned synthetic material derived "
                     "from a label at generation time (SEC-010); private "
                     "halves exist only in generator memory, are never "
                     "written anywhere, and authorize nothing real.",
        "key_id_derivation": "lowercase-hex SHA-256 over the 32 raw "
                             "public-key bytes — the same pinned derivation "
                             "as tools/check-control-schemas.py",
        "assumed_linkage": [
            {"key": "uploader-origin-1", "client_id": ORIGIN_A,
             "linked_tenant": TENANT_1,
             "epochs": {"1": "from 2026-09-01T00:00:00Z",
                        "2": "from 2026-09-11T18:10:00Z"}},
            {"key": "uploader-relay-1", "client_id": RELAY_UPLOADER,
             "linked_tenant": TENANT_1,
             "epochs": {"1": "from 2026-09-01T00:00:00Z"}},
            {"key": "uploader-origin-2", "client_id": ORIGIN_A,
             "linked_tenant": TENANT_2,
             "epochs": {"1": "from 2026-09-15T00:00:00Z"}},
        ],
        "keys": [key.public_record() for key in ALL_SIGNING_KEYS],
    }


# ---------------------------------------------------------------------------
# Manifest assembly.
# ---------------------------------------------------------------------------


def scenario_manifest_entry(scenario: Scenario) -> dict:
    files = {
        "envelope": f"scenarios/{scenario.id}/envelope.json",
        "payload": f"scenarios/{scenario.id}/payload.jsonl",
        "request_body": f"scenarios/{scenario.id}/request.body",
        "attempt": f"scenarios/{scenario.id}/attempt.json",
    }
    if scenario.receipt_key is not None:
        files["receipt"] = f"scenarios/{scenario.id}/receipt.json"
    if scenario.error is not None:
        files["error"] = f"scenarios/{scenario.id}/error.json"
    if scenario.existing_occurrence is not None:
        files["existing_occurrence"] = (
            f"scenarios/{scenario.id}/existing-occurrence.json")
    expect = {
        "outcome": "accepted" if scenario.kind == "valid" else "rejected",
        "http": 200 if scenario.kind == "valid" else scenario.error and None,
        "receipt": scenario.receipt_key is not None,
    }
    if scenario.error is not None:
        expect["http"] = None  # filled from the registry during assembly
        expect["error_code"] = scenario.error["code"]
    entry = {
        "id": scenario.id,
        "kind": scenario.kind,
        "covers": scenario.covers,
        "story": scenario.story,
        "server_time": scenario.server_time,
        "envelope_wire_canonical": scenario.envelope_wire_canonical,
        "files": files,
        "identity": scenario.identity,
        **scenario.extras,
        "expect": expect,
        "asserts": scenario.asserts,
    }
    if scenario.outcomes is not None:
        entry["expect"]["outcomes"] = scenario.outcomes
    if scenario.alteration is not None:
        entry["alteration"] = scenario.alteration
    return entry


def build_manifest(scenarios: list[Scenario], files: dict[str, bytes]) -> dict:
    entries = []
    for scenario in scenarios:
        if scenario.alteration is not None:
            if scenario.alteration["kind"] == "payload-byte-flip":
                payload = bytearray(scenario.payload)
                offset = scenario.alteration["offset_in_payload"]
                payload[offset] ^= scenario.alteration["bit"]
                scenario.payload = bytes(payload)
            body = scenario.body_bytes(boundary=scenario.alter_boundary)
            scenario.altered_body = body
        entries.append(scenario_manifest_entry(scenario))

    # Fill the expected HTTP status and retryability from the registry:
    # the code pins the status, its class pins the retryability.
    registry = load_error_registry()
    for entry in entries:
        if entry["expect"]["outcome"] == "rejected":
            code = registry["codes"][entry["expect"]["error_code"]]
            entry["expect"]["http"] = code["http"]
            entry["expect"]["retryable"] = (
                registry["classes"][code["class"]]["retryable"])
            entry["expect"]["class"] = code["class"]

    baseline = next(e for e in entries if e["id"] == "valid-direct-baseline")
    retry = next(e for e in entries if e["id"] == "valid-retry-after-window")
    relay = next(e for e in entries if e["id"] == "valid-relay-upload")
    cross = next(e for e in entries
                 if e["id"] == "valid-cross-tenant-second")
    return {
        "schema": BUNDLE_SCHEMA,
        "scan_version": 1,
        "authority": {
            "envelope": "schemas/v1/ingest-envelope.json",
            "request": "schemas/v1/ingest-request.json",
            "receipt": "schemas/v1/ingest-receipt.json",
            "error": "schemas/v1/ingest-error.json",
            "occurrence": "schemas/v1/occurrence-manifest.json",
            "vocabulary": "schemas/v1/common.json",
            "derivations": "schemas/v1/ingest-identifiers.json",
            "error_registry": "tools/error-codes.toml",
            "keys": "keys.json",
            "derivation_vectors": "derivations.json",
            "canonicalization_vectors": "canonicalization.json",
        },
        "synthetic": "Every identifier, timestamp, key, signature, and "
                     "payload byte in this bundle is pinned synthetic data "
                     "(SEC-010); nothing is copied from any real harness "
                     "store, and the keys authorize nothing real.",
        "conventions": {
            "canonical_json": "RFC 8785 as consumed by every digest: "
                              "ASCII-sorted members, no insignificant "
                              "whitespace, short escapes plus literal "
                              "UTF-8, no floats",
            "metadata_files": "canonical JSON plus one trailing LF "
                              "(keys.json, derivations.json, "
                              "canonicalization.json, attempt.json, "
                              "receipt.json, error.json, manifest.json)",
            "envelope_part_bytes": "the exact bytes of multipart part one: "
                                   "canonical JSON with no trailing LF "
                                   "(scenarios/valid-reordered-envelope-"
                                   "framing is the deliberate exception)",
            "payload_part_bytes": "the exact payload part bytes; identity "
                                  "transport only in v1 vectors, because a "
                                  "golden zstd transport digest would pin "
                                  "one compressor build and stop being "
                                  "language-neutral",
            "multipart_framing": "--<boundary> CRLF, lowercase content-type "
                                 "header, CRLF, part bytes, CRLF, repeat, "
                                 "closing --<boundary>-- CRLF; the exact "
                                 "recipe any implementer can rebuild "
                                 "byte-identically",
            "digests": "envelope_digest = SHA-256(canonical envelope "
                       "bytes); request_content_digest = SHA-256(whole "
                       "body); blob and transport digests = SHA-256 of the "
                       "canonical and as-transported payload",
            "signature_inputs": "attempt_input_hex carries the exact "
                                "Ed25519 message; receipt and certificate "
                                "signed bytes are the canonical JSON of the "
                                "record minus its signature member, no "
                                "trailing LF, digest pinned via "
                                "*signed_bytes_sha256",
            "timeline": "two commit cohorts (2026-09-11 under receipt-key-1, "
                        "2026-09-22 under receipt-key-2 and tenant two's "
                        "receipt-key-3) inside overlapping 37-day receipt-"
                        "key windows: 30-day rotation plus the 7-day "
                        "signing overlap",
            "authorization_window_seconds": AUTHORIZATION_WINDOW_SECONDS,
            "clock_skew_allowance_seconds": CLOCK_SKEW_SECONDS,
            "envelope_canonical_max_bytes": ENVELOPE_CANONICAL_MAX_BYTES,
        },
        "invariants": {
            "retry_identity_equality": {
                "scenarios": ["valid-direct-baseline",
                              "valid-retry-after-window"],
                "statement": "the frozen envelope, occurrence, attestation, "
                             "blob, and all object keys are byte-identical "
                             "across the pair while authorization, "
                             "signature, and outcomes differ (STO-004)",
                "identical_fields": ["request_id", "occurrence_id",
                                     "attestation_id", "blob_digest"],
            },
            "relay_occurrence_equality": {
                "scenarios": ["valid-direct-baseline", "valid-relay-upload"],
                "statement": "one blob object key and one occurrence object "
                             "key serve both uploaders, with two "
                             "attestation keys beside them (EC-05A, STO-013)",
                "shared": {
                    "blob_object_key": baseline["identity"]["blob_object_key"],
                    "occurrence_object_key":
                        baseline["identity"]["occurrence_object_key"],
                    "relay_attestation_object_key":
                        relay["identity"]["attestation_object_key"],
                },
            },
            "cross_tenant_separation": {
                "scenarios": ["valid-direct-baseline",
                              "valid-cross-tenant-second"],
                "statement": "tenant_id is the only changed identity input, "
                             "and session hash, occurrence, attestation, "
                             "and every object key change with it while the "
                             "blob digest is shared (EC-03, STO-002)",
                "shared_blob_digest":
                    baseline["identity"]["blob_digest"]
                    == cross["identity"]["blob_digest"],
                "distinct_session_hashes":
                    baseline["identity"]["session_hash"]
                    != cross["identity"]["session_hash"],
            },
            "unicode_normalization_never_applied": {
                "vector": "derivations.json cases unicode-nfc and unicode-nfd",
                "statement": "composed and decomposed forms of one visible "
                             "session string hash to different identities "
                             "and never merge (plan Section 7.4)",
            },
            "retry_outcomes_honest": {
                "statement": "the retry receipt reports already_present "
                             "rather than created: deterministic identities "
                             "converge and the outcome keeps the report "
                             "truthful (RCPT-003, RCPT-004)",
            },
            "receipt_rotation_overlap": {
                "statement": "cohort A receipts still verify during cohort "
                             "B: receipt-key-1's window (until 2026-09-26) "
                             "overlaps receipt-key-2's (from 2026-09-19) by "
                             "the mandated seven days, and verification of "
                             "retained receipts never expires (ID-009)",
            },
            "receipt_identity_binding": {
                "statement": "every valid scenario's receipt names exactly "
                             "the envelope-derived occurrence, attestation, "
                             "blob, and object keys, and the embedded "
                             "certificate's tenant matches (CAP-006, "
                             "VAL-002)",
            },
        },
        "scenarios": entries,
        "files": [
            {
                "path": path,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for path, data in sorted(files.items())
            if path != "manifest.json"
        ],
    }


def load_error_registry() -> dict:
    import tomllib
    with ERROR_REGISTRY.open("rb") as handle:
        return tomllib.load(handle)


# ---------------------------------------------------------------------------
# Bundle assembly, generation, verification.
# ---------------------------------------------------------------------------


def build_bundle() -> dict[str, bytes]:
    scenarios = build_scenarios()
    files: dict[str, bytes] = {}
    for scenario in scenarios:
        # Rebuild altered bodies after the manifest-time mutation bookkeeping.
        if getattr(scenario, "altered_body", None) is not None:
            scenario.body_override = scenario.altered_body
        built = build_scenario_files(scenario)
        for name, data in built.items():
            files[f"scenarios/{scenario.id}/{name}"] = data
    files["keys.json"] = metadata_bytes(build_keys_record())
    files["derivations.json"] = metadata_bytes(build_derivations(scenarios))
    files["canonicalization.json"] = metadata_bytes(build_canonicalization())
    files["manifest.json"] = metadata_bytes(
        build_manifest(scenarios, files))
    return files


def build_scenario_files(scenario: Scenario) -> dict[str, bytes]:
    """Build one scenario's files, applying any in-transit alteration."""
    if getattr(scenario, "body_override", None) is not None:
        # The signature was taken over the original body; the transmitted
        # body is the altered one.
        original = scenario.body_bytes()
        covered = scenario.covered_values(original)
        message = scenario.attempt_input_bytes(covered)
        signature = scenario.uploader_key.sign(message)
        attempt = attempt_record(covered, signature)
        files = {
            "envelope.json": scenario.envelope_wire_bytes(),
            "payload.jsonl": scenario.payload,
            "request.body": scenario.body_override,
            "attempt.json": metadata_bytes(attempt),
        }
        scenario.extras = {
            "signing": {
                "signing_key": scenario.uploader_key.name,
                "signing_key_id": scenario.uploader_key.key_id,
                "construction": "ingest-attempt-v1",
                "covered_order": [
                    "http_method", "route", "content_type",
                    "request_content_digest", "envelope_digest",
                    "payload_canonical_digest", "payload_transport_digest",
                    "uploader_key_id", "authorization_epoch",
                    "authorization_timestamp",
                ],
                "attempt_input_sha256": hashlib.sha256(message).hexdigest(),
                "attempt_input_hex": message.hex(),
                "attempt_signature": signature,
                "signed_body_sha256": hashlib.sha256(original).hexdigest(),
            },
        }
        if scenario.error is not None:
            files["error.json"] = metadata_bytes(scenario.error)
        return files
    return scenario.build()


def attempt_record(covered: dict, signature: str) -> dict:
    return {
        "http_method": covered["http_method"],
        "route": covered["route"],
        "content_type": covered["content_type"],
        "request_content_digest": covered["request_content_digest"],
        "envelope_digest": covered["envelope_digest"],
        "payload_canonical_digest": covered["payload_canonical_digest"],
        "payload_transport_digest": covered["payload_transport_digest"],
        "uploader_key_id": covered["uploader_key_id"],
        "authorization_epoch": covered["authorization_epoch"],
        "authorization_timestamp": covered["authorization_timestamp"],
        "signature_algorithm": "ed25519",
        "signature": signature,
    }


def write_bundle(output: Path, files: dict[str, bytes]) -> None:
    marker = output / "manifest.json"
    if output.exists() and any(output.iterdir()) and not (
        marker.exists()
        and json.loads(marker.read_text(encoding="utf-8")).get("schema")
        == BUNDLE_SCHEMA
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
        import jsonschema
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
    except ImportError:
        return None

    def validator(schema_path: Path):
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
        registry = Registry().with_resource(
            "urn:agent-archivist:schema:v1:common",
            Resource.from_contents(common, default_specification=DRAFT202012),
        )
        return jsonschema.Draft202012Validator(schema, registry=registry)

    return validator


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

    manifest = json.loads(expected["manifest.json"])
    metadata_endings = ("manifest.json", "keys.json", "derivations.json",
                        "canonicalization.json", "attempt.json",
                        "receipt.json", "error.json",
                        "existing-occurrence.json")

    # Canonical-format guard: metadata files carry canonical JSON plus one
    # LF; scenario envelopes are bare canonical bytes except the one
    # deliberately non-canonical framing vector.
    for path in sorted(expected):
        if path.endswith(metadata_endings):
            if path in on_disk and metadata_bytes(
                    json.loads(expected[path])) != expected[path]:
                failures.append(f"non-canonical formatting in {path}")
        elif path.endswith("envelope.json"):
            scenario_id = path.split("/")[1]
            entry = next(e for e in manifest["scenarios"]
                         if e["id"] == scenario_id)
            if entry["envelope_wire_canonical"] and path in on_disk:
                raw = expected[path]
                if canonical_bytes(json.loads(raw)) != raw:
                    failures.append(f"non-canonical envelope bytes in {path}")
                if raw.endswith(b"\n"):
                    failures.append(f"envelope part must not end with LF: "
                                    f"{path}")

    # Content safety: no private seed material anywhere in the bundle.
    for key in ALL_SIGNING_KEYS:
        seed_hex = key.seed_hex()
        for path, data in expected.items():
            if seed_hex.encode() in data or seed_hex.upper().encode() in data:
                failures.append(f"private seed material leaked into {path}")

    # Schema validation of every conformant instance.
    make_validator = load_jsonschema()
    if make_validator is None:
        print("jsonschema is not installed: instance validation skipped "
              "(pip install jsonschema)", file=sys.stderr)
        return 4
    validators = {
        "envelope": make_validator(ENVELOPE_SCHEMA),
        "attempt": make_validator(REQUEST_SCHEMA),
        "receipt": make_validator(RECEIPT_SCHEMA),
        "error": make_validator(ERROR_SCHEMA),
        "existing_occurrence": make_validator(OCCURRENCE_SCHEMA),
    }
    for entry in manifest["scenarios"]:
        sid = entry["id"]
        envelope = json.loads(expected[f"scenarios/{sid}/envelope.json"])
        if entry["kind"] == "valid" and not any(
                error in envelope for error in ("commit_time",)):
            for error in validators["envelope"].iter_errors(envelope):
                failures.append(f"{sid}/envelope.json: {error.message}")
        attempt = json.loads(expected[f"scenarios/{sid}/attempt.json"])
        for error in validators["attempt"].iter_errors(attempt):
            failures.append(f"{sid}/attempt.json: {error.message}")
        if "receipt" in entry["files"]:
            receipt = json.loads(
                expected["scenarios/" + sid + "/receipt.json"])
            for error in validators["receipt"].iter_errors(receipt):
                failures.append(f"{sid}/receipt.json: {error.message}")
        if "error" in entry["files"]:
            body = json.loads(expected[f"scenarios/{sid}/error.json"])
            for error in validators["error"].iter_errors(body):
                failures.append(f"{sid}/error.json: {error.message}")
        if "existing_occurrence" in entry["files"]:
            record = json.loads(
                expected[f"scenarios/{sid}/existing-occurrence.json"])
            for error in validators["existing_occurrence"].iter_errors(record):
                failures.append(f"{sid}/existing-occurrence.json: "
                                f"{error.message}")

    # Every invalid vector's reserved/enum defect must actually trip the
    # envelope schema, and every valid envelope must pass it.
    for entry in manifest["scenarios"]:
        sid = entry["id"]
        envelope = json.loads(expected[f"scenarios/{sid}/envelope.json"])
        errors = list(validators["envelope"].iter_errors(envelope))
        if entry["id"] == "invalid-reserved-field" and not errors:
            failures.append("invalid-reserved-field must fail the envelope "
                            "schema (reserved-name block)")
        if entry["id"] == "invalid-unknown-enum-value" and not errors:
            failures.append("invalid-unknown-enum-value must fail the "
                            "envelope schema (closed enum)")
        if entry["kind"] == "valid" and errors:
            failures.append(f"{sid}: valid envelope failed schema: "
                            f"{errors[0].message}")

    # Error-registry coherence: codes exist, class status and retryability
    # agree with the registry, and the golden bodies match their code.
    registry = load_error_registry()
    for entry in manifest["scenarios"]:
        if entry["expect"]["outcome"] != "rejected":
            continue
        sid = entry["id"]
        code = entry["expect"]["error_code"]
        if code not in registry["codes"]:
            failures.append(f"{sid}: error code {code} missing from the "
                            f"registry")
            continue
        record = registry["codes"][code]
        retryable = registry["classes"][record["class"]]["retryable"]
        if entry["expect"]["http"] != record["http"]:
            failures.append(f"{sid}: expected HTTP {entry['expect']['http']} "
                            f"but the registry pins {record['http']}")
        if entry["expect"]["retryable"] != retryable:
            failures.append(f"{sid}: retryable disagrees with the registry")
        body = json.loads(expected[f"scenarios/{sid}/error.json"])
        if body["code"] != code or body["retryable"] != retryable:
            failures.append(f"{sid}: golden error body disagrees with the "
                            f"registry entry")

    # Cryptographic verification with the independent pure-Python verifier.
    keys = {record["name"]: record
            for record in json.loads(expected["keys.json"])["keys"]}
    for record in keys.values():
        if key_id_of(record["public_key"]) != record["key_id"]:
            failures.append(f"keys.json: key_id of {record['name']} is not "
                            f"the pinned derivation")
    signatures_checked = 0
    for entry in manifest["scenarios"]:
        sid = entry["id"]
        attempt = json.loads(expected[f"scenarios/{sid}/attempt.json"])
        signing = entry["signing"]
        public = keys[signing["signing_key"]]["public_key"]
        message = bytes.fromhex(signing["attempt_input_hex"])
        if framing_from_attempt(attempt) != message:
            failures.append(f"{sid}: attempt_input_hex is not the pinned "
                            f"framing of the attempt record's own fields")
        if not ed25519_verify(public, attempt["signature"], message):
            failures.append(f"{sid}: attempt signature fails independent "
                            f"verification")
        # A one-bit change anywhere in the covered material must break it.
        tampered = bytearray(message)
        tampered[-1] ^= 0x01
        if ed25519_verify(public, attempt["signature"], bytes(tampered)):
            failures.append(f"{sid}: attempt signature accepts tampered "
                            f"covered material")
        bad_signature = bytearray(bytes.fromhex(attempt["signature"]))
        bad_signature[0] ^= 0x01
        if ed25519_verify(public, bytes(bad_signature).hex(), message):
            failures.append(f"{sid}: verification accepts a tampered "
                            f"signature")
        signatures_checked += 1
        if "receipt" in entry["files"]:
            receipt = json.loads(expected[f"scenarios/{sid}/receipt.json"])
            certificate = dict(receipt["certificate"])
            authority_signature = certificate.pop("authority_signature")
            authority = keys[next(k["name"] for k in keys.values()
                                  if k["key_id"]
                                  == receipt["certificate"]
                                  ["authority_key_id"])]["public_key"]
            if not ed25519_verify(authority, authority_signature,
                                  canonical_bytes(certificate)):
                failures.append(f"{sid}: certificate authority signature "
                                f"fails independent verification")
            receipt_body = dict(receipt)
            signature = receipt_body.pop("signature")
            signed = canonical_bytes(receipt_body)
            if hashlib.sha256(signed).hexdigest() != signing[
                    "receipt_signed_bytes_sha256"]:
                failures.append(f"{sid}: receipt signed-byte digest drifted")
            if not ed25519_verify(certificate["public_key"], signature,
                                  signed):
                failures.append(f"{sid}: receipt signature fails "
                                f"independent verification")
            # Receipt chain cross-fields.
            if certificate["key_id"] != receipt["receipt_key_id"]:
                failures.append(f"{sid}: certificate key_id does not match "
                                f"receipt_key_id")
            if certificate["tenant_id"] != receipt["tenant_id"]:
                failures.append(f"{sid}: certificate tenant does not match "
                                f"the receipt")
            if not (certificate["valid_from"] <= receipt["commit_time"]
                    <= certificate["valid_until"]):
                failures.append(f"{sid}: commit_time is outside the "
                                f"certificate signing window")
            for field in ("tenant_id", "request_id", "occurrence_id",
                          "attestation_id", "blob_digest", "blob_object_key",
                          "occurrence_object_key",
                          "attestation_object_key"):
                expected_value = (entry["identity"][field]
                                  if field in entry["identity"]
                                  else json.loads(
                                      expected[f"scenarios/{sid}/"
                                               f"envelope.json"])[field])
                if receipt[field] != expected_value:
                    failures.append(f"{sid}: receipt {field} does not match "
                                    f"the frozen envelope derivation")
            signatures_checked += 2

    # Identity re-derivation from each derivation vector's own inputs.
    derivations = json.loads(expected["derivations.json"])
    for case in derivations["cases"]:
        inputs = case["inputs"]
        payload = inputs["canonical_payload"].encode("utf-8")
        probe = finalize_envelope(make_envelope(
            tenant_id=inputs["tenant_id"],
            origin_client_id=inputs["origin_client_id"],
            harness=inputs["harness"],
            upstream_session_id=inputs["upstream_session_id"],
            artifact_kind=inputs["artifact_kind"],
            adapter_id=inputs["adapter_id"],
            adapter_projection_version=inputs["adapter_projection_version"],
            adapter_artifact_id=inputs["adapter_artifact_id"],
            generation=inputs["generation"],
            range_kind=inputs["range_kind"],
            range_start=inputs["range_start"],
            range_end=inputs["range_end"],
            uploader_client_id=inputs["uploader_client_id"],
            request_id=inputs["request_id"]), payload)
        identity = derive_identity(probe)
        for field, value in case["expected"].items():
            if identity[field] != value:
                failures.append(f"derivations.json {case['id']}: {field} "
                                f"is not re-derivable from the inputs")
    for name, preimage in derivations["preimages"].items():
        if "sha256" not in preimage:
            continue
        if hashlib.sha256(bytes.fromhex(preimage["hex"])).hexdigest() != \
                preimage["sha256"]:
            failures.append(f"derivations.json preimage {name}: hex does "
                            f"not hash to the pinned digest")

    # Canonicalization vectors recompute from their own data.
    canon = json.loads(expected["canonicalization.json"])
    cases = {case["id"]: case for case in canon["cases"]}
    base = cases["unicode-and-escapes"]
    if canonical_bytes(base["object"]).hex() != base["canonical_hex"]:
        failures.append("canonicalization.json: canonical_hex drifted")
    reordered = cases["reordered-whitespace-equivalence"]
    if canonical_bytes(json.loads(reordered["noncanonical_text"])) != \
            canonical_bytes(base["object"]):
        failures.append("canonicalization.json: non-canonical text does "
                        "not parse back to the same canonical bytes")
    look = cases["nfc-nfd-lookalikes"]
    if not look["distinct"]:
        failures.append("canonicalization.json: NFC and NFD must stay "
                        "distinct")

    # Cross-scenario invariants.
    entries = {e["id"]: e for e in manifest["scenarios"]}
    baseline, retry = (entries["valid-direct-baseline"],
                       entries["valid-retry-after-window"])
    baseline_envelope = json.loads(
        expected["scenarios/valid-direct-baseline/envelope.json"])
    retry_envelope = json.loads(
        expected["scenarios/valid-retry-after-window/envelope.json"])
    for field in manifest["invariants"]["retry_identity_equality"][
            "identical_fields"]:
        if field in baseline["identity"]:
            if baseline["identity"][field] != retry["identity"][field]:
                failures.append(f"invariant retry_identity_equality broke "
                                f"on {field}")
        elif baseline_envelope.get(field) != retry_envelope.get(field):
            failures.append(f"invariant retry_identity_equality broke on "
                            f"{field}")
    if baseline["expect"]["outcomes"] == retry["expect"]["outcomes"]:
        failures.append("invariant retry_outcomes_honest: outcomes must "
                        "differ between first commit and retry")
    relay = entries["valid-relay-upload"]
    if relay["identity"]["occurrence_id"] != baseline["identity"][
            "occurrence_id"]:
        failures.append("invariant relay_occurrence_equality broke")
    if relay["identity"]["attestation_id"] == baseline["identity"][
            "attestation_id"]:
        failures.append("relay must carry its own attestation identity")
    cross = entries["valid-cross-tenant-second"]
    if not manifest["invariants"]["cross_tenant_separation"][
            "distinct_session_hashes"]:
        failures.append("invariant cross_tenant_separation broke")
    if cross["identity"]["blob_digest"] != baseline["identity"]["blob_digest"]:
        failures.append("cross-tenant pair must share one blob digest")
    if cross["identity"]["blob_object_key"] == baseline["identity"][
            "blob_object_key"]:
        failures.append("blob object keys must be tenant-scoped")
    conflict = entries["invalid-integrity-conflict"]
    existing = json.loads(expected["scenarios/"
                                   + conflict["id"]
                                   + "/existing-occurrence.json"])
    if existing["occurrence_id"] != conflict["identity"]["occurrence_id"]:
        failures.append("conflict vector: existing object is not at the "
                        "derived occurrence key")
    if metadata_bytes(existing) == metadata_bytes(would_be_occurrence(
            conflict, expected)):
        failures.append("conflict vector: existing object must differ from "
                        "the submission's canonical bytes")

    # Object keys must satisfy the patterns common.json pins.
    common = json.loads(COMMON_SCHEMA.read_text(encoding="utf-8"))
    key_defs = {"blob_object_key": "blob-object-key",
                "occurrence_object_key": "occurrence-object-key",
                "attestation_object_key": "attestation-object-key"}
    for entry in manifest["scenarios"]:
        for field, definition in key_defs.items():
            pattern = re.compile(common["$defs"][definition]["pattern"])
            if not pattern.fullmatch(entry["identity"][field]):
                failures.append(f"{entry['id']}: {field} does not match the "
                                f"{definition} pattern")

    # Envelope size cap.
    for entry in manifest["scenarios"]:
        raw = expected[f"scenarios/{entry['id']}/envelope.json"]
        if len(canonical_bytes(json.loads(raw))) > ENVELOPE_CANONICAL_MAX_BYTES:
            failures.append(f"{entry['id']}: canonical envelope exceeds the "
                            f"64 KiB cap")

    if failures:
        print(f"conformance corpus verification FAILED ({len(failures)}):",
              file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 3
    valid = sum(1 for e in manifest["scenarios"] if e["kind"] == "valid")
    invalid = len(manifest["scenarios"]) - valid
    print(
        "conformance corpus verified: "
        f"{valid} valid + {invalid} invalid scenarios, "
        f"{signatures_checked} signatures re-verified independently "
        "(pure-Python Ed25519), all files byte-identical and schema-valid"
    )
    return 0


def framing_from_attempt(attempt: dict) -> bytes:
    """Rebuild the ingest-attempt-v1 message from the attempt record's own
    fields — the framing an independent implementer starts from."""
    return framing_bytes("ingest-attempt-v1", [
        text(attempt["http_method"]),
        text(attempt["route"]),
        text(attempt["content_type"]),
        digest(attempt["request_content_digest"]),
        digest(attempt["envelope_digest"]),
        digest(attempt["payload_canonical_digest"]),
        digest(attempt["payload_transport_digest"]),
        digest(attempt["uploader_key_id"]),
        u63(attempt["authorization_epoch"]),
        text(attempt["authorization_timestamp"]),
    ])


def would_be_occurrence(entry: dict, files: dict[str, bytes]) -> dict:
    """The occurrence manifest this scenario's envelope would commit — the
    canonical server-side object, from the envelope's frozen fields."""
    envelope = json.loads(
        files[f"scenarios/{entry['id']}/envelope.json"])
    identity = entry["identity"]
    manifest = {
        "occurrence_version": 1,
        "occurrence_id": envelope["occurrence_id"],
        "tenant_id": envelope["tenant_id"],
        "origin_client_id": envelope["origin_client_id"],
        "harness": envelope["harness"],
        "upstream_session_id": envelope["upstream_session_id"],
        "id_source": envelope["id_source"],
        "session_hash": identity["session_hash"],
        "artifact_kind": envelope["artifact_kind"],
        "adapter_id": envelope["adapter_id"],
        "adapter_projection_version": envelope["adapter_projection_version"],
        "adapter_artifact_id": envelope["adapter_artifact_id"],
        "artifact_hash": identity["artifact_hash"],
        "generation": envelope["generation"],
        "range_kind": envelope["range_kind"],
        "range_start": envelope["range_start"],
        "range_end": envelope["range_end"],
        "blob_digest": identity["blob_digest"],
        "storage_profile": envelope["storage_profile"],
    }
    if "source_time" in envelope:
        manifest["source_time"] = envelope["source_time"]
    return manifest


# ---------------------------------------------------------------------------
# Self-test: prove the verification path rejects what it must.
# ---------------------------------------------------------------------------


def self_test() -> int:
    checks: list[tuple[str, bool]] = []

    def check(name: str, condition: bool) -> None:
        checks.append((name, condition))

    # The independent verifier accepts a freshly signed attempt and
    # rejects every tampered variant of it.
    key = SigningKey("self-test-transient", "uploader")
    message = framing_bytes("ingest-attempt-v1", [text("POST")])
    signature = key.sign(message)
    check("fresh signature verifies",
          ed25519_verify(key.public_key, signature, message))
    check("wrong message rejected",
          not ed25519_verify(key.public_key, signature,
                             message + b"x"))
    flipped = bytearray(bytes.fromhex(signature))
    flipped[63] ^= 0x01
    check("flipped signature rejected",
          not ed25519_verify(key.public_key, bytes(flipped).hex(), message))
    other = SigningKey("self-test-other", "uploader")
    check("wrong key rejected",
          not ed25519_verify(other.public_key, signature, message))
    check("overlapping key ids stay distinct",
          key.key_id != other.key_id)

    # Key IDs are the pinned derivation.
    check("key id derivation", key_id_of(key.public_key) == key.key_id)

    # Canonical JSON: member order insignificant, whitespace insignificant,
    # NFC and NFD distinct, lone surrogates rejected, non-ASCII member
    # names rejected as outside the pinned domain.
    value = {"b": 1, "a": "ünicode 🤖"}
    check("member order insignificant",
          canonical_bytes(value) == canonical_bytes({"a": "ünicode 🤖",
                                                     "b": 1}))
    check("float values rejected outside the domain",
          not _canonicalizable(1.5))
    check("lone surrogate rejected",
          not _canonicalizable("caf\ud800e"))
    try:
        canonical_text({"ḱey": 1})
        check("non-ascii member name rejected", False)
    except ValueError:
        check("non-ascii member name rejected", True)

    # The framing helpers are byte-exact about label, delimiter, and
    # length prefixes.
    stream = framing_bytes("x", [b"ab", b""])
    check("framing is label+null+length-prefixed fields",
          stream == b"x\x00" + (2).to_bytes(8, "big") + b"ab"
          + (0).to_bytes(8, "big"))

    # A reserved-name envelope must fail the shipped schema; a valid one
    # must pass it.
    make_validator = load_jsonschema()
    if make_validator is None:
        print("jsonschema is not installed: self-test cannot run",
              file=sys.stderr)
        return 4
    validator = make_validator(ENVELOPE_SCHEMA)
    payload = jsonl_bytes(PAYLOAD_BASELINE_RECORDS)
    good = finalize_envelope(make_envelope(), payload)
    check("valid envelope passes schema",
          not list(validator.iter_errors(good)))
    reserved = {**good, "signature": "0" * 128}
    check("reserved name fails schema",
          bool(list(validator.iter_errors(reserved))))
    bad_enum = {**good, "storage_profile": "gzip-v9"}
    check("unknown enum fails schema",
          bool(list(validator.iter_errors(bad_enum))))

    # The error registry renders the golden bodies' codes.
    registry = load_error_registry()
    check("registry pins integrity conflict at 409",
          registry["codes"]["storage.integrity_conflict"]["http"] == 409
          and registry["codes"]["storage.integrity_conflict"]["class"]
          == "integrity_conflict")

    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if failed:
        print(f"self-test FAILED ({len(failed)})", file=sys.stderr)
        return 3
    print(f"self-test passed: {len(checks)} checks")
    return 0


def _canonicalizable(value: object) -> bool:
    try:
        canonical_text(value)
        return True
    except (ValueError, UnicodeEncodeError):
        return False


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
    args = parser.parse_args(argv)

    if args.generate is not None:
        write_bundle(Path(args.generate), build_bundle())
        return 0
    if args.self_test:
        return self_test()
    return verify_bundle()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
