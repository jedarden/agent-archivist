#!/usr/bin/env python3
"""Standalone contract verifier for the Agent Archivist ingest protocol.

Implements the Phase 1 exit gate (plan Section 8): *the Rust implementation
and a standalone verifier that does not import the protocol crate produce
identical canonical bytes, signatures, IDs, and keys* — and, on the golden
vectors, identical rejection outcomes (bead ``aa-51407b48``; the corpus
itself is bead ``aa-cfc9f227``).

**Standalone means standalone.** This file imports nothing from the repo: no
Rust crate, no generator, no sibling tool. Everything the wire contract
defines is re-implemented here from the normative sources alone
(``schemas/v1/ingest-identifiers.json``, ``schemas/v1/common.json``,
``schemas/v1/ingest-envelope.json``, RFC 8785, RFC 8032):

* bounded RFC 8785 canonical JSON over the protocol's no-float domain;
* the labeled, length-prefixed identity framing and the three object-key
  constructions;
* the full version 1 envelope validation ladder, reserved names through the
  canonical size cap, so rejection outcomes are classified independently;
* Ed25519 verification (RFC 8032) in pure Python, pinned against the RFC's
  own test vectors during ``--self-test`` — never against the corpus, which
  is the thing being verified here.

SHA-256 and SHA-512 come from the standard library's ``hashlib`` — a third
implementation, independent of both the Rust crate's hand-written SHA-256
and of anything the corpus generator used.

Subcommands:

  verify (default)
        Replay the committed conformance corpus
        (``schemas/v1/examples/conformance``) with the independent
        implementations above and check every golden value: canonical bytes,
        digests, identifier hashes, object keys, key IDs, the
        ``ingest-attempt-v1`` signing preimage, every Ed25519 signature
        (attempt, certificate authority, receipt), the receipt chains, the
        multipart framing, the attempt-level outcome classification against
        every golden error body, and the cross-scenario invariants. Then
        print the answer sheet (below) or, with ``--quiet``, a count only.

  compare
        Compute the answer sheet, obtain the Rust implementation's answer
        sheet by running ``cargo run -p archivist-protocol --bin
        conformance-replay`` (or read one with ``--rust-report FILE``), and
        require the two to be byte-identical — the cross-implementation
        diff the exit gate names. Implies ``verify``.

  self-test
        Prove the rejection paths in memory, without touching the corpus or
        the network: RFC 8032 test vectors accept and bit-flips reject,
        canonicalization accepts/escapes/sorts/rejects exactly per RFC 8785,
        the envelope ladder rejects each invalid class at the right code,
        tampered goldens are caught, and the report diff detects a
        one-character divergence. Also pins the framing and key-ID
        derivations against hand-computed constants.

Answer-sheet rows (identical spec to the Rust binary's, so the diff is
meaningful): one canonical-JSON line per vector, sorted by
``(row, id, source)``, LF-terminated — ``canonicalization`` rows carry
``canonical_hex``; ``canonicalization_rejection`` rows carry the wire
``error_code``; ``derivation`` rows carry every identity and object key;
``key_id`` rows carry the key-ID derivation; ``scenario`` rows carry the
envelope outcome (plus canonical bytes, digest, re-derived identities, and
object keys when accepted) and always the payload, transport, and request
digests plus the signing-preimage digest.

Exit codes: 0 pass; 2 answer-sheet divergence in ``compare``; 3 golden or
self-test failure; 4 a prerequisite (cargo) is unavailable; 5 the corpus is
missing or malformed. Every message is content-free: identifiers, closed
enums, hex digests, and repo-relative paths only.

Usage::

    tools/contract-verifier.py [--corpus DIR] [--quiet]
    tools/contract-verifier.py compare [--rust-report FILE]
    tools/contract-verifier.py self-test
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = REPO_ROOT / "schemas" / "v1" / "examples" / "conformance"

EXIT_PASS = 0
EXIT_DIVERGENCE = 2
EXIT_FAILURE = 3
EXIT_PREREQUISITE = 4
EXIT_CORRUPT = 5

# manifest.json "conventions": the authorization window and the clock-skew
# allowance a verifier's clock gets, and the canonical envelope cap.
AUTHORIZATION_WINDOW_SECONDS = 300
CLOCK_SKEW_SECONDS = 300
ENVELOPE_CANONICAL_MAX_BYTES = 65536

ENVELOPE_MEDIA_TYPE = "application/vnd.agent-archivist.envelope+json;version=1"
IDENTITY_MEDIA_TYPE = "application/octet-stream"
ERROR_SCHEMA_NAME = "archivist.error/v1"

# envelope.rs RESERVED_FIELDS: per-attempt and server names an envelope must
# never freeze.
RESERVED_FIELDS = (
    "authorization_epoch",
    "authorization_key_id",
    "authorization_timestamp",
    "commit_time",
    "correlation_id",
    "signature",
)

# The closed v1 enum sets (schemas/v1/common.json). Unknown tokens fail
# closed at schema validation.
ENUMS = {
    "artifact_kind": ("file-slice", "database-projection"),
    "range_kind": ("byte", "event"),
    "id_source": ("upstream", "synthetic"),
    "storage_profile": ("zstd-v1",),
    "transport_encoding": ("identity", "zstd"),
    "incoming_checksum_algorithm": ("sha256",),
}


class VerificationFailure(Exception):
    """A golden value or self-test expectation did not hold."""


class CorpusError(Exception):
    """The corpus is missing or internally malformed."""


# ---------------------------------------------------------------------------
# RFC 8785 canonical JSON over the protocol's no-float domain.
#
# Values are None | bool | int | str | list | Obj. Objects reject duplicate
# members at parse time and serialize members in UTF-16 code-unit order.
# ---------------------------------------------------------------------------


class Obj:
    """A JSON object with uniquely named members."""

    def __init__(self) -> None:
        self.members: dict[str, object] = {}

    def set(self, name: str, value: object) -> None:
        self.members[name] = value

    def get(self, name: str) -> object | None:
        return self.members.get(name)

    def has(self, name: str) -> bool:
        return name in self.members

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self.members

    def remove(self, name: str) -> None:
        self.members.pop(name, None)

    def names(self) -> list[str]:
        return sorted(self.members, key=utf16_key)

    def items(self) -> list[tuple[str, object]]:
        return [(name, self.members[name]) for name in self.names()]


def utf16_key(text: str) -> bytes:
    """The RFC 8785 §3.2.3 member order: UTF-16 code-unit sequence."""
    return text.encode("utf-16-be", "surrogatepass")


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def serialize_string(text: str, out: list[str]) -> None:
    out.append('"')
    for char in text:
        escape = _ESCAPES.get(char)
        if escape is not None:
            out.append(escape)
        elif char < " ":
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')


def canonical_bytes(value: object) -> bytes:
    """The RFC 8785 canonical serialization of a protocol value."""
    out: list[str] = []
    _write(value, out)
    return "".join(out).encode("utf-8")


def _write(value: object, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            raise VerificationFailure("integer outside the protocol's i64 domain")
        out.append(str(value))
    elif isinstance(value, str):
        serialize_string(value, out)
    elif isinstance(value, list):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _write(item, out)
        out.append("]")
    elif isinstance(value, Obj):
        out.append("{")
        for index, (name, member) in enumerate(value.items()):
            if index:
                out.append(",")
            serialize_string(name, out)
            out.append(":")
            _write(member, out)
        out.append("}")
    else:
        raise VerificationFailure(f"value of unserializable type {type(value).__name__}")


class JsonRejected(Exception):
    """A byte sequence is not a protocol JSON value.

    ``code`` is the wire error the failure maps to: ``envelope.malformed``
    for syntax, duplicate members, lone surrogates, and bounds;
    ``envelope.schema_invalid`` for a well-formed number outside the
    integer domain.
    """

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


_WS = b" \t\n\r"


class _Parser:
    def __init__(self, data: bytes, max_depth: int = 64) -> None:
        self.data = data
        self.pos = 0
        self.max_depth = max_depth

    def fail(self, reason: str) -> None:
        raise JsonRejected("envelope.malformed", f"byte {self.pos}: {reason}")

    def peek(self) -> int | None:
        return self.data[self.pos] if self.pos < len(self.data) else None

    def skip_ws(self) -> None:
        while self.pos < len(self.data) and self.data[self.pos] in _WS:
            self.pos += 1

    def value(self, depth: int) -> object:
        if depth > self.max_depth:
            raise JsonRejected("envelope.malformed", f"byte {self.pos}: nesting too deep")
        char = self.peek()
        if char == ord("{"):
            return self.object(depth)
        if char == ord("["):
            return self.array(depth)
        if char == ord('"'):
            return self.string()
        if char == ord("t"):
            self.literal("true")
            return True
        if char == ord("f"):
            self.literal("false")
            return False
        if char == ord("n"):
            self.literal("null")
            return None
        if char == ord("-") or (char is not None and 0x30 <= char <= 0x39):
            return self.number()
        self.fail("expected a value")

    def literal(self, word: str) -> None:
        if self.data[self.pos : self.pos + len(word)] == word.encode():
            self.pos += len(word)
        else:
            self.fail("unrecognized literal")

    def object(self, depth: int) -> Obj:
        self.pos += 1  # '{'
        out = Obj()
        self.skip_ws()
        if self.peek() == ord("}"):
            self.pos += 1
            return out
        while True:
            self.skip_ws()
            name = self.string()
            self.skip_ws()
            if self.peek() != ord(":"):
                self.fail("expected ':' in object")
            self.pos += 1
            self.skip_ws()
            member = self.value(depth + 1)
            if out.has(name):
                raise JsonRejected("envelope.malformed", "duplicate member name")
            out.set(name, member)
            self.skip_ws()
            char = self.peek()
            if char == ord(","):
                self.pos += 1
            elif char == ord("}"):
                self.pos += 1
                return out
            else:
                self.fail("expected ',' or '}' in object")

    def array(self, depth: int) -> list[object]:
        self.pos += 1  # '['
        out: list[object] = []
        self.skip_ws()
        if self.peek() == ord("]"):
            self.pos += 1
            return out
        while True:
            self.skip_ws()
            out.append(self.value(depth + 1))
            self.skip_ws()
            char = self.peek()
            if char == ord(","):
                self.pos += 1
            elif char == ord("]"):
                self.pos += 1
                return out
            else:
                self.fail("expected ',' or ']' in array")

    def string(self) -> str:
        if self.peek() != ord('"'):
            self.fail("expected a string")
        self.pos += 1
        chunks: list[str] = []
        while True:
            start = self.pos
            while self.pos < len(self.data):
                char = self.data[self.pos]
                if char == ord('"') or char == ord("\\") or char < 0x20:
                    break
                self.pos += 1
            if self.pos > start:
                try:
                    chunks.append(self.data[start : self.pos].decode("utf-8"))
                except UnicodeDecodeError:
                    self.fail("string is not valid UTF-8")
            char = self.peek()
            if char == ord('"'):
                self.pos += 1
                return "".join(chunks)
            if char == ord("\\"):
                self.pos += 1
                chunks.append(self.escape())
            elif char is not None and char < 0x20:
                self.fail("raw control character in string")
            else:
                self.fail("unterminated string")

    def escape(self) -> str:
        char = self.peek()
        simple = {
            ord('"'): '"',
            ord("\\"): "\\",
            ord("/"): "/",
            ord("b"): "\b",
            ord("f"): "\f",
            ord("n"): "\n",
            ord("r"): "\r",
            ord("t"): "\t",
        }.get(char)
        if simple is not None:
            self.pos += 1
            return simple
        if char != ord("u"):
            self.fail("unknown escape")
        self.pos += 1
        first = self.hex4()
        if 0xD800 <= first < 0xDC00:
            if self.data[self.pos : self.pos + 2] != b"\\u":
                self.fail("lone surrogate")
            self.pos += 2
            second = self.hex4()
            if not 0xDC00 <= second < 0xE000:
                self.fail("invalid low surrogate")
            return chr(0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00))
        if 0xDC00 <= first < 0xE000:
            self.fail("lone surrogate")
        return chr(first)

    def hex4(self) -> int:
        chunk = self.data[self.pos : self.pos + 4]
        if len(chunk) != 4:
            self.fail("truncated \\u escape")
        try:
            value = int(chunk, 16)
        except ValueError:
            self.fail("invalid hex digit in \\u escape")
        self.pos += 4
        return value

    def number(self) -> int:
        start = self.pos
        if self.peek() == ord("-"):
            self.pos += 1
        char = self.peek()
        if char == ord("0"):
            self.pos += 1
            if self.peek() is not None and 0x30 <= self.peek() < 0x3A:
                self.fail("leading zero in number")
        elif char is not None and 0x30 <= char <= 0x39:
            while self.peek() is not None and 0x30 <= self.peek() < 0x3A:
                self.pos += 1
        else:
            self.fail("invalid number")
        if self.peek() in (ord("."), ord("e"), ord("E")):
            raise JsonRejected(
                "envelope.schema_invalid", f"byte {start}: number outside the integer domain"
            )
        text = self.data[start : self.pos].decode()
        value = int(text)
        if not -(2**63) <= value < 2**63:
            raise JsonRejected(
                "envelope.schema_invalid", f"byte {start}: number outside the integer domain"
            )
        return value


def parse_json(data: bytes) -> object:
    """Parse protocol JSON; transmission order and whitespace are free."""
    parser = _Parser(data)
    parser.skip_ws()
    value = parser.value(0)
    parser.skip_ws()
    if parser.pos != len(parser.data):
        parser.fail("trailing content after the value")
    return value


def parse_json_or_malformed(data: bytes) -> tuple[object, str | None]:
    """Parse and classify: ``(value, None)`` or ``(None, wire_code)``."""
    try:
        return parse_json(data), None
    except JsonRejected as rejected:
        return None, rejected.code


# ---------------------------------------------------------------------------
# Digests and the identity constructions
# (schemas/v1/ingest-identifiers.json — the framing registry).
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _u64be(value: int) -> bytes:
    return value.to_bytes(8, "big")


class Frame:
    """`label_utf8 || 0x00 || field_1..field_n`, each field
    `u64be(len) || content`, per the construction registry's field kinds."""

    def __init__(self, label: str) -> None:
        self.parts = [label.encode(), b"\x00"]

    def text(self, value: str) -> "Frame":
        raw = value.encode()
        self.parts.append(_u64be(len(raw)))
        self.parts.append(raw)
        return self

    def digest(self, raw: bytes) -> "Frame":
        if len(raw) != 32:
            raise VerificationFailure("digest field is not 32 bytes")
        self.parts.append(_u64be(32))
        self.parts.append(raw)
        return self

    def u63(self, value: int) -> "Frame":
        self.parts.append(_u64be(8))
        self.parts.append(_u64be(value))
        return self

    def raw(self) -> bytes:
        return b"".join(self.parts)


def session_hash(tenant: str, origin: str, harness: str, upstream: str) -> bytes:
    return hashlib.sha256(
        Frame("session-v1").text(tenant).text(origin).text(harness).text(upstream).raw()
    ).digest()


def artifact_hash(
    session: bytes, kind: str, adapter: str, projection: str, artifact_id: str
) -> bytes:
    return hashlib.sha256(
        Frame("artifact-v1")
        .digest(session)
        .text(kind)
        .text(adapter)
        .text(projection)
        .text(artifact_id)
        .raw()
    ).digest()


def blob_digest(canonical_payload: bytes) -> bytes:
    # The registry's single label-less construction (STO-001).
    return hashlib.sha256(canonical_payload).digest()


def occurrence_id(
    session: bytes,
    artifact: bytes,
    generation: str,
    range_kind: str,
    range_start: int,
    range_end: int,
    blob: bytes,
) -> bytes:
    return hashlib.sha256(
        Frame("occurrence-v1")
        .digest(session)
        .digest(artifact)
        .text(generation)
        .text(range_kind)
        .u63(range_start)
        .u63(range_end)
        .digest(blob)
        .raw()
    ).digest()


def attestation_id(occurrence: bytes, uploader: str, request: str) -> bytes:
    return hashlib.sha256(
        Frame("attestation-v1").digest(occurrence).text(uploader).text(request).raw()
    ).digest()


def ingest_attempt_signing_input(
    method: str,
    route: str,
    content_type: str,
    request_digest: bytes,
    envelope_digest: bytes,
    payload_canonical: bytes,
    payload_transport: bytes,
    key_id: bytes,
    epoch: int,
    timestamp: str,
) -> bytes:
    return (
        Frame("ingest-attempt-v1")
        .text(method)
        .text(route)
        .text(content_type)
        .digest(request_digest)
        .digest(envelope_digest)
        .digest(payload_canonical)
        .digest(payload_transport)
        .digest(key_id)
        .u63(epoch)
        .text(timestamp)
        .raw()
    )


def key_id_of_public_key(public: bytes) -> bytes:
    # keys.json "key_id_derivation": lowercase-hex SHA-256 over the 32 raw
    # public-key bytes.
    return hashlib.sha256(public).digest()


# ---------------------------------------------------------------------------
# Object keys (plan Section 7.5; object_key.rs)
# ---------------------------------------------------------------------------


def blob_object_key(tenant: str, profile: str, blob: bytes) -> str:
    blob_hex = blob.hex()
    return f"tenants/{tenant}/v1/raw/blobs/{profile}/sha256/{blob_hex[:2]}/{blob_hex}.zst"


def occurrence_object_key(
    tenant: str, origin: str, harness: str, session: bytes, occurrence: bytes
) -> str:
    session_hex = session.hex()
    return (
        f"tenants/{tenant}/v1/raw/occurrences/{origin}/{harness}/"
        f"{session_hex[:2]}/{session_hex}/{occurrence.hex()}.json"
    )


def attestation_object_key(tenant: str, occurrence: bytes, attestation: bytes) -> str:
    occurrence_hex = occurrence.hex()
    return (
        f"tenants/{tenant}/v1/raw/attestations/{occurrence_hex[:2]}/"
        f"{occurrence_hex}/{attestation.hex()}.json"
    )


# ---------------------------------------------------------------------------
# Wire grammars (schemas/v1/common.json; vocabulary.rs)
# ---------------------------------------------------------------------------

_HEX = re.compile(r"\A[0-9a-f]+\Z")
_UUID = re.compile(
    r"\A([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f])([0-9a-f]{3})-([89ab])([0-9a-f]{3})-([0-9a-f]{12})\Z"
)
_SHORT_TOKEN = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
_VERSION_TOKEN = re.compile(r"\A[0-9A-Za-z._+-]{1,32}\Z")
_TIMESTAMP = re.compile(
    r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z\Z"
)
_CONTENT_TYPE = re.compile(r"\Amultipart/related; boundary=[0-9A-Za-z'()+_,.:=?-]{1,70}\Z")


def is_uuid(text: str, version: str) -> bool:
    match = _UUID.match(text)
    return match is not None and match.group(3) == version


def is_opaque_id(text: str) -> bool:
    return bool(text) and len(text.encode()) <= 1024


def is_digest_hex(text: str) -> bool:
    return len(text) == 64 and _HEX.match(text) is not None


def calendar_valid(text: str) -> bool:
    year, month, day = int(text[0:4]), int(text[5:7]), int(text[8:10])
    hour, minute, second = int(text[11:13]), int(text[14:16]), int(text[17:19])
    if not 1 <= month <= 12:
        return False
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = {1: 31, 3: 31, 5: 31, 7: 31, 8: 31, 10: 31, 12: 31,
            4: 30, 6: 30, 9: 30, 11: 30, 2: 29 if leap else 28}[month]
    return 1 <= day <= days and hour < 24 and minute < 60 and second <= 60


def _days_from_civil(year: int, month: int, day: int) -> int:
    # Howard Hinnant's algorithm; pure and timezone-free.
    year_adjusted = year - (1 if month <= 2 else 0)
    era = (year_adjusted if year_adjusted >= 0 else year_adjusted - 399) // 400
    year_of_era = year_adjusted - era * 400
    day_of_year = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    day_of_era = year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year
    return era * 146097 + day_of_era - 719468


def timestamp_epoch(text: str) -> float:
    """A grammar-valid RFC 3339 UTC timestamp as epoch seconds."""
    days = _days_from_civil(int(text[0:4]), int(text[5:7]), int(text[8:10]))
    seconds = days * 86400 + int(text[11:13]) * 3600 + int(text[14:16]) * 60 + int(text[17:19])
    if len(text) > 20:
        seconds += float("0." + text[20:-1])
    return float(seconds)


# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032), pure Python. Verify-only: the corpus
# carries signatures, never private keys.
# ---------------------------------------------------------------------------

_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P


def _recover_x(y: int, sign: int) -> int | None:
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = x * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


def _decompress(encoded: bytes) -> tuple[int, int] | None:
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _ED_P:
        return None
    x = _recover_x(y, sign)
    return None if x is None else (x, y)


_ED_BASE = _decompress((4 * pow(5, _ED_P - 2, _ED_P) % _ED_P).to_bytes(32, "little"))
assert _ED_BASE is not None


def _point_add(
    p: tuple[int, int] | None, q: tuple[int, int] | None
) -> tuple[int, int] | None:
    """The twisted-Edwards addition law (RFC 8032 §5.1.4), affine.

    The law is complete for ed25519's curve (`a = -1`, non-square `d`): it
    adds, doubles, and hits the identity uniformly with no special cases,
    so ``None`` only ever appears as a represented identity, never an
    exceptional denominator. ``None`` is the neutral element.
    """
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    xx = x1 * x2 % _ED_P
    yy = y1 * y2 % _ED_P
    dxx_yy = _ED_D * xx * yy % _ED_P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + dxx_yy, _ED_P - 2, _ED_P) % _ED_P
    y3 = (yy + xx) * pow(1 - dxx_yy, _ED_P - 2, _ED_P) % _ED_P
    return (x3, y3)


def _scalar_mult(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 §5.1.7 verification: ``[s]B == R + [k]A``."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    k = int.from_bytes(
        hashlib.sha512(signature[:32] + public + message).digest(), "little"
    ) % _ED_L
    left = _scalar_mult(s, _ED_BASE)
    right = _point_add(r, _scalar_mult(k, a))
    return left == right


# ---------------------------------------------------------------------------
# Envelope validation — the version 1 ladder, mirroring
# schemas/v1/ingest-envelope.json and envelope.rs.
# ---------------------------------------------------------------------------


class EnvelopeRejected(Exception):
    """An envelope byte sequence is not a valid v1 envelope."""

    def __init__(self, code: str, field: str | None, reason: str) -> None:
        super().__init__(f"{code} at {field}: {reason}")
        self.code = code
        self.field = field
        self.reason = reason


class Envelope:
    """A validated version 1 envelope."""

    def __init__(self, members: dict[str, object]) -> None:
        self.members = members

    def __getitem__(self, name: str) -> object:
        return self.members[name]


def _reject(code: str, field: str, reason: str) -> None:
    raise EnvelopeRejected(code, field, reason)


def _require(envelope: dict[str, object], field: str) -> object:
    if field not in envelope:
        _reject("envelope.schema_invalid", field, "required member is missing")
    return envelope[field]


def _text(envelope: dict[str, object], field: str) -> str:
    value = _require(envelope, field)
    if not isinstance(value, str):
        _reject("envelope.schema_invalid", field, "member must be a string")
    return value


def _u63(envelope: dict[str, object], field: str) -> int:
    value = _require(envelope, field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _reject("envelope.schema_invalid", field, "member must be a u63 integer")
    return value


def _grammar(envelope: dict[str, object], field: str, grammar) -> str:
    raw = _text(envelope, field)
    if not grammar(raw):
        _reject("envelope.schema_invalid", field, "value does not match the canonical grammar")
    return raw


def _enum(envelope: dict[str, object], field: str) -> str:
    raw = _text(envelope, field)
    if raw not in ENUMS[field]:
        _reject("envelope.schema_invalid", field, f"unknown enum value fails closed: {raw}")
    return raw


def _optional(envelope: dict[str, object], field: str, grammar) -> str | None:
    if field not in envelope:
        return None
    value = envelope[field]
    if not isinstance(value, str):
        _reject("envelope.schema_invalid", field, "member must be a string when present")
    if not grammar(value):
        _reject("envelope.schema_invalid", field, "value does not match the canonical grammar")
    return value


def validate_envelope(data: bytes) -> Envelope:
    """The full bounded validation ladder; raises [`EnvelopeRejected`]."""
    value, code = parse_json_or_malformed(data)
    if code is not None:
        raise EnvelopeRejected(code, None, "bounded parse of the envelope bytes failed")
    return validate_envelope_value(value, data)


def validate_envelope_value(value: object, data: bytes) -> Envelope:
    """The ladder over an already-parsed value (its bytes only feed the
    canonical size cap)."""
    if not isinstance(value, Obj):
        raise EnvelopeRejected("envelope.malformed", None, "envelope part is not a JSON object")
    envelope = value.members

    for field in RESERVED_FIELDS:
        if field in envelope:
            _reject("envelope.schema_invalid", field, "reserved per-attempt or server member")

    for field, pinned in (("protocol_version", 1), ("envelope_version", 1)):
        if field not in envelope:
            _reject("envelope.schema_invalid", field, "required member is missing")
        found = envelope[field]
        if not isinstance(found, int) or isinstance(found, bool):
            _reject("envelope.schema_invalid", field, "member must be an integer")
        if found != pinned:
            _reject("envelope.version_unsupported", field, f"version {found} is not supported")

    members: dict[str, object] = {
        "adapter_artifact_id": _grammar(envelope, "adapter_artifact_id", is_opaque_id),
        "adapter_id": _grammar(envelope, "adapter_id", lambda t: _SHORT_TOKEN.match(t)),
        "adapter_projection_version": _grammar(
            envelope, "adapter_projection_version", lambda t: _VERSION_TOKEN.match(t)
        ),
        "artifact_kind": _enum(envelope, "artifact_kind"),
        "attestation_id": bytes.fromhex(
            _grammar(envelope, "attestation_id", is_digest_hex)
        ),
        "blob_digest": bytes.fromhex(_grammar(envelope, "blob_digest", is_digest_hex)),
        "capture_time": _grammar(envelope, "capture_time", lambda t: _TIMESTAMP.match(t)),
        "compressed_size": _u63(envelope, "compressed_size"),
        "envelope_creation_time": _grammar(
            envelope, "envelope_creation_time", lambda t: _TIMESTAMP.match(t)
        ),
        "generation": _grammar(envelope, "generation", lambda t: is_uuid(t, "7")),
        "harness": _grammar(envelope, "harness", lambda t: _SHORT_TOKEN.match(t)),
        "id_source": _enum(envelope, "id_source"),
        "incoming_checksum": bytes.fromhex(
            _grammar(envelope, "incoming_checksum", is_digest_hex)
        ),
        "incoming_checksum_algorithm": _enum(envelope, "incoming_checksum_algorithm"),
        "occurrence_id": bytes.fromhex(
            _grammar(envelope, "occurrence_id", is_digest_hex)
        ),
        "origin_client_id": _grammar(envelope, "origin_client_id", lambda t: is_uuid(t, "4")),
        "range_end": _u63(envelope, "range_end"),
        "range_kind": _enum(envelope, "range_kind"),
        "range_start": _u63(envelope, "range_start"),
        "request_id": _grammar(envelope, "request_id", lambda t: is_uuid(t, "7")),
        "storage_profile": _enum(envelope, "storage_profile"),
        "tenant_id": _grammar(envelope, "tenant_id", lambda t: is_uuid(t, "4")),
        "transport_encoding": _enum(envelope, "transport_encoding"),
        "uncompressed_size": _u63(envelope, "uncompressed_size"),
        "upstream_session_id": _grammar(envelope, "upstream_session_id", is_opaque_id),
        "uploader_client_id": _grammar(envelope, "uploader_client_id", lambda t: is_uuid(t, "4")),
    }
    optional_timestamps = {
        "source_time": _optional(envelope, "source_time", lambda t: _TIMESTAMP.match(t)),
    }
    for field in ("parent_session_id", "orchestrator_attempt_id", "trace_id", "inference_request_id"):
        optional_timestamps[field] = _optional(envelope, field, is_opaque_id)
    members.update(optional_timestamps)

    # Calendar and consistency checks.
    for field in ("capture_time", "envelope_creation_time"):
        if not calendar_valid(members[field]):
            _reject("envelope.schema_invalid", field, "timestamp is not a real calendar instant")
    if members["source_time"] is not None and not calendar_valid(members["source_time"]):
        _reject("envelope.schema_invalid", "source_time", "timestamp is not a real calendar instant")
    if members["range_end"] < members["range_start"]:
        _reject("envelope.schema_invalid", "range_end", "range_end precedes range_start")
    if members["transport_encoding"] == "identity":
        if members["compressed_size"] != members["uncompressed_size"]:
            _reject(
                "envelope.schema_invalid",
                "compressed_size",
                "identity transport must declare equal compressed and uncompressed sizes",
            )
        if members["incoming_checksum"] != members["blob_digest"]:
            _reject(
                "envelope.schema_invalid",
                "incoming_checksum",
                "identity transport checksum must equal the blob digest",
            )

    # Identity re-derivation.
    session = session_hash(
        members["tenant_id"],
        members["origin_client_id"],
        members["harness"],
        members["upstream_session_id"],
    )
    artifact = artifact_hash(
        session,
        members["artifact_kind"],
        members["adapter_id"],
        members["adapter_projection_version"],
        members["adapter_artifact_id"],
    )
    occurrence = occurrence_id(
        session,
        artifact,
        members["generation"],
        members["range_kind"],
        members["range_start"],
        members["range_end"],
        members["blob_digest"],
    )
    attestation = attestation_id(
        occurrence, members["uploader_client_id"], members["request_id"]
    )
    if occurrence != members["occurrence_id"]:
        _reject(
            "envelope.schema_invalid",
            "occurrence_id",
            "declared identity does not match the re-derived one",
        )
    if attestation != members["attestation_id"]:
        _reject(
            "envelope.schema_invalid",
            "attestation_id",
            "declared identity does not match the re-derived one",
        )

    members["session_hash"] = session
    members["artifact_hash"] = artifact
    members["derived_occurrence_id"] = occurrence
    members["derived_attestation_id"] = attestation

    # The canonical size cap.
    if len(canonical_bytes(value)) > ENVELOPE_CANONICAL_MAX_BYTES:
        raise EnvelopeRejected(
            "envelope.size_exceeded", None, "canonical envelope exceeds the byte limit"
        )

    return Envelope(members)


def envelope_object_keys(envelope: Envelope) -> dict[str, str]:
    """The three server-derived object keys of a validated envelope."""
    members = envelope.members
    return {
        "blob_object_key": blob_object_key(
            members["tenant_id"], members["storage_profile"], members["blob_digest"]
        ),
        "occurrence_object_key": occurrence_object_key(
            members["tenant_id"],
            members["origin_client_id"],
            members["harness"],
            members["session_hash"],
            members["derived_occurrence_id"],
        ),
        "attestation_object_key": attestation_object_key(
            members["tenant_id"],
            members["derived_occurrence_id"],
            members["derived_attestation_id"],
        ),
    }


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------


class Corpus:
    """The committed bundle, loaded once and shared by every mode.

    Only files the manifest names are loaded, so an unexpected stray file
    shows up in the manifest-coherence check instead of silently parsing.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.files: dict[str, bytes] = {}
        self.json: dict[str, object] = {}
        manifest_data = self._read("manifest.json")
        self.manifest = self._json("manifest.json", manifest_data)
        for table in ("keys.json", "derivations.json", "canonicalization.json"):
            self._json(table, self._read(table))
        for scenario in self.scenarios:
            files = scenario.get("files")
            if not isinstance(files, Obj):
                raise CorpusError(f"scenario {_case_text(scenario, 'id')}: files is not an object")
            for name in files.names():
                rel = files.get(name)
                if not isinstance(rel, str):
                    raise CorpusError(f"scenario {_case_text(scenario, 'id')}: files.{name} is not a path")
                if rel not in self.files:
                    data = self._read(rel)
                    if rel.endswith(".json"):
                        self._json(rel, data)

    def _read(self, rel: str) -> bytes:
        if rel not in self.files:
            try:
                self.files[rel] = (self.root / rel).read_bytes()
            except OSError as error:
                raise CorpusError(f"{rel}: {error.strerror or 'unreadable'}") from error
        return self.files[rel]

    def _json(self, rel: str, data: bytes) -> object:
        value, code = parse_json_or_malformed(data)
        if code is not None or not isinstance(value, Obj):
            raise CorpusError(f"{rel}: {code or 'not a JSON object'}")
        self.json[rel] = value
        return value

    def bytes(self, rel: str) -> bytes:
        if rel not in self.files:
            raise CorpusError(f"{rel}: file is missing")
        return self.files[rel]

    def obj(self, rel: str) -> Obj:
        value = self.json.get(rel)
        if not isinstance(value, Obj):
            raise CorpusError(f"{rel}: expected a JSON object")
        return value

    def member(self, rel: str, name: str) -> object:
        value = self.obj(rel).get(name)
        if value is None:
            raise CorpusError(f"{rel}: member {name} is missing")
        return value

    def text(self, rel: str, name: str) -> str:
        value = self.member(rel, name)
        if not isinstance(value, str):
            raise CorpusError(f"{rel}: member {name} is not a string")
        return value

    @property
    def scenarios(self) -> list[Obj]:
        scenarios = self.manifest.get("scenarios")
        if not isinstance(scenarios, list):
            raise CorpusError("manifest scenarios is not an array")
        return [item for item in scenarios if isinstance(item, Obj)]


# ---------------------------------------------------------------------------
# The answer sheet — identical spec to conformance-replay.rs
# ---------------------------------------------------------------------------


def _row(row: str, id_: str, source: str, members: list[tuple[str, object]]) -> tuple[str, str]:
    obj = Obj()
    obj.set("row", row)
    obj.set("id", id_)
    if source:
        obj.set("source", source)
    for name, value in members:
        obj.set(name, value)
    return (f"{row}\x1f{id_}\x1f{source}", canonical_bytes(obj).decode() + "\n")


def compute_report(corpus: Corpus) -> list[str]:
    """Replay every golden vector and return the sorted answer-sheet lines."""
    rows: list[tuple[str, str]] = []

    # Derivation table.
    for case in _array(corpus, "derivations.json", "cases"):
        id_ = _case_text(case, "id")
        inputs = _case_member(case, "inputs")
        session = session_hash(
            _input(inputs, "tenant_id"), _input(inputs, "origin_client_id"),
            _input(inputs, "harness"), _input(inputs, "upstream_session_id"),
        )
        artifact = artifact_hash(
            session,
            _input(inputs, "artifact_kind"),
            _input(inputs, "adapter_id"),
            _input(inputs, "adapter_projection_version"),
            _input(inputs, "adapter_artifact_id"),
        )
        payload = _input(inputs, "canonical_payload").encode()
        blob = blob_digest(payload)
        occurrence = occurrence_id(
            session, artifact,
            _input(inputs, "generation"), _input(inputs, "range_kind"),
            _int(inputs, "range_start"), _int(inputs, "range_end"), blob,
        )
        attestation = attestation_id(
            occurrence, _input(inputs, "uploader_client_id"), _input(inputs, "request_id")
        )
        tenant = _input(inputs, "tenant_id")
        origin = _input(inputs, "origin_client_id")
        harness = _input(inputs, "harness")
        rows.append(_row("derivation", id_, "", [
            ("session_hash", session.hex()),
            ("artifact_hash", artifact.hex()),
            ("occurrence_id", occurrence.hex()),
            ("attestation_id", attestation.hex()),
            ("blob_digest", blob.hex()),
            ("blob_object_key", blob_object_key(tenant, "zstd-v1", blob)),
            ("occurrence_object_key", occurrence_object_key(tenant, origin, harness, session, occurrence)),
            ("attestation_object_key", attestation_object_key(tenant, occurrence, attestation)),
        ]))

    # Canonicalization table.
    table = corpus.obj("canonicalization.json")
    cases = table.get("cases")
    if not isinstance(cases, list):
        raise CorpusError("canonicalization.json cases is not an array")
    for case in cases:
        id_ = _case_text(case, "id")
        if isinstance(case, Obj):
            source = case.get("object")
            if isinstance(source, Obj):
                rows.append(_row("canonicalization", id_, "object", [
                    ("canonical_hex", canonical_bytes(source).hex()),
                ]))
            wire = case.get("noncanonical_text")
            if isinstance(wire, str):
                value, code = parse_json_or_malformed(wire.encode())
                if code is not None:
                    raise CorpusError(f"canonicalization.json case {id_}: {code}")
                rows.append(_row("canonicalization", id_, "noncanonical_text", [
                    ("canonical_hex", canonical_bytes(value).hex()),
                ]))
            for name in ("nfc", "nfd"):
                source = case.get(name)
                if isinstance(source, Obj):
                    rows.append(_row("canonicalization", id_, name, [
                        ("canonical_hex", canonical_bytes(source).hex()),
                    ]))
    rejections = table.get("rejections")
    if not isinstance(rejections, list):
        raise CorpusError("canonicalization.json rejections is not an array")
    for rejection in rejections:
        id_ = _case_text(rejection, "id")
        _, code = parse_json_or_malformed(_case_text(rejection, "text").encode())
        if code is None:
            raise CorpusError(f"canonicalization.json case {id_}: expected rejection")
        rows.append(_row("canonicalization_rejection", id_, "", [("error_code", code)]))

    # Key-ID derivation over every pinned public key.
    keys = corpus.member("keys.json", "keys")
    if not isinstance(keys, list):
        raise CorpusError("keys.json keys is not an array")
    for key in keys:
        if not isinstance(key, Obj):
            raise CorpusError("keys.json entry is not an object")
        name = key.get("name")
        public = key.get("public_key")
        if not isinstance(name, str) or not isinstance(public, str):
            raise CorpusError("keys.json entry lacks name/public_key")
        rows.append(_row("key_id", name, "", [
            ("key_id", key_id_of_public_key(bytes.fromhex(public)).hex()),
        ]))

    # Every scenario.
    for scenario in corpus.scenarios:
        rows.append(_scenario_row(corpus, scenario))

    return [line for _, line in sorted(rows, key=lambda item: item[0])]


def _scenario_row(corpus: Corpus, scenario: Obj) -> tuple[str, str]:
    id_ = _case_text(scenario, "id")
    files = scenario.get("files")
    if not isinstance(files, Obj):
        raise CorpusError(f"scenario {id_}: files is not an object")
    envelope_bytes = corpus.bytes(_file(files, "envelope"))
    payload_bytes = corpus.bytes(_file(files, "payload"))
    body_bytes = corpus.bytes(_file(files, "request_body"))
    attempt = corpus.obj(_file(files, "attempt"))
    attempt_rel = _file(files, "attempt")

    members: list[tuple[str, object]] = []
    value, parse_code = parse_json_or_malformed(envelope_bytes)
    try:
        if parse_code is not None:
            raise EnvelopeRejected(parse_code, None, "bounded parse of the envelope bytes failed")
        envelope = validate_envelope_value(value, envelope_bytes)
        canonical = canonical_bytes(value)
        keys = envelope_object_keys(envelope)
        members.append(("envelope_outcome", "accepted"))
        members.append(("canonical_hex", canonical.hex()))
        members.append(("envelope_digest", sha256_hex(canonical)))
        members.append(("wire_canonical", canonical == envelope_bytes))
        members.append(("session_hash", envelope["session_hash"].hex()))
        members.append(("artifact_hash", envelope["artifact_hash"].hex()))
        members.append(("occurrence_id", envelope["derived_occurrence_id"].hex()))
        members.append(("attestation_id", envelope["derived_attestation_id"].hex()))
        members.append(("blob_object_key", keys["blob_object_key"]))
        members.append(("occurrence_object_key", keys["occurrence_object_key"]))
        members.append(("attestation_object_key", keys["attestation_object_key"]))
    except EnvelopeRejected as rejected:
        members.append(("envelope_outcome", f"rejected:{rejected.code}"))

    payload_hex = sha256_hex(payload_bytes)
    members.append(("payload_digest", payload_hex))
    members.append(("transport_digest", payload_hex))
    members.append(("request_digest", sha256_hex(body_bytes)))

    signing_input = ingest_attempt_signing_input(
        corpus.text(attempt_rel, "http_method"),
        corpus.text(attempt_rel, "route"),
        corpus.text(attempt_rel, "content_type"),
        bytes.fromhex(corpus.text(attempt_rel, "request_content_digest")),
        bytes.fromhex(corpus.text(attempt_rel, "envelope_digest")),
        bytes.fromhex(corpus.text(attempt_rel, "payload_canonical_digest")),
        bytes.fromhex(corpus.text(attempt_rel, "payload_transport_digest")),
        bytes.fromhex(corpus.text(attempt_rel, "uploader_key_id")),
        _u63_value(corpus.member(attempt_rel, "authorization_epoch")),
        corpus.text(attempt_rel, "authorization_timestamp"),
    )
    members.append(("signing_input_sha256", sha256_hex(signing_input)))
    return _row("scenario", id_, "", members)


def _array(corpus: Corpus, rel: str, name: str) -> list[Obj]:
    value = corpus.member(rel, name)
    if not isinstance(value, list):
        raise CorpusError(f"{rel}: {name} is not an array")
    return [item for item in value if isinstance(item, Obj)]


def _case_member(case: Obj, name: str) -> dict[str, object]:
    value = case.get(name)
    if not isinstance(value, Obj):
        raise CorpusError(f"case member {name} is not an object")
    return value.members


def _case_text(case: Obj, name: str) -> str:
    value = case.get(name)
    if not isinstance(value, str):
        raise CorpusError(f"case member {name} is not a string")
    return value


def _input(inputs: dict[str, object], name: str) -> str:
    value = inputs.get(name)
    if not isinstance(value, str):
        raise CorpusError(f"case input {name} is not a string")
    return value


def _int(inputs: dict[str, object], name: str) -> int:
    value = inputs.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise CorpusError(f"case input {name} is not an integer")
    return value


def _file(files: Obj, name: str) -> str:
    value = files.get(name)
    if not isinstance(value, str):
        raise CorpusError(f"scenario files entry {name} is missing")
    return value


def _u63_value(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CorpusError("authorization_epoch is not a u63 integer")
    return value


def _parse_report_lines(lines: list[str]) -> dict[tuple[str, str, str], dict[str, object]]:
    """Parse answer-sheet lines back into rows keyed by (row, id, source)."""
    parsed: dict[tuple[str, str, str], dict[str, object]] = {}
    for line in lines:
        value, code = parse_json_or_malformed(line.encode())
        if code is not None or not isinstance(value, Obj):
            raise VerificationFailure("answer sheet contains a non-canonical line")
        key = (
            str(value.get("row")),
            str(value.get("id")),
            str(value.get("source") or ""),
        )
        if key in parsed:
            raise VerificationFailure(f"answer sheet has a duplicate row: {key[0]}/{key[1]}")
        parsed[key] = value.members
    return parsed


# ---------------------------------------------------------------------------
# Multipart framing (manifest "conventions": the exact recipe any
# implementer can rebuild byte-identically).
# ---------------------------------------------------------------------------


def multipart_body(boundary: str, envelope_bytes: bytes, payload_bytes: bytes) -> bytes:
    """The pinned two-part `multipart/related` body."""
    return (
        f"--{boundary}\r\n".encode()
        + f"content-type: {ENVELOPE_MEDIA_TYPE}\r\n\r\n".encode()
        + envelope_bytes
        + f"\r\n--{boundary}\r\n".encode()
        + f"content-type: {IDENTITY_MEDIA_TYPE}\r\n\r\n".encode()
        + payload_bytes
        + f"\r\n--{boundary}--\r\n".encode()
    )


def multipart_parts(body: bytes) -> tuple[str, list[bytes]] | None:
    """Split a body on its own boundary, or ``None`` if it is not the pinned
    two-part framing. Returns ``(boundary, [envelope part, payload part])``."""
    if not body.startswith(b"--") or b"\r\n" not in body[:80]:
        return None
    boundary = body[2 : body.index(b"\r\n")].decode("utf-8", "replace")
    opening = f"--{boundary}\r\n".encode()
    delimiter = f"\r\n--{boundary}\r\n".encode()
    closing = f"\r\n--{boundary}--\r\n".encode()
    envelope_header = f"content-type: {ENVELOPE_MEDIA_TYPE}\r\n\r\n".encode()
    payload_header = f"content-type: {IDENTITY_MEDIA_TYPE}\r\n\r\n".encode()
    if not body.endswith(closing):
        return None
    if not body.startswith(opening + envelope_header):
        return None
    envelope_start = len(opening) + len(envelope_header)
    split = body.find(delimiter, envelope_start)
    if split < 0 or not body.startswith(delimiter + payload_header, split):
        return None
    envelope_part = body[envelope_start:split]
    payload_start = split + len(delimiter) + len(payload_header)
    end = len(body) - len(closing)
    if end < payload_start:
        return None
    return boundary, [envelope_part, body[payload_start:end]]


def boundary_of_content_type(content_type: str) -> str | None:
    prefix = "multipart/related; boundary="
    if not content_type.startswith(prefix):
        return None
    boundary = content_type[len(prefix) :]
    return boundary if _CONTENT_TYPE.match(content_type) else None


# ---------------------------------------------------------------------------
# The attempt-level classifier. Order is the contract (each layer assumes the
# ones above it passed): envelope validation → attempt signature → digest
# coverage of the actual bytes → authorization window → key linkage →
# existing-occurrence conflict → accepted.
# ---------------------------------------------------------------------------


def classify_attempt(
    envelope_code: str | None,
    envelope: Envelope | None,
    attempt: dict[str, object],
    body: bytes,
    payload: bytes,
    signing_key: dict[str, object] | None,
    linkages: list[dict[str, object]],
    server_time: str,
    existing_occurrence: Obj | None,
    envelope_expected_manifest: bytes | None,
) -> str | None:
    """The wire error code the attempt earns, or ``None`` when accepted."""
    if envelope_code is not None:
        return envelope_code

    # The signature must verify over the declared covered values under the
    # pinned public key the key id names.
    if signing_key is None:
        return "auth.authorization_rejected"
    preimage = ingest_attempt_signing_input(
        str(attempt["http_method"]),
        str(attempt["route"]),
        str(attempt["content_type"]),
        bytes.fromhex(str(attempt["request_content_digest"])),
        bytes.fromhex(str(attempt["envelope_digest"])),
        bytes.fromhex(str(attempt["payload_canonical_digest"])),
        bytes.fromhex(str(attempt["payload_transport_digest"])),
        bytes.fromhex(str(attempt["uploader_key_id"])),
        int(attempt["authorization_epoch"]),
        str(attempt["authorization_timestamp"]),
    )
    if not ed25519_verify(
        bytes.fromhex(str(signing_key["public_key"])),
        preimage,
        bytes.fromhex(str(attempt["signature"])),
    ):
        return "auth.authorization_rejected"

    # The signed digests must cover the bytes actually submitted.
    if sha256_hex(body) != str(attempt["request_content_digest"]):
        return "auth.authorization_rejected"
    if sha256_hex(payload) != str(attempt["payload_transport_digest"]):
        return "auth.authorization_rejected"
    if envelope is not None and envelope["transport_encoding"] == "identity":
        if sha256_hex(payload) != str(attempt["payload_canonical_digest"]):
            return "auth.authorization_rejected"

    # Fresh authorization inside the window, with the clock-skew allowance.
    age = timestamp_epoch(server_time) - timestamp_epoch(str(attempt["authorization_timestamp"]))
    if age > AUTHORIZATION_WINDOW_SECONDS + CLOCK_SKEW_SECONDS or age < -CLOCK_SKEW_SECONDS:
        return "auth.authorization_rejected"

    # The assumed linkage record must bind this key, client, tenant, epoch.
    if envelope is not None:
        key_name = str(signing_key.get("name") or "")
        epoch = str(attempt["authorization_epoch"])
        linked = any(
            linkage.get("client_id") == envelope["uploader_client_id"]
            and linkage.get("linked_tenant") == envelope["tenant_id"]
            and linkage.get("key") == key_name
            and epoch in (linkage.get("epochs") or {})
            for linkage in linkages
        )
        if not linked or signing_key.get("role") != "uploader":
            return "auth.forbidden"

    # A differing canonical object already at the derived occurrence key.
    if existing_occurrence is not None and envelope_expected_manifest is not None:
        same_key = (
            existing_occurrence.get("tenant_id") == envelope["tenant_id"]
            and existing_occurrence.get("origin_client_id") == envelope["origin_client_id"]
            and existing_occurrence.get("harness") == envelope["harness"]
            and existing_occurrence.get("session_hash") == envelope["session_hash"].hex()
            and existing_occurrence.get("occurrence_id") == envelope["derived_occurrence_id"].hex()
        )
        if same_key and canonical_bytes(existing_occurrence) != envelope_expected_manifest:
            return "storage.integrity_conflict"

    return None


def occurrence_manifest_of(envelope: Envelope) -> bytes:
    """The occurrence manifest this envelope commits, per
    `schemas/v1/occurrence-manifest.json`: every identity member, with the
    derived hashes inlined and `occurrence_version` pinned to 1."""
    members = envelope.members
    manifest = Obj()
    for name in (
        "adapter_artifact_id",
        "adapter_id",
        "adapter_projection_version",
        "artifact_kind",
        "blob_digest",
        "generation",
        "harness",
        "id_source",
        "origin_client_id",
        "range_end",
        "range_kind",
        "range_start",
        "storage_profile",
        "tenant_id",
        "upstream_session_id",
    ):
        if name == "blob_digest":
            manifest.set(name, members["blob_digest"].hex())
        else:
            manifest.set(name, members[name])
    if members.get("source_time") is not None:
        manifest.set("source_time", members["source_time"])
    manifest.set("session_hash", members["session_hash"].hex())
    manifest.set("artifact_hash", members["artifact_hash"].hex())
    manifest.set("occurrence_id", members["derived_occurrence_id"].hex())
    manifest.set("occurrence_version", 1)
    return canonical_bytes(manifest)


# ---------------------------------------------------------------------------
# Golden verification: every committed value re-derived and checked.
# ---------------------------------------------------------------------------

METADATA_SUFFIXES = (
    "manifest.json",
    "keys.json",
    "derivations.json",
    "canonicalization.json",
    "attempt.json",
    "receipt.json",
    "error.json",
    "existing-occurrence.json",
)


def _expected_error_members() -> tuple[str, ...]:
    return ("code", "correlation_id", "message", "request_id", "retryable", "schema")


def verify_corpus(corpus: Corpus) -> tuple[list[str], dict[str, int]]:
    """Replay every golden vector; raise [`VerificationFailure`] listing
    every mismatch if any golden does not hold. Returns the answer sheet."""
    report = compute_report(corpus)
    rows = _parse_report_lines(report)
    failures: list[str] = []

    _verify_file_conventions(corpus, failures)
    _verify_derivations(corpus, rows, failures)
    _verify_canonicalization(corpus, rows, failures)
    keys_by_name, keys_by_id, linkages = _key_material(corpus, rows, failures)
    for scenario in corpus.scenarios:
        _verify_scenario(corpus, scenario, rows, keys_by_name, keys_by_id, linkages, failures)
    _verify_invariants(corpus, rows, failures)

    counts = {
        "scenarios": len(corpus.scenarios),
        "derivation_cases": len(_array(corpus, "derivations.json", "cases")),
        "canonicalization_cases": len(_array(corpus, "canonicalization.json", "cases")),
        "keys": len(keys_by_name),
    }
    if failures:
        raise VerificationFailure(
            f"{len(failures)} golden check(s) failed:\n  " + "\n  ".join(failures)
        )
    return report, counts


def _fail(failures: list[str], message: str) -> None:
    failures.append(message)


def _verify_file_conventions(corpus: Corpus, failures: list[str]) -> None:
    """Metadata files are canonical JSON plus one LF; the manifest's file
    inventory matches the tree exactly, bytes and digests included."""
    manifest_files = corpus.manifest.get("files")
    if not isinstance(manifest_files, list):
        _fail(failures, "manifest.json: files inventory is not an array")
        return
    listed: dict[str, Obj] = {}
    for entry in manifest_files:
        if not isinstance(entry, Obj):
            _fail(failures, "manifest.json: files entry is not an object")
            continue
        path = entry.get("path")
        if not isinstance(path, str):
            _fail(failures, "manifest.json: files entry has no path")
            continue
        listed[path] = entry
    for path in sorted(set(listed) - set(corpus.files)):
        _fail(failures, f"{path}: listed in the manifest but not on disk")
    # The manifest cannot inventory itself — its own entry would have to pin
    # its own bytes and digest — so it is the one loaded file exempt here.
    # It still answers to the metadata-file convention check below.
    for path in sorted(set(corpus.files) - set(listed) - {"manifest.json"}):
        _fail(failures, f"{path}: present in the corpus but absent from the manifest")
    for path, entry in sorted(listed.items()):
        data = corpus.files.get(path)
        if data is None:
            continue
        if entry.get("bytes") != len(data):
            _fail(failures, f"{path}: manifest byte count disagrees with the file")
        if entry.get("sha256") != sha256_hex(data):
            _fail(failures, f"{path}: manifest sha256 disagrees with the file")
    for rel in sorted(corpus.files):
        data = corpus.files[rel]
        if rel.endswith(METADATA_SUFFIXES):
            if not data.endswith(b"\n") or data.endswith(b"\n\n"):
                _fail(failures, f"{rel}: metadata file must be canonical JSON plus one LF")
            elif canonical_bytes(corpus.json[rel]) != data[:-1]:
                _fail(failures, f"{rel}: metadata file is not canonical JSON")
        elif rel.endswith("envelope.json"):
            scenario_id = rel.split("/")[1]
            entry = next((s for s in corpus.scenarios if s.get("id") == scenario_id), None)
            if entry is None or entry.get("envelope_wire_canonical") is not True:
                continue
            value, code = parse_json_or_malformed(data)
            if code is not None:
                _fail(failures, f"{rel}: envelope part does not parse: {code}")
            elif canonical_bytes(value) != data or data.endswith(b"\n"):
                _fail(failures, f"{rel}: envelope part is not bare canonical bytes")


def _verify_derivations(corpus: Corpus, rows: dict, failures: list[str]) -> None:
    for case in _array(corpus, "derivations.json", "cases"):
        case_id = _case_text(case, "id")
        expected = case.get("expected")
        row = rows.get(("derivation", case_id, ""))
        if not isinstance(expected, Obj) or row is None:
            _fail(failures, f"derivations.json case {case_id}: no report row or expected block")
            continue
        for name in expected.names():
            if row.get(name) != expected.get(name):
                _fail(
                    failures,
                    f"derivations.json case {case_id}: {name} "
                    f"{row.get(name)} != golden {expected.get(name)}",
                )


def _verify_canonicalization(corpus: Corpus, rows: dict, failures: list[str]) -> None:
    table = corpus.obj("canonicalization.json")
    cases = table.get("cases")
    if not isinstance(cases, list):
        _fail(failures, "canonicalization.json: cases is not an array")
        return
    for case in cases:
        if not isinstance(case, Obj):
            continue
        case_id = _case_text(case, "id")
        if isinstance(case.get("object"), Obj):
            row = rows.get(("canonicalization", case_id, "object"))
            golden_hex = case.get("canonical_hex")
            golden_sha = case.get("sha256")
            if row is None or not isinstance(golden_hex, str):
                _fail(failures, f"canonicalization.json case {case_id}: missing row or golden")
                continue
            if row.get("canonical_hex") != golden_hex:
                _fail(failures, f"canonicalization.json case {case_id}: canonical bytes differ")
            if isinstance(golden_sha, str) and sha256_hex(bytes.fromhex(golden_hex)) != golden_sha:
                _fail(failures, f"canonicalization.json case {case_id}: golden sha256 mismatch")
        if isinstance(case.get("noncanonical_text"), str):
            row = rows.get(("canonicalization", case_id, "noncanonical_text"))
            twin = case.get("same_canonical_as")
            twin_row = rows.get(("canonicalization", str(twin), "object")) if isinstance(twin, str) else None
            if row is None or twin_row is None:
                _fail(failures, f"canonicalization.json case {case_id}: missing rows")
            elif row.get("canonical_hex") != twin_row.get("canonical_hex"):
                _fail(
                    failures,
                    f"canonicalization.json case {case_id}: noncanonical text "
                    "did not converge on its twin's canonical bytes",
                )
        if isinstance(case.get("nfc"), Obj) and isinstance(case.get("nfd"), Obj):
            nfc_row = rows.get(("canonicalization", case_id, "nfc"))
            nfd_row = rows.get(("canonicalization", case_id, "nfd"))
            if nfc_row is None or nfd_row is None:
                _fail(failures, f"canonicalization.json case {case_id}: missing nfc/nfd rows")
                continue
            if sha256_hex(bytes.fromhex(str(nfc_row.get("canonical_hex")))) != case.get("nfc_sha256"):
                _fail(failures, f"canonicalization.json case {case_id}: nfc_sha256 mismatch")
            if sha256_hex(bytes.fromhex(str(nfd_row.get("canonical_hex")))) != case.get("nfd_sha256"):
                _fail(failures, f"canonicalization.json case {case_id}: nfd_sha256 mismatch")
            if nfc_row.get("canonical_hex") == nfd_row.get("canonical_hex"):
                _fail(
                    failures,
                    f"canonicalization.json case {case_id}: NFC and NFD merged",
                )
    rejections = table.get("rejections")
    if not isinstance(rejections, list):
        _fail(failures, "canonicalization.json: rejections is not an array")
        return
    for rejection in rejections:
        if not isinstance(rejection, Obj):
            continue
        case_id = _case_text(rejection, "id")
        row = rows.get(("canonicalization_rejection", case_id, ""))
        if row is None:
            _fail(failures, f"canonicalization.json rejection {case_id}: no report row")
        elif row.get("error_code") != rejection.get("error_code"):
            _fail(
                failures,
                f"canonicalization.json rejection {case_id}: "
                f"{row.get('error_code')} != golden {rejection.get('error_code')}",
            )


def _key_material(corpus: Corpus, rows: dict, failures: list[str]) -> tuple[dict, dict, list]:
    keys_by_name: dict[str, Obj] = {}
    keys_by_id: dict[str, Obj] = {}
    keys = corpus.member("keys.json", "keys")
    if not isinstance(keys, list):
        raise CorpusError("keys.json keys is not an array")
    for key in keys:
        if not isinstance(key, Obj):
            continue
        name = key.get("name")
        key_id = key.get("key_id")
        if not isinstance(name, str) or not isinstance(key_id, str):
            _fail(failures, "keys.json: entry lacks name/key_id")
            continue
        keys_by_name[name] = key
        keys_by_id[key_id] = key
        row = rows.get(("key_id", name, ""))
        derived = key_id_of_public_key(bytes.fromhex(_case_text(key, "public_key"))).hex()
        if key_id != derived:
            _fail(failures, f"keys.json key {name}: key_id is not the pinned derivation")
        if row is None or row.get("key_id") != derived:
            _fail(failures, f"keys.json key {name}: report row disagrees")
    linkages: list[dict[str, object]] = []
    raw = corpus.member("keys.json", "assumed_linkage")
    if isinstance(raw, list):
        linkages = [item.members for item in raw if isinstance(item, Obj)]
    return keys_by_name, keys_by_id, linkages


def _verify_scenario(
    corpus: Corpus,
    scenario: Obj,
    rows: dict,
    keys_by_name: dict[str, Obj],
    keys_by_id: dict[str, Obj],
    linkages: list[dict[str, object]],
    failures: list[str],
) -> None:
    scenario_id = _case_text(scenario, "id")
    files = scenario.get("files")
    if not isinstance(files, Obj):
        _fail(failures, f"scenario {scenario_id}: files is not an object")
        return
    expect = scenario.get("expect")
    if not isinstance(expect, Obj):
        _fail(failures, f"scenario {scenario_id}: expect is not an object")
        return
    signing = scenario.get("signing")
    if not isinstance(signing, Obj):
        _fail(failures, f"scenario {scenario_id}: signing is not an object")
        return
    row = rows.get(("scenario", scenario_id, ""))
    if row is None:
        _fail(failures, f"scenario {scenario_id}: no report row")
        return

    envelope_rel = _file(files, "envelope")
    envelope_bytes = corpus.bytes(envelope_rel)
    payload_bytes = corpus.bytes(_file(files, "payload"))
    body_bytes = corpus.bytes(_file(files, "request_body"))
    attempt_rel = _file(files, "attempt")
    attempt = corpus.obj(attempt_rel).members
    server_time = _case_text(scenario, "server_time")
    alteration = scenario.get("alteration")
    alteration_kind = alteration.get("kind") if isinstance(alteration, Obj) else None

    # --- envelope ladder -------------------------------------------------
    value, parse_code = parse_json_or_malformed(envelope_bytes)
    envelope: Envelope | None = None
    envelope_code: str | None = parse_code
    if parse_code is None:
        try:
            envelope = validate_envelope_value(value, envelope_bytes)
        except EnvelopeRejected as rejected:
            envelope_code = rejected.code
    outcome = "accepted" if envelope_code is None else f"rejected:{envelope_code}"
    if row.get("envelope_outcome") != outcome:
        _fail(
            failures,
            f"scenario {scenario_id}: report outcome {row.get('envelope_outcome')} "
            f"vs replay {outcome}",
        )

    if envelope is not None:
        # Identity and keys: report row vs manifest identity block. Only the
        # members the row carries compare here (the row's payload_digest,
        # transport_digest and request_digest pin digests of transmitted
        # bytes and are checked against the attempt record below).
        # blob_digest is not one of them: the identity block pins the digest
        # the envelope declares — the canonical payload as the uploader
        # signed it — which equals the digest of the transmitted bytes only
        # when the scenario alters nothing. A payload-byte-flip vector
        # exists precisely because the wire bytes diverge from it.
        identity = scenario.get("identity")
        if isinstance(identity, Obj):
            for name in identity.names():
                if name == "blob_digest":
                    declared = envelope["blob_digest"].hex()
                    if identity.get(name) != declared:
                        _fail(
                            failures,
                            f"scenario {scenario_id}: payload blob_digest "
                            f"{identity.get(name)} != envelope-declared {declared}",
                        )
                    if alteration_kind is None and blob_digest(payload_bytes).hex() != declared:
                        _fail(
                            failures,
                            f"scenario {scenario_id}: payload blob_digest "
                            f"{declared} != transmitted bytes",
                        )
                elif row.get(name) != identity.get(name):
                    _fail(
                        failures,
                        f"scenario {scenario_id}: derived {name} "
                        f"{row.get(name)} != golden {identity.get(name)}",
                    )
        if row.get("wire_canonical") != scenario.get("envelope_wire_canonical"):
            _fail(failures, f"scenario {scenario_id}: wire_canonical disagrees with the manifest")
        # The attempt record pins the digest of exactly these canonical bytes.
        canonical = canonical_bytes(value)
        if sha256_hex(canonical) != attempt.get("envelope_digest"):
            _fail(failures, f"scenario {scenario_id}: attempt envelope_digest disagrees")
    elif value is not None:
        # Even a rejected envelope's bytes are pinned by the attempt record:
        # canonicalization must not depend on grammar acceptance.
        if sha256_hex(canonical_bytes(value)) != attempt.get("envelope_digest"):
            _fail(failures, f"scenario {scenario_id}: attempt envelope_digest disagrees")

    # --- digests of the transmitted bytes --------------------------------
    payload_hex = sha256_hex(payload_bytes)
    if row.get("payload_digest") != payload_hex or row.get("transport_digest") != payload_hex:
        _fail(failures, f"scenario {scenario_id}: payload/transport digest row disagrees")
    if row.get("request_digest") != sha256_hex(body_bytes):
        _fail(failures, f"scenario {scenario_id}: request digest row disagrees")
    # Tampered vectors must actually be tampered; everyone else must tie out.
    request_ties = sha256_hex(body_bytes) == attempt.get("request_content_digest")
    payload_ties = payload_hex == attempt.get("payload_transport_digest")
    if alteration_kind is None:
        if not request_ties:
            _fail(failures, f"scenario {scenario_id}: body digest != declared request digest")
        if not payload_ties:
            _fail(failures, f"scenario {scenario_id}: payload digest != declared transport digest")
    elif alteration_kind == "payload-byte-flip":
        if request_ties or payload_ties:
            _fail(failures, f"scenario {scenario_id}: payload flip did not change the digests")
    elif alteration_kind == "boundary-substitution":
        if not payload_ties:
            _fail(failures, f"scenario {scenario_id}: boundary swap must not touch the payload")
        if request_ties:
            _fail(failures, f"scenario {scenario_id}: boundary swap did not change the body digest")

    # --- the signed preimage and the signature ---------------------------
    signing_key_id = _case_text(signing, "signing_key_id")
    signing_key_name = _case_text(signing, "signing_key")
    if attempt.get("uploader_key_id") != signing_key_id:
        _fail(failures, f"scenario {scenario_id}: attempt key id != manifest signing_key_id")
    pinned_key = keys_by_name.get(signing_key_name)
    if pinned_key is None or pinned_key.get("key_id") != signing_key_id:
        _fail(failures, f"scenario {scenario_id}: signing key not pinned under that key id")
    signing_key = keys_by_id.get(str(attempt.get("uploader_key_id")))
    preimage = ingest_attempt_signing_input(
        str(attempt["http_method"]),
        str(attempt["route"]),
        str(attempt["content_type"]),
        bytes.fromhex(str(attempt["request_content_digest"])),
        bytes.fromhex(str(attempt["envelope_digest"])),
        bytes.fromhex(str(attempt["payload_canonical_digest"])),
        bytes.fromhex(str(attempt["payload_transport_digest"])),
        bytes.fromhex(str(attempt["uploader_key_id"])),
        _u63_value(attempt["authorization_epoch"]),
        str(attempt["authorization_timestamp"]),
    )
    if row.get("signing_input_sha256") != sha256_hex(preimage):
        _fail(failures, f"scenario {scenario_id}: signing preimage digest row disagrees")
    if preimage.hex() != signing.get("attempt_input_hex"):
        _fail(failures, f"scenario {scenario_id}: preimage != golden attempt_input_hex")
    if sha256_hex(preimage) != signing.get("attempt_input_sha256"):
        _fail(failures, f"scenario {scenario_id}: preimage digest != golden attempt_input_sha256")
    signature = bytes.fromhex(str(attempt["signature"]))
    if signing_key is not None:
        public = bytes.fromhex(_case_text(signing_key, "public_key"))
        if not ed25519_verify(public, preimage, signature):
            _fail(failures, f"scenario {scenario_id}: attempt signature does not verify")
        flipped = bytearray(preimage)
        flipped[-1] ^= 1
        if ed25519_verify(public, bytes(flipped), signature):
            _fail(failures, f"scenario {scenario_id}: signature accepts tampered preimage")
        bad = bytearray(signature)
        bad[0] ^= 1
        if ed25519_verify(public, preimage, bytes(bad)):
            _fail(failures, f"scenario {scenario_id}: tampered signature verifies")

    # --- multipart framing -----------------------------------------------
    parsed = multipart_parts(body_bytes)
    if parsed is None:
        _fail(failures, f"scenario {scenario_id}: body is not the pinned two-part framing")
    else:
        boundary, parts = parsed
        if parts[0] != envelope_bytes:
            _fail(failures, f"scenario {scenario_id}: envelope part != envelope.json bytes")
        if parts[1] != payload_bytes:
            _fail(failures, f"scenario {scenario_id}: payload part != payload.jsonl bytes")
        declared = boundary_of_content_type(str(attempt["content_type"]))
        rebuilt = multipart_body(declared, envelope_bytes, payload_bytes) if declared else None
        if alteration_kind == "boundary-substitution":
            if rebuilt == body_bytes:
                _fail(failures, f"scenario {scenario_id}: boundary not actually substituted")
        elif rebuilt != body_bytes:
            _fail(
                failures,
                f"scenario {scenario_id}: body != the pinned framing under the declared boundary",
            )

    # --- attempt-level classification ------------------------------------
    existing_rel = files.get("existing_occurrence")
    existing = corpus.obj(str(existing_rel)) if isinstance(existing_rel, str) else None
    expected_manifest = occurrence_manifest_of(envelope) if envelope is not None else None
    code = classify_attempt(
        envelope_code,
        envelope,
        attempt,
        body_bytes,
        payload_bytes,
        signing_key.members if signing_key is not None else None,
        linkages,
        server_time,
        existing,
        expected_manifest,
    )
    if expect.get("outcome") == "accepted":
        if code is not None:
            _fail(failures, f"scenario {scenario_id}: classified {code}, expected acceptance")
        _verify_receipt(corpus, scenario, envelope, expect, files, keys_by_name, keys_by_id,
                        attempt, signing, failures)
    else:
        golden_code = expect.get("error_code")
        if code != golden_code:
            _fail(
                failures,
                f"scenario {scenario_id}: classified {code}, golden {golden_code}",
            )
        _verify_error_body(corpus, scenario, expect, files, value, failures)


def _verify_receipt(
    corpus: Corpus,
    scenario: Obj,
    envelope: Envelope | None,
    expect: Obj,
    files: Obj,
    keys_by_name: dict[str, Obj],
    keys_by_id: dict[str, Obj],
    attempt: dict[str, object],
    signing: Obj,
    failures: list[str],
) -> None:
    scenario_id = _case_text(scenario, "id")
    receipt_rel = files.get("receipt")
    if not isinstance(receipt_rel, str):
        _fail(failures, f"scenario {scenario_id}: accepted scenario carries no receipt")
        return
    if envelope is None:
        _fail(failures, f"scenario {scenario_id}: receipt checked without a validated envelope")
        return
    receipt = corpus.obj(receipt_rel)
    certificate = receipt.get("certificate")
    if not isinstance(certificate, Obj):
        _fail(failures, f"scenario {scenario_id}: receipt certificate is not an object")
        return

    # Identity binding: the receipt names exactly the derived identities.
    identity = scenario.get("identity")
    if isinstance(identity, Obj):
        binding = {
            "occurrence_id": receipt.get("occurrence_id"),
            "attestation_id": receipt.get("attestation_id"),
            "blob_digest": receipt.get("blob_digest"),
            "occurrence_object_key": receipt.get("occurrence_object_key"),
            "attestation_object_key": receipt.get("attestation_object_key"),
            "blob_object_key": receipt.get("blob_object_key"),
        }
        for name, found in binding.items():
            if found != identity.get(name):
                _fail(failures, f"scenario {scenario_id}: receipt {name} != derived identity")
    outcomes = expect.get("outcomes")
    if isinstance(outcomes, Obj):
        for part in ("attestation", "blob", "occurrence"):
            if receipt.get(f"{part}_outcome") != outcomes.get(part):
                _fail(
                    failures,
                    f"scenario {scenario_id}: receipt {part}_outcome "
                    f"{receipt.get(f'{part}_outcome')} != golden {outcomes.get(part)}",
                )
    if receipt.get("tenant_id") != envelope["tenant_id"]:
        _fail(failures, f"scenario {scenario_id}: receipt tenant != envelope tenant")
    if receipt.get("request_id") != envelope["request_id"]:
        _fail(failures, f"scenario {scenario_id}: receipt request_id != envelope request_id")
    if receipt.get("authorization_epoch") != attempt.get("authorization_epoch"):
        _fail(failures, f"scenario {scenario_id}: receipt epoch != attempt epoch")
    if receipt.get("authorization_key_id") != attempt.get("uploader_key_id"):
        _fail(failures, f"scenario {scenario_id}: receipt authorization_key_id != attempt key id")
    commit_time = receipt.get("commit_time")
    if not isinstance(commit_time, str) or not _TIMESTAMP.match(commit_time) or not calendar_valid(commit_time):
        _fail(failures, f"scenario {scenario_id}: receipt commit_time is not a valid instant")

    # Certificate: pinned receipt key, tenant-matched authority, in-window.
    receipt_key_name = _case_text(signing, "receipt_key")
    pinned = keys_by_name.get(receipt_key_name)
    if pinned is None:
        _fail(failures, f"scenario {scenario_id}: receipt key {receipt_key_name} is not pinned")
        return
    if certificate.get("key_id") != pinned.get("key_id"):
        _fail(failures, f"scenario {scenario_id}: certificate key_id != pinned receipt key")
    if certificate.get("public_key") != pinned.get("public_key"):
        _fail(failures, f"scenario {scenario_id}: certificate public_key != pinned key material")
    if receipt.get("receipt_key_id") != pinned.get("key_id"):
        _fail(failures, f"scenario {scenario_id}: receipt_key_id != certificate key_id")
    if certificate.get("tenant_id") != envelope["tenant_id"]:
        _fail(failures, f"scenario {scenario_id}: certificate tenant != envelope tenant")
    authority = keys_by_id.get(str(certificate.get("authority_key_id")))
    if authority is None or authority.get("role") != "tenant-authority-root":
        _fail(failures, f"scenario {scenario_id}: certificate authority is not a pinned root")
        return
    if authority.get("tenant_id") != envelope["tenant_id"]:
        _fail(failures, f"scenario {scenario_id}: authority root belongs to another tenant")
    valid_from, valid_until = certificate.get("valid_from"), certificate.get("valid_until")
    if not all(
        isinstance(t, str) and _TIMESTAMP.match(t) and calendar_valid(t)
        for t in (valid_from, valid_until)
    ):
        _fail(failures, f"scenario {scenario_id}: certificate window is not valid")
    elif isinstance(commit_time, str):
        if not timestamp_epoch(valid_from) <= timestamp_epoch(commit_time) <= timestamp_epoch(valid_until):
            _fail(failures, f"scenario {scenario_id}: commit_time outside the certificate window")

    # The signature chain: authority signs the certificate, certificate key
    # signs the receipt. Signed bytes are the canonical record minus its
    # signature member (manifest "signature_inputs" convention).
    certificate_bytes = _minus(certificate, "authority_signature")
    if sha256_hex(certificate_bytes) != signing.get("certificate_signed_bytes_sha256"):
        _fail(failures, f"scenario {scenario_id}: certificate signed bytes != golden digest")
    authority_signature = certificate.get("authority_signature")
    if not isinstance(authority_signature, str):
        _fail(failures, f"scenario {scenario_id}: certificate lacks authority_signature")
    elif not ed25519_verify(
        bytes.fromhex(_case_text(authority, "public_key")),
        certificate_bytes,
        bytes.fromhex(authority_signature),
    ):
        _fail(failures, f"scenario {scenario_id}: certificate signature does not verify")
    receipt_bytes = _minus(receipt, "signature")
    if sha256_hex(receipt_bytes) != signing.get("receipt_signed_bytes_sha256"):
        _fail(failures, f"scenario {scenario_id}: receipt signed bytes != golden digest")
    receipt_signature = receipt.get("signature")
    if not isinstance(receipt_signature, str):
        _fail(failures, f"scenario {scenario_id}: receipt lacks a signature")
    elif not ed25519_verify(
        bytes.fromhex(_case_text(certificate, "public_key")),
        receipt_bytes,
        bytes.fromhex(receipt_signature),
    ):
        _fail(failures, f"scenario {scenario_id}: receipt signature does not verify")


def _minus(record: Obj, member: str) -> bytes:
    """Canonical bytes of the record without one member."""
    stripped = Obj()
    for name in record.names():
        if name != member:
            stripped.set(name, record.get(name))
    return canonical_bytes(stripped)


def _verify_error_body(
    corpus: Corpus,
    scenario: Obj,
    expect: Obj,
    files: Obj,
    envelope_value: object,
    failures: list[str],
) -> None:
    scenario_id = _case_text(scenario, "id")
    error_rel = files.get("error")
    if not isinstance(error_rel, str):
        _fail(failures, f"scenario {scenario_id}: rejected scenario carries no error body")
        return
    error = corpus.obj(error_rel)
    if error.names() != list(_expected_error_members()):
        _fail(failures, f"scenario {scenario_id}: error body members {error.names()}")
        return
    if error.get("schema") != ERROR_SCHEMA_NAME:
        _fail(failures, f"scenario {scenario_id}: error schema != {ERROR_SCHEMA_NAME}")
    if error.get("code") != expect.get("error_code"):
        _fail(failures, f"scenario {scenario_id}: error code != expected code")
    if error.get("retryable") != expect.get("retryable"):
        _fail(failures, f"scenario {scenario_id}: error retryable != expected")
    correlation = error.get("correlation_id")
    if not isinstance(correlation, str) or not is_uuid(correlation, "7"):
        _fail(failures, f"scenario {scenario_id}: correlation_id is not a UUIDv7")
    if isinstance(envelope_value, Obj):
        request_id = envelope_value.get("request_id")
        if error.get("request_id") != request_id:
            _fail(failures, f"scenario {scenario_id}: error request_id != envelope request_id")


def _verify_invariants(corpus: Corpus, rows: dict, failures: list[str]) -> None:
    """The manifest's cross-scenario invariants, recomputed from the rows
    and the scenario files (rows carry no request_id/blob_digest of their
    own, so those two compare from the transmitted bytes)."""
    invariants = corpus.manifest.get("invariants")
    if not isinstance(invariants, Obj):
        return
    by_id = {str(s.get("id")): s for s in corpus.scenarios}

    def scenario_row(scenario_id: str) -> dict | None:
        row = rows.get(("scenario", scenario_id, ""))
        return row if isinstance(row, dict) else None

    def envelope_member(scenario_id: str, member: str) -> object:
        entry = by_id.get(scenario_id)
        files = entry.get("files") if isinstance(entry, Obj) else None
        if not isinstance(files, Obj):
            return None
        value, _ = parse_json_or_malformed(corpus.bytes(_file(files, "envelope")))
        return value.get(member) if isinstance(value, Obj) else None

    def payload_digest(scenario_id: str) -> str | None:
        entry = by_id.get(scenario_id)
        files = entry.get("files") if isinstance(entry, Obj) else None
        if not isinstance(files, Obj):
            return None
        return sha256_hex(corpus.bytes(_file(files, "payload")))

    def pair(block: Obj, label: str, check) -> None:
        names = block.get("scenarios")
        if not isinstance(names, list) or len(names) != 2:
            return
        first, second = (scenario_row(str(name)) for name in names)
        if first is None or second is None:
            _fail(failures, f"invariant {label}: missing scenario rows")
            return
        problem = check(str(names[0]), str(names[1]), first, second)
        if problem:
            _fail(failures, f"invariant {label}: {problem}")

    def _cross(a: str, b: str, first: dict, second: dict) -> str | None:
        return _invariant_cross_tenant(a, b, first, second, payload_digest)

    def _relay(block: Obj):
        def check(a: str, b: str, first: dict, second: dict) -> str | None:
            return _invariant_relay(a, b, first, second, block)
        return check

    def _retry(a: str, b: str, first: dict, second: dict) -> str | None:
        return _invariant_retry(a, b, first, second, envelope_member)

    cross = invariants.get("cross_tenant_separation")
    if isinstance(cross, Obj):
        pair(cross, "cross_tenant_separation", _cross)
    relay = invariants.get("relay_occurrence_equality")
    if isinstance(relay, Obj):
        pair(relay, "relay_occurrence_equality", _relay(relay))
    retry = invariants.get("retry_identity_equality")
    if isinstance(retry, Obj):
        pair(retry, "retry_identity_equality", _retry)


def _invariant_cross_tenant(
    baseline_id: str,
    second_id: str,
    baseline: dict,
    second: dict,
    payload_digest,
) -> str | None:
    for member in ("session_hash", "occurrence_id", "attestation_id", "blob_object_key",
                   "occurrence_object_key", "attestation_object_key"):
        if baseline.get(member) == second.get(member):
            return f"{member} did not change across tenants"
    if payload_digest(baseline_id) != payload_digest(second_id):
        return "blob digest should be shared across tenants"
    return None


def _invariant_relay(
    baseline_id: str,
    relay_id: str,
    baseline: dict,
    relay: dict,
    block: Obj,
) -> str | None:
    for member in ("blob_object_key", "occurrence_object_key"):
        if baseline.get(member) != relay.get(member):
            return f"{member} should be shared with the relay upload"
    if baseline.get("attestation_object_key") == relay.get("attestation_object_key"):
        return "relay attestation key should be its own"
    shared = block.get("shared")
    if isinstance(shared, Obj):
        for member in ("blob_object_key", "occurrence_object_key"):
            pinned = shared.get(member)
            if isinstance(pinned, str) and (
                baseline.get(member) != pinned or relay.get(member) != pinned
            ):
                return f"pinned {member} disagrees with the rows"
        relay_attestation = shared.get("relay_attestation_object_key")
        if isinstance(relay_attestation, str) and relay.get("attestation_object_key") != relay_attestation:
            return "pinned relay_attestation_object_key disagrees with the relay row"
    return None


def _invariant_retry(
    baseline_id: str,
    retry_id: str,
    baseline: dict,
    retry: dict,
    envelope_member,
) -> str | None:
    for member in ("occurrence_id", "attestation_id", "blob_object_key",
                   "occurrence_object_key", "attestation_object_key"):
        if baseline.get(member) != retry.get(member):
            return f"{member} should be frozen across the retry pair"
    for member in ("request_id", "upstream_session_id"):
        if envelope_member(baseline_id, member) != envelope_member(retry_id, member):
            return f"envelope {member} should be frozen across the retry pair"
    if baseline.get("canonical_hex") != retry.get("canonical_hex"):
        return "envelope bytes should be frozen across the retry pair"
    return None


# ---------------------------------------------------------------------------
# Self-test: pinned vectors that need no corpus. If these fail, every corpus
# result is meaningless — the primitives themselves drifted.
# ---------------------------------------------------------------------------

# RFC 8032 §7.1, the three SHA-512 Ed25519 test vectors.
_RFC8032_VECTORS = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac1"
        "8ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]

# Derivation pins computed once and frozen: independent of the corpus, so a
# regression in any primitive is caught before a corpus result is trusted.
_SESSION_PIN = "06c7da84fb96ecbf9d104a0a833b55332eeaeac43fec5ac1ca4a40d2a5a49b82"
_KEY_ID_PIN = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
_BLOB_PIN = "e4cc43d98fec5932d0a665337da43cf8d6b9657b36f9bb1d1bcd7bb7fb21005f"


def _pin_envelope() -> tuple[Obj, bytes]:
    """A self-consistent envelope built through the module's own derivations."""
    payload = b"contract-verifier pin"
    blob = blob_digest(payload)
    session = session_hash(
        "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b",
        "11111111-2222-4333-8444-555555555555",
        "claude-code",
        "session-pin",
    )
    artifact = artifact_hash(
        session, "file-slice", "adapter", "1", "artifact-pin"
    )
    occurrence = occurrence_id(
        session, artifact, "1a07a111-7000-7000-8000-000000000001",
        "byte", 0, 0, blob,
    )
    attestation = attestation_id(
        occurrence,
        "11111111-2222-4333-8444-555555555555",
        "1a07a111-7000-7000-8000-000000000002",
    )
    envelope = Obj()
    envelope.set("adapter_artifact_id", "artifact-pin")
    envelope.set("adapter_id", "adapter")
    envelope.set("adapter_projection_version", "1")
    envelope.set("artifact_kind", "file-slice")
    envelope.set("attestation_id", attestation.hex())
    envelope.set("blob_digest", blob.hex())
    envelope.set("capture_time", "2026-09-12T00:00:00Z")
    envelope.set("compressed_size", len(payload))
    envelope.set("envelope_creation_time", "2026-09-12T00:00:00Z")
    envelope.set("generation", "1a07a111-7000-7000-8000-000000000001")
    envelope.set("harness", "claude-code")
    envelope.set("id_source", "upstream")
    envelope.set("incoming_checksum", blob.hex())
    envelope.set("incoming_checksum_algorithm", "sha256")
    envelope.set("occurrence_id", occurrence.hex())
    envelope.set("origin_client_id", "11111111-2222-4333-8444-555555555555")
    envelope.set("protocol_version", 1)
    envelope.set("envelope_version", 1)
    envelope.set("range_end", 0)
    envelope.set("range_kind", "byte")
    envelope.set("range_start", 0)
    envelope.set("request_id", "1a07a111-7000-7000-8000-000000000002")
    envelope.set("storage_profile", "zstd-v1")
    envelope.set("tenant_id", "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b")
    envelope.set("transport_encoding", "identity")
    envelope.set("uncompressed_size", len(payload))
    envelope.set("upstream_session_id", "session-pin")
    envelope.set("uploader_client_id", "11111111-2222-4333-8444-555555555555")
    return envelope, blob


def self_test() -> None:
    """Raise [`VerificationFailure`] if any pinned primitive drifted."""
    checks = 0

    def check(condition: bool, label: str) -> None:
        nonlocal checks
        checks += 1
        if not condition:
            raise VerificationFailure(f"self-test: {label}")

    # Ed25519 against RFC 8032, plus the negatives that make a passing
    # verify mean something.
    for public_hex, message_hex, signature_hex in _RFC8032_VECTORS:
        public, message, signature = (
            bytes.fromhex(public_hex),
            bytes.fromhex(message_hex),
            bytes.fromhex(signature_hex),
        )
        check(ed25519_verify(public, message, signature), f"RFC 8032 {public_hex[:8]}")
        flipped = bytearray(message)
        if flipped:
            flipped[0] ^= 1
        elif len(signature) == 64:
            flipped = bytearray(signature)
            flipped[63] ^= 1
        check(
            not ed25519_verify(public, bytes(flipped), signature),
            f"RFC 8032 {public_hex[:8]} accepts a tampered input",
        )
    first = _RFC8032_VECTORS[0]
    public, message, signature = (
        bytes.fromhex(first[0]),
        bytes.fromhex(first[1]),
        bytes.fromhex(first[2]),
    )
    # Scalar bumped past the group order must not verify.
    s = int.from_bytes(signature[32:], "little")
    bumped = signature[:32] + ((s + _ED_L).to_bytes(32, "little"))
    check(not ed25519_verify(public, message, bumped), "signature with s >= L verifies")
    check(not ed25519_verify(public, message, signature[:-1]), "63-byte signature verifies")
    check(not ed25519_verify(public, message, signature + b"\x00"), "65-byte signature verifies")

    # Derivation pins.
    check(
        session_hash(
            "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b",
            "11111111-2222-4333-8444-555555555555",
            "claude-code",
            "session-pin",
        ).hex() == _SESSION_PIN,
        "session-v1 derivation pin",
    )
    check(
        key_id_of_public_key(bytes(range(32))).hex() == _KEY_ID_PIN,
        "key-id derivation pin",
    )
    check(blob_digest(b"contract-verifier pin").hex() == _BLOB_PIN, "blob digest pin")

    # The attempt preimage, re-assembled by hand rather than by the builder.
    content_type = "multipart/related; boundary=pin"
    digests = [bytes([0x00]) + bytes([0x11]) * 31] + [bytes([b]) * 32 for b in (0x22, 0x33, 0x44, 0x55)]
    hand = b"ingest-attempt-v1\x00"
    for field in (b"POST", b"/v1/ingest", content_type.encode()):
        hand += _u64be(len(field)) + field
    for digest in digests:
        hand += _u64be(32) + digest
    hand += _u64be(8) + _u64be(7)
    stamp = b"2026-09-12T00:00:00Z"
    hand += _u64be(len(stamp)) + stamp
    built = ingest_attempt_signing_input(
        "POST", "/v1/ingest", content_type,
        digests[0], digests[1], digests[2], digests[3], digests[4],
        7, "2026-09-12T00:00:00Z",
    )
    check(hand == built, "ingest-attempt-v1 preimage framing")

    # Canonical JSON: sorting, escaping, and the rejection map.
    def object_of(*pairs: tuple[str, object]) -> Obj:
        obj = Obj()
        for name, value in pairs:
            obj.set(name, value)
        return obj

    check(canonical_bytes(object_of(("b", 1), ("a", 2))) == b'{"a":2,"b":1}', "member sort")
    # The escape matrix, spelled out so a wrong rule fails loudly.
    escapes = canonical_bytes(object_of(("ctl", "\x01"), ("quote", '"'), ("solidus", "/"), ("backslash", "\\")))
    check(escapes == b'{"backslash":"\\\\","ctl":"\\u0001","quote":"\\"","solidus":"/"}', "escape matrix")
    check(
        canonical_bytes(object_of(("nul", "\x1f"))) == b'{"nul":"\\u001f"}',
        "control escapes are lowercase hex",
    )
    check(canonical_bytes(object_of((" Astral ", "\U0001F600"))) == '{" Astral ":"😀"}'.encode(), "astral literal")
    # UTF-16 code-unit order, not code-point order: U+10000 (two surrogates
    # D800 DC00) sorts before the single-unit U+FFFF.
    astral_first = canonical_bytes(object_of(("\uffff", 1), ("\U00010000", 2)))
    check(
        astral_first == '{"\U00010000":2,"￿":1}'.encode(),
        "member sort is UTF-16 code-unit order",
    )
    check(canonical_bytes(object_of(("t", True))) == b'{"t":true}', "literal spelling")
    check(canonical_bytes(object_of(("n", None))) == b'{"n":null}', "literal spelling")
    for text, expected in [
        (b'{"a":1,"a":2}', "envelope.malformed"),
        (b'{"a":"\xed\xa0\x80"}', "envelope.malformed"),
        (b'{"a":1e3}', "envelope.schema_invalid"),
        (b'{"a":9223372036854775808}', "envelope.schema_invalid"),
        (b'{"a":-9223372036854775809}', "envelope.schema_invalid"),
        (b'{"a":}', "envelope.malformed"),
    ]:
        _, code = parse_json_or_malformed(text)
        check(code == expected, f"parse rejection {text!r} -> {code}, expected {expected}")

    # The envelope ladder, end to end through the module's own derivations.
    envelope, blob = _pin_envelope()
    data = canonical_bytes(envelope)
    try:
        validate_envelope(data)
    except EnvelopeRejected as rejected:
        raise VerificationFailure(f"self-test: pin envelope rejected: {rejected}") from rejected
    check(blob.hex() == _BLOB_PIN, "pin envelope blob")
    mutations: list[tuple[str, object, str]] = [
        ("reserved member", "signature", "AA"),
        ("unknown enum", "artifact_kind", "sonnet-trace"),
        ("bad grammar", "generation", "not-a-uuid"),
        ("version", "protocol_version", 2),
        ("calendar", "capture_time", "2026-02-30T00:00:00Z"),
        ("range order", "range_end", 1),
    ]
    for label, member, value in mutations:
        mutated = Obj()
        for name in envelope.names():
            mutated.set(name, envelope.get(name))
        mutated.set(member, value)
        try:
            validate_envelope(canonical_bytes(mutated))
        except EnvelopeRejected as rejected:
            check(
                rejected.code == "envelope.schema_invalid"
                or (label == "version" and rejected.code == "envelope.version_unsupported"),
                f"mutation {label} rejected with {rejected.code}",
            )
        else:
            check(False, f"mutation {label} was accepted")
    # An identity lie is caught by re-derivation, not grammar.
    lying = Obj()
    for name in envelope.names():
        lying.set(name, envelope.get(name))
    lying.set("occurrence_id", "00" * 32)
    try:
        validate_envelope(canonical_bytes(lying))
    except EnvelopeRejected as rejected:
        check(rejected.code == "envelope.schema_invalid", "identity lie rejection code")
    else:
        check(False, "identity lie was accepted")

    # Multipart framing round-trip.
    body = multipart_body("pin", data, b"line1\nline2\n")
    parsed = multipart_parts(body)
    check(parsed is not None, "multipart framing parses")
    if parsed is not None:
        boundary, parts = parsed
        check(boundary == "pin", "multipart boundary")
        check(parts == [data, b"line1\nline2\n"], "multipart parts")
    check(boundary_of_content_type("application/json") is None, "non-multipart content type")

    # The answer-sheet parser catches the two real diff hazards: a
    # non-canonical line and a duplicate row key.
    line = _row("derivation", "x", "", [("session_hash", "00")])[1]
    check(_parse_report_lines([line]) is not None, "report line parses")
    try:
        _parse_report_lines([line, line])
    except VerificationFailure:
        checks += 1
    else:
        raise VerificationFailure("self-test: duplicate report row accepted")
    try:
        _parse_report_lines(['{"row":"x","id":"y",}\n'])
    except VerificationFailure:
        checks += 1
    else:
        raise VerificationFailure("self-test: non-canonical report line accepted")

    return checks


# ---------------------------------------------------------------------------
# Compare mode: byte-diff the Python answer sheet against the Rust replay.
# ---------------------------------------------------------------------------


def rust_report_lines(corpus_root: Path, explicit: Path | None) -> list[str]:
    """The conformance-replay bin's answer sheet, or None when unavailable."""
    if explicit is not None:
        try:
            return explicit.read_text().splitlines()
        except OSError as error:
            raise CorpusError(f"{explicit}: {error.strerror or 'unreadable'}") from error
    command = [
        "cargo", "run", "--quiet", "-p", "archivist-protocol",
        "--bin", "conformance-replay", "--", str(corpus_root),
    ]
    try:
        completed = subprocess.run(
            command, cwd=REPO_ROOT, capture_output=True, text=True, check=False
        )
    except FileNotFoundError as error:
        raise PrerequisiteError("cargo is not installed") from error
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-5:]
        raise VerificationFailure(
            "conformance-replay failed to run:\n  " + "\n  ".join(tail)
        )
    return completed.stdout.splitlines()


class PrerequisiteError(Exception):
    """A tool the comparison needs (cargo) is not available."""


def compare_reports(ours: list[str], theirs: list[str], quiet: bool) -> int:
    """Byte-diff the sheets; return the process exit code."""
    # Both sides normalize to bare lines (ours carry their LF terminators).
    ours = [line.rstrip("\n") for line in ours]
    theirs = [line.rstrip("\n") for line in theirs]
    for index, (mine, yours) in enumerate(zip(ours, theirs)):
        if mine != yours:
            if not quiet:
                print(f"divergence at row {index + 1}:")
                print(f"  python: {mine}")
                print(f"  rust:   {yours}")
            return EXIT_DIVERGENCE
    if len(ours) != len(theirs):
        if not quiet:
            extra, missing = (
                (ours, theirs) if len(ours) > len(theirs) else (theirs, ours)
            )
            print(f"row count differs: {len(ours)} python vs {len(theirs)} rust")
            for line in extra[len(missing):][:5]:
                print(f"  extra: {line}")
        return EXIT_DIVERGENCE
    if not quiet:
        print(f"answer sheets identical: {len(ours)} rows")
    return EXIT_PASS


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="contract-verifier",
        description="Independent golden-vector verifier for the archivist protocol.",
    )
    parser.add_argument(
        "mode", nargs="?", default="verify", choices=("verify", "compare", "self-test"),
        help="verify the goldens (default), also diff against the Rust replay, "
        "or run the corpus-free self-test",
    )
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS, help="corpus root")
    parser.add_argument(
        "--rust-report", type=Path, default=None,
        help="read the Rust answer sheet from this file instead of running cargo",
    )
    parser.add_argument(
        "--report", type=Path, default=None,
        help="write the Python answer sheet to this file",
    )
    parser.add_argument("--quiet", action="store_true", help="only exit codes")
    args = parser.parse_args(argv)

    if args.mode == "self-test":
        try:
            checks = self_test()
        except VerificationFailure as failure:
            if not args.quiet:
                print(str(failure), file=sys.stderr)
            return EXIT_FAILURE
        if not args.quiet:
            print(f"self-test: {checks} pinned checks pass")
        return EXIT_PASS

    try:
        if not args.corpus.is_dir():
            raise CorpusError(f"{args.corpus}: corpus directory is missing")
        corpus = Corpus(args.corpus)
        report, counts = verify_corpus(corpus)
        if not args.quiet:
            summary = ", ".join(f"{count} {name}" for name, count in sorted(counts.items()))
            print(f"verify: all goldens hold ({summary})")
    except CorpusError as error:
        if not args.quiet:
            print(f"corpus: {error}", file=sys.stderr)
        return EXIT_CORRUPT
    except VerificationFailure as failure:
        if not args.quiet:
            print(str(failure), file=sys.stderr)
        return EXIT_FAILURE

    if args.report is not None:
        args.report.write_text("".join(report))

    if args.mode == "compare":
        try:
            theirs = rust_report_lines(args.corpus, args.rust_report)
        except PrerequisiteError as error:
            if not args.quiet:
                print(f"prerequisite: {error}", file=sys.stderr)
            return EXIT_PREREQUISITE
        except (CorpusError, VerificationFailure) as error:
            if not args.quiet:
                print(str(error), file=sys.stderr)
            return (
                EXIT_CORRUPT if isinstance(error, CorpusError) else EXIT_FAILURE
            )
        return compare_reports(report, theirs, args.quiet)
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
