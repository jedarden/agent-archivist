#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Instruments for the release-image smoke harness (smoke.sh, image-smoke.md).

The smoke drives signature material whose private halves never ship in the
repository: the two committed verification corpora derive every key from a
pinned label (`archivist.conformance/v1 <name>`, `archivist.control/v1
<name>`), so this driver re-derives the same pairs at run time and signs with
a pure-Python RFC 8032 implementation — no network, no secret anywhere on
disk or in argv. When the host lacks the `cryptography` wheel the corpora
generators still import: this module installs a stand-in for exactly the raw
Ed25519 surface they touch, backed by the same RFC 8032 code, so the derived
publics and signatures are bit-identical to the wheel's; anything beyond
that surface raises. Output is content-free: paths, object keys, counts, and
booleans only; the deny-token scan never echoes what it searches for.

Modes:
  self-test       prove the signer and the whole mint path against the
                  committed corpora (RFC 8032 vectors, the golden baseline
                  signature, keys.json publics, mint determinism)
  mint            write one fresh, correctly-signed ingest attempt plus the
                  stale golden attempt and the expected raw object keys
  mint-linked      sign fresh and stale attempts with the protected identity
                  created by `archivist link request`
  verify-receipt   verify a returned receipt and its tenant-authority-signed
                  certificate using the independently implemented verifier
  control-objects write the linked-client pointer objects at their pinned
                  object keys, ready for the control bucket
  base-inventory  the final-state regular-file inventory of a `docker save`
                  extraction (layer order applied, whiteouts honored)
  scan-image      secret smoke: inventory a `docker save` extraction against
                  the base image's file list and byte-scan every layer — and
                  the image config blob — for denied material
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import posixpath
import sys
import tarfile
import types

TOOLS = pathlib.Path(__file__).resolve().parents[2] / "tools"
EXAMPLES = TOOLS.parent / "schemas" / "v1" / "examples"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

# The one file the runtime stage installs (RC-015). Its bytes legitimately
# carry the server's own credential vocabulary — the `ACCESS_KEY=` /
# `SECRET_KEY=` document literals the storage config parses and the
# `-----BEGIN `/`PRIVATE KEY-----` constants the protocol redaction detector
# matches — so the generic credential shapes exempt exactly this path. The
# deny-value scan (tenant material, the pinned authority public, the run's
# own minted secrets) covers it like every other byte: those values have no
# legitimate reason to be anywhere in the image.
BINARY_PATH = "usr/local/bin/archivist"


# ---------------------------------------------------------------------------
# Pure-Python RFC 8032 Ed25519 signing. The corpora ship verify-only
# primitives (conformancegen.ed25519_verify); signing is this module's
# addition, proven against the RFC's test vectors and against the corpora's
# own cryptography-signed golden signatures by `self-test`.
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _xrecover(_BY)
_B = (_BX % _P, _BY % _P, 1, (_BX * _BY) % _P)


def _add(p1: tuple, p2: tuple) -> tuple:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(point: tuple, scalar: int) -> tuple:
    out = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            out = _add(out, point)
        point = _add(point, point)
        scalar >>= 1
    return out


def _encode(point: tuple) -> bytes:
    x, y, z, _ = point
    zi = _inv(z)
    x = x * zi % _P
    y = y * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _clamp(seed: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 63
    a[31] |= 64
    return int.from_bytes(a, "little"), h[32:]


def public_from_seed(seed: bytes) -> bytes:
    a, _ = _clamp(seed)
    return _encode(_mul(_B, a))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _clamp(seed)
    big_a = _encode(_mul(_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    big_r = _encode(_mul(_B, r))
    k = int.from_bytes(hashlib.sha512(big_r + big_a + message).digest(), "little") % _L
    return big_r + int.to_bytes((r + k * a) % _L, 32, "little")


def _install_signing_shim() -> None:
    """A `cryptography` stand-in for builder hosts without the wheel.

    Covers exactly the raw Ed25519 surface the corpora generators touch —
    `Ed25519PrivateKey.from_private_bytes`, `public_key().public_bytes`
    over the raw encoding, and `sign` — backed by this module's RFC 8032
    implementation, so the derived publics and signatures are bit-identical
    to the wheel's. Any other attribute lookup on the shimmed modules
    raises, so a generator path that genuinely needs the wheel fails
    loudly instead of silently mis-signing.
    """

    class _ShimPublicKey:
        __slots__ = ("_seed",)

        def __init__(self, seed: bytes) -> None:
            self._seed = seed

        def public_bytes(self, _encoding=None, _format=None) -> bytes:
            return public_from_seed(self._seed)

    class ShimEd25519PrivateKey:
        __slots__ = ("_seed",)

        def __init__(self, seed: bytes) -> None:
            self._seed = seed

        @classmethod
        def from_private_bytes(cls, data) -> "ShimEd25519PrivateKey":
            data = bytes(data)
            if len(data) != 32:
                raise ValueError("an Ed25519 private key is 32 bytes")
            return cls(data)

        def public_key(self) -> _ShimPublicKey:
            return _ShimPublicKey(self._seed)

        def sign(self, message) -> bytes:
            return sign(self._seed, bytes(message))

    class Encoding:
        Raw = "Raw"

    class PublicFormat:
        Raw = "Raw"

    def module(name: str, **attrs) -> types.ModuleType:
        mod = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(mod, key, value)
        sys.modules[name] = mod
        return mod

    crypto = module("cryptography", __version__="smoke-ed25519-shim")
    hazmat = module("cryptography.hazmat")
    primitives = module("cryptography.hazmat.primitives")
    serialization = module(
        "cryptography.hazmat.primitives.serialization",
        Encoding=Encoding,
        PublicFormat=PublicFormat,
    )
    asymmetric = module("cryptography.hazmat.primitives.asymmetric")
    ed25519 = module(
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        Ed25519PrivateKey=ShimEd25519PrivateKey,
    )
    crypto.hazmat = hazmat
    hazmat.primitives = primitives
    primitives.serialization = serialization
    primitives.asymmetric = asymmetric
    asymmetric.ed25519 = ed25519


try:
    import cryptography  # noqa: F401
except ModuleNotFoundError:
    _install_signing_shim()

import conformancegen as cg  # noqa: E402
import controlgen as ct  # noqa: E402

# The control corpus's deployment story: the tenant, the linked client, and
# the pinned authority the smoke replica pins (`server.authority_key`). The
# private halves derive from the labels; keys.json carries the publics this
# self-test proves the derivation against.
TENANT = "3e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30"
CLIENT_A = "9a4c2f18-6b37-4e59-8d20-1f3a5c7e9b42"
GOLDEN_SCENARIO = "valid-direct-baseline"
STALE_SCENARIO = "invalid-stale-authorization"


# ---------------------------------------------------------------------------
# Key material: the corpora's derived pairs, duck-typed for cg.Scenario.
# ---------------------------------------------------------------------------


class DerivedSigner:
    """A corpus key pair re-derived from its pinned label."""

    def __init__(self, name: str, prefix: str):
        self.name = name
        self._seed = hashlib.sha256(f"{prefix} {name}".encode()).digest()
        self.public = public_from_seed(self._seed)
        self.public_key = self.public.hex()
        self.key_id = hashlib.sha256(self.public).hexdigest()

    def sign(self, message: bytes) -> str:
        return sign(self._seed, message).hex()


class IdentitySigner:
    """The fresh client key held by the local protected identity file."""

    def __init__(self, identity: dict):
        self.name = "newly-linked-client"
        self._seed = bytes.fromhex(identity["private_seed"])
        if len(self._seed) != 32:
            raise SystemExit("protected identity seed has the wrong size")
        self.public = public_from_seed(self._seed)
        self.public_key = self.public.hex()
        self.key_id = hashlib.sha256(self.public).hexdigest()

    def sign(self, message: bytes) -> str:
        return sign(self._seed, message).hex()


def control_signer(name: str) -> DerivedSigner:
    return DerivedSigner(name, ct.KEY_SEED_PREFIX)


def conformance_signer(name: str) -> DerivedSigner:
    return DerivedSigner(name, cg.KEY_SEED_PREFIX)


# ---------------------------------------------------------------------------
# The fresh attempt: the control corpus's deployment story over a golden
# envelope, with identities re-derived and a fresh authorization instant.
# ---------------------------------------------------------------------------


def _read_json(rel: str) -> dict:
    return json.loads((EXAMPLES / rel).read_text())


def _scenario_dir(scenario: str) -> pathlib.Path:
    return EXAMPLES / "conformance" / "scenarios" / scenario


def final_pointer() -> dict:
    """The current-pointer record CLIENT_A ends its bundle history on."""
    bundle = _read_json("control/epoch-progression.json")
    pointers = [
        entry["record"]
        for entry in bundle["history"]
        if entry["record"].get("record_kind") == "current-pointer"
        and entry["record"].get("client_id") == CLIENT_A
    ]
    if not pointers:
        raise SystemExit("control bundle carries no current pointer for the linked client")
    return pointers[-1]


def build_envelope(payload: bytes) -> dict:
    """The golden envelope re-anchored to the control corpus's identities."""
    envelope = json.loads(
        (_scenario_dir(GOLDEN_SCENARIO) / "envelope.json").read_text()
    )
    envelope["tenant_id"] = TENANT
    envelope["uploader_client_id"] = CLIENT_A
    envelope["origin_client_id"] = CLIENT_A
    envelope["blob_digest"] = cg.blob_digest(payload)
    identity = cg.derive_identity(envelope)
    envelope["occurrence_id"] = identity["occurrence_id"]
    envelope["attestation_id"] = identity["attestation_id"]
    # The declared identities must now re-derive to themselves.
    check = cg.derive_identity(envelope)
    if (
        check["occurrence_id"] != envelope["occurrence_id"]
        or check["attestation_id"] != envelope["attestation_id"]
    ):
        raise SystemExit("re-anchored envelope does not re-derive cleanly")
    return envelope


def mint(now: str) -> dict:
    """One fresh, correctly-signed ingest attempt and its expected keys."""
    pointer = final_pointer()
    scopes = pointer.get("scopes", {})
    envelope = build_envelope(( _scenario_dir(GOLDEN_SCENARIO) / "payload.jsonl").read_bytes())
    harness = envelope["harness"]
    if harness not in scopes.get("harnesses", []) or "ingest" not in scopes.get(
        "operations", []
    ):
        raise SystemExit(
            "golden harness/operation is outside the linked client's pinned scope"
        )
    signer = control_signer("control-client-a")
    if signer.key_id != pointer["key_id"]:
        raise SystemExit("derived uploader key does not match the final pointer")
    scenario = cg.Scenario(
        sid="smoke-fresh-direct",
        kind="valid",
        covers=[],
        story="release-image smoke: one fresh signed ingest attempt",
        envelope=envelope,
        payload=(_scenario_dir(GOLDEN_SCENARIO) / "payload.jsonl").read_bytes(),
        boundary="aa-smoke-fresh",
        uploader_key=signer,
        epoch=pointer["authorization_epoch"],
        authorization_time=now,
        server_time=now,
        receipt_key=None,
        outcomes=None,
        commit_time=None,
        error=None,
        asserts=[],
    )
    files = scenario.build()
    attempt = json.loads(files["attempt.json"])
    message = scenario.attempt_input_bytes(scenario.covered_values(files["request.body"]))
    if not cg.ed25519_verify(signer.public_key, attempt["signature"], message):
        raise SystemExit("minted attempt signature does not self-verify")
    identity = cg.derive_identity(envelope)
    return {
        "request_body": files["request.body"],
        "content_type": scenario.content_type(),
        "attempt": attempt,
        "object_keys": [
            identity["blob_object_key"],
            identity["occurrence_object_key"],
            identity["attestation_object_key"],
        ],
    }


def mint_linked(now: str, tenant: str, link_request: dict,
                identity_document: dict) -> dict:
    """Create a real upload proof using the identity just linked by the CLI."""
    signer = IdentitySigner(identity_document)
    client_id = link_request.get("client_id")
    if (link_request.get("requested_tenant_id") != tenant
            or link_request.get("key_id") != signer.key_id
            or link_request.get("public_key") != signer.public_key
            or not isinstance(client_id, str)):
        raise SystemExit("link request and protected identity do not agree")
    scopes = link_request.get("requested_scopes", {})
    if "codex" not in scopes.get("harnesses", []) or "ingest" not in scopes.get(
        "operations", []
    ):
        raise SystemExit("newly-linked client lacks the smoke upload scope")

    scenario_dir = _scenario_dir(GOLDEN_SCENARIO)
    payload = (scenario_dir / "payload.jsonl").read_bytes()
    envelope = json.loads((scenario_dir / "envelope.json").read_text())
    envelope["tenant_id"] = tenant
    envelope["uploader_client_id"] = client_id
    envelope["origin_client_id"] = client_id
    envelope["harness"] = "codex"
    envelope["blob_digest"] = cg.blob_digest(payload)
    # The blob digest participates in occurrence and attestation derivation.
    derived = cg.derive_identity(envelope)
    envelope["occurrence_id"] = derived["occurrence_id"]
    envelope["attestation_id"] = derived["attestation_id"]
    if cg.derive_identity(envelope) != derived:
        raise SystemExit("fresh upload identity derivation did not stabilize")

    def build_attempt(sid: str, authorization_time: str) -> tuple:
        attempt_scenario = cg.Scenario(
            sid=sid,
            kind="valid",
            covers=[],
            story="zero-state bootstrap smoke: freshly linked client upload",
            envelope=envelope,
            payload=payload,
            boundary="aa-bootstrap-first-receipt",
            uploader_key=signer,
            epoch=1,
            authorization_time=authorization_time,
            server_time=now,
            receipt_key=None,
            outcomes=None,
            commit_time=None,
            error=None,
            asserts=[],
        )
        files = attempt_scenario.build()
        attempt = json.loads(files["attempt.json"])
        message = attempt_scenario.attempt_input_bytes(
            attempt_scenario.covered_values(files["request.body"])
        )
        if not cg.ed25519_verify(signer.public_key, attempt["signature"], message):
            raise SystemExit("fresh client attempt signature did not verify")
        return attempt_scenario, files

    fresh_scenario, fresh_files = build_attempt("bootstrap-fresh", now)
    stale_time = (
        datetime.datetime.fromisoformat(now.replace("Z", "+00:00"))
        - datetime.timedelta(minutes=20)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    stale_scenario, stale_files = build_attempt("bootstrap-stale", stale_time)
    identity = cg.derive_identity(envelope)
    return {
        "request_body": fresh_files["request.body"],
        "content_type": fresh_scenario.content_type(),
        "attempt": json.loads(fresh_files["attempt.json"]),
        "object_keys": [
            identity["blob_object_key"],
            identity["occurrence_object_key"],
            identity["attestation_object_key"],
        ],
        "stale": {
            "request_body": stale_files["request.body"],
            "content_type": stale_scenario.content_type(),
            "attempt": json.loads(stale_files["attempt.json"]),
        },
    }


def verify_receipt(receipt: dict, authority_public_key: str,
                   expected_key_id: str, tenant: str,
                   authorization_key_id: str | None = None) -> bool:
    """Verify the signed receipt and its authority-certified receipt key."""
    certificate = receipt.get("certificate")
    if not isinstance(certificate, dict):
        return False
    if receipt.get("tenant_id") != tenant or certificate.get("tenant_id") != tenant:
        return False
    if (authorization_key_id is not None
            and receipt.get("authorization_key_id") != authorization_key_id):
        return False
    if receipt.get("receipt_version") != 1 or receipt.get("signature_algorithm") != "ed25519":
        return False
    public_key = certificate.get("public_key")
    try:
        public_bytes = bytes.fromhex(public_key) if isinstance(public_key, str) else b""
        authority_bytes = bytes.fromhex(authority_public_key)
    except (TypeError, ValueError):
        return False
    if len(public_bytes) != 32 or len(authority_bytes) != 32:
        return False
    key_id = hashlib.sha256(public_bytes).hexdigest()
    authority_key_id = hashlib.sha256(authority_bytes).hexdigest()
    if (key_id != expected_key_id or receipt.get("receipt_key_id") != expected_key_id
            or certificate.get("key_id") != expected_key_id
            or certificate.get("authority_key_id") != authority_key_id
            or certificate.get("key_algorithm") != "ed25519"):
        return False
    unsigned_certificate = {
        key: value for key, value in certificate.items() if key != "authority_signature"
    }
    if not cg.ed25519_verify(
        authority_public_key,
        certificate.get("authority_signature", ""),
        cg.canonical_bytes(unsigned_certificate),
    ):
        return False
    try:
        valid_from = datetime.datetime.fromisoformat(
            certificate["valid_from"].replace("Z", "+00:00")
        )
        valid_until = datetime.datetime.fromisoformat(
            certificate["valid_until"].replace("Z", "+00:00")
        )
        commit_time = datetime.datetime.fromisoformat(
            receipt["commit_time"].replace("Z", "+00:00")
        )
    except (KeyError, ValueError, TypeError):
        return False
    if not valid_from <= commit_time <= valid_until:
        return False
    unsigned_receipt = {key: value for key, value in receipt.items() if key != "signature"}
    return cg.ed25519_verify(
        public_key,
        receipt.get("signature", ""),
        cg.canonical_bytes(unsigned_receipt),
    )


def control_objects() -> dict[str, bytes]:
    """The linked-client pointer objects at their pinned object keys."""
    bundle = _read_json("control/epoch-progression.json")
    subjects = bundle["pinned"]["subjects"]
    records = [
        entry["record"]
        for entry in bundle["history"]
        if entry["record"].get("record_kind") == "current-pointer"
    ]
    by_client = {record["client_id"]: record for record in records}
    if CLIENT_A not in by_client:
        raise SystemExit("no current-pointer record for the linked client")
    pinned = {key for key, meta in subjects.items() if meta.get("key") is not None}
    objects: dict[str, bytes] = {}
    for record in records:
        client = record["client_id"]
        matches = [
            key
            for key, meta in subjects.items()
            if meta.get("client_id") == client
        ]
        if len(matches) != 1:
            raise SystemExit(f"bundle pins {len(matches)} object keys for one client")
        objects[matches[0]] = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode() + b"\n"
    if not pinned:
        raise SystemExit("bundle pins no subject keys")
    return objects


# ---------------------------------------------------------------------------
# `docker save` extraction handling. Docker's OCI layout writes the layers
# as opaque blobs (`blobs/sha256/<digest>`) with the stack in manifest.json;
# the legacy layout wrote one `<digest>.tar` per layer. Both must work: the
# base-image inventory and the deny scan are only honest when they see the
# layers the manifest actually stacks.
# ---------------------------------------------------------------------------


def _save_layers(layers_dir: pathlib.Path) -> tuple[list[pathlib.Path], pathlib.Path | None]:
    """The extraction's layer tars in stack order plus its config blob."""
    manifest = layers_dir / "manifest.json"
    if manifest.is_file():
        entry = json.loads(manifest.read_text())[0]
        layers = [layers_dir / path for path in entry.get("Layers", [])]
        config = layers_dir / entry["Config"] if entry.get("Config") else None
        return layers, config
    return sorted(layers_dir.glob("*.tar")), None


def _iter_layer_bytes(layers: list[pathlib.Path]):
    """Every regular file of every layer, in stack order, as
    (layer-file-name, member-path, bytes)."""
    for layer in layers:
        with tarfile.open(layer, "r:") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    yield layer.name, member.name, tar.extractfile(member).read()


def _final_inventory(layers: list[pathlib.Path]) -> set[str]:
    """The extraction's regular-file paths in their final state: layer
    order applied, OCI whiteouts honored (`.wh.<name>` removes one path,
    `.wh..wh..opq` empties the directory it sits in)."""
    state: set[str] = set()
    for layer in layers:
        with tarfile.open(layer, "r:") as tar:
            removals: list[str] = []
            opaques: list[str] = []
            additions: list[str] = []
            for member in tar.getmembers():
                base = posixpath.basename(member.name)
                parent = posixpath.dirname(member.name)
                if base == ".wh..wh..opq":
                    opaques.append(parent)
                elif base.startswith(".wh."):
                    removals.append(posixpath.join(parent, base[4:]))
                elif member.isfile():
                    additions.append(member.name)
            for prefix in opaques:
                state = {
                    path for path in state
                    if not path.startswith(prefix + "/")
                }
            state -= set(removals)
            state.update(additions)
    return state


# The generic deny patterns the byte scan adds to the run's own values: a
# credential document's field names and private-key PEM armor. They apply
# only to the files the image adds beyond its digest-pinned base and the
# installed binary: both of those legitimately carry the same vocabulary —
# the binary's own parsing and redaction constants (see BINARY_PATH), and
# the base's crypto libraries (gpgv, gnutls), whose PEM-armor strings are
# the same class. Base content is pinned by digest, so its bytes are a
# base-move decision, exactly as the vulnerability policy treats base
# findings; anything the build stages add is held to the full scan.
_GENERIC_PATTERNS = (
    b"ACCESS_KEY=",
    b"SECRET_KEY=",
    b"PRIVATE KEY",
)


def _denied(data: bytes, tokens: list[bytes]) -> bool:
    return any(token in data for token in tokens)


def mode_self_test(_args: argparse.Namespace) -> int:
    # RFC 8032 test vector 1 (empty message).
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    public = public_from_seed(seed)
    if public.hex() != (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ):
        raise SystemExit("RFC 8032 public derivation diverged")
    if sign(seed, b"").hex() != (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ):
        raise SystemExit("RFC 8032 signature diverged")
    if not cg.ed25519_verify(public.hex(), sign(seed, b"abc").hex(), b"abc"):
        raise SystemExit("corpus verifier rejects this signer")
    print("self-test: RFC 8032 vector and corpus verifier agree")

    # The golden baseline signature must reproduce bit-for-bit: the same
    # signing input, signed with the corpus uploader's derived seed.
    attempt = _read_json(f"conformance/scenarios/{GOLDEN_SCENARIO}/attempt.json")
    for name in ("uploader-origin-1", "uploader-relay-1", "uploader-origin-2"):
        candidate = conformance_signer(name)
        if candidate.key_id == attempt["uploader_key_id"]:
            message = cg.framing_bytes(
                "ingest-attempt-v1",
                [
                    cg.text(attempt["http_method"]),
                    cg.text(attempt["route"]),
                    cg.text(attempt["content_type"]),
                    cg.digest(attempt["request_content_digest"]),
                    cg.digest(attempt["envelope_digest"]),
                    cg.digest(attempt["payload_canonical_digest"]),
                    cg.digest(attempt["payload_transport_digest"]),
                    cg.digest(attempt["uploader_key_id"]),
                    cg.u63(attempt["authorization_epoch"]),
                    cg.text(attempt["authorization_timestamp"]),
                ],
            )
            if candidate.sign(message) != attempt["signature"]:
                raise SystemExit("golden signature does not reproduce")
            break
    else:
        raise SystemExit("golden uploader key not found among derived pairs")
    print("self-test: golden baseline signature reproduces bit-for-bit")

    # The control corpus's publics must match the derived pairs.
    keys = _read_json("control/keys.json")
    authority = control_signer("control-authority")
    uploader = control_signer("control-client-a")
    by_name = {entry["name"]: entry for entry in keys["keys"]}
    if by_name["control-authority"]["public_key"] != authority.public_key:
        raise SystemExit("derived authority key diverges from keys.json")
    if by_name["control-client-a"]["public_key"] != uploader.public_key:
        raise SystemExit("derived uploader key diverges from keys.json")
    print("self-test: control-corpus publics match the derived pairs")

    # Mint determinism: one fixed instant, two mints, byte-identical bodies.
    first = mint("2030-01-01T00:00:00Z")
    second = mint("2030-01-01T00:00:00Z")
    if first["request_body"] != second["request_body"]:
        raise SystemExit("mint is not deterministic at a fixed instant")
    if first["object_keys"] != second["object_keys"]:
        raise SystemExit("mint object keys are not deterministic")
    print("self-test: mint is deterministic at a fixed instant")

    seed = bytes(range(32))
    identity = {
        "client_id": "11111111-2222-4333-8444-555555555555",
        "private_seed": seed.hex(),
    }
    public = public_from_seed(seed).hex()
    link = {
        "client_id": identity["client_id"],
        "key_id": hashlib.sha256(bytes.fromhex(public)).hexdigest(),
        "public_key": public,
        "requested_tenant_id": TENANT,
        "requested_scopes": {"harnesses": ["codex"], "operations": ["ingest"]},
    }
    linked = mint_linked("2030-01-01T00:00:00Z", TENANT, link, identity)
    if not cg.ed25519_verify(
        public,
        linked["attempt"]["signature"],
        cg.framing_bytes(
            "ingest-attempt-v1",
            [
                cg.text(linked["attempt"]["http_method"]),
                cg.text(linked["attempt"]["route"]),
                cg.text(linked["attempt"]["content_type"]),
                cg.digest(linked["attempt"]["request_content_digest"]),
                cg.digest(linked["attempt"]["envelope_digest"]),
                cg.digest(linked["attempt"]["payload_canonical_digest"]),
                cg.digest(linked["attempt"]["payload_transport_digest"]),
                cg.digest(linked["attempt"]["uploader_key_id"]),
                cg.u63(linked["attempt"]["authorization_epoch"]),
                cg.text(linked["attempt"]["authorization_timestamp"]),
            ],
        ),
    ):
        raise SystemExit("fresh linked-client attempt does not self-verify")
    print("self-test: fresh protected identity signs the real link/upload path")

    receipt = _read_json(
        f"conformance/scenarios/{GOLDEN_SCENARIO}/receipt.json"
    )
    conformance_keys = _read_json("conformance/keys.json")["keys"]
    root = next(
        entry["public_key"]
        for entry in conformance_keys
        if entry["key_id"] == receipt["certificate"]["authority_key_id"]
    )
    if not verify_receipt(receipt, root, receipt["receipt_key_id"], receipt["tenant_id"]):
        raise SystemExit("receipt verifier rejected the committed golden receipt")
    print("self-test: receipt and authority-certified key verify independently")
    return 0


def mode_mint(args: argparse.Namespace) -> int:
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    fresh = mint(args.now)
    (out / "request.body").write_bytes(fresh["request_body"])
    (out / "content-type.txt").write_text(fresh["content_type"] + "\n")
    (out / "attempt.json").write_text(json.dumps(fresh["attempt"]) + "\n")
    (out / "object-keys.json").write_text(
        json.dumps(fresh["object_keys"], indent=2) + "\n"
    )
    # The stale golden attempt rides along for the reject lane: its covered
    # authorization instant is pinned years old by construction.
    stale = _scenario_dir(STALE_SCENARIO)
    stale_out = out / "stale"
    stale_out.mkdir(exist_ok=True)
    for name in ("request.body", "attempt.json"):
        (stale_out / name).write_bytes((stale / name).read_bytes())
    stale_attempt = _read_json(f"conformance/scenarios/{STALE_SCENARIO}/attempt.json")
    (stale_out / "content-type.txt").write_text(
        stale_attempt["content_type"] + "\n"
    )
    print(f"mint: fresh attempt and stale golden attempt written under {out}")
    print(f"mint: expected raw object keys: {len(fresh['object_keys'])}")
    return 0


def mode_mint_linked(args: argparse.Namespace) -> int:
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    link_request = json.loads(pathlib.Path(args.link_request).read_text())
    identity_document = json.loads(pathlib.Path(args.identity_file).read_text())
    fresh = mint_linked(args.now, args.tenant, link_request, identity_document)
    (out / "request.body").write_bytes(fresh["request_body"])
    (out / "content-type.txt").write_text(fresh["content_type"] + "\n")
    (out / "attempt.json").write_text(json.dumps(fresh["attempt"]) + "\n")
    (out / "object-keys.json").write_text(
        json.dumps(fresh["object_keys"], indent=2) + "\n"
    )
    stale_out = out / "stale"
    stale_out.mkdir(exist_ok=True)
    (stale_out / "request.body").write_bytes(fresh["stale"]["request_body"])
    (stale_out / "content-type.txt").write_text(
        fresh["stale"]["content_type"] + "\n"
    )
    (stale_out / "attempt.json").write_text(
        json.dumps(fresh["stale"]["attempt"]) + "\n"
    )
    print("mint-linked: fresh and stale attempts signed by the linked client")
    return 0


def mode_verify_receipt(args: argparse.Namespace) -> int:
    receipt = json.loads(pathlib.Path(args.receipt).read_text())
    if not verify_receipt(
        receipt,
        args.authority_key,
        args.key_id,
        args.tenant,
        args.authorization_key_id,
    ):
        raise SystemExit("receipt signature or authority certificate did not verify")
    print("verify-receipt: receipt signature, certificate, identity, and window verified")
    return 0


def mode_control_objects(args: argparse.Namespace) -> int:
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    objects = control_objects()
    for key, body in objects.items():
        path = out / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        print(f"control-object: {key}")
    return 0


def mode_base_inventory(args: argparse.Namespace) -> int:
    layers, _ = _save_layers(pathlib.Path(args.layers_dir))
    names = _final_inventory(layers)
    pathlib.Path(args.out).write_text(
        "".join(name + "\n" for name in sorted(names))
    )
    print(f"base-inventory: {len(names)} regular files in final state")
    return 0


def mode_scan_image(args: argparse.Namespace) -> int:
    layers_dir = pathlib.Path(args.layers_dir)
    deny_tokens = [
        line.strip().encode()
        for line in pathlib.Path(args.deny).read_text().splitlines()
        if line.strip()
    ]
    if not deny_tokens:
        raise SystemExit("deny-token file is empty")

    base_files = set()
    if args.base_files:
        base_files = set(pathlib.Path(args.base_files).read_text().splitlines())

    layers, config = _save_layers(layers_dir)
    inventory = _final_inventory(layers)

    scanned = 0
    hits: list[str] = []
    for layer_name, name, data in _iter_layer_bytes(layers):
        scanned += len(data)
        tokens = deny_tokens
        if name != BINARY_PATH and name not in base_files:
            tokens = tokens + list(_GENERIC_PATTERNS)
        if _denied(data, tokens):
            hits.append(f"{layer_name}:{name}")
    if config is not None:
        # The image config carries the environment and the build history —
        # the one place a credential can hide without ever being a file.
        data = config.read_bytes()
        scanned += len(data)
        if _denied(data, deny_tokens + list(_GENERIC_PATTERNS)):
            hits.append(f"{config.name} (image config)")

    unexpected = sorted(
        path
        for path in inventory
        if base_files and path not in base_files and path != BINARY_PATH
    )
    print(f"scan-image: {len(inventory)} regular files in final state")
    print(f"scan-image: {scanned} layer bytes scanned (config blob included)")
    if hits:
        for hit in sorted(set(hits)):
            print(f"scan-image: DENY-MATCH {hit}")
        return 1
    print("scan-image: no denied material in any layer or the config")
    if unexpected:
        for path in unexpected:
            print(f"scan-image: UNEXPECTED-FILE {path}")
        return 1
    print("scan-image: final inventory matches the base image plus the one binary")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)

    sub.add_parser("self-test", help="prove the signer and the mint path")

    mint_parser = sub.add_parser("mint", help="write the fresh and stale attempts")
    mint_parser.add_argument("--out", required=True)
    mint_parser.add_argument(
        "--now",
        default=datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        help="the fresh attempt's authorization instant (RFC 3339, Z)",
    )

    linked_parser = sub.add_parser(
        "mint-linked", help="sign attempts with a protected CLI-created identity"
    )
    linked_parser.add_argument("--out", required=True)
    linked_parser.add_argument("--tenant", required=True)
    linked_parser.add_argument("--link-request", required=True)
    linked_parser.add_argument("--identity-file", required=True)
    linked_parser.add_argument(
        "--now",
        default=datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    )

    verify_parser = sub.add_parser(
        "verify-receipt", help="verify a returned receipt against its pinned root"
    )
    verify_parser.add_argument("--receipt", required=True)
    verify_parser.add_argument("--authority-key", required=True)
    verify_parser.add_argument("--key-id", required=True)
    verify_parser.add_argument("--tenant", required=True)
    verify_parser.add_argument("--authorization-key-id", required=True)

    control_parser = sub.add_parser(
        "control-objects", help="write the linked-client pointers at their keys"
    )
    control_parser.add_argument("--out", required=True)

    inventory_parser = sub.add_parser(
        "base-inventory", help="final-state file inventory of a docker save extraction"
    )
    inventory_parser.add_argument("--layers-dir", required=True)
    inventory_parser.add_argument("--out", required=True)

    scan_parser = sub.add_parser(
        "scan-image", help="secret smoke over a docker save extraction"
    )
    scan_parser.add_argument("--layers-dir", required=True)
    scan_parser.add_argument("--deny", required=True)
    scan_parser.add_argument(
        "--base-files",
        help="sorted base-image file list; layer inventory diffs against it",
    )

    args = parser.parse_args(argv)
    if args.mode == "self-test":
        return mode_self_test(args)
    if args.mode == "mint":
        return mode_mint(args)
    if args.mode == "mint-linked":
        return mode_mint_linked(args)
    if args.mode == "verify-receipt":
        return mode_verify_receipt(args)
    if args.mode == "control-objects":
        return mode_control_objects(args)
    if args.mode == "base-inventory":
        return mode_base_inventory(args)
    return mode_scan_image(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
