# The language-neutral conformance corpus

Authority: the implementation plan, Section 8 Phase 1 ("a small
language-neutral conformance corpus containing expected signatures,
digests, and object keys") and Section 7.2's enforcement list ("golden
requests, a standalone signature verifier, reordered/whitespace JSON
cases, altered multipart cases, and retry-after-window tests"); bead
`aa-cfc9f227`. Requirements VAL-002, ID-005–ID-009, RCPT-003/RCPT-004/
RCPT-006, EC-03/EC-05A, STO-002/STO-004/STO-013, IA-02, PI-01, PI-05.

The corpus is a committed, byte-pinned bundle of complete ingest
attempts — envelope, payload, exact multipart body, per-attempt
signature parameters, and the expected receipt or error body — plus the
pure derivation and canonicalization tables behind them. Any
implementation, in any language, replays the corpus offline with only
the public keys in `keys.json`: recompute the identities, re-frame the
Ed25519 messages, verify the signatures, and walk the receipt chains.
The Rust implementation's exit-gate cross-check
(plan Section 8 Phase 1) consumes exactly this bundle.

| File | Role |
|---|---|
| [`tools/conformancegen.py`](../../tools/conformancegen.py) | The deterministic generator and verifier (`--generate`, `--verify`, `--self-test`). |
| [`schemas/v1/examples/conformance/`](../../schemas/v1/examples/conformance/) | The committed bundle — 80 files, 15 scenarios. |
| [`schemas/v1/examples/provenance/`](../../schemas/v1/examples/provenance/) | The sibling raw-provenance corpus; the two share `common.json` and their synthetic tenant/origin/session constants for one coherent deployment story. |

## What the corpus pins

1. **Golden signatures.** Every scenario carries an `attempt.json`
   (valid against `schemas/v1/ingest-request.json`) and its
   `signing.attempt_input_hex` — the exact Ed25519 message under the
   `ingest-attempt-v1` framing. Valid scenarios additionally carry a
   golden `receipt.json` whose certificate is signed by the pinned
   tenant authority root (`receipt-key-v1`) and whose body is signed by
   the certificate key (`receipt-v1`); the digest of each signed byte
   string is pinned as `*signed_bytes_sha256` so an implementation can
   locate its divergence without guessing.
2. **Canonical digests.** `envelope_digest` (canonical envelope bytes),
   `request_content_digest` (the whole multipart body), and the payload
   digests (canonical and as-transported; equal under identity
   transport) appear both per scenario and as recomputable vectors in
   `canonicalization.json`.
3. **Identifier hashes and object keys.** `derivations.json` walks every
   identity construction (`session-v1`, `artifact-v1`, `occurrence-v1`,
   `attestation-v1`, and the label-less blob digest) from raw inputs to
   hashes to the three object keys, with full pre-image bytes for one
   golden case per construction.
4. **Receipt chains.** Two tenants, three receipt keys, two commit
   cohorts (2026-09-11 and 2026-09-22) inside overlapping 37-day
   windows (30-day rotation, 7-day signing overlap) — rotation never
   invalidates retained receipts (ID-009).
5. **Retry examples.** The frozen-envelope pair
   (`valid-direct-baseline` → `valid-retry-after-window`) re-authorizes
   after the 300-second window across an epoch rotation with identical
   identity fields and `already_present` outcomes, and
   `invalid-stale-authorization` shows the same envelope rejected when
   the proof is twenty minutes old — far outside the window even with
   the full 300-second skew allowance.

## Scenario map

| Scenario | Kind | Covers |
|---|---|---|
| `valid-direct-baseline` | valid | the reference direct upload; `created` × 3 |
| `valid-retry-after-window` | valid | frozen envelope re-authorized after the window; epoch 1 → 2; `already_present` × 3 |
| `valid-unicode-session` | valid | arbitrary-Unicode session and artifact IDs; literal UTF-8 in canonical bytes |
| `valid-synthetic-session-id` | valid | adapter-minted UUIDv4 stand-in (`id_source: synthetic`); event range; `source_time` omitted |
| `valid-relay-upload` | valid | relay presents the origin's occurrence under its own key: shared blob/occurrence, own attestation |
| `valid-reordered-envelope-framing` | valid | envelope part transmitted non-canonically; every identity unchanged |
| `valid-cross-tenant-second` | valid | identical inputs under tenant two: distinct namespace, shared blob digest |
| `invalid-stale-authorization` | invalid | 401 `auth.authorization_rejected` |
| `invalid-reserved-field` | invalid | envelope freezes `commit_time` → 400 `envelope.schema_invalid` |
| `invalid-unknown-enum-value` | invalid | `transport_encoding: "gzip"` fails closed → 400 |
| `invalid-occurrence-id-mismatch` | invalid | declared ID ≠ re-derived → 400 |
| `invalid-integrity-conflict` | invalid | incompatible object at the derived key → 409, no receipt |
| `invalid-altered-payload-byte` | invalid | one payload byte flipped after signing → 401 |
| `invalid-altered-framing-boundary` | invalid | boundary swapped after signing → 401 |
| `invalid-cross-tenant-forbidden` | invalid | tenant-two envelope under a tenant-one key → 403 |

Golden error bodies carry the closed six-field `archivist.error/v1`
shape and are checked against `tools/error-codes.toml` — code, class,
HTTP status, and retryability must agree with the registry.

## Conventions the corpus relies on

- **Canonical JSON** is RFC 8785 over the protocol's value domain
  (ASCII member names, integers, strings, arrays, booleans, null — no
  floats). Bundle *metadata* files are canonical bytes plus one
  trailing LF; the scenario *envelope part* is bare canonical bytes
  with **no** trailing LF, except `valid-reordered-envelope-framing`,
  which is deliberately reverse-sorted and indented and is flagged
  `envelope_wire_canonical: false` in the manifest.
- **Multipart framing** is pinned exactly: `--<boundary>` CRLF,
  lowercase `content-type` header, CRLF, part bytes, CRLF, closing
  `--<boundary>--` CRLF, with boundaries like
  `archivist-conformance-01`. The covered `content_type` is
  `multipart/related; boundary=<boundary>`.
- **Identity transport only.** v1 vectors declare
  `transport_encoding: identity` because a golden zstd transport digest
  would pin one compressor build and stop being language-neutral; the
  canonical/transport digest equality and the schema's
  `compressed_size == uncompressed_size` rule both encode that.
- **No normalization.** Composed and decomposed Unicode forms of one
  visible session string are distinct sessions with distinct hashes and
  keys (`derivations.json` cases `unicode-nfc`/`unicode-nfd`); opaque
  identifiers are never case-folded or normalized.

## Determinism and content safety

There is no entropy source. Identifiers, timestamps, payload bytes, and
boundaries are pinned constants; every Ed25519 key pair is derived at
generation time as SHA-256 of a label string, so RFC 8032's
deterministic signing makes regeneration byte-identical on any machine
(proven by `--generate` into a scratch directory plus `diff -r`, and by
`--verify`'s byte comparison). Private halves exist only in generator
memory; `--verify` asserts no seed material appears anywhere in the
bundle. Every identifier, key, and payload byte is pinned synthetic
data from a closed vocabulary (SEC-010) — nothing is copied from any
real harness store, and the keys authorize nothing real.

## Verification model

Signing uses the installed `cryptography` wheel, but **no signature in
the bundle is trusted on the word of its signer**: `tools/
conformancegen.py` carries an independent pure-Python RFC 8032 Ed25519
verifier that shares no code with the signing path, and `--verify`
re-checks every attempt signature, certificate authority signature, and
receipt signature with it — plus bit-flip rejection cases proving the
verifier is not vacuously accepting. `--verify` additionally:
regenerates and byte-compares every file; validates every
schema-conformant instance against its schema (with `common.json`
resolved through the URN registry); re-derives every identity from the
vectors' own inputs; checks the golden error bodies against the error
registry; and re-proves the cross-scenario invariants (retry identity
equality, relay occurrence sharing, cross-tenant separation around a
shared blob digest, NFC ≠ NFD, the conflict object's key equality and
byte divergence). `--self-test` proves the rejection paths in memory:
tampered signatures, wrong keys, non-canonicalizable values, and
reserved/unknown-enum envelopes failing the shipped schema.

An independent standalone verifier (Rust or otherwise) should consume
the bundle the same way: start from `keys.json`, re-frame from
`attempt.json` fields per `ingest-identifiers.json`, compare against
`signing.attempt_input_sha256`, verify the Ed25519 signature, then walk
the receipt chain and the manifest's `asserts`.

## Where this connects

- [`wire-schemas.md`](wire-schemas.md) — the wire family this corpus
  exercises; its Verification section points here.
- [`error-codes.md`](error-codes.md) — the code registry the golden
  error bodies are checked against.
- [`fixtures.md`](fixtures.md) — the sibling byte-exact synthetic
  fixture bundle and its content scan.
- The Phase 1 exit gate: the Rust implementation and this corpus (via a
  standalone verifier that does not import the protocol crate) must
  produce identical signatures, IDs, and keys.

## Open questions

- A zstd transport corpus would need a compressor-build-independent
  frame pin (for example, a stored-block-only synthetic frame); if v1.1
  adds `transport_encoding: zstd` golden vectors, that framing decision
  lands here first.
- The corpus pins one relay topology (origin → relay → server). A
  multi-hop delegation vector would exercise the `delegation` enum the
  wire family already reserves; it waits on that enum growing a second
  value.
