# Ingest wire schemas

Authority: the implementation plan, Sections 7.1 (version axes), 7.2 (wire
request and authentication), 7.3 (envelope fields), 7.4 (identifier and
collision rules), 7.5 (object keys), 7.6 (canonical payload and limits),
7.7 (storage outcomes), and 7.8 (receipts, errors, retries); requirements
VAL-001/VAL-002/VAL-004/VAL-007, ID-002/ID-006–ID-009, RCPT-001–RCPT-006,
and ERR-001–ERR-038; threats IA-02, PI-01/PI-02/PI-03/PI-05/PI-07, and
SEC-004/SEC-006. The family is:

| File | Role |
|---|---|
| [`schemas/v1/common.json`](../../schemas/v1/common.json) | Shared v1 wire vocabulary: identifier grammars, digests, the closed enum sets, the object-key patterns. One vocabulary per version directory — the raw provenance family uses the same file. |
| [`schemas/v1/ingest-envelope.json`](../../schemas/v1/ingest-envelope.json) | The canonical, client-frozen envelope (part one of the multipart request). |
| [`schemas/v1/ingest-request.json`](../../schemas/v1/ingest-request.json) | Wire framing constants and the per-attempt signature-parameter record. |
| [`schemas/v1/ingest-identifiers.json`](../../schemas/v1/ingest-identifiers.json) | The construction registry: byte-exact derivations, object-key assembly, and the three signing constructions. Normative for this family and the raw provenance family. |
| [`schemas/v1/ingest-error.json`](../../schemas/v1/ingest-error.json) | The stable error body every producer emits (`archivist.error/v1`). |
| [`schemas/v1/ingest-receipt.json`](../../schemas/v1/ingest-receipt.json) | The authenticated receipt and the embedded receipt-key certificate. |

Three further v1 schemas live in the same directory, each owned elsewhere
and appearing here only because this gate's generic rules (draft, `$id`,
ref resolution, enum bearings, no floats) scan every file under
`schemas/v1/`:
[`schemas/v1/cli-output.json`](../../schemas/v1/cli-output.json), the
`archivist.cli-output/v1` CLI output envelope, owned by the
[CLI command conventions](cli.md) and their gate; and the two control
trust family files,
[`schemas/v1/control-envelope.json`](../../schemas/v1/control-envelope.json)
and
[`schemas/v1/control-client.json`](../../schemas/v1/control-client.json),
the `archivist.control/v1` record envelope and linked-client record, owned
by the [control trust schemas](control-trust-schemas.md) and their gate.

## Version axes and fail-closed behavior

Each record carries its own axis (plan Section 7.1): `protocol_version` and
`envelope_version` on the envelope, `receipt_version` on the receipt,
`certificate_version` on the certificate, plus the closed enum sets in
`common.json`. The compatibility rules are uniform:

- An unknown **major** on any axis fails closed — `const` pins the known
  value, so anything else is a validation error, never a best-effort parse.
- An unknown **security- or identity-bearing enum value** fails closed:
  `storage_profile`, `transport_encoding`, `checksum_algorithm`,
  `signature_algorithm`, `key_algorithm`, `artifact_kind`, `range_kind`,
  `id_source`, `storage-outcome`, `delegation`. Every one carries
  `x-archivist.bearing` and `failClosed: true`; the gate
  (`tools/check-wire-schemas.py`) rejects a closed enum without them.
- Within a major, new **optional** fields are additive; old readers retain
  them inside signed bytes and ignore their semantics (the envelope,
  receipt, and certificate use `unknownFields: retain-ignore` for exactly
  this reason). New required fields, redefined fields, or changed identity
  rules require a new major.
- The **error body** and the **signature-parameter record** are closed
  shapes (`additionalProperties: false`): they are per-response and
  per-attempt state, not retained signed material, so there is nothing to
  carry forward and an open shape would only widen the disclosure surface
  (ERR-003, ERR-033).
- No protocol structure contains a floating-point value anywhere; every
  numeric shape is the `u63` integer (or a bounded epoch ≥ 1).

## The envelope and the wire request

`POST /v1/ingest` is `multipart/related`: part one is the canonical
envelope (`application/vnd.agent-archivist.envelope+json;version=1`, RFC
8785 canonical JSON, at most 65,536 canonical bytes, no floats); part two
is the payload in the encoding the envelope declares
(`application/octet-stream` or `application/zstd`), streamed, never
base64-embedded. The media-type `version` parameter tracks
`envelope_version`, so a future major is rejected at framing time by an
old server.

The envelope is **frozen per request**: it excludes server commit time, the
per-attempt authorization epoch/key/timestamp, the per-attempt signature,
and any server attempt correlation — those names are rejected outright by
the `not` block, mirroring the occurrence manifest and upload attestation.
That exclusion is what makes the retry contract work: a retry outside the
five-minute authorization window re-authorizes (fresh epoch-bound timestamp
and `ingest-attempt-v1` signature) while the envelope, occurrence, and
attestation bytes — and therefore their identities — stay identical.

Each attempt's Ed25519 signature covers method, route, content type,
whole-request content digest, canonical envelope digest, both payload
digests (canonical and as-transported), uploader key ID, authorization
epoch, and the fresh authorization timestamp, in the pinned order and
encoding of `ingest-identifiers.json`. The server may pre-authorize the
key ID before the body arrives but commits nothing until the complete
signature and payload verify.

## Identity, keys, and the construction registry

No derived value is transmitted as a black box: the envelope carries the
*inputs* (tenant, origin, harness, opaque upstream session ID, artifact
tuple, generation, range, digest) plus the two derived IDs the plan names
(`occurrence_id`, `attestation_id`), and `ingest-identifiers.json` pins how
every derivation is computed — a UTF-8 domain label, one `0x00` delimiter,
then each field as an 8-byte unsigned big-endian length followed by
exactly that many field bytes, with the field kinds (`text`, `u63`,
`digest`, `bytes`) fixed per input. The blob digest is the one label-less
construction: plain SHA-256 over the canonical uncompressed bytes.
Object keys are assembled only from validated tenant UUIDs, the pinned
profile, and computed digests (ID-008); raw upstream identifiers and
hostnames never become key components, and opaque identifiers are neither
case-folded nor Unicode-normalized (at most 1,024 bytes, with
`x-archivist.byteMaxLength` the normative bound over the codepoint
`maxLength`).

## Where the Section 7.6 limits live

The wire schemas deliberately do **not** encode the operational limits as
field maxima. They are enforced where the bytes are actually seen, and the
schema bounds are the structural ones (identifier lengths, digest widths,
the 64 KiB canonical envelope, the no-float integer discipline):

| Limit | v1 value | Enforced by |
|---|---:|---|
| Target canonical chunk | 16 MiB | adapter chunking on record boundaries (policy) |
| Single structured record | 256 MiB | server + adapter; over ⇒ `record_too_large` quarantine, never truncation |
| Envelope | 64 KiB | `ingest-envelope.json` `canonicalMaxBytes` (schema) |
| Expansion ratio | 100:1 | server decode guard (VAL-003) |
| Request duration | 15 min | server request timeout (monotonic clock) |
| Multipart part | 8 MiB | transport framing (policy) |
| In-flight uploads (process / per client) | 16 / 4 | server admission control |
| New request rate | 60/min/client/replica, burst 8 | server rate limiter (`request.rate_limited`) |

Lowering a limit is a policy change; raising one re-runs the Section 7.6
resource/fuzz suite on the same commit. Declared sizes in the envelope
(`compressed_size`, `uncompressed_size`) are always checked against the
bytes the decoder actually produces — the declaration is evidence, not
authority.

## Errors

Every error — server HTTP response, client daemon/CLI diagnostic, adapter
failure, verification tooling — is one closed six-field body:
`schema` (const `archivist.error/v1`), `code`, `retryable`, `message`,
`request_id` (null exactly when no envelope could be parsed, ERR-027), and
`correlation_id`. `retryable` is authoritative on the wire (ERR-004); the
code vocabulary, class taxonomy, and HTTP mapping live in
`tools/error-codes.toml` behind `tools/check-error-codes.py`, and the
schema pins only the body those codes travel in. Codes are append-only
within v1: a well-formed but unregistered code still parses, and its
`retryable` boolean governs (ERR-037) — this is why the code field is
pattern-bounded rather than closed to the registry. The `message` is
rendered printable ASCII without braces, at most 200 characters, advisory
only, and can never carry transcript, path, provider, or identifier
content (VAL-007, SEC-004).

## Receipts

A receipt exists only for a complete commit — blob, occurrence manifest,
and upload attestation all durable (RCPT-001). Any partial commit returns
503 with an error body and **no receipt**; the next identical attempt
repairs the same occurrence and attestation (RCPT-005). Poison input
reports through the error matrix and never produces a receipt.

The receipt binds tenant, request, occurrence, attestation, blob digest,
the three server-derived object keys, three per-object storage outcomes,
the successful authorization key and epoch, and the UTC commit time
(RCPT-002). Per-attempt and server material lives here and *only* here.
Outcomes use the closed `storage-outcome` enum and report exactly what the
backend can establish — `already_present` requires readable compatible
metadata; a writer-only overwrite profile reports
`logically_committed_unknown_physical_result` rather than claiming
deduplication it cannot prove (RCPT-003, RCPT-004).

Authentication is a two-link chain an offline client can walk without
trusting the server transport (RCPT-006, ID-009): the tenant authority
root pinned at linking signs the receipt-key certificate
(`receipt-key-v1` over the certificate minus its `authority_signature`
member), and the certificate's key signs the receipt (`receipt-v1` over
the receipt minus its `signature` member). The certificate is embedded by
value — key ID, public key, algorithm, tenant, signing window, authority
key ID and signature — and also stored durably under
`tenants/<tenant>/v1/control/receipt-keys/<key-id>.json`, where the
control trust family's receipt-key record
(`schemas/v1/control-receipt-key.json`) is the authoritative source of
the certification: its payload members are the certificate's members,
proven member-for-member by that family's gate. Keys rotate every 30
days with a seven-day signing overlap (the control envelope's
`receiptKeyRotationDays` and `receiptKeySigningOverlapDays` named
constants, pinned here under the same names); verification of retained
receipts never expires, so rotation cannot invalidate old evidence
(ID-009). The private half reaches the server only through a secret
reference (SEC-006); only the public half ever appears in a record.

The client acknowledges — cursor advance and spool release — only after
the chain verifies, the signature verifies, and **every identity field**
matches its frozen spool entry, including re-deriving each object key from
the bound identifiers (CAP-006). Retryable transport uses full jitter from
one second doubling to a 15-minute cap with no arbitrary attempt limit;
success resets the backoff.

## Verification

`tools/check-wire-schemas.py` (fast lane of
`scripts/definition-of-done.sh`) proves the family's internal coherence:
schema validity, `$id`/`$ref` resolution across the URN space, the
reserved-name `not` blocks, `failClosed` metadata on every closed enum,
required-field presence in the derivation sources, and the receipt's
signature-member names agreeing with `ingest-identifiers.json`; its
`--self-test` proves the rejection paths. Golden request/signature/ID
vectors arrive with the language-neutral conformance corpus and the
old-reader/new-writer compatibility fixtures (plan Section 7.1), which are
separately tracked work.

## Open questions

- The certificate's authority-rotation story is deliberately minimal:
  `authority_key_id` names the signer and the client pins the root. The
  control trust family has consumed this certificate definition rather
  than duplicating it — its receipt-key record's payload members are the
  certificate's members, proven member-for-member by
  `tools/check-control-schemas.py` (see
  [control trust schemas](control-trust-schemas.md)) — but the
  authority-rotation record itself remains that family's open item.
- `media_type` placeholders in error templates are bounded tokens; if a
  future code needs to name a header or boundary value, the placeholder
  allowlist in `docs/notes/error-codes.md` Section 4 must grow first —
  that is an ERR-034 change, not a schema edit.
