# The exact-inference artifact schema and example corpus

Authority: the implementation plan, Section 8 Phase 9 (exact inference
and orchestrator correlation) with its capture-boundary and
correlation-identity rules, Section 7.1 (this family's own version
axis), and Section 11 (provider credentials must never become archive
metadata); requirement CAP-008 (exact capture is a capability separate
from harness-semantic capture, joined by explicit trace/request IDs);
threat model Section 11's credential-leak routes. The schema is
[`schemas/v1/inference-artifact.json`](../../schemas/v1/inference-artifact.json);
it shares the v1 wire vocabulary pinned in
[`schemas/v1/common.json`](../../schemas/v1/common.json). The committed
golden bundle is
[`schemas/v1/examples/inference/`](../../schemas/v1/examples/inference/),
generated and verified by
[`tools/inferencegen.py`](../../tools/inferencegen.py) — the same
generator/verifier/bundle shape as the conformance corpus
([`conformance-corpus.md`](conformance-corpus.md)). Schema definition:
bead `aa-b5cf6541`; corpus gating and the schema's kind-exclusion
repair: bead `aa-157a400d`.

## The one record and the six kinds

One schema, one record shape, six `artifact_kind` values — one artifact
per observed provider-boundary event, in the plan's order:

| Kind | Carries | Kind-gated required members |
|---|---|---|
| `provider-request` | one decoded HTTP request body | `payload` |
| `provider-response` | one decoded HTTP response body | `payload` |
| `streaming-event` | one ordered decoded event of a streamed attempt | `event_ordinal`, `payload` |
| `retry` | that a further transport attempt was started, and why | `retry_of_attempt_ordinal`, `retry_reason` |
| `usage` | the bounded usage counters extracted from a response body or stream event | `metadata` with the three usage counters, `usage_source` |
| `transport-error` | a failure that produced no decodable response | `error_class` |

Every kind-gated member is **absent — never null — on the other kinds**
(enforced per member, not per group: a `provider-response` carrying
`error_class` alone is rejected, as is a `provider-request` carrying
`backoff_ms`). Correlation members are shared by every kind:
`trace_id`, `inference_request_id`, and `provider_attempt_id` (all
UUIDv7), plus the zero-based dense `attempt_ordinal` that reconstructs
retry order even when UUIDv7 clocks are unreadable. `tenant_id` and
`origin_client_id` name the archive partition and the capturing
installation; `capture_time` is optional and omitted — never null —
when the boundary cannot clock the event.

## Boundaries the schema enforces mechanically

1. **The capture boundary.** Payload bytes are captured at the
   proxy/SDK hook boundary *after HTTP transfer decoding*: the
   transferred content, never TLS/TCP framing, never transfer-encoding
   framing. A failure below the decoded-content boundary is a
   `transport-error` record carrying a closed `error_class`
   (`connect`, `dns`, `tls-handshake`, `read-timeout`,
   `write-timeout`, `connection-reset`, `stream-interrupted`,
   `transfer-decode`, `other`) — never framing bytes. No free-text
   detail member exists: error strings are a known credential-leak
   route, and a v2 with an explicit scrubbing rule is the only path to
   detail.
2. **The closed `metadata` allowlist.** Every field the HTTP boundary
   exposed travels only inside `metadata`, whose allowlist is closed
   (`additionalProperties: false`): content type, provider request ID,
   HTTP status, the three rate-limit numbers, and the three usage
   counters — nine entries, and growth is a new schema major, never an
   additive v1 field. Unlisted names are rejected outright, innocuous
   ones included, so header material cannot drift into archive
   metadata.
3. **The reserved list.** Forty-three names — authorization and its
   epochs and key ids, cookies, API and bearer and session tokens,
   certificates and cipher and TLS material, TCP framing, and storage
   locations (`blob_key`, `object_key`, `url`, `uri`, `upload_url`,
   `storage_path`) — are rejected at the top level by a `not`/`anyOf`
   block. Content is referenced by digest only; no member of the
   record names where anything is stored.
4. **The blob-identity rule.** The payload digest is the plain
   label-less SHA-256 of the captured bytes and *nothing else*: no
   correlation identifier is an input to any digest or storage key
   (CAP-008's "joined without putting any of them in the blob
   identity"). Identical bytes deduplicate to one stored blob, and the
   correlation triple stays in record members where it is queryable
   and never amputates deduplication.

## The example corpus

Thirteen committed files: twelve artifact records across three
scenarios plus a `manifest.json` naming each file's kind, correlation
ids, and SHA-256. Every identifier, timestamp, and payload byte is a
pinned synthetic constant (SEC-010); payloads say `synthetic` in so
many words, and no real session, host, provider, or transcript appears.

| Scenario | Files | What it pins |
|---|---|---|
| `single-attempt/` | request, response, usage | the reference attempt: one request, one 200 response with provider-request-id, rate-limit, and usage metadata, and a usage record extracted from the response body (`usage_source: response-body`) |
| `retried-attempt/` | 429 response, retry, transport-error, retry, retried request, 200 response | a three-attempt chain: attempt ordinals 0→1→2, each `retry` citing `retry_of_attempt_ordinal` strictly below its own ordinal and a closed `retry_reason` (`rate-limit`, `transport-error`) with observed `backoff_ms`; the retried request reuses the first attempt's exact bytes, so one identical payload digest appears in two attempts |
| `streamed-attempt/` | events 0–2, usage | dense `event_ordinal`s 0..2 whose event bytes concatenate byte-for-byte to the attempt's decoded body, and a usage record extracted from the terminal event (`usage_source: stream-event`) whose `payload_digest` names that event's own digest |

The reconstruction invariants are recomputed from the pinned bytes at
verify time, not asserted in prose: stream events rebuild the body,
retry chains order strictly, usage counters match the reporting bytes
and satisfy the producer invariant `total = input + output` as
reported.

## Determinism contract

There is no entropy source. Identifiers are fixed UUID-shaped
constants, timestamps are six pinned RFC 3339 instants, and payload
bytes are five pinned byte strings (`REQUEST_BODY`, `RESPONSE_BODY`,
`RATE_LIMIT_BODY`, and three stream events) — regeneration on any
machine produces byte-identical files, which is what makes byte-exact
regeneration a gate rather than a hope. Records are RFC 8785-style
canonical JSON plus one trailing LF, sorted keys, no floats, no
whitespace variance; `--verify` re-checks canonical formatting on
every committed file independently of the byte comparison, so a
hand-edited file fails even if a generator bug masked the drift.

`tools/inferencegen.py --verify` proves the family's acceptance, not
just its bytes:

1. regenerates the bundle and byte-compares every file, failing on
   drift in either direction (unexpected files included);
2. re-validates every committed record against the schema, with
   `common.json` resolved through the URN registry;
3. injects the reserved-name matrix one name at a time against a valid
   control of each kind and requires rejection — including
   kind-gated members on the wrong kind (`error_class` on a response,
   `backoff_ms` on a request), which pin the per-member exclusion
   clauses;
4. proves the `metadata` closure with representative unlisted names
   (credential-shaped and innocuous alike);
5. runs the per-kind negative matrix (missing kind-gated members,
   unknown enum values, empty payload sizes, orphan retry citations);
6. recomputes the ordering and reconstruction invariants from the
   pinned bytes.

It needs only `jsonschema` + `referencing` (preflighted with
`require_modules` in the gate, like the conformance and compat
corpora) and runs offline in seconds.

## Where this connects

- [`conformance-corpus.md`](conformance-corpus.md) — the ingest-side
  corpus this corpus's generator/bundle shape is modeled on.
- The expected-inference ledger (plan Phase 9, bead `aa-e8816fd4`) —
  the downstream consumer that freezes expectations and reconciles
  coverage against artifacts carrying this schema's correlation
  triple.
- The usage-summary family (plan Phase 10, beads `aa-09b76e5b` /
  `aa-c7e22ead`) — the derived token-accounting record that stays a
  separate denominator from this family's provider-observed counts;
  its note lands with that family's commit (decision recorded on
  `aa-c7e22ead`).
- Registration: the corpus gate is the `T-CAP-008` verification
  (`tools/verification-register.json`, fast lane).
