# Exact-capture and provider-boundary threats

Status: one of six domain documents feeding the Phase 1 threat model · Last
updated: 2026-09-21

Authority: the [implementation plan](../../plan/plan.md), especially Phase 9
("Exact inference and orchestrator correlation"), Section 11 (centralized
provider-data risk), and Section 12 (content-free operational signals); the
normative [requirements](../../notes/requirements.md), especially CAP-007 and
CAP-008; the exact artifact contract in
[`schemas/v1/inference-artifact.json`](../../../schemas/v1/inference-artifact.json)
and its [schema note](../../notes/exact-inference-schemas.md); and the
committed [exact-artifact corpus](../../../schemas/v1/examples/inference/)
verified by [`tools/inferencegen.py`](../../../tools/inferencegen.py). This
document models the security consequences of Phase 9 before the proxy and SDK
hook exist. It introduces no capture route, provider compatibility claim, or
new credential-handling contract.

## Scope

In scope: centralizing provider request and response bodies, decoded response
headers, rate-limit and usage observations, provider error bodies, proxy and
SDK-hook route qualification, the content-free expected-inference ledger,
ordered streaming events, retry transitions, correlation identifiers, and
flush-before-teardown for ephemeral work. The attacker may be a malicious
provider endpoint, a compromised or misconfigured capture route, a caller
trying to make an unsupported SDK look supported, a forged ledger producer, a
buggy stream/retry state machine, or a teardown path that drops pending
artifacts.

The threat boundary is the explicit proxy or supported SDK hook **after HTTP
transfer decoding**. Exact capture does not include TLS/TCP framing or
transfer-encoding framing. A route that is not explicitly instrumented is not
an exact observation: it remains semantic-only or `unobserved`, as the
evidence permits.

Out of scope here, owned elsewhere:

- Provider-side confidentiality, correctness, or authenticity beyond what the
  route actually observed. An archived provider response is evidence of an
  observed exchange, not a provider signature or an authorization decision.
- Harness-semantic capture and source-generation integrity, which remain in the
  adapter and payload domains. Exact artifacts and semantic transcripts are
  separate coverage dimensions and must not repair one another's gaps.
- General network perimeter protection and S3 commit authorization, covered by
  the identity, payload, and receipt domains. Exact artifacts use the normal
  authenticated spool and ingest path.

## Contract basis

The findings below rely on these plan-fixed controls:

- **Explicit route qualification.** Version 1 supports only traffic explicitly
  routed through the Archivist proxy or a supported SDK hook. Ambient tracing,
  package-name detection, an orchestrator log, or the absence of a proxy log is
  not proof of observation. The first qualified hook is the versioned
  `InferenceObserver` lifecycle around the actual first-party Rust transport.
- **Decoded boundary and closed artifact shape.** `provider-request`,
  `provider-response`, and `streaming-event` payloads are the decoded bytes;
  `retry`, `usage`, and `transport-error` carry their closed kind-specific
  evidence. A transfer or stream failure is a closed error class, never raw
  framing or a free-text transport error.
- **Header minimization.** `metadata` is a closed nine-entry allowlist for
  content type, provider request ID, HTTP status, rate-limit values, and usage
  counters. The schema's reserved names reject authorization, cookies, API and
  bearer tokens, provider credentials, TLS material, transfer framing, and
  storage locations. Growing that allowlist is a new schema major.
- **Expectation-first coverage.** A content-free expected-inference ledger is
  frozen before route selection. Reconciliation matches its trace and logical
  inference identity to provider-attempt artifacts and distinguishes
  `observed`, `partial`, `failed`, `unobserved`, and `unknown`; an absent log is
  never enough to manufacture an `unobserved` denominator.
- **Attempt and stream identity.** Every transport attempt has its own UUIDv7
  and dense ordinal. Stream events have dense event ordinals, and retry records
  point backward to a prior attempt ordinal. Correlation fields join records
  but never enter payload digests or storage keys.
- **Durable completion.** An ephemeral job that claims complete exact capture
  must flush pending artifacts through the normal authenticated client path and
  wait for an acknowledged receipt. Timeout, cancellation, authorization pause,
  or storage outage remains an explicit incomplete outcome.

## Pre-implementation route and evidence gate

The following matrix is the implementation gate for both routes. The positive
evidence is the existing schema corpus where marked **present**; the negative
evidence names the rejection or fault-injection vector that must be present in
the route conformance suite before that route is called supported. A route does
not pass by forwarding bytes or by producing plausible JSON alone.

| Route | Required mitigation | Positive conformance evidence | Required negative evidence before implementation is accepted |
|---|---|---|---|
| Explicit proxy | Preserve decoded request/response, stream, retry, usage, and transport-error boundaries while forwarding the provider exchange | `tools/inferencegen.py --verify`: all six artifact kinds; `single-attempt`, `retried-attempt`, and `streamed-attempt` scenarios (**present**) | provider replacement cannot mint a supported route; transfer-framing, malformed stream, truncated stream, and credential-bearing-header cases are rejected or classified without raw bytes (**proxy-route negatives**) |
| Supported SDK hook | Emit the same lifecycle at the actual transport boundary and make hook failure visible; claim only a qualified integration | exact-artifact schema and kind matrix (**present**); first-party route conformance is the required positive | ambient tracing, wrong SDK version, pre/post-transport callback, missing hook event, and hook failure must be `partial`/`failed`, never `observed` (**hook-boundary negatives**) |
| Expected-inference ledger | Freeze the denominator before route selection and reconcile by trace plus logical inference identity | plan Phase 9 outcome taxonomy and correlation schema (**contract present**) | forged, late, duplicate, cross-session, and open-without-attempt expectations; only a closed expectation may become `unobserved` (**ledger negatives**) |
| Stream and retry reconstruction | Keep event order and attempt boundaries lossless, including incomplete attempts | corpus stream concatenation and retry ordinal checks (**present**) | event gaps, duplicate ordinals, false terminal events, self/forward/orphan retry links, and merged retry payloads (**reconstruction negatives**) |
| Flush and coverage report | Gate teardown on acknowledged flush and report incomplete work separately from complete exact coverage | CAP-007, `archivist.exact.flush`, and the explicit coverage outcomes (**contract present**) | timeout, cancellation, auth pause, storage outage, lost receipt, and process exit before acknowledgement must never report completion (**flush negatives**) |

This matrix is deliberately recorded before route code. The existing artifact
corpus proves the schema's positive and rejection properties; the named route,
ledger, reconstruction, and flush negatives are release-blocking evidence for
the proxy and hook beads. The compatibility matrix may list a route only after
both its positive conformance and its applicable negative set pass.

## Findings

### EC-01 — Centralized provider inputs, outputs, and error bodies

**STRIDE:** Information disclosure / Elevation of privilege ·
**Disposition:** Mitigated

- **Threat.** A capture service becomes a central copy of prompts, responses,
  tool results, provider errors, and usage observations. A compromised route or
  over-broad archive reader can use that concentration to disclose one tenant's
  provider traffic or make a semantic transcript appear to be exact provider
  evidence.
- **Attacker position.** A route operator, archive reader, or implementation
  bug with access to capture artifacts; the route need not defeat ingest
  authentication to cause over-collection.
- **Affected contract.** Plan Phase 9's separate exact capability, CAP-008,
  SEC-004/006, raw-versus-derived separation, and the normal tenant-scoped
  ingest boundary.
- **Mitigation and evidence.** Capture is opt-in by explicit route, stored as
  tenant-scoped immutable artifacts, and joined to semantic data only through
  bounded identities. Logs, metrics, traces, errors, and status remain
  content-free. The exact corpus proves the six closed artifact kinds and
  byte-stable payload digests; the proxy-route and coverage negatives prove
  that bypass or semantic-only evidence cannot become an exact claim.
- **Residual.** None in the v1 route contract; access to intentionally archived
  raw provider content remains governed by the existing raw-data access policy.

### EC-02 — Decoded-header capture exposes provider credentials

**STRIDE:** Information disclosure / Spoofing · **Disposition:** Mitigated

- **Threat.** A proxy or hook records an `Authorization`, API key, cookie,
  provider credential, `Set-Cookie`, endpoint, or TLS/transfer detail as a
  header-derived metadata field. The leak may be caused by a permissive header
  copier, an error renderer, or a future additive field that silently widens
  v1.
- **Attacker position.** A provider, on-path observer, compromised client, or
  later archive reader able to retrieve the artifact or diagnostic output.
- **Affected contract.** The post-decoding boundary, the closed `metadata`
  allowlist, the reserved-name list, SEC-004/006, and the v1 fail-closed schema
  major rule.
- **Mitigation and evidence.** Normalize only the nine listed metadata values;
  keep unlisted headers out of metadata and keep raw header blocks out of the
  artifact. The existing reserved-field and unlisted-metadata negative matrix
  rejects credential-shaped and innocuous names alike, while the transfer and
  TLS reserved cases prove that framing cannot be smuggled into the record.
- **Residual.** None for header-derived metadata. A provider credential
  intentionally present in a provider body is provider payload content and is
  governed by the raw-content access and downstream redaction policies; it is
  not relabeled as metadata.

### EC-03 — Proxy impersonation or route substitution

**STRIDE:** Spoofing / Tampering · **Disposition:** Mitigated

- **Threat.** A malicious or misconfigured proxy claims that it observed an
  explicitly routed provider exchange, substitutes a different upstream or
  response, or makes bypass traffic look like proxy coverage. Exact coverage
  then becomes a false assertion about which boundary was observed.
- **Attacker position.** A proxy operator, compromised proxy process, or caller
  able to select an endpoint or route policy without the orchestrator's frozen
  expectation.
- **Affected contract.** Phase 9's explicit-route rule, route policy in the
  expected-inference ledger, `origin_client_id` capture provenance, and the
  observed/unobserved distinction.
- **Mitigation and evidence.** The proxy is a qualified route only after its
  forwarding and capture conformance binds one attempt to the frozen
  expectation; it does not mint provider authenticity. Provider replacement,
  route-policy mismatch, and bypass vectors must fail or classify as
  `failed`/`unobserved`, and must never reuse another attempt's IDs. The
  `valid` artifact scenarios supply the route-independent record shape; the
  required proxy-route negatives supply the route-specific proof.
- **Residual.** None for route attribution; provider-side truth remains outside
  this model as stated in the scope boundary.

### EC-04 — SDK-hook misuse or false compatibility claim

**STRIDE:** Spoofing / Repudiation · **Disposition:** Mitigated

- **Threat.** Ambient tracing, a package-name detector, or a callback placed
  before serialization or after buffering is advertised as a lossless SDK
  integration. It misses retries, stream events, or transport errors while
  still reporting exact coverage, or a third-party SDK version is assumed to
  share the first-party hook boundary.
- **Attacker position.** A caller, integration author, or compatibility claim
  that can cause an unsupported route to enter the exact denominator.
- **Affected contract.** The versioned `InferenceObserver` lifecycle, the
  first-party Rust transport qualification, CAP-008, and the compatibility
  matrix's explicit route claims.
- **Mitigation and evidence.** A supported hook must emit logical-inference
  start/close, attempt start, decoded request, ordered response events,
  outcome, and bounded flush state around the actual transport. The existing
  kind matrix proves the output vocabulary; hook-boundary negatives for wrong
  versions, ambient tracing, missed callbacks, and callback failure must yield
  `partial` or `failed`, never `observed`. No SDK name enters the matrix before
  this evidence passes.
- **Residual.** None for the supported integration boundary; unsupported SDKs
  remain explicitly unobserved or unknown.

### EC-05 — Forged expected-inference ledger entry

**STRIDE:** Spoofing / Tampering / Repudiation · **Disposition:** Mitigated

- **Threat.** A producer creates, edits, duplicates, or closes an expectation
  after seeing route results to inflate exact coverage, turn a missing attempt
  into a benign bypass, or join an artifact to another session.
- **Attacker position.** A compromised orchestrator, untrusted ledger writer,
  or race between route selection and coverage reconciliation.
- **Affected contract.** Phase 9's frozen content-free expectation, trace and
  inference identity matching, bounded outcome taxonomy, and the rule that
  `unknown` is not silently converted to `unobserved`.
- **Mitigation and evidence.** Freeze the expectation before route selection;
  close it once with route policy, timestamps, and bounded outcome. Reconcile
  only exact identity matches and reject duplicate, late, cross-session, open,
  or forged expectations. Those ledger negatives are required before the
  ledger or either route is implementation-qualified; the artifact corpus
  supplies the matching correlation vocabulary.
- **Residual.** None in the ledger state machine; the authority of the
  orchestrator that writes an expectation is an integration trust decision,
  not evidence of provider observation.

### EC-06 — Stream truncation or false terminal completion

**STRIDE:** Tampering / Denial of service · **Disposition:** Mitigated

- **Threat.** A stream ends between events, a final event is fabricated, an
  event is dropped or duplicated, or decoded bytes are confused with chunked or
  TLS framing. The archive then presents partial output as complete or merges a
  later retry into the truncated attempt.
- **Attacker position.** A provider or proxy that closes or alters the stream,
  an on-path fault, or a parser that mishandles backpressure and EOF.
- **Affected contract.** Decoded `streaming-event` artifacts, dense event
  ordinals, `stream-incomplete` and `stream-interrupted`, and the separate
  attempt identity.
- **Mitigation and evidence.** Emit one decoded event per ordinal; reconstruct
  the attempt by ordinal order; classify an abnormal end as incomplete or a
  transport error, never as a successful terminal response. The committed
  streamed-attempt corpus proves byte concatenation and dense ordinals. The
  reconstruction negatives for gaps, duplicates, false terminal events,
  malformed transfer decoding, and truncation must pass before proxy/hook
  support is claimed.
- **Residual.** None for archive completeness classification; a provider that
  intentionally sends a semantically incomplete but well-formed response is
  provider behavior outside this boundary.

### EC-07 — Retry confusion and cross-attempt merge

**STRIDE:** Tampering / Repudiation · **Disposition:** Mitigated

- **Threat.** A retry is mistaken for the original attempt, two attempts share
  an identity, a retry record points forward or to another inference, or
  identical request bytes are treated as evidence that the responses were one
  exchange. The resulting archive loses failure, latency, or provider-outcome
  history.
- **Attacker position.** A retrying client, route race, lost response, or
  implementation that keys only on the logical inference ID or payload digest.
- **Affected contract.** UUIDv7 `provider_attempt_id`, dense `attempt_ordinal`,
  `retry_of_attempt_ordinal`, and the rule that payload deduplication never
  deduplicates provenance.
- **Mitigation and evidence.** Every transport attempt receives a fresh
  attempt identity; retries point strictly backward within one logical
  inference, while identical payload bytes may reuse a digest without merging
  records. The committed retried-attempt corpus proves a three-attempt chain,
  two retry transitions, and byte reuse. Self/forward/orphan links and merged
  attempt IDs are required negative cases.
- **Residual.** None.

### EC-08 — Correlation leakage or identity contamination

**STRIDE:** Information disclosure / Tampering · **Disposition:** Mitigated

- **Threat.** Trace, logical-request, attempt, session, or provider request
  identifiers leak into payload digests, object keys, metric labels, or error
  bodies; alternatively, a collision or mutable correlation value joins
  unrelated sessions. This defeats deduplication and exposes sensitive
  relationship metadata.
- **Attacker position.** A reader of telemetry or storage, a caller choosing
  identifiers, or a serializer that accidentally folds provenance into content
  identity.
- **Affected contract.** CAP-008's explicit join, the plain SHA-256 payload
  digest, server-derived object keys, the closed metrics registry, and
  content-free error/status rules.
- **Mitigation and evidence.** Correlation is record metadata only: it is
  UUIDv7-validated, never an input to a digest or storage key, and never a
  metric label or free-text diagnostic. `inferencegen.py --verify` recomputes
  the plain content digest and proves identical bytes reuse one digest across
  attempts; the metrics and wire-schema negative gates reject sensitive labels
  and diagnostic fields. Cross-session collision and digest-movement cases
  are required route negatives.
- **Residual.** None.

### EC-09 — Semantic/exact bypass conflation

**STRIDE:** Spoofing / Repudiation · **Disposition:** Mitigated

- **Threat.** A semantic harness transcript is counted as a provider-boundary
  observation, or a session with no expectation is counted as an unobserved
  exact miss. Conversely, a bypassed call disappears from the denominator and
  the report claims universal exactness.
- **Attacker position.** A reporting layer, unsupported route, or operator who
  infers capture from an absent proxy record.
- **Affected contract.** The separate semantic and exact dimensions, the
  `observed`/`partial`/`failed`/`unobserved`/`unknown` outcomes, and CAP-008/009.
- **Mitigation and evidence.** Only a closed expectation can be reconciled;
  semantic records cannot create exact artifacts, and no expectation/artifact
  evidence remains `unknown` rather than being guessed. The required
  semantic-versus-exact divergence fixture has one routed observed attempt and
  one bypassed unobserved gap without merging them; absence-of-proxy-log and
  no-expectation negatives must reject the universal-coverage claim.
- **Residual.** None.

### EC-10 — Incomplete flush reported as complete

**STRIDE:** Repudiation / Denial of service · **Disposition:** Mitigated

- **Threat.** An ephemeral job exits after emitting provider events but before
  the spool is durable or a receipt is acknowledged. A timeout, cancellation,
  authorization pause, or storage outage is swallowed, and the coverage report
  says exact capture completed even though the last request, stream event, or
  retry artifact is missing.
- **Attacker position.** A teardown race, scheduler failure, storage outage, or
  caller that treats process exit as acknowledgement.
- **Affected contract.** CAP-007, the flush-before-teardown requirement,
  receipt-gated client acknowledgement, and the `flush_outcome` exact metric.
- **Mitigation and evidence.** Teardown waits for the normal authenticated
  spool/upload/receipt path when complete capture is required. It records
  incomplete rather than fabricated completion for timeout, cancellation,
  authorization pause, storage outage, lost receipt, and process exit before
  acknowledgement. The flush integration negatives are release-blocking, and
  the existing receipt contract prevents a cursor from advancing without a
  durable receipt.
- **Residual.** None; an incomplete flush remains visible as a coverage gap
  and is retriable rather than silently discarded.

## Cross-cutting controls relied on above

- The exact artifact schema's closed shape is the first containment layer:
  unknown kinds, kind-gated fields, reserved names, and unlisted metadata fail
  closed before an artifact reaches the normal ingest path.
- The three correlation identities are provenance joins, not content identity.
  This preserves deduplication while keeping retries and stream events
  reconstructable and prevents identifiers from becoming storage or telemetry
  disclosure channels.
- The normal authenticated spool and receipt chain provide durability; exact
  capture cannot invent a new acknowledgement path. CAP-007 is therefore a
  lifecycle gate over the same receipt evidence, not a best-effort shutdown
  hook.
- Route qualification is a compatibility claim backed by conformance, not a
  parser capability. A proxy or hook that fails a negative vector is not
  supported and reports the corresponding bounded gap.

## Coverage and disposition register

| ID | Finding | STRIDE | Disposition | Enforcing test class | Owner of residual |
|---|---|---|---|---|---|
| EC-01 | Centralized provider inputs, outputs, and error bodies | I/E | Mitigated | exact-artifact corpus; content-free telemetry; proxy-route coverage negatives | — |
| EC-02 | Decoded-header capture exposes provider credentials | I/S | Mitigated | reserved-field and closed-metadata negative matrix; transfer/TLS framing negatives | — |
| EC-03 | Proxy impersonation or route substitution | S/T | Mitigated | explicit-route conformance; proxy replacement and route-policy negatives | — |
| EC-04 | SDK-hook misuse or false compatibility claim | S/R | Mitigated | `InferenceObserver` lifecycle conformance; hook-boundary and hook-failure negatives | — |
| EC-05 | Forged expected-inference ledger entry | S/T/R | Mitigated | expectation/artifact reconciliation; forged, late, duplicate, and cross-session negatives | — |
| EC-06 | Stream truncation or false terminal completion | T/D | Mitigated | streamed-attempt reconstruction; gap, duplicate, terminal, transfer, and truncation negatives | — |
| EC-07 | Retry confusion and cross-attempt merge | T/R | Mitigated | retried-attempt reconstruction; self/forward/orphan/merge negatives | — |
| EC-08 | Correlation leakage or identity contamination | I/T | Mitigated | plain-digest independence; metrics/wire disclosure gates; correlation-collision negatives | — |
| EC-09 | Semantic/exact bypass conflation | S/R | Mitigated | semantic-versus-exact divergence; absent-log and no-expectation negatives | — |
| EC-10 | Incomplete flush reported as complete | R/D | Mitigated | receipt-gated flush integration; timeout/cancel/auth-pause/outage negatives | — |

Acceptance check for this document: all ten Phase 9 findings are represented
above. The existing exact-artifact corpus is the present positive and schema
negative evidence; the route, ledger, reconstruction, divergence, and flush
negative vectors named in the matrix are mandatory evidence before the proxy,
SDK hook, or compatibility matrix claims support. No finding relies on an
absence of logs as proof, and no row adds a contract beyond the plan,
requirements, exact schema, metrics registry, and normal receipt-gated ingest
path.
