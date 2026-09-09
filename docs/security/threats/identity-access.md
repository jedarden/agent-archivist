# Identity and access threats — ingestion path

Status: one of four domain documents feeding the Phase 1 threat model · Last
updated: 2026-09-09

Authority: the [implementation plan](../../plan/plan.md) — primarily Section 5
("Control-plane boundary"), Section 7.2 ("Wire request and authentication"),
and Section 7.3 ("Envelope fields"), with the plan's §7.11 edge-case catalog
(`EC-*`), other contract sections, and phase exit gates cited where a claim
depends on them — and the normative
[requirements](../../notes/requirements.md) (`ID-*`, `VAL-*`, `SEC-*`,
`STO-*`). This document interprets those contracts; it introduces no new
contract. The four domain documents under `docs/security/threats/` are
consolidated into `docs/security/threat-model.md`, whose register must let a
reader verify the Phase 1 exit gate ("the threat model has a mitigation or
explicitly accepted risk for every finding") from the register alone.

## Scope

In scope: identity and access threats against `POST /v1/ingest` — uploader key
spoofing, request/envelope replay, and cross-tenant writes.

Out of scope here, owned by sibling documents:

- Relay and delegation abuse (an uploader asserting an origin it does not own,
  scope-union escalation, revoked delegation replay) —
  `docs/security/threats/relay-delegation.md`. This document references the
  plan's `delegation` test only where the same Section 5 contract enforces
  uploader identity.
- Digest confusion, decompression bombs, and poisoned manifests —
  `docs/security/threats/payload-integrity.md`.
- Receipt trust failure and metadata leakage —
  `docs/security/threats/receipts-and-disclosure.md`.

### Contract basis

The findings below rely on exactly these plan-fixed mechanisms, restated so
each finding can name what it attacks:

- **Per-client proof of possession.** Each client owns an Ed25519 key (plan
  §5). Every attempt carries an Ed25519 HTTP message signature covering the
  HTTP method, route, content type, whole-request content digest, canonical
  envelope digest, payload digests, uploader key ID, authorization epoch, and
  fresh authorization timestamp (plan §7.2). Requirements ID-001, ID-004.
- **Tenant-signed trust records.** The server authenticates the uploader by
  loading its tenant-authority-signed linked-client record from S3 or the
  unexpired in-memory cache (plan §5, server data-flow steps 2–3). Ingest
  replicas hold tenant authority public keys, never the `ControlAdminStore`
  credential (plan §5). Requirement ID-003.
- **Fresh per-attempt authorization.** Authorization is fresh per attempt,
  valid five minutes, with at most five minutes of clock skew (plan §5). The
  immutable envelope excludes the per-attempt signature, epoch, key, and
  timestamp, so a retry outside the window is re-authorized without changing
  occurrence or attestation identity (plan §7.2, §7.3).
- **Cache and failure behavior.** Trust records cache for at most 60 seconds.
  On registry unavailability an unexpired record may be used; otherwise the
  server fails closed with retryable 503 (plan §5, EC-09). Revocation
  propagates within 60 seconds (plan §5, Phase 3 exit gate).
- **Rotation.** Old and new keys both verify for 24 hours; authorization
  epochs are monotonic (plan §5, Phase 3).
- **Server-derived, tenant-scoped keys.** Object keys are derived by the
  server from validated identity fields; clients never choose paths (plan
  §7.5, requirement ID-008). Tenant authorization is enforced before
  object-key construction or any storage call (plan §11, requirement SEC-003).
- **Rejection behavior.** Unlinked/revoked/unauthorized requests return
  401/403 and the client pauses uploads pending link/rotation action; registry
  and storage failures return retryable 5xx with no receipt (plan §7.8,
  EC-12).

Where a finding records an accepted risk, the acceptance is of a bound the
plan already states (for example the 60-second revocation propagation bound);
it is not a new tolerance. Accepted-risk owners are drawn from existing
vocabulary: the `SEC` verification owner (plan §16 traceability table) for
the threat model itself; the `archivist-auth` and `archivist-server` crate
owners for their enforcing components (owning phases 3 and 4 per the
[crate ownership map](../../notes/crate-ownership.md)); and the operator who
performs a tenant's control-plane actions — linking, revocation, rotation
(plan §5; EC-12) — called the *tenant operator* throughout this document.

### Enforcing test classes

Plan §5 fixes the test classes that enforce this contract: **altered**,
**stale**, **cross-tenant**, **revoked**, **registry-outage**, **delegation**,
and **rotation-with-pending-spool**. Phase 3's exit gate extends them
(unlinked, revoked, stale-epoch, cross-tenant, altered, replay-expired, and
unauthorized-relay requests fail closed). Tests do not exist yet — Phase 1
delivers the conformance corpus and Phase 3 the auth negative tests — so
findings cite the test class plus the plan clause it enforces.

## Findings

### IA-01 — Unlinked uploader identity (spoofing without a key)

**STRIDE:** Spoofing · **Disposition:** Mitigated

- **Threat.** A party that is not a linked client submits an ingest request
  asserting an arbitrary tenant ID, uploader client ID, and key ID — or a
  client ID it has observed in traffic — and signs with a key it controls,
  hoping the server authorizes on asserted identity fields instead of
  verified proof of possession.
- **Attacker position.** Any network peer that can reach the `/v1/ingest`
  endpoint. No linked private key, no trust record, no storage credential.
  Client and tenant identifiers are not secret: they travel in the envelope
  (plan §7.3) and must not be treated as authentication.
- **Affected contract.** Plan §5 (verification of the per-attempt signature
  against the tenant-signed linked-client record, server data-flow steps 2–3);
  plan §7.2 (signature coverage); requirements ID-003, ID-004; SEC-003.
- **Mitigation and enforcing tests.** Verification resolves the asserted key
  ID to a tenant-authority-signed linked-client record and verifies the
  Ed25519 signature before any storage commitment (plan §7.2: the server may
  pre-authorize the key ID before the body but commits nothing until the
  complete signature and payload verify). An unlinked or self-minted identity
  has no signed record to satisfy this and fails closed with 401/403 (plan
  §7.8). Enforced by the **altered** test class (a signature from a key that
  does not match the trust record is an altered authorization) and Phase 3's
  exit gate "unlinked … requests fail closed". Tenant IDs are issuer-created
  UUIDv4 values (plan §7.4), so guessing a tenant identifier grants nothing
  by itself. A linked uploader asserting an origin client other than itself
  crosses into the delegation boundary — enforced by the **delegation** test
  class (plan §5) and documented in
  `docs/security/threats/relay-delegation.md`.
- **Residual.** Unauthenticated requests consume pre-commit work only, which
  is bounded before payload-scale allocation (plan §5 server data-flow step
  1); volumetric abuse is the payload-integrity document's scope.

### IA-02 — Altered request under a valid signer (authorization transplant)

**STRIDE:** Tampering · **Disposition:** Mitigated

- **Threat.** A holder of one legitimately signed authorization attempts to
  change what it authorizes: substituting payload bytes, editing envelope
  fields (tenant, origin client, digests, sizes, source coordinates), or
  detaching the signature from its envelope and reattaching it to a different
  request, including across multipart part reordering.
- **Attacker position.** An on-path attacker who has captured a signed
  request, or a malicious linked client trying to stretch one authorization
  over content it does not cover. Position is stronger than IA-01: the
  attacker has (or has observed) genuinely valid signed bytes.
- **Affected contract.** Plan §7.2 (the signature covers method, route,
  content type, whole-request content digest, canonical envelope digest, and
  payload digests; the envelope is canonical RFC 8785 JSON with no floats and
  a 64 KiB cap, and the multipart framing is fixed); plan §7.3 (the spooled
  envelope is immutable); requirement ID-004 (the proof binds tenant,
  metadata, payload digest, request ID, and timestamp).
- **Mitigation and enforcing tests.** Every alteration surface named above is
  inside the signed material, so any change breaks verification; byte
  substitution in the payload breaks the whole-request content digest and the
  declared digests before a blob could be committed under a false address
  (requirements VAL-004, VAL-005). Enforced by the **altered** test class
  (plan §5) and §7.2's "Enforced by" list: altered multipart cases and
  reordered/whitespace JSON cases, plus golden signed-envelope vectors and a
  standalone verifier (Phase 1 exit gate). Signature verification uses
  constant-time implementations from reviewed cryptographic libraries (plan
  §11).

### IA-03 — Replay of a captured request inside the five-minute window

**STRIDE:** Repudiation / resource abuse · **Disposition:** Mitigated by
design; residual amplification accepted

- **Threat.** An attacker (or a lost-response duplicate) captures a complete
  signed request and resubmits it unchanged while its authorization is still
  inside the five-minute window, attempting to multiply records, confuse
  provenance, or spend storage.
- **Attacker position.** On-path capture of one valid request; no key
  material required.
- **Affected contract.** Plan §5 ("Replays inside that window are harmless
  because the operation is logically idempotent"); EC-04; requirements
  ID-007 (identical authorized retries remain logically idempotent) and
  STO-004 (converge on the same blob, occurrence, and upload-attestation keys
  without duplicate logical records).
- **Mitigation and enforcing tests.** This is the plan's explicit design
  position, not a gap: occurrence and upload-attestation IDs are deterministic
  (plan §7.4), so a byte-identical replay reproduces the same identities and
  converges to one logical blob, occurrence, and attestation across replicas
  (EC-04; Phase 4 exit gate "two or more replicas pass identical-request and
  concurrent-retry tests"). Enforced by the identical-request/concurrent-retry
  convergence tests and STO-004's no-duplicate-records assertion.
- **Residual (accepted).** A replay still costs the service bandwidth,
  decompression, and storage I/O for bytes already stored. The per-client
  token bucket of 60 new requests per minute per replica with burst 8, the
  four-uploads-per-client in-flight cap, and the 15-minute request deadline
  (plan §7.6) bound that amplification. **Owner:** SEC working group
  (plan §16 Security verification owner), with the `archivist-server` owner
  (Phase 4) for the limit enforcement.

### IA-04 — Replay of a captured request after the window (stale authorization)

**STRIDE:** Spoofing / repudiation · **Disposition:** Mitigated

- **Threat.** The IA-03 replay attempted later: a captured request is held and
  resubmitted after its authorization expired, hoping the server validates
  only the immutable envelope — which remains perfectly valid — and skips
  authorization expiry.
- **Attacker position.** On-path capture plus delayed replay; no key material.
- **Affected contract.** Plan §5 (five-minute per-attempt window);
  Phase 3 exit gate ("a replayed authorization outside its five-minute window
  is rejected even when its immutable occurrence envelope is valid");
  requirement ID-007 (stale authorization must be rejected).
- **Mitigation and enforcing tests.** The server verifies the authorization
  timestamp and the five-minute replay window as part of the per-attempt
  check (plan §5 server data-flow step 3); a stale authorization fails closed
  with 401/403. A legitimate client in this position simply re-authorizes the
  frozen envelope — the envelope excludes per-attempt authorization precisely
  so a retry outside the window receives fresh authorization without changing
  occurrence or attestation identity (plan §7.2, §7.3). Enforced by the
  **stale** test class (plan §5) and the Phase 3 replay-expired exit gate.

### IA-05 — Clock-skew stretching of the acceptance window

**STRIDE:** Tampering · **Disposition:** Accepted risk

- **Threat.** The plan fixes a five-minute validity window and an at-most
  five-minute clock-skew allowance (plan §5) but does not fix their
  composition. A deployment that stacks the full skew allowance on the
  window's late edge accepts an authorization for up to ten minutes past its
  timestamp — twice the nominal five-minute horizon — when client and server
  clocks disagree maximally in the attacker's favor; adding the allowance at
  both edges stretches the total acceptance span to roughly three times the
  nominal window. Either composition widens IA-03's replay horizon
  proportionally.
- **Attacker position.** On-path capture (as IA-03) plus the ability to
  observe or influence clock disagreement — typically just knowledge that the
  linked client's clock drifts, since the client supplies the signed
  authorization timestamp.
- **Affected contract.** Plan §5 ("valid for five minutes with at most five
  minutes of clock skew"); the five-minute operational allowance is the same
  constant the plan uses for policy evaluation (plan Phase 10: "clock
  uncertainty outside the five-minute operational allowance also denies use").
- **Accepted risk.** The composed window-plus-skew horizon is accepted as the
  operative replay bound. Consequence is bounded by the same mechanisms as
  IA-03: replay is logically idempotent (IA-04 still rejects anything past
  the composed horizon), fresh authorizations from a revoked client are cut
  off by the 60-second revocation propagation bound (IA-08), and a client
  whose clock is badly wrong is diagnosed by its own clock-sanity health
  check (`doctor --json`, Phase 5 deliverable and exit gate) rather than
  silently stretching the window.
  **Owner:** SEC working group (plan §16).
- **Note for implementation.** Within the plan's stated bound, the skew
  allowance should be applied to the window's endpoints, not stacked on both
  sides of it; this document records the composition question for the Phase 11
  independent threat-model review (plan §8, Phase 11) without adding a new
  requirement here.

### IA-06 — Cross-tenant write (tenant impersonation or identifier escape)

**STRIDE:** Elevation of privilege · **Disposition:** Mitigated

- **Threat.** Two variants of writing into another tenant's archive:
  (a) a validly linked client of tenant A submits an envelope declaring
  tenant B, or replays tenant A's authorization over a tenant-B envelope;
  (b) an uploader crafts identifier fields (harness ID, upstream session or
  adapter artifact ID, range coordinates) containing path-like or oversized
  content hoping to escape the derived tenant prefix
  `tenants/<tenant>/v1/raw/…` (plan §7.5) or to collide with another
  tenant's deterministic keys.
- **Attacker position.** A linked client (strongest realistic position on
  this path: holds a genuine key and trust record for its own tenant), or an
  unlinked attacker as in IA-01 attempting variant (b) blindly.
- **Affected contract.** Plan §11 required control "Tenant authorization
  before object-key construction or storage calls" (SEC-003: tenant
  authorization must be enforced before deriving or writing any tenant-scoped
  key), made concrete by §5's server data flow — step 3 verifies the
  signature and the declared tenant before step 7 commits anything; plan §3
  fixed decision "Object keys are tenant-scoped and derived by the server"
  with §7.5 (tenant-scoped key shapes; all key segments are validated opaque
  IDs or hashes) and §7.7 ("The server derives every target key"); plan §7.4
  (session/artifact identities are domain-separated over length-prefixed
  tenant and origin-client fields; identifier syntax and bounds; tenant IDs
  are issuer-created UUIDv4); requirements ID-008 (clients never select object
  keys), VAL-002 (identifier syntax/length and tenant authorization validated
  before commit), STO-003 (keys deterministic and tenant-scoped).
- **Mitigation and enforcing tests.** The linked-client trust record is
  tenant-authority-signed and tenant-addressed
  (`tenants/<tenant>/v1/control/clients/<client>.json`, plan §7.5), and server
  data-flow step 3 verifies the signature *and* the declared tenant before
  any commit (plan §5; SEC-003). A tenant-A authorization over a tenant-B
  envelope is therefore an altered request (IA-02) — the canonical envelope
  digest the signature covers includes the tenant field (plan §7.2, §7.3) —
  and fails signature or tenant verification. Key derivation
  uses domain-separated, length-prefixed fields, so identifier content cannot
  cross the tenant boundary or forge another tenant's deterministic keys
  (plan §7.4). Enforced by the **cross-tenant** test class (plan §5; §7.4
  "cross-tenant tests"; Phase 3 exit gate) and the §10 property test that
  arbitrary identifiers cannot escape tenant prefixes. Defense in depth: the
  ingestion storage identity can write only the configured tenant raw prefix
  and cannot read, delete, or reach control/catalog/derived prefixes (plan
  §5, §7.7), so a derivation defect is contained to one tenant's raw prefix
  rather than the bucket. The ingestion path has no read route and its
  storage identity cannot read, so cross-tenant exposure here is write-only.

### IA-07 — Forged or substituted trust record; tenant-authority key compromise

**STRIDE:** Spoofing / elevation of privilege · **Disposition:** Forged
record mitigated; authority-key compromise accepted

- **Threat.** (a) An attacker plants or rewrites a linked-client,
  revocation, or pointer record in the control prefix to authorize a key of
  their choosing, or rolls a pointer back to a pre-revocation epoch.
  (b) The tenant authority signing key itself is compromised, letting its
  holder mint valid trust records at will.
- **Attacker position.** (a) Anyone with write access to the control prefix
  — a compromised `ControlAdminStore` credential, a mis-scoped storage
  identity, or a storage-backend compromise. (b) The tenant operator's
  signing-key holder.
- **Affected contract.** Plan §5 (control records are tenant-authority-signed
  complete immutable records; ingest replicas verify against configured
  tenant authority public keys; the S3 adapter derives each key from the
  validated record type, rejects overwrite of an incompatible immutable
  record, and permits a current-pointer replacement only when its signed
  epoch increases; ingest replicas never receive the admin credential).
- **Mitigation (a) and enforcing tests.** A planted or altered record fails
  tenant-authority signature verification at load time; a rolled-back pointer
  fails the monotonic signed-epoch check. The ingestion path's write identity
  cannot write the control prefix at all, so the raw-data plane cannot
  self-authorize (plan §5: "tenant-signed records retain a stateless data
  plane without letting a compromised raw-data credential authorize itself").
  Enforced by the **altered** and **stale**-epoch test classes applied to
  control records (plan §5 enforced-by list; Phase 3 exit gate
  "stale-epoch … fail closed"), plus the incompatible-object tests of the
  §7.7 storage contract (its enforced-by list), which cover the admin-store
  adapter's rejection of an incompatible immutable record.
- **Accepted risk (b).** The tenant authority key is the root of trust for
  client identity on this path; its compromise defeats record verification
  for that tenant. The plan locks this shape — the linked-client registry
  decision is resolved in Section 5 (plan §15, locked-decision index item 3)
  — and its revisit clause contemplates replacement only if "an external
  identity provider can preserve the same offline verification and
  origin/uploader delegation semantics" (plan §5). **Owner:** tenant
  operator, with the
  `archivist-auth` owner (Phase 3) for the verification path. Recovery is the
  Phase 7 runbooks for linking, revocation, and key rotation.

### IA-08 — Revoked client still authorized during propagation

**STRIDE:** Spoofing · **Disposition:** Mitigated; residual window accepted

- **Threat.** A client is revoked (or a key is known compromised) but keeps
  uploading successfully during the interval before every healthy replica
  observes the revocation — exploiting the 60-second trust-record cache and
  the plan's stated maximum 60-second propagation delay (plan §5).
- **Attacker position.** The revoked client itself; it holds a genuine key
  and needs no additional position.
- **Affected contract.** Plan §5 (60-second cache; "Revocation therefore has a
  maximum 60-second propagation delay"); EC-09, EC-12; Phase 3 exit gate
  ("Revocation takes effect on every healthy replica within 60 seconds");
  requirement ID-006.
- **Mitigation and enforcing tests.** Revocation is a signed control record
  read through the same verified path as linking; once visible (≤60 s), the
  trust record shows the revocation and every subsequent request fails closed
  401/403, and the client preserves its spool and pauses until an operator
  links a valid epoch/key (EC-12, plan §7.8 error table). Monotonic
  authorization epochs (Phase 3) prevent a revoked client from presenting a
  pre-revocation epoch.
  Enforced by the **revoked** test class (plan §5; Phase 3 exit gate; EC-12)
  and the 60-second propagation test (plan §14 risk register, "Link registry
  cache is stale"; §12 operational objectives).
- **Residual (accepted).** Uploads accepted in the ≤60-second window, and
  requests already past verification (IA-11), remain in the archive. This is
  the plan's stated bound, not a new tolerance: the archive keeps complete
  provenance for everything accepted, so the operator can identify and govern
  the affected occurrences afterward. **Owner:** tenant operator (revocation
  decision and follow-up), with the `archivist-server` owner (Phase 4) for
  cache-expiry enforcement.

### IA-09 — Registry outage downgrade

**STRIDE:** Elevation of privilege / denial of service · **Disposition:**
Mitigated

- **Threat.** An attacker (or any S3 outage) makes the control prefix
  unreadable, hoping the server falls open — accepting requests without trust
  records — or falls back to cache entries older than their 60-second life,
  quietly extending IA-08's window indefinitely.
- **Attacker position.** Ability to disrupt control-prefix reads (storage
  outage, prefix-level denial) against a replica whose cache has expired.
- **Affected contract.** Plan §5 ("If S3 is unavailable, an unexpired record
  may be used; otherwise the server fails closed with retryable 503"); EC-09
  ("Use a valid cached record for at most 60 seconds; then remove readiness
  and return retryable 503 without storage writes"); Phase 3 ("A cache entry
  is unusable after expiry; registry failure then fails closed with a
  retryable service error"); Phase 4 (readiness requires a successful signed
  control-record read per tenant within the last 60 seconds).
- **Mitigation and enforcing tests.** Expired cache plus unavailable registry
  removes readiness and returns retryable 503 with no storage writes; the
  client sees the §7.8 registry-failure row — retry, no receipt — and keeps
  its spool. There is no open fallback to accept. Enforced by the
  **registry-outage** test class (plan §5; EC-09); the serving-path backstop
  is Phase 4's readiness contract, which requires a successful signed
  control-record read for each tenant within the last 60 seconds and stops
  advertising readiness immediately when that evidence expires (plan §8,
  Phase 4).

### IA-10 — Key-rotation overlap abuse

**STRIDE:** Spoofing · **Disposition:** Compromised-old-key horizon accepted;
stranding mitigated

- **Threat.** Two directions from the 24-hour old/new verification overlap
  (plan §5): (a) an attacker holding a superseded (for example, stolen) old
  key keeps signing successfully for up to 24 hours after rotation;
  (b) rotation strands a legitimate client's already-spooled requests, or a
  client attempts to keep uploading with an epoch the tenant no longer
  expects.
- **Attacker position.** (a) Holder of the old private key at rotation time.
  (b) No attacker — this is the availability face of the same contract.
- **Affected contract.** Plan §5 ("Key rotation accepts old and new keys for
  24 hours, and retries authorize the frozen envelope with the current key");
  Phase 3 (overlapping verification and monotonic authorization epochs; exit
  gates "rotation does not strand already spooled requests inside the
  documented overlap" and "stale-epoch … fail closed"); plan §7.8 (401/403
  row: "Pause uploads; require link/rotation action"); EC-12.
- **Accepted risk (a).** The 24-hour overlap is the plan's deliberate price
  for not stranding spooled work, so a compromised old key verifies for up to
  24 hours unless acted on. Rotation is the normal-key-hygiene path;
  compromise is handled by the revocation path, which cuts a key off within
  the 60-second bound (IA-08) regardless of overlap. **Owner:** tenant
  operator (decides rotate-versus-revoke per event), with the
  `archivist-auth` owner (Phase 3) for epoch enforcement.
- **Mitigation (b) and enforcing tests.** Retries authorize the frozen
  envelope with the current key, and stale epochs fail closed, so a rotated
  client neither loses spooled work nor keeps an expired epoch alive.
  Enforced by the **rotation-with-pending-spool** and **stale**-epoch test
  classes (plan §5; Phase 3 exit gates).

### IA-11 — Mid-request revocation race (verification precedes commit)

**STRIDE:** Spoofing (time-of-check to time-of-use) · **Disposition:**
Accepted risk, flagged for independent review

- **Threat.** The plan's server data flow authenticates and authorizes at
  steps 2–3 and streams/commits at steps 4–7 (plan §5). A revocation that
  propagates after a request's authorization was verified but before its
  commit does not, under the documented order, stop that in-flight request;
  the attacker position is simply to be mid-upload when revocation lands.
- **Attacker position.** The revoked client itself, with a large or
  long-running upload in flight when the operator revokes it.
- **Affected contract.** Plan §5 server data-flow ordering (verify at steps
  2–3, commit at steps 7–9); the 15-minute request deadline and body bounds
  (plan §7.6); §7.8 (the signed receipt records the successful authorization
  key/epoch, so what was accepted and under which key is auditable).
- **Accepted risk.** The plan fixes the verification-before-commit order but
  does not state that revocation is re-examined between verification and
  commit; this document records the consequence under the existing contract
  rather than adding a re-check requirement. Consequence is bounded: the
  in-flight request is limited by the 15-minute deadline and the per-request
  size bounds, everything it commits is deterministic and provenance-bearing
  — the blob by canonical digest, the occurrence by session/artifact/range
  identity, and the upload attestation keyed to the uploader and request ID
  (plan §7.4–7.5) — and the receipt's recorded authorization key/epoch lets
  the operator attribute the accepted material after the fact. **Owner:**
  `archivist-server` owner (Phase 4), accepted by the SEC working group
  (plan §16); revisit at the Phase 11 independent threat-model review.

## Cross-cutting controls relied on above

- Bounded pre-allocation: headers, envelope, body size, duration, and
  concurrency are bounded before payload-scale resources are allocated (plan
  §5 server data-flow step 1) — caps the cost of unauthenticated and spoofed
  attempts (IA-01, IA-03).
- Constant-time signature verification through reviewed cryptographic
  libraries (plan §11) — supports IA-01/IA-02 verification.
- Fail-closed error taxonomy: 401/403 pauses uploads pending link/rotation;
  registry/storage failures are retryable 5xx with no receipt (plan §7.8) —
  the behavior IA-04, IA-08, and IA-09 depend on.
- Content-free telemetry: no transcript bodies or authorization values in
  logs, metrics, errors, or traces (plan §11; SEC-004) — the authorization
  path never becomes a disclosure channel. Findings about disclosure live in
  `docs/security/threats/receipts-and-disclosure.md`.

## Coverage and disposition register

| ID | Finding | STRIDE | Disposition | Enforcing test class | Owner of residual |
|---|---|---|---|---|---|
| IA-01 | Unlinked uploader identity | S | Mitigated | altered; unlinked fail-closed (Phase 3) | — |
| IA-02 | Altered request / authorization transplant | T | Mitigated | altered (+ altered multipart, JSON reorder) | — |
| IA-03 | In-window replay | R/D | Mitigated by design | identical-request / concurrent-retry (EC-04, STO-004) | SEC working group (amplification) |
| IA-04 | Stale replay outside window | S/R | Mitigated | stale (Phase 3 replay-expired) | — |
| IA-05 | Clock-skew window stretching | T | Accepted | — (bounded by IA-03/IA-08 tests) | SEC working group |
| IA-06 | Cross-tenant write | E | Mitigated | cross-tenant (+ tenant-prefix property test) | — |
| IA-07 | Forged trust record / authority compromise | S/E | (a) mitigated, (b) accepted | altered + stale-epoch on control records | tenant operator (b) |
| IA-08 | Revoked client during propagation | S | Mitigated; residual accepted | revoked (+ 60 s propagation) | tenant operator |
| IA-09 | Registry outage downgrade | E/D | Mitigated | registry-outage (EC-09, Phase 4 readiness) | — |
| IA-10 | Rotation overlap abuse | S | (a) accepted, (b) mitigated | rotation-with-pending-spool + stale-epoch | tenant operator (a) |
| IA-11 | Mid-request revocation race | S | Accepted | — (bounded; flagged for Phase 11 review) | `archivist-server` owner / SEC working group |

Acceptance check for this document: spoofing (IA-01, IA-02, IA-07, IA-08,
IA-10, IA-11), replay (IA-03, IA-04, IA-05), and cross-tenant write (IA-06)
are each documented; every finding carries either an enforcing test class
from plan §5's list or an explicitly accepted risk with a named owner; no
finding introduces a contract that plan §5, §7.2, or §7.3 does not state.
