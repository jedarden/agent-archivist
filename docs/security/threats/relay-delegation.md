# Relay delegation and provenance threats — ingestion path

Status: one of four domain documents feeding the Phase 1 threat model · Last
updated: 2026-09-12

Authority: the [implementation plan](../../plan/plan.md) — primarily Section 5
("Control-plane boundary", whose fixed sentence is that relay authority is the
conjunction of tenant, origin, harness, and operation scopes, never their
union), Section 7.4 ("Identifier and collision rules", whose
occurrence/attestation identity separation is the provenance defense), and
Section 7.7's commit contract ("request, uploader, and capture-time fields
live in the attestation, preventing a relay from overwriting source
provenance"), with the §7.11 edge-case catalog (`EC-05A` above all), other
contract sections, and phase exit gates cited where a claim depends on them —
the normative [requirements](../../notes/requirements.md) (`ID-*`, `SID-*`,
`STO-*`, `VAL-*`, `SEC-*`, `OPS-*`), the control-plane contracts
([control-trust](../../notes/control-trust.md) and
[`schemas/v1/control-delegation.json`](../../../schemas/v1/control-delegation.json)),
and the wire contract as pinned in [protocol v1](../../protocol/v1.md). This
document interprets those contracts; it introduces no new contract. The four
domain documents under `docs/security/threats/` are consolidated into
`docs/security/threat-model.md`, whose register must let a reader verify the
Phase 1 exit gate ("the threat model has a mitigation or explicitly accepted
risk for every finding") from the register alone.

## Scope

In scope: relay and delegation abuse against `POST /v1/ingest` and the
control records that gate it — an uploader asserting an origin it does not
own or a scope it was not granted, a relay overwriting or laundering source
provenance, scope-union escalation, replay of a withdrawn or narrowed
delegation, attacks on the delegation record itself, and the concurrent
origin/relay upload of one source occurrence (EC-05A).

Out of scope here, owned by sibling documents and later phases:

- Uploader key spoofing, request/envelope replay, and cross-tenant writes —
  `docs/security/threats/identity-access.md`. Its IA-01/IA-02 establish the
  authentication this document builds on (a relay is first a *linked
  uploader*); its IA-07 owns the tenant-authority compromise acceptance this
  document cross-references rather than re-argues; its IA-11 owns the
  mid-request revocation race whose delegation-shaped twin is noted in RD-04.
- Identifier-escape mechanics (path traversal, oversized identifiers,
  digest-confusion plumbing) — `docs/security/threats/payload-integrity.md`
  PI-06. RD-07 covers only the relay-specific re-identification behaviors and
  shares PI-06's enforcing test classes.
- Fabricated provenance by a *direct* uploader — payload-integrity PI-07.
  RD-08 covers the delegation-shaped face of the same acceptance (fabrication
  *under a grant*) and defers to PI-07's disposition and owner.
- Digest confusion, decompression bombs, and resource exhaustion —
  payload-integrity. A relay is one more volumetric abuser; the limits are
  that document's findings (PI-03, PI-04).
- Receipt trust failure and metadata/log leakage —
  `docs/security/threats/receipts-and-disclosure.md`.
- Downstream consumption of relay-archived content (prompt injection, trust
  classification) — SEC-009 and Phase 10 governance.

### Contract basis

The findings below rely on exactly these plan-fixed mechanisms, restated so
each finding can name what it attacks:

- **The delegation record.** A grant is a tenant-authority-signed
  current-pointer control record at
  `tenants/<tenant>/v1/control/delegations/<relay>/<origin>.json`, written
  only by the offline `ControlAdminStore`, read by every ingestion replica
  when it authenticates a relay attempt (plan §5; Phase 3 "origin/uploader
  delegation for approved relays"; ID-005). It names exactly one relay, one
  origin, one tenant, and carries explicit `harnesses` and `operations`
  allowlists (v1 grants exactly `ingest`). There is **one current object per
  (relay, origin) pair** — replaced only by a strictly higher signed
  `authorization_epoch`, withdrawn by publishing `delegation_state:
  withdrawn` at that higher epoch (the store has no delete). It carries no
  key material (SEC-006): it grants a relation between two linked clients,
  each verified through its own record.
- **The conjunction, by construction.** Relay authority is the conjunction of
  tenant, origin, harness, and operation scopes, never their union (plan §5).
  The record's shape makes that true mechanically: one current object per
  pair leaves no set of grants to union over; the harness and operation
  allowlists are *intersected with the relay's own linked-client allowlists*
  at verification, never added to; the harness grammar
  (`[a-z0-9][a-z0-9._-]{0,63}`) has no wildcard token; and a grant for one
  origin is nothing for any other.
- **Verification order.** Server data-flow step 3 verifies "the per-attempt
  signature, tenant, **origin delegation**, timestamp, and five-minute replay
  window" (plan §5) — before schema/identifier validation, streaming, and the
  blob/occurrence/attestation commits of steps 7–9. Tenant authorization
  precedes object-key construction (SEC-003; ID-008).
- **Identity separation.** `occurrence_id` is a deterministic function of
  session/artifact/generation/range/blob-digest inputs; `attestation_id = H(
  "attestation-v1", occurrence_id, uploader_client, request_id)` (plan §7.4).
  Uploader and request never enter occurrence identity — the plan rejected
  embedding them precisely because "concurrent authorized uploaders would
  produce different bytes at one deterministic key." The occurrence manifest
  is a pure function of source-stable inputs (STO-010) and rejects sixteen
  reserved names outright — `uploader_client_id`, `request_id`,
  `delegation`, `capture_time`, `commit_time` among them; the attestation is
  the sole home of uploader/request/capture provenance (STO-013; SID-006).
  `delegation` on the attestation is **server-derived**, not client-asserted:
  `direct` requires `uploader_client_id = origin_client_id`; `relay` requires
  them to differ *and* the uploader to hold verified delegation (ID-005;
  VAL-002 server-side validation).
- **Propagation.** Trust records — linked-client, delegation, rotation,
  receipt-key — cache for at most 60 seconds (plan §5;
  `trustRecordCacheTtlSeconds`). A grant carries no validity window:
  currency is the pointer epoch, and revision/withdrawal propagation is
  bounded by the reader cache (EC-09), never by an expiry on the record.
- **Convergence.** Deterministic keys plus deterministic canonical bytes make
  re-presentation idempotent: a compatible existing object reports
  `already_present` or is rewritten byte-identically (logically idempotent,
  possibly a noncurrent physical version); only *incompatible* content at a
  derived key is `integrity_conflict` (EC-06; plan §7.7).

Where a finding records an accepted risk, the acceptance is of a bound or
trust decision the plan already states; it is not a new tolerance.
Accepted-risk owners are drawn from existing vocabulary, as in the sibling
documents: the *SEC working group* (plan §16 traceability table's Security
verification owner), the `archivist-auth` and `archivist-server` crate owners
for their enforcing components (owning Phases 3 and 4 per the
[crate ownership map](../../notes/crate-ownership.md)), and the *tenant
operator*, who performs a tenant's control-plane actions — here most importantly
granting, narrowing, and withdrawing delegations (plan §5; Phase 3).

### Enforcing test classes

Plan §5 fixes the **delegation** test class alongside altered, stale,
cross-tenant, revoked, registry-outage, and rotation-with-pending-spool; its
Phase 3 exit gate extends the family: "Unlinked, revoked, stale-epoch,
cross-tenant, altered, replay-expired, and **unauthorized relay** requests
fail closed." Plan §7.4's enforced-by list adds **synthetic-ID tests** and
**concurrent relay/origin tests**; §7.11/OPS-007 require relay-upload fault
coverage.

Unlike when the sibling documents were written, the positive face of this
contract is *pinned executable today*: the
[conformance corpus](../../notes/conformance-corpus.md) scenario
`valid-relay-upload` (a relay presenting the origin's occurrence under its
own key: shared blob and occurrence, its own attestation, receipt outcomes
`already_present`/`already_present`/`created`), the derivation vector
`ascii-baseline-relay-pair` (only the attestation axis moves), and
`valid-synthetic-session-id` (the adapter-minted stand-in), plus the
[provenance bundle](../../notes/raw-provenance-schemas.md) scenarios
`delegated-relay` (the same occurrence manifest bytes with a second
attestation differing only in uploader) and
`multiple-attestations-one-occurrence` (the origin's, the relay's, and a
re-frozen request's attestations coexisting on one occurrence). Both run in
the fast lane of [`scripts/definition-of-done.sh`](../../../scripts/definition-of-done.sh)
(`tools/conformancegen.py --verify`, `tools/provenancegen.py --verify`) and
re-prove the cross-scenario invariants (`relay_occurrence_equality`,
`retry_identity_equality`). The *negative* vectors — no grant, withdrawn
grant, out-of-scope harness/origin/tenant, self-asserted `direct` — are the
**delegation** class proper and land with Phase 3's delegation
implementation; findings below cite the test class plus the plan clause it
enforces, naming the corpus proof where one exists today.

## Findings

### RD-01 — Unauthorized or out-of-scope relay writing as an origin

**STRIDE:** Spoofing / elevation of privilege · **Disposition:** Mitigated

- **Threat.** A linked client presents an envelope whose `origin_client_id`
  names an origin it is not authorized to present: (a) no delegation record
  exists for the (relay, origin) pair; (b) a record exists but the attempt
  falls outside it — a different tenant, a harness absent from the grant's
  allowlist, or an operation the v1 grant cannot contain; (c) uploader
  impersonation of the origin — declaring `uploader_client_id =
  origin_client_id` while signing with the relay's own key, hoping the
  server records `delegation: direct` and never consults a grant. The goal is
  writing into the origin's occurrence namespace — planting, shadowing, or
  back-dating material that reads as the origin's own capture.
- **Attacker position.** A linked client of the tenant is the strongest
  realistic position: it holds a genuine key and trust record, which is
  exactly the party the delegation gate exists for. Variant (c) needs only
  key control plus knowledge of the origin's client ID (not secret — it
  travels in the envelope, plan §7.3). An unlinked attacker fails earlier at
  IA-01 and never reaches the delegation check.
- **Affected contract.** Plan §5 (the conjunction sentence; server
  data-flow step 3 verifies origin delegation before any commit); plan §7.3
  (the envelope carries tenant, origin client, and uploader client IDs);
  protocol §2.5 (`delegation` is server-derived: `direct` requires uploader
  = origin, `relay` requires a verified grant — ID-005, VAL-002
  server-side); the delegation record contract (one current object per pair;
  `delegation_state: active`; harness/operation membership in the grant
  intersected with the relay's own linked-client allowlists); requirements
  ID-005, ID-004, VAL-002, SEC-003.
- **Mitigation and enforcing tests.** Authentication resolves the signing
  key to a tenant-signed linked-client record whose client ID must equal the
  declared uploader; origin authority is then established *separately*, by
  loading the (relay, origin) record and requiring every dimension of the
  conjunction at once: attempt tenant = record tenant, declared origin =
  record origin, attempt harness ∈ grant ∩ the relay's own allowlist,
  operation ∈ grant ∩ the relay's own allowlist, and `delegation_state =
  active`. Any miss fails closed 401/403 (the §7.8 `authorization` class:
  pause uploads, no receipt) before object-key derivation or any storage
  call — step 3 precedes steps 7–9 (SEC-003; ID-008). Variant (c) fails
  because `delegation` is derived from *verified* state, never asserted: the
  server computes `direct` only when the uploader's own verified client
  identity equals the origin ID, and a relay's key resolves to the relay's
  record, not the origin's. Enforced by the **delegation** test class
  (plan §5) and Phase 3's exit gate "unauthorized relay requests fail
  closed" — the negative vectors land with Phase 3; today the corpus pins
  the positive face (`valid-relay-upload`: the in-scope relay converging on
  the origin's occurrence) and the key→record resolution and tenant
  equality the negatives exercise (`invalid-cross-tenant-forbidden` → 403).
- **Residual.** None beyond the propagation window of RD-04 and the
  control-prefix integrity assumptions of RD-06.

### RD-02 — Relay overwriting source provenance

**STRIDE:** Tampering · **Disposition:** Mitigated

- **Threat.** A relay attempts to make the origin's stored occurrence
  reflect relay-asserted facts — uploader, request, capture time, delegation
  relation — either by writing those fields into the occurrence object or by
  re-presenting the occurrence with tweaked per-attempt fields hoping the
  second write replaces the first with relay-flavored bytes. Goals: erase the
  origin's provenance, launder modified content under the origin identity,
  or make the origin's own later upload read as a duplicate or conflict.
- **Attacker position.** An authorized relay presenting the origin's
  occurrences — the party the occurrence/attestation separation is designed
  for. An out-of-scope or unlinked uploader never gets a write at all
  (RD-01); the mechanics documented here are what even an authorized relay
  faces.
- **Affected contract.** Plan §7.4 (`attestation_id` folds in uploader and
  request; the rejected alternative of embedding uploader/request fields in
  the occurrence, "because concurrent authorized uploaders would produce
  different bytes at one deterministic key"); plan §7.7 ("request, uploader,
  and capture-time fields live in the attestation, preventing a relay from
  overwriting source provenance"); EC-05A ("never let uploader fields
  overwrite the occurrence"); requirements SID-006, STO-010, STO-013;
  protocol §2.5 (the occurrence manifest rejects `uploader_client_id`,
  `request_id`, `delegation`, `capture_time`, `commit_time`, and eleven
  other reserved names outright).
- **Mitigation and enforcing tests.** The occurrence manifest is a pure
  function of source-stable identity inputs (STO-010): whoever uploads it,
  whenever, derives byte-identical canonical bytes at one deterministic key.
  Uploader, request, and capture provenance live in a separate attestation
  object keyed by `attestation_id = H("attestation-v1", occurrence_id,
  uploader_client, request_id)`. A relay re-presentation therefore *adds* a
  second attestation beside the origin's and never touches the occurrence —
  the overwrite is structurally impossible, not merely forbidden. The
  smuggling route fails at validation: reserved names are rejected with 400
  `envelope.schema_invalid` (corpus proof `invalid-reserved-field`), and
  per-attempt variation cannot enter the frozen envelope at all (IA-02 —
  the signature covers the canonical envelope digest). Enforced today by
  corpus proofs `valid-relay-upload` and `derivations.json` case
  `ascii-baseline-relay-pair` (only the attestation axis moves), the
  manifest's `relay_occurrence_equality` assert, and the provenance
  bundle's `delegated-relay` scenario (the *same* occurrence manifest bytes
  plus a second attestation differing only in uploader) — all in the DoD
  fast lane. Plan §7.4's **concurrent relay/origin tests** (RD-05) re-prove
  the same separation under racing writers.

### RD-03 — Scope-union escalation

**STRIDE:** Elevation of privilege · **Disposition:** Mitigated

- **Threat.** A relay holding legitimate authority in several dimensions
  tries to assemble an unauthorized one: (a) union over grants — granted
  (origin A, harness `h1`) and (origin B, harness `h2`), it presents A under
  `h2` or B under `h1`; (b) union with its own record — the relay's
  linked-client allowlist permits `h3`, so it presents A under `h3` even
  though no grant mentions `h3`; (c) union across tenants — linked in tenants
  1 and 2, granted only in tenant 1, it presents tenant-2 occurrences; (d)
  permissive matching — reading a grant for `claude-code` as covering
  `claude-codex` by prefix or wildcard; (e) union over epochs — reading an
  old broad epoch together with the current narrow one.
- **Attacker position.** A legitimately linked, legitimately delegated relay
  stretching aggregate authority — the strongest in-scope position, needing
  no key compromise. The operator granted each dimension honestly; the
  attack is the *composition*.
- **Affected contract.** Plan §5 (the conjunction sentence — the norm this
  finding attacks); the delegation record contract (one current object per
  (relay, origin) pair; scopes intersected with the relay's own
  linked-client allowlists, "intersected, never added to"; closed enums;
  withdrawn scopes inert); plan §7.4 (the harness grammar
  `[a-z0-9][a-z0-9._-]{0,63}` — no wildcard token, exact-string semantics);
  EC-03 (never merge on the upstream UUID alone — origin scoping); ID-005.
- **Mitigation and enforcing tests.** The conjunction holds by
  construction, not by evaluation discipline. There is exactly one current
  record per (relay, origin) pair under one tenant, so there is no set of
  grants a reader or writer could union over (a); the harness check is
  membership in the single grant's allowlist *and* the relay's own
  linked-client allowlist — both must contain the attempt's harness (b);
  the tenant dimension is the control-prefix namespace the record lives
  under, and a mismatched tenant fails key resolution and the reader's
  re-made segment check — cross-tenant failures are IA-06's territory
  (`invalid-cross-tenant-forbidden` → 403) (c); the grammar cannot express
  a wildcard and matching is exact (d); only the current pointer epoch is
  read, and a rolled-back one is refused by the strictly-increasing epoch
  rule (e; RD-06). Enforced by the **delegation** test class negative
  vectors (Phase 3): out-of-scope harness, cross-origin, and cross-tenant
  relay attempts each fail closed; today the corpus pins the grammars and
  the tenant dimension these checks consume (`valid-cross-tenant-second`,
  `invalid-cross-tenant-forbidden`, the closed harness vocabulary).
- **Residual.** None — v1's `operations` enum contains exactly `ingest`, so
  no operation dimension exists to escalate *to* until the enum grows, at
  which point each new token ships with its readers (fail-closed on
  unknowns) and this finding's test class extends with it.

### RD-04 — Replay of a withdrawn or narrowed delegation

**STRIDE:** Spoofing · **Disposition:** Mitigated; ≤60-second residual
accepted

- **Threat.** The operator withdraws a delegation (or narrows its scopes at
  a higher epoch) and the relay keeps presenting the origin's occurrences:
  (a) inside the trust-record cache window; (b) by replaying a captured
  signed request from before the withdrawal; (c) mid-request — a withdrawal
  that lands after step-3 verification but before commit, the delegation
  twin of IA-11. The mirror case: the relay's *own client* is revoked while
  its grants stay active, and it relies on the grants alone.
- **Attacker position.** The relay itself — genuine key and, until
  withdrawal, genuine authority; for (b), any capture of one of its signed
  requests. No control-plane access needed.
- **Affected contract.** Plan §5 (trust records cache at most 60 seconds;
  withdrawal is a strictly higher-epoch current-pointer replacement;
  revocation's maximum 60-second propagation bound — the same cache covers
  delegation records); the delegation record (`delegation_state: withdrawn`
  grants nothing regardless of scopes; "propagation of a revision or
  withdrawal is bounded by the reader's trust-record cache, never by an
  expiry here"; a revoked relay "fails closed through its own pointer and
  revocation record regardless of how active its grants are"); EC-09;
  Phase 3 exit gates; requirements ID-006, ID-007.
- **Mitigation and enforcing tests.** Withdrawal publishes a signed
  higher-epoch record at the same key carrying `delegation_state:
  withdrawn`; readers re-read within 60 seconds, and a withdrawn record
  fails the RD-01 conjunction (state ≠ active) with 401/403. A grant has no
  validity window to stretch — currency is the pointer epoch, and a
  rolled-back pointer is refused by the monotonic-epoch check (RD-06). A
  captured request must additionally clear the five-minute per-attempt
  authorization window (IA-03/IA-04), which bounds variant (b) harder than
  the cache bounds variant (a). The revoked-relay mirror needs no
  delegation-specific rule: the relay's own linked-client pointer and
  revocation record gate every attempt before the grant is consulted.
  Enforced by the **delegation** and **revoked** test classes (plan §5) and
  Phase 3's exit gates ("unauthorized relay requests fail closed";
  "Revocation takes effect on every healthy replica within 60 seconds").
- **Residual (accepted).** Uploads accepted in the ≤60-second cache window
  — and in-flight requests past step 3, as in IA-11 — remain in the
  archive. This is the plan's stated bound, not a new tolerance, and the
  archive keeps complete attribution for everything accepted: the
  attestation names `uploader_client_id` = the relay and server-derived
  `delegation: relay`, so the operator can identify and govern the affected
  occurrences afterward. **Owner:** tenant operator (withdrawal decision
  and follow-up), with the `archivist-server` owner (Phase 4) for
  cache-expiry enforcement; the mid-request race mirrors IA-11's acceptance
  (`archivist-server` owner, accepted by the SEC working group, revisit at
  the Phase 11 independent threat-model review).

### RD-05 — Concurrent origin/relay upload of one occurrence (EC-05A)

**STRIDE:** Tampering / denial-of-service · **Disposition:** Mitigated by
design

- **Threat.** Origin and relay upload the same source occurrence
  simultaneously (or near-simultaneously on different replicas), aiming to
  (a) make one side's write clobber the other's provenance, (b) fork one
  source event into two divergent "occurrences", or (c) turn the race into
  an `integrity_conflict` that blocks the source — a denial-of-service
  against the origin's archive via its own relay.
- **Attacker position.** No attacker is required — this is the legitimate
  concurrency EC-05A names, and it is a *required-behavior* row, not merely
  a threat. An attacker influences it only by inducing racing retries
  (EC-04's territory) or, as RD-08, by racing fabricated content against
  the origin's genuine upload.
- **Affected contract.** EC-05A ("Keep one occurrence plus one attestation
  per frozen uploader/request; never let uploader fields overwrite the
  occurrence"); EC-04; plan §7.4 (uploader and request never enter
  occurrence identity — the rejection rationale names concurrent
  authorized uploaders; enforced-by list names **concurrent relay/origin
  tests**); plan §7.7 (deterministic overwrite is logically idempotent and
  may create a noncurrent physical version under concurrency; receipts
  report `created` / `already_present` / `replaced_equivalent` /
  `logically_committed_unknown_physical_result`); requirements STO-002,
  STO-004, STO-013; OPS-007 (tests must cover relay upload).
- **Mitigation and enforcing tests.** Both writers derive the identical
  blob and occurrence keys from source-stable fields, and the occurrence
  bytes are uploader-independent, so the race converges rather than
  conflicts: whichever commit lands first stands, the other reports
  `already_present` (read-capable profile) or rewrites byte-identical
  canonical content (`replaced_equivalent` or
  `logically_committed_unknown_physical_result`) — a conflict requires
  *incompatible* content (EC-06), and both sides produce identical bytes.
  The attestations differ by construction (`attestation_id` folds in
  uploader and frozen request), so both land beside each other under
  distinct keys: one occurrence, two attestations, two compatible receipts.
  Divergence appears only if one side's canonical bytes actually differ —
  and then the occurrence IDs differ too (`blob_digest` is an
  occurrence-hash input), so there is no shared key to fight over and no
  fork at one identity. Enforced by plan §7.4's **concurrent relay/origin
  tests**, together with Phase 4's identical-request/concurrent-retry
  replica gate and OPS-007's relay-upload fault-injection shapes. Pinned
  today, sequentially, by corpus `valid-relay-upload` — whose receipt
  (blob and occurrence `already_present`, attestation `created`) is exactly
  the shape a racing origin/relay pair converges to — and by the provenance
  bundle's `multiple-attestations-one-occurrence` scenario (the origin's,
  the relay's, and a re-frozen request's attestations coexisting on one
  occurrence; a retry of any *one* frozen request rewrites its identical
  object rather than adding a fourth).

### RD-06 — Forged, transplanted, or rolled-back delegation record

**STRIDE:** Spoofing / elevation of privilege · **Disposition:** Forged and
transplanted records mitigated; tenant-authority compromise accepted
(IA-07(b))

- **Threat.** Attack the grant rather than the attempt: (a) plant a
  delegation record authorizing a relay of the attacker's choosing;
  (b) transplant a genuine record — swap the object-key segments so the
  reverse pair is read as granted, replay the record under another
  tenant's control prefix, or replay it as a different record type
  (client, rotation, revocation); (c) roll the current pointer back to a
  pre-withdrawal epoch after the operator withdraws; (d) self-delegation —
  a client grants itself.
- **Attacker position.** Write access to the control prefix — a compromised
  `ControlAdminStore` credential, a mis-scoped storage identity, or a
  storage-backend compromise: the same position as IA-07(a). The
  transplant variants (b) need only *read* access to a genuine record plus
  write somewhere it can be re-served from.
- **Affected contract.** Plan §5 (control records are
  tenant-authority-signed; the control adapter derives each key from the
  validated record type, rejects overwrite of an incompatible immutable
  record, and permits current-pointer replacement only when the signed
  epoch strictly increases; ingest replicas never receive the admin
  credential; the ingestion writer identity cannot reach the control
  prefix at all); the delegation record (`record_type` domain separation —
  "a delegation can never be replayed as a client, rotation, or revocation
  record or the reverse"; the tenant/relay/origin members must equal their
  object-key segments, order-sensitive, which "keeps a swapped key from
  being read as the reverse grant"; self-delegation rejected as a
  cross-field check; closed shape with no member for key material,
  SEC-006).
- **Mitigation and enforcing tests.** A planted or altered record fails
  tenant-authority signature verification at load; a transplanted record
  fails the segment-equality checks (its members do not match the key the
  reader derived) or the tenant namespace it lands in; a cross-type replay
  fails `record_type` domain separation; a rolled-back pointer fails the
  strictly-increasing epoch rule; a self-grant is refused at write time by
  the admin store. The data plane cannot self-authorize any of this: the
  ingestion writer identity has no control-prefix access whatsoever, so a
  compromised raw credential cannot mint or move a grant (plan §5's stated
  reason for tenant-signed records). Enforced by the **altered** and
  **stale**-epoch test classes applied to control records (plan §5; Phase 3
  exit gate "stale-epoch … fail closed") plus §7.7's incompatible-object
  tests; `tools/check-control-schemas.py` proves the control-record
  family's closed shapes and cross-field rules in the DoD fast lane.
- **Accepted risk (authority compromise).** A holder of the tenant
  authority key mints valid grants at will — the same root-of-trust
  acceptance as IA-07(b), of which this is the delegation face; recovery
  is the Phase 7 runbooks (re-link, rotate, re-delegate under a new root).
  **Owner:** tenant operator, with the `archivist-auth` owner (Phase 3) for
  the verification path. Not re-argued here; see IA-07.

### RD-07 — Relay identifier substitution (re-minted synthetic IDs and
identity divergence)

**STRIDE:** Tampering / spoofing · **Disposition:** Mitigated — divergence
only, aliasing prevented

- **Threat.** The relay re-identifies the material it presents: (a)
  re-mints a fresh adapter-synthetic session ID for an occurrence whose
  capture had none (or replaces a real upstream ID with a minted one),
  forking one source session into phantom occurrences; (b) normalizes —
  NFC/NFD, case-folding, trimming — the upstream session or artifact ID;
  (c) launders a path- or hostname-derived identifier as
  `id_source: upstream` (or the reverse); (d) crafts an identifier to alias
  *another client's* session, exploiting a cloned harness UUID (EC-03's
  case). Goals: split the origin's history to hide content, manufacture a
  cover session, or blur which client captured what.
- **Attacker position.** An authorized relay — the one party that re-freezes
  and re-presents envelopes it did not capture. For (d), any uploader
  observing another client's harness session UUIDs, which are not secret
  and never were (SID-002).
- **Affected contract.** Plan §7.4 (no case-folding or Unicode
  normalization; a missing harness session ID is an adapter-minted UUIDv4
  with `id_source=synthetic`, "never inferred from a path name";
  `session_hash = H("session-v1", tenant, origin_client, harness,
  upstream_session)`); EC-03; requirements ID-002, SID-001, SID-002;
  protocol §2.1 (no-normalization rule; NFC and NFD lookalikes are
  distinct sessions).
- **Mitigation and enforcing tests.** Session identity is namespaced by
  tenant, origin client, harness, and the verbatim upstream session string,
  so relay-side re-identification cannot *alias* the origin's existing
  identity — it can only produce a distinct `session_hash`, hence a
  distinct `occurrence_id`, stored as a separate object attributed through
  the relay's own attestation. Divergence is therefore visible in the
  archive (two occurrences, one relay-attested) and never a silent merge,
  overwrite, or shadow of the genuine one — RD-02's structure applied to
  identifiers. `id_source` records which kind of identifier a session
  carries, so variant (c) either contradicts the recorded provenance or
  mints a value that hashes to a distinct identity. The origin-scoped
  namespace contains cloned UUIDs (EC-03), so variant (d) creates a second
  session under the *attacker's* origin scope, not an alias of the
  victim's. Enforced by plan §7.4's **synthetic-ID tests** — pinned today
  by corpus `valid-synthetic-session-id` and the NFC≠NFD derivation
  vectors, re-proven by `--verify` — and EC-03's distinct-identity tests;
  the identifier-escape mechanics these build on are PI-06's findings and
  test classes. Residual: the archive guarantees a diverging relay is
  *attributable*, not invisible; whether one diverged is an audit question
  (comparing relay-attested sessions against the origin's own), accepted
  with RD-08.

### RD-08 — Authorized relay fabricating occurrences under the origin's
identity

**STRIDE:** Spoofing / repudiation · **Disposition:** Accepted risk, bounded
by attribution, containment, and scope (PI-07's delegation face)

- **Threat.** Inside a live grant's scopes, the relay uploads occurrences
  the origin never captured — fabricated or altered content attributed to
  the origin's client ID, harness, and plausible session coordinates. This
  is the deepest relay threat: delegation authorizes *presentation*, and
  the ingest plane has no way to verify the relay received exactly what the
  origin froze.
- **Attacker position.** An authorized relay — an insider. The trust
  decision was the tenant operator's (Phase 3: delegation exists "for
  approved relays"); the protocol's job is to keep the abuse attributable
  and contained, which is what the plan locks.
- **Affected contract.** ID-005 (the grant and its non-replacement rule);
  STO-013 (a distinct authorized uploader/request remains separately
  auditable); SID-006/STO-010 (provenance separation); plan §5 (the
  harness/operation conjunction bounding the fabricatable namespace);
  plan §7.4 (range coordinates and the blob digest inside occurrence
  identity); STO-011 (the raw namespaces carry everything a rebuild or
  audit needs).
- **Bounding properties and enforcing tests.** Three contract properties
  bound the damage. *Attribution*: every object a relay writes carries an
  attestation naming `uploader_client_id` = the relay and server-derived
  `delegation: relay` — the relay cannot launder its uploads as `direct`
  (RD-01), so any auditor holding the control records can tell relay path
  from origin path; the signed receipt's authorization key/epoch is
  after-the-fact evidence of which relay key committed it. *Containment*:
  a fabrication aimed at a genuine occurrence's coordinates carries a
  different `blob_digest`, hence a different `occurrence_id` (the digest is
  an identity input), so it lands *beside* the genuine object, never over
  it — and if the relay later presents the genuine bytes, they converge
  with the origin's object (EC-05A/RD-05) rather than standing as a
  contradiction; the genuine key itself is protected by EC-06. *Scope*:
  the grant's harness allowlist bounds which namespaces can be targeted at
  all, and narrowing it propagates within the RD-04 bound. The attribution
  and containment proofs are the corpus and provenance vectors cited in
  RD-02 and RD-05; the fabrication acceptance itself is PI-07's, restated
  here for the delegated shape.
- **Accepted risk.** Nothing at ingest time verifies that relay-presented
  content matches what the origin captured; the plan's model is attribution
  plus operator trust in the delegated relay, not content attestation by
  the origin. Detection is downstream — comparing relay-attested
  occurrences against the origin's own uploads and spool — and the raw
  namespaces are rebuild- and audit-sufficient for that comparison
  (STO-011). **Owner:** tenant operator (the delegation decision and its
  periodic review — grant narrowly, withdraw on doubt), accepted by the
  SEC working group, aligned with PI-07's owner; revisit at the Phase 11
  independent threat-model review.

## Cross-cutting controls relied on above

- Data-plane/control-plane split (plan §5): the ingestion writer identity
  cannot read, delete, or reach the control prefix, and the admin store
  cannot touch raw data — a relay with a *compromised raw credential*
  cannot manufacture, widen, or retract its own grant (RD-06).
- Control records carry no key material, and their closed shapes plus the
  banned-name gate leave no member for material to ride in (SEC-006) — the
  delegation record grants a relation, never a second key.
- Fail-closed error taxonomy (plan §7.8): every delegation failure is the
  `authorization` class — 401/403, pause uploads, no receipt, content-safe
  message — so a rejected relay neither retries into acceptance nor learns
  scope contents from the error.
- Content-free telemetry (plan §11; SEC-004): authorization and delegation
  failures log bounded error codes, never scope or session values; the
  delegation path cannot become a disclosure channel (receipts-and-
  disclosure owns that domain).
- Deterministic identity and convergence (plan §7.4, §7.7; STO-004): the
  same machinery that makes retries safe makes relay re-presentation
  safe — RD-02, RD-05, and RD-07's containment are one property viewed
  from three angles.

## Coverage and disposition register

| ID | Finding | STRIDE | Disposition | Enforcing test class | Owner of residual |
|---|---|---|---|---|---|
| RD-01 | Unauthorized or out-of-scope relay writing as an origin | S/E | Mitigated | delegation (+ Phase 3 unauthorized-relay fail-closed; corpus `valid-relay-upload`) | — |
| RD-02 | Relay overwriting source provenance | T | Mitigated | corpus `valid-relay-upload` + `ascii-baseline-relay-pair` + provenance `delegated-relay`; concurrent relay/origin (RD-05) | — |
| RD-03 | Scope-union escalation | E | Mitigated | delegation (Phase 3 negative vectors; corpus tenant/grammar pins) | — |
| RD-04 | Withdrawn/narrowed delegation replay | S | Mitigated; ≤60 s residual accepted | delegation + revoked (Phase 3 gates) | tenant operator; `archivist-server` owner (cache expiry) |
| RD-05 | Concurrent origin/relay upload (EC-05A) | T/D | Mitigated by design | concurrent relay/origin (§7.4) + Phase 4 concurrent-retry + OPS-007; corpus/provenance pins | — |
| RD-06 | Forged/transplanted/rolled-back delegation record | S/E | (a–d) mitigated; authority compromise accepted (IA-07(b)) | altered + stale-epoch on control records; `check-control-schemas.py` | tenant operator (authority compromise) |
| RD-07 | Relay identifier substitution / synthetic-ID re-minting | T/S | Mitigated (divergence attributable; aliasing prevented) | synthetic-ID (§7.4; corpus `valid-synthetic-session-id`, NFC≠NFD) + EC-03 | — (audit visibility: RD-08) |
| RD-08 | Authorized relay fabricating origin-attributed occurrences | S/R | Accepted (attribution + containment + scope) | — (bounded by RD-01/02/05 proofs; PI-07 alignment) | tenant operator; SEC working group |

Acceptance check for this document: the bead's five mandated threats are
each documented — an unauthorized or out-of-scope relay writing as an origin
(RD-01), a relay overwriting source provenance (RD-02), scope-union
escalation (RD-03), replay of a revoked delegation (RD-04, withdrawal being
v1's revocation of a grant), and concurrent origin/relay uploads of one
occurrence (RD-05) — plus the delegation-record attack surface (RD-06) and
the relay-specific identifier and fabrication faces (RD-07, RD-08). Every
finding carries either an enforcing test class from plan §5's or §7.4's
enforced-by lists — **delegation**, **synthetic-ID**, **concurrent
relay/origin**, with the unauthorized-relay fail-closed gate of Phase 3 —
with today's corpus and provenance proofs named where they exist, or an
explicitly accepted risk with a named owner; and no finding introduces a
contract that plan §5, §7.4, §7.7, EC-05A, or the cited schemas do not
state.
