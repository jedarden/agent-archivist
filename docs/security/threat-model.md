# Threat model — agent-archivist ingestion and archive path

Status: top-level index and accepted-risk register, consolidating the four
Phase 1 domain documents · Last updated: 2026-09-12

Authority: the [implementation plan](../plan/plan.md), whose Phase 1
deliverables name this artifact ("A threat model covering spoofing, replay,
cross-tenant writes, digest confusion, decompression bombs, poisoned
manifests, and metadata leakage") and whose Phase 1 exit gate fixes the line
it must close: "The threat model has a mitigation or explicitly accepted risk
for every finding." The findings live in four domain documents under
`docs/security/threats/`, each interpreting the plan and the normative
[requirements](../notes/requirements.md) without introducing new contract;
this document indexes them, consolidates their registers into one, and
introduces no contract of its own. It is owned by the **SEC working group** —
plan §16's traceability table makes the Security (`SEC`) requirement group's
verification owner "Threat model, scans, adversarial tests", and the domain
documents shorten that owner to *SEC working group* throughout.

## Scope

In scope: threats against the ingestion path (`POST /v1/ingest`) and the
control records that gate it — uploader identity, replay, cross-tenant
writes, trust-record and delegation-record integrity; payload integrity and
resource exhaustion — digest confusion, decompression bombs, limit abuse,
chunk-boundary manipulation, poisoned manifest fields, poison-input queue
behavior; relay and delegation abuse — unauthorized or out-of-scope relay,
scope-union escalation, withdrawn-delegation replay, provenance overwrite,
concurrent origin/relay upload; and the acknowledgement, observability, and
retention surfaces — receipt trust, receipt-key rotation, object-key and
metadata enumeration, metadata leakage through logs/status/metrics/error
bodies, and retention/deletion abuse. This is the plan's Phase 1 deliverable
list plus the relay and receipt surfaces the same plan sections fix.

Out of scope, owned elsewhere:

- Downstream consumption of stored content — prompt injection, trust
  classification, and the derived data plane's redaction pipeline
  (`redaction-v1`, `rules-v1`) — SEC-009 and Phase 10 governance. The domain
  documents contain the boundary notes; the derived layer's own defenses are
  the Phase 10 contracts.
- Transport protection below the HTTP contract (SEC-001 baseline), and
  network-level volumetric floods or cross-replica aggregate spend below it —
  the deployment perimeter, per PI-04's accepted residual.
- Client capture internals beyond what the ingest contract fixes (spool,
  chunk boundaries, retries, queue discipline); harness-side capture threats
  are separate work, not part of this protocol threat model.

## Method

Each domain document derives its findings the same way, and this register
inherits that method:

- **STRIDE per finding.** Every finding is classified against the six STRIDE
  categories — **S**poofing, **T**ampering, **R**epudiation, **I**nformation
  disclosure, **D**enial of service, **E**levation of privilege — applied at
  each trust-boundary crossing of the path: uploader→server (identity),
  signer→canonical bytes (payload), relay→origin (delegation),
  server→client (receipts), and service→diagnostics (disclosure).
- **Attacker position first.** Findings name the strongest realistic position
  the threat requires (unlinked peer, on-path capture, linked client,
  authorized relay, key-holding server, storage reader, offline operator)
  before the mitigation, so the strength of each mitigation is checkable
  against the position it must defeat.
- **Disposition taxonomy.** *Mitigated* — an enforcing test class pins the
  mitigation. *Mitigated by design* — a plan-fixed structural property
  (deterministic identity, idempotent convergence, identity separation) makes
  the attack inert, with tests pinning the property. *Accepted* — the
  residual is a bound or trust decision the plan already states; every
  accepted risk names an owner.
- **Test-class citation.** Findings cite the plan's enforced-by test classes
  (plan §5, §7.4, §7.6, §7.8, §7.10, §10) plus the phase whose suite renders
  them executable — Phase 1 conformance corpus and derivation vectors,
  Phase 3 auth negatives, Phase 4 fuzz/limit/shutdown gates, Phase 5
  spool/receipt suites, Phase 6 adapter oracles, Phase 8 restore sample,
  Phase 10 retention gates. Where a proof is executable today, the register
  names it (conformance corpus scenarios, provenance bundle, fast-lane
  checker gates in [`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh)).
- **Owner vocabulary.** Owners are drawn from existing vocabulary only: the
  **SEC working group** (plan §16 Security verification owner — owner of this
  threat model); the crate owners of the
  [crate ownership map](../notes/crate-ownership.md) — `archivist-protocol`
  (Phase 1), `archivist-storage-s3` (Phase 2), `archivist-auth` (Phase 3),
  `archivist-server` (Phase 4), `archivist-client-core` (Phase 5), the
  adapter owners (Phase 6); and the **tenant operator**, who performs a
  tenant's control-plane and offline actions (linking, revocation, rotation,
  delegation, key custody, storage-read scoping, backup credentialing, the
  deletion workflow).

The consolidated register below is the authoritative index: a finding's full
argument — threat, attacker position, affected contract, mitigation detail —
stays in its domain document, but the register row alone carries the
disposition, the enforcing test class or the accepted risk, and the owner of
every residual, so the Phase 1 exit gate is verifiable from this file alone.

## Domain documents

| Document | Findings | Domain |
|---|---|---|
| [Identity and access threats](threats/identity-access.md) | IA-01 … IA-11 | Uploader key spoofing, request/envelope replay, cross-tenant writes, trust-record forgery, registry outage, rotation overlap |
| [Payload integrity and resource exhaustion](threats/payload-integrity.md) | PI-01 … PI-08 | Digest confusion, decompression bombs, limit and slot exhaustion, chunk-boundary manipulation, identifier poisoning, fabricated provenance, poison-input queues |
| [Relay delegation and provenance threats](threats/relay-delegation.md) | RD-01 … RD-08 | Unauthorized/out-of-scope relay, provenance overwrite, scope-union escalation, withdrawn-delegation replay, delegation-record attacks, relay identifier substitution, relay fabrication |
| [Receipt trust and metadata disclosure](threats/receipts-and-disclosure.md) | RMD-01 … RMD-07 | Forged/unsigned/false receipts, rotation and stale-key trust, enumeration, leakage through logs/status/metrics/errors, retention and deletion abuse |

## Consolidated register

Thirty-four findings, one per row, each with its enforcing test class (a
tested mitigation) and/or its explicitly accepted risk and owner. An owner of
"—" means no residual: the finding is fully mitigated and tested.

| ID | Finding | STRIDE | Disposition | Tested mitigation — enforcing test class | Accepted risk — owner |
|---|---|---|---|---|---|
| IA-01 | Unlinked uploader identity | S | Mitigated | **altered**; Phase 3 unlinked fail-closed (plan §5) | — |
| IA-02 | Altered request / authorization transplant | T | Mitigated | **altered** — altered multipart, JSON reorder; golden signed-envelope vectors, standalone verifier (§7.2; Phase 1) | — |
| IA-03 | In-window replay | R/D | Mitigated by design | identical-request / concurrent-retry convergence (EC-04, STO-004; Phase 4) | Replay amplification (bandwidth, decompression, storage I/O) — SEC working group; `archivist-server` owner enforces the §7.6 limits |
| IA-04 | Stale replay outside window | S/R | Mitigated | **stale**; Phase 3 replay-expired fail-closed | — |
| IA-05 | Clock-skew window stretching | T | Accepted | — (bounded by IA-03/IA-04 convergence and IA-08 revocation tests) | Composed window-plus-skew acceptance horizon — SEC working group; composition question recorded for the Phase 11 review |
| IA-06 | Cross-tenant write | E | Mitigated | **cross-tenant** (plan §5; §7.4; Phase 3) + tenant-prefix-escape property test (§10) | — |
| IA-07 | Forged trust record / tenant-authority compromise | S/E | (a) mitigated; (b) accepted | **altered** + **stale**-epoch on control records (plan §5; Phase 3); incompatible-object tests (§7.7) | (b) Authority-key compromise is the plan-locked root of trust — tenant operator; `archivist-auth` owner for the verification path |
| IA-08 | Revoked client during propagation | S | Mitigated; residual accepted | **revoked** + 60-second propagation test (plan §5, §14; Phase 3) | Uploads accepted in the ≤60 s window remain archived, governed by provenance — tenant operator; `archivist-server` owner for cache expiry |
| IA-09 | Registry outage downgrade | E/D | Mitigated | **registry-outage** (plan §5; EC-09) + Phase 4 readiness contract | — |
| IA-10 | Rotation overlap abuse | S | (a) accepted; (b) mitigated | **rotation-with-pending-spool** + **stale**-epoch (plan §5; Phase 3) | (a) Compromised old key verifies for the 24 h overlap; revoke cuts it in 60 s — tenant operator; `archivist-auth` owner for epoch enforcement |
| IA-11 | Mid-request revocation race | S | Accepted | — (bounded by the 15-minute deadline, size caps, deterministic provenance, receipt-recorded key/epoch) | Verification-precedes-commit order leaves the in-flight request standing — `archivist-server` owner, accepted by the SEC working group; Phase 11 review |
| PI-01 | False content address (declared digest/size mismatch) | T | Mitigated | Digest/checksum/decompressed-length mismatch conformance (§10); incompatible-existing-object (§7.4); incompatible-object (§7.7); golden blobs (§7.6) | — |
| PI-02 | Canonical-versus-stored digest confusion | T | Mitigated | Cross-platform golden blobs; digest/checksum mismatch conformance (§10); incompatible-object (§7.7); Phase 8 deterministic restore sample | — |
| PI-03 | Decompression bomb | D | Mitigated | **Decompression fuzzing** + **limit-boundary tests** (§7.6); adversarial 100:1 benchmark (§10); Phase 4 fuzz/RSS gates | — |
| PI-04 | Resource-slot exhaustion within bounds | D | Mitigated; aggregate accepted | **Limit-boundary tests** (§7.6); Phase 4 shutdown/drain gate; Phase 2 multipart-abort lifecycle | Aggregate cross-replica spend and sub-HTTP floods are deployment-layer — SEC working group records the acceptance; tenant operator owns the perimeter |
| PI-05 | Chunk-boundary manipulation | T | Containment mitigated; source-truth accepted | Chunk-boundary selection + oversized-record unit/property (§10); adapter round-trip and byte-parity oracles (Phase 6); poison-continuation (§7.8) | Server cannot verify declared ranges against source bytes — SEC working group, with the adapter owners and `archivist-client-core` owner for honest-client machinery |
| PI-06 | Identifier poisoning of identity and keys | T | Mitigated | **Golden ID/key vectors**, **arbitrary-Unicode properties**, **synthetic-ID tests**, incompatible-existing-object (§7.4); tenant-prefix-escape property (§10) | — |
| PI-07 | Fabricated provenance in the manifest | S/R | Accepted | — (attribution via the signed envelope and separate upload attestation; EC-06 containment) | Archive stores attributed assertions, not verified source truth — SEC working group; downstream trust classification is Phase 10 |
| PI-08 | Poison-input queue stall / conflict overwrite loop | D/T | Mitigated | **Error/action matrix**, **poison-continuation**, **lost-receipt**, **partial-commit** (§7.8); §7.9 disk-pressure and bounded-starvation tests | — |
| RD-01 | Unauthorized or out-of-scope relay | S/E | Mitigated | **Delegation** negatives (plan §5; Phase 3 unauthorized-relay fail-closed); corpus `valid-relay-upload` pins the positive face | — |
| RD-02 | Relay overwriting source provenance | T | Mitigated | Corpus `valid-relay-upload` + derivation `ascii-baseline-relay-pair` + provenance `delegated-relay`; **concurrent relay/origin** tests (§7.4) | — |
| RD-03 | Scope-union escalation | E | Mitigated | **Delegation** negative vectors (Phase 3); corpus tenant and harness-grammar pins | — |
| RD-04 | Withdrawn or narrowed delegation replay | S | Mitigated; ≤60 s residual accepted | **Delegation** + **revoked** (plan §5; Phase 3 gates) | Withdrawal propagates on the 60 s cache bound; in-flight race mirrors IA-11 — tenant operator; `archivist-server` owner for cache expiry |
| RD-05 | Concurrent origin/relay upload (EC-05A) | T/D | Mitigated by design | **Concurrent relay/origin** tests (§7.4); Phase 4 concurrent-retry gate; OPS-007 relay fault shapes; corpus and provenance pins | — |
| RD-06 | Forged/transplanted/rolled-back delegation record | S/E | (a–d) mitigated; authority compromise accepted | **Altered** + **stale**-epoch on control records (plan §5; Phase 3); `tools/check-control-schemas.py` shape proofs | Authority-key compromise is IA-07(b)'s delegation face — tenant operator; `archivist-auth` owner for the verification path |
| RD-07 | Relay identifier substitution / synthetic-ID re-minting | T/S | Mitigated — divergence attributable, aliasing prevented | **Synthetic-ID tests** (§7.4; corpus `valid-synthetic-session-id`, NFC≠NFD vectors); EC-03 distinct-identity tests | — (audit visibility of divergence is accepted with RD-08) |
| RD-08 | Authorized relay fabricating origin-attributed occurrences | S/R | Accepted | — (bounded by the RD-01/02/05 attribution-and-containment proofs) | Ingest cannot verify relay-presented content matches the origin's capture — tenant operator (delegation decision and review), SEC working group; Phase 11 review |
| RMD-01 | Forged or unsigned receipt acceptance | S/T | Mitigated | **Authority-chain** + **receipt-signature** (§7.8; Phase 4); corpus chains with bit-flip rejection and the independent verifier | — |
| RMD-02 | Signed-but-false receipt | S/R | Bounded; residual accepted | **Partial-commit** + **lost-receipt** (§7.8; T-RCPT-001/005); §7.10 restore drill (OV-OPS-008); corpus `valid-retry-after-window` | A key-holding server can sign false receipts until the next inventory freeze — tenant operator (evidence cycle); `archivist-server` owner (complete-commit envelope); SEC working group |
| RMD-03 | Receipt rotation and overlap abuse | S/T | Mitigated | **Receipt-key-rotation** (§7.8; Phase 3); corpus overlapping-window cohorts; `check-control-schemas.py` constants | — |
| RMD-04 | Stale signer-key trust | S/R | In-flight mitigated; retained forging accepted | **Authority-chain** + **receipt-signature** + corpus rotation pins; the accepted face has no enforcing test by definition | Retired keys forge inside their 37-day window forever; no v1 authority rotation — tenant operator (key custody, post-incident audit); `archivist-auth` owner; SEC working group |
| RMD-05 | Object-key and metadata enumeration | I | Identity content mitigated; structural residual accepted | Golden ID/key vectors + NFC≠NFD (§7.4); enumeration contract per backend profile (OPS-006); fixtures/corpus content scans | Key namespace is structural metadata (clients, harnesses, counts, sizes, timing) — tenant operator (storage-read scoping, backup credentialing); SEC working group |
| RMD-06 | Metadata leakage through logs, status, metrics, errors | I | Mitigated (machine-checked); aggregate accepted | **Error/action matrix** + **poison-continuation** (§7.8); ERR-041 forced-error content-freedom; MET-043 cardinality bounds; fast-lane gates `check-error-codes` / `check-wire-schemas` / `check-metrics`; T-VAL-007, T-SEC-004, T-OPS-004/005 | Aggregate telemetry discloses coarse activity patterns — SEC working group, with `archivist-server` and `archivist-client-core` owners for the emitting surfaces |
| RMD-07 | Retention and deletion abuse | T/E | Mitigated; operator residual accepted | **Two-pass GC simulation**, **legal-hold**, **retained-reference**, **deterministic rebuild** (§7.10; Phase 10); T-SEC-007/008; T-STO-011; OV-OPS-008 | A compromised offline administrator can still delete shared blobs; correlated failure domains carry the documented risk — tenant operator (deletion authority, evidence cycle); SEC working group |

## Accepted-risk register

The explicitly accepted risks in one place — the parent criterion's second
arm. Every row names the plan-stated bound being accepted, what contains it,
and the owner; each expands a row above whose disposition says "accepted".

| ID | Accepted risk | Containment (plan-fixed) | Owner |
|---|---|---|---|
| IA-03 | Replay inside the window costs bandwidth, decompression, and storage I/O for bytes already stored | Logical idempotence (EC-04, STO-004); 60 req/min/client token bucket, four in-flight per client, 15-minute deadline (§7.6) | SEC working group; `archivist-server` owner (limits) |
| IA-05 | Composed window-plus-skew acceptance horizon, up to ~2–3× the nominal five-minute window | Replay stays idempotent; IA-04 rejects past the composed horizon; 60 s revocation (IA-08); client clock-sanity check (Phase 5) | SEC working group |
| IA-07(b) | Tenant-authority signing-key compromise defeats trust-record verification for that tenant | Plan-locked root of trust (§15 item 3); data plane cannot self-authorize; recovery via Phase 7 runbooks | Tenant operator; `archivist-auth` owner |
| IA-08 | Uploads accepted in the ≤60 s revocation window remain archived | Complete provenance and receipt-recorded key/epoch for after-the-fact governance | Tenant operator; `archivist-server` owner (cache expiry) |
| IA-10(a) | A compromised old key keeps verifying for the 24-hour rotation overlap | Revocation cuts a key within 60 s regardless of overlap; monotonic epochs refuse stale ones | Tenant operator; `archivist-auth` owner |
| IA-11 | A revocation landing between verification and commit does not stop the in-flight request | 15-minute deadline and size caps; deterministic provenance-bearing commits; receipt records the accepting key/epoch | `archivist-server` owner; accepted by SEC working group |
| PI-04 | Aggregate spend across replicas and sub-HTTP volumetric floods | Controls are per process/replica by plan statement ("not a billing or tenant-wide quota"); deployment perimeter | SEC working group; tenant operator (perimeter) |
| PI-05 | Declared range coordinates cannot be checked against real source bytes | Fabricated ranges create distinct deterministic occurrences — attribution without overwrite or aliasing (§7.4; EC-06) | SEC working group; adapter owners; `archivist-client-core` owner |
| PI-07 | Manifest provenance is attributed assertion, not verified source truth | Whole envelope inside the signature (non-repudiable); separate attestation; fabricated manifests land at new keys; consumers treat raw data as untrusted (SEC-009, Phase 10) | SEC working group |
| RD-04 | Withdrawn-delegation uploads accepted in the ≤60 s cache window (and in flight) | Attestation names the relay with server-derived `delegation: relay` for after-the-fact governance | Tenant operator; `archivist-server` owner |
| RD-06 | Authority-key compromise mints valid grants (IA-07(b)'s delegation face) | Same root-of-trust acceptance; record shape and segment checks contain everything short of authority compromise; Phase 7 runbooks | Tenant operator; `archivist-auth` owner |
| RD-08 | Ingest cannot verify relay-presented content matches what the origin captured | Attribution (relay-named attestations), containment (distinct occurrence IDs, EC-06), scope (harness allowlist, 60 s narrowing) | Tenant operator; SEC working group |
| RMD-02 | A receipt-key holder can sign false acceptance evidence until the next inventory freeze (longer if the inventory is suppressed or co-tampered) | Complete-commit-only shape; §7.10 evidence cycle — daily signed inventory, independent second failure domain, quarterly sampled restore | Tenant operator; `archivist-server` owner; SEC working group |
| RMD-04 | Retired receipt keys forge receipts inside their 37-day window indefinitely; v1 has no authority rotation or receipt-key supersession | In-flight face gated by the field-by-field spool cross-check; detection external — inventory divergence and audit against control records | Tenant operator; `archivist-auth` owner; SEC working group |
| RMD-05 | The key namespace is structural metadata visible to any bucket reader | Session IDs hashed into keys (existence, not identity); SEC-002 encrypts content; inventory travels offline to an independently credentialed destination | Tenant operator; SEC working group |
| RMD-06 | Aggregate telemetry discloses coarse per-deployment activity patterns | Closed telemetry registry, closed-kind labels, cardinality ceilings; per-source detail lives in the status document, not labels | SEC working group |
| RMD-07 | A compromised or negligent offline administrator can delete shared blobs; correlated failure domains are a documented risk | Deletion identity held by no ingestion replica; 30-day tombstone, two-scan, HEAD revalidation ordering; GC disabled by default; Phase 7 runbooks | Tenant operator; SEC working group |

## Deliverable-list coverage

The plan's Phase 1 deliverable names seven threat families; the umbrella
adds relay abuse and receipt trust. Each maps to findings above:

- Spoofing — IA-01, IA-07, IA-08, IA-10, PI-07, RD-01, RD-04, RD-08,
  RMD-01, RMD-02, RMD-04
- Replay — IA-03, IA-04, IA-05, RD-04
- Cross-tenant writes — IA-06, RD-03
- Digest confusion — PI-01, PI-02
- Decompression bombs — PI-03 (with PI-04 for the resource-exhaustion face)
- Poisoned manifests — PI-05, PI-06, PI-07, RD-07
- Metadata leakage — RMD-05, RMD-06
- Relay/delegation abuse — RD-01 … RD-08
- Receipt trust failure — RMD-01 … RMD-04 (with RMD-07 for the retention
  evidence cycle that answers it)

## Acceptance check

- **Coverage.** The register holds every finding from all four domain
  documents — 34 rows: IA-01…IA-11 (11), PI-01…PI-08 (8), RD-01…RD-08 (8),
  RMD-01…RMD-07 (7) — matching each document's own closing register row for
  row; none missing, none added.
- **Disposition.** Every row carries an enforcing test class (a tested
  mitigation) or an explicitly accepted risk; every accepted risk names an
  owner drawn from the plan §16 vocabulary (SEC working group, crate owners
  per the crate ownership map, tenant operator), and every owner-bearing row
  appears in the accepted-risk register above.
- **Phase 1 exit gate.** "The threat model has a mitigation or explicitly
  accepted risk for every finding" is verifiable from this register alone —
  the per-row test class or accepted-risk/owner pair is the evidence; the
  domain documents carry the supporting argument.
- **No new contract.** This document introduces no requirement, tolerance,
  or mechanism beyond what the plan, the requirements, and the cited
  registries state; where it records an acceptance, the accepted bound is
  the plan's own.
- **Machine check.** Every clause above except "No new contract" (a review
  judgement) is enforced by [`tools/check-threat-model.py`](../../tools/check-threat-model.py)
  in the definition-of-done fast lane: register shape and STRIDE vocabulary,
  row-for-row coverage across the domain registers and the declared ranges,
  the per-row mitigation-or-acceptance rule, accepted-risk register
  expansion with closed-vocabulary owners mapping one to one with the
  owner-bearing rows, backticked crate owners naming real crates, and the
  nine plan-named families each mapping to existing findings.
