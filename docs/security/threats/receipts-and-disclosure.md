# Receipt trust and metadata disclosure threats — acknowledgement and observability path

Status: one of four domain documents feeding the Phase 1 threat model · Last
updated: 2026-09-12

Authority: the [implementation plan](../../plan/plan.md) — primarily Section
7.8 ("Receipts, errors, retries, and poison artifacts", whose fixed sentences
are that receipts are authority-authenticated acceptance evidence a client
verifies offline before acknowledging, and that metrics record bounded error
codes, never messages derived from source content), Section 7.10
("Retention, backup, rebuild, and deletion", which fixes the evidence cycle a
receipt's claim of durability is checked against), Section 11 (the
content-freedom controls — no transcript body, prompt, response, tool output,
key, or credential in logs, metrics, traces, panics, fixtures, snapshots, or
CLI arguments), and Section 12 (client status without session text or raw
paths; server signals without sensitive labels), with Section 7.5 (object
keys), Section 7.7's commit contract, and the Section 7.11 edge-case catalog
(`EC-04`, `EC-07`, `EC-10` above all) cited where a claim depends on them —
the normative [requirements](../../notes/requirements.md) (`RCPT-*`, `ID-009`,
`SEC-004`, `SEC-006`–`SEC-008`, `VAL-007`, `OPS-001`, `OPS-004`, `OPS-005`,
`OPS-008`, `CAP-006`, `CAP-010`), the error contract
([error conventions](../../notes/error-codes.md) and
[`tools/error-codes.toml`](../../../tools/error-codes.toml)), the telemetry
contract ([metrics conventions](../../notes/metrics.md) and
[`tools/metrics.toml`](../../../tools/metrics.toml)), the control trust
family ([control trust](../../notes/control-trust.md),
[`schemas/v1/control-receipt-key.json`](../../../schemas/v1/control-receipt-key.json)),
the receipt wire contract
([`schemas/v1/ingest-receipt.json`](../../../schemas/v1/ingest-receipt.json)),
the error wire contract
([`schemas/v1/ingest-error.json`](../../../schemas/v1/ingest-error.json)),
and the wire contract as pinned in [protocol v1](../../protocol/v1.md)
(Sections 5–7). This document interprets those contracts; it introduces no
new contract. The four domain documents under `docs/security/threats/` are
consolidated into `docs/security/threat-model.md`, whose register must let a
reader verify the Phase 1 exit gate ("the threat model has a mitigation or
explicitly accepted risk for every finding") from the register alone.

## Scope

In scope: receipt trust failure and metadata disclosure — a forged, unsigned,
altered, transplanted, or signed-but-false receipt inducing a client to
acknowledge; abuse of the 30-day/seven-day receipt-key rotation and its
overlap; stale trust in retired signer keys and in the pinned authority root;
enumeration of the object-key namespace, its inventories, and its control
records by a storage-side reader; and leakage of sensitive metadata through
logs, client status output, metrics, spans, error bodies, quarantine reports,
or verification evidence.

Out of scope here, owned by sibling documents and later phases:

- Uploader key spoofing, request replay, cross-tenant writes, trust-record
  forgery, and tenant-authority root compromise —
  `docs/security/threats/identity-access.md`. Its IA-01/IA-02 establish the
  authentication whose success the receipt records; its IA-07(b) owns the
  authority-root compromise acceptance this document cross-references rather
  than re-argues; its IA-10 owns *client-key* rotation overlap (the 24-hour
  `rotationVerificationOverlapHours` window) — a different trust object from
  the receipt-key rotation RMD-03 treats; its IA-11 owns the mid-request
  revocation race whose after-the-fact evidence the receipt's
  `authorization_key_id`/`authorization_epoch` members are.
- Digest confusion, decompression bombs, poisoned manifests, and resource
  exhaustion — `docs/security/threats/payload-integrity.md`. Its PI-06 owns
  the identifier-escape mechanics of object-key construction; RMD-05 covers
  only what a *reader* of the resulting namespace learns. Its PI-08 owns
  poison-continuation mechanics; RMD-06 owns the disclosure face of
  quarantine and gap reporting.
- Relay and delegation abuse — `docs/security/threats/relay-delegation.md`.
- Downstream consumption of archived content — prompt injection, trust
  classification, and the derived-layer redaction pipeline (`redaction-v1`,
  `rules-v1`) — SEC-009 and Phase 10 governance. RMD-06 owns the
  operational-signal surfaces (logs, status, metrics, errors); the derived
  data plane's own disclosure defenses are the Phase 10 contracts.
- Transport protection — SEC-001 baseline; nothing here relaxes it.

### Contract basis

The findings below rely on exactly these plan-fixed mechanisms, restated so
each finding can name what it attacks:

- **The receipt's division of labor.** The receipt is the *only* sanctioned
  home for per-attempt and server material: the successful authorization key
  and epoch and the UTC commit time exist in it and nowhere else — the
  envelope, occurrence manifest, and upload attestation reject those names
  outright (plan §7.5; protocol §5). It is a closed nineteen-member record
  (RCPT-002: identity, server-derived object keys, per-object storage
  outcomes, successful authorization, commit time, authentication), RFC 8785
  canonical, `receipt_version` pinned to 1 with unknown majors failing closed.
- **The two-signature chain.** `receipt-v1`: the tenant-scoped server receipt
  key signs the canonicalization of the receipt with the `signature` member
  removed, *with the embedded certificate inside the covered bytes* — so
  certificate substitution fails the receipt signature before the chain is
  consulted. `receipt-key-v1`: the tenant authority signs the certificate
  record with its `authority_signature` member removed. The client pinned
  that authority root during linking (ID-009), so the chain — pinned root
  over certificate, certificate key over receipt — walks offline, without
  trusting the server transport. The plan rejected "TLS-only or unsigned
  receipts, because they cannot survive endpoint or replica replacement as
  evidence" (plan §7.8).
- **Certificate by value, record by authority.** Every receipt embeds its
  signer's certificate by value; the authoritative original is the immutable
  control record at `tenants/<tenant>/v1/control/receipt-keys/<key_id>.json`,
  written once at its own key ID and never overwritten, whose payload
  members are the certificate's members, proven member-for-member by
  `tools/check-control-schemas.py` so record and certificate cannot fork.
  Private halves enter the server only through secret references and appear
  in no record, file, or argument (SEC-006).
- **Rotation, fixed by two named constants.** A fresh key is certified every
  `receiptKeyRotationDays` (30); each key signs for
  `receiptKeySigningOverlapDays` (7) past its successor's first signing
  instant, so a key's window spans the two summed, 37 days, adjacent windows
  overlap for seven, and *expiry bounds signing only — verification of
  retained receipts never expires* (ID-009). The cross-field checks —
  `valid_until − valid_from` = 37 days, successor `valid_from` =
  predecessor + 30 days, `key_id` = the pinned SHA-256 derivation of
  `public_key` — are re-makeable by any reader from the records alone
  (VAL-002), and the verification-time check is `valid_from ≤ commit_time ≤
  valid_until` against the signed commit time.
- **Complete commits only, one acknowledgement transaction.** A receipt
  exists exactly when the blob, occurrence manifest, and upload attestation
  are all durably accepted (RCPT-001); a partial commit is 503 with no
  receipt, and the identical retry repairs it (RCPT-005; EC-10). The client
  acknowledges only after verifying the authority chain, the receipt
  signature, *and every identity field* against its frozen spool entry —
  tenant, request, occurrence, attestation, digest — re-deriving each object
  key rather than taking the receipt's word (ID-008) and checking the
  certificate's tenant, algorithm, and window. Receipt storage, cursor
  advance, and spool release then happen in one crash-safe transaction, and a
  cursor never advances past data without a durable receipt (CAP-006;
  OPS-001). A receipt for any other request is not evidence for this one
  (ERR-025).
- **The closed error body.** Every error travels as the six-field
  `archivist.error/v1` body, `additionalProperties: false` — "an unbounded
  detail field is an unbounded disclosure surface" (ERR-003, ERR-033) — with
  a pattern-bounded `domain.condition` code (≤ 49 chars), an authoritative
  `retryable` boolean, and a `message` that is a registered template over a
  frozen placeholder allowlist (`version`, `media_type`, `field`, byte and
  count integers), rendered only from charset-constrained values with a
  deterministic bracket fallback, and never carrying transcript, path,
  provider, or identifier content (VAL-007; SEC-004; ERR-011–ERR-014).
  Every `/v1/*` response is machine-readable; an HTML error page is banned
  (ERR-020). Server logs are structured, content-free lines keyed by `code`,
  `request_id`, and `correlation_id`; the error counter is labeled by `code`
  alone (ERR-032).
- **The bounded telemetry registry.** No metric, span, or attribute exists
  that the registry and gate have not agreed on (MET-003): label values are
  closed-kind (`enum` ≤ 128 values, `token` ≤ 32, `boolean`), a signal
  carries at most four labels with a cardinality product ≤ 512, and a label
  naming a correlation identifier, content, or location — `session_id`,
  `blob_digest`, `tenant_id`, `client_id`, `key_id`, `path`, `hostname`,
  `message`, through the full MET-020 list — is forbidden outright and
  pinned in the checker. Tenant and client identity never label metrics
  (MET-021); exemplars are disabled (MET-036); `/metrics` carries no request
  content (MET-037); `error_code` is the only error-derived label (MET-023).
  Per-source detail lives in the client status document, not in labels
  (MET-034).
- **Content-free status and quarantine.** Client status exposes per
  adapter/account counts, bytes, lags, and classified errors "without
  session text or raw paths" (plan §12; OPS-004) under closed result
  schemas (CLI-015); quarantine and coverage gaps are reported with
  bounded, content-free reasons and are durable client state, not log lines
  (ERR-024; EC-07; CAP-010).
- **The hashed key namespace and the retention identity boundary.** Raw
  upstream session IDs are hashed in object keys; all key segments are
  validated opaque IDs or hashes, and source paths and hostnames never
  become unsanitized key components (plan §7.5). Tenant authorization
  precedes object-key construction (SEC-003). The ingestion write identity
  holds raw-prefix write and control-prefix read only; deletion belongs to a
  separate identity no ingestion replica receives — "there is no request,
  hostile or malformed, that reaches a delete path" (plan §5, §7.7; protocol
  §7.1). Deletion is an offline workflow — tombstone, legal hold, 30-day
  wait, two full-reference scans ≥ 24 hours apart, `HEAD` revalidation —
  with garbage collection disabled by default and shared blobs never removed
  while a retained occurrence references them (plan §7.10; SEC-008).
  Retention reduction is gated on the evidence cycle: daily signed
  `inventory-v1`, an independent second failure-domain copy or protected
  version history, and a quarterly sampled restore — recorded as
  operational evidence without object paths or identifiers (plan §7.10;
  OPS-008).

Where a finding records an accepted risk, the acceptance is of a bound or
trust decision the plan already states; it is not a new tolerance.
Accepted-risk owners are drawn from existing vocabulary, as in the sibling
documents: the *SEC working group* (plan §16 traceability table's Security
verification owner), the crate owners for the enforcing components —
`archivist-auth` (Phase 3: the authority chain and receipt keys),
`archivist-server` (Phase 4: signed receipts), `archivist-client-core`
(Phase 5: receipts and acknowledgements), per the
[crate ownership map](../../notes/crate-ownership.md) — and the *tenant
operator*, who performs a tenant's control-plane and offline administrative
actions — here most importantly key custody, storage-read scoping, backup
destination credentialing, and the deletion workflow (plan §5, §7.10).

### Enforcing test classes

Plan §7.8's enforced-by list fixes the receipt family — **authority-chain**,
**receipt-key-rotation**, **receipt-signature**, **lost-receipt**,
**partial-commit**, plus the **error/action matrix** and
**poison-continuation** classes; §7.10's adds **deterministic rebuild**,
**two-pass GC simulation**, **legal-hold**, **retained-reference**, and
quarterly **restore-drill evidence**. Phase 3's deliverable names the
rotation mechanism ("clients accept a receipt only through the pinned tenant
authority chain"); the [verification register](../../notes/verification.md)
maps the requirements to owners — `T-RCPT-001`–`T-RCPT-006`
(fault-injection), `T-SEC-004` and `T-SEC-007`/`T-SEC-008`
(security-scans), `T-VAL-007` (protocol-corpus), `T-ID-009`
(auth-conformance), `T-OPS-004`/`T-OPS-005` and `OV-OPS-008`
(operations-exercises).

The positive face of this contract is *pinned executable today*: the
[conformance corpus](../../notes/conformance-corpus.md) carries complete
receipt chains — two tenants, three receipt keys, two commit cohorts inside
overlapping 37-day windows — and `tools/conformancegen.py --verify` (fast
lane of [`scripts/definition-of-done.sh`](../../../scripts/definition-of-done.sh))
re-checks every certificate authority signature and receipt signature with an
independent pure-Python Ed25519 verifier that shares no code with the
signing path, *plus bit-flip rejection cases proving the verifier is not
vacuously accepting*. The disclosure face is machine-checked in the same
lane: `tools/check-error-codes.py --self-test` proves source-derived
placeholders, class drift, and status mismatches are rejected (ERR-040);
`tools/check-wire-schemas.py --self-test` pins the closed six-field body and
the message charset; `tools/check-metrics.py` rejects unregistered,
unbounded, or sensitive labels and cross-checks `error_code` against the
error registry; `tools/check-control-schemas.py` pins the certificate/record
member-for-member agreement, the object-key agreement, and both rotation
constants; the [fixture bundle](../../notes/fixtures.md) content scan proves
public artifacts are synthetic-only (SEC-010); and the corpus's golden error
bodies are checked against the error registry code-for-code. The *negative*
vectors — a forged chain, an out-of-window certificate, a forced partial
commit, a content-bearing message under real malformed input — are the
Phase 3/4/5 suites named above (ERR-041's forced-error content-freedom
assertions, MET-043's cardinality-bound assertions); findings below cite the
test class plus the plan clause it enforces, naming today's corpus and gate
proofs where they exist.

## Findings

### RMD-01 — Forged or unsigned receipt acceptance

**STRIDE:** Spoofing / Tampering · **Disposition:** Mitigated

- **Threat.** An attacker delivers an acceptance the client mistakes for a
  durable one: (a) an unsigned or TLS-only receipt — an impostor endpoint,
  a compromised replica, or an on-path attacker returns HTTP 200 with a
  receipt-shaped body and no valid signature, the exact alternative the plan
  rejected; (b) an altered genuine receipt — bit flips or field swaps in a
  captured receipt, aiming the client's acknowledgement at different
  identities or outcomes; (c) certificate substitution — a genuine receipt
  re-signed or re-presented under a certificate the attacker holds;
  (d) transplant — another tenant's, or another request's, genuine receipt
  presented as evidence for this attempt; (e) a fabricated chain — a
  self-signed certificate or attacker-run "authority". The goal in every
  variant is one thing: the client's cursor advances past data that was not
  durably committed (CAP-006's forbidden state), silently losing history.
- **Attacker position.** Anyone who can produce the client's HTTP response —
  an impostor or compromised endpoint without the tenant's keys, an on-path
  attacker, a malicious replica. This is deliberately the weakest-position
  attacker the receipt machinery exists for: the plan's stated reason for
  signing receipts at all is evidence "independent of the current TLS
  endpoint or replica" (RCPT-006). Attackers holding genuine keys are
  RMD-02's position, not this one.
- **Affected contract.** Plan §7.8 ("The client acknowledges only after
  verifying the authority chain, receipt signature, and every identity
  field"; rejected: "TLS-only or unsigned receipts"); RCPT-002, RCPT-006;
  ID-009; ERR-025; protocol §5.2–§5.3 (the chain, the by-value certificate
  inside the signed bytes, the identity cross-checks, the window check);
  `schemas/v1/ingest-receipt.json` (nineteen required members,
  `receipt_version` failing closed on unknown majors).
- **Mitigation and enforcing tests.** Nothing but a completely verified
  chain acknowledges: the certificate — including its own authority
  signature — is inside the `receipt-v1` covered bytes, so variant (c)
  fails the receipt signature before the chain is even consulted, and the
  chain then requires `receipt-key-v1` verification against the root pinned
  at linking, killing (a) and (e). Variant (b) fails the signature over the
  canonical bytes — any altered member breaks it — and the corpus's bit-flip
  rejection cases prove the verifier is not vacuously accepting. Variant
  (d) fails the field-by-field cross-check against the frozen spool entry:
  tenant, request, occurrence, attestation, and digest must each match the
  client's own frozen request, the object keys must re-derive from those
  identifiers (ID-008), and the certificate's tenant, algorithm, and window
  must agree — a receipt for any other request is not evidence for this one
  (ERR-025). Enforced by the **authority-chain** and **receipt-signature**
  test classes (plan §7.8; Phase 4), with today's corpus pinning the whole
  chain end to end and the independent verifier re-proving it; the
  transplant face additionally rides the corpus's
  `valid-cross-tenant-second` / `invalid-cross-tenant-forbidden` pair, which
  pins the tenant dimension the cross-check consumes.
- **Residual.** None beyond RMD-02's (a key-holding signer) and RMD-04's
  (a retired-but-still-verifying key) positions.

### RMD-02 — Signed but false receipt (acceptance evidence for a
non-durable commit)

**STRIDE:** Spoofing / Repudiation · **Disposition:** Bounded by protocol
shape and after-the-fact evidence; residual accepted

- **Threat.** A server that *holds* the receipt key signs a false claim:
  (a) a receipt over a partial commit — blob or occurrence durably written,
  attestation not — so the client acknowledges and releases spool for
  material that is not fully stored; (b) fabricated storage outcomes —
  `created` or `already_present` asserted for objects never written;
  (c) the repudiation mirror — the server later denies acceptance while the
  client, having trusted the receipt, has already destroyed its local copy.
  The chain verifies perfectly in every variant; this is RMD-01's attack
  run by a signer who cannot be caught by verification.
- **Attacker position.** The ingestion server itself — compromised, buggy,
  or malicious — or anyone who compromises a receipt key's private half
  (which enters only through secret references, SEC-006). The strongest
  realistic position in this document: signature verification is
  *designed* not to stop it.
- **Affected contract.** RCPT-001 (success only after all three objects are
  durably accepted); RCPT-005 (a partial commit is 503 with no receipt, and
  the identical retry repairs it); EC-10; CAP-006 / OPS-001 (a cursor never
  advances past data without a durable receipt); plan §7.10 (the evidence
  cycle — daily signed inventory, an independent second failure-domain copy
  or protected version history, quarterly sampled restore — that gates any
  retention reduction); plan §12's operational objective ("zero
  acknowledged-but-unrecoverable chunks in fault-injection testing");
  protocol §5.1 ("A receipt is evidence of acceptance, and nothing else
  is").
- **Mitigation and enforcing tests.** The protocol shape makes the false
  receipt *narrow* to produce honestly: complete-commit-only means a
  partial state has no success response at all — it is 503
  `server.partial_commit`, and the retry repairs the same occurrence and
  attestation (RCPT-005), so a conforming server that cannot finish says so
  rather than lying. The client's side never trusts a single response's
  durability claim beyond what the receipt binds: acknowledgement is one
  crash-safe transaction keyed to the verified receipt, and the lost-
  response retry receives a *fresh* receipt with identical identity fields
  and converged outcomes (EC-04; corpus proof `valid-retry-after-window`).
  What verification cannot establish, the §7.10 evidence cycle does: the
  daily signed `inventory-v1` freezes what storage actually holds, the
  independent copy (or protected version history) survives a lying primary,
  and the quarterly sampled restore proves it — so variant (b)'s fabricated
  outcomes surface as inventory divergence, and variant (c)'s denial is
  answered by the retained receipt naming the authorization key and epoch
  that accepted (IA-11's audit evidence). Enforced by the **partial-commit**
  and **lost-receipt** test classes (plan §7.8; `T-RCPT-001`/`T-RCPT-005`,
  fault-injection) and the §7.10 restore-drill evidence
  (`OV-OPS-008`); the fault-injection objective above is the acceptance
  line those suites measure.
- **Residual (accepted).** A receipt proves *which key accepted what
  identity fields at what claimed time*; it does not prove storage obeyed,
  and a fully malicious key-holding server can sign false receipts until
  the next inventory freeze exposes the divergence — and a suppressed or
  co-tampered inventory extends that window. The plan's model is detection
  through the evidence cycle, not prevention at verification. **Owner:**
  tenant operator (deployment trust, backup destination credentialing, and
  running the evidence cycle), with the `archivist-server` owner (Phase 4)
  for the complete-commit envelope and the SEC working group for the
  acceptance; revisit at the Phase 11 independent threat-model review.

### RMD-03 — Receipt rotation and overlap abuse

**STRIDE:** Spoofing / Tampering · **Disposition:** Mitigated

- **Threat.** Attack the rotation rather than the receipt: (a) window
  stretching — a certificate with an elongated signing window, extending a
  compromised key's plausible signing range; (b) out-of-window signing — a
  retired key signing receipts dated beyond (or before) its window;
  (c) overlap ambiguity — during the seven-day overlap two keys may sign
  concurrently, and an attempt is made to have a receipt verified against
  the wrong signer, or to paint correct dual-signing as an inconsistency
  that pressures a verifier into skipping checks; (d) re-dating — altering
  a certificate's `valid_from`/`valid_until` after issuance; (e) key
  resurrection — re-certifying a retired key under a fresh record to
  restart its window.
- **Attacker position.** Variant (a), (d), and (e) need control-prefix
  write access — the same position as IA-07(a)/RD-06, whose boundary
  treatment those findings own. Variants (b) and (c) need only a receipt
  key's private half or a captured receipt plus a verifier to fool — the
  client-side face this finding owns.
- **Affected contract.** Plan §7.8 ("Receipt keys rotate every 30 days with
  seven days of old/new signing overlap; old public records remain
  readable indefinitely for retained receipts"); ID-009; the
  `receiptKeyRotationDays`/`receiptKeySigningOverlapDays` constants as
  pinned in the envelope registry, indexed in `tools/control-records.toml`,
  and enforced by `tools/check-control-schemas.py`;
  `schemas/v1/control-receipt-key.json` (immutable write class; the
  `rotationRule` cross-field checks; `key_id` as the pinned SHA-256
  derivation of `public_key`); protocol §5.3 (the by-value certificate and
  the verification-time window check).
- **Mitigation and enforcing tests.** The window is tamper-evident twice
  over: it lives inside the authority-signed record *and* inside the
  receipt-signed certificate, so variants (a) and (d) fail the
  `receipt-key-v1` signature (and the receipt signature, since the
  certificate is covered bytes) — there is no unsigned place to stretch a
  window. A reader re-makes the arithmetic from the records alone
  (VAL-002): span = 37 days, successor = predecessor + 30, `key_id`
  recomputable from `public_key` — so a stretched or gapped schedule is
  detectable by anyone holding two adjacent records. Variant (b) fails the
  verification-time check `valid_from ≤ commit_time ≤ valid_until` against
  the *signed* commit time — a signer cannot shift a receipt into a window
  it was not signed under, because the commit time is covered bytes.
  Variant (e) fails key addressing: a record is written once at the key ID
  derived from its own public key, the admin store rejects an incompatible
  overwrite of an immutable record, and re-certifying the same key
  collides with its own live record — there is no fresh identity to
  resurrect under. Variant (c) is by construction harmless: during the
  overlap *each receipt names its own signer by value*, so verification
  against whichever key signed is the correct path, not an ambiguity — the
  design's stated purpose is that "a receipt issued inside the overlap
  verifies against whichever key signed it". Enforced by the
  **receipt-key-rotation** test class (plan §7.8; the Phase 3 deliverable
  "tenant-scoped receipt-key generation/certification and 30-day rotation
  with seven-day signing overlap"), pinned today by the corpus's two
  commit cohorts inside overlapping 37-day windows across three keys with
  every chain re-verified, and by `tools/check-control-schemas.py` proving
  the two constants, the member-for-member certificate/record agreement,
  and the object-key agreement in the fast lane.
- **Residual.** None beyond the authority-compromise acceptance of
  RMD-04/IA-07(b) — a holder of the authority key certifies elongated
  windows at will, which is that finding, not a rotation defect.

### RMD-04 — Stale signer-key trust

**STRIDE:** Spoofing / Repudiation · **Disposition:** In-flight acceptance
mitigated; retained-evidence forging accepted

- **Threat.** Trust that outlives the key: (a) a *retired* receipt key's
  private half, compromised at any time after retirement, still verifies
  receipts dated inside its 37-day window — forever, because verification
  of retained receipts never expires (ID-009) and old public records
  remain readable indefinitely (plan §7.8, §7.10). Nothing in a receipt
  distinguishes "signed then" from "signed later with the then-valid key":
  the signature carries no freshness proof, and the window check bounds
  the *claimed* commit time, not the signing instant. (b) The pinned
  tenant authority root has no v1 rotation mechanism — the receipt-key
  record's own contract defers authority rotation to a mechanism that does
  not yet exist — so a compromised root certifies fresh receipt keys
  indefinitely, which is IA-07(b)'s acceptance with the receipt chain as
  its payload.
- **Attacker position.** (a) Anyone who obtains a retired receipt key's
  private half — an ex-employee, a key-management lapse, a server
  compromise outside the rotation window's currency. (b) The authority
  root's holder. Neither needs any position on the wire.
- **Affected contract.** ID-009 ("Receipt-key rotation MUST NOT invalidate
  retained receipts" — the deliberate design whose flip side this is);
  plan §7.8 and §7.10 (indefinitely readable old records); protocol §5.3
  ("Expiry bounds signing only; verification of retained receipts never
  expires"); `schemas/v1/control-receipt-key.json` (the
  "once authority rotation exists" deferral); SEC-006 (private halves only
  through secret references); IA-07(b) (the root-compromise acceptance
  this cross-references).
- **Mitigation and enforcing tests.** The in-flight face is gated hard: a
  forged receipt still has to pass RMD-01's field-by-field cross-check
  against a frozen spool entry, so the forger must already possess the
  target request's exact identity fields (tenant, request, occurrence,
  attestation, digest — all re-derived, ID-008) and gains only a false
  acknowledgement of the client's *own* in-flight request, for as long as
  that one spool entry is being retried; and the receipt's
  `authorization_key_id`/`authorization_epoch`
  evidence lets an auditor replay the claimed acceptance against the
  immutable control records and the signed inventory — a forged
  acceptance of material storage never held diverges at the next
  `inventory-v1` freeze. Private-half exposure is minimized by SEC-006's
  reference-only rule, and the retired records' indefinite readability is
  exactly what keeps *genuine* retained receipts verifiable — the exposure
  is the cost of that evidence property, not an oversight. Enforced on the
  in-flight side by the **authority-chain** and **receipt-signature**
  classes plus the corpus's rotation pins (two cohorts, retained
  verification across a rotation boundary); the accepted face has no
  enforcing test by definition.
- **Accepted risk.** Post-compromise forging inside an old key's window is
  undetectable from receipts alone, and v1 offers no authority rotation
  and no receipt-key revocation or supersession path — records are
  immutable and nothing removes a predecessor, by design. Detection is
  external: inventory divergence, occurrence-level audit against control
  records, and the §7.10 evidence cycle. **Owner:** tenant operator (key
  custody across the whole 37-day window and beyond, the linking pin, and
  post-incident audit), with the `archivist-auth` owner (Phase 3) for the
  verification path; accepted by the SEC working group, aligned with
  IA-07(b); revisit at the Phase 11 independent threat-model review, or
  when an authority-rotation contract exists to pin.

### RMD-05 — Object-key and metadata enumeration

**STRIDE:** Information disclosure · **Disposition:** Identity content
mitigated; structural residual accepted

- **Threat.** A reader of the storage — a mis-scoped storage identity, the
  backup destination, an exfiltrated snapshot, or a catalog consumer —
  enumerates the namespace and harvests metadata without ever decrypting a
  blob: tenant IDs, client IDs and harnesses (visible key segments under
  `tenants/<tenant>/v1/raw/occurrences/<origin>/<harness>/…`), session
  cardinality and arrival timing (how many sessions, how often, how
  large), the control topology (who linked, who delegated to whom, who was
  revoked when, the receipt-key lineage), and — from a frozen
  `inventory-v1` or a verification manifest that forgot its content-free
  constraints — the same map pre-aggregated with sizes, ETags, and version
  identifiers. Receipts and attestations are themselves identity maps:
  each receipt reports the three server-derived object keys, and each
  attestation carries occurrence, origin, uploader, and request IDs.
- **Attacker position.** Any holder of storage *read* — the weakest
  position that sees anything, and one the ingestion identities
  deliberately grant in part (the ingestion reader holds control-prefix
  read, whose records are public material by design). No upload, no
  signature, no tenant authorization is needed; enumeration is passive.
- **Affected contract.** Plan §7.5 ("Raw upstream session IDs are hashed in
  object keys for safety and privacy"; "All key segments are validated
  opaque IDs or hashes; source paths and hostnames never become
  unsanitized key components"); plan §7.10 and protocol §7.3–§7.4 (the
  enumeration contract; backup through an offline identity to an
  independently credentialed destination; the verification manifest
  recording "no object paths or identifiers"); STO-012 (derived lineage
  without exposing raw object paths to unauthorized consumers); SEC-002
  (encryption at rest); SEC-003 (authorization before key construction);
  SEC-010 / PUB-002 (public artifacts synthetic-only, no real identifiers
  or bucket names).
- **Mitigation and enforcing tests.** What enumeration *cannot* get: raw
  upstream session or artifact IDs (hashed into `session_hash` before they
  touch a key), source paths and hostnames (never key components),
  transcript content (SEC-002 encryption at rest, and the occurrence
  manifest's upstream identifier is its encrypted form), and anything
  under another tenant's prefix (the namespace is the boundary IA-06
  enforces for writers; for readers, per-tenant scoping is the operator's
  storage-identity configuration). The aggregation surfaces are bounded by
  their own contracts: the inventory is signed and travels only through
  the offline identity to the independently credentialed destination; the
  verification manifest is content-free by construction; derived outputs
  reference occurrence IDs under pipeline-versioned prefixes rather than
  raw paths; the public repo carries only synthetic fixtures, proven by
  the fixture content scan's closed-vocabulary and marker rules. The
  receipt reports keys only to the authenticated requester whose own
  request derived them, and the client re-derives rather than trusts
  (ID-008). Enforced by the §7.4 **golden ID/key derivation vectors**
  (with the NFC≠NFD cases proving no normalization leaks a second form of
  an identifier into a key; PI-06 owns the underlying identifier-escape
  mechanics), the §7.3 enumeration contract's fail-closed rules —
  duplicate and out-of-prefix key rejection — exercised by the storage
  compatibility suite on every backend profile (OPS-006), and the
  fixture/corpus content scans (`--verify` asserts no seed material
  appears anywhere in the bundle).
- **Residual (accepted).** The key namespace is *structural* metadata:
  client IDs, harness names, object counts, byte sizes, and timing are
  visible to any bucket reader by construction — hashing hides session
  *identity*, not session *existence* or volume — and SEC-002 encrypts
  object content, not keys or sizes. An inventory in the wrong hands is a
  complete corpus map. **Owner:** tenant operator (storage-read scoping,
  backup-destination credentialing and access review, per-tenant reader
  isolation), with the SEC working group for the acceptance.

### RMD-06 — Sensitive-metadata leakage through logs, status output,
metrics, or error bodies

**STRIDE:** Information disclosure · **Disposition:** Mitigated
(machine-checked); aggregate-signal residual accepted

- **Threat.** Hostile material rides the diagnostics out: (a) a malformed
  or hostile source crafts content that an error `message` echoes — an
  oversized record's path, a provider's raw error string relayed by an
  adapter, a session ID inside a validation complaint; (b) an
  implementation adds "just one more" detail field, or an intermediary
  substitutes an HTML error page for the machine body; (c) a metric or
  span acquires a high-cardinality or sensitive label — per-session
  counters, digest-keyed series, tenant-labeled error rates — turning the
  time-series database into a metadata mirror of the archive; (d) status
  output includes session text or raw source paths (plan §12's forbidden
  content); (e) a quarantine reason or coverage-gap report carries
  transcript fragments; (f) a log line, panic, or trace dumps a payload or
  an authorization value; (g) fixtures, snapshots, or CLI arguments carry
  real identifiers or secrets; (h) verification and audit evidence (the
  restore sample, the inventory report) records object paths or
  identifiers. Each is an exfiltration channel that needs no storage read
  and no key — only a diagnostic surface that renders attacker-influenced
  input.
- **Attacker position.** A hostile or compromised *source* (the transcript
  producer controls the bytes an adapter and validator process), a hostile
  upstream provider whose error strings an adapter might relay, or a
  careless contributor adding a debug field. The strongest face: the
  attacker chooses the input and simply reads the output back.
- **Affected contract.** Plan §7.8 ("Metrics record bounded error codes,
  never messages derived from source content"); plan §11 / SEC-004 (no
  transcript body, prompt, response, tool output, key, or credential in
  logs, metrics, traces, panics, fixtures, snapshots, or CLI arguments);
  plan §12 (client status "without session text or raw paths"; "Do not
  label metrics with session ID, client hostname, source path, digest,
  request ID, or other unbounded/sensitive values by default" — with the
  registry gate making the rule "machine-checked rather than advisory");
  VAL-007; OPS-004/OPS-005; ERR-003, ERR-011–ERR-014, ERR-020, ERR-032,
  ERR-033, ERR-040; MET-016–MET-023, MET-034, MET-036, MET-037, MET-043;
  CLI-015; ERR-024/EC-07/CAP-010 (bounded quarantine and gap reporting);
  SEC-006 (secrets only by reference); the content-free constraints of the
  verification register.
- **Mitigation and enforcing tests.** Every surface is closed by
  construction, and the closures are gated: the error body is the closed
  six-field `archivist.error/v1` shape with `additionalProperties: false` —
  there is no member for content to ride in — and every `/v1/*` response
  is that body or a defined success shape, never HTML (ERR-020). The
  message is a registered template whose placeholder allowlist is frozen
  (`version`, `media_type`, `field`, byte/count integers), each value is
  validated against its constraint at render time, and a failing value
  renders as its bracketed placeholder name — never verbatim — so no
  `Display` of a path, provider string, payload fragment, or untyped
  error reaches a message (ERR-013, "the encoding of SEC-004 and VAL-007
  at the error boundary"). Codes are pattern-bounded `domain.condition`
  strings; the error counter is labeled by `code` alone, and logs are
  structured content-free lines keyed by `code`, `request_id`, and
  `correlation_id` (ERR-032) — correlation IDs appear as structured
  context, never as labels (MET-023). The telemetry namespace is closed
  (MET-003) with closed-kind labels, cardinality ceilings, at most four
  labels per signal, the MET-020 forbidden-label list pinned in the
  checker, tenant/client identity excluded (MET-021), exemplars disabled
  (MET-036), and no content on `/metrics` (MET-037); a runtime series
  exceeding its declared bound is a test-detected defect (MET-043).
  Status documents carry counts, bytes, lags, and classified errors under
  closed result schemas (CLI-015) with the status document — not a metric
  label — as the sanctioned home of per-source detail (MET-034);
  quarantine and gap reports are bounded and content-free and are durable
  state, not log lines, so a hostile source cannot churn them out of
  visibility (PI-08's durability point). Fixtures and corpus content are
  synthetic-only with a four-rule content scan, the corpus asserts no seed
  material anywhere in the bundle, and no command consumes a secret value.
  Enforced today in the fast lane by `tools/check-error-codes.py
  --self-test` (which proves source-derived placeholder rejection),
  `tools/check-wire-schemas.py --self-test`, `tools/check-metrics.py`, and
  the content scans; the runtime faces land with the Phase 4/5 forced-error
  suites asserting emitted codes against the registry and the
  content-freedom of messages and logs under synthetic malformed input
  (ERR-041), mapped as `T-VAL-007` (protocol-corpus), `T-SEC-004`
  (security-scans), and `T-OPS-004`/`T-OPS-005`
  (operations-exercises).
- **Residual (accepted).** Aggregate signals — accepted bytes, per-code
  error frequencies, latencies, freshness lags, spool use — disclose
  coarse per-deployment activity patterns to telemetry readers; that is
  their function, and per-tenant or per-source alerting is required to be
  derived from the coverage, catalog, and status homes rather than the
  registry (MET-021, MET-034). **Owner:** SEC working group, with the
  `archivist-server` and `archivist-client-core` owners for the emitting
  surfaces' phase gates.

### RMD-07 — Retention and deletion abuse (unsafe removal of shared or
retained data)

**STRIDE:** Tampering / Elevation of privilege · **Disposition:** Mitigated
by identity boundary and workflow; operator residual accepted

- **Threat.** Archive material is destroyed or forged-destroyed out from
  under accepted evidence: (a) a blob is deleted while retained occurrences
  still reference it — shared content loss across every occurrence with
  those canonical bytes (SEC-008's forbidden state), turning past receipts
  into acknowledgements of the unrecoverable; (b) deletion is reached from
  the data plane — a hostile request or compromised replica finding a
  delete path; (c) tombstone or legal-hold records are forged, suppressed,
  or back-dated to force a sweep past a hold, or to evade one; (d) restore
  and backup evidence overstates recoverability (a copy that was never
  verified, a version-history claim on a backend with unknown version
  state), letting retention be reduced on faith; (e) cutover or rollback
  deletes legacy or new data during migration.
- **Attacker position.** (b) needs a request-handling identity — and none
  exists with delete reach; (a), (c), (d) need the offline administrator
  position (or its compromise): the sweep, the tombstones, and the
  evidence cycle are operator workflows by design. (e) needs migration
  access.
- **Affected contract.** Plan §7.10 (the deletion workflow — tombstone,
  legal hold, 30-day wait, two full-reference scans ≥ 24 hours apart, GC
  disabled by default; the backup preconditions — daily inventory,
  independent second failure domain or protected version history,
  quarterly sampled restore; legacy archives read-only ≥ 90 days and until
  a post-cutover drill passes); SEC-007, SEC-008; STO-011 (raw namespaces
  rebuild-sufficient); OPS-008; plan §7.11's anti-patterns (no blanket
  raw-blob lifecycle expiry); protocol §7.1 ("there is no request, hostile
  or malformed, that reaches a delete path, because no request-handling
  identity holds one"), §7.2 (lifecycle rules target noncurrent versions
  only and must not expire current raw objects), §7.5 (the sweep order,
  `HEAD` revalidation, holds blocking regardless of age).
- **Mitigation and enforcing tests.** Variant (b) is excluded by identity,
  not validation: the ingestion write identity holds raw-prefix write and
  control-prefix read only, and the separately configured deletion
  identity is given to no ingestion replica — the attack has no reachable
  surface. Variant (a) is what the workflow ordering exists for: a blob is
  deleted only after a 30-day tombstone age, two complete inventory-freeze
  reference scans at least 24 hours apart, absence from *both*, no
  retained occurrence referencing it, and a `HEAD` revalidation
  immediately before deletion — any changed or unreadable candidate
  survives the pass — and garbage collection is disabled by default, so
  the sweep never runs uninvited. Blanket age-based lifecycle expiry on
  raw prefixes is prohibited outright because it cannot see occurrence
  references (§7.11 anti-patterns; protocol §7.2). Variant (c) meets the
  same control-record defenses as every other control object — signed
  records under dedicated prefixes, written by the offline store, with
  the data plane unable to reach them — plus the hold-blocking rule that
  operates "regardless of tombstone age". Variant (d) is answered by the
  evidence cycle's own shape: the signed daily inventory, the
  deterministic destination sample, the "unknown version state never
  passes" rule, and the quarterly drill recorded as operational evidence
  — recoverability is proven, not assumed, before retention may be
  reduced. Variant (e) is bounded by the 90-day read-only floor and the
  post-cutover drill gate, with cutover and rollback forbidden from
  deleting data. Enforced by the §7.10 test family — **two-pass GC
  simulation**, **legal-hold**, **retained-reference**, and
  **deterministic rebuild** — rendered executable by the Phase 10 exit
  gates, plus `T-SEC-007`/`T-SEC-008` (security-scans), `T-STO-011`
  (compatibility-matrix), and `OV-OPS-008` (the restore-drill
  operational evidence).
- **Residual (accepted).** The sweep is an offline operator workflow: a
  compromised or negligent administrator identity can still delete shared
  blobs — the ordering and the two-scan requirement make accidental loss
  hard, not malicious loss impossible — and a deployment that meets its
  backup precondition with two correlated failure domains carries the
  documented correlated-failure risk the plan names. Recovery for
  authority-adjacent compromise is the Phase 7 runbooks. **Owner:** tenant
  operator (the offline deletion authority and the backup/restore
  evidence cycle), with the SEC working group for the acceptance and
  Phase 10 governance for the executable gates.

## Cross-cutting controls relied on above

- The offline chain (plan §7.8; ID-009): acceptance evidence independent
  of the current endpoint or replica is what makes RMD-01's weakest
  attacker fail and what gives RMD-02's repudiation mirror its answer —
  the same property from two directions.
- Immutability of control records (plan §5; the receipt-key record's
  write-once key addressing): there is no overwrite, supersession, or
  deletion path for a certificate, which is simultaneously why rotation
  never invalidates retained receipts (RMD-03) and why a retired key's
  trust never retires either (RMD-04) — one design decision, both faces
  documented.
- The closed-shape discipline (six-field error body, closed label kinds,
  closed result schemas): every disclosure surface in RMD-06 is closed by
  construction and held closed by a fast-lane gate, so content-freedom is
  a structural property, not a logging convention.
- The identity split (plan §5, §11): raw-write and control-read ingestion
  identities, an offline control administrator, and a separately
  credentialed deletion identity — the boundary that makes RMD-07(b)
  unreachable and that scopes RMD-05's reader exposure to what the
  operator actually grants.
- The §7.10 evidence cycle (signed inventory, independent copy, sampled
  restore): the only machinery that answers what signature verification
  structurally cannot — whether storage actually holds what receipts
  claim (RMD-02, RMD-04's detection, RMD-07's precondition).

## Coverage and disposition register

| ID | Finding | STRIDE | Disposition | Enforcing test class | Owner of residual |
|---|---|---|---|---|---|
| RMD-01 | Forged or unsigned receipt acceptance | S/T | Mitigated | authority-chain + receipt-signature (§7.8; Phase 4); corpus chains + bit-flip rejection + independent verifier | — |
| RMD-02 | Signed-but-false receipt (non-durable acceptance) | S/R | Bounded; residual accepted | partial-commit + lost-receipt (§7.8; T-RCPT-001/005) + §7.10 restore-drill (OV-OPS-008); corpus `valid-retry-after-window` | tenant operator; `archivist-server` owner; SEC working group |
| RMD-03 | Receipt rotation and overlap abuse | S/T | Mitigated | receipt-key-rotation (§7.8; Phase 3); corpus overlapping-window cohorts; `check-control-schemas.py` constants | — |
| RMD-04 | Stale signer-key trust (retired keys; pinned authority root) | S/R | In-flight mitigated; retained-evidence forging accepted | authority-chain + receipt-signature + corpus rotation pins; accepted face untested by definition | tenant operator; `archivist-auth` owner; SEC working group (IA-07(b) alignment) |
| RMD-05 | Object-key and metadata enumeration | I | Identity content mitigated; structural residual accepted | golden ID/key vectors + NFC≠NFD (§7.4); enumeration contract on every backend (OPS-006); fixtures/corpus content scans | tenant operator; SEC working group |
| RMD-06 | Metadata leakage through logs, status, metrics, error bodies | I | Mitigated (machine-checked); aggregate residual accepted | error/action matrix + poison-continuation (§7.8); ERR-041 forced-error content-freedom; MET-043; `check-error-codes`/`check-wire-schemas`/`check-metrics` self-tests; T-VAL-007/T-SEC-004/T-OPS-004/005 | SEC working group (server/client-core owners for phase gates) |
| RMD-07 | Retention and deletion abuse | T/E | Mitigated (identity boundary + workflow); operator residual accepted | two-pass GC simulation + legal-hold + retained-reference + deterministic rebuild (§7.10; Phase 10); T-SEC-007/008; T-STO-011; OV-OPS-008 | tenant operator; SEC working group |

Acceptance check for this document: the bead's five mandated threats are
each documented — forged or unsigned receipt acceptance (RMD-01, with the
signed-but-false face RMD-02 beside it, since verification's honest limit is
where the first threat's mitigation ends), receipt rotation and overlap
abuse (RMD-03), stale signer-key trust (RMD-04), object-key and metadata
enumeration (RMD-05), and sensitive-metadata leakage through logs, status
output, metrics, or error bodies (RMD-06) — plus the §7.10 retention,
backup, rebuild, and deletion surface the bead's scope names (RMD-07).
Every finding carries either an enforcing test class from plan §7.8's or
§7.10's enforced-by lists — **authority-chain**, **receipt-signature**,
**receipt-key-rotation**, **lost-receipt**, **partial-commit**,
**error/action matrix**, **poison-continuation**, **two-pass GC
simulation**, **legal-hold**, **retained-reference**, **deterministic
rebuild** — with today's corpus, gate, and content-scan proofs named where
they exist, or an explicitly accepted risk with a named owner; and no
finding introduces a contract that plan §7.5, §7.8, §7.10, §11, §12, the
cited requirements, or the cited schemas and registries do not state.
