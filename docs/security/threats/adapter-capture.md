# Model-adapter capture threats

Status: one of six domain documents feeding the Phase 1 threat model · Last
updated: 2026-09-21

Authority: the [implementation plan](../../plan/plan.md), especially Phase 6
("Harness adapters") with its parity decision and exit gate, the §7.11
edge-case catalog (`EC-01`, `EC-02`, `EC-07`, `EC-08`), and the fuzz and
compatibility-matrix items among the Phase 11 deliverables; the normative
[requirements](../../notes/requirements.md) (`CAP-001` … `CAP-010`,
`SID-003`, `SID-004`, `SEC-004`, `SEC-005`, `SEC-009`, `SEC-010`, `OPS-004`);
and the landed Phase 6D interfaces in
[`crates/archivist-adapter-sdk`](../../../crates/archivist-adapter-sdk) —
the adapter descriptor, the bounded discovery report, the fail-closed
source-fingerprint allowlist, the generation-cause vocabulary, the
content-free status contract, and the conformance suite the committed
`synthetic_conformance` test executes. The retained content-free fleet
inventory ([fleet-source-inventory](../../notes/fleet-source-inventory.md))
is the pre-adapter evidence whose sanitization contract this document
inherits. This document models the capture side of every real-source adapter
before those adapters exist. It introduces no adapter, no harness
compatibility claim, and no new contract.

## Scope

In scope: the capture boundary between a harness's durable session stores
and the canonical artifact stream — how sources are discovered and named,
how growing files are read on complete-record boundaries, how replacement,
truncation, rewind, and incompatible rewrites become generations, how
database sources are opened, projected, and parity-checked, how unknown
fingerprints and unreadable sources fail closed, what adapter surfaces may
disclose, and what a harness's own stored content can do to the parser and
the identity derivation. The attacker may be a hostile or merely misleading
source store (planted roots, rewritten history, hostile record content), the
live harness racing the reader, a misconfigured discovery root, a buggy
adapter state machine, or a support claim made without evidence.

Out of scope here, owned elsewhere:

- Everything downstream of the canonical artifact — spool, envelopes,
  ingest, receipts, storage — `docs/security/threats/identity-access.md`,
  `docs/security/threats/payload-integrity.md`, and
  `docs/security/threats/receipts-and-disclosure.md`. The adapter hands over
  complete-record artifacts; cursor and queue discipline are the client
  engine's (PI-05, PI-08).
- Provider-boundary exact capture — `docs/security/threats/exact-capture.md`.
  An adapter's semantic transcript and an exact artifact are separate
  coverage dimensions and must not repair one another's gaps.
- Downstream consumption of captured content (prompt injection, trust
  classification, redaction) — SEC-009 and Phase 10. This document treats
  source content as untrusted *input to the adapter itself*; the derived
  layer's defenses are the Phase 10 contracts.

## Contract basis

The findings below rely on these plan-fixed controls:

- **Adapter-specific discovery over configured roots.** Discovery runs only
  under explicitly configured, allowlisted roots and exclusions (CAP-001,
  SEC-005); the report is bounded and content-free; a pass ends in one of
  the closed `ScanClassification` values, and status retains the last one —
  a source that stopped being scannable keeps saying why (CAP-010).
- **Complete-record boundaries.** File sources are read only on complete
  record boundaries; an incomplete trailing record waits for a later pass
  (CAP-003, plan `EC-01`). The measurement splits `complete_bytes` from
  `incomplete_tail_bytes`, and the tail is never part of any backlog figure.
- **Read-only, allowlisted, versioned database projections.** A
  database-backed harness's store is opened read-only with a five-second
  busy timeout, schema-checked before querying, and projected onto an
  explicit, versioned field allowlist; wholesale upload is prohibited
  (CAP-004, plan Phase 6B).
- **Generation detection.** Replacement, truncation, rewind, and
  incompatible rewrite start a new UUIDv7 generation and preserve both
  histories (CAP-005, `SID-003`, plan `EC-02`); the cause is one of the
  closed `GenerationCause` values.
- **Fail-closed fingerprints.** Each released adapter embeds the exact
  supported fingerprint allowlist; an unknown fingerprint reads no projected
  content and reports `unsupported` instead of attempting a best-effort
  parse (plan `EC-08`).
- **The parity decision.** File-adapter parity is reconstructing each
  captured generation from its ordered occurrence manifests to exactly the
  complete-record byte prefix of the source snapshot; database-adapter
  parity is identical ordered allowlisted primary keys, row counts,
  null/presence bits, and per-field SHA-256 digests, with large fields
  verified against direct database reads. Non-allowlisted columns are
  neither read nor hashed (plan Phase 6 decision).
- **Bounded records.** A complete record over 256 MiB, or an expansion
  ratio over 100:1, aborts before commit and quarantines locally with a
  bounded reason (plan `EC-07`).
- **The Phase 6 exit-gate test list.** Golden projection tests,
  active-growth tests, source-replacement tests, permission-error tests, and
  missing-root tests per adapter; allowlist tests proving credential tables
  cannot be projected; byte-for-byte reconstruction through the last
  complete record; and a committed compatibility matrix reconciling every
  observed fingerprint as supported or unsupported.

## Pre-claim evidence gate

The following matrix is the implementation gate for every real-source
adapter. The positive evidence marked **present** is executed today by the
committed `synthetic_conformance` test against the SDK's reference adapter;
it proves the SDK contracts, not that any harness adapter passes them. The
negative and fault evidence names the rejection or fault-injection vector
that must exist and pass in the adapter's own suite **before that real-source
adapter is claimable** — before it enters the compatibility matrix or any
support claim. An adapter does not qualify by producing plausible output;
it qualifies when its faults land in the closed vocabularies.

| Capture surface | Required mitigation (plan-fixed) | Present positive evidence | Required negative or fault evidence before the adapter is claimable |
|---|---|---|---|
| File (JSONL) sources — Claude Code, Codex, Pi JSONL | Complete-record capture with content-addressed chunks and a cursor that never passes an incomplete boundary | `complete-records`, `partial-tail`, and `growth` conformance scenarios (**present**) | **partial-record-faults** — concurrent-append and always-torn stores leave the cursor at the last complete boundary, the tail is re-measured next pass, and a record that later completes is captured whole |
| File (JSONL) sources — generation integrity | Identity, digest, tail, and incompatibility signals each close the generation and preserve both histories | `replacement` conformance scenario (**present**) | **rewrite-generation-faults** — truncation, rewind, tail-mismatch, and incompatible-rewrite vectors each produce a distinct correctly-caused generation and never merge histories |
| Immutable single-file sources — Pi durable session files | One object per fingerprinted file; a new generation whenever identity or digest changes | `replacement` conformance scenario (**present**) | **rewrite-generation-faults** — an in-place digest change yields a new generation, not a silent overwrite |
| Database sources — OpenCode | Read-only open, five-second busy timeout, schema-version gate, explicit allowlisted projection | Fingerprint allowlist and projection vocabulary (**contract present**) | **database-contention-faults** — a lock held past the timeout classifies `read-error`, never blocks the harness's own writes, and never fabricates projected content |
| Database sources — projection allowlist | Credential, account, provider-auth, and unrelated cache tables are excluded; non-allowlisted columns are neither read nor hashed | Allowlist vocabulary and parity decision (**contract present**) | **projection-allowlist-negatives** — allowlist tests prove credential tables cannot be projected and a hostile schema cannot widen the projection through joins, views, or renames |
| Database sources — parity | Parity compares independent observations: ordered allowlisted keys, row counts, presence bits, per-field digests; large fields re-read directly | Parity decision (**contract present**) | **parity-mismatch-faults** — truncated fields, reordered or missing rows, altered presence bits, and digest drift fail the oracle and quarantine rather than pass |
| Discovery and inventory surface — every adapter | Allowlisted configured roots, bounded content-free report, one closed classification per pass | `missing-root` and `permissions` conformance scenarios (**present**) | **discovery-fault-negatives** — substituted, excluded, planted, and vanished roots report bounded classifications and never silently widen what is read |
| Source permission boundary — every adapter | Denial is a retained classification distinct from absence; no privilege escalation, no reads beyond configured roots | `permissions` conformance scenario (**present**, honestly skipped where the process bypasses permissions) | **permission-faults** — unreadable, partially readable, and over-privileged deployments classify per source without fabrication or escalation |
| Fingerprint gate — every adapter | Embedded allowlist; unknown fingerprint fails closed as `unsupported` after the header and not one byte more | `unsupported-fingerprint` conformance scenario (**present**) | **unknown-fingerprint-negatives** — a store whose header admits but whose body diverges is caught by record-level gates, and every inventory-observed fingerprint reconciles to supported or unsupported |
| Status and telemetry surface — every adapter | Closed status vocabularies with bounded, content-free fields | `ScanClassification` and `CoverageState` vocabularies (**contract present**) | **content-freedom-negatives** — hostile strings planted in paths, record fields, or fingerprint headers never reach status, inventory, metrics, or error bodies |
| Hostile source content — every adapter | Bounded complete-record parsing; limit breach quarantines with a bounded reason; identifiers derived, never free-form | Record-boundary and digest discipline in `complete-records` (**present**) | **hostile-source-negatives** — fuzzed projections, oversized and malformed records, and hostile identifier content quarantine or classify rather than crash, allocate unboundedly, or contaminate keys |
| Support-claim gate — compatibility matrix | A real-source adapter is claimable only with every applicable gate row's negative/fault evidence passing | The adapter descriptor publishing allowlist and capabilities (**contract present**) | **claim-gate-audit** — a support claim without its gate evidence is rejected, and the finding↔test-class mapping is machine-checked in the definitions-of-done fast lane |

This matrix is recorded before any real-source adapter exists. The
conformance scenarios are the SDK's own contracts executed against its
reference adapter; each real-source adapter inherits them by implementing
the suite's subject trait, and its additional negatives are release-blocking
evidence for that adapter's bead. The compatibility matrix may list a
real-source adapter only after both the positive conformance and every
applicable negative set pass (AC-11).

## Findings

### AC-01 — Source discovery manipulated or fabricated

**STRIDE:** Tampering / Spoofing · **Disposition:** Mitigated

- **Threat.** Discovery enumerates account and source roots from
  configuration and well-known locations. A hostile or stale store can
  substitute a root (a symlink, a moved directory, another user's store),
  plant accounts that were never configured, or vanish between passes; a
  discovery bug can fabricate sources that do not exist or silently drop
  configured ones. Capture then reads the wrong bytes, or reports coverage
  for sources it never actually sees.
- **Attacker position.** Local code execution or a misconfigured environment
  able to influence the configured roots or the store layout; the adapter's
  own discovery logic on the bug face.
- **Affected contract.** CAP-001 adapter-specific discovery, SEC-005
  allowlists and exclusions, the bounded `DiscoveryReport`, the
  `root-absent` / `no-database` / `transport-unreachable` classifications,
  and CAP-010's coverage states.
- **Mitigation and evidence.** Discovery reads only under explicitly
  configured, allowlisted roots, and every pass ends in a bounded,
  content-free classification. The `missing-root` scenario proves an absent
  configured root is `root-absent`, not a construction or transport failure.
  The `discovery-fault-negatives` must show substituted, excluded, planted,
  and vanished roots reporting bounded classifications — never a silent
  widening of what is read, never a fabricated source.
- **Residual.** None in the discovery contract; a tenant that configures a
  hostile path has delegated that trust, and SEC-005 is the operator's
  control.

### AC-02 — Partial record captured or boundary advanced

**STRIDE:** Tampering · **Disposition:** Mitigated

- **Threat.** A harness mid-write leaves a torn tail. A reader that splits
  on bytes rather than complete records captures a half record, digests it,
  and advances a cursor past it; the incomplete prefix is then archived as
  if final, and the gap is unrecoverable because the cursor will never
  return.
- **Attacker position.** The live harness racing the reader — normal
  operation, not malice; or a hostile store that always ends mid-record.
- **Affected contract.** CAP-003, plan `EC-01`, `SourceScan`'s
  complete-bytes versus incomplete-tail split, and SID-004's chunk ranges.
- **Mitigation and evidence.** Chunking happens only on complete record
  boundaries; the incomplete tail is measured, never captured, and never
  part of any backlog figure. The `partial-tail` scenario pins the waiting
  behavior. The `partial-record-faults` must show concurrent-append and
  always-torn stores leaving the cursor at the last complete boundary with
  the tail re-measured on the next pass, and a record that later completes
  being captured whole.
- **Residual.** None; a record that never completes is a visible coverage
  gap in status, not silent loss.

### AC-03 — Rewrite, truncation, or replacement mis-generationalized

**STRIDE:** Tampering / Repudiation · **Disposition:** Mitigated; residual
accepted

- **Threat.** A source is truncated, replaced under the same name, rolled
  back, or rewritten in place incompatibly. A reader that misses the
  identity, digest, or tail signals splices new content onto the old
  generation's history — the archive quietly contradicts what the harness
  actually had, which is the exact loss `SID-003` exists to prevent.
- **Attacker position.** The live harness (log rotation, session
  replacement), a hostile store deliberately rewriting history under the
  same name, or a buggy detection state machine.
- **Affected contract.** CAP-005, `SID-003`, the closed `GenerationCause`
  vocabulary (`file-identity-change`, `digest-change`, `truncation`,
  `rewind`, `incompatible-rewrite`, `tail-mismatch`), plan `EC-02`.
- **Mitigation and evidence.** Every detected discontinuity closes the
  generation and opens a UUIDv7 one, preserving both histories; capture
  restarts at the new generation's first complete record. The `replacement`
  scenario pins file-identity detection. The `rewrite-generation-faults`
  must show truncation, rewind, tail-mismatch, and incompatible-rewrite
  vectors each producing a distinct, correctly-caused generation and never
  merging histories.
- **Residual.** Detection is per-pass. A rewrite that lands and reverts
  between two passes is invisible, and a rewrite mid-read yields generations
  from what each pass observed. Containment: per-pass causes preserve both
  histories and parity bounds what any single pass may claim — **adapter
  owners; SEC working group**.

### AC-04 — Live-database lock contention

**STRIDE:** Denial of service · **Disposition:** Mitigated; residual
accepted

- **Threat.** A database-backed harness owns its store. A capture reader
  that opens the store non-read-only, holds long transactions, or waits
  unbounded on locks can block the harness's own writes — capture degrading
  the very session it is capturing, with the hang then misread as the
  harness's fault.
- **Attacker position.** No attacker is required: a normal live harness plus
  a careless reader. The denial-of-service face runs in both directions,
  capture→harness and harness→capture.
- **Affected contract.** CAP-004's read-only open, plan Phase 6B's
  five-second busy timeout, and the `read-error` / `no-database`
  classifications.
- **Mitigation and evidence.** Database sources open read-only with a
  bounded busy timeout and take short, consistent read snapshots. The
  `database-contention-faults` must show a lock held past the timeout
  classifying as a bounded `read-error` — never blocking the harness beyond
  the timeout, never fabricating projected content — and a schema change
  mid-read landing on the fingerprint or parity gates rather than yielding a
  partial projection.
- **Residual.** For the busy-timeout window the read still shares the store
  file with the harness's writer. Containment: read-only mode, the
  five-second bound, and honest classification instead of retries inside the
  window — **adapter owners**.

### AC-05 — Unknown fingerprint parsed best-effort

**STRIDE:** Information disclosure / Elevation of privilege ·
**Disposition:** Mitigated

- **Threat.** A harness upgrades its schema. An adapter that "mostly
  understands" the new layout reads projected fields from wrong offsets or
  keys — misattributed or semantically garbage records — or worse, reads
  credential-shaped fields the old allowlist never named. Best-effort
  parsing turns a routine version skew into silent corruption or disclosure.
- **Attacker position.** Version skew (normal); a hostile store wearing a
  familiar fingerprint header over an unfamiliar body; a downgrade presenting
  old content as new.
- **Affected contract.** Plan `EC-08`'s fail-closed rule, the embedded
  fingerprint allowlist (`FingerprintAllowlist::admit`), the
  `fingerprint-unsupported` classification forcing `Unsupported` coverage,
  and CAP-010's reporting duty.
- **Mitigation and evidence.** An unknown fingerprint fails closed as
  `unsupported` having read no projected content. The
  `unsupported-fingerprint` scenario proves the adapter stops after the
  header line and not one byte more. The `unknown-fingerprint-negatives`
  must show a store whose header admits but whose body diverges being caught
  by record-level gates rather than parsed permissively, and the inventory
  reporting every observed fingerprint as supported or unsupported (the
  Phase 6 exit gate).
- **Residual.** None; unsupported capture is a designed, visible coverage
  gap (CAP-009, CAP-010), not a hidden one.

### AC-06 — Projection allowlist escape

**STRIDE:** Information disclosure · **Disposition:** Mitigated

- **Threat.** A database adapter reads or emits fields outside its
  allowlisted projection — account, token, credential, provider-auth, or
  unrelated cache tables. A schema that relocates credential state into an
  allowlisted-looking table, a projection query with a loose column list, or
  a hostile store whose join paths reach unallowlisted content leaks secrets
  into the archive.
- **Attacker position.** A buggy or over-eager projection; a harness schema
  that moves secrets; a hostile store crafted so allowlisted joins reach
  unallowlisted content.
- **Affected contract.** CAP-004's allowlisted, versioned projection and its
  prohibition on wholesale upload, plan Phase 6B's exclusion list, and the
  parity decision's rule that non-allowlisted columns are neither read nor
  hashed.
- **Mitigation and evidence.** The projection is an explicit, versioned
  allowlist, and the parity hash list is the same allowlist — a column that
  is not projected cannot be smuggled into a digest. The
  `projection-allowlist-negatives` must include the Phase 6 exit gate's
  allowlist tests proving credential tables cannot be projected, and must
  show joins, views, and renames failing to widen the projection.
- **Residual.** None within the projection; a secret the harness itself
  stores inside an allowlisted field is source content, governed by SEC-009
  and the raw-content access policy (the same boundary EC-02 draws for
  provider bodies).

### AC-07 — Silent truncation defeats parity

**STRIDE:** Tampering / Repudiation · **Disposition:** Mitigated

- **Threat.** An export path truncates a large field, or a reader samples
  instead of reading. Row counts look right, digests are computed over
  truncated bytes, and the archive records a complete-looking projection
  that dropped content — parity degenerates into a formality that always
  passes because it compares the adapter against itself.
- **Attacker position.** The harness's own export truncation (bounded
  column output), a hostile store serving short reads, or a parity
  implementation keyed to what the adapter already read.
- **Affected contract.** Plan Phase 6B's rule to verify large fields against
  direct database reads; the parity decision (ordered allowlisted primary
  keys, row counts, null/presence bits, per-field SHA-256; file parity as
  complete-record byte-prefix reconstruction); plan `EC-07`'s quarantine on
  oversize.
- **Mitigation and evidence.** Parity compares independent observations —
  the adapter's projection against direct database reads on the database
  face, and reconstruction from ordered occurrence manifests on the file
  face. The `parity-mismatch-faults` must show truncated fields, reordered
  or missing rows, altered presence bits, and digest drift failing the
  oracle and quarantining rather than passing; the `complete-records`
  scenario already pins byte-prefix reconstruction with digests and ordering
  on the file face.
- **Residual.** None for the captured stream; parity is evidence about what
  was captured, not about what the harness's live interface showed —
  attribution, not verified source truth (PI-07's boundary).

### AC-08 — Permission boundary dishonesty

**STRIDE:** Spoofing / Information disclosure · **Disposition:** Mitigated;
residual accepted

- **Threat.** Two opposite failures. A source the process cannot read is
  treated as absent (coverage lies) or as a crash (capture dies) — or
  silently skipped with no trace. And the inverse: an over-privileged
  process (root, broad ACLs) reads across user boundaries the tenant meant
  to keep, capturing stores it was never pointed at.
- **Attacker position.** A multi-user host where another user's store is
  readable; a deployment run over-privileged; the local operator
  misconfiguring roots.
- **Affected contract.** The Phase 6 exit gate's permission-error and
  missing-root tests; the `permission-denied` classification forcing
  `Failed` coverage; CAP-010's duty to distinguish failed from absent;
  SEC-005.
- **Mitigation and evidence.** A denial is a bounded classification that
  status retains — a source that stopped being scannable keeps saying why —
  distinct from absence and from read errors. The `permissions` scenario
  pins the classification and is honestly skipped where the host's process
  bypasses permissions. The `permission-faults` must show unreadable,
  partially readable (some accounts readable, others not), and over-privileged
  deployments classifying per source without fabrication and without
  escalation: the adapter never raises its privileges and never reads beyond
  the configured roots.
- **Residual.** The filesystem's permission boundary is not the control the
  plan relies on — the configured allowlist is (SEC-005). A deployment run
  over-privileged can read stores only as far as its configuration names
  them; mis-scoped configuration is the **tenant operator**'s residual.

### AC-09 — Adapter-surface metadata leakage

**STRIDE:** Information disclosure · **Disposition:** Mitigated

- **Threat.** Paths, user names, host names, account labels, session IDs,
  counts and timing, or fragments of hostile record content leak through
  adapter status, inventory output, metrics, or error diagnostics — the
  store's existence pattern, and sometimes content itself, escapes the
  content-free contract.
- **Attacker position.** A reader of local status, metrics, or telemetry; a
  hostile store whose strings end up in a diagnostic; a bug that formats a
  path or record value into an error body.
- **Affected contract.** SEC-004, CAP-010's "without exposing transcript
  content", the bounded `DiscoveryReport` and `SourceScan` shapes, OPS-004's
  metric labels, and the fleet inventory's sanitization contract.
- **Mitigation and evidence.** Adapter surfaces carry closed vocabularies
  and bounded fields — classifications, counts, byte sums, and account
  labels taken from configuration, never from source content. The
  `content-freedom-negatives` must show hostile strings planted in paths
  (where the filesystem permits), record fields, and fingerprint headers
  never appearing in status, inventory, metrics, or error bodies. The
  retained fleet inventory — content-free by construction, with
  distinct-value counts instead of values — is the working precedent.
- **Residual.** Aggregate per-source activity (counts, sizes, timestamps)
  remains visible to a local status reader; the acceptance shape is
  RMD-05/RMD-06's — **tenant operator** (local access); **SEC working
  group**.

### AC-10 — Hostile source content against the adapter

**STRIDE:** Tampering / Denial of service / Information disclosure ·
**Disposition:** Mitigated; residual accepted

- **Threat.** Transcript content is attacker-influenced in general — agents
  ingest untrusted material, and a harness stores what the web served it.
  The adapter parses all of it: deep or malformed records, hostile strings
  in identifier-bearing fields, extreme nesting, records crafted to
  maximize decompressed size (plan `EC-07`'s expansion face), absurd or
  duplicate session IDs, control characters. The failure faces are parser
  bugs, resource exhaustion, and contamination of identifiers, keys, or
  telemetry with raw hostile text.
- **Attacker position.** Anyone who can influence what a linked harness
  stores — the strongest realistic position is unlinked content inside a
  linked store; the transcript itself is not trusted merely because the
  store is.
- **Affected contract.** SEC-009 (raw archive data is untrusted input),
  SEC-010 (public tests use synthetic data only), plan `EC-07`'s record
  limits and quarantine, `SID-001`–`SID-004`'s namespaced identity
  derivation, PI-06's identifier-poisoning precedent, and the plan's fuzz
  item covering adapter projections.
- **Mitigation and evidence.** Records are bounded and read only on complete
  boundaries; a limit breach aborts before commit and quarantines with a
  bounded reason (`EC-07`); session and artifact identifiers are derived
  into the namespaced identity and digests, never carried free-form into
  keys or telemetry. The `hostile-source-negatives` must include fuzzed
  projections per the plan's fuzz list, oversized/nested/malformed vectors
  quarantining or classifying rather than crashing or allocating
  unboundedly, and hostile identifier content never reaching object keys or
  diagnostics as raw text.
- **Residual.** An exploitable parser bug in the adapter's own trusted code
  remains possible. Containment: the fuzz gate, record limits and
  quarantine, and capture running unprivileged on the local host only —
  **SEC working group** (fuzz evidence each release); **adapter owners**.

### AC-11 — Unqualified real-source support claim

**STRIDE:** Spoofing / Repudiation · **Disposition:** Mitigated

- **Threat.** A real-source adapter — Claude Code, Codex, OpenCode, or Pi —
  is announced as supported, in the compatibility matrix or a release
  claim, with only golden positive tests or no evidence at all. Tenants
  route real capture to it, and the faults above — partial records,
  uncaught rewrites, unknown fingerprints, credential projections — happen
  in production instead of in the gate. A false support claim is a spoofing
  assertion about coverage.
- **Attacker position.** An impatient implementation, a community adapter
  author, a release process that ships before the gate.
- **Affected contract.** The Phase 6 exit gate ("the committed compatibility
  matrix names every supported source fingerprint"), the plan's Phase 11
  compatibility-matrix publication, CAP-002's supported set, CAP-010's
  honest states, and the adapter descriptor.
- **Mitigation and evidence.** The pre-claim gate above is the binding order
  of operations: every gate row applicable to an adapter's source class must
  carry both its positive conformance and its negative/fault evidence,
  passing, before that adapter is claimable — and the fleet inventory's
  observed fingerprints must each reconcile to supported or unsupported.
  The `claim-gate-audit` is the enforcement class: a support claim without
  its gate evidence is rejected, and the finding↔test-class mapping is
  machine-checked by
  [`tools/check-threat-model.py`](../../../tools/check-threat-model.py) in
  the definitions-of-done fast lane, so the gate cannot silently rot.
- **Residual.** None in the claim contract; a harness changing underneath a
  qualified adapter afterwards is AC-05's fail-closed face, not a false
  claim.

## Cross-cutting controls relied on above

- **Closed vocabularies are the containment layer.** A fault must land in a
  `ScanClassification`, `CoverageState`, or `GenerationCause` name; an
  adapter that fails outside the vocabulary is wrong, whatever its output
  looks like.
- **Status retains the last classification.** A source that stopped being
  scannable keeps saying why, so a silent skip has no place to hide.
- **The SDK is the enforcement point.** Adapters implement SDK contracts,
  and the committed conformance suite executes the positive and fault
  scenarios against the SDK's reference adapter today; a real-source adapter
  inherits the same subject trait, so the gate rides the trait rather than
  reviewer memory.
- **Content-free by construction.** Adapter surfaces carry bounded fields —
  counts, sums, classifications, configured labels — never formatted source
  values; the fleet inventory demonstrates the discipline end to end.

## Coverage and disposition register

| ID | Finding | STRIDE | Disposition | Enforcing test class | Owner of residual |
|---|---|---|---|---|---|
| AC-01 | Source discovery manipulated or fabricated | T/S | Mitigated | `missing-root` scenario (present); **discovery-fault-negatives** | — |
| AC-02 | Partial record captured or boundary advanced | T | Mitigated | `partial-tail` scenario (present); **partial-record-faults** | — |
| AC-03 | Rewrite, truncation, or replacement mis-generationalized | T/R | Mitigated; residual accepted | `replacement` scenario (present); **rewrite-generation-faults** | Mid-read rewrite race is per-pass, not atomic — adapter owners; SEC working group |
| AC-04 | Live-database lock contention | D | Mitigated; residual accepted | **database-contention-faults** | Shared store file for the busy-timeout window — adapter owners |
| AC-05 | Unknown fingerprint parsed best-effort | I/E | Mitigated | `unsupported-fingerprint` scenario (present); **unknown-fingerprint-negatives** | — |
| AC-06 | Projection allowlist escape | I | Mitigated | **projection-allowlist-negatives** | — |
| AC-07 | Silent truncation defeats parity | T/R | Mitigated | `complete-records` scenario (present, file face); **parity-mismatch-faults** | — |
| AC-08 | Permission boundary dishonesty | S/I | Mitigated; residual accepted | `permissions` scenario (present); **permission-faults** | Over-privileged deployments bounded only by the SEC-005 allowlist — tenant operator |
| AC-09 | Adapter-surface metadata leakage | I | Mitigated | **content-freedom-negatives** | Coarse local activity patterns, RMD-05/RMD-06's shape — tenant operator; SEC working group |
| AC-10 | Hostile source content against the adapter | T/D/I | Mitigated; residual accepted | **hostile-source-negatives**; fuzz gate per the Phase 11 fuzz item | Parser-bug residual contained by limits, fuzzing, unprivileged local capture — SEC working group; adapter owners |
| AC-11 | Unqualified real-source support claim | S/R | Mitigated | **claim-gate-audit**; checker-enforced finding↔test-class mapping | — |

Acceptance check for this document: all eleven adapter-capture findings are
represented above, one per named capture threat — discovery, partial
records, rewrites, database locking, unknown fingerprints, projection
allowlists, parity reads, filesystem permissions, metadata leakage, hostile
source content, and the support claim itself. Every finding's enforcing test
class cites at least one `**tagged**` class from the pre-claim evidence
gate, every gate class is cited by at least one finding, and the mapping is
enforced by `tools/check-threat-model.py`. The conformance scenarios marked
present are the SDK's own committed evidence; the named negatives and faults
are mandatory evidence in the adapter's own suite before that real-source
adapter is claimable. No row claims any harness adapter exists, passes, or
is supported, and no row adds a contract beyond the plan, the requirements,
and the landed SDK interfaces.
