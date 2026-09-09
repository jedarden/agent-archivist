# Payload integrity and resource-exhaustion threats — ingestion path

Status: one of four domain documents feeding the Phase 1 threat model · Last
updated: 2026-09-09

Authority: the [implementation plan](../../plan/plan.md) — primarily Section 7.4
("Identifier and collision rules"), Section 7.6 ("Canonical payload,
compression, chunking, and limits"), and Section 7.8 ("Receipts, errors,
retries, and poison artifacts"), with Section 5's server data flow (the
pre-allocation bound and the validate–stream–abort–commit order), other
contract sections, the §7.11 edge-case catalog (`EC-*`), and phase exit gates
cited where a claim depends on them — and the normative
[requirements](../../notes/requirements.md) (`VAL-*`, `STO-*`, `CAP-*`,
`ID-*`, `SEC-*`, `OPS-*`). This document interprets those contracts; it
introduces no new contract. The four domain documents under
`docs/security/threats/` are consolidated into
`docs/security/threat-model.md`, whose register must let a reader verify the
Phase 1 exit gate ("the threat model has a mitigation or explicitly accepted
risk for every finding") from the register alone.

## Scope

In scope: payload-integrity and resource-exhaustion threats against
`POST /v1/ingest` and the client pipeline that feeds it — digest confusion,
decompression bombs, limit abuse, chunk-boundary manipulation, poisoned
manifest fields, and poison-input queue behavior.

Out of scope here, owned by sibling documents and later phases:

- Uploader key spoofing, request/envelope replay, and cross-tenant writes —
  `docs/security/threats/identity-access.md`. Its IA-06(b) documents the
  identifier-escape mechanism this document's PI-06 shares; the cross-tenant
  consequence stays there and is not repeated as a finding here.
- An uploader asserting an origin it does not own, scope-union escalation, and
  revoked-delegation replay — `docs/security/threats/relay-delegation.md`.
- Receipt trust failure and metadata/log leakage —
  `docs/security/threats/receipts-and-disclosure.md`.
- Downstream consumption of stored raw content — prompt injection, trust
  classification, and compressed content hidden *inside* canonical bytes —
  which is SEC-009 and Phase 10 governance. The server decompresses exactly
  one declared transport encoding per request (plan §7.6); anything nested in
  the canonical bytes themselves threatens derived readers, not the ingest
  path this document covers.

### Contract basis

The findings below rely on exactly these plan-fixed mechanisms, restated so
each finding can name what it attacks:

- **Pre-allocation bounds.** Request headers, the 64 KiB envelope, body size,
  the 15-minute duration, and 16-request process concurrency are bounded
  *before* payload-scale resources are allocated (plan §5 server data-flow
  step 1) — and before authentication, so the bound covers unauthenticated
  requests too. Requirements VAL-003, VAL-008.
- **Validate before resource commitment.** Schema, identifiers, source
  coordinates, encoding, and the declared digest are validated at step 4,
  before streaming writes begin: identifier syntax and length, tenant
  authorization, media type, artifact kind, encoding, declared sizes, range
  consistency, and timestamp bounds (plan §5; VAL-002).
- **Streaming decompress-and-hash.** The body is stream-decompressed and
  hashed while writing *uncommitted* multipart data (step 5). The server
  computes SHA-256 over the canonical uncompressed bytes itself (VAL-004;
  §7.4 `blob_digest = SHA256(canonical_uncompressed_bytes)`) under bounded
  memory (VAL-008).
- **Abort before commit.** The write aborts if size, expansion ratio, media,
  or digest validation fails (step 6; VAL-005: a mismatch must not leave a
  committed blob under the claimed content address). The multipart upload
  completes "only after all sizes, digests, and the request signature verify"
  (§7.7), and when a compatible blob already exists "the server still drains
  and verifies the submitted payload" (§7.7) — no verification short-circuit.
- **One address basis.** Raw blobs are addressed by SHA-256 of canonical
  uncompressed payload bytes (plan §3 fixed decision; STO-001). The envelope's
  "incoming representation checksum" (§7.3) and the stored frame's checksum
  (§7.6) are separate, secondary checks. Stored bytes are produced by the
  server-owned pinned `zstd-v1` encoder — level 3, single-threaded, no
  dictionary, content size and checksum enabled — never by client-chosen
  compression (§7.6; VAL-006).
- **Limits.** Target chunk 16 MiB, single structured record 256 MiB, envelope
  64 KiB, expansion ratio 100:1, request duration 15 minutes, multipart part
  8 MiB, in-flight uploads 16 per process of which at most four belong to one
  client, new-request rate 60/minute/client/replica with burst 8 (§7.6;
  Phase 4). Limits may be lowered by policy; raising a hard cap requires the
  resource/fuzz suite on the same commit (§7.6).
- **Deterministic identity.** Occurrence IDs are SHA-256 over a domain label
  and zero-delimited, length-prefixed fields including the range coordinates
  and blob digest (§7.4); the server derives every object key from validated
  opaque IDs or hashes (§7.5, §7.7; ID-008; SEC-003). An existing object key
  with different canonical content or incompatible identity metadata, when
  found by read-capable ingest or audit, produces `integrity_conflict` —
  HTTP 409 before a receipt, and after a receipt it
  blocks the source/prefix and requires operator action (§7.4; EC-06).
- **Chunking rules.** Adapters chunk on complete-record boundaries and never
  split a structured record to meet the target; a record over 256 MiB is
  quarantined as `record_too_large`, reported as a coverage gap, and never
  silently truncated (§7.6; CAP-003; EC-01, EC-07).
- **Poison taxonomy.** Invalid envelope/media quarantines the artifact and
  continues other sources (400/415); integrity conflict stops the affected
  tenant/source and pages the operator (409); oversized-but-splittable
  rechunks at a record boundary, oversized-unsplittable quarantines (413);
  retryable failures back off with full jitter from one second to a
  15-minute cap with no arbitrary attempt limit (§7.8).

Where a finding records an accepted risk, the acceptance is of a bound or
trust position the plan already states (for example that the per-client rate
limit is "a resource guard, not a billing or tenant-wide quota"); it is not a
new tolerance. Accepted-risk owners are drawn from existing vocabulary: the
`SEC` verification owner (plan §16 traceability table) for the threat model
itself, shortened to *SEC working group* below; the crate owners of the
[crate ownership map](../../notes/crate-ownership.md) —
`archivist-protocol` (Phase 1: validation, deterministic identifiers, object-key
derivation), `archivist-storage-s3` (Phase 2: `zstd-v1` commits,
validate-before-complete multipart), `archivist-server` (Phase 4: bounded
middleware, streaming, fuzz gates), `archivist-client-core` (Phase 5: spool,
retries, queue), and the adapter owners (Phase 6: chunk boundaries and parity
oracles); and the *tenant operator*, who deploys the endpoint and performs a
tenant's control-plane actions.

### Enforcing test classes

Plan §7.6 fixes the resource test classes — **cross-platform golden blobs,
decompression fuzzing, limit-boundary tests**, and the RSS ceiling of 512 MiB
at the default 16-request concurrency on the reference four-vCPU runner — and
§7.4 the identity classes — **golden ID/key vectors, arbitrary-Unicode
properties, synthetic-ID tests, and incompatible-existing-object tests**.
Section 7.8 adds the **error/action matrix, poison-continuation,
lost-receipt, and partial-commit** tests; §10's conformance list adds
**content-length, decompressed-length, digest, and checksum mismatch** cases
and §10's unit/property list adds **chunk-boundary selection and
oversized-record behavior**; Phase 4's exit gate adds fuzzed envelopes and
compressed streams that must not "panic, over-allocate, or commit invalid
objects"; and Phase 6 contributes the adapter round-trip and byte-parity
oracles. Tests do not exist yet — Phase 1 delivers the vectors and conformance
corpus, Phase 2 the multipart/abort compatibility suite, Phase 4 the fuzz and
limit enforcement, Phase 5 the queue/spool behavior, Phase 6 the adapter
oracles — so findings cite the test class plus the plan clause it enforces.

## Findings

### PI-01 — False content address (declared digest or size mismatch)

**STRIDE:** Tampering · **Disposition:** Mitigated

- **Threat.** An uploader streams canonical bytes that do not match what it
  declares: the canonical uncompressed SHA-256, the incoming representation
  checksum, or the compressed/uncompressed sizes of different content
  (plan §7.3), or a transport encoding or media type that misdescribes the
  body. The goal is to commit a blob under a digest it does not have —
  poisoning the content-addressed namespace so every present and future
  occurrence referencing that digest reads different bytes — or to pass
  step-4 validation with declared in-bounds values while streaming
  out-of-bounds content.
- **Attacker position.** A malicious or compromised linked client; reaching
  the streaming stage requires passing authorization (plan §5 steps 2–3).
  On-path substitution of a legitimate request's body or envelope is the
  altered-request case IA-02 already covers — the whole-request content
  digest, canonical envelope digest, and payload digests are all inside the
  signature (plan §7.2) — so the interesting position here is the signer
  itself lying.
- **Affected contract.** Plan §7.4 (`blob_digest =
  SHA256(canonical_uncompressed_bytes)`; `integrity_conflict` on incompatible
  existing objects); §5 server data-flow steps 4–6; §7.7 ("completes only
  after all sizes, digests, and the request signature verify"; "When a
  compatible blob already exists, the server still drains and verifies the
  submitted payload"; a preflight HEAD "never treats it as the correctness
  guard"); requirements VAL-002, VAL-004, VAL-005; STO-001, STO-007; EC-06,
  EC-07.
- **Mitigation and enforcing tests.** The server never addresses a blob by a
  declared digest: it recomputes SHA-256 over the canonical bytes it actually
  decoded while streaming (VAL-004) and derives the key from that computed
  digest (§7.7: "The server derives every target key"). Any mismatch —
  including a declared-encoding lie, which makes the decoded canonical bytes
  diverge — aborts the uncommitted multipart write before completion, so
  nothing lands under the claimed address (step 6; VAL-005; EC-07). The
  drain-and-verify rule for already-present blobs closes the short-circuit
  variant (claim an existing digest, send anything, hope the server skips
  verification), and the preflight-HEAD clause keeps the optional read
  optimization from becoming the guard (§7.7; STO-007). An attacker who
  cannot invert SHA-256 cannot make arbitrary bytes match a chosen address,
  and unverified bytes never complete. Enforced by the §10 conformance cases
  "content-length, decompressed-length, digest, and checksum mismatch", the
  incompatible-existing-object tests (§7.4 enforced-by) and
  incompatible-object tests (§7.7 enforced-by), EC-06's
  conflict behavior, and the cross-platform golden blob vectors (§7.6) that
  fix the digest's byte basis across implementations.

### PI-02 — Canonical-versus-stored digest confusion

**STRIDE:** Tampering · **Disposition:** Mitigated

- **Threat.** A component verifies the wrong digest basis. The stored object
  is `zstd-v1` compressed bytes beneath an uncompressed-digest key (plan §7.5
  key shape `blobs/zstd-v1/sha256/<digest>.zst`), and the envelope carries
  several distinguishable integrity declarations (§7.3: canonical
  uncompressed SHA-256, incoming representation checksum, and compressed and
  uncompressed sizes). A verifier that hashes the
  stored zstd bytes and compares them to the content address, treats the
  transport checksum or the zstd frame checksum (§7.6: "content size and
  checksum enabled") as proof of canonical identity, or reports
  `already_present` from bare existence, will either accept corrupted or
  mismatched bytes as verified content or manufacture false conflicts. A
  malicious uploader probes for exactly this confusion — for example
  declaring a representation checksum that matches whatever it sends while
  the canonical digest field names other content.
- **Attacker position.** An implementation defect is the primary vector — no
  attacker is required for the failure; a linked client probes and exploits
  one once it exists.
- **Affected contract.** Plan §3 ("Raw blobs are addressed by SHA-256 of
  canonical uncompressed payload bytes"); §7.3 (canonical digest and incoming
  representation checksum as distinct envelope fields); §7.6 (pinned
  server-owned `zstd-v1` encoder; "Rejected: client-specific gzip/zstd output
  under one key"); §7.7 (capability model `stored_checksum`; "conditional
  existence without readable compatible metadata is not reported as
  `already_present`"); requirements VAL-006, STO-001, STO-005.
- **Mitigation and enforcing tests.** The address basis is a locked decision
  (§3), so there is exactly one digest that names a blob, and the Phase 4
  pipeline runs decompression, uncompressed hashing, and the stored-byte
  checksum as separate computations over the same stream — each check
  verifies what it claims. The server-owned pinned encoder removes
  client-side compression variance under one key entirely (§7.6; VAL-006's
  deterministic canonical form), and the zstd frame's embedded content size
  and checksum give the *stored* object its own integrity check without ever
  being promoted to content identity. Deduplication honesty is contractual:
  `already_present` requires readable compatible metadata, and the capability
  matrix reports `stored_checksum` as observed, never converting an unknown
  result into a stronger guarantee (§7.7; §10 storage-compatibility report
  rule; STO-005). Enforced by the
  cross-platform golden blobs (§7.6 enforced-by), the digest and checksum
  mismatch conformance cases (§10), the incompatible-object tests (§7.7
  enforced-by), and the Phase 8 deterministic restore sample — required at
  100% success on MinIO, B2, and ARMOR (plan §12 initial operational
  objectives) — which exercises read-side decompression-and-verify of stored
  frames against the canonical address.

### PI-03 — Decompression bomb against the size and expansion-ratio ceilings

**STRIDE:** Denial of service · **Disposition:** Mitigated

- **Threat.** The classic compression bomb: a small transport body that
  expands enormously, with declared sizes kept inside the caps so step-4
  validation passes. Targets are ingest-process memory, multipart buffer and
  disk, and CPU (a bomb tuned for decompression cost rather than size). This
  is the plan's own risk-register row "Compression bomb | M | H | Resource
  exhaustion | Size/ratio/time/concurrency bounds and fuzzing" (§14).
- **Attacker position.** A linked client, and — because the body streams
  before the whole-request signature can complete (plan §7.2: the server
  "may pre-authorize the key ID before receiving the body, but does not
  commit storage until it verifies the complete signature and payload", and
  the complete signature covers the whole-request content digest) — also a
  sender that reaches the streaming stage without holding the key. The bomb
  defenses therefore must not, and do not, depend on authentication: the
  abort conditions fire on the bytes the decoder actually produces. This is
  the volumetric face IA-01's residual defers to this document.
- **Affected contract.** Plan §7.6 limits (single structured record 256 MiB,
  expansion ratio 100:1, multipart part 8 MiB; "raising a hard cap requires
  the resource/fuzz suite on the same commit"); §5 steps 5–6; EC-07; §10
  benchmark contract ("adversarial 100:1 input"); Phase 4 exit gates ("Memory
  use is bounded by configured concurrency and multipart buffers, not total
  payload size"; RSS at or below 512 MiB with 16 worst-case uploads; "Fuzzed
  envelopes and compressed streams do not panic, over-allocate, or commit
  invalid objects"); requirements VAL-003, VAL-008.
- **Mitigation and enforcing tests.** Streaming decode with hard abort: the
  uncompressed-size and 100:1 expansion ceilings are enforced against the
  bytes the decoder actually produces during step 5, not against the declared
  values validated at step 4, so a lying declaration buys nothing once the
  stream overruns (VAL-003; EC-07: abort before commit). Decompressed output
  flows only into uncommitted 8 MiB multipart parts, so memory stays bounded
  by part buffers and concurrency regardless of expansion (VAL-008; Phase 4
  exit gate), and the 15-minute request deadline reclaims the slot from
  slow-decompression CPU variants. EC-07 fixes the client-side face too:
  quarantine locally with a bounded reason, report a coverage gap, never
  silently truncate. Enforced by **decompression fuzzing** and
  **limit-boundary tests** (§7.6 enforced-by), the adversarial 100:1 profile
  of the §10 performance budget, and the Phase 4 fuzz exit gate. Any future
  ceiling raise must rerun the resource/fuzz suite on the same commit
  (§7.6).
- **Residual.** Each request's cost is bounded, not zero; cross-request
  aggregate exhaustion is PI-04's scope.

### PI-04 — Resource-slot exhaustion within every per-request bound

**STRIDE:** Denial of service · **Disposition:** Mitigated; aggregate
residual accepted

- **Threat.** An attacker who stays inside every per-request cap still
  occupies shared ingest resources: many maximum-duration slow requests
  holding the 16 in-flight process slots; abandoned or interrupted uploads
  accumulating incomplete multipart state and its storage reservations; a
  flood of unauthenticated requests each consuming the bounded pre-commit
  work (envelope parsing, validation) that IA-01's residual already notes is
  the unauthenticated attacker's only purchase.
- **Attacker position.** Any network peer for the unauthenticated flood and
  the multipart-abandonment variants (abandoned parts stream under §7.2's
  pre-authorization, before a complete signature can exist); a linked client
  for the slot-and-duration variants.
- **Affected contract.** Plan §5 step 1 (headers, envelope, body size,
  duration, and process concurrency bounded before payload-scale
  allocation); §7.6 limits (15-minute duration, 16 in-flight per process,
  four per client, 60 new requests/minute/client/replica with burst 8);
  §7.7 enforced-by ("24-hour orphaned-multipart cleanup") and Phase 2's
  reference profile (incomplete-multipart lifecycle rule; exit gate:
  interrupted uploads "leave no committed content-addressed object and are
  cleanable"); Phase 4 (the token bucket "is a resource guard, not a billing
  or tenant-wide quota"; graceful shutdown drains 30 seconds then aborts
  unfinished multipart uploads and exits nonzero if an abort fails; exit
  gate: shutdown leaves no multipart upload older than the lifecycle
  window); §12 server signals (in-flight requests, concurrency rejection,
  multipart abort failures); §7.8 (408/425/429 rows are retryable, so
  backoff — not persistence — governs the client's share); §11 ("Tight
  limits on … duration, concurrent uploads, and multipart resources").
- **Mitigation and enforcing tests.** Every request, authenticated or not,
  meets the entry bounds first (step 1 precedes authentication), so
  unauthenticated floods cannot allocate payload-scale resources at all.
  The four-per-client in-flight cap bounds one client to a quarter of the
  process's slots, and the per-client token bucket bounds its request rate;
  the 15-minute deadline bounds how long anything holds a slot; orphaned
  multipart state is reaped by the 24-hour lifecycle rule, aborted on
  graceful shutdown, and visible as a metric (§12). Enforced by
  **limit-boundary tests** (§7.6), the Phase 4 shutdown/drain exit gate, the
  Phase 2 multipart-abort and lifecycle compatibility tests, and the §7.8
  rate-limit retry branches in the every-error-branch conformance suite
  (§10).
- **Residual (accepted).** The plan's controls are per process and per
  replica, and it says so explicitly: the token bucket is "not a billing or
  tenant-wide quota" (Phase 4). Aggregate spend across replicas, and
  network-level volumetric floods below the HTTP contract, are outside the
  plan's control set; protecting the endpoint at that layer is a deployment
  concern. **Owner:** SEC working group records the acceptance (plan §16);
  the tenant operator owns the deployment perimeter.

### PI-05 — Chunk-boundary manipulation (split, overlapping, or gapped ranges)

**STRIDE:** Tampering · **Disposition:** Server-side containment mitigated;
source-truth residual accepted

- **Threat.** Occurrences whose range coordinates misdescribe a source: a
  structured record split across two chunks (destroying the source fidelity
  plan §7.6's "never split a structured record" rule protects), overlapping
  ranges (the same bytes counted twice, or a part-plus-whole pair),
  engineered gaps (content silently skipped while coverage looks complete),
  or declared coordinates that simply do not match the payload bytes. A
  related hostile-source variant: records deliberately sized over 256 MiB to
  force quarantine churn or coverage gaps on an honest client.
- **Attacker position.** A malicious linked uploader fabricates chunks
  freely — the server never sees the source. Separately, a hostile or
  corrupted harness source drives an *honest* client: the client's chunker
  is trusted code, but source content chooses record boundaries and sizes.
- **Affected contract.** Plan §7.6 (chunking rules; `record_too_large`
  quarantine); CAP-003; EC-01, EC-07; §7.3 (artifact identity, source
  generation, byte/event range, and ordering fields); §7.4 (occurrence ID
  includes `range_kind, range_start, range_end`; determinism);
  VAL-002 (range consistency before commit); Phase 6 parity decision
  ("reconstructing each captured generation from its ordered occurrence
  manifests yields exactly the complete-record byte prefix of the source
  snapshot"); §10 unit/property list ("Chunk boundary selection and
  oversized-record behavior") and adapter round-trip / file-prefix
  byte-parity tests.
- **Mitigation and enforcing tests.** Client side: chunkers cut only on
  complete-record boundaries (CAP-003; Phase 6A "Parse JSONL only on
  complete record boundaries"), oversized records quarantine rather than
  truncate (§7.6; EC-07), and the Phase 6 parity oracles prove an honest
  client's chunks reconstruct the source byte-for-byte through the last
  complete record (Phase 6 exit gate). Server side: range consistency is
  validated before commit (VAL-002), and the range coordinates sit inside
  the occurrence identity (§7.4), so overlapping, gapped, or re-declared
  ranges produce *distinct* deterministic occurrences — a fabricated chunk
  can never overwrite, alias, or merge with an existing one, and a genuine
  re-upload of the same range converges (EC-04). Enforced by the
  **chunk-boundary selection and oversized-record** unit/property tests
  (§10), the adapter round-trip and byte-parity tests (§10; Phase 6 exit
  gate), and the poison-continuation behavior of §7.8 for hostile sources.
- **Residual (accepted).** No plan clause claims the server can verify that
  declared ranges correspond to real source bytes — source-side truth is the
  uploader's assertion (the trust position PI-07 records). Containment is
  attribution plus determinism: fabricated ranges create new provenance-
  bearing objects and can never corrupt archived ones (§7.4; EC-06).
  **Owner:** SEC working group, with the `archivist-client-core` and adapter
  owners (Phases 5–6) for the parity oracles that keep an honest client's
  chunks faithful.

### PI-06 — Identifier poisoning of occurrence identity and derived keys

**STRIDE:** Tampering · **Disposition:** Mitigated

- **Threat.** A same-tenant poisoning of the manifest identity chain:
  crafted harness IDs, upstream session IDs, or adapter artifact IDs
  (path-like content, oversized strings, case- or Unicode-folded lookalikes
  of a victim session's identifiers) aimed at (a) colliding with another
  session's deterministic occurrence key, (b) escaping or reshaping the
  derived object-key namespaces, or (c) conflating two distinct sessions
  through normalization. Includes misusing the synthetic-ID channel —
  presenting an adapter-minted session ID as harness-native, or poisoning
  the `id_source` marker (plan §7.4).
- **Attacker position.** A linked client of the tenant. The same mechanism
  aimed across the tenant boundary is IA-06 in the identity-access document
  and is not repeated here.
- **Affected contract.** Plan §7.4 (harness IDs match
  `[a-z0-9][a-z0-9._-]{0,63}`; upstream session and artifact IDs are opaque
  UTF-8 of at most 1,024 bytes, neither case-folded nor Unicode-normalized;
  domain-separated, length-prefixed hashing — "length-prefixed opaque bytes
  prevent delimiter, path, case, and Unicode ambiguity"; synthetic-ID rule
  with `id_source=synthetic`, "never inferred from a path name"); §7.5 ("All
  key segments are validated opaque IDs or hashes; source paths and
  hostnames never become unsanitized key components"); §7.7 ("The server
  derives every target key"); §7.1/VAL-001 (unknown versions and
  security-bearing enum values fail closed); requirements ID-008, SEC-003,
  VAL-002.
- **Mitigation and enforcing tests.** Step-4 validation enforces identifier
  syntax and length before any commit (VAL-002), so path-like or oversized
  content is rejected outright rather than sanitized into a key. Identity
  hashes take domain labels and length-prefixed fields, so no delimiter,
  case, or Unicode trick makes distinct field tuples hash equal (§7.4), and
  a deliberate collision requires breaking SHA-256. Keys are assembled by
  the server from validated opaque IDs and hashes only — never from
  uploader-chosen paths (§7.5; ID-008) — and the raw upstream identifiers
  are hashed into key positions with the originals living only inside the
  restricted manifest (§7.5). Because identifiers are *not* normalized,
  lookalikes remain distinct sessions rather than silently merging (§7.4).
  Enforced by **golden ID/key vectors**, **arbitrary-Unicode properties**,
  **synthetic-ID tests**, and **incompatible-existing-object tests** (§7.4
  enforced-by), plus the §10 identifier parsing/bounds unit tests and the
  tenant-prefix-escape property test shared with IA-06.

### PI-07 — Fabricated provenance in the canonical occurrence manifest

**STRIDE:** Spoofing / repudiation · **Disposition:** Accepted risk

- **Threat.** The uploader asserts false source-side facts the server cannot
  check: source, capture, or envelope-creation timestamps; artifact kind and
  adapter projection version; generation numbering; the optional parent
  session, orchestrator attempt, trace, and inference-request correlation
  IDs (plan §7.3). Goals include poisoning derived analytics, misdating or
  misattributing content, and constructing later deniability ("that is not
  my session").
- **Attacker position.** A linked client. The server validates syntax and
  bounds but never sees the source, so truth of these fields is unverifiable
  on this path by construction.
- **Affected contract.** Plan §7.3 (envelope fields and timestamps);
  §7.5 (canonical occurrence fields; uploader, request, discovery/capture,
  authorization, and commit-time fields excluded; the attestation carries
  the uploader-side facts separately); §7.4 ("Hostname is mutable
  provenance and never enters these identities"); requirements STO-010
  (canonical fields must not vary by uploader or upload attempt), STO-013,
  ID-004.
- **Accepted risk.** The archive is a record of *attributed assertions*, not
  verified source truth — a bound the plan states by design when it freezes
  the envelope as immutable and excludes server commit time and per-attempt
  authorization from it (§7.3). Containment, all four clauses plan-fixed:
  the entire canonical envelope is inside the signed material (§7.2; IA-02),
  so fabrication is non-repudiable evidence against the signing uploader;
  the separate upload attestation independently records who uploaded what
  and when (§7.5; STO-013), leaving later disputes two records — the
  asserted provenance and the verified upload event; deterministic identity
  means fabricated manifests land at new keys and can never overwrite
  genuine occurrences (§7.4; EC-06); and derived consumers must treat raw
  archive data as untrusted, with redaction, provenance tracking, and trust
  classification before any agent consumption (SEC-009; Phase 10 — the
  out-of-scope note above). **Owner:** SEC working group; downstream trust
  classification is Phase 10's governance work.

### PI-08 — Poison-input queue stall and integrity-conflict overwrite loop

**STRIDE:** Denial of service / tampering · **Disposition:** Mitigated

- **Threat.** Three loop shapes the §7.8 "Because" clause names the stakes
  for ("poison input must not block the entire historical queue, integrity
  failures must not become overwrite loops"): (a) client-side — malformed or
  oversized artifacts that keep failing stall the client's queue, or during
  an ingestion outage grow the spool until the coding host itself is
  disrupted; (b) server-side — an uploader repeatedly resubmits a
  conflicting occurrence hoping the server treats the conflict as transient
  (retryable 5xx churn) or silently overwrites; (c) a hostile source
  churning quarantine to hide coverage gaps in noise.
- **Attacker position.** A malicious linked uploader for (b); hostile or
  corrupted source content driving an honest client for (a) and (c); any
  storage transient fault amplifying (a).
- **Affected contract.** Plan §7.8 error/action matrix and retry policy
  (full jitter from one second doubling to a 15-minute cap, no arbitrary
  attempt limit, success resets); §7.4/EC-06 (conflict containment);
  §7.9 and EC-11 (2 GiB spool cap, 5 GiB free-space floor, stop
  materializing and degrade — never disrupt the host); §12 client status
  (classified last error, coverage state); requirements OPS-003, VAL-007,
  SEC-004.
- **Mitigation and enforcing tests.** The per-class matrix does the work:
  invalid envelope/media quarantines the artifact and *continues other
  sources* (400/415); integrity conflict returns 409, stops only the
  affected tenant/source, and pages the operator — it is never retried as
  transient and never silently overwritten, before or after a receipt
  (§7.8; §7.4; EC-06); oversized-but-splittable rechunks at a record
  boundary and oversized-unsplittable quarantines with a reported coverage
  gap (413; EC-07). Retry storms are bounded because only the retryable
  classes loop at all, under the jittered cap, while poison classes stop —
  and the no-arbitrary-attempt-limit policy is safe precisely because
  non-retryable classes exit the loop. Client disk pressure degrades
  visibly instead of disrupting the host (EC-11; OPS-003), and all error
  surfaces carry bounded, content-free codes (VAL-007; SEC-004; §7.8
  "Metrics record bounded error codes, never messages derived from source
  content"). Enforced by the §7.8 suite — **error/action matrix,
  poison-continuation, lost-receipt, partial-commit** tests — the §10
  conformance requirement to cover every §7.8 branch ("pause on
  authentication failure, stop on integrity conflict, rechunk/quarantine on
  size rejection, and retry after a lost successful receipt"), and §7.9's
  disk-pressure and bounded-starvation tests.
- **Residual.** A conflict does require operator action to clear the blocked
  source/prefix; that availability price for integrity is the documented
  design (§7.4), not an open risk.

## Cross-cutting controls relied on above

- Pre-allocation bounds before authentication (plan §5 step 1) — caps what
  unauthenticated and pre-verification traffic can spend (PI-03, PI-04),
  including the IA-01 residual this document inherits.
- Validate-before-complete on every stream, including bodies for blobs that
  already exist (§7.7) — the shared guard behind PI-01, PI-02, and PI-03.
- Deterministic, domain-separated identity (§7.4) — the containment common
  to PI-05, PI-06, and PI-07: fabrication creates new attributed objects and
  can never overwrite or alias archived ones.
- The server-owned pinned `zstd-v1` encoder and the honestly reported
  capability matrix (§7.6, §7.7) — keep stored bytes and their checksums
  from being mistaken for content identity (PI-02).
- Bounded, content-free error codes and metrics (VAL-007; SEC-004; §7.8) —
  validation failures never echo transcript content back at the attacker;
  disclosure findings live in
  `docs/security/threats/receipts-and-disclosure.md`.

## Coverage and disposition register

| ID | Finding | STRIDE | Disposition | Enforcing test class | Owner of residual |
|---|---|---|---|---|---|
| PI-01 | False content address (declared digest/size mismatch) | T | Mitigated | digest/checksum mismatch conformance; incompatible-existing-object; golden blobs | — |
| PI-02 | Canonical-versus-stored digest confusion | T | Mitigated | golden blobs; digest/checksum mismatch; incompatible-object; Phase 8 restore sample | — |
| PI-03 | Decompression bomb (size and ratio ceilings) | D | Mitigated | decompression fuzzing; limit-boundary; adversarial 100:1 benchmark; Phase 4 fuzz gate | — |
| PI-04 | Resource-slot exhaustion within bounds | D | Mitigated; aggregate accepted | limit-boundary; shutdown/drain; multipart-abort lifecycle | SEC working group + tenant operator |
| PI-05 | Chunk-boundary manipulation | T | Containment mitigated; source-truth accepted | chunk-boundary + oversized-record unit/property; adapter byte parity; poison-continuation | SEC working group (client-core/adapter owners for parity) |
| PI-06 | Identifier poisoning of identity and keys | T | Mitigated | golden ID/key vectors; arbitrary-Unicode properties; synthetic-ID; incompatible-existing-object | — |
| PI-07 | Fabricated provenance in the manifest | S/R | Accepted | — (attribution via signed envelope + attestation; EC-06 containment) | SEC working group (Phase 10 for consumers) |
| PI-08 | Poison-input queue stall / conflict overwrite loop | D/T | Mitigated | error/action matrix; poison-continuation; lost-receipt; partial-commit; §7.9 disk-pressure | — |

Acceptance check for this document: digest confusion (PI-01, PI-02),
decompression bombs and the uncompressed-size and expansion-ratio ceilings
(PI-03), compressed-size, duration, concurrency, and rate resource exhaustion
(PI-04), chunk-boundary attacks (PI-05), and the poisonable manifest fields —
occurrence identity and derived object keys (PI-06), source coordinates
(PI-05), and remaining provenance (PI-07) — are each documented; every finding
carries either a named enforcing test class from the §7.4, §7.6, §7.8, or §10
enforced-by lists or an explicitly accepted risk with a named owner; and no
finding introduces a contract that plan §7.4, §7.6, or §7.8 does not state.
