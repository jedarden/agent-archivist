# ARMOR storage qualification — the ARMOR S3 profile over B2

Qualified 2026-09-21 (bead `aa-0a2562d8`). Records the qualification run of
the `armor` profile lane — the target-class deployment profile qualified
before deployment on the ARMOR path (plan Section 10;
[storage profiles](storage-profiles.md) Section 1) — and the five things
the bead's acceptance names: logical convergence, authority separation,
restore access, lifecycle guidance, and observed physical results that
match the public storage contract.

The ARMOR path fronts B2 (the [provisioning
note](armor-storage-provisioning.md) records the deployment), so its
physical storage semantics are the backing store's: the lane's capability
shape is deliberately identical to the [B2
qualification](b2-storage-qualification.md) lane's, and what distinguishes
the profile is the encryption axis — ARMOR's envelope (`storage.encryption
= armor`, ARCH-006) instead of S3-SSE named against B2 directly. The run
goes through the public storage contract only: the same runner, the same
portable configuration keys, and the six-method raw-write seam. Nothing
ARMOR-specific is exercised — no ARMOR extension appears anywhere in the
adapter's request surface, and the suite's only profile-specific input is
the named encryption policy, which is part of the public configuration
grammar, not an ARMOR protocol.

## 1. The run

- Suite: `crates/archivist-storage-s3/tests/storage_compatibility.rs`
  (landed in commit a43feb5, lint fix 0c2dd9a), unchanged runner across all
  five registry profiles.
- Execution: a clean `git archive HEAD` extraction of commit 9b4d540, run
  `cargo test -p archivist-storage-s3 --test storage_compatibility --
  --nocapture` — exit 0 (all five lanes). The qualification commit touches
  documentation only, so the suite bytes are identical at the landing
  commit.
- Isolation: every profile lane constructs its own backend state; the
  ARMOR lane's writes land in an isolated synthetic prefix no other lane
  reads or writes.
- The ARMOR lane's report, verbatim:

```
storage-compatibility profile=armor conditional_create=unavailable stored_checksum=provider_specific versioning=enabled server_side_encryption=verified physical_versions=[concurrent-writers:2:["v5", "v6"],duplicate-request:2:["v1", "v2"],equivalent-overwrite:2:["v3", "v4"],multipart-commit:1:["v9"],origin-attestation:1:["v10"],read-capable-conflict:2:["v7", "v8"],relay-attestation:1:["v11"]]
```

## 2. Observed capability matrix

| Axis | Observed | Consequence for ARMOR→B2 |
| --- | --- | --- |
| `conditional_create` | `unavailable` | No atomic create-if-absent: the commit decision layer selects deterministic overwrite (STO-006); the adapter's `ConditionalCreateStore` default fails closed with `CapabilityUnavailable` if a report ever claims otherwise while no primitive exists. |
| `stored_checksum` | `provider_specific` | The checksum observable at the S3 seam is not assumed to be SHA-256 — behind ARMOR's envelope it is the backing store's form, and the envelope's own integrity verification is ARMOR's contract (ARCH-006), not something the adapter re-derives. The archive's integrity rests on the SHA-256 content address of canonical bytes (STO-001); a backend-native checksum may be verified additionally, never substituted. |
| `versioning` | `enabled` | Every write — including a deterministic overwrite — lands a new physical version on the B2 backing bucket; noncurrent versions accumulate and are a lifecycle concern (STO-009, Section 4). |
| `server_side_encryption` | `verified` | Configuration validation requires a named encryption policy; the ARMOR lane exercises the `armor` arm (`EncryptionPolicy::Armor`). The suite proves the policy is *named and carried*; it does not reach inside the envelope — what the envelope guarantees is ARCH-006's, and a deployment that cannot name its encryption mechanism is not a store configuration at all. |
| multipart commit/abort | verified | The one non-degradable primitive (SP-004): a backend without begin/write/commit/abort is not a supported profile at all. The ARMOR lane proves the session lifecycle end to end, including the writer's own teardown grant at the edge (`abort`, never `delete`). |

## 3. Logical convergence — the honest ceiling

On a profile without atomic conditional create, every manifest commit —
first write, replayed duplicate, equivalent overwrite, concurrent writer,
multipart commit, each attestation — reports
`StorageOutcome::LogicallyCommittedUnknownPhysicalResult` (RCPT-003,
RCPT-004). The ARMOR lane asserts exactly that, for every one of its
commits including the *first*: a writer-only identity cannot distinguish
creation from byte-equivalent replacement, so the outcome never claims
`Created` or `AlreadyPresent`, and never converts an unknown physical
result into a deduplication claim.

Convergence is real nonetheless: replaying the same request rewrites the
same canonical bytes at the same derived key, so the logical object is one
and unchanged (STO-004). Three pins the lane makes for this profile:

- Equivalent overwrite is a successful logical replay, never an
  `IntegrityConflict`. The `read-capable-conflict` scenario shows the
  honest result: the preloaded incompatible object is overwritten (2
  physical versions), not detected — the lane is read-capable, but the
  commit path has no conditional-create primitive to consume that evidence
  with. Correctness rests on deterministic tenant-scoped keys and frozen
  canonical bytes (STO-003, STO-010), never on a preflight check
  (STO-007) and never on a database or lock promising physical
  exactly-once (STO-008).
- Concurrent writers on one immutable manifest both succeed with the
  unknown-physical result; the backend keeps both physical versions
  (`v5`, `v6`) and the logical object is the shared canonical bytes
  either way.
- Multipart teardown is idempotent cleanup: the terminal `abort`
  tombstones the session, a repeat `abort` succeeds, and the backend
  holds no object and no open upload afterwards (`aborts = 1`, open
  uploads 0, physical count 0).

## 4. Noncurrent duplicate versions — STO-006 inherited through ARMOR

**An ARMOR→B2 deployment retains redundant noncurrent physical versions.**
Versioning is enabled on the backing bucket and conditional create is
unavailable, so every replayed duplicate and every equivalent overwrite
adds one physical version behind the current one. The run observed exactly
that: `duplicate-request:2`, `equivalent-overwrite:2`,
`concurrent-writers:2` — one current version plus one noncurrent copy
each, all at the same derived key, with one logical object throughout.

This is the same disclosure the [B2
qualification](b2-storage-qualification.md) Section 4 records for direct
B2, inherited unchanged through the ARMOR path: the physical story is the
backing store's because the backing store keeps the versions.
[Requirements](requirements.md) STO-009 makes the remedy a deployment
action — **configure lifecycle expiration for redundant noncurrent
versions** — and Section 7 says where that configuration lives when the
path is ARMOR. The rule MUST be noncurrent-only for raw, both control
families, catalog, and derived; only the synthetic probe namespace may use
whole-object expiration. Without it the duplicate traffic the idempotency contract
invites becomes unbounded storage growth; with it, the noncurrent copies
age out while the current version — always the same canonical bytes — is
untouched. The disclosure is normative for ARMOR operators too, not
advisory.

## 5. Authority separation

The acceptance clause is proven at three layers, none of them
ARMOR-specific:

- **Type level.** The raw-write seam
  (`crates/archivist-storage-s3/src/raw_write.rs`) exposes put,
  create-if-absent, and the multipart quartet — no read, no list, no
  delete method exists for the write path to call. The control-read seam
  (`control_read.rs`) is deliberately narrower than an S3 client: get and
  head only, with the missing verbs pinned in its documentation the same
  way. A credential cannot leak across the boundary through code that has
  no verb for it.
- **Configuration level.** `raw_write_credentials_ref` and
  `control_read_credentials_ref` are pairwise distinct by validation
  (plan Section 5); one identity cannot be configured into both roles.
- **Live edge.** The ARMOR deployment's six-identity set enforces the
  same separation at the S3 edge, and the [provisioning
  note](armor-storage-provisioning.md) "Full four-role enforcement
  matrix" (2026-09-21) exercised it live against the serving pod that is
  still serving: the control reader is refused every write and all raw
  access (rows 2–3, 8–9); the raw writer is refused reads of committed
  objects and every cross-prefix operation (rows 7–9); the control admin
  is refused reads and all raw writes (rows 11–12); wrong-secret and
  unknown-key calibrations (rows 16–17) prove the 403s are ACL refusals,
  not credential failures. `abort` never implies `delete`: the writer
  reaps its own uncommitted sessions (row 6) and still cannot destroy a
  committed object — no credential in the set holds any destroy
  capability.

## 6. Restore access

The portable configuration carries an optional
`storage.offline_restore_credentials_ref`
([configuration](configuration.md); requirements STO-007 preflight and the
offline restore role). On the ARMOR deployment the role exists as the
backup/restore identity — `get+list` across all four tenant prefixes and
nothing else — and the enforcement matrix proves the shape live: lists
across `raw/`, `control/`, `catalog/`, `derived/` return 200 (row 13), a
committed-object read returns 200 (row 14), and a write attempt is
refused (row 15).

That read-probe target was deliberate: the provisioning note reserved the
committed aa-e827d0f0 canary — unremovable by design, since no archivist
identity holds `delete` — as a read-probe target for this qualification.
Matrix rows 7 and 14 are that probe, run to completion: the raw writer's
read of the canary is refused (403 AccessDenied) while the backup/restore
identity's read of the same object succeeds (200), on the identical key.
Restore access and write-path authority separation are thereby proven
against the same physical object, and the residue an earlier bead could
not remove became this bead's evidence. A deployment that omits the
optional restore credential simply has no such identity — fail-closed,
like every omitted capability.

## 7. Lifecycle guidance

Two rules, both living on the B2 backing bucket, because that is where
the physical versions and the incomplete sessions are:

1. **Expiration of noncurrent versions** (STO-009; Section 4). Scope it
   to noncurrent copies only — current versions under raw, control,
   catalog, and derived are protected claims; the current version at a
   derived key is the archive's content address, and expiring current
   objects destroys the archive while every logical claim still holds. The per-prefix
   baselines the rule takes — and the exception that the control
   current-pointer families' noncurrent copies are the previous signed
   trust epoch's only copy and are retained, not expired — are the
   [noncurrent-version lifecycle note](s3-noncurrent-lifecycle.md)'s
   retention matrix, row for row.
2. **A 24-hour incomplete-multipart abort rule** (the B2 qualification's
   Section 6, unchanged here). A commit that dies mid-session orphans the
   upload at the backend; the rule is the designed backstop that reaps
   it. The archivist-side complement is the raw writer's `abort` grant
   (ARMOR 0.1.1969+ verb split), which covers teardown of the writer's
   *own* uncommitted sessions on validation-failure and shutdown paths.

Who can touch the rules: ARMOR serves bucket lifecycle configuration as a
passthrough to its backing store, and authorizes it by the operation's
effect — reading the configuration maps to the `get` verb, setting it to
`put`, deleting it to `delete` (ARMOR ADR-012's extension table; an
effect-decides-verb mapping, not an ARMOR-specific protocol the archivist
code depends on). The archivist identity set is prefix-scoped and holds
no `delete` anywhere, so the rules are **operator-managed**: a lifecycle
misfire cannot originate from any archivist credential, and ARMOR's own
ADR-006 already classifies a lifecycle-rule misfire as an operator-level
risk outside every storage safeguard. Verify after any reconfiguration —
the rules are invisible to the archivist identity set by construction, so
a drifted or deleted rule surfaces only through an operator check or the
cost it fails to cap.

## 8. What the run establishes, and what it does not

**Established:** the ARMOR profile's claims hold on the portable
contract — the lane's capability report (Section 1) is the input the
adapter acts on, its physical observations match the profile's own
five-axis model exactly (Section 2), logical identity is preserved
through every overwrite race (Section 3), and the live edge proves the
authority separation and restore access the contract demands (Sections
5–6) on the deployment that is serving today.

**Not established:** the production S3 request backend does not exist yet
(open bead: implement it over the RawWrite and ControlRead seams), so
nothing here exercises archivist code against live ARMOR — the identity
matrix is exercised through the S3 semantics at the edge, and the suite's
lane is the credential-free synthetic seam. A live release-time run must
still establish: real latency and throttling through the ARMOR path, the
live capability probe's answer against the deployment, the backing
store's native checksum semantics behind the envelope, ARMOR passthrough
behavior under partial failure, and account-level controls outside the
tenant prefixes. The capability report a live run observes is the input
the adapter acts on; this run pins the branches, not the live answers —
and unknown facts reduce fail-closed (plan Section 10), never stronger.
The live run of 2026-09-27 has since pinned the seam's physical answer
set — the live capability answers, real latency, and the seam's own
failure modes (Section 11) — re-scoping what remains unknown to the list
recorded there.

## 9. Required actions for an ARMOR deployment

1. **Provision through the provisioning note's identity set** — the six
   scoped identities, `put`-without-`get` writers, `get`-only readers,
   `abort` on the raw writer alone, `delete` nowhere. The set is
   machine-checked against the note; a change that alters it updates the
   registry and the note in the same commit.
2. **Name the encryption policy** (`storage.encryption = armor`);
   validation refuses to build the store without it.
3. **Set the two lifecycle rules on the backing bucket** (Section 7) and
   re-verify them after any reconfiguration — no archivist identity can
   see them, by construction.
4. **Before each deployment on the path, run the capability probe** once
   the production request backend exists, and pin the observed report:
   the store believes the probe, not the backend's documentation.
5. **Record the outcome honestly** (SP-005): a run that could not execute
   or that fails is recorded as such; a partial or inconclusive run
   qualifies nothing. Target profiles carry no registry `[[records]]` —
   their qualification is the release gate this run feeds.

## 10. Acceptance: the five clauses

| Clause | Evidence |
| --- | --- |
| Logical convergence | Section 3: every commit reports the honest unknown-physical outcome; replays and races rewrite the same canonical bytes at the same derived key — one logical object throughout, per the lane's physical report (Section 1). |
| Authority separation | Section 5: no read/list/delete on the raw-write seam; read-only control seam; pairwise-distinct credential refs by validation; live four-role matrix refusals with calibrations, `abort` never implying `delete`. |
| Restore access | Section 6: the optional restore credential ref; the backup/restore identity's live cross-prefix `get+list` and the canary read-probe (writer 403 / restorer 200 on the identical key); no write, no delete. |
| Lifecycle guidance | Section 7: noncurrent-version expiration scoped away from current objects, 24-hour incomplete-multipart abort, operator-managed via the effect-decides-verb mapping, invisible to the archivist identity set by construction. |
| Observed physical results match the public storage contract | Sections 1–2: the verbatim lane report — every version count and id traced to its scenario's contract expectation (`2` where deterministic overwrite lands a noncurrent copy, `1` where the primitive lands exactly one object), `multipart-commit:1`, idempotent abort, and the profile's own five-axis tokens with no strengthened unknown. |

## 11. Physical results — the live run (2026-09-27, bead `aa-c4a549c6`)

The live release-time run Section 8 deferred executed the same day it
was staged — against the deployment's tailnet S3 edge, through ARMOR's
own S3 layer, on the tenant's real backing store. This section records
the physical observations at the ARMOR seam; Sections 1–8 and 10 remain
the synthetic lane's record and are distinct from it.

**Staging, blockage, recovery.** The edge the run needs is the
`armor-s3-vpn` IngressRoute (`armor-iad-ci-ts.ardenone.com:8444` →
`armor:9000`, path-style) deployed that morning. It came up broken: the
route reached Traefik (v3.7.13) at 09:58:45Z, the `armor/armor-s3-tls`
secret did not exist yet, Traefik logged `Error configuring TLS` through
09:59:52Z and gave up, and cert-manager reported the Certificate Ready
at 10:00:07Z — fifteen seconds after the last retry. Every request met
the Traefik default handler (404 over the default certificate), polled
unchanged through 16:32:29Z; the transient port-forward alternative the
2026-09 rotation drills used is gone (the read-only service account
cannot create `pods/portforward`; the real iad-ci kubeconfig is an
interactive-OIDC credential unusable from this box). The route was
serving by the run window — its earliest server-timestamped artifact is
17:39:47Z — and no restart of Traefik or the serving pod was observed:
the dynamic-config rebuild happened without this bead taking any action
(candidate trigger: the 16:43:55Z declarative-config sync landing inside
the recovery window; Traefik's log carries no route-level record either
way). At record time the edge serves its own Let's Encrypt certificate
for `armor-iad-ci-ts.ardenone.com` — the route's Host rule and the
certificate's name, with hyphens; the underscore form in the morning's
staging record was a transcription error, corrected here.

**The run.** 2026-09-27, bead `aa-c4a549c6`, complete lane 17:45–17:52Z.
The instrument is the kit's equivalent live lane — the same driver that
executed the live B2 run ([B2 qualification
note](b2-storage-qualification.md) Section 9) — aimed at
`https://armor-iad-ci-ts.ardenone.com:8444`, bucket `iad-ci`, region
`us-west-002`, run prefix `agent-archivist/raw/aa-c4a549c6-live-qual/`.
The identities are the provisioning note's scoped pairs, loaded from
their per-role OpenBao paths into the environment only (raw writer for
the writes, backup/restore for the read-backs); the anchors were
verified first (raw writer v4, backup/restore v1; the raw-writer
fingerprint `4e5d334895dfff80` matches the drill record). The serving
pod was `armor-6dbb6ff7c4-89tvk` (`ronaldraygun/armor:0.1.1971`). The
lane ran three times at the edge: two partial bring-up runs (stamps
`a800dc0b`, `160fa507`) committed a few objects each before dying, and
the complete run (`3770b390`) executed every instrument, its teardown
aborting the partial run's one leftover open multipart session (`204`,
zero open after). Every operation's status, response headers of
interest, and latency were captured; the transcript is retained with
the bead, not committed (SP-006), and the five-axis reduction below is
re-derivable from it with the driver's `--from-transcript` mode.

**Observed five-axis report** (tokens as defined in
[storage profiles](storage-profiles.md) Section 3; reduced from the
retained transcript by the committed driver):

```text
storage-compatibility profile=armor[live,armor-seam] conditional_create=unavailable stored_checksum=provider_specific versioning=enabled server_side_encryption=unavailable multipart_commit_abort=verified
```

**Physical observations**, per instrument:

| Instrument | Observed live at the ARMOR seam | Latency |
| --- | --- | --- |
| calibration list (run prefix, raw writer) | `200` (the prefix already carried the partial runs' objects; the response omits `KeyCount`, so no count was captured) | ~4.3 s |
| conditional create (`If-None-Match: *`, fresh key, then same key) | **`500 InternalError` on both** — ARMOR's own failure ("Failed to encode block table: cannot encode empty block table: invalid block table entry"), not the backing store's `501` | ~0.5–0.7 s |
| checksum (PUT, response ETag) | `200`; ETag in the 32-hex MD5-derived form; no version-id echo | ~1.2 s |
| versioning (two PUTs, one key) | `200`/`200`; **neither PUT echoes `x-amz-version-id`** | ~1.2–1.3 s |
| per-key version listing (`GET key?versions`, backup/restore) | `200` — **but the body is the object's content** (`application/octet-stream`), not a version listing | ~1.8 s |
| server-side encryption (PUT with `x-amz-server-side-encryption: AES256`; plain PUT; GetBucketEncryption) | both PUTs `200`; **the SSE header is not echoed**; GetBucketEncryption is `403 AccessDenied` from ARMOR's own authorizer — the prefix-scoped ACLs refuse the bucket-level question before the backend is asked | ~0.9–2.3 s |
| multipart commit (create → part → complete) | `200`/`200`/`200`; complete ETag in the backing store's non-MD5 `…-1` multipart form; no version id | ~0.9–1.8 s |
| multipart abort (create → part → abort → abort again) | first abort `204`; repeat abort `404 NoSuchUpload`; zero open uploads afterwards | ~0.9–1.6 s |
| read-back (list objects + versions under the run prefix, backup/restore) | `200`/`200`; 12 current objects / 15 versions, exactly one `IsLatest` per multi-version key | ~2.5–4.8 s |

**What the live run adds to the synthetic lane's record:**

1. **Four of the five tokens held; one was honestly downgraded.**
   `server_side_encryption=verified` (the synthetic lane's answer) does
   not survive contact with the seam — not because encryption is absent
   but because **the seam does not expose SSE state**: no echo on either
   PUT, and the bucket-level question is ACL-refused before the backend,
   so the direct seam's 404 answer is unreachable through ARMOR. The
   fail-closed reduction is `unavailable`: what cannot be observed is
   not claimed. Objects written through the tenant tree carry no
   observable at-rest SSE guarantee at this seam; tenant-data protection
   remains ARMOR's envelope (ARCH-006) on ARMOR's own API, and the
   backing bucket has no default encryption ([B2 qualification
   note](b2-storage-qualification.md) Section 9, fact 3).
2. **Conditional create fails inside ARMOR, not at the backing store.**
   The direct seam's `501 NotImplemented` predicted nothing: at this
   seam the same request shape dies in ARMOR's block-table encoder on
   both the fresh and the repeat PUT. ARMOR demonstrably serves
   conditional-PUT semantics for another consumer (a genuine `412`), so
   the `If-None-Match: *` path — exactly what the adapter's conditional
   create would issue — is a concrete defect surface in the serving
   release (0.1.1971), and the ARMOR lane's conditional-create
   observation was indeed a required measurement, not an inference from
   either side. The adapter-side rule stands unchanged: a non-2xx on
   conditional create reduces to `unavailable`, and the write path must
   not depend on the primitive.
3. **`GET key?versions` is not version retrieval at this seam.** ARMOR
   returns the object's current content with `200` and
   `application/octet-stream` — the per-key `?versions` subresource is
   silently swallowed. The prefix-wide `?versions&prefix=` listing
   parses correctly and is the only usable version history here; the
   behavior re-probed identically at record time, so it is a stable
   seam property, not a transient. A version-aware client that trusted
   the per-key shape would read object bytes as if they were a listing;
   the adapter's version reconciliation must use prefix-wide listings
   only.
4. **No version-id echo, though the store versions every write.**
   Physically proven through the seam — 15 versions behind 12 current
   keys, exactly one latest per multi-version key — yet no PUT response
   carries `x-amz-version-id`. The adapter cannot bind a returned
   version id on this path; history reconciliation is list-only, which
   is what the probe model's read-back-primary versioning reduction
   already requires.
5. **Multipart matches the direct seam, including the teardown fact.**
   Commit `200`/`200`/`200`; abort `204` with the repeat abort's
   `404 NoSuchUpload` — the same non-idempotence the B2 run established,
   now through ARMOR's layer, so the teardown mapping (`NoSuchUpload` →
   idempotent success) is required at both seams. One new ARMOR-specific
   fact: the completed multipart object is accompanied by a sibling
   `mp-commit-3770b390.armor-manifest` object the seam itself writes
   under the tenant prefix — prefix listings through ARMOR include
   ARMOR's own bookkeeping objects, and an enumerator must expect
   non-data siblings.
6. **Real latency through the layer, for the first time.** Write-shaped
   operations ~0.5–2.3 s (direct seam: ~0.7–0.9 s — comparable medians,
   fatter tail) and listings up to ~4.8 s (direct: ~3.1 s for a versions
   list). The synthetic lane models logical behavior only; these are
   the magnitudes the release-time budget inherits.
7. **Residue, by design — and the retired canary replaced.** The run
   prefix holds 12 current objects / 15 versions across the three run
   stamps (`checksum` ×3; `versioned` ×3 keys × 2 versions; `sse` and
   `sse-plain` ×2 each; the committed multipart object and its
   `.armor-manifest` sibling; the conditional-create keys hold nothing —
   both PUTs errored). No archivist identity holds `delete`, so this
   residue stands exactly as the aa-e827d0f0 canary stood: removal is an
   operator action. It also fills the gap the canary's disappearance
   left — Sections 5–6's read-probe expectations (writer 403 / restorer
   200 on an identical committed key) now have a live, bead-owned target
   in any key under this prefix.

**Record-time reconciliation** (read-only, same identities, ~18:10Z,
this bead's second attempt): prefix state unchanged (12 keys / 15
versions / 3 multi-version keys, each with exactly one latest), zero
open multipart uploads, the per-key `?versions` behavior reproduces, and
the edge serves its own Let's Encrypt certificate. The reconciliation
transcript is retained with the bead alongside the run's.

**Still not established** (SP-005 honesty): throttling and error
behavior under load; passthrough behavior under partial failure beyond
the conditional-create 500; account-level controls outside the tenant
prefixes; the backing bucket's lifecycle rules (invisible to this
identity set by construction); and the production request backend's
composition on these semantics — the backend does not exist yet
(Section 8), so nothing here exercises archivist code against live
ARMOR. What this run establishes is the seam's physical answer set: the
capability report the adapter must treat as the truth when the backend
lands.
