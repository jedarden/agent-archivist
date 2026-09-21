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
path is ARMOR. Without it the duplicate traffic the idempotency contract
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
   to noncurrent copies only — the current version at a derived key is
   the archive's content address; expiring current objects destroys the
   archive while every logical claim still holds.
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
