# B2 storage qualification — the direct Backblaze B2 profile

Qualified 2026-09-21 (bead `aa-db9146dd`). Records the qualification run of
the `backblaze-b2` profile lane — the target-class deployment profile the
plan qualifies on an isolated synthetic prefix before each compatible
release (plan Section 10;
[storage profiles](storage-profiles.md) Section 1) — and the B2-specific
required actions, prefix limitations, and disclosures a deployment there
inherits. The disclosure Section 4 is the one
[requirements](requirements.md) STO-006 makes mandatory for a
deterministic-overwrite profile.

The lane is the credential-free synthetic seam: it drives the real adapter
decision layer (`crates/archivist-storage`) and the real S3 raw writer
(`crates/archivist-storage-s3`) over a backend modeled from the profile's
capability report. It establishes the portable contract and the honest
capability branches; it does not substitute for the live release-time run
against a real B2 instance, whose cadence this run does not change
(SP-005's rule holds here: what the synthetic lane cannot establish stays
unknown, and unknown never strengthens — plan Section 10).

## 1. The run

- Suite: `crates/archivist-storage-s3/tests/storage_compatibility.rs`
  (landed in commit a43feb5, lint fix 0c2dd9a), unchanged runner across all
  five registry profiles.
- Execution: a clean `git archive HEAD` extraction of commit 7753c70, run
  `cargo test -p archivist-storage-s3 --test storage_compatibility --
  --nocapture` — exit 0.
- Isolation: every profile lane constructs its own backend state; the B2
  lane's writes land in an isolated synthetic prefix no other lane reads or
  writes, so "noncurrent version" observations are that lane's own physical
  history and logical convergence is never mistaken for cross-lane
  contamination.
- The B2 lane's report, verbatim:

```
storage-compatibility profile=backblaze-b2 conditional_create=unavailable stored_checksum=provider_specific versioning=enabled server_side_encryption=verified physical_versions=[concurrent-writers:2:["v5", "v6"],duplicate-request:2:["v1", "v2"],equivalent-overwrite:2:["v3", "v4"],multipart-commit:1:["v9"],origin-attestation:1:["v10"],read-capable-conflict:2:["v7", "v8"],relay-attestation:1:["v11"]]
```

## 2. Observed capability matrix

| Axis | Observed | Consequence for B2 |
| --- | --- | --- |
| `conditional_create` | `unavailable` | No atomic create-if-absent: the commit decision layer selects deterministic overwrite (STO-006); the adapter's `ConditionalCreateStore` default fails closed with `CapabilityUnavailable` if a report ever claims otherwise while no primitive exists. |
| `stored_checksum` | `provider_specific` | The backend's stored checksum is not assumed to be SHA-256. The archive's integrity rests on the SHA-256 content address of canonical bytes (STO-001); a backend-native checksum may be verified additionally, never substituted. |
| `versioning` | `enabled` | Every write — including a deterministic overwrite — lands a new physical version; noncurrent versions accumulate and are a lifecycle concern (STO-009, Section 4). |
| `server_side_encryption` | `verified` | Configuration validation requires a named encryption policy; the B2 lane exercises the S3-SSE arm (`EncryptionPolicy::S3Sse`). ARMOR's envelope is the separate `armor` profile. |
| multipart commit/abort | verified | The one non-degradable primitive (SP-004): a backend without begin/write/commit/abort is not a supported profile at all. B2's lane proves the session lifecycle end to end. |

## 3. Truthful overwrite results

On a profile without atomic conditional create, every manifest commit —
first write, replayed duplicate, equivalent overwrite, concurrent writer —
reports `StorageOutcome::LogicallyCommittedUnknownPhysicalResult`
(RCPT-003, RCPT-004). That is the honest ceiling: a writer-only identity
cannot distinguish creation from byte-equivalent replacement, so the
outcome never claims `Created` or `AlreadyPresent`, and never converts an
unknown physical result into a deduplication claim. Convergence is real
nonetheless: replaying the same request rewrites the same canonical bytes
at the same derived key, so the logical object is one and unchanged
(STO-004) — the primitive decides only which physical story the outcome
may tell.

Two consequences the suite pins for this profile:

- Equivalent overwrite is a successful logical replay, never an
  `IntegrityConflict` — conflict detection needs the conditional-create
  path's readable evidence, which this profile's commit path does not
  consume. The `read-capable-conflict` scenario shows the honest result:
  the preloaded incompatible object is overwritten (2 physical versions),
  not detected. Correctness therefore rests on deterministic tenant-scoped
  keys and frozen canonical bytes (STO-003, STO-010), never on a preflight
  check (STO-007) — and never on a database or lock promising physical
  exactly-once (STO-008).
- Concurrent writers on one immutable manifest both succeed with the
  unknown-physical result; the backend keeps both physical versions
  (`v5`, `v6`) and the logical object is the shared canonical bytes either
  way.

## 4. Noncurrent duplicate versions — the STO-006 disclosure

**A B2 deployment retains redundant noncurrent physical versions.**
Versioning is enabled and conditional create is unavailable, so every
replayed duplicate and every equivalent overwrite adds one physical
version behind the current one. The run observed exactly that:
`duplicate-request:2`, `equivalent-overwrite:2`, `concurrent-writers:2` —
one current version plus one noncurrent copy each, all at the same derived
key, with one logical object throughout.

[Requirements](requirements.md) STO-009 makes the remedy a deployment
action: **configure lifecycle expiration for redundant noncurrent
versions**, subject to retention policy. The rule MUST be noncurrent-only
for raw, both control families, catalog, and derived; only the synthetic
probe namespace may use whole-object expiration. Without it the duplicate traffic
the idempotency contract invites becomes unbounded storage growth; with
it, the noncurrent copies age out while the current version — always the
same canonical bytes — is untouched. This disclosure is normative for B2
operators, not advisory. The per-prefix, per-profile retention and
cleanup configuration that action takes — including the
prefix-scoped noncurrent-only baselines this profile's deployment
configures and the rule that the control current-pointer families'
history is never a lifecycle target — is the
[noncurrent-version lifecycle note](s3-noncurrent-lifecycle.md)'s
retention matrix.

## 5. Prefix limitations

What the profile and a prefix-scoped synthetic run honestly cannot offer:

- **No atomic create-or-exists.** The race window of a conditional `PUT`
  does not exist on this profile; idempotency is convergence by
  construction, not exclusion.
- **No readable preflight on the write path.** The raw-writer credential
  "can create, multipart-write, and abort only the tenant raw prefix but
  cannot read or delete objects or access control/catalog/derived
  prefixes" (plan Section 5), and the adapter's request seam exposes no
  read, list, or delete method at all. An incompatible object already at a
  derived key is overwritten, not detected (Section 3).
- **No SHA-256 storage checksum assumption** (`provider_specific`):
  backend-native checksums cannot back the content address.
- **What the synthetic prefix cannot establish** and a live release-time
  run must: real-B2 latency and throttling behavior, the live capability
  probe's answer against the production endpoint, account-level controls
  outside the tenant prefix, and B2's native checksum semantics. The
  capability report a live run observes is the input the adapter acts on;
  this run pins the branches, not the live answers.

## 6. Multipart cleanup

The B2 lane proves the session contract end to end:

- `begin` mints a session for the derived blob key; `write_part` appends
  strictly ordered commitments; `commit` assembles the object and lands
  exactly one physical version (`multipart-commit:1:["v9"]`).
- `abort` is cleanup and must be idempotent: the terminal operation
  tombstones the session, a repeat `abort` succeeds, the backend holds no
  object and no open upload afterwards (`aborts = 1`, open uploads 0,
  physical count 0).
- A commit that fails in flight leaves the session open for the caller's
  abort — a dead session is never retried (EC-10) — and a process that
  dies mid-session orphans it at the backend. The deployment's **24-hour
  incomplete-multipart lifecycle rule** is the designed backstop that
  reaps such sessions; it is a required B2 action (Section 7), not an
  adapter behavior.

## 7. Required actions

For the release-time live qualification run, and for any standing B2
deployment:

1. **Provision an isolated synthetic prefix** — a dedicated bucket/prefix
   carrying only synthetic qualification data, never production content;
   the run's isolation claim is only as good as the prefix's isolation.
2. **Run the capability probe first**
   (`crates/archivist-storage/src/probe.rs`): it observes the five axes
   without mutating arbitrary keys — the reserved
   `tenants/<tenant>/v1/probe/<label>` namespace sits outside the raw
   prefix and expires by one lifecycle rule without touching tenant
   content — and the observed report, not the backend's documentation, is
   what the store believes. Pin the report the run observed; unknown
   facts reduce fail-closed to weaker model values.
3. **Versioning enabled, with noncurrent-only lifecycle rules**
   (STO-009; Section 4's disclosure) for raw, both control families,
   catalog, and derived; current objects in those namespaces MUST remain
   outside lifecycle cleanup. The reserved probe namespace is the only
   whole-object-expiration exception.
4. **A 24-hour incomplete-multipart abort rule** (Section 6).
5. **Server-side encryption configured and named** in the deployment
   configuration — validation refuses to build the store without it.
6. **Scoped credentials**: a raw writer limited to
   put + list + abort on the tenant raw prefix (abort never implies
   delete), and a separate control reader; neither identity can read
   transcript bodies or mutate control records.
7. **Record the outcome honestly**: a run that could not execute or that
   fails is recorded as such; a partial or inconclusive run qualifies
   nothing (SP-005). Target profiles carry no registry `[[records]]` —
   their qualification is the release gate this run feeds.

## 8. Acceptance: logical identity preservation

The bead's acceptance — *a profile without atomic conditional create still
preserves logical blob, occurrence, and attestation identities* — is
proven by the B2 lane at the run's exit 0:

| Logical identity | Physical truth on B2 | Preservation proof |
| --- | --- | --- |
| Blob (STO-001, STO-003) | `multipart-commit:1` at the derived blob key | Addressed by tenant + storage profile + SHA-256 of canonical bytes; the multipart object the backend holds is byte-identical to the parts, and its checksum observation matches the profile's own checksum form. |
| Occurrence (STO-004, STO-010) | `duplicate-request:2`, `equivalent-overwrite:2`, `concurrent-writers:2` — two physical versions, one logical object | Replays and races rewrite the same canonical bytes at the same derived key; the latest version's checksum equals the digest of the canonical bytes, so the logical occurrence is one and unchanged, with no duplicate logical record despite the noncurrent copies. |
| Attestation (STO-013) | `origin-attestation:1`, `relay-attestation:1` | The two uploaders' attestations derive distinct object keys (asserted byte-distinct in the suite); each lands exactly one version and neither ever overwrites the other — distinct authorized uploaders remain separately auditable. |

Deterministic overwrite degrades the *physical story*, never the
*logical identity*: that is the property the B2 profile is qualified on.

## 9. Physical results — the live run (2026-09-27, bead `aa-c4a549c6`)

The live release-time run Section 5 deferred has now executed against a
real B2 instance — not through a synthetic backend but through the same
S3-compatible API, path-style SigV4, on the deployment's own backing
bucket. This section records the physical observations; Sections 1–8
remain the synthetic lane's record and are distinct from it.

**The run.** 2026-09-27, bead `aa-c4a549c6`. The instrument is the
kit's equivalent live lane: five write-shaped instruments (one per
capability axis, plus multipart commit and abort sessions and reader
read-backs) over a pure-stdlib SigV4 driver executed on the tailnet
workstation, aimed at an isolated run prefix at the bucket root —
outside every tenant tree, carrying only synthetic data. The identity
was the deployment's bucket-scoped B2 application key (its native
capabilities verified before use: list/read/write/delete files,
lifecycle and encryption read/write, restricted to the one bucket).
Every operation's status code, response headers, and elapsed time were
captured; the full transcript is retained with the bead, not committed
(SP-006). Post-run cleanup deleted all six versions the run created and
verified zero remaining — the key holds delete, so unlike any
archivist-path identity this lane leaves no residue.

**Observed five-axis report** (tokens as defined in
[storage profiles](storage-profiles.md) Section 3):

```text
storage-compatibility profile=backblaze-b2[live,direct] conditional_create=unavailable stored_checksum=provider_specific versioning=enabled server_side_encryption=verified multipart_commit_abort=verified
```

**Physical observations**, per instrument:

| Instrument | Observed live | Latency |
| --- | --- | --- |
| calibration list (run prefix) | `200`, empty prefix | ~730 ms |
| conditional create (`If-None-Match: *`, fresh key, then same key) | `501 NotImplemented` on **both** PUTs — B2's S3 API does not implement conditional writes | ~720 ms |
| checksum (PUT, response ETag) | `200`; ETag is the 32-hex MD5-derived form — **not** SHA-256 | ~700 ms |
| versioning (two PUTs, one key; ListObjectVersions) | `200`/`200`; each PUT echoes a distinct `x-amz-version-id`; list returns 2 versions with correct `IsLatest` flags | ~0.8–0.9 s |
| server-side encryption (PUT with `x-amz-server-side-encryption: AES256`; plain PUT; GetBucketEncryption) | conditional PUT echoes `AES256`; plain PUT echoes nothing; **the bucket carries no default encryption configuration** (`404 ServerSideEncryptionConfigurationNotFoundError`) | ~730 ms |
| multipart commit (create → part → complete) | `200`/`200`/`200`; response ETag in a provider-specific (non-MD5) form; version id header present | ~0.7–0.8 s |
| multipart abort (create → part → abort → abort again) | first abort `204`; **repeat abort `404 NoSuchUpload`**; zero open uploads afterwards | ~0.7–0.8 s |
| read-back (list objects + versions under the run prefix) | 4 current objects / 6 versions — exactly the instruments' writes, reconciled | ~0.8–3.1 s |

**What the live run adds to the synthetic lane's record:**

1. **The five-axis tokens held.** The live answers match the synthetic
   lane's declared matrix (`unavailable`, `provider_specific`,
   `enabled`, `verified`, multipart verified) — the synthetic backend
   was a faithful model on every axis it modeled.
2. **Repeat abort is not idempotent at the physical edge.** The
   synthetic lane (Section 6) proves "a repeat `abort` succeeds"; live
   B2 returns `404 NoSuchUpload` for an upload id already reaped. The
   adapter's teardown path must map `NoSuchUpload` on abort to
   idempotent success — a physical fact the synthetic lane could not
   expose, and a required behavior for the writer's own validation-
   failure and shutdown cleanup.
3. **The bucket carries no default S3 encryption.** At-rest SSE is
   opt-in per request on this bucket. Tenant data written through the
   ARMOR path is protected by ARMOR's envelope (ARCH-006), not by a
   bucket policy — consistent with the profile model, but a deployment
   fact an operator writing to the bucket outside ARMOR must know.
4. **Real latency, for the first time.** ~0.7–0.9 s per write-shaped
   operation and ~3.1 s for a versions listing, workstation to
   `us-west-002`. The synthetic lane models logical behavior only;
   these are the magnitudes the release-time budget inherits.
5. **The documented aa-e827d0f0 canary no longer exists** at the
   backing store (404 via a bucket-wide read-capable key, 2026-09-27).
   The provisioning note's residue record — and the read-probe
   expectations that cite it — describe an object that is no longer
   there; the next ARMOR-path run needs its own committed probe target.

**Still not established by this run** (SP-005 honesty): throttling and
error behavior under load, account-level controls outside the bucket,
the ARMOR path's own layer over this backing store — the
[ARMOR qualification note](armor-storage-qualification.md) Section 11
records that layer's own live run, executed the same day.
