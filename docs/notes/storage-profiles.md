# Storage profiles

Status: accepted baseline · Last updated: 2026-09-27

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** are to be interpreted as described in RFC 2119 and RFC 8174 when
they appear in bold.

Authority: the implementation plan, Section 7.7 (S3 commit and concurrency
contract), Section 10 (storage compatibility tests), and Phase 2 (backend
compatibility deliverables); [protocol v1](../protocol/v1.md) Section 4.2
(the capability matrix); requirements ARCH-007, OPS-006, PUB-002, and
SEC-010; [SUPPORT.md](../../SUPPORT.md) for the support surface a profile
can enter. This note defines the storage-profile classes, the qualification
procedure for community profiles, the recording format for qualification
results, and the support obligation a qualified community profile creates.
The machine-readable record is
[`tools/storage-profiles.toml`](../../tools/storage-profiles.toml); the
gate that keeps the registry, this note, and the README agreeing is
[`tools/check-storage-profiles.py`](../../tools/check-storage-profiles.py)
in the fast lane of
[`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh).

## 1. Profile classes

An S3-compatible backend becomes a *profile* by being named in the registry
with one of three classes. The class states where the profile's
qualification evidence comes from — never whether the storage contract
differs, because one adapter serves every class
(`crates/archivist-storage-s3`):

- **reference** — exactly one profile, MinIO (plan Section 7.7). Qualified
  by the storage compatibility suite itself on every full verification
  run: the backend the suite is developed against and the only one project
  automation ever runs. The
  [verification baseline](../../CONTRIBUTING.md) uses no external
  credentials or services, and that rule is what keeps the reference
  profile honest — no other backend can quietly inherit its qualification.
- **target** — Backblaze B2 and ARMOR's S3 path: the deployment profiles
  the plan commits to. The isolated synthetic lane is a prerequisite, not
  release evidence. B2 additionally requires a redacted live run before
  each compatible release; ARMOR has its deployment gate. Per-profile
  operator configuration — verified capabilities, credential roles,
  encryption, lifecycle cleanup, backup or versioning, restore identity,
  logical versus physical deduplication — remains owned by the
  deployment-profiles documentation (Section 6).
- **community** — every other compatible implementation; today AWS S3 and
  Garage, both standing unqualified. No deployment profile, no operator
  documentation, and no
  capability claim until a recorded qualification run says otherwise;
  SP-002 makes "no record" a gate failure rather than a soft default.

## 2. The community qualification procedure

- **SP-001** — A community profile **MUST** be qualified by one run of the
  storage compatibility suite (OPS-006) against a real instance of the
  backend, executed by a community operator who supplies the instance,
  bucket prefix, and credentials. Project automation never runs community
  profiles: the verification baseline is credential-free by construction,
  so qualification evidence always originates outside it and arrives as a
  record (Section 3), never as CI output.
- **SP-002** — Every community profile in the registry **MUST** carry at
  least one qualification record, qualified or unqualified. An absent
  record is a gate failure, not a neutral state: the failure mode this
  rule exists to prevent is a profile standing on an unevidenced
  expectation of usability.
- **SP-003** — The qualification run **MUST** execute the complete
  per-profile suite, with no subset waived: the write-path exercises
  (portable-core `PUT`/`HEAD`/`GET` plus multipart
  create/upload/complete/abort; conditional create; concurrent writers;
  multipart abort; stored checksums; versioning; equivalent overwrite;
  honest logical-versus-physical deduplication), the enumeration
  fault-injection set (page mutation, duplicate pages, token loops,
  concurrent writes — plan Section 7.7), and the capability-probe reduction
  onto the five-axis matrix. A community profile has no other evidence, so
  there is no smaller honest subset; the pass bar is the Phase 2 exit gate.
- **SP-004** — A backend without multipart begin/write/commit/abort
  **MUST NOT** be qualified on any terms; the capability model has no
  degraded arm for that primitive, so a backend lacking it is not a
  supported profile at all. A qualified record states
  `multipart_commit_abort = "verified"` — the only value that axis holds.
- **SP-005** — A run that could not be executed is recorded as
  `unqualified` with the reason, exactly as a run that failed is. The
  record never strengthens: unknown stays unknown, and a partial or
  inconclusive run qualifies nothing (plan Section 10).

The harness precondition is met — the storage compatibility suite landed
with plan Phase 2, and its reference and target lanes run on every full
verification and release-qualification path — but a harness alone
qualifies nothing: until a community operator executes the complete kit
against a real instance, no qualification exists for either community
profile, and Section 5's records say exactly that rather than leaving the
profiles claimable.

The procedure's self-service half — the fixture inputs a run consumes,
the suite's expected outcome branches, the capability-probe entry point,
the report shape, and the record template with its acceptance checks —
is the [community qualification run kit](community-qualification-kit.md).

## 3. The qualification record

The recording format is the append-only `[[records]]` array of
[`tools/storage-profiles.toml`](../../tools/storage-profiles.toml): one
table per run, never edited or deleted, only superseded by a later record
on the same profile. A profile's standing is its latest record; SP-002
makes "no record" impossible for community profiles. Fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `profile` | always | registry key of the profile the run targeted |
| `date` | always | ISO 8601 calendar date of the run; per-profile dates never decrease |
| `release` | target live or `unqualified` | SemVer release whose live support evidence or negative disposition this record governs |
| `evidence` | target records only | must be `live`; distinguishes release-time evidence from the synthetic lane |
| `outcome` | always | `qualified` or `unqualified` — a closed set |
| `submitted_by` | always | public contributor handle, or `maintainer` |
| `reason` | `unqualified` only | why no capability claim exists (a failed run, or no run possible) |
| `suite_revision` | `qualified` only | the suite version or commit the run executed |
| `operator` | `qualified` only | who executed the run — the community side of SP-001 |
| `capability` | `qualified` only | the observed five-axis matrix, closed tokens |

- **SP-006** — A record **MUST NOT** contain endpoints, hostnames, bucket
  names, account or tenant identifiers, or credentials (PUB-002, SEC-010).
  The suite output backing a qualified record is attached to the
  contribution that adds it, not committed; the gate scans for the obvious
  identifier shapes, and the rule binds even where a shape evades the scan.

Target release evidence uses the same append-only array but must identify the
live handoff explicitly. The B2 shape is:

```toml
[[records]]
profile = "backblaze-b2"
date = "<run date>"
release = "<SemVer release being qualified>"
evidence = "live"
outcome = "qualified"
submitted_by = "<maintainer handle>"
suite_revision = "<revision that built the live driver>"
operator = "<operator handle>"
capability = { conditional_create = "supported|unavailable", multipart_commit_abort = "verified", stored_checksum = "sha256|md5|provider_specific|unavailable", versioning = "enabled|disabled|unknown", server_side_encryption = "verified|unavailable" }
```

If the live run is unavailable or fails, append the same shape with
`outcome = "unqualified"`, the release, `evidence = "live"`, and a
non-empty `reason`; omit the capability fields. The release gate treats that
record, and a missing record, as a hard stop for the B2 support claim.
- **SP-007** — A `qualified` record's `capability` table **MUST** report
  every axis of the plan Section 7.7 model with its closed tokens —
  `conditional_create`, `multipart_commit_abort` (SP-004),
  `stored_checksum`, `versioning`, `server_side_encryption` — because the
  record, not the backend's compatibility documentation, is what the
  published compatibility matrix cites.
- **SP-008** — Registry, this note, and README **MUST** agree: the standing
  table in Section 5 matches the computed standing, and the README states
  what the records state. The README's retired sentence — an unevidenced
  expectation that compatible implementations are usable through the same
  contract — is the exact shape of claim this registry replaced; the gate
  rejects its return.
- **SP-009** — Release and support documentation **MUST** name a community
  profile as supported only when its latest record is `qualified`. An
  `unqualified` record is a versioned deferral: the profile may be named
  only to state that it is unqualified and deferred for that release, with
  no deployment profile, capability claim, or support claim. A later release
  keeps that disposition until a complete kit run appends a new record.
- **SP-010** — A target profile's synthetic lane **MUST NOT** be treated as
  live release evidence. A target record is allowed only with
  `evidence = "live"`, a release SemVer, and the same redaction and
  capability rules as a qualified or unqualified record. A missing or
  unqualified live record is an honest negative, never a support claim.
- **SP-011** — Before a release claims Backblaze B2 support, the release
  gate **MUST** be run with that release's SemVer. It rejects when no B2
  `evidence = "live"` record exists for the requested release or when the
  latest such record is `unqualified`; a prior release's record and the
  synthetic lane do not satisfy the gate.

## 4. What qualification creates — and what it does not

A qualified community profile enters the published compatibility matrix
(plan Phase 11) pinned to its suite revision and observed capability
report. That is the entire obligation:

- Reports against a qualified community profile are accepted and triaged:
  reproduced against the reference profile, they are bugs in project code;
  specific to the qualified profile, they are handled best-effort, exactly
  as [SUPPORT.md](../../SUPPORT.md) scopes a single-maintainer project.
- Qualification creates **no** CI coverage — automation still qualifies
  only the reference profile — **no** hosting or service-level commitment,
  and **no** operator documentation beyond the recorded capability report;
  target-profile operator configuration is the deployment-profiles
  documentation's scope, not a community qualification's product.
- Qualification decays. A storage-layout or protocol minor bump, or a
  suite revision change, leaves the profile standing on evidence from a
  world that no longer exists; a new `unqualified` record (or a
  re-qualification run) is the honest response. An incompatibility report
  of the integrity-conflict class — two logical blobs where one is
  possible, a false content address — downgrades standing immediately.

## 5. Standing today

Computed from the registry and checked by the gate; this table is not
maintained by hand.

| Profile | Class | Standing | Qualification evidence |
| --- | --- | --- | --- |
| `minio` | reference | qualified by the suite on every full verification run | plan Section 7.7 |
| `backblaze-b2` | target | release-gated | plan Section 10; live record 2026-09-27 (the [B2 qualification note](b2-storage-qualification.md) Section 9) |
| `armor` | target | qualified before deployment on the ARMOR path | plan Section 10; live run recorded 2026-09-27 (the [ARMOR qualification note](armor-storage-qualification.md) Section 11) |
| `aws-s3` | community | unqualified | record 2026-09-27 (release 1.0.0) |
| `garage` | community | unqualified | record 2026-09-27 (release 1.0.0) |

Each community profile's latest record states the same fact: no suite run
has been executed against either implementation. The release `0.1.0`
records (2026-09-15) predate the suite itself; the release `1.0.0`
records (2026-09-27) keep both profiles unqualified with the suite and
the run kit in hand — SP-001 puts community evidence outside project
automation, the credential-free baseline holds no AWS S3 or Garage
instance, and no community operator run has been submitted. Each record
is an explicit unqualified disposition for its release: AWS S3 and
Garage are unsupported and excluded from that release's claims — no
supported storage profile, no deployment profile, no capability claim.
Where the README previously carried an expectation, this table carries
the record — and `unqualified` here means "no evidence", not "known
broken".

The two target rows carry their live release-time run state, recorded
where the deployment-profile documentation owns it. The B2 profile's
successful live run on 2026-09-27 is also a redacted `[[records]]` entry
with `evidence = "live"`; `tools/check-storage-profiles.py --release
<SemVer>` consumes that entry. A synthetic result, a note-only claim, or a
live record for another release cannot pass the B2 gate. The ARMOR profile's
live run executed the same day at the deployment's tailnet S3 edge — its
note's Section 11 records the run, including the morning the staged edge was
blocked, with the same SP-005 seriousness a failed run gets.

For a later release, a contributor either runs the complete kit and appends
a `qualified` record with its suite revision and capability matrix, or
appends a new `unqualified` record with that release's SemVer and the reason
the run was unavailable or failed. Release and support text changes only as
the paired disposition changes; it never infers support from S3 compatibility.

## 6. Ownership and neighbors

- The suite, its lanes, and the reference/target qualification cadence are
  the plan's (Sections 7.7 and 10) and the verification register's
  (T-OPS-006, T-STO-*). This note adds no suite requirements; it defines
  how a community run of that suite becomes a durable claim.
- Operator configuration for the qualified target profiles — credential
  roles, encryption, lifecycle cleanup, backup or versioning, restore
  identity, deduplication semantics — is the deployment-profiles
  documentation's scope; a community qualification never substitutes for
  it (Section 4). The lifecycle-cleanup half of that scope has its own
  note: the [noncurrent-version lifecycle](s3-noncurrent-lifecycle.md)
  defines the per-prefix, per-profile retention matrix the target
  profiles' noncurrent-version expiration follows, backed by
  `tools/s3-lifecycle-rules.toml` and its fast-lane gate.
- The published compatibility matrix (plan Phase 11) cites this registry;
  [SUPPORT.md](../../SUPPORT.md) cites both.
