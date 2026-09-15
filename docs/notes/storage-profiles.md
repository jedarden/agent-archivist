# Storage profiles

Status: accepted baseline · Last updated: 2026-09-15

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
  the plan commits to. Qualified on an isolated synthetic prefix before
  each compatible release (B2) and before deployment there (ARMOR), with
  per-profile operator configuration — verified capabilities, credential
  roles, encryption, lifecycle cleanup, backup or versioning, restore
  identity, logical versus physical deduplication — owned by the
  deployment-profiles documentation (Section 6).
- **community** — every other compatible implementation; today AWS S3 and
  Garage. No deployment profile, no operator documentation, and no
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

Until the suite itself lands (plan Phase 2; register verification
T-OPS-006, status `planned`), no community qualification run is possible
at all — the procedure's first precondition is the harness — and
Section 5's records say exactly that rather than leaving the profiles
claimable.

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
| `backblaze-b2` | target | qualified before each compatible release | plan Section 10 |
| `armor` | target | qualified before deployment on the ARMOR path | plan Section 10 |
| `aws-s3` | community | unqualified | record 2026-09-15 |
| `garage` | community | unqualified | record 2026-09-15 |

Both community records state the same fact from the same cause: no suite
run has been executed against either implementation, because the suite is
itself a planned Phase 2 deliverable and no community operator run has
been submitted. Where the README previously carried an expectation, this
table carries the record — and `unqualified` here means "no evidence",
not "known broken".

## 6. Ownership and neighbors

- The suite, its lanes, and the reference/target qualification cadence are
  the plan's (Sections 7.7 and 10) and the verification register's
  (T-OPS-006, T-STO-*). This note adds no suite requirements; it defines
  how a community run of that suite becomes a durable claim.
- Operator configuration for the qualified target profiles — credential
  roles, encryption, lifecycle cleanup, backup or versioning, restore
  identity, deduplication semantics — is the deployment-profiles
  documentation's scope; a community qualification never substitutes for
  it (Section 4).
- The published compatibility matrix (plan Phase 11) cites this registry;
  [SUPPORT.md](../../SUPPORT.md) cites both.
