# Noncurrent-version lifecycle — retention and cleanup on the S3 prefixes

Status: accepted baseline · Last updated: 2026-09-27

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** are to be interpreted as described in RFC 2119 and RFC 8174 when
they appear in bold.

Authority: requirements STO-006 (deterministic overwrite where conditional
create is absent) and STO-009 (lifecycle expiration for redundant
noncurrent versions, subject to retention policy); plan Section 7.5 (the
tenant object-key tree) and Section 7.7 (the S3 commit and concurrency
contract); the [B2](b2-storage-qualification.md) and
[ARMOR](armor-storage-qualification.md) qualification records, whose
Section 4 disclosures make the accumulation normative for operators;
[control trust](control-trust.md) for the control record families' write
classes; [storage profiles](storage-profiles.md) for the profile classes.
This note is the deployment-profiles documentation's lifecycle half —
the per-prefix, per-profile retention and cleanup guidance
[storage profiles](storage-profiles.md) Section 1 assigns to the target
profiles' operator configuration. The machine-readable record is
[`tools/s3-lifecycle-rules.toml`](../../tools/s3-lifecycle-rules.toml);
the gate that keeps the registry, this note, the control-record registry,
the audit constant, and the reference provisioning script agreeing is
[`tools/check-s3-lifecycle.py`](../../tools/check-s3-lifecycle.py) in the
fast lane of
[`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh).

## 1. The physical model

On a versioned backend (the reference profile's raw bucket; both target
profiles' buckets), every write lands a physical version, and where
conditional create is unavailable (STO-006) the commit decision layer
selects deterministic overwrite — so replayed duplicates, equivalent
overwrites, and concurrent writers each add one physical version *behind*
the current one at the same derived key. The B2 and ARMOR lanes observed
exactly that: `duplicate-request:2`, `equivalent-overwrite:2`,
`concurrent-writers:2` — one current version plus one noncurrent copy
each, one logical object throughout. Without a lifecycle rule the
duplicate traffic the idempotency contract invites becomes unbounded
storage growth (STO-009); with one, the noncurrent copies age out and the
current version is untouched.

What a noncurrent copy *is* depends on the prefix family's write shape,
and the retention guidance follows that shape rather than the bucket it
happens to land in:

- **Convergent families** — every overwrite rewrites the same canonical
  bytes at the same derived key (raw blobs are content-addressed; raw
  occurrence and attestation canonical fields are frozen by STO-010 and
  STO-013; catalog rebuilds and derived projections are deterministic).
  A noncurrent copy is pure redundancy: byte-identical to the current
  version, worthless the moment it is superseded, retained only as
  conflict evidence and to keep the physical story honest.
- **Epoch-replacement families** — the control current-pointer records
  (`clients/`, `delegations/`): a replacement is valid only when its
  signed authorization epoch strictly increases
  ([control trust](control-trust.md)), so a valid overwrite carries
  *different* bytes. The noncurrent version behind a current-pointer key
  is the previous trust epoch's only copy at that key — unique history,
  not redundancy.

## 2. The protection invariant

The current version at any tenant key is the archive's claim about that
key: for raw, the content address itself and the rebuild root everything
else is derived from (STO-011); for control, the trust state revocation
and authorization read. Lifecycle automation is a cost tool and source-of-truth
destruction is not a cost outcome. Therefore:

- **L-001** — A lifecycle rule on a tenant prefix **MUST** select
  noncurrent versions only. Expiration of the *current* version of any
  object under `raw/`, `control/`, `catalog/`, or `derived/` **MUST
  NOT** be configured.
- **L-002** — The control current-pointer families (`clients/`,
  `delegations/`) **MUST NOT** carry automatic expiration of noncurrent
  versions either: their noncurrent copies are the previous signed
  trust epoch's only copy at that key. Retention there is indefinite
  until a retention policy says otherwise, and any change to that is a
  policy decision recorded against the control-records registry, never
  a bucket-default cleanup.
- **L-003** — The one exception is the reserved probe namespace
  (`probe/<label>`): synthetic, content-free, never source-of-truth,
  and the whole object **MAY** expire. It sits outside the four tenant
  prefixes by construction (the B2 qualification's Section 7).
- **L-004** — An incomplete-multipart-upload abort rule **SHOULD** run
  bucket-wide at 24 hours: the designed backstop for a writer that dies
  mid-session (the B2 qualification's Section 6). It reaps sessions,
  not objects, and cannot touch a committed version.

A rule that satisfies L-001 can still misfire in one way: expiring
noncurrent copies *too fast* destroys the evidence an integrity
investigation needs. The read-capable-conflict scenario in both target
profiles' lanes lands two physical versions — the superseded bytes are
the only copy of what was overwritten. The baselines below are chosen to
outrun any plausible investigation window; a deployment may lengthen
them under its retention policy (STO-009's own subject), never shorten
them below the registry's floor without recording why.

## 3. The retention matrix

One rule per profile and prefix family; this table is canonical and the
gate holds the registry to it row for row. Days are baselines. The
families are the plan Section 7.5 tree's: `raw/` (blobs, occurrences,
attestations), the two control write classes from the control-records
registry, `catalog/checkpoints/`, `derived/<pipeline>/<version>/`, and
the reserved `probe/` namespace.

| Profile | Family | Rule | Days | Basis |
| --- | --- | --- | ---: | --- |
| minio | raw | expire-noncurrent | 30 | STO-006, STO-009, STO-011 |
| minio | control-current-pointer | not-applicable | — | control bucket carries no versioning in the reference shape |
| minio | control-immutable | not-applicable | — | control bucket carries no versioning in the reference shape |
| minio | catalog | not-applicable | — | no catalog namespace in the verified reference shape |
| minio | derived | not-applicable | — | no derived namespace in the verified reference shape |
| minio | probe | not-applicable | — | the provisioning script removes its probes in an epilogue, not by a rule |
| backblaze-b2 | raw | expire-noncurrent | 30 | STO-006, STO-009, STO-011 |
| backblaze-b2 | control-current-pointer | retain-noncurrent | — | L-002; control-trust current-pointer write class |
| backblaze-b2 | control-immutable | expire-noncurrent | 30 | STO-006, STO-009; control-trust immutable write class |
| backblaze-b2 | catalog | expire-noncurrent | 7 | STO-011, STO-012 |
| backblaze-b2 | derived | expire-noncurrent | 7 | STO-011, STO-012 |
| backblaze-b2 | probe | expire-objects | 1 | L-003; B2 qualification Section 7 |
| armor | raw | expire-noncurrent | 30 | STO-006, STO-009, STO-011 |
| armor | control-current-pointer | retain-noncurrent | — | L-002; control-trust current-pointer write class |
| armor | control-immutable | expire-noncurrent | 30 | STO-006, STO-009; control-trust immutable write class |
| armor | catalog | expire-noncurrent | 7 | STO-011, STO-012 |
| armor | derived | expire-noncurrent | 7 | STO-011, STO-012 |
| armor | probe | expire-objects | 1 | L-003; ARMOR qualification Section 7 |
| all | multipart | abort-incomplete-multipart | 1 | L-004; plan Section 7.7; both target qualifications' Section 6 |

`minio`'s versioning is a raw-bucket property
([reference profile](minio-reference-profile.md) Section 2) — the control
bucket is written by one administration identity and carries no overwrite
race, so four of its six cells are `not-applicable` rather than absent:
an explicit cell says the profile's shape was considered, where an empty
row would only say the matrix was not filled in. `all` is the reserved
bucket-wide scope for the multipart rule, which knows no prefix.

The rule tokens are a closed set: `expire-noncurrent` (age out
noncurrent copies after N days; the current version is out of reach by
L-001), `retain-noncurrent` (never expire; L-002), `expire-objects`
(expire whole objects, current included; legal only where the family is
not source-of-truth — the probe namespace), `not-applicable` (no rule,
with the profile-shape reason), and `abort-incomplete-multipart`
(bucket-wide session reaping, L-004).

## 4. Who owns the configuration

- **minio (reference)** — the project owns the configuration:
  [`tools/minio-reference-provision.sh`](../../tools/minio-reference-provision.sh)
  provisions the raw bucket's noncurrent-expiration rule scoped to the
  tenant raw prefix at the registry's 30 days, and its `verify` mode
  re-reads the rule from the server and fails on drift — the only place
  a lifecycle rule in this system is both documented and machine-applied.
  The [reference profile note](minio-reference-profile.md) records the
  mechanism and the live evidence.
- **backblaze-b2 (target)** — operator-managed on the bucket. The
  lifecycle rules are account-level controls outside the tenant prefix:
  no archivist identity can read, set, or delete them, and the release
  gate's required actions (the B2 qualification's Section 7) carry the
  matrix above as the configuration a live run must show.
- **armor (target)** — operator-managed on the B2 backing bucket, where
  the physical versions live. ARMOR serves bucket lifecycle configuration
  as a passthrough authorized by effect (the ARMOR qualification's
  Section 7): reading maps to `get`, setting to `put`, deleting to
  `delete` — and the archivist identity set holds none of these against
  the configuration, so a lifecycle misfire cannot originate from any
  archivist credential. The rules are invisible to the deployment by
  construction; re-verify them after any reconfiguration.
- **community profiles** — no guidance. A community qualification
  creates no operator documentation ([storage
  profiles](storage-profiles.md) Section 4); the matrix applies to a
  community deployment only when that deployment's own qualification
  evidence earns it.

## 5. The operational checks

Three layers prove the invariant, from the committed tree to the live
bucket:

1. **The gate** (`tools/check-s3-lifecycle.py --self-test`, fast lane).
   Proves, offline and on committed files only: every rule aimed at a
   source-of-truth family selects a noncurrent-only action (L-001 as a
   rejected mutation, not a prose promise); the current-pointer family is
   the one `retain-noncurrent` cell per target profile (L-002); the
   control families' split matches the control-records registry's write
   classes exactly — a new or reclassified control record fails this gate
   until the matrix says how its versions age; the note's matrix table
   and the registry agree row for row; the guidance id the audit renders
   equals the registry's; and the reference script configures exactly the
   minio raw cell.
2. **The audit store** (`archivist_storage::lifecycle_audit`, the S3
   adapter's `S3LifecycleAuditStore`). The offline-restore identity's
   versions listing, frozen and reduced to the STO-009 measurement:
   noncurrent counts and retained bytes per scope, rendered with the
   guidance citation. The rules themselves are invisible to every
   archivist identity by construction (Section 4), so the audit never
   claims a rule is present or drifted — the residue is the evidence:
   noncurrent counts that grow without bound past the baseline are the
   sound a missing or deleted rule makes, and consecutive audits are how
   an operator who cannot see the rules still checks them.
3. **The reference profile's live verify**
   (`tools/minio-reference-provision.sh verify`). Re-reads the
   provisioned rule from the server — scope, noncurrent action, days —
   and fails the run on any drift from the registry's minio raw cell.

## 6. What this note cannot establish

The baselines are committed judgment, not live observation. What a live
release-time run against a real target-profile backend must still
establish: the backend's exact lifecycle-rule semantics and their
interaction with versioning (B2's native rule forms are a live-run
input, not something the synthetic lanes pin — SP-005's rule holds:
unknown never strengthens), the observability of rule evaluation at
account scale, and the audit's numbers against real duplicate traffic.
The matrix pins what the configuration must say; the live run pins what
the backend actually does with it.
