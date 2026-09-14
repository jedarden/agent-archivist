# ARMOR storage provisioning — prefix layout and scoped identities

Provisioned 2026-09-14 (bead `aa-adeab1be`); raw-writer abort enablement
2026-09-14 (bead `aa-e4dcf1c2`); abort deployment promotion and live
enforcement matrix 2026-09-14 (bead `aa-e827d0f0`). Records the ARMOR-side storage
decision for this tenant: the prefix tree, the four scoped identities that
gate it, the OpenBao paths that hold them, and the raw writer's abort
grant. The identity model is plan §"Control-plane boundary"; the ACL
grammar is ARMOR ADR-012 (`<bucket>:<prefix>:<verbs>`, verbs from
{get, put, delete, list, abort}; an entry with no verb segment permits all
verbs, so every credential here pins its verbs explicitly).

## Deployment

- ARMOR instance: `iad-ci` (`ARMOR_BUCKET=iad-ci`, `ARMOR_B2_REGION=us-west-002`).
- Credential delivery: ARMOR reads named credentials from the YAML document
  mounted at `ARMOR_AUTH_FILE=/etc/armor/credentials.yaml`, materialized by
  the `armor-credentials` ExternalSecret from OpenBao
  `secret/rs-manager/iad-ci/armor/credentials` (property `credentials.yaml`),
  hot-reloaded on change — adding credentials requires no ARMOR Deployment
  change.
- rs-manager's OpenBao is the authority for `secret/rs-manager/*`; the
  iad-ci-local instance that ESO reads is a replica fed by the ~30-minute
  cross-cluster replicator, so a write here is visible to ARMOR within
  roughly one ESO refresh interval plus one replication cycle.

## Prefix layout

One tenant-scoped tree under the ARMOR bucket:

| Prefix | Purpose | Status |
|---|---|---|
| `agent-archivist/raw/` | blobs, occurrence manifests, upload attestations | active |
| `agent-archivist/control/` | tenant-authority-signed trust records | active |
| `agent-archivist/catalog/` | catalog checkpoints | reserved, Phase 10 |
| `agent-archivist/derived/` | derived projections | reserved, Phase 10 |

Plan §7.5's logical scheme (`tenants/<tenant>/v1/{raw,control,catalog,derived}/…`)
maps onto this tree per storage profile; the physical ARMOR keys are what the
ACLs below guard. `catalog/` and `derived/` are provisioned in the
backup/restore credential's ACL now so that enabling them in Phase 10 is a
code event, not a credential event.

## Identities

Four credentials, disjoint action-by-prefix policy. Values were generated in
place and piped into OpenBao under the write-only provisioning identity; they
have never been agent-visible text.

| Role | Auth-file name | ACL | Held by | OpenBao path (per-role copy) |
|---|---|---|---|---|
| control reader | `ARCHIVIST_CONTROL_READER` | `iad-ci:agent-archivist/control/*:get+list` | ingest replicas | `secret/rs-manager/iad-ci/armor/archivist-control-reader` |
| raw writer | `ARCHIVIST_RAW_WRITER` | `iad-ci:agent-archivist/raw/*:put+list+abort` | ingest replicas | `secret/rs-manager/iad-ci/armor/archivist-raw-writer` |
| control admin | `ARCHIVIST_CONTROL_ADMIN` | `iad-ci:agent-archivist/control/*:put+list` | offline admin CLI only | `secret/rs-manager/iad-ci/armor/archivist-control-admin` |
| backup/restore | `ARCHIVIST_BACKUP_RESTORE` | `iad-ci:agent-archivist/{raw,control,catalog,derived}/*:get+list` (four comma-separated entries) | offline backup tooling | `secret/rs-manager/iad-ci/armor/archivist-backup-restore` |

Per-role paths hold `ACCESS_KEY` / `SECRET_KEY` (the same field convention as
the `transcripts` path), so a future ingest-replica ExternalSecret references
them directly. The same four pairs are entries in the ARMOR_AUTH_FILE
document — that is how ARMOR itself learns them. Ingest replicas receive the
first two ONLY; the plan is explicit that they never receive the control-admin
credential.

The raw writer's `abort` covers only uncommitted multipart sessions —
`abort` never implies `delete` (see Enforcement notes), so no credential in
this set holds any destroy capability over committed objects.
Notably the control admin is `put+list` without `get`: the admin CLI writes
validated, tenant-authority-signed records and never reads raw or control
data back through this identity.

## Raw writer and abort

ARMOR granted `AbortMultipartUpload` its own `abort` verb on 2026-09-13
(ARMOR bead `armor-7bee0797`, commit `3cb77d474`; first shipped in release
0.1.1969). At provisioning time the iad-ci deployment still ran **0.1.1964**,
which predates the split: there `abort` does not exist as a verb, and
aborting maps to `delete` — the exact power the raw writer must never hold.
Worse, 0.1.1964's ACL parser rejects `abort` as an unknown verb, which fails
the whole auth file, so the verb could not be pre-provisioned either. The
raw writer was therefore provisioned `put+list` as a recorded interim state:
immutability held throughout, and what was deferred was cleanup of the
writer's OWN uncommitted multipart uploads on the validation-failure path
(size, expansion-ratio, media, digest) — storage cost, never integrity.

**Enabled 2026-09-14 (bead `aa-e4dcf1c2`):**

1. **Deployment first.** iad-ci ARMOR promoted to
   `ronaldraygun/armor:0.1.1969@sha256:2e015bb1eef6c04fd8ee60111588ef82e7cf56a88f7c125d3b3a6128865cca4c`
   via declarative-config commit `5808d3d7` (bead `aa-e827d0f0`); the
   serving pod runs it. The credential change below was made only after the
   new version was confirmed live, since 0.1.1964 would have refused the
   verb at parse time and failed the whole auth file.
2. **ACL + re-issue.** Under the write-only provisioning identity, by pipe
   and never argv: the merged ARMOR_AUTH_FILE document
   (`secret/rs-manager/iad-ci/armor/credentials`, CAS 5→6) had its
   `ARCHIVIST_RAW_WRITER` entry rewritten to
   `iad-ci:agent-archivist/raw/*:put+list+abort` and re-issued with a fresh
   keypair; the per-role path
   `secret/rs-manager/iad-ci/armor/archivist-raw-writer` (CAS 1→2) holds the
   same new pair. The transform asserted exactly three line replacements
   inside the raw-writer block — no other entry touched. Nothing held the
   old pair (ingest replicas are not deployed yet), so the re-issue broke
   nothing.
3. **Propagation, no restart.** rs-manager is the owning authority; the
   change reaches ARMOR through the ~30-minute cross-cluster replicator,
   the `armor-credentials` ExternalSecret refresh (1h interval), and the
   auth-file hot-reload watcher (10s poll).

`delete` remains ungranted, permanently: `abort` never implies `delete`
(see Enforcement notes), so the raw writer can tear down its own
uncommitted multipart sessions and still cannot destroy a committed object.
This unblocks incomplete-upload teardown on the validation-failure and
graceful-shutdown paths (bead `aa-1fa9b1dc`).

## Enforcement notes

- Prefix matching is literal `strings.HasPrefix` after ACL normalization:
  `agent-archivist/control/*` means every key under
  `agent-archivist/control/`. The bare prefix without a key (e.g. the exact
  string `agent-archivist/raw`) is NOT inside the grant.
- Bucket-level listings (ListObjectsV2) are authorized against the request's
  `prefix` query parameter, so scoped clients must always list WITH an
  explicit in-scope prefix; a bare bucket GET is refused. ListBuckets is
  refused for every prefix-scoped credential.
- `delete` implies `abort` for entries that hold it (backward compatibility);
  `abort` never implies `delete`.

## Verification

Property-based (values never printed): each per-role path verified via
`bao kv metadata get` (version 1, created 2026-09-14); the merged document
verified at version 5 with the six pre-existing consumer entries
(`FORGEJO_BACKUP`, `FORGEJO`, `CNPG_BACKUPS`, `CI_CACHE`,
`RESTORE_VERIFIER`, `TRANSCRIPTS`) untouched, plus the four new entries with
exactly the ACL strings above.

Live authorization: positive and negative S3 calls per role against the
serving iad-ci ARMOR pod. The full per-role matrix staged by the
provisioning bead (calibration: TRANSCRIPTS list → AccessDenied, i.e.
signature verified and ACL-refused) was left pending its propagation
window; the raw-writer role's matrix, run at abort enablement, is appended
below.

### Abort enablement (2026-09-14, bead aa-e4dcf1c2)

Property-based (values never printed): merged document CAS 5→6, per-role
raw-writer path CAS 1→2 via `bao kv metadata get`. The rewritten document
was verified structurally before the write: same ten entries, exactly one
`put+list+abort` occurrence, no remaining `put+list`-only raw-writer line;
the transform asserted exactly one access_key, one secret_key and one acl
replacement inside the `ARCHIVIST_RAW_WRITER` block, no other line changed.
The re-issued pair matches between the merged document and the per-role
path (verified by comparison, never by printing). ARMOR-side pickup is
observable in the serving pod's log — the hot-reload watcher logs
`reloaded ARMOR_AUTH_FILE successfully` with entry names, never keys.

Live authorization (SigV4 over port-forward against the serving pod,
credentials by environment only, only status and error codes printed),
run 2026-09-14 against pod `armor-ffbccc787-s8lh7` (0.1.1969, started
21:08:24Z), matrix under bead `aa-e827d0f0`:

| # | Caller | Operation | Observed |
|---|---|---|---|
| 1 | raw writer | ListObjectsV2 prefix `agent-archivist/raw/` | 200 (prefix empty at run time) |
| 2 | backup/restore | ListObjectsV2 prefix `agent-archivist/raw/` | 200 |
| 3 | control admin | ListObjectsV2 prefix `agent-archivist/control/` | 200 |
| 4 | raw writer | CreateMultipartUpload `agent-archivist/raw/aa-e827d0f0-abort-matrix/canary` | 200 |
| 5 | raw writer | UploadPart part 1 (64 KiB) | 200 |
| 6 | control admin | AbortMultipartUpload — the writer's in-flight upload | 403 AccessDenied |
| 7 | backup/restore | AbortMultipartUpload — the writer's in-flight upload | 403 AccessDenied |
| 8 | control admin | PutObject into `agent-archivist/raw/` | 403 AccessDenied |
| 9 | backup/restore | PutObject into `agent-archivist/raw/` | 403 AccessDenied |
| 10 | raw writer | AbortMultipartUpload — its own in-flight upload | 204, session discarded |
| 11 | raw writer | PutObject of a documented canary (row 4's key) | 200 |
| 12 | raw writer | DeleteObject — the committed canary | 403 AccessDenied |
| 13 | raw writer, superseded pair | ListObjectsV2 prefix `agent-archivist/raw/` | 403 InvalidAccessKeyId |

Rows 1–3 calibrate the matrix: each identity's signature verifies where its
ACL grants the verb, so every 403 below is an ACL refusal, not a credential
failure. Rows 6–7 keep the other two identities out of the writer's
teardown path; that refusal is unchanged from 0.1.1964. What the split
changed is the writer's own row: pre-split, row 10 was evaluated against
`delete` and refused (the writer holds no `delete`); post-split the same
call authorizes on `abort` alone and returns 204. Row 12 pins the one-way
door: `abort` never implies `delete`, so the writer reaps uncommitted
sessions and still cannot destroy a committed object. Row 13 proves the
merged document was replaced, not augmented — the superseded key is dead
at the edge. Pre-split, this live matrix could not have been staged at
all: 0.1.1964's parser rejects `abort` as an unknown verb and fails the
entire auth file at load, which is why the deployment promotion (step 1)
had to precede the credential re-issue (step 2).

Pickup, without any credential-driven restart: the serving pod's startup
config log (entry names and key IDs only, secret keys `<set>`) shows the
raw-writer auth-file entry loaded with `actions {abort, list, put}` — the
re-issued pair (written 20:43Z) was already in the document before this
pod's first load; the 10 s hot-reload watcher (up 21:16:26Z, after the
480 s manifest load) stood by but had nothing to do. Propagation chain as
recorded in step 3: OpenBao rs-manager → ~30 min cross-cluster replicator
→ `armor-credentials` ExternalSecret (1 h refresh) → auth file.

Residue: row 11 leaves one committed canary object,
`agent-archivist/raw/aa-e827d0f0-abort-matrix/canary` (the raw prefix held
zero objects at run time — ingest replicas are not deployed yet). The raw
writer cannot remove it by design; it stands as a read-probe target for
the ARMOR profile qualification bead (`aa-0a2562d8`) and can be removed
only by an operator — no archivist identity holds `delete`. The row-4
multipart session left nothing; it was aborted in-row.
