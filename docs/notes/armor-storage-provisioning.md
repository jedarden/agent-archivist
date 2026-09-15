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
  `secret/rs-manager/iad-ci/armor/credentials` (property `credentials.yaml`).
  On change the credential set is replaced with no ARMOR Deployment change —
  measured 2026-09-15 the delivery is a Reloader-triggered pod replacement
  (the deployment mounts the file via `subPath`, so the in-process 10 s
  watcher stays armed but does not fire); see "Rotation propagation".
- rs-manager's OpenBao is the authority for `secret/rs-manager/*`, and the
  iad-ci ExternalSecret store resolves to that authority directly (ExternalName
  Service → Tailscale proxy → `traefik-rs-manager.tail1b1987.ts.net:8200`;
  the ~30-minute cross-cluster replicator is NOT in this path). A write here
  is visible to ARMOR within one ESO refresh interval (1 h, phase-uniform)
  plus the rollout window — measured end-to-end 35 m 07 s on 2026-09-15
  (see "Rotation propagation").

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
   change reaches ARMOR through the `armor-credentials` ExternalSecret
   refresh (1h interval) and a Reloader-triggered pod replacement.
   [Corrected 2026-09-15, bead `aa-51a272be`: the original text credited
   the ~30-minute cross-cluster replicator and the 10s in-file watcher —
   neither is in the delivery path; see "Rotation propagation".]

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
config log (entry names and access-key **fingerprints** only — corrected
2026-09-15, bead `aa-51a272be`: the "key IDs" below are
`crypto.IdentifierFingerprint` values, first 16 hex of SHA-256 of the
identifier, not the raw IDs; secret keys `<set>`) shows the
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

## Rotation propagation (2026-09-15, bead aa-51a272be)

Both documented behaviors exercised live by rotating the control-reader
credential. The rotation was staged 2026-09-15 03:41Z through the
write-only provisioning identity, by pipe and never agent-visible text:
new pair generated in place (`openssl rand` piped into `bao kv put`),
merged document CAS 6→7 at **03:41:20Z**, per-role path CAS 1→2 at
**03:41:22Z**, the transform asserting exactly two line replacements
inside the `ARCHIVIST_CONTROL_READER` block and nothing else changed.
Attempt 1 of the bead staged the write and pinned the pre-propagation
baseline, then hit its hard timeout before the refresh window opened;
attempt 2 completed observation and made no further write — the serving
pod had already picked the pair up, and re-rotating would have forced a
second serving-pod replacement for no additional evidence.

### Measured propagation

| Hop | Time (UTC) | Δ from write |
|---|---|---|
| OpenBao rs-manager write (authority; KV v7 / per-role v2) | 03:41:22 | t0 |
| `armor-credentials` ExternalSecret refresh materializes the Secret | 04:08:26 | +27m04s |
| Reloader rollout: replacement pod process start | 04:08:29 | +3s |
| Replacement pod Ready, serving the rotated set (flip effective at edge) | 04:16:29 | +8m07s |
| **End-to-end** | | **35m07s** |

The ESO materialization time is read from its hourly refresh cadence
(status `refreshTime` 06:08:26Z, interval 1h → prior refreshes 05:08:26,
04:08:26); the write at 03:41 landed in the 04:08:26 window, i.e. the
27m04s wait is pure refresh-phase, uniformly distributed 0–60 min by
schedule. Inside the documented bound (one ESO refresh interval plus one
replication cycle ≈ ≤90 min), but the decomposition shows the bound's
replication term never applies — see corrections.

### Chain corrections

1. **No replication hop exists in ARMOR's credential path.** The iad-ci
   ClusterSecretStore `openbao` (`http://openbao.external-secrets.svc.cluster.local:8200`)
   is an ExternalName Service → Tailscale proxy pod `ts-openbao-zcwbs` →
   `traefik-rs-manager.tail1b1987.ts.net:8200` — the rs-manager authority
   itself (verified via unauthenticated `/v1/sys/health`: same cluster id
   as the authority; the proxy pod's operator annotation names the target
   FQDN). The ~30-minute cross-cluster replicator targets
   ardenone-cluster-v2 and ardenone-manager; it feeds other instances,
   not this store. True bound: **one ESO refresh interval (≤1h,
   phase-uniform) + seconds of Reloader rollout + the manifest-load
   window** — observed 8m07s (the startup manifest load ran its full
   480s timeout on a stale writer shard before the S3 listener bound;
   the startupProbe budget caps Ready delay at ~10 min).
2. **Delivery is a Reloader rollout, not the in-process watcher.** The
   Deployment mounts the auth file via `subPath` and carries
   `reloader.stakater.com/auto: "true"`, so a Secret change rolls the pod
   automatically — "adding credentials requires no ARMOR Deployment
   change" holds, but the mechanism is pod replacement (default
   RollingUpdate; the prior pod serves until the replacement is Ready),
   not hot reload. The 10s auth-file watcher polls the file's mtime, and
   the kubelet never rewrites a running container's subPath mount —
   accordingly no `reloaded ARMOR_AUTH_FILE successfully` line exists in
   the serving pod's log. The watcher stays armed as defense in depth for
   direct in-place file edits.

### Enforcement flip (live, 07:06Z)

SigV4 over port-forward to the serving pod `armor-7bdfd64cf5-h5n62`
(0.1.1969), credentials by environment only, only status and error codes
printed:

| # | Caller | Operation | Observed |
|---|---|---|---|
| 1 | control reader, rotated pair | ListObjectsV2 prefix `agent-archivist/control/` | 200 (prefix empty) |
| 2 | control reader, retired pair | ListObjectsV2 prefix `agent-archivist/control/` | 403 InvalidAccessKeyId |
| 3 | control reader, rotated key, wrong secret | ListObjectsV2 prefix `agent-archivist/control/` | 403 SignatureDoesNotMatch |
| 4 | control reader, rotated pair | ListObjectsV2 prefix `agent-archivist/raw/` (no grant) | 403 AccessDenied |

Rows 3–4 calibrate row 2: the retired pair's refusal is identity-level
(key unknown to ARMOR), not a signature error; row 1's 200 is an in-scope
authorization, not a bypass. The pre-propagation inverse (retired pair
**200** on the same prefix, new pair **403 InvalidAccessKeyId** against
the then-serving pod) was pinned at 04:11Z — minutes before the ESO
refresh landed — so the flip is complete and exclusively attributable to
the propagation event.

Pickup is also provable offline, without printing keys: ARMOR's `ARMOR
starting` dump runs `Redacted()`, which replaces every access-key ID and
the bucket name with a `crypto.IdentifierFingerprint` (first 16 hex of
SHA-256 of the identifier). The dump's control-reader entry
`7d535850c0aaba71` equals the fingerprint of the rotated access key; the
retired key's fingerprint (`aedcc191835ba481`) appears nowhere; the raw
writer, control admin, backup/restore and transcripts fingerprints also
match their expected pairs, and the bucket renders as
`202f132fe6eecc0f` = fingerprint of `iad-ci`.

### Distribution invariant (pinned)

Ingest replicas receive ONLY the control-reader and raw-writer
credentials and never the control-admin credential. Pinned 2026-09-15 at
three layers:

- **Manifests:** zero references to any
  `secret/rs-manager/iad-ci/armor/archivist-*` per-role path anywhere in
  declarative-config (all clusters, all resource kinds).
- **Live cluster:** zero ExternalSecrets across iad-ci reference a
  per-role archivist path — every consumer secret targets its own
  per-consumer path (`forgejo`, `cnpg-backups`, `ci-cache`, `transcripts`,
  …). The only cluster-side copy of the four archivist credentials is
  ARMOR's own merged auth-file document, which must hold all four because
  ARMOR is the enforcement point; it is not an ingest replica.
- **OpenBao:** `archivist-control-admin` is at v1 — never re-issued and
  never copied since creation (2026-09-14T06:51:07Z);
  `archivist-backup-restore` likewise v1; `archivist-raw-writer` v2 (the
  recorded abort re-issue); `archivist-control-reader` v2 (this
  rotation).

When ingest replicas are provisioned, their ExternalSecrets must
reference only `secret/rs-manager/iad-ci/armor/archivist-control-reader`
and `.../archivist-raw-writer` — never `.../archivist-control-admin`,
which stays with the offline admin CLI.

KV state after this exercise: `secret/rs-manager/iad-ci/armor/credentials`
v7, `.../archivist-control-reader` v2 — current serving state matches
both. Residue noted: the `armor-credentials-externalsecret.yaml` header
comment in declarative-config still lists five named credentials (ten
since 2026-09-14); comment-only, no functional effect.
