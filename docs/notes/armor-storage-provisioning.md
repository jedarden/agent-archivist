# ARMOR storage provisioning — prefix layout and scoped identities

Provisioned 2026-09-14 (bead `aa-adeab1be`); raw-writer abort enablement
2026-09-14 (bead `aa-e4dcf1c2`); abort deployment promotion and live
enforcement matrix 2026-09-14 (bead `aa-e827d0f0`); catalog/derived writer
provisioning 2026-09-15 (bead `aa-649c5895`). Records the ARMOR-side storage
decision for this tenant: the prefix tree, the six scoped identities that
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
| `agent-archivist/catalog/` | catalog checkpoints | reserved, Phase 10 — writer provisioned 2026-09-15 |
| `agent-archivist/derived/` | derived projections | reserved, Phase 10 — writer provisioned 2026-09-15 |

Plan §7.5's logical scheme (`tenants/<tenant>/v1/{raw,control,catalog,derived}/…`)
maps onto this tree per storage profile; the physical ARMOR keys are what the
ACLs below guard. `catalog/` and `derived/` are provisioned in the
backup/restore credential's ACL now so that enabling them in Phase 10 is a
code event, not a credential event — and since 2026-09-15 (bead
`aa-649c5895`) each also has its own scoped write identity, so the Phase 10
writers need no credential event either.

## Identities

Six credentials, disjoint action-by-prefix policy. Values were generated in
place and piped into OpenBao under the write-only provisioning identity; they
have never been agent-visible text. The first four were provisioned
2026-09-14 (bead `aa-adeab1be`); the two Phase 10 writers followed
2026-09-15 (bead `aa-649c5895`, see "Catalog and derived writer
provisioning").

| Role | Auth-file name | ACL | Held by | OpenBao path (per-role copy) |
|---|---|---|---|---|
| control reader | `ARCHIVIST_CONTROL_READER` | `iad-ci:agent-archivist/control/*:get+list` | ingest replicas | `secret/rs-manager/iad-ci/armor/archivist-control-reader` |
| raw writer | `ARCHIVIST_RAW_WRITER` | `iad-ci:agent-archivist/raw/*:put+list+abort` | ingest replicas | `secret/rs-manager/iad-ci/armor/archivist-raw-writer` |
| control admin | `ARCHIVIST_CONTROL_ADMIN` | `iad-ci:agent-archivist/control/*:put+list` | offline admin CLI only | `secret/rs-manager/iad-ci/armor/archivist-control-admin` |
| backup/restore | `ARCHIVIST_BACKUP_RESTORE` | `iad-ci:agent-archivist/{raw,control,catalog,derived}/*:get+list` (four comma-separated entries) | offline backup tooling | `secret/rs-manager/iad-ci/armor/archivist-backup-restore` |
| catalog writer | `ARCHIVIST_CATALOG_WRITER` | `iad-ci:agent-archivist/catalog/*:put+list` | Phase 10 catalog rebuild (not yet resident) | `secret/rs-manager/iad-ci/armor/archivist-catalog-writer` |
| derived writer | `ARCHIVIST_DERIVED_WRITER` | `iad-ci:agent-archivist/derived/*:put+list` | Phase 10 derived projections (not yet resident) | `secret/rs-manager/iad-ci/armor/archivist-derived-writer` |

Per-role paths hold `ACCESS_KEY` / `SECRET_KEY` (the same field convention as
the `transcripts` path), so a future ingest-replica ExternalSecret references
them directly. The same six pairs are entries in the ARMOR_AUTH_FILE
document — that is how ARMOR itself learns them. Ingest replicas receive ONLY
the control-reader and raw-writer credentials; the plan is explicit that they
never receive the control-admin credential — nor the backup/restore pair, nor
either Phase 10 writer, which belong to the archivist server's catalog and
derived pipelines.

The raw writer's `abort` covers only uncommitted multipart sessions —
`abort` never implies `delete` (see Enforcement notes), so no credential in
this set holds any destroy capability over committed objects.
Notably the control admin is `put+list` without `get`: the admin CLI writes
validated, tenant-authority-signed records and never reads raw or control
data back through this identity. The two Phase 10 writers repeat that shape
one prefix over: `put+list`, no `get`, so a writer can append checkpoints or
projections and list what is there, but never reads object bodies back
through the write identity and holds no destroy capability.

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

## Catalog and derived writer provisioning (2026-09-15, bead aa-649c5895)

Until 2026-09-15 the two reserved prefixes had a read grant only: the note
above claimed enabling them in Phase 10 was "a code event, not a credential
event", but no credential in the set could put to either prefix, so every
Phase 10 writer (deterministic catalog rebuild, versioned Parquet inventory,
derived projections such as redacted episodes and usage summaries) would
have required a credential event after all. The two write identities in the
table above close that gap, preserving the documented invariant that no
credential holds destroy capability: `put+list` only, never `delete`, never
`abort`.

Provisioned under the write-only provisioning identity, by pipe and never
agent-visible text, same as every change to this document:

- **Merged document (CAS 8→9).** Exactly two entries appended —
  `ARCHIVIST_CATALOG_WRITER` and `ARCHIVIST_DERIVED_WRITER` with the ACL
  strings in the table — entry count 10→12, every pre-existing entry
  byte-identical (asserted by structural diff of versions 8 and 9, names/
  ACLs/key shapes only). The transform asserted exactly the two appended
  blocks and nothing else.
- **Per-role paths created at v1.** `archivist-catalog-writer` and
  `archivist-derived-writer`, each verified to match its merged entry by
  comparison, never by printing.
- **Pair shape.** Access key 20 mixed-case alphanumeric characters (the
  archivist convention); secret key 40 characters — not the canonical
  64-hex shape the rotation procedure below pins, which was recorded after
  these pairs were minted. ARMOR imposes no key format (the auth-file
  parser accepts any non-empty key), so the pairs stand; the first
  calendar rotation of either role brings it to the canonical shape.
- **Concurrency.** The raw-writer rotation drill (`aa-d0c81e9e`) landed as
  merged-document v8 mid-provisioning; the CAS-guarded write re-read and
  rebuilt on v8, so the two changes composed without either asserting
  against a stale base.

Verification: pre-pickup calibration over port-forward — backup/restore
ListObjectsV2 on `agent-archivist/catalog/` returned 200 (endpoint, SigV4,
and the read grant proven); the new catalog-writer pair returned 403 on
both list and put (identity not yet known to ARMOR). Pickup followed the
documented delivery chain (ESO refresh → Reloader rollout): the
`armor-credentials` ExternalSecret materialized v9 at the 08:08:26Z refresh,
Reloader started the replacement pod at 08:08:29Z, and that pod's startup
dump — entry names and identifier fingerprints only — shows all twelve
auth-file entries, with the catalog-writer and derived-writer fingerprints
(`sha256:65f8885b053ed7ac`, `sha256:5ab94eafc82e2369`, first 16 hex of
SHA-256 of the identifier) matching the provisioned pairs and normalized
ACLs `agent-archivist/catalog/:{put,list}` and
`agent-archivist/derived/:{put,list}`. The six-identity set is live at the
edge as of that rollout; no object has been written under either prefix
(the prefixes stay empty until the Phase 10 code lands).

Re-verified 2026-09-15 by the bead's follow-up run, after attempt 1's hard
timeout left everything above unconfirmed (the writes landed at
07:43:27–29Z inside that attempt's window; pickup happened after it died).
OpenBao metadata matches this section — merged document v9, both per-role
paths v1, raw-writer v4 and control-reader v2 anchors unchanged. A
structural diff of merged-document v8→v9 shows exactly the two appended
blocks, every shared entry byte-identical (names, ACLs, and both key lines
compared per entry by fingerprint). Each per-role pair's AKID and secret
fingerprints equal its merged entry's and the serving pod's startup-dump
entry (`armor-664d76cbbd-mrx9n`). A live SigV4 matrix over port-forward
against that pod returned 200 on each writer's in-scope list, 403
AccessDenied out of scope (raw/ prefix), 403 SignatureDoesNotMatch on the
wrong-secret calibration, and KeyCount 0 on both prefixes — still empty.
Positive put was deliberately not probed: the put grant is pinned by the
startup dump's `actions {list, put}`, and probing it would break the
empty-prefix invariant this section records. Correction made in the same
pass: the access keys are 20 mixed-case alphanumeric characters, not
uppercase as first recorded here and in the rotation procedure's step 2 —
every identity in the set checks out mixed-case, the never-rotated
control-admin and backup/restore originals included, so the word was
never accurate.

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
exactly the ACL strings above. (A historical count: the set was four
identities then; the two Phase 10 writers were appended 2026-09-15 — see
"Catalog and derived writer provisioning".)

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
  …). The only cluster-side copy of the six archivist credentials is
  ARMOR's own merged auth-file document, which must hold all six because
  ARMOR is the enforcement point; it is not an ingest replica.
- **OpenBao:** `archivist-control-admin` is at v1 — never re-issued and
  never copied since creation (2026-09-14T06:51:07Z);
  `archivist-backup-restore` likewise v1; `archivist-raw-writer` v2 (the
  recorded abort re-issue); `archivist-control-reader` v2 (this
  rotation). [Extended 2026-09-15, bead `aa-649c5895`: the per-role set
  adds `archivist-catalog-writer` and `archivist-derived-writer`, each
  created at v1 that day; no ExternalSecret anywhere references any
  archivist per-role path, so the extension changes nothing about what
  the cluster holds.]

When ingest replicas are provisioned, their ExternalSecrets must
reference only `secret/rs-manager/iad-ci/armor/archivist-control-reader`
and `.../archivist-raw-writer` — never `.../archivist-control-admin`,
which stays with the offline admin CLI; never
`.../archivist-backup-restore`, which stays with offline backup tooling;
and never `.../archivist-catalog-writer` or
`.../archivist-derived-writer`, which belong to the archivist server's
Phase 10 catalog and derived pipelines.

KV state after this exercise: `secret/rs-manager/iad-ci/armor/credentials`
v7, `.../archivist-control-reader` v2 — current serving state matches
both. Residue noted: the `armor-credentials-externalsecret.yaml` header
comment in declarative-config still lists five named credentials (ten
since 2026-09-14); comment-only, no functional effect.

## Rotation and revocation lifecycle (bead aa-d0c81e9e)

Added 2026-09-15. The six identities are long-lived machine credentials;
**rotation is the revocation mechanism** — a re-issued pair makes the
retired one stop being accepted at the edge at the next propagation, and
nothing is ever deleted. Every step below runs under the write-only
provisioning identity (`bao-as rs-manager-provision`), by pipe, values
never agent-visible; the merged document is read once per rotation via the
read identity into a mode-600 tmpfs file that is shredded after the write.

### Rotation procedure

The same six steps rotate any of the six roles; only the entry block and
the per-role path change. End-to-end cost is bounded by one ESO refresh
(0–60 min, phase-uniform by schedule) plus the Reloader rollout — see
"Rotation propagation" for the measured decomposition.

1. **Pin the serving state.** Before writing anything: the serving pod's
   `ARMOR starting` dump must show the role's current fingerprint (first
   16 hex of SHA-256 of the access key ID), or a live positive call with
   the current pair must succeed. This is the "old pair works" half of the
   flip evidence and must predate the write.
2. **Generate the replacement in place.** Pair shape: access key = 20
   mixed-case alphanumeric characters, secret = 64 hex characters, piped
   straight from `openssl rand`/`tr` into the stash or KV — never argv,
   never a file the transcript can read.
3. **Write the merged document (CAS+1).** Read
   `secret/rs-manager/iad-ci/armor/credentials` (single KV field
   `credentials.yaml`, ten 4-line entries: `name`/`access_key`/
   `secret_key`/`acl`) via the read identity into a mode-600 tmpfs file;
   rewrite ONLY the role's block — replace the `access_key` and
   `secret_key` lines, leaving the `acl` line untouched for a pure
   rotation — asserting exactly two line-level replacements, the entry
   count unchanged, and every other line byte-identical. Write back
   through the provision identity with `-cas=<current>`.
4. **Write the per-role path (CAS+1).** Same new pair into
   `secret/rs-manager/iad-ci/armor/archivist-<role>` via the provision
   identity with `-cas` (JSON `@file`; get the current version from
   `bao kv metadata get` — 0 if the path does not exist). The two copies
   must match, verified by comparison, never by printing.
5. **Pin the inverse.** Against the then-serving pod, before propagation:
   new pair → `403 InvalidAccessKeyId`, retired pair → still
   200/2xx. This is what later makes the flip exclusively attributable
   to the propagation event rather than to a coincidental restart.
6. **Verify the flip.** After one ESO refresh materializes the Secret
   (observable as `status.refreshTime` bump and a Secret resourceVersion
   change — no value reads) and Reloader replaces the pod: new pair
   positive cycle (list / create-mpu / upload-part / abort for the raw
   writer; list for the reader), retired pair → `403 InvalidAccessKeyId`,
   wrong secret → `403 SignatureDoesNotMatch`, out-of-scope prefix →
   `403 AccessDenied` (the last two calibrate the refusal as
   signature- vs ACL-level). Offline: the replacement pod's startup dump
   must show the new fingerprint and the retired fingerprint must appear
   nowhere.

Every rotation runs the full step-6 matrix, so **every rotation is itself
a drill** of the propagation path — no separate drill cadence is needed;
the calendar rotations below keep it exercised.

### Probe tool

`tools/rotation-drill-probe.py` is the instrument for the live steps
(1, 5, and 6 above). One invocation exercises one credential against
the serving edge and prints only HTTP status codes and S3 error codes —
never key material, never object contents — so its output is safe to
record verbatim in a drill log. Modes: `list` (in-scope ListObjectsV2),
`list-control` (out-of-scope ListObjectsV2), `cycle` (create-mpu →
upload-part 64 KiB canary → abort-mpu, leaving nothing behind —
`abort`, never `delete`). The full matrix is composed across
invocations, one credential state per run: current pair positive
cycle, retired pair `403 InvalidAccessKeyId`, wrong secret
`403 SignatureDoesNotMatch`, out-of-scope `403 AccessDenied`.

Inputs are environment variables only, values by reference:
`ARMOR_PROBE_ENDPOINT` (the serving edge — both drills ran it over a
transient port-forward to the serving pod), `ARMOR_PROBE_AKID` /
`ARMOR_PROBE_SECRET` (the pair under test, exported from an OpenBao
read into the environment without ever being printed), and optional
shape overrides (`ARMOR_PROBE_BUCKET`, `ARMOR_PROBE_REGION`,
`ARMOR_PROBE_PREFIX`, `ARMOR_PROBE_OOS_PREFIX`) whose defaults pin
today's tree. Like the gate tools it carries a deterministic
`--self-test` (in-process fake client; no network, no credentials, no
boto3 import — the real import is lazy) wired into the DoD fast lane;
the live run itself is deliberately not a gate, because it needs a
reachable serving edge and real pairs.

### Intended rotation interval per role

| Role | Interval | Anchor (current version) | Next due | Rationale |
|---|---|---|---|---|
| control reader | 90 days | v2, 2026-09-15 | 2026-12-14 | resident in every ingest replica once deployed (`aa-22f5652d`) |
| raw writer | 90 days | v4, 2026-09-15 | 2026-12-14 | resident in every ingest replica; write-scoped |
| control admin | 180 days | v1, 2026-09-14 | 2027-03-13 | offline admin CLI only; never resident on any server |
| backup/restore | 180 days | v1, 2026-09-14 | 2027-03-13 | offline backup tooling; never resident |
| catalog writer | 90 days | v1, 2026-09-15 | 2026-12-14 | Phase 10 catalog rebuild; write-scoped, resident only once Phase 10 lands |
| derived writer | 90 days | v1, 2026-09-15 | 2026-12-14 | Phase 10 derived projections; write-scoped, resident only once Phase 10 lands |

The 90/180-day split keeps the always-resident pairs (merged auth file
today; per-replica ExternalSecrets once ingest replicas deploy) on a
quarterly cadence and the offline pairs on a semiannual one. Event-driven
rotation overrides the calendar for all six: immediately on suspected
disclosure, on turnover of the person or tooling holding an offline pair,
or whenever a value is observed outside the OpenBao → ESO → auth-file
channel. Both drills to date (control-reader, `aa-51a272be`; raw writer,
`aa-d0c81e9e`) ran as event-driven exercises of the documented path.

### Revocation

- **Suspected compromise, any role:** run the rotation procedure out of
  cycle. The only irreducible delay is the ESO refresh phase — worst case
  one refresh interval plus the ~10 min rollout budget. If the per-role
  OpenBao path itself is the leak, agents cannot delete it (`delete` was
  removed from every agent-reachable policy fleet-wide, 2026-08-31):
  rotate anyway, treat every historical version as burned, and ask an
  operator to prune history if the exposure was of the store itself.
- **Deregistering an identity entirely** (e.g. retiring a role after a
  migration): remove its entry from the merged document via an
  entry-level transform asserting the removal, and overwrite the per-role
  path with a fresh pair reserved for future re-registration (never
  resurrect an old version). ARMOR drops the identity at the next
  propagation. Per-role paths are append-only under agent policy;
  history is retained (`max_versions=20`) by design.
- **The control-admin identity is break-glass:** its revocation or
  deregistration is an operator decision, never an agent action.

### Raw-writer rotation drill (2026-09-15, bead aa-d0c81e9e)

The rotation wrote merged document v8 at 07:37:06Z and per-role
path v4 at 07:38:11Z (a v3 field-name slip — stash keys `AKID`/`SECRET`
instead of the path's `ACCESS_KEY`/`SECRET_KEY` convention — was
corrected a minute later; v3 is retained as history, per-role paths
being append-only). t0 is the last write, matching the control-reader
drill's convention. Observed by the drill's background watcher
(ExternalSecret `status.refreshTime`, pod list, container status — no
value reads):

| Hop | Time (UTC) | Δ from write |
|---|---|---|
| OpenBao rs-manager writes (merged doc v8 07:37:06, per-role v4 07:38:11) | 07:38:11 | t0 |
| `armor-credentials` ExternalSecret refresh materializes the Secret | 08:08:26 | +30m15s |
| Reloader rollout: replacement pod `armor-664d76cbbd-mrx9n` process start | 08:08:29 | +3s |
| Replacement pod Ready | 08:16:48 | +8m19s |
| **End-to-end** | | **38m37s** |

A second data point consistent with the control-reader decomposition
above: pure ESO refresh phase (30m15s of the 0–60 min uniform window),
the same +3s Reloader rollout, and a startup budget (~8m19s) inside the
~10 min startupProbe cap. The step-6 flip matrix (positive cycle,
retired-pair inverse, wrong-secret and out-of-scope calibration,
startup-dump fingerprint) is the drill's remaining evidence and stays
open on bead `aa-d0c81e9e`.
