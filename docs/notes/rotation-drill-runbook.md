# ARMOR storage-identity rotation drill runbook

Status: accepted baseline · Last updated: 2026-09-28

Authority: [ARMOR storage provisioning](armor-storage-provisioning.md),
"Rotation procedure" and "Rotation propagation" (bead `aa-d0c81e9e`; the
control-reader drill is bead `aa-51a272be`). This runbook is the operating
guide that turns that procedure's deployment half into one repeatable,
machine-checked sequence; the property it owns is that **every rotation is
itself a drill** — the calendar rotations keep the propagation path
exercised, and each run leaves evidence that the four drill properties
held, without a single credential value leaving the channel.

Two tools, one operator:

- [`tools/rotation-drill.py`](../../tools/rotation-drill.py) — the
  orchestrator: `baseline` → `watch` → `flip` → `verify` around one
  evidence file. It observes the cluster through the credential-free
  read-only kubectl endpoint and composes the probe; it never writes a
  credential anywhere.
- [`tools/rotation-drill-probe.py`](../../tools/rotation-drill-probe.py) —
  the per-credential live instrument (steps 1, 5, and 6 of the
  procedure). One invocation exercises one credential against the serving
  edge and prints only HTTP status and S3 error codes.

Staging the rotation itself — procedure steps 2–4 — stays a manual OpenBao
write under the provisioning identity, by pipe, values never agent-visible.
That is deliberate: the drill automates observation and verification, never
the write.

## 1. What a drill proves

| Drill property | Stage | Machine check (`verify`) |
|---|---|---|
| the documented delivery chain still stands | `baseline` preflight | Reloader annotation, subPath secret mount, RollingUpdate, startup/readiness probes, ready ExternalSecret with its refresh interval |
| replacement replicas serve the new credential | `watch` + `verify` | the replacement pod's startup dump carries the new fingerprint; the retired fingerprint appears nowhere in the replacement dumps |
| old credentials are rejected at the edge | `flip` | retired pair → `403 InvalidAccessKeyId` |
| refusals are calibrated, not coincidental | `flip` | wrong secret → `403 SignatureDoesNotMatch`; out-of-scope prefix → `403 AccessDenied` |
| service continuity through the rollout | `watch` | per-sample ready count never sampled at 0; the recorded hop shows ESO refresh bump → new pod Ready → baseline pods gone |
| no secret values in evidence | every stage | the evidence write is refused (exit 5) if any supplied pair value reaches the text; only fingerprints and status codes are recorded |

## 2. Prerequisites

- **Cluster reads:** kubectl against the credential-free read-only proxy
  (`http://traefik-iad-ci:8001` — the default; override with
  `ARMOR_DRILL_KUBECTL_SERVER`). The proxy cannot read Secrets and cannot
  port-forward, so the watch observes the ExternalSecret's
  `status.refreshTime` (never the Secret's contents) and the probes need an
  edge reachable from the drill host — both are recorded as evidence facts.
- **Probe edge:** `ARMOR_PROBE_ENDPOINT` — the vpn entrypoint
  (`https://armor-iad-ci-ts.ardenone.com`) or a transient port-forward to
  the serving pod, which is how the recorded drills ran it. boto3 must be
  importable for a live probe run.
- **Pairs, environment only:** the current (post-write: soon-to-be-retired)
  and replacement pairs travel in `ARMOR_DRILL_CURRENT_AKID` /
  `ARMOR_DRILL_CURRENT_SECRET` / `ARMOR_DRILL_RETIRED_AKID` /
  `ARMOR_DRILL_RETIRED_SECRET`. Export them from an OpenBao read without
  ever printing them — never argv, never a file the transcript can read.
  `verify` needs only the two access-key IDs (fingerprints), never the
  secrets. `ARMOR_DRILL_ROLE` is a free-text label for the evidence.
- **Scope defaults:** namespace/deployment `armor`, ExternalSecret
  `armor-credentials`, selector `app=armor`, container `armor` — all
  overridable (`ARMOR_DRILL_*`); the probe's bucket/region/prefix defaults
  pin today's tree.

## 3. Running a drill

Numbering here is the drill's; each stage names the procedure step it
implements. Every stage appends to the same `--out` evidence file (created
mode `600`).

1. **`baseline`** (procedure step 1 — pin the serving state):

   ```bash
   tools/rotation-drill.py baseline --out /run/armor-drill/evidence.json \
     [--probe-mode list|cycle]
   ```

   Preflight asserts the delivery chain where it stands (a drift is a
   finding, not a tool error), snapshots the serving pods, captures the
   serving pod's `ARMOR starting` dump fingerprints (best effort — kubelet
   log rotation can retire the line; the positive probe is the accepted
   substitute), and runs the "old pair works" positive pin. Use
   `--probe-mode cycle` for a raw-writer rotation: the pin is then the full
   create-mpu → upload-part → abort cycle, ending at abort's 2xx (the
   serving edge answers 204).

2. **Generate the replacement in place** (procedure step 2): piped straight
   from `openssl rand`/`tr` into the stash or KV — 20 mixed-case
   alphanumeric access key, 64-hex secret. Never argv, never a file the
   transcript can read.

3. **Write both copies, CAS-guarded** (procedure steps 3 and 4): the merged
   document `secret/rs-manager/iad-ci/armor/credentials` — rewrite only the
   role's block, asserting exactly two line-level replacements and every
   other line byte-identical — and the per-role path
   `secret/rs-manager/iad-ci/armor/archivist-<role>`. Both through
   `bao-as rs-manager-provision` with `-cas=<current>`. The copies must
   match by comparison of fingerprints, never by printing. Record the last
   write time (`date -u`) — it is the watch's `t0`.

4. **Pin the inverse** (procedure step 5; recommended, not yet automated):
   against the still-serving pre-rollout pod, two direct probe runs —
   replacement pair → `403 InvalidAccessKeyId`, current pair → 2xx. This is
   what later makes the flip exclusively attributable to the propagation
   event; paste both probe output lines into the drill log.

5. **`watch`** (procedure step 6, propagation half):

   ```bash
   tools/rotation-drill.py watch --out /run/armor-drill/evidence.json \
     --timeout 95m --interval 30s [--t0 <last-write, RFC3339>]
   ```

   Polls until the full chain is observed — ExternalSecret `refreshTime`
   bump, new pod appears and goes Ready, baseline pods terminate, and the
   replacement pod's startup dump captured the moment it runs (kubelet
   retention can be under an hour at request volume). `--timeout 95m`
   budgets one ESO refresh phase (0–60 min, phase-uniform) plus the
   seconds-long Reloader rollout plus the ~10 min startupProbe cap; the
   recorded drills measured 38m37s and similar end to end. Each sample
   records the ready count, so continuity is a fact about the rollout, not
   an impression. Exit 4 on timeout — evidence is still written; read the
   hop before re-running anything.

6. **`flip`** (procedure step 6, enforcement matrix):

   ```bash
   tools/rotation-drill.py flip --out /run/armor-drill/evidence.json \
     [--probe-mode cycle]   # raw writer; reader roles stay on list
   ```

   One probe subprocess per credential state, pair in the child's
   environment only: current pair positive (2xx), retired pair
   `403 InvalidAccessKeyId`, current key with a fixed sentinel wrong
   secret `403 SignatureDoesNotMatch`, out-of-scope prefix
   `403 AccessDenied`. Under `--probe-mode cycle` the refused rows refuse
   at create-mpu with the same calibrated codes and nothing is ever
   written.

7. **`verify`** (the verdict):

   ```bash
   tools/rotation-drill.py verify --out /run/armor-drill/evidence.json
   ```

   Replays the evidence against the documented expectations and prints one
   line per failed check. Exit 0 is the drill's PASS; exit 3 names every
   failed check. Record the verdict and the evidence path on the rotation
   bead, then update the provisioning note's interval table (new anchor
   version and date) in the same commit as the drill record.

## 4. Rolling back a rotation

A rollback is the six-step procedure run in reverse: the pair that was
serving before the bad write goes back into both copies, CAS-guarded, and
the same drill stages prove the recovery. It is the documented response to
a rotation that must be undone — a pair written with a wrong value, a
transform staged against the wrong role's block, a drill `verify` failing
on rows attributable to the new pair, a rotation executed in error. It is
**not** the response to a suspected compromise of the new pair: a rollback
puts a previously-live credential back into service, so it presumes that
credential is still good — compromise re-rotates *forward* (the
provisioning note's "Revocation" section), never back.

Three properties make it safe to run under the same rules as the forward
rotation:

- **Nothing is deleted.** KV v2 history is the safety net
  (`max_versions=20`; `delete` left every agent-reachable policy
  2026-08-31). A rollback write is a CAS-guarded create of a new version
  whose content is the known-good pair.
- **The Deployment spec never changes.** There is no `kubectl rollout
  undo` to reach for — mutating kubectl is prohibited fleet-wide, and it
  would be beside the point: the credential arrives through the Secret
  mount, so the fix is entirely on the OpenBao side and the preflight
  sees no drift.
- **The version counter is append-only, not a stack.** After a rollback
  the newest version's content equals an older version's, so naive
  "current − 1" arithmetic points at the bad pair. Always target the
  version the rotation record names, never one less than current.

### The propagation window is the cheap rollback

The ExternalSecret reads the merged document at its refresh tick (1 h,
phase-uniform), so a bad write has a head start before it can reach the
cluster at all — the recorded rotation's write landed 27 minutes ahead of
its tick. If **both** copies are restored before the next tick, the
Secret's content never changes, Reloader never fires, and no pod ever
rolls: the bad write never becomes live, and the drill record is the two
CAS writes plus a positive pin (the restored pair never stopped being the
serving pair, so the pin stays 2xx throughout). The merged document is
the copy the ExternalSecret reads
(`secret/rs-manager/iad-ci/armor/credentials`, property
`credentials.yaml`); the per-role path is the mirror whose match the
invariant asserts — a rollback is only complete when both are back, and
only the merged document's restore is time-critical.

### Rolling back after propagation

Once the tick has passed, the bad pair is live and the rollback is a full
rotation in reverse, budgeted like one (one refresh phase plus the
Reloader rollout; the standing `--timeout 95m`):

1. **Pin the restore point.** From the rotation record, name the version
   of both paths that was serving and verified before the bad write; `bao
   kv metadata get -format=json` confirms both paths' current versions
   (metadata only — no value read).
2. **Restore the merged document (CAS+1).** Read the current document via
   the read identity into a mode-600 tmpfs file, then run the same scoped
   transform as procedure step 3, writing the restored values into the
   role's `access_key`/`secret_key` lines — asserting exactly two
   line-level replacements, the entry count unchanged, and every other
   line byte-identical **against the current document**, never a
   wholesale restore of the old file (any other role that rotated onto it
   in the meantime must survive).
3. **Restore the per-role path (CAS+1)** with the same pair; match the
   copies by comparison of fingerprints, never by printing.
4. **Pin the inverse** (stage 4 above): against the then-serving pod, the
   pair being restored → refused and the live (bad) pair → 2xx — the
   mirror image of a forward rotation's pin, and what attributes the
   later flip to the rollback propagation. (If the bad pair is
   shape-invalid it cannot produce a calibrated refusal; record what the
   probe reported — that report is itself evidence of the fault.)
5. **`watch`** the rollback rollout (stage 5 above): ESO refresh bump,
   new pod Ready, baseline pods gone, per-sample ready counts.
6. **`flip` + `verify`** (stages 6–7 above) with the pairs swapped:
   `current` = the restored pair (must go positive), `retired` = the bad
   pair. Two verdict shapes are possible, and the record must say which
   it ran:
   - bad pair **shape-valid but wrong**: its refusal is the calibrated
     `403 InvalidAccessKeyId` and the verdict is a normal PASS;
   - bad pair **shape-invalid**: the probe fails client-side before any
     HTTP exchange, the `retired_pair_rejected` row records `?` and
     fails. That single named failure is the expected rollback verdict in
     this case — every other check must pass. A verdict failing anything
     else is not a rollback that worked.
   The fingerprint checks scope correctly on their own: the bad pair's
   fingerprint belongs in this drill's *baseline* dumps (it was serving
   when they were taken) and must be absent from the replacement dumps.
   For the same reason the baseline positive pin is expected to be
   refused when the drill starts against a bad-serving edge — `baseline`
   records it and exits 0, and `verify`'s step-1 check recovers through
   the replacement dump's restored fingerprint.
7. **Record** which versions were restored and why. The interval table's
   anchor keeps the restored pair's fingerprint but takes the rollback's
   version number — write it as `v<N> (restore of v<M>)` so the next
   reader's version arithmetic starts from the right place.

### Availability during a rollback

The same property that makes a forward rotation safe makes the rollback
safe: the edge keeps answering with the credential the serving pod
started with until Reloader replaces it, and the rollout is 1 replica
with `maxUnavailable: 25%` — which rounds to zero unavailable, so the
prior pod serves until the replacement is Ready (the propagation
measurements agree: neither recorded drill sampled a ready gap). If the
bad pair was merely unwanted, it serves like any other credential and
readiness never dips. If it is malformed enough that ARMOR cannot serve
from it, the replacement pod stalls the rollout instead — the prior pod
keeps serving while the startupProbe budget (~10 min) runs — and the
rollback write heals the deployment on the next propagation. What no
rollback can shorten is the ESO refresh phase: plan on the same 0–60
minutes, or catch the write before the tick and spend none of it.

## 5. Evidence handling

The evidence file is JSON, mode `600`, schema
`rotation-drill-evidence/v1`, written to a tmpfs path
(`/run/armor-drill/`) and treated like the drill log it is: references and
statuses only. Credential-derived values appear solely as fingerprints —
first 16 hex of SHA-256 of an access-key ID, the same
`crypto.IdentifierFingerprint` shape ARMOR's startup dump prints — plus
the redacted ACL shapes ARMOR itself prints in that dump. Before every
write the serialized text is scanned for each supplied pair value; a hit
refuses the write (exit 5) rather than redacting, because a hit is a tool
bug. The file never enters a repository; keep it out of `$HOME` globs and
shred it when the drill record is written.

## 6. Exit codes

| Code | Meaning |
|---|---|
| 0 | stage succeeded / self-test pass / verify PASS |
| 1 | usage or environment error (missing pairs for `flip`, bad duration) |
| 2 | self-test failure |
| 3 | verify verdict FAIL (each failed check is named) |
| 4 | stage or evidence error (watch without baseline, watch timeout, verify on an incomplete drill) |
| 5 | evidence write refused — a supplied pair value reached the evidence text |

## 7. Deliberately not automated

- **The OpenBao writes.** Procedure steps 2–4 — and their rollback
  counterparts in "Rolling back a rotation" — stay manual, under the
  write-only provisioning identity, by pipe — the drill observes and
  verifies, it never holds a credential.
- **The live drill is not a DoD gate.** It needs a reachable serving edge
  and real pairs. What gates instead is both tools' `--self-test` in the
  fast lane of [`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh):
  the probe proves its output contract against an in-process fake client
  (no network, no boto3 import, a planted pair unreachable); the
  orchestrator proves the evidence/redaction contract and that every
  injected fault — a ready-count gap, a retired fingerprint still in a
  replacement dump, a flip row off by one error code, a degraded
  preflight, a stripped replacement dump, a leaky probe — fails the
  verdict, against a scripted fake cluster with a real rollout timeline.
