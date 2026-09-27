# ARMOR storage-identity rotation drill runbook

Status: accepted baseline · Last updated: 2026-09-27

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

## 4. Evidence handling

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

## 5. Exit codes

| Code | Meaning |
|---|---|
| 0 | stage succeeded / self-test pass / verify PASS |
| 1 | usage or environment error (missing pairs for `flip`, bad duration) |
| 2 | self-test failure |
| 3 | verify verdict FAIL (each failed check is named) |
| 4 | stage or evidence error (watch without baseline, watch timeout, verify on an incomplete drill) |
| 5 | evidence write refused — a supplied pair value reached the evidence text |

## 6. Deliberately not automated

- **The OpenBao writes.** Procedure steps 2–4 stay manual, under the
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
