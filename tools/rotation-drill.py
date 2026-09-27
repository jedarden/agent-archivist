#!/usr/bin/env python3
"""Orchestrator for the ARMOR storage-identity rotation drills.

Turns the rotation procedure's deployment half (``docs/notes/
armor-storage-provisioning.md`` and ``docs/notes/rotation-drill-runbook.md``)
into one repeatable, machine-checkable sequence. The per-credential live
instrument remains ``tools/rotation-drill-probe.py`` — this tool composes it
into a drill and adds the propagation watch the probe cannot do:

1. ``baseline`` — pin the serving state before any write: the structural
   preflight of the documented delivery chain (Reloader annotation, subPath
   secret mount, RollingUpdate strategy, startup/readiness probes,
   ExternalSecret with its refresh interval), a snapshot of the serving
   pods, the serving pod's ``ARMOR starting`` dump fingerprints (best
   effort — kubelet log rotation can retire them; the procedure accepts a
   live positive call in their place), and the step-1 "old pair works"
   positive probe.
2. ``watch`` — after the operator stages the rotation through OpenBao (by
   pipe, under the provisioning identity — deliberately not automated), poll
   the chain until the flip is observed: the ExternalSecret ``refreshTime``
   bump, the rollout (new pod appears, goes Ready, baseline pods terminate),
   a per-sample ready count (service continuity), and the replacement pod's
   startup-dump fingerprints captured promptly — kubelet retention can be
   under an hour at request volume, so the dump is taken the moment the pod
   is Running, not at the end.
3. ``flip`` — the step-6 enforcement matrix, one probe subprocess per
   credential state: current pair positive, retired pair ``403
   InvalidAccessKeyId``, current key with a sentinel wrong secret ``403
   SignatureDoesNotMatch``, out-of-scope prefix ``403 AccessDenied``.
4. ``verify`` — replay the evidence file against the documented
   expectations and print the verdict: preflight held, baseline pinned,
   exactly the propagation hops observed, ready count never dropped to
   zero, the replacement pod's dump carries the new fingerprint and not the
   retired one, and every flip row matched.

Policy, one rule per check in the self-test:

1. credential pairs arrive via environment variables only (the same
   channel the probe uses) and are never echoed, logged, or written; the
   evidence file is scanned for every supplied pair value before it is
   written, and a scan hit aborts the write rather than redacting;
2. the only credential-derived values in evidence are fingerprints —
   first 16 hex of SHA-256 of the access-key ID, the same ``crypto.
   IdentifierFingerprint`` shape ARMOR's startup dump prints — plus the
   redacted ACL shapes (prefix + action verbs) that ARMOR itself deems
   non-secret in that dump;
3. assertions are machine-checked, so a drill that "went fine" without
   them cannot pass ``verify``: a ready-count gap, a retired fingerprint
   still present, a flip row off by one error code, or a missing
   replacement-pod dump each fail the verdict;
4. ``--self-test`` proves all of the above deterministically against a
   scripted fake cluster and fake probes: no network, no kubectl binary,
   no boto3, no credentials.

Usage::

    tools/rotation-drill.py baseline --out FILE [--probe-mode list|cycle]
    tools/rotation-drill.py watch   --out FILE [--timeout 95m] [--interval 30s] [--t0 RFC3339]
    tools/rotation-drill.py flip    --out FILE
    tools/rotation-drill.py verify  --out FILE
    tools/rotation-drill.py --self-test

Environment — cluster access (defaults pin today's iad-ci tree):
``ARMOR_DRILL_KUBECTL`` (kubectl), ``ARMOR_DRILL_KUBECTL_SERVER``
(``http://traefik-iad-ci:8001``, the credential-free read-only endpoint),
``ARMOR_DRILL_NAMESPACE`` (``armor``), ``ARMOR_DRILL_DEPLOYMENT``
(``armor``), ``ARMOR_DRILL_EXTERNAL_SECRET`` (``armor-credentials``),
``ARMOR_DRILL_SELECTOR`` (``app=armor``), ``ARMOR_DRILL_CONTAINER``
(``armor``). Probe edge: ``ARMOR_PROBE_ENDPOINT`` (default
``https://armor-iad-ci-ts.ardenone.com``, the vpn entrypoint; the
historical drills ran the same probes over a transient port-forward).
Pairs (only when a mode probes): ``ARMOR_DRILL_CURRENT_AKID`` /
``ARMOR_DRILL_CURRENT_SECRET`` — the pair serving now — and
``ARMOR_DRILL_RETIRED_AKID`` / ``ARMOR_DRILL_RETIRED_SECRET`` — the
superseded pair. ``ARMOR_DRILL_ROLE`` is a free-text label for the
evidence. ``verify`` needs only the two AKIDs, never the secrets.

The read-only proxy cannot port-forward and cannot read Secrets, so the
watch observes the ExternalSecret ``refreshTime`` rather than the
Secret's resourceVersion, and the flip probes need an edge reachable from
the drill host — both recorded as evidence facts, not assumed.

Exit codes: 0 success (or self-test pass / verify PASS), 1 usage or
environment error, 2 self-test failure, 3 verify verdict FAIL, 4 stage or
evidence error (watch without a baseline, watch timed out, verify on an
incomplete drill), 5 evidence write refused (redaction scan hit).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

EVIDENCE_SCHEMA = "rotation-drill-evidence/v1"
PROBE_TOOL = Path(__file__).resolve().parent / "rotation-drill-probe.py"
# Deliberately wrong and deliberately publishable: the wrong-secret probe
# row needs a secret that is not the pair's, and a fixed sentinel proves the
# refusal is signature-level without introducing a value anyone must keep.
SENTINEL_WRONG_SECRET = "drill-sentinel-wrong-secret"
DUMP_MSG = "ARMOR starting"
DUMP_TAIL = 4000

MODES = ("baseline", "watch", "flip", "verify")

USAGE = (
    f"usage: rotation-drill.py {{{','.join(MODES)}}} --out FILE  (baseline:"
    " [--probe-mode list|cycle]; watch: [--timeout 95m] [--interval 30s]"
    " [--t0 RFC3339]; flip; verify)  |  rotation-drill.py --self-test"
)


def fingerprint(value):
    """First 16 hex of SHA-256 of the identifier — ARMOR's
    ``crypto.IdentifierFingerprint``, the form its startup dump prints."""
    if not value:
        return ""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_duration(text):
    """``95m`` / ``30s`` / ``2h`` / ``90`` (seconds) → timedelta."""
    unit = text[-1] if text[-1].isalpha() else "s"
    value = text[:-1] if unit != "s" or not text[-1].isdigit() else text
    try:
        n = int(value)
    except ValueError:
        raise SystemExit(f"cannot parse duration: {text!r}")
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours"}[unit]: n})


def settings(env=None):
    """Read the drill's configuration from the environment."""
    env = os.environ if env is None else env
    return {
        "kubectl": env.get("ARMOR_DRILL_KUBECTL", "kubectl"),
        "server": env.get("ARMOR_DRILL_KUBECTL_SERVER", "http://traefik-iad-ci:8001"),
        "namespace": env.get("ARMOR_DRILL_NAMESPACE", "armor"),
        "deployment": env.get("ARMOR_DRILL_DEPLOYMENT", "armor"),
        "externalsecret": env.get("ARMOR_DRILL_EXTERNAL_SECRET", "armor-credentials"),
        "selector": env.get("ARMOR_DRILL_SELECTOR", "app=armor"),
        "container": env.get("ARMOR_DRILL_CONTAINER", "armor"),
        "probe_endpoint": env.get("ARMOR_PROBE_ENDPOINT", "https://armor-iad-ci-ts.ardenone.com"),
        "role": env.get("ARMOR_DRILL_ROLE", "unspecified"),
        "current_akid": env.get("ARMOR_DRILL_CURRENT_AKID"),
        "current_secret": env.get("ARMOR_DRILL_CURRENT_SECRET"),
        "retired_akid": env.get("ARMOR_DRILL_RETIRED_AKID"),
        "retired_secret": env.get("ARMOR_DRILL_RETIRED_SECRET"),
    }


# --- cluster reads (all read-only; the runner is injectable for the self-test)


class Kubectl:
    """Thin read-only wrapper: every call is a `get` or `logs` against the
    configured server. The self-test injects a scripted fake instead."""

    def __init__(self, cfg, runner=None):
        self.cfg = cfg
        self._runner = runner or self._subprocess

    def _subprocess(self, args, timeout):
        try:
            r = subprocess.run(
                [self.cfg["kubectl"], "--server", self.cfg["server"], "-n",
                 self.cfg["namespace"]] + args,
                capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return 124, "", f"kubectl timed out after {timeout}s"

    def get_json(self, args, timeout=60):
        rc, out, err = self._runner(args, timeout)
        if rc != 0:
            raise RuntimeError(f"kubectl {' '.join(args)} failed ({rc}): {err.strip()[:200]}")
        return json.loads(out)

    def deployment(self):
        return self.get_json(["get", "deployment", self.cfg["deployment"], "-o", "json"])

    def externalsecret(self):
        return self.get_json(["get", "externalsecret", self.cfg["externalsecret"], "-o", "json"])

    def pods(self):
        return self.get_json(["get", "pods", "-l", self.cfg["selector"], "-o", "json"])

    def logs(self, pod, tail=DUMP_TAIL, timeout=120):
        rc, out, err = self._runner(
            ["logs", pod, "-c", self.cfg["container"], f"--tail={tail}"], timeout)
        if rc != 0:
            raise RuntimeError(f"logs {pod} failed ({rc}): {err.strip()[:200]}")
        return out


def container_of(pod, container):
    """The target container's status list entry, or None."""
    for c in pod.get("status", {}).get("containerStatuses", []):
        if c.get("name") == container:
            return c
    return None


def pod_brief(pod, container):
    """The non-secret per-pod facts the evidence records."""
    c = container_of(pod, container)
    spec = next((s for s in pod.get("spec", {}).get("containers", [])
                 if s.get("name") == container), {})
    return {
        "name": pod["metadata"]["name"],
        "uid": pod["metadata"]["uid"],
        "phase": pod.get("status", {}).get("phase"),
        "ready": bool(c and c.get("ready")),
        "started": bool(c and c.get("started")),
        "restarts": (c or {}).get("restartCount", 0),
        "start_time": pod.get("status", {}).get("startTime"),
        "image": spec.get("image"),
        "deleting": bool(pod["metadata"].get("deletionTimestamp")),
    }


def ready_count(pods_json, container):
    n = 0
    for p in pods_json.get("items", []):
        c = container_of(p, container)
        if p.get("status", {}).get("phase") == "Running" and c and c.get("ready"):
            n += 1
    return n


def snapshot(cfg, kc):
    """One cluster sample: the pod briefs and the ready count."""
    pj = kc.pods()
    pods = [pod_brief(p, cfg["container"]) for p in pj.get("items", [])]
    return {"pods": pods, "ready": ready_count(pj, cfg["container"]),
            "refresh_time": eso_refresh(kc, cfg)}


def eso_refresh(kc, cfg):
    """The ExternalSecret's status.refreshTime, or None if unreadable."""
    try:
        st = kc.externalsecret().get("status", {})
    except RuntimeError:
        return None
    return st.get("refreshTime")


# --- preflight: the documented delivery chain, asserted where it stands


def preflight(cfg, kc):
    """Assert the deployment still matches the documented rotation
    behavior and record the observed facts. Each check is reported even
    when false — the drift IS a drill finding, not a tool error."""
    checks = {}
    observed = {}
    try:
        d = kc.deployment()
    except RuntimeError as e:
        return {"deployment_exists": False, "error": str(e)}, {}, False
    checks["deployment_exists"] = True
    ann = d["metadata"].get("annotations", {})
    checks["reloader_annotation"] = ann.get("reloader.stakater.com/auto") == "true"
    strat = d.get("spec", {}).get("strategy", {})
    checks["rolling_update"] = strat.get("type") == "RollingUpdate"
    observed["strategy"] = {k: strat.get(k) for k in ("type", "rollingUpdate")}
    observed["replicas"] = d.get("spec", {}).get("replicas")
    tmpl = d.get("spec", {}).get("template", {})
    spec = tmpl.get("spec", {})
    target = next((c for c in spec.get("containers", [])
                   if c.get("name") == cfg["container"]), {})
    volumes = {v.get("name"): v for v in spec.get("volumes", [])}
    mount = next((m for m in target.get("volumeMounts", []) if m.get("subPath")), None)
    vol = volumes.get((mount or {}).get("name", ""), {})
    checks["subpath_secret_mount"] = bool(mount and vol.get("secret", {}).get("secretName"))
    observed["credential_mount"] = {
        "mount_path": (mount or {}).get("mountPath"),
        "sub_path": (mount or {}).get("subPath"),
        "secret_name": vol.get("secret", {}).get("secretName"),
    }
    checks["startup_probe"] = bool(target.get("startupProbe"))
    checks["readiness_probe"] = bool(target.get("readinessProbe"))
    es_checks, es_observed = preflight_externalsecret(cfg, kc)
    checks.update(es_checks)
    observed["externalsecret"] = es_observed
    ok = all(v is True for v in checks.values())
    return checks, observed, ok


def preflight_externalsecret(cfg, kc):
    try:
        es = kc.externalsecret()
    except RuntimeError as e:
        return {"externalsecret_exists": False, "externalsecret_ready": False}, {"error": str(e)}
    spec = es.get("spec", {})
    st = es.get("status", {})
    ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                for c in st.get("conditions", []))
    observed = {
        "refresh_interval": spec.get("refreshInterval"),
        "store": spec.get("storeRef", {}).get("name"),
        "store_type": (spec.get("storeRef") or {}).get("kind", "ClusterSecretStore"),
        "refresh_time": st.get("refreshTime"),
        "ready_condition": ready,
    }
    return {"externalsecret_exists": True, "externalsecret_ready": ready}, observed


# --- startup-dump parsing (ARMOR's Redacted() output; fingerprints only)


def parse_dump(log_text):
    """Extract the credential fingerprints and ACL shapes from the last
    ``ARMOR starting`` line of a pod log. ARMOR prints that dump through
    ``Redacted()``: the credentials map is keyed by identifier fingerprint
    and its ACL entries carry prefix + verbs — nothing secret. Returns
    None when no dump line is in the retained window (kubelet rotation)."""
    dump_line = None
    for line in log_text.splitlines():
        if DUMP_MSG in line:
            dump_line = line
    if dump_line is None:
        return None
    try:
        obj = json.loads(dump_line)
    except ValueError:
        return None
    cfg = (obj.get("Fields") or {}).get("config") or obj.get("config") or {}
    creds = cfg.get("credentials") or {}
    if not isinstance(creds, dict) or not creds:
        return None
    entries = {}
    for fp, entry in creds.items():
        acls = [{"prefix": a.get("prefix"),
                 "actions": sorted(k for k, v in (a.get("actions") or {}).items() if v)}
                for a in (entry or {}).get("acls", [])]
        entries[fp] = {"acls": acls}
    return {"fingerprints": sorted(entries), "entries": entries}


def capture_dump(cfg, kc, pod):
    try:
        return parse_dump(kc.logs(pod))
    except RuntimeError:
        return None


# --- probe composition (one credential state per subprocess, env only)


def probe_invoke(mode, akid, secret, extra_env=None, runner=None):
    """Run the probe tool for one credential state. The pair travels in the
    child's environment — never argv — and only the probe's status/code
    lines come back. The runner seam lets the self-test script probes."""
    env = dict(os.environ)
    env["ARMOR_PROBE_AKID"] = akid or ""
    env["ARMOR_PROBE_SECRET"] = secret or ""
    env.update(extra_env or {})
    if runner is not None:
        rc, out, err = runner(mode, env)
    else:
        try:
            r = subprocess.run([sys.executable, str(PROBE_TOOL), mode],
                               capture_output=True, text=True, timeout=300, env=env)
            rc, out, err = r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            rc, out, err = 124, "", "probe timed out"
    output = [ln for ln in out.splitlines() if ln.strip()]
    return {"mode": mode, "exit": rc, "output": output, "stderr": err.strip()[-200:]}


def probe_last_status(result):
    """`label: status [code]` from the probe's last output line."""
    if not result["output"]:
        return "?"
    parts = result["output"][-1].split(": ", 1)
    return parts[1].strip() if len(parts) == 2 else "?"


def status_matches(got, expected):
    """`2xx` matches any 200–299 terminal status (a positive pin's "the
    call succeeded": `list` ends at 200, a `cycle` ends at abort's 204);
    every other expected value — the calibrated refusals — is exact."""
    if expected != "2xx":
        return got == expected
    code = got.split(" ", 1)[0]
    return code.isdigit() and 200 <= int(code) <= 299


# --- evidence (JSON, mode 600, redaction-scanned before every write)


PAIR_ENV_KEYS = ("ARMOR_DRILL_CURRENT_AKID", "ARMOR_DRILL_CURRENT_SECRET",
                 "ARMOR_DRILL_RETIRED_AKID", "ARMOR_DRILL_RETIRED_SECRET")


def supplied_pair_values(env=None):
    env = os.environ if env is None else env
    return [env[k] for k in PAIR_ENV_KEYS if env.get(k)]


def evidence_scan(text, values):
    """Return the supplied values that leaked into the serialized
    evidence. Values are secrets or credential halves; the evidence may
    carry only fingerprints and status codes, so a hit is a bug."""
    return [v for v in values if v and v in text]


def save_evidence(path, ev, values):
    ev["schema"] = EVIDENCE_SCHEMA
    text = json.dumps(ev, indent=1, sort_keys=True)
    leaked = evidence_scan(text, values)
    if leaked:
        print("evidence write refused: supplied pair value(s) reached the "
              "evidence text; this is a tool bug — no file written",
              file=sys.stderr)
        return 5
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text + "\n")
    return 0


def load_evidence(path):
    try:
        with open(path) as f:
            ev = json.load(f)
    except (OSError, ValueError) as e:
        print(f"cannot read evidence {path}: {e}", file=sys.stderr)
        return None
    if ev.get("schema") != EVIDENCE_SCHEMA:
        print(f"evidence {path} is not {EVIDENCE_SCHEMA}", file=sys.stderr)
        return None
    return ev


# --- modes


def cmd_baseline(cfg, args, kc, probe_runner=None, values=None):
    values = supplied_pair_values() if values is None else values
    checks, observed, preflight_ok = preflight(cfg, kc)
    try:
        snap = snapshot(cfg, kc)
    except RuntimeError as e:
        print(f"baseline: cluster read failed: {e}", file=sys.stderr)
        return 4
    ev = {
        "role": cfg["role"],
        "server": cfg["server"],
        "probe_endpoint": cfg["probe_endpoint"],
        "created_at": now_iso(),
        "preflight": {"checks": checks, "ok": preflight_ok, "observed": observed},
        "pods": snap["pods"],
        "ready": snap["ready"],
        "externalsecret_refresh_time": snap["refresh_time"],
        "fingerprint_of_current_akid": fingerprint(cfg["current_akid"]) or None,
        "fingerprint_of_retired_akid": fingerprint(cfg["retired_akid"]) or None,
        "dump": {"status": "not_attempted"},
        "positive_probe": {"status": "skipped"},
    }
    serving = [p for p in snap["pods"] if p["ready"]]
    if serving:
        dumps = {p["name"]: d for p in serving
                 if (d := capture_dump(cfg, kc, p["name"]))}
        ev["dump"] = {"status": "captured" if dumps else "unavailable", "pods": dumps}
    if cfg["current_akid"] and cfg["current_secret"]:
        mode = "cycle" if args.get("probe_mode") == "cycle" else "list"
        r = probe_invoke(mode, cfg["current_akid"], cfg["current_secret"],
                         {"ARMOR_PROBE_ENDPOINT": cfg["probe_endpoint"]},
                         runner=probe_runner)
        ev["positive_probe"] = {"status": "ran", "expected": "2xx", "got": probe_last_status(r),
                                "result": r}
    else:
        print("baseline: no current pair in the environment — the step-1 "
              "positive pin is skipped (verify will demand the dump instead)",
              file=sys.stderr)
    rc = save_evidence(args["out"], ev, values)
    if rc:
        return rc
    print(f"baseline: preflight {'ok' if preflight_ok else 'DEGRADED'}"
          f" ({sum(1 for v in checks.values() if v is True)}/{len(checks)} checks),"
          f" {len(serving)} serving pod(s),"
          f" dump {ev['dump']['status']},"
          f" positive probe {ev['positive_probe'].get('got', ev['positive_probe']['status'])}")
    print("baseline: stage the rotation now (OpenBao, by pipe, provisioning"
          " identity — the runbook's steps 2-4), then run `watch`.")
    return 0


def cmd_watch(cfg, args, kc, clock=None, sleeper=None, values=None):
    values = supplied_pair_values() if values is None else values
    clock = clock or (lambda: datetime.now(timezone.utc))
    sleeper = sleeper or time.sleep
    ev = load_evidence(args["out"])
    if not ev or "created_at" not in ev or "preflight" not in ev:
        print("watch: run `baseline` first — no baseline evidence found",
              file=sys.stderr)
        return 4
    baseline_uids = {p["uid"] for p in ev.get("pods", [])}
    baseline_refresh = ev.get("externalsecret_refresh_time")
    timeout = parse_duration(args.get("timeout", "95m"))
    interval = parse_duration(args.get("interval", "30s"))
    t0_text = args.get("t0") or ev.get("staged_at") or ev["created_at"]
    samples = []
    dumps = {}
    hop = {"t0": t0_text, "eso_refresh_bumped": False, "new_pods": [],
           "baseline_pods_gone": False, "new_pod_ready": False, "timed_out": False}
    deadline = clock() + timeout
    while True:
        try:
            snap = snapshot(cfg, kc)
        except RuntimeError as e:
            samples.append({"t": now_iso(), "error": str(e)[:200], "ready": None})
            snap = None
        if snap is not None:
            uids = {p["uid"] for p in snap["pods"]}
            new = [p for p in snap["pods"] if p["uid"] not in baseline_uids]
            for p in new:
                if p["name"] not in dumps and p["started"]:
                    d = capture_dump(cfg, kc, p["name"])
                    if d:
                        dumps[p["name"]] = d
            if new and not hop["new_pods"]:
                hop["new_pods_seen_at"] = now_iso()
            hop["new_pods"] = sorted({p["name"] for p in new})
            gone = bool(baseline_uids) and not (uids & baseline_uids)
            if gone and not hop["baseline_pods_gone"]:
                hop["baseline_pods_gone_at"] = now_iso()
            hop["baseline_pods_gone"] = hop["baseline_pods_gone"] or gone
            nready = any(p["ready"] for p in new)
            if nready and not hop["new_pod_ready"]:
                hop["new_pod_ready_at"] = now_iso()
            hop["new_pod_ready"] = hop["new_pod_ready"] or nready
            bump = (snap["refresh_time"] or "") != (baseline_refresh or "") and snap["refresh_time"]
            if bump and not hop["eso_refresh_bumped"]:
                hop["eso_refresh_bumped_at"] = now_iso()
            hop["eso_refresh_bumped"] = hop["eso_refresh_bumped"] or bool(bump)
            samples.append({"t": now_iso(), "ready": snap["ready"],
                            "refresh_time": snap["refresh_time"],
                            "new_ready": sorted(p["name"] for p in new if p["ready"])})
        hop["new_pods"] = hop["new_pods"] or []
        if (hop["eso_refresh_bumped"] and hop["new_pod_ready"]
                and hop["baseline_pods_gone"] and dumps):
            break
        if clock() >= deadline:
            hop["timed_out"] = True
            break
        sleeper(interval.total_seconds())
    readies = [s["ready"] for s in samples if s.get("ready") is not None]
    ev["watch"] = {
        "completed_at": now_iso(),
        "t0": t0_text,
        "samples": samples,
        "min_ready": min(readies) if readies else None,
        "replacement_dumps": dumps,
        "hop": hop,
    }
    rc = save_evidence(args["out"], ev, values)
    if rc:
        return rc
    if hop["timed_out"]:
        print("watch: TIMED OUT before the full chain was observed "
              f"(eso_bumped={hop['eso_refresh_bumped']}, new_ready={hop['new_pod_ready']}, "
              f"baseline_gone={hop['baseline_pods_gone']}, dumps={len(dumps)}) — "
              "evidence recorded; investigate before re-running")
        return 4
    print(f"watch: flip observed — eso {hop.get('eso_refresh_bumped_at')}, "
          f"new pod ready {hop.get('new_pod_ready_at')}, baseline gone "
          f"{hop.get('baseline_pods_gone_at')}, {len(dumps)} replacement dump(s), "
          f"min ready {ev['watch']['min_ready']} across {len(samples)} samples")
    print("watch: run `flip` for the enforcement matrix, then `verify`.")
    return 0


FLIP_ROWS = (
    # (row, probe mode, whose akid, whose secret, expected status[/code]).
    # The positive row is 2xx, not 200: under --probe-mode cycle it ends at
    # abort-mpu, which the serving edge answers 204 (the documented drill
    # record's "abort 204"). The refusal rows are exact — they are the
    # calibration.
    ("in_scope_positive", "list", "current", "current", "2xx"),
    ("retired_pair_rejected", "list", "retired", "retired", "403 InvalidAccessKeyId"),
    ("wrong_secret_rejected", "list", "current", "sentinel", "403 SignatureDoesNotMatch"),
    ("out_of_scope_denied", "list-control", "current", "current", "403 AccessDenied"),
)


def cmd_flip(cfg, args, probe_runner=None, values=None):
    values = supplied_pair_values() if values is None else values
    if not (cfg["current_akid"] and cfg["current_secret"]
            and cfg["retired_akid"] and cfg["retired_secret"]):
        print("flip: both the current and the retired pair must be in the "
              "environment (ARMOR_DRILL_CURRENT_* / ARMOR_DRILL_RETIRED_*)",
              file=sys.stderr)
        return 1
    path = args["out"]
    ev = load_evidence(path)
    if not ev or "created_at" not in ev:
        print("flip: run `baseline` first — no evidence file", file=sys.stderr)
        return 4
    pairs = {
        "current": (cfg["current_akid"], cfg["current_secret"]),
        "retired": (cfg["retired_akid"], cfg["retired_secret"]),
        "sentinel": (cfg["current_akid"], SENTINEL_WRONG_SECRET),
    }
    primary = "cycle" if args.get("probe_mode") == "cycle" else None
    rows = {}
    for name, mode, akid_ref, secret_ref, expected in FLIP_ROWS:
        run_mode = primary or mode
        akid, secret = pairs[akid_ref][0], pairs[secret_ref][1]
        r = probe_invoke(run_mode, akid, secret,
                         {"ARMOR_PROBE_ENDPOINT": cfg["probe_endpoint"]},
                         runner=probe_runner)
        got = probe_last_status(r)
        rows[name] = {"expected": expected, "got": got,
                      "match": status_matches(got, expected), "result": r}
        print(f"flip {name}: expected {expected!r}, got {got!r}"
              f" {'ok' if rows[name]['match'] else 'MISMATCH'}")
    ev["flip"] = {"completed_at": now_iso(), "rows": rows}
    rc = save_evidence(path, ev, values)
    return rc


def cmd_verify(cfg, args):
    ev = load_evidence(args["out"])
    if not ev:
        return 4
    results = []

    def check(name, ok, detail=""):
        results.append((name, bool(ok), detail))

    pre = ev.get("preflight", {})
    for name, ok in sorted(pre.get("checks", {}).items()):
        check(f"preflight {name}", ok)
    new_fp = fingerprint(cfg["current_akid"]) if cfg["current_akid"] else None
    retired_fp = fingerprint(cfg["retired_akid"]) if cfg["retired_akid"] else None
    if not new_fp:
        print("verify: ARMOR_DRILL_CURRENT_AKID is required to derive the "
              "new fingerprint (the secret is not needed)", file=sys.stderr)
        return 1
    pos = ev.get("positive_probe", {})
    dump = ev.get("dump", {})
    pinned_by_probe = status_matches(pos.get("got") or "", "2xx")
    all_dumps = dict(dump.get("pods") or {})
    watch = ev.get("watch") or {}
    repl_dumps = watch.get("replacement_dumps") or {}
    all_dumps.update(repl_dumps)
    all_fps = sorted({fp for d in all_dumps.values() for fp in d.get("fingerprints", [])})
    repl_fps = sorted({fp for d in repl_dumps.values() for fp in d.get("fingerprints", [])})
    check("baseline step-1 pin (positive probe 200 or dump fingerprint)",
          pinned_by_probe or (new_fp in all_fps),
          f"probe got={pos.get('got', pos.get('status'))}, dump={dump.get('status')}")
    if watch:
        hop = watch.get("hop", {})
        check("watch: eso refresh bumped", hop.get("eso_refresh_bumped"))
        check("watch: replacement pod appeared and went ready", hop.get("new_pod_ready"))
        check("watch: baseline pods replaced", hop.get("baseline_pods_gone"))
        check("watch: not timed out", not hop.get("timed_out"))
        mr = watch.get("min_ready")
        check("watch: service continuity (ready never sampled at 0)", mr is not None and mr >= 1,
              f"min_ready={mr} over {len(watch.get('samples', []))} samples")
        check("replacement dump captured", bool(repl_dumps),
              "kubelet may have rotated it; re-run the drill capturing promptly")
    else:
        check("watch stage present", False, "run `watch` between the write and `flip`")
    check("new fingerprint in a replacement dump", new_fp in repl_fps,
          f"new_fp={new_fp}, replacement dump fingerprints={repl_fps}")
    if retired_fp:
        # Scoped to the replacement pods, per the procedure's step 6: the
        # pre-rotation baseline dump is SUPPOSED to carry the retired
        # fingerprint — it was the serving credential when it was taken.
        check("retired fingerprint appears nowhere in the replacement dumps",
              retired_fp not in repl_fps, f"retired_fp={retired_fp}")
    flip = ev.get("flip")
    if not flip:
        check("flip matrix present", False, "run `flip` after the rollout")
    else:
        check("flip matrix present", True)
        for name, row in sorted(flip.get("rows", {}).items()):
            check(f"flip {name}", row.get("match"),
                  f"expected {row.get('expected')!r}, got {row.get('got')!r}")
    failed = [(n, d) for n, ok, d in results if not ok]
    print(f"verify: {len(results) - len(failed)}/{len(results)} checks pass"
          + (f" — {len(failed)} FAILED" if failed else " — VERDICT: PASS"))
    for n, d in failed:
        print(f"verify: FAIL {n}" + (f" ({d})" if d else ""))
    return 0 if not failed else 3


# --- self-test ---------------------------------------------------------------
# Scripted fake cluster + fake probes; no network, no kubectl binary, no
# boto3, no real credentials. Proves the output/redaction contract and that
# every injected fault fails the verdict.


def fixture_dump_line(fps_and_acls, extra_fps=()):
    """A startup-dump line shaped like ARMOR's: JSON with msg ``ARMOR
    starting`` and a Redacted() config whose credentials map is keyed by
    fingerprint (access keys `<set>`, ACL prefix + verbs only)."""
    creds = {}
    for fp, acls in fps_and_acls.items():
        creds[fp] = {"access_key": fp, "secret_key": "<set>",
                     "acls": [{"bucket": "0123456789abcdef", "prefix": prefix,
                               "actions": {a: True for a in acts}}
                              for prefix, acts in acls]}
    for fp in extra_fps:
        creds[fp] = {"access_key": fp, "secret_key": "<set>", "acls": []}
    obj = {"time": "2026-09-27T08:08:29Z", "level": "INFO", "service": "armor",
           "msg": DUMP_MSG, "Fields": {"config": {"credentials": creds}}}
    return json.dumps(obj)


def make_env(overrides):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("ARMOR_DRILL_", "ARMOR_PROBE_"))}
    env.update(overrides)
    return env


class FakeClock:
    def __init__(self, start):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


class FakeCluster:
    """Scripted read-only cluster. `states` is a list of dicts consumed one
    per watch sample: {refresh, pods, dump} where pods is a list of
    (name, uid, phase, ready, started) tuples. Requests past the last state
    repeat it. Deployment/ES fixtures are fixed; `overrides` can fault them."""

    def __init__(self, states, deployment=None, externalsecret=None, dump_by_pod=None):
        self.states = states
        self.i = -1
        self.deployment = deployment or FIXTURE_DEPLOYMENT
        self.externalsecret = externalsecret or FIXTURE_EXTERNALSECRET
        self.dump_by_pod = dump_by_pod or {}
        self.calls = []

    def _state(self):
        # Before the first pods() read (i == -1) the cluster is still in its
        # first state, so preflight's reads see state 0, not the last one.
        return self.states[min(max(self.i, 0), len(self.states) - 1)]

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        if args[0] == "get" and args[1] == "deployment":
            return 0, json.dumps(self.deployment), ""
        if args[0] == "get" and args[1] == "externalsecret":
            es = json.loads(json.dumps(self.externalsecret))
            refresh = self._state().get("refresh")
            if refresh:
                es.setdefault("status", {})["refreshTime"] = refresh
            return 0, json.dumps(es), ""
        if args[0] == "get" and args[1] == "pods":
            self.i += 1
            st = self._state()
            items = []
            for name, uid, phase, ready, started in st["pods"]:
                items.append({
                    "metadata": {"name": name, "uid": uid},
                    "status": {"phase": phase, "startTime": "2026-09-27T08:00:00Z",
                               "containerStatuses": [{"name": "armor", "ready": ready,
                                                      "started": started,
                                                      "restartCount": 0}]},
                    "spec": {"containers": [{"name": "armor", "image": "armor:fixture"}]},
                })
            return 0, json.dumps({"items": items}), ""
        if args[0] == "logs":
            pod = args[1]
            dump = self.dump_by_pod.get(pod)
            if dump is None:
                return 1, "", f'logs: pod "{pod}" not found'
            return 0, dump + "\n" + '{"msg":"request completed"}\n', ""
        return 1, "", f"unexpected kubectl args: {args}"


FIXTURE_DEPLOYMENT = {
    "metadata": {"annotations": {"reloader.stakater.com/auto": "true"}},
    "spec": {
        "replicas": 1,
        "strategy": {"type": "RollingUpdate",
                     "rollingUpdate": {"maxSurge": "25%", "maxUnavailable": "25%"}},
        "template": {"spec": {
            "volumes": [{"name": "credentials",
                         "secret": {"secretName": "armor-credentials"}}],
            "containers": [{
                "name": "armor",
                "volumeMounts": [{"name": "credentials",
                                  "mountPath": "/etc/armor/credentials.yaml",
                                  "readOnly": True, "subPath": "credentials.yaml"}],
                "startupProbe": {"tcpSocket": {"port": 9000}},
                "readinessProbe": {"httpGet": {"path": "/readyz", "port": 9000}},
            }]}}},
}
FIXTURE_EXTERNALSECRET = {
    "spec": {"refreshInterval": "1h", "storeRef": {"name": "openbao",
                                                   "kind": "ClusterSecretStore"}},
    "status": {"refreshTime": "2026-09-27T22:06:27Z",
               "conditions": [{"type": "Ready", "status": "True"}]},
}


def self_test():
    failures = []
    total = 0

    def check(name, ok):
        nonlocal total
        total += 1
        if not ok:
            failures.append(name)

    planted = {
        "akid": "planted-drill-access-key-id",
        "secret": "planted-drill-secret-key-material",
        "retired_akid": "planted-retired-access-key-id",
        "retired_secret": "planted-retired-secret-material",
    }
    env = make_env({
        "ARMOR_DRILL_CURRENT_AKID": planted["akid"],
        "ARMOR_DRILL_CURRENT_SECRET": planted["secret"],
        "ARMOR_DRILL_RETIRED_AKID": planted["retired_akid"],
        "ARMOR_DRILL_RETIRED_SECRET": planted["retired_secret"],
    })
    cfg = settings(env)
    values = supplied_pair_values(env)
    check("four pair values supplied", len(values) == 4)
    check("sentinel is not a supplied value",
          all(v != SENTINEL_WRONG_SECRET for v in values))

    # 1. fingerprint derivation: 16 hex, SHA-256-shaped, and empty-safe.
    fp = fingerprint(planted["akid"])
    check("fingerprint is 16 hex", len(fp) == 16 and all(c in "0123456789abcdef" for c in fp))
    check("fingerprint empty-safe", fingerprint("") == "" and fingerprint(None) == "")
    check("fingerprint distinct per value", fp != fingerprint(planted["retired_akid"]))

    # 2. dump parsing: fingerprints + ACL shapes extracted; nothing secret
    #    exists in the fixture to begin with, and a non-dump log yields None.
    dump_line = fixture_dump_line(
        {fp: [("agent-archivist/raw/", ["put", "list", "abort"])]})
    parsed = parse_dump(dump_line + "\n" + '{"msg":"request completed"}')
    check("dump parsed", parsed is not None)
    check("dump fingerprints", parsed and parsed["fingerprints"] == [fp])
    check("dump acl shape",
          parsed and parsed["entries"][fp]["acls"] ==
          [{"prefix": "agent-archivist/raw/", "actions": ["abort", "list", "put"]}])
    check("no dump in request-only log", parse_dump('{"msg":"request completed"}') is None)
    check("dump parse survives garbage", parse_dump("not json at all") is None)

    # 3. probe composition: the scripted runner receives the pair in env,
    #    the child's output lines are recorded verbatim, and the last
    #    status is extracted.
    seen_env = {}

    def fake_probe(mode, penv):
        seen_env[mode] = dict(penv)
        return 0, f"list in-scope: 200\n", ""

    r = probe_invoke("list", planted["akid"], planted["secret"], runner=fake_probe)
    check("probe env carries pair", seen_env["list"]["ARMOR_PROBE_AKID"] == planted["akid"]
          and seen_env["list"]["ARMOR_PROBE_SECRET"] == planted["secret"])
    check("probe output recorded", r["output"] == ["list in-scope: 200"])
    check("probe last status", probe_last_status(r) == "200")

    # 3b. positive-pin matching: 2xx covers list's 200 and a cycle's
    #     terminal abort 204 (the serving edge's documented answer); the
    #     calibrated refusals stay exact, and garbage cannot match.
    check("status 2xx matches 200", status_matches("200", "2xx"))
    check("status 2xx matches abort 204", status_matches("204", "2xx"))
    check("status 2xx refuses a 403 code",
          not status_matches("403 InvalidAccessKeyId", "2xx"))
    check("status exact refuses 204 against 200", not status_matches("204", "200"))
    check("status exact matches the calibrated code",
          status_matches("403 InvalidAccessKeyId", "403 InvalidAccessKeyId"))
    check("status matches garbage safely", not status_matches("?", "2xx"))

    # 4. full happy-path drill: baseline -> watch -> flip -> verify PASS,
    #    with the fake cluster advancing through a real rollout timeline
    #    (eso bump, surge pod not-ready, new pod Running, new pod Ready,
    #    baseline gone) and continuity held throughout.
    old_uid, new_uid = "uid-old", "uid-new"
    old_fp = fingerprint(planted["retired_akid"])
    timeline = [
        {"refresh": "2026-09-27T22:06:27Z",
         "pods": [("armor-old", old_uid, "Running", True, True)]},
        {"refresh": "2026-09-27T23:08:26Z",
         "pods": [("armor-old", old_uid, "Running", True, True)]},
        {"refresh": "2026-09-27T23:08:26Z",
         "pods": [("armor-old", old_uid, "Running", True, True),
                  ("armor-new", new_uid, "Running", False, True)]},
        {"refresh": "2026-09-27T23:08:26Z",
         "pods": [("armor-old", old_uid, "Running", True, True),
                  ("armor-new", new_uid, "Running", False, True)]},
        {"refresh": "2026-09-27T23:08:26Z",
         "pods": [("armor-old", old_uid, "Running", True, True),
                  ("armor-new", new_uid, "Running", True, True)]},
        {"refresh": "2026-09-27T23:08:26Z",
         "pods": [("armor-new", new_uid, "Running", True, True)]},
        {"refresh": "2026-09-27T23:08:26Z",
         "pods": [("armor-new", new_uid, "Running", True, True)]},
    ]
    # Step 6: the replacement dump carries the new fingerprint and the
    # retired one appears nowhere — so the happy-path fixture lists only fp;
    # the retired-present case is its own fault injection below.
    dumps = {"armor-new": fixture_dump_line({fp: [("agent-archivist/raw/",
                                                   ["put", "list"])]})}
    clock = FakeClock(datetime(2026, 9, 27, 22, 30, tzinfo=timezone.utc))

    def fake_kc(states, deployment=None, dump_by_pod=None):
        """The stages take a Kubectl whose reads run against a fresh
        FakeCluster each time, so every stage replays the timeline from
        its first sample."""
        return Kubectl(cfg, runner=FakeCluster(list(states), deployment=deployment,
                                               dump_by_pod=dump_by_pod or {}))

    cluster = fake_kc(list(timeline), dump_by_pod=dumps)

    def fake_flip_probe(mode, penv):
        if penv["ARMOR_PROBE_AKID"] == planted["retired_akid"]:
            return 0, "list in-scope: 403 InvalidAccessKeyId\n", ""
        if penv["ARMOR_PROBE_SECRET"] == SENTINEL_WRONG_SECRET:
            return 0, "list in-scope: 403 SignatureDoesNotMatch\n", ""
        if mode == "list-control":
            return 0, "list out-of-scope: 403 AccessDenied\n", ""
        return 0, "list in-scope: 200\n", ""

    # The raw-writer drill's step-1 pin is the full write cycle, ending at
    # abort's 204 — the baseline must pin on 2xx, not on a literal 200.
    def fake_cycle_probe(mode, penv):
        return 0, "create-mpu: 200\nupload-part: 200\nabort-mpu: 204\n", ""

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "evidence.json")
        a = {"out": out}
        # The pre-rotation serving pod's dump legitimately shows the retired
        # fingerprint — that is the pair it was serving.
        baseline_dumps = {"armor-old": fixture_dump_line(
            {old_fp: [("agent-archivist/raw/", ["put", "list", "abort"])]})}
        rc = cmd_baseline(cfg, dict(a, probe_mode="cycle"),
                          fake_kc(timeline, dump_by_pod=baseline_dumps),
                          probe_runner=fake_cycle_probe)
        check("baseline exit 0", rc == 0)
        ev = load_evidence(out)
        check("baseline preflight ok", ev and ev["preflight"]["ok"])
        check("baseline records current fingerprint",
              ev and ev["fingerprint_of_current_akid"] == fp)
        baseline_dump_pod = list((ev.get("dump") or {}).get("pods") or {})
        check("baseline dump captured from serving pod",
              baseline_dump_pod and ev["dump"]["status"] == "captured")

        # the redaction scan: planted values must not be in the evidence text
        with open(out) as f:
            text = f.read()
        check("no planted value in evidence",
              not evidence_scan(text, values))
        check("evidence carries fingerprints not values",
              fp in text and planted["akid"] not in text)

        rc = cmd_watch(cfg, dict(a, timeout="95m", interval="30s"),
                       cluster, clock=clock, sleeper=lambda s: clock.advance(seconds=s))
        check("watch exit 0", rc == 0)
        ev = load_evidence(out)
        hop = ev["watch"]["hop"]
        check("watch eso bump", hop["eso_refresh_bumped"])
        check("watch new pod ready", hop["new_pod_ready"])
        check("watch baseline gone", hop["baseline_pods_gone"])
        check("watch replacement dump", bool(ev["watch"]["replacement_dumps"]))
        check("watch continuity held", ev["watch"]["min_ready"] >= 1)
        check("watch saw the rollout", new_uid not in {p["uid"] for p in ev["pods"]}
              and "armor-new" in hop["new_pods"])

        rc = cmd_flip(cfg, a, probe_runner=fake_flip_probe)
        check("flip exit 0", rc == 0)
        ev = load_evidence(out)
        check("flip rows all match",
              all(row["match"] for row in ev["flip"]["rows"].values()))

        rc = cmd_verify(cfg, a)
        check("verify PASS on the happy path", rc == 0)

    # 5. fault injections, each of which must fail verify (exit 3) or the
    #    stage: continuity gap, retired fingerprint still present, a flip
    #    row off by one code, a chain that never completes (missing
    #    replacement dump -> watch timeout), degraded preflight, and a
    #    redaction-scan refusal on write. The drill runner advances the
    #    fake clock on every poll sleep so a never-completing chain times
    #    out instead of hanging the self-test.
    def run_drill(cluster_states, cluster_dumps=None, flip_probe=None,
                  deployment=None, timeout="95m"):
        # cluster_dumps=None keeps the happy-path replacement dump, so a
        # fault test exercises its own injected fault; the missing-dump
        # fault opts out explicitly with {} and times the watch out.
        drill_dumps = dumps if cluster_dumps is None else cluster_dumps
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "evidence.json")
            a = {"out": out}
            rc = cmd_baseline(cfg, a,
                              fake_kc(cluster_states, deployment=deployment,
                                      dump_by_pod=drill_dumps),
                              probe_runner=fake_probe, values=values)
            if rc:
                return rc, None
            clock_r = FakeClock(datetime(2026, 9, 27, 22, 30, tzinfo=timezone.utc))
            rc = cmd_watch(cfg, dict(a, timeout=timeout, interval="30s"),
                           fake_kc(cluster_states, deployment=deployment,
                                   dump_by_pod=drill_dumps),
                           clock=clock_r,
                           sleeper=lambda s: clock_r.advance(seconds=s), values=values)
            if rc:
                return rc, load_evidence(out)
            cmd_flip(cfg, a, probe_runner=flip_probe or fake_flip_probe, values=values)
            return cmd_verify(cfg, a), load_evidence(out)

    # continuity gap: a state where nothing is ready (bad rollout)
    gapped = list(timeline)
    gapped[4] = {"refresh": "2026-09-27T23:08:26Z",
                 "pods": [("armor-new", new_uid, "Running", False, True)]}
    gapped[5] = {"refresh": "2026-09-27T23:08:26Z",
                 "pods": [("armor-new", new_uid, "Running", True, True)]}
    rc, _ = run_drill(gapped)
    check("continuity gap fails verify", rc == 3)

    # retired fingerprint still present in the replacement dump
    dumps_retired = {"armor-new": fixture_dump_line(
        {fp: [("agent-archivist/raw/", ["put", "list"])], old_fp: []})}
    rc, _ = run_drill(list(timeline), cluster_dumps=dumps_retired)
    check("retired fingerprint fails verify", rc == 3)

    # flip row off by one error code (retired pair refused as AccessDenied)
    def wrong_flip(mode, penv):
        if penv["ARMOR_PROBE_AKID"] == planted["retired_akid"]:
            return 0, "list in-scope: 403 AccessDenied\n", ""
        return fake_flip_probe(mode, penv)

    rc, _ = run_drill(list(timeline), flip_probe=wrong_flip)
    check("wrong flip code fails verify", rc == 3)

    # replacement dump never capturable (kubelet rotated it before the
    # drill could read it) — the watch must time out, not hang or pass
    rc, ev = run_drill(list(timeline), cluster_dumps={}, timeout="5m")
    check("missing replacement dump times the watch out (exit 4)", rc == 4)
    check("timeout recorded in evidence",
          ev and ev["watch"]["hop"]["timed_out"])

    # degraded preflight (Reloader annotation lost) fails verify, and the
    # failing check is named
    drifted = json.loads(json.dumps(FIXTURE_DEPLOYMENT))
    drifted["metadata"]["annotations"] = {}
    rc, ev = run_drill(list(timeline), deployment=drifted)
    check("drifted preflight fails verify", rc == 3)
    check("drift check names the reloader annotation",
          any(name == "preflight reloader_annotation" and not ok
              for name, ok, _d in _verify_results(ev or {})))

    # a happy-path drill whose replacement dump is later removed from the
    # evidence fails verify on the dump check specifically
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "evidence.json")
        a = {"out": out}
        cmd_baseline(cfg, a, fake_kc(timeline),
                     probe_runner=fake_probe, values=values)
        clock3 = FakeClock(datetime(2026, 9, 27, 22, 30, tzinfo=timezone.utc))
        cmd_watch(cfg, dict(a, timeout="95m", interval="30s"),
                  fake_kc(timeline, dump_by_pod=dumps),
                  clock=clock3, sleeper=lambda s: clock3.advance(seconds=s),
                  values=values)
        cmd_flip(cfg, a, probe_runner=fake_flip_probe, values=values)
        ev3 = load_evidence(out)
        ev3["watch"]["replacement_dumps"] = {}
        rc = save_evidence(out, ev3, values)
        check("tampered evidence saves", rc == 0)
        check("stripped replacement dump fails verify", cmd_verify(cfg, a) == 3)

    # redaction refusal: a leaky probe runner whose output embeds the secret
    def leaky_probe(mode, penv):
        return 0, f"list in-scope: 200 secret={planted['secret']}\n", ""

    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "evidence.json")
        a = {"out": out}
        rc = cmd_baseline(cfg, a, fake_kc(timeline),
                          probe_runner=leaky_probe, values=values)
        check("redaction scan refuses the write (exit 5)", rc == 5)
        check("refused write left no file", not os.path.exists(out))

    # 6. usage paths: watch without a baseline; verify without evidence;
    #    flip without pairs.
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "none.json")
        check("watch without baseline exits 4",
              cmd_watch(cfg, {"out": out, "timeout": "1m", "interval": "1s"},
                        fake_kc([]), clock=FakeClock(datetime(2026, 9, 27,
                                                              tzinfo=timezone.utc)),
                        sleeper=lambda s: None) == 4)
        check("verify without evidence exits 4", cmd_verify(cfg, {"out": out}) == 4)
        nopair_cfg = settings(make_env({"ARMOR_DRILL_CURRENT_AKID": "",
                                        "ARMOR_DRILL_RETIRED_AKID": ""}))
        for k in ("current_akid", "current_secret", "retired_akid", "retired_secret"):
            nopair_cfg[k] = None
        check("flip without pairs exits 1",
              cmd_flip(nopair_cfg, {"out": out}, probe_runner=fake_probe) == 1)

    # 7. parse_duration contract
    check("duration 95m", parse_duration("95m") == timedelta(minutes=95))
    check("duration 30s", parse_duration("30s") == timedelta(seconds=30))
    check("duration 2h", parse_duration("2h") == timedelta(hours=2))
    check("duration bare seconds", parse_duration("45") == timedelta(seconds=45))

    passed = total - len(failures)
    print(f"self-test: {passed} passed, {len(failures)} failed")
    for name in failures:
        print(f"self-test: FAILED {name}", file=sys.stderr)
    return 2 if failures else 0


def _verify_results(ev):
    """Re-run the verify checks read-only over an evidence file, returning
    the raw (name, ok, detail) triples — used by the self-test to inspect
    which check failed, without treating this as a second verdict path."""
    out = []
    pre = ev.get("preflight", {}).get("checks", {})
    for name, ok in sorted(pre.items()):
        out.append((f"preflight {name}", ok is True, ""))
    return out


def main(argv):
    if "--self-test" in argv[1:]:
        return self_test()
    args = {}
    positional = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--out":
            args["out"] = argv[i + 1]
            i += 2
        elif a == "--probe-mode":
            args["probe_mode"] = argv[i + 1]
            i += 2
        elif a == "--timeout":
            args["timeout"] = argv[i + 1]
            i += 2
        elif a == "--interval":
            args["interval"] = argv[i + 1]
            i += 2
        elif a == "--t0":
            args["t0"] = argv[i + 1]
            i += 2
        else:
            positional.append(a)
            i += 1
    if len(positional) != 1 or positional[0] not in MODES or not args.get("out"):
        print(USAGE, file=sys.stderr)
        return 1
    mode = positional[0]
    cfg = settings()
    if mode == "baseline":
        return cmd_baseline(cfg, args, Kubectl(cfg))
    if mode == "watch":
        return cmd_watch(cfg, args, Kubectl(cfg))
    if mode == "flip":
        return cmd_flip(cfg, args)
    return cmd_verify(cfg, args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
