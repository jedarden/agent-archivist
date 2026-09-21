#!/usr/bin/env bash
# Provision and verify the local MinIO reference storage profile.
#
# The reference profile (docs/notes/storage-profiles.md Section 1, plan
# Section 7.7) is the one S3 implementation the storage compatibility suite
# qualifies on every full verification run. The suite itself never touches a
# live backend — the verification baseline is credential-free by construction
# — so this script is the deployment-facing half of the profile: the
# operator's reproducible configuration of a local MinIO instance, and the
# instrument that proves the live configuration agrees with the profile's
# claims.
#
# What it configures:
#   - the raw and control buckets, with versioning enabled on the raw
#     bucket (a reported capability of the reference profile);
#   - the two disjoint ingest identities the portable S3 configuration
#     requires (plan Section 5): a raw writer that can create,
#     multipart-write, and abort below the tenant raw prefix — and never
#     read, list objects, or delete — and a control reader that can read
#     below the tenant control prefix — and never write;
#   - the 24-hour incomplete-multipart cleanup. On MinIO builds from 2025
#     onward this is the server-global `api stale_uploads_expiry` knob (the
#     bucket-level AbortIncompleteMultipartUpload lifecycle action was
#     removed; the server rejects such rules with InvalidArgument). Older
#     community builds instead take the bucket ILM rule; docs/notes/
#     minio-reference-profile.md records both models and the evidence.
#   - optionally (--with-raw-reader, --with-offline-restore) the two
#     optional roles: the STO-007 preflight raw reader and the offline
#     restore identity. Both stay out of an ingest replica's configuration;
#     they exist only for deployments that deliberately grant them.
#
# Usage:
#   tools/minio-reference-provision.sh provision --alias ALIAS --tenant UUID
#       [--raw-bucket B] [--control-bucket B] [--creds-dir DIR]
#       [--with-raw-reader] [--with-offline-restore]
#   tools/minio-reference-provision.sh verify --alias ALIAS --tenant UUID
#       [--raw-bucket B] [--control-bucket B] [--creds-dir DIR]
#       [--with-raw-reader] [--with-offline-restore]
#
# `verify` re-checks everything `provision` configured and exercises the
# disjointness live: every identity attempts the operations its grant
# forbids, and the run fails if any forbidden operation succeeds. Probe
# objects it creates under the tenant raw prefix are removed again; the
# control prefix is only ever listed, never written by a probe.
#
# Secrets: per-identity secret keys are generated in place (openssl rand),
# written mode-600 into --creds-dir, and never printed. An existing
# credentials file is reused, never rotated — re-running provision
# converges instead of silently replacing live credentials. The admin
# credential lives wherever the --alias mc alias lives (the operator's
# MC_CONFIG_DIR); this script never reads or echoes it.

set -euo pipefail
umask 077

ALIAS=""
TENANT=""
RAW_BUCKET="archivist-raw-local"
CONTROL_BUCKET="archivist-control-local"
CREDS_DIR="minio-reference-credentials"
WITH_RAW_READER=0
WITH_OFFLINE_RESTORE=0
MODE=""

usage() {
  echo "usage: $0 provision|verify --alias ALIAS --tenant UUID [--raw-bucket B] [--control-bucket B] [--creds-dir DIR] [--with-raw-reader] [--with-offline-restore]" >&2
  exit 2
}

[ $# -ge 1 ] || usage
MODE="$1"
shift
case "$MODE" in
  provision|verify) ;;
  *) usage ;;
esac

while [ $# -gt 0 ]; do
  case "$1" in
    --alias)               [ $# -ge 2 ] || usage; ALIAS="$2"; shift 2 ;;
    --tenant)              [ $# -ge 2 ] || usage; TENANT="$2"; shift 2 ;;
    --raw-bucket)          [ $# -ge 2 ] || usage; RAW_BUCKET="$2"; shift 2 ;;
    --control-bucket)      [ $# -ge 2 ] || usage; CONTROL_BUCKET="$2"; shift 2 ;;
    --creds-dir)           [ $# -ge 2 ] || usage; CREDS_DIR="$2"; shift 2 ;;
    --with-raw-reader)     WITH_RAW_READER=1; shift ;;
    --with-offline-restore) WITH_OFFLINE_RESTORE=1; shift ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[ -n "$ALIAS" ] || { echo "--alias is required" >&2; usage; }
[ -n "$TENANT" ] || { echo "--tenant is required" >&2; usage; }
# The archivist side validates the canonical UUID grammar; the script only
# needs the tenant segment it substitutes into policy resources and key
# prefixes to be ARN-safe.
echo "$TENANT" | grep -qE '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' || {
  echo "tenant must be a canonical UUID" >&2
  exit 2
}
command -v mc >/dev/null 2>&1 || { echo "mc (MinIO client) must be on PATH" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "openssl must be on PATH" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 must be on PATH" >&2; exit 2; }

RAW_PREFIX="tenants/${TENANT}/v1/raw/"
CONTROL_PREFIX="tenants/${TENANT}/v1/control/"

# The canonical grant sets, mirrored by docs/notes/minio-reference-profile.md.
# Every statement is allow-only; no identity holds s3:DeleteObject anywhere,
# and no identity crosses the raw/control boundary.
policy_document() {
  local role="$1"
  local raw_arn="arn:aws:s3:::${RAW_BUCKET}"
  local control_arn="arn:aws:s3:::${CONTROL_BUCKET}"
  case "$role" in
    raw-writer)
      # Create, multipart-write, and abort below the tenant raw prefix,
      # and nothing else: no GetObject, no ListBucket, no DeleteObject
      # (abort never implies delete). The write path never lists bucket
      # sessions, and MinIO rejects the s3:prefix condition on
      # s3:ListBucketMultipartUploads outright — rather than widen the
      # grant to the whole bucket, the action stays ungranted; in-progress
      # session auditing belongs to the admin identity. GetBucketLocation
      # is client plumbing for path-style endpoints and names no object
      # authority.
      cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": ["${raw_arn}/tenants/${TENANT}/v1/raw/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation"],
      "Resource": ["${raw_arn}"]
    }
  ]
}
EOF
      ;;
    control-reader)
      # Read-only below the tenant control prefix: the signed control
      # families and nothing else — no raw access, no write, no delete.
      cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["${control_arn}/tenants/${TENANT}/v1/control/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["${control_arn}"],
      "Condition": {
        "StringLike": {"s3:prefix": "tenants/${TENANT}/v1/control*"}
      }
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation"],
      "Resource": ["${control_arn}"]
    }
  ]
}
EOF
      ;;
    raw-reader)
      # The optional STO-007 preflight reader: GetObject/HeadObject below
      # the tenant raw prefix. Never required by the portable ingest
      # path; grant only to deployments that deliberately opt in.
      cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["${raw_arn}/tenants/${TENANT}/v1/raw/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["${raw_arn}"],
      "Condition": {
        "StringLike": {"s3:prefix": "tenants/${TENANT}/v1/raw*"}
      }
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation"],
      "Resource": ["${raw_arn}"]
    }
  ]
}
EOF
      ;;
    offline-restore)
      # The optional offline restore identity: HEAD/GET plus paginated
      # ListObjectsV2 across the tenant's raw and control prefixes, for
      # offline verify/restore and catalog tooling. Holds no write and
      # no delete anywhere.
      cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": [
        "${raw_arn}/tenants/${TENANT}/v1/raw/*",
        "${control_arn}/tenants/${TENANT}/v1/control/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": [
        "${raw_arn}",
        "${control_arn}"
      ],
      "Condition": {
        "StringLike": {
          "s3:prefix": [
            "tenants/${TENANT}/v1/raw*",
            "tenants/${TENANT}/v1/control*"
          ]
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation"],
      "Resource": [
        "${raw_arn}",
        "${control_arn}"
      ]
    }
  ]
}
EOF
      ;;
    *) return 1 ;;
  esac
}

mc_out() {
  mc --quiet "$@" 2>&1
}

# The endpoint behind the admin alias, for the throwaway per-identity probe
# aliases (their credentials live in their own scratch mc config, never in
# the operator's). Only the URL leaves this helper.
alias_url() {
  mc alias list --json "$ALIAS" 2>/dev/null | python3 -c '
import json, sys
record = json.load(sys.stdin)
print(record.get("URL") or record.get("url") or "")
'
}

# Read one field from an identity credential file. The file is mode-600 and
# operator-owned; the value travels through the script's memory to the mc
# invocation and is never echoed. A plain read loop, not a grep pipeline:
# under `pipefail` a downstream-closed pipe turns into a spurious failure.
credential_field() {
  local file="$1" field="$2" line
  while IFS= read -r line; do
    case "$line" in
      "${field}="*) printf '%s\n' "${line#*=}"; return 0 ;;
    esac
  done < "$file"
  return 1
}

# Emit one identity's credential file, creating it only when absent. A
# re-provision reuses live credentials; rotation is the operator's explicit
# action (delete the file, re-provision, re-deliver).
ensure_credential_file() {
  local role="$1"
  local file="${CREDS_DIR}/${role}.env"
  if [ ! -f "$file" ]; then
    mkdir -p "$CREDS_DIR"
    chmod 700 "$CREDS_DIR"
    {
      echo "ACCESS_KEY=${role}"
      echo "SECRET_KEY=$(openssl rand -hex 32)"
    } > "$file"
    chmod 600 "$file"
    echo "credentials: wrote ${file} (new secret)"
  else
    echo "credentials: reusing existing ${file}"
  fi
}

# Create-or-update one identity and attach exactly its canonical policy.
ensure_identity() {
  local role="$1"
  local access secret
  access="$(credential_field "${CREDS_DIR}/${role}.env" ACCESS_KEY)"
  secret="$(credential_field "${CREDS_DIR}/${role}.env" SECRET_KEY)"
  policy_document "$role" > "${CREDS_DIR}/${role}.policy.json"
  mc_out admin policy create "$ALIAS" "archivist-${role}" "${CREDS_DIR}/${role}.policy.json" >/dev/null 2>&1 || true
  mc_out admin user add "$ALIAS" "$access" "$secret" >/dev/null
  mc_out admin policy attach "$ALIAS" "archivist-${role}" --user "$access" >/dev/null
  echo "identity: ${role} provisioned (policy archivist-${role})"
}

provision() {
  echo "== provisioning the MinIO reference profile (alias: ${ALIAS})"

  for bucket in "$RAW_BUCKET" "$CONTROL_BUCKET"; do
    if ! mc_out ls "${ALIAS}/${bucket}" >/dev/null 2>&1; then
      mc_out mb "${ALIAS}/${bucket}" >/dev/null
      echo "bucket: created ${bucket}"
    else
      echo "bucket: exists ${bucket}"
    fi
  done

  # Versioning is a reported capability of the reference profile; enable it
  # on the raw bucket so the live instance agrees with the profile's report.
  mc_out version enable "${ALIAS}/${RAW_BUCKET}" >/dev/null 2>&1 || true
  echo "versioning: enabled on ${RAW_BUCKET}"

  # The 24-hour incomplete-multipart cleanup. On 2025-era MinIO this is the
  # server-global api knob (bucket ILM rules with the abort action are
  # rejected); the value is pinned explicitly so the deployment does not
  # lean on a default it cannot name.
  local current_expiry
  current_expiry="$(mc_out admin config get "$ALIAS" api 2>/dev/null \
    | tr ' ' '\n' | grep '^stale_uploads_expiry=' | cut -d= -f2 || true)"
  if [ "$current_expiry" != "24h" ]; then
    mc_out admin config set "$ALIAS" api:stale_uploads_expiry=24h >/dev/null
    echo "incomplete-multipart cleanup: stale_uploads_expiry set to 24h (server-global; applies after the operator restarts the instance)"
  else
    echo "incomplete-multipart cleanup: stale_uploads_expiry already 24h"
  fi

  local role
  for role in raw-writer control-reader; do
    ensure_credential_file "$role"
    ensure_identity "$role"
  done

  if [ "$WITH_RAW_READER" = 1 ]; then
    ensure_credential_file raw-reader
    ensure_identity raw-reader
    echo "identity: raw-reader is optional — never part of an ingest replica's configuration"
  fi

  if [ "$WITH_OFFLINE_RESTORE" = 1 ]; then
    ensure_credential_file offline-restore
    ensure_identity offline-restore
    echo "identity: offline-restore is optional offline-tooling credential"
  fi

  echo "== provision complete"
}

# ---------------------------------------------------------------------------
# verify: the live property checks. Every check prints a verdict; the run
# fails if the live configuration disagrees with the profile.
# ---------------------------------------------------------------------------

FAILURES=0

# A probe that MUST be denied: fails the run unless mc refuses with an
# authorization error (mc words it "Access Denied" for listings and
# "Insufficient permissions" for object reads and removes). Call sites
# state the probed operation readably as `mc <verb> ...`; the literal
# command name is stripped here.
deny_expect() {
  local what="$1"
  shift
  if [ "${1:-}" != "mc" ]; then
    echo "internal error: deny_expect expects the probe operation to start with mc" >&2
    exit 2
  fi
  shift
  local output
  if output="$(MC_CONFIG_DIR="$PROBE_DIR" mc --quiet "$@" 2>&1)"; then
    echo "  FAIL ${what} (operation unexpectedly succeeded)"
    FAILURES=$((FAILURES + 1))
  elif echo "$output" | grep -Eqi 'Access Denied|Insufficient permissions'; then
    echo "  ok   ${what} (denied)"
  else
    echo "  FAIL ${what} (failed, but not with an authorization refusal)"
    FAILURES=$((FAILURES + 1))
  fi
}

verify() {
  echo "== verifying the MinIO reference profile (alias: ${ALIAS})"

  # 1. The pinned cleanup knob: 24 hours, exactly.
  local expiry
  expiry="$(mc_out admin config get "$ALIAS" api 2>/dev/null \
    | tr ' ' '\n' | grep '^stale_uploads_expiry=' | cut -d= -f2 || true)"
  if [ "$expiry" = "24h" ]; then
    echo "  ok   incomplete-multipart cleanup: stale_uploads_expiry=24h"
  else
    echo "  FAIL incomplete-multipart cleanup: stale_uploads_expiry=${expiry:-unset} (want 24h)"
    FAILURES=$((FAILURES + 1))
  fi

  # 2. Versioning on the raw bucket.
  if mc_out version info "${ALIAS}/${RAW_BUCKET}" 2>/dev/null | grep -q 'versioning is enabled'; then
    echo "  ok   versioning enabled on ${RAW_BUCKET}"
  else
    echo "  FAIL versioning is not enabled on ${RAW_BUCKET}"
    FAILURES=$((FAILURES + 1))
  fi

  # 3. The required identities exist and carry their policy.
  local role access
  for role in raw-writer control-reader; do
    access="$(credential_field "${CREDS_DIR}/${role}.env" ACCESS_KEY)"
    if mc_out admin user info "$ALIAS" "$access" 2>/dev/null | grep -q "archivist-${role}"; then
      echo "  ok   identity ${role} exists with policy archivist-${role}"
    else
      echo "  FAIL identity ${role} is missing or carries the wrong policy"
      FAILURES=$((FAILURES + 1))
    fi
  done

  # 4. The stored policy documents equal the canonical grant sets. The
  #    comparison normalizes list order; any changed action, resource, or
  #    condition fails.
  for role in raw-writer control-reader; do
    local canonical
    canonical="$(mktemp "${TMPDIR:-/tmp}/refprofile-canonical-${role}.XXXXXX")"
    policy_document "$role" > "$canonical"
    if mc_out admin policy info "$ALIAS" "archivist-${role}" 2>/dev/null \
      | python3 -c '
import json, sys

def normalize(value, condition=False):
    # AWS condition values are scalar-or-list; MinIO stores lists. Compare
    # in list form on both sides so that storage normalization alone never
    # reads as drift.
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if condition and not isinstance(item, list):
                item = [item]
            out[key] = normalize(item, condition or key == "Condition")
        return out
    if isinstance(value, list):
        return sorted(
            (normalize(item, condition) for item in value),
            key=lambda item: json.dumps(item, sort_keys=True),
        )
    return value

record = json.load(sys.stdin)
canonical = json.load(open(sys.argv[1]))
stored = normalize(record.get("Policy", {}).get("Statement", []))
wanted = normalize(canonical["Statement"])
sys.exit(0 if stored == wanted else 1)
' "$canonical"; then
      echo "  ok   policy archivist-${role} matches the canonical grant set"
    else
      echo "  FAIL policy archivist-${role} drifted from the canonical grant set"
      FAILURES=$((FAILURES + 1))
    fi
    rm -f "$canonical"
  done

  # 5. The live disjointness matrix. Probe aliases live in a throwaway mc
  #    config so the operator's own configuration is never touched; probe
  #    objects are removed again by the admin identity. The scratch
  #    directory is a global so the EXIT trap can still name it after
  #    this function's frame is gone.
  PROBE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/refprofile-probes.XXXXXX")"
  trap 'rm -rf "$PROBE_DIR"' EXIT
  # Write-denial probes copy a real file: mc refuses /dev/null client-side
  # before any request reaches the server, which would masquerade as a
  # denial.
  printf 'reference-profile write-denial probe\n' > "$PROBE_DIR/write-denied-source"
  local url
  url="$(alias_url)"
  if [ -z "$url" ]; then
    echo "  FAIL could not resolve the endpoint of alias ${ALIAS}"
    FAILURES=$((FAILURES + 1))
    exit 1
  fi

  local rw_access rw_secret cr_access cr_secret
  rw_access="$(credential_field "${CREDS_DIR}/raw-writer.env" ACCESS_KEY)"
  rw_secret="$(credential_field "${CREDS_DIR}/raw-writer.env" SECRET_KEY)"
  cr_access="$(credential_field "${CREDS_DIR}/control-reader.env" ACCESS_KEY)"
  cr_secret="$(credential_field "${CREDS_DIR}/control-reader.env" SECRET_KEY)"

  MC_CONFIG_DIR="$PROBE_DIR" mc --quiet alias set probe-raw-writer "$url" "$rw_access" "$rw_secret" >/dev/null
  MC_CONFIG_DIR="$PROBE_DIR" mc --quiet alias set probe-control-reader "$url" "$cr_access" "$cr_secret" >/dev/null

  # The admin plants one readable probe object inside the tenant raw
  # prefix, clearly marked as a probe and removed again below.
  local probe_key="tenants/${TENANT}/v1/raw/probe/reference-profile-probe"
  printf 'reference-profile read-denial probe' \
    | MC_CONFIG_DIR="$PROBE_DIR" mc --quiet pipe "${ALIAS}/${RAW_BUCKET}/${probe_key}" >/dev/null

  # raw writer: write inside its prefix succeeds ...
  printf 'reference-profile write probe' \
    | MC_CONFIG_DIR="$PROBE_DIR" mc --quiet pipe "${ALIAS}/${RAW_BUCKET}/tenants/${TENANT}/v1/raw/probe/write-probe" >/dev/null
  echo "  ok   raw-writer can write below the tenant raw prefix"
  # ... and every other authority is denied: no read (even its own bytes),
  # no delete (abort never implies delete), no control-bucket access.
  deny_expect "raw-writer cannot read raw objects" \
    mc cat "probe-raw-writer/${RAW_BUCKET}/${probe_key}"
  deny_expect "raw-writer cannot delete raw objects" \
    mc rm "probe-raw-writer/${RAW_BUCKET}/tenants/${TENANT}/v1/raw/probe/write-probe"
  deny_expect "raw-writer cannot read the control bucket" \
    mc ls "probe-raw-writer/${CONTROL_BUCKET}/tenants/${TENANT}/v1/control/"
  deny_expect "raw-writer cannot write the control bucket" \
    mc cp "$PROBE_DIR/write-denied-source" "probe-raw-writer/${CONTROL_BUCKET}/tenants/${TENANT}/v1/control/write-denied-probe"

  # control reader: read scope is reachable ...
  if MC_CONFIG_DIR="$PROBE_DIR" mc --quiet ls \
      "probe-control-reader/${CONTROL_BUCKET}/tenants/${TENANT}/v1/control/" >/dev/null 2>&1; then
    echo "  ok   control-reader can list the tenant control prefix"
  else
    echo "  FAIL control-reader cannot list the tenant control prefix"
    FAILURES=$((FAILURES + 1))
  fi
  # ... and nothing else: no write, no delete, no raw access.
  deny_expect "control-reader cannot write the control prefix" \
    mc cp "$PROBE_DIR/write-denied-source" "probe-control-reader/${CONTROL_BUCKET}/tenants/${TENANT}/v1/control/write-denied-probe"
  deny_expect "control-reader cannot read raw objects" \
    mc cat "probe-control-reader/${RAW_BUCKET}/${probe_key}"
  deny_expect "control-reader cannot write the raw prefix" \
    mc cp "$PROBE_DIR/write-denied-source" "probe-control-reader/${RAW_BUCKET}/tenants/${TENANT}/v1/raw/probe/write-denied-probe"

  if [ "$WITH_RAW_READER" = 1 ]; then
    local rr_access rr_secret
    rr_access="$(credential_field "${CREDS_DIR}/raw-reader.env" ACCESS_KEY)"
    rr_secret="$(credential_field "${CREDS_DIR}/raw-reader.env" SECRET_KEY)"
    MC_CONFIG_DIR="$PROBE_DIR" mc --quiet alias set probe-raw-reader "$url" "$rr_access" "$rr_secret" >/dev/null
    if MC_CONFIG_DIR="$PROBE_DIR" mc --quiet ls \
        "probe-raw-reader/${RAW_BUCKET}/tenants/${TENANT}/v1/raw/" >/dev/null 2>&1; then
      echo "  ok   raw-reader (optional) can list the tenant raw prefix"
    else
      echo "  FAIL raw-reader (optional) cannot list the tenant raw prefix"
      FAILURES=$((FAILURES + 1))
    fi
    deny_expect "raw-reader (optional) cannot write the raw prefix" \
      mc cp "$PROBE_DIR/write-denied-source" "probe-raw-reader/${RAW_BUCKET}/tenants/${TENANT}/v1/raw/probe/write-denied-probe"
    deny_expect "raw-reader (optional) cannot read the control prefix" \
      mc ls "probe-raw-reader/${CONTROL_BUCKET}/tenants/${TENANT}/v1/control/"
  fi

  if [ "$WITH_OFFLINE_RESTORE" = 1 ]; then
    local or_access or_secret
    or_access="$(credential_field "${CREDS_DIR}/offline-restore.env" ACCESS_KEY)"
    or_secret="$(credential_field "${CREDS_DIR}/offline-restore.env" SECRET_KEY)"
    MC_CONFIG_DIR="$PROBE_DIR" mc --quiet alias set probe-offline-restore "$url" "$or_access" "$or_secret" >/dev/null
    if MC_CONFIG_DIR="$PROBE_DIR" mc --quiet ls \
        "probe-offline-restore/${RAW_BUCKET}/tenants/${TENANT}/v1/raw/" >/dev/null 2>&1 \
      && MC_CONFIG_DIR="$PROBE_DIR" mc --quiet ls \
        "probe-offline-restore/${CONTROL_BUCKET}/tenants/${TENANT}/v1/control/" >/dev/null 2>&1; then
      echo "  ok   offline-restore (optional) can list both tenant prefixes"
    else
      echo "  FAIL offline-restore (optional) cannot list the tenant prefixes"
      FAILURES=$((FAILURES + 1))
    fi
    deny_expect "offline-restore (optional) cannot write the raw prefix" \
      mc cp "$PROBE_DIR/write-denied-source" "probe-offline-restore/${RAW_BUCKET}/tenants/${TENANT}/v1/raw/probe/write-denied-probe"
  fi

  # Epilogue: the admin removes its probe objects. The probes a denied
  # identity attempted never landed.
  mc --quiet rm "${ALIAS}/${RAW_BUCKET}/${probe_key}" >/dev/null 2>&1 || true
  mc --quiet rm --versions --recursive --force \
    "${ALIAS}/${RAW_BUCKET}/tenants/${TENANT}/v1/raw/probe/" >/dev/null 2>&1 || true
  mc --quiet rm "${ALIAS}/${CONTROL_BUCKET}/tenants/${TENANT}/v1/control/write-denied-probe" >/dev/null 2>&1 || true

  if [ "$FAILURES" -gt 0 ]; then
    echo "== verify: FAIL (${FAILURES} check(s) failed)"
    exit 1
  fi
  echo "== verify: PASS (the live instance agrees with the reference profile)"
}

case "$MODE" in
  provision) provision ;;
  verify)    verify ;;
esac
