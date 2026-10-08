#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# The release-image smoke harness: build the release image from a clean
# git-archive extraction on a BuildKit host and exercise the five smoke
# categories the packaging acceptance names (plan Section 13; parent bead
# aa-580ffbb2) — health, secret, vulnerability, signature-input, and
# multi-replica — against that one image. The live MinIO stage starts with
# fresh buckets and executes the released zero-state bootstrap commands.
#
# The contract this harness verifies is docs/notes/release-container.md; the
# category definitions, instruments, and failure modes are owned by
# docs/notes/image-smoke.md.
#
# Invocation — the harness runs on the BuildKit CI host from the exact
# committed tree. A checkout must be clean; an archive extraction receives
# its source epoch explicitly (release-container.md Section 6):
#
#   D=$(mktemp -d) && git archive HEAD | tar -x -C "$D"
#   SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD) \
#     bash "$D/containers/agent-archivist/smoke.sh"
#
# The extraction carries no .git, so the one build input the canonical
# invocation cannot derive comes in through the environment:
# SOURCE_DATE_EPOCH, the commit timestamp of the extracted tree.
#
# Prerequisites on the builder host: docker with BuildKit, curl, python3
# (standard library only — the signing backend shims itself when the
# cryptography wheel is absent), tar, sha256sum, openssl, and — for the
# vulnerability category — grype (its absence degrades that one category
# to a documented GAP, never a silent pass). The live categories drive the
# pinned MinIO reference binaries (docs/notes/minio-reference-profile.md
# Section 1); they are fetched once per work directory and SHA-256-verified
# against the pins this script carries from that note.
#
# Secret hygiene: the run mints its own MinIO identity credentials into the
# work directory, mode 600, never printed; the secret category's deny list
# holds those values plus the run's tenant material and is consumed by the
# driver's scanner, which reports matches as counts and file names only.

set -euo pipefail
umask 077

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER="$SELF_DIR/smoke-attempt-driver.py"
REPO_DIR="$SELF_DIR/../.."

# --- knobs -----------------------------------------------------------------

SMOKE_IMAGE="${SMOKE_IMAGE:-agent-archivist-smoke:smoke}"
SMOKE_VERSION="${SMOKE_VERSION:-$(cat "$SELF_DIR/VERSION")}"
SMOKE_WORK_DIR="${SMOKE_WORK_DIR:-$(mktemp -d /tmp/aa-smoke.XXXXXX)}"
SMOKE_SKIP_BUILD="${SMOKE_SKIP_BUILD:-0}"
SMOKE_KEEP_ON_FAIL="${SMOKE_KEEP_ON_FAIL:-0}"
SMOKE_KEEP_IMAGE="${SMOKE_KEEP_IMAGE:-0}"
SMOKE_PORT_MINIO="${SMOKE_PORT_MINIO:-19000}"
SMOKE_PORT_R1="${SMOKE_PORT_R1:-18087}"
SMOKE_PORT_R2="${SMOKE_PORT_R2:-18088}"
# The multi-replica reference envelope (phase4_resource_benchmark.rs, bead
# aa-feadbc99): four vCPU and 512 MiB for the serving plane. The pair shares
# it — two replicas at half the CPU floor and half the memory ceiling each —
# and docker enforces both halves (--cpus/--memory; an OOM kill is a fail).
SMOKE_REPLICA_CPUS="${SMOKE_REPLICA_CPUS:-2}"
SMOKE_REPLICA_MEMORY="${SMOKE_REPLICA_MEMORY:-256m}"
# These remain overrideable while investigating a failing builder, but the
# committed acceptance path requires the complete MinIO round trip.
# The vulnerability threshold: grype --fail-on SEVERITY over the findings
# with an available fix (--only-fixed). The recorded policy is "a fixable
# Critical fails the smoke"; the digest-pinned base's unfixable findings are
# recorded in full and are a base-move decision for the maintainer, exactly
# as the secret category treats base bytes.
SMOKE_VULN_FAIL_ON="${SMOKE_VULN_FAIL_ON:-critical}"

# The MinIO reference pins (docs/notes/minio-reference-profile.md Section 1;
# the upstream is archived, so these are fixed artifacts, hash-verified).
# The asset name puts the platform first: minio.linux-amd64.<RELEASE>.
MINIO_RELEASE="RELEASE.2025-09-07T16-13-09Z"
MINIO_SHA256="7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f"
MC_RELEASE="RELEASE.2025-08-13T08-35-41Z"
MC_SHA256="01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"
MINIO_URL="https://github.com/minio/minio/releases/download/${MINIO_RELEASE}/minio.linux-amd64.${MINIO_RELEASE}"
MC_URL="https://github.com/minio/mc/releases/download/${MC_RELEASE}/mc.linux-amd64.${MC_RELEASE}"

# Each run gets fresh buckets so the bootstrap proof cannot inherit a control
# record when a builder reuses SMOKE_WORK_DIR.
TENANT="3e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30"
RUN_SUFFIX="$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
RAW_BUCKET="aa-smoke-raw-$RUN_SUFFIX"
CONTROL_BUCKET="aa-smoke-control-$RUN_SUFFIX"
AUTHORITY_KEY=""
RECEIPT_KEY_ID=""

# --- harness plumbing -------------------------------------------------------

PASS=0; FAIL=0; GAP=0
declare -a SUMMARY=()

record() { # record PASS|FAIL|GAP "category" "what"
  local verdict="$1" category="$2" what="$3"
  SUMMARY+=("$verdict $category: $what")
  case "$verdict" in
    PASS) PASS=$((PASS + 1)); echo "[smoke] PASS $category: $what" ;;
    FAIL) FAIL=$((FAIL + 1)); echo "[smoke] FAIL $category: $what" >&2 ;;
    GAP)  GAP=$((GAP + 1));  echo "[smoke] GAP $category: $what" >&2 ;;
  esac
}

fail_stage() { echo "[smoke] stage abort: $*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || fail_stage "prerequisite missing on the builder host: $1"; }

cleanup() {
  local status=$?
  docker rm -f aa-smoke-r1 aa-smoke-r2 >/dev/null 2>&1 || true
  if [ -n "${MINIO_PID:-}" ]; then kill "$MINIO_PID" >/dev/null 2>&1 || true; fi
  if [ "$status" -ne 0 ] && [ "$SMOKE_KEEP_ON_FAIL" = 1 ]; then
    echo "[smoke] failed run kept for diagnosis: $SMOKE_WORK_DIR" >&2
  else
    if [ "$SMOKE_KEEP_IMAGE" != 1 ]; then
      docker rmi -f "$SMOKE_IMAGE" >/dev/null 2>&1 || true
    fi
    rm -rf "$SMOKE_WORK_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT

# Poll a URL until it answers with the wanted status.
await_url() { # url want-status timeout-seconds
  local url="$1" want="$2" timeout="${3:-45}" waited=0 got=""
  while [ "$waited" -lt "$timeout" ]; do
    got="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" || true)"
    [ "$got" = "$want" ] && return 0
    sleep 1; waited=$((waited + 1))
  done
  echo "[smoke] $url answered ${got:-none}, wanted $want" >&2
  return 1
}

docker_health() { docker inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null || echo absent; }

run_scan() { # layers-dir deny base-files ; prints output, sets SCAN_STATUS
  SCAN_STATUS=0
  SCAN_OUTPUT="$(python3 "$DRIVER" scan-image \
    --layers-dir "$1" --deny "$2" --base-files "$3" 2>&1)" || SCAN_STATUS=$?
  printf '%s\n' "$SCAN_OUTPUT" | sed 's/^/[smoke] /'
}

response_class() { # response-json ; the wire class it carries, if any
  grep -o '"code":"[a-z._]*"' "$1" 2>/dev/null | head -1 | cut -d'"' -f4 || true
}

# --- stage: prereqs ---------------------------------------------------------

echo "=== smoke: prerequisites (work dir $SMOKE_WORK_DIR)"
require docker; require curl; require python3; require tar; require sha256sum; require openssl
docker info >/dev/null 2>&1 || fail_stage "docker daemon unreachable"
mkdir -p "$SMOKE_WORK_DIR"/{bin,minio-data,creds,layers,layers-base,attempts,admin,client,records}
chmod 700 "$SMOKE_WORK_DIR"

# --- stage: build -----------------------------------------------------------

if [ "$SMOKE_SKIP_BUILD" != 1 ]; then
  echo "=== smoke: build (the canonical invocation's shape, RC-019)"
  if git -C "$REPO_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    [ -z "$(git -C "$REPO_DIR" status --porcelain --untracked-files=normal)" ] \
      || fail_stage "BuildKit smoke requires a clean committed checkout"
    if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
      SOURCE_DATE_EPOCH="$(git -C "$REPO_DIR" log -1 --format=%ct HEAD)"
      export SOURCE_DATE_EPOCH
    fi
  fi
  : "${SOURCE_DATE_EPOCH:?set SOURCE_DATE_EPOCH to the commit timestamp of the extracted tree (git log -1 --format=%ct)}"
  docker build --provenance=false --sbom=false \
    -f "$SELF_DIR/Dockerfile" \
    --build-arg AGENT_ARCHIVIST_VERSION="$SMOKE_VERSION" \
    --build-arg SOURCE_DATE_EPOCH \
    --tag "$SMOKE_IMAGE" \
    "$REPO_DIR" \
    || fail_stage "image build failed"
  echo "[smoke] built $SMOKE_IMAGE at version $SMOKE_VERSION"
fi
docker image inspect "$SMOKE_IMAGE" >/dev/null 2>&1 \
  || fail_stage "image $SMOKE_IMAGE absent (build it first, or point SMOKE_IMAGE at one)"

# --- stage: secret ----------------------------------------------------------

echo "=== smoke: secret (no credential material in any layer or the filesystem)"
docker save "$SMOKE_IMAGE" | tar -x -C "$SMOKE_WORK_DIR/layers"
BASE_REF="debian:12.15-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
docker pull -q "$BASE_REF" >/dev/null
docker save "$BASE_REF" | tar -x -C "$SMOKE_WORK_DIR/layers-base"
# The base's regular-file inventory in its final state (layer order,
# whiteouts honored): what the image may carry without explanation. Anything
# outside it — plus the one installed binary — is a finding.
python3 "$DRIVER" base-inventory \
  --layers-dir "$SMOKE_WORK_DIR/layers-base" \
  --out "$SMOKE_WORK_DIR/base-files.txt" | sed 's/^/[smoke] /'
# The deny list: the tenant and authority material, plus (after the live
# stage mints them) the run's own credential values. Mode 600 via the work
# dir; consumed by the scanner; never printed.
printf '%s\n' "$TENANT" > "$SMOKE_WORK_DIR/deny.txt"
run_scan "$SMOKE_WORK_DIR/layers" "$SMOKE_WORK_DIR/deny.txt" "$SMOKE_WORK_DIR/base-files.txt"
if [ "$SCAN_STATUS" -eq 0 ]; then
  record PASS secret "layer inventory matches the digest-pinned base plus the one binary; no credential shape in any layer or the config"
else
  record FAIL secret "layer scan found denied material or an unexpected file (scan-image output above)"
fi
# The filesystem leg: the running image's own root. The generic credential
# shapes apply to the stateful trees (/etc, /tmp); the installed binary's
# own bytes carry its parsing and redaction vocabulary (the driver's
# BINARY_PATH note), so the binary is scanned for value material only —
# tenant and authority material, which have no business anywhere in the
# image.
docker run --rm --entrypoint /bin/sh "$SMOKE_IMAGE" -c \
  "out=\$(grep -rslF -e 'ACCESS_KEY=' -e 'SECRET_KEY=' -e 'PRIVATE KEY' -e '$TENANT' /etc /tmp 2>/dev/null); [ -z \"\$out\" ]" \
  && record PASS secret "no credential shape or tenant material in /etc or /tmp" \
  || record FAIL secret "credential shape or tenant material in /etc or /tmp"
docker run --rm --entrypoint /bin/sh "$SMOKE_IMAGE" -c \
  "out=\$(grep -rslF -e '$TENANT' /usr/local/bin 2>/dev/null); [ -z \"\$out\" ]" \
  && record PASS secret "no tenant material in the installed binary" \
  || record FAIL secret "tenant material in the installed binary"

# --- stage: vulnerability ---------------------------------------------------

echo "=== smoke: vulnerability (grype over the built image; --fail-on $SMOKE_VULN_FAIL_ON over fixable findings)"
if ! command -v grype >/dev/null 2>&1; then
  record GAP vulnerability "scanner absent on this host; the documented invocation stands: grype <image> --fail-on $SMOKE_VULN_FAIL_ON --only-fixed"
elif ! grype db status >/dev/null 2>&1; then
  record GAP vulnerability "grype present but its vulnerability database is unavailable; the documented invocation stands: grype <image> --fail-on $SMOKE_VULN_FAIL_ON --only-fixed"
else
  GRYPE_JSON="$SMOKE_WORK_DIR/records/grype.json"
  # The record: one full scan, every finding retained — both count lines and
  # the release-evidence bead read from this JSON.
  set +e
  grype "$SMOKE_IMAGE" -o json --file "$GRYPE_JSON" \
    2>"$SMOKE_WORK_DIR/records/grype.stderr"
  set -e
  python3 - "$GRYPE_JSON" <<'PY'
import collections, json, sys
doc = json.load(open(sys.argv[1]))
matches = doc.get("matches", [])

def fixable(match):
    fix = match["vulnerability"].get("fix", {})
    return fix.get("state") == "fixed" or bool(fix.get("versions"))

counts = collections.Counter(m["vulnerability"]["severity"] for m in matches)
gating = collections.Counter(m["vulnerability"]["severity"] for m in matches if fixable(m))
print("[smoke] grype findings by severity (all):",
      ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none")
print("[smoke] grype findings the build can act on (fix available):",
      ", ".join(f"{k}={v}" for k, v in sorted(gating.items())) or "none")
PY
  # The gate: grype's own threshold machinery, over the findings the image
  # build can act on (--only-fixed). The digest-pinned base's unfixable
  # findings stand in the record above and are a base-move decision, exactly
  # as the secret category treats base bytes.
  set +e
  grype "$SMOKE_IMAGE" --fail-on "$SMOKE_VULN_FAIL_ON" --only-fixed \
    >>"$SMOKE_WORK_DIR/records/grype.stderr" 2>&1
  GRYPE_STATUS=$?
  set -e
  if [ "$GRYPE_STATUS" -eq 0 ]; then
    record PASS vulnerability "no fixable finding at or above --fail-on $SMOKE_VULN_FAIL_ON (all findings counted above from the retained JSON; unfixable base findings are a base-move decision)"
  else
    record FAIL vulnerability "grype exited $GRYPE_STATUS: a fixable finding at or above --fail-on $SMOKE_VULN_FAIL_ON (full record retained)"
  fi
fi

# --- stage: live (MinIO backend, health, signature-input, multi-replica) ----

echo "=== smoke: live (MinIO reference backend + capped replicas)"

# 1. The pinned MinIO reference binaries, fetched once, hash-verified.
fetch_pin() { # url sha256 dest
  local url="$1" sha="$2" dest="$3"
  if [ -f "$dest" ] && echo "$sha  $dest" | sha256sum -c --status 2>/dev/null; then
    return 0
  fi
  curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url"
  echo "$sha  $dest" | sha256sum -c --status \
    || fail_stage "pinned artifact does not match its committed hash: $(basename "$dest")"
}
fetch_pin "$MINIO_URL" "$MINIO_SHA256" "$SMOKE_WORK_DIR/bin/minio"
fetch_pin "$MC_URL" "$MC_SHA256" "$SMOKE_WORK_DIR/bin/mc"
chmod 555 "$SMOKE_WORK_DIR/bin/minio" "$SMOKE_WORK_DIR/bin/mc"
PATH="$SMOKE_WORK_DIR/bin:$PATH"
export PATH
MC_CONFIG_DIR="$SMOKE_WORK_DIR/mc-config"
export MC_CONFIG_DIR
mkdir -m 700 -p "$MC_CONFIG_DIR"

# MinIO's root credential is generated per smoke run and never appears in a
# process argument or terminal output. The isolated mc configuration is the
# alias consumed by the repository's reference provisioner.
python3 - "$SMOKE_WORK_DIR/creds/minio-root.env" "$MC_CONFIG_DIR/config.json" "$MINIO_ENDPOINT" <<'PY'
import json, os, pathlib, secrets, sys
credentials = pathlib.Path(sys.argv[1])
if credentials.exists():
    fields = dict(
        line.rstrip("\n").split("=", 1)
        for line in credentials.read_text().splitlines()
        if "=" in line
    )
    access, secret = fields.get("MINIO_ROOT_USER"), fields.get("MINIO_ROOT_PASSWORD")
    if not access or not secret:
        raise SystemExit("retained MinIO root credentials are malformed")
else:
    access, secret = secrets.token_hex(16), secrets.token_hex(32)
    credentials.write_text(
        f"MINIO_ROOT_USER={access}\nMINIO_ROOT_PASSWORD={secret}\n"
    )
os.chmod(credentials, 0o600)
config_path = pathlib.Path(sys.argv[2])
config = {
    "version": "10",
    "aliases": {
        "local": {
            "url": sys.argv[3],
            "accessKey": access,
            "secretKey": secret,
            "api": "s3v4",
            "path": "auto",
        }
    },
}
config_path.write_text(json.dumps(config, separators=(",", ":")) + "\n")
os.chmod(config_path, 0o600)
PY
# Values come from the protected run-local file and are inherited only by the
# MinIO process. The generated values are URL-safe hexadecimal strings.
set -a
. "$SMOKE_WORK_DIR/creds/minio-root.env"
set +a

# The reference provisioner mints its secrets with `openssl rand -hex 32`.
# A builder whose openssl is broken (a missing shared library, a botched
# upgrade) must not turn into a smoke failure or, worse, an empty secret:
# when openssl cannot answer a probe, this run ships a stand-in ahead of it
# on PATH implementing exactly that one invocation over the python3
# standard library, and failing loudly for anything else.
if ! openssl rand -hex 8 >/dev/null 2>&1; then
  cat > "$SMOKE_WORK_DIR/bin/openssl" <<'SH'
#!/usr/bin/env bash
# Minimal openssl stand-in: implements only `rand -hex N` (the reference
# provisioner's use), via the python3 standard library. Anything else
# fails loudly — this is not a general openssl.
if [ "${1:-}" = rand ] && [ "${2:-}" = -hex ] && [ -n "${3:-}" ]; then
  exec python3 -c 'import secrets, sys; print(secrets.token_hex(int(sys.argv[1])))' "$3"
fi
echo "openssl shim: only 'rand -hex N' is implemented" >&2
exit 1
SH
  chmod +x "$SMOKE_WORK_DIR/bin/openssl"
  echo "[smoke] system openssl unusable; the run's rand shim is on PATH"
fi

# 2. MinIO on loopback, single-node single-drive (the reference shape).
# Readiness probes the server's own health endpoint over plain HTTP — the
# language mc speaks to it; the replicas' endpoint is decided separately.
MINIO_PID=""
MINIO_ENDPOINT="http://127.0.0.1:${SMOKE_PORT_MINIO}"
minio_ready() {
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
    "$MINIO_ENDPOINT/minio/health/live" 2>/dev/null || true)" = 200 ]
}
if [ -f "$SMOKE_WORK_DIR/minio.pid" ] \
    && kill -0 "$(cat "$SMOKE_WORK_DIR/minio.pid")" 2>/dev/null \
    && minio_ready; then
  MINIO_PID="$(cat "$SMOKE_WORK_DIR/minio.pid")"
else
  MINIO_ROOT_USER="$MINIO_ROOT_USER" \
  MINIO_ROOT_PASSWORD="$MINIO_ROOT_PASSWORD" \
  nohup "$SMOKE_WORK_DIR/bin/minio" server "$SMOKE_WORK_DIR/minio-data" \
    --address "127.0.0.1:${SMOKE_PORT_MINIO}" \
    --console-address "127.0.0.1:$((SMOKE_PORT_MINIO + 1))" \
    >"$SMOKE_WORK_DIR/minio.log" 2>&1 &
  MINIO_PID=$!
  echo "$MINIO_PID" > "$SMOKE_WORK_DIR/minio.pid"
fi
unset MINIO_ROOT_USER MINIO_ROOT_PASSWORD
for _ in $(seq 1 30); do minio_ready && break; sleep 1; done
minio_ready || fail_stage "MinIO reference backend not ready (see $SMOKE_WORK_DIR/minio.log)"
python3 - "$MC_CONFIG_DIR/config.json" "$SMOKE_WORK_DIR/creds/control-admin.env" <<'PY'
import json, os, pathlib, sys
config = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = config.get("aliases", {}).get("local", {})
access, secret = root.get("accessKey"), root.get("secretKey")
if not access or not secret:
    raise SystemExit("MinIO admin alias did not retain its protected credential")
target = pathlib.Path(sys.argv[2])
target.write_text(f"ACCESS_KEY={access}\nSECRET_KEY={secret}\n")
os.chmod(target, 0o600)
PY
echo "[smoke] MinIO reference backend ready on $MINIO_ENDPOINT (pid $MINIO_PID)"

# The smoke opts into plaintext only for its loopback MinIO endpoint; the
# replica configuration states `storage.tls=disabled` explicitly.
SMOKE_ENDPOINT="$MINIO_ENDPOINT"

# 3. Buckets and the two disjoint ingest identities (the committed tool).
"$REPO_DIR/tools/minio-reference-provision.sh" provision \
  --alias local --tenant "$TENANT" \
  --raw-bucket "$RAW_BUCKET" --control-bucket "$CONTROL_BUCKET" \
  --creds-dir "$SMOKE_WORK_DIR/creds" \
  || fail_stage "reference provisioning failed"
echo "[smoke] buckets and the two ingest identities provisioned"
# The minted credential values now join the deny list.
sed -n 's/^SECRET_KEY=//p' "$SMOKE_WORK_DIR/creds/raw-writer.env" >> "$SMOKE_WORK_DIR/deny.txt"
sed -n 's/^SECRET_KEY=//p' "$SMOKE_WORK_DIR/creds/control-reader.env" >> "$SMOKE_WORK_DIR/deny.txt"
sed -n 's/^SECRET_KEY=//p' "$SMOKE_WORK_DIR/creds/control-admin.env" >> "$SMOKE_WORK_DIR/deny.txt"
sed -n 's/^MINIO_ROOT_PASSWORD=//p' "$SMOKE_WORK_DIR/creds/minio-root.env" >> "$SMOKE_WORK_DIR/deny.txt"

# The first control read starts from no records. The CLI creates the root,
# creates one protected client identity, publishes its signed link, and then
# issues the receipt key used by the replica.
if mc --quiet ls --recursive --json "local/$CONTROL_BUCKET" \
    > "$SMOKE_WORK_DIR/records/control-before-bootstrap.jsonl" 2>/dev/null \
    && [ ! -s "$SMOKE_WORK_DIR/records/control-before-bootstrap.jsonl" ]; then
  record PASS signature-input "new MinIO control bucket is empty before authority bootstrap"
else
  fail_stage "fresh MinIO control bucket was not empty"
fi

cli_environment() {
  cat <<EOF
ARCHIVIST_INGEST_ENDPOINT_URL=http://127.0.0.1:$SMOKE_PORT_R1
ARCHIVIST_STORAGE_ENDPOINT_URL=$SMOKE_ENDPOINT
ARCHIVIST_STORAGE_TLS=disabled
ARCHIVIST_STORAGE_REGION=us-east-1
ARCHIVIST_STORAGE_PATH_STYLE=path
ARCHIVIST_STORAGE_ENCRYPTION=client_envelope
ARCHIVIST_STORAGE_RAW_BUCKET=$RAW_BUCKET
ARCHIVIST_STORAGE_CONTROL_BUCKET=$CONTROL_BUCKET
ARCHIVIST_STORAGE_TENANT=$TENANT
ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF=file:$SMOKE_WORK_DIR/creds/raw-writer.env
ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF=file:$SMOKE_WORK_DIR/creds/control-reader.env
ARCHIVIST_SERVER_LISTEN_ADDRESS=127.0.0.1:$SMOKE_PORT_R1
ARCHIVIST_ADMIN_ENDPOINT_URL=$SMOKE_ENDPOINT
ARCHIVIST_ADMIN_TLS=disabled
ARCHIVIST_ADMIN_REGION=us-east-1
ARCHIVIST_ADMIN_PATH_STYLE=path
ARCHIVIST_ADMIN_CONTROL_BUCKET=$CONTROL_BUCKET
ARCHIVIST_ADMIN_TENANT=$TENANT
ARCHIVIST_ADMIN_CREDENTIALS_REF=file:$SMOKE_WORK_DIR/creds/control-admin.env
ARCHIVIST_ADMIN_AUTHORITY_SEED_REF=file:$SMOKE_WORK_DIR/admin/authority.seed
ARCHIVIST_ADMIN_RECEIPT_SIGNING_KEY_PATH=$SMOKE_WORK_DIR/admin/receipt.seed
ARCHIVIST_CLIENT_STATE_DIR=$SMOKE_WORK_DIR/client
ARCHIVIST_CLIENT_TENANT=$TENANT
ARCHIVIST_CLIENT_HARNESS=codex
EOF
}
cli_environment > "$SMOKE_WORK_DIR/records/bootstrap-cli.env"
chmod 600 "$SMOKE_WORK_DIR/records/bootstrap-cli.env"

run_archivist() { # output-file ; CLI args follow
  local output="$1"
  shift
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$SMOKE_WORK_DIR,dst=$SMOKE_WORK_DIR" \
    --env-file "$SMOKE_WORK_DIR/records/bootstrap-cli.env" \
    "$SMOKE_IMAGE" --non-interactive --json "$@" \
    > "$output" 2> "$output.stderr" \
    || fail_stage "released CLI bootstrap command failed (diagnostics withheld)"
}

extract_cli_result() { # output-file result-file
  python3 - "$1" "$2" <<'PY'
import json, pathlib, sys
output = json.loads(pathlib.Path(sys.argv[1]).read_text())
result = output.get("result")
if not isinstance(result, dict):
    raise SystemExit("CLI result is not a document")
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
)
PY
}

run_archivist "$SMOKE_WORK_DIR/records/create-authority.json" \
  admin create-authority "$SMOKE_WORK_DIR/admin/authority.seed"
extract_cli_result "$SMOKE_WORK_DIR/records/create-authority.json" \
  "$SMOKE_WORK_DIR/records/authority-result.json"
AUTHORITY_KEY="$(python3 - "$SMOKE_WORK_DIR/records/authority-result.json" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["authority_key"])
PY
)"
printf '%s\n' "$AUTHORITY_KEY" >> "$SMOKE_WORK_DIR/deny.txt"
docker run --rm --entrypoint /bin/sh "$SMOKE_IMAGE" -c \
  "out=\$(grep -rslF -e '$AUTHORITY_KEY' /etc /tmp /usr/local/bin 2>/dev/null); [ -z \"\$out\" ]" \
  && record PASS secret "generated authority public key is absent from the image filesystem and binary" \
  || record FAIL secret "generated authority public key appeared in the image"

run_archivist "$SMOKE_WORK_DIR/records/link-request.json" link request
extract_cli_result "$SMOKE_WORK_DIR/records/link-request.json" \
  "$SMOKE_WORK_DIR/records/link-draft.json"
run_archivist "$SMOKE_WORK_DIR/records/approve.json" \
  admin approve "$SMOKE_WORK_DIR/records/link-draft.json"
run_archivist "$SMOKE_WORK_DIR/records/receipt-key.json" admin receipt-key
extract_cli_result "$SMOKE_WORK_DIR/records/receipt-key.json" \
  "$SMOKE_WORK_DIR/records/receipt-key-result.json"
RECEIPT_KEY_ID="$(python3 - "$SMOKE_WORK_DIR/records/receipt-key-result.json" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["record"]["key_id"])
PY
)"
python3 - "$SMOKE_WORK_DIR/admin/authority.seed" \
  "$SMOKE_WORK_DIR/admin/receipt.seed" \
  "$SMOKE_WORK_DIR/client/identity.json" <<'PY'
import pathlib, stat, sys
for path in map(pathlib.Path, sys.argv[1:]):
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SystemExit("bootstrap private file mode is not 0600")
    if stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise SystemExit("bootstrap private directory mode is not 0700")
PY
echo "[smoke] released CLI created the tenant root, linked one client, and published a receipt key"

# 5. Replica configuration. Credential documents, authority seed, and receipt
# signing seed stay in the mode-restricted work directory and are referenced
# by path; their contents never enter command arguments.
replica_env_file() { # port ; plain KEY=VALUE lines (no multi-line values)
  cat <<EOF
ARCHIVIST_SERVER_LISTEN_ADDRESS=0.0.0.0:$1
ARCHIVIST_INGEST_ENDPOINT_URL=http://127.0.0.1:$1
ARCHIVIST_SERVER_AUTHORITY_KEY=$AUTHORITY_KEY
ARCHIVIST_SERVER_RECEIPT_CERTIFICATE_PATH=$SMOKE_WORK_DIR/admin/receipt.seed.certificate.json
ARCHIVIST_SERVER_RECEIPT_SIGNING_KEY_REF=file:$SMOKE_WORK_DIR/admin/receipt.seed
ARCHIVIST_STORAGE_ENDPOINT_URL=$SMOKE_ENDPOINT
ARCHIVIST_STORAGE_REGION=us-east-1
ARCHIVIST_STORAGE_PATH_STYLE=path
ARCHIVIST_STORAGE_ENCRYPTION=client_envelope
ARCHIVIST_STORAGE_RAW_BUCKET=$RAW_BUCKET
ARCHIVIST_STORAGE_CONTROL_BUCKET=$CONTROL_BUCKET
ARCHIVIST_STORAGE_TENANT=$TENANT
ARCHIVIST_STORAGE_TLS=disabled
ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF=file:$SMOKE_WORK_DIR/creds/raw-writer.env
ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF=file:$SMOKE_WORK_DIR/creds/control-reader.env
EOF
}

start_replica() { # name port
  local name="$1" port="$2"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" \
    --network host \
    --cpus "$SMOKE_REPLICA_CPUS" --memory "$SMOKE_REPLICA_MEMORY" \
    --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$SMOKE_WORK_DIR,dst=$SMOKE_WORK_DIR,readonly" \
    --env-file <(replica_env_file "$port") \
    "$SMOKE_IMAGE" serve >/dev/null
}

# One replica first: health before scale.
start_replica aa-smoke-r1 "$SMOKE_PORT_R1"

echo "=== smoke: health (liveness, HEALTHCHECK, fail-closed readiness)"
if await_url "http://127.0.0.1:$SMOKE_PORT_R1/health/live" 200; then
  if [ "$(curl -s --max-time 5 "http://127.0.0.1:$SMOKE_PORT_R1/health/live")" = '{"live":true}' ]; then
    record PASS health "/health/live answers 200 {\"live\":true} from the replica"
  else
    record FAIL health "/health/live answered 200 with an unexpected body"
  fi
else
  record FAIL health "/health/live did not answer 200"
fi
HEALTH_OK=0
for _ in $(seq 1 30); do
  [ "$(docker_health aa-smoke-r1)" = "healthy" ] && { HEALTH_OK=1; break; }
  sleep 3
done
if [ "$HEALTH_OK" -eq 1 ]; then
  record PASS health "the image HEALTHCHECK reaches healthy"
else
  record FAIL health "HEALTHCHECK never reached healthy"
fi
READY_STATUS="$(curl -s --max-time 5 -o "$SMOKE_WORK_DIR/records/ready-before-upload.json" -w '%{http_code}' \
  "http://127.0.0.1:$SMOKE_PORT_R1/health/ready")"
if [ "$READY_STATUS" = 503 ] \
    && grep -q 'trust_evidence_absent' "$SMOKE_WORK_DIR/records/ready-before-upload.json"; then
  record PASS health "readiness remains fail-closed before the first verified client read"
else
  record FAIL health "readiness before the first upload answered $READY_STATUS"
fi

echo "=== smoke: signature-input (zero-state bootstrap and first receipt)"
python3 "$DRIVER" mint-linked --out "$SMOKE_WORK_DIR/attempts" \
  --tenant "$TENANT" \
  --link-request "$SMOKE_WORK_DIR/records/link-draft.json" \
  --identity-file "$SMOKE_WORK_DIR/client/identity.json" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
CLIENT_KEY_ID="$(python3 - "$SMOKE_WORK_DIR/records/link-draft.json" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["key_id"])
PY
)"
post_attempt() { # port body-file content-type-file attempt-json-file outfile -> http status
  curl -s --max-time 30 -o "$5" -w '%{http_code}' \
    -H "Content-Type: $(cat "$3")" \
    -H "x-archivist-attempt: $(cat "$4")" \
    --data-binary "@$2" \
    "http://127.0.0.1:$1/v1/ingest"
}
raw_listing() { mc --quiet ls --recursive --json "local/$RAW_BUCKET" 2>/dev/null || true; }
raw_key_count() { raw_listing | grep -c '"key"' || true; }

# The first upload uses the newly linked key. Its receipt is verified by
# the independent RFC 8032 implementation; only then is readiness expected.
FRESH_STATUS="$(post_attempt "$SMOKE_PORT_R1" \
  "$SMOKE_WORK_DIR/attempts/request.body" \
  "$SMOKE_WORK_DIR/attempts/content-type.txt" \
  "$SMOKE_WORK_DIR/attempts/attempt.json" \
  "$SMOKE_WORK_DIR/records/first-receipt.json")"
if [ "$FRESH_STATUS" = 200 ] \
    && python3 "$DRIVER" verify-receipt \
      --receipt "$SMOKE_WORK_DIR/records/first-receipt.json" \
      --authority-key "$AUTHORITY_KEY" \
      --key-id "$RECEIPT_KEY_ID" \
      --tenant "$TENANT" \
      --authorization-key-id "$CLIENT_KEY_ID" >/dev/null; then
  record PASS signature-input "fresh linked-client upload returned a valid receipt and authority-certified key"
else
  record FAIL signature-input "first upload did not return a valid authority-certified receipt (status=$FRESH_STATUS)"
fi

raw_listing > "$SMOKE_WORK_DIR/records/raw-after-fresh.jsonl"
KEYS_MATCH="$(python3 - "$SMOKE_WORK_DIR" <<'PY'
import json, pathlib, sys
work = pathlib.Path(sys.argv[1])
expected = sorted(json.load(open(work / "attempts" / "object-keys.json")))
listed = sorted(
    json.loads(line)["key"].split("/", 1)[1]
    for line in (work / "records" / "raw-after-fresh.jsonl").read_text().splitlines()
    if line.strip()
)
print("1" if listed == expected else "0")
PY
)"
if [ "$KEYS_MATCH" = 1 ] && [ "$(raw_key_count)" -eq 3 ]; then
  record PASS signature-input "the first receipt binds the three expected objects committed to MinIO"
else
  record FAIL signature-input "first upload object set differs from the derived keys"
fi
READY_STATUS="$(curl -s --max-time 5 -o "$SMOKE_WORK_DIR/records/ready-after-upload.json" -w '%{http_code}' \
  "http://127.0.0.1:$SMOKE_PORT_R1/health/ready")"
if [ "$READY_STATUS" = 200 ] \
    && grep -q '"ready":true' "$SMOKE_WORK_DIR/records/ready-after-upload.json"; then
  record PASS health "readiness reached 200 after the first verified upload and receipt"
else
  record FAIL health "readiness after the first upload answered $READY_STATUS"
fi

# Rejections after the first success must not change the stored object set.
STALE_STATUS="$(post_attempt "$SMOKE_PORT_R1" \
  "$SMOKE_WORK_DIR/attempts/stale/request.body" \
  "$SMOKE_WORK_DIR/attempts/stale/content-type.txt" \
  "$SMOKE_WORK_DIR/attempts/stale/attempt.json" \
  "$SMOKE_WORK_DIR/records/stale-response.json")"
ALTERED="$SMOKE_WORK_DIR/attempts/altered.body"
cp "$SMOKE_WORK_DIR/attempts/request.body" "$ALTERED"
FLIP_AT="$(python3 - "$ALTERED" "$SMOKE_WORK_DIR/attempts/content-type.txt" <<'PY'
import sys
body = open(sys.argv[1], "rb").read()
content_type = open(sys.argv[2]).read()
boundary = ("--" + content_type.split("boundary=")[1].strip()).encode()
part_two = body.find(boundary, body.find(boundary) + 1)
closing = body.find(boundary, part_two + 1)
print((part_two + closing) // 2)
PY
)"
printf 'X' | dd of="$ALTERED" bs=1 seek="$FLIP_AT" conv=notrunc status=none
ALTERED_STATUS="$(post_attempt "$SMOKE_PORT_R1" "$ALTERED" \
  "$SMOKE_WORK_DIR/attempts/content-type.txt" \
  "$SMOKE_WORK_DIR/attempts/attempt.json" \
  "$SMOKE_WORK_DIR/records/altered-response.json")"
REJECT_OK=1
grep -q '"code":"auth.authorization_rejected"' \
  "$SMOKE_WORK_DIR/records/stale-response.json" || REJECT_OK=0
grep -q '"code":"auth.authorization_rejected"' \
  "$SMOKE_WORK_DIR/records/altered-response.json" || REJECT_OK=0
[ "$(raw_key_count)" -eq 3 ] || REJECT_OK=0
if [ "$REJECT_OK" -eq 1 ]; then
  record PASS signature-input "stale and altered attempts were refused without changing the first upload's three raw objects"
else
  record FAIL signature-input "stale or altered proof changed durable storage (stale=$STALE_STATUS altered=$ALTERED_STATUS)"
fi

echo "=== smoke: multi-replica (two replicas inside the 4 vCPU / 512 MiB envelope)"
start_replica aa-smoke-r2 "$SMOKE_PORT_R2"
if await_url "http://127.0.0.1:${SMOKE_PORT_R2}/health/live" 200; then
  record PASS multi-replica "second replica live alongside the first (--cpus $SMOKE_REPLICA_CPUS --memory $SMOKE_REPLICA_MEMORY each)"
else
  record FAIL multi-replica "second replica never went live; logs follow"
  docker logs --tail 30 aa-smoke-r2 > "$SMOKE_WORK_DIR/records/aa-smoke-r2.log" 2>&1 || true
fi
# Retry the exact accepted upload through the second replica. It must
# converge on the same durable objects and independently return a valid receipt.
R2_STATUS="$(post_attempt "$SMOKE_PORT_R2" \
  "$SMOKE_WORK_DIR/attempts/request.body" \
  "$SMOKE_WORK_DIR/attempts/content-type.txt" \
  "$SMOKE_WORK_DIR/attempts/attempt.json" \
  "$SMOKE_WORK_DIR/records/fresh-r2-response.json")"
if [ "$R2_STATUS" = 200 ] \
    && python3 "$DRIVER" verify-receipt \
      --receipt "$SMOKE_WORK_DIR/records/fresh-r2-response.json" \
      --authority-key "$AUTHORITY_KEY" \
      --key-id "$RECEIPT_KEY_ID" \
      --tenant "$TENANT" \
      --authorization-key-id "$CLIENT_KEY_ID" >/dev/null; then
  record PASS multi-replica "second replica returned a valid receipt for the identical accepted upload"
else
  record FAIL multi-replica "second replica did not return a valid receipt (status=$R2_STATUS)"
fi
# Concurrent retry: four identical attempts at once across both replicas —
# the plan's concurrent-retry test — converge on one answer, and nothing
# partial stands afterward.
RETRY_PIDS=()
for i in 1 2 3 4; do
  port="$SMOKE_PORT_R1"; [ $((i % 2)) -eq 0 ] && port="$SMOKE_PORT_R2"
  post_attempt "$port" "$SMOKE_WORK_DIR/attempts/request.body" \
    "$SMOKE_WORK_DIR/attempts/content-type.txt" \
    "$SMOKE_WORK_DIR/attempts/attempt.json" \
    "$SMOKE_WORK_DIR/records/retry-$i.json" &
  RETRY_PIDS+=("$!")
done
# Wait only on the four probes. A bare `wait` would also hold for the
# MinIO backend — a background child of this shell since the live stage —
# and the run would never reach its summary.
wait "${RETRY_PIDS[@]}"
RETRY_OK=1
for i in 1 2 3 4; do
  python3 "$DRIVER" verify-receipt \
    --receipt "$SMOKE_WORK_DIR/records/retry-$i.json" \
    --authority-key "$AUTHORITY_KEY" \
    --key-id "$RECEIPT_KEY_ID" \
    --tenant "$TENANT" \
    --authorization-key-id "$CLIENT_KEY_ID" >/dev/null || RETRY_OK=0
done
FINAL_KEYS="$(raw_key_count)"
if [ "$RETRY_OK" -eq 1 ] && [ "$FINAL_KEYS" -eq 3 ]; then
  record PASS multi-replica "4 concurrent identical retries returned verified receipts; MinIO retains exactly 3 raw objects"
else
  record FAIL multi-replica "concurrent retries misbehaved (all-verified=$RETRY_OK keys=$FINAL_KEYS wanted=3)"
fi
CAPS_OK=1
for name in aa-smoke-r1 aa-smoke-r2; do
  # The second replica booted moments ago; its docker HEALTHCHECK probes
  # on a 30s interval behind a 15s start period. Give each replica the
  # same bounded window the health stage gives the first before judging
  # it left the envelope.
  HEALTHY=0
  for _ in $(seq 1 30); do
    [ "$(docker_health "$name")" = "healthy" ] && { HEALTHY=1; break; }
    sleep 3
  done
  [ "$HEALTHY" -eq 1 ] || { CAPS_OK=0; echo "[smoke] $name never reached healthy ($(docker_health "$name"))" >&2; }
  state="$(docker inspect --format '{{.State.OOMKilled}} {{.RestartCount}}' "$name" 2>/dev/null || echo missing)"
  [ "$state" = "false 0" ] || { CAPS_OK=0; echo "[smoke] $name state: $state" >&2; }
done
if [ "$CAPS_OK" -eq 1 ]; then
  record PASS multi-replica "both replicas healthy, never OOM-killed, zero restarts inside the reference envelope"
else
  record FAIL multi-replica "a replica left the reference envelope (state lines above)"
fi

for name in aa-smoke-r1 aa-smoke-r2; do
  docker logs "$name" > "$SMOKE_WORK_DIR/records/$name.log" 2>&1 \
    || fail_stage "could not capture replica diagnostics for the secret-hygiene scan"
done

# --- the second secret scan -------------------------------------------------

echo "=== smoke: secret (second scan, against the run's own minted credentials)"
docker save "$SMOKE_IMAGE" | tar -x -C "$SMOKE_WORK_DIR/layers"
run_scan "$SMOKE_WORK_DIR/layers" "$SMOKE_WORK_DIR/deny.txt" "$SMOKE_WORK_DIR/base-files.txt"
if [ "$SCAN_STATUS" -eq 0 ]; then
  record PASS secret "second layer scan clean against this run's own credential values"
else
  record FAIL secret "second layer scan matched this run's credential values or an unexpected file"
fi

if python3 - "$SMOKE_WORK_DIR" <<'PY'
import json, pathlib, sys
work = pathlib.Path(sys.argv[1])
private_values = [
    (work / "admin" / "authority.seed").read_text().strip(),
    (work / "admin" / "receipt.seed").read_text().strip(),
    json.loads((work / "client" / "identity.json").read_text())["private_seed"],
]
if any(len(value) != 64 for value in private_values):
    raise SystemExit("unexpected bootstrap signing-seed encoding")
logs = list((work / "records").rglob("*"))
logs += [work / "minio.log"]
for path in logs:
    if path.is_file():
        contents = path.read_bytes()
        if any(value.encode("ascii") in contents for value in private_values):
            raise SystemExit("bootstrap private material appeared in runtime diagnostics")
PY
then
  record PASS secret "tenant authority, receipt, and client signing seeds are absent from command and server logs"
else
  record FAIL secret "bootstrap private material appeared in a captured command or server log"
fi

# --- summary ----------------------------------------------------------------

echo "=== smoke: summary"
for line in "${SUMMARY[@]}"; do echo "  $line"; done
echo "[smoke] $PASS passed, $FAIL failed, $GAP gap(s); only the vulnerability scanner may be recorded as a gap"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
