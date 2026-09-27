#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# The release-image smoke harness: build the release image from a clean
# git-archive extraction on a BuildKit host and exercise the five smoke
# categories the packaging acceptance names (plan Section 13; parent bead
# aa-580ffbb2) — health, secret, vulnerability, signature-input, and
# multi-replica — against that one image.
#
# The contract this harness verifies is docs/notes/release-container.md; the
# category definitions, instruments, failure modes, and the three documented
# gaps (the receipt signing-schedule composition, the readiness evidence
# wiring, and the storage transport key — none landed on the composition
# yet) are owned by docs/notes/image-smoke.md. Read that note before
# changing a category's assertions.
#
# Invocation — the harness runs ON the BuildKit host, from the extraction,
# never from a working tree (codinghome has no docker daemon; the precedent
# is release-container.md Section 6):
#
#   D=$(mktemp -d) && git archive HEAD | tar -x -C "$D"
#   ssh builder "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD) \
#     bash $D/containers/agent-archivist/smoke.sh"
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
# 0 = assert today's documented fail-closed composition answers; 1 = assert
# the post-landing answers. See image-smoke.md "What is deliberately not yet
# true" before flipping any of the three.
SMOKE_EXPECT_READY="${SMOKE_EXPECT_READY:-0}"
SMOKE_EXPECT_RECEIPT="${SMOKE_EXPECT_RECEIPT:-0}"
SMOKE_EXPECT_TRANSPORT="${SMOKE_EXPECT_TRANSPORT:-0}"
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

# The smoke's own S3 namespace, provisioned by the committed reference tool.
TENANT="3e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30"   # the control corpus tenant
RAW_BUCKET="aa-smoke-raw"
CONTROL_BUCKET="aa-smoke-control"
# The pinned control-corpus authority public half (schemas/v1/examples/
# control/keys.json) — the trust anchor the replica pins and a deny-scan
# token, since tenant trust material has no business inside an image.
AUTHORITY_KEY="f97cf56e5cfdeed89c2d9243c57873437300700ab7e9d0c9bc6119676b29e9ba"

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
mkdir -p "$SMOKE_WORK_DIR"/{bin,minio-data,creds,layers,layers-base,attempts,control,records}
chmod 700 "$SMOKE_WORK_DIR"

# --- stage: build -----------------------------------------------------------

if [ "$SMOKE_SKIP_BUILD" != 1 ]; then
  echo "=== smoke: build (the canonical invocation's shape, RC-019)"
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
printf '%s\n%s\n' "$TENANT" "$AUTHORITY_KEY" > "$SMOKE_WORK_DIR/deny.txt"
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
  "out=\$(grep -rslF -e 'ACCESS_KEY=' -e 'SECRET_KEY=' -e 'PRIVATE KEY' -e '$TENANT' -e '$AUTHORITY_KEY' /etc /tmp 2>/dev/null); [ -z \"\$out\" ]" \
  && record PASS secret "no credential shape or tenant material in /etc or /tmp" \
  || record FAIL secret "credential shape or tenant material in /etc or /tmp"
docker run --rm --entrypoint /bin/sh "$SMOKE_IMAGE" -c \
  "out=\$(grep -rslF -e '$TENANT' -e '$AUTHORITY_KEY' /usr/local/bin 2>/dev/null); [ -z \"\$out\" ]" \
  && record PASS secret "no tenant or authority material in the installed binary" \
  || record FAIL secret "tenant or authority material in the installed binary"

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
  nohup "$SMOKE_WORK_DIR/bin/minio" server "$SMOKE_WORK_DIR/minio-data" \
    --address "127.0.0.1:${SMOKE_PORT_MINIO}" \
    --console-address "127.0.0.1:$((SMOKE_PORT_MINIO + 1))" \
    >"$SMOKE_WORK_DIR/minio.log" 2>&1 &
  MINIO_PID=$!
  echo "$MINIO_PID" > "$SMOKE_WORK_DIR/minio.pid"
fi
for _ in $(seq 1 30); do minio_ready && break; sleep 1; done
minio_ready || fail_stage "MinIO reference backend not ready (see $SMOKE_WORK_DIR/minio.log)"
mc --quiet alias set local "$MINIO_ENDPOINT" minioadmin minioadmin >/dev/null
echo "[smoke] MinIO reference backend ready on $MINIO_ENDPOINT (pid $MINIO_PID)"

# The endpoint handed to the replicas. Today's registry grammar is TLS-only
# by construction (the storage config carries no key that disables TLS,
# SEC-001), so the scheme claim is https:// — config-honest, and never
# conversed with by the categories that only prove a replica's own signals.
# When the transport key lands (image-smoke.md Section 7, gap three) and
# SMOKE_EXPECT_TRANSPORT=1, the claim and the plaintext backend agree.
if [ "$SMOKE_EXPECT_TRANSPORT" = 1 ]; then
  SMOKE_ENDPOINT="$MINIO_ENDPOINT"
else
  SMOKE_ENDPOINT="https://127.0.0.1:${SMOKE_PORT_MINIO}"
fi

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

# 4. The linked-client pointers, at their pinned object keys.
python3 "$DRIVER" control-objects --out "$SMOKE_WORK_DIR/control" >/dev/null
find "$SMOKE_WORK_DIR/control" -type f -name '*.json' | while read -r object; do
  rel="${object#"$SMOKE_WORK_DIR/control/"}"
  mc --quiet cp "$object" "local/$CONTROL_BUCKET/$rel" >/dev/null
done
echo "[smoke] linked-client pointers placed under the control prefix"

# 5. Replica configuration: every non-secret key through the environment
# tier; the two identities through env references, so no credential value
# ever sits in a file the image or a bind mount could carry.
RAW_DOC="$(printf 'ACCESS_KEY=%s\nSECRET_KEY=%s' \
  "$(sed -n 's/^ACCESS_KEY=//p' "$SMOKE_WORK_DIR/creds/raw-writer.env")" \
  "$(sed -n 's/^SECRET_KEY=//p' "$SMOKE_WORK_DIR/creds/raw-writer.env")")"
CTRL_DOC="$(printf 'ACCESS_KEY=%s\nSECRET_KEY=%s' \
  "$(sed -n 's/^ACCESS_KEY=//p' "$SMOKE_WORK_DIR/creds/control-reader.env")" \
  "$(sed -n 's/^SECRET_KEY=//p' "$SMOKE_WORK_DIR/creds/control-reader.env")")"

# Every non-secret configuration key through the environment tier. The
# composition-required client ingest endpoint (ingest.endpoint_url) is
# included even though serve itself never dials it: the configuration
# registry marks it required, so the replica's load refuses to resolve
# without it — the operator command's readiness probe is what targets the
# URL, and the replica's own serve address is the truthful value.
replica_env_file() { # port ; plain KEY=VALUE lines (no multi-line values)
  cat <<EOF
ARCHIVIST_SERVER_LISTEN_ADDRESS=0.0.0.0:$1
ARCHIVIST_INGEST_ENDPOINT_URL=http://127.0.0.1:$1
ARCHIVIST_SERVER_AUTHORITY_KEY=$AUTHORITY_KEY
ARCHIVIST_STORAGE_ENDPOINT_URL=$SMOKE_ENDPOINT
ARCHIVIST_STORAGE_REGION=us-east-1
ARCHIVIST_STORAGE_PATH_STYLE=path
ARCHIVIST_STORAGE_ENCRYPTION=client_envelope
ARCHIVIST_STORAGE_RAW_BUCKET=$RAW_BUCKET
ARCHIVIST_STORAGE_CONTROL_BUCKET=$CONTROL_BUCKET
ARCHIVIST_STORAGE_TENANT=$TENANT
ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF=env:SMOKE_RAW_WRITER
ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF=env:SMOKE_CONTROL_READER
EOF
}

start_replica() { # name port
  local name="$1" port="$2"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" \
    --network host \
    --cpus "$SMOKE_REPLICA_CPUS" --memory "$SMOKE_REPLICA_MEMORY" \
    --env-file <(replica_env_file "$port") \
    -e SMOKE_RAW_WRITER="$RAW_DOC" \
    -e SMOKE_CONTROL_READER="$CTRL_DOC" \
    "$SMOKE_IMAGE" serve >/dev/null
}

# One replica first: health before scale.
start_replica aa-smoke-r1 "$SMOKE_PORT_R1"

echo "=== smoke: health (liveness, HEALTHCHECK, fail-closed readiness)"
if await_url "http://127.0.0.1:${SMOKE_PORT_R1}/health/live" 200; then
  if [ "$(curl -s --max-time 5 "http://127.0.0.1:${SMOKE_PORT_R1}/health/live")" = '{"live":true}' ]; then
    record PASS health "/health/live answers 200 {\"live\":true} from the replica"
  else
    record FAIL health "/health/live answered 200 with an unexpected body"
  fi
else
  record FAIL health "/health/live did not answer 200; replica logs follow"
  docker logs --tail 30 aa-smoke-r1 >&2 || true
fi
HEALTH_OK=0
for _ in $(seq 1 30); do
  [ "$(docker_health aa-smoke-r1)" = "healthy" ] && { HEALTH_OK=1; break; }
  sleep 3
done
if [ "$HEALTH_OK" -eq 1 ]; then
  record PASS health "the image HEALTHCHECK reaches 'healthy' (the binary probing its own liveness route, RC-020)"
else
  record FAIL health "HEALTHCHECK never reached 'healthy' (status: $(docker_health aa-smoke-r1))"
fi
READY_STATUS="$(curl -s --max-time 5 -o "$SMOKE_WORK_DIR/records/ready1.json" -w '%{http_code}' \
  "http://127.0.0.1:${SMOKE_PORT_R1}/health/ready")"
if [ "$SMOKE_EXPECT_READY" = 1 ]; then
  if [ "$READY_STATUS" = 200 ]; then
    record PASS health "readiness reached 200 (the evidence wiring has landed)"
  else
    record FAIL health "readiness answered $READY_STATUS; SMOKE_EXPECT_READY=1 wanted 200"
  fi
else
  if [ "$READY_STATUS" = 503 ] \
      && grep -q 'trust_evidence_absent' "$SMOKE_WORK_DIR/records/ready1.json"; then
    record PASS health "readiness is fail-closed before any verified control read (503 trust_evidence_absent; the ready-200 flip is the documented gap in image-smoke.md Section 7)"
  else
    record FAIL health "readiness answered $READY_STATUS; wanted the documented 503 trust_evidence_absent"
  fi
fi

echo "=== smoke: signature-input (signed submission round trip over the wire)"
python3 "$DRIVER" mint --out "$SMOKE_WORK_DIR/attempts" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
post_attempt() { # port body-file content-type-file attempt-json-file outfile -> http status
  curl -s --max-time 30 -o "$5" -w '%{http_code}' \
    -H "Content-Type: $(cat "$3")" \
    -H "x-archivist-attempt: $(cat "$4")" \
    --data-binary "@$2" \
    "http://127.0.0.1:${1}/v1/ingest"
}
raw_listing() { mc --quiet ls --recursive --json "local/$RAW_BUCKET" 2>/dev/null || true; }
raw_key_count() { raw_listing | grep -c '"key"' || true; }

# The fail-closed lane (the live half of the acceptance property: altered,
# replay-expired, and unauthorized requests make no storage writes). The two
# probes answer in different places, and both places are asserted: the
# stale-signed proof dies at the replica's freshness gate — the one
# authorization decision that needs no control evidence — and answers the
# one closed wire class; the altered body carries a proof whose digests no
# longer describe it, but the replica verifies nothing it cannot check
# against readable control evidence, so today it stops at the registry
# boundary instead — and writes nothing either way.
STALE_STATUS="$(post_attempt "$SMOKE_PORT_R1" \
  "$SMOKE_WORK_DIR/attempts/stale/request.body" \
  "$SMOKE_WORK_DIR/attempts/stale/content-type.txt" \
  "$SMOKE_WORK_DIR/attempts/stale/attempt.json" \
  "$SMOKE_WORK_DIR/records/stale-response.json")"
ALTERED="$SMOKE_WORK_DIR/attempts/altered.body"
cp "$SMOKE_WORK_DIR/attempts/request.body" "$ALTERED"
# The flip lands inside part two — the payload bytes — by construction:
# the midpoint between the payload part's boundary line and the closing
# boundary. A flip in part one would corrupt the envelope's schema and
# answer the parse gate (envelope.schema_invalid) before authorization
# is even reached; a payload flip survives parsing, and the digest
# agreement it breaks is checked only after the evidence gate — 503
# server.unavailable today, the rejection class once the transport key
# makes digest verification reachable.
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
if [ "$SMOKE_EXPECT_TRANSPORT" = 1 ]; then
  grep -q '"code":"auth.authorization_rejected"' \
    "$SMOKE_WORK_DIR/records/altered-response.json" || REJECT_OK=0
else
  grep -q '"code":"server.unavailable"' \
    "$SMOKE_WORK_DIR/records/altered-response.json" || REJECT_OK=0
fi
[ "$(raw_key_count)" -eq 0 ] || REJECT_OK=0
if [ "$REJECT_OK" -eq 1 ]; then
  record PASS signature-input "stale-signed attempt answers the closed class auth.authorization_rejected (the freshness gate, live) and the altered attempt is refused with nothing durable standing; the raw bucket holds zero objects"
else
  record FAIL signature-input "fail-closed lane broken (stale=$STALE_STATUS altered=$ALTERED_STATUS raw keys after rejects=$(raw_key_count))"
  cat "$SMOKE_WORK_DIR/records/stale-response.json" \
    "$SMOKE_WORK_DIR/records/altered-response.json" >&2 || true
fi

# The admitted lane: the fresh attempt presents a proof that survives every
# check the replica can apply without readable control evidence (header
# parse, content-type coverage, freshness). Where it stops is the transport
# gap's position (image-smoke.md Section 7): today the control plane is
# unreachable over the registry's TLS-only grammar, so the replica answers
# the fail-closed registry class with nothing durable standing, and
# SMOKE_EXPECT_TRANSPORT=1 — after the transport key lands — asserts the
# round trip instead: the commit answers the composition result and the
# three derived object keys stand (the receipt knob on top asserts the
# signed receipt).
FRESH_STATUS="$(post_attempt "$SMOKE_PORT_R1" \
  "$SMOKE_WORK_DIR/attempts/request.body" \
  "$SMOKE_WORK_DIR/attempts/content-type.txt" \
  "$SMOKE_WORK_DIR/attempts/attempt.json" \
  "$SMOKE_WORK_DIR/records/fresh-response.json")"
ADMIT_CLASS="$(response_class "$SMOKE_WORK_DIR/records/fresh-response.json")"
if [ "$SMOKE_EXPECT_TRANSPORT" = 1 ]; then
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
print("1" if listed == expected else f"0 listed={listed[:6]}")
PY
)"
  if grep -q '"code":"server.partial_commit"' \
        "$SMOKE_WORK_DIR/records/fresh-response.json" \
        && [ "$KEYS_MATCH" = 1 ]; then
    if [ "$SMOKE_EXPECT_RECEIPT" = 1 ]; then
      record FAIL signature-input "fresh attempt answered partial_commit; SMOKE_EXPECT_RECEIPT=1 wanted a signed receipt (the signing-schedule composition has not landed)"
    else
      record PASS signature-input "fresh signed attempt authorized and committed; its 3 objects stand at the derived raw keys (the schedule-less replica answers the documented partial_commit, image-smoke.md Section 7)"
    fi
  else
    record FAIL signature-input "fresh attempt did not commit cleanly (status=$FRESH_STATUS class=${ADMIT_CLASS:-none} keys-match=$KEYS_MATCH)"
    cat "$SMOKE_WORK_DIR/records/fresh-response.json" >&2 || true
  fi
else
  if [ "$ADMIT_CLASS" = "server.unavailable" ] \
      && [ "$(raw_key_count)" -eq 0 ]; then
    record PASS signature-input "fresh attempt answers the fail-closed registry boundary (503 server.unavailable) with nothing durable standing — its proof is behind every check the replica can apply without readable control evidence (the transport gap, image-smoke.md Section 7)"
  else
    record FAIL signature-input "fresh attempt neither stopped at the registry boundary nor committed (status=$FRESH_STATUS class=${ADMIT_CLASS:-none} keys=$(raw_key_count))"
    cat "$SMOKE_WORK_DIR/records/fresh-response.json" >&2 || true
  fi
fi

echo "=== smoke: multi-replica (two replicas inside the 4 vCPU / 512 MiB envelope)"
start_replica aa-smoke-r2 "$SMOKE_PORT_R2"
if await_url "http://127.0.0.1:${SMOKE_PORT_R2}/health/live" 200; then
  record PASS multi-replica "second replica live alongside the first (--cpus $SMOKE_REPLICA_CPUS --memory $SMOKE_REPLICA_MEMORY each)"
else
  record FAIL multi-replica "second replica never went live; logs follow"
  docker logs --tail 30 aa-smoke-r2 >&2 || true
fi
# Identical request across replicas, no sticky routing: the same signed
# bytes against the other replica. With the transport gap, equivalence means
# the same authorized-then-failed-closed answer; post-landing it means the
# same commit result converging on the standing objects.
R2_STATUS="$(post_attempt "$SMOKE_PORT_R2" \
  "$SMOKE_WORK_DIR/attempts/request.body" \
  "$SMOKE_WORK_DIR/attempts/content-type.txt" \
  "$SMOKE_WORK_DIR/attempts/attempt.json" \
  "$SMOKE_WORK_DIR/records/fresh-r2-response.json")"
R2_CLASS="$(response_class "$SMOKE_WORK_DIR/records/fresh-r2-response.json")"
if [ "$SMOKE_EXPECT_TRANSPORT" = 1 ]; then
  if grep -q '"code":"server.partial_commit"' \
      "$SMOKE_WORK_DIR/records/fresh-r2-response.json"; then
    record PASS multi-replica "identical signed attempt served by the second replica converges on the standing objects"
  else
    record FAIL multi-replica "second replica did not serve the identical attempt (status=$R2_STATUS class=${R2_CLASS:-none})"
    cat "$SMOKE_WORK_DIR/records/fresh-r2-response.json" >&2 || true
  fi
else
  if [ -n "$R2_CLASS" ] && [ "$R2_CLASS" = "$ADMIT_CLASS" ]; then
    record PASS multi-replica "identical signed attempt served by the second replica answers the same commit-path class (${R2_CLASS}) — replica equivalence at the fail-closed boundary"
  else
    record FAIL multi-replica "second replica answered differently from the first (r1=${ADMIT_CLASS:-none} r2=${R2_CLASS:-none})"
    cat "$SMOKE_WORK_DIR/records/fresh-r2-response.json" >&2 || true
  fi
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
  if [ "$SMOKE_EXPECT_TRANSPORT" = 1 ]; then
    grep -q '"code":"server.partial_commit"' "$SMOKE_WORK_DIR/records/retry-$i.json" \
      || RETRY_OK=0
  else
    [ "$(response_class "$SMOKE_WORK_DIR/records/retry-$i.json")" = "$ADMIT_CLASS" ] \
      || RETRY_OK=0
  fi
done
if [ "$SMOKE_EXPECT_TRANSPORT" = 1 ]; then
  EXPECTED_KEYS="$(python3 -c "import json;print(len(json.load(open('$SMOKE_WORK_DIR/attempts/object-keys.json'))))")"
else
  EXPECTED_KEYS=0
fi
FINAL_KEYS="$(raw_key_count)"
if [ "$RETRY_OK" -eq 1 ] && [ "$FINAL_KEYS" -eq "$EXPECTED_KEYS" ]; then
  record PASS multi-replica "4 concurrent identical retries across both replicas converge on one answer; the raw bucket holds exactly $EXPECTED_KEYS object keys"
else
  record FAIL multi-replica "concurrent retries misbehaved (all-answered=$RETRY_OK keys=$FINAL_KEYS wanted=$EXPECTED_KEYS)"
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

# --- the second secret scan -------------------------------------------------

echo "=== smoke: secret (second scan, against the run's own minted credentials)"
docker save "$SMOKE_IMAGE" | tar -x -C "$SMOKE_WORK_DIR/layers"
run_scan "$SMOKE_WORK_DIR/layers" "$SMOKE_WORK_DIR/deny.txt" "$SMOKE_WORK_DIR/base-files.txt"
if [ "$SCAN_STATUS" -eq 0 ]; then
  record PASS secret "second layer scan clean against this run's own credential values"
else
  record FAIL secret "second layer scan matched this run's credential values or an unexpected file"
fi

# --- summary ----------------------------------------------------------------

echo "=== smoke: summary"
for line in "${SUMMARY[@]}"; do echo "  $line"; done
echo "[smoke] $PASS passed, $FAIL failed, $GAP gap(s); a gap is a defined check this tree cannot yet satisfy (image-smoke.md Section 7)"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
