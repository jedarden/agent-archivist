#!/usr/bin/env bash
# Deterministic SBOM generator for the Agent Archivist release image.
#
# Emits the CycloneDX 1.5 JSON document committed at
# containers/agent-archivist/sbom.json: the subject is the release unit
# ("agent-archivist" at the VERSION content) and every Cargo.lock package is
# a component, each registry crate corroborated against its vendored source
# (vendor/<name>[-<version>]: the vendored manifest must name the same
# package and version, and .cargo-checksum.json's recorded crate checksum
# must equal Cargo.lock's). Rules RC-021 through RC-023 of
# docs/notes/release-container.md; the digest is recorded in the qualified
# commit's verification manifest (RC-024, RELEASE.md release step 1).
#
# Determinism contract (RC-022): the document is a pure function of
# Cargo.lock + vendor/ + VERSION. Output is canonical (key-sorted JSON,
# components ordered by name then version), carries no serial number or
# other random identifier, and takes no input from the wall clock —
# SOURCE_DATE_EPOCH is the only clock, rendered as the metadata timestamp.
# Two runs over one tree are byte-identical. Pure bash + python3 stdlib on
# a bare checkout: no network, no container runtime, no git.
#
# Usage:
#   SOURCE_DATE_EPOCH=<unix-seconds> \
#     containers/agent-archivist/generate-sbom.sh [--output FILE]
#   containers/agent-archivist/generate-sbom.sh --check
#   containers/agent-archivist/generate-sbom.sh --self-test
#
# --check regenerates using the timestamp embedded in the committed
# sbom.json and byte-compares: exit 0 means the committed copy is exactly
# the generator's output for this tree, exit 2 means it drifted (a tree
# change without regeneration, or a hand edit — RC-021 makes both
# violations). The fast lane runs --self-test
# (scripts/definition-of-done.sh, "release sbom"), whose step 3 is
# --check against the committed copy; tools/check-release-container.py
# validates the document's structure (presence, schema, subject version,
# lock coherence) on every commit beside it.
#
# --self-test proves the contract: two runs are byte-identical, the
# byte-compare detects a single-character mutation, and the committed copy
# passes --check. Output names paths, versions, and digests only.

set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

SBOM_FILE="containers/agent-archivist/sbom.json"

die() { printf 'generate-sbom: %s\n' "$1" >&2; exit 2; }

MODE="emit"
OUT=""
case "${1:-}" in
  "") ;;
  --output) OUT="${2:-}"; [ -n "$OUT" ] || die "--output needs a path" ;;
  --check) MODE="check" ;;
  --self-test) MODE="self-test" ;;
  *) die "unknown argument: ${1:-} (usage: generate-sbom.sh [--output FILE|--check|--self-test])" ;;
esac

require_epoch() {
  local epoch="${SOURCE_DATE_EPOCH:-}"
  [ -n "$epoch" ] || die "SOURCE_DATE_EPOCH must be set — it is the SBOM's only clock (RC-022)"
  [[ "$epoch" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be unix seconds, found '${epoch}'"
  export SOURCE_DATE_EPOCH
}

# generate DEST — render the document for $SOURCE_DATE_EPOCH to DEST
# ("-" for stdout). Fails closed on any input that is not exactly the
# committed tree's resolved dependency set.
generate() {
  local dest="$1"
  python3 - "$dest" "$SOURCE_DATE_EPOCH" <<'PYEOF'
import json
import re
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

dest, epoch_text = sys.argv[1], sys.argv[2]

def die(message: str) -> None:
    print(f"generate-sbom: {message}", file=sys.stderr)
    raise SystemExit(2)

if not re.fullmatch(r"[0-9]+", epoch_text):
    die(f"SOURCE_DATE_EPOCH must be unix seconds, found {epoch_text!r}")
timestamp = datetime.fromtimestamp(
    int(epoch_text), tz=timezone.utc
).strftime("%Y-%m-%dT%H:%M:%SZ")

SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
version_path = Path("containers/agent-archivist/VERSION")
raw_version = version_path.read_text(encoding="ascii")
if not SEMVER.fullmatch(raw_version[:-1]) or not raw_version.endswith("\n"):
    die(f"{version_path} is not one strict core SemVer line")
version = raw_version[:-1]

lock = tomllib.loads(Path("Cargo.lock").read_text(encoding="utf-8"))
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"

components = []
seen: set[tuple[str, str]] = set()
for pkg in lock.get("package", []):
    name, ver = pkg["name"], pkg["version"]
    if (name, ver) in seen:
        die(f"Cargo.lock lists {name}@{ver} twice")
    seen.add((name, ver))
    component = {
        "type": "library",
        "bom-ref": f"pkg:cargo/{name}@{ver}",
        "name": name,
        "version": ver,
        "purl": f"pkg:cargo/{name}@{ver}",
        "properties": [],
    }
    properties = component["properties"]
    source = pkg.get("source")
    if source is None:
        properties.append({"name": "archivist:source", "value": "workspace"})
    else:
        if source != REGISTRY:
            die(f"{name}@{ver} comes from {source}; the release build is "
                f"vendored crates.io only (RC-014)")
        checksum = pkg.get("checksum")
        if not checksum:
            die(f"{name}@{ver} has no Cargo.lock checksum to corroborate")
        vdir = Path("vendor") / f"{name}-{ver}"
        if not vdir.is_dir():
            vdir = Path("vendor") / name
        if not vdir.is_dir():
            die(f"{name}@{ver} is not vendored (no vendor/{name}[-{ver}]); "
                f"an unvendored dependency cannot enter the SBOM (RC-014)")
        vendored = tomllib.loads((vdir / "Cargo.toml").read_text(encoding="utf-8"))
        vpkg = vendored.get("package", {})
        if vpkg.get("name") != name or vpkg.get("version") != ver:
            die(f"vendor/{vdir.name} holds {vpkg.get('name')}@{vpkg.get('version')}, "
                f"Cargo.lock wants {name}@{ver}")
        sums = json.loads((vdir / ".cargo-checksum.json").read_text(encoding="utf-8"))
        recorded = sums.get("package", sums.get("crate"))
        if recorded != checksum:
            die(f"vendor/{vdir.name} records crate checksum {recorded!r}, "
                f"Cargo.lock says {checksum!r}")
        component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        properties.append({"name": "archivist:source", "value": source})
        properties.append({"name": "archivist:vendored", "value": f"vendor/{vdir.name}"})
    components.append(component)

components.sort(key=lambda c: (c["name"], c["version"]))

document = {
    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": timestamp,
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "containers/agent-archivist/generate-sbom.sh",
                    "version": version,
                }
            ]
        },
        "component": {
            "type": "application",
            "bom-ref": f"pkg:cargo/agent-archivist@{version}",
            "name": "agent-archivist",
            "version": version,
        },
    },
    "components": components,
}
rendered = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
if dest == "-":
    sys.stdout.write(rendered)
else:
    Path(dest).write_text(rendered, encoding="utf-8")
PYEOF
}

# timestamp_of FILE — the metadata timestamp committed in a rendered SBOM,
# as unix seconds.
timestamp_of() {
  python3 - "$1" <<'PYEOF'
import json
import sys
from datetime import datetime, timezone

document = json.loads(open(sys.argv[1], encoding="utf-8").read())
stamp = document["metadata"]["timestamp"]
parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
print(int(parsed.replace(tzinfo=timezone.utc).timestamp()))
PYEOF
}

# render_to FILE — regenerate with the caller's epoch into a temp file and
# echo the path.
render_to() {
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/agent-archivist-sbom.XXXXXXXX")"
  generate "$tmp"
  printf '%s' "$tmp"
}

case "$MODE" in
  emit)
    require_epoch
    if [ -n "$OUT" ]; then
      generate "$OUT"
      printf 'generate-sbom: wrote %s (%s components) at epoch %s\n' \
        "$OUT" "$(python3 -c "import json,sys;print(len(json.load(open(sys.argv[1]))['components']))" "$OUT")" \
        "${SOURCE_DATE_EPOCH}"
    else
      generate "-"
    fi
    ;;
  check)
    [ -f "$SBOM_FILE" ] || die "$SBOM_FILE is missing; the release image's SBOM is part of the baseline (RC-021)"
    SOURCE_DATE_EPOCH="$(timestamp_of "$SBOM_FILE")"; export SOURCE_DATE_EPOCH
    rendered="$(render_to)"
    trap 'rm -f "$rendered"' EXIT
    if ! cmp -s "$SBOM_FILE" "$rendered"; then
      die "$SBOM_FILE is not the output this tree generates — regenerate it or revert the hand edit (RC-021/RC-022): run 'SOURCE_DATE_EPOCH=<commit-epoch> $0 --output $SBOM_FILE'"
    fi
    printf 'generate-sbom: ok — %s is byte-identical to the generated document (%s components)\n' \
      "$SBOM_FILE" "$(python3 -c "import json,sys;print(len(json.load(open(sys.argv[1]))['components']))" "$SBOM_FILE")"
    ;;
  self-test)
    # 1. Determinism: two runs at one epoch are byte-identical.
    SOURCE_DATE_EPOCH="1789272549"; export SOURCE_DATE_EPOCH
    first="$(render_to)"
    second="$(render_to)"
    trap 'rm -f "$first" "$second"' EXIT
    if ! cmp -s "$first" "$second"; then
      die "two runs over one tree differ — the generator is not deterministic (RC-022)"
    fi
    printf 'generate-sbom: ok — two runs are byte-identical (%s bytes)\n' "$(wc -c < "$first")"
    # 2. Sensitivity: the byte-compare detects a single-character mutation.
    mutated="$(mktemp "${TMPDIR:-/tmp}/agent-archivist-sbom-mut.XXXXXXXX")"
    trap 'rm -f "$first" "$second" "$mutated"' EXIT
    python3 - "$first" "$mutated" <<'PYEOF'
import sys
text = open(sys.argv[1], encoding="utf-8").read()
marker = '"name": "'
head, _, rest = text.partition(marker)
name, _, tail = rest.partition('"')
open(sys.argv[2], "w", encoding="utf-8").write(head + marker + name[:-1] + ("0" if name[-1] != "0" else "1") + '"' + tail)
PYEOF
    if cmp -s "$first" "$mutated"; then
      die "the mutation self-test mutated nothing"
    fi
    printf 'generate-sbom: ok — the byte-compare detects a mutated component name\n'
    # 3. The committed copy is the generator's output for this tree.
    "$0" --check > /dev/null
    printf 'generate-sbom: ok — %s matches the generated document\n' "$SBOM_FILE"
    ;;
esac
