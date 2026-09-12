#!/usr/bin/env bash
# Unified Definition of Done for agent-archivist.
#
# Single source of truth for "is this work acceptable?", invoked identically by
# a developer at a terminal, by CI, and by the NEEDLE validation gate.
#
# Lanes:
#   - Fast:  fmt, build, clippy (-D warnings), rustdoc, stub scan, crate
#     graph, license gate, error-code registry gate, metrics registry
#     gate, config-key registry gate, wire-schema coherence gate, CLI
#     command registry gate,
#     control trust schema gate, synthetic-fixture regeneration and
#     content scan,
#     verification-register gate, secret scan of the working tree
#     (seconds, offline; safe as a gate)
#   - Slow:  the workspace test suite
#   - Audit: dependency audit (cargo audit; fetches the public RustSec
#     advisory database — network, but no credentials) and a secret scan of
#     the full git history
#
# Usage:
#   scripts/definition-of-done.sh [--fast|--slow|--audit|--all]
#
#   --fast   Fast lane only (default; this is what the NEEDLE gate runs)
#   --slow   Test suite only
#   --audit  Dependency audit + history secret scan only
#   --all    Every lane; what a developer runs before pushing
#
# Behaviour: aggregates failures rather than aborting on the first one, so a
# single run reports everything that is wrong. Exits non-zero if any check
# failed or a prerequisite tool is missing.
#
# Output safety: every check reports names, paths, and identifiers only.
# Secret-scanning findings are redacted at the source (`gitleaks --redact`),
# so a finding names the rule, file, and line but never the matched value.
#
# The stub scan enforces the plan's no-placeholder rule: crate skeletons carry
# documented purposes, never `todo!()`/`unimplemented!()` bodies. See
# docs/plan/plan.md section 17 (Definition of done).

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT" || exit 1

LANE="fast"
while [ $# -gt 0 ]; do
  case $1 in
    --fast) LANE="fast" ;;
    --slow) LANE="slow" ;;
    --audit) LANE="audit" ;;
    --all)  LANE="all" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

FAILURES=()
CHECKS=0

run_check() {
  local name="$1"; shift
  CHECKS=$((CHECKS + 1))
  echo "Running: ${name}..."
  if "$@" >/tmp/dod-$$.log 2>&1; then
    echo "  ok  ${name}"
  else
    echo "  FAIL ${name}"
    sed 's/^/    /' /tmp/dod-$$.log | tail -40
    FAILURES+=("${name}")
  fi
  rm -f /tmp/dod-$$.log
}

# A missing prerequisite is a failure, never a silent skip: the gate must not
# pass because a scanner was absent.
require_tool() {
  local tool="$1" hint="$2"
  if command -v "$tool" >/dev/null 2>&1; then
    return 0
  fi
  echo "  FAIL prerequisite: ${tool} is not installed (${hint})"
  FAILURES+=("prerequisite: ${tool}")
  return 1
}

# The stub scan is a grep whose SUCCESS is "no matches", so it cannot go
# through run_check directly.
stub_scan() {
  local hits
  hits="$(grep -rnE 'todo!|unimplemented!|FIXME' crates tools 2>/dev/null || true)"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits"
    return 1
  fi
  return 0
}

echo "=== agent-archivist Definition of Done (lane: ${LANE}) ==="
echo "NEEDLE_VERIFICATION_GATE: definition-of-done"

if [ "$LANE" = "fast" ] || [ "$LANE" = "all" ]; then
  run_check "cargo fmt --check"    cargo fmt --check --all
  run_check "cargo build"          cargo build --workspace
  run_check "cargo clippy"         cargo clippy --workspace --all-targets -- -D warnings
  run_check "cargo doc"            cargo doc --workspace --no-deps
  run_check "stub scan"            stub_scan
  run_check "crate graph"          python3 tools/check-crate-graph.py
  run_check "license gate"         python3 tools/check-licenses.py
  run_check "error-code registry"  python3 tools/check-error-codes.py --self-test
  # Metrics and telemetry registry (docs/notes/metrics.md): metric, span,
  # attribute, unit, histogram, status, and bounded-label conventions; the
  # forbidden correlation/content/location label list; and the pinned
  # OpenTelemetry-to-Prometheus translation with an injectivity proof, so
  # exporters retain consistent names; `--self-test` proves the rejection
  # paths.
  run_check "metrics registry"     python3 tools/check-metrics.py --self-test
  # Configuration-key registry (docs/notes/configuration.md): naming,
  # precedence, types/bounds, secret-reference grammar, and a tree scan
  # that rejects literal values assigned to *_ref settings; `--self-test`
  # proves the rejection paths.
  run_check "config registry"     python3 tools/check-config.py --self-test
  # CLI command registry (docs/notes/cli.md): command grammar, the three
  # disjoint flag namespaces, the versioned output envelope, and
  # cross-registry coherence with the config keys — including that no
  # secret key ever exposes a flag tier; `--self-test` proves the
  # rejection paths.
  run_check "cli command registry"  python3 tools/check-cli.py --self-test
  # Wire-schema coherence (docs/notes/wire-schemas.md): refs, fail-closed
  # enum/version metadata, reserved-name blocks, the construction registry,
  # and the error-message charset; `--self-test` proves the rejection paths.
  run_check "wire schema coherence"  python3 tools/check-wire-schemas.py --self-test
  # Control trust family (docs/notes/control-trust.md and
  # docs/notes/control-trust-schemas.md): the archivist.control/v1
  # envelope registry, flat wrapper composition, closed shapes, the
  # no-private-material rule, behavioural validation of the golden
  # records, and the append-only record registry
  # (tools/control-records.toml) agreeing with the envelope registry,
  # its object-key patterns, and the plan's Section 7.5 layouts and
  # timing sentences; `--self-test` proves the rejection paths.
  run_check "control trust schemas"  python3 tools/check-control-schemas.py --self-test
  # Byte-exact regeneration from the recorded seed plus the closed-
  # vocabulary content scan (docs/notes/fixtures.md). Output is
  # content-free: counts, bytes, and digests only.
  run_check "synthetic fixtures"   python3 tools/fixturegen.py --verify
  # Requirement-to-verification mapping (docs/notes/verification.md):
  # `check` validates this tree's register (consistency with the
  # requirements document plus the located-check rule for anything marked
  # implemented); `self-test` proves the manifest rejection paths. Both are
  # register-only mode: offline, content-free.
  run_check "verification register"  python3 tools/verification-manifest.py check
  run_check "verification map"       python3 tools/verification-manifest.py self-test
  # .gitleaks.toml (extend-default + never-committed path exclusions) is
  # picked up automatically from the repository root.
  require_tool gitleaks "gitleaks >= 8.19 (dir mode, --redact); see CONTRIBUTING.md" \
    && run_check "secret scan (working tree)" gitleaks dir --redact --no-banner .
fi

if [ "$LANE" = "slow" ] || [ "$LANE" = "all" ]; then
  run_check "cargo test"           cargo test --workspace
fi

if [ "$LANE" = "audit" ] || [ "$LANE" = "all" ]; then
  require_tool cargo-audit "cargo install cargo-audit --locked" \
    && run_check "cargo audit"     cargo audit --file Cargo.lock --deny warnings
  require_tool gitleaks "gitleaks >= 8.19 (dir mode, --redact); see CONTRIBUTING.md" \
    && run_check "secret scan (git history)" gitleaks detect --redact --no-banner
fi

echo
echo "=== Definition of Done Summary ==="
echo "Lane: ${LANE}"
echo "Checks run: ${CHECKS}"
echo "Failures: ${#FAILURES[@]}"

if [ "${#FAILURES[@]}" -gt 0 ]; then
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi

echo "Definition of Done: PASS"
