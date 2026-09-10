#!/usr/bin/env bash
# Unified Definition of Done for agent-archivist.
#
# Single source of truth for "is this work acceptable?", invoked identically by
# a developer at a terminal, by CI, and by the NEEDLE validation gate.
#
# Lanes:
#   - Fast: fmt, build, clippy, rustdoc, stub scan (seconds; safe as a gate)
#   - Slow: the workspace test suite
#
# Usage:
#   scripts/definition-of-done.sh [--fast|--slow|--all]
#
#   --fast   Fast lane only (default; this is what the NEEDLE gate runs)
#   --slow   Test suite only
#   --all    Both lanes
#
# Behaviour: aggregates failures rather than aborting on the first one, so a
# single run reports everything that is wrong. Exits non-zero if any check
# failed.
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
  run_check "cargo clippy"         cargo clippy --workspace --all-targets
  run_check "cargo doc"            cargo doc --workspace --no-deps
  run_check "stub scan"            stub_scan
fi

if [ "$LANE" = "slow" ] || [ "$LANE" = "all" ]; then
  run_check "cargo test"           cargo test --workspace
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
