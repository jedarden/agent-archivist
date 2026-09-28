#!/usr/bin/env bash
# Unified Definition of Done for agent-archivist.
#
# Single source of truth for "is this work acceptable?", invoked identically by
# a developer at a terminal, by CI, and by the NEEDLE validation gate.
#
# Lanes:
#   - Fast:  fmt, build, clippy (-D warnings), rustdoc, stub scan, crate
#     graph, license gate, error-code registry gate, metrics registry
#     gate, config-key registry gate, wire-schema coherence gate, the
#     protocol-bindings regeneration drift gate, CLI
#     command registry gate, the CLI implementation coherence gate,
#     release container baseline gate, release SBOM determinism gate,
#     storage-profile registry gate,
#     adapter compatibility-matrix gate,
#     S3 noncurrent-version lifecycle gate,
#     control trust schema gate, threat-model acceptance gate,
#     synthetic-fixture, conformance-corpus, compat-corpus,
#     inference-corpus, usage-summary-corpus, and control-corpus
#     regeneration and content scan,
#     the standalone contract verifier and its cross-implementation
#     comparison against the Rust implementation (the plan Section 8
#     Phase 1 exit gate),
#     verification-register gate, README status-coherence gate,
#     secret scan of the working
#     tree (seconds, offline; safe as a gate)
#   - Slow:  the workspace test suite, the isolated MinIO compatibility
#     suite, plus the #[ignore]d OpenCode marathon-scale validation — the
#     compatibility matrix's marathon evidence (the opencode row),
#     re-measured on every full run
#   - Audit: dependency audit (cargo audit; fetches the public RustSec
#     advisory database — network, but no credentials) and a secret scan of
#     the full git history
#
# Usage:
#   scripts/definition-of-done.sh [--fast|--slow|--audit|--all]
#                                 [--outcomes FILE]
#
#   --fast   Fast lane only (default; this is what the NEEDLE gate runs)
#   --slow   Test suite only
#   --audit  Dependency audit + history secret scan only
#   --all    Every lane; what a developer runs before pushing
#   --outcomes FILE
#            Append one `name<TAB>pass|fail` line per check as it completes.
#            This is the run-evidence feed for `tools/verification-manifest.py
#            emit --outcomes` (docs/notes/verification.md, Section 5): a
#            full run's outcomes become the versioned verification-manifest
#            entry keyed to the evaluated commit.
#
# Behaviour: aggregates failures rather than aborting on the first one, so a
# single run reports everything that is wrong. Exits non-zero if any check
# failed or a prerequisite tool or Python module is missing.
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
OUTCOMES_FILE=""
while [ $# -gt 0 ]; do
  case $1 in
    --fast) LANE="fast" ;;
    --slow) LANE="slow" ;;
    --audit) LANE="audit" ;;
    --all)  LANE="all" ;;
    --outcomes)
      [ $# -ge 2 ] || { echo "--outcomes needs a FILE argument" >&2; exit 2; }
      OUTCOMES_FILE="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

FAILURES=()
CHECKS=0

run_check() {
  local name="$1"; shift
  local outcome
  CHECKS=$((CHECKS + 1))
  echo "Running: ${name}..."
  if "$@" >/tmp/dod-$$.log 2>&1; then
    echo "  ok  ${name}"
    outcome="pass"
  else
    echo "  FAIL ${name}"
    sed 's/^/    /' /tmp/dod-$$.log | tail -40
    FAILURES+=("${name}")
    outcome="fail"
  fi
  rm -f /tmp/dod-$$.log
  if [ -n "$OUTCOMES_FILE" ]; then
    printf '%s\t%s\n' "${name}" "${outcome}" >> "$OUTCOMES_FILE"
  fi
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

# The same rule for the Python packages the schema gates import. These are
# imported function-locally inside the tools (jsonschema/referencing in the
# schema validators, cryptography in conformancegen's SigningKey), so a
# top-of-file import scan misses them and a missing package surfaces as a raw
# traceback or an "instance validation skipped" degradation instead of a named
# prerequisite failure — exactly the hollow outcome require_tool prevents for
# binaries. Known-good versions are recorded in CONTRIBUTING.md.
require_module() {
  local module="$1" hint
  case "$module" in
    jsonschema)   hint="pip install 'jsonschema>=4.18' (known-good 4.26.0; Debian bookworm's 4.10 predates the referencing resolver); see CONTRIBUTING.md" ;;
    referencing)  hint="imported directly by the schema gates; ships with jsonschema >= 4.18; see CONTRIBUTING.md" ;;
    cryptography) hint="pip install 'cryptography>=46' (known-good 46.0.5); see CONTRIBUTING.md" ;;
    *)            hint="see CONTRIBUTING.md" ;;
  esac
  if python3 -c "import ${module}" >/dev/null 2>&1; then
    return 0
  fi
  echo "  FAIL prerequisite: python3 module '${module}' is not importable (${hint})"
  FAILURES+=("prerequisite: python3 ${module}")
  return 1
}

# All of MODULE... must be importable; every missing one is reported, so a
# single run names the whole absent set rather than the first.
require_modules() {
  local module ok=0
  for module in "$@"; do
    require_module "$module" || ok=1
  done
  [ "$ok" -eq 0 ]
}

MINIO_COMPATIBILITY_REPORT='storage-compatibility profile=minio conditional_create=supported stored_checksum=sha256 versioning=enabled server_side_encryption=verified physical_versions=[concurrent-writers:1:["v3"],duplicate-request:1:["v1"],equivalent-overwrite:1:["v2"],multipart-commit:1:["v5"],origin-attestation:1:["v6"],read-capable-conflict:1:["v4"],relay-attestation:1:["v7"]] noncurrent_audit=[noncurrent-version-audit scope=tenants/0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b/v1/raw/ keys=7 versions=7 noncurrent=0 retained_bytes=0 guidance=sto-009-noncurrent-version-expiration]'

minio_compatibility() {
  local output
  if ! output="$(cargo test -p archivist-storage-s3 --test storage_compatibility \
    minio_reference_profile_reports_expected_capabilities -- --exact --nocapture 2>&1)"; then
    printf '%s\n' "$output"
    return 1
  fi
  if ! grep -Fqx "$MINIO_COMPATIBILITY_REPORT" <<<"$output"; then
    echo "expected MinIO compatibility report was not emitted"
    printf '%s\n' "$output"
    return 1
  fi
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
  # No-SDK-type boundary (plan Section 4; docs/notes/crate-ownership.md
  # rules 1 and 6): the manifest half — archivist-protocol stays sealed,
  # dependency-free — is the crate-graph check above; this is the source
  # half: every public signature and re-export names only project-owned
  # type paths, and the public API inventory test is complete and current.
  # (--self-test replays every rejection path against fixture crates.)
  run_check "protocol boundary"    python3 tools/check-protocol-boundary.py
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
  # cross-registry coherence in both directions — with the config keys
  # (every consumed key registered under a workspace-crate owner, every
  # registered key consumed, no secret key ever exposing a flag tier) and
  # with the error-code registry (every code the CLI contract exits on
  # named, classified, and derived by a command's registry row);
  # `--self-test` proves the rejection paths.
  run_check "cli command registry"  python3 tools/check-cli.py --self-test
  # CLI implementation coherence (docs/notes/cli.md CLI-032): the
  # implementation half of CLI-002's three-registry join, which no other
  # gate scans end to end — every attached handler names a registered
  # command with no duplicate attachment and a pinned result schema, the
  # runtime parser's mode-flag and operand-kind match arms equal the
  # closed registry vocabularies, every code and configuration key the
  # CLI's Rust surface names is registered (keys within their command's
  # row), and the runtime success envelope and error/v1 diagnostic body
  # agree with their schemas; `--self-test` proves the rejection paths.
  run_check "cli implementation coherence"  python3 tools/check-cli-implementation.py --self-test
  # Phase 10's attached command proof: execute the real router in a
  # non-interactive child-process matrix covering successful rebuilds,
  # canonical JSON output, retries, missing configuration/credentials, and
  # both authorization-boundary refusals.
  run_check "catalog rebuild CLI" cargo test -p archivist-cli --test catalog-rebuild-end-to-end
  # Wire-schema coherence (docs/notes/wire-schemas.md): refs, fail-closed
  # enum/version metadata, reserved-name blocks, the construction registry,
  # and the error-message charset; `--self-test` proves the rejection paths.
  run_check "wire schema coherence"  python3 tools/check-wire-schemas.py --self-test
  # Schema-derived bindings (plan Section 8, Phase 1 exit gate): the Rust
  # bindings module (crates/archivist-protocol/src/bindings.rs) is
  # regenerated from the checked-in schemas/v1 family and byte-compared with
  # the committed source, so a hand edit or a schema change without
  # regeneration fails the fast lane; `--self-test` proves the rejection
  # paths (nondeterminism, schema-insensitive output, undetected drift).
  run_check "protocol bindings"         python3 tools/bindingsgen.py --verify
  run_check "protocol bindings policy"  python3 tools/bindingsgen.py --self-test
  # Release container baseline (docs/notes/release-container.md): the
  # VERSION grammar and its equality with the workspace version, the
  # digest-pinned two-stage Dockerfile matching the pinned toolchain, the
  # same-commit rule for the two version records walked over git history,
  # and the committed SBOM's presence, CycloneDX 1.5 shape, subject
  # version, and Cargo.lock coherence (RC-021 through RC-023);
  # `--self-test` proves the rejection paths.
  run_check "release container baseline"  python3 tools/check-release-container.py --self-test
  # Release image SBOM determinism (docs/notes/release-container.md
  # RC-021 through RC-023): the committed CycloneDX document is the
  # deterministic output of the committed generator over this tree —
  # two runs byte-identical, the byte-compare sensitive to a single
  # mutated character, and the committed copy fresh. Plain bash plus the
  # Python standard library: offline, no docker, no git.
  run_check "release sbom"  containers/agent-archivist/generate-sbom.sh --self-test
  # Storage-profile registry (docs/notes/storage-profiles.md and
  # tools/storage-profiles.toml): the community qualification path —
  # profile classes with MinIO pinned as the one reference profile,
  # append-only per-profile records whose shape follows the outcome, the
  # five-axis capability matrix with closed tokens and multipart
  # commit/abort verified, the release-scoped negative record, and
  # registry/note/README/release/support coherence including the retirement
  # of the unevidenced usability claim and the prohibition on
  # deployment-profile or support claims for a community profile while its
  # latest record is unqualified; `--self-test` proves the rejection
  # paths.
  run_check "storage profiles"  python3 tools/check-storage-profiles.py --self-test
  # Adapter compatibility matrix (docs/notes/compatibility-matrix.md): the
  # published per-adapter fingerprint allowlists, projection versions,
  # artifact kinds, and known gaps, reconciled row-for-row against the
  # adapter source constants and every fingerprint the fleet inventory
  # observed, with the six-state coverage vocabulary pinned to status.rs
  # (plan Phase 6 exit gate; threat AC-11's support-claim rule); a
  # fingerprint that is not in the note is a claim the project does not
  # make, and the three records cannot drift apart silently.
  # `--self-test` proves the rejection paths.
  run_check "compatibility matrix"  python3 tools/check-compatibility-matrix.py --self-test
  # Provider-capture route registry (docs/notes/compatibility-matrix.md,
  # "The published provider-capture route registry"): the published half
  # of the compatibility matrix — one row per exact-capture route the
  # project claims, naming its route fingerprint, artifact schema version
  # and kinds, support state, qualifying conformance suite, and known
  # gap — checked field for field against the PUBLISHED_REGISTRY const,
  # the note table, and the conformance mint sites, so a support claim
  # cannot drift from the evidence that earned it (plan Phase 9; threat
  # EC-04). --self-test proves the rejection paths.
  run_check "provider-capture registry"  python3 tools/check-provider-capture-registry.py --self-test
  # Rotation-drill probe (docs/notes/armor-storage-provisioning.md,
  # "Rotation procedure" steps 1/5/6): the live instrument takes credential
  # pairs via environment only and prints only HTTP status and S3 error
  # codes; --self-test proves that contract — statuses and error codes
  # only, a planted pair unreachable, boto3 never imported — against an
  # in-process fake client. The live run is a drill instrument, never a
  # gate.
  run_check "rotation probe"  python3 tools/rotation-drill-probe.py --self-test
  # Rotation-drill orchestrator (docs/notes/rotation-drill-runbook.md): the
  # baseline/watch/flip/verify composition of the probe into one drill —
  # delivery-chain preflight, the propagation watch with per-sample
  # continuity, the step-6 enforcement matrix, and the machine-checked
  # verdict. Credential pairs travel by environment only, the only
  # credential-derived evidence values are fingerprints, and an evidence
  # write carrying a supplied pair value is refused; --self-test proves
  # that contract and that every injected fault fails the verdict, against
  # a scripted fake cluster. The live drill is a runbook run, never a gate.
  run_check "rotation drill orchestrator"  python3 tools/rotation-drill.py --self-test
  # Armor identity set (docs/notes/armor-storage-provisioning.md,
  # "Identities" and tools/armor-identities.toml): the machine-readable
  # record of the six scoped storage identities — ADR-012 ACL grammar,
  # the no-delete invariant with abort pinned to the raw writer, the
  # closed holder classes, and the note's identity and prefix tables row
  # for row, plus the current-state counts — so the documented set cannot
  # drift from the provisioned one; a change to the identity set updates
  # registry, note, and this gate in the same commit. `--self-test`
  # proves the rejection paths.
  run_check "armor identities"  python3 tools/check-armor-identities.py --self-test
  # S3 noncurrent-version lifecycle (docs/notes/s3-noncurrent-lifecycle.md
  # and tools/s3-lifecycle-rules.toml): the per-prefix, per-profile
  # retention matrix for the noncurrent versions deterministic overwrite
  # leaves behind — every rule aimed at a source-of-truth family is
  # noncurrent-only, the control current-pointer families' history is
  # retained, the control families' split matches the control-records
  # registry's write classes, and the note, registry, audit guidance
  # constant, and the MinIO reference script's owned rule cannot drift
  # apart; `--self-test` proves the rejection paths.
  run_check "s3 lifecycle rules"  python3 tools/check-s3-lifecycle.py --self-test
  # Control trust family (docs/notes/control-trust.md and
  # docs/notes/control-trust-schemas.md): the archivist.control/v1
  # envelope registry, flat wrapper composition, closed shapes, the
  # no-private-material rule, behavioural validation of the golden
  # records, and the append-only record registry
  # (tools/control-records.toml) agreeing with the envelope registry,
  # its object-key patterns, and the plan's Section 7.5 layouts and
  # timing sentences; `--self-test` proves the rejection paths.
  # The three schema gates below (this one, the conformance corpus, and the
  # compat corpus) import third-party Python packages, so they are preflighted
  # with require_modules: without it a missing package degrades the gate into
  # a traceback or a "validation skipped" note rather than naming the
  # prerequisite.
  require_modules jsonschema referencing \
    && run_check "control trust schemas"  python3 tools/check-control-schemas.py --self-test
  # Threat-model acceptance (docs/security/threat-model.md): the Phase 1
  # exit-gate rule that every finding carries a mitigation or an explicitly
  # accepted risk with a closed-vocabulary owner, the consolidated register
  # covers the four domain documents row for row and the declared ranges,
  # and the accepted-risk register maps one to one with the owner-bearing
  # rows; `--self-test` proves the rejection paths.
  run_check "threat model"          python3 tools/check-threat-model.py --self-test
  # Byte-exact regeneration from the recorded seed plus the closed-
  # vocabulary content scan (docs/notes/fixtures.md). Output is
  # content-free: counts, bytes, and digests only.
  run_check "synthetic fixtures"   python3 tools/fixturegen.py --verify
  # Language-neutral conformance corpus (docs/notes/conformance-corpus.md):
  # byte-exact regeneration of the golden envelopes, signatures, digests,
  # identifier hashes, object keys, receipt chains, and retry examples;
  # every signature is re-verified by the generator's independent
  # pure-Python Ed25519 verifier and every golden error body is checked
  # against the error-code registry.
  require_modules jsonschema referencing cryptography \
    && run_check "conformance corpus"  python3 tools/conformancegen.py --verify
  # Standalone contract verifier (plan Section 8, Phase 1 exit gate): the
  # verifier re-derives every golden from the normative sources alone
  # (schemas, RFC 8785, RFC 8032), and `compare` requires the Rust
  # implementation's answer sheet to be byte-identical — signatures, IDs,
  # and keys agree across two independent implementations on the evaluated
  # tree. `compare` implies `verify`.
  run_check "contract verifier"    python3 tools/contract-verifier.py self-test
  run_check "contract cross-implementation" \
                                   python3 tools/contract-verifier.py compare --quiet
  # Schema compatibility corpus (docs/notes/schema-compatibility.md):
  # byte-exact regeneration of the two-reader-generation matrix; the
  # manifest coverage check proves every plan Section 7.1 version-axis
  # rule maps to at least one pinned positive or negative scenario, the
  # exhaustive failClosed-enum matrix rejects every synthesized unknown
  # value under both reader generations, and --require-complete fails
  # while any scenario verification is still deferred; `--self-test`
  # proves the rejection paths.
  require_modules jsonschema referencing \
    && run_check "compat corpus"  python3 tools/compatgen.py --verify --require-complete
  run_check "compat policy"  python3 tools/compatgen.py --self-test
  # Exact-inference example corpus (docs/notes/exact-inference-schemas.md):
  # byte-exact regeneration of the twelve golden artifacts across the
  # single/retried/streamed scenarios, schema validation of every record,
  # the reserved-name and closed-metadata-allowlist negative matrices, and
  # the ordering/reconstruction invariants recomputed from the pinned bytes.
  require_modules jsonschema referencing \
    && run_check "inference corpus"  python3 tools/inferencegen.py --verify
  # Usage-summary example corpus (docs/notes/usage-summary-schema.md):
  # byte-exact regeneration of the eight golden records, schema validation
  # of every record plus the reserved-name negative matrix, and the
  # digest/object-key/unknown-never-zero invariants recomputed from the
  # pinned bytes. The committed corpus is additionally replayed against
  # the schema by the Rust suite
  # (crates/archivist-protocol/tests/usage_summary_corpus.rs, slow lane),
  # so the record shape is enforced where its producer will be built.
  require_modules jsonschema referencing \
    && run_check "usage corpus"  python3 tools/usagegen.py --verify
  # The generator's rejection paths proven without the committed bundle:
  # the digest construction's label/preimage/key rules, the per-record
  # fault rejection, the write guard, and the schema's negative matrix
  # with a valid control. Shares "usage corpus"'s exit-code contract
  # (3 on any failed proof, 4 without jsonschema), so one run_check
  # wrapper governs both.
  require_modules jsonschema referencing \
    && run_check "usage corpus policy"  python3 tools/usagegen.py --self-test
  # Control-record corpus (docs/notes/conformance-corpus.md, "The
  # current-pointer bundles"): byte-exact regeneration of the
  # archivist.control/v1 golden-vector table under
  # schemas/v1/examples/control/ — five scenario files and an
  # authority-rotation chain sharing one keys.json — every record
  # validated against the envelope registry per the
  # check-control-schemas.py conventions, every signature re-verified
  # with the generator's independent pure-Python Ed25519 verifier, and
  # every pinned accept/reject outcome, acceptance-table verdict, and
  # manifest record/outcome/digest invariant replayed from the pinned
  # bytes. The committed authority-rotation chain is additionally
  # replayed by the Rust suite
  # (crates/archivist-auth/tests/authority_corpus.rs, slow lane).
  require_modules jsonschema referencing cryptography \
    && run_check "control corpus"  python3 tools/controlgen.py --verify
  # The control generator's rejection paths proven without the
  # committed bundle: build determinism, tampered/foreign-key/forged
  # signatures, the decision procedure's flipped-pin detection, the
  # write guard's refusal of unrecognized files, and the schema's
  # no-private-material fault matrix over one record of every family.
  # Shares "usage corpus"'s exit-code contract (3 on any failed proof,
  # 4 without jsonschema).
  require_modules jsonschema referencing cryptography \
    && run_check "control corpus policy"  python3 tools/controlgen.py --self-test
  # Requirement-to-verification mapping (docs/notes/verification.md):
  # `check` validates this tree's register (consistency with the
  # requirements document plus the located-check rule for anything marked
  # implemented); `self-test` proves the manifest rejection paths. Both are
  # register-only mode: offline, content-free.
  run_check "verification register"  python3 tools/verification-manifest.py check
  run_check "verification map"       python3 tools/verification-manifest.py self-test
  # README status coherence (docs/notes/crate-ownership.md and
  # tools/verification-register.json): the README's implementation-status
  # statements — the implemented/total requirement counts, the
  # landed/total crate counts, the links to both authorities, and the
  # retired stage claims ("design-stage", "still ahead of their phases")
  # this reconciliation removed — are re-derived from the machine-checked
  # records on every fast-lane run, so the README cannot drift from the
  # register or the ownership map silently; `--self-test` proves the
  # rejection paths.
  run_check "readme status"  python3 tools/check-readme-status.py --self-test
  # .gitleaks.toml (extend-default + never-committed path exclusions) is
  # picked up automatically from the repository root.
  require_tool gitleaks "gitleaks >= 8.19 (dir mode, --redact); see CONTRIBUTING.md" \
    && run_check "secret scan (working tree)" gitleaks dir --redact --no-banner .
fi

if [ "$LANE" = "slow" ] || [ "$LANE" = "all" ]; then
  run_check "cargo test"           cargo test --workspace
  # Isolated MinIO reference lane (plan Section 10 and README): execute only
  # the reference profile, require its exact capability/physical-version
  # report, and treat either a test failure or report drift as a gate failure.
  run_check "MinIO compatibility" minio_compatibility
  # OpenCode marathon-scale validation (docs/notes/compatibility-matrix.md,
  # the opencode row's marathon evidence; requirement CAP-004 at scale):
  # the #[ignore]d marathon_scale suite runs the production capture path
  # over a deterministic synthetic 2,048-session / 227,328-row store —
  # parity against the SDK's oracle, exact per-session accounting,
  # byte-identical repeat captures, the full append re-capture, the
  # excluded-table negative at scale, and the throughput/memory bounds —
  # and the compatibility-matrix gate pins the note's published figures to
  # this suite's constants, so the matrix's marathon evidence stays
  # re-measured by the definition of done's slow lane, never merely
  # narrated.
  run_check "opencode marathon scale" \
    cargo test -p archivist-adapter-opencode --test marathon_scale -- --ignored
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
