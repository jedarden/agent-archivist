# Agent Archivist requirement-verification mapping

Status: accepted baseline · Last updated: 2026-09-11

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
to be interpreted as described by RFC 2119 and RFC 8174 when they appear in bold.

This document is the traceability contract between the normative
[requirements](requirements.md) and the evidence that proves them: stable
verification identifiers, the machine-readable register that maps requirements
to verifications, and the versioned run manifest that binds evidence to one
evaluated commit. The behavior being verified is owned by the requirements
document and the [implementation plan](../plan/plan.md); what this document
adds is the rule that no requirement may be called implemented without
evidence the gate accepts. Plan Section 10 defines what a verification
manifest records; plan Section 16 defines the per-group verification owners
and the CI rule this gate enforces.

The machine-readable mapping is
[`tools/verification-register.json`](../../tools/verification-register.json);
`tools/verification-manifest.py` (fast lane of
[`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh))
enforces every rule marked enforceable below. When this document and the tool
disagree, the tool's pinned constants decide, and one of the two is wrong and
must be fixed in the same commit.

## 1. Verification identifiers

- **VER-001** — Every normative requirement in
  [requirements.md](requirements.md) **MUST** carry at least one verification
  identifier in the register: `T-<REQ>` for an automated test and `OV-<REQ>`
  for an operational verification, where `<REQ>` is the requirement's stable
  document ID (for example `T-ARCH-001`, `OV-OPS-008`).
- **VER-002** — A verification identifier **MUST** be derived from exactly one
  requirement ID; the prefix states the kind and nothing else. There is no
  independent numbering, so an identifier cannot drift away from the
  requirement it verifies.
- **VER-003** — Verification identifiers **MUST** be treated as frozen once
  committed: an identifier is never renamed, renumbered, or reassigned to a
  different requirement. A requirement that changes meaning normatively is a
  new requirement ID and new identifiers, decided with the requirements
  document in the same commit.
- **VER-004** — A requirement **MAY** carry both kinds — an automated check
  and an operational exercise — listed together in the register. A
  requirement's register entry lists every verification that must pass before
  it may be marked implemented.
- **VER-005** — The register **MUST** cover the requirements document exactly:
  every documented requirement has an entry, and no entry references an
  undocumented requirement. `tools/verification-manifest.py sync` adds
  skeleton entries (`status: planned`, a `T-<REQ>` with the group's default
  owner and no locator) for newly documented requirements; completing the
  mapping happens in the same commit as the requirements change.

## 2. The register

`tools/verification-register.json` is versioned (`register_version`) and has
two maps:

- `requirements[<REQ>]` — `{status, verifications}`:
  - `status` is `planned` (no implementation claim) or `implemented` (the
    claim the gate polices; flipping it is part of the implementation commit,
    never a retrospective edit).
  - `verifications` is the non-empty list of verification IDs from Section 1.
- `verifications[<VID>]` — `{kind, lane, owner, locator?, evidence,
  operational_kind?}`:
  - `kind` — `test` or `operational`, and **MUST** agree with the ID prefix.
  - `lane` — which definition-of-done lane produces the evidence: `fast`,
    `slow`, `audit`, or `release`.
  - `owner` — the verification owner suite, one per requirement group,
    mirroring plan Section 16: `stateless-replacement` (ARCH),
    `auth-conformance` (ID), `golden-ids` (SID), `adapter-suites` (CAP),
    `scheduler-simulation` (SCH), `protocol-corpus` (VAL),
    `compatibility-matrix` (STO), `fault-injection` (RCPT),
    `security-scans` (SEC), `operations-exercises` (OPS), and `release-audit`
    (PUB). A new requirement group extends this map in the tool and the plan
    in the same commit.
  - `locator` — repo-relative path of the mapped check's source (a test file
    or suite entry). The key is omitted while a verification is unplanned;
    `sync` writes no locator. When present the path **MUST** resolve inside
    the repository and exist in the evaluated commit — a locator naming a
    missing file is a register error even for a planned requirement.
  - `evidence` — the non-empty, duplicate-free subset of manifest sections
    (Section 3) this verification draws on. A `test` verification **MUST**
    include `outcomes`.
  - `operational_kind` — for operational verifications only, pins the pilot
    evidence kind (Section 3) the evidence must carry; omitted otherwise.

- **VER-006** — A requirement marked `implemented` **MUST** have every mapped
  `test` verification located in the evaluated commit; the per-change gate
  rejects the claim otherwise, manifest or no manifest. This is the plan
  Section 16 rule that a mapped check absent from the commit fails CI.
- **VER-007** — Flipping a requirement to `implemented` **MUST** happen in the
  commit that implements it, together with its locators, so the per-change
  gate evaluates the claim against the tree that carries the code.

## 3. The verification manifest

A verification run emits `verification-manifest.json` (`manifest_version`)
keyed to the evaluated commit. CI retains it as an artifact; a release
manifest includes and signs it (plan Section 10). Top level:

| Key | Shape | Meaning |
|---|---|---|
| `commit` | 40-hex SHA | the Git commit the evidence describes |
| `generated_at` | RFC 3339 UTC | when the run produced the manifest |
| `toolchain` | `{channel, digest}` | pinned `rust-toolchain.toml` channel and its `sha256:` digest |
| `lock_digest` | `sha256:<hex>` | digest of the committed `Cargo.lock` |
| `fixture_digest` | `sha256:<hex>` or `absent` | tree hash of `fixtures/` (per-file path+content digests, sorted order) |
| `outcomes` | map ID → entry | test-run results |
| `benchmarks` | map ID → entry | benchmark runs against their floors |
| `capability_reports` | map ID → entry | storage backend capability reports |
| `sbom` | `{format, digest}` | CycloneDX or SPDX document digest |
| `artifacts` | map name → entry | release artifacts (OCI image, archive, checksum) |
| `pilot_evidence` | map ID → entry | content-free operational evidence |

Entry shapes: an `outcomes` entry is `{result: pass|fail, locator_digest?}`,
where `locator_digest` proves the outcome was produced by the evaluated bytes
of the mapped check (the `emit` subcommand attaches it automatically). A
`benchmarks` entry is `{profile, results_digest, passed}`. A
`capability_reports` entry is `{profiles: [non-empty], report_digest}`. An
`artifacts` entry is `{kind: oci|archive|checksum, digest}`. A `pilot_evidence`
entry is `{kind, digest, result}` with `kind` one of `pilot-soak`,
`restore-drill`, `review-record`, `coverage-report`, `cutover-checklist` —
and **MUST** equal the verification's pinned `operational_kind` when one is
pinned.

`emit` writes the environment keys and the `outcomes` section from a run's
outcomes file (TSV `name<TAB>pass|fail` lines or the equivalent JSON object);
the remaining sections arrive from later pipeline stages before the final
`check`. An emitted manifest therefore checks clean only when nothing else is
required — which is the point: incomplete evidence is rejected, not patched
up.

## 4. The gate and its rejection categories

`tools/verification-manifest.py check` validates the register (always) and,
given `--manifest`, the recorded evidence. Every failure line carries one
category, which is how each acceptance clause maps to an observable rejection:

| Category | Rejects |
|---|---|
| `REGISTER` | a register inconsistent with the requirements document or with itself |
| `MALFORMED` | a manifest that violates the schema or the content-free constraints |
| `CROSS-COMMIT` | evidence keyed to a commit other than the evaluated one |
| `STALE` | toolchain, lock, fixture, or locator digests that no longer match the evaluated tree |
| `ABSENT` | required evidence (outcome, section entry, located check) that does not exist |
| `INCOMPLETE` | an entry that exists but is not passing or not well-formed |

- **VER-008** — For every requirement marked `implemented`, each mapped
  verification **MUST** have all its `evidence` sections present, well-formed,
  and passing for the evaluated commit; a single violation fails the run.
- **VER-009** — A test outcome recorded without a `locator_digest`, or with
  one matching an earlier version of the mapped check, **MUST** fail as
  incomplete or stale respectively — an outcome produced by different bytes
  than the evaluated tree is not evidence for this commit.
- **VER-010** — An operational verification that lists `outcomes` in its
  evidence **MUST** have that outcome recorded and passing, exactly like a
  test verification; operational status does not weaken the outcomes rule.

The `self-test` subcommand proves the rejection paths against sandbox roots:
the committed register validates, then mutated registers and manifests are
rejected under the right category (every row above has at least one case),
and an `emit`-produced manifest checks clean for its own commit and is
rejected against another. It runs in the fast lane.

## 5. Workflow

1. A requirements change runs `sync` and completes the new entries in the
   same commit (VER-005).
2. Every change runs the per-change gate in the definition-of-done fast
   lane: `check` (register consistency plus the located-check rule,
   VER-006, against this tree) and `self-test` (the Section 4 rejection
   paths, including that the committed register validates). Both are
   offline and content-free.
3. A full verification run (CI, release) runs the lanes, collects the
   outcomes file, emits the manifest for the evaluated commit, adds the
   non-outcomes sections as the lanes produce them, and runs `check
   --manifest` as the release gate (plan Section 10: a gate fails if
   evidence comes from a different commit or any required entry is missing).
4. `sync` is idempotent and refuses to proceed over an inconsistent
   register; repair the register first.

## 6. Content-free constraints

The register and manifest record identifiers, closed enums, hex digests,
repo-relative locators, and pass/fail results — nothing else:

- **VER-011** — Every string in either file **MUST** be bounded (≤ 128
  characters) and drawn from identifier-safe characters; a string that cannot
  appear includes emails, URLs with queries, `key=value` pairs, and free
  prose. Floating-point values and JSON nulls are not recorded at all — an
  absent fact is an omitted key.
- **VER-012** — Locators **MUST** resolve inside the repository; absolute
  paths and `..` traversal are rejected.
- **VER-013** — Findings, manifest entries, and self-test output **MUST**
  name rules, identifiers, paths, and digests only, the same redaction ethos
  as the `gitleaks --redact` lanes; a pilot-soak or restore-drill entry
  records the *fact and digest* of the exercise, never its content. This is
  the manifest-level expression of requirements
  [SEC-004](requirements.md) and [PUB-002](requirements.md).
