# Contributing to Agent Archivist

Agent Archivist is a design-stage project: the architecture and requirements are
settled, the Rust workspace is scaffolded, and implementation arrives through the
phases in the [implementation plan](docs/plan/plan.md). Contributions are welcome
at every level — issue reports, contract review, synthetic fixtures,
documentation, and implementation work as phases open.

## Where development happens

Development is hosted on Forgejo at
`https://git.ardenone.com/jedarden/agent-archivist`, which is the authoritative
repository. The GitHub mirror is read-only: it receives pushes automatically and
pull requests and issues opened there are not reviewed. File issues and open
pull requests on Forgejo.

## Ground rules specific to this project

These rules follow from the project's purpose — archiving transcripts that are
by nature private — and they bind every contribution:

- **Synthetic data only.** Never attach real transcripts, prompts, responses,
  tool outputs, credentials, tenant identifiers, private hostnames, internal
  endpoints, or bucket names to an issue, pull request, fixture, test, or
  screenshot. Reproductions must be built from synthetic input. This mirrors
  requirements SEC-006, SEC-010, PUB-001, and PUB-002.
- **Raw transcripts are sensitive, untrusted data** (design principle 6). Code,
  tests, designs, and proposals must treat captured content accordingly:
  operational logs, metrics, errors, and traces never contain transcript
  bodies, authorization values, or signing material (SEC-004).
- **No secrets in the repository or in command lines.** Configuration examples
  use safe placeholders (PUB-004).

A pull request that adds real session data of any kind will be rejected on
sight, even if the data looks harmless.

## Development environment

- Rust 1.97.1 (edition 2024) is pinned in `rust-toolchain.toml`; a normal
  `rustup` toolchain manager picks it up automatically. No pre-1.0 release
  promises an older minimum supported Rust version.
- `Cargo.lock` is committed; dependency changes belong in the same commit as
  the code that needs them.
- The verification baseline needs no external credentials or services. The
  only network it touches is the public RustSec advisory database fetched by
  `cargo audit`.

## Verification baseline

`scripts/definition-of-done.sh` is the single entry point; a developer runs it
with `--all` before pushing. It expresses the same baseline as the individual
commands:

```sh
cargo fmt --check                                  # formatting
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                             # unit tests
cargo doc --workspace --no-deps                    # docs; broken links deny
python3 tools/check-crate-graph.py                 # crate purpose + cycle check
python3 tools/check-licenses.py                    # dependency license gate
python3 tools/check-error-codes.py --self-test     # error-code registry gate
gitleaks dir --redact .                            # secret scan, working tree
gitleaks detect --redact                           # secret scan, git history
cargo audit --file Cargo.lock --deny warnings      # dependency audit
```

The script's lanes keep per-change gating cheap:

- `--fast` (default; what automation runs per change): fmt, build, Clippy,
  rustdoc, stub scan, crate graph, license gate, error-code registry gate,
  working-tree secret scan — seconds, fully offline.
- `--slow`: the workspace test suite.
- `--audit`: `cargo audit` and the git-history secret scan. The audit
  downloads the public RustSec advisory database; no credentials are involved.
- `--all`: every lane.

A missing prerequisite tool is reported as a failure, never skipped: the gate
does not pass because a scanner was absent. Prerequisites beyond the pinned
Rust toolchain and `python3` are `gitleaks` (>= 8.19, for `dir` mode and
redacted findings; see `.gitleaks.toml`) and `cargo-audit`
(`cargo install cargo-audit --locked`).

`unsafe_code` is forbidden, `missing_docs` and the Clippy `pedantic` set warn,
and the rustdoc build fails on a broken intra-doc link (all configured in the
workspace `Cargo.toml`); the Clippy invocation denies all warnings, so a
warning is a failed check. Secret-scan findings are redacted at the source: a
finding names the rule, file, and line, never the matched value. The license
gate requires every third-party lockfile entry to have a recorded SPDX
identifier in `tools/license-allowlist.toml`, added in the same commit as the
dependency. The error-code registry gate requires every emitted error code to
be an appended entry in `tools/error-codes.toml` whose class, HTTP status,
message template, and labels satisfy the
[error-code conventions](docs/notes/error-codes.md); adding a code is a
compatible change, redefining one is not. The Argo CI workflow that runs this baseline on Forgejo pushes is
tracked as separate Phase 0 work; until it lands, run the script locally and
state in the pull request that it passes.

## Workspace rules

- **Crate boundaries are fixed** through the first vertical slice. The
  [crate ownership map](docs/notes/crate-ownership.md) states each crate's
  purpose and dependency boundary. Collapsing a boundary requires cycle or
  benchmark evidence and updates to the ownership map and the plan in the same
  commit.
- Keep a change to one crate-level interface plus its tests. A schema change is
  never mixed with an unrelated adapter or deployment change (plan Section 9).

## Changing the design

The plan is the decision ledger. Architectural decisions listed in plan
Section 3 are locked, not suggestions: changing one requires updating the
[research findings](docs/research/transcript-archiving-findings.md), the
[system requirements](docs/notes/requirements.md), and the plan together in the
same commit. Each locked decision names its revisit trigger; if none has fired,
propose the change as an issue first rather than redeciding it inside a pull
request.

## Pull requests

- Small and self-contained; one behavior, contract, or crate boundary at a
  time.
- Subject line in the imperative mood, matching the existing history (for
  example, "Make cargo doc a gate instead of a warning source").
- Describe what was verified and how; a change that adds behavior adds tests.
- New external dependencies are pinned in the workspace `Cargo.toml` so every
  member resolves one version, and should not leak SDK types across crate
  boundaries.

## Reporting bugs

Open a Forgejo issue containing: the commit or version observed, the platform,
what happened, what was expected, and a synthetic reproduction if possible.
Reports containing real transcript content or credentials cannot be accepted —
see the ground rules above. Security vulnerabilities are never filed as public
issues; follow the [security policy](SECURITY.md) instead.

## License

Contributions are licensed under the Apache License 2.0, the project's license
([LICENSE](LICENSE)). You retain ownership of your contribution; by submitting
it you agree it is licensed and distributed under Apache-2.0 as part of this
project.
