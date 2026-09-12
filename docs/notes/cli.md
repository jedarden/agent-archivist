# Agent Archivist CLI command conventions

Status: accepted baseline · Last updated: 2026-09-11

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
to be interpreted as described by RFC 2119 and RFC 8174 when they appear in bold.

This document is the command-surface contract for the `archivist` binary:
command names, flags, output framing, exit behavior, non-interactive
operation, and the operand/secret discipline at the argument boundary. It is
the Phase 1 "versioned CLI/config reference" deliverable for the command
side; the key side (TOML keys, defaults, precedence, secret references) is
owned by the [configuration conventions](configuration.md) and is not
redecided here. Error codes, class taxonomy, process exit allocation, and
stream behavior are owned by the [error-code conventions](error-codes.md);
plan [Section 7.9](../plan/plan.md) and the Phase 5 deliverables own the
lock, scheduling, and non-interactive behavior this surface exposes.

The machine-readable registry is
[`tools/cli-commands.toml`](../../tools/cli-commands.toml); the output
envelope is [`schemas/v1/cli-output.json`](../../schemas/v1/cli-output.json);
`tools/check-cli.py` (fast lane of
[`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh))
rejects a registry, a flag namespace, or an envelope that violates any rule
marked enforceable below. When this document and the tool disagree, the
tool's pinned constants decide, and one of the two is wrong and must be fixed
in the same commit.

## 1. Scope and authority

- **CLI-001** — The `archivist` binary built from `archivist-cli` is the only
  published executable of this project in v1. Every capability a user or a
  service invokes — client, server, linking, administration, catalog — is a
  command of that binary. Nothing ships a second binary or a `main` function
  outside `archivist-cli` (crate boundary rule 7).
- **CLI-002** — Three registries pin the command surface and **MUST** agree:
  the command registry here, the [configuration-key
  registry](../../tools/config-keys.toml) that names every value a command
  can be told, and the [error-code
  registry](../../tools/error-codes.toml) that names every condition a
  command can exit on. A command may not consume a key, emit a code, or exit
  on a class that its registry does not already name — the same
  register-before-implement discipline as CFG-001 and ERR-008.
- **CLI-003** — A command that is not an entry in the command registry
  **MUST NOT** be implemented, documented as available, or invoked in a
  committed example. The registry is therefore the complete command surface,
  and generated help cites it rather than a second list maintained beside it.

## 2. Command grammar

- **CLI-004** — An invocation is `archivist [mode flags] <command>
  [operational flags] [key flags] [--] [operand]`. A command path is one or
  two space-separated segments, each matching `[a-z][a-z0-9-]{0,31}` — for
  example `daemon`, `verify-state`, `catalog rebuild`. Three-level paths,
  command aliases, and abbreviation **MUST NOT** exist in v1; each is a
  registry-format extension with a same-commit gate update (Section 8).
- **CLI-005** — The *joined form* of a command path — segments joined by a
  hyphen, as in `catalog-rebuild` — is the command's output token (CLI-014)
  and **MUST** be unique across the registry: no two command paths may share
  one. The derivation is injective by construction, not by convention, and
  the gate rejects a registry where it is not (the CFG-008 rule, applied to
  commands).
- **CLI-006** — Every registry entry pins, for its command: a bounded
  summary, the implementing plan phase, the owning crate, the state lock it
  takes, its stdout kind, its operand kind, its stdin kind, the configuration
  keys it consumes, and its operational flags. The v1 set (the registry is
  the authority; the table is illustrative):

| Command | Phase | Lock | stdout | Operand | Purpose |
|---|---:|---|---|---|---|
| `daemon` | 5 | exclusive | none | — | the internal 15-minute scheduling loop |
| `run --once` | 5 | exclusive | document | — | one foreground scheduling cycle |
| `inventory` | 5 | read-only | document | — | source discovery and outstanding-byte estimate |
| `status` | 5 | read-only | document | — | local collection status snapshot |
| `verify-state` | 5 | read-only | document | — | spool/receipt/cursor consistency verification |
| `doctor` | 5 | read-only | document | — | non-mutating health check; nonzero exit when action is needed |
| `serve` | 4 | none | none | — | the stateless ingestion server |
| `link request` | 3 | none | document | — | emit a link request carrying public identity only |
| `admin approve` | 3 | none | document | path | sign and write a linked-client record |
| `admin revoke` | 3 | none | document | path | sign and write a revocation record |
| `admin rotate` | 3 | none | document | path | record a key rotation with overlapping epochs |
| `admin delegate` | 3 | none | document | path | record origin/uploader relay delegation |
| `admin receipt-key` | 3 | none | document | — | generate and certify a receipt-signing key |
| `catalog rebuild --from-occurrences` | 10 | none | document | — | rebuild the catalog from raw provenance |

  The plan's crate-tree sketch of the CLI as "collect, serve, link, admin,
  status" is realized by this table: capture is `run`/`daemon`, and the
  crate map points here rather than restating names.
- **CLI-007** — The state-lock field states the command's relationship to
  the plan Section 7.9 single-mutator contract: `exclusive` commands take
  the advisory lock and a second mutator exits 75 with `client.lock_held`;
  `read_only` commands open a snapshot and **MUST** stay available while the
  daemon owns the lock (the Phase 5 exit gate); `none` commands never touch
  client state. A command's lock class never changes without a plan-level
  decision in the same commit.

## 3. Flags

- **CLI-008** — Exactly three flag kinds exist: *mode flags* (CLI-009),
  *key flags* (CLI-010), and *operational flags* (CLI-011). A flag that is
  none of these is a usage error (`cli.usage_error`, exit 64) — never a
  warning, never silently ignored — so a script written for a newer binary
  fails loudly on an older one rather than half-applying (the CFG-012
  ethos, at the argument boundary).
- **CLI-009** — Mode flags are exactly the CFG-003 set and **MUST NOT**
  grow within v1: `--non-interactive` and `--json` accepted by every
  command; `--config PATH` accepted by every command (the only value-taking
  mode flag, and a path, never a value — CFG-011's absolute-path rule
  applies); `--help` accepted by every command; `--version` accepted at the
  top level only and printing `<name> <semver>` with exit 0, never JSON.
  Mode flags have no environment or file form. There are **no short flags
  anywhere in v1**: no flag has a one-letter alias, so every invocation a
  script can write is unambiguous in `ps` output and shell history.
- **CLI-010** — A key flag is the CFG-007 derivation of a registered key
  whose tiers include `flag`. A command accepts exactly the key flags
  derived from its registry key list: a key flag passed to a command that
  does not list the key is a usage error. The file and environment tiers
  are deployment state and validate against the whole key registry
  regardless of command — a key irrelevant to the invoked command is
  recognized and inert, so one configuration file may serve a host that
  runs several commands. Every registered key **MUST** be consumed by at
  least one command; the gate rejects a key registry and a command registry
  that disagree, which is what makes "the key registries are the complete
  configuration surface" (CFG-001) true rather than aspirational.
- **CLI-011** — An operational flag is command-specific behavior selection,
  is **boolean** (it never takes a value), and is **globally unique**
  across the registry: one name, one meaning, no command reuses another
  command's flag name. Operational flags **MUST NOT** collide with any mode
  flag name or any key-flag name derivable from the key registry — the
  three namespaces are disjoint and the gate proves it. The v1 set is
  exactly two: `run --once` and `catalog rebuild --from-occurrences`, both
  `required` — invoking the command without its required flag is a usage
  error, which is why the plan writes both commands with their flag. A
  value-taking operational flag is a registry-format extension (Section 8),
  not a v1 edit.
- **CLI-012** — Parsing is strict: each flag **MAY** appear at most once —
  repetition is a usage error, never last-wins; mode flags may precede or
  follow the command path, while operational and key flags attach to their
  command; `--` terminates flag parsing so an operand is never mistaken for
  a flag; and an unknown value for a known key flag fails per CFG-013.

## 4. Output

- **CLI-013** — Streams follow ERR-029 through ERR-031: stdout carries
  exactly the command's documented output; stderr carries diagnostics —
  human-readable by default, newline-delimited `archivist.error/v1` bodies
  under `--json`; a failed command emits **no** stdout value so a downstream
  pipe never consumes partial output; ANSI escapes appear only on a detected
  TTY stderr, never with `--json`, never redirected. Human-readable output is
  the TTY default and is advisory: automation **MUST** parse only `--json`
  output, exactly as an error consumer **MUST NOT** parse messages
  (ERR-004).
- **CLI-014** — Under `--json`, a successful command writes exactly one
  versioned value to stdout: the `archivist.cli-output/v1` envelope pinned by
  [`schemas/v1/cli-output.json`](../../schemas/v1/cli-output.json), with four
  members and no others — `schema` (the namespace, fail-closed), `command`
  (the joined-form token, CLI-005), `generated_at` (RFC 3339 UTC), and
  `result` (the command's document). The envelope shape is closed; nothing
  may be added to it within v1.
- **CLI-015** — `result` is the one delegated member: each command's result
  document is a **closed** schema under `schemas/v1/`, attached to the
  command's registry entry (`result_schema`) by the phase that implements
  the command, additive within that schema per the plan Section 7.1 rules.
  A command with no result schema has not shipped. Result documents obey
  the content rules all output obeys: no transcript bodies, no secret
  values or reference strings, no unbounded identifiers (SEC-004, CFG-027).
  An unregistered `command` token in an envelope still parses — commands
  are append-only, and the consumer reads `schema` first (the ERR-037
  ethos).
- **CLI-016** — Commands with stdout kind `none` — `daemon` and `serve` —
  emit **no** stdout value on any path and run until signalled: their
  operational evidence is `status`, the health endpoints, and metrics, not
  a stdout stream. A long-running process printing progress lines would
  break the one-value contract, so they print none.
- **CLI-017** — `--help` output is human-readable regardless of `--json`,
  exits 0, and cites the registry; `--help` for an unknown command does not
  rescue it from CLI-004 (unknown command is still exit 64). `--version`
  never emits the envelope (CLI-009).

## 5. Exit codes

- **CLI-018** — Exit codes are allocated **only** by the error-code
  conventions (ERR-022, ERR-023); the command registry allocates none and
  no command may exit on an unallocated code. Exit 0 means the command's
  primary objective completed; quarantine is not failure (ERR-024); the
  terminating error's class determines a nonzero exit (ERR-030).
- **CLI-019** — `doctor` exits nonzero precisely when operator action is
  needed: the code is the class of its most severe finding, and every
  finding is an error body with a registered code — so `doctor --json
  --non-interactive` failing on permissions, corruption, disk floor, clock
  skew, readiness, or linkage is a stable, content-free signal (the Phase 5
  exit gate).
- **CLI-020** — Termination by signal follows the shell `128+n` convention
  and stays outside the allocation table (ERR-023); `daemon` and `serve`
  shut down gracefully per their plan phases before allowing the signal to
  complete.

## 6. Non-interactive operation

- **CLI-021** — Every command accepts `--non-interactive` and `--json`
  (CFG-025). `daemon` and `serve` are **always** non-interactive whether or
  not the flag is passed — a service invocation can never be made
  interactive by forgetting it, and no key or file can flip a mode
  (CFG-003).
- **CLI-022** — In non-interactive mode a missing decision or required
  configuration field is exit 64 with `cli.decision_missing` naming the
  field (CFG-020, ERR-022); in interactive mode only a non-secret required
  key **MAY** prompt, only on a TTY, and the answer is never echoed to a
  diagnostic. A secret required key never prompts (CFG-026).
- **CLI-023** — No v1 command reads stdin. The registry's `stdin` field is
  the reserved growth point: a future subcommand that consumes bulk payload
  stdin sets `stdin = "payload"` in the same commit that documents it and
  updates the gate, and that subcommand is never a secret path (CFG-026).

## 7. Operands and secrets

- **CLI-024** — **No secret value is accepted as a literal argument, by
  construction.** The only value-taking arguments in the whole surface are
  `--config PATH` (a path), the key flags of non-secret keys (a secret key
  exposes no flag tier, CFG-031), and — never, in v1 — an operational flag.
  The gate proves the conjunction: the mode-flag set is closed and
  path-valued at exactly `--config`; every operational flag is boolean; no
  key with `secret = true` carries a flag tier. This is the argument-side
  expression of SEC-006 and CFG-032.
- **CLI-025** — A command takes at most one positional operand, of a
  closed kind: `path` (a document to read — a link-request or control-record
  draft, never a credential store) or `identifier` (a registered identifier
  grammar). An operand is never a free-form value, and secret material
  reaches a command only through a `*_ref` key in the file or environment
  tier (CFG-028 through CFG-031).
- **CLI-026** — Command output — envelope, result documents, diagnostics —
  never contains a secret value or a reference string (CFG-027): linking and
  administration output carries public keys, key IDs, record digests, and
  object-key shapes, and verifies sensitive material by property.

## 8. Registry and compatibility

- **CLI-027** — The registry is
  [`tools/cli-commands.toml`](../../tools/cli-commands.toml) under schema
  `archivist.cli-registry/v1`. Its shape is closed: unknown top-level or
  per-command keys are rejected. Within registry v1 the surface is
  append-only: adding a command, appending an operational flag, growing a
  command's key list, and attaching a result schema are compatible; renaming
  or removing a command, changing its phase, owner, lock, stdout, operand,
  or stdin kind, removing a key from its list, or redefining an operational
  flag is a v2 event. Marking a command `deprecated = true` is compatible:
  it keeps parsing and keeps working; removal is v2 (the CFG-034 rule).
- **CLI-028** — The registry *format* may grow compatibly within
  `archivist.cli-registry/v1` (new optional per-command keys; new
  operational-flag attributes; new operand, stdin, lock, or stdout kinds;
  deeper command paths) only in a commit that updates this document and the
  gate's pinned constants together. The registry format, the output
  namespace, and the package version are separate axes (plan Section 7.1):
  a SemVer bump is never a substitute for a registry or namespace version.

## 9. Verification

- **CLI-029** — `tools/check-cli.py` is the enforcing test. It validates
  the committed registry (grammar, closed shapes, bounds, uniqueness), the
  three flag namespaces (mode, key-derived, operational — pairwise disjoint,
  each injective), cross-registry coherence with
  [`tools/config-keys.toml`](../../tools/config-keys.toml) (command key
  lists reference registered keys; every registered key is consumed; no
  secret key exposes a flag tier), and the output envelope schema
  (`$id`, namespace const, closed member set, `command` pattern agreement
  with the registry's joined forms, resolvable `generated_at` reference,
  no floats). It runs in the fast lane, so no commit can land an invalid
  command surface.
- **CLI-030** — Its `--self-test` mode mutates copies of the committed
  trio — bad command grammar, joined-form collisions, flag collisions in
  each direction, a value-taking operational flag, unknown or duplicate key
  references, a registered key no command consumes, a secret key granted a
  flag tier, enum and bound drift, and a schema with a wrong namespace, an
  opened shape, a dropped member, a float, or a dangling reference — and
  fails unless every one is rejected. The rejection paths are tested, not
  assumed.
- **CLI-031** — Runtime tests that follow (the Phase 3 linking, Phase 4
  server, and Phase 5 client suites) **MUST** assert against this registry:
  a command's accepted and rejected flags, the one-value stdout contract,
  envelope validation against the command's result schema, exit codes by
  error class, and the no-secret-argument property under synthetic
  malformed input — closing the loop between these conventions and the
  phases that implement them.

## Examples

Canonical invocations (no command consumes a secret value; the references
name files whose contents never appear in output):

```sh
archivist --non-interactive --json status
archivist --non-interactive --json run --once
archivist --config /etc/archivist/production.toml daemon
archivist --non-interactive --json doctor
archivist --json catalog rebuild --from-occurrences
```

A deployment's `archivist.toml` carries the secret references the daemon
resolves at run time — for example a `storage.raw_write_credentials_ref`
line whose value is a well-formed `file:` reference such as
`file:/etc/archivist/storage/raw-write-credentials` (CFG-029), never a
value; and the flag form of that key does not exist to be passed (CFG-031,
CLI-024).
