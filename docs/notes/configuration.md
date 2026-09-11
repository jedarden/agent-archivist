# Agent Archivist configuration conventions

Status: accepted baseline · Last updated: 2026-09-11

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
to be interpreted as described by RFC 2119 and RFC 8174 when they appear in bold.

This document is the naming, precedence, typing, default, path, non-interactive,
and secret-reference contract for every setting a deployment can change in the
public crates and commands. Behavior contracts it rests on are owned elsewhere
and are not redecided here: client state, scheduling, and disk degradation by
[implementation plan](../plan/plan.md) Section 7.9, the Phase 5 non-interactive
and XDG deliverables, storage endpoint configuration by the Phase 2
deliverables, server limits by the Phase 4 deliverables, and content-freedom by
requirements [SEC-004](requirements.md), [SEC-005](requirements.md),
[SEC-006](requirements.md), and [SEC-010](requirements.md). What this document
adds is the closed surface those settings are expressed through, so that a key
cannot appear in code, documentation, or an example that the registry and gate
have not already agreed on.

The machine-readable registry is [`tools/config-keys.toml`](../../tools/config-keys.toml);
`tools/check-config.py` (fast lane of
[`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh)) rejects a
registry or a committed file that violates any rule marked enforceable below.
When this document and the tool disagree, the tool's pinned constants decide,
and one of the two is wrong and must be fixed in the same commit.

## 1. Scope and ownership

- **CFG-001** — A *configuration key* is every deployment-settable knob that
  changes the behavior of a public crate or the `archivist` binary. Every key
  **MUST** be an entry in the registry before any crate reads it; a setting
  that is not a registered key is not configuration and **MUST NOT** be read
  from a file, the environment, or a flag. The registry is therefore the
  complete configuration surface, and the Phase 1 CLI/config reference is
  generated from it rather than maintained beside it.
- **CFG-002** — Every key declares exactly one owning crate, consistent with
  the [crate ownership map](crate-ownership.md). The owner validates the key's
  value and consumes it; `archivist-cli` composes surfaces and owns keys only
  for composition-root behavior. A key's owner never changes silently
  (Section 9).
- **CFG-003** — Mode flags are not keys: `--non-interactive`, `--json`,
  `--config`, `--help`, and `--version` have no environment or file form, the
  `ARCHIVIST_` namespace never carries them, and no key can flip a command's
  interaction or output mode. `--config PATH` selects *which* file the file
  tier reads; it is not a tier of its own. This keeps a service invocation
  non-interactive regardless of what a config file says.
- **CFG-004** — Harness-specific and per-source settings (source-root
  allowlists, adapter toggles) arrive as appended registry entries in the
  phase that implements them, under the same grammar as everything else.
  There is no free-form adapter configuration table outside the registry, and
  no key whose value is an unbounded map or list in v1.

## 2. Naming

- **CFG-005** — A key is two dot-separated lowercase segments,
  `section.name`, each matching `[a-z][a-z0-9_]{0,63}` — for example
  `spool.max_bytes`, `storage.raw_write_credentials_ref`. Sections group by
  owning surface (`client`, `schedule`, `ingest`, `storage`, `server`, and
  future appended sections); a segment is at most 64 characters.
- **CFG-006** — The environment form of a key is `ARCHIVIST_` plus the key
  with every dot replaced by an underscore, uppercased — for example
  `ARCHIVIST_SPOOL_MAX_BYTES`. The `ARCHIVIST_` prefix is reserved for
  exactly this mapping: the tools read no other meaning from it, and a
  deployment must not expect an unregistered `ARCHIVIST_*` variable to do
  anything (CFG-012 rejects it if presented).
- **CFG-007** — The flag form of a key is the key with dots and underscores
  replaced by hyphens — for example `--spool-max-bytes`. A key exposes a flag
  only when its tiers include `flag` (Section 8); each key has at most one
  long flag and no short alias, because a config key is not a frequent
  interactive gesture.
- **CFG-008** — Derived names **MUST NOT** collide: the gate computes every
  key's environment name and flag name and rejects any pair that maps to the
  same string (for example `spool.max_bytes` and `spool_max.bytes` share an
  environment name and cannot both exist). The derivation is injective by
  construction, not by convention.
- **CFG-009** — The XDG base-directory variables (`XDG_CONFIG_HOME`,
  `XDG_STATE_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`) and `HOME` are the one
  sanctioned environment dependency outside the `ARCHIVIST_` namespace: they
  participate only in path resolution (Section 6) and never carry values.

## 3. Precedence and fail-closed loading

- **CFG-010** — Precedence is per key, highest tier wins: flag, then
  environment, then config file, then the registry default. Lower tiers are
  not merged, patched, or reported when a higher tier supplies a value. A key
  absent from every tier resolves to its default or, if required, fails per
  CFG-020.
- **CFG-011** — The file tier reads exactly one TOML file: `--config PATH`
  when given, otherwise the platform-native default of Section 6. The path
  given to `--config` **MUST** be absolute after `HOME` expansion; includes,
  overlays, and directory-drop directories are v1-out of scope by CFG-004.
- **CFG-012** — Loading fails closed: an unrecognized key in the file tier or
  the environment tier is a usage error (`cli.usage_error`, exit 64), never a
  warning and never a silent ignore. A misspelled key therefore announces
  itself, and a config written for a newer major fails loudly on an older
  binary instead of half-applying.
- **CFG-013** — A value that does not parse or range-check as its key's type
  is a usage error naming the key and the violated constraint. The offending
  value is never echoed for reference-typed keys (Section 8) and is echoed
  for no key in `--json` mode; error bodies follow the error-code
  conventions, so no unbounded value can enter a diagnostic.

## 4. Types and bounds

- **CFG-014** — The v1 type set is closed: `boolean`, `integer`, `string`,
  `path`, `enum`, and `reference`. The registry schema is likewise closed
  (CFG-033); a new type is a registry-format extension with a same-commit
  gate update, and v1 keys never change type (Section 9).
- **CFG-015** — There are no floating-point configuration values anywhere;
  every quantity is an integer whose name carries its unit as a suffix, and
  the suffix fixes its bounds. The unit suffixes are frozen:

| Suffix | Meaning | Bounds |
|---|---|---:|
| `_bytes` | byte quantity | 1 .. 2^48 |
| `_seconds` | duration in seconds | 1 .. 31,536,000 |
| `_percent` | percentage | 0 .. 100 |
| `_count` | cardinality | 0 .. 2^31−1 |
| `_ratio` | ratio as integer N of N:1 | 1 .. 10,000 |

  Every `integer` key **MUST** end in one of them; the gate rejects an
  integer key without a unit suffix and any value outside its suffix bounds.
  A duration that ever needs sub-second resolution is a new unit suffix, not
  a float.
- **CFG-016** — A `string` value is printable ASCII, at most 128 characters,
  with no brace characters. Endpoints, regions, and bucket names fit; free
  prose does not, by design. A secret is never of type `string`
  (Section 8).
- **CFG-017** — An `enum` key declares its closed value set in the registry;
  values match `[a-z][a-z0-9_]{0,31}`. A value outside the set fails per
  CFG-013. Adding a value to an existing enum is a v2 event (Section 9): an
  old binary must fail closed on it, and that failure is a compatibility
  decision, not a surprise.
- **CFG-018** — A `path` value is either a literal absolute POSIX path or a
  leading XDG/`HOME` template variable (CFG-009) followed by an absolute
  suffix. Tilde shorthand, relative paths, and `.` or `..` segments are
  rejected; the loader expands the template and requires the result to be
  absolute. Reference targets are always literal and follow the stricter
  grammar of CFG-029.

## 5. Defaults and required keys

- **CFG-019** — Every key declares exactly one of a `default` or
  `required = true` — never both, never neither. Defaults live only in the
  registry; documentation, examples, and code quote the registry and are not
  a second source. The gate is the proof that the sentence "every key has a
  defined resolution" is true.
- **CFG-020** — A required key missing from every tier is a usage error: in
  non-interactive mode, exit 64 with `cli.decision_missing` naming the field;
  in interactive mode a non-secret required key **MAY** prompt. A secret
  required key never prompts (CFG-026) and is therefore always resolved by a
  reference supplied in the file or environment tier.
- **CFG-021** — A default is a pinned decision, not a tuning knob: each
  registry default traces to the plan section or requirement that fixed it,
  and changing one follows the locked-decision process for that source in the
  same commit — a registry-only default change is not a compatible edit
  (Section 9).

## 6. Paths and platform-native locations

- **CFG-022** — Locations are platform-native and owned by `archivist-cli`:
  on Linux, XDG base directories. The default config file is
  `${XDG_CONFIG_HOME}/archivist/archivist.toml` (defaulting under `HOME` per
  the XDG specification) and client state lives under
  `${XDG_STATE_HOME}/archivist`. Additional platforms adopt their native
  conventions when added, with the same key registry and the same permission
  discipline; the registry itself never carries platform-conditional keys.
- **CFG-023** — Client state and spool directories are mode `0700` and their
  files mode `0600`. A component that finds unsafe permissions refuses the
  operation explicitly, and `doctor` reports the condition by property — the
  offending mode, never a listing of file contents.
- **CFG-024** — The state directory is single-mutator by OS advisory lock,
  and second-mutator behavior is plan Section 7.9's contract (exit 75,
  `client.lock_held`); this document only fixes that the state directory's
  location is the `client.state_dir` key and its permissions follow CFG-023.

## 7. Non-interactive discipline

- **CFG-025** — Every automation-facing command accepts `--non-interactive`
  and `--json`. Daemon and service invocations are always non-interactive.
  These flags are mode flags (CFG-003): no key or environment variable can
  turn them on, so a deployment's configuration cannot make a service
  interactive.
- **CFG-026** — No command reads a secret from an interactive prompt or from
  an implicit stdin read. Secret-bearing settings are supplied as references
  (Section 8) through the file or environment tier before the command runs;
  bulk payload stdin is reserved for an explicitly documented subcommand,
  and that subcommand is never a secret path.
- **CFG-027** — Commands never echo resolved secret values, and never echo
  reference strings either: diagnostics name the key and the failure class,
  following the verify-by-property rule the error-code conventions already
  impose on messages (ERR-011 through ERR-013). Output streams obey
  ERR-029 through ERR-031; this section adds that stdout and diagnostics are
  secret-free by construction, not by redaction at print time.

## 8. Secret references

- **CFG-028** — A secret-bearing setting is exactly the conjunction of three
  facts: type `reference`, a name ending in `_ref`, and `secret = true`. The
  gate enforces all three directions — a `_ref` name that is not a secret
  reference type, a secret key without the suffix, and a reference type
  without the secret flag are each violations. There is no second spelling
  for "this value is sensitive".
- **CFG-029** — A reference value is one of two closed forms: `file:` plus a
  literal absolute path matching `[A-Za-z0-9._+-]` path segments with no `.`
  or `..` segment and no tilde, or `env:` plus an environment variable name
  matching `[A-Z][A-Z0-9_]{0,63}` that **MUST NOT** start with `ARCHIVIST_`
  — that prefix is reserved for the config tier itself (CFG-006), so a
  secret's channel can never be confused with a configuration key. A new
  reference kind (a key-store, for example) extends this set only with a
  same-commit gate update.
- **CFG-030** — The `file:` kind resolves to a regular file readable by the
  running user only (mode `0600` or stricter); a file with group or other
  permissions is refused, and `doctor` reports the refusal by property. The
  value is the file's full contents with at most one trailing newline
  trimmed. The path itself is operator-supplied configuration and appears in
  no diagnostic (CFG-027).
- **CFG-031** — A secret key's tiers are a subset of `env` and `file` —
  never `flag` — because a reference on a command line is one `ps` or shell
  history away from a transcript. Every key, secret or not, includes the
  `file` tier: the TOML file is the substrate every deployment can express.
  The environment tier carries the *reference string*, never the secret
  value; the only sanctioned non-reference home for a secret value is the
  `file:`/`env:` target named by a reference.
- **CFG-032** — No literal secret value may appear assigned to a `*_ref`
  setting anywhere: not in arguments (impossible by CFG-031), not in output
  (forbidden by CFG-027), and not in examples or committed fixtures — the
  gate's working-tree scan rejects any configuration-bearing committed file
  (the TOML registry and config, YAML/env/INI shapes, and the documentation
  that shows them) that assigns a non-reference value to a `*_ref` name,
  and the gitleaks lanes remain the backstop for credential-shaped strings
  everywhere else. This rule is the configuration-surface expression of
  SEC-004, SEC-006, and SEC-010.

## 9. Registry and compatibility

- **CFG-033** — The registry is
  [`tools/config-keys.toml`](../../tools/config-keys.toml) under schema
  `archivist.config-registry/v1`. Its shape is closed: unknown top-level or
  per-key keys are rejected by the gate. Every entry carries `owner`,
  `type`, `tiers`, `secret`, exactly one of `default`/`required`, a bounded
  one-line `description`, and an `example` value that **MUST** validate as
  the key's type — examples are checked data, not decoration, which is what
  makes CFG-032 enforceable in examples by machine.
- **CFG-034** — Within registry v1, keys are append-only. Renaming or
  deleting a key, changing its type, owner, tiers, secretness, bounds, enum
  values, default, or required-ness is a v2 event. Marking a key
  `deprecated = true` is compatible: it keeps its meaning and keeps loading;
  removal is v2. Configuration compatibility follows the same fail-closed
  ethos as the wire schemas — a v2 arrives with a documented transition, not
  as an accumulation of silent redefinitions.
- **CFG-035** — The registry *format* may grow compatibly within
  `archivist.config-registry/v1` (new optional per-key keys, new types or
  reference kinds per CFG-014/CFG-029) only in a commit that updates this
  document and the gate's pinned constants together. The registry format is
  versioned separately from the configuration surface for the same reason
  the error registry is (ERR-035): format growth is metadata, surface
  change is semantics.

## 10. Verification

- **CFG-036** — `tools/check-config.py` is the enforcing test. It validates
  the committed registry against every enforceable rule above, scans the
  committed tree's configuration-bearing files for `*_ref` assignments of
  non-reference values, and runs in the fast lane, so no commit can land an
  invalid registry or a literal secret in an example or fixture.
- **CFG-037** — Its `--self-test` mode mutates the committed registry with
  known defects — a secret without the `_ref` suffix, a reference exposed as
  a flag, literal-looking example values, reserved-namespace and non-absolute
  references, float and out-of-bounds defaults, unitless integers, derived
  name collisions, enum drift — and writes sandbox files carrying literal
  `*_ref` assignments; it fails unless every one is rejected. The rejection
  paths are tested, not assumed.
- **CFG-038** — Runtime tests that follow (the Phase 4/5/6 configuration,
  doctor, and daemon suites) **MUST** load through this registry's surface
  and assert the behavior rules: unknown-key rejection (CFG-012), per-key
  precedence (CFG-010), non-interactive exit 64 on missing required keys
  (CFG-020), permission refusal (CFG-023/CFG-030), and the no-echo rule
  (CFG-027) under synthetic malformed input — closing the loop between
  these conventions and the phases that implement them.
