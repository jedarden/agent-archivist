# Adapter compatibility matrix — published (Phase 6 exit gate)

The committed compatibility matrix the plan's Phase 6 exit gate names: every
source fingerprint the released adapters support, the projection version and
artifact kind each is captured under, its supported state, and its known gap
— reconciled row for row against the fingerprints the fleet inventory
observed (`docs/notes/fleet-source-inventory.md`, 2026-09-08). A fingerprint
named here is a *claim* backed by the adapter's own gate evidence (threat
`AC-11`: a real-source adapter is claimable only with its positive
conformance and every applicable negative set passing —
`docs/security/threats/adapter-capture.md`, "Pre-claim evidence gate"); a
fingerprint absent here is a claim the project does not make.

This note is the **source-adapter** matrix (plan Phase 6). The
provider-capture route registry is a separate matrix with separate evidence
(`archivist-adapter-sdk::compatibility`, plan Phase 9); neither subsumes the
other, and a row in one confers nothing in the other. The SDK's synthetic
reference adapter (`synthetic-append-only-jsonl-v1`) is deliberately not a
row: it is the conformance suite's own subject, not a released source, and
support for it is a statement about the SDK contracts, not about any
harness.

Content-free like the inventory it reconciles: tokens, versions, counts, and
verdicts only — no host, user, path, session, account, or credential text.

## The published matrix

| Adapter | Projection | Source fingerprint | Artifact kind | State | Known gap and evidence |
|---|---|---|---|---|---|
| `claude-jsonl` | `1` | `claude-jsonl-v1` | `file-slice` | supported | Session and subagent JSONL with no account-identifying member in the bounded header window. Fleet: the two single-version hosts (CLI `2.1.220`, `2.1.226`) hold exactly this shape. Complete-but-unparseable lines (154 fleet-wide) are skipped without failing the source; the fleet maximum complete record of 12.7 MB bounds per-record handling. |
| `claude-jsonl` | `1` | `claude-jsonl-v2` | `file-slice` | supported | Session and subagent JSONL where any account-identifying member (`accountUuid`, `ownerAccountUuid`, `ownerOrganizationUuid`) appears in the header window. Fleet: the two multi-version hosts (CLI `2.1.220`–`2.1.266`, 31 distinct versions). Account values are identifiers — counted per host, never projected as content. |
| `claude-jsonl` | `1` | `claude-sidecar-v1` | `file-slice` | supported | One whole sidecar object per file: tool-result and session-sidecar roles, captured with explicit sidecar relationships. Fleet: tool-result files on every Claude host; session sidecars are rare — one host carries the only two in the fleet. |
| `codex-jsonl` | `1` | `codex-rollout-jsonl` | `file-slice` | supported | Per-session rollout JSONL under the session date tree; the 7-key envelope over 8 record types. Fleet: one host, session dates 2026-08-03 through 2026-09-08, maximum complete record 5.1 MB; the other three hosts have no Codex root (reported `root-absent`, a coverage gap, never an error). |
| `codex-jsonl` | `1` | `codex-history-jsonl` | `file-slice` | supported | The account-wide shared prompt-history sidecar. Fleet: exactly one per host beside the rollouts; captured as a related sidecar artifact, not a session. |
| `opencode` | `0.1.0` | `opencode-sqlite-v1` | `database-projection` | supported | Read-only projection of the five allowlisted tables (`session`, `message`, `part`, `session_input`, `todo`) with their exact column sets. Only allowlisted application version: `1.18.29`. Fleet: a single host, 18 sessions — schema conformance only, no marathon-scale validation (fleet finding 7). |
| `pi` | `1.0.0` | `pi-jsonl-v1` | `file-slice` | supported | Session JSONL, header version 1 (the version-less default). Never observed in the fleet: no Pi root exists on any in-scope host; supported on the SDK conformance and synthetic fixtures only — a declared coverage gap (plan §6C). |
| `pi` | `1.0.0` | `pi-jsonl-v2` | `file-slice` | supported | Session JSONL, header version 2. Same fleet gap as `pi-jsonl-v1`. |
| `pi` | `1.0.0` | `pi-jsonl-v3` | `file-slice` | supported | Session JSONL, header version 3. Same fleet gap as `pi-jsonl-v1`. |
| `pi` | `1.0.0` | `pi-immutable-v1` | `file-slice` | supported | One complete immutable session object per file; an identity or digest change opens a new generation, never an overwrite. Same fleet gap as the JSONL dialects. |

The artifact kinds are the protocol's closed pair (`file-slice`,
`database-projection`); the adapter-local kinds they surface as — Claude
`Jsonl`/`Object`, Codex `Rollout`/`History`, Pi `Jsonl`/`Immutable` — are
the same rows one level down. Each adapter also publishes constant
unknown-shape tokens (`claude-jsonl-unknown`, `claude-unknown-format`,
`codex-unknown-format`, `pi-jsonl-unknown`, `pi-immutable-unknown`,
`pi-unknown-format`): the fail-closed reports for shapes outside this table.
They are classifications of non-support, never rows in it.

## Observed-fingerprint reconciliation

Every fingerprint the fleet inventory observed, mapped to supported or
unsupported as the Phase 6 exit gate requires. `unobserved` is the third
honest verdict — recorded when the inventory looked and found no source, so
there is no evidence either way.

| Observed fingerprint | Verdict | Admitted by | Evidence |
|---|---|---|---|
| `claude-jsonl` | supported | `claude-jsonl-v1`, `claude-jsonl-v2` | Fleet union of 22 record types and 134 top-level keys across CLI `2.1.220`–`2.1.266`. Both dialects observed: account members present on the two multi-version hosts (one distinct account value each, never stored), absent on the two single-version hosts; the container host contributes stale mirror evidence only (its live workload was unschedulable at scan time). The fingerprint is envelope shape, not CLI version — a future CLI writing a matching envelope still admits, an envelope nobody has seen fails closed. |
| `codex-rollout-jsonl` | supported | `codex-rollout-jsonl`, `codex-history-jsonl` | The rollout sessions plus the one shared prompt-history sidecar per host; both admit. 192 complete-but-unparseable lines and 6 files with an unterminated final line on the one live host — skipped and re-measured next pass, never source failures. |
| `opencode-sqlite` | supported | `opencode-sqlite-v1` | The observed store is exactly the allowlisted layout: five tables, full column sets, application version `1.18.29`. A store written by any other version classifies `fingerprint-unsupported` before one projected row is read; the container host was not scanned live (transport-unreachable at scan time). |
| `pi-session-jsonl` | unobserved | — | Root absent on all four in-scope hosts. No fleet evidence exists either way; the Pi adapter ships with its coverage-gap reporting (plan §6C) and its fingerprints stay supported on synthetic evidence only. |
| `prototype-legacy` | unsupported | — | The pre-existing age+gzip encrypted corpus. No released adapter claims the envelope, and the interior is unmeasurable without decryption inside the trust boundary. Known gap: it stays on the legacy collector (the plan Phase 8 rollback path) until a future adapter qualifies through this same gate. |

## Coverage status vocabulary

The states a source — and, aggregated, an adapter/account scope — can be in
(`archivist-adapter-sdk::status::CoverageState`, requirement CAP-010). The
aggregate is the highest-rank per-source state in the scope, so the states
an operator must attend to win:

| State | Token | Rank | Meaning |
|---|---|---|---|
| Absent | `missing` | 0 | Nothing observable at the configured root (root absent, no database) — a coverage gap the inventory reports explicitly, distinct from an empty backlog. |
| Fully backfilled | `backfilled` | 1 | A backfill-lane source whose measured history has been captured completely. |
| Current | `current` | 2 | A freshness-lane source with no outstanding data: capture is keeping up with the live session. |
| Partial | `partial` | 3 | Measured outstanding data capture has not yet acknowledged — active growth or backfill in progress. |
| Unsupported | `unsupported` | 4 | The observed fingerprint is not on any adapter allowlist; no content was read (plan `EC-08` — unknown fingerprints fail closed). |
| Failed | `failed` | 5 | The last inventory pass could not read the source: transport, read, or permission failure. |

Mapping to this matrix: an inventory verdict of supported above means a
source showing that fingerprint proceeds to backlog arithmetic — `partial`,
`current`, or `backfilled` by its measured outstanding data. The matrix's
own verdicts enter status as `unsupported` (classification
`fingerprint-unsupported`), and absent roots or missing databases as
`missing` (classifications `root-absent`, `no-database`).

## Maintenance rules

1. A fingerprint enters or leaves this matrix only in the same commit as the
   adapter's allowlist constant and its gate evidence change — the three
   cannot drift, because `tools/check-compatibility-matrix.py` fails the
   fast lane otherwise.
2. An unknown fingerprint fails closed as `unsupported` after the bounded
   header probe and not one byte more (plan `EC-08`); no adapter carries a
   best-effort parse for a shape outside this table.
3. A support claim without its gate evidence is rejected (threat `AC-11`):
   the pre-claim evidence gate names the negative and fault evidence every
   row above rests on, and the finding-to-test-class mapping is
   machine-checked in the fast lane.
4. Every fingerprint a new fleet inventory observes is reconciled here in
   the same commit it is recorded, each to `supported`, `unsupported`, or
   `unobserved`.
