# Plan Review: Agent Archivist implementation plan

**Verdict:** READY<br>
**Plan:** `docs/plan/plan.md` @ `915f842 · 2026-09-08` · **Type:** Greenfield with integration, port, and migration phases · **Code exists:** no<br>
**Reviewed:** 2026-09-08 by plan-review 2.0 after locking DN-1 through DN-12

The plan is ready to decompose and implement. Its high-reversal choices now live in
the sections that consume them, with rejected alternatives, enforcement, and reopen
signals. An implementer can build the first slice without selecting a language,
wire frame, identifier scheme, storage commit model, trust model, retry policy,
deployment path, or cutover rule. The largest remaining risk is source-format drift
in private harness data, but it is now an explicit read-only inventory and parity
gate with fail-closed unknown-version behavior rather than an architectural fork.

**Next action:** `/plan-to-bead`, starting with the Phase 0 foundation and Phase 1
contract/conformance tasks. Do not begin a production data-path task before the
Phase 1 gate passes on the same commit.

---

## 1. Decisions remaining

None. The former twelve-item decision queue is struck through with pointers to the
binding decision homes at `docs/plan/plan.md:1506-1536`. New evidence can reopen a
choice only through its stated `Revisit if` condition and a same-commit plan,
contract, fixture, and test update.

## 2. First questions an implementer hits (dry run)

**Phase 0 walk.** A worker creates `rust-toolchain.toml` with Rust 1.97.1 and edition
2024, then the exact workspace tree at `docs/plan/plan.md:294-345`. The repository
rules, synthetic fixture seed, version file, and downstream Argo verification path
are specified at `:729-778`. No schema or data-path choice is needed in this phase.

**Phase 1 walk.** A worker translates Sections 7.1–7.11 into schemas and a verifier.
Multipart framing and fresh outer authorization are fixed at `:371-395`; identity,
including the source-occurrence/upload-attestation split, is fixed at `:417-490`;
the S3 commit order and truthful outcomes are fixed at `:533-587`. The gate requires
the Rust implementation and standalone verifier to agree on one commit (`:780-812`).

**Riskiest later phase (Phase 6/8).** Adapter code cannot guess a source schema. It
first records content-free aggregate fingerprints, embeds an allowlist, and proves
file-byte or database-field parity (`:976-1053`). Migration then uses seven days of
shadow evidence, deterministic restore sampling, explicit stop conditions, and a
rehearsed GitOps rollback while retaining the legacy archive (`:1093-1143`).

**Fleet test:** passes. Tasks divide by crate interface, schema family, adapter, or
deployment artifact; the phase-size cut lines at `:1262-1284` prevent a worker from
absorbing an adjacent design decision. The two remaining evidence-dependent gates—
real backend compatibility and observed source fingerprints—have fixed tests and
fail-closed outcomes.

## 3. Reality check and consistency

| # | Claim | Where | Result | Note |
|---|---|---|---|---|
| R1 | Repository is still greenfield | repository | VERIFIED | Six tracked files and no Rust, Go, Python, JavaScript, or TypeScript source files |
| R2 | Selected Rust toolchain exists | `plan.md:166` | VERIFIED | Local `rustc` and `cargo` are both 1.97.1 |
| R3 | Public history is independent | repository | VERIFIED | One root commit, `c5da1aa`; no imported implementation history |
| R4 | Required CI primitives exist | `plan.md:729` | VERIFIED | Read-only inspection found the shared Rust verifier and Argo/buildx precedents; the generic mutable-tag container template is correctly rejected in favor of a dedicated workflow |
| R5 | License is decided | `LICENSE` | VERIFIED | Apache License 2.0 is present and README matches it |
| R6 | B2 and ARMOR pass the new contract | `plan.md:813` | UNVERIFIED BY DESIGN | Phase 2 black-box compatibility is the proof obligation; no unsupported guarantee is asserted now |
| R7 | Harness projections are lossless | `plan.md:976` | UNVERIFIED BY DESIGN | Phase 6 inventory, fingerprint allowlist, and parity oracle must prove this before support is claimed |
| R8 | Plan is current and clean | repository | VERIFIED | Reviewed exact clean commit `915f842`, dated 2026-09-08 |

No blocking contradiction remains. Three formerly dangerous tensions are resolved:

- immutable occurrence envelopes use fresh per-attempt authorization, so long-lived
  spool retries do not weaken replay limits (`:371-415`);
- one source occurrence and separate uploader/request attestations preserve relay
  provenance without last-writer-wins mutation (`:417-490`); and
- the portable ingest credential needs raw write only; `HEAD`/`GET` belong to
  optional verification and offline restore identities (`:533-587`).

## 4. Safety caps

| Cap | Result | Evidence |
|---|---|---|
| C1 observable acceptance for the central outcome | pass | Five named scenarios at `:109-138`; numeric pilot and definition-of-done gates at `:1093-1143`, `:1559-1583` |
| C2 destructive steps have backup, rollback, and trigger | pass | Indefinite raw default, restore prerequisites, tombstones/two-pass GC at `:665-687`; exact pilot rollback at `:1093-1143` |
| C3 bounded first slice exists | pass | Eight-step two-replica blob/occurrence/attestation slice at `:1585-1606` |
| C4 no high-stakes open fork on Phase 0–1 path | pass | DN-1–DN-12 locked at their homes; index closed at `:1506-1536` |
| C5 load-bearing claims hold | pass | Rust/CI facts verified; backend and adapter claims remain explicit future gates, not assumptions |
| C6 house rules respected | pass | Forgejo/Argo path, no GitHub Actions, no mutable deployment tag, no Kubernetes Job/CronJob, and public synthetic-only boundary |
| C7 secrets and untrusted input policy stated | pass | Split storage identities, reference-only secrets, content-free telemetry, encryption, and downstream trust boundary at `:1380-1405` |

## 5. Structural gaps that apply

No blocking structural gap remains. The automated header sweep reports every key
section present, and the heuristic score is 36/36. One artifact is intentionally not
present yet: the concrete threat-to-vector matrix is a Phase 1 deliverable with a
named threat set and pass gate, not a decision prerequisite (`:780-812`). Real
backend reports, source fingerprints, pilot evidence, and restore evidence are
likewise implementation outputs with explicit gates.

## 6. What this plan gets right

- It models blob, source occurrence, and uploader/request attestation separately and
  carries the distinction through keys, commit order, receipts, GC, tests, and the
  first slice (`:417-490`, `:533-631`, `:1585-1606`).
- It makes statelessness operational rather than aspirational: partial commits have
  a deterministic repair order, no server recovery queue, and nine kill points
  (`:239-257`, `:1324-1340`).
- It reports only the deduplication guarantee the backend proves, retaining a
  portable overwrite path for B2 without inventing a database or lock
  (`:533-587`).
- It prioritizes the largest histories without sacrificing active-session freshness
  or smaller sources, using a 15-minute cycle, active-source reservation, 256 MiB
  quantum, and bounded disk policy (`:633-664`, `:923-974`).
- It distinguishes semantic transcript coverage from exact provider-boundary
  coverage and explicitly labels bypass traffic unobserved (`:109-138`,
  `:1145-1174`).
- It makes cutover and deletion conservative: seven-day shadowing, byte/field parity,
  deterministic restore samples, explicit rollback triggers, indefinite raw default,
  and disabled-by-default two-pass GC (`:665-687`, `:1093-1143`).

---

## Appendix A — Decision ledger

| # | Fork | State | Stakes | First needed | Decision home |
|---|---|---|---|---|---|
| DN-1 | 1.0 semantic vs. exact coverage | LOCKED | H | P0/P9 | `:109-138`, `:1145-1174` |
| DN-2 | Language/toolchain | LOCKED | H | P0 | `:166-201` |
| DN-3 | Framing/serialization/signing | LOCKED | H | P1 | `:349-395` |
| DN-4 | IDs, collision, uploader provenance | LOCKED | H | P1 | `:397-490` |
| DN-5 | Canonical payload/compression/limits | LOCKED | H | P1 | `:492-531` |
| DN-6 | Portable S3 commit/concurrency | LOCKED | H | P1/P2 | `:533-587` |
| DN-7 | Linking/trust/replay/rotation | LOCKED | H | P1/P3 | `:259-292`, `:850-879` |
| DN-8 | Receipts/errors/retries/poison | LOCKED | H | P1 | `:588-631` |
| DN-9 | Client state/config/scheduler/disk | LOCKED | H | P5 | `:633-664`, `:923-974` |
| DN-10 | CI/release/deploy/exposure | LOCKED | M | P0/P7 | `:729-778`, `:1055-1091` |
| DN-11 | Retention/backup/rebuild/deletion | LOCKED | H | P7/P10 | `:665-687`, `:1176-1202` |
| DN-12 | Adapter parity/source support | LOCKED | H | P6 | `:976-1053` |

The locator still reports twelve `SHADOW` hits because the audit index intentionally
strikes the old questions and points to these homes. Its five `DEFER` and five
`HEDGE` hits are false positives or trigger-bound non-goals/revisit clauses; none is
an implementation choice. The deferral count decreased from six before locking to
five after locking.

## Appendix B — Structural sweep

| ID | Item | Rating | Note |
|---|---|---|---|
| 1.1 | North star | PRESENT | Observable collection/storage/coverage outcome at `:14-34` |
| 1.2 | Non-goals with rationale | PRESENT | Each material exclusion gives rationale/reopen rule at `:56-84` |
| 1.3 | Hard requirements | PRESENT | Fixed decisions plus accepted normative requirements |
| 1.4 | Glossary | PRESENT | Identity, storage, and coverage terms at `:86-107` |
| 1.5 | Normative language | PRESENT | RFC 2119/8174 declared in accepted requirements |
| 1.6 | What it is not | PRESENT | Sequenced work and non-goals adjacent to scope |
| 1.7 | Scope doctrine | PRESENT | Decision changes require coordinated docs/contracts/tests |
| 1.8 | Self-contained background | PRESENT | Outcome, scenarios, and boundaries stand alone |
| 1.9 | Date/revision | PRESENT | Status, date, and lock revision at top |
| 2.1 | Named acceptance scenarios | PRESENT | Five setup/action/expected scenarios |
| 2.2 | Pass/fail criteria | PRESENT | Scenario outcomes plus error and phase gates |
| 2.3 | Happy path | PRESENT | Fresh active session scenario |
| 2.4 | Degraded/error path | PRESENT | Lost response and marathon outage scenarios |
| 2.5 | Machine mode | PRESENT | JSON/non-interactive/doctor behavior and exit codes |
| 2.6 | Success metrics | PRESENT | Numeric freshness, restore, throughput, memory, and security gates; adoption N/A for self-hosted infrastructure |
| 3.1 | Component model | PRESENT | Diagram, flows, ownership, and repo tree |
| 3.2 | Data model/schema | PRESENT | Envelope, identities, keys, records, version rules |
| 3.3 | State/request lifecycle | PRESENT | Client and server transitions plus crash boundaries |
| 3.4 | Concurrency model | PRESENT | One client mutator; bounded multi-replica server |
| 3.5 | Technology rationale | PRESENT | Rust/library choice with rejected alternatives |
| 3.6 | Dependency contracts | PRESENT | S3/control capabilities and failure behavior |
| 3.7 | File/module layout | PRESENT | Fixed crate/deploy/docs tree |
| 3.8 | Decisions at homes | PRESENT | Twelve churn magnets use Decision/Because/Rejected/Enforced/Revisit |
| 3.9 | Open questions | N/A | No open decision remains |
| 3.10 | Cross-cutting concerns | PRESENT | Errors, logs, cancellation, encoding, metrics |
| 3.11 | Adjacent boundaries | PRESENT | Client/control/S3/derived/legacy ownership split |
| 4.1 | Edge-case catalog | PRESENT | Fourteen resolved entries at `:689-719` |
| 4.2 | Failure modes/recovery | PRESENT | Error/action and nine-point fault matrices |
| 4.3 | Anti-patterns | PRESENT | Explicit prohibited patterns at `:713-719` |
| 4.4 | Error taxonomy | PRESENT | HTTP class to client action at `:600-613` |
| 4.5 | Rollback/state capture | PRESENT | Legacy retained; GitOps revert and stop triggers |
| 4.6 | Graceful degradation | PRESENT | Registry, S3, disk, poison, and unknown-schema paths |
| 4.7 | Invariants | PRESENT | Fixed decisions and receipt/cursor rules |
| 4.8 | Safe defaults | PRESENT | No delete route, GC off, no ingress, auth mandatory |
| 4.9 | Proof obligations | PRESENT | Every major decision has enforcement and revisit signals |
| 5.1 | Named phases | PRESENT | Phases 0–11 |
| 5.2 | Completion criteria | PRESENT | Objective exit gate per phase |
| 5.3 | Walking skeleton | PRESENT | Eight-step vertical slice |
| 5.4 | Entry gates | PRESENT | Dependency gates must pass on same evaluated commit |
| 5.5 | Size estimate | PRESENT | S/M/L effort and task-count bounds at `:1262-1284` |
| 5.6 | Parallel/sequential work | PRESENT | Dependency table, critical path, cut lines |
| 6.1 | Test strategy | PRESENT | Unit/property/protocol/fault/storage/adapter/load |
| 6.2 | Tests beside decisions | PRESENT | `Enforced by` clause at each decision home |
| 6.3 | Property/fuzz tests | PRESENT | IDs, parsing, decompression, projections, SQLite |
| 6.4 | Port conformance | PRESENT | Standalone verifier and adapter parity oracle |
| 6.5 | Stop-ship gates | PRESENT | Security, restore, pilot, performance, compatibility gates |
| 6.6 | Same-commit gates | PRESENT | Phase and evidence manifests bind one commit |
| 6.7 | Evidence bundle | PRESENT | Versioned verification manifest at `:1286-1294` |
| 7.1 | Threat model | PRESENT | Threat set and Phase 1 mitigation/risk gate |
| 7.2 | Secrets handling | PRESENT | References only, split identities, rotations |
| 7.3 | Audit logging | PRESENT | Upload attestations plus content-free operational/audit policy |
| 7.4 | Untrusted input | PRESENT | Raw archive and all payloads treated as untrusted |
| 7.5 | Supply chain | PRESENT | Pinned lock/base, SBOM, scans, signed releases |
| 7.6 | Threat matrix | PARTIAL | Named Phase 1 output; concrete matrix intentionally produced with implementation fixtures |
| 8.1 | Numeric budgets | PRESENT | Bytes, time, concurrency, memory, throughput, freshness |
| 8.2 | Benchmark denominator | PRESENT | Exact client/session/replica/failure mix at `:1364-1379` |
| 8.3 | CI-gated benchmarks | PRESENT | Required floor and same-commit evidence gate |
| 8.4 | Memory budget | PRESENT | 512 MiB RSS at 16 worst-case uploads |
| 8.5 | Scalability limits | PRESENT | Per-client/process/disk/storage limits stated |
| 9.1 | Install/deploy | PRESENT | Binary, service, Compose, Helm paths |
| 9.2 | Migration | PRESENT | Shadow comparator, keep/freeze/retain sequence |
| 9.3 | Backward compatibility | PRESENT | Independent version axes and 90-day support window |
| 9.4 | Rollout/rollback | PRESENT | Numeric go/no-go and exact GitOps fallback |
| 9.5 | Data-format compatibility | PRESENT | Fingerprint allowlist and fail-closed unknowns |
| 9.6 | Non-interactive mode | PRESENT | JSON/stdout/stderr/ANSI/prompt/exit contract |
| 9.7 | Monitoring/alerting | PRESENT | Client/server signals and numeric objectives |
| 9.8 | Doctor/health | PRESENT | Non-mutating doctor plus live/ready semantics |
| 10.1 | Dual output surfaces | PRESENT | TTY human output and versioned JSON machine output |
| 10.2 | Pipe/agent compatibility | PRESENT | stdout/stderr, ANSI, stdin, secret rules |
| 10.3 | Surface before code | PRESENT | Phase 1 CLI/config reference/schema gate |
| 10.4 | Versioning | PRESENT | Wire/object/adapter/package axes and upgrade rules |
| 10.5 | Token/output budget | N/A | Raw release has no transcript-query response surface |
| 11.1 | Risk register | PRESENT | Likelihood, impact, consequence, mitigation for fourteen risks |
| 11.2 | Plan B | PRESENT | ARMOR, S3, adapter, pilot, exact-capture fallbacks |
| 11.3 | Ambition calibration | PRESENT | 1.0, post-raw sequence, and non-goals separated |
| 11.4 | Known unknowns | PRESENT | Backend/source evidence has resolve-by gates and safe defaults |
| 11.5 | Incident named | N/A | Greenfield public architecture; private incidents are excluded |
| P.1 | Port source metrics | PRESENT | Content-free aggregate inventory before adapter code |
| P.2 | Living parity matrix | PRESENT | Phase 6 compatibility matrix exit gate |
| P.3 | Conformance from day one | PRESENT | Phase 1 verifier; Phase 6 adapter oracle |
| P.4 | ABI/FFI stance | N/A | Behavior/data port, not symbol compatibility |
| P.5 | File-format round trip | PRESENT | Complete-record byte reconstruction |
| P.6 | Port order | PRESENT | Claude/Codex, then OpenCode/Pi |
| P.7 | Feature flags | N/A | Runtime coverage states, not compile-time parity gates |
| P.8 | Toolchain pin | PRESENT | Rust 1.97.1/edition 2024/lockfile |
| J.1 | Post-integration ownership | PRESENT | Client/server/control/S3/derived split |
| J.2 | Failure isolation | PRESENT | S3, registry, client disk, adapter failures isolated |
| J.3 | Data ownership/conflicts | PRESENT | S3 truth and deterministic conflict behavior |
| J.4 | Contract versioning | PRESENT | Compatibility and breaking-change rules |
| J.5 | End-to-end ownership | PRESENT | Phase gates and verification manifest |
| J.6 | Coordinated rollback | PRESENT | Downstream GitOps revert plus legacy collector |
| M.1 | Backup/restore before destructive work | PRESENT | Restore/copy prerequisites precede source reduction |
| M.2 | Idempotent/resumable migration | PRESENT | Deterministic retry and shadow collection |
| M.3 | Shadow/canary diff | PRESENT | Seven-day comparator pilot |
| M.4 | Cutover/rollback trigger | PRESENT | Numeric gates and immediate security triggers |
| M.5 | Post-cutover retirement | PRESENT | Legacy read-only at least 90 days plus restore drill |
| S.1–S.6 | Spike-specific controls | N/A | This is an execution plan, not a spike |
