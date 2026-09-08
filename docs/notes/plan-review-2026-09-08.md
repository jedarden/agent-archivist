# Plan Review: Agent Archivist implementation plan

**Verdict:** NOT READY<br>
**Plan:** `docs/plan/plan.md` @ `9f83a19 · 2026-09-08` · **Type:** Greenfield with port, integration, and migration phases · **Code exists:** no<br>
**Reviewed:** 2026-09-08 by plan-review 2.0

The architecture is thoughtful, unusually explicit about failure recovery, and
strong on storage provenance, but it is not ready to decompose into autonomous
implementation tasks. Cap C4 is tripped: Phase 1 is a queue of seven high-reversal
ADRs rather than decisions, while Phase 0 already needs several of their answers to
shape crates, fixtures, CI, and the first vertical slice. The largest risk is a
worker choosing wire framing, signing, identity, compression, or S3 commit semantics
inside an implementation task and turning that choice into a post-hoc ADR. Lock the
first eight decisions below before implementation; the remaining four must be
resolved before their named later phases.

**Next action:** Fix Cap C4 by accepting or revising DN-1 through DN-8 and folding
them into the plan's scope, implementation, contract, and Phase 0/1 sections before
creating implementation tasks.

---

## 1. Decide these now

### DN-1 · Stable-release completeness boundary — DEFERRED · stakes H · first needed: Phase 1

**Where:** `docs/plan/plan.md:46`, `docs/plan/plan.md:55`,
`docs/plan/plan.md:568`, `docs/plan/plan.md:808`,
`docs/plan/plan.md:872`<br>
**Plan says:** exact inference capture is optional and deferred, then includes it in
Phase 9 and `0.7+`, but the 1.0 definition of done does not say whether it is required.

**Proposed decision:** Version 1.0 has two separately reported coverage dimensions:
semantic harness capture and exact inference capture. Claude Code, Codex, OpenCode,
and Pi semantic capture is mandatory. Exact capture is also a supported 1.0
capability for traffic explicitly routed through the Archivist proxy or a supported
SDK hook, but it never claims to observe traffic that bypasses those integrations.
Phase 9 is therefore on the path to 1.0; a universal transparent proxy remains a
non-goal.

**Because:** the motivating outcome is the full corpus, but a harness transcript and
a provider exchange are not equivalent. Separate coverage prevents both silent gaps
and the impossible promise of observing uninstrumented traffic. **Rejected:** calling
harness transcripts “complete” — it hides transport omissions; requiring universal
interception — it is not portable or technically honest. **Enforced by:** an
acceptance test in which one provider exchange produces distinct, correlated
semantic and wire occurrences, plus a test in which bypassed traffic is reported as
`wire_coverage=unobserved`. **Revisit if:** all supported harnesses expose a stable,
lossless provider-event API that makes the proxy redundant.

### DN-2 · Language, toolchain, and workspace baseline — ASSERTED · stakes H · first needed: Phase 0

**Where:** `docs/plan/plan.md:89`, `docs/plan/plan.md:95`,
`docs/plan/plan.md:169`, `docs/plan/plan.md:316`<br>
**Plan says:** the implementation “should” be Rust and lists proposed libraries, but
the repository tree and Phase 0 already assume Rust.

**Proposed decision:** Use Rust 1.97.1, edition 2024, pinned in
`rust-toolchain.toml`; commit the workspace `Cargo.lock`. Use Tokio, Axum/Tower,
Serde, the AWS SDK behind the project storage trait, SQLite, Clap, and Tracing as
listed. Do not promise an older MSRV before 1.0; every release records its exact
toolchain.

**Because:** one Rust workspace shares protocol types across a low-footprint host
daemon and streaming server, and the required toolchain is installed in the build
environment. **Rejected:** Python — weaker single-binary distribution and more
runtime variability; Go — viable, but loses the shared Rust type/state-machine
implementation already chosen by the plan without providing a requirement-level
advantage. **Enforced by:** pinned toolchain, edition and `rust-version` workspace
settings, `cargo fmt --check`, Clippy with warnings denied, and the full workspace
test on one commit. **Revisit if:** a required supported platform cannot run the
Rust binary or the selected S3/TLS stack cannot pass its compatibility suite.

### DN-3 · Request framing, serialization, and signing surface — DEFERRED · stakes H · first needed: Phase 1

**Where:** `docs/plan/plan.md:104`, `docs/plan/plan.md:234`,
`docs/plan/plan.md:337`, `docs/plan/plan.md:837`<br>
**Plan says:** request framing and signature canonicalization will be decided by a
future ADR.

**Proposed decision:** `POST /v1/ingest` accepts exactly one occurrence as
`multipart/related`: part one is an envelope using RFC 8785 canonical JSON and part
two is the payload representation declared by the envelope. The envelope is limited
to 64 KiB, contains no floating-point values, and binds both uncompressed and stored
payload digests. Authenticate each attempt with an Ed25519 HTTP message signature
covering the method, route, canonical envelope digest, payload digest, uploader key
ID, and fresh authorization timestamp. The immutable envelope and occurrence ID do
not contain the per-attempt signature, so a stale retry can receive fresh
authorization without changing logical identity.

**Because:** multipart permits a small bounded envelope followed by a streaming body;
canonical JSON keeps fixtures language-neutral; separating immutable identity from
fresh authorization resolves the replay-window/retry conflict at
`docs/plan/plan.md:137` and `docs/plan/plan.md:342`. **Rejected:** envelope data in
HTTP headers — proxy limits are inconsistent; a custom binary frame — harder for
community implementations and debugging; byte-identical authorization on every
retry — it becomes invalid after the replay window. **Enforced by:** language-neutral
golden requests, a second standalone signature verifier, reordered/whitespace JSON
tests, and retry-after-window tests. **Revisit if:** multipart streaming cannot be
implemented without buffering by one of the two reference HTTP stacks.

### DN-4 · Identifier formats and collision behavior — DEFERRED · stakes H · first needed: Phase 1

**Where:** `docs/plan/plan.md:74`, `docs/plan/plan.md:76`,
`docs/plan/plan.md:234`, `docs/plan/plan.md:252`,
`docs/plan/plan.md:344`<br>
**Plan says:** the namespace components and hash inputs are named, but their formats,
canonicalization, and collision policy are not.

**Proposed decision:** Tenant and client IDs are issuer/generated UUIDv4 values;
generation and request IDs are UUIDv7 values frozen when the spool entry is created.
Harness IDs are registered lowercase ASCII slugs. Upstream session and artifact IDs
are bounded opaque UTF-8 byte strings and are not Unicode-normalized. Derive session,
artifact, and occurrence hashes from domain-separated, length-prefixed fields using
SHA-256. Derive occurrence ID from session hash, artifact hash, generation, range
kind/start/end, and blob digest. Store only hashes in key paths; keep original IDs in
the authorized occurrence body. Hostname never participates in identity. An existing
key with different canonical bytes is `integrity_conflict`, returns HTTP 409, stops
that source, and pages the operator; it is never overwritten as a duplicate.

**Because:** explicit byte encoding prevents delimiter, path, case, and Unicode
ambiguity, while origin client scope handles cloned session UUIDs. **Rejected:** raw
`host-session` keys — hostnames mutate and raw IDs are unsafe path components; a
single random occurrence UUID — retries cannot reproduce it after lost responses.
**Enforced by:** golden ID/key vectors, arbitrary-Unicode property tests, cross-tenant
collision tests, and incompatible-existing-object tests. **Revisit if:** the archive
must merge one physical installation identity across tenant migration; that needs an
explicit alias record rather than new hash rules.

### DN-5 · Canonical payload, compression, chunking, and hard limits — DEFERRED/SPIKED · stakes H · first needed: Phase 1

**Where:** `docs/plan/plan.md:78`, `docs/plan/plan.md:145`,
`docs/plan/plan.md:242`, `docs/plan/plan.md:293`,
`docs/plan/plan.md:343`<br>
**Plan says:** compare three chunk sizes and define limits later, without a decision
metric, time box, environment, or default.

**Proposed decision:** Define canonical uncompressed bytes as exact source slices for
file adapters and RFC 8785 JSONL projections for database adapters. Start with a
16 MiB target, complete-record boundaries, 256 MiB hard maximum for one record,
64 KiB envelope maximum, 100:1 expansion maximum, 15-minute request maximum, 8 MiB
multipart parts, and 16 in-flight uploads per server process. Limits are server
configuration that may be lowered; clients treat 413 as rechunkable only when a
record boundary permits it.

Run a two-day Phase 1 compression spike comparing uncompressed storage, pinned
single-threaded Zstandard, and server-side recompression. Measure ratio, ingest
throughput, maximum RSS, stored-byte equality across x86_64/aarch64, and compatibility
against the local reference store plus B2/ARMOR using synthetic fixtures. Decide
before the storage schema is committed. Default if inconclusive: store canonical
uncompressed bytes and allow transport compression; correctness beats an unstable
canonical encoding.

**Because:** content-addressing uncompressed bytes is only safe when every encoder
agrees on what those bytes are, and resource limits are security decisions rather
than tuning trivia. **Rejected:** “whatever gzip/zstd emits” — upgrades can produce
different stored bytes under one key; silently splitting a large structured record —
it destroys source fidelity. **Enforced by:** cross-platform golden fixtures,
oversized-record tests, decompression fuzzing, memory assertions, and the published
spike report. **Revisit if:** representative corpus storage cost or measured ingest
throughput violates the budget established by the spike.

### DN-6 · Portable S3 commit and concurrency contract — DEFERRED · stakes H · first needed: Phase 1

**Where:** `docs/plan/plan.md:143`, `docs/plan/plan.md:270`,
`docs/plan/plan.md:337`, `docs/plan/plan.md:367`,
`docs/plan/plan.md:840`<br>
**Plan says:** use the backend's strongest primitive and decide multipart behavior
later; it also allows `multipart_abort=unavailable` while the server flow depends on
uncommitted multipart data.

**Proposed decision:** The production S3 profile requires multipart create/upload/
complete/abort, `PUT`, `HEAD`, and `GET`; conditional create is an advertised optional
capability. MinIO is the local reference implementation. The server streams to an
uncommitted multipart upload and completes it only after all declared sizes and
digests verify. It writes blob first, then a canonical occurrence manifest. Use
conditional create when supported; otherwise overwrite the deterministic key and
report only logical idempotency. `HEAD` is a bandwidth optimization, never the race
guard. Existing compatible objects are success; incompatible objects are 409. Do not
add a server database or distributed lock. Server storage credentials can write the
raw prefix and read—but not write—the control prefix.

**Because:** this is the strongest portable contract that preserves stateless
replicas and prevents invalid claimed content from becoming visible. **Rejected:**
`HEAD` then `PUT` as exactly-once — concurrent replicas race; staging under random
keys plus a durable recovery queue — it creates server state; requiring conditional
create — it excludes the target B2 profile. **Enforced by:** concurrent MinIO and B2
tests, commit-boundary kill tests, IAM-policy tests, physical-version reporting, and
orphaned-multipart lifecycle verification. **Revisit if:** B2 gains verified atomic
conditional creation or the project elects to require it in a new storage profile.

### DN-7 · Linked-client trust, replay, rotation, and registry failure — DEFERRED · stakes H · first needed: Phase 1

**Where:** `docs/plan/plan.md:159`, `docs/plan/plan.md:239`,
`docs/plan/plan.md:342`, `docs/plan/plan.md:346`,
`docs/plan/plan.md:392`<br>
**Plan says:** signed S3 client records, delegation, cache behavior, rotation, and the
replay window will be designed later.

**Proposed decision:** Each client owns an Ed25519 key. A tenant authority signs
client, key, scope, delegation, and revocation records stored in S3; ingestion
replicas are configured with tenant authority public keys and have read-only control
prefix access. Request authorization is fresh per attempt with a five-minute window
and five-minute maximum clock skew; replay inside the window is harmless because the
operation is logically idempotent. Trust records cache for at most 60 seconds. When
the registry is unavailable, an unexpired cached record may be used; otherwise fail
closed with retryable 503. Revocation therefore has a documented 60-second maximum
propagation delay. Key rotation accepts old and new keys for 24 hours, and pending
immutable envelopes are authorized with the current request key. Relay authority is
the conjunction of tenant, origin, harness, and operation scopes, never a union.

**Because:** a signed registry keeps the server stateless without allowing a
compromised raw-data credential to authorize itself. Fresh outer authorization keeps
long-lived spool retries valid. **Rejected:** bearer tokens — replayable and weakly
bound to a host; mTLS-only — operationally heavy for public clients and relays; using
stale registry entries indefinitely — revoked clients remain trusted. **Enforced
by:** altered/stale/cross-tenant/revoked/delegation tests, registry-outage tests, and a
rotation test with a pre-rotation spool entry. **Revisit if:** an external OIDC/device
attestation service can provide the same origin/uploader delegation and offline
verification properties.

### DN-8 · Receipt, error, retry, and poison-item policy — DEFERRED · stakes H · first needed: Phase 1

**Where:** `docs/plan/plan.md:137`, `docs/plan/plan.md:153`,
`docs/plan/plan.md:347`, `docs/plan/plan.md:424`,
`docs/plan/plan.md:448`<br>
**Plan says:** errors are stable and retries use exponential backoff, but no error
classes determine acknowledgement, retry, pause, quarantine, or operator action.

**Proposed decision:** Receipts are canonical JSON signed by a configured server
Ed25519 key and bind tenant, request, occurrence, blob, object keys, result, and
commit time. A client acknowledges only after signature and identity verification.
Network errors, 408, 425, 429, and 5xx retry indefinitely while the spool entry is
retained, using full jitter from 1 second to a 15-minute cap. Validation 400/415 and
an unsplittable 413 quarantine that artifact and allow other sources to progress.
401/403 pause uploads until relinking or rotation. Integrity 409 stops the affected
tenant/source and requires operator action. A partial storage commit returns
retryable 503 without a receipt. The JSON error body always carries version, stable
code, retryable boolean, safe message, and request ID; it never echoes source data.

**Because:** without a poison policy one malformed historical record blocks the
entire largest-first queue, while treating integrity failures as retryable creates an
infinite overwrite loop. **Rejected:** fixed retry count — outages outlive arbitrary
counts; retry every non-2xx — permanent malformed data storms the server. **Enforced
by:** a status/error matrix test, poison-record continuation test, lost-receipt test,
and signature-negative receipt tests. **Revisit if:** deployments need a tenant-wide
maximum retry age, in which case expiration must become an explicit retention policy,
not implicit data loss.

### DN-9 · Client state ownership, configuration, scheduling, and disk caps — UNNOTICED · stakes H · first needed: Phase 5

**Where:** `docs/plan/plan.md:101`, `docs/plan/plan.md:129`,
`docs/plan/plan.md:439`, `docs/plan/plan.md:453`<br>
**Plan says:** SQLite WAL, atomic transitions, quotas, and high/low water behavior,
but not who may mutate one state directory or what the defaults are.

**Proposed decision:** One mutating process owns a client state directory, enforced
by an OS advisory lock; a second mutator exits 75 with a versioned JSON error, while
`status` uses a read-only SQLite snapshot. Use XDG config/state roots with TOML.
Precedence is non-secret CLI flags, non-secret environment, config file, then
defaults; secrets are accepted only by file/key-store reference. The daemon uses an
internal 15-minute loop with up to 10% jitter and never overlaps itself. Each cycle
first gives one chunk to every active source, then spends the remaining budget
largest-backlog-first with a per-source 256 MiB quantum. Default spool cap is 2 GiB
with a 5 GiB filesystem-free floor; stop discovering new payload bytes at either cap,
continue retrying existing entries, and resume below 80% of the cap and above the
floor.

**Because:** SQLite WAL does not define multi-process ownership, and an unbounded
backfill spool can disrupt the coding host it is meant to observe. **Rejected:** two
writers relying on SQLite serialization — filesystem scans and spool cleanup remain
racy; external cron-only scheduling — overlap and portability differ by host.
**Enforced by:** second-writer, crash-transition, disk-pressure, jitter, non-overlap,
and bounded-starvation tests. **Revisit if:** pilot measurements show 2 GiB cannot
keep one scheduling cycle fresh or supported hosts routinely have less than the free
floor.

### DN-10 · Build, release, deployment, and exposure path — DEFERRED · stakes M · first needed: Phase 0/7

**Where:** `docs/plan/plan.md:324`, `docs/plan/plan.md:414`,
`docs/plan/plan.md:515`, `docs/plan/plan.md:798`<br>
**Plan says:** add CI, signed binaries, a container, Compose, and Helm, but does not
choose the pipeline, image/version source, ingress default, or deployment rollback.

**Proposed decision:** Add an `agent-archivist-ci` Argo WorkflowTemplate in the
downstream GitOps repository, based on the available Rust verification and generic
container-build templates; do not add GitHub Actions. Tag source and binary releases
as `vMAJOR.MINOR.PATCH`; build the server image as
`ronaldraygun/agent-archivist:<same-version>` from
`containers/agent-archivist/VERSION`; never publish or deploy `latest`. The host
client is a user daemon; the server is an OCI container/Deployment. The Helm chart
creates no Ingress by default and has no unauthenticated mode. Production TLS may
terminate at the ingress or server, but readiness fails if the configured secure
path is absent. Actual cluster/namespace choices and credentials remain in the
private GitOps deployment, not this public repository. One-shot catalog work uses an
Argo WorkflowTemplate; periodic work uses a Deployment's internal loop, never a
Kubernetes Job or CronJob.

**Because:** this locks the environment's allowed build and deployment path while
keeping the public project portable. **Rejected:** GitHub Actions — prohibited and
not the deployment source; a public default Ingress — easy accidental exposure;
floating image tags — no deterministic rollback. **Enforced by:** repository lint,
chart tests, non-`latest` policy, TLS/auth startup tests, and a release smoke test from
tag to mirrored artifacts. **Revisit if:** the public project adopts an additional CI
system for outside contributors; it must remain non-authoritative for this
deployment.

### DN-11 · Retention, backup, rebuild, and deletion — DEFERRED · stakes H · first needed: Phase 7/10

**Where:** `docs/plan/plan.md:52`, `docs/plan/plan.md:537`,
`docs/plan/plan.md:558`, `docs/plan/plan.md:591`,
`docs/plan/plan.md:752`<br>
**Plan says:** retention and deletion will be designed later, and backup/restore will
be demonstrated, without a safe default or recovery command.

**Proposed decision:** Raw occurrences and blobs default to indefinite retention;
ingestion exposes no delete route. A production deployment must retain source copies
unchanged until it has a daily S3 inventory, an independent second failure-domain
copy or protected version history, and a successful quarterly sampled restore.
`archivist catalog rebuild --from-occurrences` rebuilds all indexes from S3. Deletion
is an offline administrator workflow: write an occurrence tombstone, honor legal
holds, wait 30 days, complete two independent full-reference scans at least 24 hours
apart, and only then delete an unreferenced blob. GC remains disabled by default.

**Because:** content-addressed blobs are shared, so an ordinary delete API can erase
other retained sessions; S3 durability is not evidence that restore semantics work.
**Rejected:** reference counts updated during ingest — they add mutable global state;
bucket lifecycle on raw blobs — it cannot see occurrence references. **Enforced by:**
catalog rebuild test, two-pass GC simulation, legal-hold test, and a restore drill
recorded before any source retention reduction. **Revisit if:** immutable per-tenant
retention law requires shorter default storage, in which case tombstone policy must
be part of linking and consent.

### DN-12 · Adapter parity oracle and supported-source policy — DEFERRED · stakes H · first needed: Phase 6

**Where:** `docs/plan/plan.md:466`, `docs/plan/plan.md:479`,
`docs/plan/plan.md:483`, `docs/plan/plan.md:491`,
`docs/plan/plan.md:539`<br>
**Plan says:** adapters have golden tests and a late migration comparator, but it
does not define supported source versions or which system proves parity.

**Proposed decision:** File adapters are byte-preserving: concatenating ordered
chunks for a generation must equal the captured complete-record prefix. Database
adapters emit versioned RFC 8785 JSONL projections and prove parity with allowlisted
row counts plus per-field digests from the same read transaction. Each adapter ships
an explicit supported source-schema range and fails closed on unknown schemas; it
never guesses columns. The adjacent private prototype is an inventory/coverage
oracle only, not a canonical projection oracle. Capture source counts, bytes, active
files, largest record, and detected schema versions before Phase 6 sizing; commit
only aggregated, non-sensitive results.

**Because:** a port can agree with itself and still omit old or large sessions.
Byte/field-level source oracles detect truncation without treating private prototype
behavior as a public standard. **Rejected:** harness export commands as the oracle —
they may truncate or transform; “latest schema only” — it silently abandons the
largest historical accounts. **Enforced by:** round-trip file tests, database
snapshot parity tests, unsupported-schema failures, large-field tests, and a living
adapter parity matrix. **Revisit if:** a harness publishes a stable, lossless export
contract with versioned compatibility guarantees.

## 2. First questions an implementer hits (dry run)

**Phase 0 walk.** A worker starts with `rust-toolchain.toml`, but must choose a Rust
version and edition (DN-2). Next comes the root `Cargo.toml`, where “should be Rust”
and the provisional crate count force language, dependency, and workspace decisions
the plan has not actually locked (DN-2). The third file is the CI entrypoint, but the
plan neither names the available Argo template nor the release/image version source
(DN-10). The fourth is `archivist-protocol/src/lib.rs`, which cannot define its first
public type until framing, canonical JSON, signing, and ID encodings are chosen
(DN-3, DN-4). The fifth is the synthetic fixture generator, which cannot produce a
golden blob until canonical bytes, compression, chunk sizes, and hard limits are
settled (DN-5). The worker has already become the architect before reaching a useful
vertical slice.

**Riskiest later phase (Phase 4).** Implementing `/v1/ingest` immediately asks whether
authorization can be refreshed without changing occurrence identity (DN-3, DN-7),
how an invalid stream remains uncommitted on B2 (DN-6), which storage failures retry
(DN-8), and what readiness means when the trust registry or S3 is unavailable
(DN-7, DN-8). The current “strongest supported primitive” wording cannot be translated
into one deterministic state machine.

**Fleet test:** fails. Any task for a Phase 1 ADR is explicitly a design call, and
Phase 0 tasks for workspace, CI, protocol fixtures, and synthetic data are blocked on
those calls. Locking DN-1 through DN-8 converts Phase 1 from architecture invention
into specification and conformance implementation. DN-9 through DN-12 remain named
human gates before their later phases.

## 3. Reality check and contradictions

| # | Claim | Where | Result | Note |
|---|---|---|---|---|
| R1 | The repo is greenfield and has no implementation code | `docs/plan/plan.md:89` | VERIFIED | Five tracked files, zero Rust/Go/Python/JS/TS source files |
| R2 | This public repo has independent history | `docs/plan/plan.md:84` | VERIFIED | Exactly one root commit; no private archive history |
| R3 | Rust is usable in the current build environment | `docs/plan/plan.md:91` | VERIFIED | `rustc` and `cargo` 1.97.1 are installed; `cargo` is the environment wrapper |
| R4 | A deployment-specific collector exists to compare during migration | `docs/plan/plan.md:541` | VERIFIED | Adjacent private prototype collector and ARMOR archive documentation exist |
| R5 | CI foundations exist for Rust and containers | `docs/plan/plan.md:324` | VERIFIED | Read-only inspection found generic Rust verification and container-build templates; no project-specific template exists yet |
| R6 | Forgejo is primary and the public mirror is current | repository state | VERIFIED | Local, Forgejo, and GitHub `main` were identical at review start |
| R7 | B2 and ARMOR satisfy the new portable storage contract | `docs/plan/plan.md:380` | UNVERIFIABLE-FROM-HERE | Prototype evidence exists, but the new contract and compatibility suite do not yet exist |
| R8 | Supported harness schemas can be projected losslessly | `docs/plan/plan.md:466` | UNVERIFIABLE-FROM-HERE | Requires the Phase 6 source metrics and parity matrix proposed in DN-12 |

**Contradictions and ambiguities:**

- `docs/plan/plan.md:91` says Rust “should” be used, while the repository tree and
  Phase 0 at `:169` and `:320` require it. DN-2 makes the effective decision explicit.
- `docs/plan/plan.md:137` says retries never regenerate timestamps, while `:342`
  requires a replay window. A byte-identical authorization eventually becomes stale;
  DN-3 and DN-7 separate immutable occurrence identity from per-attempt authorization.
- `docs/plan/plan.md:149` depends on abortable uncommitted multipart writes, while
  `:277` allows `multipart_abort=unavailable`. DN-6 makes multipart abort a production
  storage requirement.
- `docs/plan/plan.md:55` calls exact inference capture optional, Phase 9 builds it,
  and the 1.0 definition at `:872` omits it. DN-1 defines what 1.0 actually promises.
- `docs/plan/plan.md:161` gives an administrator control-prefix writes but does not
  state that the ingestion data-plane credential cannot write that prefix. DN-6 and
  DN-7 close the self-authorization path.

**Freshness:** the plan is dated the same day as its only implementation-plan commit,
and no code has appeared since. It is current, not stale.

## 4. Safety caps

| Cap | Result | Evidence |
|---|---|---|
| C1 observable acceptance for the central outcome | pass | Baseline requirements at `:25` and definition of done at `:872` |
| C2 destructive steps have backup, rollback, and trigger | pass, later detail required | Legacy writes freeze only after restore and the old archive is retained at `:539-566`; deletion is simulated before enablement at `:591-612` → DN-11 |
| C3 bounded first slice exists | pass | Two-replica, one-blob/two-occurrence slice at `:893-910` |
| C4 no high-stakes open fork on Phase 0–1 path | **TRIPPED** | Seven undecided ADRs at `:337-347`, plus asserted Rust at `:89-105` → DN-1 through DN-8 |
| C5 load-bearing claims hold | pass | No false checked claim; R7/R8 are future proof obligations, not asserted facts |
| C6 house rules respected | pass | No GitHub Actions, Job/CronJob, mutable cluster action, floating image, unsafe credential, force-push, or worktree is prescribed; DN-10 makes compliant paths explicit |
| C7 secrets/untrusted-input policy exists | pass | Required controls and blanket untrusted-data posture at `:734-756` |

## 5. Structural gaps that apply

- **1.2 Non-goals with rationale — PARTIAL.** The exclusions at
  `docs/plan/plan.md:58-65` are clear but do not state why or what reopens them.
- **1.4 Glossary — MISSING.** “Artifact,” “occurrence,” “generation,” “canonical,”
  “linked,” “origin,” “uploader,” and “complete” can be read differently.
- **2.1–2.5 Acceptance scenarios — PARTIAL.** The linked requirements and first slice
  list outcomes, but not named setup/action/pass/fail scenarios for happy, offline,
  machine, and corrupt-input paths.
- **3.2–3.6 Contract/concurrency/dependency detail — PARTIAL.** These reduce to
  DN-3 through DN-9.
- **3.8 Locked churn-magnets — MISSING.** Phase 1 intentionally defers them → DN-1
  through DN-8.
- **3.9 Open-question defaults — MISSING.** The decision queue at `:833-850` has
  resolve-by gates but no recommended defaults or deciding measurements.
- **4.1 Edge-case catalog — MISSING.** Edge cases appear throughout tests and risks,
  but there is no numbered resolution catalog an adapter/server worker can consume.
- **4.2–4.6 Failure, error, rollback, and degradation detail — PARTIAL.** The plan has
  strong fault points but lacks dependency-by-dependency behavior → DN-7, DN-8,
  DN-10, DN-11.
- **5.4 Phase entry criteria — PARTIAL.** Exit gates exist, but phases do not state
  the exact prior gate required on the same commit.
- **5.5 Size estimate — MISSING.** No phase has effort/LOC bounds or a cut line; source
  metrics are also absent → DN-12.
- **6.4 Port conformance from day one — PARTIAL.** The comparator arrives in Phase 8;
  adapter source parity should begin in Phase 6 → DN-12.
- **6.5–6.7 Stop-ship and evidence bundle — PARTIAL.** Tests are extensive, but the
  plan does not define the artifact bundle or state that every gate runs on the same
  commit.
- **7.1 and 7.6 Threat model/matrix — PARTIAL.** The plan schedules one but does not
  yet contain threat → vector → mitigation → test mappings.
- **8.1–8.4 Numeric resource and performance budgets — PARTIAL/MISSING.** “Bounded”
  is not a number; DN-5 supplies safe initial resource limits and a measurement gate.
- **9.2 and 9.4 Migration/cutover trigger — PARTIAL.** Shadowing and rollback are
  present, but no equivalence threshold, exact revert mechanism, or rollback trigger
  is locked → DN-10/DN-11.
- **10.1–10.3 Machine CLI surface — PARTIAL.** Command names exist, but config
  precedence, stdin/stdout, exit codes, TTY/ANSI, and error schema are not complete →
  DN-8/DN-9.
- **11.1–11.4 Risk decisions — PARTIAL.** The risk table is strong, but lacks
  likelihood/impact, Plan B, and reopen signals for its highest risks.
- **P.1–P.3 Port evidence — MISSING/PARTIAL.** Source metrics, a living parity matrix,
  and early private-prototype comparison are not yet Phase 6 entry gates → DN-12.
- **M.1–M.5 Migration safety — PARTIAL.** Restore and shadowing are present; backup,
  cutover thresholds, rollback triggers, and legacy retirement duration remain open
  → DN-10/DN-11.

## 6. What this plan gets right

- It separates content deduplication from provenance at
  `docs/plan/plan.md:76-80` and carries that distinction through commit order,
  receipts, tests, and migration. This prevents the most damaging logical shortcut.
- The blob-first/occurrence-second flow at `:143-157` and eight explicit crash points
  at `:688-701` give the implementation a real recovery model rather than generic
  “retry safely” language.
- The client owns durable progress while S3 owns accepted history (`:71-83`), so
  stateless server replicas are an invariant with a test, not a scaling aspiration.
- Largest-first historical capture is balanced with freshness and fairness at
  `:439-464`, and the adapter plan includes active rewrites, partial records, database
  allowlists, and missing-source coverage states.
- Security treats transcript content as both sensitive and untrusted at `:734-756`;
  it explicitly covers logs, metrics, panics, fixtures, source allowlists, encryption,
  supply chain, and downstream prompt-injection boundaries.
- The first slice at `:893-910` tests the core architecture with two replicas and both
  dedup dimensions before real harness complexity is introduced.

---

## Appendix A — Decision ledger

| # | Fork | State | Stakes | First needed | Where | Note |
|---|---|---|---|---|---|---|
| 1 | Stable 1.0 scope (1.6) | DEFERRED | H | P1 | `:46-56`, `:568-589` | Exact inference inclusion unclear → DN-1 |
| 2 | Language/runtime pin (1.1) | ASSERTED | H | P0 | `:89-105` | Rust assumed, not locked → DN-2 |
| 3 | Deployment units (1.2) | ASSERTED | H | P7 | `:31-44`, `:515-537` | Client/server units named; target/exposure open → DN-10 |
| 4 | Repo topology (1.3) | LOCKED | M | P0 | `:43-44`, `:84` | Public, independent history; Forgejo/mirror verified |
| 5 | Build/CI path (1.4) | DEFERRED | M | P0 | `:324-329` | Checks named, pipeline/image source absent → DN-10 |
| 6 | Version/release (1.5) | ASSERTED | M | P0 | `:218-232`, `:798-813` | SemVer stated; cut mechanism open → DN-10 |
| 7 | Source of truth (2.1) | LOCKED | H | P1 | `:71-83` | S3 raw; derived rebuildable |
| 8 | Storage engines (2.2) | LOCKED/ASSERTED | H | P2/P5 | `:72`, `:101` | S3 fixed, client SQLite asserted → DN-9 |
| 9 | Schema evolution (2.3) | RECOMMENDED | H | P1 | `:218-232` | Version axes good; additive/unknown rules incomplete → DN-3 |
| 10 | ID scheme/collision (2.4) | DEFERRED | H | P1 | `:234-268` | Inputs named, formats open → DN-4 |
| 11 | Serialization/wire (2.5) | DEFERRED | H | P1 | `:234-250`, `:337-347` | JSON schemas do not settle request framing → DN-3 |
| 12 | Retention/growth (2.6) | DEFERRED | M | P5 | `:52`, `:453`, `:558` | No numbers/default → DN-9/DN-11 |
| 13 | Registry staleness (2.7) | DEFERRED | M | P3 | `:163-164`, `:404` | Cache TTL and outage behavior open → DN-7 |
| 14 | Time/clock (2.8) | DEFERRED | M | P1 | `:244`, `:342` | Wall/monotonic/replay semantics open → DN-7 |
| 15 | Backup/restore (2.9) | RECOMMENDED | H | P7 | `:526-537` | Drill named, artifact/cadence absent → DN-11 |
| 16 | Idempotency/dedup (2.10) | LOCKED | M | P1 | `:76-80`, `:270-291` | Logical scheme strong; exact tuple → DN-4/DN-6 |
| 17 | Server concurrency (3.1) | LOCKED | H | P4 | `:71`, `:431-437` | Stateless multi-replica |
| 18 | Client concurrency (3.1) | UNNOTICED | H | P5 | `:101`, `:439-455` | One state directory writer not defined → DN-9 |
| 19 | Retry policy (3.2) | DEFERRED | M | P1 | `:448-449` | Backoff named, taxonomy absent → DN-8 |
| 20 | Ordering/delivery (3.3) | LOCKED | H | P1 | `:129-157`, `:688-701` | At-least-once transport, idempotent logical commit |
| 21 | Dependency failure policy (3.4) | UNNOTICED | H | P3 | `:143-157` | Registry/S3/telemetry modes incomplete → DN-7/DN-8 |
| 22 | Timeouts/budgets (3.5) | DEFERRED | M | P1 | `:145`, `:295-297` | No safe defaults → DN-5 |
| 23 | Client scheduling (3.6) | DEFERRED | M | P5 | `:450-453` | Lanes named, interval/overlap open → DN-9 |
| 24 | Shutdown (3.7) | ASSERTED | M | P4 | `:425` | Abort named, drain budget open → DN-5/DN-8 |
| 25 | Readiness/doctor (3.8) | ASSERTED | M | P4 | `:418`, `:454` | Surfaces named, dependency semantics open → DN-7/DN-8 |
| 26 | Rebuild/recovery (3.9) | RECOMMENDED | H | P7 | `:537`, `:597-609` | Rebuild source clear, command absent → DN-11 |
| 27 | Primary consumers (4.1) | ASSERTED | H | P0 | `:31-44`, `:454-455` | Service/client/script surfaces evident |
| 28 | Surface shape (4.2) | RECOMMENDED | H | P1 | `:418`, `:454` | Commands/routes named, flags/status incomplete → DN-3/DN-8/DN-9 |
| 29 | Error model (4.3) | DEFERRED | M | P1 | `:328`, `:424` | Stable codes promised, taxonomy absent → DN-8 |
| 30 | Config surface (4.4) | UNNOTICED | M | P5 | `:443` | Sources/precedence/secrets refs absent → DN-9 |
| 31 | Compatibility (4.5) | RECOMMENDED | M | P1 | `:218-232` | Major versions clear; field policy remains |
| 32 | Streaming/batching (4.6) | DEFERRED | M | P1 | `:149`, `:341` | Request framing open → DN-3/DN-6 |
| 33 | Logging (4.7) | LOCKED | M | P0 | `:83`, `:740-742` | Structured/content-free invariant |
| 34 | Agent output budget (4.8) | N/A | M | — | — | No archive-query/agent response surface in raw release |
| 35 | Auth model (5.1) | DEFERRED | H | P1 | `:104-105`, `:159-167` | Proof mechanism and roots open → DN-3/DN-7 |
| 36 | Authorization granularity (5.2) | DEFERRED | H | P1 | `:147`, `:401` | Relay scope combination open → DN-7 |
| 37 | Secrets path/injection (5.3) | RECOMMENDED | H | P3 | `:396-411`, `:738-752` | Never-log strong; injection surface open → DN-9/DN-10 |
| 38 | Exposure (5.4) | DEFERRED | H | P7 | `:515-525` | No ingress/default boundary → DN-10 |
| 39 | Untrusted input (5.5) | LOCKED | H | P0 | `:734-756` | Blanket policy and bounds |
| 40 | Audit (5.6) | ASSERTED | M | P7 | `:601`, `:752` | Audit named; event set open → DN-11 |
| 41 | Walking skeleton (6.1) | LOCKED | H | P0/P1 | `:893-910` | Exact two-replica invariant demo |
| 42 | Phase order/gates (6.2) | LOCKED | M | P0 | `:310-635`, `:637-661` | Dependency path and exits present |
| 43 | Rollout/rollback (6.3) | RECOMMENDED | H | P8 | `:539-566` | Legacy retained; trigger/mechanism incomplete → DN-10/DN-11 |
| 44 | Migration/cutover (6.4) | RECOMMENDED | H | P8 | `:539-566` | Shadow comparator strong, thresholds open |
| 45 | Observability (6.5) | RECOMMENDED | M | P4 | `:758-796` | Signals strong, thresholds later |
| 46 | Test oracle (6.6) | DEFERRED | H | P6 | `:506-513`, `:547-548` | Source parity not defined → DN-12 |
| 47 | Performance budget (6.7) | SPIKED/DEFERRED | M | P1/P4 | `:723-732`, `:787-796` | Measurement intent lacks contract → DN-5 |
| 48 | Human gates (6.8) | ASSERTED | H | P1 | `:833-850` | Gates named; defaults/decision owner absent |
| 49 | Task decomposability (6.9) | DEFERRED | M | P0 | `:337-347` | Phase 1 tasks are design calls; fleet test fails |

## Appendix B — Structural sweep

| ID | Item | Rating | Note |
|---|---|---|---|
| 1.1 | North star | PRESENT | Observable system outcome at `:11-27` |
| 1.2 | Non-goals with rationale | PARTIAL | Clear exclusions, sparse rationale/reopen rules |
| 1.3 | Hard requirements | PRESENT | Fixed decisions at `:67-87` plus linked normative requirements |
| 1.4 | Glossary | MISSING | Core identity/storage terms undefined in plan |
| 1.5 | Normative language | PRESENT | Linked requirements declare RFC 2119/8174 usage |
| 1.6 | What it is not | PRESENT | Deferred and non-goals at `:46-65` |
| 1.7 | Scope doctrine | PRESENT | Coordinated document change at `:86-87` |
| 1.8 | Self-contained background | PRESENT | Outcome and boundaries understandable without code |
| 1.9 | Date/revision history | PARTIAL | Current date present; no revision ledger |
| 2.1 | Named acceptance scenarios | PARTIAL | Requirements criteria and first slice, no scenario format |
| 2.2 | Pass and fail per scenario | PARTIAL | Exit gates have pass conditions, few explicit fail conditions |
| 2.3 | Happy-path scenario | PARTIAL | First slice implies it but lacks setup/action/pass/fail |
| 2.4 | Degraded/error scenario | PRESENT | Commit-boundary and outage tests |
| 2.5 | Machine-mode scenario | PARTIAL | `status --json` named, expected schema/exit absent |
| 2.6 | Success metrics | PARTIAL | Functional strong; performance/adoption unquantified |
| 3.1 | Component model | PRESENT | Diagram and crate ownership at `:111-214` |
| 3.2 | Data model/schema | PARTIAL | Field list exists; exact schema deferred |
| 3.3 | State machine/lifecycle | PARTIAL | Client/server flow present; explicit client states absent |
| 3.4 | Concurrency model | PARTIAL | Server locked; client writer ownership missing → DN-9 |
| 3.5 | Technology decisions/rationale | PARTIAL | Rust rationale present; choices provisional → DN-2 |
| 3.6 | Dependency contracts | PARTIAL | S3 capabilities present; failure behavior incomplete |
| 3.7 | File/module layout | PRESENT | Detailed tree at `:169-210` |
| 3.8 | Decisions locked in place | MISSING | Churn-magnets are future ADRs → DN-1–DN-8 |
| 3.9 | Open questions default/gate | PARTIAL | Gates present, defaults absent |
| 3.10 | Cross-cutting concerns | PRESENT | Security, tests, metrics, cancellation sections |
| 3.11 | Adjacent boundaries | PRESENT | Client/data/control/derived boundaries explicit |
| 4.1 | Edge-case catalog | MISSING | Cases dispersed across tests and risks |
| 4.2 | Failure modes/recovery | PARTIAL | Fault points strong; error-to-action matrix absent |
| 4.3 | Anti-pattern catalog | PARTIAL | Non-goals and rejected patterns dispersed |
| 4.4 | Error taxonomy | MISSING | Stable codes promised only → DN-8 |
| 4.5 | Rollback/state capture | PARTIAL | Legacy preservation good; exact trigger/mechanism open |
| 4.6 | Graceful degradation | PARTIAL | Spool/error behavior not dependency-complete |
| 4.7 | Invariants | PRESENT | Fixed decisions and fault assertions |
| 4.8 | Safe defaults | PARTIAL | Security posture strong; numeric/config defaults open |
| 4.9 | Proof obligations | PARTIAL | Exit gates and risks lack systematic revisit triggers |
| 5.1 | Named phases | PRESENT | Phases 0–11 |
| 5.2 | Completion per phase | PRESENT | Every phase has an exit gate |
| 5.3 | Walking skeleton | PRESENT | Exact first slice at `:893-910` |
| 5.4 | Entry gates | PARTIAL | Dependency graph present, phase-local entry gates absent |
| 5.5 | Size estimate | MISSING | No effort/LOC bounds or cut lines |
| 5.6 | Parallel/sequential tracks | PRESENT | Table and critical path at `:637-661` |
| 6.1 | Test strategy | PRESENT | Unit, property, conformance, fault, compatibility, load |
| 6.2 | Tests co-located | PARTIAL | Phase exits name tests; decisions themselves often do not |
| 6.3 | Property/fuzz tests | PRESENT | Protocol, IDs, compression, SQLite |
| 6.4 | Port conformance | PARTIAL | Comparator is late; source oracle undefined → DN-12 |
| 6.5 | Stop-ship gates | PARTIAL | Security has one; global release gate not explicit |
| 6.6 | All gates same commit | PARTIAL | Phase “committed artifact” does not require all evidence same SHA |
| 6.7 | Evidence bundle | PARTIAL | Reports named; retained artifacts/methodology incomplete |
| 7.1 | Threat model | PARTIAL | Required Phase 1 output, not yet present |
| 7.2 | Secrets handling | PARTIAL | Never-log/ref-only strong; locations/rotation open |
| 7.3 | Audit logging | PARTIAL | Never-log clear; positive audit event list absent |
| 7.4 | Untrusted input | PRESENT | Blanket raw-data and bounds policy |
| 7.5 | Supply chain | PARTIAL | Pinning/SBOM/scans named; update cadence absent |
| 7.6 | Threat matrix | MISSING | Threat list has no committed vector/mitigation/test matrix |
| 8.1 | Numeric budgets | MISSING | Only zero-loss is numeric → DN-5 |
| 8.2 | Benchmark denominator | MISSING | Representative measurements deferred |
| 8.3 | CI-gated benchmarks | MISSING | No regression threshold |
| 8.4 | Memory budget | PARTIAL | Bounded formula, no number → DN-5 |
| 8.5 | Scalability limits | PARTIAL | Physical dedup limit clear; throughput/client limits absent |
| 9.1 | Install/deploy path | PRESENT | Compose, Helm, service packaging with operator scenario |
| 9.2 | Migration plan | PARTIAL | Shadow/cutover present, keep/drop/reinterpret matrix absent |
| 9.3 | Compatibility stance | PRESENT | Independent version axes at `:218-232` |
| 9.4 | Rollout/rollback | PARTIAL | Rollback exercised, trigger/mechanism open |
| 9.5 | Data format compatibility | PARTIAL | Adapter tests named, supported versions open → DN-12 |
| 9.6 | Non-interactive mode | PARTIAL | Daemon/JSON named; prompt bypass not specified |
| 9.7 | Monitoring/alerting | PARTIAL | Signals present, health thresholds absent |
| 9.8 | Doctor/health | PARTIAL | Routes/command named, readiness semantics open |
| 10.1 | Dual output surfaces | PARTIAL | JSON named only for status/errors |
| 10.2 | Pipe/agent compatibility | MISSING | TTY, ANSI, stdin/stdout not addressed |
| 10.3 | Surface before code | PARTIAL | Command/route names, not signatures/flags/config keys |
| 10.4 | Versioning | PRESENT | Wire/data/package axes explicit |
| 10.5 | Token/output budget | N/A | Raw release has no query response returning transcript content |
| 11.1 | Risk register | PARTIAL | Strong risk/consequence/mitigation, no likelihood/impact rating |
| 11.2 | Plan B per top risk | PARTIAL | Some fallbacks; not systematic |
| 11.3 | Ambition calibration | PRESENT | First-release, deferred, non-goal boundaries |
| 11.4 | Known unknowns | PARTIAL | Decision queue lacks defaults/measurements |
| 11.5 | Incident named | N/A | Primarily greenfield; private incidents should not enter public plan |
| P.1 | Port source metrics | MISSING | Required by DN-12 before adapter sizing |
| P.2 | Living parity matrix | MISSING | Required by DN-12 |
| P.3 | Conformance from day one | PARTIAL | Protocol yes; adapter/private prototype later |
| P.4 | ABI/FFI stance | N/A | Behavior/data port, not ABI port |
| P.5 | File-format round-trip | PRESENT | Adapter reconstruction at `:715-721` |
| P.6 | Port order | PRESENT | File adapters, then database/Pi |
| P.7 | Feature flags | N/A | No compile-time parity gates planned |
| P.8 | Toolchain pin | PARTIAL | Rust proposed, not pinned → DN-2 |
| J.1 | Post-integration ownership | PRESENT | Client/server/S3/control/derived split |
| J.2 | Failure isolation | PARTIAL | Client spool strong; registry/storage behavior open |
| J.3 | Data ownership/conflict | PRESENT | S3/raw and deterministic identities |
| J.4 | Contract versioning | PRESENT | Version axes explicit |
| J.5 | End-to-end ownership | PARTIAL | Suites named, responsible component/process absent |
| J.6 | Coordinated rollback | PARTIAL | Legacy retained, deployment revert not locked |
| M.1 | Backup/restore before destructive step | PARTIAL | Restore gate present; backup artifact/cadence open → DN-11 |
| M.2 | Idempotent/resumable migration | PARTIAL | Ingest is resumable; cutover actions not enumerated |
| M.3 | Shadow/canary diff | PRESENT | Comparator and shadow client at `:545-556` |
| M.4 | Cutover/rollback trigger | PARTIAL | No numeric equivalence or trigger |
| M.5 | Post-cutover retirement | PARTIAL | Legacy retained for unspecified retention period |
