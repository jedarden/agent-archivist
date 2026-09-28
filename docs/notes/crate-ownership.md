# Crate ownership map

Authority: the [implementation plan](../plan/plan.md), Sections 4 and 6. This
map is the per-crate purpose and dependency-boundary statement that the Phase 0
exit gate requires ("every planned crate has an owner/purpose statement and no
circular dependency").

Crate boundaries are fixed through the first vertical slice. Consolidating or
splitting a crate requires benchmark or dependency-cycle evidence and updates
this map, the plan tree, and the manifests in the same commit; workers do not
collapse boundaries ad hoc.

## Workspace baseline

- Toolchain pinned to 1.97.1 in [`rust-toolchain.toml`](../../rust-toolchain.toml)
  (components: rustfmt, clippy); edition 2024; `Cargo.lock` is committed.
- Phase 0 delivered skeletons with **no external dependencies and no
  production behavior**, and the rule still governs what a not-yet-started
  crate may contain: it stays documentation-only instead of growing `todo!()`
  stubs that pretend to work. Landed behavior has since replaced the skeleton
  in the crates whose phase work has started (see the Landed state column
  below); each piece lands with the verification that gates it. External
  dependencies are introduced per phase the same way — pinned through
  `[workspace.dependencies]` in the root manifest, admitted by the license
  allowlist
  ([tools/license-allowlist.toml](../../tools/license-allowlist.toml)), and
  pinned in the committed lockfile. The client state database (`rusqlite`,
  bundled SQLite) is the first direct dependency, with its transitive tree
  enumerated in the allowlist.
- Shared lint baseline in the root manifest: `missing_docs = "warn"`,
  `unsafe_code = "forbid"`, clippy `all` and `pedantic` at `warn`, and
  `rustdoc::broken_intra_doc_links` denied (rustdoc runs outside clippy, so its
  lints must be denied in the manifest for `cargo doc` to be a gate rather than
  a source of warnings). Verification runs clippy with warnings denied.

## Layering

```text
layer 3  archivist-cli (composition root, binary: archivist)
           │
layer 2  archivist-server    archivist-client-core    archivist-storage-s3
           │                       │                        │
layer 1  archivist-auth ── archivist-storage ── archivist-adapter-sdk
           └───────────────────┴────────────────────────┘
layer 0  archivist-protocol

layer 2  archivist-adapter-{claude,codex,opencode,pi} → archivist-adapter-sdk
```

## Ownership

The Layer column uses the same zero-based topological numbering that
`tools/check-crate-graph.py` prints: a crate's layer is one above the highest
layer of its internal dependencies. `archivist-server` therefore sits at
layer 2 — its dependencies (`protocol`, `auth`, `storage`) all resolve at
layer 1 — not on a tier of its own above the client engine.

The Landed state column records what each crate carries at the commit that
last moved it: committed behavior gated by the verification baseline, not
declared intent. Move a crate's cell forward in the same commit as the work
it describes, and leave a not-started crate documentation-only per the
baseline rule above.

| Crate | Layer | Purpose | Owning phase | Internal dependencies | Landed state |
|---|---|---|---|---|---|
| `archivist-protocol` | 0 | Versioned wire types, validation, deterministic identifiers and object-key derivation, RFC 8785 canonical serialization, and the derived-record derivation cores (the usage-summary projection is the first; plan Phase 10) | 1 | none | Landed — Phase 1 core plus the Phase 10 usage-summary derivation and the Phase 9 capture and correlation types: the versioned wire types with validation, RFC 8785 canonical JSON, SHA-256, deterministic identifiers, object keys, and correlation minting, the inference capture artifact with its six closed event kinds, the read-side fold that reconstructs ordered artifact streams into first-class transport attempts (partial and failed attempts represented, retries never merged) with the `conformance-replay` corpus harness, and the content-free orchestrator-provenance correlation record with its self-verifying digest and relationship fold ([orchestrator correlation](orchestrator-correlation.md)), and the `redaction-v1` policy with its detector-corpus seam and the per-occurrence redaction transformation it feeds |
| `archivist-auth` | 1 | Ed25519 signing and verification, linked-client records, tenant authority chain, delegation, revocation and rotation epochs, receipt keys — the `archivist.control/v1` types of the [control trust](control-trust.md) family | 3 | protocol | Landed — Phase 3 record and primitive core: owned Ed25519 signatures over owned SHA-512, client identity, linked-client and authority-chain records with rotation epochs, delegation, revocation, and receipt keys, with the authority-rotation corpus replayed offline |
| `archivist-storage` | 1 | Capability model, capability probe, and the `RawWriteStore`, `ControlReadStore`, `ControlAdminStore`, `AuditRestoreStore` traits; streaming multipart writer over raw-write sessions; `inventory-v1` contract; disabled-by-default two-pass blob collection planner and execution evidence | 2 | protocol | Landed — Phase 2 contract: the capability model and probe, the four store traits, the streaming multipart writer over raw-write sessions, the `inventory-v1` contract, and the retention-aware two-pass collector with simulation, pre-delete revalidation, and canonical evidence |
| `archivist-adapter-sdk` | 1 | Adapter lifecycle, capability, status, discovery, and immutable-artifact projection interfaces; fingerprint allowlists; conformance suite; the Phase 9 expected-inference ledger and its capture-attempt alignment | 6D | protocol | Landed — Phase 6D interfaces published: the bounded, content-free status contract; the fail-closed fingerprint allowlist; the capability vocabulary and set; the discovery interface and bounded report; the generation-cause vocabulary and SID-004 immutable-chunk identification; the three-state lifecycle and idempotent close contract; and the CAP-002 adapter descriptor. Phase 9 added the content-free expected-inference ledger (`ExactOutcome`) and the capture-attempt alignment that joins the protocol's reconstructed attempts to it by the `(TraceId, InferenceRequestId)` pair — a bypassed exchange resolves `unobserved` with no fabricated attempt, an empty session stays `unknown`, and no API expresses a universal-completeness claim. The same phase publishes the per-route exact partition as the inference-coverage manifest (`coverage_manifest`): one bounded document naming, per instrumented client, the content-free observed/partial/failed/unobserved counts beside — never merged with — the semantic session states, plus the claimed routes, known bypasses, schema version, flush outcome, and the coverage-evidence digest a verification run records ([`inference-coverage-manifest.md`](inference-coverage-manifest.md)). The manifest-level adapter dependency boundary and the pre-1.0 workspace-version lockstep are pinned by the crate's dependency-boundary test. The Phase 6D conformance suite and its `synthetic_append_only` example, the file-source capture core (complete-record boundary selection, generation detection, sidecar relationships, opaque session-identity resolution), the Phase 9 first-party HTTP/1.1 transport with the OpenAI-compatible client and routed capture proxy, their exact-capture conformance suites and the compatibility registry a route earns a row in, the ephemeral flush-before-teardown gate, and the archive-level completeness report have since landed with their phases |
| `archivist-storage-s3` | 2 | Portable S3 implementation of the storage traits; `zstd-v1` commits; validate-before-complete multipart | 2 | protocol, storage, auth | Landed — six slices over the portable S3 seams: the validated configuration surface; the offline control administrator writing immutable families once and replacing current pointers only on a strictly higher signed epoch (the administrator act routes the authority's signed link approvals and revocations through it; `auth` joined the dependency list for those two publication types, no cryptography moved); the raw writer with `zstd-v1` content-addressed commits, conditional-create when the observed capability establishes it and deterministic overwrite otherwise, multipart sessions committed on exactly their own recorded commitments, and idempotent abort; the Phase 10 scoped catalog and derived writers over the two provisioned `put+list` identities; the replica's five bounded control reads over the dedicated read-only credential; and the offline lifecycle audit reporting the noncurrent accumulation STO-009 makes a deployment duty. Capability probing, the synthetic compatibility suite against the reference backend, the B2 and ARMOR qualification runs, and the ingest reads are the remaining work |
| `archivist-client-core` | 2 | Cursors, crash-safe spool, immutable envelopes with per-attempt re-authorization, freshness/backfill scheduler, receipts and acknowledgements, SQLite state | 5 | protocol, adapter-sdk | Landed — Phase 5: the crash-safe mode-restricted spool, SQLite (WAL) state with explicit migrations, the configuration loader (XDG-native TOML, flag/environment/file/default precedence, protected secret references, the stable exit-64 surface), the per-source backlog inventory, the two-lane freshness/backfill scheduler — spool drain first, one reserved chunk per active source, then largest-backlog-first under the 256 MiB per-source quantum, proven by deterministic starvation-bound simulations — the immutable upload retry state (identity frozen at spool creation, fresh per-attempt re-authorization, the full-jitter retry schedule to a fifteen-minute cap, restart-surviving quarantine), the nonoverlapping daemon loop, the operator report documents behind `status`, `verify-state`, and `run`, the nonmutating doctor, the durable receipt acknowledgement binding an authenticated receipt to its frozen request before the spool entry releases, and the registry-driven CLI parser, output envelope, and handler router; Phase 8's read-only archive inventory comparator (the pilot's coverage-gap evidence engine) arrived with its phase |
| `archivist-adapter-claude` | 2 | Claude Code: JSONL complete-record capture, sidecars, generation detection | 6A | adapter-sdk | Landed — Phase 6A opened: the Claude Code source adapter — environment and configured account-root discovery (`CLAUDE_CONFIG_DIR`, the home default) with the prototype's inventory exclusions (`memory/` directories, `.pre-union` files); tree-shape role mapping (session, subagent, tool-result, session-sidecar, unknown); the bounded-header dialect gate admitting `claude-jsonl-v1`/`claude-jsonl-v2` by the account-member discriminator and `claude-sidecar-v1` for single-object sidecars, failing closed on everything else; append-only complete-record capture over the file-core cursor with growth/replacement/truncation/tail-mismatch/rewrite generation detection; digest-sensitive whole-object sidecar capture; same-stem session-sidecar bindings stated only when the annotated transcript was discovered; and opaque harness/upstream session-identity resolution (`claude-code` harness). The Phase 10 usage projection reader landed with the deterministic catalog rebuild |
| `archivist-adapter-codex` | 2 | Codex: JSONL complete-record capture, sidecars, generation detection | 6A | adapter-sdk | Landed — Phase 6A: the Codex source adapter — `CODEX_HOME` (default `.codex` under the home directory) discovery admitting only the observed tree shapes; the shared `history.jsonl` prompt-history sidecar and the rollout session transcripts captured as separate artifact kinds on complete-record boundaries under the pinned dialect gate; the fail-closed fingerprint allowlist; inode/truncation/tail-mismatch/rewrite generation detection; and opaque harness/upstream session-identity resolution (`codex` harness) |
| `archivist-adapter-opencode` | 2 | OpenCode: read-only allowlisted database projection | 6B | adapter-sdk | Landed — Phase 6B in progress: the read-only store connection (driver read-only flag, five-second busy window, open-time outcomes in the closed `ScanClassification` vocabulary), the schema-version gate against the embedded allowlist with the fail-closed descriptor, the transactionally consistent snapshot over the five allowlisted tables, the allowlisted projection rendering one RFC 8785 canonical record per row with cells lacking a faithful canonical form failing closed, the parity evidence reconciling the Phase 6 parity tuple against direct database reads, and the assembled-reader fault suite (unknown schemas, locks past the busy window, stores vanishing mid-scan, permission denials); marathon-scale parity, growth, and resource-bound validation landed with it |
| `archivist-adapter-pi` | 2 | Pi: configured-root discovery, durable session formats, coverage gaps | 6C | adapter-sdk | Landed — Phase 6C: configured-root discovery (`PI_CODING_AGENT_SESSION_DIR`, `PI_CODING_AGENT_DIR`, the home fallback) reading only bounded headers and retaining unknown files as unsupported sources; append-only JSONL capture over the SDK file-core cursor with replacement, truncation, rewind, and rewrite opening new generations and torn tails measured, never captured; the immutable session-object digest probe where every digest change opens a new generation; and explicit ephemeral and no-session roots reported as coverage gaps |
| `archivist-server` | 2 | Stateless HTTP data plane: `/v1/ingest`, health, metrics, bounded middleware, commit ordering, signed receipts | 4 | protocol, auth, storage | Landed — Phase 4 bootstrap surface complete: the validated configuration, the pinned trust anchors, the shared replica state with the per-tenant readiness ledger, the registered metrics families with their Prometheus exposition, the four routes (`/health/live` process-only, `/health/ready` from the readiness ledger, `/metrics`, and `/v1/ingest` streaming through the bounded parse and transport decode into the blob → occurrence → upload-attestation commit with signed receipts and the `server.partial_commit` class when the provenance tail fails), the admission guards (sixteen-slot process cap, four-per-client share, sixty-per-minute burst-eight token bucket, fifteen-minute deadline), the cancellation-aware serve lifecycle with graceful drain and multipart abort, the bounded liveness probe behind the release image's HEALTHCHECK, and authority-chain verification through the bounded trust cache; the phase's resource-benchmark and data-path fuzz suites landed as its gate evidence |
| `archivist-cli` | 3 | `archivist` binary: the command surface pinned in [`tools/cli-commands.toml`](../../tools/cli-commands.toml) (run, daemon, inventory, status, verify-state, doctor, serve, probe, link request, admin, catalog rebuild); selects backend and adapters | 3, 5, 6, 7 | all of the above | Landed — the command-surface plumbing in `archivist-client-core::cli` (registry-driven strict parsing, the `archivist.cli-output/v1` envelope, `archivist.error/v1` diagnostics, handler routing); the offline administration control plane composed in the crate from the registered `admin.*` keys under the ingest-credential split, with `admin approve` (link-request validation, authority signing, and linked-client publication) and `admin revoke` proven over the control-admin seam, each with its registry result schema pinned (CLI-015); the Phase 5 operator surface (`daemon`, `run --once`, `inventory`, `status`, `verify-state`, `doctor`) and the Phase 4 `serve` composition attached at the binary — `serve` selects the concrete S3 raw-write and control-read identities and drives the server crate's compose/bind/serve lifecycle — with `probe` (the release image's HEALTHCHECK mechanism, RC-020) beside them; the deterministic catalog rebuild over the adapters' usage projections is production-bound at the binary with the offline audit/restore and dedicated scoped-writer identities, and its result schema is pinned |

## Boundary rules

1. `archivist-protocol` depends on no workspace crate; every other crate
   reaches the wire contract through it.
2. Only `archivist-cli` may depend on a concrete storage backend. The server
   depends on the storage traits only, so replicas compose any backend.
3. Source adapters depend on `archivist-adapter-sdk` only, never on each
   other, the client engine, storage, or the server. Harness-specific
   dependencies stay inside their adapter crate.
4. `archivist-client-core` never depends on `archivist-server` or on any
   storage implementation; client and server meet only through
   `archivist-protocol`.
5. Cryptography lives in `archivist-auth`; no other crate signs, verifies, or
   derives keys.
6. Library choices are not an excuse to expose SDK types across crate
   boundaries — protocol, storage, adapter, and state-machine interfaces are
   owned by this project (plan Section 4), so an implementation can be
   replaced without changing the wire contract.
7. `archivist-cli` composes; it holds no business logic that belongs in a
   library crate as a peer.
8. Derived-record derivations live in `archivist-protocol` as pure
   functions from an adapter projection's normalized reading to canonical
   record bytes — the record's types, digest construction, serialization,
   and object key are layer-0 wire material, so the derivation core is
   protocol's, not the producer command's. Reading harness-specific raw
   bytes into that normalized form is the adapter projections' job
   (`archivist-adapter-sdk` and its adapters); the `archivist catalog
   rebuild` composes storage read → projection → derivation and holds no
   derivation logic of its own. First instance: the usage-summary
   projection ([usage-summary schema](usage-summary-schema.md), plan
   Phase 10).

## Verification

Dependency analysis (cycle check, purpose statements, entry-point
documentation, path-dependency resolution):

```sh
python3 tools/check-crate-graph.py
```

Standard-library only, so it runs before any dependency is fetched. It exits 0
and prints the implied layers when the graph is acyclic, and 2 with a report on
stderr otherwise. Current state: 12 members, 25 internal edges, 4 layers,
acyclic.

Build and lint baseline:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

External dependencies now exist (see the workspace baseline), and the
committed lockfile pins their versions and checksums, so a clean checkout
builds reproducibly: the crates are fetched from the registry on first build,
and compiling the client state database's bundled SQLite adds a C toolchain
to the build prerequisites. The verification harness wires these into CI as a
separate work item.
