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
| `archivist-protocol` | 0 | Versioned wire types, validation, deterministic identifiers and object-key derivation, RFC 8785 canonical serialization, and the derived-record derivation cores (the usage-summary projection is the first; plan Phase 10) | 1 | none | Landed — Phase 1 core plus the Phase 10 usage-summary derivation and the Phase 9 capture types: the versioned wire types with validation, RFC 8785 canonical JSON, SHA-256, deterministic identifiers, object keys, and correlation minting, the inference capture artifact with its six closed event kinds, and the read-side fold that reconstructs ordered artifact streams into first-class transport attempts (partial and failed attempts represented, retries never merged), with the `conformance-replay` corpus harness |
| `archivist-auth` | 1 | Ed25519 signing and verification, linked-client records, tenant authority chain, delegation, revocation and rotation epochs, receipt keys — the `archivist.control/v1` types of the [control trust](control-trust.md) family | 3 | protocol | Landed — Phase 3 record and primitive core: owned Ed25519 signatures over owned SHA-512, client identity, linked-client and authority-chain records with rotation epochs, delegation, revocation, and receipt keys, with the authority-rotation corpus replayed offline |
| `archivist-storage` | 1 | Capability model, capability probe, and the `RawWriteStore`, `ControlReadStore`, `ControlAdminStore`, `AuditRestoreStore` traits; streaming multipart writer over raw-write sessions; `inventory-v1` contract; disabled-by-default two-pass blob collection planner and execution evidence | 2 | protocol | Landed — Phase 2 contract: the capability model and probe, the four store traits, the streaming multipart writer over raw-write sessions, the `inventory-v1` contract, and the retention-aware two-pass collector with simulation, pre-delete revalidation, and canonical evidence |
| `archivist-adapter-sdk` | 1 | Adapter lifecycle, capability, status, discovery, and immutable-artifact projection interfaces; fingerprint allowlists; conformance suite; the Phase 9 expected-inference ledger and its capture-attempt alignment | 6D | protocol | Landed — Phase 6D interfaces published: the bounded, content-free status contract; the fail-closed fingerprint allowlist; the capability vocabulary and set; the discovery interface and bounded report; the generation-cause vocabulary and SID-004 immutable-chunk identification; the three-state lifecycle and idempotent close contract; and the CAP-002 adapter descriptor. Phase 9 added the content-free expected-inference ledger (`ExactOutcome`) and the capture-attempt alignment that joins the protocol's reconstructed attempts to it by the `(TraceId, InferenceRequestId)` pair — a bypassed exchange resolves `unobserved` with no fabricated attempt, an empty session stays `unknown`, and no API expresses a universal-completeness claim. The manifest-level adapter dependency boundary and the pre-1.0 workspace-version lockstep are pinned by the crate's dependency-boundary test. The synthetic adapter example and conformance suite are the phase's open work |
| `archivist-storage-s3` | 2 | Portable S3 implementation of the storage traits; `zstd-v1` commits; validate-before-complete multipart | 2 | protocol, storage, auth | Landed — Phase 2 in progress: the portable S3 raw-write and control-admin stores, with `zstd-v1` content-addressed commits, validate-before-complete multipart, and scope-gated control-admin under corpus test; Phase 3 opened: the administrator act routes the authority's signed link approvals and revocations through the control-admin store (`auth` joined the dependency list for those two publication types; no cryptography moved) |
| `archivist-client-core` | 2 | Cursors, crash-safe spool, immutable envelopes with per-attempt re-authorization, freshness/backfill scheduler, receipts and acknowledgements, SQLite state | 5 | protocol, adapter-sdk | Landed — Phase 5 opened: the crash-safe mode-restricted spool, SQLite (WAL) state with explicit migrations, configuration, the per-source backlog inventory, and the two-lane freshness/backfill scheduler — spool drain first, one reserved chunk per active source, then largest-backlog-first under the 256 MiB per-source quantum, proven by deterministic starvation-bound simulations — plus the nonoverlapping daemon loop that paces the engine's cycles: fifteen minutes with up to ten percent jitter on monotonic timing, the first cycle immediate, never self-overlapping, stopping only on cancellation or a dead jitter source; discovery cursors, envelopes, and receipts/acks are the phase's open work |
| `archivist-adapter-claude` | 2 | Claude Code: JSONL complete-record capture, sidecars, generation detection | 6A | adapter-sdk | Phase 6A not started — documentation-only |
| `archivist-adapter-codex` | 2 | Codex: JSONL complete-record capture, sidecars, generation detection | 6A | adapter-sdk | Phase 6A not started — documentation-only |
| `archivist-adapter-opencode` | 2 | OpenCode: read-only allowlisted database projection | 6B | adapter-sdk | Phase 6B not started — documentation-only |
| `archivist-adapter-pi` | 2 | Pi: configured-root discovery, durable session formats, coverage gaps | 6C | adapter-sdk | Phase 6C not started — documentation-only |
| `archivist-server` | 2 | Stateless HTTP data plane: `/v1/ingest`, health, metrics, bounded middleware, commit ordering, signed receipts | 4 | protocol, auth, storage | Landed — Phase 4 opened: configuration, shared state, and control-trust wiring; the listener, routes, and metrics modules are the phase's open work |
| `archivist-cli` | 3 | `archivist` binary: the command surface pinned in [`tools/cli-commands.toml`](../../tools/cli-commands.toml) (run, daemon, inventory, status, verify-state, doctor, serve, link request, admin, catalog rebuild); selects backend and adapters | 3, 5, 6, 7 | all of the above | Landed — Phase 3 opened: command-surface plumbing in `archivist-client-core::cli` (registry-driven strict parsing, the `archivist.cli-output/v1` envelope, `archivist.error/v1` diagnostics, handler routing); the offline administration control plane composed in the crate from the registered `admin.*` keys under the ingest-credential split; `admin approve` (link-request validation, authority signing, and linked-client publication) and `admin revoke` landed and were proven over the control-admin seam, each with its registry result schema pinned (CLI-015); the production S3 transport the binary's handler registrations name is the phase's open work |

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
