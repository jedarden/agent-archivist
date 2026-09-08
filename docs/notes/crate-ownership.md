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
- The scaffold intentionally contains **no external dependencies and no
  production behavior**. Phase 0 requires skeletons without placeholder
  production behavior: a crate whose phase has not started stays
  documentation-only instead of growing `todo!()` stubs that pretend to work.
  External dependencies are introduced per phase, pinned through
  `[workspace.dependencies]` in the root manifest, and land in the committed
  lockfile.
- Shared lint baseline in the root manifest: `missing_docs = "warn"`,
  `unsafe_code = "forbid"`, clippy `all` and `pedantic` at `warn`. Verification
  runs clippy with warnings denied.

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

| Crate | Layer | Purpose | Owning phase | Internal dependencies |
|---|---|---|---|---|
| `archivist-protocol` | 0 | Versioned wire types, validation, deterministic identifiers and object-key derivation, RFC 8785 canonical serialization | 1 | none |
| `archivist-auth` | 1 | Ed25519 signing and verification, linked-client records, tenant authority chain, delegation, revocation and rotation epochs, receipt keys | 3 | protocol |
| `archivist-storage` | 1 | Capability model and the `RawWriteStore`, `ControlReadStore`, `ControlAdminStore`, `AuditRestoreStore` traits; `inventory-v1` contract | 2 | protocol |
| `archivist-adapter-sdk` | 1 | Adapter lifecycle, capability, status, discovery, and immutable-artifact projection interfaces; fingerprint allowlists; conformance suite | 6D | protocol |
| `archivist-storage-s3` | 2 | Portable S3 implementation of the storage traits; `zstd-v1` commits; validate-before-complete multipart | 2 | storage |
| `archivist-client-core` | 2 | Cursors, crash-safe spool, immutable envelopes with per-attempt re-authorization, freshness/backfill scheduler, receipts and acknowledgements, SQLite state | 5 | protocol, adapter-sdk |
| `archivist-adapter-claude` | 2 | Claude Code: JSONL complete-record capture, sidecars, generation detection | 6A | adapter-sdk |
| `archivist-adapter-codex` | 2 | Codex: JSONL complete-record capture, sidecars, generation detection | 6A | adapter-sdk |
| `archivist-adapter-opencode` | 2 | OpenCode: read-only allowlisted database projection | 6B | adapter-sdk |
| `archivist-adapter-pi` | 2 | Pi: configured-root discovery, durable session formats, coverage gaps | 6C | adapter-sdk |
| `archivist-server` | 3 | Stateless HTTP data plane: `/v1/ingest`, health, metrics, bounded middleware, commit ordering, signed receipts | 4 | protocol, auth, storage |
| `archivist-cli` | 4 | `archivist` binary: collect, serve, link, admin, status; selects backend and adapters | 3, 5, 6, 7 | all of the above |

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

## Verification

Dependency analysis (cycle check, purpose statements, entry-point
documentation, path-dependency resolution):

```sh
python3 tools/check-crate-graph.py
```

Standard-library only, so it runs before any dependency is fetched. It exits 0
and prints the implied layers when the graph is acyclic, and 2 with a report on
stderr otherwise. Current state: 12 members, 24 internal edges, 4 layers,
acyclic.

Build and lint baseline:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

With no external dependencies, a clean checkout builds without network access.
The verification harness wires these into CI as a separate work item.
