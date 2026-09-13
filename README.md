# Agent Archivist

Agent Archivist is a design-stage, open system for collecting complete coding-agent
session histories from many hosts into S3-compatible object storage.

The intended system has two deliberately small halves:

- a host client discovers and incrementally uploads transcripts from supported
  agent harnesses; and
- a stateless ingestion service authenticates linked clients, validates payloads,
  and writes content-addressed blobs and provenance records to object storage.

S3 is the durable source of truth. ARMOR can provide the S3-compatible encrypted
storage path for a deployment, but it is an integration rather than a requirement.
AWS S3, Backblaze B2, MinIO, Garage, and other compatible implementations should
be usable through the same storage contract.

This repository records the architecture before the private,
deployment-specific prototype is generalized. It contains no transcripts,
credentials, infrastructure inventory, or history copied from that prototype.

The Rust workspace is scaffolded: twelve crates with fixed boundaries, a pinned
toolchain, a committed lockfile, and no production behavior yet. The
[crate ownership map](docs/notes/crate-ownership.md) states each crate's
purpose, its phase, and its dependency boundary.

## Workspace

One command runs the whole verification baseline:

```sh
scripts/definition-of-done.sh --all
```

It covers formatting, Clippy with warnings denied, unit tests, rustdoc, the
crate purpose/cycle check, the dependency license gate, the error-code
registry gate, the metrics registry gate (name, unit, label, span, and
status conventions, the forbidden-label list, and export-name collision
checking), byte-exact regeneration and a content scan of the synthetic
fixture corpus, the requirement-verification register gate, the release
container baseline gate (version equality, digest-pinned bases, the
mtime-pinned reproducible install layer, the same-commit version rule),
a redacted
secret scan of the working tree and the git history, and a `cargo audit`
dependency audit.
The fast subset (`--fast`) is what the automation gate runs per change. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the lane layout and prerequisites.

Rust 1.97.1 (edition 2024) is pinned in `rust-toolchain.toml`; `Cargo.lock` is
committed.

## Documents

- [Implementation plan](docs/plan/plan.md) turns the requirements into phased
  deliverables, verification gates, and a public-release path.
- [Research findings](docs/research/transcript-archiving-findings.md) explains
  the observations and architectural conclusions behind the design.
- [System requirements](docs/notes/requirements.md) defines the normative
  behavior expected from the public implementation.
- [Error-code conventions](docs/notes/error-codes.md) define the versioned
  error namespace, bounded safe-message rules, retryability, HTTP and process
  exit mapping, correlation, and stream behavior, backed by the
  machine-checked registry in `tools/error-codes.toml`.
- [Configuration conventions](docs/notes/configuration.md) define the
  configuration-key naming, precedence, type, default, path, non-interactive,
  and secret-reference rules for every setting the public crates and
  commands read, backed by the machine-checked registry in
  `tools/config-keys.toml` and a tree scan that rejects literal values
  assigned to secret-reference settings.
- [CLI command conventions](docs/notes/cli.md) define the versioned command,
  flag, output-envelope, exit-code, non-interactive, and secret-argument
  contract of the `archivist` binary before command implementation, backed by
  the machine-checked registry in `tools/cli-commands.toml`, the
  `archivist.cli-output/v1` envelope schema, and a gate that proves the
  three flag namespaces disjoint and no secret value accepted as a literal
  argument.
- [Metrics conventions](docs/notes/metrics.md) define the metric, span,
  attribute, unit, histogram, status, and bounded-label contract for the
  client, server, adapter, storage, pilot, and exact-coverage signals,
  backed by the machine-checked registry in `tools/metrics.toml` and a gate
  that rejects forbidden high-cardinality and sensitive labels and proves
  the OpenTelemetry-to-Prometheus name translation injective, so exporters
  retain consistent names.
- [Control trust](docs/notes/control-trust.md) ties together the
  `archivist.control/v1` record family — linked-client, delegation,
  revocation, rotation, and receipt-key records under the control prefix —
  backed by the append-only record registry in `tools/control-records.toml`
  and a gate that proves the registry, the envelope's own registries, and
  the plan's object-key table and timing sentences one contract; the
  per-record contracts live in
  [control trust schemas](docs/notes/control-trust-schemas.md).
- [Release container conventions](docs/notes/release-container.md) define the
  `containers/agent-archivist/` baseline — the strict-SemVer `VERSION`
  record kept equal to the workspace version and moved only in the same
  commit, and the digest-pinned two-stage Dockerfile whose builder tag
  matches the pinned toolchain and whose single install layer pins every
  mtime it stamps (verified reproducible by a double-build digest
  comparison) — backed by a gate that walks the git
  history of both version records and structurally validates the
  Dockerfile.
- [Synthetic fixtures](docs/notes/fixtures.md) define the deterministic,
  seeded generator behind the `fixtures/synthetic/` corpus — normal,
  malformed, rewritten, and large synthetic sessions — its byte-exact
  regeneration gate, and the closed-vocabulary content scan that keeps
  private material out.
- [Requirement verification](docs/notes/verification.md) defines the stable
  requirement-to-test and operational-verification IDs, the
  machine-readable register mapping every normative requirement to its
  verifications, and the commit-keyed verification manifest whose absent,
  stale, cross-commit, or incomplete evidence is rejected for any
  requirement marked implemented.

## Governance

- [Contributing](CONTRIBUTING.md) — development environment, verification
  baseline, workspace rules, and how to propose changes.
- [Security policy](SECURITY.md) — supported versions and how to report a
  vulnerability.
- [Support policy](SUPPORT.md) — what is supported, for how long, and how to
  get help.
- [Release process](RELEASE.md) — versioning, release gates, signing, and
  distribution rules.
- [Code of conduct](CODE_OF_CONDUCT.md) — standards for participation in the
  project community.

## Design principles

1. Capture all durable agent sessions, not only sessions launched by an
   orchestrator.
2. Preserve original bytes and provenance independently.
3. Make retries harmless through deterministic object identity.
4. Keep ingestion replicas stateless and replaceable.
5. Give clients no general-purpose object-store write access.
6. Treat raw transcripts as sensitive, untrusted data.
7. Keep storage and protocols open, versioned, and vendor-neutral.

## Status

Architecture and requirements are established. The implementation workspace is
scaffolded and its crate boundaries are fixed; behavior arrives through the
phases in the [implementation plan](docs/plan/plan.md). No production-ready
client or server is included yet.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
