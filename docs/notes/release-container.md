# Agent Archivist release container conventions

Status: accepted baseline · Last updated: 2026-09-12

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
to be interpreted as described in RFC 2119 and RFC 8174 when they appear in bold.

This document is the versioning and reproducibility contract for the
project's single release image: the grammar and authority of
`containers/agent-archivist/VERSION`, the rule that a release moves both
version records in one commit, and the properties that make the image
build a deterministic function of its inputs. The release *sequence* —
what a release contains, how it is tagged, signed, and announced — is
owned by [RELEASE.md](../../RELEASE.md); the repository layout is owned by
plan [Section 6](../plan/plan.md). This note is deliberately narrower: it
pins the baseline the gate can check on every commit, before any image is
published.

The artifacts are
[`containers/agent-archivist/VERSION`](../../containers/agent-archivist/VERSION)
and
[`containers/agent-archivist/Dockerfile`](../../containers/agent-archivist/Dockerfile);
`tools/check-release-container.py` (fast lane of
[`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh))
rejects a version file, Dockerfile, or commit history that violates any
rule marked enforceable below. When this document and the tool disagree,
the tool's pinned constants decide, and one of the two is wrong and must
be fixed in the same commit.

## 1. Scope and authority

- **RC-001** — The project publishes exactly one image lineage,
  `ronaldraygun/agent-archivist`, built from
  `containers/agent-archivist/Dockerfile` with the repository root as the
  build context. A second image is a new contract decision recorded here
  and in the gate in the same commit, not an incidental `containers/`
  subdirectory.
- **RC-002** — The image and its version records are the *package*
  release axis only. Data-format versions (envelope, occurrence,
  attestation, storage layout, adapter projection, derived pipelines) move
  independently of the image SemVer, exactly as RELEASE.md's versioning
  section and plan Section 7.1 require; nothing in this contract may be
  read as a data-format claim.
- **RC-003** — The Dockerfile **MUST** remain the complete and only build
  recipe for the image. No wrapper script, build hook, or out-of-tree
  patch participates in a released image; anything the image needs is a
  `COPY` from the repository or a pinned base layer.

## 2. The version record

- **RC-004** — `containers/agent-archivist/VERSION` contains exactly one
  line: a core semantic version `X.Y.Z` in ASCII digits with no leading
  zeros, followed by a single newline. Pre-release and build metadata
  **MUST NOT** appear: OCI tags cannot carry `+`, the release sequence
  (plan Section 13) uses plain `X.Y.Z`, and widening the grammar is a
  contract change recorded here with a gate update in the same commit.
- **RC-005** — The version in `VERSION` and the `[workspace.package]
  version` in the root `Cargo.toml` **MUST** be the same string, and every
  member crate **MUST** inherit it (`version.workspace = true`); no
  `crates/*/Cargo.toml` declares its own `[package] version`. The two
  records are one fact written twice, which is what makes the equality
  testable rather than aspirational.
- **RC-006** — A release tag has the form `vX.Y.Z` and **MUST** point at a
  commit whose `VERSION` is exactly `X.Y.Z`; a tag that does not match
  fails the gate (and, per RELEASE.md, the release gate proper).
- **RC-007** — Distribution follows RELEASE.md's rules verbatim: immutable
  SemVer tags only, never a mutable convenience tag and never a bare git
  SHA, and deployment manifests name an immutable SemVer tag matching
  `VERSION`. The gate polices the same-commit *movement* of the version
  (Section 3); the immutability of what has already been published is
  enforced by the registry, not re-derived here.

## 3. The same-commit rule

- **RC-008** — A change to the workspace version in `Cargo.toml` and a
  change to `containers/agent-archivist/VERSION` **MUST** land in the same
  commit. The gate walks the commit history of both files from the commit
  that introduced `VERSION` and rejects any commit at which the two
  records diverge — which is precisely a commit that moved one without the
  other. Reconciling a divergence afterwards with a second commit does not
  repair it: the divergent commit itself fails.
- **RC-009** — From its introduction commit onward, the `VERSION` record
  **MUST NOT** disappear from any later commit. Deleting the file is a
  contract change (this document plus the gate), never a cleanup.
- **RC-010** — The same-commit rule is scoped from the introduction commit
  because the version contract starts there. History before the first
  `VERSION` commit is grandfathered; history after it is fully policed,
  including merges and rebases rewritten after the contract landed.

## 4. The reproducible build

The acceptance property is: identical repository bytes, identical
Dockerfile, identical base digests, and one pinned `SOURCE_DATE_EPOCH`
(see RC-018) produce a bit-identical image digest from the same builder —
the comparison is two runs of one `docker build`, not
docker-versus-kaniko; the release workflow's build is deterministic on its
own terms and owns its own digest. The rules below are the
static, machine-checkable subset of that property; the double-build digest
comparison in Section 6 is its demonstration.

- **RC-011** — Every `FROM` reference **MUST** be digest-pinned:
  `name:tag@sha256:<64 lowercase hex>`. The digest is the pin; the tag
  documents what the digest is and **MUST** stay version-exact (never a
  bare name, never a convenience tag, never a floating suite alias) so
  that name and digest cannot drift apart in meaning. Moving a base is a
  reviewed change: update the digest and rerun the gate in the same
  commit. Digests are content-addressed per manifest, so the same
  reference resolves identically on every architecture the release
  workflow builds.
- **RC-012** — The build stage's base tag **MUST** be exactly
  `rust:<channel>-slim-bookworm`, where `<channel>` is the pinned channel
  in `rust-toolchain.toml`. Inside the container the image *is* the
  toolchain: `rust-toolchain.toml` is deliberately not `COPY`ied into the
  build, so no rustup download can occur and the toolchain cannot silently
  differ from the image. The gate cross-checks the tag against
  `rust-toolchain.toml`, so a toolchain bump that leaves the Dockerfile
  behind fails.
- **RC-013** — The runtime stage's base **MUST** be
  `debian:<major.minor>-slim` (both version components pinned) from the
  same distribution generation as the build stage, so the release binary's
  glibc and the runtime's glibc cannot diverge.
- **RC-014** — The image build invokes
  `cargo build --release --frozen --offline --bin archivist` and nothing
  else that compiles. `--frozen` is lockfile discipline; `--offline`
  proves the build performs zero crate-network access. The workspace is
  dependency-free today, which is what makes `--offline` honest; the first
  external dependency **MUST** land with vendored sources and a
  same-commit update to this rule's realization in the Dockerfile.
  `cargo install` and `rustup` invocations **MUST NOT** appear in any
  stage.
- **RC-015** — `COPY` is the only directive that moves build-context
  files into the image: `ADD` **MUST NOT** appear, so no URL fetch or
  archive extraction can smuggle non-reproducible bytes into a layer, and
  the `COPY` directives are the complete build-context contract — the
  repository root context minus everything they do not name never enters
  the image. The release binary itself crosses from the builder stage
  into the runtime stage by a different mechanism, because a plain
  `COPY --from=builder` **MUST NOT** appear: writing a file into a
  directory that exists in the base stamps that directory's mtime with
  the copy moment, the layer tar records it, and two builds of identical
  content ship two digests. The sanctioned crossing is the read-only
  bind mount consumed by the runtime stage's install RUN (RC-017), whose
  mtime pin (RC-018) covers everything the step stamps.
- **RC-016** — The build injects no timestamps, commit identifiers, or
  build-host names into the binary: the package version compiled in from
  `Cargo.toml` is the only version the binary carries. The image's
  `org.opencontainers.image.version` label comes only from the
  `AGENT_ARCHIVIST_VERSION` build argument, which the canonical invocation
  (Section 6) sets from the `VERSION` file content (RC-004).
- **RC-017** — The image has exactly two stages, named `builder` and
  `runtime`. The runtime stage installs no packages and adds exactly one
  layer: the install `RUN`, which bind-mounts the builder's release
  binary read-only
  (`--mount=type=bind,from=builder,…,ro,target=…`), `cp`s it to its
  destination, fixes its mode, and performs the RC-018 mtime pin. It then
  sets a fixed numeric non-root `USER` (`65532:65532`, the distroless
  nonroot convention — a numeric UID needs no `/etc/passwd` entry) and an
  exec-form `ENTRYPOINT` naming exactly the `cp` destination. A future
  stage that must install packages does it in one `RUN` combining the
  install with `rm -rf /var/lib/apt/lists/*` and the RC-018 mtime pin.
  Adding a stage is a contract change recorded here with a gate update in
  the same commit.
- **RC-018** — Wall-clock time is not a build input. Every `RUN` step
  **MUST** normalize the modification times of the files — and of every
  directory — it creates, modifies, or causes to be modified to
  `SOURCE_DATE_EPOCH` (POSIX `touch --date=@…`), and each stage
  **MUST** declare `ARG SOURCE_DATE_EPOCH`, which the canonical build
  (Section 6) sets to the commit timestamp of the tree being built. The
  install RUN's pin set is therefore fixed, not best-effort: the binary,
  its parent directory (the `cp` stamps it), and `/etc` and `/tmp` (the
  bind mount creates its target under `/tmp`, and the mount machinery
  stamps `/etc`; both directory mtimes land in the layer diff). The
  image config's `created` field and the layer history timestamps take
  the same epoch, and build attestations — whose manifests embed
  invocation metadata no tree can reproduce — are disabled
  (`--provenance=false --sbom=false`), matching the kaniko release
  workflow, which emits none. This is the rule that turns "the layers
  happen to be identical" into "the digest is a function of the tree":
  without it, two builds of identical content still produce different
  layer digests, because a layer tar records file mtimes — including,
  non-obviously, the mtimes of the directories a step writes into.

## 5. What is deliberately not yet true

The project is design-stage (plan Section 17): the binary the image
carries is the scaffold entry point and exits immediately. Accordingly:

- the image is not published anywhere yet; publication starts with the
  packaging releases of plan Section 13 (`0.4`/`0.5`), through the Argo
  release workflow described in RELEASE.md — never a local push, and never
  a mutable tag;
- there is no `HEALTHCHECK`: nothing serves an endpoint yet, and a
  healthcheck that probes nothing would be false evidence. One arrives
  with the `serve` command and this note's gate rules in the same commit;
- multi-architecture (`amd64`, `arm64`) builds are the release workflow's
  duty under the same contract — the digest-pinned references are
  manifest digests and resolve per architecture without Dockerfile
  changes.

None of these deferrals weaken the baseline: the version contract and the
reproducibility rules above are in force from the introduction commit.

## 6. Verification

`tools/check-release-container.py` runs in the fast lane of
[`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh) and
checks, offline and in seconds:

- the `VERSION` grammar (RC-004) and its equality with the workspace
  version and every member's inheritance (RC-005);
- the Dockerfile rules RC-011 through RC-018 — digest-pinned bases, the
  toolchain-tag cross-check against `rust-toolchain.toml`, the exact
  build invocation, `COPY`-only context, the bind-mount install RUN with
  its cp destination equal to the entrypoint and its RC-018 pin set
  covering the binary, its parent directory, `/etc`, and `/tmp`, label
  wiring, the fixed numeric non-root final user, and the
  `SOURCE_DATE_EPOCH` mtime discipline on every `RUN` — by structural
  validation of the Dockerfile, without building anything;
- the same-commit rule (RC-008 through RC-010) by walking the commit
  history of both version records from the introduction of `VERSION`, and
  the release-tag rule (RC-006) by resolving every `vX.Y.Z` tag against
  the `VERSION` content at its commit.

`--self-test` first validates the committed tree, then proves the
rejection paths — mutated version files, mutated Dockerfiles, and
synthetic divergent histories — the same way the other registry gates do.
Output is content-free: paths, versions, digests, and commit counts only.

The reproducibility property itself sits outside the per-commit
gate — the gate is offline, seconds-fast, and never builds anything. It is
demonstrated by building the image twice from the same tree — the second
build fully uncached — and comparing digests, running the canonical
invocation documented in the Dockerfile header (the same
`docker build --provenance=false --sbom=false` with both the version and
the epoch build arguments) twice with `--iidfile`:

```sh
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)"
for n in 1 2; do
  docker build --provenance=false --sbom=false $([ $n = 2 ] && echo --no-cache) \
    -f containers/agent-archivist/Dockerfile \
    --build-arg AGENT_ARCHIVIST_VERSION="$(cat containers/agent-archivist/VERSION)" \
    --build-arg SOURCE_DATE_EPOCH \
    --tag agent-archivist-verify:$n --iidfile build$n.iid .
done
diff build1.iid build2.iid && echo "reproducible"
```

codinghome has no docker daemon — only the client — so the comparison runs
wherever a BuildKit daemon exists. Today that is the lab machine, driven
over ssh from codinghome (which is where the baseline's mtime debugging
and the recorded verification below ran); from the first packaged release,
the release workflow's own build (RELEASE.md, release steps) is the
authoritative producer and can run the same double-build check before
publishing. Two builds from one tree under one builder produce one
digest; a divergence is a failed baseline change no matter which rule
loosened.

## Examples

The `0.1.0` baseline this note ships with: `VERSION` is `0.1.0`, the
workspace version is `0.1.0`, the build stage is
`rust:1.97.1-slim-bookworm@sha256:2775…bdd3` matching the pinned
`1.97.1` channel, and the runtime stage is
`debian:12.15-slim@sha256:8820…4171`. The double-build comparison above
was run on 2026-09-12, on the lab machine over ssh (codinghome has no
docker daemon), from a clean `git archive` of `main` at `328a774` with
`SOURCE_DATE_EPOCH` pinned to that commit's timestamp: both builds — the
second under `--no-cache`, recompiling every workspace crate — produced
the single digest `sha256:4bb784d9…cbc4c7`, which is what the
RC-015/RC-018 pin set buys. Getting there took the evidence path this
note records: the plain `COPY --from=builder` form was built first and
demonstrably diverged (`sha256:5216…d69` versus `sha256:ca8f…b88` from
one tree), and diffing the layer tars of a still-diverging successor
showed the two images differing only in the `/etc` and `/tmp` directory
mtimes — stamped one wall-clock second apart by the build itself — which
is why the install RUN pins all four paths. A hypothetical `0.2.0`
release bumps `Cargo.toml` and `VERSION` to `0.2.0` in one commit and
tags that commit `v0.2.0`; a commit that bumps only `Cargo.toml` is
rejected by the gate as a same-commit violation even if the next commit
repairs it.
