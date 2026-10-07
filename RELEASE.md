# Release process

Releases run automatically after the complete verification and signing gates pass.
The project maintainer owns the release policy. They are published
from the authoritative Forgejo repository
(`https://git.ardenone.com/jedarden/agent-archivist`); the GitHub mirror
receives tags and artifacts automatically and is never published to directly.

No release is called production-ready solely because all crates compile. A
release states what it actually supports and what it does not.

## Versioning

- Package versions follow semantic versioning. The version lives in the
  workspace `Cargo.toml` and in `containers/agent-archivist/VERSION`, and the
  two change in the same commit as the release.
- Releases are annotated tags of the form `vX.Y.Z`. A tag that does not match
  `containers/agent-archivist/VERSION` fails the release gate.
- Pre-1.0 releases are previews: only the newest release is supported, breaking
  changes between releases are allowed without notice, and no minimum supported
  Rust version is promised. Every release records its exact toolchain;
  toolchain bumps are reviewed changes with the full conformance and
  compatibility suite.
- Package version is never a substitute for a data-format version. The wire
  route, envelope, occurrence, attestation, storage-layout, adapter-projection,
  and derived-pipeline versions move independently of package SemVer (plan
  Section 7.1). Readers retain support for old occurrence and attestation
  schema versions; unknown major versions fail closed.
- A published tag is immutable: it is never moved or rewritten, and history is
  never force-pushed.

The machine-checked baseline for this contract is
[docs/notes/release-container.md](docs/notes/release-container.md):
`tools/check-release-container.py` (definition-of-done fast lane) enforces the
`VERSION` grammar, its equality with the workspace version at every commit,
the same-commit rule over git history, release-tag matching, the
digest-pinned Dockerfile whose builder tag matches the pinned toolchain, and
the committed CycloneDX SBOM against the lock (RC-021 through RC-023;
RC-024 binds its digest into the verification manifest of release step 1).

## Release sequence

Releases follow the sequence fixed in the [implementation
plan](docs/plan/plan.md) (Section 13): `0.1` protocol preview through `1.0`
stable raw archive. Each release's notes must state:

- supported adapters and the exact source fingerprints they accept;
- supported storage profiles;
- known coverage gaps, including what remains explicitly unobserved;
- schema versions in effect; and
- the deduplication guarantees actually provided (logical versus physical).

The storage-profile registry is also the negative-claim gate for release
notes. AWS S3 and Garage are explicitly unqualified and deferred, and
excluded from the `1.0.0` claims: the records dated 2026-09-27 supersede
the `0.1.0` deferrals and govern the stable release. They are not
supported storage profiles and carry no deployment profile and no
capability claim in `1.0.0`. A later release may change either
disposition only by citing a new registry record produced by the complete
[community qualification run kit](docs/notes/community-qualification-kit.md);
S3 compatibility alone is not a support claim.

Backblaze B2 has a separate positive release gate because its synthetic lane
cannot establish live-provider behavior. Before a release names B2 as
supported, the maintainer must append the redacted `evidence = "live"` record
for that release and run:

```sh
python3 tools/check-storage-profiles.py --release <SemVer>
```

The command fails when the B2 live record is missing, belongs to another
release, or is the latest `unqualified` result. A synthetic report, a prior
release's live record, or prose in the B2 qualification note cannot satisfy
this gate.

## Release steps

1. **Qualify the commit.** The full verification baseline (see
   [CONTRIBUTING.md](CONTRIBUTING.md)) plus every phase gate in effect for the
   release target passes on the exact commit being released. The gate emits a
   `verification-manifest.json` keyed by the Git commit recording toolchain and
   dependency-lock digests, test and fuzz outcomes, benchmark results, storage
   capability reports, and SBOM and artifact digests (plan Section 10). A
   release gate fails if any required entry is missing or its evidence comes
   from a different commit.
   Run the storage-profile release gate for the exact version being released;
   in particular, `python3 tools/check-storage-profiles.py --release <SemVer>`
   must exit 0 before B2 appears in the support claims.
2. **Bump the version** in `Cargo.toml` and
   `containers/agent-archivist/VERSION` together, and commit.
3. **Tag** the release commit with the annotated `vX.Y.Z` matching the version
   file.
4. **Run the release workflow.** Release automation is an Argo WorkflowTemplate
   in the project's CI cluster — never GitHub Actions, and never a local
   developer machine. It:
   - cross-builds signed Linux binaries for `x86_64` and `aarch64` (glibc 2.31
     or newer) and attaches release archives and checksums to the Forgejo
     `vX.Y.Z` release;
   - builds and publishes the OCI images
     `ronaldraygun/agent-archivist:X.Y.Z` for Linux `amd64` and `arm64`; and
   - signs the OCI image digest and a release manifest with cosign. The
     release key is exposed to the release step by reference only; the public
     key committed to this repository verifies both signatures.
5. **Sign the evidence.** The release manifest includes the
   `verification-manifest.json` from step 1 and is signed with the release key.
6. **Verify before announcing.** Every archive, checksum manifest, and OCI
   digest verifies with the committed release public key; the release smoke
   test includes signature verification. An artifact that does not verify is a
   failed release regardless of how it was produced.
7. **Publish the notes** with the required contents above, linking the signed
   manifest.

## Distribution rules

- OCI artifacts carry immutable SemVer tags only. Mutable tags (`latest`) and
  bare git-SHA tags are never published, and deployment manifests name an
  immutable SemVer tag matching `containers/agent-archivist/VERSION`.
- Third-party adapters and integrations must not publish under the
  `ronaldraygun/agent-archivist` name.
- Supply-chain scans (dependency, license, secret, container) run on releases;
  findings are fixed or documented in the release notes before publication.

## Automatic release transaction

The main-push sensor invokes `agent-archivist-auto-release` in iad-ci. It
reserves the next patch in a version-only main commit, preserving an explicit
version increase, and runs the full existing CI on that exact candidate. A
failed candidate can leave a reserved version on main; it creates no release
tag or promoted image. A retry of that candidate reuses its version.

The successful candidate supplies the verification manifest and both glibc
2.31 archives to the publisher. Before any image upload, the existing
`tools/check-storage-profiles.py --release <VERSION>` gate must pass for that
exact candidate version. Both OCI platforms then build, execute their
version smoke check, and pass the container vulnerability scan. Only then may
the annotated tag, verified image signature, signed release manifest, immutable
SemVer image, and Forgejo release be published. The signed manifest binds the
exact source, both archive hashes, committed SBOM, verification manifest, and
both container scan reports, and the exact-release storage qualification with
its registry digest. A duplicate event verifies the published signatures,
evidence and every asset hash before becoming a no-op; any mismatch fails closed.

Automation preserves the release steps above; changing the wording of support
claims cannot bypass the storage-profile release gate. Missing live evidence
for the reserved version blocks tagging and publication. Synthetic results or
a prior version's qualification cannot satisfy that requirement. AWS S3 and
Garage remain unqualified.
Signing material is referenced through the release step's OpenBao-backed
Secret; `containers/agent-archivist/release.pub` is the verification key.
