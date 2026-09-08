# Support policy

Agent Archivist is a community-supported, single-maintainer open-source
project. Support is best-effort: there is no hosting, no service-level
agreement, and no paid support channel. The project is design-stage — no
production-ready client or server has been released yet.

## What is supported

### Today

- No released version is supported in production, because no production-ready
  version exists. Preview releases follow the sequence in the
  [implementation plan](docs/plan/plan.md) (Section 13), starting with the
  `0.1` protocol preview.
- Reports against the design, contracts, and scaffolded workspace are welcome
  at any time.

### Pre-1.0 releases

- Only the **newest** release receives fixes.
- Wire formats, storage layouts, and commands may break between releases
  without notice.
- No minimum supported Rust version is promised; every release records its
  exact toolchain.

### From 1.0 (planned)

- The **newest minor release** is supported.
- Its **immediate predecessor** receives critical security and data-loss fixes
  for **90 days** after it is superseded.
- Older releases are unsupported and should be upgraded.
- Raw `v1` readers remain available for rebuild and restore even after client
  and server support expires, so an archive remains readable after the software
  that wrote it ages out of support.

## Planned 1.0 support matrix

These are the targets fixed by the plan, not yet-shipped guarantees:

- **Platforms:** signed Linux binaries for `x86_64` and `aarch64` (glibc 2.31
  or newer) and Linux `amd64`/`arm64` OCI images. macOS and Windows are
  explicitly outside the 1.0 support matrix; source builds on those platforms
  do not imply support.
- **Harness adapters:** Claude Code, Codex, OpenCode, and Pi. Each released
  adapter names the exact source fingerprints it supports.
- **Storage profiles:** the local reference S3 implementation (MinIO), Backblaze
  B2, and the ARMOR S3 path, with optional community profiles for AWS S3,
  Garage, and other compatible implementations.

The published compatibility matrix lands with version 1.0 (plan Phase 11) and
becomes the authoritative statement of supported adapters, storage profiles,
and coverage guarantees per release.

## Getting help

- **Bugs, documentation gaps, and feature discussion:** open an issue on
  Forgejo (`https://git.ardenone.com/jedarden/agent-archivist`), the
  authoritative repository. The GitHub mirror is read-only.
- **Anything sensitive:** email **github@jedarden.com**.
- **Security vulnerabilities:** follow the [security policy](SECURITY.md) —
  never a public issue.

Good bug reports state the commit or version observed, the platform, what
happened, what was expected, and a synthetic reproduction if possible. Reports
must not include real transcript content or credentials; see
[CONTRIBUTING.md](CONTRIBUTING.md) for the content rules.

## What is not offered

- A hosted or managed service.
- Support for deployments operated by third parties beyond fixes in the
  project's own code.
- Migration assistance from arbitrary third-party transcript archives.
- Support for harness versions or storage backends outside the published
  compatibility matrix (once published) — an unsupported source is reported as
  `unsupported`, never best-effort parsed.
