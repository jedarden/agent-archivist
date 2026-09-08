# Security policy

Agent Archivist centralizes coding-agent session histories — data that is
private by default and untrusted once stored. Security reporting for the
project itself follows this document.

## Supported versions

The project is design-stage: no production-ready client or server has shipped,
and no released version is deployed in production.

| Version | Supported |
|---|---|
| pre-1.0 releases | newest release only |
| 1.0 and later (planned) | newest minor release, plus its immediate predecessor for critical security and data-loss fixes for 90 days after supersession |

Once the version 1.0 storage layout exists, raw `v1` readers remain available
for rebuild and restore even after client and server support for a release
expires — archived data outlives the support window of the software that wrote
it.

Reports against the current design, the scaffolded workspace, and the protocol
contracts are welcome now, before any release exists to be affected.

## Reporting a vulnerability

Email **github@jedarden.com** with a subject beginning `[security]`.

Do **not** open a public issue, pull request, or forum post for a suspected
vulnerability. Keep the report private until a fix or mitigation is published.

Include what you can:

- the affected component (crate, protocol contract, or planned artifact);
- the exact commit hash or release version observed;
- a description of the issue and its security impact;
- a reproduction or proof of concept, crash output, or the relevant contract
  section;
- any suggested remediation.

**Reproductions must use synthetic data only.** The same content rules that
bind public contributions (see [CONTRIBUTING.md](CONTRIBUTING.md)) bind private
reports: do not include real transcript content, credentials, tenant
identifiers, or private infrastructure details. A report that would require
real session data to demonstrate should describe the mechanism and offer a
synthetic variant instead.

### What to expect

This is a single-maintainer project operating on a best-effort basis:

- acknowledgment target of **7 days**; if the fix is straightforward, the fix
  and disclosure may happen sooner;
- coordinated disclosure: publication of the fix, the advisory, and credit
  happens together after a fix or mitigation is available, on a timeline
  agreed with the reporter;
- credit in the release notes and advisory if desired; anonymous reports are
  fine.

## Scope

In scope:

- code and documentation in this repository;
- the protocol, identity, and storage contract designs in the plan, including
  their security consequences (replay, cross-tenant writes, digest confusion,
  decompression bombs, metadata leakage);
- published release artifacts and their signatures, once releases exist;
- the dependency and supply chain of published artifacts.

Out of scope:

- third-party agent harnesses, S3-compatible storage services, and other
  upstream software — report those to their maintainers;
- deployments of Agent Archivist operated by someone else — including loss or
  exposure of real archived transcripts — which is the operating party's
  incident, not a project vulnerability;
- the private, deployment-specific prototype this repository deliberately
  excludes (see the README).

## Verifying release artifacts

Once releases are published, every official archive, checksum manifest, and OCI
image digest is signed and must verify with the release public key committed to
this repository; see the [release process](RELEASE.md). Unsigned artifacts
claiming to be Agent Archivist releases should be treated as suspect and
reported as above.
