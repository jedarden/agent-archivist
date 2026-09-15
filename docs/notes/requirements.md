# Agent Archivist requirements

Status: accepted baseline · Last updated: 2026-09-13

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
to be interpreted as described by RFC 2119 and RFC 8174 when they appear in bold.

## 1. Scope and goals

The system collects durable coding-agent session artifacts from linked clients,
preserves exact file-source bytes or exact versioned database-projection bytes plus
provenance in S3-compatible storage, and provides a stable foundation for later
redaction, indexing, reflection, evaluation, and dataset generation.

The first public release **MUST** include a host client, a versioned ingestion API,
a stateless ingestion server, and an S3-compatible storage implementation.

The raw ingestion path **MUST NOT** automatically train a model, alter prompts, or
feed archived content into an agent. Self-improvement workflows are downstream,
explicitly governed consumers.

## 2. Architecture

- **ARCH-001** — The ingestion server **MUST** be stateless between requests. It
  **MUST NOT** require a local database, persistent volume, leader, sticky session,
  or single replica for logical correctness.
- **ARCH-002** — S3-compatible object storage **MUST** be the durable source of
  truth for accepted blobs, occurrence manifests, and upload attestations.
- **ARCH-003** — Any healthy ingestion replica **MUST** be able to handle any
  request or retry.
- **ARCH-004** — Client cursors, the retry queue, and the pending upload spool
  **MUST** be durable client-side state.
- **ARCH-005** — Trust registration **MUST** live in an external identity/control
  plane or a signed/S3-backed registry, not authoritative process-local state.
- **ARCH-006** — ARMOR **MAY** implement the S3/encryption path, but clients and
  protocol schemas **MUST NOT** depend on ARMOR-specific behavior.
- **ARCH-007** — A backend capability matrix **MUST** distinguish portable S3
  requirements from optional conditional-create, checksum, object-lock, and
  versioning features.

## 3. Identity and linking

- **ID-001** — A client installation **MUST** generate a cryptographically random,
  persistent client ID and a proof-of-possession key pair.
- **ID-002** — A human-readable host name **MUST NOT** serve as the security
  identity or sole global namespace.
- **ID-003** — Linking **MUST** associate a client public key with a tenant and an
  authorization policy before ingestion accepts its payloads.
- **ID-004** — Every request **MUST** authenticate the linked uploader and bind the
  tenant, metadata, payload digest, request ID, and timestamp to its proof of
  possession.
- **ID-005** — The server **MUST** authorize an uploader to write for the declared
  origin client. A relay or mirror **MUST NOT** silently replace origin identity
  with its own.
- **ID-006** — Credentials **MUST** be revocable. The ingestion path **SHOULD** use
  short-lived authorization derived from a registered client key.
- **ID-007** — Replay protection **MUST** reject stale or altered authorization,
  while an identical authorized upload retried within policy **MUST** remain
  logically idempotent.
- **ID-008** — Object keys **MUST** be derived by the server. A client **MUST NOT**
  receive arbitrary bucket write access or select an unrestricted object key.
- **ID-009** — A client **MUST** pin a tenant authority root during linking and
  verify receipts through a tenant-authority-signed server receipt-key record.
  Receipt-key rotation **MUST NOT** invalidate retained receipts.
- **ID-010** — An authority-key rotation **MUST** publish one immutable link
  per retired authority key, addressed by the key it retires and signed by it,
  and verification of a tenant-authority-signed record **MUST** resolve the
  signer by walking the chain forward from the client-pinned root: a successor
  half verifies from its establishing link's instant, a retired half only
  inside the 24-hour signing overlap, a retired half's later signature fails
  closed, and no rotation invalidates a record that was verifiable at its own
  signing instant. The language-neutral replay vectors live at
  `schemas/v1/examples/control/authority-rotation-chain.json`.

## 4. Session and artifact identity

- **SID-001** — A logical session **MUST** be namespaced by tenant ID, origin
  client ID, harness ID, and the harness's upstream session ID.
- **SID-002** — Session UUID entropy alone **MUST NOT** be treated as global
  uniqueness across tenants, clients, and harnesses.
- **SID-003** — Source replacement, truncation, rewind, or incompatible rewrite
  **MUST** start a new artifact generation.
- **SID-004** — Each immutable chunk **MUST** identify its artifact kind,
  generation, byte or event range, ordering information, and canonical payload
  digest.
- **SID-005** — The occurrence ID **MUST** be a deterministic function of the
  session namespace, artifact identity, generation, range, and blob digest.
- **SID-006** — Importers and mirrors **MUST** preserve original provenance and
  record importer/uploader provenance independently.

## 5. Capture coverage

- **CAP-001** — The client **MUST** use adapter-specific discovery. It **MUST NOT**
  assume that orchestrator records cover interactive harness sessions.
- **CAP-002** — The initial supported adapter set **SHOULD** include Claude Code,
  Codex, OpenCode, and Pi, with a documented plugin interface for additional
  harnesses.
- **CAP-003** — File-based append-only transcripts **MUST** be chunked on complete
  record boundaries. An incomplete trailing record **MUST** wait for a later pass.
- **CAP-004** — An adapter for a database-backed harness **MUST** open the source
  read-only and emit only an allowlisted, versioned session projection. It
  **MUST NOT** upload the application database wholesale.
- **CAP-005** — Adapters **MUST** detect source truncation or replacement and
  preserve both generations.
- **CAP-006** — The client **MUST** persist an acknowledgement only after a durable
  server receipt covers the blob, occurrence manifest, and upload attestation.
- **CAP-007** — Ephemeral workers **MUST** emit or flush their transcript before
  source teardown if complete coverage is claimed.
- **CAP-008** — Exact provider request/response capture **MUST** be described as a
  separate capability from harness-semantic capture. When enabled, the two sources
  **SHOULD** be joined by explicit trace/request IDs.
- **CAP-009** — Ephemeral/no-session harness modes that cannot be captured **MUST**
  be detected, disabled by policy, or reported as a coverage gap.
- **CAP-010** — A source adapter **MUST** publish enough status to distinguish
  missing, unsupported, failed, partially captured, current, and fully backfilled
  states without exposing transcript content.

## 6. Backfill scheduling

- **SCH-001** — Before uploading new discoveries, the client **MUST** drain its
  durable pending spool.
- **SCH-002** — The client **MUST** inventory configured accounts/source roots and
  estimate unacknowledged bytes or records.
- **SCH-003** — Historical backfill **SHOULD** prioritize accounts with the largest
  measured unacknowledged history first.
- **SCH-004** — Each source **MUST** have a configurable byte/time quota so the
  largest history cannot starve smaller histories indefinitely.
- **SCH-005** — Every scheduling cycle **SHOULD** reserve capacity for recently
  modified active sessions before spending the remaining budget on historical
  backfill.
- **SCH-006** — Scheduling priority **MUST NOT** change object identity or final
  archive contents.

## 7. Payload and protocol validation

- **VAL-001** — The API and every envelope **MUST** carry explicit protocol and
  schema versions. Unsupported versions **MUST** fail closed with a machine-readable
  error.
- **VAL-002** — The server **MUST** validate identifier syntax and length, tenant
  authorization, media type, artifact kind, encoding, declared sizes, range
  consistency, and timestamp bounds before committing an occurrence.
- **VAL-003** — The server **MUST** enforce configurable compressed-size,
  uncompressed-size, expansion-ratio, request-duration, and metadata limits.
- **VAL-004** — The server **MUST** calculate and verify the digest of the canonical
  uncompressed payload while streaming it.
- **VAL-005** — A digest or size mismatch **MUST NOT** leave a committed blob under
  the claimed content address, occurrence manifest, or upload attestation.
- **VAL-006** — Compression **MUST** have a deterministic canonical form when its
  bytes are persisted beneath an uncompressed content address.
- **VAL-007** — Validation failures **MUST** return stable machine-readable error
  codes and **MUST NOT** echo transcript content.
- **VAL-008** — The server **SHOULD** use bounded-memory streaming or multipart
  upload and abort uncommitted parts on failure.

## 8. Storage and deduplication

- **STO-001** — A raw blob **MUST** be addressed by SHA-256 of its canonical,
  uncompressed bytes. An implementation **MAY** additionally verify a
  backend-native checksum of stored bytes.
- **STO-002** — A distinct occurrence manifest **MUST** be stored for every unique
  source occurrence, even when multiple occurrences reference one blob.
- **STO-003** — Blob, occurrence, and upload-attestation object keys **MUST** be
  deterministic and tenant-scoped.
- **STO-004** — Replaying the same valid request **MUST** converge on the same blob
  occurrence, and upload-attestation keys and **MUST NOT** create duplicate logical
  records.
- **STO-005** — Where atomic conditional create exists, the storage adapter
  **SHOULD** use it and treat “already exists” as successful deduplication after
  validating compatible object metadata.
- **STO-006** — Where conditional create is absent, deterministic overwrite **MAY**
  provide logical idempotency. Documentation **MUST** disclose that versioned
  stores can retain redundant noncurrent physical versions.
- **STO-007** — A preflight existence check **MAY** reduce bandwidth but **MUST NOT**
  be the only correctness mechanism.
- **STO-008** — The baseline stateless service **MUST NOT** add a database or
  distributed lock solely to promise physical exactly-once writes on an incapable
  backend.
- **STO-009** — Deployments using deterministic overwrite on a versioned backend
  **SHOULD** configure lifecycle expiration for redundant noncurrent versions,
  subject to retention policy.
- **STO-010** — An occurrence manifest **MUST** include its blob digest, logical
  session identity, source coordinates, origin, adapter/projection version, and
  schema version. Its canonical fields **MUST NOT** vary by uploader or upload
  attempt.
- **STO-011** — Raw blob, occurrence, and upload-attestation namespaces **MUST** be
  sufficient to rebuild catalogs and all derived indexes.
- **STO-012** — Derived artifacts **MUST** live under separate, pipeline-versioned
  prefixes and **MUST** retain references to raw occurrence IDs.
- **STO-013** — An upload attestation **MUST** bind an occurrence ID, origin,
  uploader, frozen request ID, capture/envelope timestamps, delegation relation, and
  schema version. Retries of one frozen request **MUST** converge to one attestation;
  a distinct authorized uploader/request **MUST** remain separately auditable.

## 9. Commit and receipt semantics

- **RCPT-001** — A request is successful only after the blob, occurrence manifest,
  and upload attestation are durably accepted by the configured storage path.
- **RCPT-002** — The receipt **MUST** contain tenant, request ID, blob digest,
  occurrence ID, upload-attestation ID, server-derived object keys, commit timestamp,
  and per-object storage outcomes.
- **RCPT-003** — Storage outcome **MUST** distinguish what the backend can actually
  establish, such as `created`, `already_present`, `replaced_equivalent`, or
  `logically_committed_unknown_physical_result`.
- **RCPT-004** — The server **MUST NOT** claim physical deduplication when the
  backend only guarantees logical overwrite.
- **RCPT-005** — If any required later write fails after an earlier blob or
  occurrence write succeeds, the request **MUST** fail without a receipt. Retrying
  the identical request **MUST** repair the partial commit.
- **RCPT-006** — Receipts **MUST** be authenticated through the tenant authority so
  a client can retain them as durable evidence of acceptance independently of the
  current endpoint or replica.

## 10. Security, privacy, and governance

- **SEC-001** — Transport **MUST** be encrypted and authenticated.
- **SEC-002** — Raw objects **MUST** be encrypted at rest by ARMOR, S3 server-side
  encryption, client-side envelope encryption, or an equivalently documented
  mechanism.
- **SEC-003** — Tenant authorization **MUST** be enforced before deriving or writing
  any tenant-scoped key.
- **SEC-004** — Operational logs, metrics, errors, and traces **MUST NOT** contain
  transcript bodies, authorization values, signing material, or raw prompt/tool
  content.
- **SEC-005** — Clients **MUST** support source-root allowlists and exclusions. The
  documentation **MUST** explain what each adapter captures.
- **SEC-006** — Credentials and signing private keys **MUST NOT** be stored in the
  repository, command-line arguments, or transcript fixtures.
- **SEC-007** — The project **MUST** define retention, legal hold, tenant export,
  and deletion semantics before claiming production readiness.
- **SEC-008** — Deletion logic **MUST** account for blobs referenced by more than one
  occurrence and **MUST NOT** remove shared content while a retained occurrence
  still references it.
- **SEC-009** — Raw archive data **MUST** be treated as untrusted input. Derived
  reflection or learning pipelines **MUST** perform redaction, provenance tracking,
  trust classification, and prompt-injection defenses before agent consumption.
- **SEC-010** — Public tests and examples **MUST** use synthetic data only.
- **SEC-011** — Administrative control mutation **MUST** run through a separate
  configuration surface with its own dedicated credential reference, and each
  configured storage role **MUST** map a distinct credential reference. A
  validated ingestion or replica configuration **MUST NOT** carry the
  control-administration credential.
- **SEC-012** — Control-record object keys **MUST** be derived by the control
  administrator from the validated record's own members, following the record
  registry's layout for its family. A record that does not carry its family's
  key grammar **MUST** fail closed, and no configuration or request **MUST**
  substitute an arbitrary key.
- **SEC-013** — An immutable control record (revocation, key rotation, receipt
  verification key) **MUST** be written once at its derived key: an
  incompatible object already at that key **MUST** fail closed as an integrity
  conflict, while a byte-identical replay **MUST** succeed idempotently without
  a second write.
- **SEC-014** — A current-pointer control record (linked client, delegation)
  **MUST** be replaced only when the presented record carries a valid signed
  authorization epoch strictly greater than the stored pointer's; an equal,
  lower, or invalid epoch **MUST** fail closed before any backend write, and a
  corrupt stored pointer **MUST** surface as an integrity conflict.
- **SEC-015** — The control-administration credential's backend permissions
  **MUST** allow exactly the pinned tenant's control prefix and **MUST** deny
  every other prefix — raw, catalog, derived, tombstone, legal-hold — and every
  other tenant's control prefix. A record outside that scope **MUST** be
  refused before any backend request is issued.
- **SEC-016** — The ingestion configuration **MUST** reject the
  control-administration credential reference offered in any ingestion role —
  raw writer, control reader, optional raw reader, offline restore — before
  a deployment is accepted.

## 11. Reliability and operations

- **OPS-001** — Client spool writes and cursor transitions **MUST** be crash-safe.
  A cursor **MUST NOT** advance past data without a durable receipt.
- **OPS-002** — Retries **MUST** use bounded exponential backoff with jitter and
  preserve the original deterministic request identity.
- **OPS-003** — An ingestion outage **MUST NOT** cause unbounded client spool growth;
  clients **MUST** expose limits and stop or degrade predictably.
- **OPS-004** — Health metrics **MUST** include per-adapter discovered, pending,
  acknowledged, failed, and estimated remaining counts/bytes without content.
- **OPS-005** — Server metrics **MUST** include authorization failures, validation
  failures, accepted bytes, storage latency/errors, retries, and reported dedup
  outcomes without high-cardinality session labels by default.
- **OPS-006** — Storage compatibility tests **MUST** exercise at least one reference
  S3 implementation and **SHOULD** exercise B2 plus a self-hosted implementation.
- **OPS-007** — Tests **MUST** cover lost responses, repeated requests, concurrent
  retries, blob-only and blob-plus-occurrence partial commits, attestation retry
  repair, active-file growth, incomplete trailing records, truncation, replacement,
  and relay upload.
- **OPS-008** — Backup/restore or replication procedures **MUST** be documented and
  verified before production-readiness claims.
- **OPS-009** — Object schema and protocol evolution **MUST** remain readable by at
  least one documented migration or compatibility path.

## 12. Public distribution

- **PUB-001** — The public repository **MUST NOT** share Git history with a private
  transcript archive.
- **PUB-002** — It **MUST NOT** contain real transcripts, private host inventory,
  internal endpoints, tenant identifiers, bucket names, or deployment credentials.
- **PUB-003** — The project **SHOULD** provide container images, a local Compose
  example, a Helm chart, and service definitions appropriate for common host
  operating systems as implementation matures.
- **PUB-004** — Configuration examples **MUST** be safe placeholders and **MUST NOT**
  default to public unauthenticated ingestion.
- **PUB-005** — Wire schemas, storage layout versions, adapter interfaces, and
  receipts **MUST** be documented independently of any one deployment.

## 13. Baseline acceptance criteria

A first end-to-end release is acceptable when all of the following are demonstrated
with synthetic fixtures:

1. Two linked clients can upload sessions with the same upstream session UUID
   without collision.
2. The same client can retry an identical chunk through different server replicas
   and produce one logical blob, one logical occurrence, and one upload attestation.
3. Two distinct occurrences with identical payload bytes produce one logical blob
   and two occurrence manifests, each with its own upload attestation.
4. A marathon JSONL session is archived incrementally without storing a partial
   final record, and resumes after a client crash without loss.
5. A truncated or replaced source becomes a new generation.
6. Origin and relay uploads of the same source event preserve one occurrence while
   recording distinct uploader/request attestations.
7. A blob/occurrence/attestation partial failure converges after retry.
8. The B2 compatibility suite reports honest logical and physical dedup semantics.
9. No server replica requires persistent local state, and replacement during
   retries does not change the result.
10. Logs and metrics remain content-free during success and forced error cases.

## 14. Release container baseline

The versioning and reproducibility contract for the single release image is
owned by [release-container.md](release-container.md); the requirement IDs
below are that note's rule numbers, kept identical so the verification
register maps one to one. The note's scope rules (RC-001 through RC-003) and
its distribution pointer (RC-007) are contract framing owned by the note and
[RELEASE.md](../../RELEASE.md) and carry no separate register entries.

- **RC-004** — `containers/agent-archivist/VERSION` **MUST** contain exactly
  one line: a core semantic version `X.Y.Z` in ASCII digits with no leading
  zeros, one trailing newline, and no pre-release or build metadata.
- **RC-005** — The `VERSION` record and the `[workspace.package] version` in
  the root `Cargo.toml` **MUST** be the same string, and every member crate
  **MUST** inherit it; no `crates/*/Cargo.toml` declares its own
  `[package] version`.
- **RC-006** — A release tag has the form `vX.Y.Z` and **MUST** point at a
  commit whose `VERSION` is exactly `X.Y.Z`.
- **RC-008** — A change to the workspace version and a change to the
  `VERSION` record **MUST** land in the same commit; any commit at which the
  two records diverge fails, and a later reconciling commit does not repair
  it.
- **RC-009** — From its introduction commit onward, the `VERSION` record
  **MUST NOT** disappear from any later commit.
- **RC-010** — The same-commit rule is scoped from the commit that introduced
  `VERSION`: earlier history is grandfathered, and later history — including
  merges and rebases rewritten after the contract landed — is fully policed.
- **RC-011** — Every `FROM` reference **MUST** be digest-pinned
  (`name:tag@sha256:<64 lowercase hex>`) with a version-exact tag that cannot
  drift from the digest in meaning.
- **RC-012** — The build stage's base tag **MUST** be exactly
  `rust:<channel>-slim-bookworm` for the channel pinned in
  `rust-toolchain.toml`, and the toolchain file **MUST NOT** be copied into
  the build.
- **RC-013** — The runtime stage's base **MUST** be
  `debian:<major.minor>-slim`, both version components pinned, from the same
  distribution generation as the build stage.
- **RC-014** — The build stage **MUST** invoke exactly
  `cargo build --release --frozen --offline --bin archivist` and nothing else
  that compiles; `cargo install` and `rustup` invocations **MUST NOT** appear
  in any stage.
- **RC-015** — `COPY` **MUST** be the only directive that moves build-context
  files into the image: `ADD` **MUST NOT** appear, and the release binary
  crosses from the builder stage by the read-only bind mount of RC-017,
  never by a plain `COPY --from=builder`.
- **RC-016** — The build **MUST NOT** inject timestamps, commit identifiers,
  or build-host names into the binary or the image config; the
  `org.opencontainers.image.version` label **MUST** come only from the
  `AGENT_ARCHIVIST_VERSION` build argument set from the `VERSION` content.
- **RC-017** — The image **MUST** have exactly two stages, named `builder`
  and `runtime`; the runtime stage installs no packages, adds exactly one
  layer (the install `RUN`), sets a fixed numeric non-root `USER`, and
  declares an exec-form `ENTRYPOINT` naming exactly the install destination.
- **RC-018** — Wall-clock time **MUST NOT** be a build input: every `RUN`
  **MUST** normalize the modification times of the files and directories it
  stamps to `SOURCE_DATE_EPOCH`, and each stage **MUST** declare
  `ARG SOURCE_DATE_EPOCH`.
- **RC-019** — Identical repository bytes, Dockerfile, base digests, and one
  pinned `SOURCE_DATE_EPOCH` **MUST** produce a bit-identical image digest
  from the same builder, demonstrated by the recorded double-build in
  [release-container.md](release-container.md) Section 6.
