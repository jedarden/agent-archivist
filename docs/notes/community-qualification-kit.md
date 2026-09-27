# Community qualification run kit

Status: accepted baseline · Last updated: 2026-09-27

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** are to be interpreted as described in RFC 2119 and RFC 8174 when
they appear in bold.

Authority: [storage profiles](storage-profiles.md) Sections 2–4 (the
SP-001…SP-008 procedure and the record), plan Section 7.7 (the S3 commit
and concurrency contract) and Section 10 (storage compatibility tests),
requirements OPS-006, PUB-002, and SEC-010, [SUPPORT.md](../../SUPPORT.md)
for what a qualification creates. The machine-readable record is the
append-only `[[records]]` array of
[`tools/storage-profiles.toml`](../../tools/storage-profiles.toml); the
gate is [`tools/check-storage-profiles.py`](../../tools/check-storage-profiles.py).

The [registry note](storage-profiles.md) defines the qualification
procedure and the record; what neither defines is *how* a contributor
executes a run. This kit is that self-service half: the fixture inputs a
run consumes (Section 4), the write-path suite with its expected outcome
branches (Section 2), the capability probe that reduces onto the five-axis
matrix (Section 3), the execution path over the workspace's public seams
and the report shape the record cites (Section 5), and the record template
with its acceptance checks (Section 6). The kit carries no evidence
itself — a run executed with it changes a profile's standing only through
a record, and until such a record exists `aws-s3` and `garage` stand
unqualified exactly as the registry says.

## 1. Who does what

SP-001 puts the evidence outside the project: the verification baseline is
credential-free by construction, so project automation never runs a
community profile and never holds an instance or credential for one.

| Side | Supplies |
| --- | --- |
| Community operator | a real instance of the backend, a dedicated bucket pair (or prefix-scoped equivalent) under their control, per-role credentials, and the machine that executes the run |
| The operator's driver | composes the public seams of Section 5, executes the three legs of Section 2, renders the report and transcript |
| Maintainer (on acceptance) | reviews the transcript's completeness and evidence, applies the record plus the SP-008 document edits, runs the fast lane |

Both sides stay inside the record's rules: SP-006 (no endpoints,
hostnames, bucket names, account or tenant identifiers, or credentials in
any committed record field — the transcript is attached to the
contribution, never committed), and SP-005 (a run that fails or could not
complete is recorded `unqualified` with the reason; unknown stays
unknown).

## 2. What a run executes — the suite, no subset waived

SP-003 requires the complete per-profile suite: the write-path exercises,
the enumeration fault-injection set, and the capability-probe reduction.
A qualification run has no smaller honest subset. The legs run in order —
the probe first, because the write-path exercises declare the
capabilities the probe observed, and the suite asserts the portable
contract *given* those declared capabilities. Any leg that fails, or any
observed behavior that contradicts a declared capability, fails the run:
the record it produces is `unqualified` with that reason (SP-005), and a
partial run qualifies nothing.

### Leg A — the write-path exercises

Seven scenarios, driven through the store's public commit paths
(`commit_manifest`, `write_manifest`, `begin_multipart`/`write_part`/
`commit_multipart`/`abort_multipart`) exactly as the in-repo synthetic
lane drives them ([`crates/archivist-storage-s3/tests/storage_compatibility.rs`](../../crates/archivist-storage-s3/tests/storage_compatibility.rs)).
The expected branch follows the declared `conditional_create` capability
and whether the run's configuration can read back existing-object
evidence (read-capable, or writer-only under the minimal write-only
grant):

| Scenario | Drive | Expected |
| --- | --- | --- |
| duplicate-request | two identical `commit_manifest` calls on one occurrence key | read-capable + supported: `Created` then `AlreadyPresent`; writer-only + supported: `Created` then `LogicallyCommittedUnknownPhysicalResult`; unavailable: both `LogicallyCommittedUnknownPhysicalResult` |
| equivalent-overwrite | two `write_manifest` calls, same deterministic key and bytes — a successful replay, never an integrity conflict | same branch table as duplicate-request |
| concurrent-writers | the same key committed from two independent threads | supported: exactly one `Created`, the rest `AlreadyPresent` (read-capable) or `LogicallyCommittedUnknownPhysicalResult` (writer-only); unavailable: every outcome `LogicallyCommittedUnknownPhysicalResult` |
| read-capable-conflict | existing bytes preloaded at the key; commit different bytes | read-capable + supported: `IntegrityConflict`, existing bytes untouched; writer-only + supported: `LogicallyCommittedUnknownPhysicalResult`; unavailable: `LogicallyCommittedUnknownPhysicalResult`, both writes land |
| multipart-abort | begin, write one part, abort, abort again | the repeat abort **MUST NOT** error; zero open uploads remain; zero objects exist |
| multipart-commit | begin, write one part, commit | `LogicallyCommittedUnknownPhysicalResult` (commit is unconditional); the bytes are stored with the declared checksum and version behavior |
| origin/relay-attestation | one source occurrence, two uploader attestation keys | each key independent: `Created` (supported) or `LogicallyCommittedUnknownPhysicalResult` (unavailable); exactly one object per key; the keys never collide |

The physical-version expectations that ride along with every scenario:

| Declared versioning | Expected physical history |
| --- | --- |
| `enabled` | every write leaves one distinct, stable version id; count equals writes |
| `disabled` | one object per key regardless of writes; no version ids |
| `unknown` | counts observed, no version-id claims |

Multipart is the profile question, not an axis to negotiate: a backend
that cannot begin/write/commit/abort is not a supported profile at all
(SP-004), and the run ends there with an `unqualified` record.

### Leg B — the enumeration fault-injection set

Plan Section 7.7's four faults — page mutation, duplicate pages, token
loops, concurrent writes — exercised by the suite's fault-injecting
enumeration source. The faults are injected into the enumeration source,
not the backend, so this leg is identical for every profile and runs
against the same in-repo enumeration suites that every full verification
run executes (catalog-source pagination and tamper detection, the
collection scanner's between-scan mutation detection). The live
instance's contribution is the unfaulted half: a real paginated
enumeration of the run's control prefix (duplicate keys across pages,
truncated pages, and looping continuations must surface as failures, not
be silently consumed), and the concurrent-writes observation of Leg A
against real storage.

## 3. The capability probe — the five-axis reduction

The probe is implemented, not described:
[`archivist_storage::probe`](../../crates/archivist-storage/src/probe.rs)
observes what a backend actually supports and reduces each fact
fail-closed — an unestablished fact reports the weakest value the model
has, never a guess. A driver implements the one-method
`CapabilitySource` trait against the live instance (its write-shaped
instrument **MUST** aim only at `ProbeKey`s in the reserved
`tenants/<tenant>/v1/probe/` namespace) and calls `probe::observe` to
bind the findings into a `CapabilityReport`.

| Axis | Established by | Reduction |
| --- | --- | --- |
| `conditional_create` | the probe's conditional-create instrument | `supported` when observed; `unavailable` when not |
| `stored_checksum` | the checksum form observed on stored bytes | the observed form (`sha256`, `md5`, `provider_specific`); `unavailable` when nothing verifiable |
| `versioning` | bucket configuration plus physical history over repeated writes | `enabled` or `disabled` when observed; `unknown` when not |
| `server_side_encryption` | the configured policy observed taking effect | `verified` when observed; `unavailable` when not |
| `multipart_commit_abort` | a full begin/write/commit/abort session | reported as `profile_supported`, not as a degradable axis — `false` means the backend is not a profile (SP-004) |

The record's `capability` table **MUST** be the report's observed matrix
(SP-007): all five axes, closed tokens, `multipart_commit_abort = "verified"`
on a qualified record — earned by the multipart scenarios completing, and
by nothing else.

## 4. Fixture inputs

The run's objects are fixed synthetic fixtures, identical to the
in-repo suite's, so a transcript is reproducible and purgeable by the
identity set alone. The identity set **MUST NOT** be substituted with
production tenant, client, or session values.

| Fixture | Value |
| --- | --- |
| tenant | `0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b` |
| client | `aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f` |
| harness | `synthetic` |
| session hash | `fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210` |
| occurrence (attestation source) | `0011223344556677001122334455667700112233445566770011223344556677` |
| occurrence (duplicate) | `1111111111111111111111111111111111111111111111111111111111111111` |
| occurrence (overwrite) | `2222222222222222222222222222222222222222222222222222222222222222` |
| occurrence (concurrent) | `3333333333333333333333333333333333333333333333333333333333333333` |
| occurrence (conflict) | `4444444444444444444444444444444444444444444444444444444444444444` |
| attestation (origin) | `9988776655443322110088776655443322110088776655443322110088776655` |
| attestation (relay) | `8877665544332211008877665544332211008877665544332211008877665544` |
| blob digest (`zstd-v1`) | `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` |

Object keys are the protocol's typed key constructors
(`OccurrenceObjectKey`, `AttestationObjectKey`, `BlobObjectKey`) under the
store's prefix — a driver **MUST NOT** hand-build key strings. The byte
fixtures per scenario:

| Scenario | Bytes |
| --- | --- |
| duplicate-request | `duplicate-request` |
| equivalent-overwrite | `equivalent-overwrite` |
| concurrent-writers | `concurrent-writers` |
| read-capable-conflict (preloaded / incoming) | `old-incompatible` / `new-compatible-length` |
| multipart-abort part | `abandoned-part` |
| multipart-commit part | `committed-part` |
| origin / relay attestation | `uploader=origin;request=request-origin` / `uploader=relay;request=request-relay` |

Isolation and hygiene:

- The operator dedicates a raw and a control bucket (or a prefix-scoped
  equivalent their backend enforces) to the run; the run writes only
  under `tenants/<tenant>/v1/raw/`, `…/v1/control/`, and the probe
  namespace `…/v1/probe/`.
- Credentials enter the driver as `env:`/`file:` references per
  [configuration conventions](configuration.md) (CFG-029), pairwise
  distinct per role, never literals in any committed file: a write-shaped
  role for the probe instrument and Leg A, a control-read role for
  Leg B, and a read-shaped role (or the operator's own S3 tooling) for
  the physical observations the report cites.
- Post-run cleanup is the operator's: the run's objects live only under
  the three prefixes above, so one purge — or one lifecycle rule on the
  probe namespace, as the probe module documents — removes every trace.

## 5. The execution path and the expected report shape

The workspace already carries every seam a live run needs; the driver
composes them and adds only the two things project automation cannot
hold: the live binding and the physical observation.

1. **Probe (Section 3):** implement `CapabilitySource` over the live
   backend; `probe::observe` yields the `CapabilityReport` — canonical
   RFC 8785 JSON bytes under `archivist.capability-report/v1`, bound by a
   `sha256:<hex>` `report_digest`. If `profile_supported()` is false,
   stop: the record is `unqualified` (SP-004).
2. **Declare:** build the store the deployment would build —
   `S3StorageConfig` (endpoint, region, path style, encryption policy,
   both buckets, per-role credential references) →
   `S3RequestBackend::raw_write(&config, &tenant)`, the production SigV4
   binding — and `.with_capabilities(report.capabilities())`. The
   composition is the one [`crates/archivist-cli/src/serve.rs`](../../crates/archivist-cli/src/serve.rs)
   already performs; the synthetic lane's `SyntheticBackend` is the seat
   the live binding now takes behind the same six-method
   `RawWriteBackend` seam.
3. **Execute Leg A** through the store's public commit paths, asserting
   the Section 2 branch table against the declared capabilities, and
   observing the physical facts (object counts, version ids, returned
   checksums) through the read-shaped role or tooling.
4. **Execute Leg B** and record its outcome.
5. **Render the report** — one line per run, the exact grammar the
   in-repo suite renders, with all seven scenario observations present:

```text
storage-compatibility profile=<key> conditional_create=<token> stored_checksum=<token> versioning=<token> server_side_encryption=<token> physical_versions=[<scenario>:<count>:[<version-ids>],…]
```

(See [the MinIO reference profile](minio-reference-profile.md) Section 7
for a real rendered line; the values above are placeholders, not
evidence.)

The transcript a contribution attaches **MUST** contain: the capability
report's canonical bytes and digest, the `profile_supported` answer, the
report line with every scenario observation, the Leg B outcome, the exit
status of each leg, and the repository revision the executed driver was
built from — which becomes the record's `suite_revision`. The transcript
itself is attached to the contribution, never committed (SP-006).

## 6. The record template and acceptance

A qualifying run files one record per profile, appended to the registry's
`[[records]]` array — never edited, only superseded by a later record on
the same profile:

```toml
[[records]]
profile = "<community profile key>"
date = "<ISO 8601 calendar date of the run>"
outcome = "qualified"
submitted_by = "<public contributor handle>"
suite_revision = "<repository revision the executed driver was built from>"
operator = "<who executed the run>"
capability = { conditional_create = "supported|unavailable",
               multipart_commit_abort = "verified",
               stored_checksum = "sha256|md5|provider_specific|unavailable",
               versioning = "enabled|disabled|unknown",
               server_side_encryption = "verified|unavailable" }
```

A run that failed, or could not be executed, files the honest negative —
and that is an accepted contribution too (SP-005):

```toml
[[records]]
profile = "<community profile key>"
date = "<ISO 8601 calendar date of the run>"
outcome = "unqualified"
submitted_by = "<public contributor handle>"
reason = "<why no capability claim exists — no capability fields on this shape>"
```

An optional free-text `note` field is allowed on either shape.

A qualified record changes standing, so it **MUST** arrive paired with
the SP-008 edits — the profile's row in the registry note's standing
table flips to `qualified` citing `record <date>`, and the README's
standing sentence follows. The gate rejects an unpaired registry: a
record whose note row still states the old standing is a failure, not a
staging state.

Before filing, the contributor runs locally with the record applied:

```bash
python3 tools/check-storage-profiles.py --self-test   # the record gate
scripts/definition-of-done.sh --fast                  # the full fast lane
```

Acceptance is the maintainer's confirmation that the transcript shows
SP-003 completeness (all three legs, no waived subset), that
`multipart_commit_abort = "verified"` is earned rather than declared
(SP-004), that the five-axis matrix is the probe's output with closed
tokens (SP-007), that no committed field carries an identifier shape
(SP-006), and that registry, note, and README agree (SP-008) — after
which the record lands and the profile's standing changes.

Standing decays exactly as the registry note's Section 4 states: a
storage-layout or protocol minor bump, or a suite revision change, leaves
the record standing on evidence from a world that no longer exists, and
the honest response is a new record — `unqualified` or a
re-qualification run. An integrity-conflict report downgrades standing
immediately.

## 7. What a run establishes, and what it does not

A qualified community profile enters the published compatibility matrix
(plan Phase 11) pinned to its suite revision and observed capability
report — reports against it are accepted and triaged (reproduced against
the reference profile, they are project bugs; profile-specific, they are
handled best-effort per [SUPPORT.md](../../SUPPORT.md)). It creates no CI
coverage, no hosting or service-level commitment, and no operator
documentation beyond the recorded capability report. The kit makes
executing the run possible; it does not qualify anything, and it does not
weaken the credential-free baseline that keeps the reference profile
honest: project automation never runs community profiles.
