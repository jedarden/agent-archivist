# Image smoke — health, secret, vulnerability, signature-input, multi-replica

The acceptance property this note owns (plan Section 13 release sequence;
parent bead `aa-580ffbb2`): the hardened server image **passes health,
secret, vulnerability, signature-input, and multi-replica smoke tests
within the four-vCPU and 512 MiB reference limits**. One harness exercises
all five categories against **one** image built from **one** clean
git-archive extraction on a BuildKit host:

- `containers/agent-archivist/smoke.sh` — the orchestrator: builds (or
  reuses) the image, then runs the five categories and a summary;
- `containers/agent-archivist/smoke-attempt-driver.py` — the signature and
  scanning instrument: mints a fresh signed ingest attempt, places the
  control-corpus pointer objects, inventories and byte-scans a `docker
  save` extraction, and self-proves its own signing against the committed
  corpora.

The five categories are acceptance gates for the image contract, not a
test suite of the server: everything they assert is either already
machine-checked elsewhere (the DoD gates, the conformance and control
corpora) or is only observable when a real image serves real traffic on a
real S3 backend. The harness therefore proves the *composition* — the
committed binary inside the committed image against the reference
backend — and records what that composition can and cannot yet answer.

## 1. Invocation

The harness runs **on the BuildKit host**, from the extraction, never from
a working tree — the same discipline as the reproducibility double-build
(release-container.md Section 6), and for the same reason: the image must
come from committed bytes, not from whatever is dirty in a checkout.
codinghome has no docker daemon; the lab machine is the builder, reached
over ssh per that section's precedent.

```console
$ D=$(mktemp -d) && git archive HEAD | tar -x -C "$D"
$ scp -q -r "$D" builder:/tmp/smoke-tree
$ ssh builder "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD) \
    bash /tmp/smoke-tree/containers/agent-archivist/smoke.sh"
```

The extraction carries no `.git`, so the one build input the canonical
invocation (RC-011..RC-019) cannot derive itself arrives through the
environment: `SOURCE_DATE_EPOCH`, the commit timestamp of the extracted
tree. Every other build input — base digests, version label, SBOM
document, build args — is already pinned in the tree, and the build stage
runs the Dockerfile's canonical invocation shape (`--provenance=false
--sbom=false`, `AGENT_ARCHIVIST_VERSION`, `SOURCE_DATE_EPOCH`).

Builder-host prerequisites: docker with BuildKit, `curl`, `python3`,
`tar`, `sha256sum`, `openssl`; for the vulnerability category, `grype`
(its absence degrades that one category to a recorded GAP — never a
silent pass). The python needs nothing beyond the standard library: where
the `cryptography` wheel is absent the driver installs a stand-in for
exactly the raw-Ed25519 surface the corpora generators touch, backed by
its own RFC 8032 implementation, so the derived publics and signatures are
bit-identical to the wheel's and anything beyond that surface fails
loudly; where the host `openssl` is too broken to answer
`openssl rand -hex` (the reference provisioner's mint invocation), the
run ships a stand-in on PATH implementing exactly that one invocation
and failing loudly for anything else. The live categories fetch the
pinned MinIO reference binaries once per work directory and SHA-256-verify
them against the pins in `minio-reference-profile.md` Section 1 before
use (the release asset name puts the platform first:
`minio.linux-amd64.<RELEASE>`).

Knobs (environment variables, all defaulted):

| Knob | Default | Meaning |
|---|---|---|
| `SMOKE_IMAGE` | `agent-archivist-smoke:smoke` | image tag built and exercised |
| `SMOKE_WORK_DIR` | `mktemp -d` | scratch root (MinIO data, creds, layers, records) |
| `SMOKE_SKIP_BUILD` | `0` | `1` re-exercises an existing image (iteration aid) |
| `SMOKE_KEEP_ON_FAIL` | `0` | `1` keeps the work dir and image on failure for diagnosis |
| `SMOKE_KEEP_IMAGE` | `0` | `1` keeps the image even on success |
| `SMOKE_PORT_MINIO` / `_R1` / `_R2` | 19000 / 18087 / 18088 | loopback ports (MinIO, replica 1, replica 2) |
| `SMOKE_REPLICA_CPUS` / `_MEMORY` | `2` / `256m` | per-replica caps; the pair sums to the reference envelope |
| `SMOKE_EXPECT_READY` | `0` | flip after the readiness-evidence wiring lands (Section 7) |
| `SMOKE_EXPECT_RECEIPT` | `0` | flip after the receipt-schedule composition lands (Section 7) |
| `SMOKE_EXPECT_TRANSPORT` | `0` | flip after the storage transport key lands (Section 7) |
| `SMOKE_VULN_FAIL_ON` | `critical` | grype failure threshold |

## 2. Reference environment

The live categories need a real S3 backend, the tenant's bucket layout,
and a linked-client control record — the same material the conformance
and control corpora pin, stood up for the smoke's own namespace:

- **Backend**: the archived upstream MinIO reference profile
  (`minio-reference-profile.md` Section 1), single-node single-drive on
  loopback, binaries hash-pinned to
  `RELEASE.2025-09-07T16-13-09Z` / mc `RELEASE.2025-08-13T08-35-41Z`.
- **Buckets and identities**: `tools/minio-reference-provision.sh`
  provisions the raw and control buckets and the two disjoint ingest
  identities (raw-writer, control-reader) exactly as the qualification
  notes describe. The minted secrets live mode-600 in the work directory
  and are never printed; the replicas receive them through `env:`
  credential references, so no credential value ever sits in a file the
  image or a bind mount could carry.
- **Control material**: the driver emits the linked-client pointer
  records of the control corpus's deployment story — tenant
  `3e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30`, client
  `9a4c2f18-6b37-4e59-8d20-1f3a5c7e9b42`, authority public
  `f97cf56e…e9ba` (`schemas/v1/examples/control/keys.json`) — at their
  pinned object keys under the control bucket, and the replica pins the
  same authority through `server.authority_key`.
- **The endpoint scheme claim**: today's registry grammar is TLS-only by
  construction — the storage config carries no key that disables TLS
  (SEC-001), and the TLS client trusts only the compiled-in webpki roots,
  so a loopback backend is unreachable over either plaintext or a
  self-signed certificate. The replicas are therefore configured with
  `https://<loopback-minio>`: scheme and the mandatory transport setting
  agree (the configuration validates and the replica boots), and the
  categories that only prove a replica's own signals never converse with
  storage at all. Categories that do converse get today's documented
  fail-closed answer at the storage boundary (Sections 6 and 8).

## 3. Health

Asserted:

1. `/health/live` answers `200` with body `{"live":true}` from a replica
   started from the image with a complete, valid environment-tier
   configuration (every `server.*` and `storage.*` key the serve
   composition requires, secrets by `env:` reference).
2. The image `HEALTHCHECK` (RC-020 — the binary probing its own
   `probe` command) reaches `healthy` on its pinned schedule, proving
   the image's liveness signal works as declared, not just as
   unit-tested.
3. `/health/ready` answers the **fail-closed** response until a verified
   control read has produced trust evidence: `503`
   `trust_evidence_absent`. A smoke replica that has served no such read
   must refuse readiness — a ready-200 from a fresh replica would be a
   trust-boundary failure, not a success.

Failure modes: (1) failing means the composition or the environment tier
broke (config keys unreadable, port bound, configuration invalid — replica
logs are printed); (2) failing means the HEALTHCHECK directive and the
binary disagree (wrong probe route, unpinned schedule, or the probe
command regressed); (3) answering anything but the documented 503 is a
FAIL in both directions.

## 4. Secret

Asserted, in two passes — one before the live stage mints any
credential, one after:

1. **Layer inventory**: the image's final-state regular-file inventory
   (layer order applied, whiteouts honored, read from the `docker save`
   extraction's manifest so the OCI blob layout is walked in stack order)
   must be exactly the digest-pinned runtime base's own final-state
   inventory plus the installed binary at `/usr/local/bin/archivist` —
   the one file RC-015 installs, by exact path. An image that grew any
   other file fails even if the file holds nothing sensitive — the
   release contract is that the runtime stage adds the binary and nothing
   else (RC-014).
2. **Deny-token scan**: every layer byte-stream — and the image config
   blob, where environment values and build history live — is scanned for
   the run's tenant UUID, the pinned control-authority public, the minted
   identity secret keys, and the generic credential shapes (the
   `ACCESS_KEY=`/`SECRET_KEY=` document literals and `PRIVATE KEY` PEM
   armor). The generic shapes apply only to the files the image adds
   beyond its digest-pinned base and the installed binary: both of those
   legitimately carry the same vocabulary — the binary's own credential-
   document and redaction-detector constants, and the base crypto
   libraries' (`gpgv`, `gnutls`) PEM-armor strings. Base content is
   pinned by digest, so its bytes are a base-move decision, exactly as
   the vulnerability policy treats base findings. The deny *values* —
   tenant material, authority public, the run's own secrets — cover
   every byte of every file. Matches are reported as file names only;
   values are never echoed.
3. **Filesystem leg**: the running image's own root is grepped two ways —
   the stateful trees (`/etc`, `/tmp`) for the full shape set, and the
   installed binary for the value material only (same carve-out as the
   layer scan). This is the check that catches material written at
   runtime or baked outside the layers the tarball shows.

The second pass re-runs the scan with the *run's own minted credential
values* on the deny list — the strongest form of the property: the
secrets this very run generated appear nowhere in the image.

Failure modes: an inventory mismatch means a build stage grew files
(embed a log, a stray `COPY`); a deny match means credential or tenant
material entered the image and the image must not ship; a filesystem
match means runtime contamination. All three fail the smoke regardless
of severity thresholds.

## 5. Vulnerability

The documented invocation, run verbatim by the harness:

```console
$ grype <image> --fail-on critical -o json --file grype.json
```

**Recorded policy**: any **Critical** finding fails the smoke. High and
below are reported (severity counts are printed from the retained JSON
and recorded on the release-evidence bead) for the maintainer's review
against the base image's own findings — the runtime base is
digest-pinned, so its findings are a base-move decision, not a build
accident. A `--fail-on` threshold other than `critical` is an explicit
knob (`SMOKE_VULN_FAIL_ON`), never a silent relaxation.

A missing scanner or an unusable vulnerability database is a **GAP**,
not a PASS: the invocation is defined, the invocation did not run, and
the gap is recorded with exactly the invocation a qualifying builder
must run. This is the acceptance wording's "if the builder host lacks a
scanner the invocation is still defined and the gap recorded".

Failure modes: grype exit non-zero means the threshold was met or
exceeded — the image fails until the base or a dependency moves; grype
erroring on the image itself (unparseable config, unreachable daemon) is
a stage abort, not a category result.

## 6. Signature-input

The category the corpora cannot cover end to end: a **signed ingest
submission round-trips through the running image** — authorization,
commit, storage — over real HTTP.

*Instrument.* The driver re-derives the control corpus's key pairs from
their pinned labels (`archivist.control/v1 <name>`) and signs with a
**pure-Python RFC 8032 Ed25519 implementation** — the driver must be
able to mint on any host the harness runs on, wheel or no wheel. The
implementation is proven by `self-test`: RFC 8032 test vector 1,
bit-for-bit reproduction of the conformance corpus's golden baseline
signature (the same signing input, signed with the derived uploader
seed), agreement with `keys.json` publics, and mint determinism at a
fixed instant.

*The fresh attempt.* The golden `valid-direct-baseline` envelope
re-anchored to the control corpus's identities (tenant, linked client)
with `blob_digest`, `occurrence_id`, and `attestation_id` re-derived
through `conformancegen.derive_identity` and asserted stable, signed by
the derived `control-client-a` key at the final pointer's
authorization epoch, inside the 5-minute freshness window. `mint`
self-verifies the signature with the corpus's own `ed25519_verify`
before handing the body to the harness.

Asserted:

1. **Fail-closed lane** — two rejected attempts, the live half of the
   parent property ("altered, replay-expired, and unauthorized requests
   make no storage writes"):
   - the golden `invalid-stale-authorization` attempt (authorization
     pinned years outside the freshness window), and
   - a byte-altered fresh body (one flipped byte at a fixed offset,
     breaking the request digest and the envelope transport together);
   each must answer the single closed wire class
   `auth.authorization_rejected`, and the raw bucket must hold **zero
   objects** afterward. The rejection happens in the authorization
   layer, before any storage conversation, so this lane proves the
   trust boundary over the wire today.
2. **Admit lane** — the fresh attempt is authorized over the wire: the
   answer is a commit-path class, not the rejection class. What the
   commit path can answer is gated by the transport gap (Section 7):
   today the attempt stops at the storage boundary, the answer is a
   named failure class, and the raw bucket still holds zero objects —
   the boundary fails closed, nothing partial stands. With
   `SMOKE_EXPECT_TRANSPORT=1` the round trip is asserted instead: the
   commit answers `server.partial_commit` and the raw bucket holds
   **exactly** the three derived object keys — blob, occurrence,
   attestation — and nothing else.
3. **Second replica** — the identical signed bytes POSTed to a second
   independently started replica: today, the same authorized-then-
   failed-closed answer (replica equivalence at the boundary);
   post-landing, convergence on the standing objects.
4. **Concurrent retry** — four identical attempts fired at once across
   both replicas all answer the same class, and the raw bucket holds
   exactly what the admit lane's branch says it should (zero today, the
   three keys post-landing).

Failure modes: a reject lane hit means authorization admitted material
it must not (freshness, linkage, digest agreement, or scope checks
regressed) — the highest-severity outcome this category can produce,
because it is the trust boundary itself; a reject with a stray object
written means rejection is not atomic; an admit lane that answers the
rejection class means the minted authorization is wrong; a admit lane
that answers success with objects standing while
`SMOKE_EXPECT_TRANSPORT=0` means the transport gap has closed and the
knobs must move with it.

## 7. What is deliberately not yet true (the three gaps)

Three composition landings the parent contract expects have not happened
on `main`, and the harness encodes today's honest answers instead of
pretending otherwise. Each is asserted as PASS **in its fail-closed
direction** and carries a knob for the post-landing assertion:

1. **Receipt signing schedule.** The serve composition constructs
   `ReceiptSigners::new()` — an empty schedule — so a complete commit
   answers `server.partial_commit` (partial: no receipt issued) and no
   receipt exists to verify. When the schedule composition lands,
   `SMOKE_EXPECT_RECEIPT=1` flips the admit-lane assertion to require a
   signed receipt whose signature input verifies through the
   `archivist-auth` signers; until that landing the flip is a
   guaranteed FAIL, which is what makes the gap visible instead of
   forgotten.
2. **Readiness evidence.** `record_verified_control_read` has no
   production caller, so no replica can ever hold trust evidence and
   `/health/ready` is permanently `503 trust_evidence_absent`. The
   health category asserts this fail-closed answer today — the pointer
   objects the live stage places are exactly the substrate a verified
   control read will consume, so the harness is already wired for the
   landing. When the evidence wiring lands, `SMOKE_EXPECT_READY=1`
   flips the readiness assertion to require 200.
3. **Storage transport key.** A registry-assembled serve configuration
   is TLS-only by construction: the storage config has no key that
   states `Tls::Disabled` (SEC-001 — plaintext is never reached by
   omission), and the TLS client trusts only the compiled-in webpki
   roots, so no local backend — plaintext or self-signed — is
   reachable from a configured replica. The reference round trip
   (authorization → commit → durable objects in the reference MinIO)
   therefore cannot complete on current `main`: an admitted attempt
   stops at the storage boundary, which fails closed with a named
   failure class and nothing durable standing — the assertable
   fail-closed answer, and the one the harness pins. The landing that
   closes the gap is a registry transport key (after which the scheme
   claim in Section 2 becomes a plaintext endpoint and
   `SMOKE_EXPECT_TRANSPORT=1` asserts the full round trip).

A run with any knob flipped on current `main` is *expected* to fail; a
run with all knobs at their defaults that fails anything else is a real
regression.

## 8. Multi-replica

The reference envelope from the closed Phase 4 resource benchmark (bead
`aa-feadbc99`): **four vCPU and 512 MiB for the serving plane**. The
smoke maps the envelope onto two replicas sharing it — each capped with
`docker --cpus 2 --memory 256m`, the pair summing exactly to the
reference floor and ceiling — so the category proves both *concurrency*
(two replicas serve simultaneously) and *fit* (each runs, healthy,
inside its half).

Asserted: the second replica reaches live and answers while the first
keeps serving; identical signed bytes get the same answer through
either replica (post-transport: convergence on the standing objects);
four concurrent identical retries across both converge on one answer
with nothing partial standing; and both containers end the run
`healthy`, never `OOMKilled`, with `RestartCount` 0 — a memory-cap kill
or a crash-restart loop inside the envelope is a FAIL, not a footnote.

Failure modes: a cap kill means the Phase 4 budget does not hold for the
real composition; a restart loop or an unhealthy second replica means
the two replicas do not actually share the backend cleanly (credential
collision, bucket contention, port binding); a divergence between the
replicas' answers means one of them is not serving the signed bytes
honestly — the exact defect the category exists to catch.

## 9. Recorded results

Results of the acceptance run are recorded on the owning bead (the
dispatch for the harness, then the parent bead at the release landing):
per-category verdicts, the grype severity counts, the three gap knobs'
state, the image the run built, and the commit it was extracted from.
The summary block the harness prints (one line per assertion, then
`N passed, N failed, N gap(s)`) is the unit of record; a GAP line is
expected only for the vulnerability scanner's absence or its unusable
database on a non-qualifying builder.
