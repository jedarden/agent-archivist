# MinIO reference storage profile — provisioning and live verification

Qualified 2026-09-21 (bead `aa-1b6a2063`). The `minio` profile is the one
[reference-class](storage-profiles.md) deployment profile: the storage
compatibility suite qualifies it on every full verification run, and that
run is credential-free by construction, so the suite's backend is an
in-process S3-shaped double rather than a live server. This note is the
deployment-facing half of the profile — the operator's reproducible
configuration of a real local MinIO instance and the live verification
that the configured instance agrees with everything the profile claims.
Its instrument is [`tools/minio-reference-provision.sh`](../../tools/minio-reference-provision.sh)
(`provision` and `verify` modes); its evidence below is from a live run.

It records the upstream disclosure a MinIO deployment inherits, the
identity set with its disjointness proof, the 24-hour incomplete-multipart
cleanup mechanism, the mapping into the portable `storage.*`
[configuration keys](configuration.md), and the honest boundary of what a
local run establishes.

## 1. Upstream disclosure: the open-source server is archived

MinIO archived the open-source server and client in 2025. The consequence
a deployment inherits is concrete:

- `dl.min.io` no longer serves release binaries — the download endpoint
  answers HTTP **410 Gone**. Binaries remain on the GitHub releases pages,
  which is where the pinned versions below come from.
- No further community releases or security updates are published. A MinIO
  deployment is a **fixed artifact**, to be pinned and hash-verified, not
  a following dependency.

This run pins:

| Artifact | Release | SHA-256 |
| --- | --- | --- |
| `minio` (server, linux-amd64) | `RELEASE.2025-09-07T16-13-09Z` | `7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f` |
| `mc` (client, linux-amd64) | `RELEASE.2025-08-13T08-35-41Z` | `01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891` |

Nothing here recommends MinIO for a new internet-exposed production
deployment. The profile's role is narrower: it is the local reference the
suite is developed against, and the reference implementation an operator
or community-run reproduction stands on. A production deployment picks a
*target* profile (B2, ARMOR) — or, with a recorded qualification run, a
community one.

## 2. Deployment shape

The verified shape is a single-node, single-drive server bound to the
loopback interface, which is exactly what the reference profile's
portable configuration assumes:

- **Path-style addressing** — `storage.path_style` defaults to `path`
  precisely because this is the MinIO reference shape.
- **Plaintext HTTP requires an explicit `Tls::Disabled`** on the archivist
  side (the `file:`/`env:` reference grammar refuses an implicit
  plaintext endpoint). A real deployment terminates TLS in front; the
  local reference run states the disabling outright rather than silently.
- **Region** is a fixed string (`us-east-1` in the verified run); MinIO
  accepts any value but the signatures must agree.
- **Two buckets**: `archivist-raw-local` (content-addressed raw blobs,
  occurrences, attestations) and `archivist-control-local` (control-plane
  records). Key layouts follow plan Section 5:
  `tenants/<tenant>/v1/raw/...` and `tenants/<tenant>/v1/control/...`;
  every policy below scopes to these prefixes.
- **Versioning enabled on the raw bucket only.** The raw bucket is where
  an overwrite race lands a noncurrent copy (the suite's
  `versioning=enabled` capability), so the backend keeps physical history
  a lifecycle rule can age out. Control records are written by a single
  administration identity and carry no overwrite race to protect.

## 3. The identity set

Four identities, mirroring plan Section 5. The two required roles are the
ingest pair the portable configuration demands; the two optional roles
exist only where a deployment deliberately grants them
([requirements](requirements.md) STO-007 preflight; offline restore).
Canonical grants live in `policy_document()` in the provisioning script;
`verify` diffs the server's copy against them.

| Role | Grant | Deliberately absent |
| --- | --- | --- |
| `raw-writer` (required) | `s3:PutObject`, `s3:AbortMultipartUpload`, `s3:ListMultipartUploadParts` under `tenants/<tenant>/v1/raw/*`; `s3:GetBucketLocation` on the raw bucket | `s3:GetObject`, `s3:ListBucket`, `s3:DeleteObject` — **abort never implies delete** |
| `control-reader` (required) | `s3:GetObject` under `tenants/<tenant>/v1/control/*`; `s3:ListBucket` with an `s3:prefix` condition; `s3:GetBucketLocation` | any write, any raw access |
| `raw-reader` (optional) | `s3:GetObject` under the raw prefix; scoped `s3:ListBucket`; `s3:GetBucketLocation` | any write, any control access |
| `offline-restore` (optional) | `s3:GetObject` and scoped `s3:ListBucket` across both tenant prefixes; `s3:GetBucketLocation` | any write, any delete |

Two MinIO IAM facts the grant set absorbs:

- MinIO rejects an `s3:prefix` condition on `s3:ListBucketMultipartUploads`
  ("unsupported condition keys") while accepting the same condition on
  `s3:ListBucket`. The raw-writer therefore holds no
  `ListBucketMultipartUploads` at all: the write path never calls it, and
  rather than widen the grant bucket-wide, in-progress session auditing
  stays with the admin identity.
- MinIO normalizes scalar condition values to singleton lists; `verify`'s
  drift check lifts scalars on both sides before comparing, so a policy
  that is semantically identical does not read as drifted.

## 4. The 24-hour incomplete-multipart cleanup

A commit that dies mid-session orphans an in-progress multipart upload at
the backend; the deployment's 24-hour cleanup is the designed backstop
that reaps it (the same role the B2 qualification records —
[b2 qualification](b2-storage-qualification.md) Section 6). On the pinned
2025-era MinIO the mechanism is **the server-global API knob**, not a
bucket lifecycle rule:

```
$ mc admin config get <alias> api   # relevant knobs, live values
  stale_uploads_cleanup_interval=6h  stale_uploads_expiry=24h
```

`stale_uploads_expiry=24h` is the default and `provision` pins it;
`stale_uploads_cleanup_interval=6h` is the sweep cadence, so an orphaned
session is reaped within 24–30 hours of initiation.

The bucket-level alternative an operator would reach for first — an
`AbortIncompleteMultipartUpload` lifecycle rule — **does not exist on this
build**. The server rejects it at validation:

```
PutBucketLifecycleConfiguration(AbortIncompleteMultipartUpload, DaysAfterInitiation: 1)
→ InvalidArgument: The XML you provided was not well-formed or did not
  validate against our published schema
```

with a control run in the same session proving the rejection is specific
to the action: an expiration-only lifecycle rule on the same bucket is
accepted. The server source parses the abort action only to refuse it.
Pre-2025 community builds that still accept the ILM rule should prefer it
(bucket-scoped beats server-global); the script's pin and the note's
evidence describe the 2025+ behavior.

## 5. The verification run

`provision` configures the instance; `verify` re-checks every claim live
and then exercises disjointness with throwaway per-identity probe aliases
(their credentials never leave a scratch mc config). Probe objects are
purged version-and-marker with `--versions` afterwards; the control
prefix is only ever listed, never written by a probe.

The run's full matrix — 20 checks, exit 0, and idempotent across repeated
runs (provision reuses existing mode-600 credential files, never rotates;
verify is convergent):

```
== verifying the MinIO reference profile (alias: refqual)
  ok   incomplete-multipart cleanup: stale_uploads_expiry=24h
  ok   versioning enabled on archivist-raw-local
  ok   identity raw-writer exists with policy archivist-raw-writer
  ok   identity control-reader exists with policy archivist-control-reader
  ok   policy archivist-raw-writer matches the canonical grant set
  ok   policy archivist-control-reader matches the canonical grant set
  ok   raw-writer can write below the tenant raw prefix
  ok   raw-writer cannot read raw objects (denied)
  ok   raw-writer cannot delete raw objects (denied)
  ok   raw-writer cannot read the control bucket (denied)
  ok   raw-writer cannot write the control bucket (denied)
  ok   control-reader can list the tenant control prefix
  ok   control-reader cannot write the control prefix (denied)
  ok   control-reader cannot read raw objects (denied)
  ok   control-reader cannot write the raw prefix (denied)
  ok   raw-reader (optional) can list the tenant raw prefix
  ok   raw-reader (optional) cannot write the raw prefix (denied)
  ok   raw-reader (optional) cannot read the control prefix (denied)
  ok   offline-restore (optional) can list both tenant prefixes
  ok   offline-restore (optional) cannot write the raw prefix (denied)
== verify: PASS (the live instance agrees with the reference profile)
```

Every forbidden operation fails with a server authorization refusal (mc
phrases it "Access Denied." or "Insufficient permissions" depending on
subcommand; `verify` accepts either and fails on anything else — a
client-side error can never masquerade as a denial). Secret keys are
generated in place with `openssl rand`, written mode-600 into
`--creds-dir`, and never printed.

## 6. Mapping into the portable configuration

The `storage.*` keys ([configuration](configuration.md),
`tools/config-keys.toml`) a MinIO reference deployment carries:

| Key | Reference value |
| --- | --- |
| `storage.endpoint_url` | the MinIO endpoint (e.g. `https://minio.internal.example` — plain `http://` demands explicit `Tls::Disabled`) |
| `storage.region` | the server's region string |
| `storage.path_style` | `path` (the default, and the reference shape) |
| `storage.encryption` | a named policy — see below |
| `storage.raw_bucket` / `storage.control_bucket` | the two buckets from Section 2 |
| `storage.raw_write_credentials_ref` | `file:<creds-dir>/raw-writer` |
| `storage.control_read_credentials_ref` | `file:<creds-dir>/control-reader` |
| `storage.raw_read_credentials_ref` (optional) | `file:<creds-dir>/raw-reader` |
| `storage.offline_restore_credentials_ref` (optional) | `file:<creds-dir>/offline-restore` |

The credential references are pairwise distinct by validation (plan
Section 5); the files `provision` writes are exactly the four identities
above, and the optional two are present only when the flags were given —
an ingest replica omits both.

**Encryption.** Configuration validation refuses to build a store without
a named encryption policy (`s3_sse`, `armor`, or `client_envelope`).
MinIO's own SSE-SSE-KMS path needs KES and an external KMS, which an
archived upstream makes a poor dependency; the honest local reference
answer is `client_envelope` (the archive encrypts before the backend ever
sees bytes) unless the deployment already operates KES. The suite's
`server_side_encryption=verified` capability models what a *configured*
backend must show, not a claim that MinIO ships encryption built in.

## 7. What the run establishes, and what it does not

**Established:** the reference profile's claims are reproducible on a real
MinIO — the disjointness matrix (Section 5) proves the two required
identities cannot cross the raw/control boundary or escalate from write to
read or delete; the 24-hour cleanup is pinned and observable; the
provisioning is idempotent and secret-hygienic; and the compatibility
suite's reference lane holds its capability report against the same
expectations a live operator configures:

```
storage-compatibility profile=minio conditional_create=supported stored_checksum=sha256 versioning=enabled server_side_encryption=verified physical_versions=[concurrent-writers:1:["v3"],duplicate-request:1:["v1"],equivalent-overwrite:1:["v2"],multipart-commit:1:["v5"],origin-attestation:1:["v6"],read-capable-conflict:1:["v4"],relay-attestation:1:["v7"]]
```

— exit 0 across all five lanes on a clean `git archive` extraction of the
run's commit, with no external credentials or services reachable. The
suite stays credential-free: this note and its script add an operator
instrument; they never move live-backend qualification into automation
([storage profiles](storage-profiles.md) Section 1).

**Not established:** the production S3 request backend does not exist yet
(open bead: implement it over the RawWrite and ControlRead seams), so
nothing here exercises archivist code against live MinIO — the identity
matrix is exercised through mc and S3 semantics directly. A single-node
loopback run says nothing about distributed MinIO behavior. The upstream
archive (Section 1) means the pinned artifact ages without patches. And a
live deployment's capability probe answer, not this report, is what the
store believes at runtime — as with every profile, unknown facts reduce
fail-closed.

## 8. Required actions for an operator

1. **Pin and hash-verify** the binaries (Section 1); never track a moving
   download URL — `dl.min.io` answers 410.
2. **Run `provision`**, not hand-written IAM: the canonical grant set and
   the 24-hour pin live in the script, and `verify` diffs policy drift.
3. **Keep the identity set minimal**: the two required roles for ingest;
   grant `raw-reader`/`offline-restore` only where the deployment
   deliberately opts in, and reflect exactly that in the configuration's
   optional keys.
4. **Confirm the cleanup pin** after any server reconfiguration —
   `stale_uploads_expiry` is server-global, so another operator's change
   to it is invisible at the bucket level where a lifecycle rule would
   have been.
5. **Re-run `verify` on a schedule**; a converged `verify` is the
   deployment's evidence that the instance still agrees with the profile.
