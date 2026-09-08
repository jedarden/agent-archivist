# Coding-agent transcript archiving: findings and architecture

Status: design research · Last updated: 2026-09-08

## Problem statement

Useful agent history is spread across several independent surfaces:

- interactive Claude Code, Codex, OpenCode, Pi, and similar CLI sessions;
- long-running coding sessions whose transcript files grow for hours or days;
- sessions started by an orchestrator such as NEEDLE;
- ephemeral workers that disappear before a periodic host collector can inspect
  their files; and
- provider requests and responses that may contain details omitted or transformed
  by a harness transcript.

Capturing only orchestrator output does not produce the full corpus. The durable
archive has to begin at each harness's canonical session store, with live emission
for ephemeral environments. Provider-level instrumentation is an additional source
when exact inference inputs and outputs are required.

The raw archive is intended for later reflection, evaluation, retrieval, and
carefully governed dataset construction. It is not itself a safe prompt source or
an automatic self-improvement loop.

## Findings

### 1. There is no single universal transcript source

Harness-native session records are the best semantic source available on a normal
host: they retain user turns, assistant turns, tool calls, tool results, and local
context in the structure understood by that harness. They do not necessarily
contain the byte-for-byte provider request and response. A harness may summarize,
redact, transform, retry, or omit transport details.

Consequently, complete collection has two complementary layers:

1. **Harness capture** archives each supported tool's durable semantic session.
2. **Inference capture** optionally records the exact provider exchange through a
   supported SDK hook, callback, or OpenAI-compatible proxy.

The two records should be joined by explicit trace, request, attempt, and session
identifiers. Neither should be declared a duplicate of the other merely because
their text overlaps.

### 2. A host collector is necessary, but a host name is not an identity

A collector on every host covers interactive sessions and harnesses that an
orchestrator never sees. A mutable display hostname is useful provenance but is a
poor namespace: hosts are renamed, rebuilt, cloned, and reused.

Each installation should instead create a persistent random client identifier and
a signing key. Linking registers the public key with a tenant. The stable client
identifier represents the originating installation; display hostname and machine
metadata remain mutable attributes.

Mirrors and relays must preserve that origin identifier. Their own identity is
recorded separately as the uploader so a mirrored session is not relabeled as a
session created by the relay host.

### 3. `host + session` helps, but it solves only logical namespacing

Most coding harnesses use session UUIDs with enough entropy for normal operation.
Even so, a bare session UUID is not a safe global key because:

- separate harnesses may use different ID schemes or the same identifier;
- imported histories and cloned home directories can repeat an identifier;
- multiple tenants may own unrelated sessions with the same identifier; and
- a session file may be truncated, replaced, or rewritten in place.

The logical session namespace should therefore be:

```text
tenant_id / origin_client_id / harness_id / upstream_session_id
```

This is the durable form of “host-session.” A generation or revision is then added
when the source artifact is replaced or rewound. It has sufficient uniqueness for
session provenance, assuming the linked client ID is persistent and independently
generated. It is not payload deduplication.

### 4. Blob, occurrence, and uploader identity are different

Content-addressing answers “have these exact bytes already been stored?” It does
not answer “where did these bytes occur?” Identical bytes can legitimately appear
on two clients, in two sessions, or through both a canonical transcript and a
mirror.

The archive should store:

- one immutable **blob** keyed by the SHA-256 digest of the canonical,
  uncompressed payload bytes; and
- one immutable **occurrence manifest** for every distinct source occurrence,
  pointing to that blob and carrying source-stable provenance; and
- one immutable **upload attestation** for each frozen uploader/request that commits
  an occurrence.

A useful logical model is:

```text
session_key = tenant / origin_client / harness / upstream_session
blob_key    = sha256(canonical_uncompressed_payload)
occurrence  = hash(session_key, artifact, generation, byte_or_event_range,
                   blob_key)
attestation = hash(occurrence, uploader_client, request_id)
```

This deduplicates bytes and source occurrences without erasing evidence that the
same content arose in more than one place or that more than one authorized relay
submitted it. Keeping uploader/request/timing fields out of the occurrence prevents
concurrent origin and relay writes from replacing its source provenance with a
last-writer-wins variant.

### 5. Active sessions require chunking and a client-side acknowledgement ledger

Waiting for a session to end loses marathon sessions during crashes or retention
cleanup. Re-uploading the whole growing file wastes bandwidth and creates changing
objects.

Append-oriented formats should be divided into immutable chunks on complete record
boundaries. A partial final record waits for the next scan. The client records the
source's device/file identity (where meaningful), generation, acknowledged offset,
and a checksum around the boundary. Truncation, replacement, or a mismatched tail
starts a new generation rather than silently skipping or overwriting history.

For database-backed harnesses, copying the entire application database is unsafe:
it may include tokens, accounts, caches, and unrelated state. The adapter should
open the database read-only and emit a versioned, allowlisted projection of session
content. Export commands must be tested for truncation and fidelity before they are
trusted.

### 6. Stateless ingestion moves durable progress to the client and S3

The ingestion process does not need a database, distributed cursor, queue, or local
filesystem state. During a request it can authenticate, validate, hash, and stream;
after the request it can disappear.

Durable responsibility is divided as follows:

| Concern | Durable owner |
|---|---|
| Discovery cursor, pending spool, retry schedule | Client |
| Linked-client trust record | External identity/control plane or S3 |
| Transcript bytes | S3 blob namespace |
| Source provenance and logical idempotency | S3 occurrence namespace |
| Uploader/request provenance | S3 upload-attestation namespace |
| Query indexes, redacted episodes, datasets | Versioned derived S3 prefixes |

Any ingestion replica can accept the next retry. A receipt is issued only after
the required objects are durable.

### 7. S3 is the storage contract; ARMOR is an optional implementation layer

The public architecture should speak a conservative S3-compatible subset rather
than require a particular cluster or encryption service. ARMOR can sit behind the
ingestion service and encrypt objects into B2, while another deployment can use S3
server-side encryption, MinIO, Garage, or a compatible store directly.

This separation also keeps storage credentials out of host clients. A client is
authorized to submit a validated archive envelope; it is not authorized to choose
arbitrary bucket keys or perform general S3 operations.

### 8. Logical idempotency is portable; physical exactly-once storage is not

The server derives deterministic object keys. A retry therefore addresses the same
logical blob, occurrence manifest, and uploader/request attestation.

Backends differ in their support for atomic create-if-absent operations:

- When conditional create is supported, `If-None-Match: *` (or the backend's
  equivalent) avoids a second physical write.
- Without it, overwriting the same deterministic key preserves logical
  idempotency. A versioned backend may still retain a noncurrent physical version.
- A preliminary `HEAD` can reduce writes, but it cannot provide correctness because
  two replicas can race after the check.

Strictly one physical version under concurrency cannot be guaranteed by a
stateless, horizontally scaled service on a backend without atomic conditional
create. Adding a database or distributed lock solely to mask that storage
limitation contradicts the base architecture. Prefer a capable backend when
physical exactly-once behavior is required; otherwise use lifecycle rules to
expire redundant noncurrent versions.

Compression must be deterministic, or deduplication should address the stored
representation rather than assume two compressed encodings are identical.
Semantic normalization belongs in a derived pipeline; raw capture should not
rewrite historically meaningful bytes.

### 9. Backfill priority should be measured, bounded, and fair

Initial history can be much larger for one account or harness than another. The
client should inventory all configured roots and prioritize accounts by estimated
unacknowledged bytes, largest first. Hard-coded harness ordering is a weak proxy for
the real backlog.

A per-source byte/time quota is still necessary. Without one, the largest account
can starve every smaller account and prevent fresh sessions from reaching durable
storage. A good scheduling cycle is:

1. drain previously spooled objects;
2. capture a small freshness window from every source;
3. spend the remaining budget on backfill in descending backlog order; and
4. persist progress only after durable server receipts.

Within a source, recently modified active sessions deserve a freshness lane while
oldest or largest outstanding ranges progress through the historical lane.

### 10. Ephemeral workers must emit before teardown

A periodic collector cannot recover a pod, container, or disposable VM after its
local volume has been deleted. Ephemeral workers need the same client library or a
sidecar and must flush acknowledged chunks before teardown. An orchestrator can add
attempt and outcome metadata, but should reference the canonical raw occurrence
rather than upload a second nominally canonical transcript.

### 11. Raw transcripts are sensitive and untrusted

Transcripts routinely contain credentials, private code, personal information,
command output, and instructions copied from untrusted repositories or websites.
Encryption at rest is necessary but insufficient.

The system needs tenant isolation, transport encryption, least-privilege storage
access, content-free operational logs, bounded decompression, retention controls,
and an auditable deletion path. Raw data must not be injected directly into another
agent. Redaction, trust classification, prompt-injection handling, bounded episode
extraction, evaluation, and human policy belong in a derived-data pipeline.

## Protocol shape carried into the implementation plan

A versioned upload request carries an immutable canonical envelope plus separate,
fresh proof-of-possession authorization for each attempt. The envelope includes:

- protocol and schema version;
- tenant and origin client IDs;
- uploader client ID when different from the origin;
- harness, upstream session ID, artifact kind, and source generation;
- byte or event range and ordering metadata;
- canonical payload digest, encoding, media type, and size;
- capture and source timestamps;
- a frozen request ID; and
- optional trace, inference request, orchestrator attempt, and parent-session IDs.

The per-attempt authorization adds the uploader key ID, authorization epoch, and
signature timestamp without changing occurrence or attestation identity.

The request flow is:

1. Authenticate the linked client and authorize the tenant/origin relationship.
2. Verify that the proof-of-possession signature binds the envelope and payload
   digest, and enforce a replay window for the request credential.
3. Validate versions, identifiers, range limits, sizes, encodings, and media types.
4. Stream the payload while verifying size, decompression bounds, and digest.
5. Derive all object keys server-side.
6. Durably create or idempotently replace the blob.
7. Durably create or idempotently replace the occurrence manifest.
8. Durably create or idempotently replace the upload attestation.
9. Return a tenant-authority-verifiable signed receipt only after all three writes
   succeed.

A failed or ambiguous response is retried with exactly the same identity. Partial
success is repaired by the retry because all destination keys are deterministic.

## Illustrative S3 layout

The exact escaping and sharding scheme should be versioned, but the logical split
is important:

```text
tenants/<tenant>/v1/raw/blobs/zstd-v1/sha256/<prefix>/<digest>.zst
tenants/<tenant>/v1/raw/occurrences/<origin>/<harness>/<session>/<occurrence>.json
tenants/<tenant>/v1/raw/attestations/<occurrence>/<attestation>.json
tenants/<tenant>/v1/control/clients/<client>.json
tenants/<tenant>/v1/catalog/checkpoints/<timestamp>.json
tenants/<tenant>/v1/derived/episodes/<pipeline-version>/<episode>.json
tenants/<tenant>/v1/derived/datasets/<pipeline-version>/<partition>.parquet
```

Blob, occurrence, and upload-attestation prefixes are the ingest contract. Catalogs
and derived objects can be rebuilt from them and should identify their producing
schema and pipeline versions.

## Public-project boundary

The public repository should contain protocol schemas, synthetic fixtures, clients,
server code, storage compatibility tests, deployment examples, and threat-model
documentation. It must not inherit a private archive's Git history or include real
transcripts, host inventory, service URLs, credentials, tenant IDs, bucket names,
or infrastructure-specific configuration.

## Open questions for implementation

- Which proof-of-possession format gives the best interoperability: mTLS, HTTP
  message signatures, or short-lived tokens bound to a registered client key?
- Should the minimal portable storage contract require conditional create, or make
  physical duplicate suppression an advertised backend capability?
- Which canonical compression and chunk size balance deterministic storage,
  streaming verification, and provider portability?
- Which harness schemas are stable enough for first-party adapters, and which need
  a plugin boundary maintained outside the core release cadence?
- How should deletion tombstones and retention enforcement interact with shared
  content-addressed blobs referenced by more than one occurrence?
- What completeness signal can distinguish “fully captured” from “the adapter did
  not know that a source root existed”?
