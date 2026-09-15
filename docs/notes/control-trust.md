# Control trust

Authority: the implementation plan, Section 5 (control-plane boundary),
Section 7.1 (version axes), Section 7.2 (wire authentication), Section
7.5 (object keys), Section 7.8 (receipts), Section 7.10 (retention and
deletion), and Section 7.11 EC-09 (the
trust-record cache); requirements ID-003, ID-005, ID-006, ID-008,
ID-009, SEC-006, SEC-007, and SEC-008. This note is the map of the control trust family —
what it is, where each contract lives, and how the pieces check each
other. The per-record normative contracts (the envelope's decisions,
member-by-member shapes, the signing construction, the write rules) live
in [control trust schemas](control-trust-schemas.md); the
machine-readable index of the family lives in
[`tools/control-records.toml`](../../tools/control-records.toml); the
gate that keeps every home agreeing is
[`tools/check-control-schemas.py`](../../tools/check-control-schemas.py)
in the fast lane of `scripts/definition-of-done.sh`; and the family's
committed golden-vector bundle — every record byte-pinned with its
pinned expected outcome — is the control verification corpus, mapped
record by record in [control-corpus.md](control-corpus.md).

## The trust story in one pass

Control records are what the control-plane boundary (plan Section 5)
runs on: objects below `tenants/<tenant>/v1/control/`, written only by
the offline `ControlAdminStore` — which can put nothing but validated,
tenant-authority-signed control objects — read by every ingestion
replica when it authenticates an uploader, and cacheable for at most 60
seconds. Eight schema files carry the family
([`schemas/v1/control-envelope.json`](../../schemas/v1/control-envelope.json)
plus seven record schemas), and the trust they describe is one story:

1. **Link.** The linked-client record is one installation's identity in
   one tenant: its Ed25519 public key, base scopes, and the current
   authorization epoch. The link is epoch 1, and every subsequent
   administrative act on that client publishes the next epoch of the
   same object — a replacement is valid only when its signed epoch
   strictly increases.
2. **Authorize.** An ingest attempt presents the current epoch inside
   its signature; a stale-epoch attempt fails closed even when its
   envelope and signature are otherwise valid. Authorization is fresh
   per attempt and valid for five minutes, with at most five minutes of
   clock skew (plan Sections 5 and 7.2 — the wire family's
   [ingest schemas](wire-schemas.md) pin the two constants beside the
   attempt shape).
3. **Rotate.** A key rotation publishes the rotation record — both
   public halves, at the epoch the rotation establishes — together with
   the higher-epoch client pointer. For 24 hours from the record's
   `signed_at`, an attempt at the current epoch may sign with either
   half, so a retry of an already-frozen envelope never strands in the
   spool.
4. **Revoke.** A revocation writes the epoch-addressed revocation
   record and completes by publishing a higher-epoch client pointer. No
   operation removes or supersedes a revocation; propagation is bounded
   by the reader's 60-second trust cache (EC-09), never by anything in
   the record.
5. **Delegate.** A delegation record grants one relay client authority
   to present one origin client's frozen occurrences — the conjunction
   of tenant, origin, harness, and operation scopes, never their union.
   Withdrawal is the one move the current-pointer shape permits: a
   higher-epoch record at the same key with `delegation_state:
   withdrawn`.
6. **Certify receipts.** The receipt-key record is the authoritative
   control-prefix original of the certificate embedded by value in
   every receipt: a fresh key is certified every 30 days, each key signs
   for seven days past its successor's first signing instant, and
   verification of retained receipts never expires. The
   [wire schemas note](wire-schemas.md) documents the two-signature
   chain from its side; the schemas note proves the record and the
   certificate are one statement.
7. **Rotate the authority.** When the tenant authority itself rotates,
   the authority-rotation record chains the successor key to the
   predecessor — one immutable link per retired key, addressed by the
   key it retires and signed by it, so verification walks forward from
   the pinned root by fetch-verify-adopt-repeat. For 24 hours from the
   link's `signed_at`, either half may sign control records and
   receipt-key certifications and both verify; the window bounds
   signing acceptance, never what was already signed, and the pin
   never moves.
8. **Retain and delete.** The retention record is the tenant
   authority's durable decision about one stored occurrence — one
   closed action per record: a `tombstone` schedules deletion with the
   30-day grace anchored at its `signed_at`, a `legal-hold` bars
   deletion and overrides any tombstone regardless of epoch order, and
   a `release` ends the active hold. Epoch-addressed and immutable
   like the revocation, one object per (occurrence, epoch), the
   current state is the fold of the records in ascending epoch order,
   and the default — no records at all — is indefinite retention (plan
   Section 7.10). The one record type no ingestion replica reads: the
   ingestion API has no delete route, so the ingest path stays
   retention-blind and the record serves the offline deletion workflow
   and audit.

No private-key material appears anywhere in the family (SEC-006):
key members are public halves under the shared common shapes, key IDs
are the pinned SHA-256-of-encoded-public-key derivation, and the gate
rejects `private`/`secret`/`seed` member names outright.

## Where the contract lives — three homes, one gate

The family's contract is written once and indexed twice, and no home may
drift from the others:

| Home | What it holds |
|---|---|
| The record schemas, `schemas/v1/control-*.json` | The normative shapes: the envelope's shared defs, wrapper registry, object-key patterns, and in-band `x-archivist` registries (record types, write classes, timing constants), plus each record type's complete object. |
| [`tools/control-records.toml`](../../tools/control-records.toml) | The external, append-only index: every record type with its write class, schema, object-key layout, key members, and status, and every timing constant with its value, unit, plan sections, and the verbatim plan sentence that pins it. |
| The plan, `docs/plan/plan.md` Sections 5, 7.2, 7.5, 7.8, 7.10, 7.11 | The authority: the object-key table (Section 7.5) and the timing sentences the registry quotes verbatim. |

`tools/check-control-schemas.py` holds the three together: the
registry's record types agree with the envelope's `recordTypes` registry
and the record-type enum two-way, member for member; every object key
sits under the plan Section 7.5 control prefix and, with the golden
identifiers substituted, reproduces a key the envelope's pattern
accepts; every control layout the plan's table pins appears in the
registry exactly as the plan writes it; and each timing constant's
`plan_quote` is proven verbatim plan text that states the constant's
number exactly once — words-to-numbers included, because the plan pins
the five-minute window and the seven-day overlap as words. The plan is
load-bearing, not decorative: rewriting a pinned sentence, or dropping
the control lines from Section 7.5's table, fails the gate.

## The record registry

Within registry schema `archivist.control-registry/v1` the record-type
set is **append-only**: adding a record type — with its schema, envelope
registry entry, record-type enum token, and object-key pattern in the
same change — is a compatible change; renaming, removing, or redefining
a declared attribute of an existing record type is a v2 event. The gate
enforces this as two-way agreement with the committed envelope registry
and the record-type enum, so neither home can drift without failing the
fast lane. The shipped set:

| Record type | Write class | Object key | Key members |
|---|---|---|---|
| `linked-client` | current-pointer | `tenants/<tenant_id>/v1/control/clients/<client_id>.json` | `tenant_id`, `client_id` |
| `delegation` | current-pointer | `tenants/<tenant_id>/v1/control/delegations/<relay_client_id>/<origin_client_id>.json` | `tenant_id`, `relay_client_id`, `origin_client_id` |
| `revocation` | immutable | `tenants/<tenant_id>/v1/control/revocations/<client_id>/<authorization_epoch>.json` | `tenant_id`, `client_id`, `authorization_epoch` |
| `rotation` | immutable | `tenants/<tenant_id>/v1/control/rotations/<client_id>/<authorization_epoch>.json` | `tenant_id`, `client_id`, `authorization_epoch` |
| `receipt-key` | immutable | `tenants/<tenant_id>/v1/control/receipt-keys/<key_id>.json` | `tenant_id`, `key_id` |
| `authority-rotation` | immutable | `tenants/<tenant_id>/v1/control/authority-rotations/<previous_key_id>.json` | `tenant_id`, `previous_key_id` |
| `retention` | immutable | `tenants/<tenant_id>/v1/control/retention/<occurrence_id>/<authorization_epoch>.json` | `tenant_id`, `occurrence_id`, `authorization_epoch` |

Object-key layouts are written with the record's own member names as
placeholders, in the order the store concatenates them
(`key_members`): the store derives each key from exactly those
validated fields (ID-008), the gate proves every key member is a
required property of the shipped record, and substituting the pinned
golden records' identifiers into a layout must produce a key the
envelope's object-key pattern accepts — layout, pattern, and key
members are one contract. Plan Section 7.5's table spells its generic
placeholders `<tenant>`, `<client>`, `<epoch>`, `<key>`; the gate maps
them onto the member names and requires the plan's control lines to
appear in the registry exactly under that mapping. The plan's table
currently pins the client, revocation, and receipt-key control keys;
the delegation, rotation, authority-rotation, and retention layouts
extend it from the envelope registry (a documented plan follow-up the
schemas note's open questions track).

## The timing constants

Seven named constants, each encoded exactly once — the envelope's
`x-archivist.constants` registry is the one authoritative encoding
inside the schemas, `tools/control-records.toml` is its index, and
every consuming schema pins the same number where it applies, with the
gate proving agreement and rejecting any second encoding:

| Constant | Value | Plan sentence (quoted verbatim by the registry) | Pinned where it applies |
|---|---|---|---|
| `trustRecordCacheTtlSeconds` | 60 s | "Trust records cache for at most 60 seconds." | linked-client, delegation, rotation, receipt-key, authority-rotation records; re-expressed as the revocation record's `revocationPropagationBoundSeconds` |
| `authorizationWindowSeconds` | 300 s | "Request authorization is fresh per upload attempt and valid for five minutes" | `ingest-request.json` (wire family) |
| `clockSkewAllowanceSeconds` | 300 s | "with at most five minutes of clock skew" | `ingest-request.json` (wire family) |
| `rotationVerificationOverlapHours` | 24 h | "Key rotation accepts old and new keys for 24 hours" | linked-client, rotation, authority-rotation records |
| `receiptKeyRotationDays` | 30 d | "Receipt keys rotate every 30 days" | receipt-key record, receipt certificate |
| `receiptKeySigningOverlapDays` | 7 d | "with seven days of old/new signing overlap" | receipt-key record, receipt certificate |
| `deletionGraceDays` | 30 d | "wait 30 days" | retention record (the tombstone's grace, anchored at its `signed_at`) |

Two of the values are deliberately equal but separately named — the
authorization window protects the signer's freshness, the clock-skew
allowance the verifier's clock — and two five-minute values must not
silently become one ten-minute window. Two more are deliberately equal
by coincidence of the plan's own numbers — the 30-day receipt-key
rotation and the 30-day deletion grace guard unrelated calendars (a
signing cadence; a deletion delay) and must never be unified. The
revocation propagation bound is the cache TTL re-expressed where the
revocation record needs it: the same number, never a second value, and
the exactly-once walk treats it as the TTL's alias. The retention
record is the one type that pins no TTL on purpose: nothing online
reads it to serve stale — the ingest path is retention-blind (plan
Section 7.10's no-delete-route rule) and its offline readers re-read
rather than cache.

## Verification

`tools/check-control-schemas.py` (fast lane of
`scripts/definition-of-done.sh`) validates the family structurally and
behaviourally: envelope registry coherence, flat wrapper composition,
closed shapes, the no-private-material rule, the named-constant
registry with every cross-file agreement proven, golden records
validated and mutated, and — over `tools/control-records.toml` and the
plan — the registry agreement, object-key, plan-layout, and
plan-quote checks this note describes. Its `--self-test` proves every
rejection path, registry drift and plan rewrites included.

```sh
tools/check-control-schemas.py             # accept path
tools/check-control-schemas.py --self-test # rejection paths
```

Cryptographic verification — real Ed25519 authority signatures over real
records — is Phase 3 conformance work; schema validation here is
syntactic and structural only. The family's offline cryptographic
proof, however, already exists as golden vectors: the [control
verification corpus](control-corpus.md) commits 40 tenant-authority-signed
records with pinned outcomes under
`schemas/v1/examples/control/`, checked byte-exactly in the fast lane
by `tools/controlgen.py --verify` and replayed offline by the
archivist-auth suites (`control_corpus.rs`, `authority_corpus.rs`).

## Ownership and neighbors

The control-plane types and their verification live in
`archivist-auth` (layer 1) with the storage traits in
`archivist-storage` (the `ControlReadStore` and `ControlAdminStore`
boundaries; see the [crate ownership map](crate-ownership.md)). The
receipt-key record is the control-prefix half of a certification that
also lives in the wire family's receipt — the
[wire schemas note](wire-schemas.md) documents the hand-off and the
two-signature chain — and the envelope's signing construction reuses
the receipt certificate's verifier shape so one core walks both
families. Deep per-record contracts: [control trust
schemas](control-trust-schemas.md).
