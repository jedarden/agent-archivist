# Control trust schemas

Authority: the implementation plan, Section 5 (control-plane boundary),
Section 7.1 (version axes), and Section 7.5 (object keys); requirements
ID-001, ID-003, ID-006, ID-008, ID-009, and SEC-006. The family is:

| File | Role |
|---|---|
| [`schemas/v1/control-envelope.json`](../../schemas/v1/control-envelope.json) | The shared conventions registry and member library: the `archivist.control/v1` namespace, the wrapper member set, the two write classes, the `control-record-v1` signing construction, the record-type registry, and the control object-key patterns. |
| [`schemas/v1/control-client.json`](../../schemas/v1/control-client.json) | The linked-client record (plan Section 7.5 `tenants/<tenant>/v1/control/clients/<client>.json`): client identity, Ed25519 public key, base scopes, and the current authorization epoch. |

Control records are what the control-plane boundary runs on: objects
below `tenants/<tenant>/v1/control/`, written only by the offline
`ControlAdminStore` (which can put nothing but validated,
tenant-authority-signed control objects), read by every ingestion replica
when it authenticates an uploader, and cacheable for at most 60 seconds
(plan Section 5). Revocation, receipt-key, delegation, and
authority-rotation record types arrive as later schema changes composed
from the same envelope — the decision list below is what binds them.

## The envelope: decisions every record type follows

These are settled. A future control record schema that contradicts any of
them is wrong, not a variation:

1. **One namespace, one version axis.** Every control record carries
   `schema` = `archivist.control/v1`, exactly the way the
   `archivist.error/v1` and `archivist.cli-output/v1` families express
   theirs — no numeric version twin beside it. A v2 is a new namespace
   string, never a second field, and an unknown namespace fails closed
   before anything else is read.
2. **Flat composition, no nested envelope.** A record-type schema is the
   complete object: every wrapper member (from the envelope's
   `wrapper.members` registry) plus the type's payload members, side by
   side, `additionalProperties: false`. The wrapper is deliberately not an
   envelope-with-`record` shape, because the receipt-key certificate inside
   `ingest-receipt.json` is already a flat authority-signed control record —
   that definition is consumed, not duplicated (the
   [wire schemas note](wire-schemas.md) open question this family exists to
   answer). A record type narrows `record_type` and `record_kind` to consts
   of its own; every other wrapper member references the registry's
   declared source unchanged.
3. **Closed shapes, rejected unknowns.** `additionalProperties: false` at
   every object level that declares properties. This is a deliberate
   deviation from the plan Section 7.1 retain-ignore rule the ingest
   envelope, receipt, and certificate follow, and the reason is the material
   difference: those are data-plane records whose unknown additive fields
   are provenance carried inside signed bytes, while a control record *is*
   authorization semantics — a member a reader cannot interpret might carry
   a grant or a restriction, and authorization never rests on partially
   understood evidence. The single-writer model (the administrator CLI
   through the `ControlAdminStore`) makes the strictness affordable: member
   additions, redefinitions, and new required members are all v2 namespace
   events. The only in-place appends are new tokens inside already-closed
   enums (`record_type`, and `operations` in the linked-client record),
   each shipped together with the readers that understand it; an old reader
   fails closed on a new token until upgraded, which is the plan Section 7.1
   rule for security-bearing values, not a compatibility break.
4. **The wrapper member set.** `schema`, `record_type`, `record_kind`,
   `tenant_id`, `authorization_epoch`, `signed_at`, `authority_key_id`,
   `authority_signature` — the envelope's `wrapper.requiredByKind` registry
   pins which are required per write class, and
   `tools/check-control-schemas.py` proves every shipped record schema
   composes exactly that set. Hostnames are never members (ID-002); the
   tenant and client identifiers appear as canonical UUIDv4 text.
5. **Two write classes, one epoch rule.** `record_kind` is either
   `immutable` or `current-pointer` (plan Section 5). An immutable record is
   written once at a record-type-derived key; the store rejects an
   overwrite outright unless the bytes are the identical record, so a
   lost-response retry of one administrative write is an idempotent repair.
   A current-pointer record holds the current state of one subject at a
   fixed key, and a replacement is accepted **only when its signed
   `authorization_epoch` strictly increases** — equal or lower is a stale
   write and is rejected. The epoch is signed precisely so a stale record
   cannot displace a newer pointer without the authority key: rollback
   requires publishing another higher-epoch record, never repointing to an
   older one. The epoch is required for current-pointer records and carried
   by immutable types only when it is part of their identity (the revocation
   key names the revoked epoch).
6. **One signing construction.** `control-record-v1`: Ed25519 by the tenant
   authority key named by `authority_key_id`, over the RFC 8785
   canonicalization of the complete record object with the
   `authority_signature` member removed — exactly the `receipt-key-v1`
   shape, reused so one verifier core walks both families. Domain
   separation under one authority key comes from the member sets: every
   control record's signed bytes contain the `schema` namespace member and
   no bare certificate's do. The chain always starts at the tenant authority
   root the client pinned during linking (ID-009); when the authority itself
   rotates, an authority-rotation record type chains successor keys to
   predecessor ones, and `authority_key_id` then names the signing authority
   record's key. Verification walks forward from the pinned root and never
   trusts a key because a record asserts it.
7. **Public material only.** No member of any control record carries
   private-key material (SEC-006, ID-001): key members are public halves
   under the common shapes, key IDs are the pinned SHA-256-of-encoded-public-
   key derivation, and the closed shape leaves no undeclared member for
   anything else to ride in. The gate rejects `private`/`secret`/`seed`
   member names outright, so the property is machine-checked.
8. **Server-derived object keys.** Keys are derived from the validated
   record type and fields (ID-008): `clients/<client>.json` for the
   linked-client record, and — pinned in the envelope now because plan
   Section 7.5 fixes the layout — `revocations/<client>/<epoch>.json` and
   `receipt-keys/<key>.json` for their pending record types. Key segments
   must equal the record's own identifiers (`tenant_id`, `client_id`, the
   revoked epoch); the store refuses a mismatch and any reader can re-make
   the check. The receipt-key pattern is cross-checked against the
   certificate's documented `objectKey` so the two cannot fork.
9. **Numeric and timestamp discipline.** RFC 8785 canonical JSON, no
   floats, integers bounded (`authorization_epoch` 1 through
   999999999999999999 — the 18-digit canonical decimal the revocation key
   can carry, kept in lockstep with that grammar), timestamps RFC 3339 UTC
   with the `Z` suffix, scope and identifier arrays issued sorted so
   equivalent grants produce identical canonical bytes (writer discipline —
   RFC 8785 does not sort arrays).

## The linked-client record

The record links one installation to one tenant (ID-003): `client_id` (the
installation-generated UUIDv4, ID-001), `key_id`/`key_algorithm`/
`public_key` (its Ed25519 authorization key — the `uploader_key_id` an
attempt signs with and the `authorization_key_id` a receipt reports),
`scopes`, and `authorization_epoch`. It is a current-pointer record at
`tenants/<tenant>/v1/control/clients/<client>.json`: the link is epoch 1,
and every rotation, scope change, and revocation publishes the next epoch
of the same object.

The epoch lifecycle is what the rest of the system leans on. An ingest
attempt presents the current epoch inside its signature, and a stale-epoch
attempt fails closed even when its immutable envelope is valid (plan Phase
3 exit gate); during key rotation the old and new keys both verify for 24
hours while attempts must present the current epoch, so retries of an
already-frozen envelope authorize with the current key rather than
stranding in the spool; a revocation writes the revocation record for the
named epoch and publishes a higher epoch here, so propagation is bounded
by the reader's 60-second trust cache, not by anything in this record.
There is deliberately no validity window: the record is current until
replaced or revoked — unlike the receipt-key certificate, whose
`valid_from`/`valid_until` bound *signing* while verification of retained
receipts never expires (ID-009).

`scopes` carries the base grants the client holds **as itself**. Relay
authority is a conjunction of tenant, origin, harness, and operation
scopes — never their union (plan Section 5) — and the four dimensions
resolve like this:

- **tenant**: the record itself; it lives under the tenant's control
  prefix and is valid nowhere else;
- **origin**: the client itself, for base uploads — this record grants
  nothing for other origins. Relay grants for an origin are delegation
  records (a later record type), so an approved relay is the conjunction
  of its own client record and the delegation record, never a union;
- **harness**: the explicit `scopes.harnesses` allowlist (no wildcard
  token in v1 — a new harness is a new epoch, granted as deliberately as
  the first);
- **operation**: the explicit `scopes.operations` allowlist (`ingest` only
  in v1; the dimension exists from day one because relay authority is
  defined over it).

Empty allowlists are structurally impossible (`minItems: 1`): a client
with no grants is not a linked client with empty arrays, it is a revoked
client.

## Verification

`tools/check-control-schemas.py` proves the family's coherence
structurally and behaviourally: envelope registry coherence (namespace
const, closed fail-closed enums, recordTypes/write-class/key-pattern
agreement), flat wrapper composition against `wrapper.requiredByKind`,
closed shapes at every object level, the banned private-member-name
grammar, the plan-pinned 60-second cache and 24-hour rotation overlap
constants, draft 2020-12 validity, a zero-entropy golden linked-client
record whose key IDs are computed by the pinned SHA-256 derivation and
whose object key is re-derived from its own identifiers, thirteen
behavioural rejections of that record, and the receipt-key pattern
cross-check against `ingest-receipt.json`. Its `--self-test` proves the
rejection paths.

```sh
tools/check-control-schemas.py             # accept path
tools/check-control-schemas.py --self-test # rejection paths
```

Cryptographic verification — real Ed25519 authority signatures over real
records — is Phase 3 conformance work; schema validation here is
syntactic and structural only. No private key is generated, pinned, or
stored for schema work at any point.

The family shares `schemas/v1/common.json` with the ingest wire and raw
provenance families (one vocabulary per version directory) and reuses the
receipt-key certificate definition rather than duplicating it; the
[wire schemas note](wire-schemas.md) documents that hand-off from its
side.

## Open questions

- The **authority-rotation record** — how a successor authority key is
  chained to its predecessor and how clients re-pin — is the first open
  item the envelope's authority-chain rule anticipates; `authority_key_id`
  already names the signer generally enough for it.
- The **delegation record** (relay grants) and the **revocation record**
  follow next; their key patterns are already pinned in the envelope.
- Whether a scope grant ever needs a per-grant qualifier (expiry, per-origin
  limits inside the client record) — v1 says no: grants change by epoch,
  and anything richer is a new record type's decision, made against the
  list above.
