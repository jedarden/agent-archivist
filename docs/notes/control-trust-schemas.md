# Control trust schemas

Authority: the implementation plan, Section 5 (control-plane boundary),
Section 7.1 (version axes), Section 7.2 (wire authentication),
Section 7.5 (object keys), and Section 7.8 (receipts); requirements
ID-001, ID-003, ID-005, ID-006, ID-008, ID-009, RCPT-006, and SEC-006.
The family is:

| File | Role |
|---|---|
| [`schemas/v1/control-envelope.json`](../../schemas/v1/control-envelope.json) | The shared conventions registry and member library: the `archivist.control/v1` namespace, the wrapper member set, the two write classes, the named timing-constants registry, the `control-record-v1` signing construction, the record-type registry, and the control object-key patterns. |
| [`schemas/v1/control-client.json`](../../schemas/v1/control-client.json) | The linked-client record (plan Section 7.5 `tenants/<tenant>/v1/control/clients/<client>.json`): client identity, Ed25519 public key, base scopes, and the current authorization epoch. |
| [`schemas/v1/control-delegation.json`](../../schemas/v1/control-delegation.json) | The delegation record (`tenants/<tenant>/v1/control/delegations/<relay>/<origin>.json`): the relay grant — one uploader client authorized to present one origin client's occurrences, as the conjunction of tenant, origin, harness, and operation scopes. |
| [`schemas/v1/control-rotation.json`](../../schemas/v1/control-rotation.json) | The key-rotation record (`tenants/<tenant>/v1/control/rotations/<client>/<epoch>.json`): the durable evidence of one client key rotation — both public halves and the 24-hour overlap during which either verifies. |
| [`schemas/v1/control-revocation.json`](../../schemas/v1/control-revocation.json) | The revocation record (plan Section 7.5 `tenants/<tenant>/v1/control/revocations/<client>/<epoch>.json`): the append-only, epoch-addressed revocation of one client's authorization at one epoch. |
| [`schemas/v1/control-receipt-key.json`](../../schemas/v1/control-receipt-key.json) | The receipt-key record (`tenants/<tenant>/v1/control/receipt-keys/<key>.json`, plan Section 7.5): the tenant-authority certification of one server receipt-signing key — the authoritative control-prefix source of the certificate embedded in every receipt (plan Section 7.8). |

Control records are what the control-plane boundary runs on: objects
below `tenants/<tenant>/v1/control/`, written only by the offline
`ControlAdminStore` (which can put nothing but validated,
tenant-authority-signed control objects), read by every ingestion replica
when it authenticates an uploader, and cacheable for at most 60 seconds
(plan Section 5). The authority-rotation record type arrives as a later
schema change composed from the same envelope — the decision
list below is what binds it.

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
   and the receipt-key record type consumes that definition rather than
   duplicating it (the [wire schemas note](wire-schemas.md) open question
   this family existed to answer; see the receipt-key section below for
   how the consumption is proven). A record type narrows `record_type` and
   `record_kind` to consts of its own; every other wrapper member
   references the registry's declared source unchanged.
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
   by immutable types only when it is part of their identity — the
   revocation and rotation records are the shipped types that do, because
   their object keys name their epochs, the revoked and the established
   (the registry's `keyMembers` names the members the store derives each
   type's key from, and the gate proves every one is a required property
   of the shipped record). Monotonicity is per subject, and a subject is
   a client or a relation: the linked-client pointer's epoch only
   increases, a delegation record's epoch is its (relay, origin)
   relation's own sequence, and the immutable types permanently fix the
   rungs they name.
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
   linked-client record, `delegations/<relay>/<origin>.json` for the
   delegation record, `rotations/<client>/<epoch>.json` for the
   key-rotation record, `revocations/<client>/<epoch>.json` for the
   revocation record, and `receipt-keys/<key>.json` for the receipt-key
   record — all shipped. Key segments must equal the
   record's own identifiers (`tenant_id`; `client_id`; for a delegation
   the relay and origin in order; for a revocation or rotation, the
   epoch its key names; and, for a receipt-key record, the certified
   key ID under the pinned derivation); the store refuses a mismatch and
   any reader can re-make the check. The receipt-key pattern is
   cross-checked against the certificate's documented `objectKey` so the
   two cannot fork.
9. **Numeric and timestamp discipline.** RFC 8785 canonical JSON, no
   floats, integers bounded (`authorization_epoch` 1 through
   999999999999999999 — the 18-digit canonical decimal the revocation key
   can carry, kept in lockstep with that grammar), timestamps RFC 3339 UTC
   with the `Z` suffix, scope and identifier arrays issued sorted so
   equivalent grants produce identical canonical bytes (writer discipline —
   RFC 8785 does not sort arrays).
10. **Named timing constants, one registry.** The timing values the
    control plane and the wire lean on are named constants in the
    envelope's `x-archivist.constants` registry — never prose — and each
    schema that applies one pins the same number where it applies, with
    the gate proving agreement: the 60-second trust-record cache TTL that
    bounds revocation propagation (plan Section 5; EC-09; pinned as
    `trustRecordCacheTtlSeconds`, mirrored in the linked-client record and
    re-expressed as the revocation record's
    `revocationPropagationBoundSeconds`), and the 300-second
    fresh-per-attempt authorization window with its separate 300-second
    clock-skew allowance (plan Sections 5 and 7.2; the window already
    lives as `authorizationWindowSeconds` in
    `schemas/v1/ingest-request.json`, and the allowance is pinned beside
    it there as `clockSkewAllowanceSeconds`). Skew is named separately
    from the window because it protects a different clock — the
    verifier's, not the signer's — and two five-minute values must not
    silently become one ten-minute window. The fourth constant is the
    24-hour rotation verification overlap (plan Section 5: "Key rotation
    accepts old and new keys for 24 hours"), pinned as
    `rotationVerificationOverlapHours` and mirrored in the linked-client
    record — which documents the epoch rule it feeds — and in the
    rotation record that anchors the window to its `signed_at`. It is
    hours-valued because the plan pins it in hours; the registry's
    `unit` field, not the name alone, carries that distinction from the
    second-valued constants beside it. The fifth and sixth constants are
    the receipt-key rotation and its signing overlap (plan Section 7.8:
    "Receipt keys rotate every 30 days with seven days of old/new signing
    overlap"), pinned as `receiptKeyRotationDays` (30) and
    `receiptKeySigningOverlapDays` (7) in the receipt-key record and —
    under the same names, so agreement is plain equality — in the
    certificate definition inside `schemas/v1/ingest-receipt.json`, the
    one wire-family member of the registry's agreement set.

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
stranding in the spool (the `control-rotation` record below is where the
previous half and the window live); a revocation writes the revocation
record for the named epoch and publishes a higher epoch here, so
propagation is bounded by the reader's 60-second trust cache, not by
anything in this record.
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
  records (the `control-delegation` record below), so an approved relay
  is the conjunction of its own client record and the delegation record,
  never a union;
- **harness**: the explicit `scopes.harnesses` allowlist (no wildcard
  token in v1 — a new harness is a new epoch, granted as deliberately as
  the first);
- **operation**: the explicit `scopes.operations` allowlist (`ingest` only
  in v1; the dimension exists from day one because relay authority is
  defined over it).

Empty allowlists are structurally impossible (`minItems: 1`): a client
with no grants is not a linked client with empty arrays, it is a revoked
client.

## The revocation record

The record revokes one client's authorization at one epoch (ID-006:
credentials must be revocable) and lives at
`tenants/<tenant>/v1/control/revocations/<client>/<epoch>.json` (plan
Section 7.5). It is the shipped immutable record type, and its three
defining properties are all structural:

- **Epoch-addressed.** The object key names the revoked epoch, and the
  record's signed `authorization_epoch` equals that segment in canonical
  decimal without leading zeros. The epoch is an identity member here,
  not a pointer guard: an immutable record protects no pointer, and it
  carries the epoch exactly because the key names it (decision 5).
- **Append-only.** One object per (client, epoch), written once; the
  store rejects an overwrite of an incompatible immutable record, and no
  operation removes or supersedes a revocation. The only way to add is a
  new epoch.
- **Monotonic per client.** The linked-client pointer's epoch only
  increases, and each revocation permanently fixes one rung of that
  sequence. The store accepts a revocation only when the revoked epoch
  does not exceed the pointer's current signed epoch — one cannot
  pre-revoke an epoch the client has not reached, because a
  forward-dated revocation would arm itself against a legitimate later
  rotation — and the revocation completes by publishing a strictly
  higher-epoch linked-client record.

That pointer bump is the enforcement: an attempt presenting the revoked
epoch is stale against the new pointer even when its envelope and
signature are otherwise valid (plan Phase 3 exit gate), which is why the
revocation record carries no expiry and propagation is bounded by the
reader's 60-second trust cache (plan Section 5; EC-09) — the envelope's
`trustRecordCacheTtlSeconds` named constant, re-expressed in this record
as `revocationPropagationBoundSeconds` and proven equal by the gate. The
record itself is the durable evidence half: `client_id` (the linked
installation), `authorization_epoch` (the boundary), and
`revoked_key_id` — the `key_id` the linked-client record held at that
epoch, under the pinned SHA-256 derivation. The pointer retains no
history once it moves on, so `revoked_key_id` is the durable statement
of which credential died; it cross-checks against the
`authorization_key_id` of receipts for attempts at that epoch and
against the `uploader_key_id` an attempt signs with. Relinking after a
revocation (EC-12: preserve the spool, pause on `401`/`403`, resume only
after an operator links a valid epoch/key) is a new, higher epoch with a
new key — never an edit of the revocation.

## The delegation record

The record grants one linked client — the relay, the uploader of the
plan glossary — authority to present one origin client's frozen
occurrences (ID-005: the server authorizes an uploader to write for the
declared origin, and a relay never silently replaces origin identity
with its own). It is a current-pointer record at
`tenants/<tenant>/v1/control/delegations/<relay>/<origin>.json`: one
object per (relay, origin) pair, replaced only by a strictly higher
signed epoch — grant, revision, and withdrawal are all the same move.

**The grant is the conjunction of four scopes, never their union** (plan
Section 5), and the shape is what makes it so:

- **tenant**: the record lives under the tenant's control prefix and is
  valid nowhere else — a relay attempt's declared tenant must equal it
  exactly;
- **origin**: the record names the one origin its relay may present, as
  the second segment of its own object key — a grant for one origin is
  nothing for any other, and there is exactly one current object per
  pair, so there is no set of records a reader could union over;
- **harness**: the explicit `scopes.harnesses` allowlist, intersected
  with the relay's own linked-client allowlist — never added to it;
- **operation**: the explicit `scopes.operations` allowlist, intersected
  the same way (`ingest` only in v1).

So an authorized relay attempt needs every dimension at once: the
relay's linked-client record (key, current epoch, and its own harness
and operation allowlists) **and** this record (tenant, pair, and its
allowlists) **and** the attempt's declared tenant, origin, harness, and
operation. No wildcard token exists in v1 — the harness grammar rejects
`*`, and the gate proves it on `["*"]` — so a new harness or origin is a
new epoch, granted as deliberately as the first. Empty allowlists are
structurally impossible, exactly as in the client record: a delegation
with no grants is not an active record with empty arrays, it is a
withdrawn one.

**Withdrawal** is the one representation the current-pointer shape
permits: the store has no delete, so withdrawing a grant publishes a
strictly higher-epoch record at the same key with
`delegation_state: withdrawn`. A withdrawn record's scopes are inert —
carried so the record still names the shape of the grant it withdraws —
and only `active` records grant. The gate proves the withdrawn variant
validates and that an unknown state token fails closed: a reader must
never guess whether a grant it cannot interpret is live. Propagation of
a revision or withdrawal is bounded by the reader's 60-second trust
cache, like every control record (plan Section 5; EC-09).

**The epoch is the relation's, not a client's.** `authorization_epoch`
here is the grant's own monotonic sequence — the first grant of a pair
is epoch 1 and every revision or withdrawal publishes the next epoch of
the same object. The relay's client epoch is a separate sequence,
presented by the attempt and checked against the relay's own pointer:
revoking or rotating the relay does not touch this object, and a revoked
relay fails closed through its own pointer and revocation record
regardless of how active its grants are. Self-delegation
(`relay_client_id` equal to `origin_client_id`) is rejected by the store
as a VAL-002 cross-field check — the origin's own base grants already
cover self-upload, so a self-grant is redundant authority at best.

No key material appears anywhere in the record: it grants a relation
between two linked clients, each of whose keys live in their own
linked-client records (SEC-006). The relay signs attempts with the
relay's key and verifies through the relay's record; this record adds
origin authority, not a second key.

## The key-rotation record

The record is the durable evidence of one client key rotation (plan
Section 5: key rotation accepts old and new keys for 24 hours; Phase 3:
key rotation with overlapping verification and monotonic authorization
epochs). It is an immutable record at
`tenants/<tenant>/v1/control/rotations/<client>/<epoch>.json`, where the
epoch segment is the epoch the rotation **establishes** — so a reader
holding the linked-client pointer at epoch E finds the overlap evidence
for E's key at exactly `rotations/<client>/E.json`.

Enforcement rides the pointer, evidence rides this record, and the
split is the same one revocation uses: the rotation is published
together with the strictly higher-epoch linked-client record naming the
new key, and that pointer bump is what fails stale-epoch attempts
closed. The pointer retains no history once it moves, so this record
preserves what it cannot — the previous epoch, the previous public key,
and both key IDs under the pinned SHA-256 derivation, each computable
from the record's own public material.

**The overlap is what keeps retries from stranding.** For
`rotationVerificationOverlapHours` (24, plan Section 5 — the envelope's
named constant, mirrored here and in the linked-client record,
gate-proven equal) from the record's `signed_at`, an attempt presenting
the current epoch may sign with **either** the previous or the new
public key. The old half verifies from this record, never from
server-local state — which is what lets a stateless replica serve the
window (plan Section 3: the data plane is stateless between requests).
The overlap widens which key may sign, never which epoch is current: an
attempt outside the current epoch is stale regardless of key, and after
the window only the new key verifies. A retry of an already-frozen
envelope therefore re-authorizes with fresh per-attempt state under
either half inside the window, and with the current key after it (plan
Phase 3 exit gate: rotation does not strand already-spooled requests
inside the documented overlap; EC-12).

Structural rules, all cross-checked by the gate:

- **Epoch-addressed and immutable.** One object per (client,
  established epoch), written once; the store accepts it only when the
  established epoch does not exceed the pointer's current signed epoch
  and the pointer at that epoch carries this record's `public_key` —
  one cannot pre-date a rotation for an epoch the client has not
  reached, because a forward-dated rotation would arm its overlap
  window early. The record and the pointer bump that activates it are
  one administrative act.
- **Adjacent epochs only.** `previous_epoch` equals
  `authorization_epoch` − 1 (VAL-002): every pointer move publishes the
  next epoch — the link is epoch 1 and each rotation, scope change, or
  revocation publishes exactly the next one — so a rotation never skips
  an epoch it would otherwise leave unaccounted for.
- **Public material only, both halves.** `previous_public_key` and
  `public_key` are public halves; `previous_key_id` and `key_id` are
  their pinned derivations, computable from the record itself, and
  cross-check against the `uploader_key_id` of attempts and the
  `authorization_key_id` of receipts. The new private half is generated
  on the client host and never appears in any record, file, or
  argument; the old private half retires with the rotation (SEC-006,
  ID-001).

## The receipt-key record

The record certifies one server receipt-signing key (plan Section 7.8;
ID-009: a client verifies receipts through a
tenant-authority-signed server receipt-key record, and rotation never
invalidates retained receipts). It lives at
`tenants/<tenant>/v1/control/receipt-keys/<key>.json` (plan Section 7.5),
where the key segment is the certified key's ID under the pinned
SHA-256 derivation — key-addressed, the one shipped immutable type that
carries no `authorization_epoch`, because its identity is the key its
object key names, not an epoch.

**The record is the authoritative half of a certification that exists in
two homes.** The same certification statement travels as the certificate
embedded by value in every receipt the key signs
(`schemas/v1/ingest-receipt.json`), so an offline client verifies a
receipt without reaching the store (RCPT-006); this record is the
durable, control-prefix original the `ControlAdminStore` writes.
Consumption, not duplication: the record's payload members — `key_id`,
`key_algorithm`, `public_key`, `valid_from`, `valid_until` — *are* the
certificate's members under identical shapes, and the gate proves the
member-for-member agreement in both directions (every certificate member
except its own `certificate_version` axis appears in the record under the
same shape; the record adds nothing beyond the wrapper members), re-derives
the golden record's certificate projection (payload plus
`certificate_version`, wrapper members dropped by the registry's own
definition) and validates it against the certificate definition itself,
and cross-checks the object-key pattern against the certificate's
documented `objectKey`. `certificate_version` stays wire-only by design:
it is the certificate's own version axis (plan Section 7.1), while the
control family's axis is the namespace member — one axis per family, no
numeric twin inside a control record (decision 1).

**Two signatures, one authority, structurally distinct byte ranges.** The
administrative act produces both signatures the chain needs:
`control-record-v1` over this record (the wrapper members in the signed
bytes), and `receipt-key-v1` over the bare certificate (no wrapper
members, `certificate_version` in) — because a receipt's embedded
certificate is a data-plane object whose signed bytes cannot grow the
wrapper. Domain separation under the one pinned authority key comes from
the member sets themselves, exactly as the envelope's signing rule
records: a control record's signed bytes contain the `schema` namespace
member and no bare certificate's do. The chain a client walks is then
pure public material — pinned authority root over the certificate,
certificate key over the receipt (`receipt-v1`) — with no private key
material anywhere: the certified private half enters the server only
through a secret reference and appears in no record, file, or argument
(SEC-006).

**Rotation is non-invalidating by the write class, and the window is the
named constants.** Certifying a fresh key writes a new immutable object
at its own key ID; nothing removes or rewrites a predecessor, so every
certificate ever issued stays in the store and keeps verifying —
verification of retained receipts never expires (ID-009). The signing
window runs on the registry's two constants: a fresh key is certified
every `receiptKeyRotationDays` (30) and each key signs for
`receiptKeySigningOverlapDays` (7) past its successor's first signing
instant, so `valid_until` − `valid_from` is exactly the two summed —
37 days — and a successor's `valid_from` sits exactly 30 days after its
predecessor's (VAL-002 cross-field checks a reader re-makes from the two
records alone; the gate proves the 37-day span on the golden instance's
parsed timestamps). The overlap exists for signing continuity — the
signer is never without a valid key across a rotation boundary, late or
on time — and never widens verification, which the immutability above
already makes permanent. `signed_at` anchors nothing (unlike the
rotation record's overlap, anchored at its `signed_at`): the window is
anchored by `valid_from`, carried inside the signed bytes, and the
certification is signed no later than the window opens.

## Verification

`tools/check-control-schemas.py` proves the family's coherence
structurally and behaviourally: envelope registry coherence (namespace
const, closed fail-closed enums, recordTypes/write-class/key-pattern/
keyMembers agreement), flat wrapper composition against
`wrapper.requiredByKind` — with every wrapper member a record carries
referencing the registry's declared source, the revocation's and
rotation's identity epochs included — closed shapes at every object
level, the banned private-member-name grammar, the named timing-constant
registry with every plan-pinned value and every cross-file agreement
proven (envelope ↔ linked-client, delegation, rotation, and receipt-key
TTLs ↔ revocation propagation bound; envelope ↔ ingest-request window
and skew allowance; envelope ↔ linked-client and rotation overlap;
envelope ↔ receipt-key record and certificate rotation and overlap),
draft 2020-12 validity, zero-entropy golden linked-client, delegation,
rotation, revocation, and receipt-key records — one coherent story: the
client at epoch 3, its key established by the golden rotation from a
synthetic previous half, the relay grant presenting that client as
origin, the revocation of that epoch naming that client's key, and the
receipt-key certification the same pinned authority root signs, window
spanning exactly the rotation and overlap constants summed — whose key
IDs are computed by the pinned SHA-256 derivation (the rotation's
previous and current halves and the receipt key's own half) and whose
object keys are re-derived from their own identifiers, with the
revocation and rotation keys also checked at the epoch ceiling so the
18-digit epoch bound and both key grammars are proven in lockstep, the
delegation record's withdrawn variant proven valid (the only withdrawal
a current-pointer shape permits), the receipt-key record and the
certificate in `ingest-receipt.json` proven one certification statement
(object-key agreement, member-for-member shape agreement, and the
golden record's certificate projection validating against the
certificate definition itself), seventy-eight behavioural rejections
across the five records, and the receipt-key pattern cross-check
against `ingest-receipt.json`.
Its `--self-test` proves the rejection paths.

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
side, and the receipt-key section above records how the consumption is
proven.

## Open questions

- The **authority-rotation record** — how a successor authority key is
  chained to its predecessor and how clients re-pin — is the first open
  item the envelope's authority-chain rule anticipates; `authority_key_id`
  already names the signer generally enough for it, and the receipt-key
  record and certificate inherit that generality unchanged: both name
  their signer through `authority_key_id` and defer to the envelope's
  authority-chain rule wherever they explain it.
- Plan Section 7.5's object-key list still names only the client,
  revocation, and receipt-key control keys. The delegation
  (`delegations/<relay>/<origin>.json`) and rotation
  (`rotations/<client>/<epoch>.json`) patterns extend that list from the
  envelope registry; the plan's list should gain the two lines as a
  documentation follow-up — the plan file was under concurrent edit when
  these records shipped, so the amendment is deliberately not bundled
  with them.
- Whether a scope grant ever needs a per-grant qualifier (expiry, per-origin
  limits inside the client record) — v1 says no: grants change by epoch,
  and anything richer is a new record type's decision, made against the
  list above.
