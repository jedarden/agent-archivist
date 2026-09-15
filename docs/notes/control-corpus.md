# The control verification corpus

Authority: the implementation plan, Section 5 (control-plane boundary),
Section 7.5 (object keys), Section 7.8 (receipts), and Section 7.11
EC-06/EC-09/EC-12; requirements ID-006, ID-009, ID-010, VAL-002,
SEC-006, and SEC-010; the control trust story items 1, 3, 4, 5, 6, and
7 ([control-trust.md](control-trust.md)) and schemas notes 5–9
([control-trust-schemas.md](control-trust-schemas.md)); beads
`aa-2b38806f` and `aa-ff319c43`.

This note is the scenario map of the control trust family's
verification corpus — the sibling of the ingest family's
[conformance corpus](conformance-corpus.md) and the second of the two
committed, byte-pinned bundles. Where that bundle pins complete
ingest attempts, this one pins complete control records: every record
of [`schemas/v1/examples/control/`](../../schemas/v1/examples/control/)
is a tenant-authority-signed `archivist.control/v1` object carrying the
outcome a replay must produce. Any implementation, in any language,
replays the bundle offline with no server and only the public halves in
[`keys.json`](../../schemas/v1/examples/control/keys.json): recompute
each key ID as the lowercase-hex SHA-256 of the raw public bytes,
canonicalize per RFC 8785, verify each record's Ed25519 signature over
its pre-signature canonical bytes, and walk each family's decision
procedure over its history in order. The Rust implementation's replay
consumes exactly this bundle
([crates/archivist-auth/tests/control_corpus.rs](../../crates/archivist-auth/tests/control_corpus.rs)
and
[crates/archivist-auth/tests/authority_corpus.rs](../../crates/archivist-auth/tests/authority_corpus.rs)).

| File | Role |
|---|---|
| [`tools/controlgen.py`](../../tools/controlgen.py) | The deterministic generator and verifier (`--generate`, `--verify`, `--self-test`). |
| [`schemas/v1/examples/control/keys.json`](../../schemas/v1/examples/control/keys.json) | The public halves the five current-pointer and immutable-record scenario files replay against, with the pinned key-ID and seed derivations. |
| [`schemas/v1/examples/control/manifest.json`](../../schemas/v1/examples/control/manifest.json) | The machine-readable scenario map: every file's byte pin (`sha256`, `bytes`), every record's family and expected outcome, every acceptance-table verdict count, and the aggregate invariants. |
| [`schemas/v1/examples/control/epoch-progression.json`](../../schemas/v1/examples/control/epoch-progression.json) | Scenario bundle: the linked-client epoch rule (story item 1). |
| [`schemas/v1/examples/control/delegation-lifecycle.json`](../../schemas/v1/examples/control/delegation-lifecycle.json) | Scenario bundle: the delegation lifecycle (story item 5). |
| [`schemas/v1/examples/control/revocation.json`](../../schemas/v1/examples/control/revocation.json) | Scenario bundle: the revocation act and the pointer that completes it (story item 4). |
| [`schemas/v1/examples/control/key-rotation.json`](../../schemas/v1/examples/control/key-rotation.json) | Scenario bundle: the client key-rotation act and its attempt window (story item 3). |
| [`schemas/v1/examples/control/receipt-key-cohort.json`](../../schemas/v1/examples/control/receipt-key-cohort.json) | Scenario bundle: the receipt-key certification cohort and its signing windows (story item 6). |
| [`schemas/v1/examples/control/authority-rotation-chain.json`](../../schemas/v1/examples/control/authority-rotation-chain.json) | Scenario bundle: the tenant-authority rotation chain, self-pinned (story item 7). |

## What the corpus pins

1. **Byte-pinned records.** Every scenario file is RFC 8785-style
   canonical JSON plus one trailing LF, and every record carries
   `canonical_bytes_sha256` — the pre-signature canonical bytes, the
   exact input to the `control-record-v1` signing construction. The one
   exception is the authority-rotation chain, whose digests cover
   complete records (signature in): the convention its dedicated
   replay consumes.
2. **Pinned outcomes.** Every record carries an `expected` outcome
   (`accepted` or `rejected` with a closed `reason`), and every
   rejection is decided by the rule it pins: the record's authority
   signature *verifies* against the key it names (except the
   `untrusted-signer` members, whose rejection is that check), so no
   rejection rests on malformed input or a broken signature — only on
   the decision procedure the record exists to prove.
3. **Acceptance tables.** The windowed rules pin their windows
   themselves as verdict tables: the rotation record's
   `attempt_acceptance` (5 verdicts), the receipt-key cohort's
   `signing_acceptance` (7 verdicts), and the chain's `acceptance`
   (12 verdicts — one per (signer, `signed_at`) pair). 24 decision
   vectors over 40 records.
4. **Closed fold.** Each history's fold must land on the file's
   `final_state`, and each file's `generation` block states the
   decision procedure, the signature construction, the key-ID
   derivation, and the named timing constants
   (`rotationVerificationOverlapHours` 24, `receiptKeyRotationDays` 30,
   `receiptKeySigningOverlapDays` 7, the 60-second trust-cache bound of
   EC-09) the procedure runs on.
5. **The manifest's own invariants.** `manifest.json` re-states every
   scenario's record set and outcomes and aggregates them: 40 records,
   24 accepted, 16 rejected, and `rejections_by_reason` — `stale-epoch`
   × 4, `integrity-conflict` × 3, `key-id-mismatch` × 2,
   `epoch-unreached` × 2, `pointer-key-mismatch` × 1,
   `window-discontinuity` × 1, `untrusted-signer` × 1. The replay
   checks the manifest against the scenario files, so a record landing
   without its map entry, or an outcome changing without its pin, is a
   failure. (`stale-epoch` is the storage family's own closed
   error-class token,
   [`crates/archivist-storage/src/error.rs`](../../crates/archivist-storage/src/error.rs);
   the other reasons are the corpus's decision vocabulary.)

## Scenario map

Every pinned record, its scenario family, and its pinned expected
outcome — the manifest's `scenarios` tables in human form.

| Record | Family (bundle) | Expected | Pins |
|---|---|---|---|
| `client-a-link-epoch-1` | linked-client (epoch-progression) | accepted | the origin client's link: epoch 1 is the floor |
| `client-b-link-epoch-1` | linked-client (epoch-progression) | accepted | the relay's own link — monotonicity is per subject |
| `client-a-revision-epoch-2` | linked-client (epoch-progression) | accepted | a strictly higher epoch replaces the pointer |
| `client-a-revision-epoch-3` | linked-client (epoch-progression) | accepted | every administrative act is the next epoch of the same object |
| `client-a-stale-equal-epoch-3` | linked-client (epoch-progression) | rejected `stale-epoch` | equal epoch: the rule, not the signature, rejects |
| `client-a-stale-lower-epoch-2` | linked-client (epoch-progression) | rejected `stale-epoch` | lower epoch, same rule |
| `delegation-grant-epoch-1` | delegation (delegation-lifecycle) | accepted | the (relay, origin) grant opens the relation's own epoch sequence |
| `delegation-revision-epoch-2` | delegation (delegation-lifecycle) | accepted | a scope revision at a higher epoch |
| `delegation-withdrawal-epoch-3` | delegation (delegation-lifecycle) | accepted | withdrawal — the one move the current-pointer shape permits (the store has no delete) |
| `delegation-stale-regrant-epoch-3` | delegation (delegation-lifecycle) | rejected `stale-epoch` | a re-grant at the standing epoch |
| `delegation-regrant-epoch-4` | delegation (delegation-lifecycle) | accepted | the deliberate re-grant: a higher epoch restores the relation |
| `delegation-forged-epoch-5` | delegation (delegation-lifecycle) | rejected `untrusted-signer` | a valid Ed25519 signature by the relay's own key naming the authority's: verification precedes the epoch rule |
| `client-b-link-epoch-1` | linked-client (revocation) | accepted | the client whose revocation story follows |
| `client-b-revocation-epoch-1` | revocation (revocation) | accepted | revocation at the standing epoch only |
| `client-b-relink-epoch-2` | linked-client (revocation) | accepted | the act completes: new key, strictly higher epoch (EC-12) |
| `client-b-stale-replay-epoch-1` | linked-client (revocation) | rejected `stale-epoch` | the revoked epoch's pointer replays stale though envelope and signature verify — the plan's Phase 3 exit gate |
| `client-b-forward-dated-revocation-epoch-5` | revocation (revocation) | rejected `epoch-unreached` | one cannot pre-revoke an epoch the client has not reached |
| `client-b-revocation-wrong-half-epoch-2` | revocation (revocation) | rejected `key-id-mismatch` | names a half the standing pointer does not hold |
| `client-b-revocation-rewrite-epoch-1` | revocation (revocation) | rejected `integrity-conflict` | an incompatible object at the revocation's derived key (EC-06) |
| `client-a-link-epoch-1` | linked-client (key-rotation) | accepted | the client's original half |
| `client-a-pointer-epoch-2` | linked-client (key-rotation) | accepted | the pointer bump — half of the rotation act |
| `client-a-rotation-epoch-2` | rotation (key-rotation) | accepted | the immutable evidence record — both public halves at adjacent epochs, key IDs recomputable from the record alone |
| `client-a-rotation-replay-epoch-2` | rotation (key-rotation) | accepted | a byte-identical retry is an idempotent repair, not a second write |
| `client-a-rotation-rewrite-epoch-2` | rotation (key-rotation) | rejected `integrity-conflict` | an incompatible rewrite of the evidence key (EC-06) |
| `client-a-pointer-epoch-3` | linked-client (key-rotation) | accepted | a later administrative act at the new half |
| `client-a-rotation-mismatch-epoch-3` | rotation (key-rotation) | rejected `pointer-key-mismatch` | the record's new half is not the standing pointer's |
| `client-a-rotation-ahead-epoch-5` | rotation (key-rotation) | rejected `epoch-unreached` | a forward-dated rotation rejected before it can arm its window early |
| `receipt-key-one-certified` | receipt-key (receipt-key-cohort) | accepted | key one's window opens: `valid_until − valid_from` = 30 + 7 days exactly |
| `receipt-key-one-retry-identical` | receipt-key (receipt-key-cohort) | accepted | the byte-identical retry: certification is write-once with idempotent repair |
| `receipt-key-two-certified` | receipt-key (receipt-key-cohort) | accepted | the successor, certified 30 days after its predecessor's window opened |
| `receipt-key-discontinuous-window` | receipt-key (receipt-key-cohort) | rejected `window-discontinuity` | windows must chain on the two named constants — no gap, no ad-hoc overlap |
| `receipt-key-mismatched-id` | receipt-key (receipt-key-cohort) | rejected `key-id-mismatch` | the record's key ID is not the derivation of its own certified half |
| `receipt-key-one-rewrite` | receipt-key (receipt-key-cohort) | rejected `integrity-conflict` | rotation is non-invalidating because nothing rewrites a predecessor |
| `root-retires` | authority-rotation (authority-rotation-chain) | accepted | link 1: the pinned root retires itself and carries the successor half, signed by the key it retires |
| `successor-retires` | authority-rotation (authority-rotation-chain) | accepted | link 2: the chain walks two deep, each link verified against the `previous_public_key` it carries |
| `root-signed-before-rotation` | receipt-key (authority-rotation-chain) | accepted | a control record signed by the root before its retirement |
| `root-signed-at-overlap-end` | receipt-key (authority-rotation-chain) | accepted | the dual-key window includes its last instant |
| `root-signed-past-overlap` | receipt-key (authority-rotation-chain) | retired | one nanosecond past the 24-hour overlap the old root no longer signs |
| `successor-signed-at-establishment` | receipt-key (authority-rotation-chain) | accepted | the successor signs from its first instant |
| `stranger-key-unreachable` | receipt-key (authority-rotation-chain) | unreachable | no chain path from the pinned root reaches the key — fetch-verify-adopt refuses it |

### The acceptance tables

The three windowed rules pin their windows as verdict tables rather
than as history records — the 24 decision vectors the manifest counts.

**`key-rotation.json` `attempt_acceptance`** — attempts at the current
epoch against the rotation record's `signed_at`: the old half verifies
inside the 24-hour `rotationVerificationOverlapHours` window (a retry
of an already-frozen envelope re-authorizes under the old half instead
of stranding in the spool, EC-12), the new half from the rotation
instant onward, the overlap includes its last instant, one second past
is rejected `outside-overlap` — the window bounds signing acceptance,
never what was already signed — and a month later the standing half is
simply the current key. 5 verdicts.

**`receipt-key-cohort.json` `signing_acceptance`** — receipt signing
against the two certified keys' windows: mid-window accepted; before
`valid_from` rejected `outside-signing-window` (the certification does
not backdate signing); the successor's first instant accepted; both
halves accepted mid-overlap (seven days of signing continuity); the
window includes its last instant; one second past `valid_until`
rejected `outside-signing-window` while a receipt the key already
signed keeps verifying forever (ID-009). 7 verdicts.

**`authority-rotation-chain.json` `acceptance`** — one verdict per
(signer, `signed_at`) pair across the two-link chain: before the
rotation the root signs and the successor is `not_established` (down to
one nanosecond before); mid-window either half signs; the overlap's
last instant is inclusive; one nanosecond past, the root's verdict is
`retired`; link 2 closes the middle half's window the same way; a
stranger key is `unreachable`; and the half link 2 establishes signs
within its own validity. 12 verdicts over the vocabulary `accepted` /
`retired` / `not_established` / `unreachable`.

## Test-key provenance — corpus keys only, never real credentials

Every key in `keys.json` is a corpus test key, and every one is
reproducible from its name alone: a private seed is
`SHA-256("archivist.control/v1 <name>")` for the key's documented name,
signing is deterministic Ed25519 (RFC 8032), and **only public halves
are committed** — the derivation is documented in `keys.json` and the
generator, never emitted, and the replays derive nothing from the seed
names either (verification consumes public halves and pinned
expectations only). The authority-rotation chain pins its own
deployment in-file — its seeds are one byte repeated 32 times, as its
generation block documents — and none of those keys appears in
`keys.json`. Nothing any corpus key authorizes is real: every
identifier, tenant, client, and timestamp is pinned synthetic data
(SEC-006, SEC-010), and the keys sign nothing outside the bundle.
Correspondingly: never substitute a real credential, a real key pair,
or a real tenant identifier into the corpus, and never use a corpus key
anywhere but the corpus — the bundle's value is that it is safe to
commit, safe to replay anywhere, and byte-identical everywhere.

## Regeneration

```sh
python3 tools/controlgen.py --generate   # rewrite the committed location (the default output)
python3 tools/controlgen.py --verify     # regenerate, byte-compare, validate, re-verify, replay
python3 tools/controlgen.py --self-test  # prove the machinery without the committed bundle
```

There is no entropy source: seeds derive from key names, timestamps and
identifiers are pinned constants, and deterministic Ed25519 signing
makes `--generate` byte-identical on any machine. `--verify` regenerates
every file and byte-compares it, validates every record against the
`archivist.control/v1` envelope registry per the
[`check-control-schemas.py`](../../tools/check-control-schemas.py)
conventions, re-verifies every signature with the generator's
independent pure-Python Ed25519 verifier (no code shared with the
signing path), and replays every pinned outcome, acceptance-table
verdict, and manifest invariant from the committed bytes.

## The definition-of-done check and the replay tests

The fast lane of
[`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh)
runs the corpus twice: the **`control corpus`** check
(`tools/controlgen.py --verify` — the full proof above) and the
**`control corpus policy`** check (`tools/controlgen.py --self-test` —
build determinism, tampered and foreign-key signatures, the decision
procedure's flipped-pin detection, the write guard, and the schema's
no-private-material fault matrix, all without the committed bundle).

The Rust implementation consumes the same bundle offline:

- [`crates/archivist-auth/tests/control_corpus.rs`](../../crates/archivist-auth/tests/control_corpus.rs)
  replays the five `keys.json` families end to end from the committed
  bytes — pre-signature canonical bytes against the pinned digests,
  signatures against the named `keys.json` halves, each family's
  decision procedure in history order, each fold onto its
  `final_state` — plus the manifest's byte pins, the manifest
  invariants, and both the rotation `attempt_acceptance` and
  receipt-key `signing_acceptance` tables. Its manifest test fails if
  a scenario family lands without a Rust replay.
- [`crates/archivist-auth/tests/authority_corpus.rs`](../../crates/archivist-auth/tests/authority_corpus.rs)
  replays the chain: the fetch-verify-adopt walk from the pinned root,
  all 12 acceptance verdicts at their own `signed_at` against the
  24-hour window, and every chain-signed record end to end through
  `verify_signing_authority`.

These suites run in the definition-of-done slow lane; the committed
bundle they read is proven by the fast-lane checks above.

## Where this connects

- [`conformance-corpus.md`](conformance-corpus.md) — the ingest
  family's byte-pinned corpus; the two bundles are siblings and share
  the synthetic-deployment story (one tenant, its origin client, and
  the relay that may present its occurrences).
- [`control-trust.md`](control-trust.md) — the family map whose story
  items 1, 3, 4, 5, 6, and 7 these bundles are the golden vectors for.
- [`control-trust-schemas.md`](control-trust-schemas.md) — the
  normative per-record shapes every corpus record validates against.
- [`tools/control-records.toml`](../../tools/control-records.toml) —
  the append-only record registry the envelope registry and the gate
  hold the corpus's record types to.
- The plan's Phase 3 exit gate: the `client-b-stale-replay-epoch-1`
  vector is that gate as bytes — an attempt presenting the revoked
  epoch is stale against the new pointer even when its envelope and
  signature verify.
