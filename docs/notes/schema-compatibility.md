# The schema compatibility corpus

Authority: the implementation plan, Section 7.1's closing sentence —
"These compatibility rules are enforced by old-reader/new-writer and
new-reader/old-writer fixtures"; bead `aa-fe4cf4bd`. Requirement
OPS-009 (schema and protocol evolution stays readable by a documented
compatibility path) is the register's mapping for this corpus:
`T-OPS-009` is located here and verified in the definition-of-done fast
lane. The corpus also produces evidence for VAL-001 (unknown versions
and security enums fail closed), STO-010 (the adapter/projection
version preserved in provenance), and STO-012 (derived pipelines under
separate, pipeline-versioned prefixes).

The corpus is a committed, byte-pinned bundle that proves the whole
Section 7.1 compatibility policy mechanically: a matrix of writer
documents read by two reader generations, the negative cases every
reader must reject, and the candidate "v1.2" schemas a policy checker
must flag as requiring a new major. Every rule in the plan's table and
closing paragraph maps to at least one pinned scenario, and a coverage
check — not a manual count — enforces that mapping.

| File | Role |
|---|---|
| [`tools/compatgen.py`](../../tools/compatgen.py) | The deterministic generator, verifier, and compatibility policy checker (`--generate`, `--verify [--require-complete]`, `--self-test`). |
| [`schemas/v1/examples/compat/`](../../schemas/v1/examples/compat/) | The committed bundle — 35 files, 31 scenarios, one `manifest.json` coverage map. |
| [`schemas/v1/examples/conformance/`](../../schemas/v1/examples/conformance/) | Source of the old-writer envelope, payload, attempt, and receipt baselines (digest-pinned here). |
| [`schemas/v1/examples/provenance/`](../../schemas/v1/examples/provenance/) | Source of the old-writer occurrence manifest and attestation baselines (digest-pinned here). |

## The two reader generations

- **v1.0** is the shipped `schemas/v1` family itself. The manifest
  records the SHA-256 of every reader stem (`ingest-envelope`,
  `ingest-request`, `ingest-receipt`, `occurrence-manifest`,
  `upload-attestation`), so the corpus always names the schema
  generation it was verified against; edit a schema without
  regenerating and `--verify` fails on the manifest's own bytes.
- **v1.1** is a *mechanical projection* of that family, not a hand-
  written future schema: each of the four retain-ignore durable records
  (envelope, occurrence manifest, upload attestation, receipt) gains
  exactly one hypothetical optional field — `client_build`,
  `adapter_build_id`, `uploader_agent_version`, `server_build` — each
  declared with the `optional-additive-v1` compat metadata and a
  `bearing` an additive field must state. Every other stem is shared
  with v1.0 unchanged. This is exactly the additive change Section 7.1
  permits inside a major, so "the new reader" in every new-reader case
  is precisely "v1 plus one legal addition".

The old-writer documents are the sibling corpora's committed golden
baselines — the conformance corpus's `valid-direct-baseline` envelope,
payload, attempt, and receipt, and the raw-provenance corpus's direct
upload occurrence manifest and first-request attestation — each pinned
by digest in the manifest. Nothing new is invented about v1; every
v1.1 document is a baseline plus one member.

## Scenario taxonomy

Three kinds, all regenerated and verified by `--verify`:

1. **`compatible`** — the positive matrix. `orn-*` (old reader, new
   writer): a v1.1 writer's document is accepted by the v1.0 reader,
   the unknown member survives a parse → canonicalize round trip, the
   pinned `signed_bytes_sha256` covers canonical bytes *including* it,
   and every identity and object key equals the baseline's. `nro-*`
   (new reader, old writer): the untouched v1.0 documents stay
   accepted, pinning readers-retain-old-version support on the
   occurrence, attestation, and receipt axes. The storage-layout
   scenarios pin key stability across writer generations, the
   adapter-projection bump (fresh occurrence, stable blob, old objects
   never overwritten), the new-profile segment, and derived-pipeline
   isolation (rebuildable, versioned keys, prefix-disjoint from raw).
2. **`rejected`** — the negative matrix. Unknown security- and
   identity-bearing enum values (seven named cases) and unknown
   majors on every axis (`envelope`/`protocol`/`occurrence`/
   `attestation`/`receipt` version 2) fail closed under *both*
   generations, each rejection pinned to the offending member via the
   error's JSON path; a `version=2` envelope media type is refused at
   framing before any body parse (the route-major rule); a float in a
   would-be additive field has no RFC 8785 form and is rejected at the
   canonicalization layer even though an open-shape schema alone would
   accept it.
3. **`policy`** — candidate "v1.2" schemas committed as fixtures
   together with the finding codes the built-in checker must return:
   adding a required field, redefining a field, weakening an identity
   input, growing a fail-closed enum, drifting the identity-derivation
   registry, and repurposing an object-key prefix map to
   `requires-v2`/`requires-new-prefix`. Each finding carries its
   behavioural proof, not just the code: an old-writer document the
   candidate accepts or rejects differently, or a committed object
   whose key the mutated grammar would move.

## Coverage and digest pinning

The manifest's `rules` block is the Section 7.1 inventory (the seven
table rows plus additive-optional, retained-unknown-optional,
fail-closed enums/majors, no-floats, requires-v2 — eleven ids), and
`coverage` maps each rule to its scenarios. `--verify` fails if any
rule has no scenario, any scenario names an unknown rule, or the map
is missing a rule: the parent bead's acceptance criterion is a check,
not a count. Three further pin families keep the proof honest:

- **Baseline digests** — the sibling corpora's golden files are pinned
  by SHA-256, so drift there forces regeneration here rather than
  silently re-deriving against changed bytes.
- **Reader-stem digests** — the v1.0 generation is the shipped schema
  bytes themselves, digest-pinned per stem.
- **`signed_bytes_sha256`** — the canonical bytes a signature covers
  (the whole record for the envelope; the record minus its signature
  member for the receipt), pinned *including* the retained unknown
  member, so an implementation that drops unknown data breaks the
  digest, not just the schema.

On top of the named enum scenarios, `--verify` runs an exhaustive
failClosed-enum matrix: every top-level property whose `common.json`
def is a closed enum is fed a synthesized unknown value under both
reader generations and must be rejected (30 checks at current shape;
a collapse below ten fails as a vacuous matrix).

## Determinism and content safety

No entropy source, no clock, no key material: this corpus proves the
schema and canonical-bytes layers only, and deliberately leaves
signature-level proofs to the conformance corpus, whose
`*signed_bytes_sha256` convention it reuses. Every identifier and
document byte derives from the sibling corpora's pinned synthetic
baselines (SEC-010). Bundle metadata files are RFC 8785 canonical
JSON plus one trailing LF; regeneration is byte-identical everywhere,
proven by `--verify`'s byte comparison of every file against the
committed tree (unexpected or missing bundle files fail too).

## Regeneration and verification

```sh
tools/compatgen.py --generate                # rewrite the committed bundle (byte-identical)
tools/compatgen.py --verify                  # regenerate, byte-compare, verify every scenario
tools/compatgen.py --verify --require-complete   # ...and fail on any deferred verification
tools/compatgen.py --self-test               # prove the rejection paths in memory
```

Exit codes follow the repo convention: 0 pass, 2 byte drift or
non-canonical formatting, 3 verification/coverage/policy failure,
4 `jsonschema` unavailable. After changing a schema, an additive-field
declaration, or a sibling baseline, regenerate and commit the tool,
bundle, and manifest together.

`scripts/definition-of-done.sh` runs the corpus in the fast lane as
two checks: **compat corpus** (`--verify --require-complete`, so a
deferred scenario verification can never silently outlive the split
that owed it) and **compat policy** (`--self-test`, which proves the
rejection paths: the policy checker's finding codes, the key-grammar
and canonicalizer rejections, the coverage-hole detector, and the
baseline digest tamper check). The requirement-verification register
maps `T-OPS-009` to `tools/compatgen.py` in that lane
([verification](verification.md)).

## Where this connects

- [`wire-schemas.md`](wire-schemas.md) — the wire family whose
  fail-closed enums and version consts the rejected scenarios
  exercise.
- [`raw-provenance-schemas.md`](raw-provenance-schemas.md) — the
  durable records whose additive evolutions and object-key grammars
  the compatible and policy scenarios pin.
- [`conformance-corpus.md`](conformance-corpus.md) — the golden
  baselines and the signature-level proofs this corpus deliberately
  does not duplicate.
- [`fixtures.md`](fixtures.md) — the repo's other byte-exact
  regeneration gates and their content scans.

## Open questions

- The v1.1 projection adds one field per record. A real v1.1 with
  several additions per record should extend `ADDITIVE_FIELDS` (and
  regenerate) rather than grow hand-written reader files, so the
  projection stays provably mechanical.
- A `zstd` transport corpus would need the compressor-build-independent
  frame pin noted in [conformance-corpus.md](conformance-corpus.md);
  until then the layout scenarios render keys for a hypothetical
  `zstd-v2` *profile* without pinning its compressed bytes.
