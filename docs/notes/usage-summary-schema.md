# The usage-summary schema

Authority: the implementation plan, Phase 10 (token accounting) and
Sections 7.1 (version axes), 7.5 (object keys and derived layout), and
7.10 (retention and sweep); requirements STO-012 (derived artifacts
retain raw occurrence IDs), SEC-006 and SEC-010 (no key material in
records, synthetic examples only), and the self-verification discipline
VAL-005 carried into the derived namespace. The schema is
[`schemas/v1/usage-summary.json`](../../schemas/v1/usage-summary.json);
it shares the v1 wire vocabulary pinned in
[`schemas/v1/common.json`](../../schemas/v1/common.json) (which also owns
the family's `usage-summary-object-key` pattern) and cites occurrence
identities built by the constructions pinned in
[`schemas/v1/ingest-identifiers.json`](../../schemas/v1/ingest-identifiers.json).
The record's types and its digest construction belong to
`archivist-protocol` — the same layer-0 crate that owns every wire
family's vocabulary, canonical serialization, and derivation machinery
([crate ownership](crate-ownership.md)); the producer is the
deterministic `archivist catalog rebuild`, a Phase 10 deliverable, and
nothing on the ingest path emits or accepts this record.

## The record, and what stays out

A usage summary is the versioned, content-free derived row the catalog
rebuild emits per raw occurrence — the model identity and service tier
the source reported, the harness-reported token counts read straight
from the raw bytes, the number of assistant messages they were summed
from, the adapter projection that read them, and the occurrence
provenance. It is called **usage, never consumption**:
`consumption-policy-v1` governs who may read derived content, which is a
different question. The Phase 10 material and where it lives:

| Phase 10 material | Where it lives |
|---|---|
| Record-shape version | `usage_summary_version` — integer, currently 1 |
| Row identity | `usage_summary_digest` — construction `usage-summary-v1`, self-verifying |
| Tenant scope | `tenant_id` — the derived family stays tenant-scoped |
| Pipeline axis | `pipeline_id` (closed enum, v1 ships exactly `usage`), `pipeline_version` (v1 pins `1`) |
| Reading provenance | `adapter_id`, `adapter_projection_version` — the projection whose usage reader produced the counts |
| Raw evidence | `occurrence_id` — the `occurrence-v1` digest, never a raw object path |
| Source-reported identity | `model_id`, `service_tier` — optional, omitted-never-null |
| The harness-reported denominator | `harness_usage` — `measured` or `unknown`, never absent, never a third encoding |
| The provider-observed denominator | `provider_usage` — reserved member, `measured` or `unknown`, and **absent** when the occurrence is outside exact-capture coverage |

`harness_usage` is the record's contract core. `measured` is a complete
object: every count required, at least one assistant message summed
(`assistant_message_count ≥ 1`), and explicit zeros where the source
genuinely reported none — `cache_read_tokens: 0` is an observation, not
an absence, so no member is ever ambiguous between zero and unreported.
`unknown` is the bounded refusal: exactly `{state, reason}` and nothing
else, with `reason` from the closed set `absent` (no usage region at
all), `malformed` (a region present but not parseable under the
source's own declared shape), and `unsupported` (the region parses but
the pinned projection does not support its shape — an unknown usage
dialect, cache creation with no ephemeral-class split, or counts
spanning more than one model identity or service tier). A count may
never sit beside an `unknown`: zeros next to the refusal would
reintroduce the ambiguity the state exists to remove. This is the
plan's "an incomplete source can never read as free" sentence, made
mechanical.

Everything else is rejected by name. The reserved list — the schema's
`x-archivist.reservedFields`, enforced member-for-member by the `not`
block — covers the categories this family must never carry:

- **transcript content** — `text`, `prompt`, `prompts`, `transcript`,
  `message`, `messages`, `body`, `completion`, `response`, `context`,
  `plaintext`, `source_content`, `redacted_content`, `tool_*`,
  and the rest of the content-carrier names;
- **monetary material** — `cost`, `cost_usd`, `price`, `prices`,
  `pricing`, `unit_price`, `rate`, `cents`, `currency`, `usd`, `spend`,
  `billing`, `charge`, `fee` — the archive stores no monetary amount:
  cost is computed outside the archive at query time from model, service
  tier, token counts, and a versioned price table, because provider
  prices change retroactively and per contract, and a stored amount
  would be unreproducible from the raw bytes and wrong from the moment
  pricing moved;
- **grand-total tokens** — `total_tokens`, `combined_tokens`,
  `summed_tokens`, `aggregate_tokens`, `total_token_count` — no
  precomputed total exists to disagree with the sum of its own parts;
- **governance and redaction material** — `use_approval`, `approval`,
  `approved_by`, `policy`, `policy_version`, `assessment*`,
  `classification`, `severity`, `verdict`, `trust_decision`,
  `redaction_map`, `pseudonym_map`, `salt`;
- **raw object paths** — `raw_object_key`, `object_key`, `path`,
  `source_path`, `blob_key`, `location`, `url` — traceability runs
  occurrence ID → catalog → the governed raw read (STO-012);
- **derivation-stability breakers** — `built_at`, `created_at`,
  `generated_at`, `produced_at`, `producer`, `run_id`, `recorded_at`,
  `ingested_at` — wall-clock, producer, and run identity never enter.

The negative matrix in [`tools/usagegen.py`](../../tools/usagegen.py)
`--verify` injects every reserved name into a valid record and proves
the schema rejects each one, so the content-freeness claim is
machine-checked rather than aspirational. The member grammars do the
other half of the work: `model_id` is a bounded token (≤ 128 bytes, no
whitespace, no control characters — a transcript sentence cannot fit),
every count is an integer, and the schema sets `floats: false` — the
derived family carries no floating-point value at all.

Because the record carries no transcript content it is **not subject to
`use-approval-v1`** — it raises none of the risk approval exists to
gate. It stays tenant-scoped and inherits raw retention: the
disabled-by-default mark-and-sweep (Section 7.10) removes the usage row
in the same pass that removes the cited occurrence, because a catalog
row that cannot be rebuilt from the raw prefix is a divergence.

## The digest

`usage_summary_digest` is SHA-256 under the domain label
`usage-summary-v1`, using exactly the framing every ingest identifier
uses — UTF-8 label bytes, one `0x00` terminator, an 8-byte unsigned
big-endian length, then that many bytes — over the RFC 8785
canonicalization of the complete record **with the
`usage_summary_digest` member removed**. That exclusion shape is the
same one `episode-v1`, the `control-record-v1` signature, and the
receipt-key certificate use, so one verifier core pattern walks every
family.

Two properties follow:

1. **Self-verification.** An auditor recomputes the digest from the
   stored record's own canonical bytes — nothing else — and refuses a
   mismatch (VAL-005). Every record in the example bundle is re-digested
   this way by `--verify`.
2. **Re-derivable identity.** The object key is a pure function of the
   digest — `tenants/<tenant>/v1/derived/usage/1/usage-summaries/<shard>/<digest>.json`,
   the shard being the digest's first two hex — so the key is
   reconstructible from the stored bytes alone and the Parquet inventory
   export can carry a stable row identity an auditor recomputes from the
   record itself.

Acyclicity comes free: the digest member is excluded from its own
preimage, and no member of a usage summary references any record derived
from it. A query-time cost computation binds a row by citing its digest
and never writes back — the record's write order is *after* the cited
occurrence and its upload attestation are durable, *before* anything
outside the archive prices it.

## Derivation stability and the rebuild gate

Every member is a deterministic function of the cited occurrence's raw
bytes, `pipeline_id` + `pipeline_version`, and the adapter projection
version that read the usage region. No wall-clock, producer, run,
assessment, approval, policy, or price input exists to make two
derivations of the same inputs diverge — which is what makes the
Phase 10 exit gate (catalogs rebuild byte-identically from the same raw
prefix and pipeline version) possible, and why the stability breakers
are rejected by name rather than merely omitted. One row per
occurrence: the catalog emits exactly one usage row per occurrence, and
the row exists only while that occurrence does.

## Versioning

`usage_summary_version` is the record-shape axis, independent of the
pipeline axis (`pipeline_id` + `pipeline_version`, the plan Section 7.1
derived two-axis rule: a changed mapping — which usage dialects are
supported, how the ephemeral classes map, the partial-coverage
discipline — is a new pipeline version writing a new derived prefix
segment, never a silent rewrite of an old row). This family takes the
**control-family deviation** from the plan's retain-ignore envelope
rule, recorded for the episode family in
[derived-episode-schema.md](derived-episode-schema.md) and extended
here: the closed shape is the compatibility rule
(`additionalProperties: false`, unknown fields rejected), and anything
beyond it — new members, redefined fields, changed digest rules — is
`usage_summary_version` 2. Unknown security-bearing enum values fail
closed, the plan Section 7.1 rule, not a compatibility break. The one
sanctioned in-major addition is already spent: `provider_usage` landed
inside pre-release v1 as the sibling record revision, so the closed
shape now rejects everything outside the two denominators, and the next
new member — whatever it is — is version 2.

The first denominator is semantic and complete for every supported
adapter. The Phase 9 provider-observed counts are the **second
denominator, `provider_usage`**: a separate, reserved member with its
own coverage state — never merged into `harness_usage`, never summed
with it; a row may carry both, either, or neither. Its `measured`
object aggregates the exact-inference `usage` artifacts reconciled to
the occurrence (`input_tokens`, `output_tokens`, `total_tokens`, and
`usage_report_count ≥ 1` as the coverage denominator, the analog of
`assistant_message_count`); `total_tokens` is the providers' own
reported total retained as reported, never recomputed from the parts.
Its `unknown` is the bounded refusal over a closed set of two:
`unreconciled` (covered traffic whose exact count does not yet exist)
and `malformed`. And the member's **absence is itself the third
coverage state**, distinct from its `unknown`: absent means the
occurrence is outside exact-capture coverage entirely — traffic that
was neither routed nor hooked — while `unknown` means covered traffic
whose exact count still does not exist. No producer API emits the member
yet: it stays reserved until the Phase 9 join that aggregates usage
reports per occurrence exists to derive it, so every committed
`provider_usage` row is generator-pinned.

## Canonical serialization

The record serializes as RFC 8785 canonical JSON (`x-archivist:
canonicalization rfc8785`, `floats false`, object keys sorted, no
whitespace) plus exactly one trailing LF, the family-wide rendering the
example bundle commits and `--verify` byte-checks. The canonical bytes
are also the digest preimage, so serialization is not a presentation
choice: two byte-serializations of one record would be two identities.

## The example bundle

[`schemas/v1/examples/usage-summaries/`](../../schemas/v1/examples/usage-summaries/)
is generated by [`tools/usagegen.py`](../../tools/usagegen.py) with zero
entropy (SEC-010): every identifier, model string, tier, and count is a
pinned synthetic constant, and every digest is computed with the
byte-exact construction pinned above. No monetary amount exists anywhere
in the generator or the bundle. The occurrence IDs cited as provenance
are the very IDs the [raw-provenance bundle](raw-provenance-schemas.md)
materializes, so the two bundles together demonstrate the Phase 10
traceability sentence: token questions answered by a content-free row
that traces to raw evidence by occurrence ID alone. The eight scenarios:

1. **full-coverage** — every measured member at a nonzero value, model
   and tier present: the fixture that round-trips the full shape.
2. **observed-zero** — a measured record whose cache and reasoning axes
   are explicit zeros: the source reported a complete usage object that
   simply used no cache and reasoned nothing. Zero is an observation;
   this record is the contrast that keeps "never zero" from being
   misread as "never zero values".
3. **usage-absent** — the source carried no usage region at all: the
   record validates as `unknown`/`absent`, and no all-zero measured
   encoding of the occurrence exists anywhere in the family, because
   the measured branch demands every count with at least one summed
   message.
4. **usage-malformed** — a present-but-unparseable usage region: the
   bounded refusal, never a partial sum over whatever happened to
   parse. `service_tier` is omitted here — the source named no tier.
5. **usage-unsupported** — the region parses but the pinned projection
   does not support its shape: `unknown`/`unsupported`, with both
   identity members omitted rather than invented.
6. **provider-observed** — both denominators measured on one row: the
   harness semantic counts and the provider boundary's own counts
   disagree (the provider's total includes tokens the harness never
   saw), and the record carries both without any grand total.
7. **provider-only** — the harness denominator is `unknown`/`absent`
   while the provider denominator is measured: exact capture answered
   the question the harness could not. The row carries exactly one of
   the two denominators and validates.
8. **provider-unreconciled** — covered traffic whose exact count does
   not exist yet: `provider_usage` present as `unknown`/`unreconciled`
   beside a measured harness denominator, the third cell of the
   coverage matrix (member-absent rows appear among scenarios 3–5).

Regeneration and verification:

```sh
tools/usagegen.py --generate   # write the bundle (byte-identical)
tools/usagegen.py --verify     # regenerate, byte-compare, schema-validate
tools/usagegen.py --self-test  # prove the rejection paths
```

`--verify` regenerates the bundle and byte-compares every file, requires
each JSON file to be exactly its canonical rendering plus one trailing
LF, re-digests every record from its own bytes, walks every value for
nulls (members are omitted, never null), checks the pinned
pipeline/projection identity and the occurrence citations against the
provenance bundle, matches every object key against the
`usage-summary-object-key` pattern in `common.json` (shard included),
validates every committed record against the schema (draft 2020-12,
`common` resolved from `schemas/v1/common.json`), runs the reserved-name
negative matrix plus the structural cases (counts beside an `unknown`,
a measured record missing a count member, zero summed messages,
negative and fractional counts, an extra ephemeral class, null where a
member is omitted, the `harness_usage` member removed, unknown version
or pipeline) with a valid control that must not be rejected, proves the
two denominators cannot collapse: the provider counters cannot ride
`harness_usage`, the harness axes cannot ride `provider_usage`, the
artifact's own counter names cannot be hoisted to the root, and the
provider denominator cannot be summed into one number — with rows
carrying one denominator and both staying valid as controls — pins the
both/either/neither coverage matrix of the committed records against
the manifest's counts, and reconciles the reserved provider member
with the exact-inference artifact schema's own `usage`-kind definition
(read from `schemas/v1/inference-artifact.json`, never restated). It
then proves the committed records collectively exercise every member
the schema defines — required and optional, measured and unknown, both
ephemeral classes, both denominators. Exit codes: 0 pass, 2 bundle
directory missing, 3 byte drift, non-canonical formatting, or
schema/invariant failure, 4 `jsonschema` unavailable.

`--self-test` proves the same rejection paths without the committed
bundle: the digest construction recomputes from a record's own
canonical bytes, changes under tampering, excludes the digest member
from its own preimage, and pins its domain label; the derived object
key matches the `usage-summary-object-key` pattern with the digest's
own shard, and foreign pipelines and non-hex shards miss it; the
per-record invariants reject every fault class (tampered digest, null
where a member is omitted, counts beside an `unknown`, a reason outside
the closed set, wrong pipeline or projection identity, an
unvouchable occurrence, zero summed messages, negative and fractional
counts, an extra ephemeral class — and the provider denominator's own:
measured-with-zero-reports, counts beside its `unknown`, a reason
outside its closed set, the denominator summed into one number) while
valid records pass clean — one denominator alone and both together;
`--generate` writes every file byte-identically, is idempotent on its
own bundle, and refuses a foreign directory; the schema rejects
the whole reserved-name matrix while the valid control stays valid; and
the reconciliation with the exact-inference artifact schema catches
drift injected on either side of the two schemas.
It shares `--verify`'s exit-code contract: 0 pass, 3 on any failed
proof, 4 `jsonschema` unavailable.

The bundle is wired into the definition-of-done fast lane as the
`usage corpus` check, with `--self-test` beside it as the
`usage corpus policy` check (the way the fixture and exact-inference
corpora are wired: the scan runs per change, and `--all` inherits the
full regeneration), and the Rust side replays the committed corpus against
the schema in
[`crates/archivist-protocol/tests/usage_summary_corpus.rs`](../../crates/archivist-protocol/tests/usage_summary_corpus.rs) —
the crate's own parser, canonicalizer, and `FrameBuilder` re-derive
every digest and re-check the closed shape, so the record shape is
enforced where its producer will be built.

## Relationship to the other families

The family shares `schemas/v1/common.json` with the ingest wire, raw
provenance, and episode schemas — one vocabulary per version directory —
and its provenance axis is the ingest family's: the `occurrence-v1`
derivation is normative for both, so the same `occurrence_id` names the
stored manifest's key and the usage row's evidence citation. The
digest's exclusion shape is shared with the episode and control
families. The `model_id` grammar (`AdapterId`-style bounded token,
deliberately not a closed enum) is the raw-provenance decision again:
community adapters and new model catalogs never require a schema
change.

With the [metrics conventions](metrics.md) the relationship is a
boundary, not an overlap. The metrics registry governs the *telemetry*
surface — bounded-label, aggregated signals — and its `artifact_kind`
enum already carries `usage` as a Phase 9 exact-capture artifact class
at the provider boundary; that label names captured material, not this
record's denominator. Per-occurrence token accounting is derived-record
data, answered by query against the derived prefix and the Parquet
inventory, never by a per-occurrence metric (which would be exactly the
unbounded cardinality the metrics registry forbids). The two usage
denominators stay separate on both surfaces: the harness-reported
counts here, the provider-observed exact-capture counts of the
Phase 9 inference family — separate columns, separate coverage states,
never summed — and when the provider-observed denominator lands as the
reserved sibling revision, its reconciliation with the
exact-inference schema is that revision's contract to state.

## Open questions

- The two ephemeral classes are the whole of the v1 cache-creation
  axis. A source reporting cache creation under an unrecognized class
  is `unsupported` for the whole denominator — the projection never
  distributes an unclassifiable total across classes, because an
  invented split is indistinguishable from a real one downstream. The
  first real third class should double-check whether it is a
  `harness-usage` shape change (record revision) or merely a new
  pipeline version before assuming either.
- `assistant_message_count` discloses partial coverage by being lower
  than the occurrence's total assistant messages. Nothing in v1 carries
  the *total*, so coverage fractions are not computable from the archive
  alone; if a consumer ever needs them, that is a new member and a
  record revision, not a reinterpretation of this one.
- The query-time price table (its format, versioning, and who curates
  it) is deliberately outside the archive's contract. The record pins
  only the inputs — model identity, service tier, counts — that make
  pricing somebody else's problem.
