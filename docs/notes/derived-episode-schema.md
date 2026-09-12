# The redacted episode schema

Authority: the implementation plan, Phase 10 (safe consumption) and
Sections 7.1 (version axes) and 7.5 (object keys and derived layout);
requirements STO-012 (derived artifacts under separate, pipeline-versioned
prefixes, retaining raw occurrence IDs), SEC-009 (raw data is untrusted
input; derived pipelines redact, track provenance, and defend before
agent consumption), SEC-006 and SEC-010 (no key material in records or
examples, synthetic examples only), and the validation discipline
VAL-002/VAL-005 carried over as producer invariants and self-verification.
The schema is
[`schemas/v1/derived-episode.json`](../../schemas/v1/derived-episode.json);
it shares the v1 wire vocabulary pinned in
[`schemas/v1/common.json`](../../schemas/v1/common.json) (which also owns
the family's `derived-episode-object-key` pattern) and cites occurrence
identities built by the constructions pinned in
[`schemas/v1/ingest-identifiers.json`](../../schemas/v1/ingest-identifiers.json).

## The record, and what stays out

An episode is the deterministic derived record the pinned `redaction-v1`
pipeline emits from validated raw occurrences — and it is deliberately
the dumbest object in the derived family. Every judgment about it lives
in a record that comes *after* it and points back at it by digest:

| Phase 10 material | Where it lives |
|---|---|
| Redacted content (records in episode order) | `records` — role, ordinal, optional `source_time`, backward-only `parent_ordinals`, redacted `content` |
| Raw occurrence provenance | `occurrence_ids` — the `occurrence-v1` digests, never raw object paths |
| Redaction metadata | `marker_counts` — the five detector families that destroy what they match, every class explicit, zero included |
| Transformation metadata | `pseudonym_counts`, `pseudonym_key_id`, `detector_corpus_digest` — the five pseudonym families, the tenant-scoped key reference, and the digest of the corpus that froze the detectors |
| Pipeline version | `pipeline_id` (`redaction`), `pipeline_version` (v1 pins `1`) |
| Episode identity | `episode_digest` — construction `episode-v1`, self-verifying |

Everything else is rejected by name. The reserved list — the schema's
`x-archivist.reservedFields`, enforced member-for-member by the `not`
block — covers the four categories this family must never carry:

- **embedded risk assessment or trust decision** — `risk_assessment`,
  `assessment`, `assessment_digest`, `assessment_id`, `labels`,
  `classification`, `severity`, `verdict`, `trust_decision`;
- **use approval or governance material** — `use_approval`, `approval`,
  `approved_by`, `policy`, `policy_version`;
- **raw object paths** — `raw_object_key`, `object_key`, `path`,
  `source_path`, `blob_key`, `location`, `url`;
- **reversible redaction material** — `redaction_map`, `pseudonym_map`,
  `reverse_map`, `removed_content`, `plaintext`, `pseudonym_salt`,
  `salt`, `mapping` (the plan's no-removed-bytes rule: counts by class
  are the whole redaction report);

plus the derivation-stability breakers — wall-clock, producer, and run
identity (`built_at`, `created_at`, `generated_at`, `produced_at`,
`producer`, `run_id`) — which would make two derivations of the same
inputs diverge and break the rebuild exit gate. The negative matrix in
[`tools/episodegen.py`](../../tools/episodegen.py) `--verify` injects
every reserved name into a valid episode and proves the schema rejects
each one, so the boundary is machine-checked, not aspirational.

Provenance is carried as occurrence IDs, never paths, on purpose: an ID
is an opaque digest that names evidence, while a path would hand any
derived consumer a direct route to unredacted bytes. Traceability from
an episode to its raw evidence runs occurrence ID → catalog → the
governed raw read, so raw stays separately governed (the Phase 10 exit
gate: derived data traceable to raw occurrences without exposing raw
object paths to unauthorized consumers).

## The digest, and why assessment binding cannot be circular

`episode_digest` is SHA-256 under the domain label `episode-v1`, using
exactly the framing every ingest identifier uses — UTF-8 label bytes,
one `0x00` terminator, an 8-byte unsigned big-endian length, then that
many bytes — over the RFC 8785 canonicalization of the complete episode
object **with the `episode_digest` member removed**. That exclusion
shape is the same one the `control-record-v1` signature and the
receipt-key certificate use, so one verifier core pattern walks every
family.

Two properties follow, and they are the bead-level acceptance of this
schema:

1. **Self-verification.** An auditor recomputes the digest from the
   stored record's own bytes — nothing else — and refuses a mismatch
   (VAL-005 discipline carried into the derived namespace). Every
   episode in the example bundle is re-digested this way by `--verify`.
2. **Acyclic binding.** The digest member is excluded from its own
   preimage, and *no member of an episode references any record derived
   from it*. So a later `risk-assessment-v1` binds the episode by
   carrying `episode_digest`, and a `use-approval-v1` binds episode and
   assessment the same way — in neither direction does one record's
   serialization contain the other's bytes. A re-assessment supersedes
   in place, a policy change fails closed, and an approval can expire
   or be revoked, all without the episode ever knowing: governance
   state changes never rewrite derived bytes, and derived bytes never
   freeze governance state into the very object it is about.

## Derivation stability and the rebuild gate

Every member is a deterministic function of the input occurrence set,
`pipeline_id` + `pipeline_version` (with the detector corpus that
version freezes, digest-pinned as `detector_corpus_digest`), and the
tenant pseudonym key. No wall-clock, producer, run, assessment,
approval, or policy input exists to make two derivations of the same
inputs diverge. That is what makes the Phase 10 exit gate — catalogs
and episodes rebuild byte-identically from the same raw prefix and
pipeline version — possible at all, and it is why the stability
breakers are rejected by name rather than merely omitted.

`detector_corpus_digest` makes the derivation's *behavior*
content-addressed: two producers claiming the same pipeline version but
differing effective detectors are exposed by differing corpus digests
before their episodes can be mistaken for each other, and a rebuild
that drifts from the pinned corpus fails the byte-identical gate rather
than silently staling every assessment.

`pseudonym_key_id` is a keyed self-ID — lowercase hex of
HMAC-SHA256(pseudonym key, `pseudonym-key-id-v1`) — recomputable and
verifiable only by key holders and disclosing nothing about the key
(SEC-006; the key itself never appears in any record, file, or
argument). Rotating the key changes every pseudonym, hence the episode
bytes, hence `episode_digest`: all assessments over the old episodes go
stale and use fails closed until re-derivation and re-assessment.
Rotation is a derived-corpus event, deliberately not transparent.

## Versioning

`episode_version` is the record-shape axis, independent of the pipeline
axis (`pipeline_id` + `pipeline_version`, the plan Section 7.1 derived
two-axis rule: a changed detector is a new pipeline version writing a
new derived prefix segment, never a silent rewrite of an old episode).
This family takes the **control-family deviation** from the plan's
retain-ignore envelope rule, and this note is where that deviation is
recorded and why: the ingest envelope, occurrence manifest, attestation,
and receipt are data-plane records whose unknown additive fields are
provenance carried inside signed bytes, so an old reader may retain and
ignore them; an episode is the object a *classifier reasons over*, and
a rule set (or a human, or an agent-facing loader) must never reason
over content it only partially understands — an unrecognized member
might change what the content means. So the closed shape is the
compatibility rule (`additionalProperties: false`, unknown fields
rejected), the only in-place growth is new tokens inside the
already-closed enums (`role`, `pipeline_id`) shipped together with the
readers that understand them, and anything else — new members,
redefined fields, new required members, changed digest rules — is
`episode_version` 2. Unknown security-bearing enum values fail closed,
the plan Section 7.1 rule, not a compatibility break.

## The example bundle

[`schemas/v1/examples/episodes/`](../../schemas/v1/examples/episodes/)
is generated by [`tools/episodegen.py`](../../tools/episodegen.py) with
zero entropy (SEC-010): every identifier, timestamp, key, and content
byte is a pinned synthetic constant, and every derived value — the
episode digests, the pseudonym key self-ID, every pseudonym text, the
detector corpus digest — is computed with the byte-exact constructions
pinned above. The occurrence IDs cited as provenance are the very IDs
the [raw-provenance bundle](raw-provenance-schemas.md) materializes, so
the two bundles together demonstrate the traceability sentence end to
end: episode → occurrence ID → the provenance bundle's manifest, with
no raw object path anywhere in the derived bytes. The marker and
pseudonym text formats are the *synthetic* rendering formats of the
pinned example corpus (`pipeline/redaction-v1-corpus.json`) — the
schema bounds the bytes, the corpus digest pins what produced them, and
neither claims to be the real producer's format. The manifest records
the scenarios and their assertions:

1. **full-detector-sweep** — every census class nonzero; the four
   roles, contiguous ordinals, backward-only parents, and source_time
   present and absent; the census provably counts the content.
2. **clean-scan** — every census class an explicit zero, so a clean
   scan is distinguishable from a detector that silently failed to run.
3. **shared-pseudonym-space** — one episode from two occurrences, and a
   source hostname shared with scenario 1 pseudonymized to
   byte-identical text: tenant-scoped analytic stability, with the two
   episodes remaining distinct objects under distinct digests.

Regeneration and verification:

```sh
tools/episodegen.py --generate   # rewrite the bundle (byte-identical)
tools/episodegen.py --verify     # byte-compare, schema-validate, check invariants
```

`--verify` regenerates the bundle and byte-compares every file, requires
each JSON file to be exactly its canonical rendering plus one trailing
LF, re-digests every episode from its own bytes, re-counts both censuses
from the content actually present, checks ordinals/parents/occurrence
ordering, matches every object key against the
`derived-episode-object-key` pattern in `common.json` (shard included),
recomputes the corpus digest and the pseudonym key self-ID, validates
every instance against the schema (draft 2020-12, `common` resolved from
`schemas/v1/common.json`), and runs the forbidden-member negative
matrix — every reserved name plus unknown member, unknown role, unknown
pipeline, duplicate occurrence IDs, empty records, and an unknown record
member must be rejected, with a valid control case that must not be.
Exit codes: 0 pass, 2 drift or non-canonical formatting, 3 schema or
invariant failure, 4 `jsonschema` unavailable.

Wiring the bundle into the definition-of-done fast lane (the way the
conformance and compat corpora are wired) is deliberately not done in
the defining change: the gate list is being edited concurrently for the
release-container baseline, and a `--verify` row belongs with the
producer work that will consume this schema, where its failures become
actionable. The generator is committed runnable either way.

## Relationship to the other families

The family shares `schemas/v1/common.json` with the ingest wire and raw
provenance schemas — one vocabulary per version directory, no
per-family copies of the identifier grammars or key patterns — and its
provenance axis is defined by the ingest family's constructions: the
`occurrence-v1` derivation is normative for both, so the same
`occurrence_id` names the stored manifest's key and the episode's
evidence citation. The digest's exclusion shape is shared with the
control family's signing construction. The [schema compatibility
corpus](schema-compatibility.md) intentionally does not cover this
family: it exists to pin the retain-ignore rule for the four data-plane
durable records, and this family rejects that rule by design.

## Open questions

- The five marker classes and five pseudonym classes are the plan's
  pinned v1 detector families. A sixth family is a corpus change (new
  pipeline version, new derived prefix) *and* a census shape change —
  the census members are required with explicit zeros, so a new class
  cannot arrive additively for old readers. That is the intended
  fail-closed behavior, but the first real detector addition should
  double-check the blast radius before assuming episode_version 2 is
  avoidable.
- `source_time` is bounded to UTC second precision by the shared
  timestamp shape. If a harness ever reports sub-second event times
  that matter to classification ordering, the shared
  `rfc3339-utc-timestamp` shape gains fractional support (its pattern
  already permits it) rather than this family growing a private format.
- An episode spans occurrences from a single tenant by construction
  (`tenant_id` scopes the object key and the pseudonym key). Whether a
  cross-tenant derivation is ever needed is a governance question that
  has not been asked yet; if it is, it is a new pipeline under a new
  prefix, not a member added here.
