# The orchestrator-provenance correlation record

Authority: the [implementation plan](../plan/plan.md), Section 8 Phase 9
deliverable "Have orchestrators reference canonical occurrence IDs rather
than uploading a second canonical transcript", with Section 7.4 (correlation
identifiers are join handles, joined exactly and never inferred — EC-13),
Section 7.5 (content-free provenance records; the attestation sets the
family's precedent), and requirement CAP-008 (exact capture is a capability
separate from harness-semantic capture, joined by explicit trace/request
IDs). The record's types, its digest construction, and the relationship fold
belong to `archivist-protocol`
([crate ownership](crate-ownership.md)): layer-0 wire material, like every
other record family's identity machinery.

Implementation: `crates/archivist-protocol/src/orchestrator_correlation.rs`.
The record-shape version is `orchestrator_correlation_version`, currently 1.

## The record, and what stays out

One record is one orchestrator's content-free reference from its own
provenance to canonical occurrences its harness sessions produced:

| Member | Carries |
|---|---|
| `orchestrator_correlation_version` | the record-shape version (1) |
| `tenant_id` | the archive partition the references point into |
| `trace_id` | the orchestrator operation's `UUIDv7` trace identity |
| `orchestrator_attempt_id` | the orchestrator attempt, joined exactly (EC-13) |
| `inference_request_id` | optional; the logical inference the record narrows to — absent, never null |
| `occurrence_ids` | the referenced `occurrence-v1` digests, ascending and duplicate-free, at least one |
| `correlation_digest` | construction `orchestrator-correlation-v1`, self-verifying (VAL-005) |

Everything else is rejected by name. The member set is **closed**: a record
carrying any other member is refused, not retained and not ignored. This is
the mechanical half of the family's central rule — there is no spelling of a
completeness assertion this record accepts.

Three things stay out by construction:

- **No content.** The record carries identifiers and digests only. A
  harness adapter already captured the session bytes; the orchestrator
  re-emitting them as a second artifact would multiply raw transcript
  storage and change nothing the archive could verify. The record cites
  the occurrences that exist instead.
- **No completeness claim.** Correlation is not coverage. The exact-
  inference denominator stays the expected-inference ledger (the
  `ExactOutcome` types in `archivist-adapter-sdk`, bead `aa-e8816fd4`), and
  semantic capture stays independent of this record in every case. A
  session whose occurrences are all referenced here has not thereby proved
  anything about capture completeness.
- **No identity inputs.** The correlation identifiers are join handles:
  they enter no blob, occurrence, session, artifact, or object-key
  derivation (plan Section 7.4). A correlation record can be deleted,
  restated, or re-reported without changing any stored object's identity.

## Identity and set semantics

The digest is SHA-256 over the canonical record bytes with the digest
member removed — the same self-verifying exclusion shape as the usage
summary (VAL-005). `parse` recomputes it on every read, so an altered
reference set, a reordered array, or any other post-construction edit
fails before the record is returned.

The occurrence references are a **set**: `new` canonicalizes them to
ascending order and refuses duplicates within one record, so the digest is
a pure function of the relationship the record states. Two reports of one
relationship are one record identity, not two — re-reporting never
multiplies, which is the storage half of the acceptance: correlation
records are references, and references are cheap because the transcript
exists exactly once.

## The relationship fold

`OrchestratorCorrelationGraph::build` folds a set of records into the
relationship structure: operations by `trace_id`, each operation's attempts
by `orchestrator_attempt_id`, each attempt's references split by logical
inference (records with no `inference_request_id` reference at the
attempt's own scope — provenance about the attempt as a whole, not an
inference). The reverse join (`referencing`) answers an occurrence-side
reader's question — which record-set provenance named this occurrence.

The fold is deliberately reference-only. An occurrence named in the graph
is not asserted to exist, to be complete, or to have passed any capture
gate; the fold fabricates no such semantics. Repeated references to one
occurrence collapse into one entry per distinct relationship.

## Storage layout

The record is asserted raw provenance, so its family lives under the raw
namespace beside the attestations, not under the catalog rebuild's
`derived/` namespace:

```text
tenants/<tenant>/v1/raw/correlations/<digest-prefix>/<correlation_digest>.json
```

The key is a pure function of the record's own bytes, sharded by the
digest's first two hex, reconstructible from the stored record alone
(plan Section 7.5). The stored object's bytes are the RFC 8785 canonical
serialization plus exactly one trailing LF — the family-wide rendering;
the canonical bytes are also the digest preimage, so the rendering is not
a presentation choice.

## What lands later

The wire schema (`orchestrator-correlation.json` in the `schemas/v1`
vocabulary) and its golden corpus arrive with the transport slice that
first puts the record on a route — the same split the exact-inference
family used (schema bead `aa-b5cf6541`, transport bead `aa-2892115b`).
No ingest-path change is part of the correlation record itself: the
envelope's optional correlation identifiers
([`ingest-envelope.json`](../../schemas/v1/ingest-envelope.json)) remain
the wire-time join, and this record is the durable one.
