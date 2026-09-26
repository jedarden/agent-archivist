# The published inference-coverage manifest

Authority: the implementation plan, Section 8 Phase 9 exit gate ("the
coverage report separately states semantic session coverage and exact
inference coverage, including observed, partial, failed, and unobserved
counts for each instrumented client") and the 1.0 gate ("make exact
inference capture and its independent coverage report part of the 1.0
compatibility matrix; exact coverage is required for traffic routed
through a supported proxy or SDK hook, while bypassed traffic remains
explicitly unobserved"); requirements CAP-007 and CAP-008; threat `EC-13`
(semantic and exact coverage stay independent). The publisher is
[`archivist-adapter-sdk::coverage_manifest`](../../crates/archivist-adapter-sdk/src/coverage_manifest.rs);
the per-route partition it publishes was landed by bead `aa-76e1c512`
(`ExpectedInferenceLedger::route_coverage` / `route_states`).

## What one document publishes

`InferenceCoverageManifest::publish` joins four inputs the SDK already
owns — the compatibility matrix, the expected-inference ledger, one
semantic snapshot, and one ephemeral teardown report — into a single
bounded, content-free document with a fixed top-level key set:

| Key | Carries | Names |
|---|---|---|
| `schema`, `schema_version` | `archivist.inference-coverage/v1`, `1` | the manifest schema version (growth is a new token, never a key added in place) |
| `clients` | one flat row per claimed integration | the **claimed routes**: integration token, route, lifecycle version, **coverage evidence** digest — beside that route's observed / partial / failed / unobserved counters and open denominator |
| `routes` | one row per closed route (`proxy`, `sdk_hook`) | the exact counters for **every** route, claimed or not, explicit zeroes included |
| `known_bypasses` | per-route `unobserved` counts plus `total` | the **known bypasses**: closed expectations with no matching artifact, counted against the route each expectation declared before route selection |
| `expectation_version` | `1` | the frozen expected-inference record version the counters derive from |
| `semantic_sessions` | the CAP-010 vocabulary (`missing`, `unsupported`, `failed`, `partial`, `current`, `backfilled`) | the **semantic session states**, stated separately |
| `flush` | `outcome` (`complete` / `incomplete`), `state`, `policy`, counters, `abandonment` when present | the **flush outcome** (CAP-007): `complete` only when the sink acknowledged every recorded teardown and nothing was abandoned |

The five acceptance facts — claimed routes, known bypasses, schema
version, flush outcome, and coverage evidence — are therefore all named
by the same document that publishes the per-client exact counts; nothing
else in the crate publishes them together.

## The rules the publisher enforces

1. **A claim exists only with its evidence.** `clients` rows come from
   `CompatibilityMatrix` rows, and a matrix row is minted exclusively by
   a passing conformance run (`archivist-adapter-sdk::compatibility`).
   An integration token never appears in the manifest without the
   lifecycle version and evidence digest it was qualified with.
2. **Zeroes are not coverage.** A claimed client with no expectations
   reports explicit zeroes in every bucket; a route with no expectations
   reports explicit zeroes in `routes`. Absence of traffic never reads as
   complete coverage, and the type exposes no completeness predicate
   (threat `EC-13`).
3. **A bypass never vanishes.** The per-route sums equal the ledger's
   closed totals, so an unobserved exchange stays counted against the
   route it declared. Activity on an *unclaimed* route stays visible in
   `routes` (and in `known_bypasses`) but earns no `clients` row: the
   manifest never promotes unevidenced activity to a claim.
4. **The dimensions stay disjoint.** The exact counters live under
   `clients`/`routes`; the semantic states live under `semantic_sessions`
   alone. `failed` and `partial` exist in both vocabularies, which is
   exactly why the rule is about disjoint objects: no object mixes the
   dimensions, and a session that is semantically `current` while exactly
   `unobserved` reads as both.
5. **The flush outcome is always named.** `outcome` is one of the two
   closed tokens — the metrics registry's `flush_outcome` vocabulary — so
   an unpublished completion claim cannot hide behind the counters, and a
   gate that never ran reports `incomplete` / `not_started` rather than
   an absent or unclassified value.

## Content-freedom, boundedness, and the evidence digest

Like every report in the crate, the manifest is a fixed key set of closed
tokens, version integers, and saturating counters: no session, host,
path, prompt, provider, or credential text can appear, because no member
accepts it. The document serializes to canonical RFC 8785 bytes, and
`evidence_digest()` is the SHA-256 of those bytes.

That digest is the publication link to the verification flow
([`verification.md`](verification.md), Section 3): a verification run can
record the manifest as a `coverage-report` pilot-evidence entry
(`{kind: coverage-report, digest, result}`) keyed to the evaluated
commit, so the emitted `verification-manifest.json` names this document's
coverage evidence without carrying it. The digest moves whenever any
counter, claim, or flush outcome moves — a manifest cannot be replayed
against different coverage.

## Where this connects

- [`compatibility-matrix.md`](compatibility-matrix.md) — the published
  *source-adapter* matrix (plan Phase 6). The route-registry claims this
  manifest's `clients` rows carry are the separate Phase 9 matrix
  (`archivist-adapter-sdk::compatibility`); the 1.0 gate joins the exact
  coverage report to the compatibility publication without subsuming one
  matrix into the other.
- [`exact-inference-schemas.md`](exact-inference-schemas.md) — the
  provider-boundary artifact schema whose correlation triple feeds the
  ledger the counters derive from.
- [`metrics.md`](metrics.md) — `archivist.exact.coverage` (label
  `exact_outcome`) and `archivist.exact.flush` (label `flush_outcome`)
  are the time-series projections of the same closed vocabularies.
- Bead `aa-545b043a` — this manifest's landing; beads `aa-76e1c512`
  (per-route partition) and `aa-dda69ef3` (the flush gate) are its
  inputs.
