# Agent Archivist metrics and telemetry naming conventions

Status: accepted baseline · Last updated: 2026-09-11

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
to be interpreted as described by RFC 2119 and RFC 8174 when they appear in bold.

This document is the naming, unit, instrument, histogram, span, attribute,
status, and bounded-label contract for every telemetry signal the system
emits, across six surfaces: client, server, adapter, storage, pilot, and
exact coverage. Behavior it rests on is owned elsewhere and is not redecided
here: the signal inventory by [implementation plan](../plan/plan.md) Section
12, the phases that emit them (Phases 2, 4, 5, 6, 8, and 9), content-freedom
by requirements [SEC-004](requirements.md), [OPS-004](requirements.md), and
[OPS-005](requirements.md), and the error-side label rules by
[ERR-028](error-codes.md) through [ERR-034](error-codes.md). What this
document adds is the closed namespace those signals are expressed through —
no metric, span, or attribute exists that the registry and gate have not
agreed on — and the pinned OpenTelemetry-to-Prometheus name translation that
keeps exported names stable, so a dashboard written against an exporter today
is not forked by a naming change tomorrow.

The machine-readable registry is [`tools/metrics.toml`](../../tools/metrics.toml);
`tools/check-metrics.py` (fast lane of
[`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh))
rejects a registry that violates any rule marked enforceable below,
cross-checks the error-code label against
[`tools/error-codes.toml`](../../tools/error-codes.toml), and proves its own
rejection paths with `--self-test`. When this document and the checker
disagree, the checker's pinned constants decide, and one of the two is wrong
and must be fixed in the same commit.

## 1. Namespace and surfaces

- **MET-001** — Every metric name, internal span name, and project attribute
  key belongs to the `archivist.` namespace. The prefix is explicit in the
  registry and in every emitted signal; it is never implied by context, and
  no signal may be registered or emitted outside it.
- **MET-002** — Every signal belongs to exactly one *surface*, which names
  the emitting component and fixes the owning crate and base phase:

| Surface | Owning crate | Base phase | Carries |
|---|---|---:|---|
| `server` | `archivist-server` | 4 | ingestion, commit, trust, shutdown signals |
| `client` | `archivist-client-core` | 5 | spool, backlog, coverage, scheduler signals |
| `adapter` | `archivist-adapter-sdk` | 6 | discovery, projection, quarantine signals |
| `storage` | `archivist-storage` | 2 | backend operation, capability signals |
| `pilot` | `archivist-cli` | 8 | comparator, freshness, restore-evidence signals |
| `exact` | `archivist-adapter-sdk` | 9 | expectation, artifact, proxy, flush signals |

  The surface map is frozen in the checker: a registry edit cannot move a
  surface to another crate or phase, and adding a surface is a same-commit
  update to this document, the plan, and the checker (MET-040).
- **MET-003** — A signal exists only by appending an entry to the registry
  in the same commit as the producer that emits it. Emitting an unregistered
  metric, span, attribute, or label value is a defect, exactly as emitting an
  unregistered error code is (ERR-008).

## 2. Metric names and instrument kinds

- **MET-004** — A metric name is `archivist.<surface>` followed by one to
  four noun segments: `archivist` `.` surface `.` segment{1,4}. Segments are
  lowercase `[a-z][a-z0-9]{0,23}` with **no underscores** — words within a
  segment are run together or split into further dot segments — and the
  whole name is at most 100 characters. Underscore-free segments are what
  makes the dot-to-underscore translation of Section 4 injective by
  construction.
- **MET-005** — The v1 instrument kind set is closed: `counter`, `gauge`,
  `histogram`. A counter is a monotonically increasing cumulative sum of
  events; a gauge is a point-in-time value; a histogram is a fixed-boundary
  distribution (Section 8). There is no up-down counter, no observable
  gauge, and no summary in v1; adding one is a registry-format extension
  with a same-commit gate update (MET-040).
- **MET-006** — Kind matches meaning: events that accumulate are counters,
  levels that rise and fall (spool usage, backlog, in-flight requests,
  capability state) are gauges, and durations or size distributions are
  histograms. A quantity that is neither monotonic nor a distribution —
  "last error time", for example — is a gauge whose unit carries the
  meaning, never a counter reset on change.
- **MET-007** — The name states the measured quantity, not the instrument,
  the unit, or the type. The unit lives in the `unit` field (Section 3); the
  kind lives in the `kind` field; suffixes like `total`, `count`, or `bytes`
  appended by hand are naming defects the gate rejects (MET-013, MET-014).

## 3. Units

- **MET-008** — Every signal declares exactly one unit from the frozen v1
  unit set, using OpenTelemetry UCUM-style abbreviations. Units and their
  exported suffixes are pinned in the checker; an existing mapping never
  changes (that would rename every exported family — MET-012), and a new
  unit arrives only with this document and the gate in the same commit:

| Unit | Exported suffix | Measures |
|---|---|---|
| `1` | (none) | ratio, count of states, presence |
| `s` | `_seconds` | durations, ages, lags |
| `By` | `_bytes` | payload, spool, and backlog sizes |
| `{attempts}` | `_attempts` | upload, flush, refresh attempts |
| `{errors}` | `_errors` | failures by class or code |
| `{objects}` | `_objects` | blobs, occurrences, attestations, chunks |
| `{records}` | `_records` | source records discovered or quarantined |
| `{requests}` | `_requests` | HTTP requests and exact expectations |
| `{sources}` | `_sources` | client sources in a state |

- **MET-009** — The unit is never also the name's final segment:
  `archivist.client.spool.usage` with unit `By` is correct;
  `archivist.client.spool.usage.bytes` is rejected. The rule exists because
  the exporter appends the unit (MET-012), so an embedded unit becomes a
  doubled suffix in every scraped series.
- **MET-010** — Counters count discrete things: a counter's unit is `By` or
  an annotation unit, never `s` and never `1`. Durations accumulate as
  histograms, and a dimensionless counter has no meaning to accumulate. The
  unit `1` appears only on gauges of ratio, state, or presence.

## 4. Exported-name stability

- **MET-011** — Every OpenTelemetry exporter, and the Prometheus text
  exposition of `/metrics`, **MUST** derive the exported family name from
  the registry entry by exactly this pinned translation: replace every `.`
  with `_`; if the unit is not `1`, append `_` and the unit's exported
  suffix from the Section 3 table; if the kind is `counter`, append
  `_total`. A histogram additionally exposes `_bucket`, `_sum`, and
  `_count` series in that family. No exporter, scrape adapter, or
  deployment rewrites, shortens, or re-cases a registered name.
- **MET-012** — The translation **MUST** be injective over the registry:
  the gate computes every signal's exported family and rejects any two
  signals that produce the same string. This is the machine form of the
  acceptance that exporters retain consistent names — a dashboard joins on
  an exported name, so no two registered signals may ever collide on one,
  and one registered signal may never surface under two.
- **MET-013** — A name whose final segment is `total`, `sum`, `count`,
  `bucket`, `info`, or `created` is rejected: those are the suffixes the
  exposition format itself appends, and pre-embedding one forks the series
  (for example, a counter named `...count` exports as `...count_total`).
- **MET-014** — Renaming or deleting a registered metric is a v2 event
  (Section 11). Within v1 a metric keeps its name, unit, and kind for the
  lifetime of the registry; new quantities get new names, and a retired
  metric is marked `deprecated = true` and keeps exporting.

## 5. Attributes and bounded labels

- **MET-015** — A *label* is a metric or span attribute. Its registry key is
  `[a-z][a-z0-9_]{0,31}`; its OpenTelemetry attribute name is `archivist.`
  plus the key (for example `archivist.error_code`), and its exported label
  name is the attribute with dots replaced by underscores
  (`archivist_error_code`). Label keys are unique and translate injectively;
  the gate checks both.
- **MET-016** — Every label declares its value bound through a closed kind
  set: `enum` (a closed, registered list of values over the
  `[a-z0-9][a-z0-9._+-]{0,63}` charset — the error codes' `class.member`
  shape is why the charset allows dots), `token` (a declared
  cardinality ceiling over the same charset), or
  `boolean`. There is no free-form string kind, no pattern kind, and no
  unbounded kind: an unbounded label is an unbounded log surface, the same
  way a free-form error field is (ERR-033).
- **MET-017** — Cardinality ceilings are enforceable numbers: an enum
  carries at most **128** values, a token label declares a bound of at most
  **32** distinct values, and a boolean is 2. Values are append-only within
  v1; a runtime series that exceeds its label's declared bound is a defect
  the phase's tests assert against (MET-043).
- **MET-018** — A signal carries at most **4** labels, and the product of
  its labels' cardinalities is at most **512**. A span carries at most **3**
  attributes with a product of at most **128**. A proposed signal over
  either ceiling is decomposed — usually by moving per-source detail to the
  client status document (MET-035) — not exempted.
- **MET-019** — A signal or span references only registered label keys,
  each at most once, and every registered label is referenced by at least
  one signal or span: the registry carries no speculative taxonomy, and a
  producer cannot invent a label mid-flight.

## 6. Forbidden labels

- **MET-020** — A label whose key names a correlation identifier, content,
  or location is forbidden outright. The checker pins the list; additions
  are compatible tightenings made with this document in the same commit, and
  removals are v2 events. The v1 list: `session_id`, `upstream_session_id`,
  `artifact_id`, `generation_id`, `occurrence_id`, `attestation_id`,
  `request_id`, `correlation_id`, `trace_id`, `inference_request_id`,
  `provider_attempt_id`, `blob_digest`, `digest`, `tenant_id`, `client_id`,
  `origin_client_id`, `uploader_client_id`, `hostname`, `host`, `path`,
  `source_path`, `account`, `username`, `user`, `user_agent`, `url`, `ip`,
  `address`, `key_id`, `token`, `secret`, `credential`, `password`,
  `message`, `body`, `prompt`, `response`, `transcript`, `content`,
  `error_message`, `exception`.
- **MET-021** — Tenant and client identity never label metrics, even though
  both are bounded in one deployment: they are identifying, they are
  unbounded across deployments, and per-tenant aggregation already has a
  correct home — the coverage reports, catalog, and status documents — that
  does not feed a time-series database next to operational telemetry. A
  multi-tenant deployment needing per-tenant alerting derives it there, not
  by forking this registry.
- **MET-022** — No label value is ever derived from source or transcript
  content, credentials, or authorization material (SEC-004). The kind system
  is the encoding: an enum value is registered text, a token matches its
  charset, and neither can carry a path, a prompt, or a key. A label that
  cannot be declared under MET-016 does not exist.
- **MET-023** — Correlation identifiers — `request_id`, `correlation_id`,
  trace and span identifiers — appear only as structured log and span
  context, never as metric labels (ERR-028). The bounded `error_code` is the
  only error-derived label value in the system; message text, provider
  strings, and exception detail never label anything.

## 7. Status and state label sets

- **MET-024** — Status-valued labels use the plan's own vocabularies, and
  the checker pins them so neither the plan nor the registry drifts alone:

| Label | Values | Pinned by |
|---|---|---|
| `coverage_state` | `missing`, `unsupported`, `failed`, `partial`, `current`, `backfilled` | plan Section 12; CAP-010 |
| `exact_outcome` | `observed`, `partial`, `failed`, `unobserved`, `unknown` | plan Phase 9 decision |
| `commit_outcome` | `created`, `already_present`, `replaced_equivalent`, `logically_committed_unknown_physical_result` | RCPT-003 |
| `harness` | `claude`, `codex`, `opencode`, `pi`, `synthetic` | plan Phase 6; first slice |
| `error_code` | the code set of [`tools/error-codes.toml`](../../tools/error-codes.toml) | ERR-008, cross-checked |

- **MET-025** — These sets are append-only: a new state (a new harness, a
  new error code) is a compatible registry addition that lands with the
  producer in the same commit, and the gate's cross-check of `error_code`
  against the error registry fails the build when one file moves without
  the other. Changing or removing a state value is a v2 event.
- **MET-026** — Every state a signal reports is one of its enum's values —
  no `other`, no empty string, no unclassified bucket. Where the plan
  demands "no unclassified state" (Section 12 objectives, Phase 8 exit), the
  enum is the proof surface: a state that needs reporting is registered
  first, then emitted.

## 8. Histograms

- **MET-027** — A histogram declares its explicit boundaries in the
  registry: at least one and at most **32**, each positive and finite, in
  strictly increasing order, expressed in the signal's unit. Boundaries are
  advice to the SDK and the exact bucket edges of the exported `_bucket`
  series; a histogram without registered boundaries does not exist.
- **MET-028** — Boundary sets are pinned decisions like defaults (CFG-021):
  each traces to the plan limit or budget it brackets. The request-duration
  histogram brackets up to the 15-minute request deadline; the scheduling
  cycle histogram brackets the 15-minute interval and jitter; the storage
  operation histogram brackets the latency budget of Section 12's storage
  latency signal. Changing a boundary set changes bucket interpretation and
  is therefore a v2 event, not a tuning edit.
- **MET-029** — Sizes and durations distribute; they are never emitted as
  pre-aggregated min/max/mean gauges in v1 — a derived mean hides tail
  behavior the histograms exist to preserve. Consumers needing summaries
  compute them from `_sum` and `_count` at query time.

## 9. Spans

- **MET-030** — An internal span is named `archivist.<surface>.<operation>`
  with the same segment grammar as metrics, at most three operation
  segments. Span names are registered like metrics: the registry is the
  closed set an emitter may produce, which is what makes span-name
  cardinality lintable by construction.
- **MET-031** — An HTTP span is named `{METHOD} {route}` with the routed
  template, never a concrete path: `POST /v1/ingest`, `GET /health/ready`.
  A name containing a request-specific segment, a brace placeholder, or any
  identifier value is a defect. Routes are static in v1; if a parameterized
  route ever exists, its template is registered here first.
- **MET-032** — Span attributes are registered label keys only, plus
  OpenTelemetry standard semantic attributes (for example `http.route`,
  `url.scheme`) used as the SDK defines them and never extended with
  project meaning. Span events follow the same rule and additionally carry
  no free-text body: an event is a name plus registered attributes.
- **MET-033** — Span status uses the OpenTelemetry codes: `Error` is set
  when the operation failed, with the bounded `error_code` attribute naming
  why — never an exception message, provider string, or payload fragment in
  the status description (SEC-004, ERR-013's discipline at the span
  boundary).

## 10. Runtime cardinality and content discipline

- **MET-034** — The client status document (`archivist status --json`, the
  CLI output envelope) is where per-source and per-account detail lives:
  counts, bytes, lags, and classified errors per source, under the CLI
  conventions' redaction rules. Metrics are the aggregate projection of
  that document; anything too fine for MET-018 belongs there, not in a
  label.
- **MET-035** — Resource attributes come from the OpenTelemetry standard
  set only (`service.name`, `service.version`, `service.instance.id`,
  `deployment.environment.name`, and peers): `service.name` is
  `archivist-server` or `archivist-client`. No project resource attribute
  exists in v1, and tenant identity is never a resource attribute
  (MET-021).
- **MET-036** — Exemplars are disabled by default: an exemplar embeds trace
  and span identifiers in metric series, which MET-023 keeps out of metrics.
  A deployment enabling exemplars accepts a documented deviation, not a
  registry change.
- **MET-037** — The server's `/metrics` endpoint carries no request
  content, requires the same transport protection as every other route, and
  fails closed like them. Client metrics leave through OTLP to a configured
  collector or stay in the status document; the client never opens a
  listener for telemetry.

## 11. Registry and compatibility

- **MET-038** — The registry is [`tools/metrics.toml`](../../tools/metrics.toml)
  under schema `archivist.metrics-registry/v1`. Its shape is closed: a
  signal carries `kind`, `unit`, `phase`, `description`, and optionally
  `labels`, `boundaries`, and `deprecated`; a label carries its kind's
  bound keys and `description`; a span carries `surface`, `description`,
  and optionally `attributes` and `deprecated`. Unknown keys are rejected —
  there is no free-form metadata field, for the same reason the error
  registry has none.
- **MET-039** — Within registry v1, entries are append-only. Renaming or
  deleting a metric, span, or label; changing its kind, unit, surface,
  labels, or boundaries; or removing an enum value or token bound is a v2
  event. Marking an entry `deprecated = true` is compatible: it keeps its
  meaning and keeps exporting; removal is v2.
- **MET-040** — The registry *format* may grow compatibly (new optional
  keys, new kinds, new units, new label kinds) only in a commit that updates
  this document and the checker's pinned constants together. The frozen
  tables — surfaces, units, pinned status sets, the forbidden-label list —
  live in the checker precisely so a registry edit cannot silently redefine
  them, mirroring how the error-class taxonomy is pinned.
- **MET-041** — `archivist.metrics-registry/v2` is the escape hatch for
  taxonomy or namespace changes, arrived at with a documented transition per
  VAL-001 and OPS-009 — both namespaces served side by side — never as an
  accumulation of silent redefinitions. The registry schema is versioned
  separately from the signals themselves, as the error registry is
  (ERR-038).

## 12. Verification

- **MET-042** — `tools/check-metrics.py` is the enforcing test. It
  validates the committed registry against every enforceable rule above,
  cross-checks `error_code` against the error-code registry in both
  directions, computes and checks the injectivity of the exported-name
  translation, and runs in the fast lane, so no commit can land an invalid
  registry, a forbidden label, or an export collision.
- **MET-043** — Its `--self-test` mode mutates the committed registry with
  known defects — forbidden labels (`session_id`, `hostname`), free-form
  kinds, enum and cross-registry drift, unit-embedding and reserved-suffix
  names, exported-name collisions, boundary violations, cardinality and
  label-count overruns, span grammar defects — and fails unless every one
  is rejected. The rejection paths are tested, not assumed.
- **MET-044** — Runtime tests that follow (the Phase 4 server, Phase 5
  client, Phase 6 adapter, Phase 8 pilot, and Phase 9 exact suites)
  **MUST** assert emitted metric, span, attribute, and label values against
  this registry and assert content-freedom under successful and forced-
  error synthetic input — closing the loop between these conventions and
  the behavior that implements them, as ERR-041 does for errors.

## Worked example

One registry entry and everything it pins:

```toml
[signals."archivist.storage.operation.duration"]
kind = "histogram"
unit = "s"
labels = ["storage_operation"]
boundaries = [0.005, 0.025, 0.1, 0.5, 2.5, 10, 60]
phase = 2
description = "..."
```

- OpenTelemetry instrument: histogram `archivist.storage.operation.duration`,
  unit `s`, attribute `archivist.storage_operation` (enum: `put_object`,
  `begin_multipart`, …), explicit-bucket advice as registered.
- Exported family: `archivist_storage_operation_duration_seconds` with
  `_bucket`, `_sum`, `_count` series and label `archivist_storage_operation`
  — derived, unique, and identical from every exporter that follows
  Section 4.
- Not, ever: `archivist_storage_operation_duration_seconds_hist` (type
  suffix), a `..._nanoseconds` variant (unit change), a
  `storage_operation_path` label (forbidden), or an unregistered
  `region` label (MET-019).
