# Agent Archivist error-code conventions

Status: accepted baseline · Last updated: 2026-09-11

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
to be interpreted as described by RFC 2119 and RFC 8174 when they appear in bold.

This document is the naming, encoding, and compatibility contract for every
error every producer emits: the ingestion server's HTTP responses, the client
daemon and CLI, adapters, and the verification tooling. Behavior contracts it
rests on are owned elsewhere and are not redecided here: the error/action
matrix and backoff policy by [implementation plan](../plan/plan.md) Section
7.8, CLI stream and non-interactive conventions by Section 7.9 and the Phase
5 deliverables, and content-freedom by requirements
[SEC-004](requirements.md) and [VAL-007](requirements.md). What this document
adds is the stable namespace those rules are expressed through.

The machine-readable registry is [`tools/error-codes.toml`](../../tools/error-codes.toml);
`tools/check-error-codes.py` (fast lane of
[`scripts/definition-of-done.sh`](../../scripts/definition-of-done.sh))
rejects a registry that violates any rule marked enforceable below. When this
document and the registry disagree, the checker's pinned constants decide,
and one of the two is wrong and must be fixed in the same commit.

## 1. Namespace and wire shape

- **ERR-001** — Every error, on the wire or in a process exit path, belongs to
  the namespace `archivist.error/v1`. The namespace string appears in every
  serialized error body and **MUST NOT** be implied by context.
- **ERR-002** — An error body **MUST** carry, at minimum: the namespace
  string, a stable `code` from the registry, the effective `retryable`
  boolean, a content-safe `message`, and the correlation fields of Section 8.
  Field names are illustrative here and are pinned by the Phase 1 error
  schema, which this registry seeds.
- **ERR-003** — The body **MUST NOT** contain any other field derived from
  request content. Diagnostic detail beyond the registered fields belongs in
  server logs under the content-free logging rules, never in the response.
- **ERR-004** — On the wire, `retryable` is authoritative: a consumer
  **MUST** retry solely on that boolean (plus transport failure), never by
  string-matching messages. This is what makes adding codes compatible
  (Section 11).

Example body (field names illustrative until the Phase 1 schema; the
request/correlation shapes are the pinned ones — lowercase canonical
UUIDv7):

```json
{
  "schema": "archivist.error/v1",
  "code": "request.rate_limited",
  "retryable": true,
  "message": "The per-client request rate was exceeded; retry after the indicated interval.",
  "request_id": "6bc6d1e0-f2a5-47c9-8b3d-7a1f0c5b2e4d",
  "correlation_id": "9f2a51b0-e8c7-7d6a-a3b0-1e2d3c4b5a69"
}
```

## 2. The class taxonomy

- **ERR-005** — Every code belongs to exactly one *class*. Classes are the
  closed condition taxonomy: the plan Section 7.8 matrix rows plus the
  client-local conditions that never reach HTTP. The class determines the
  allowed HTTP statuses, retryability, the client action, and the process
  exit code.
- **ERR-006** — The v1 class set and their attributes are **frozen**:
  the registry **MUST NOT** add, remove, or redefine a class or any of its
  attributes within v1. The checker pins them; a change is a v2 namespace
  event (Section 11).

| Class | HTTP | Retryable | Client action | Exit |
|---|---|---:|---|---:|
| `request_invalid` | 400, 415 | no | quarantine artifact, continue other sources | 65 |
| `authorization` | 401, 403 | no | pause uploads; complete linking or rotation | 78 |
| `integrity_conflict` | 409 | no | stop affected tenant source; page operator | 80 |
| `payload_limit_splittable` | 413 | no | rechunk at a record boundary and resubmit | 65 |
| `payload_limit_unsplittable` | 413 | no | quarantine; report the coverage gap | 65 |
| `throttle` | 408, 425, 429 | yes | backoff and retry | 75 |
| `server_failure` | 500, 502, 503, 504 | yes | backoff and retry; no receipt exists | 75 |
| `network` | — | yes | retry the identical envelope with fresh authorization | 75 |
| `usage` | — | no | fix the invocation | 64 |
| `lock_contention` | — | no | exit; one mutator at a time | 75 |
| `resource_exhausted` | — | no | pause predictably until the floor is restored | 75 |
| `local_state` | — | no | run `doctor` before mutating state | 74 |
| `internal` | — | no | report a bug with the correlation identifier | 70 |

Classes with an empty HTTP column are client-local: they exist only in
process-exit and local-diagnostic paths and **MUST NOT** be returned by the
server. A server-side internal fault is `server.internal` in class
`server_failure`, never class `internal`.

## 3. Code naming and allocation

- **ERR-007** — A code is two dot-separated lowercase segments,
  `[a-z][a-z0-9_]{0,23}` each, matching `domain.condition` — for example
  `envelope.schema_invalid`, `transport.response_lost`. Domains in use:
  `envelope`, `auth`, `storage`, `request`, `server`, `transport`, `cli`,
  `client`.
- **ERR-008** — Codes are unique and allocated only by appending an entry to
  the registry in the same commit as the producer that emits the code. A code
  **MUST NOT** be emitted before it is registered.
- **ERR-009** — A server-facing code declares exactly one HTTP status from
  its class's allowed set; a client-local code declares none. The registry
  carries the status so the class table stays the single authority on what
  each status means.
- **ERR-010** — Every registry entry carries a one-line bounded
  `description` of the condition it names, the same way every crate
  documents its purpose.

## 4. Bounded safe messages

- **ERR-011** — `message` is a registered template. Its literal text uses
  printable ASCII only, contains no brace characters, no line breaks, and is
  at most **160** characters before rendering. The rendered message is
  truncated to at most **200** characters; because every interpolable value
  is charset-constrained (ERR-013), truncation cannot introduce content.
- **ERR-012** — A template **MAY** reference only these placeholder fields,
  and no others. This allowlist is frozen in v1 and enforced by the checker:

| Placeholder | Kind | Constraint |
|---|---|---|
| `version` | token | `[0-9A-Za-z._+-]{1,32}` |
| `media_type` | token | `[0-9A-Za-z.+/-]{1,64}` |
| `expected_media_type` | token | `[0-9A-Za-z.+/-]{1,64}` |
| `field` | identifier | `[a-z0-9_.-]{1,64}` |
| `actual_bytes`, `limit_bytes`, `free_bytes`, `count`, `max_ratio` | integer | decimal, at most 19 digits; values below 2^63 at render time |

- **ERR-013** — At render time the producer **MUST** validate each value
  against its constraint and format it itself (integers as plain decimal). A
  value that fails validation renders as the placeholder's name in square
  brackets (for example `[version]`) — deterministic, bounded, and visibly
  wrong — and **MUST NOT** be emitted verbatim. No `Display` of an untyped
  error, path, payload fragment, provider message, or identifier outside the
  allowlist may ever reach a message. This rule is the encoding of SEC-004
  and VAL-007 at the error boundary.
- **ERR-014** — The message is advisory. Producers **MAY** reword a template
  within the grammar in any commit; consumers **MUST NOT** parse it
  (ERR-004). A condition needing a genuinely different message is a new
  code.

## 5. Retryability semantics

- **ERR-015** — `retryable` means: an identical resubmission of the same
  frozen envelope could plausibly succeed. It is fixed per class, travels on
  the wire, and is authoritative there (ERR-004).
- **ERR-016** — Retryable failures follow plan Section 7.8: full jitter from
  one second, doubling to a 15-minute cap, no attempt limit while the spool
  entry is retained, backoff reset on success, and fresh authorization on
  every attempt while the envelope bytes stay identical.
- **ERR-017** — Both `payload_limit` classes are non-retryable as defined:
  the identical envelope fails identically. The splittable class carries a
  client *action* (rechunk, then a new envelope and new request) rather than
  a retry. `network` is retryable with no HTTP status at all.
- **ERR-018** — `retryable` and exit 75 are different axes. Exit 75 marks a
  transient *process-local* condition (lock held, disk floor, foreground
  drain incomplete) where an operator rerun is sensible; the corresponding
  classes are non-retryable because this process must not spin on them.

## 6. HTTP mapping

- **ERR-019** — A server error response uses the code's registered status,
  which is one of its class's allowed statuses. The mapping of classes to
  statuses is the plan Section 7.8 matrix, restated in Section 2 above; no
  other status may be registered in v1.
- **ERR-020** — Every `/v1/*` response — including routing and method
  failures — is a machine-readable `archivist.error/v1` body or a defined
  success shape; an HTML error page **MUST NOT** be produced.
- **ERR-021** — Every response carries the correlation headers of Section 8.
  `429` and `425` responses **SHOULD** also carry the standard retry
  scheduling header.

## 7. Process exit mapping

- **ERR-022** — Exit codes are allocated from `sysexits.h` where a standard
  meaning fits, plus one project code:

| Exit | Meaning | Classes |
|---|---|---|
| 0 | command's primary objective completed | — |
| 64 | usage (EX_USAGE); missing decision/config field in non-interactive mode (plan-fixed) | `usage` |
| 65 | unworkable input data (EX_DATAERR) | `request_invalid`, `payload_limit_*` |
| 70 | internal invariant failure (EX_SOFTWARE) | `internal` |
| 74 | local state I/O failure (EX_IOERR) | `local_state` |
| 75 | temporary failure (EX_TEMPFAIL): second mutator holds the lock (plan-fixed), spool cap/disk floor, retryable foreground drain | `throttle`, `server_failure`, `network`, `lock_contention`, `resource_exhausted` |
| 78 | corrective action required before progress (EX_CONFIG): linking, rotation, configuration | `authorization` |
| 80 | integrity conflict: stop and page (project-allocated; no sysexits analog) | `integrity_conflict` |

- **ERR-023** — Every exit code not in the table — specifically 1–63, 66–69,
  71–73, 76–77, 79, and 81–125 — is unallocated and **MUST NOT** be used.
  Termination by signal follows the shell `128+n` convention and is outside
  this table.
- **ERR-024** — Quarantine is not failure: a run that quarantines a poison
  artifact and continues exits 0, with the quarantine and any coverage gap
  reported in output. The exit code reflects the class of the condition that
  prevented the *command's primary objective*, when one did.

## 8. Request correlation

- **ERR-025** — Every logical upload request carries a `request_id`: a
  lowercase canonical UUIDv7 (plan Section 7.4) generated by the client
  when the request is frozen, reused across every retry of that request,
  and bound into the envelope, attestation, receipt, and error bodies. It
  is a correlation handle, not a security identity (ID-002's caution
  applies).
- **ERR-026** — Every server attempt carries a fresh server-assigned
  `correlation_id` of the same shape, so one `request_id` fans out into
  per-attempt evidence across replicas. Responses carry both as headers
  (`x-archivist-request-id`, `x-archivist-correlation-id`) in addition to
  the body fields.
- **ERR-027** — An error body for an envelope that could not be parsed
  carries `request_id: null`; the `correlation_id` is always present. A
  consumer **MUST** log at least one of them with every error it records.
- **ERR-028** — Correlation identifiers appear only as structured log/body
  fields. They **MUST NOT** become metric labels (OPS-005); the bounded code
  is the only error-derived label value.

## 9. stdout and stderr behavior

- **ERR-029** — stdout carries exactly the command's documented output and
  nothing else. With `--json`, that is one versioned JSON value (plan Phase
  5); a command that fails **MUST NOT** emit a stdout value at all, so a
  downstream pipe never consumes partial output.
- **ERR-030** — stderr carries diagnostics: human-readable text by default,
  or newline-delimited `archivist.error/v1` bodies with `--json`. The
  terminating error of a failed command is the last stderr diagnostic, and
  its class determines the exit code.
- **ERR-031** — ANSI escapes appear only on a detected TTY stderr, never
  with `--json`, never in redirected output (plan-fixed).
- **ERR-032** — Server logs are structured, content-free lines keyed by
  `code`, `request_id`, and `correlation_id`. The error counter metric is
  labeled by `code` alone — a value bounded by the registry — never by
  message, tenant, session, or correlation identifiers. This section pins
  the error side of metrics naming only; general metrics naming is defined
  by `docs/notes/metrics.md` and its registry gate, whose `error_code`
  label is cross-checked against this registry so neither can drift.

## 10. Metrics-label safety

- **ERR-033** — The registry schema is closed: unknown keys are rejected by
  the checker. There is no free-form label, tag, or detail field anywhere in
  the registry or the error body, because an unbounded label is an unbounded
  log surface (the acceptance this document exists to enforce).
- **ERR-034** — Any future detail mechanism **MUST** follow the placeholder
  discipline of Section 4: named fields, declared constraints, closed at
  schema level.

## 11. Compatibility for producers

Within `archivist.error/v1`:

- **ERR-035** — *Compatible*: appending a registry entry (code, message,
  description) and its emitting producer in one commit; rewording a template
  within the grammar; marking a code `deprecated = true` (it keeps working
  and keeps its meaning; removal is a v2 event).
- **ERR-036** — *Incompatible, therefore forbidden in v1*: renaming,
  deleting, or recycling a code; changing a code's class or HTTP status;
  changing a class attribute; extending the placeholder allowlist with a
  field whose constraint admits source-derived content (a bounded structural
  field may be added only with a same-commit checker update that pins its
  constraint).
- **ERR-037** — A consumer that meets an unregistered code **MUST** fall
  back to the wire `retryable` boolean and, where applicable, the HTTP
  status class — never fail to parse. Producers rely on this: an added code
  is deployable before every consumer has learned its name.
- **ERR-038** — v2 (`archivist.error/v2`) is the escape hatch for taxonomy
  or namespace changes. Both namespaces are served through a documented
  transition per VAL-001 and OPS-009, with a migration note in the same
  commit that introduces v2.

The registry file itself carries `archivist.error-registry/v1`, versioned
separately from the wire namespace: the registry format may grow optional
keys compatibly, while the wire namespace changes only as ERR-038 allows.

## 12. Verification

- **ERR-039** — `tools/check-error-codes.py` is the enforcing test. It
  validates the committed registry against every enforceable rule above and
  runs in the fast lane, so no commit can land an invalid registry.
- **ERR-040** — Its `--self-test` mode mutates the committed registry with
  known defects — source-derived placeholders (`{path}`,
  `{provider_message}`, `{transcript_excerpt}`), unbounded label keys,
  template-bound violations, class drift, unknown classes, bad code names,
  status/class mismatches — and fails unless every one is rejected. The
  rejection paths are therefore tested, not assumed.
- **ERR-041** — Runtime tests that follow (forced-error cases in the plan's
  error/action, poison-continuation, and lost-receipt suites) **MUST**
  assert emitted codes against the registry and assert content-freedom of
  messages and logs under synthetic malformed input, closing the loop
  between the conventions and the Phase 4/5 behavior that implements them.
