# Fleet source inventory — content-free baseline (2026-09-08)

Read-only inventory of the in-scope fleet performed with the private,
deployment-specific prototype before any adapter implementation, as required
by the plan's Phase 6 pre-adapter gate (`docs/plan/plan.md`, "Harness
adapters"). This note is the retained evidence; it is deliberately
content-free.

**Sanitization contract.** No hostname, user name, file path, session
identifier, prompt, response, or credential appears in this document, and no
such value was retained by the scan. Hosts are anonymized to labels with a
transport class only. Values that could identify an account or organization
were counted in flight and never stored: the account-dimension results below
are distinct-value *counts*, not values. Retained data is limited to source
kind, structural fingerprints (key-name sets, record-type enums, version
strings), counts, byte sums, and failure classes.

## Method

- Scope: four in-scope hosts — H1 (local, multi-source), H2 and H3 (remote
  single-source, scanned read-only over ssh with aggregation performed on the
  remote side; no transcript bytes crossed the wire), H4 (container workload
  host).
- Discovery rules replicate the prototype: for the Claude Code source, all
  regular files under the harness's projects root excluding `memory/`
  directories and `.pre-union` files, with session identity derived from the
  tree shape (session / subagent / tool-result / session-sidecar roles); for
  Codex, one JSONL rollout per session in a date tree plus a shared prompt
  history sidecar; for Pi, JSONL session trees; for OpenCode, a read-only
  sqlite probe of the allowlisted tables using the prototype adapter's own
  schema detection and session export (defining the projected record).
- One streaming pass per file source. A record is *complete* only if
  newline-terminated; the maximum-record figure counts complete records only,
  and files whose final line lacks a terminator are counted separately.
- "Active" means source-file mtime within the stated window of scan time
  (24 h and 7 d are both reported). For the database source, activity is the
  session row's updated timestamp within 24 h.
- Lines that parse as JSON objects contribute their top-level key names and
  bounded structural-enum values (`type`, `version`, and similar discriminators,
  capped at 32 short strings) to the fingerprint. No other field values were
  inspected or kept.

## Observed fingerprints

These are the adapter-detectable fingerprints the compatibility matrix must
eventually name. Version strings are harness CLI versions observed in record
envelopes; they bound the corpus a Claude Code / Codex adapter must parse.

**claude-jsonl** — newline-delimited JSON objects, one record per line,
session identity from tree shape. Fleet union of record `type` values (22):
`agent-name`, `ai-title`, `artifact-autoreact-ledger`,
`artifact-comment-monitor`, `assistant`, `atis-latch`, `attachment`,
`bridge-session`, `cost-state`, `file-history-delta`,
`file-history-snapshot`, `fork-context-ref`, `frame-link`, `last-prompt`,
`mode`, `permission-mode`, `pr-link`, `queue-operation`, `result`,
`started`, `system`, `user`. `userType` observed as `external` only.
CLI versions observed fleet-wide: `2.1.220` through `2.1.266` (31 distinct,
per-host spreads in the table). Account-identifying fields
(`accountUuid`, `ownerAccountUuid`, `ownerOrganizationUuid`) appear in
records from newer CLI versions; where present the scan observed exactly one
distinct account value per host. Fleet union of top-level key names (134,
schema evidence for projection allowlists):

```
accountUuid agentId agentName aiTitle apiBlockIndex apiError
apiErrorIsTransient apiErrorStatus apiRefusalCategory apiRefusalExplanation
artifactCount artifacts atis attachment attributionAgent attributionMcpServer
attributionMcpTool attributionSkill backup bridgeSessionId classifierMetaLines
compactMetadata content contextLength cron cronKind cwd direction durationMs
effort entrypoint error errorDetails fallbackModel foldedUuids frameUrl
gitBranch hasOutput hasUnknownModelCost hookAdditionalContext hookCount
hookErrors hookInfos interruptedByShutdown interruptedMessageId
isAbortedMidStream isApiErrorMessage isCompactSummary isMeta isSidechain
isSnapshotUpdate isVisibleInTranscriptOnly is_error key lastPrompt
lastSequenceNum leafUuid level logicalParentUuid maxRetries message
messageCount messageId mode modelUsage noOpStreak operation origin
originalModel ownerAccountUuid ownerOrganizationUuid parentLastUuid
parentSessionId parentUuid path pendingBackgroundAgentCount permissionMode
prNumber prRepository prUrl preventedContinuation prompt promptId promptSource
queuePriority queueSkipAttachments quotaLimits reason refusedUserMessageUuid
rendered requestId result retractedMessageUuids retryAttempt retryInMs
scheduledFireId scheduledTaskId scope sessionId session_id slug snapshot
snapshotMessageId source sourceToolAssistantUUID sourceToolUseID startTime
stopReason streakStartedAt subtype taskId taskKind timestamp title
toolDenialKind toolUseID toolUseResult totalAPIDuration
totalAPIDurationWithoutRetries totalCostUSD totalDuration totalLinesAdded
totalLinesRemoved totalToolDuration trackingPath trigger truncatedAfterOutput
turnCompanion type userFeedback userType uuid v version
```

**codex-rollout-jsonl** — newline-delimited JSON objects; top-level key
union (7): `ordinal`, `payload`, `session_id`, `text`, `timestamp`, `ts`,
`type`. Record `type` values (8): `compacted`, `event_msg`,
`inter_agent_communication_metadata`, `response_item`, `session_meta`,
`token_usage_record`, `turn_context`, `world_state`. One rollout file per
session under a `YYYY/MM/DD` date tree, plus one shared prompt-history
sidecar. Observed session dates span 2026-08-03 through 2026-09-08. No
account-identifying field is present in the envelope.

**opencode-sqlite** — single database file, read-only probe. All five
allowlisted tables (`session`, `message`, `part`, `session_input`, `todo`)
present with the adapter allowlist's full column sets (28, 5, 6, 7, 7
columns respectively; exactly the prototype's projection allowlist, no
extra columns observed). Application version observed in session rows:
`1.18.29` (single value). The projected record is the adapter export of one
session; maximum observed export size 422,953 bytes; maximum single
message/part `data` field 10,332 bytes.

**pi-session-jsonl** — not observed. The default session root is absent on
every in-scope host; this source kind is a coverage gap (plan §6C requires
reporting no-session/ephemeral mode explicitly).

**prototype-legacy (age-encrypted corpus)** — the prototype's pre-existing
encrypted recovery corpus on H1: age+gzip envelope over JSONL. Record
interior is not measurable without decryption and was not decrypted;
fingerprint is the envelope alone.

## Per-host results

### Claude Code (file source)

| Host | Failure class | Sessions | Files (all / JSONL) | Bytes | Active 24 h | Active 7 d | Max complete record (B) | CLI versions | Account field |
|---|---|---|---|---|---|---|---|---|---|
| H1 | ok | 37,834 | 47,063 / 40,154 | 19,537,439,026 | 1,748 | 8,794 | 12,707,472 | 31 (2.1.220–2.1.266) | present, 1 distinct |
| H2 | ok | 17,469 | 19,698 / 17,903 | 5,510,775,277 | 1,248 | 5,331 | 5,242,749 | 6 (2.1.222–2.1.252) | present, 1 distinct |
| H3 | ok | 1,745 | 2,094 / 1,876 | 394,337,882 | 0 | 0 | 637,054 | 1 (2.1.220) | absent |
| H4 live | transport_unreachable | — | — | — | — | — | — | — | — |
| H4 (mirror of 2026-08-15, stale) | ok (stale evidence) | 517 | 546 / 517 | 313,036,795 | 0 | 0 | 397,592 | 1 (2.1.226) | absent |

H4's container workload was not `Running` at scan time (unschedulable for
more than five days), so no live read was possible; the row above aggregates
the prototype's own last successful mirror pull, 24 days stale, and is
evidence only of that snapshot. File-role mix per host (session /
subagent / tool-result / sidecar): H1 37,848 / 4,619 / 4,594 / 2;
H2 17,472 / 870 / 1,356 / 0; H3 1,745 / 262 / 87 / 0; H4-mirror
517 / 0 / 29 / 0. Distinct workspace roots (top-level project directories):
H1 140, H2 22, H3 2, H4-mirror 1.

### Codex (file source)

| Host | Failure class | Sessions | Files | Bytes | Active 24 h | Active 7 d | Max complete record (B) |
|---|---|---|---|---|---|---|---|
| H1 | ok | 7,482 rollouts + 1 history sidecar | 7,483 | 9,857,522,520 | 16 | 73 | 5,117,940 |
| H2, H3, H4 | root_absent | — | — | — | — | — | — |

### OpenCode (database source)

| Host | Failure class | Sessions | Active 24 h | Max projected record (B) | Max row data (B) |
|---|---|---|---|---|---|
| H1 | ok | 18 | 0 | 422,953 | 10,332 |
| H2, H3 | no_database | — | — | — | — |
| H4 | not scanned (transport unreachable) | — | — | — | — |

### Pi (file source)

Absent on all four hosts: `root_absent` everywhere (coverage gap).

### Prototype legacy corpus (H1 only)

| Failure class | Objects | Distinct sessions | Plaintext bytes | Span |
|---|---|---|---|---|
| ok (record size not measurable without decryption) | 71,087 | 66,384 | 32,527,063,911 | 2026-08-12 → 2026-09-08 |

Composition: 63,626 objects (22,931,314,786 B) from the Claude Code source
and 7,461 objects (9,595,749,125 B) from the Codex source.

## Failure classes and parse anomalies

Classes observed: `ok`, `root_absent` (Pi everywhere; Codex and OpenCode on
the single-source hosts), `transport_unreachable` (H4 live scan — workload
not running), `no_database` (OpenCode where absent), and
`not-measurable-without-decryption` (legacy record size). No host × source
combination failed with a read error: every file opened for scanning
succeeded (`read_error_files = 0` throughout).

Anomalies retained as counts, per plan requirements that parsing stop at
complete-record boundaries and tolerate trailing partial writes:

- Complete-but-unparseable lines: H1 Claude 143, H1 Codex 192, H2 Claude 11,
  H3 and H4-mirror 0. These are newline-terminated lines that failed JSON
  parsing — consistent with mid-write flushes observed by a concurrent live
  scan; an adapter must skip them without failing the source.
- Files with an incomplete (unterminated) final line: H1 Claude 4, H1 Codex 6,
  all other hosts 0 — the active-growth case the marathon chunker must handle.

## Findings that constrain the adapters

1. **Record-size bounds are large.** Maximum complete records reach 12.7 MB
   (Claude) and 5.1 MB (Codex) on the busiest hosts. Per-record handling,
   decompression bounds, and any single-record buffering must assume at least
   this scale, with headroom for growth.
2. **Version spread is wide.** 31 Claude CLI versions in one host's history
   (2.1.220–2.1.266), with envelope keys accumulating over time
   (account-identifying fields appear only in newer versions). The fingerprint
   allowlist must be a set of envelope shapes, not a single version, and must
   treat absent newer fields as valid older records — unknown fingerprints
   still fail closed.
3. **The account dimension is real but sparse.** Claude records carry
   account-identifying fields only in newer versions; exactly one distinct
   account value exists per host where present, and hosts differ in whether
   the field exists at all. Account counting belongs in the adapter
   fingerprint report; these values are identifiers and must never be
   projected as content.
4. **Freshness is concentrated.** The fleet holds 3,012 active-24 h files
   (Claude 1,748 + Codex 16 on H1; Claude 1,248 on H2) while H3 is fully
   idle — measured backlog, not a harness preference, must drive scheduling,
   matching the plan's backfill policy.
5. **Scale skew is extreme.** Claude live sources total ~25.4 GB / 57,048
   sessions across three hosts, with the largest host holding 37,834 sessions
   (19.5 GB) — largest-first backfill with per-source quotas is mandatory or
   the small hosts starve.
6. **Pi is a declared gap.** No Pi source exists anywhere in scope; the Pi
   adapter ships with its coverage-gap reporting and cannot be validated
   against fleet data.
7. **OpenCode is single-host and small** (18 sessions) — sufficient for
   schema conformance, insufficient for marathon-scale validation.
8. **The legacy corpus is the single largest body of evidence** (66,384
   sessions, 32.5 GB plaintext) and overlaps the live sources by design; its
   interior record sizes remain unmeasured until it is ingested and decrypted
   inside the trust boundary.

Supported/unsupported status per fingerprint is intentionally absent here:
no adapter exists yet (the workspace is scaffolded with no production
behavior). This note records what was *observed*; the Phase 6 exit gate's
compatibility matrix must reconcile every fingerprint above against the
released adapter allowlists.
