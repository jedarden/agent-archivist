// SPDX-License-Identifier: Apache-2.0

//! Multi-adapter scheduling acceptance (plan Phase 6 exit gate: "a
//! multi-account synthetic inventory backfills largest outstanding
//! histories first while keeping every adapter fresh"; plan Section 6A:
//! "actual scheduling still uses measured backlog rather than a hard-coded
//! harness preference"): every implemented source adapter — Claude Code,
//! Codex, Pi, and `OpenCode` — discovered over real synthetic account trees
//! with multi-chunk initial histories, measured through the client
//! inventory against the real `SQLite` state, and drained by the real
//! two-lane scheduler, with receipts modeled as acknowledged ranges the
//! way the state layer records them.
//!
//! Four properties, one per acceptance clause:
//!
//! - **Measured outstanding data controls priority.** Every round's
//!   backfill grants are ordered by the descending outstanding bytes the
//!   inventory *measured* that round, and the round-one spend lands on the
//!   largest measured source regardless of which adapter owns it — here
//!   deliberately the database adapter, not a file adapter.
//! - **Largest histories make the fastest backfill progress.** The
//!   cumulative backfill bytes granted are pointwise ordered by initial
//!   outstanding size at every round, and each history's first grant
//!   round never falls behind a smaller history's. Completion order is
//!   deliberately *not* asserted: the round's chunk floor legitimately
//!   lets an exactly-fitting smaller history finish before a larger
//!   history's residual chunk, so "progress" is grant dominance, not who
//!   crosses the finish line first.
//! - **Every active source remains fresh.** One live session per adapter
//!   grows every round; each receives the freshness reservation ahead of
//!   all backfill every round (never short) and never accumulates beyond
//!   one round's growth. Every trace measures *before* its round's grants
//!   apply, so a growing session always reads `partial` there — the
//!   coverage vocabulary's active-growth case — and the pass that ends
//!   the drive is the steady one after the last receipts land: no growth,
//!   every live session measuring zero outstanding and `current`, every
//!   history `backfilled`, and the plan over that caught-up fleet granting
//!   nothing.
//! - **No hard-coded harness preference exists.** Two fleets hold exactly
//!   the same measured history figures with the adapter and account
//!   assignment deranged (every adapter owns different figures in each
//!   fleet); their per-round totals, per-figure grant curves, and
//!   per-figure completion rounds are identical.
//!
//! The scan bridge is this test's stand-in for the daemon cycle's scan
//! assembly (Phase 5 open work) and composes only published surfaces:
//! each adapter's own discovery decides which sources exist under which
//! account, the SDK's record-boundary rule measures bytes and events
//! through the last complete record (whole-object measurement for the
//! Claude sidecar roles; the read-only snapshot projection for `OpenCode`),
//! and the source id is derived from stable inputs — adapter, account,
//! first complete record — never from a path. Source-side activity is the
//! fixture's own modification time against a 24-hour freshness window:
//! history fixtures are pinned outside it, live fixtures are rewritten by
//! growth every round.
//!
//! The three file adapters write fixed 4,096-byte records, so every
//! history class has an exact byte figure and the swap fleets' schedules
//! are pinned to hand-computed totals.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use archivist_adapter_claude::{
    ADAPTER_ID as CLAUDE_ADAPTER_ID, ClaudeAdapter, ConfiguredRoot as ClaudeRoot,
};
use archivist_adapter_codex::{
    ADAPTER_ID as CODEX_ADAPTER_ID, CodexAdapter, ConfiguredRoot as CodexRoot,
};
use archivist_adapter_opencode::{Projection, Snapshot, StoreConnection};
use archivist_adapter_pi::{ADAPTER_ID as PI_ADAPTER_ID, ConfiguredRoot as PiRoot, PiAdapter};
use archivist_adapter_sdk::file_capture::RecordBoundary;
use archivist_adapter_sdk::status::{
    AccountLabel, CoverageState, FreshnessLane, ScanClassification, SourceId, SourceScan,
};
use archivist_client_core::cli::now_rfc3339;
use archivist_client_core::inventory::{
    InventoryOptions, SourceInventory, inventory, measured_sources,
};
use archivist_client_core::scheduler::{self, CyclePlan, CycleTotals, DrainLoad, SchedulerLimits};
use archivist_client_core::state::StateStore;
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{AdapterId, Timestamp};
use rusqlite::{Connection, params};

/// Every synthetic record is exactly this many bytes including its
/// terminating newline, so a history's measured figure is its record
/// count times a constant.
const LINE_BYTES: u64 = 4096;

/// The history size classes, in descending measured size. The byte
/// figures are exact multiples of `LINE_BYTES` and pairwise distinct, so
/// the scheduler's byte ranking is never decided by a tiebreak.
const XL_LINES: u64 = 12_288;
const LG_LINES: u64 = 8_192;
const MD_LINES: u64 = 4_096;
const SM_LINES: u64 = 1_280;
const XS_LINES: u64 = 512;
const HS_LINES: u64 = 192;

/// A live session's initial size and per-round growth, in records: small
/// enough that one freshness reservation chunk always covers the whole
/// outstanding remainder, which is the shape a kept-current session has.
const ACTIVE_LINES: u64 = 16;
const GROWTH_LINES: u64 = 16;

/// The Claude tool-result sidecar's whole-object size: distinct from every
/// line-class figure so the object-shaped source also ranks without a
/// tiebreak.
const SIDECAR_BYTES: usize = 6_144;

/// The materialization capacity each scheduling round admits: two and a
/// half chunks, so the largest history cannot finish in round one and the
/// largest-first order is visible across rounds.
const CAPACITY_BYTES: u64 = 40 * 1024 * 1024;

/// The freshness window the bridge measures source activity against (the
/// fleet inventory's active-24h idea).
const FRESHNESS_WINDOW: Duration = Duration::from_hours(24);

/// The wall-clock instant aged history fixtures are pinned to: far enough
/// before any near-term run that their modification times sit outside the
/// freshness window.
const AGED_MTIME: &str = "2026-08-01T00:00:00Z";

/// The `OpenCode` history store's row count and data-cell size: the data
/// cells alone outsize the largest file history, so the projection
/// measures larger still no matter its per-row envelope.
const OPENCODE_HISTORY_ROWS: usize = 40_000;
const OPENCODE_HISTORY_DATA: usize = 1_600;

/// The `OpenCode` live store's seed size and per-round growth, in rows and
/// data-cell bytes.
const OPENCODE_SEED_ROWS: usize = 1;
const OPENCODE_GROWTH_ROWS: usize = 16;
const OPENCODE_GROWTH_DATA: usize = 96;

/// The most rounds any fleet may take; the drives assert they drain in
/// far fewer, so hitting this means the schedule stopped progressing.
const MAX_ROUNDS: usize = 24;

const MIB: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------
// Scratch directory
// ---------------------------------------------------------------------------

/// A unique scratch directory, removed when the test ends either way.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "archivist-multi-adapter-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("the scratch directory is creatable");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Fixture records: every line is one valid JSON object of exactly
// LINE_BYTES, padded inside a string member so admission never depends on
// the padding.
// ---------------------------------------------------------------------------

/// Build one fixture record: `prefix` + padding + `suffix` + newline,
/// exactly `LINE_BYTES` in all, where prefix and suffix wrap the padding
/// inside a JSON string member.
fn padded_line(prefix: &str, suffix: &str) -> String {
    let line_bytes = usize::try_from(LINE_BYTES).expect("line size fits the platform");
    let pad = line_bytes - prefix.len() - suffix.len() - 1;
    let line = format!("{prefix}{}{suffix}\n", "x".repeat(pad));
    assert_eq!(line.len(), line_bytes, "the record template pads exactly");
    line
}

/// One Claude Code session record; `account_member` selects the v2 shape
/// (an account-identifying member inside the bounded header window).
fn claude_line(session: &str, account_member: bool) -> String {
    let account = if account_member {
        r#","accountUuid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee""#
    } else {
        ""
    };
    padded_line(
        &format!(
            r#"{{"parentUuid":null,"sessionId":"{session}","type":"user","uuid":"u1","timestamp":"2026-08-01T00:00:00.000Z"{account},"text":""#
        ),
        "\"}",
    )
}

/// One Codex rollout record: members inside the observed envelope
/// vocabulary, a record type from the closed set, every typed member in
/// its admitted class.
fn codex_rollout_line(session: &str) -> String {
    padded_line(
        &format!(
            r#"{{"ordinal":1,"payload":{{"id":"p1"}},"session_id":"{session}","type":"response_item","text":""#
        ),
        "\"}",
    )
}

/// One Codex shared prompt-history record: exactly the three-key envelope
/// the history dialect admits.
fn codex_history_line() -> String {
    padded_line(
        r#"{"session_id":"session-hs","text":""#,
        r#"","ts":1754505600}"#,
    )
}

/// One Pi record. `header` selects the session header the format gate
/// requires (`type` `session` with a numeric `version`); the `sid` member
/// keeps every file's first record — the source-id input — distinct
/// without being path-derived.
fn pi_line(session: &str, header: bool) -> String {
    let suffix = if header {
        r#"","type":"session","version":3}"#
    } else {
        "\"}"
    };
    padded_line(&format!(r#"{{"sid":"{session}","text":""#), suffix)
}

// ---------------------------------------------------------------------------
// Fixture writers
// ---------------------------------------------------------------------------

/// Write `count` copies of one record line to `path`.
fn write_repeated(path: &Path, line: &str, count: u64) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture directories are creatable");
    }
    let repeats = usize::try_from(count).expect("line count fits the platform");
    fs::write(path, line.repeat(repeats)).expect("the fixture writes");
}

fn claude_session_path(root: &Path, file: &str) -> PathBuf {
    root.join("proj").join(file)
}

fn claude_session(root: &Path, file: &str, session: &str, lines: u64, v2: bool) -> PathBuf {
    let path = claude_session_path(root, file);
    write_repeated(&path, &claude_line(session, v2), lines);
    path
}

/// A Claude tool-result sidecar below the session's `tool-results/`
/// directory: one whole JSON object whose measured figure is its full
/// length.
fn claude_tool_result(root: &Path, session_dir: &str) -> PathBuf {
    let path = root
        .join("proj")
        .join(session_dir)
        .join("tool-results")
        .join("toolu_1.json");
    fs::create_dir_all(path.parent().expect("the sidecar parent exists"))
        .expect("the sidecar directory is creatable");
    let prefix = r#"{"content":""#;
    let object = format!(
        "{prefix}{}\"}}",
        "x".repeat(SIDECAR_BYTES - prefix.len() - 2)
    );
    assert_eq!(
        object.len(),
        SIDECAR_BYTES,
        "the sidecar object pads exactly"
    );
    fs::write(&path, object).expect("the sidecar fixture writes");
    path
}

fn codex_rollout_path(root: &Path, file: &str) -> PathBuf {
    root.join("sessions/2026/09/24").join(file)
}

fn codex_rollout(root: &Path, file: &str, session: &str, lines: u64) -> PathBuf {
    let path = codex_rollout_path(root, file);
    write_repeated(&path, &codex_rollout_line(session), lines);
    path
}

fn codex_history(root: &Path, lines: u64) -> PathBuf {
    let path = root.join("history.jsonl");
    write_repeated(&path, &codex_history_line(), lines);
    path
}

fn pi_session_path(root: &Path, project: &str) -> PathBuf {
    root.join(project).join("session.jsonl")
}

fn pi_session(root: &Path, project: &str, session: &str, lines: u64) -> PathBuf {
    let path = pi_session_path(root, project);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture directories are creatable");
    }
    // The header is the format gate's subject and the source-id input;
    // growth appends body records after it, so it never moves.
    let body_repeats = usize::try_from(lines.saturating_sub(1)).expect("line count fits");
    let mut contents = pi_line(session, true).into_bytes();
    contents.extend_from_slice(pi_line(session, false).repeat(body_repeats).as_bytes());
    fs::write(&path, contents).expect("the fixture writes");
    path
}

/// The `OpenCode` store schema: the five allowlisted tables with exactly
/// the embedded allowlist's columns, the extra tables a real store
/// legitimately holds, and one session row carrying the only admitted
/// application version.
const OPENCODE_DDL: &str = r"
    CREATE TABLE session (
        id TEXT PRIMARY KEY, project_id TEXT, workspace_id TEXT, parent_id TEXT,
        slug TEXT, directory TEXT, path TEXT, title TEXT, version TEXT,
        share_url TEXT, summary_additions INTEGER, summary_deletions INTEGER,
        summary_files INTEGER, summary_diffs INTEGER, metadata TEXT, cost REAL,
        tokens_input INTEGER, tokens_output INTEGER, tokens_reasoning INTEGER,
        tokens_cache_read INTEGER, tokens_cache_write INTEGER, revert TEXT,
        permission TEXT, agent TEXT, model TEXT, time_created INTEGER,
        time_updated INTEGER, time_compacting INTEGER, time_archived INTEGER
    );
    CREATE TABLE message (
        id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER,
        time_updated INTEGER, data TEXT
    );
    CREATE TABLE part (
        id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT,
        time_created INTEGER, time_updated INTEGER, data TEXT
    );
    CREATE TABLE session_input (
        id TEXT PRIMARY KEY, session_id TEXT, prompt TEXT, delivery TEXT,
        admitted_seq INTEGER, promoted_seq INTEGER, time_created INTEGER
    );
    CREATE TABLE todo (
        session_id TEXT, content TEXT, status TEXT, priority TEXT,
        position INTEGER, time_created INTEGER, time_updated INTEGER
    );
    CREATE TABLE account (
        id TEXT PRIMARY KEY, email TEXT, url TEXT, access_token TEXT,
        refresh_token TEXT, token_expiry INTEGER, time_created INTEGER,
        time_updated INTEGER
    );
    CREATE TABLE credential (
        id TEXT PRIMARY KEY, integration_id TEXT, label TEXT, value TEXT,
        connector_id TEXT, method_id TEXT, active INTEGER,
        time_created INTEGER, time_updated INTEGER
    );
    CREATE TABLE provider_auth (
        id TEXT PRIMARY KEY, provider_id TEXT, user_id TEXT, api_key TEXT,
        time_created INTEGER, time_updated INTEGER
    );
    CREATE TABLE cache (
        key TEXT PRIMARY KEY, payload TEXT, time_created INTEGER
    );
    INSERT INTO session (id, project_id, slug, title, version)
        VALUES ('session-a', 'project-a', 'a', 'a', '1.18.29');
";

/// Create an `OpenCode` store whose message rows run `m000000` upward, with
/// `rows` rows of `data_len`-byte data cells, under `<dir>/opencode.db`.
/// Row ids are zero-padded so lexicographic order matches numeric order
/// and the first record stays stable across growth.
fn opencode_store(dir: &Path, rows: usize, data_len: usize, session: &str) -> PathBuf {
    let path = dir.join("opencode.db");
    fs::create_dir_all(dir).expect("the store directory is creatable");
    let writer = Connection::open(&path).expect("the seed store is creatable");
    writer
        .execute_batch(OPENCODE_DDL)
        .expect("the seed schema applies");
    insert_opencode_rows(&writer, session, 0, rows, data_len);
    drop(writer);
    path
}

/// Insert message rows `m{first}..m{first+count}` in one transaction.
fn insert_opencode_rows(
    writer: &Connection,
    session: &str,
    first: usize,
    count: usize,
    data_len: usize,
) {
    let data = "d".repeat(data_len);
    writer
        .execute("BEGIN", [])
        .expect("the seed transaction opens");
    {
        let insert =
            format!("INSERT INTO message (id, session_id, data) VALUES (?1, '{session}', ?2)");
        let mut statement = writer.prepare(&insert).expect("the insert prepares");
        for row in first..first + count {
            statement
                .execute(params![format!("m{row:06}"), data])
                .expect("the seed row inserts");
        }
    }
    writer
        .execute("COMMIT", [])
        .expect("the seed transaction commits");
}

/// Pin a fixture's modification time outside the freshness window: the
/// filesystem's own record that this source is history, not a live
/// session.
fn age(path: &Path) {
    let status = Command::new("touch")
        .arg("-d")
        .arg(AGED_MTIME)
        .arg(path)
        .status()
        .expect("touch runs");
    assert!(status.success(), "aging {} failed", path.display());
}

// ---------------------------------------------------------------------------
// The scan bridge
// ---------------------------------------------------------------------------

/// Domain-separation label for the bridge's source-id derivation: the
/// status contract's `source_id` joins the scan to the state database, so
/// it is derived from stable inputs — adapter, account, first complete
/// record — never from a path (the same rule the SDK's synthetic adapter
/// example publishes).
const SOURCE_ID_LABEL: &[u8] = b"archivist.multi-adapter-scheduling.source-id.v1";

fn derive_source_id(adapter: &str, account: &str, first_record: &[u8]) -> SourceId {
    let mut framed = SOURCE_ID_LABEL.to_vec();
    for part in [adapter.as_bytes(), account.as_bytes(), first_record] {
        framed.push(0);
        framed.extend_from_slice(part);
    }
    let hex = sha256::encode_hex(&sha256::digest(&framed));
    SourceId::parse(&format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
    .expect("the derived identifier satisfies the source-id grammar")
}

/// Whether the fixture's own modification time sits inside the freshness
/// window: the bridge's activity rule. A future mtime counts as inactive.
fn active_within_window(path: &Path) -> bool {
    let modified = fs::metadata(path)
        .expect("the fixture stats")
        .modified()
        .expect("the fixture mtime reads");
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age <= FRESHNESS_WINDOW)
}

fn first_record(bytes: &[u8]) -> &[u8] {
    bytes.split(|byte| *byte == b'\n').next().unwrap_or(bytes)
}

/// One scan for a newline-delimited source: the SDK's complete-record
/// boundary rule over the file's bytes, discovery and admission having
/// been the adapter's own pass.
fn scan_jsonl_file(adapter: &AdapterId, account: &AccountLabel, path: &Path) -> SourceScan {
    let bytes = fs::read(path).expect("the discovered fixture reads");
    let boundary = RecordBoundary::select(&bytes);
    SourceScan {
        source: derive_source_id(adapter.as_str(), account.as_str(), first_record(&bytes)),
        adapter: adapter.clone(),
        account: account.clone(),
        complete_bytes: boundary.complete_bytes,
        complete_events: boundary.complete_records,
        incomplete_tail_bytes: boundary.incomplete_tail_bytes,
        last_activity: None,
        active_in_window: active_within_window(path),
        classification: ScanClassification::Ok,
    }
}

/// One scan for a whole-object source (the Claude sidecar roles): the
/// measured figure is the object's full length and one event — the
/// digest-sensitive whole-object capture contract.
fn scan_object_file(adapter: &AdapterId, account: &AccountLabel, path: &Path) -> SourceScan {
    let bytes = fs::read(path).expect("the discovered sidecar reads");
    SourceScan {
        source: derive_source_id(adapter.as_str(), account.as_str(), first_record(&bytes)),
        adapter: adapter.clone(),
        account: account.clone(),
        complete_bytes: u64::try_from(bytes.len()).expect("the sidecar size fits u64"),
        complete_events: 1,
        incomplete_tail_bytes: 0,
        last_activity: None,
        active_in_window: active_within_window(path),
        classification: ScanClassification::Ok,
    }
}

/// One scan for an `OpenCode` account: the read-only snapshot of the
/// allowlisted store, projected to its canonical JSONL — the artifact
/// body the projection emits — and measured by the same boundary rule.
fn scan_opencode(account: &AccountLabel, path: &Path) -> SourceScan {
    let descriptor = archivist_adapter_opencode::adapter_descriptor();
    let store = StoreConnection::open(path).expect("the seeded store opens read-only");
    let snapshot = Snapshot::take(&store).expect("the allowlisted store snapshots");
    let projection = Projection::project(&snapshot).expect("the seeded store projects");
    let jsonl = projection.jsonl();
    let boundary = RecordBoundary::select(&jsonl);
    SourceScan {
        source: derive_source_id(
            descriptor.adapter.as_str(),
            account.as_str(),
            first_record(&jsonl),
        ),
        adapter: descriptor.adapter,
        account: account.clone(),
        complete_bytes: boundary.complete_bytes,
        complete_events: boundary.complete_records,
        incomplete_tail_bytes: boundary.incomplete_tail_bytes,
        last_activity: None,
        active_in_window: active_within_window(path),
        classification: ScanClassification::Ok,
    }
}

// ---------------------------------------------------------------------------
// Fleets
// ---------------------------------------------------------------------------

fn label(text: &str) -> AccountLabel {
    AccountLabel::parse(text).expect("the fixture account label is grammar-valid")
}

/// A growing file source: the exact line to append each round.
struct FileGrower {
    path: PathBuf,
    line: String,
}

/// A growing `OpenCode` store: the next row id to insert.
struct StoreGrower {
    path: PathBuf,
    next_row: usize,
    session: String,
}

/// One multi-adapter fleet over synthetic account trees. Adapters without
/// sources in a fleet stay `None` (the swap fleets carry no `OpenCode`).
struct Fleet {
    claude: Option<ClaudeAdapter>,
    claude_accounts: Vec<AccountLabel>,
    codex: Option<CodexAdapter>,
    codex_accounts: Vec<AccountLabel>,
    pi: Option<PiAdapter>,
    pi_accounts: Vec<AccountLabel>,
    opencode_accounts: Vec<AccountLabel>,
    opencode_paths: Vec<PathBuf>,
    file_growers: Vec<FileGrower>,
    store_growers: Vec<StoreGrower>,
}

impl Fleet {
    /// Grow every live source by one round's activity, before the round's
    /// discovery and measurement.
    fn grow(&mut self) {
        for grower in &self.file_growers {
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(&grower.path)
                .expect("the live fixture opens for append");
            let repeats = usize::try_from(GROWTH_LINES).expect("growth fits the platform");
            file.write_all(grower.line.repeat(repeats).as_bytes())
                .expect("the live fixture grows");
        }
        for grower in &mut self.store_growers {
            let writer = Connection::open(&grower.path).expect("the live store opens for growth");
            insert_opencode_rows(
                &writer,
                &grower.session,
                grower.next_row,
                OPENCODE_GROWTH_ROWS,
                OPENCODE_GROWTH_DATA,
            );
            grower.next_row += OPENCODE_GROWTH_ROWS;
        }
    }

    /// One discovery and measurement pass over every adapter and account:
    /// the scans the daemon cycle's composition will hand the inventory.
    /// Each adapter's own discovery and admission decide what is here.
    fn scans(&self) -> Vec<SourceScan> {
        let mut scans = Vec::new();
        if let Some(claude) = &self.claude {
            let adapter = AdapterId::parse(CLAUDE_ADAPTER_ID).expect("the claude adapter id");
            for account in &self.claude_accounts {
                for source in claude.inventory(account).supported() {
                    let scan = if source.role().is_jsonl() {
                        scan_jsonl_file(&adapter, account, source.path())
                    } else {
                        scan_object_file(&adapter, account, source.path())
                    };
                    scans.push(scan);
                }
            }
        }
        if let Some(codex) = &self.codex {
            let adapter = AdapterId::parse(CODEX_ADAPTER_ID).expect("the codex adapter id");
            for account in &self.codex_accounts {
                for source in codex.inventory(account).supported() {
                    scans.push(scan_jsonl_file(&adapter, account, source.path()));
                }
            }
        }
        if let Some(pi) = &self.pi {
            let adapter = AdapterId::parse(PI_ADAPTER_ID).expect("the pi adapter id");
            for account in &self.pi_accounts {
                for source in pi.inventory(account).supported() {
                    scans.push(scan_jsonl_file(&adapter, account, source.path()));
                }
            }
        }
        for (account, path) in self.opencode_accounts.iter().zip(&self.opencode_paths) {
            scans.push(scan_opencode(account, path));
        }
        scans
    }
}

/// The main fleet: every adapter crate, seven account scopes, the largest
/// measured history deliberately on the `OpenCode` database adapter, one
/// live session per adapter, and the Claude tool-result sidecar present
/// as a whole-object source.
#[allow(clippy::too_many_lines)] // one fleet laid out place by place
fn build_main_fleet(scratch: &Path) -> Fleet {
    let claude_alpha_root = scratch.join("claude-alpha");
    let claude_beta_root = scratch.join("claude-beta");
    let claude_live = claude_session(
        &claude_alpha_root,
        "sess-live.jsonl",
        "session-claude-live",
        ACTIVE_LINES,
        false,
    );
    let claude_xl = claude_session(
        &claude_alpha_root,
        "sess-xl.jsonl",
        "session-xl",
        XL_LINES,
        false,
    );
    let claude_sidecar = claude_tool_result(&claude_alpha_root, "sess-xl");
    let claude_sm = claude_session(
        &claude_beta_root,
        "sess-sm.jsonl",
        "session-sm",
        SM_LINES,
        true,
    );

    let codex_gamma_home = scratch.join("codex-gamma");
    let codex_delta_home = scratch.join("codex-delta");
    let codex_live = codex_rollout(
        &codex_gamma_home,
        "rollout-live.jsonl",
        "session-codex-live",
        ACTIVE_LINES,
    );
    let codex_lg = codex_rollout(
        &codex_gamma_home,
        "rollout-lg.jsonl",
        "session-lg",
        LG_LINES,
    );
    let codex_history = codex_history(&codex_gamma_home, HS_LINES);
    let codex_xs = codex_rollout(
        &codex_delta_home,
        "rollout-xs.jsonl",
        "session-xs",
        XS_LINES,
    );

    let pi_root = scratch.join("pi-epsilon");
    let pi_live = pi_session(&pi_root, "proj-live", "session-pi-live", ACTIVE_LINES);
    let pi_md = pi_session(&pi_root, "proj-md", "session-md", MD_LINES);

    let opencode_history = opencode_store(
        &scratch.join("opencode-kappa"),
        OPENCODE_HISTORY_ROWS,
        OPENCODE_HISTORY_DATA,
        "session-oc-big",
    );
    let opencode_live = opencode_store(
        &scratch.join("opencode-lambda"),
        OPENCODE_SEED_ROWS,
        OPENCODE_GROWTH_DATA,
        "session-oc-live",
    );

    // Histories are pinned outside the freshness window; live fixtures
    // were just written, so their own mtimes keep them in it.
    for path in [
        &claude_xl,
        &claude_sidecar,
        &claude_sm,
        &codex_lg,
        &codex_history,
        &codex_xs,
        &pi_md,
        &opencode_history,
    ] {
        age(path);
    }

    let claude_alpha = label("claude-alpha");
    let claude_beta = label("claude-beta");
    let codex_gamma = label("codex-gamma");
    let codex_delta = label("codex-delta");
    let pi_epsilon = label("pi-epsilon");
    let opencode_kappa = label("opencode-kappa");
    let opencode_lambda = label("opencode-lambda");

    Fleet {
        claude: Some(
            ClaudeAdapter::new([
                ClaudeRoot::new(claude_alpha.clone(), claude_alpha_root),
                ClaudeRoot::new(claude_beta.clone(), claude_beta_root),
            ])
            .expect("the claude adapter configures"),
        ),
        claude_accounts: vec![claude_alpha, claude_beta],
        codex: Some(
            CodexAdapter::new([
                CodexRoot::new(codex_gamma.clone(), codex_gamma_home),
                CodexRoot::new(codex_delta.clone(), codex_delta_home),
            ])
            .expect("the codex adapter configures"),
        ),
        codex_accounts: vec![codex_gamma, codex_delta],
        pi: Some(
            PiAdapter::new([PiRoot::durable(pi_epsilon.clone(), pi_root)])
                .expect("the pi adapter configures"),
        ),
        pi_accounts: vec![pi_epsilon],
        opencode_accounts: vec![opencode_kappa, opencode_lambda.clone()],
        opencode_paths: vec![opencode_history, opencode_live.clone()],
        file_growers: vec![
            FileGrower {
                path: claude_live,
                line: claude_line("session-claude-live", false),
            },
            FileGrower {
                path: codex_live,
                line: codex_rollout_line("session-codex-live"),
            },
            FileGrower {
                path: pi_live,
                line: pi_line("session-pi-live", false),
            },
        ],
        store_growers: vec![StoreGrower {
            path: opencode_live,
            next_row: OPENCODE_SEED_ROWS,
            session: "session-oc-live".to_owned(),
        }],
    }
}

// ---------------------------------------------------------------------------
// The swap fleets
// ---------------------------------------------------------------------------

/// Which adapter crate owns a slot's fixture.
#[derive(Clone, Copy)]
enum Seat {
    Claude,
    Codex,
    Pi,
}

/// A history size class or a live session.
#[derive(Clone, Copy)]
enum Class {
    Xl,
    Lg,
    Md,
    Sm,
    Xs,
    Hs,
    Live,
}

impl Class {
    fn lines(self) -> u64 {
        match self {
            Self::Xl => XL_LINES,
            Self::Lg => LG_LINES,
            Self::Md => MD_LINES,
            Self::Sm => SM_LINES,
            Self::Xs => XS_LINES,
            Self::Hs => HS_LINES,
            Self::Live => ACTIVE_LINES,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Self::Xl => "xl",
            Self::Lg => "lg",
            Self::Md => "md",
            Self::Sm => "sm",
            Self::Xs => "xs",
            Self::Hs => "hs",
            Self::Live => "live",
        }
    }

    fn is_live(self) -> bool {
        matches!(self, Self::Live)
    }
}

/// One fixture placement: the adapter that must discover it, the account
/// label it lives under, and its size class. The claude account holding
/// `Sm`/`Xs` writes the v2 dialect (an account-identifying member in the
/// header window), so both claude dialects are exercised in both fleets.
struct Slot {
    seat: Seat,
    account: &'static str,
    class: Class,
}

/// Fleet A: claude {Xl, Sm, live}, codex {Lg, Xs, Hs, live}, pi {Md,
/// live}. The shared prompt-history sidecar lives beside the Xs rollout.
const SWAP_FLEET_A: [Slot; 9] = [
    Slot {
        seat: Seat::Claude,
        account: "claude-alpha",
        class: Class::Xl,
    },
    Slot {
        seat: Seat::Claude,
        account: "claude-alpha",
        class: Class::Live,
    },
    Slot {
        seat: Seat::Claude,
        account: "claude-beta",
        class: Class::Sm,
    },
    Slot {
        seat: Seat::Codex,
        account: "codex-gamma",
        class: Class::Lg,
    },
    Slot {
        seat: Seat::Codex,
        account: "codex-gamma",
        class: Class::Live,
    },
    Slot {
        seat: Seat::Codex,
        account: "codex-delta",
        class: Class::Xs,
    },
    Slot {
        seat: Seat::Codex,
        account: "codex-delta",
        class: Class::Hs,
    },
    Slot {
        seat: Seat::Pi,
        account: "pi-epsilon",
        class: Class::Md,
    },
    Slot {
        seat: Seat::Pi,
        account: "pi-epsilon",
        class: Class::Live,
    },
];

/// Fleet B, deranged from A: claude {Lg, Xs, live}, codex {Md, Hs, live},
/// pi {Xl, Sm, live}. Every adapter owns different figures than it did in
/// fleet A, every account label differs, and the history sidecar lives
/// beside the Md rollout.
const SWAP_FLEET_B: [Slot; 9] = [
    Slot {
        seat: Seat::Pi,
        account: "pi-nu",
        class: Class::Xl,
    },
    Slot {
        seat: Seat::Pi,
        account: "pi-nu",
        class: Class::Live,
    },
    Slot {
        seat: Seat::Pi,
        account: "pi-xi",
        class: Class::Sm,
    },
    Slot {
        seat: Seat::Claude,
        account: "claude-iota",
        class: Class::Lg,
    },
    Slot {
        seat: Seat::Claude,
        account: "claude-iota",
        class: Class::Live,
    },
    Slot {
        seat: Seat::Claude,
        account: "claude-kappa",
        class: Class::Xs,
    },
    Slot {
        seat: Seat::Codex,
        account: "codex-lambda",
        class: Class::Md,
    },
    Slot {
        seat: Seat::Codex,
        account: "codex-lambda",
        class: Class::Live,
    },
    Slot {
        seat: Seat::Codex,
        account: "codex-lambda",
        class: Class::Hs,
    },
];

fn is_v2(class: Class) -> bool {
    matches!(class, Class::Sm | Class::Xs)
}

/// Lay out one swap fleet: write every slot's fixture under its account
/// root, age the histories, and register the live growers.
fn build_swap_fleet(scratch: &Path, slots: &[Slot]) -> Fleet {
    let mut aged: Vec<PathBuf> = Vec::new();
    let mut file_growers = Vec::new();
    for slot in slots {
        let root = scratch.join(slot.account);
        let live_session = match slot.seat {
            Seat::Claude => "session-claude-live",
            Seat::Codex => "session-codex-live",
            Seat::Pi => "session-pi-live",
        };
        let path = match (slot.seat, slot.class) {
            (Seat::Claude, Class::Live) => {
                claude_session(&root, "sess-live.jsonl", live_session, ACTIVE_LINES, false)
            }
            (Seat::Claude, class) => claude_session(
                &root,
                &format!("sess-{}.jsonl", class.tag()),
                &format!("session-{}", class.tag()),
                class.lines(),
                is_v2(class),
            ),
            (Seat::Codex, Class::Live) => {
                codex_rollout(&root, "rollout-live.jsonl", live_session, ACTIVE_LINES)
            }
            (Seat::Codex, Class::Hs) => codex_history(&root, HS_LINES),
            (Seat::Codex, class) => codex_rollout(
                &root,
                &format!("rollout-{}.jsonl", class.tag()),
                &format!("session-{}", class.tag()),
                class.lines(),
            ),
            (Seat::Pi, Class::Live) => pi_session(&root, "proj-live", live_session, ACTIVE_LINES),
            (Seat::Pi, class) => pi_session(
                &root,
                &format!("proj-{}", class.tag()),
                &format!("session-{}", class.tag()),
                class.lines(),
            ),
        };
        if slot.class.is_live() {
            let line = match slot.seat {
                Seat::Claude => claude_line(live_session, false),
                Seat::Codex => codex_rollout_line(live_session),
                Seat::Pi => pi_line(live_session, false),
            };
            file_growers.push(FileGrower {
                path: path.clone(),
                line,
            });
        } else {
            aged.push(path);
        }
    }
    for path in aged {
        age(&path);
    }

    // One configured root per distinct account, in first-seen order.
    let mut claude_roots = Vec::new();
    let mut claude_accounts: Vec<AccountLabel> = Vec::new();
    let mut codex_roots = Vec::new();
    let mut codex_accounts: Vec<AccountLabel> = Vec::new();
    let mut pi_roots = Vec::new();
    let mut pi_accounts: Vec<AccountLabel> = Vec::new();
    for slot in slots {
        let root = scratch.join(slot.account);
        let known = |accounts: &[AccountLabel]| {
            accounts
                .iter()
                .any(|account| account.as_str() == slot.account)
        };
        match slot.seat {
            Seat::Claude if !known(&claude_accounts) => {
                claude_accounts.push(label(slot.account));
                claude_roots.push(ClaudeRoot::new(label(slot.account), root));
            }
            Seat::Codex if !known(&codex_accounts) => {
                codex_accounts.push(label(slot.account));
                codex_roots.push(CodexRoot::new(label(slot.account), root));
            }
            Seat::Pi if !known(&pi_accounts) => {
                pi_accounts.push(label(slot.account));
                pi_roots.push(PiRoot::durable(label(slot.account), root));
            }
            _ => {}
        }
    }

    Fleet {
        claude: (!claude_roots.is_empty())
            .then(|| ClaudeAdapter::new(claude_roots).expect("the claude adapter configures")),
        claude_accounts,
        codex: (!codex_roots.is_empty())
            .then(|| CodexAdapter::new(codex_roots).expect("the codex adapter configures")),
        codex_accounts,
        pi: (!pi_roots.is_empty())
            .then(|| PiAdapter::new(pi_roots).expect("the pi adapter configures")),
        pi_accounts,
        opencode_accounts: Vec::new(),
        opencode_paths: Vec::new(),
        file_growers,
        store_growers: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// The state harness
// ---------------------------------------------------------------------------

/// The per-adapter facts the state schema records for an enrolled source.
struct AdapterFacts {
    harness: &'static str,
    projection: &'static str,
    artifact_kind: &'static str,
}

fn adapter_facts(adapter: &str) -> AdapterFacts {
    match adapter {
        CLAUDE_ADAPTER_ID => AdapterFacts {
            harness: "claude-code",
            projection: "1",
            artifact_kind: "file-slice",
        },
        CODEX_ADAPTER_ID => AdapterFacts {
            harness: "codex",
            projection: "1",
            artifact_kind: "file-slice",
        },
        PI_ADAPTER_ID => AdapterFacts {
            harness: "pi",
            projection: "1.0.0",
            artifact_kind: "file-slice",
        },
        "opencode" => AdapterFacts {
            harness: "opencode",
            projection: "0.1.0",
            artifact_kind: "database-projection",
        },
        _ => panic!("no facts for unexpected adapter {adapter}"),
    }
}

/// A 36-character lowercase identifier derived from stable text.
fn derived_id(seed: &str) -> String {
    let hex = sha256::encode_hex(&sha256::digest(seed.as_bytes()));
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The acknowledged-state side of the drive: the real state store, with
/// the enrollment and acknowledged-range rows a receipt-acknowledging
/// capture path records.
struct Harness {
    store: StateStore,
    generations: HashMap<String, String>,
    occurrence: u64,
}

impl Harness {
    fn new() -> Self {
        let mut store = StateStore::open_in_memory().expect("the in-memory state opens");
        store.migrate().expect("the state schema migrates");
        Self {
            store,
            generations: HashMap::new(),
            occurrence: 0,
        }
    }

    /// Enroll one measured source on its first grant, recording the lane
    /// the measurement itself assigned.
    fn enroll(&mut self, record: &SourceInventory, now: &str) {
        if self.generations.contains_key(record.source.as_str()) {
            return;
        }
        let facts = adapter_facts(record.adapter.as_str());
        let generation = derived_id(&format!("{}-generation", record.source.as_str()));
        let session_seed = format!("{}-session", record.source.as_str());
        let artifact_seed = format!("{}-artifact", record.source.as_str());
        self.store
            .connection()
            .execute(
                "INSERT INTO sources (source_id, harness, upstream_session_id, id_source,
                    session_hash, artifact_kind, adapter_id, adapter_projection_version,
                    adapter_artifact_id, artifact_hash, freshness_lane, last_cursor,
                    created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'natural', ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11, ?11)",
                params![
                    record.source.as_str(),
                    facts.harness,
                    format!("{}-{}", record.account.as_str(), record.source.as_str()),
                    sha256::encode_hex(&sha256::digest(session_seed.as_bytes())),
                    facts.artifact_kind,
                    record.adapter.as_str(),
                    facts.projection,
                    format!("{}-artifact", record.source.as_str()),
                    sha256::encode_hex(&sha256::digest(artifact_seed.as_bytes())),
                    record.lane.token(),
                    now,
                ],
            )
            .expect("the measured source enrolls");
        self.store
            .connection()
            .execute(
                "INSERT INTO generations (generation_id, source_id, ordinal, state,
                    detected_reason, tail_checksum, file_identity, detected_at)
                 VALUES (?1, ?2, 1, 'open', 'first-observed', NULL, NULL, ?3)",
                params![generation, record.source.as_str(), now],
            )
            .expect("the source's first generation opens");
        self.generations
            .insert(record.source.as_str().to_owned(), generation);
    }

    /// Record one round's acknowledged extents for a source — the rows a
    /// verified receipt leaves behind: incremental ranges whose ends are
    /// the new acknowledged positions, bytes and events separately.
    fn acknowledge(
        &mut self,
        record: &SourceInventory,
        new_bytes: u64,
        new_events: u64,
        now: &str,
    ) {
        self.enroll(record, now);
        let generation = self
            .generations
            .get(record.source.as_str())
            .expect("enrollment opened the generation");
        for (kind, start, end) in [
            ("bytes", record.acknowledged_bytes, new_bytes),
            ("events", record.acknowledged_events, new_events),
        ] {
            self.occurrence += 1;
            self.store
                .connection()
                .execute(
                    "INSERT INTO ranges (occurrence_id, generation_id, range_kind, range_start,
                        range_end, sequence, blob_digest, spool_entry_id, captured_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
                    params![
                        format!("{:064x}", self.occurrence),
                        generation,
                        kind,
                        i64::try_from(start).expect("the range start fits i64"),
                        i64::try_from(end).expect("the range end fits i64"),
                        i64::try_from(self.occurrence).expect("the sequence fits i64"),
                        sha256::encode_hex(&sha256::digest(
                            format!("{}-{}-{}", record.source.as_str(), kind, self.occurrence)
                                .as_bytes(),
                        )),
                        now,
                    ],
                )
                .expect("the acknowledged range records");
        }
    }
}

// ---------------------------------------------------------------------------
// The drive loop
// ---------------------------------------------------------------------------

/// One round's evidence: the plan as spent, and the measurements it ran
/// over.
struct RoundTrace {
    totals: CycleTotals,
    reserved: Vec<String>,
    backfill: Vec<(String, u64, u64)>,
    outstanding: HashMap<String, u64>,
    lane: HashMap<String, FreshnessLane>,
    coverage: HashMap<String, CoverageState>,
}

/// One discovery and measurement pass over every adapter and account —
/// the scans the daemon cycle's composition would hand the inventory —
/// holding every measured record to the drive's health bar: clean
/// classification, no coverage contradiction, no failed source.
fn measure_pass(fleet: &Fleet, harness: &Harness, pass: &str) -> Vec<SourceInventory> {
    let scans = fleet.scans();
    let now = Timestamp::parse(&now_rfc3339()).expect("the rendered instant parses");
    let sources = measured_sources(
        harness.store.connection(),
        &scans,
        &now,
        &InventoryOptions::default(),
    )
    .expect("the inventory pass measures");
    for record in &sources {
        assert_eq!(
            record.classification,
            ScanClassification::Ok,
            "every source measures clean in {pass}"
        );
        assert!(
            record.anomaly.is_none(),
            "no coverage contradiction in {pass}"
        );
        assert_ne!(
            record.coverage,
            CoverageState::Failed,
            "no source fails in {pass}"
        );
    }
    sources
}

/// Plan one pass over measured sources and capture the pass's evidence:
/// the plan as spent, and the measurements it ran over.
fn plan_pass(sources: &[SourceInventory], limits: SchedulerLimits) -> (CyclePlan, RoundTrace) {
    let plan = scheduler::plan(sources, DrainLoad::default(), CAPACITY_BYTES, limits);
    let trace = RoundTrace {
        totals: plan.totals.clone(),
        reserved: plan
            .reservations
            .iter()
            .map(|grant| grant.source.as_str().to_owned())
            .collect(),
        backfill: plan
            .backfill
            .iter()
            .map(|grant| {
                (
                    grant.source.as_str().to_owned(),
                    grant.granted_bytes,
                    grant.chunk_count,
                )
            })
            .collect(),
        outstanding: sources
            .iter()
            .map(|record| (record.source.as_str().to_owned(), record.outstanding_bytes))
            .collect(),
        lane: sources
            .iter()
            .map(|record| (record.source.as_str().to_owned(), record.lane))
            .collect(),
        coverage: sources
            .iter()
            .map(|record| (record.source.as_str().to_owned(), record.coverage))
            .collect(),
    };
    (plan, trace)
}

/// Run the fleet: grow the live sources, discover and measure through
/// every adapter, plan the round, apply the plan's grants as acknowledged
/// ranges — until a pass measures no outstanding data on any backfill
/// lane source (the live sessions keep growing by design). The trace
/// sequence ends with two closing passes: the quiescent pass that first
/// measures the histories drained (the live sessions still carrying one
/// round of growth), then the steady pass — no growth, after that round's
/// receipts have landed — where every source measures its acknowledged
/// position.
fn drive(fleet: &mut Fleet, harness: &mut Harness) -> Vec<RoundTrace> {
    let limits = SchedulerLimits::plan_defaults();
    let mut traces = Vec::new();
    for round in 0..MAX_ROUNDS {
        if round > 0 {
            fleet.grow();
        }
        let pass = format!("round {}", round + 1);
        let sources = measure_pass(fleet, harness, &pass);
        let (plan, trace) = plan_pass(&sources, limits);
        traces.push(trace);

        let histories_drained = sources
            .iter()
            .filter(|record| record.lane == FreshnessLane::Backfill)
            .all(|record| record.outstanding_bytes == 0 && record.outstanding_events == 0);

        // Apply the plan the way completed receipts would: bytes exactly,
        // events at an even per-byte rate, the final grant landing exactly
        // on the complete boundary.
        let now_text = now_rfc3339();
        let mut deltas: HashMap<&str, u64> = HashMap::new();
        for grant in plan.reservations.iter().chain(&plan.backfill) {
            *deltas.entry(grant.source.as_str()).or_insert(0) += grant.granted_bytes;
        }
        let by_id: HashMap<&str, &SourceInventory> = sources
            .iter()
            .map(|record| (record.source.as_str(), record))
            .collect();
        let mut targets = Vec::new();
        for (source, delta_bytes) in deltas {
            let record = *by_id
                .get(source)
                .unwrap_or_else(|| panic!("a grant names a measured source: {source}"));
            let new_bytes = record.acknowledged_bytes + delta_bytes;
            let new_events = if new_bytes == record.complete_bytes {
                record.complete_events
            } else {
                record.acknowledged_events
                    + record.outstanding_events * delta_bytes / record.outstanding_bytes.max(1)
            };
            assert!(
                new_bytes <= record.complete_bytes && new_events <= record.complete_events,
                "a grant never acknowledges beyond the measured boundary"
            );
            targets.push((record.clone(), new_bytes, new_events));
        }
        for (record, new_bytes, new_events) in targets {
            harness.acknowledge(&record, new_bytes, new_events, &now_text);
        }

        if histories_drained {
            // The steady pass: the instant after this round's receipts land
            // and before any new activity. Nothing grows, so every source
            // measures its acknowledged position and the plan over the
            // caught-up fleet grants nothing at all.
            let sources = measure_pass(fleet, harness, "the steady pass");
            let (plan, trace) = plan_pass(&sources, limits);
            assert!(
                plan.reservations.is_empty() && plan.backfill.is_empty(),
                "a fleet with no measured outstanding data plans nothing"
            );
            traces.push(trace);
            return traces;
        }
    }
    panic!("the fleet did not drain within {MAX_ROUNDS} rounds");
}

// ---------------------------------------------------------------------------
// Shared analysis helpers
// ---------------------------------------------------------------------------

/// Per-source cumulative backfill bytes across the trace sequence, one
/// entry per round.
fn cumulative_backfill(traces: &[RoundTrace]) -> HashMap<String, Vec<u64>> {
    let mut sources: Vec<String> = Vec::new();
    for trace in traces {
        for (source, _, _) in &trace.backfill {
            if !sources.contains(source) {
                sources.push(source.clone());
            }
        }
    }
    let mut curves = HashMap::new();
    for source in &sources {
        let mut running = 0u64;
        let curve: Vec<u64> = traces
            .iter()
            .map(|trace| {
                running += trace
                    .backfill
                    .iter()
                    .find(|(s, _, _)| s == source)
                    .map_or(0, |(_, bytes, _)| *bytes);
                running
            })
            .collect();
        curves.insert(source.clone(), curve);
    }
    curves
}

/// The first round a source's measured outstanding reaches zero (rounds
/// are one-based). Every drained source appears exactly once.
fn completion_rounds(traces: &[RoundTrace]) -> HashMap<String, u64> {
    let mut completion: HashMap<String, u64> = HashMap::new();
    for (index, trace) in traces.iter().enumerate() {
        let round = u64::try_from(index).expect("the round index fits u64") + 1;
        for (source, outstanding) in &trace.outstanding {
            if *outstanding == 0 {
                completion
                    .entry(source.clone())
                    .and_modify(|kept| *kept = (*kept).min(round))
                    .or_insert(round);
            }
        }
    }
    completion
}

/// The first round a source receives a backfill grant (one-based); a
/// source never granted has no entry.
fn first_grant_rounds(traces: &[RoundTrace]) -> HashMap<String, u64> {
    let mut firsts: HashMap<String, u64> = HashMap::new();
    for (index, trace) in traces.iter().enumerate() {
        let round = u64::try_from(index).expect("the round index fits u64") + 1;
        for (source, _, _) in &trace.backfill {
            firsts
                .entry(source.clone())
                .and_modify(|kept| *kept = (*kept).min(round))
                .or_insert(round);
        }
    }
    firsts
}

/// (source, initial outstanding bytes) for every backfill-lane source in
/// the first trace, sorted by descending figure.
fn ranked_histories(traces: &[RoundTrace]) -> Vec<(String, u64)> {
    let mut histories: Vec<(String, u64)> = traces[0]
        .outstanding
        .iter()
        .filter(|(source, _)| traces[0].lane[source.as_str()] == FreshnessLane::Backfill)
        .map(|(source, bytes)| (source.clone(), *bytes))
        .collect();
    histories.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));
    histories
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)] // one deterministic fleet drive, read top to bottom
fn multi_adapter_fleet_backfills_largest_measured_first_and_keeps_every_adapter_fresh() {
    let scratch = Scratch::new("main");
    let mut fleet = build_main_fleet(scratch.path());
    let scans = fleet.scans();
    assert_eq!(scans.len(), 12, "every fixture source is discovered");

    let mut harness = Harness::new();
    let traces = drive(&mut fleet, &mut harness);
    assert!(
        traces.len() >= 6,
        "the multi-round drain is visible ({} traces)",
        traces.len()
    );

    // ---- The measurement itself: every adapter crate, seven scopes,
    // every source on its expected lane. ----
    let first = &traces[0];
    let mut adapters = HashSet::new();
    let mut scopes = HashSet::new();
    let mut adapter_of = HashMap::new();
    for scan in &scans {
        adapters.insert(scan.adapter.as_str().to_owned());
        scopes.insert(format!(
            "{}:{}",
            scan.adapter.as_str(),
            scan.account.as_str()
        ));
        adapter_of.insert(
            scan.source.as_str().to_owned(),
            scan.adapter.as_str().to_owned(),
        );
    }
    let expected_adapters: HashSet<String> = ["claude-jsonl", "codex-jsonl", "opencode", "pi"]
        .map(String::from)
        .into_iter()
        .collect();
    assert_eq!(
        adapters, expected_adapters,
        "every implemented adapter crate is exercised"
    );
    assert_eq!(scopes.len(), 7, "seven adapter/account scopes measured");
    assert_eq!(
        first.outstanding.len(),
        scans.len(),
        "one measured record per discovered source"
    );
    let lane_count =
        |lane: FreshnessLane| first.lane.values().filter(|seen| **seen == lane).count();
    assert_eq!(lane_count(FreshnessLane::Backfill), 8, "eight histories");
    assert_eq!(
        lane_count(FreshnessLane::Freshness),
        4,
        "four live sessions"
    );
    let sidecar_figure = u64::try_from(SIDECAR_BYTES).expect("the sidecar figure fits u64");
    let sidecar = first
        .outstanding
        .iter()
        .find(|(_, bytes)| **bytes == sidecar_figure)
        .map(|(source, _)| source.clone())
        .expect("the claude sidecar is measured");
    assert_eq!(
        first.lane[sidecar.as_str()],
        FreshnessLane::Backfill,
        "the whole-object sidecar rides the backfill lane"
    );

    // ---- Measured outstanding controls priority. The largest initial
    // backlog is the OpenCode database projection, strictly larger than
    // the largest file history — and it, not a file adapter, receives the
    // first and largest grant of round one. ----
    let biggest = |adapter: &str| {
        first
            .outstanding
            .iter()
            .filter(|(source, _)| adapter_of[source.as_str()] == adapter)
            .max_by_key(|(_, bytes)| **bytes)
            .map_or_else(
                || panic!("the {adapter} adapter holds a history"),
                |(source, bytes)| (source.clone(), *bytes),
            )
    };
    let (opencode_big, opencode_bytes) = biggest("opencode");
    let (claude_big, claude_bytes) = biggest("claude-jsonl");
    assert!(
        opencode_bytes > claude_bytes && claude_bytes >= 48 * MIB,
        "the database adapter holds the largest measured history: {opencode_big} at \
         {opencode_bytes} beats {claude_big} at {claude_bytes} (>= 48 MiB)"
    );
    assert_eq!(
        traces[0].backfill.first().map(|(s, _, _)| s.as_str()),
        Some(opencode_big.as_str()),
        "round one's first backfill grant is the largest measured source"
    );
    for (round, trace) in traces.iter().enumerate() {
        let figures: Vec<u64> = trace
            .backfill
            .iter()
            .map(|(source, _, _)| trace.outstanding[source.as_str()])
            .collect();
        assert!(
            figures.windows(2).all(|pair| pair[0] >= pair[1]),
            "round {} spends largest-measured-first",
            round + 1
        );
        assert_eq!(
            trace.totals.short_reservations,
            0,
            "round {} is never short",
            round + 1
        );
        assert!(
            trace.totals.planned_bytes <= CAPACITY_BYTES,
            "round {} stays inside its capacity",
            round + 1
        );
    }

    // ---- Largest histories make the fastest backfill progress:
    // cumulative grants dominate pointwise, and a history's first grant
    // round never falls behind a smaller history's. ----
    let histories = ranked_histories(&traces);
    assert_eq!(histories.len(), 8, "every history class is present");
    let curves = cumulative_backfill(&traces);
    let firsts = first_grant_rounds(&traces);
    for pair in histories.windows(2) {
        let (bigger, smaller) = (&pair[0], &pair[1]);
        let bigger_curve = &curves[bigger.0.as_str()];
        let smaller_curve = &curves[smaller.0.as_str()];
        assert!(
            bigger_curve
                .iter()
                .zip(smaller_curve.iter())
                .all(|(b, s)| b >= s),
            "the {}-byte history's grant curve dominates the {}-byte one",
            bigger.1,
            smaller.1
        );
        assert!(
            firsts[bigger.0.as_str()] <= firsts[smaller.0.as_str()],
            "the {}-byte history is first granted no later than the {}-byte one",
            bigger.1,
            smaller.1
        );
    }
    let last = traces.len() - 1;
    for (source, initial) in &histories {
        assert_eq!(
            curves[source.as_str()][last],
            *initial,
            "every history byte is granted exactly once"
        );
        assert_eq!(
            traces[last].coverage[source.as_str()],
            CoverageState::FullyBackfilled,
            "{source} ends fully backfilled"
        );
    }

    // ---- Every active source remains fresh: one live session per
    // adapter, growing every round, reserved ahead of all backfill every
    // round, never outstanding beyond one round's growth. ----
    let actives: Vec<String> = first
        .lane
        .iter()
        .filter(|(_, lane)| **lane == FreshnessLane::Freshness)
        .map(|(source, _)| source.clone())
        .collect();
    assert_eq!(actives.len(), 4, "one live session per adapter");
    let active_adapters: HashSet<&String> = actives
        .iter()
        .map(|source| {
            adapter_of
                .get(source.as_str())
                .expect("the active's adapter")
        })
        .collect();
    assert_eq!(active_adapters.len(), 4, "every adapter has a live session");
    for (round, trace) in traces.iter().enumerate() {
        let measured_active: HashSet<&String> = trace
            .outstanding
            .iter()
            .filter(|(source, outstanding)| {
                **outstanding > 0 && trace.lane[source.as_str()] == FreshnessLane::Freshness
            })
            .map(|(source, _)| {
                actives
                    .iter()
                    .find(|active| active.as_str() == *source)
                    .expect("a known active source")
            })
            .collect();
        let reserved: HashSet<&String> = trace.reserved.iter().collect();
        assert_eq!(
            measured_active,
            reserved,
            "every active source with outstanding data is reserved in round {}",
            round + 1
        );
        for active in &actives {
            assert!(
                trace.outstanding[active.as_str()] < SchedulerLimits::plan_defaults().chunk_bytes,
                "a live session never accumulates beyond a chunk in round {}",
                round + 1
            );
        }
    }
    for active in &actives {
        assert_eq!(
            traces[last].coverage[active.as_str()],
            CoverageState::Current,
            "the steady pass measures {active} current"
        );
    }

    // ---- The report surface agrees: the fleet ends current, every scope
    // healthy, no source left unscanned. ----
    let final_scans = fleet.scans();
    let now = Timestamp::parse(&now_rfc3339()).expect("the rendered instant parses");
    let report = inventory(
        harness.store.connection(),
        &final_scans,
        &now,
        &InventoryOptions::default(),
    )
    .expect("the final inventory report");
    assert_eq!(report.overall, CoverageState::Current);
    assert_eq!(report.sources_without_scan, 0);
    assert_eq!(report.totals.active_backlog_bytes, 0);
    assert_eq!(report.totals.active_backlog_events, 0);
    assert_eq!(report.totals.historical_backlog_bytes, 0);
    assert_eq!(report.totals.historical_backlog_events, 0);
    assert_eq!(report.statuses.len(), 7);
    for status in &report.statuses {
        assert!(
            status.coverage == CoverageState::Current
                || status.coverage == CoverageState::FullyBackfilled,
            "the scope ends healthy"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)] // two deterministic fleet drives, read top to bottom
fn scheduling_is_invariant_under_adapter_and_account_permutation() {
    let mut traces_per_fleet: Vec<Vec<RoundTrace>> = Vec::new();
    for slots in [&SWAP_FLEET_A, &SWAP_FLEET_B] {
        let scratch = Scratch::new("swap");
        let mut fleet = build_swap_fleet(scratch.path(), slots);
        assert_eq!(fleet.scans().len(), 9, "every fixture source is discovered");
        let mut harness = Harness::new();
        traces_per_fleet.push(drive(&mut fleet, &mut harness));
    }
    let (traces_a, traces_b) = (&traces_per_fleet[0], &traces_per_fleet[1]);

    // The fleets really are permuted: no source id is shared.
    let sources_a: HashSet<&String> = traces_a[0].outstanding.keys().collect();
    let sources_b: HashSet<&String> = traces_b[0].outstanding.keys().collect();
    assert!(
        sources_a.is_disjoint(&sources_b),
        "the permutation moved every source identity"
    );

    // Same rounds, and identical arithmetic in every one: the totals are
    // a function of the measured figures alone.
    assert_eq!(traces_a.len(), traces_b.len(), "both fleets drain alike");
    for (round, (a, b)) in traces_a.iter().zip(traces_b.iter()).enumerate() {
        assert_eq!(
            a.totals,
            b.totals,
            "round {}'s arithmetic is permutation-invariant",
            round + 1
        );
    }

    // Identical per-figure grant curves and completion rounds.
    let figure_of = |traces: &[RoundTrace], source: &str| traces[0].outstanding[source];
    let curves_a = cumulative_backfill(traces_a);
    let curves_b = cumulative_backfill(traces_b);
    let completions_a = completion_rounds(traces_a);
    let completions_b = completion_rounds(traces_b);
    let curve_by_figure_a: HashMap<u64, &Vec<u64>> = curves_a
        .iter()
        .map(|(source, curve)| (figure_of(traces_a, source.as_str()), curve))
        .collect();
    let curve_by_figure_b: HashMap<u64, &Vec<u64>> = curves_b
        .iter()
        .map(|(source, curve)| (figure_of(traces_b, source.as_str()), curve))
        .collect();
    assert_eq!(
        curve_by_figure_a.len(),
        curve_by_figure_b.len(),
        "both fleets grant the same figures"
    );
    for (figure, curve_a) in &curve_by_figure_a {
        assert_eq!(
            curve_a.as_slice(),
            curve_by_figure_b[figure].as_slice(),
            "the grant curve for {figure} outstanding bytes is permutation-invariant"
        );
    }
    let completion_by_figure_a: HashMap<u64, u64> = completions_a
        .iter()
        .map(|(source, round)| (figure_of(traces_a, source.as_str()), *round))
        .collect();
    let completion_by_figure_b: HashMap<u64, u64> = completions_b
        .iter()
        .map(|(source, round)| (figure_of(traces_b, source.as_str()), *round))
        .collect();
    assert_eq!(
        completion_by_figure_a, completion_by_figure_b,
        "completion follows the figure, not the adapter"
    );

    // ---- And the schedule is the hand-computed one. Round one reserves
    // the three live sessions and grants two chunks to the 48 MiB
    // history; the histories drain in four rounds; every figure is
    // granted exactly once; the trace sequence closes with the quiescent
    // pass and then the steady pass, which plans nothing. ----
    let totals = |round: usize| &traces_a[round].totals;
    assert_eq!(
        traces_a.len(),
        6,
        "four spending rounds, the quiescent pass, and the steady pass"
    );
    assert_eq!(totals(0).eligible_sources, 9);
    assert_eq!(totals(0).reserved_sources, 3);
    assert_eq!(totals(0).reserved_chunks, 3);
    assert_eq!(
        totals(0).reserved_bytes,
        3 * ACTIVE_LINES * LINE_BYTES,
        "each live session's outstanding is exactly its growth"
    );
    assert_eq!(totals(0).backfilled_sources, 1);
    assert_eq!(totals(0).backfill_chunks, 2);
    assert_eq!(totals(0).backfill_bytes, 32 * MIB);
    assert_eq!(totals(0).short_reservations, 0);
    assert_eq!(totals(0).deferred_sources, 5);
    assert_eq!(totals(1).backfill_bytes, 32 * MIB);
    assert_eq!(totals(1).deferred_sources, 5);
    assert_eq!(totals(2).backfill_bytes, 32 * MIB);
    assert_eq!(totals(2).backfilled_sources, 2);
    assert_eq!(totals(2).deferred_sources, 3);
    assert_eq!(
        totals(3).backfill_bytes,
        (SM_LINES + XS_LINES + HS_LINES) * LINE_BYTES
    );
    assert_eq!(totals(3).backfilled_sources, 3);
    assert_eq!(totals(3).backfill_chunks, 3);
    assert_eq!(totals(3).deferred_sources, 0);
    let quiescent = totals(4);
    assert_eq!(
        quiescent.eligible_sources, 3,
        "only the live sessions remain"
    );
    assert_eq!(quiescent.backfilled_sources, 0);
    assert_eq!(quiescent.backfill_bytes, 0);
    assert_eq!(quiescent.reserved_sources, 3);
    let steady = totals(5);
    assert_eq!(
        steady.eligible_sources, 0,
        "the caught-up fleet schedules nothing"
    );
    assert_eq!(steady.reserved_sources, 0);
    assert_eq!(steady.backfilled_sources, 0);
    assert_eq!(steady.backfill_bytes, 0);
    assert_eq!(steady.planned_bytes, 0);
    assert_eq!(steady.deferred_sources, 0);

    let last = traces_a.len() - 1;
    let curves = cumulative_backfill(traces_a);
    let histories = ranked_histories(traces_a);
    assert_eq!(
        histories.len(),
        6,
        "six history figures drain in both fleets"
    );
    for (source, initial) in &histories {
        assert_eq!(
            traces_a[last].outstanding[source.as_str()],
            0,
            "{source} drained to zero"
        );
        assert_eq!(
            curves[source.as_str()][last],
            *initial,
            "every measured history byte is granted exactly once"
        );
    }
}
