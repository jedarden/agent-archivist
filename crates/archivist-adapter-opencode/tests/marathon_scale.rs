// SPDX-License-Identifier: Apache-2.0

//! Marathon-scale validation of the `OpenCode` read-only projection capture.
//!
//! The published compatibility matrix (docs/notes/compatibility-matrix.md,
//! the `opencode-sqlite-v1` row) supported this adapter on schema
//! conformance and one small fleet store — a single host, 18 sessions, and
//! the fleet inventory's own finding 7: "sufficient for schema conformance,
//! insufficient for marathon-scale validation". This suite closes that gap
//! with a deterministic synthetic store far past the fleet's shape — 2,048
//! sessions and over 200,000 allowlisted rows across all five allowlisted
//! tables, with planted credential rows in the excluded tables — and runs
//! the production capture path (`StoreConnection::open` → `Snapshot::take`
//! → `Projection::project` → `Projection::jsonl`) over it, asserting:
//!
//! - **correctness at scale** — the projection parities with an
//!   independent direct read of the same store through the SDK's parity
//!   oracle (ordered keys, row counts, presence bits, per-field digests);
//!   per-session row accounting is exact for every session; the excluded
//!   tables' planted credential content never appears in the projected
//!   bytes; the column-level authorizer denies every non-allowlisted read
//!   the capture path could have attempted;
//! - **determinism** — two captures of the unchanged store produce
//!   byte-identical canonical JSONL;
//! - **growth measurability** — appended rows for new sessions (two of
//!   which sort into the middle of the existing key space) surface in a
//!   re-capture with exact per-session counts and full parity, so progress
//!   on a live marathon store stays measurable;
//! - **bounded resources** — the capture completes at a floor throughput
//!   and the whole run's kernel peak RSS (`VmHWM`) stays within a stated
//!   multiple of the store's own size.
//!
//! Like the Phase 4 server resource benchmark, the run is meaningful only
//! at its own scale, so the test is `#[ignore]`d from the ordinary lanes;
//! the throughput floor and memory ceiling below leave wide multiples of
//! headroom over the observed figures so a slower or busier runner
//! re-proves the bounds rather than the exact timings. It is not run by
//! hand, though: the definition of done's slow lane invokes it as the
//! `opencode marathon scale` check, and the compatibility-matrix gate
//! (`tools/check-compatibility-matrix.py`, the marathon-evidence rule)
//! pins the published matrix's marathon figures to these constants — the
//! assertions are a regression gate, not a benchmark someone remembers to
//! run:
//!
//! ```text
//! cargo test -p archivist-adapter-opencode --test marathon_scale \
//!   -- --ignored --nocapture
//! ```
//!
//! The measurement runs in a child process (this binary re-executed with
//! the role environment set) so the peak-RSS high-water mark is the
//! validation's alone, read from `/proc/self/status` `VmHWM` — the same
//! kernel counter the Phase 4 profile measures.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use archivist_adapter_opencode::{
    ALLOWED_TABLES, FieldValue, Json, Projection, Snapshot, StoreConnection,
};
use archivist_adapter_sdk::file_capture::RecordBoundary;
use archivist_adapter_sdk::parity::{
    DatabaseObservation, ObservedValue, RowObservation, TableObservation, compare,
};
use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::types::ValueRef;

// ---------------------------------------------------------------------------
// The scale
// ---------------------------------------------------------------------------

/// The store's session count: 114× the fleet store's 18 sessions, the
/// figure the matrix row's known-gap cell recorded before this validation.
const SESSIONS: usize = 2_048;

/// Messages per session.
const MESSAGES_PER_SESSION: usize = 32;

/// Parts per message.
const PARTS_PER_MESSAGE: usize = 2;

/// Session inputs per session.
const INPUTS_PER_SESSION: usize = 8;

/// Todos per session.
const TODOS_PER_SESSION: usize = 6;

/// Sessions whose first input prompt is a giant multi-megabyte field, so
/// the large-field path stays warm at scale (one per 256 sessions).
const GIANT_PROMPT_SESSIONS: usize = 8;

/// The giant prompt's target byte length.
const GIANT_PROMPT_BYTES: usize = 1024 * 1024;

/// Sessions appended after the first captures: the live-growth case.
const GROWTH_SESSIONS: usize = 16;

/// The fixed base instant every timestamp offsets from: a fixed window,
/// integer arithmetic, no clock (the fixture generator's determinism rule).
const TIME_BASE: i64 = 1_768_000_000;

/// The role environment that turns a re-executed test binary into the
/// measured child.
const CHILD_ROLE_ENV: &str = "ARCHIVIST_OPENCODE_MARATHON_CHILD";

/// The stdout prefix every child measurement line carries.
const LINE_PREFIX: &str = "MARATHON ";

/// The byte marker planted in every excluded-table row: its absence from
/// the projection is the allowlist negative at scale.
const PLANTED_MARKER: &[u8] = b"planted-";

/// The memory ceiling as a multiple of the store's own size: the capture
/// path materializes the snapshot, the projection, and the canonical byte
/// stream, so the peak is a small multiple of the store — and the bound
/// asserts it stays one. The observed run sits near 6.5× (the two
/// byte-compared streams of the determinism pass dominate); the bound
/// leaves the wide margin a slower runner re-proves the shape, not the
/// exact figure.
const MAX_PEAK_RSS_STORE_MULTIPLE: u64 = 10;

/// An absolute memory ceiling, in MiB, so a pathological store-size
/// relationship cannot hide behind the multiple.
const MAX_PEAK_RSS_ABSOLUTE_MIB: u64 = 3_000;

/// The capture throughput floor, in MiB of store per second (snapshot,
/// projection, and canonical stream together): orders of magnitude under
/// the observed figure, so the bound catches an order-class regression,
/// never runner noise.
const MIN_CAPTURE_MIB_PER_S: f64 = 5.0;

/// The session id for slot `i`.
fn session_id(i: usize) -> String {
    format!("s-{i:06}")
}

/// The expected allowlisted row count of the seeded store.
fn expected_rows() -> u64 {
    let per_session = MESSAGES_PER_SESSION
        + MESSAGES_PER_SESSION * PARTS_PER_MESSAGE
        + INPUTS_PER_SESSION
        + TODOS_PER_SESSION;
    u64::try_from(SESSIONS * (1 + per_session)).expect("the row count fits u64")
}

/// The expected allowlisted row count after the growth append.
fn expected_rows_after_growth() -> u64 {
    let per_session = MESSAGES_PER_SESSION
        + MESSAGES_PER_SESSION * PARTS_PER_MESSAGE
        + INPUTS_PER_SESSION
        + TODOS_PER_SESSION;
    expected_rows()
        + u64::try_from(GROWTH_SESSIONS * (1 + per_session)).expect("the row count fits u64")
}

/// The closed content vocabulary: the fixture generator's own ethos —
/// nature words only, no path, host, account, or credential shape.
const WORDS: [&str; 16] = [
    "meadow", "river", "cedar", "harbor", "ember", "summit", "orchard", "canyon", "willow",
    "falcon", "glade", "tundra", "prairie", "basin", "reef", "sigma",
];

/// Deterministic payload text of about `target` bytes: vocabulary words
/// joined with spaces, every eighth payload ending in a fixed non-ASCII
/// tail so the UTF-8 path stays warm at scale.
fn payload(seed: u64, target: usize) -> String {
    let mut out = String::with_capacity(target + 8);
    while out.len() < target {
        let word = WORDS[usize::try_from((seed >> (out.len() % 13)) % WORDS.len() as u64)
            .expect("the word index fits usize")];
        if out.len() + word.len() + 1 > target {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if seed.is_multiple_of(8) && out.len() + 5 <= target {
        out.push_str(" \u{03c3}\u{1d11e}");
    }
    out
}

/// The per-row content seed: integer arithmetic only, no RNG.
fn seed(i: usize, k: usize) -> u64 {
    (u64::try_from(i).expect("fits u64") * 7_919)
        .wrapping_add(u64::try_from(k).expect("fits u64") * 104_729)
        .wrapping_add(1)
}

// ---------------------------------------------------------------------------
// Scratch directory
// ---------------------------------------------------------------------------

/// A unique scratch directory, removed when the run ends either way.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let unique = format!(
            "archivist-opencode-marathon-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("the clock is after the epoch")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
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
// The store generator
// ---------------------------------------------------------------------------

/// The five allowlisted tables with exactly the embedded allowlist's
/// columns, plus the excluded tables the real store legitimately holds.
const STORE_DDL: &str = r"
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
        refresh_token TEXT, token_expiry INTEGER, time_created INTEGER, time_updated INTEGER
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
";

/// Generate the marathon store at `path` and return its size in bytes.
///
/// Every row is arithmetic from its own index — no clock, no RNG, no
/// environment — so two runs produce byte-for-byte comparable content.
/// Every session carries the one admitted application version, and the
/// excluded tables carry planted credential rows the projection must never
/// surface.
fn generate_store(path: &Path) -> u64 {
    let writer = Connection::open(path).expect("the store is creatable");
    writer
        .execute_batch(STORE_DDL)
        .expect("the store schema applies");
    writer
        .execute("BEGIN", [])
        .expect("the seed transaction opens");

    seed_sessions(&writer);
    seed_messages(&writer);
    seed_parts(&writer);
    seed_inputs(&writer);
    seed_todos(&writer);
    seed_excluded(&writer);

    writer
        .execute("COMMIT", [])
        .expect("the seed transaction commits");
    drop(writer);
    let bytes = fs::metadata(path).expect("the generated store stats").len();
    assert!(
        bytes > 64 * 1024 * 1024,
        "the generated store holds marathon-scale content ({bytes} bytes)"
    );
    bytes
}

/// Seed the session rows: every one carrying the admitted version, with
/// deterministic NULL patterns across the optional columns and the two
/// boundary integers the projection must carry exactly.
fn seed_sessions(writer: &Connection) {
    let mut insert = writer
        .prepare(
            "INSERT INTO session (id, project_id, workspace_id, parent_id, slug, directory,
                path, title, version, share_url, summary_additions, summary_deletions,
                summary_files, summary_diffs, metadata, cost, tokens_input, tokens_output,
                tokens_reasoning, tokens_cache_read, tokens_cache_write, revert, permission,
                agent, model, time_created, time_updated, time_compacting, time_archived)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .expect("the session insert prepares");
    for i in 0..SESSIONS {
        let id = session_id(i);
        let boundary = |at: usize| i64::try_from(i.saturating_sub(at)).expect("the integer fits");
        insert
            .execute(rusqlite::params![
                id,
                format!("project-{}", WORDS[i % WORDS.len()]),
                if i % 2 == 0 {
                    None
                } else {
                    Some(format!("ws-{}", i % 8))
                },
                if i % 64 == 0 { Some("s-000000") } else { None },
                format!("slug-{i:06}"),
                format!("dir-{}-{:02}", WORDS[(i / 3) % WORDS.len()], i % 97),
                format!("dir-{}-{:02}", WORDS[(i / 3) % WORDS.len()], i % 97),
                format!(
                    "{} {}",
                    WORDS[i % WORDS.len()],
                    WORDS[(i * 7) % WORDS.len()]
                ),
                "1.18.29",
                if i % 3 == 0 {
                    None
                } else {
                    Some(format!("share-{i:06}"))
                },
                if i == 0 { i64::MIN } else { boundary(0) * 3 },
                if i == 1 { i64::MAX } else { boundary(1) * 5 },
                boundary(2) * 7,
                boundary(3) * 11,
                if i % 4 == 0 {
                    None
                } else {
                    Some(format!(
                        "{{\"notes\":\"{}\"}}",
                        WORDS[(i * 5) % WORDS.len()]
                    ))
                },
                if i % 5 == 0 {
                    None
                } else {
                    Some(
                        f64::from(u32::try_from(i).expect("the session index fits u32")) * 0.25
                            - 64.0,
                    )
                },
                if i == 2 { i64::MAX } else { boundary(4) * 137 },
                boundary(5) * 29,
                boundary(6) * 11,
                if i % 9 == 0 {
                    None
                } else {
                    Some(boundary(7) * 53)
                },
                boundary(8) * 17,
                if i % 6 == 0 {
                    None
                } else {
                    Some(format!("revert-{:02}", i % 100))
                },
                if i % 7 == 0 { None } else { Some("allow") },
                if i % 10 == 0 {
                    None
                } else {
                    Some(format!("agent-{}", WORDS[i % WORDS.len()]))
                },
                format!("model-{}", WORDS[(i * 3) % WORDS.len()]),
                TIME_BASE + i64::try_from(i * 60).expect("the timestamp fits"),
                TIME_BASE + i64::try_from(i * 60).expect("the timestamp fits") + 30,
                if i % 8 == 0 {
                    Some(TIME_BASE + i64::try_from(i * 60).expect("the timestamp fits") + 45)
                } else {
                    None
                },
                if i % 16 == 0 {
                    Some(TIME_BASE + i64::try_from(i * 60).expect("the timestamp fits") + 50)
                } else {
                    None
                },
            ])
            .expect("the session row inserts");
    }
}

/// Seed the message rows: `MESSAGES_PER_SESSION` per session, zero-padded
/// ids so lexicographic order matches generation order, with sparse NULLs
/// in `time_updated` and `data` for presence-bit coverage at scale.
fn seed_messages(writer: &Connection) {
    let mut insert = writer
        .prepare(
            "INSERT INTO message (id, session_id, time_created, time_updated, data)
                  VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .expect("the message insert prepares");
    for i in 0..SESSIONS {
        for k in 0..MESSAGES_PER_SESSION {
            let row_seed = seed(i, k);
            insert
                .execute(rusqlite::params![
                    format!("m-{i:06}-{k:04}"),
                    session_id(i),
                    TIME_BASE + i64::try_from(k * 5).expect("the timestamp fits"),
                    if k % 4 == 0 {
                        None
                    } else {
                        Some(TIME_BASE + i64::try_from(k * 5).expect("fits") + 2)
                    },
                    if (i * MESSAGES_PER_SESSION + k).is_multiple_of(97) {
                        None
                    } else {
                        Some(payload(
                            row_seed,
                            1024 + usize::try_from(row_seed % 512).expect("fits"),
                        ))
                    },
                ])
                .expect("the message row inserts");
        }
    }
}

/// Seed the part rows: `PARTS_PER_MESSAGE` per message.
fn seed_parts(writer: &Connection) {
    let mut insert = writer
        .prepare(
            "INSERT INTO part (id, message_id, session_id, time_created, time_updated, data)
                  VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .expect("the part insert prepares");
    for i in 0..SESSIONS {
        for k in 0..MESSAGES_PER_SESSION {
            for j in 0..PARTS_PER_MESSAGE {
                let row_seed = seed(i, k * PARTS_PER_MESSAGE + j);
                insert
                    .execute(rusqlite::params![
                        format!("p-{i:06}-{k:04}-{j}"),
                        format!("m-{i:06}-{k:04}"),
                        session_id(i),
                        TIME_BASE + i64::try_from(k * 5 + j).expect("the timestamp fits"),
                        if (k + j) % 3 == 0 {
                            None
                        } else {
                            Some(TIME_BASE + i64::try_from(k * 5 + j).expect("fits") + 1)
                        },
                        if (k * 2 + j) % 89 == 0 {
                            None
                        } else {
                            Some(payload(
                                row_seed,
                                384 + usize::try_from(row_seed % 256).expect("fits"),
                            ))
                        },
                    ])
                    .expect("the part row inserts");
            }
        }
    }
}

/// Seed the session-input rows, including the giant multi-megabyte
/// prompts one session in every 256 carries.
fn seed_inputs(writer: &Connection) {
    let mut insert = writer
        .prepare(
            "INSERT INTO session_input (id, session_id, prompt, delivery, admitted_seq,
                  promoted_seq, time_created) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .expect("the input insert prepares");
    for i in 0..SESSIONS {
        for n in 0..INPUTS_PER_SESSION {
            let row_seed = seed(i, 1_000 + n);
            let giant = i % (SESSIONS / GIANT_PROMPT_SESSIONS) == 0 && n == 0;
            let prompt = if n % 11 == 0 {
                None
            } else if giant {
                Some(payload(row_seed, GIANT_PROMPT_BYTES))
            } else {
                Some(payload(
                    row_seed,
                    256 + usize::try_from(row_seed % 256).expect("fits"),
                ))
            };
            insert
                .execute(rusqlite::params![
                    format!("i-{i:06}-{n:02}"),
                    session_id(i),
                    prompt,
                    if n % 7 == 0 {
                        None
                    } else if n % 2 == 0 {
                        Some("tty")
                    } else {
                        Some("api")
                    },
                    i64::try_from(n * 3).expect("the sequence fits"),
                    if n % 3 == 0 {
                        None
                    } else {
                        i64::try_from(n).ok()
                    },
                    TIME_BASE + i64::try_from(n * 60).expect("the timestamp fits"),
                ])
                .expect("the input row inserts");
        }
    }
}

/// Seed the todo rows: `TODOS_PER_SESSION` per session, every tuple
/// distinct because `todo`'s projection key is its full column tuple.
fn seed_todos(writer: &Connection) {
    let mut insert = writer
        .prepare(
            "INSERT INTO todo (session_id, content, status, priority, position,
                  time_created, time_updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .expect("the todo insert prepares");
    for i in 0..SESSIONS {
        for p in 0..TODOS_PER_SESSION {
            let row_seed = seed(i, 2_000 + p);
            insert
                .execute(rusqlite::params![
                    session_id(i),
                    payload(row_seed, 48 + p * 8),
                    if p % 2 == 0 { "open" } else { "done" },
                    if p % 5 == 0 { None } else { Some("p2") },
                    i64::try_from(p).expect("the position fits"),
                    TIME_BASE + i64::try_from(p).expect("the timestamp fits"),
                    if p % 2 == 0 {
                        None
                    } else {
                        Some(TIME_BASE + i64::try_from(p).expect("fits") + 1)
                    },
                ])
                .expect("the todo row inserts");
        }
    }
}

/// Seed the excluded tables with planted credential rows: content the
/// projection must never surface, counted in the marker scan.
fn seed_excluded(writer: &Connection) {
    let mut account = writer
        .prepare(
            "INSERT INTO account (id, email, url, access_token, refresh_token,
                  token_expiry, time_created, time_updated)
                  VALUES (?1, NULL, NULL, ?2, ?3, NULL, ?4, ?4)",
        )
        .expect("the account insert prepares");
    for n in 0..64_usize {
        account
            .execute(rusqlite::params![
                format!("acct-{n:03}"),
                format!("planted-credential-token-{n}"),
                format!("planted-refresh-{n}"),
                TIME_BASE,
            ])
            .expect("the account row inserts");
    }
    let mut credential = writer
        .prepare(
            "INSERT INTO credential (id, integration_id, label, value, connector_id,
                  method_id, active, time_created, time_updated)
                  VALUES (?1, NULL, ?2, ?3, NULL, NULL, 1, ?4, ?4)",
        )
        .expect("the credential insert prepares");
    for n in 0..128_usize {
        credential
            .execute(rusqlite::params![
                format!("cred-{n:03}"),
                format!("label-{n:03}"),
                format!("planted-credential-value-{n}"),
                TIME_BASE,
            ])
            .expect("the credential row inserts");
    }
    let mut provider = writer
        .prepare(
            "INSERT INTO provider_auth (id, provider_id, user_id, api_key,
                  time_created, time_updated) VALUES (?1, ?2, NULL, ?3, ?4, ?4)",
        )
        .expect("the provider insert prepares");
    for n in 0..64_usize {
        provider
            .execute(rusqlite::params![
                format!("pa-{n:03}"),
                format!("provider-{}", WORDS[n % WORDS.len()]),
                format!("planted-provider-key-{n}"),
                TIME_BASE,
            ])
            .expect("the provider row inserts");
    }
    let mut cache = writer
        .prepare("INSERT INTO cache (key, payload, time_created) VALUES (?1, ?2, ?3)")
        .expect("the cache insert prepares");
    for n in 0..256_usize {
        cache
            .execute(rusqlite::params![
                format!("k-{n:04}"),
                format!("planted-cache-{n} {}", WORDS[n % WORDS.len()]),
                TIME_BASE,
            ])
            .expect("the cache row inserts");
    }
}

/// Append the growth sessions: `GROWTH_SESSIONS` new sessions with their
/// full row families, two of them under ids that sort into the middle of
/// the existing key space so the re-capture must place them, not just
/// extend the tail.
fn append_growth(path: &Path) {
    let writer = Connection::open(path).expect("the store opens for growth");
    writer
        .execute("BEGIN", [])
        .expect("the growth transaction opens");

    // Sessions 2048..2063 sort after every seeded session; these two sort
    // between seeded neighbours ("s-000256x" sits between "s-000256" and
    // "s-000257").
    let growth_ids: Vec<String> = (0..GROWTH_SESSIONS - 2)
        .map(|g| session_id(SESSIONS + g))
        .chain(["s-000256x".to_owned(), "s-001024x".to_owned()])
        .collect();

    let mut session = writer
        .prepare(
            "INSERT INTO session (id, project_id, slug, title, version, cost, tokens_input)
             VALUES (?1, 'project-growth', ?2, ?3, '1.18.29', ?4, ?5)",
        )
        .expect("the growth session insert prepares");
    for (g, id) in growth_ids.iter().enumerate() {
        session
            .execute(rusqlite::params![
                id,
                format!("slug-growth-{g:03}"),
                format!("growth {}", WORDS[g % WORDS.len()]),
                f64::from(u8::try_from(g).expect("the growth index fits u8")) * 1.5,
                i64::try_from(g * 91).expect("the token count fits"),
            ])
            .expect("the growth session inserts");
    }
    let mut message = writer
        .prepare(
            "INSERT INTO message (id, session_id, time_created, data)
                  VALUES (?1, ?2, ?3, ?4)",
        )
        .expect("the growth message insert prepares");
    let mut part = writer
        .prepare(
            "INSERT INTO part (id, message_id, session_id, time_created, data)
                  VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .expect("the growth part insert prepares");
    let mut input = writer
        .prepare(
            "INSERT INTO session_input (id, session_id, prompt, delivery, admitted_seq)
                  VALUES (?1, ?2, ?3, 'tty', ?4)",
        )
        .expect("the growth input insert prepares");
    let mut todo = writer
        .prepare(
            "INSERT INTO todo (session_id, content, status, priority, position)
                  VALUES (?1, ?2, 'open', 'p1', ?3)",
        )
        .expect("the growth todo insert prepares");
    for (g, id) in growth_ids.iter().enumerate() {
        for k in 0..MESSAGES_PER_SESSION {
            let message_id = format!("m-g{g:03}-{k:04}");
            message
                .execute(rusqlite::params![
                    message_id,
                    id,
                    TIME_BASE + 1_000 + i64::try_from(k * 5).expect("fits"),
                    payload(seed(SESSIONS + g, k), 512),
                ])
                .expect("the growth message inserts");
            for j in 0..PARTS_PER_MESSAGE {
                part.execute(rusqlite::params![
                    format!("{message_id}-p{j}"),
                    message_id,
                    id,
                    TIME_BASE + 1_000 + i64::try_from(k * 5 + j).expect("fits"),
                    payload(seed(SESSIONS + g, 100 + k * 2 + j), 256),
                ])
                .expect("the growth part inserts");
            }
        }
        for n in 0..INPUTS_PER_SESSION {
            input
                .execute(rusqlite::params![
                    format!("i-g{g:03}-{n:02}"),
                    id,
                    payload(seed(SESSIONS + g, 1_000 + n), 128),
                    i64::try_from(n).expect("fits"),
                ])
                .expect("the growth input inserts");
        }
        for p in 0..TODOS_PER_SESSION {
            todo.execute(rusqlite::params![
                id,
                payload(seed(SESSIONS + g, 2_000 + p), 64),
                i64::try_from(p).expect("fits"),
            ])
            .expect("the growth todo inserts");
        }
    }
    writer
        .execute("COMMIT", [])
        .expect("the growth transaction commits");
}

// ---------------------------------------------------------------------------
// Independent observation and verification
// ---------------------------------------------------------------------------

/// The allowlist positions of a table's key columns: the `id` column when
/// the table has one, every column otherwise (`todo`, whose full tuple is
/// its identity).
fn key_positions(table: &str) -> Vec<usize> {
    let (_, columns) = ALLOWED_TABLES
        .iter()
        .find(|(name, _)| *name == table)
        .unwrap_or_else(|| panic!("{table} is an allowlisted table"));
    match columns.iter().position(|name| *name == "id") {
        Some(at) => vec![at],
        None => (0..columns.len()).collect(),
    }
}

/// The direct observation of one stored value — the same storage-class
/// mapping the snapshot applies, reached without a single adapter type.
fn observed_value(value: ValueRef<'_>) -> ObservedValue {
    match value {
        ValueRef::Null => ObservedValue::Null,
        ValueRef::Integer(value) => ObservedValue::Integer(value),
        ValueRef::Real(value) => ObservedValue::Real(value),
        ValueRef::Text(bytes) => ObservedValue::Text(bytes.to_vec()),
        ValueRef::Blob(bytes) => ObservedValue::Blob(bytes.to_vec()),
    }
}

/// The source-side observation: this suite's own queries on their own
/// read-only connection, one per allowlisted table, rows in the same
/// deterministic collation the snapshot orders by — independent of the
/// adapter's snapshot, projection, and types.
fn source_observation(path: &Path) -> DatabaseObservation {
    let reader = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("the store opens read-only for the independent read");
    let mut tables = Vec::with_capacity(ALLOWED_TABLES.len());
    for (table, columns) in ALLOWED_TABLES {
        let mut select = String::from("SELECT ");
        for (index, column) in columns.iter().enumerate() {
            if index > 0 {
                select.push_str(", ");
            }
            select.push('"');
            select.push_str(column);
            select.push('"');
        }
        select.push_str(" FROM \"");
        select.push_str(table);
        select.push_str("\" ORDER BY ");
        for (index, column) in columns.iter().enumerate() {
            if index > 0 {
                select.push_str(", ");
            }
            select.push('"');
            select.push_str(column);
            select.push_str("\" COLLATE BINARY");
        }
        let mut statement = reader.prepare(&select).expect("the direct scan prepares");
        let mut scanned = statement.query([]).expect("the direct scan runs");
        let mut rows = Vec::new();
        while let Some(row) = scanned.next().expect("the direct scan row reads") {
            let values: Vec<ObservedValue> = (0..columns.len())
                .map(|index| {
                    observed_value(row.get_ref(index).expect("the direct column is served"))
                })
                .collect();
            let positions = key_positions(table);
            let key: Vec<ObservedValue> = positions.iter().map(|at| values[*at].clone()).collect();
            rows.push(RowObservation::observe(key, values));
        }
        tables.push(TableObservation::new(rows));
    }
    DatabaseObservation::new(tables)
}

/// The projection-side observation from the adapter's projected rows:
/// key and every allowlisted field in allowlist order.
fn projection_observation(projection: &Projection) -> DatabaseObservation {
    let mut tables = Vec::with_capacity(ALLOWED_TABLES.len());
    for (table, _) in ALLOWED_TABLES {
        let mut rows = Vec::new();
        for projected in projection.rows().iter().filter(|row| row.table() == *table) {
            let fields: Vec<ObservedValue> = projected
                .fields()
                .iter()
                .map(|(_, value)| match value {
                    FieldValue::Null => ObservedValue::Null,
                    FieldValue::Integer(value) => ObservedValue::Integer(*value),
                    FieldValue::Real(value) => ObservedValue::Real(*value),
                    FieldValue::Text(text) => ObservedValue::Text(text.as_bytes().to_vec()),
                })
                .collect();
            let key: Vec<ObservedValue> = projected
                .key()
                .iter()
                .map(|value| match value {
                    Json::Null => ObservedValue::Null,
                    Json::Integer(value) => ObservedValue::Integer(*value),
                    Json::Real(value) => ObservedValue::Real(*value),
                    Json::Text(text) => ObservedValue::Text(text.as_bytes().to_vec()),
                    other => panic!("a projected key is scalar, not {other:?}"),
                })
                .collect();
            rows.push(RowObservation::observe(key, fields));
        }
        tables.push(TableObservation::new(rows));
    }
    DatabaseObservation::new(tables)
}

/// Whether `haystack` contains `needle`: a first-byte-filtered scan that
/// stays linear over the multi-hundred-megabyte projection stream.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    let first = needle[0];
    haystack.iter().enumerate().any(|(at, byte)| {
        *byte == first
            && haystack
                .get(at..)
                .is_some_and(|rest| rest.starts_with(needle))
    })
}

/// The direct per-session row counts one allowlisted child table holds,
/// from this suite's own connection.
fn direct_session_counts(path: &Path, table: &str) -> HashMap<String, u64> {
    let reader = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("the store opens read-only for the count pass");
    let sql = format!("SELECT session_id, count(*) FROM \"{table}\" GROUP BY session_id");
    let mut statement = reader.prepare(&sql).expect("the count query prepares");
    let scanned = statement
        .query_map([], |row| {
            let session: String = row.get(0).expect("the session id reads");
            let count: i64 = row.get(1).expect("the count reads");
            Ok((
                session,
                u64::try_from(count).expect("the count is non-negative"),
            ))
        })
        .expect("the count query runs");
    scanned
        .map(|row| row.expect("the count row reads"))
        .collect()
}

/// The per-session row counts the projection itself carries for one
/// allowlisted child table, keyed by the session-id field's position.
fn projected_session_counts(
    projection: &Projection,
    table: &str,
    session_at: usize,
) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for row in projection.rows().iter().filter(|row| row.table() == table) {
        match &row.fields()[session_at].1 {
            FieldValue::Text(session) => {
                *counts.entry(session.clone()).or_insert(0) += 1;
            }
            other => panic!("a {table} session_id projects as text, not {other:?}"),
        }
    }
    counts
}

/// Assert the per-session accounting of one child table is exact: the
/// projection carries, for every session, exactly the row count a direct
/// read of the store counts.
fn assert_per_session_exact(path: &Path, projection: &Projection) {
    for (table, session_at) in [
        ("message", 1_usize),
        ("part", 2),
        ("session_input", 1),
        ("todo", 0),
    ] {
        let direct = direct_session_counts(path, table);
        let projected = projected_session_counts(projection, table, session_at);
        assert_eq!(
            direct.len(),
            projected.len(),
            "{table}: the projection covers every session exactly once"
        );
        for (session, count) in &direct {
            assert_eq!(
                projected.get(session),
                Some(count),
                "{table}: session {session} projects its exact row count"
            );
        }
    }
}

/// Install the column-level authorizer on the capture connection: reads
/// of exactly the allowlisted (table, column) pairs and the schema index
/// pass; every other read is denied at the driver. The capture completing
/// under the binding is the scale-scale proof the read path never widened.
fn install_allowlist_authorizer(store: &StoreConnection) {
    store
        .connection()
        .authorizer(Some(|context: AuthContext<'_>| {
            if let AuthAction::Read {
                table_name,
                column_name,
            } = context.action
            {
                let allowlisted = table_name == "sqlite_master"
                    || ALLOWED_TABLES.iter().any(|(table, columns)| {
                        *table == table_name && columns.contains(&column_name)
                    });
                if !allowlisted {
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        }))
        .expect("the authorizer installs");
}

/// Open, snapshot, and project the store at `path` — the production
/// capture path, nothing else.
fn capture(path: &Path) -> (Projection, Vec<u8>) {
    let store = StoreConnection::open(path).expect("the store opens read-only");
    let snapshot = Snapshot::take(&store).expect("the supported store snapshots");
    drop(store);
    let projection = Projection::project(&snapshot).expect("the store projects");
    drop(snapshot);
    let jsonl = projection.jsonl();
    (projection, jsonl)
}

/// The table names the projection emitted, de-duplicated in emit order.
fn projected_tables(projection: &Projection) -> Vec<&'static str> {
    let mut seen = Vec::new();
    for row in projection.rows() {
        if !seen.contains(&row.table()) {
            seen.push(row.table());
        }
    }
    seen
}

/// The whole validation, measured: generate, capture, and verify, then
/// print one `MARATHON ` line per figure. Runs as the re-executed child
/// so the process peak-RSS high-water mark is this run's alone.
#[allow(clippy::too_many_lines)] // one deterministic validation, read top to bottom
#[allow(clippy::cast_precision_loss)] // the throughput figure loses only noise bits
fn child_role(scratch: &Path) {
    let path = scratch.join("opencode.db");
    let store_bytes = generate_store(&path);
    println!("{LINE_PREFIX}store_bytes={store_bytes}");
    println!("{LINE_PREFIX}rows={}", expected_rows());

    // ---- Capture #1, under the column-level authorizer: the honest
    // capture path completes touching only allowlisted pairs. ----
    let start = Instant::now();
    let store = StoreConnection::open(&path).expect("the store opens read-only");
    install_allowlist_authorizer(&store);
    let snapshot = Snapshot::take(&store).expect("the supported store snapshots");
    drop(store);
    let projection = Projection::project(&snapshot).expect("the store projects");
    drop(snapshot);
    let capture_elapsed = start.elapsed();
    let jsonl_start = Instant::now();
    let jsonl = projection.jsonl();
    let jsonl_elapsed = jsonl_start.elapsed();
    let total_elapsed = capture_elapsed + jsonl_elapsed;

    let boundary = RecordBoundary::select(&jsonl);
    assert_eq!(
        u64::try_from(jsonl.len()).expect("the stream length fits u64"),
        boundary.complete_bytes,
        "every projected record is newline-terminated"
    );
    assert_eq!(boundary.incomplete_tail_bytes, 0, "no incomplete tail");
    assert_eq!(
        boundary.complete_records,
        expected_rows(),
        "one projected record per allowlisted row"
    );
    println!("{LINE_PREFIX}boundary_events={}", boundary.complete_records);
    println!("{LINE_PREFIX}boundary_bytes={}", boundary.complete_bytes);
    println!(
        "{LINE_PREFIX}jsonl_bytes={}",
        u64::try_from(jsonl.len()).expect("the stream length fits u64")
    );

    // ---- The allowlist negative at scale: no planted excluded-table
    // byte reaches the projection stream, and the record set is exactly
    // the five allowlisted tables. ----
    assert!(
        !contains(&jsonl, PLANTED_MARKER),
        "planted excluded-table content reached the projection"
    );
    let tables = projected_tables(&projection);
    assert_eq!(
        tables,
        ["session", "message", "part", "session_input", "todo"],
        "the projection emits exactly the five allowlisted tables"
    );
    println!("{LINE_PREFIX}excluded_content=absent");
    println!("{LINE_PREFIX}tables={}", tables.len());

    // ---- Parity at scale, against an independent direct read. ----
    let verdict = compare(
        &source_observation(&path),
        &projection_observation(&projection),
    );
    assert!(
        verdict.is_equal(),
        "the marathon projection parities with the independent read: {verdict:?}"
    );
    println!("{LINE_PREFIX}parity=equal");

    // ---- Per-session progress accounting: every session's rows project
    // exactly, so progress is attributable per session at scale. ----
    assert_per_session_exact(&path, &projection);
    println!("{LINE_PREFIX}per_session=exact");

    // ---- Determinism: a second capture of the unchanged store is
    // byte-identical canonical JSONL. ----
    let (_, jsonl_again) = capture(&path);
    assert_eq!(
        jsonl, jsonl_again,
        "two captures of the unchanged store are byte-identical"
    );
    drop(jsonl_again);
    println!("{LINE_PREFIX}determinism=byte-identical");
    drop(jsonl);
    drop(projection);

    // ---- Growth: appended rows for new sessions — two of which sort
    // into the middle of the seeded key space — surface in a re-capture
    // with exact counts and full parity. ----
    append_growth(&path);
    let (projection_after, jsonl_after) = capture(&path);
    let boundary_after = RecordBoundary::select(&jsonl_after);
    assert_eq!(
        boundary_after.complete_records,
        expected_rows_after_growth(),
        "the re-capture projects every seeded and appended row"
    );
    assert!(
        !contains(&jsonl_after, PLANTED_MARKER),
        "the appended rows surface no excluded-table content either"
    );
    let after_verdict = compare(
        &source_observation(&path),
        &projection_observation(&projection_after),
    );
    assert!(
        after_verdict.is_equal(),
        "the growth re-capture parities with the independent read: {after_verdict:?}"
    );
    assert_per_session_exact(&path, &projection_after);
    println!(
        "{LINE_PREFIX}rows_after={}",
        boundary_after.complete_records
    );
    println!("{LINE_PREFIX}growth=ok");

    // ---- The bounds, kernel-measured over the whole run. ----
    let mib_per_s = store_bytes as f64 / 1024.0 / 1024.0 / total_elapsed.as_secs_f64().max(0.001);
    println!("{LINE_PREFIX}capture_ms={}", capture_elapsed.as_millis());
    println!("{LINE_PREFIX}jsonl_ms={}", jsonl_elapsed.as_millis());
    println!("{LINE_PREFIX}total_ms={}", total_elapsed.as_millis());
    println!("{LINE_PREFIX}peak_rss_kib={}", peak_rss_kib());
    println!("{LINE_PREFIX}mib_per_s={mib_per_s:.1}");
}

/// The kernel-maintained peak resident set of this process, in KiB — the
/// same `/proc/self/status` `VmHWM` the Phase 4 profile measures.
fn peak_rss_kib() -> u64 {
    let status = fs::read_to_string("/proc/self/status").expect("status reads");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .expect("VmHWM carries a KiB count");
        }
    }
    panic!("VmHWM is a /proc/self/status field on Linux");
}

/// Parse the child's `MARATHON ` measurement lines into a map.
fn parse_lines(stdout: &str) -> HashMap<String, String> {
    let mut parsed = HashMap::new();
    for line in stdout.lines().filter(|line| line.starts_with(LINE_PREFIX)) {
        let entry = line.trim_start_matches(LINE_PREFIX);
        if let Some((key, value)) = entry.split_once('=') {
            parsed.insert(key.to_owned(), value.to_owned());
        }
    }
    parsed
}

/// Require one measurement line, parsed as `u64`.
fn require_u64(figures: &HashMap<String, String>, key: &str) -> u64 {
    figures
        .get(key)
        .unwrap_or_else(|| panic!("the child reported {key}"))
        .parse::<u64>()
        .unwrap_or_else(|_| panic!("the child's {key} is an integer"))
}

/// Require one measurement line, parsed as `f64`.
fn require_f64(figures: &HashMap<String, String>, key: &str) -> f64 {
    figures
        .get(key)
        .unwrap_or_else(|| panic!("the child reported {key}"))
        .parse::<f64>()
        .unwrap_or_else(|_| panic!("the child's {key} is a number"))
}

/// The parent role: run the measured child, then hold every figure to its
/// bound and every correctness claim to its token.
fn parent_role() {
    let exe = std::env::current_exe().expect("the test binary is locatable");
    let output = Command::new(exe)
        .args([
            "--ignored",
            "--exact",
            "marathon_store_projects_correctly_within_bounds",
            // The child's measurement lines reach this parent's pipe only
            // uncaptured: its own harness would otherwise hold them.
            "--nocapture",
        ])
        .env(CHILD_ROLE_ENV, "1")
        .output()
        .expect("the measured child spawns");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "the measured child failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let figures = parse_lines(&stdout);
    assert!(
        !figures.is_empty(),
        "the child reported no measurements:\n{stdout}"
    );
    for (key, value) in &figures {
        println!("{LINE_PREFIX}{key}={value}");
    }

    // Correctness tokens from the measured run.
    for (key, expected) in [
        ("parity", "equal"),
        ("per_session", "exact"),
        ("determinism", "byte-identical"),
        ("growth", "ok"),
        ("excluded_content", "absent"),
    ] {
        assert_eq!(
            figures.get(key).map(String::as_str),
            Some(expected),
            "the child must report {key}={expected}"
        );
    }

    // The measured figures against their bounds.
    let store_bytes = require_u64(&figures, "store_bytes");
    assert_eq!(
        require_u64(&figures, "rows"),
        expected_rows(),
        "the seeded store holds exactly the expected allowlisted rows"
    );
    assert_eq!(
        require_u64(&figures, "rows_after"),
        expected_rows_after_growth(),
        "the grown store holds exactly the expected allowlisted rows"
    );
    assert_eq!(
        require_u64(&figures, "boundary_events"),
        expected_rows(),
        "one measured record per projected row"
    );
    assert_eq!(
        require_u64(&figures, "boundary_bytes"),
        require_u64(&figures, "jsonl_bytes"),
        "the measured boundary is the whole newline-terminated stream"
    );
    let peak_rss_kib = require_u64(&figures, "peak_rss_kib");
    let peak_rss_bytes = peak_rss_kib.saturating_mul(1024);
    assert!(
        peak_rss_bytes <= store_bytes.saturating_mul(MAX_PEAK_RSS_STORE_MULTIPLE),
        "peak RSS {peak_rss_bytes} bytes stays within {MAX_PEAK_RSS_STORE_MULTIPLE}x the \
         store's own {store_bytes} bytes"
    );
    assert!(
        peak_rss_kib / 1024 <= MAX_PEAK_RSS_ABSOLUTE_MIB,
        "peak RSS stays under the absolute {MAX_PEAK_RSS_ABSOLUTE_MIB} MiB ceiling"
    );
    let mib_per_s = require_f64(&figures, "mib_per_s");
    assert!(
        mib_per_s >= MIN_CAPTURE_MIB_PER_S,
        "capture throughput {mib_per_s} MiB/s stays at or above the \
         {MIN_CAPTURE_MIB_PER_S} MiB/s floor"
    );
}

#[test]
#[ignore = "the marathon-scale validation; the module docs carry the invocation"]
fn marathon_store_projects_correctly_within_bounds() {
    if std::env::var(CHILD_ROLE_ENV).is_ok() {
        let scratch = Scratch::new("child");
        child_role(scratch.path());
        return;
    }
    parent_role();
}
