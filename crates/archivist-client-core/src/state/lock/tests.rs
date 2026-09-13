// SPDX-License-Identifier: Apache-2.0

//! Tests for single-mutator ownership: the advisory lock's contention and
//! release behavior, the CFG-023 permission refusals, the registered
//! exit-75 surface, and the rule that a read-only snapshot stays available
//! while the daemon owns the directory.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use archivist_protocol::json;
use archivist_protocol::vocabulary::RequestId;

use super::{
    LOCK_FILE_NAME, LOCK_HELD_EXIT_CODE, LOCK_HELD_MESSAGE, StateDirLock, StateErrorKind,
    lock_held_body_bytes,
};
use crate::state::{LATEST_SCHEMA_VERSION, StateSnapshot, StateStore};

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

/// A private directory (mode 0700, the state-directory posture) removed on
/// drop, so lock tests never share state and never leave debris behind.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("archivist-lock-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("pin temp dir mode");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn mode_of(path: &Path) -> u32 {
    path.metadata().expect("metadata").permissions().mode() & 0o777
}

// --- Contention and release -------------------------------------------------

#[test]
fn a_second_mutator_is_refused_immediately() {
    let dir = TempDir::new("contended");
    let owner = StateDirLock::acquire(dir.path()).expect("first mutator owns the directory");
    let started = std::time::Instant::now();
    let error = StateDirLock::acquire(dir.path()).expect_err("second mutator refused");
    assert!(started.elapsed().as_secs() < 5, "refusal must not wait");
    assert_eq!(error.kind(), StateErrorKind::LockHeld);
    let rendered = error.to_string();
    let path_text = dir.path().to_string_lossy();
    assert!(
        !rendered.contains(path_text.as_ref()),
        "error leaked the path: {rendered}"
    );
    drop(owner);
}

#[test]
fn ownership_releases_when_the_guard_drops() {
    let dir = TempDir::new("release");
    {
        let _owner = StateDirLock::acquire(dir.path()).expect("first ownership");
    }
    let _next =
        StateDirLock::acquire(dir.path()).expect("the lock is free again once the guard dropped");
}

#[test]
fn contention_paths_are_content_free_in_the_error_type() {
    let dir = TempDir::new("content-free");
    let _owner = StateDirLock::acquire(dir.path()).expect("ownership");
    let error = StateDirLock::acquire(dir.path()).expect_err("refused");
    let rendered = format!("{error:?}");
    let path_text = dir.path().to_string_lossy();
    assert!(
        !rendered.contains(path_text.as_ref()),
        "debug leaked the path: {rendered}"
    );
}

// --- CFG-023 permission posture ---------------------------------------------

#[test]
fn acquiring_creates_the_directory_and_lock_file_private() {
    let parent = TempDir::new("create");
    let state_dir = parent.path().join("state");
    let _owner = StateDirLock::acquire(&state_dir).expect("ownership");
    assert_eq!(mode_of(&state_dir), 0o700, "state directory is mode 0700");
    assert_eq!(
        mode_of(&state_dir.join(LOCK_FILE_NAME)),
        0o600,
        "lock file is mode 0600"
    );
}

#[test]
fn a_directory_with_unsafe_permissions_is_refused_not_repaired() {
    let parent = TempDir::new("unsafe-dir");
    let state_dir = parent.path().join("state");
    std::fs::create_dir_all(&state_dir).expect("create directory");
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755))
        .expect("widen directory");
    let error = StateDirLock::acquire(&state_dir).expect_err("refused");
    assert_eq!(error.kind(), StateErrorKind::Unavailable);
    assert!(
        error.detail().contains("permissions"),
        "refusal names the permission condition: {}",
        error.detail()
    );
    assert!(
        !state_dir.join(LOCK_FILE_NAME).exists(),
        "a refused mutator never creates the lock file"
    );
}

#[test]
fn a_lock_file_with_unsafe_permissions_is_refused_not_repaired() {
    let dir = TempDir::new("unsafe-file");
    let lock_path = dir.path().join(LOCK_FILE_NAME);
    std::fs::write(&lock_path, b"").expect("create lock file");
    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644))
        .expect("widen lock file");
    let error = StateDirLock::acquire(dir.path()).expect_err("refused");
    assert_eq!(error.kind(), StateErrorKind::Unavailable);
    assert!(
        error.detail().contains("permissions"),
        "refusal names the permission condition: {}",
        error.detail()
    );
}

#[test]
fn a_state_directory_path_that_is_a_file_is_unavailable() {
    let parent = TempDir::new("not-a-dir");
    let state_dir = parent.path().join("state");
    std::fs::write(&state_dir, b"").expect("occupy the path with a file");
    let error = StateDirLock::acquire(&state_dir).expect_err("refused");
    assert_eq!(error.kind(), StateErrorKind::Unavailable);
}

// --- The registered exit-75 surface ------------------------------------------

/// The committed error-code registry, the same bytes the registry gate
/// checks.
const REGISTRY: &str = include_str!("../../../../../tools/error-codes.toml");

/// The TOML section under `[header]`, up to the next section header.
fn registry_section(header: &str) -> String {
    let marker = format!("[{header}]");
    let start = REGISTRY.find(&marker).unwrap_or_else(|| {
        panic!("registry is missing the [{header}] section");
    });
    let rest = &REGISTRY[start + marker.len()..];
    let end = rest.find("\n[").unwrap_or(rest.len());
    rest[..end].to_owned()
}

/// The value of `key = "…"` (or `key = …`) in one section's text.
fn registry_field(section: &str, key: &str) -> String {
    let prefix = format!("{key} = ");
    let line = section
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("section is missing {key}"));
    line.trim().trim_matches('"').to_owned()
}

#[test]
fn the_registry_pins_the_lock_held_surface() {
    let class = registry_section("classes.lock_contention");
    assert_eq!(registry_field(&class, "retryable"), "false");
    assert_eq!(
        registry_field(&class, "exit").parse::<i32>(),
        Ok(LOCK_HELD_EXIT_CODE),
        "the exit constant tracks the registry"
    );
    let code = registry_section("codes.\"client.lock_held\"");
    assert_eq!(registry_field(&code, "class"), "lock_contention");
    assert_eq!(registry_field(&code, "message"), LOCK_HELD_MESSAGE);
}

#[test]
fn the_body_is_the_closed_versioned_error_shape() {
    let bytes = lock_held_body_bytes();
    let parsed = json::parse(&bytes).expect("body is valid json");
    let json::Value::Object(object) = &parsed else {
        panic!("body is an object, got {parsed:?}");
    };
    assert_eq!(
        object.len(),
        6,
        "the body carries exactly the registered fields"
    );
    let schema = match object.get("schema") {
        Some(json::Value::Text(text)) => text.as_str(),
        other => panic!("schema is text, got {other:?}"),
    };
    assert_eq!(schema, "archivist.error/v1");
    let code = match object.get("code") {
        Some(json::Value::Text(text)) => text.as_str(),
        other => panic!("code is text, got {other:?}"),
    };
    assert_eq!(code, "client.lock_held");
    assert_eq!(object.get("retryable"), Some(&json::Value::Bool(false)));
    let message = match object.get("message") {
        Some(json::Value::Text(text)) => text.as_str(),
        other => panic!("message is text, got {other:?}"),
    };
    assert_eq!(message, LOCK_HELD_MESSAGE);
    assert_eq!(object.get("request_id"), Some(&json::Value::Null));
    match object.get("correlation_id") {
        Some(json::Value::Text(text)) => {
            RequestId::parse(text).expect("correlation id is a canonical uuid v7");
        }
        other => panic!("correlation id is text, got {other:?}"),
    }
}

#[test]
fn the_body_never_names_the_directory() {
    let dir = TempDir::new("body-free");
    let _owner = StateDirLock::acquire(dir.path()).expect("ownership");
    let error = StateDirLock::acquire(dir.path()).expect_err("refused");
    assert_eq!(error.kind(), StateErrorKind::LockHeld);
    let bytes = lock_held_body_bytes();
    let text = String::from_utf8(bytes).expect("body is utf-8");
    let path_text = dir.path().to_string_lossy();
    assert!(
        !text.contains(path_text.as_ref()),
        "body leaked the directory path"
    );
}

#[test]
fn correlation_identifiers_are_canonical_and_unique() {
    let first = correlation_of(&lock_held_body_bytes());
    let second = correlation_of(&lock_held_body_bytes());
    assert_ne!(first, second, "each body carries a fresh correlation id");
    let first_bytes = first.as_str().as_bytes();
    assert_eq!(first_bytes[14], b'7', "uuid version nibble");
    assert!(
        matches!(first_bytes[19], b'8' | b'9' | b'a' | b'b'),
        "uuid variant nibble"
    );
}

fn correlation_of(bytes: &[u8]) -> RequestId {
    let parsed = json::parse(bytes).expect("body is valid json");
    let json::Value::Object(object) = &parsed else {
        panic!("body is an object, got {parsed:?}");
    };
    match object.get("correlation_id") {
        Some(json::Value::Text(text)) => RequestId::parse(text).expect("canonical uuid v7"),
        other => panic!("correlation id is text, got {other:?}"),
    }
}

// --- The acceptance condition ------------------------------------------------

#[test]
fn a_second_mutator_is_refused_while_a_snapshot_stays_available() {
    let dir = TempDir::new("ownership");
    let database = dir.path().join("state.db");
    let mut daemon = StateStore::open(&database).expect("the daemon opens state");
    daemon.migrate().expect("migrate");
    let _ownership = StateDirLock::acquire(dir.path()).expect("the daemon owns the directory");

    let refused = StateDirLock::acquire(dir.path()).expect_err("a second mutator is refused");
    assert_eq!(refused.kind(), StateErrorKind::LockHeld);

    // The read-only class never takes the lock: `status` opens its
    // snapshot while the daemon owns the directory.
    let snapshot = StateSnapshot::open(&database).expect("snapshot during ownership");
    assert_eq!(
        snapshot.schema_version().expect("schema version"),
        LATEST_SCHEMA_VERSION
    );
    assert!(
        snapshot.integrity().expect("integrity").healthy(),
        "the snapshot's checks pass during daemon ownership"
    );
}
