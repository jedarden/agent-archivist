// SPDX-License-Identifier: Apache-2.0

//! Single-mutator ownership of the client state directory (plan
//! Section 7.9, CFG-024): an OS advisory lock every mutator holds for its
//! whole life, and the versioned, content-free error surface a refused
//! second mutator exits with.
//!
//! A mutator takes the lock with [`StateDirLock::acquire`] and never waits:
//! the owner may be the daemon, which runs indefinitely, so contention is
//! an exit condition, not a queue. The refused process reports
//! [`StateErrorKind::LockHeld`], writes the `archivist.error/v1` body from
//! [`lock_held_body_bytes`] to its error stream, and exits with
//! [`LOCK_HELD_EXIT_CODE`] — the `lock_contention` class exit.
//!
//! Readers never touch the lock. The `read_only` command class (`status`,
//! `doctor`, and friends, CLI-007) opens a [`super::StateSnapshot`]
//! instead, which stays available for as long as the daemon owns the
//! directory.
//!
//! # Content-free diagnostics
//!
//! The error body carries exactly the registered fields of
//! `docs/notes/error-codes.md` Section 1 — namespace, code, retryability,
//! message, and correlation identifiers — and nothing else. The state
//! directory's path never enters a diagnostic, and operating-system error
//! strings (which can embed paths) are dropped at the boundary: every
//! failure this module reports is a static, content-free detail.
//!
//! The registered surface is pinned, not restated: `tools/error-codes.toml`
//! is the single source of truth for the code, its class, the message, and
//! the exit code, and the tests in this module read the same bytes the
//! registry gate checked and refuse to let the constants drift. When the
//! configuration loader's embedded registry lands in this crate, these
//! pins should move onto it; until then the lockstep test is the
//! enforcement.

use std::fmt::Write as _;
use std::fs::{DirBuilder, File, OpenOptions, Permissions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use archivist_protocol::json;
use archivist_protocol::vocabulary::RequestId;

use super::{StateError, StateErrorKind};

/// The advisory lock file inside the state directory. The file is never
/// written: ownership is a property of the open file description, visible
/// through the operating system (`fuser`, `lsof`), never through content.
pub const LOCK_FILE_NAME: &str = "mutator.lock";

/// The exit code a refused second mutator exits with: the `lock_contention`
/// class allocation (ERR-022), pinned to `tools/error-codes.toml` by a
/// test in this module.
pub const LOCK_HELD_EXIT_CODE: i32 = 75;

/// The registered code the lock-held condition reports.
const LOCK_HELD_CODE: &str = "client.lock_held";

/// The registered message for [`LOCK_HELD_CODE`], pinned to
/// `tools/error-codes.toml` by a test in this module.
const LOCK_HELD_MESSAGE: &str =
    "Another process owns the state directory lock; only one mutator may run at a time.";

/// The error namespace every serialized error body carries (ERR-001).
const ERROR_BODY_SCHEMA: &str = "archivist.error/v1";

/// Exclusive ownership of a client state directory.
///
/// Held for the entire life of a mutating process — across every
/// scheduling cycle, spool write, and state transaction — because the
/// single-mutator contract covers the directory, not individual
/// operations: `SQLite`'s own locks coordinate a mutator's connections with
/// readers, but only the advisory lock makes filesystem scans, spool
/// cleanup, and cursor repair single-threaded (plan Section 7.9).
///
/// The lock is advisory by construction: it is honored by every process
/// that goes through this module, which is all of them. Dropping the guard
/// closes the lock file's description, and the operating system releases
/// the lock with it.
#[derive(Debug)]
pub struct StateDirLock {
    // The open description is the lock, so the field is carried to be
    // dropped, never read. `Debug` is derived rather than field-free
    // because the field is the lock file's handle, not a driver
    // connection: it renders no path.
    #[allow(dead_code)] // the open description is the lock; no behavior reads it
    file: File,
}

impl StateDirLock {
    /// Take exclusive ownership of the state directory at `dir`, creating
    /// the directory (mode 0700, CFG-023) when it does not exist. Never
    /// waits: when another process owns the lock this returns
    /// [`StateErrorKind::LockHeld`] immediately.
    ///
    /// A directory that exists with permissions other than 0700, or a lock
    /// file that exists with permissions other than 0600, is refused
    /// rather than widened or narrowed (CFG-023): the mutator refuses the
    /// operation explicitly, and `doctor` is the surface that reports the
    /// offending mode.
    ///
    /// # Errors
    ///
    /// [`StateErrorKind::LockHeld`] when another process owns the
    /// directory. [`StateErrorKind::Unavailable`] when the directory or
    /// the lock file cannot be prepared — unusable, or unsafe permissions
    /// (CFG-023). Every detail is static and content-free; the path and
    /// the operating system's error text never appear.
    pub fn acquire(dir: &Path) -> Result<Self, StateError> {
        prepare_directory(dir)?;
        let lock_path = dir.join(LOCK_FILE_NAME);
        let existed = lock_path.exists();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|_| lock_file_unusable())?;
        if !existed {
            // Pin the mode explicitly so a permissive process umask
            // cannot narrow what this process just created.
            file.set_permissions(Permissions::from_mode(0o600))
                .map_err(|_| lock_file_unusable())?;
        }
        // A lock file that predates this process must already carry the
        // pinned mode: refuse, never repair (CFG-023).
        let mode = file
            .metadata()
            .map_err(|_| lock_file_unusable())?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(unsafe_permissions());
        }
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(std::fs::TryLockError::WouldBlock) => {
                Err(StateError::of_kind(StateErrorKind::LockHeld))
            }
            Err(std::fs::TryLockError::Error(_)) => Err(lock_file_unusable()),
        }
    }
}

/// The static error for every lock-file failure that is not contention.
fn lock_file_unusable() -> StateError {
    StateError::with_detail(
        StateErrorKind::Unavailable,
        "mutator lock file could not be prepared",
    )
}

/// The static error for a CFG-023 permission refusal.
fn unsafe_permissions() -> StateError {
    StateError::with_detail(
        StateErrorKind::Unavailable,
        "state directory or lock file permissions are unsafe",
    )
}

/// Create the state directory when absent — mode 0700, pinned explicitly
/// so a permissive process umask cannot widen it — and refuse anything
/// that pre-exists with other permissions (CFG-023).
fn prepare_directory(dir: &Path) -> Result<(), StateError> {
    if !dir.is_dir() {
        DirBuilder::new()
            .recursive(true)
            .create(dir)
            .map_err(|_| unsafe_permissions())?;
        std::fs::set_permissions(dir, Permissions::from_mode(0o700))
            .map_err(|_| unsafe_permissions())?;
    }
    let mode = dir
        .metadata()
        .map_err(|_| unsafe_permissions())?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o700 {
        return Err(unsafe_permissions());
    }
    Ok(())
}

/// The versioned, content-free error body for the lock-held condition: the
/// registered `client.lock_held` surface. The body carries exactly the
/// registered fields — namespace, code, retryability, message, a `null`
/// `request_id` (client-local condition, ERR-027), and a freshly minted
/// `correlation_id` (ERR-026) — and never the directory's path.
#[must_use]
pub fn lock_held_body() -> json::Value {
    let mut object = json::Object::new();
    object.set("schema", json::Value::Text(ERROR_BODY_SCHEMA.to_owned()));
    object.set("code", json::Value::Text(LOCK_HELD_CODE.to_owned()));
    object.set("retryable", json::Value::Bool(false));
    object.set("message", json::Value::Text(LOCK_HELD_MESSAGE.to_owned()));
    object.set("request_id", json::Value::Null);
    object.set(
        "correlation_id",
        json::Value::Text(mint_correlation_id().as_str().to_owned()),
    );
    json::Value::Object(object)
}

/// The canonical bytes of [`lock_held_body`] — the exact error-stream JSON
/// a refused second mutator writes before exiting 75.
#[must_use]
pub fn lock_held_body_bytes() -> Vec<u8> {
    lock_held_body().canonical_bytes()
}

/// Mint a correlation identifier: a canonical lowercase `UUIDv7` (plan
/// Section 7.4), re-validated through the protocol's own grammar so a
/// formatting regression cannot ship.
fn mint_correlation_id() -> RequestId {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
    let mut random = [0u8; 10];
    if read_urandom(&mut random).is_err() {
        fill_fallback(&mut random);
    }
    // UUIDv7 layout (RFC 9562): 48-bit Unix millisecond timestamp,
    // version 7, 12-bit rand_a, variant `10`, 62 bits of rand_b. The
    // random bits are consumed without truncating casts: byte 6 takes
    // rand_a's top four bits, byte 7 its low eight, byte 8 the variant
    // marker plus rand_b's top six.
    let timestamp = milliseconds.to_be_bytes();
    let bytes = [
        timestamp[2],
        timestamp[3],
        timestamp[4],
        timestamp[5],
        timestamp[6],
        timestamp[7],
        0x70 | (random[0] >> 4),
        (random[0] << 4) | (random[1] >> 4),
        0x80 | (random[1] & 0x3f),
        random[2],
        random[3],
        random[4],
        random[5],
        random[6],
        random[7],
        random[8],
    ];
    let mut text = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        let _ = write!(text, "{byte:02x}");
    }
    RequestId::parse(&text).expect("minted correlation identifier is canonical uuid v7")
}

/// Fill `buffer` from the operating system's random source.
fn read_urandom(buffer: &mut [u8]) -> std::io::Result<()> {
    File::open("/dev/urandom")?.read_exact(buffer)
}

/// Deterministic-unique fallback when the host has no random source:
/// nanosecond clock, process id, and a process-local counter, mixed so no
/// single input dominates.
fn fill_fallback(buffer: &mut [u8]) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |since| {
            u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
        });
    let tick = COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    let mixed = nanos ^ (u64::from(std::process::id()) << 32) ^ tick.rotate_left(17);
    let mixed_bytes = mixed.to_be_bytes();
    for (index, slot) in buffer.iter_mut().enumerate() {
        *slot = mixed_bytes[index % mixed_bytes.len()];
    }
}

#[cfg(test)]
mod tests;
