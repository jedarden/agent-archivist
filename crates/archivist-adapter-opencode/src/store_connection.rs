// SPDX-License-Identifier: Apache-2.0

//! The read-only store connection (plan Phase 6B; requirement CAP-004).
//!
//! Opens the configured `OpenCode` `SQLite` database strictly for reading:
//! the driver's read-only flag, so a missing database is classified
//! instead of created and no statement this connection issues can write
//! the store the harness owns. Open-time outcomes land in the SDK's
//! closed [`ScanClassification`] vocabulary:
//!
//! | open outcome                                       | classification        |
//! |----------------------------------------------------|-----------------------|
//! | no file at the configured path                     | `no-database`         |
//! | the path or a component denies this process reads  | `permission-denied`   |
//! | anything else, including a lock held past the      | `read-error`          |
//! | busy window                                        |                       |
//!
//! The busy window bounds what the reader can cost the harness's own
//! writer (AC-04 in docs/security/threats/adapter-capture.md): a store
//! locked past the window classifies as a bounded
//! [`StoreOpenError::ReadError`] instead of waiting harder, and the
//! writer keeps the store throughout.
//!
//! Content-freedom (docs/security/threats/adapter-capture.md, the
//! content-freedom gate row): the error type is a closed set of unit
//! variants, so no field can carry the database path, a schema string, or
//! any other source-derived text — and driver error text is dropped at
//! the classification boundary, never wrapped or logged.
//!
//! [`AC-04`]: https://yard.ardenone.com/adapter-capture#ac-04-live-database-lock-contention

use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

use archivist_adapter_sdk::ScanClassification;
use rusqlite::{Connection, OpenFlags};

/// The busy window a production open waits on a competing writer before
/// classifying (plan Phase 6B: "open the supported database read-only with
/// a five-second busy timeout").
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a configured `OpenCode` store could not be opened for reading.
///
/// A closed set of unit variants: the type is incapable of carrying the
/// database path, a schema string, or any other source-derived text, so
/// every formatting — [`Display`](std::fmt::Display) included — is content-free by
/// construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreOpenError {
    /// No database file exists at the configured path. The open never
    /// materializes one: the driver's create flag is never set, and the
    /// path is classified before the driver is involved at all.
    NoDatabase,
    /// The path exists but this process lacks read permission somewhere
    /// along it. A denial is a retained classification, never a crash and
    /// never a silent skip (AC-08 in docs/security/threats/adapter-capture.md).
    PermissionDenied,
    /// The store could not be read this pass: any driver failure,
    /// including a lock held past the busy window, a crashed journal the
    /// reader may not recover, or a file that is not a database.
    ReadError,
}

impl StoreOpenError {
    /// The closed classification this open outcome reports to the
    /// inventory: the value status retains as the source's last
    /// classification.
    #[must_use]
    pub fn classification(self) -> ScanClassification {
        match self {
            Self::NoDatabase => ScanClassification::NoDatabase,
            Self::PermissionDenied => ScanClassification::PermissionDenied,
            Self::ReadError => ScanClassification::ReadError,
        }
    }
}

impl fmt::Display for StoreOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The classification token is the whole message: no path, no
        // schema text, no driver prose.
        f.write_str(self.classification().token())
    }
}

impl std::error::Error for StoreOpenError {}

/// A read-only connection to the configured `OpenCode` store.
///
/// The connection is opened with the driver's read-only flag, so it can
/// neither create the database nor write anything it holds: a statement
/// that would write fails at the driver. No journal mode is negotiated —
/// a reader never rewrites the store's journaling behind the harness's
/// back — and every acquisition of the read lock is bounded by the busy
/// window, so a harness writer holding the store is classified around,
/// never blocked indefinitely and never blocked past the window.
pub struct StoreConnection {
    conn: Connection,
}

impl StoreConnection {
    /// Open the store at `path` strictly read-only under the production
    /// five-second busy window ([`BUSY_TIMEOUT`]).
    ///
    /// # Errors
    ///
    /// [`StoreOpenError::NoDatabase`] when no file exists at `path` — the
    /// open never creates one; [`StoreOpenError::PermissionDenied`] when
    /// the path denies this process reads; [`StoreOpenError::ReadError`]
    /// otherwise, including a lock held past the busy window. No error
    /// carries the path or any other source-derived text.
    pub fn open(path: &Path) -> Result<Self, StoreOpenError> {
        Self::open_with_busy_timeout(path, BUSY_TIMEOUT)
    }

    /// Open the store read-only under an explicit busy window. Production
    /// callers use [`StoreConnection::open`] and its [`BUSY_TIMEOUT`]
    /// constant; the explicit window exists so the contention
    /// classification can be proven without waiting five seconds. A zero
    /// window fails immediately on contention.
    ///
    /// # Errors
    ///
    /// The same closed set as [`StoreConnection::open`]; the window bounds
    /// only how long a competing lock is waited for before
    /// [`StoreOpenError::ReadError`] is classified.
    pub fn open_with_busy_timeout(
        path: &Path,
        busy_timeout: Duration,
    ) -> Result<Self, StoreOpenError> {
        let conn = open_read_only(path, busy_timeout)?;
        Ok(Self { conn })
    }

    /// The underlying read-only connection, for the schema-version gate
    /// and the allowlisted projection queries. Any statement that would
    /// write fails at the driver.
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// Open `path` with the driver's read-only flag under `busy_timeout`.
///
/// The path is classified *before* the driver is involved: a read-only
/// open must never create a file, and the driver's own cannot-open error
/// cannot distinguish absence from denial.
fn open_read_only(path: &Path, busy_timeout: Duration) -> Result<Connection, StoreOpenError> {
    classify_path(path)?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| StoreOpenError::ReadError)?;
    conn.busy_timeout(busy_timeout)
        .map_err(|_| StoreOpenError::ReadError)?;
    // Opening the file takes no database lock; the first statement does.
    // The probe reads the schema index and no projected content, inside
    // the busy window, so a store locked by the harness's own writer
    // surfaces as a bounded classification instead of hanging the scan —
    // and the writer holds the store throughout, unblocked past the
    // window by construction of the driver's busy handler.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .map_err(|_| StoreOpenError::ReadError)?;
    Ok(conn)
}

/// Classify absence and denial from the filesystem alone.
///
/// [`ErrorKind::NotFound`] is the no-database class: the store is
/// reported missing, never materialized. [`ErrorKind::PermissionDenied`]
/// anywhere along the path is the permission class. A path that exists
/// but is not a regular file is a read failure, not an absence — and the
/// explicit read probe classifies a mode-bits denial the driver would
/// report only as a generic cannot-open.
fn classify_path(path: &Path) -> Result<(), StoreOpenError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(match error.kind() {
                ErrorKind::NotFound => StoreOpenError::NoDatabase,
                ErrorKind::PermissionDenied => StoreOpenError::PermissionDenied,
                _ => StoreOpenError::ReadError,
            });
        }
    };
    if !metadata.is_file() {
        // A directory or special file where the store is configured is
        // not a database file: it cannot be read as one, but something is
        // there — honestly a read failure, never a fabricated absence.
        // Checking before the read probe also keeps a special file from
        // being opened at all.
        return Err(StoreOpenError::ReadError);
    }
    if let Err(error) = fs::File::open(path) {
        return Err(match error.kind() {
            ErrorKind::PermissionDenied => StoreOpenError::PermissionDenied,
            _ => StoreOpenError::ReadError,
        });
    }
    Ok(())
}
