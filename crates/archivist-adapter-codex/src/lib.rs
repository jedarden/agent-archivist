// SPDX-License-Identifier: Apache-2.0

//! Codex source adapter.
//!
//! Discovers interactive Codex CLI account homes and their durable session
//! roots, captures rollout session transcripts and the shared prompt-history
//! sidecar as separate artifact kinds on complete record boundaries, and
//! detects inode/file identity changes, truncation, tail mismatch, and
//! rewrites as new source generations. Harness and upstream session IDs are
//! preserved without treating either as global (implementation plan, Phase
//! 6A).
//!
//! Ships in the first adapter wave alongside the Claude Code adapter: file
//! capture exercises marathon chunking and these histories are expected to
//! be among the largest. An embedded fingerprint allowlist fails closed on
//! unknown schema versions rather than attempting a best-effort parse.
//!
//! # The observed tree shape
//!
//! Discovery reads the Codex CLI home — the `CODEX_HOME` directory, by
//! default `.codex` beneath the home directory — and admits only the tree
//! shapes the fleet inventory observed:
//!
//! - a `history.jsonl` file directly inside the home is the shared
//!   [`CodexRole::HistorySidecar`]: one append-only prompt history for the
//!   whole account;
//! - a `.jsonl` file under `sessions/YYYY/MM/DD` (four-digit year, two-digit
//!   month and day) is a [`CodexRole::Rollout`]: one file per session in the
//!   interactive durable date tree;
//! - anything else — `archived_sessions/`, configuration, logs — is
//!   [`CodexRole::Unknown`] and is retained visible but never captured. The
//!   archive is a different durability class than the interactive tree this
//!   adapter covers, so it is reported rather than parsed.
//!
//! Roles come from the tree shape, not from names or content, and an
//! unknown-role file's bytes are never read at all.
//!
//! # The pinned dialect
//!
//! Both dialects are newline-delimited JSON objects admitted by a bounded
//! header window, and the probe is structural, not role-bound: a complete
//! record carrying a string `type` member plus at least one rollout
//! envelope member (`payload`, `session_id`, `ordinal`) reads as
//! [`CodexFormat::Rollout`] — the envelope every observed rollout record
//! type is written in — and a complete record carrying the prompt-record
//! members (`text`, `session_id`, `ts`) without a `type` reads as
//! [`CodexFormat::History`]. No account-identifying member exists in either
//! envelope, so there is one observed writer generation per dialect and no
//! version split to pin. Anything else fails closed as
//! [`CodexFormat::Unknown`] and opens as `unsupported`.
//!
//! # Sidecar relationships
//!
//! The descriptor does not declare `SidecarRelationships`, and the adapter
//! states no per-session bindings, because the observed Codex tree offers
//! none to state: session metadata rides in-band as the rollout's
//! `session_meta` record, and the one sidecar (`history.jsonl`) annotates
//! the account rather than any single session. Declaring the capability
//! would promise relationships the tree cannot express.
//!
//! # Dependency boundary
//!
//! Depends on `archivist-adapter-sdk` only. Must not depend on the other
//! adapters, the client engine, storage, or the server.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use archivist_adapter_sdk::artifact::SourceGeneration;
use archivist_adapter_sdk::capability::{AdapterCapability, CapabilitySet};
use archivist_adapter_sdk::descriptor::AdapterDescriptor;
use archivist_adapter_sdk::discovery::{
    DiscoveredSource, DiscoveredSources, DiscoveryError, DiscoveryReport, SourceDiscovery,
};
use archivist_adapter_sdk::file_capture::{CaptureCursor, CaptureCursorError};
use archivist_adapter_sdk::file_generation::{
    FileGenerationTracker, FileIdentity, GenerationDecision,
};
use archivist_adapter_sdk::fingerprint::{
    FingerprintAllowlist, SourceFingerprint, UnsupportedFingerprint,
};
use archivist_adapter_sdk::lifecycle::{AdapterLifecycle, LifecycleState};
use archivist_adapter_sdk::session_identity::{SessionIdentity, SessionIdentityError};
use archivist_adapter_sdk::status::{AccountLabel, ScanClassification};
use archivist_adapter_sdk::{AdapterId, VersionToken};

/// The adapter identity stamped on captured Codex artifacts
/// (`adapter_id` on the occurrence manifest).
pub const ADAPTER_ID: &str = "codex-jsonl";

/// The harness name used when resolving upstream session identities
/// (plan Section 7.4 grammar).
pub const HARNESS_ID: &str = "codex";

/// The projection version stamped on captured artifacts
/// (`adapter_projection_version`). It pins the same dialect revision the
/// usage reader reads: a changed reading is a new version, never a silent
/// reinterpretation.
pub const PROJECTION_VERSION: &str = "1";

/// The default Codex CLI home beneath the home directory.
pub const DEFAULT_CODEX_HOME: &str = ".codex";

/// The maximum header prefix read while identifying a source.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// The supported rollout session JSONL fingerprint: one file per session
/// under the interactive `sessions/YYYY/MM/DD` date tree.
pub const ROLLOUT_FINGERPRINT: &str = "codex-rollout-jsonl";

/// The supported shared prompt-history JSONL fingerprint.
pub const HISTORY_FINGERPRINT: &str = "codex-history-jsonl";

const UNKNOWN_FINGERPRINT: &str = "codex-unknown-format";

/// The directory beneath the Codex home holding the interactive durable
/// session date tree.
const SESSIONS_DIR: &str = "sessions";

/// The shared prompt-history sidecar at the Codex home root.
const HISTORY_FILE: &str = "history.jsonl";

/// The rollout envelope members whose presence beside a `type` member
/// marks the rollout dialect (fleet inventory: the rollout top-level key
/// union).
const ROLLOUT_ENVELOPE_MEMBERS: [&str; 3] = ["payload", "session_id", "ordinal"];

/// The complete top-level key vocabulary observed in rollout records.
const ROLLOUT_KEYS: [&str; 7] = [
    "ordinal",
    "payload",
    "session_id",
    "text",
    "timestamp",
    "ts",
    "type",
];

/// The closed record-type vocabulary observed in rollout files.
const ROLLOUT_TYPES: [&str; 8] = [
    "compacted",
    "event_msg",
    "inter_agent_communication_metadata",
    "response_item",
    "session_meta",
    "token_usage_record",
    "turn_context",
    "world_state",
];

/// The shared history sidecar's complete top-level key set.
const HISTORY_KEYS: [&str; 3] = ["session_id", "text", "ts"];

/// How a discovered file plays in the Codex CLI home tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodexRole {
    /// A primary session transcript: a `.jsonl` file under the
    /// `sessions/YYYY/MM/DD` date tree.
    Rollout,
    /// The shared prompt-history sidecar at the home root.
    HistorySidecar,
    /// A file discovered under a configured home but not admitted.
    Unknown,
}

impl CodexRole {
    /// The stable content-free token for diagnostics and tests.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Rollout => "rollout",
            Self::HistorySidecar => "history-sidecar",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this role captures as append-only JSONL slices. Both
    /// admitted Codex roles do: the rollout tree and the shared history
    /// sidecar are append-only transcripts.
    #[must_use]
    pub const fn is_jsonl(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// Whether this role may be opened for capture.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// The source format recognized by the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodexFormat {
    /// An append-only Codex rollout session JSONL file.
    Rollout,
    /// An append-only shared prompt-history JSONL file.
    History,
    /// A file discovered under a configured home but not admitted.
    Unknown,
}

/// The kind of captured Codex artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodexArtifactKind {
    /// A per-session rollout transcript.
    Rollout,
    /// The account-wide prompt-history sidecar.
    History,
}

impl CodexArtifactKind {
    /// Whether this artifact is a per-session rollout transcript.
    #[must_use]
    pub const fn is_rollout(self) -> bool {
        matches!(self, Self::Rollout)
    }

    /// Whether this artifact is the shared history sidecar.
    #[must_use]
    pub const fn is_history(self) -> bool {
        matches!(self, Self::History)
    }
}

impl CodexFormat {
    /// Whether this format is admitted by this adapter.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// The content-free fingerprint used in discovery and admission.
    #[must_use]
    pub fn fingerprint(self) -> SourceFingerprint {
        let token = match self {
            Self::Rollout => ROLLOUT_FINGERPRINT,
            Self::History => HISTORY_FINGERPRINT,
            Self::Unknown => UNKNOWN_FINGERPRINT,
        };
        SourceFingerprint::parse(token).expect("Codex fingerprints are constants")
    }
}

/// A configured Codex CLI account and its home directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredRoot {
    account: AccountLabel,
    path: PathBuf,
}

impl ConfiguredRoot {
    /// Configure an account's Codex home.
    #[must_use]
    pub fn new(account: AccountLabel, path: impl Into<PathBuf>) -> Self {
        Self {
            account,
            path: path.into(),
        }
    }

    /// The account label chosen by configuration.
    #[must_use]
    pub fn account(&self) -> &AccountLabel {
        &self.account
    }

    /// The configured filesystem root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Alias for callers that name a configured root a Codex home.
pub type CodexRoot = ConfiguredRoot;

/// One file discovered below a configured Codex home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexSource {
    account: AccountLabel,
    path: PathBuf,
    role: CodexRole,
    format: CodexFormat,
    fingerprint: SourceFingerprint,
    read_classification: Option<ScanClassification>,
}

impl CodexSource {
    fn new(account: &AccountLabel, path: PathBuf, role: CodexRole, format: CodexFormat) -> Self {
        Self {
            account: account.clone(),
            path,
            role,
            format,
            fingerprint: format.fingerprint(),
            read_classification: None,
        }
    }

    fn unreadable(
        account: &AccountLabel,
        path: PathBuf,
        role: CodexRole,
        classification: ScanClassification,
    ) -> Self {
        let mut source = Self::new(account, path, role, CodexFormat::Unknown);
        source.read_classification = Some(classification);
        source
    }

    /// The configured account owning this source.
    #[must_use]
    pub fn account(&self) -> &AccountLabel {
        &self.account
    }

    /// The source path. It is capture input, not status material.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The tree-shape role this file plays.
    #[must_use]
    pub const fn role(&self) -> CodexRole {
        self.role
    }

    /// The detected source format.
    #[must_use]
    pub const fn format(&self) -> CodexFormat {
        self.format
    }

    /// The content-free format fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> &SourceFingerprint {
        &self.fingerprint
    }

    /// Whether this source may be opened for capture.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.role.is_supported() && self.format.is_supported()
    }

    /// Why the file could not be read during discovery, if it could not.
    #[must_use]
    pub const fn read_classification(&self) -> Option<ScanClassification> {
        self.read_classification
    }
}

/// The result of one Codex inventory pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexInventory {
    /// The bounded SDK discovery report.
    pub report: DiscoveryReport,
    /// Every file found, including unsupported formats.
    pub sources: Vec<CodexSource>,
}

impl CodexInventory {
    /// The supported sources in discovery order.
    pub fn supported(&self) -> impl Iterator<Item = &CodexSource> {
        self.sources.iter().filter(|source| source.is_supported())
    }

    /// The unsupported sources in discovery order.
    pub fn unsupported(&self) -> impl Iterator<Item = &CodexSource> {
        self.sources.iter().filter(|source| !source.is_supported())
    }

    /// The distinct supported fingerprints as the SDK routing list: one
    /// entry per observed supported format, never per file.
    pub fn discovered_sources(&self) -> Result<DiscoveredSources, DiscoveryError> {
        let mut seen = BTreeSet::new();
        let entries = self
            .sources
            .iter()
            .filter(|source| source.is_supported())
            .filter(|source| seen.insert(source.fingerprint().clone()))
            .map(|source| DiscoveredSource {
                account: source.account().clone(),
                fingerprint: source.fingerprint().clone(),
            })
            .collect();
        DiscoveredSources::new(entries)
    }
}

/// Construction errors for adapter configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodexConfigError {
    /// The adapter must have at least one configured account home.
    EmptyRoots,
    /// More than one home used the same account label.
    DuplicateAccount,
}

impl fmt::Display for CodexConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyRoots => "codex_empty_roots",
            Self::DuplicateAccount => "codex_duplicate_account",
        })
    }
}

impl std::error::Error for CodexConfigError {}

/// Errors returned while reading or admitting a Codex source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodexCaptureError {
    /// The source fingerprint is not on the adapter's allowlist.
    Unsupported(UnsupportedFingerprint),
    /// The source disappeared or its home was absent.
    RootAbsent,
    /// The source exists but this process lacks read permission.
    PermissionDenied,
    /// The source could not be read for another filesystem reason.
    ReadError,
    /// The file became a different, unsupported format between passes.
    FormatChanged(UnsupportedFingerprint),
    /// The file-core cursor observed an impossible shrink.
    CursorSourceShrank,
}

impl CodexCaptureError {
    /// The closed SDK classification for this error.
    #[must_use]
    pub const fn classification(&self) -> ScanClassification {
        match self {
            Self::Unsupported(_) | Self::FormatChanged(_) => {
                ScanClassification::FingerprintUnsupported
            }
            Self::RootAbsent => ScanClassification::RootAbsent,
            Self::PermissionDenied => ScanClassification::PermissionDenied,
            Self::ReadError | Self::CursorSourceShrank => ScanClassification::ReadError,
        }
    }
}

impl fmt::Display for CodexCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported(_) => "codex_unsupported_fingerprint",
            Self::RootAbsent => "codex_root_absent",
            Self::PermissionDenied => "codex_permission_denied",
            Self::ReadError => "codex_read_error",
            Self::FormatChanged(_) => "codex_format_changed",
            Self::CursorSourceShrank => "codex_capture_source_shrank",
        })
    }
}

impl std::error::Error for CodexCaptureError {}

/// A digest of canonical captured bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CodexDigest([u8; 32]);

impl CodexDigest {
    /// Construct a digest from raw SHA-256 bytes.
    #[must_use]
    pub const fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return raw digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Render the lower-case hexadecimal digest.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex(self.0)
    }
}

impl fmt::Display for CodexDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex(self.0))
    }
}

/// One capture emitted by the adapter: a complete-record slice from an
/// append-only rollout or history JSONL file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexCapturedChunk {
    /// Whether this chunk came from a per-session rollout or the shared
    /// prompt-history sidecar.
    pub artifact: CodexArtifactKind,
    /// The generation that owns the bytes.
    pub generation: SourceGeneration,
    /// Complete canonical bytes, including terminating newlines.
    pub bytes: Vec<u8>,
    /// SHA-256 over bytes.
    pub digest: CodexDigest,
    /// Inclusive byte range within this generation's source stream.
    pub range_start: u64,
    /// Inclusive byte range within this generation's source stream.
    pub range_end: u64,
    /// Zero-based chunk order within the generation.
    pub sequence: u64,
    /// The admitted source fingerprint.
    pub fingerprint: SourceFingerprint,
}

impl CodexCapturedChunk {
    /// Whether this chunk came from a per-session rollout transcript.
    #[must_use]
    pub const fn is_rollout(&self) -> bool {
        self.artifact.is_rollout()
    }

    /// Whether this chunk came from the shared prompt-history sidecar.
    #[must_use]
    pub const fn is_history(&self) -> bool {
        self.artifact.is_history()
    }

    /// The byte length of the canonical payload.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the canonical payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The filesystem-backed Codex source adapter.
#[derive(Clone, Debug)]
pub struct CodexAdapter {
    descriptor: AdapterDescriptor,
    roots: Vec<ConfiguredRoot>,
    state: LifecycleState,
}

impl CodexAdapter {
    /// Build an adapter from one or more account homes.
    pub fn new<I>(roots: I) -> Result<Self, CodexConfigError>
    where
        I: IntoIterator<Item = ConfiguredRoot>,
    {
        let roots: Vec<_> = roots.into_iter().collect();
        if roots.is_empty() {
            return Err(CodexConfigError::EmptyRoots);
        }
        let mut accounts = BTreeSet::new();
        if roots
            .iter()
            .any(|root| !accounts.insert(root.account().clone()))
        {
            return Err(CodexConfigError::DuplicateAccount);
        }
        Ok(Self {
            descriptor: descriptor(),
            roots,
            state: LifecycleState::Constructed,
        })
    }

    /// Compatibility constructor named after mounting an adapter.
    pub fn mount<I>(roots: I) -> Result<Self, CodexConfigError>
    where
        I: IntoIterator<Item = ConfiguredRoot>,
    {
        Self::new(roots)
    }

    /// Construct an adapter from Codex CLI's environment-selected home:
    /// `CODEX_HOME` when set, else the `.codex` default beneath the home
    /// directory.
    pub fn from_environment(account: AccountLabel) -> Result<Self, CodexConfigError> {
        Self::new([ConfiguredRoot::new(account, configured_home())])
    }

    /// The descriptor published by this adapter.
    #[must_use]
    pub const fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    /// The configured homes, in construction order.
    #[must_use]
    pub fn roots(&self) -> &[ConfiguredRoot] {
        &self.roots
    }

    /// Inventory one configured account, retaining unsupported files.
    #[must_use]
    pub fn inventory(&self, account: &AccountLabel) -> CodexInventory {
        let roots: Vec<_> = self
            .roots
            .iter()
            .filter(|root| root.account() == account)
            .collect();
        if roots.is_empty() {
            return empty_inventory(&self.descriptor, account, ScanClassification::NotObserved);
        }

        let mut sources = Vec::new();
        let mut root_access = RootAccess::Ok;
        for root in roots {
            root_access = root_access.combine(inventory_root(root, &mut sources));
        }
        let saw_permission_denied = root_access == RootAccess::PermissionDenied
            || sources.iter().any(|source| {
                source.read_classification() == Some(ScanClassification::PermissionDenied)
            });
        let saw_read_error = root_access == RootAccess::ReadError
            || sources
                .iter()
                .any(|source| source.read_classification() == Some(ScanClassification::ReadError));
        let supported = sources
            .iter()
            .filter(|source| source.is_supported())
            .count();
        let unsupported = sources.len().saturating_sub(supported);
        let classification = if saw_permission_denied {
            ScanClassification::PermissionDenied
        } else if saw_read_error {
            ScanClassification::ReadError
        } else if supported == 0 && unsupported > 0 {
            ScanClassification::FingerprintUnsupported
        } else if supported > 0 {
            ScanClassification::Ok
        } else {
            ScanClassification::RootAbsent
        };
        let report = DiscoveryReport::new(
            self.descriptor.adapter.clone(),
            account.clone(),
            classification,
            measured(sources.len()),
            measured(supported),
            measured(unsupported),
        )
        .expect("inventory counts are derived from one source list");
        CodexInventory { report, sources }
    }

    /// Open one source after exact fingerprint admission.
    pub fn open(&self, source: &CodexSource) -> Result<CodexCapture, CodexCaptureError> {
        if let Some(classification) = source.read_classification() {
            return Err(match classification {
                ScanClassification::PermissionDenied => CodexCaptureError::PermissionDenied,
                _ => CodexCaptureError::ReadError,
            });
        }
        if !source.is_supported() {
            return Err(CodexCaptureError::Unsupported(UnsupportedFingerprint {
                fingerprint: source.fingerprint().clone(),
            }));
        }
        self.descriptor
            .fingerprints
            .admit(source.fingerprint())
            .map_err(CodexCaptureError::Unsupported)?;
        Ok(CodexCapture::new(source.clone()))
    }

    /// Alias for open used by callers that call a capture a stream.
    pub fn capture(&self, source: &CodexSource) -> Result<CodexCapture, CodexCaptureError> {
        self.open(source)
    }
}

impl AdapterLifecycle for CodexAdapter {
    fn state(&self) -> LifecycleState {
        self.state
    }

    fn close(&mut self) {
        self.state = LifecycleState::Closed;
    }
}

impl SourceDiscovery for CodexAdapter {
    fn discover(&self, account: &AccountLabel) -> DiscoveryReport {
        self.inventory(account).report
    }
}

/// A live capture stream for a supported Codex source: append-only JSONL
/// complete-record capture over the SDK file-core cursor, for both the
/// rollout and the history dialects.
#[derive(Clone, Debug)]
pub struct CodexCapture {
    source: CodexSource,
    tracker: Option<FileGenerationTracker>,
    cursor: CaptureCursor,
    sequence: u64,
}

impl CodexCapture {
    /// Start an unopened capture stream.
    #[must_use]
    pub fn new(source: CodexSource) -> Self {
        Self {
            source,
            tracker: None,
            cursor: CaptureCursor::new(),
            sequence: 0,
        }
    }

    /// The source this stream reads.
    #[must_use]
    pub fn source(&self) -> &CodexSource {
        &self.source
    }

    /// The current generation.
    #[must_use]
    pub fn generation(&self) -> &SourceGeneration {
        self.tracker
            .as_ref()
            .map(FileGenerationTracker::current)
            .expect("a generation exists after the first capture pass")
    }

    /// Closed generations in detection order.
    #[must_use]
    pub fn history(&self) -> &[SourceGeneration] {
        self.tracker
            .as_ref()
            .map_or(&[], FileGenerationTracker::history)
    }

    /// The complete-record cursor's acknowledged byte position.
    #[must_use]
    pub fn cursor_position(&self) -> u64 {
        self.cursor.position()
    }

    /// Pull the next complete JSONL byte slice. None means no newly
    /// complete bytes exist.
    pub fn next_chunk(&mut self) -> Result<Option<CodexCapturedChunk>, CodexCaptureError> {
        let identity = file_identity(&self.source.path)?;
        let prefix = read_prefix(&self.source.path)?;
        let detected = detect(&prefix);
        if detected != self.source.format {
            return Err(CodexCaptureError::FormatChanged(UnsupportedFingerprint {
                fingerprint: detected.fingerprint(),
            }));
        }
        let bytes = read_all(&self.source.path)?;
        if !snapshot_matches_format(&bytes, self.source.format) {
            return Err(CodexCaptureError::FormatChanged(UnsupportedFingerprint {
                fingerprint: CodexFormat::Unknown.fingerprint(),
            }));
        }
        let rotated = if let Some(tracker) = self.tracker.as_mut() {
            matches!(
                tracker.observe(identity, &bytes),
                GenerationDecision::Rotated(_)
            )
        } else {
            self.tracker = Some(FileGenerationTracker::begin(identity, &bytes));
            false
        };
        if rotated {
            self.cursor = CaptureCursor::new();
            self.sequence = 0;
        }
        let start = self.cursor.position();
        let outcome = self.cursor.observe(&bytes).map_err(|error| match error {
            CaptureCursorError::SourceShrank => CodexCaptureError::CursorSourceShrank,
        })?;
        if outcome.captured.is_empty() {
            return Ok(None);
        }
        let captured = outcome.captured.to_vec();
        let end = start
            .checked_add(measured(captured.len()))
            .and_then(|value| value.checked_sub(1))
            .unwrap_or(u64::MAX);
        let chunk = CodexCapturedChunk {
            artifact: match self.source.role {
                CodexRole::Rollout => CodexArtifactKind::Rollout,
                CodexRole::HistorySidecar => CodexArtifactKind::History,
                CodexRole::Unknown => unreachable!("unsupported roles cannot be opened"),
            },
            generation: self.generation().clone(),
            digest: CodexDigest::from_raw(sha256(&captured)),
            bytes: captured,
            range_start: start,
            range_end: end,
            sequence: self.sequence,
            fingerprint: self.source.fingerprint().clone(),
        };
        self.sequence = self.sequence.saturating_add(1);
        Ok(Some(chunk))
    }

    /// Alias for [`Self::next_chunk`], matching the SDK capture terminology.
    pub fn capture_pass(&mut self) -> Result<Option<CodexCapturedChunk>, CodexCaptureError> {
        self.next_chunk()
    }
}

/// Resolve the session identity capture namespaces by: the harness name
/// is fixed at [`HARNESS_ID`], and the harness's stated session ID is
/// preserved byte-for-byte — never case-folded, normalized, or merged
/// with a lookalike. An absent or empty stated ID is a synthetic
/// identity, never a path-derived guess.
///
/// The stated ID is the rollout envelope's `session_id` member (or the
/// in-band `session_meta` payload's), carried opaquely; the shared
/// history sidecar's own `session_id` members reference the sessions
/// whose prompts they record and never mint identities of their own.
///
/// # Errors
/// [`SessionIdentityError::UpstreamSessionInvalid`] when the stated
/// session ID is outside the opaque bound.
pub fn resolve_session_identity(
    stated: Option<&str>,
) -> Result<SessionIdentity, SessionIdentityError> {
    SessionIdentity::resolve(HARNESS_ID, stated)
}

/// How the configured home itself answered this pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootAccess {
    Ok,
    RootAbsent,
    PermissionDenied,
    ReadError,
}

impl RootAccess {
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::PermissionDenied, _) | (_, Self::PermissionDenied) => Self::PermissionDenied,
            (Self::ReadError, _) | (_, Self::ReadError) => Self::ReadError,
            (Self::RootAbsent, _) | (_, Self::RootAbsent) => Self::RootAbsent,
            (Self::Ok, Self::Ok) => Self::Ok,
        }
    }
}

fn descriptor() -> AdapterDescriptor {
    let capabilities = CapabilitySet::parse([
        AdapterCapability::FileSliceCapture.token(),
        AdapterCapability::CompleteRecordBoundaries.token(),
        AdapterCapability::GenerationDetection.token(),
        AdapterCapability::CoverageGapReporting.token(),
    ])
    .expect("Codex capabilities are constants");
    let fingerprints = FingerprintAllowlist::parse([ROLLOUT_FINGERPRINT, HISTORY_FINGERPRINT])
        .expect("Codex fingerprints are constants");
    AdapterDescriptor::publish(
        AdapterId::parse(ADAPTER_ID).expect("Codex adapter id is canonical"),
        VersionToken::parse(PROJECTION_VERSION).expect("Codex projection is canonical"),
        capabilities,
        fingerprints,
    )
    .expect("Codex declares capture capabilities")
}

fn empty_inventory(
    descriptor: &AdapterDescriptor,
    account: &AccountLabel,
    classification: ScanClassification,
) -> CodexInventory {
    CodexInventory {
        report: DiscoveryReport::new(
            descriptor.adapter.clone(),
            account.clone(),
            classification,
            0,
            0,
            0,
        )
        .expect("empty inventory counts are consistent"),
        sources: Vec::new(),
    }
}

fn inventory_root(root: &ConfiguredRoot, output: &mut Vec<CodexSource>) -> RootAccess {
    let metadata = match fs::metadata(root.path()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return RootAccess::RootAbsent,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return RootAccess::PermissionDenied;
        }
        Err(_) => return RootAccess::ReadError,
    };
    if metadata.is_file() {
        output.push(CodexSource::new(
            root.account(),
            root.path().to_path_buf(),
            CodexRole::Unknown,
            CodexFormat::Unknown,
        ));
        return RootAccess::Ok;
    }
    let mut stack = match fs::read_dir(root.path()) {
        Ok(entries) => vec![entries],
        Err(error) if error.kind() == io::ErrorKind::NotFound => return RootAccess::RootAbsent,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return RootAccess::PermissionDenied;
        }
        Err(_) => return RootAccess::ReadError,
    };
    let mut access = RootAccess::Ok;
    while let Some(entries) = stack.pop() {
        for entry in entries {
            let Ok(entry) = entry else {
                access = access.combine(RootAccess::ReadError);
                continue;
            };
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                access = access.combine(RootAccess::ReadError);
                continue;
            };
            if metadata.is_dir() {
                match fs::read_dir(&path) {
                    Ok(nested) => stack.push(nested),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        access = access.combine(RootAccess::PermissionDenied);
                    }
                    Err(_) => access = access.combine(RootAccess::ReadError),
                }
            } else if metadata.is_file() {
                let role = role_for(&path, root.path());
                output.push(inspect_source(root.account(), path, role));
            }
        }
    }
    output.sort_by(|left, right| left.path().cmp(right.path()));
    access
}

fn inspect_source(account: &AccountLabel, path: PathBuf, role: CodexRole) -> CodexSource {
    if role == CodexRole::Unknown {
        // An unknown-role file is never captured, so its bytes are never
        // probed: the closed-world fingerprint stands in for a format the
        // adapter deliberately does not read.
        return CodexSource::new(account, path, role, CodexFormat::Unknown);
    }
    let prefix = match read_prefix(&path) {
        Ok(prefix) => prefix,
        Err(error) => {
            return CodexSource::unreadable(account, path, role, error.classification());
        }
    };
    CodexSource::new(account, path, role, detect(&prefix))
}

/// The tree-shape role of one regular file: `history.jsonl` directly
/// inside the home is the shared prompt-history sidecar, and a `.jsonl`
/// file under `sessions/YYYY/MM/DD` is a rollout transcript. Everything
/// else — the archive tree, configuration, logs, wrong-depth strays — is
/// unknown.
fn role_for(path: &Path, root: &Path) -> CodexRole {
    let Ok(relative) = path.strip_prefix(root) else {
        return CodexRole::Unknown;
    };
    let components: Vec<_> = relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    let Some(file_name) = components.last() else {
        return CodexRole::Unknown;
    };
    let directories = &components[..components.len() - 1];
    if directories.is_empty() {
        return if *file_name == HISTORY_FILE {
            CodexRole::HistorySidecar
        } else {
            CodexRole::Unknown
        };
    }
    if directories.len() == 4
        && directories[0] == SESSIONS_DIR
        && is_date_component(directories[1], 4)
        && is_date_component(directories[2], 2)
        && is_date_component(directories[3], 2)
        && is_jsonl_name(file_name)
    {
        return CodexRole::Rollout;
    }
    CodexRole::Unknown
}

/// A date-tree directory component: exactly `width` ASCII digits.
fn is_date_component(text: &str, width: usize) -> bool {
    text.len() == width && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Detect the Codex JSONL dialect from a bounded header window: some
/// complete line must carry the rollout envelope (a string `type` member
/// beside an envelope member) or the history record shape (`text`,
/// `session_id`, `ts`, no `type`). The probe is structural, so a
/// history-shaped file at rollout depth still admits — the dialect is a
/// property of the content, and the tree decides only the role.
fn detect(prefix: &[u8]) -> CodexFormat {
    let mut detected = None;
    for line in complete_lines(prefix) {
        if trim_ascii_space(line).is_empty() {
            continue;
        }
        let Some(format) = classify_record(line) else {
            return CodexFormat::Unknown;
        };
        if detected.is_some_and(|previous| previous != format) {
            return CodexFormat::Unknown;
        }
        detected = Some(format);
    }
    detected.unwrap_or(CodexFormat::Unknown)
}

/// Validate the complete records visible in a source snapshot. A trailing
/// fragment is deliberately ignored: the file-core cursor owns completion
/// and will reconsider that same byte range on the next pass.
fn snapshot_matches_format(snapshot: &[u8], expected: CodexFormat) -> bool {
    let mut found = false;
    for line in complete_lines(snapshot) {
        if trim_ascii_space(line).is_empty() {
            continue;
        }
        if classify_record(line) != Some(expected) {
            return false;
        }
        found = true;
    }
    found
}

/// Classify one complete JSONL object under the exact observed Codex
/// fingerprints. The tree role is intentionally not consulted here: a
/// history-shaped record remains the history dialect wherever it is found.
fn classify_record(line: &[u8]) -> Option<CodexFormat> {
    let members = parse_top_level_object(line)?;
    if members.is_empty() {
        return None;
    }
    let names: BTreeSet<&str> = members.iter().map(|member| member.name.as_str()).collect();
    if names.iter().any(|name| !ROLLOUT_KEYS.contains(name)) {
        return None;
    }
    if names.len() == HISTORY_KEYS.len()
        && HISTORY_KEYS.iter().all(|key| names.contains(key))
        && member_is_string(&members, "session_id")
        && member_is_string(&members, "text")
        && member_is_number(&members, "ts")
    {
        return Some(CodexFormat::History);
    }
    let type_name = member_string(&members, "type")?;
    if !ROLLOUT_TYPES.contains(&type_name.as_str())
        || !ROLLOUT_ENVELOPE_MEMBERS
            .iter()
            .any(|member| names.contains(member))
        || member_is_non_string(&members, "timestamp")
        || member_is_non_string(&members, "session_id")
        || member_is_non_string(&members, "text")
        || member_is_non_number(&members, "ts")
        || member_is_non_number(&members, "ordinal")
    {
        return None;
    }
    Some(CodexFormat::Rollout)
}

/// The complete lines of a bounded header window: a trailing fragment
/// without its terminator is torn and probes as nothing.
fn complete_lines(prefix: &[u8]) -> impl Iterator<Item = &[u8]> {
    let end = match prefix.last() {
        Some(b'\n') => prefix.len(),
        _ => prefix
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |last| last + 1),
    };
    prefix[..end].split(|byte| *byte == b'\n')
}

fn is_jsonl_name(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))
}

fn trim_ascii_space(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JsonValueKind {
    String,
    Number,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JsonMember {
    name: String,
    kind: JsonValueKind,
    string: Option<String>,
}

fn member_string(members: &[JsonMember], key: &str) -> Option<String> {
    members
        .iter()
        .find(|member| member.name == key)
        .and_then(|member| member.string.clone())
}

fn member_is_string(members: &[JsonMember], key: &str) -> bool {
    members
        .iter()
        .any(|member| member.name == key && member.kind == JsonValueKind::String)
}

fn member_is_number(members: &[JsonMember], key: &str) -> bool {
    members
        .iter()
        .any(|member| member.name == key && member.kind == JsonValueKind::Number)
}

fn member_is_non_string(members: &[JsonMember], key: &str) -> bool {
    members
        .iter()
        .find(|member| member.name == key)
        .is_some_and(|member| member.kind != JsonValueKind::String)
}

fn member_is_non_number(members: &[JsonMember], key: &str) -> bool {
    members
        .iter()
        .find(|member| member.name == key)
        .is_some_and(|member| member.kind != JsonValueKind::Number)
}

fn parse_top_level_object(bytes: &[u8]) -> Option<Vec<JsonMember>> {
    let mut parser = JsonParser { bytes, position: 0 };
    let members = parser.object(0)?;
    parser.whitespace();
    (parser.position == bytes.len()).then_some(members)
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl JsonParser<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn object(&mut self, depth: usize) -> Option<Vec<JsonMember>> {
        if depth > 64 || self.bytes.get(self.position) != Some(&b'{') {
            return None;
        }
        self.position += 1;
        self.whitespace();
        let mut members = Vec::new();
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Some(members);
        }
        loop {
            self.whitespace();
            let name = self.string()?;
            self.whitespace();
            if self.bytes.get(self.position) != Some(&b':') {
                return None;
            }
            self.position += 1;
            self.whitespace();
            let (kind, string) = self.value(depth + 1)?;
            if members
                .iter()
                .any(|member: &JsonMember| member.name == name)
            {
                return None;
            }
            members.push(JsonMember { name, kind, string });
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Some(members);
                }
                _ => return None,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<()> {
        if depth > 64 || self.bytes.get(self.position) != Some(&b'[') {
            return None;
        }
        self.position += 1;
        self.whitespace();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Some(());
        }
        loop {
            self.value(depth + 1)?;
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }

    fn value(&mut self, depth: usize) -> Option<(JsonValueKind, Option<String>)> {
        self.whitespace();
        match self.bytes.get(self.position)? {
            b'"' => self
                .string()
                .map(|string| (JsonValueKind::String, Some(string))),
            b'{' => {
                self.object(depth)?;
                Some((JsonValueKind::Other, None))
            }
            b'[' => {
                self.array(depth)?;
                Some((JsonValueKind::Other, None))
            }
            b'-' | b'0'..=b'9' => {
                self.number()?;
                Some((JsonValueKind::Number, None))
            }
            b't' => {
                self.literal(b"true")?;
                Some((JsonValueKind::Other, None))
            }
            b'f' => {
                self.literal(b"false")?;
                Some((JsonValueKind::Other, None))
            }
            b'n' => {
                self.literal(b"null")?;
                Some((JsonValueKind::Other, None))
            }
            _ => None,
        }
    }

    fn string(&mut self) -> Option<String> {
        if self.bytes.get(self.position) != Some(&b'"') {
            return None;
        }
        self.position += 1;
        let mut output = Vec::new();
        loop {
            let byte = *self.bytes.get(self.position)?;
            self.position += 1;
            match byte {
                b'"' => return String::from_utf8(output).ok(),
                b'\\' => {
                    let escape = *self.bytes.get(self.position)?;
                    self.position += 1;
                    match escape {
                        b'"' | b'\\' | b'/' => output.push(escape),
                        b'b' => output.push(0x08),
                        b'f' => output.push(0x0c),
                        b'n' => output.push(b'\n'),
                        b'r' => output.push(b'\r'),
                        b't' => output.push(b'\t'),
                        b'u' => {
                            let high = self.hex_quad()?;
                            let code = if (0xd800..=0xdbff).contains(&high) {
                                if self.bytes.get(self.position..self.position + 2) != Some(b"\\u")
                                {
                                    return None;
                                }
                                self.position += 2;
                                let low = self.hex_quad()?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return None;
                                }
                                0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00)
                            } else if (0xdc00..=0xdfff).contains(&high) {
                                return None;
                            } else {
                                high
                            };
                            let character = char::from_u32(code)?;
                            let mut encoded = [0_u8; 4];
                            output
                                .extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                        }
                        _ => return None,
                    }
                }
                byte if byte < 0x20 => return None,
                _ => output.push(byte),
            }
        }
    }

    fn hex_quad(&mut self) -> Option<u32> {
        let mut value = 0_u32;
        for _ in 0..4 {
            value = value
                .checked_mul(16)?
                .checked_add(u32::from(hex_digit(*self.bytes.get(self.position)?)?))?;
            self.position += 1;
        }
        Some(value)
    }

    fn number(&mut self) -> Option<()> {
        if self.bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        match self.bytes.get(self.position) {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.position += 1;
                while self
                    .bytes
                    .get(self.position)
                    .is_some_and(u8::is_ascii_digit)
                {
                    self.position += 1;
                }
            }
            _ => return None,
        }
        if self.bytes.get(self.position) == Some(&b'.') {
            self.position += 1;
            let start = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == start {
                return None;
            }
        }
        if matches!(self.bytes.get(self.position), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
                self.position += 1;
            }
            let start = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == start {
                return None;
            }
        }
        Some(())
    }

    fn literal(&mut self, literal: &[u8]) -> Option<()> {
        let end = self.position.checked_add(literal.len())?;
        if self.bytes.get(self.position..end) == Some(literal) {
            self.position = end;
            Some(())
        } else {
            None
        }
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The Codex home selected by the process environment: `CODEX_HOME` when
/// set, else the `.codex` default beneath the home directory.
fn configured_home() -> PathBuf {
    configured_home_from(
        env::var_os("CODEX_HOME").as_deref(),
        env::var_os("HOME").as_deref(),
    )
}

/// The pure core of [`configured_home`], so the precedence rule is
/// testable without mutating process state.
fn configured_home_from(codex_home: Option<&OsStr>, home: Option<&OsStr>) -> PathBuf {
    if let Some(codex_home) = codex_home {
        return PathBuf::from(codex_home);
    }
    if let Some(home) = home {
        return PathBuf::from(home).join(DEFAULT_CODEX_HOME);
    }
    PathBuf::from(DEFAULT_CODEX_HOME)
}

fn file_identity(path: &Path) -> Result<FileIdentity, CodexCaptureError> {
    let metadata = fs::metadata(path).map_err(|error| map_io_error(&error))?;
    Ok(metadata_identity(&metadata))
}

fn metadata_identity(metadata: &Metadata) -> FileIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        FileIdentity::new(metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        FileIdentity::new(0, 0)
    }
}

fn read_prefix(path: &Path) -> Result<Vec<u8>, CodexCaptureError> {
    let file = File::open(path).map_err(|error| map_io_error(&error))?;
    let mut bytes = Vec::new();
    file.take(measured(MAX_HEADER_BYTES))
        .read_to_end(&mut bytes)
        .map_err(|error| map_io_error(&error))?;
    Ok(bytes)
}

fn read_all(path: &Path) -> Result<Vec<u8>, CodexCaptureError> {
    fs::read(path).map_err(|error| map_io_error(&error))
}

fn map_io_error(error: &io::Error) -> CodexCaptureError {
    match error.kind() {
        io::ErrorKind::NotFound => CodexCaptureError::RootAbsent,
        io::ErrorKind::PermissionDenied => CodexCaptureError::PermissionDenied,
        _ => CodexCaptureError::ReadError,
    }
}

/// A slice length widened into the byte-count domain: `usize` fits `u64`
/// on every supported target, so the saturating fallback is dead
/// arithmetic kept for the conversion's totality.
fn measured(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

fn hex(bytes: [u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

/// Dependency-free SHA-256 for the adapter's byte-level capture result.
#[allow(clippy::many_single_char_names, clippy::unreadable_literal)]
fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = INITIAL;
    let bit_len = measured(input.len()).saturating_mul(8);
    let padded_len = input.len().saturating_add(9).div_ceil(64) * 64;
    let mut padded = vec![0_u8; padded_len];
    padded[..input.len()].copy_from_slice(input);
    padded[input.len()] = 0x80;
    let length_start = padded.len() - 8;
    padded[length_start..].copy_from_slice(&bit_len.to_be_bytes());
    for block in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut output = [0_u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn account() -> AccountLabel {
        AccountLabel::parse("test-account").expect("valid account")
    }

    fn second_account() -> AccountLabel {
        AccountLabel::parse("other-account").expect("valid account")
    }

    fn temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        env::temp_dir().join(format!("archivist-codex-{label}-{nanos}"))
    }

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture root");
        }
        fs::write(path, bytes).expect("write fixture");
    }

    fn append(path: &Path, bytes: &[u8]) {
        fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open for append")
            .write_all(bytes)
            .expect("append fixture bytes");
    }

    fn adapter(root: &Path) -> CodexAdapter {
        CodexAdapter::new([ConfiguredRoot::new(account(), root)]).expect("adapter")
    }

    fn first_supported(root: &Path) -> (CodexAdapter, CodexSource) {
        let configured = adapter(root);
        let source = configured
            .inventory(&account())
            .supported()
            .next()
            .cloned()
            .expect("source");
        (configured, source)
    }

    /// A rollout record of the pinned dialect, with an explicit payload
    /// id so tests can rewrite one record at a constant byte length.
    fn rollout_record_with(type_name: &str, id: &str) -> String {
        format!(
            r#"{{"timestamp":"2026-09-24T00:00:00.000Z","type":"{type_name}","payload":{{"id":"{id}"}}}}"#
        )
    }

    fn rollout_record(type_name: &str) -> String {
        rollout_record_with(type_name, "r1")
    }

    /// A history record of the pinned dialect.
    fn history_record(text: &str) -> String {
        format!(r#"{{"session_id":"s1","ts":1758700800,"text":"{text}"}}"#)
    }

    fn rollout_path(root: &Path, day: &str, name: &str) -> PathBuf {
        root.join(format!("sessions/2026/08/{day}/{name}"))
    }

    #[test]
    fn descriptor_publishes_the_observed_fingerprint_allowlist() {
        let descriptor = descriptor();
        assert_eq!(descriptor.adapter.as_str(), ADAPTER_ID);
        assert_eq!(descriptor.projection.as_str(), PROJECTION_VERSION);
        let tokens: Vec<_> = descriptor
            .fingerprints
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(tokens, ["codex-history-jsonl", "codex-rollout-jsonl"]);
        assert!(
            descriptor
                .capabilities
                .supports(AdapterCapability::CompleteRecordBoundaries)
        );
        assert!(
            descriptor
                .capabilities
                .supports(AdapterCapability::GenerationDetection)
        );
        // No per-session sidecar bindings are stateable in the Codex tree,
        // so the capability is not declared.
        assert!(
            !descriptor
                .capabilities
                .supports(AdapterCapability::SidecarRelationships)
        );
        // An unknown observed fingerprint fails closed.
        let future = SourceFingerprint::parse("codex-rollout-jsonl-v2").expect("parses");
        assert!(descriptor.fingerprints.admit(&future).is_err());
    }

    #[test]
    fn the_golden_tree_maps_roles_fingerprints_and_out_of_scope_trees() {
        let root = temp_root("golden");
        write(
            &rollout_path(&root, "03", "rollout-a.jsonl"),
            format!(
                "{}\n{}\n",
                rollout_record("session_meta"),
                rollout_record("response_item")
            )
            .as_bytes(),
        );
        write(
            &rollout_path(&root, "03", "rollout-b.jsonl"),
            format!(
                "{}\n{}\n",
                rollout_record("event_msg"),
                rollout_record("token_usage_record")
            )
            .as_bytes(),
        );
        write(
            &rollout_path(&root, "01", "rollout-c.jsonl"),
            format!("{}\n", rollout_record("turn_context")).as_bytes(),
        );
        write(
            &root.join("history.jsonl"),
            format!(
                "{}\n{}\n",
                history_record("first"),
                history_record("second")
            )
            .as_bytes(),
        );
        // Out of scope but visible: the archive is a different durability
        // class, and configuration and logs are never session material.
        write(
            &root.join("archived_sessions/2026/08/01/rollout-old.jsonl"),
            format!("{}\n", rollout_record("session_meta")).as_bytes(),
        );
        write(
            &root.join("sessions/2026/08/rollout-shallow.jsonl"),
            format!("{}\n", rollout_record("session_meta")).as_bytes(),
        );
        write(&root.join("config.toml"), b"model = \"gpt-5\"");
        write(&root.join("log/codex-tui.log"), b"log line");
        let inventory = adapter(&root).inventory(&account());
        assert_eq!(inventory.report.sources, 8);
        assert_eq!(inventory.report.supported, 4);
        assert_eq!(inventory.report.unsupported, 4);
        assert_eq!(inventory.report.classification, ScanClassification::Ok);

        let role_of = |path: &str| {
            let found = inventory
                .sources
                .iter()
                .find(|source| source.path().ends_with(path));
            found.map_or_else(
                || panic!("no source for {path}"),
                |source| (source.role(), source.fingerprint().clone()),
            )
        };
        assert_eq!(role_of("rollout-a.jsonl").0, CodexRole::Rollout);
        assert_eq!(role_of("rollout-a.jsonl").1.as_str(), "codex-rollout-jsonl");
        assert_eq!(role_of("rollout-b.jsonl").1.as_str(), "codex-rollout-jsonl");
        assert_eq!(role_of("rollout-c.jsonl").0, CodexRole::Rollout);
        assert_eq!(role_of("history.jsonl").0, CodexRole::HistorySidecar);
        assert_eq!(role_of("history.jsonl").1.as_str(), "codex-history-jsonl");
        assert_eq!(role_of("rollout-old.jsonl").0, CodexRole::Unknown);
        assert_eq!(
            role_of("rollout-old.jsonl").1.as_str(),
            "codex-unknown-format"
        );
        assert_eq!(role_of("rollout-shallow.jsonl").0, CodexRole::Unknown);
        assert_eq!(role_of("config.toml").0, CodexRole::Unknown);
        assert_eq!(role_of("codex-tui.log").0, CodexRole::Unknown);
        assert_eq!(inventory.supported().count(), 4);
        assert_eq!(
            inventory.discovered_sources().expect("routing list").len(),
            2,
            "one routing entry per distinct supported fingerprint"
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn the_dialect_is_a_property_of_the_content_not_the_tree_slot() {
        let root = temp_root("dialect-by-content");
        // A history-shaped file at rollout depth admits as the history
        // dialect; the tree decides the role, the content the format.
        write(
            &rollout_path(&root, "03", "rollout-misplaced.jsonl"),
            format!("{}\n", history_record("misplaced")).as_bytes(),
        );
        let inventory = adapter(&root).inventory(&account());
        let source = inventory.supported().next().cloned().expect("admitted");
        assert_eq!(source.role(), CodexRole::Rollout);
        assert_eq!(source.fingerprint().as_str(), "codex-history-jsonl");
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn jsonl_growth_captures_only_complete_records_and_preserves_generation() {
        let root = temp_root("growth");
        let path = rollout_path(&root, "03", "rollout-a.jsonl");
        write(
            &path,
            format!("{}\n", rollout_record("session_meta")).as_bytes(),
        );
        let (configured, source) = first_supported(&root);
        let mut capture = configured.open(&source).expect("open");
        let first = capture.next_chunk().expect("first pass").expect("header");
        assert_eq!(first.sequence, 0);
        let generation = first.generation.clone();
        assert_eq!(capture.next_chunk().expect("unchanged pass"), None);

        // A torn record is measured, never captured.
        append(&path, rollout_record("response_item").as_bytes());
        assert_eq!(capture.next_chunk().expect("torn pass"), None);

        // Completing the torn record captures it whole, in the same
        // generation, at continuing ranges.
        append(&path, b"\n");
        let second = capture.next_chunk().expect("growth pass").expect("growth");
        assert_eq!(second.generation, generation);
        assert_eq!(second.sequence, 1);
        assert_eq!(second.range_start, first.range_end + 1);
        assert_eq!(
            second.bytes,
            format!("{}\n", rollout_record("response_item")).into_bytes()
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn replacement_truncation_tail_mismatch_and_rewrite_open_generations() {
        let root = temp_root("replacement");
        let path = rollout_path(&root, "03", "rollout-a.jsonl");
        let first_line = format!("{}\n", rollout_record_with("session_meta", "r1"));
        write(&path, first_line.as_bytes());
        let (configured, source) = first_supported(&root);
        let mut capture = configured.open(&source).expect("open");
        let initial = capture
            .next_chunk()
            .expect("first pass")
            .expect("initial bytes");
        assert!(capture.history().is_empty());

        // Inode replacement: the file under the same name is a different
        // file, and detection opens a new generation holding its whole
        // content.
        let replacement = format!("{first_line}{}\n", rollout_record_with("event_msg", "r2"));
        let staged = root.join("staged.jsonl");
        write(&staged, replacement.as_bytes());
        fs::rename(&staged, &path).expect("replace source inode");
        let replaced = capture
            .next_chunk()
            .expect("replacement pass")
            .expect("generation 2");
        assert_eq!(capture.history().len(), 1);
        assert_ne!(
            capture.generation().generation,
            initial.generation.generation
        );
        assert_eq!(replaced.bytes, replacement.clone().into_bytes());
        assert_eq!(replaced.sequence, 0);

        // Truncation: the surviving head is intact, so the shrink is a
        // truncation and the next generation restarts from the survivor.
        fs::write(&path, first_line.as_bytes()).expect("truncate source");
        let shrunk = capture
            .next_chunk()
            .expect("truncation pass")
            .expect("generation 3");
        assert_eq!(capture.history().len(), 2);
        assert_eq!(shrunk.bytes, first_line.clone().into_bytes());

        // Growth continues the truncated generation: the acknowledged
        // prefix is intact.
        append(
            &path,
            format!("{}\n", rollout_record_with("event_msg", "r2")).as_bytes(),
        );
        let growth = capture
            .next_chunk()
            .expect("growth pass")
            .expect("growth chunk");
        assert_eq!(growth.sequence, 1);
        assert_eq!(capture.history().len(), 2);

        // Tail mismatch: the acknowledged last record is rewritten in
        // place at an identical byte length with the earlier head intact.
        let mismatched_bytes = format!("{first_line}{}\n", rollout_record_with("event_msg", "r3"));
        let current = fs::read_to_string(&path).expect("read current");
        let rewritten = current.replace(
            &rollout_record_with("event_msg", "r2"),
            &rollout_record_with("event_msg", "r3"),
        );
        assert_eq!(rewritten.len(), mismatched_bytes.len(), "same scale");
        fs::write(&path, rewritten.as_bytes()).expect("rewrite acknowledged tail");
        let mismatched = capture
            .next_chunk()
            .expect("tail-mismatch pass")
            .expect("generation 4");
        assert_eq!(capture.history().len(), 3);
        assert_eq!(mismatched.bytes, mismatched_bytes.into_bytes());

        // Digest change: the acknowledged head is rewritten in place and
        // the file also grows past the acknowledged scale — the general
        // rewrite signal.
        let digest_change = format!(
            "{}\n{}\n{}\n",
            rollout_record_with("session_meta", "r4"),
            rollout_record_with("event_msg", "r3"),
            rollout_record("response_item")
        );
        fs::write(&path, digest_change.as_bytes()).expect("rewrite head and grow");
        let general = capture
            .next_chunk()
            .expect("digest-change pass")
            .expect("generation 5");
        assert_eq!(capture.history().len(), 4);
        assert_eq!(general.bytes, digest_change.into_bytes());
        assert_eq!(capture.next_chunk().expect("settled pass"), None);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn the_history_sidecar_grows_through_the_same_file_core_rules() {
        let root = temp_root("history-growth");
        let path = root.join("history.jsonl");
        write(&path, format!("{}\n", history_record("first")).as_bytes());
        let (configured, source) = first_supported(&root);
        assert_eq!(source.role(), CodexRole::HistorySidecar);
        assert_eq!(source.fingerprint().as_str(), "codex-history-jsonl");
        let mut capture = configured.open(&source).expect("open");
        let first = capture.next_chunk().expect("first pass").expect("record");
        assert!(first.artifact.is_history());
        assert_eq!(
            first.bytes,
            format!("{}\n", history_record("first")).into_bytes()
        );
        let generation = first.generation.clone();
        let second_record = history_record("second");
        append(
            &path,
            &second_record.as_bytes()[..second_record.len().saturating_sub(2)],
        );
        assert_eq!(capture.next_chunk().expect("torn pass"), None);
        append(
            &path,
            &second_record.as_bytes()[second_record.len().saturating_sub(2)..],
        );
        append(&path, b"\n");
        let second = capture.next_chunk().expect("growth pass").expect("growth");
        assert_eq!(second.generation, generation);
        assert_eq!(second.range_start, first.range_end + 1);
        assert_eq!(second.bytes, format!("{second_record}\n").into_bytes());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn permission_denied_fails_closed_without_reading_content() {
        let root = temp_root("permission");
        let path = rollout_path(&root, "03", "rollout-a.jsonl");
        write(
            &path,
            format!("{}\n", rollout_record("session_meta")).as_bytes(),
        );
        // A root process ignores mode bits; probe whether the denial is
        // observable at all before asserting it.
        let probe = root.join("probe");
        write(&probe, b"probe");
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o000)).expect("chmod probe");
        if fs::read(&probe).is_ok() {
            fs::set_permissions(&probe, fs::Permissions::from_mode(0o644)).expect("restore probe");
            fs::remove_dir_all(root).expect("remove fixture");
            return;
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod source");
        let configured = adapter(&root);
        let inventory = configured.inventory(&account());
        assert_eq!(
            inventory.report.classification,
            ScanClassification::PermissionDenied
        );
        let source = inventory
            .sources
            .iter()
            .find(|source| source.path() == path.as_path())
            .cloned()
            .expect("permission-denied source visible");
        assert_eq!(
            source.read_classification(),
            Some(ScanClassification::PermissionDenied)
        );
        let error = configured
            .open(&source)
            .expect_err("permission denied fails closed");
        assert_eq!(error.classification(), ScanClassification::PermissionDenied);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("restore source");
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn a_missing_home_is_an_absent_inventory() {
        let missing = temp_root("missing");
        let configured = adapter(&missing);
        let inventory = configured.inventory(&account());
        assert_eq!(
            inventory.report.classification,
            ScanClassification::RootAbsent
        );
        assert!(inventory.sources.is_empty());
        assert_eq!(inventory.supported().count(), 0);
        // An account with no configured home is not observed at all.
        assert_eq!(
            configured
                .inventory(&second_account())
                .report
                .classification,
            ScanClassification::NotObserved
        );
        fs::remove_dir_all(missing).ok();
    }

    #[test]
    fn unknown_fingerprints_fail_closed_before_body_capture() {
        let root = temp_root("unknown");
        let path = rollout_path(&root, "03", "rollout-future.jsonl");
        let body: &[u8] = b"{\"record\":1}\n{\"secret\":\"must-not-be-captured\"}\n";
        write(&path, body);
        let configured = adapter(&root);
        let inventory = configured.inventory(&account());
        assert_eq!(
            inventory.report.classification,
            ScanClassification::FingerprintUnsupported
        );
        let source = inventory
            .unsupported()
            .next()
            .cloned()
            .expect("unsupported source retained visible");
        assert_eq!(source.fingerprint().as_str(), "codex-unknown-format");
        let error = configured
            .open(&source)
            .expect_err("unknown source rejected");
        assert_eq!(
            error.classification(),
            ScanClassification::FingerprintUnsupported
        );
        assert_eq!(fs::read(&path).expect("source unchanged"), body.to_vec());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn a_valid_header_does_not_admit_a_later_unknown_record() {
        let root = temp_root("body-fingerprint");
        let path = rollout_path(&root, "03", "rollout-future.jsonl");
        let mut body = format!("{}\n", rollout_record("session_meta"));
        for _ in 0..240 {
            body.push_str(&rollout_record("response_item"));
            body.push('\n');
        }
        body.push_str(
            r#"{"timestamp":"2026-09-24T00:00:00.000Z","type":"future_record","payload":{}}"#,
        );
        body.push('\n');
        write(&path, body.as_bytes());

        let configured = adapter(&root);
        let inventory = configured.inventory(&account());
        let source = inventory
            .supported()
            .next()
            .cloned()
            .expect("the bounded header contains the supported dialect");
        let error = configured
            .open(&source)
            .expect("header admission succeeds")
            .next_chunk()
            .expect_err("the complete body is checked before capture");
        assert_eq!(
            error.classification(),
            ScanClassification::FingerprintUnsupported
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn a_session_that_becomes_an_unsupported_format_is_a_format_change() {
        let root = temp_root("format-change");
        let path = rollout_path(&root, "03", "rollout-a.jsonl");
        write(
            &path,
            format!("{}\n", rollout_record("session_meta")).as_bytes(),
        );
        let (configured, source) = first_supported(&root);
        let mut capture = configured.open(&source).expect("open");
        capture.next_chunk().expect("first pass");
        fs::write(&path, b"not jsonl any more\n").expect("rewrite as foreign layout");
        let error = capture
            .next_chunk()
            .expect_err("the rewrite is not a readable generation");
        assert!(
            matches!(error, CodexCaptureError::FormatChanged(_)),
            "unexpected error: {error}"
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn multi_account_homes_route_independently() {
        let first_root = temp_root("multi-a");
        let second_root = temp_root("multi-b");
        write(
            &rollout_path(&first_root, "03", "rollout-a.jsonl"),
            format!("{}\n", rollout_record("session_meta")).as_bytes(),
        );
        write(
            &second_root.join("history.jsonl"),
            format!("{}\n", history_record("prompt")).as_bytes(),
        );
        let configured = CodexAdapter::new([
            ConfiguredRoot::new(account(), &first_root),
            ConfiguredRoot::new(second_account(), &second_root),
        ])
        .expect("adapter");
        let first = configured.inventory(&account());
        let second = configured.inventory(&second_account());
        assert_eq!(first.report.sources, 1);
        assert_eq!(second.report.sources, 1);
        assert_eq!(
            first.sources[0].fingerprint().as_str(),
            "codex-rollout-jsonl"
        );
        assert_eq!(
            second.sources[0].fingerprint().as_str(),
            "codex-history-jsonl"
        );
        let routed = first.discovered_sources().expect("routing list");
        assert_eq!(
            routed.iter().next().expect("entry").account,
            account(),
            "routing entries name their own account"
        );
        // The same account label cannot own two homes, and homes cannot
        // be empty.
        assert_eq!(
            CodexAdapter::new([
                ConfiguredRoot::new(account(), &first_root),
                ConfiguredRoot::new(account(), &second_root),
            ])
            .expect_err("duplicate account rejected"),
            CodexConfigError::DuplicateAccount
        );
        assert_eq!(
            CodexAdapter::new(Vec::<ConfiguredRoot>::new()).expect_err("empty rejected"),
            CodexConfigError::EmptyRoots
        );
        fs::remove_dir_all(first_root).expect("remove fixture");
        fs::remove_dir_all(second_root).expect("remove fixture");
    }

    #[test]
    fn parity_reconstructs_the_complete_record_prefix() {
        let root = temp_root("parity");
        let path = rollout_path(&root, "03", "rollout-a.jsonl");
        write(
            &path,
            format!("{}\n", rollout_record("session_meta")).as_bytes(),
        );
        let (configured, source) = first_supported(&root);
        let mut capture = configured.open(&source).expect("open");
        let mut captured: Vec<u8> = Vec::new();
        let mut current_generation: Option<SourceGeneration> = None;
        let mut expected_sequence = 0_u64;

        for round in 0..5_u32 {
            match round {
                1 => append(
                    &path,
                    format!(
                        "{}\n{}\n",
                        rollout_record("response_item"),
                        rollout_record("event_msg")
                    )
                    .as_bytes(),
                ),
                // A torn record is appended without its terminator.
                2 => append(&path, rollout_record("response_item").as_bytes()),
                // The torn record completes on a later pass.
                3 => append(&path, b"\n"),
                4 => append(
                    &path,
                    format!("{}\n", rollout_record("turn_context")).as_bytes(),
                ),
                _ => {}
            }
            while let Some(chunk) = capture.next_chunk().expect("parity pass") {
                let matches_current = current_generation
                    .as_ref()
                    .is_some_and(|open| open.generation == chunk.generation.generation);
                if !matches_current {
                    current_generation = Some(chunk.generation.clone());
                    expected_sequence = 0;
                }
                assert_eq!(chunk.sequence, expected_sequence);
                expected_sequence += 1;
                captured.extend_from_slice(&chunk.bytes);
            }
        }
        let snapshot = fs::read(&path).expect("read final snapshot");
        assert_eq!(
            captured,
            archivist_adapter_sdk::file_capture::RecordBoundary::complete_prefix(&snapshot),
            "ordered captures reconstruct the source's complete-record prefix"
        );
        assert_eq!(capture.history().len(), 0, "growth never rotates");
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn the_environment_home_prefers_codex_home_over_the_home_default() {
        assert_eq!(
            configured_home_from(
                Some(OsStr::new("/custom/codex")),
                Some(OsStr::new("/home/u"))
            ),
            PathBuf::from("/custom/codex")
        );
        assert_eq!(
            configured_home_from(None, Some(OsStr::new("/home/u"))),
            PathBuf::from("/home/u/.codex")
        );
        assert_eq!(
            configured_home_from(None, None),
            PathBuf::from(DEFAULT_CODEX_HOME)
        );
    }

    #[test]
    fn stated_session_ids_are_preserved_opaquely() {
        let stated = resolve_session_identity(Some("Session-ABC")).expect("stated identity");
        let lower = resolve_session_identity(Some("session-abc")).expect("stated identity");
        assert!(!stated.is_synthetic());
        assert_ne!(
            stated.upstream_session_id(),
            lower.upstream_session_id(),
            "opaque is opaque: lookalikes stay distinct"
        );
        assert!(
            resolve_session_identity(None)
                .expect("synthetic identity")
                .is_synthetic()
        );
        assert!(
            resolve_session_identity(Some(""))
                .expect("the empty string is absence")
                .is_synthetic()
        );
    }

    #[test]
    fn sha256_matches_the_standard_empty_vector() {
        assert_eq!(
            CodexDigest::from_raw(sha256(b"")).to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
