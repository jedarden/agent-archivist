// SPDX-License-Identifier: Apache-2.0

//! Claude Code source adapter.
//!
//! Discovers default and explicitly configured Claude Code account and source
//! roots, captures JSONL session files and related sidecars as separate
//! artifact kinds with explicit relationships, parses only on complete record
//! boundaries, and detects inode/file identity changes, truncation, tail
//! mismatch, and rewrites as new source generations. Harness and upstream
//! session IDs are preserved without treating either as global
//! (implementation plan, Phase 6A).
//!
//! Ships in the first adapter wave: file-based capture exercises marathon
//! chunking and these histories are expected to be the largest. An embedded
//! fingerprint allowlist fails closed on unknown schema versions rather than
//! attempting a best-effort parse.
//!
//! # The observed tree shape
//!
//! Discovery replicates the prototype's read-only inventory rule: all regular
//! files under each configured root's project directories, excluding
//! `memory/` directories and `.pre-union` files. Roles come from the tree
//! shape, not from names or content:
//!
//! - a `.jsonl` file directly inside a project directory is a [`Role::Session`]
//!   transcript;
//! - a `.jsonl` file below a per-session directory is a [`Role::Subagent`]
//!   transcript;
//! - any file below a `tool-results/` directory is a [`Role::ToolResult`]
//!   object the transcript references;
//! - any other file directly inside a per-session directory is a
//!   [`Role::SessionSidecar`];
//! - anything else is [`Role::Unknown`] and is retained visible but never
//!   captured.
//!
//! A session directory annotates the sibling transcript of the same stem:
//! `<uuid>/meta.json` is related to `<uuid>.jsonl`, and the relationship is
//! recorded only when that transcript was actually discovered
//! ([`ClaudeAdapter::sidecar_relationships`]). Nothing is guessed for an
//! orphaned session directory.
//!
//! # The pinned dialect
//!
//! A `.jsonl` file is Claude Code session JSONL when its bounded header
//! window carries a complete record with both a `type` and a `sessionId`
//! member — the envelope every observed record type in the fleet inventory
//! is written in. When an account-identifying member (`accountUuid`,
//! `ownerAccountUuid`, `ownerOrganizationUuid`) appears in the window the
//! dialect reads as `claude-jsonl-v2`, and without one as `claude-jsonl-v1`
//! — the observed structural discriminator between newer and older CLI
//! writers. A single-object `.json` sidecar admits as `claude-sidecar-v1`.
//! Anything else fails closed as [`ClaudeFormat::Unknown`] and opens as
//! `unsupported`.
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
use archivist_adapter_sdk::file_sidecar::SidecarKind;
use archivist_adapter_sdk::fingerprint::{
    FingerprintAllowlist, SourceFingerprint, UnsupportedFingerprint,
};
use archivist_adapter_sdk::lifecycle::{AdapterLifecycle, LifecycleState};
use archivist_adapter_sdk::session_identity::{SessionIdentity, SessionIdentityError};
use archivist_adapter_sdk::status::{AccountLabel, ScanClassification};
use archivist_adapter_sdk::{AdapterId, VersionToken};

/// The adapter identity stamped on captured Claude Code artifacts
/// (`adapter_id` on the occurrence manifest).
pub const ADAPTER_ID: &str = "claude-jsonl";

/// The harness name used when resolving upstream session identities
/// (plan Section 7.4 grammar).
pub const HARNESS_ID: &str = "claude-code";

/// The projection version stamped on captured artifacts
/// (`adapter_projection_version`). It pins the same dialect revision the
/// usage reader reads: a changed reading is a new version, never a silent
/// reinterpretation.
pub const PROJECTION_VERSION: &str = "1";

/// The default Claude Code projects root beneath the home directory.
pub const DEFAULT_PROJECTS_ROOT: &str = ".claude/projects";

/// The maximum header prefix read while identifying a source.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// The supported append-only Claude Code session JSONL fingerprints.
pub const JSONL_FINGERPRINTS: [&str; 2] = ["claude-jsonl-v1", "claude-jsonl-v2"];

/// The supported single-object sidecar fingerprint.
pub const SIDECAR_FINGERPRINT: &str = "claude-sidecar-v1";

const UNKNOWN_JSONL_FINGERPRINT: &str = "claude-jsonl-unknown";
const UNKNOWN_FILE_FINGERPRINT: &str = "claude-unknown-format";

/// The account-identifying members whose presence in the bounded header
/// window marks the `claude-jsonl-v2` dialect (fleet inventory: the
/// fields appear in records written by newer CLI versions).
const ACCOUNT_MEMBERS: [&str; 3] = ["accountUuid", "ownerAccountUuid", "ownerOrganizationUuid"];

/// Files under a directory with this name are never session material.
const MEMORY_DIR: &str = "memory";
/// Files under a directory with this name are tool results.
const TOOL_RESULTS_DIR: &str = "tool-results";
/// Files whose name carries this marker predate the identity union and
/// are never session material.
const PRE_UNION_MARKER: &str = ".pre-union";

/// How a discovered file plays in the Claude Code tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A primary session transcript: `.jsonl` directly inside a project
    /// directory.
    Session,
    /// A `.jsonl` transcript below a per-session directory.
    Subagent,
    /// A file below a `tool-results/` directory, referenced by the
    /// transcript.
    ToolResult,
    /// Harness metadata carried directly inside a per-session directory.
    SessionSidecar,
    /// A file discovered under a configured root but not admitted.
    Unknown,
}

impl Role {
    /// The stable content-free token for diagnostics and tests.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Subagent => "subagent",
            Self::ToolResult => "tool-result",
            Self::SessionSidecar => "session-sidecar",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this role captures as append-only JSONL slices.
    #[must_use]
    pub const fn is_jsonl(self) -> bool {
        matches!(self, Self::Session | Self::Subagent)
    }

    /// Whether this role may be opened for capture.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// The source format recognized by the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaudeFormat {
    /// An append-only Claude Code session JSONL file and its dialect
    /// version.
    Jsonl {
        /// The dialect version: 1 without, 2 with account-identifying
        /// members in the header window.
        version: u8,
    },
    /// A complete single-object sidecar file.
    Sidecar,
    /// A file discovered under a configured root but not admitted.
    Unknown,
}

impl ClaudeFormat {
    /// Whether this format is admitted by this adapter.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// The content-free fingerprint used in discovery and admission.
    #[must_use]
    pub fn fingerprint(self) -> SourceFingerprint {
        let token = match self {
            Self::Jsonl { version: 1 } => "claude-jsonl-v1",
            Self::Jsonl { version: 2 } => "claude-jsonl-v2",
            Self::Jsonl { .. } => UNKNOWN_JSONL_FINGERPRINT,
            Self::Sidecar => SIDECAR_FINGERPRINT,
            Self::Unknown => UNKNOWN_FILE_FINGERPRINT,
        };
        SourceFingerprint::parse(token).expect("Claude fingerprints are constants")
    }
}

/// A configured Claude Code account and its projects root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredRoot {
    account: AccountLabel,
    path: PathBuf,
}

impl ConfiguredRoot {
    /// Configure an account's projects root.
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

/// Alias for callers that name a configured root a Claude Code root.
pub type ClaudeRoot = ConfiguredRoot;

/// One file discovered below a configured projects root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaudeSource {
    account: AccountLabel,
    path: PathBuf,
    role: Role,
    format: ClaudeFormat,
    fingerprint: SourceFingerprint,
    read_classification: Option<ScanClassification>,
}

impl ClaudeSource {
    fn new(account: &AccountLabel, path: PathBuf, role: Role, format: ClaudeFormat) -> Self {
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
        role: Role,
        classification: ScanClassification,
    ) -> Self {
        let mut source = Self::new(account, path, role, ClaudeFormat::Unknown);
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
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The detected source format.
    #[must_use]
    pub const fn format(&self) -> ClaudeFormat {
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

/// The result of one Claude Code inventory pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaudeInventory {
    /// The bounded SDK discovery report.
    pub report: DiscoveryReport,
    /// Every file found, including unsupported formats.
    pub sources: Vec<ClaudeSource>,
}

impl ClaudeInventory {
    /// The supported sources in discovery order.
    pub fn supported(&self) -> impl Iterator<Item = &ClaudeSource> {
        self.sources.iter().filter(|source| source.is_supported())
    }

    /// The unsupported sources in discovery order.
    pub fn unsupported(&self) -> impl Iterator<Item = &ClaudeSource> {
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

/// One explicit sidecar relationship the adapter records: a session
/// sidecar annotates its sibling transcript, and the relationship is
/// stated only when that transcript was discovered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarBinding {
    /// The parent transcript the sidecar annotates.
    pub session: ClaudeSource,
    /// The sidecar artifact in its own right.
    pub sidecar: ClaudeSource,
    /// The role the sidecar plays beside its parent.
    pub kind: SidecarKind,
}

/// Construction errors for adapter configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaudeConfigError {
    /// The adapter must have at least one configured account root.
    EmptyRoots,
    /// More than one root used the same account label.
    DuplicateAccount,
}

impl fmt::Display for ClaudeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyRoots => "claude_empty_roots",
            Self::DuplicateAccount => "claude_duplicate_account",
        })
    }
}

impl std::error::Error for ClaudeConfigError {}

/// Errors returned while reading or admitting a Claude Code source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaudeCaptureError {
    /// The source fingerprint is not on the adapter's allowlist.
    Unsupported(UnsupportedFingerprint),
    /// The source disappeared or its root was absent.
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

impl ClaudeCaptureError {
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

impl fmt::Display for ClaudeCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported(_) => "claude_unsupported_fingerprint",
            Self::RootAbsent => "claude_root_absent",
            Self::PermissionDenied => "claude_permission_denied",
            Self::ReadError => "claude_read_error",
            Self::FormatChanged(_) => "claude_format_changed",
            Self::CursorSourceShrank => "claude_capture_source_shrank",
        })
    }
}

impl std::error::Error for ClaudeCaptureError {}

/// The kind of captured Claude Code artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaudeArtifactKind {
    /// A complete-record slice from an append-only session or subagent
    /// JSONL file.
    Jsonl,
    /// One complete sidecar object: a tool result or session sidecar.
    Object,
}

/// A digest of canonical captured bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClaudeDigest([u8; 32]);

impl ClaudeDigest {
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

impl fmt::Display for ClaudeDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex(self.0))
    }
}

/// One capture emitted by the adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaudeCapturedChunk {
    /// Whether this chunk is a JSONL slice or a whole sidecar object.
    pub artifact: ClaudeArtifactKind,
    /// The generation that owns the bytes.
    pub generation: SourceGeneration,
    /// Complete canonical bytes. JSONL chunks include terminating newlines.
    pub bytes: Vec<u8>,
    /// SHA-256 over bytes.
    pub digest: ClaudeDigest,
    /// Inclusive byte range within this generation's source stream.
    pub range_start: u64,
    /// Inclusive byte range within this generation's source stream.
    pub range_end: u64,
    /// Zero-based chunk order within the generation.
    pub sequence: u64,
    /// The admitted source fingerprint.
    pub fingerprint: SourceFingerprint,
}

impl ClaudeCapturedChunk {
    /// Whether this chunk is a whole sidecar object.
    #[must_use]
    pub const fn is_object(&self) -> bool {
        matches!(self.artifact, ClaudeArtifactKind::Object)
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

/// The filesystem-backed Claude Code source adapter.
#[derive(Clone, Debug)]
pub struct ClaudeAdapter {
    descriptor: AdapterDescriptor,
    roots: Vec<ConfiguredRoot>,
    state: LifecycleState,
}

impl ClaudeAdapter {
    /// Build an adapter from one or more account roots.
    pub fn new<I>(roots: I) -> Result<Self, ClaudeConfigError>
    where
        I: IntoIterator<Item = ConfiguredRoot>,
    {
        let roots: Vec<_> = roots.into_iter().collect();
        if roots.is_empty() {
            return Err(ClaudeConfigError::EmptyRoots);
        }
        let mut accounts = BTreeSet::new();
        if roots
            .iter()
            .any(|root| !accounts.insert(root.account().clone()))
        {
            return Err(ClaudeConfigError::DuplicateAccount);
        }
        Ok(Self {
            descriptor: descriptor(),
            roots,
            state: LifecycleState::Constructed,
        })
    }

    /// Compatibility constructor named after mounting an adapter.
    pub fn mount<I>(roots: I) -> Result<Self, ClaudeConfigError>
    where
        I: IntoIterator<Item = ConfiguredRoot>,
    {
        Self::new(roots)
    }

    /// Construct an adapter from Claude Code's environment-selected
    /// projects root: `CLAUDE_CONFIG_DIR` beneath its `projects`
    /// directory, else the home default.
    pub fn from_environment(account: AccountLabel) -> Result<Self, ClaudeConfigError> {
        Self::new([ConfiguredRoot::new(account, configured_projects_root())])
    }

    /// The descriptor published by this adapter.
    #[must_use]
    pub const fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    /// The configured roots, in construction order.
    #[must_use]
    pub fn roots(&self) -> &[ConfiguredRoot] {
        &self.roots
    }

    /// Inventory one configured account, retaining unsupported files.
    #[must_use]
    pub fn inventory(&self, account: &AccountLabel) -> ClaudeInventory {
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
        ClaudeInventory { report, sources }
    }

    /// Open one source after exact fingerprint admission.
    pub fn open(&self, source: &ClaudeSource) -> Result<ClaudeCapture, ClaudeCaptureError> {
        if let Some(classification) = source.read_classification() {
            return Err(match classification {
                ScanClassification::PermissionDenied => ClaudeCaptureError::PermissionDenied,
                _ => ClaudeCaptureError::ReadError,
            });
        }
        if !source.is_supported() {
            return Err(ClaudeCaptureError::Unsupported(UnsupportedFingerprint {
                fingerprint: source.fingerprint().clone(),
            }));
        }
        self.descriptor
            .fingerprints
            .admit(source.fingerprint())
            .map_err(ClaudeCaptureError::Unsupported)?;
        if source.role().is_jsonl() {
            Ok(ClaudeCapture::Jsonl(JsonlCapture::new(source.clone())))
        } else {
            Ok(ClaudeCapture::Object(ObjectCapture::new(source.clone())))
        }
    }

    /// Alias for open used by callers that call a capture a stream.
    pub fn capture(&self, source: &ClaudeSource) -> Result<ClaudeCapture, ClaudeCaptureError> {
        self.open(source)
    }

    /// The explicit sidecar relationships discovered for one account:
    /// every session sidecar bound to its same-stem sibling transcript.
    /// Tool results are artifacts in their own right and bind to no
    /// parent; an orphaned session directory binds to nothing, because
    /// the transcript it would annotate was never discovered.
    #[must_use]
    pub fn sidecar_relationships(&self, account: &AccountLabel) -> Vec<SidecarBinding> {
        let inventory = self.inventory(account);
        let mut bindings = Vec::new();
        for sidecar in inventory.supported() {
            if sidecar.role() != Role::SessionSidecar {
                continue;
            }
            let Some(session_dir) = sidecar.path().parent() else {
                continue;
            };
            let Some(dir_name) = session_dir.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let mut transcript = session_dir.to_path_buf();
            transcript.pop();
            transcript.push(format!("{dir_name}.jsonl"));
            if let Some(session) = inventory
                .supported()
                .find(|source| source.role() == Role::Session && source.path() == transcript)
            {
                bindings.push(SidecarBinding {
                    session: session.clone(),
                    sidecar: sidecar.clone(),
                    kind: SidecarKind::SessionMetadata,
                });
            }
        }
        bindings.sort_by(|left, right| {
            left.session
                .path()
                .cmp(right.session.path())
                .then(left.sidecar.path().cmp(right.sidecar.path()))
        });
        bindings
    }
}

impl AdapterLifecycle for ClaudeAdapter {
    fn state(&self) -> LifecycleState {
        self.state
    }

    fn close(&mut self) {
        self.state = LifecycleState::Closed;
    }
}

impl SourceDiscovery for ClaudeAdapter {
    fn discover(&self, account: &AccountLabel) -> DiscoveryReport {
        self.inventory(account).report
    }
}

/// A live capture stream for a supported Claude Code source.
#[derive(Clone, Debug)]
pub enum ClaudeCapture {
    /// Append-only JSONL complete-record capture.
    Jsonl(JsonlCapture),
    /// Digest-sensitive whole-object sidecar capture.
    Object(ObjectCapture),
}

impl ClaudeCapture {
    /// Pull one capture unit. None means no newly complete bytes exist.
    pub fn next_chunk(&mut self) -> Result<Option<ClaudeCapturedChunk>, ClaudeCaptureError> {
        match self {
            Self::Jsonl(capture) => capture.next_chunk(),
            Self::Object(capture) => capture.next_chunk(),
        }
    }

    /// The currently open generation.
    #[must_use]
    pub fn generation(&self) -> &SourceGeneration {
        match self {
            Self::Jsonl(capture) => capture.generation(),
            Self::Object(capture) => capture.generation(),
        }
    }

    /// Generations closed by replacement, truncation, or rewrite.
    #[must_use]
    pub fn history(&self) -> &[SourceGeneration] {
        match self {
            Self::Jsonl(capture) => capture.history(),
            Self::Object(capture) => capture.history(),
        }
    }

    /// The source this stream reads.
    #[must_use]
    pub fn source(&self) -> &ClaudeSource {
        match self {
            Self::Jsonl(capture) => capture.source(),
            Self::Object(capture) => capture.source(),
        }
    }
}

/// JSONL capture state using the SDK file-core cursor.
#[derive(Clone, Debug)]
pub struct JsonlCapture {
    source: ClaudeSource,
    tracker: Option<FileGenerationTracker>,
    cursor: CaptureCursor,
    sequence: u64,
}

impl JsonlCapture {
    /// Start an unopened JSONL stream.
    #[must_use]
    pub fn new(source: ClaudeSource) -> Self {
        Self {
            source,
            tracker: None,
            cursor: CaptureCursor::new(),
            sequence: 0,
        }
    }

    /// The source this stream reads.
    #[must_use]
    pub fn source(&self) -> &ClaudeSource {
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

    /// Pull the next complete JSONL byte slice.
    pub fn next_chunk(&mut self) -> Result<Option<ClaudeCapturedChunk>, ClaudeCaptureError> {
        let identity = file_identity(&self.source.path)?;
        let prefix = read_prefix(&self.source.path)?;
        let detected = detect_jsonl(&prefix);
        if detected != self.source.format {
            return Err(ClaudeCaptureError::FormatChanged(UnsupportedFingerprint {
                fingerprint: detected.fingerprint(),
            }));
        }
        let bytes = read_all(&self.source.path)?;
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
            CaptureCursorError::SourceShrank => ClaudeCaptureError::CursorSourceShrank,
        })?;
        if outcome.captured.is_empty() {
            return Ok(None);
        }
        let captured = outcome.captured.to_vec();
        let end = start
            .checked_add(measured(captured.len()))
            .and_then(|value| value.checked_sub(1))
            .unwrap_or(u64::MAX);
        let chunk = ClaudeCapturedChunk {
            artifact: ClaudeArtifactKind::Jsonl,
            generation: self.generation().clone(),
            digest: ClaudeDigest::from_raw(sha256(&captured)),
            bytes: captured,
            range_start: start,
            range_end: end,
            sequence: self.sequence,
            fingerprint: self.source.fingerprint().clone(),
        };
        self.sequence = self.sequence.saturating_add(1);
        Ok(Some(chunk))
    }
}

/// Whole-object capture state. The generation tracker observes a
/// fixed-size digest probe with the real filesystem identity, so every
/// digest change is a generation boundary.
#[derive(Clone, Debug)]
pub struct ObjectCapture {
    source: ClaudeSource,
    tracker: Option<FileGenerationTracker>,
    last_digest: Option<ClaudeDigest>,
    sequence: u64,
}

impl ObjectCapture {
    /// Start an unopened whole-object stream.
    #[must_use]
    pub fn new(source: ClaudeSource) -> Self {
        Self {
            source,
            tracker: None,
            last_digest: None,
            sequence: 0,
        }
    }

    /// The source this stream reads.
    #[must_use]
    pub fn source(&self) -> &ClaudeSource {
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

    /// Pull the whole object once per digest-sensitive generation.
    pub fn next_chunk(&mut self) -> Result<Option<ClaudeCapturedChunk>, ClaudeCaptureError> {
        let identity = file_identity(&self.source.path)?;
        let prefix = read_prefix(&self.source.path)?;
        if detect_sidecar(&prefix) != self.source.format {
            return Err(ClaudeCaptureError::FormatChanged(UnsupportedFingerprint {
                fingerprint: ClaudeFormat::Unknown.fingerprint(),
            }));
        }
        let bytes = read_all(&self.source.path)?;
        let digest = ClaudeDigest::from_raw(sha256(&bytes));
        let probe = digest_probe(digest);
        let rotated = if let Some(tracker) = self.tracker.as_mut() {
            matches!(
                tracker.observe(identity, &probe),
                GenerationDecision::Rotated(_)
            )
        } else {
            self.tracker = Some(FileGenerationTracker::begin(identity, &probe));
            false
        };
        let changed = self.last_digest != Some(digest);
        self.last_digest = Some(digest);
        if (!rotated && !changed) || bytes.is_empty() {
            return Ok(None);
        }
        let end = measured(bytes.len()).saturating_sub(1);
        let chunk = ClaudeCapturedChunk {
            artifact: ClaudeArtifactKind::Object,
            generation: self.generation().clone(),
            digest,
            bytes,
            range_start: 0,
            range_end: end,
            sequence: self.sequence,
            fingerprint: self.source.fingerprint().clone(),
        };
        self.sequence = self.sequence.saturating_add(1);
        Ok(Some(chunk))
    }
}

/// Resolve the session identity capture namespaces by: the harness name
/// is fixed at [`HARNESS_ID`], and the harness's stated session ID is
/// preserved byte-for-byte — never case-folded, normalized, or merged
/// with a lookalike. An absent or empty stated ID is a synthetic
/// identity, never a path-derived guess.
///
/// # Errors
/// [`SessionIdentityError::UpstreamSessionInvalid`] when the stated
/// session ID is outside the opaque bound.
pub fn resolve_session_identity(
    stated: Option<&str>,
) -> Result<SessionIdentity, SessionIdentityError> {
    SessionIdentity::resolve(HARNESS_ID, stated)
}

/// How the configured root itself answered this pass.
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
        AdapterCapability::SidecarRelationships.token(),
        AdapterCapability::CoverageGapReporting.token(),
    ])
    .expect("Claude capabilities are constants");
    let fingerprints =
        FingerprintAllowlist::parse(JSONL_FINGERPRINTS.into_iter().chain([SIDECAR_FINGERPRINT]))
            .expect("Claude fingerprints are constants");
    AdapterDescriptor::publish(
        AdapterId::parse(ADAPTER_ID).expect("Claude adapter id is canonical"),
        VersionToken::parse(PROJECTION_VERSION).expect("Claude projection is canonical"),
        capabilities,
        fingerprints,
    )
    .expect("Claude declares capture capabilities")
}

fn empty_inventory(
    descriptor: &AdapterDescriptor,
    account: &AccountLabel,
    classification: ScanClassification,
) -> ClaudeInventory {
    ClaudeInventory {
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

fn inventory_root(root: &ConfiguredRoot, output: &mut Vec<ClaudeSource>) -> RootAccess {
    let metadata = match fs::metadata(root.path()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return RootAccess::RootAbsent,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return RootAccess::PermissionDenied;
        }
        Err(_) => return RootAccess::ReadError,
    };
    if metadata.is_file() {
        output.push(inspect_source(
            root.account(),
            root.path().to_path_buf(),
            Role::Unknown,
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
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.contains(PRE_UNION_MARKER) {
                continue;
            }
            if metadata.is_dir() {
                if name == MEMORY_DIR {
                    continue;
                }
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

fn inspect_source(account: &AccountLabel, path: PathBuf, role: Role) -> ClaudeSource {
    let prefix = match read_prefix(&path) {
        Ok(prefix) => prefix,
        Err(error) => {
            return ClaudeSource::unreadable(account, path, role, error.classification());
        }
    };
    let format = match role {
        Role::Session | Role::Subagent => detect_jsonl(&prefix),
        Role::ToolResult | Role::SessionSidecar => detect_sidecar(&prefix),
        Role::Unknown => ClaudeFormat::Unknown,
    };
    ClaudeSource::new(account, path, role, format)
}

/// The tree-shape role of one regular file: a `.jsonl` file directly
/// inside a project directory is a session transcript, anything under a
/// `tool-results/` directory is a tool result, a `.jsonl` file below a
/// per-session directory is a subagent transcript, and any other file
/// directly inside a per-session directory is a session sidecar.
/// Everything else is unknown.
fn role_for(path: &Path, root: &Path) -> Role {
    let Ok(relative) = path.strip_prefix(root) else {
        return Role::Unknown;
    };
    let components: Vec<_> = relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    let Some(file_name) = components.last() else {
        return Role::Unknown;
    };
    let directories = &components[..components.len() - 1];
    if directories.len() == 1 {
        return if is_jsonl_name(file_name) {
            Role::Session
        } else {
            Role::Unknown
        };
    }
    if directories.contains(&TOOL_RESULTS_DIR) {
        return Role::ToolResult;
    }
    if is_jsonl_name(file_name) {
        if directories.len() >= 2 {
            return Role::Subagent;
        }
    } else if directories.len() == 2 {
        return Role::SessionSidecar;
    }
    Role::Unknown
}

/// Detect the Claude Code JSONL dialect and its version from a bounded
/// header window: some complete line must carry both a `type` and a
/// `sessionId` member, and any account-identifying member in the window
/// marks the v2 dialect.
fn detect_jsonl(prefix: &[u8]) -> ClaudeFormat {
    let mut saw_dialect = false;
    let mut saw_account = false;
    for line in complete_lines(prefix) {
        if json_string_member(line, "type").is_some()
            && json_string_member(line, "sessionId").is_some()
        {
            saw_dialect = true;
        }
        if ACCOUNT_MEMBERS
            .iter()
            .any(|member| json_has_member(line, member))
        {
            saw_account = true;
        }
    }
    if !saw_dialect {
        return ClaudeFormat::Unknown;
    }
    ClaudeFormat::Jsonl {
        version: if saw_account { 2 } else { 1 },
    }
}

/// Detect the single-object sidecar format: the file must begin with a
/// JSON object.
fn detect_sidecar(prefix: &[u8]) -> ClaudeFormat {
    if trim_ascii_space(prefix).first() != Some(&b'{') {
        return ClaudeFormat::Unknown;
    }
    ClaudeFormat::Sidecar
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

fn json_string_member(bytes: &[u8], key: &str) -> Option<String> {
    let start = json_member_value(bytes, key)?;
    if start.first() != Some(&b'"') {
        return None;
    }
    let end = start[1..].iter().position(|byte| *byte == b'"')? + 1;
    std::str::from_utf8(&start[1..end]).ok().map(str::to_owned)
}

fn json_has_member(bytes: &[u8], key: &str) -> bool {
    json_member_value(bytes, key).is_some()
}

/// The raw value bytes following `"key":` in a bounded window, found by
/// the prototype's own structural-probe rule.
fn json_member_value<'a>(bytes: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let needle = format!("\"{key}\"");
    if needle.len() > bytes.len() {
        return None;
    }
    let start = bytes
        .windows(needle.len())
        .position(|window| window == needle.as_bytes())?;
    let rest = &bytes[start + needle.len()..];
    let colon = rest.iter().position(|byte| *byte == b':')?;
    Some(trim_ascii_space(&rest[colon + 1..]))
}

fn configured_projects_root() -> PathBuf {
    if let Some(config_dir) = env::var_os("CLAUDE_CONFIG_DIR") {
        return PathBuf::from(config_dir).join("projects");
    }
    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(DEFAULT_PROJECTS_ROOT);
    }
    PathBuf::from(DEFAULT_PROJECTS_ROOT)
}

fn file_identity(path: &Path) -> Result<FileIdentity, ClaudeCaptureError> {
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

fn read_prefix(path: &Path) -> Result<Vec<u8>, ClaudeCaptureError> {
    let file = File::open(path).map_err(|error| map_io_error(&error))?;
    let mut bytes = Vec::new();
    file.take(measured(MAX_HEADER_BYTES))
        .read_to_end(&mut bytes)
        .map_err(|error| map_io_error(&error))?;
    Ok(bytes)
}

fn read_all(path: &Path) -> Result<Vec<u8>, ClaudeCaptureError> {
    fs::read(path).map_err(|error| map_io_error(&error))
}

fn map_io_error(error: &io::Error) -> ClaudeCaptureError {
    match error.kind() {
        io::ErrorKind::NotFound => ClaudeCaptureError::RootAbsent,
        io::ErrorKind::PermissionDenied => ClaudeCaptureError::PermissionDenied,
        _ => ClaudeCaptureError::ReadError,
    }
}

fn digest_probe(digest: ClaudeDigest) -> Vec<u8> {
    let mut probe = Vec::with_capacity(33);
    probe.extend_from_slice(&digest.0);
    probe.push(b'\n');
    probe
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
        env::temp_dir().join(format!("archivist-claude-{label}-{nanos}"))
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

    fn adapter(root: &Path) -> ClaudeAdapter {
        ClaudeAdapter::new([ConfiguredRoot::new(account(), root)]).expect("adapter")
    }

    fn first_supported(root: &Path) -> (ClaudeAdapter, ClaudeSource) {
        let configured = adapter(root);
        let source = configured
            .inventory(&account())
            .supported()
            .next()
            .cloned()
            .expect("source");
        (configured, source)
    }

    /// A session record of the pinned dialect, with an explicit record
    /// UUID so tests can rewrite one record at a constant byte length.
    fn record_with(type_name: &str, uuid: &str, account_member: bool) -> String {
        let account = if account_member {
            r#","accountUuid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee""#
        } else {
            ""
        };
        format!(
            r#"{{"parentUuid":null,"sessionId":"s1","type":"{type_name}","uuid":"{uuid}","timestamp":"2026-09-24T00:00:00.000Z"{account}}}"#
        )
    }

    fn record(type_name: &str, account_member: bool) -> String {
        record_with(type_name, "u1", account_member)
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
        assert_eq!(
            tokens,
            ["claude-jsonl-v1", "claude-jsonl-v2", "claude-sidecar-v1"]
        );
        assert!(
            descriptor
                .capabilities
                .supports(AdapterCapability::CompleteRecordBoundaries)
        );
        assert!(
            descriptor
                .capabilities
                .supports(AdapterCapability::SidecarRelationships)
        );
        // An unknown observed version fails closed.
        let future = SourceFingerprint::parse("claude-jsonl-v9").expect("parses");
        assert!(descriptor.fingerprints.admit(&future).is_err());
    }

    #[test]
    fn the_golden_tree_maps_roles_fingerprints_and_exclusions() {
        let root = temp_root("golden");
        write(
            &root.join("proj/s1.jsonl"),
            format!(
                "{}\n{}\n",
                record("user", false),
                record("assistant", false)
            )
            .as_bytes(),
        );
        write(
            &root.join("proj/s2.jsonl"),
            format!("{}\n{}\n", record("user", false), record("assistant", true)).as_bytes(),
        );
        write(
            &root.join("proj/s1/subagents/agent-1.jsonl"),
            format!("{}\n", record("assistant", false)).as_bytes(),
        );
        write(
            &root.join("proj/s1/tool-results/toolu_1.json"),
            br#"{"type":"tool_result","content":" oversized"}"#,
        );
        write(
            &root.join("proj/s1/meta.json"),
            br#"{"version":"2.1.250","model":"claude-sonnet-5"}"#,
        );
        // Excluded by the discovery rule: memory directories and
        // .pre-union files never become sources at all.
        write(&root.join("proj/s1/memory/note.md"), b"memory");
        write(&root.join("proj/memory/deep.jsonl"), b"memory");
        write(
            &root.join("proj/s3.jsonl.pre-union"),
            format!("{}\n", record("user", false)).as_bytes(),
        );
        // Unsupported but visible.
        write(&root.join("proj/stray.txt"), b"not a transcript");
        let inventory = adapter(&root).inventory(&account());
        assert_eq!(inventory.report.sources, 6);
        assert_eq!(inventory.report.supported, 5);
        assert_eq!(inventory.report.unsupported, 1);
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
        assert_eq!(role_of("s1.jsonl").0, Role::Session);
        assert_eq!(role_of("s1.jsonl").1.as_str(), "claude-jsonl-v1");
        assert_eq!(role_of("s2.jsonl").0, Role::Session);
        assert_eq!(role_of("s2.jsonl").1.as_str(), "claude-jsonl-v2");
        assert_eq!(role_of("agent-1.jsonl").0, Role::Subagent);
        assert_eq!(role_of("toolu_1.json").0, Role::ToolResult);
        assert_eq!(role_of("toolu_1.json").1.as_str(), "claude-sidecar-v1");
        assert_eq!(role_of("meta.json").0, Role::SessionSidecar);
        assert_eq!(role_of("stray.txt").0, Role::Unknown);
        assert_eq!(inventory.supported().count(), 5);
        assert_eq!(
            inventory.discovered_sources().expect("routing list").len(),
            3,
            "one routing entry per distinct supported fingerprint"
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn a_summary_first_session_still_admits_on_its_window() {
        let root = temp_root("summary-first");
        write(
            &root.join("proj/s3.jsonl"),
            format!(
                "{}\n{}\n",
                r#"{"type":"summary","summary":"a title","leafUuid":"leaf-1"}"#,
                record("user", false)
            )
            .as_bytes(),
        );
        let inventory = adapter(&root).inventory(&account());
        let source = inventory.supported().next().cloned().expect("admitted");
        assert_eq!(source.fingerprint().as_str(), "claude-jsonl-v1");
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn jsonl_growth_captures_only_complete_records_and_preserves_generation() {
        let root = temp_root("growth");
        let path = root.join("proj/s1.jsonl");
        write(&path, format!("{}\n", record("user", false)).as_bytes());
        let (configured, source) = first_supported(&root);
        let mut capture = configured.open(&source).expect("open");
        let first = capture.next_chunk().expect("first pass").expect("header");
        assert_eq!(first.artifact, ClaudeArtifactKind::Jsonl);
        assert_eq!(first.sequence, 0);
        let generation = first.generation.clone();
        assert_eq!(capture.next_chunk().expect("unchanged pass"), None);

        // A torn record is measured, never captured.
        append(&path, record("assistant", false).as_bytes());
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
            format!("{}\n", record("assistant", false)).into_bytes()
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn replacement_truncation_tail_mismatch_and_rewrite_open_generations() {
        let root = temp_root("replacement");
        let path = root.join("proj/s1.jsonl");
        let first_line = format!("{}\n", record_with("user", "u1", true));
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
        let replacement = format!("{first_line}{}\n", record_with("mode", "u2", true));
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
            format!("{}\n", record_with("mode", "u2", true)).as_bytes(),
        );
        let growth = capture
            .next_chunk()
            .expect("growth pass")
            .expect("growth chunk");
        assert_eq!(growth.sequence, 1);
        assert_eq!(capture.history().len(), 2);

        // Tail mismatch: the acknowledged last record is rewritten in
        // place at an identical byte length with the earlier head intact.
        let mismatched_bytes = format!("{first_line}{}\n", record_with("mode", "u3", true));
        let current = fs::read_to_string(&path).expect("read current");
        let rewritten = current.replace(
            &record_with("mode", "u2", true),
            &record_with("mode", "u3", true),
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
            "{}{}\n{}\n",
            record_with("user", "u4", true),
            record_with("mode", "u3", true),
            record("assistant", false)
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
    fn sidecar_objects_reemit_only_on_digest_change() {
        let root = temp_root("sidecar-object");
        let path = root.join("proj/s1/tool-results/toolu_1.json");
        let first_body: &[u8] = br#"{"type":"tool_result","content":"a"}"#;
        let second_body: &[u8] = br#"{"type":"tool_result","content":"b"}"#;
        write(&path, first_body);
        let (configured, source) = first_supported(&root);
        assert_eq!(source.role(), Role::ToolResult);
        let mut capture = configured.open(&source).expect("open");
        let first = capture.next_chunk().expect("first pass").expect("object");
        assert!(first.is_object());
        assert_eq!(first.bytes, first_body.to_vec());
        assert_eq!(first.range_start, 0);
        assert_eq!(first.sequence, 0);
        assert_eq!(capture.next_chunk().expect("idempotent pass"), None);
        let generation = first.generation.clone();
        write(&path, second_body);
        let second = capture.next_chunk().expect("rewrite pass").expect("object");
        assert_ne!(second.generation.generation, generation.generation);
        assert_eq!(capture.history().len(), 1);
        assert_eq!(second.bytes, second_body.to_vec());
        assert_eq!(capture.next_chunk().expect("settled pass"), None);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn permission_denied_fails_closed_without_reading_content() {
        let root = temp_root("permission");
        let path = root.join("proj/s1.jsonl");
        write(&path, format!("{}\n", record("user", false)).as_bytes());
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
        let source = inventory.sources.first().cloned().expect("visible");
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
    fn a_missing_root_is_an_absent_inventory() {
        let missing = temp_root("missing");
        let configured = adapter(&missing);
        let inventory = configured.inventory(&account());
        assert_eq!(
            inventory.report.classification,
            ScanClassification::RootAbsent
        );
        assert!(inventory.sources.is_empty());
        assert_eq!(inventory.supported().count(), 0);
        // An account with no configured root is not observed at all.
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
        let path = root.join("proj/future.jsonl");
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
        assert_eq!(source.fingerprint().as_str(), "claude-unknown-format");
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
    fn a_session_that_becomes_an_unsupported_format_is_a_format_change() {
        let root = temp_root("format-change");
        let path = root.join("proj/s1.jsonl");
        write(&path, format!("{}\n", record("user", false)).as_bytes());
        let (configured, source) = first_supported(&root);
        let mut capture = configured.open(&source).expect("open");
        capture.next_chunk().expect("first pass");
        fs::write(&path, b"not jsonl any more\n").expect("rewrite as foreign layout");
        let error = capture
            .next_chunk()
            .expect_err("the rewrite is not a readable generation");
        assert!(
            matches!(error, ClaudeCaptureError::FormatChanged(_)),
            "unexpected error: {error}"
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn multi_account_roots_route_independently() {
        let first_root = temp_root("multi-a");
        let second_root = temp_root("multi-b");
        write(
            &first_root.join("proj/s1.jsonl"),
            format!("{}\n", record("user", false)).as_bytes(),
        );
        write(
            &second_root.join("proj/s9.jsonl"),
            format!("{}\n", record("user", true)).as_bytes(),
        );
        let configured = ClaudeAdapter::new([
            ConfiguredRoot::new(account(), &first_root),
            ConfiguredRoot::new(second_account(), &second_root),
        ])
        .expect("adapter");
        let first = configured.inventory(&account());
        let second = configured.inventory(&second_account());
        assert_eq!(first.report.sources, 1);
        assert_eq!(second.report.sources, 1);
        assert_eq!(first.sources[0].fingerprint().as_str(), "claude-jsonl-v1");
        assert_eq!(second.sources[0].fingerprint().as_str(), "claude-jsonl-v2");
        let routed = first.discovered_sources().expect("routing list");
        assert_eq!(
            routed.iter().next().expect("entry").account,
            account(),
            "routing entries name their own account"
        );
        // The same account label cannot own two roots, and roots cannot
        // be empty.
        assert_eq!(
            ClaudeAdapter::new([
                ConfiguredRoot::new(account(), &first_root),
                ConfiguredRoot::new(account(), &second_root),
            ])
            .expect_err("duplicate account rejected"),
            ClaudeConfigError::DuplicateAccount
        );
        assert_eq!(
            ClaudeAdapter::new(Vec::<ConfiguredRoot>::new()).expect_err("empty rejected"),
            ClaudeConfigError::EmptyRoots
        );
        fs::remove_dir_all(first_root).expect("remove fixture");
        fs::remove_dir_all(second_root).expect("remove fixture");
    }

    #[test]
    fn parity_reconstructs_the_complete_record_prefix() {
        let root = temp_root("parity");
        let path = root.join("proj/s1.jsonl");
        write(&path, format!("{}\n", record("user", false)).as_bytes());
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
                        "{}{}\n",
                        record("assistant", false),
                        record("system", false)
                    )
                    .as_bytes(),
                ),
                // A torn record is appended without its terminator.
                2 => append(&path, record("assistant", false).as_bytes()),
                // The torn record completes on a later pass.
                3 => append(&path, b"\n"),
                4 => append(&path, format!("{}\n", record("user", false)).as_bytes()),
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
    fn sidecar_relationships_bind_to_their_named_session_only() {
        let root = temp_root("sidecar-bindings");
        write(
            &root.join("proj/s1.jsonl"),
            format!("{}\n", record("user", false)).as_bytes(),
        );
        write(&root.join("proj/s1/meta.json"), br#"{"version":"2.1.250"}"#);
        write(
            &root.join("proj/s1/tool-results/toolu_1.json"),
            br#"{"type":"tool_result"}"#,
        );
        // An orphaned session directory: no s2.jsonl was discovered, so
        // nothing binds to it.
        write(
            &root.join("proj/s2/orphan.json"),
            br#"{"version":"2.1.250"}"#,
        );
        let configured = adapter(&root);
        let bindings = configured.sidecar_relationships(&account());
        assert_eq!(bindings.len(), 1, "tool results bind to no parent");
        let binding = &bindings[0];
        assert!(binding.session.path().ends_with("s1.jsonl"));
        assert!(binding.sidecar.path().ends_with("meta.json"));
        assert_eq!(binding.kind, SidecarKind::SessionMetadata);
        assert_eq!(binding.kind.token(), "session-metadata");
        fs::remove_dir_all(root).expect("remove fixture");
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
            ClaudeDigest::from_raw(sha256(b"")).to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
